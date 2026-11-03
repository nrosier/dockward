//! The in-process job worker (`specs/backend.md`, Durable job queue).
//!
//! The worker claims one due `sync_jobs` row at a time and passes it to a [`JobHandler`].
//! A success marks the job `done`. A failure is recorded with the backoff from
//! [`crate::services::sync_jobs`]. It stops taking new jobs after the stop signal.
//!
//! The handler that runs real syncs is added with the Harbor and GitHub pipeline. Until
//! then the worker uses [`NoopHandler`], which completes every job.

use std::time::Duration;

use sqlx::SqlitePool;
use tokio::sync::watch;

use crate::db::sync_jobs::{self, ClaimedJob};
use crate::error::AppError;
use crate::services::sync_jobs::{AfterFailure, after_failure};

/// Runs one claimed job. An `Err` is a failed attempt. Its text is stored in `last_error`,
/// so it must not contain secrets.
#[allow(async_fn_in_trait)]
pub trait JobHandler {
    async fn run(&self, job: &ClaimedJob) -> Result<(), String>;
}

/// The default handler until the sync pipeline exists. It completes every job.
pub struct NoopHandler;

impl JobHandler for NoopHandler {
    async fn run(&self, _job: &ClaimedJob) -> Result<(), String> {
        Ok(())
    }
}

/// How long the worker sleeps when no job is due.
pub const IDLE_POLL: Duration = Duration::from_secs(5);

/// The outcome of one worker step, for tests and logs. Carries no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nothing was due.
    Idle,
    /// A job finished.
    Done,
    /// A job failed and will retry at `next_attempt_at` (Unix seconds).
    Retry { next_attempt_at: i64 },
    /// A job failed for the last time and is `failed`.
    GaveUp,
}

/// Claims at most one due job, runs it, and records the outcome.
pub async fn step<H: JobHandler>(
    pool: &SqlitePool,
    handler: &H,
    now: i64,
) -> Result<Step, AppError> {
    let Some(job) = sync_jobs::claim_next(pool, now).await? else {
        return Ok(Step::Idle);
    };
    match handler.run(&job).await {
        Ok(()) => {
            sync_jobs::mark_done(pool, &job.id, now).await?;
            Ok(Step::Done)
        }
        Err(message) => {
            let attempts = job.attempts + 1;
            let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
            let outcome = match after_failure(attempts) {
                AfterFailure::RetryIn(secs) => {
                    let next = now + secs;
                    sync_jobs::record_failure(
                        &mut tx,
                        &job.id,
                        attempts,
                        Some(next),
                        &message,
                        false,
                        now,
                    )
                    .await?;
                    Step::Retry {
                        next_attempt_at: next,
                    }
                }
                AfterFailure::GiveUp => {
                    sync_jobs::record_failure(
                        &mut tx, &job.id, attempts, None, &message, true, now,
                    )
                    .await?;
                    Step::GaveUp
                }
            };
            tx.commit().await.map_err(|_| AppError::InternalError)?;
            Ok(outcome)
        }
    }
}

/// Runs steps until `stop` turns true. A job already taken finishes its current step,
/// then the loop exits without taking another job.
pub async fn run<H: JobHandler>(pool: SqlitePool, handler: H, mut stop: watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        match step(&pool, &handler, now_secs()).await {
            Ok(Step::Idle) => {}
            Ok(_) => continue,
            Err(_) => tracing::warn!("job worker step failed; retrying after the idle delay"),
        }
        tokio::select! {
            _ = tokio::time::sleep(IDLE_POLL) => {}
            _ = stop.changed() => return,
        }
    }
}

/// Current Unix time in seconds.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    /// A handler that always fails with the given message.
    struct AlwaysFail;

    impl JobHandler for AlwaysFail {
        async fn run(&self, _job: &ClaimedJob) -> Result<(), String> {
            Err("upstream said no".to_owned())
        }
    }

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("harborgate-worker-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// Inserts a mapping row and one queued job for it. The mapping satisfies the foreign key.
    async fn queued_job(pool: &SqlitePool, job_id: &str) {
        sqlx::query(
            "INSERT OR IGNORE INTO users (id, username, password_hash, role, token_version)
             VALUES ('u1', 'u1', NULL, 'user', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES ('c1', 'u1', 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake'),
                    ('c2', 'u1', 'github', 'g', NULL, NULL, 'v1:fake')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch)
             VALUES ('m1', 'u1', 'c1', 'c2', 'https://harbor.example.com', 'p', 'r', 'o', 'g', 'h1', 'h2', 0, 'CRITICAL', 'main')",
        )
        .execute(pool)
        .await
        .unwrap();
        db::sync_jobs::enqueue(pool, job_id, "m1", "{}", 1_000)
            .await
            .unwrap();
    }

    async fn job_row(pool: &SqlitePool, job_id: &str) -> (String, i64, Option<i64>) {
        sqlx::query_as::<_, (String, i64, Option<i64>)>(
            "SELECT status, attempts, next_attempt_at FROM sync_jobs WHERE id = ?",
        )
        .bind(job_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn failures_follow_the_backoff_then_the_eighth_marks_failed() {
        let (pool, dir) = fresh_pool("backoff").await;
        queued_job(&pool, "j1").await;
        let mut now = 1_000;
        let mut delays = Vec::new();
        for _ in 0..7 {
            match step(&pool, &AlwaysFail, now).await.unwrap() {
                Step::Retry { next_attempt_at } => {
                    delays.push(next_attempt_at - now);
                    now = next_attempt_at;
                }
                other => panic!("expected a retry, got {other:?}"),
            }
        }
        assert_eq!(delays, vec![30, 60, 120, 240, 480, 960, 1920]);
        // The eighth failure gives up and schedules nothing.
        assert_eq!(step(&pool, &AlwaysFail, now).await.unwrap(), Step::GaveUp);
        let (status, attempts, next) = job_row(&pool, "j1").await;
        assert_eq!((status.as_str(), attempts, next), ("failed", 8, None));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_running_job_is_requeued_at_startup_with_attempts_unchanged() {
        let (pool, dir) = fresh_pool("requeue").await;
        queued_job(&pool, "j2").await;
        // Simulate a crash mid-run: the job is claimed and never finished.
        let claimed = db::sync_jobs::claim_next(&pool, 1_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.attempts, 0);
        assert_eq!(job_row(&pool, "j2").await.0, "running");

        let requeued = db::sync_jobs::requeue_running(&pool, 2_000).await.unwrap();
        assert_eq!(requeued, 1);
        let (status, attempts, _) = job_row(&pool, "j2").await;
        assert_eq!((status.as_str(), attempts), ("queued", 0));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_successful_job_is_marked_done() {
        let (pool, dir) = fresh_pool("done").await;
        queued_job(&pool, "j3").await;
        assert_eq!(step(&pool, &NoopHandler, 1_000).await.unwrap(), Step::Done);
        assert_eq!(job_row(&pool, "j3").await.0, "done");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
