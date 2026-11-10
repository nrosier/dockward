//! The in-process job worker (`specs/backend.md`, Durable job queue).
//!
//! The worker claims one due `sync_jobs` row at a time and passes it to a [`JobHandler`].
//! A success marks the job `done`. A failure is recorded with the backoff from
//! [`crate::services::sync_jobs`]. A deferral puts the job back in `queued` without using
//! an attempt. A panic in a handler fails that job only. The worker stops taking new jobs
//! after the stop signal.
//!
//! The handlers for the spinoff job kinds live in `services::discovery::handler` (discover and
//! the pull stub); the scan and publish kinds arrive with the later steps and fail with
//! [`MSG_UNHANDLED`] until then. Tests that only exercise the queue use [`NoopHandler`], which
//! completes every job.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::sync::watch;

use crate::db::sync_jobs::{self, ClaimedJob};
use crate::error::AppError;
use crate::services::sync_jobs::{AfterFailure, after_failure};

/// How many times a failed write after the handler is retried before the step returns
/// the error. One original write plus this many retries makes 4 writes in total.
const WRITE_RETRIES: u32 = 3;
/// Delay between a failed write and its retry.
const WRITE_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Runs one claimed job. The outcome decides what the worker records. `Failed` and
/// `Deferred` carry text that is stored or logged, so it must not contain secrets.
pub trait JobHandler: Send + Sync + 'static {
    fn run(&self, job: ClaimedJob) -> impl Future<Output = JobOutcome> + Send;

    /// Called once after a job was recorded as `failed` for good (the last attempt failed).
    /// It must return at once: a handler that does slow work spawns it, so the queue is
    /// never delayed. `now` is Unix seconds. The default does nothing.
    fn on_give_up(&self, _job: &ClaimedJob, _now: i64) {}
}

/// What a handler reports for one job. Real handlers arrive with the later steps, so some
/// variants are built by tests only until then.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum JobOutcome {
    /// The job is complete. It becomes `done`.
    Done,
    /// The job is complete, with a fixed note kept in `last_error` (for example
    /// `covered by parent index`). It becomes `done`.
    DoneWithNote(String),
    /// The attempt failed and may succeed later. Its text is stored in `last_error`, and the
    /// job retries with backoff.
    Failed(String),
    /// The failure cannot heal by retrying, for example an image with no revision label. The
    /// job is marked `failed` after this one attempt, with no retries (`specs/integrations.md`).
    Permanent(String),
    /// The job cannot run yet, for example after an upstream rate limit. It goes back to
    /// `queued` at `until` (Unix seconds), capped at one hour, and no attempt is used.
    /// `reason` is logged, not stored.
    Deferred { until: i64, reason: String },
}

/// The fixed text stored when a job kind has no handler yet.
pub const MSG_UNHANDLED: &str = "the job kind has no handler";

/// A test handler that completes every job.
#[cfg(test)]
pub struct NoopHandler;

#[cfg(test)]
impl JobHandler for NoopHandler {
    async fn run(&self, _job: ClaimedJob) -> JobOutcome {
        JobOutcome::Done
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
    /// A job was deferred and is due again at `next_attempt_at` (Unix seconds).
    Deferred { next_attempt_at: i64 },
}

/// Runs `write`, and retries it up to [`WRITE_RETRIES`] times, [`WRITE_RETRY_DELAY`] apart,
/// while it fails. Returns the last result.
async fn with_write_retries<T, F, Fut>(mut write: F) -> Result<T, AppError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let mut result = write().await;
    let mut retries_left = WRITE_RETRIES;
    while result.is_err() && retries_left > 0 {
        retries_left -= 1;
        tokio::time::sleep(WRITE_RETRY_DELAY).await;
        result = write().await;
    }
    result
}

/// Claims at most one due job, runs it in its own task, and records the outcome.
/// A panic in the handler is a failed attempt for that job only.
pub async fn step<H: JobHandler>(
    pool: &SqlitePool,
    handler: &Arc<H>,
    now: i64,
) -> Result<Step, AppError> {
    let Some(job) = sync_jobs::claim_next(pool, now).await? else {
        return Ok(Step::Idle);
    };
    let joined = tokio::spawn({
        let h = handler.clone();
        let job = job.clone();
        async move { h.run(job).await }
    })
    .await;
    let outcome = match joined {
        Ok(outcome) => outcome,
        Err(join_error) if join_error.is_panic() => {
            JobOutcome::Failed("job handler panicked".into())
        }
        // The task was cancelled, so there is no outcome. The job stays `running` and the
        // next loop iteration re-queues it (see `tick`).
        Err(_) => return Err(AppError::InternalError),
    };
    let id = job.id.as_str();
    match outcome {
        JobOutcome::Done => {
            with_write_retries(|| sync_jobs::mark_done(pool, id, now)).await?;
            Ok(Step::Done)
        }
        JobOutcome::DoneWithNote(note) => {
            with_write_retries(|| sync_jobs::mark_done_with_note(pool, id, &note, now)).await?;
            Ok(Step::Done)
        }
        JobOutcome::Failed(message) => {
            let attempts = job.attempts + 1;
            let message = message.as_str();
            match after_failure(attempts) {
                AfterFailure::RetryIn(secs) => {
                    let next = now + secs;
                    with_write_retries(|| {
                        record_failure_tx(pool, id, attempts, Some(next), message, false, now)
                    })
                    .await?;
                    Ok(Step::Retry {
                        next_attempt_at: next,
                    })
                }
                AfterFailure::GiveUp => {
                    with_write_retries(|| {
                        record_failure_tx(pool, id, attempts, None, message, true, now)
                    })
                    .await?;
                    handler.on_give_up(&job, now);
                    Ok(Step::GaveUp)
                }
            }
        }
        JobOutcome::Permanent(message) => {
            // One attempt, no retry: the failure is a property of the input, not of timing.
            let attempts = job.attempts + 1;
            with_write_retries(|| record_failure_tx(pool, id, attempts, None, &message, true, now))
                .await?;
            handler.on_give_up(&job, now);
            Ok(Step::GaveUp)
        }
        JobOutcome::Deferred { until, reason } => {
            tracing::info!(reason = %reason, "sync job deferred");
            let next_attempt_at =
                with_write_retries(|| sync_jobs::defer(pool, id, until, now)).await?;
            Ok(Step::Deferred { next_attempt_at })
        }
    }
}

/// Writes one failed attempt in its own transaction.
async fn record_failure_tx(
    pool: &SqlitePool,
    id: &str,
    attempts: i64,
    next_attempt_at: Option<i64>,
    last_error: &str,
    give_up: bool,
    now: i64,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    sync_jobs::record_failure(
        &mut tx,
        id,
        attempts,
        next_attempt_at,
        last_error,
        give_up,
        now,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)
}

/// One loop iteration: re-queue every `running` job, then run at most one step.
/// Each re-queue counts one attempt, as at startup. No job is in flight when this runs,
/// because `step` awaits its handler before it returns. So a `running` row here was left
/// by a write that failed after the handler (`specs/backend.md`, Durable job queue).
pub async fn tick<H: JobHandler>(
    pool: &SqlitePool,
    handler: &Arc<H>,
    now: i64,
) -> Result<Step, AppError> {
    let requeued = sync_jobs::requeue_running(pool, now).await?;
    if requeued > 0 {
        tracing::warn!(
            requeued,
            "re-queued sync jobs left running by a failed write"
        );
    }
    step(pool, handler, now).await
}

/// Runs steps until `stop` turns true. A job already taken finishes its current step,
/// then the loop exits without taking another job.
pub async fn run<H: JobHandler>(
    pool: SqlitePool,
    handler: Arc<H>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        if *stop.borrow() {
            return;
        }
        match tick(&pool, &handler, now_secs()).await {
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
        async fn run(&self, _job: ClaimedJob) -> JobOutcome {
            JobOutcome::Failed("upstream said no".to_owned())
        }
    }

    /// A handler that always reports a permanent failure, as a missing revision label does.
    struct AlwaysPermanent;

    impl JobHandler for AlwaysPermanent {
        async fn run(&self, _job: ClaimedJob) -> JobOutcome {
            JobOutcome::Permanent(
                "the image has no org.opencontainers.image.revision label.".to_owned(),
            )
        }
    }

    /// A handler that panics for the job `j-panic` and completes every other job.
    struct PanicOnOne;

    impl JobHandler for PanicOnOne {
        async fn run(&self, job: ClaimedJob) -> JobOutcome {
            if job.id == "j-panic" {
                panic!("handler bug");
            }
            JobOutcome::Done
        }
    }

    /// A handler that defers every job until the given Unix time.
    struct DeferUntil(i64);

    impl JobHandler for DeferUntil {
        async fn run(&self, _job: ClaimedJob) -> JobOutcome {
            JobOutcome::Deferred {
                until: self.0,
                reason: "rate limited".to_owned(),
            }
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

    /// Inserts a source row and one queued job for it. The source satisfies the foreign key.
    async fn queued_job(pool: &SqlitePool, job_id: &str) {
        sqlx::query(
            "INSERT OR IGNORE INTO users (id, username, password_hash, role, token_version)
             VALUES ('u1', 'u1', NULL, 'user', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('c2', 'u1', 'g', 'v1:fake')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('m1', 'u1', 'hub-default-ghcr', 'p/r', '*', 'c2', 'o', 'g')",
        )
        .execute(pool)
        .await
        .unwrap();
        db::sync_jobs::enqueue(pool, job_id, Some("m1"), "{}", 1_000)
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

    async fn last_error(pool: &SqlitePool, job_id: &str) -> Option<String> {
        sqlx::query_scalar::<_, Option<String>>("SELECT last_error FROM sync_jobs WHERE id = ?")
            .bind(job_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_permanent_failure_gives_up_after_one_attempt() {
        let (pool, dir) = fresh_pool("permanent").await;
        queued_job(&pool, "j1").await;
        let handler = Arc::new(AlwaysPermanent);
        // One step: the job is recorded as failed with one attempt, and nothing is scheduled.
        assert_eq!(step(&pool, &handler, 1_000).await.unwrap(), Step::GaveUp);
        let (status, attempts, next) = job_row(&pool, "j1").await;
        assert_eq!((status.as_str(), attempts, next), ("failed", 1, None));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn failures_follow_the_backoff_then_the_eighth_marks_failed() {
        let (pool, dir) = fresh_pool("backoff").await;
        queued_job(&pool, "j1").await;
        let handler = Arc::new(AlwaysFail);
        let mut now = 1_000;
        let mut delays = Vec::new();
        for _ in 0..7 {
            match step(&pool, &handler, now).await.unwrap() {
                Step::Retry { next_attempt_at } => {
                    delays.push(next_attempt_at - now);
                    now = next_attempt_at;
                }
                other => panic!("expected a retry, got {other:?}"),
            }
        }
        assert_eq!(delays, vec![30, 60, 120, 240, 480, 960, 1920]);
        // The eighth failure gives up and schedules nothing.
        assert_eq!(step(&pool, &handler, now).await.unwrap(), Step::GaveUp);
        let (status, attempts, next) = job_row(&pool, "j1").await;
        assert_eq!((status.as_str(), attempts, next), ("failed", 8, None));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A handler that always fails and records the jobs it was told were given up.
    struct RecordGiveUp(std::sync::Mutex<Vec<(String, i64)>>);

    impl JobHandler for RecordGiveUp {
        async fn run(&self, _job: ClaimedJob) -> JobOutcome {
            JobOutcome::Failed("upstream said no".to_owned())
        }

        fn on_give_up(&self, job: &ClaimedJob, now: i64) {
            if let Ok(mut seen) = self.0.lock() {
                seen.push((job.id.clone(), now));
            }
        }
    }

    #[tokio::test]
    async fn giving_up_a_job_triggers_a_sync_failed_alert() {
        use crate::services::alerts::{ChannelConfig, Notifier};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (pool, dir) = fresh_pool("give-up-alert").await;
        queued_job(&pool, "j-alert").await;

        // The hook: only the last failure reports a give-up, and the retries report nothing.
        let handler = Arc::new(RecordGiveUp(std::sync::Mutex::default()));
        let mut now = 1_000;
        for _ in 0..7 {
            match step(&pool, &handler, now).await.unwrap() {
                Step::Retry { next_attempt_at } => now = next_attempt_at,
                other => panic!("expected a retry, got {other:?}"),
            }
        }
        assert!(handler.0.lock().unwrap().is_empty(), "a retry gave up");
        assert_eq!(step(&pool, &handler, now).await.unwrap(), Step::GaveUp);
        assert_eq!(
            handler.0.lock().unwrap().clone(),
            vec![("j-alert".to_owned(), now)]
        );

        // The alert: one enabled channel, a recording sender. The notifier sends one
        // `sync_failed` alert keyed `sync_failed:<job id>`, with mapping names and fixed text.
        let key = Arc::new(
            crate::auth::crypto::credentials_key(
                &crate::config::parse_encryption_key(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let actor = crate::services::audit::Actor {
            user_id: None,
            username: "test-admin".to_owned(),
        };
        crate::services::alert_channels::create(
            &pool,
            &key,
            &actor,
            false,
            "webhook",
            true,
            serde_json::json!({"url": "https://hooks.example.test/services/FAKE_URL_TOKEN_1"}),
        )
        .await
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (counter, log) = (calls.clone(), seen.clone());
        let notifier = Notifier::with_sender(pool.clone(), key, move |config, alert| {
            assert!(matches!(config, ChannelConfig::Webhook(_)));
            counter.fetch_add(1, Ordering::SeqCst);
            log.lock().unwrap().push(alert);
            Box::pin(async { Ok(()) })
        });
        notifier.spawn_sync_failed("j-alert", "m1", now);
        for _ in 0..200 {
            if calls.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let alert = seen.lock().unwrap()[0].clone();
        assert_eq!(
            alert.event,
            crate::services::alert_send::AlertEvent::SyncFailed
        );
        assert_eq!(alert.harbor, "ghcr.io/p/r");
        assert_eq!(alert.github, "o/g");
        let key_used: String = sqlx::query_scalar("SELECT dedupe_key FROM alert_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(key_used, "sync_failed:j-alert");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn requeue_at_startup_counts_an_attempt() {
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
        assert_eq!((status.as_str(), attempts), ("queued", 1));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn requeue_of_a_job_at_seven_attempts_marks_it_failed() {
        let (pool, dir) = fresh_pool("requeue-limit").await;
        queued_job(&pool, "j-limit").await;
        // A job already interrupted seven times, and now running again.
        sqlx::query("UPDATE sync_jobs SET status = 'running', attempts = 7 WHERE id = 'j-limit'")
            .execute(&pool)
            .await
            .unwrap();

        let requeued = db::sync_jobs::requeue_running(&pool, 2_000).await.unwrap();
        assert_eq!(requeued, 1);
        let (status, attempts, next) = job_row(&pool, "j-limit").await;
        assert_eq!((status.as_str(), attempts, next), ("failed", 8, None));
        assert_eq!(
            last_error(&pool, "j-limit").await.as_deref(),
            Some("interrupted by restart")
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_job_left_running_is_requeued_on_the_next_loop_iteration() {
        let (pool, dir) = fresh_pool("loop-requeue").await;
        queued_job(&pool, "j-loop").await;
        // A write after an earlier run failed, so the job was left `running`.
        db::sync_jobs::claim_next(&pool, 1_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job_row(&pool, "j-loop").await.0, "running");

        let handler = Arc::new(NoopHandler);
        assert_eq!(tick(&pool, &handler, 2_000).await.unwrap(), Step::Done);
        let (status, attempts, _) = job_row(&pool, "j-loop").await;
        assert_eq!((status.as_str(), attempts), ("done", 1));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_successful_job_is_marked_done() {
        let (pool, dir) = fresh_pool("done").await;
        queued_job(&pool, "j3").await;
        let handler = Arc::new(NoopHandler);
        assert_eq!(step(&pool, &handler, 1_000).await.unwrap(), Step::Done);
        assert_eq!(job_row(&pool, "j3").await.0, "done");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_panicking_handler_fails_that_job_and_the_next_job_runs() {
        let (pool, dir) = fresh_pool("panic").await;
        queued_job(&pool, "j-panic").await;
        // Due one second later, so it is taken after `j-panic`.
        db::sync_jobs::enqueue(&pool, "j-next", Some("m1"), "{}", 1_001)
            .await
            .unwrap();
        let handler = Arc::new(PanicOnOne);

        // The first step takes `j-panic`. The panic fails that job and the step returns.
        assert_eq!(
            step(&pool, &handler, 1_001).await.unwrap(),
            Step::Retry {
                next_attempt_at: 1_001 + 30
            }
        );
        let (status, attempts, _) = job_row(&pool, "j-panic").await;
        assert_eq!((status.as_str(), attempts), ("queued", 1));
        assert_eq!(
            last_error(&pool, "j-panic").await.as_deref(),
            Some("job handler panicked")
        );

        // The next step takes `j-next`, which still runs.
        assert_eq!(step(&pool, &handler, 1_001).await.unwrap(), Step::Done);
        assert_eq!(job_row(&pool, "j-next").await.0, "done");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deferred_job_is_requeued_without_using_an_attempt() {
        let (pool, dir) = fresh_pool("defer").await;
        queued_job(&pool, "j-defer").await;
        sqlx::query("UPDATE sync_jobs SET last_error = 'earlier' WHERE id = 'j-defer'")
            .execute(&pool)
            .await
            .unwrap();
        let handler = Arc::new(DeferUntil(1_600));

        assert_eq!(
            step(&pool, &handler, 1_000).await.unwrap(),
            Step::Deferred {
                next_attempt_at: 1_600
            }
        );
        let (status, attempts, next) = job_row(&pool, "j-defer").await;
        assert_eq!(
            (status.as_str(), attempts, next),
            ("queued", 0, Some(1_600))
        );
        assert_eq!(
            last_error(&pool, "j-defer").await.as_deref(),
            Some("earlier")
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deferral_is_capped_at_one_hour() {
        let (pool, dir) = fresh_pool("defer-cap").await;
        queued_job(&pool, "j-cap").await;
        // The handler asks for ten days. The worker caps it at one hour from now.
        let handler = Arc::new(DeferUntil(1_000 + 10 * 24 * 60 * 60));

        assert_eq!(
            step(&pool, &handler, 1_000).await.unwrap(),
            Step::Deferred {
                next_attempt_at: 1_000 + 3_600
            }
        );
        assert_eq!(job_row(&pool, "j-cap").await.2, Some(1_000 + 3_600));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
