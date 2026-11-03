//! Retry policy for the durable job queue (`specs/backend.md`, Durable job queue).
//!
//! After failure number `n` (counted after the failure), the next attempt is at
//! `now + min(30 s x 2^(n-1), 1 hour)`, while `n < 8`. The eighth failure marks the job
//! `failed` and schedules nothing. Manual retry resets the attempt count.

use std::time::Duration;

/// Base delay after the first failure.
pub const BASE_DELAY: Duration = Duration::from_secs(30);
/// Upper bound on any single delay. It is a guard if the attempt limit changes.
pub const MAX_DELAY: Duration = Duration::from_secs(60 * 60);
/// Failures allowed before the job is `failed`.
pub const MAX_ATTEMPTS: i64 = 8;

/// What to do after a failure that made `attempts` total attempts so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterFailure {
    /// Schedule the next attempt this many seconds from now.
    RetryIn(i64),
    /// No attempts left. The job becomes `failed`.
    GiveUp,
}

/// The decision after failure number `attempts` (1-based, counted after the failure).
pub fn after_failure(attempts: i64) -> AfterFailure {
    if attempts >= MAX_ATTEMPTS {
        return AfterFailure::GiveUp;
    }
    // attempts is at least 1 here, so the exponent is never negative.
    let exponent = (attempts - 1).clamp(0, 62) as u32;
    let factor = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let delay = BASE_DELAY
        .as_secs()
        .saturating_mul(factor)
        .min(MAX_DELAY.as_secs());
    AfterFailure::RetryIn(delay as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_double_from_thirty_seconds() {
        let delays: Vec<i64> = (1..MAX_ATTEMPTS)
            .map(|n| match after_failure(n) {
                AfterFailure::RetryIn(secs) => secs,
                AfterFailure::GiveUp => panic!("gave up early at {n}"),
            })
            .collect();
        assert_eq!(delays, vec![30, 60, 120, 240, 480, 960, 1920]);
    }

    #[test]
    fn the_eighth_failure_gives_up() {
        assert_eq!(after_failure(8), AfterFailure::GiveUp);
        assert_eq!(after_failure(9), AfterFailure::GiveUp);
    }

    #[test]
    fn the_one_hour_cap_holds_for_large_attempt_counts() {
        // Not reachable under the 8-attempt limit, but the guard must not overflow.
        assert_eq!(after_failure(40), AfterFailure::GiveUp);
        let capped = (1..=200)
            .filter_map(|n| match after_failure(n) {
                AfterFailure::RetryIn(secs) => Some(secs),
                AfterFailure::GiveUp => None,
            })
            .max()
            .unwrap_or(0);
        assert!(capped <= MAX_DELAY.as_secs() as i64);
    }
}

use sqlx::SqlitePool;

use crate::db::sync_jobs as db;
use crate::error::AppError;

/// Manual retry (`POST /api/v1/sync-jobs/:id/retry`, `specs/api.md`). The mapping owner
/// or an admin may retry. Only a `failed` job can be retried; any other status is `409`.
/// No audit entry is written: `sync_job.retry` is not in the audit vocabulary yet.
pub async fn retry(
    pool: &SqlitePool,
    caller_id: &str,
    caller_is_admin: bool,
    id: &str,
    now: i64,
) -> Result<db::SyncJobView, AppError> {
    let owner = db::owner_of_job(pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !caller_is_admin && owner != caller_id {
        // Another tenant's job is not revealed: it looks the same as a missing one.
        return Err(AppError::NotFound);
    }
    let changed = db::reset_failed(pool, id, now).await?;
    if changed == 0 {
        return Err(AppError::Conflict(
            "only a failed sync job can be retried.".to_owned(),
        ));
    }
    db::view(pool, id).await?.ok_or(AppError::NotFound)
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::db;

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "harborgate-sync-retry-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// One user owning one mapping with one job in the given status.
    async fn job_with_status(pool: &SqlitePool, status: &str) {
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, token_version)
             VALUES ('owner', 'owner', NULL, 'user', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES ('c1', 'owner', 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake'),
                    ('c2', 'owner', 'github', 'g', NULL, NULL, 'v1:fake')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch)
             VALUES ('m1', 'owner', 'c1', 'c2', 'https://harbor.example.com', 'p', 'r', 'o', 'g', 'h1', 'h2', 0, 'CRITICAL', 'main')",
        )
        .execute(pool)
        .await
        .unwrap();
        db::sync_jobs::enqueue(pool, "job-1", "m1", "{}", 1_000)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE sync_jobs SET status = ?, attempts = 8, last_error = 'boom' WHERE id = 'job-1'",
        )
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retry_of_a_non_failed_job_is_a_conflict() {
        let (pool, dir) = fresh_pool("conflict").await;
        job_with_status(&pool, "queued").await;
        let result = retry(&pool, "owner", false, "job-1", 2_000).await;
        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn retry_of_a_failed_job_resets_attempts_and_error() {
        let (pool, dir) = fresh_pool("reset").await;
        job_with_status(&pool, "failed").await;
        let view = retry(&pool, "owner", false, "job-1", 2_000).await.unwrap();
        assert_eq!(view.status, "queued");
        assert_eq!(view.attempts, 0);
        assert_eq!(view.last_error, None);
        assert_eq!(view.next_attempt_at, Some(2_000));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn another_tenant_cannot_retry_and_sees_not_found() {
        let (pool, dir) = fresh_pool("tenant").await;
        job_with_status(&pool, "failed").await;
        let result = retry(&pool, "stranger", false, "job-1", 2_000).await;
        assert!(matches!(result, Err(AppError::NotFound)), "{result:?}");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_admin_may_retry_any_tenants_failed_job() {
        let (pool, dir) = fresh_pool("admin").await;
        job_with_status(&pool, "failed").await;
        let view = retry(&pool, "admin-user", true, "job-1", 2_000)
            .await
            .unwrap();
        assert_eq!(view.status, "queued");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
