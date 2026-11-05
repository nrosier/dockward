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

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::sync_jobs as db;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::pagination::{Page, Pagination};
use crate::services::time;

/// Sort keys `GET /sync-jobs` accepts. The first is the default (`specs/api.md`, Sync jobs).
const SORTS: &[&str] = &["created_at", "updated_at"];

/// Most jobs in the dashboard's `recent_syncs` (`specs/api.md`, Dashboard).
pub const RECENT_SYNCS: i64 = 10;

/// The `report` of a `SyncJob`: the linked `sync_reports` row (`specs/api.md`, Sync jobs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncReport {
    pub image_tag: String,
    pub image_digest: String,
    pub commit_sha: Option<String>,
    /// The stored JSON text, parsed back into an object.
    pub vulnerability_summary: serde_json::Value,
    pub sarif_status: String,
    pub synced_at: Option<String>,
}

/// The image a job is for, from its payload, so queued jobs show it before a report exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobImage {
    pub repo_full_name: Option<String>,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

/// The `SyncJob` object (`specs/api.md`, Sync jobs). Timestamps are RFC 3339 strings.
/// `last_error` is cut to 500 characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncJob {
    pub id: String,
    pub mapping_id: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// `webhook` or `poll`. A payload with no `trigger` is `webhook`.
    pub trigger: String,
    /// `sync` or `resolve`. A payload with no `kind` is `sync` (#132).
    pub kind: String,
    pub image: JobImage,
    pub report: Option<SyncReport>,
}

/// Turns a stored job row into the API object. The payload and report text are untrusted
/// and only read as JSON values; a summary that is not JSON becomes `null`.
fn to_sync_job(row: db::JobRow) -> Result<SyncJob, AppError> {
    let report = match row.report {
        None => None,
        Some(report) => Some(SyncReport {
            image_tag: report.image_tag,
            image_digest: report.image_digest,
            commit_sha: report.commit_sha,
            vulnerability_summary: serde_json::from_str(&report.vulnerability_summary)
                .unwrap_or(serde_json::Value::Null),
            sarif_status: report.sarif_status,
            synced_at: report.synced_at.map(time::rfc3339).transpose()?,
        }),
    };
    Ok(SyncJob {
        id: row.id,
        mapping_id: row.mapping_id,
        status: row.status,
        attempts: row.attempts,
        next_attempt_at: row.next_attempt_at.map(time::rfc3339).transpose()?,
        last_error: row.last_error,
        created_at: row.created_at.map(time::rfc3339).transpose()?,
        updated_at: row.updated_at.map(time::rfc3339).transpose()?,
        trigger: row.trigger.unwrap_or_else(|| "webhook".to_owned()),
        kind: match row.kind.as_deref() {
            Some("resolve") => "resolve",
            _ => "sync",
        }
        .to_owned(),
        image: JobImage {
            repo_full_name: row.repo_full_name,
            tag: row.tag,
            digest: row.digest,
        },
        report,
    })
}

/// Filters for `GET /sync-jobs`, already parsed by the handler.
#[derive(Debug, Default)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub status: Option<String>,
    pub mapping_id: Option<String>,
    /// `true` lists every user's jobs (admin `scope=all`).
    pub all_users: bool,
}

/// The statuses a `status` filter may name (`sync_jobs.status`).
const STATUSES: &[&str] = &["queued", "running", "done", "failed"];

/// `GET /sync-jobs`. One user sees only their own mappings' jobs. A `mapping_id` that is
/// not theirs gives an empty page, not `404` (`specs/api.md`; decided on #55).
pub async fn list(
    pool: &SqlitePool,
    caller_id: &str,
    query: &ListQuery,
) -> Result<Page<SyncJob>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        SORTS,
    )?;
    if let Some(status) = query.status.as_deref()
        && !STATUSES.contains(&status)
    {
        return Err(AppError::InvalidRequest(
            "status is not a sync job status.".to_owned(),
        ));
    }
    let scope = if query.all_users {
        None
    } else {
        Some(caller_id)
    };
    let filter = db::JobFilter {
        user_id: scope,
        id: None,
        status: query.status.as_deref(),
        mapping_id: query.mapping_id.as_deref(),
        sort: &paging.sort,
        sort_sign: if paging.ascending { 1 } else { -1 },
        limit: paging.page_size,
        offset: paging.offset(),
    };
    let rows = db::list_jobs(pool, &filter).await?;
    let total = db::count_jobs(
        pool,
        scope,
        query.status.as_deref(),
        query.mapping_id.as_deref(),
    )
    .await?;
    let items = rows
        .into_iter()
        .map(to_sync_job)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

/// `GET /sync-jobs/:id`. An admin reads any tenant's job; a user reads only their own.
/// Another tenant's job, like a missing one, is `404`.
pub async fn get(
    pool: &SqlitePool,
    caller_id: &str,
    caller_is_admin: bool,
    id: &str,
) -> Result<SyncJob, AppError> {
    let row = db::find(pool, id).await?.ok_or(AppError::NotFound)?;
    if !caller_is_admin && !owns_job(pool, caller_id, &row.id).await? {
        return Err(AppError::NotFound);
    }
    to_sync_job(row)
}

/// True when `user_id` owns the mapping of the job. Used before a tenant read.
async fn owns_job(pool: &SqlitePool, user_id: &str, job_id: &str) -> Result<bool, AppError> {
    Ok(db::owner_of_job(pool, job_id).await?.as_deref() == Some(user_id))
}

/// The dashboard's `recent_syncs`: the 10 jobs with the newest `updated_at`, for the same
/// scope as the counts. Admins with `all_users` see every tenant's jobs.
pub async fn recent(pool: &SqlitePool, user_id: Option<&str>) -> Result<Vec<SyncJob>, AppError> {
    let filter = db::JobFilter {
        user_id,
        id: None,
        status: None,
        mapping_id: None,
        sort: "updated_at",
        sort_sign: -1,
        limit: RECENT_SYNCS,
        offset: 0,
    };
    db::list_jobs(pool, &filter)
        .await?
        .into_iter()
        .map(to_sync_job)
        .collect()
}

/// The `last_sync` of a mapping list item: the status and `updated_at` of the mapping's most
/// recently updated job (`specs/api.md`, Mappings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastSync {
    pub status: String,
    pub updated_at: Option<String>,
}

/// The mapping's most recently updated job as `last_sync`, or `None` when it has no job.
pub async fn last_sync(pool: &SqlitePool, mapping_id: &str) -> Result<Option<LastSync>, AppError> {
    match db::latest_for_mapping(pool, mapping_id).await? {
        None => Ok(None),
        Some((status, updated_at)) => Ok(Some(LastSync {
            status,
            updated_at: updated_at.map(time::rfc3339).transpose()?,
        })),
    }
}

/// Manual retry (`POST /api/v1/sync-jobs/:id/retry`, `specs/api.md`). The mapping owner
/// or an admin may retry. Only a `failed` job can be retried; any other status is `409`.
/// The reset and the `sync_job.retry` audit row commit in one transaction.
pub async fn retry(
    pool: &SqlitePool,
    actor: &Actor,
    caller_is_admin: bool,
    id: &str,
    now: i64,
) -> Result<SyncJob, AppError> {
    let caller_id = actor.user_id.as_deref().unwrap_or_default();
    let owner = db::owner_of_job(pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !caller_is_admin && owner != caller_id {
        // Another tenant's job is not revealed: it looks the same as a missing one.
        return Err(AppError::NotFound);
    }
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let changed = db::reset_failed(&mut tx, id, now).await?;
    if changed == 0 {
        // Dropping the transaction rolls it back.
        return Err(AppError::Conflict(
            "only a failed sync job can be retried.".to_owned(),
        ));
    }
    // The response is read in the same transaction, before the commit, so a read that
    // fails rolls the retry back instead of leaving a 500 after a retry that happened.
    let row = db::find_in(&mut tx, id).await?.ok_or(AppError::NotFound)?;
    let mapping_id = row.mapping_id.clone();
    let job = to_sync_job(row)?;
    audit::record(
        &mut tx,
        actor,
        "sync_job.retry",
        &format!("sync_job:{id}"),
        Some(&serde_json::json!({ "job_id": id, "mapping_id": mapping_id })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(job)
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::db;

    /// An actor with a user id, as the API handler builds it from the session.
    fn actor_of(id: &str) -> Actor {
        Actor {
            user_id: Some(id.to_owned()),
            username: id.to_owned(),
        }
    }

    fn owner_actor() -> Actor {
        actor_of("owner")
    }

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
        let result = retry(&pool, &owner_actor(), false, "job-1", 2_000).await;
        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn retry_of_a_failed_job_resets_attempts_and_error() {
        let (pool, dir) = fresh_pool("reset").await;
        job_with_status(&pool, "failed").await;
        let view = retry(&pool, &owner_actor(), false, "job-1", 2_000)
            .await
            .unwrap();
        assert_eq!(view.status, "queued");
        assert_eq!(view.attempts, 0);
        assert_eq!(view.last_error, None);
        assert_eq!(
            view.next_attempt_at.as_deref(),
            Some("1970-01-01T00:33:20Z")
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn another_tenant_cannot_retry_and_sees_not_found() {
        let (pool, dir) = fresh_pool("tenant").await;
        job_with_status(&pool, "failed").await;
        let result = retry(&pool, &actor_of("stranger"), false, "job-1", 2_000).await;
        assert!(matches!(result, Err(AppError::NotFound)), "{result:?}");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_admin_may_retry_any_tenants_failed_job() {
        let (pool, dir) = fresh_pool("admin").await;
        job_with_status(&pool, "failed").await;
        // The audit row's actor is a foreign key, so the admin must exist.
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, token_version)
             VALUES ('admin-user', 'admin-user', NULL, 'admin', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let view = retry(&pool, &actor_of("admin-user"), true, "job-1", 2_000)
            .await
            .unwrap();
        assert_eq!(view.status, "queued");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn retry_writes_a_sync_job_retry_audit_row() {
        let (pool, dir) = fresh_pool("audit").await;
        job_with_status(&pool, "failed").await;
        retry(&pool, &owner_actor(), false, "job-1", 2_000)
            .await
            .unwrap();
        let row = sqlx::query_as::<_, (Option<String>, String, String, Option<String>)>(
            "SELECT actor_user_id, actor_username, target, details FROM audit_log
             WHERE action = 'sync_job.retry'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let (actor_user_id, actor_username, target, details) = row;
        assert_eq!(actor_user_id.as_deref(), Some("owner"));
        assert_eq!(actor_username, "owner");
        assert_eq!(target, "sync_job:job-1");
        let details: serde_json::Value = serde_json::from_str(details.as_deref().unwrap()).unwrap();
        assert_eq!(
            details,
            serde_json::json!({ "job_id": "job-1", "mapping_id": "m1" })
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
