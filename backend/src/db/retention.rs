//! SQL for age-based retention (`specs/cve-lifecycle.md`, Retention). Each function
//! deletes the rows of one table whose timestamp is strictly before `cutoff` (Unix
//! seconds) and returns how many rows it deleted. The service picks the cutoffs.
//!
//! `github_issues`, `cve_findings` and `cve_acceptances` are never touched here.

use sqlx::SqliteConnection;

use crate::error::AppError;

/// Deletes `sync_reports` rows synced before `cutoff`.
pub async fn delete_sync_reports(
    conn: &mut SqliteConnection,
    cutoff: i64,
) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM sync_reports WHERE synced_at < ?", cutoff)
        .execute(conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(|_| AppError::InternalError)
}

/// Deletes finished (`done` or `failed`) `sync_jobs` rows last updated before `cutoff`.
/// Rows in `queued` or `running` are never deleted.
pub async fn delete_sync_jobs(conn: &mut SqliteConnection, cutoff: i64) -> Result<u64, AppError> {
    sqlx::query!(
        "DELETE FROM sync_jobs WHERE status IN ('done', 'failed') AND updated_at < ?",
        cutoff
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Deletes `job_runs` rows started before `cutoff`.
pub async fn delete_job_runs(conn: &mut SqliteConnection, cutoff: i64) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM job_runs WHERE started_at < ?", cutoff)
        .execute(conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(|_| AppError::InternalError)
}

/// Deletes `alert_deliveries` rows sent before `cutoff`.
pub async fn delete_alert_deliveries(
    conn: &mut SqliteConnection,
    cutoff: i64,
) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM alert_deliveries WHERE sent_at < ?", cutoff)
        .execute(conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(|_| AppError::InternalError)
}

/// Deletes `audit_log` rows created before `cutoff`.
pub async fn delete_audit_log(conn: &mut SqliteConnection, cutoff: i64) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM audit_log WHERE created_at < ?", cutoff)
        .execute(conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(|_| AppError::InternalError)
}
