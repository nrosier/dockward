//! SQL for the `job_runs` table (`specs/database.md`). One row per housekeeping run
//! (`cleanup`, `retention`, `poll`). Rows hold counts and error text only, never secrets.

use sqlx::SqlitePool;

use crate::error::AppError;

/// One finished run. `error_summary` is `None` when `status` is `done`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRun {
    pub id: String,
    /// `cleanup`, `retention` or `poll`.
    pub job_kind: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    /// `done` or `failed`.
    pub status: String,
    pub processed_count: i64,
    pub error_summary: Option<String>,
}

/// Stores one run.
pub async fn insert(pool: &SqlitePool, run: &JobRun) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO job_runs
            (id, job_kind, started_at, finished_at, status, processed_count, error_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        run.id,
        run.job_kind,
        run.started_at,
        run.finished_at,
        run.status,
        run.processed_count,
        run.error_summary
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}
