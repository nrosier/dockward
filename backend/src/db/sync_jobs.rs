//! Queue operations on `sync_jobs` (`specs/backend.md`, Durable job queue).
//! Times are Unix seconds, matching `unixepoch()` in the schema.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// A job the worker can take. `payload` is the validated event, with no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedJob {
    pub id: String,
    pub mapping_id: String,
    pub attempts: i64,
    pub payload: String,
}

/// Adds a queued job for a mapping. `payload` must hold no secrets.
pub async fn enqueue(
    pool: &SqlitePool,
    id: &str,
    mapping_id: &str,
    payload: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO sync_jobs (id, mapping_id, status, attempts, next_attempt_at, payload, created_at, updated_at)
         VALUES (?, ?, 'queued', 0, ?, ?, ?, ?)",
        id,
        mapping_id,
        now,
        payload,
        now,
        now
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Moves a `running` job back to `queued` at startup. Its `attempts` is unchanged.
/// Returns how many jobs were re-queued.
pub async fn requeue_running(pool: &SqlitePool, now: i64) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE sync_jobs SET status = 'queued', next_attempt_at = ?, updated_at = ?
         WHERE status = 'running'",
        now,
        now
    )
    .execute(pool)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Claims the oldest queued job that is due. The row becomes `running` in the same
/// statement, so two workers cannot take the same job. Returns `None` when nothing is due.
pub async fn claim_next(pool: &SqlitePool, now: i64) -> Result<Option<ClaimedJob>, AppError> {
    let row = sqlx::query!(
        r#"UPDATE sync_jobs SET status = 'running', updated_at = ?
           WHERE id = (
               SELECT id FROM sync_jobs
               WHERE status = 'queued' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
               ORDER BY next_attempt_at, created_at
               LIMIT 1
           )
           RETURNING id AS "id!", mapping_id AS "mapping_id!", attempts AS "attempts!: i64", payload AS "payload!""#,
        now,
        now
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| ClaimedJob {
        id: row.id,
        mapping_id: row.mapping_id,
        attempts: row.attempts,
        payload: row.payload,
    }))
}

/// Marks a job `done` after a successful run.
pub async fn mark_done(pool: &SqlitePool, id: &str, now: i64) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE sync_jobs SET status = 'done', last_error = NULL, updated_at = ? WHERE id = ?",
        now,
        id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Records a failed attempt. `attempts` is the new total (the job's previous count plus
/// one). `status` is `queued` with `next_attempt_at` set, or `failed` when `give_up` is set.
pub async fn record_failure(
    conn: &mut SqliteConnection,
    id: &str,
    attempts: i64,
    next_attempt_at: Option<i64>,
    last_error: &str,
    give_up: bool,
    now: i64,
) -> Result<(), AppError> {
    let status = if give_up { "failed" } else { "queued" };
    sqlx::query!(
        "UPDATE sync_jobs SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
         WHERE id = ?",
        status,
        attempts,
        next_attempt_at,
        last_error,
        now,
        id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Resets a `failed` job for another run: `queued`, `attempts` 0, no error, due now.
/// Returns the rows changed. Zero means the job was not `failed`.
pub async fn reset_failed(pool: &SqlitePool, id: &str, now: i64) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE sync_jobs SET status = 'queued', attempts = 0, last_error = NULL, next_attempt_at = ?, updated_at = ?
         WHERE id = ? AND status = 'failed'",
        now,
        now,
        id
    )
    .execute(pool)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// The user who owns the mapping of a job. `None` when the job does not exist.
pub async fn owner_of_job(pool: &SqlitePool, id: &str) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        "SELECT m.user_id AS \"user_id!\" FROM sync_jobs j
         JOIN repo_mappings m ON m.id = j.mapping_id
         WHERE j.id = ?",
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| row.user_id))
}

/// One job row in the `SyncJob` shape of `specs/api.md`. `report` is not joined here, so
/// the route returns it as `null` until the sync reports exist.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SyncJobView {
    pub id: String,
    pub mapping_id: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

/// Reads one job in the `SyncJob` shape.
pub async fn view(pool: &SqlitePool, id: &str) -> Result<Option<SyncJobView>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id AS "id!", mapping_id AS "mapping_id!", status AS "status!",
                  attempts AS "attempts!: i64", next_attempt_at AS "next_attempt_at?: i64",
                  last_error, created_at AS "created_at?: i64", updated_at AS "updated_at?: i64"
           FROM sync_jobs WHERE id = ?"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| SyncJobView {
        id: row.id,
        mapping_id: row.mapping_id,
        status: row.status,
        attempts: row.attempts,
        next_attempt_at: row.next_attempt_at,
        last_error: row.last_error,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }))
}
