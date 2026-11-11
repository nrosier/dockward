//! SQL for the per-step job log (`job_log_steps`, `job_log_lines`; migration 0004, #308).
//!
//! Lines hold text that has already been redacted by `services::scanner::redact` before it is
//! passed here. This module stores what it is given and never sees a raw line.
//! Times are Unix seconds. The log rows follow their job: `ON DELETE CASCADE` from `jobs`.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// The newest lines kept per step. Older lines of a step are deleted on flush.
pub const KEEP_LINES_PER_STEP: i64 = 500;

/// One step as the log route returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRow {
    pub id: String,
    pub seq: i64,
    pub command: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub timeout_secs: i64,
    pub outcome: String,
    pub exit_code: Option<i64>,
    pub truncated: bool,
}

/// One stored line as the log route returns it. `id` is the paging cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRow {
    pub id: i64,
    pub step_seq: i64,
    pub at: i64,
    pub stream: String,
    pub text: String,
}

/// Writes a step row when the step starts, with outcome `running`.
#[allow(clippy::too_many_arguments)]
pub async fn start_step(
    pool: &SqlitePool,
    id: &str,
    job_id: &str,
    attempt: i64,
    seq: i64,
    command: &str,
    started_at: i64,
    timeout_secs: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO job_log_steps
            (id, job_id, attempt, seq, command, started_at, timeout_secs, outcome)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'running')",
        id,
        job_id,
        attempt,
        seq,
        command,
        started_at,
        timeout_secs
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Records how a step ended. `outcome` is one of the stored outcome texts.
pub async fn finish_step(
    pool: &SqlitePool,
    id: &str,
    outcome: &str,
    exit_code: Option<i64>,
    truncated: bool,
    finished_at: i64,
) -> Result<(), AppError> {
    let truncated = i64::from(truncated);
    sqlx::query!(
        "UPDATE job_log_steps
            SET outcome = ?, exit_code = ?, truncated = ?, finished_at = ?
          WHERE id = ?",
        outcome,
        exit_code,
        truncated,
        finished_at,
        id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// One line to store, already redacted and capped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLine<'a> {
    pub at: i64,
    pub stream: &'a str,
    pub text: &'a str,
}

/// Stores a batch of lines for one step and keeps only the newest [`KEEP_LINES_PER_STEP`] of
/// that step, in one transaction.
pub async fn append_lines(
    conn: &mut SqliteConnection,
    step_id: &str,
    lines: &[NewLine<'_>],
) -> Result<(), AppError> {
    for line in lines {
        sqlx::query!(
            "INSERT INTO job_log_lines (step_id, at, stream, text) VALUES (?, ?, ?, ?)",
            step_id,
            line.at,
            line.stream,
            line.text
        )
        .execute(&mut *conn)
        .await
        .map_err(|_| AppError::InternalError)?;
    }
    sqlx::query!(
        "DELETE FROM job_log_lines
          WHERE step_id = ?
            AND id <= (SELECT id FROM job_log_lines WHERE step_id = ?
                        ORDER BY id DESC LIMIT 1 OFFSET ?)",
        step_id,
        step_id,
        KEEP_LINES_PER_STEP
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// The latest attempt of a job that has any step, or `None` when the job has no log.
pub async fn latest_attempt(pool: &SqlitePool, job_id: &str) -> Result<Option<i64>, AppError> {
    let row = sqlx::query!(
        r#"SELECT MAX(attempt) AS "attempt?: i64" FROM job_log_steps WHERE job_id = ?"#,
        job_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.attempt)
}

/// The steps of one attempt of a job, in order.
pub async fn steps(
    pool: &SqlitePool,
    job_id: &str,
    attempt: i64,
) -> Result<Vec<StepRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", seq AS "seq!: i64", command AS "command!",
                  started_at AS "started_at!: i64", finished_at AS "finished_at?: i64",
                  timeout_secs AS "timeout_secs!: i64", outcome AS "outcome!",
                  exit_code AS "exit_code?: i64", truncated AS "truncated!: i64"
           FROM job_log_steps
           WHERE job_id = ? AND attempt = ?
           ORDER BY seq ASC"#,
        job_id,
        attempt
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| StepRow {
            id: row.id,
            seq: row.seq,
            command: row.command,
            started_at: row.started_at,
            finished_at: row.finished_at,
            timeout_secs: row.timeout_secs,
            outcome: row.outcome,
            exit_code: row.exit_code,
            truncated: row.truncated != 0,
        })
        .collect())
}

/// The lines of one attempt of a job with an id after `after`, oldest first, at most `limit`.
/// `after` is the id of the last line the caller has, or 0 for the first page.
pub async fn lines_after(
    pool: &SqlitePool,
    job_id: &str,
    attempt: i64,
    after: i64,
    limit: i64,
) -> Result<Vec<LineRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT l.id AS "id!", s.seq AS "step_seq!: i64", l.at AS "at!: i64",
                  l.stream AS "stream!", l.text AS "text!"
           FROM job_log_lines l
           JOIN job_log_steps s ON s.id = l.step_id
           WHERE s.job_id = ? AND s.attempt = ? AND l.id > ?
           ORDER BY l.id ASC
           LIMIT ?"#,
        job_id,
        attempt,
        after,
        limit
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| LineRow {
            id: row.id,
            step_seq: row.step_seq,
            at: row.at,
            stream: row.stream,
            text: row.text,
        })
        .collect())
}
