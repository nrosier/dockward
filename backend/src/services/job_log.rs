//! The job log route (#308): the latest attempt's steps and redacted lines of one job.
//!
//! Access follows `services::jobs::get`: an admin reads any job, and a user reads only a job
//! whose source they own. A `db_update` job has no owner, so it is admin only. Any other job a
//! caller may not read is `404`, like a missing one, so the id is not revealed.
//!
//! The lines are the redacted text stored by the scanner step recorder. Scan stdout is never
//! among them.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::{self, job_log};
use crate::error::AppError;

/// Lines returned by one page. A caller pages with `after` for the rest.
pub const PAGE_LINES: i64 = 500;

/// The query values of `GET /jobs/:id/log`, already read from the URL.
#[derive(Debug, Default)]
pub struct LogQuery {
    /// The attempt to read. `None` reads the latest attempt.
    pub attempt: Option<i64>,
    /// The id of the last line the caller has. Only later lines are returned.
    pub after: Option<i64>,
}

/// One step of the log.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StepView {
    pub seq: i64,
    pub command: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub timeout_secs: i64,
    pub outcome: String,
    pub exit_code: Option<i64>,
    pub truncated: bool,
}

/// One line of the log. `id` is the paging cursor.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LineView {
    pub id: i64,
    pub seq: i64,
    pub at: String,
    pub stream: String,
    pub text: String,
    /// The scanner of the job (`trivy` or `grype`), on every line. `null` for a job without one.
    pub scanner: Option<String>,
    /// The kind of the job, on every line. `null` when the payload has none.
    pub kind: Option<String>,
}

/// The log of one job, as `GET /jobs/:id/log` returns it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JobLog {
    pub job_id: String,
    pub kind: Option<String>,
    pub scanner: Option<String>,
    pub status: String,
    pub attempt: i64,
    pub steps: Vec<StepView>,
    pub lines: Vec<LineView>,
    /// The id to pass as `after` for the next page, or `null` when this page is empty.
    pub next_after: Option<i64>,
}

/// Reads the log of one job for the caller.
pub async fn get(
    pool: &SqlitePool,
    caller_id: &str,
    caller_is_admin: bool,
    job_id: &str,
    query: &LogQuery,
) -> Result<JobLog, AppError> {
    let job = db::jobs::find(pool, job_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !caller_is_admin && !owns(pool, caller_id, &job.id).await? {
        return Err(AppError::NotFound);
    }
    // A db_update job has no source, so only an admin reaches it (the check above).
    let attempt = match query.attempt {
        Some(attempt) => attempt,
        None => match job_log::latest_attempt(pool, &job.id).await? {
            Some(attempt) => attempt,
            None => {
                return Ok(JobLog {
                    job_id: job.id,
                    kind: job.kind,
                    scanner: job.scanner,
                    status: job.status,
                    attempt: 0,
                    steps: Vec::new(),
                    lines: Vec::new(),
                    next_after: None,
                });
            }
        },
    };
    let steps = job_log::steps(pool, &job.id, attempt).await?;
    let after = query.after.unwrap_or(0);
    let rows = job_log::lines_after(pool, &job.id, attempt, after, PAGE_LINES).await?;
    let next_after = rows.last().map(|row| row.id);
    let steps = steps
        .into_iter()
        .map(|row| {
            Ok(StepView {
                seq: row.seq,
                command: row.command,
                started_at: crate::services::time::rfc3339(row.started_at)?,
                finished_at: row
                    .finished_at
                    .map(crate::services::time::rfc3339)
                    .transpose()?,
                timeout_secs: row.timeout_secs,
                outcome: row.outcome,
                exit_code: row.exit_code,
                truncated: row.truncated,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let (line_scanner, line_kind) = (job.scanner.clone(), job.kind.clone());
    let lines = rows
        .into_iter()
        .map(|row| {
            Ok(LineView {
                id: row.id,
                seq: row.step_seq,
                at: crate::services::time::rfc3339(row.at)?,
                stream: row.stream,
                text: row.text,
                scanner: line_scanner.clone(),
                kind: line_kind.clone(),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(JobLog {
        job_id: job.id,
        kind: job.kind,
        scanner: job.scanner,
        status: job.status,
        attempt,
        steps,
        lines,
        next_after,
    })
}

/// True when `user_id` owns the source of the job.
async fn owns(pool: &SqlitePool, user_id: &str, job_id: &str) -> Result<bool, AppError> {
    Ok(matches!(
        db::jobs::owner_of_job(pool, job_id).await?,
        Some(Some(owner)) if owner == user_id
    ))
}
