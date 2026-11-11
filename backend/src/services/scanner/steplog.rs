//! Stores the step log of a scanner job (#308): one row per step, written when the step starts
//! (`running`) and updated when it ends, and the redacted lines flushed in batches.
//!
//! A failure to store a log never fails the scanner step: it is logged without detail and the
//! step's own result is returned unchanged.

use sqlx::SqlitePool;

use super::process::{StepLine, StepRecord};
use crate::db::job_log::{self, NewLine};
use crate::services::ids;

/// Lines written in one batch. A step's lines are flushed in batches of this size.
pub const FLUSH_BATCH: usize = 100;

/// Where a step's log goes: the job, its attempt, and the step's position in the attempt.
#[derive(Debug, Clone)]
pub struct StepSlot<'a> {
    pub job_id: &'a str,
    pub attempt: i64,
    pub seq: i64,
}

/// Writes the `running` row of a step, before the process starts. Returns the step's id, or
/// `None` when the row could not be written (the step still runs).
pub async fn begin(
    pool: &SqlitePool,
    slot: &StepSlot<'_>,
    command: &str,
    started_at: i64,
    timeout_secs: u64,
) -> Option<String> {
    let id = ids::new_id().ok()?;
    let timeout = i64::try_from(timeout_secs).unwrap_or(i64::MAX);
    match job_log::start_step(
        pool,
        &id,
        slot.job_id,
        slot.attempt,
        slot.seq,
        command,
        started_at,
        timeout,
    )
    .await
    {
        Ok(()) => Some(id),
        Err(_) => {
            tracing::warn!("could not record the start of a scanner step");
            None
        }
    }
}

/// Stores a finished step: its lines in batches, then its outcome. `step_id` is `None` when
/// [`begin`] could not write the start row; the step is then not logged.
pub async fn finish(pool: &SqlitePool, step_id: Option<&str>, record: &StepRecord) {
    let Some(step_id) = step_id else {
        return;
    };
    let mut failed = false;
    for batch in record.lines.chunks(FLUSH_BATCH) {
        if store_batch(pool, step_id, batch).await.is_err() {
            failed = true;
            break;
        }
    }
    let exit = record.exit_code.map(i64::from);
    let finished = job_log::finish_step(
        pool,
        step_id,
        record.outcome.as_str(),
        exit,
        record.truncated,
        record.finished_at,
    )
    .await;
    if failed || finished.is_err() {
        tracing::warn!("could not store the log of a scanner step");
    }
}

/// Stores one batch of lines for `step_id`, through one connection, with the keep-newest cap.
async fn store_batch(
    pool: &SqlitePool,
    step_id: &str,
    batch: &[StepLine],
) -> Result<(), crate::error::AppError> {
    let rows: Vec<NewLine<'_>> = batch
        .iter()
        .map(|line| NewLine {
            at: line.at,
            stream: line.stream.as_str(),
            text: &line.text,
        })
        .collect();
    let mut conn = pool
        .acquire()
        .await
        .map_err(|_| crate::error::AppError::InternalError)?;
    job_log::append_lines(&mut conn, step_id, &rows).await
}
