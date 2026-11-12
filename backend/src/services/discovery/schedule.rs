//! The hourly discovery schedule (`specs/spinoff-local-scan.md`, section 5; decision 16).
//!
//! Every hour the scheduler queues one `discover` job per distinct (hub, repository) that has a
//! source. The job covers every source on the repository. The run itself writes the
//! `job_runs` row with kind `discover`.
//!
//! A repository is skipped while its discover job is still `queued` or `running`, so a slow run
//! never piles up jobs. A repository whose latest discover job is `failed` is queued again: one
//! failure does not block it indefinitely. Each queued job still gets the job's own 8 attempts,
//! and the hourly pass queues at most one job per repository per pass, so a repository that
//! keeps failing is retried once an hour and never runs a second retry loop.

use std::time::Duration;

use sqlx::{SqliteConnection, SqlitePool};
use tokio::sync::watch;

use crate::db::discovery as db;
use crate::db::jobs;
use crate::error::AppError;
use crate::services::discovery::DiscoverPayload;
use crate::services::ids;
use crate::worker::now_secs;

/// Time between scheduling passes (decision 16; fixed, not operator-set).
pub const INTERVAL: Duration = Duration::from_secs(3_600);
/// Delay before the first pass after start.
const FIRST_DELAY: Duration = Duration::from_secs(60);

/// Queues a discover job for each repository that is due. Returns how many were queued.
pub async fn schedule_once(pool: &SqlitePool, now: i64) -> Result<usize, AppError> {
    let targets = db::distinct_repositories(pool).await?;
    let mut queued = 0usize;
    for target in targets {
        let payload = DiscoverPayload::new(&target.hub_id, &target.repository, None).to_text()?;
        let mut tx = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| AppError::InternalError)?;
        let latest = db::latest_job_status(&mut tx, &payload).await?;
        if matches!(latest.as_deref(), Some("queued" | "running")) {
            continue;
        }
        let id = ids::new_id()?;
        jobs::enqueue_in(&mut tx, &id, Some(&target.first_source_id), &payload, now).await?;
        tx.commit().await.map_err(|_| AppError::InternalError)?;
        queued += 1;
    }
    Ok(queued)
}

/// Queues a discover job scoped to one source, so its image is discovered (and pulled) now
/// rather than at the next hourly pass (#331). Called inside the source's create or update
/// transaction. A job for the same payload that is `queued` or `running` is not duplicated.
/// Like [`schedule_once`], a `failed` job does not block it. Returns whether a job was queued.
pub async fn queue_source_discovery(
    conn: &mut SqliteConnection,
    source_id: &str,
    hub_id: &str,
    repository: &str,
    now: i64,
) -> Result<bool, AppError> {
    let payload = DiscoverPayload::new(hub_id, repository, Some(source_id)).to_text()?;
    if matches!(
        db::latest_job_status(&mut *conn, &payload)
            .await?
            .as_deref(),
        Some("queued" | "running")
    ) {
        return Ok(false);
    }
    let id = ids::new_id()?;
    jobs::enqueue_in(conn, &id, Some(source_id), &payload, now).await?;
    Ok(true)
}

/// Runs [`schedule_once`] shortly after start and then every hour, until `stop` turns true.
pub async fn run(pool: SqlitePool, mut stop: watch::Receiver<bool>) {
    let mut delay = FIRST_DELAY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        match schedule_once(&pool, now_secs()).await {
            Ok(queued) => tracing::info!(queued, "discovery schedule pass finished"),
            Err(_) => tracing::warn!("discovery schedule pass failed"),
        }
        delay = INTERVAL;
    }
}
