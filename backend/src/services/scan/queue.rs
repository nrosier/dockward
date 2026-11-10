//! Queueing scans (`specs/spinoff-local-scan.md`, section 6 step 4, and section 8 for the
//! `db_update` trigger).
//!
//! One `scan` job per (platform image, enabled scanner). The job and its `scan_runs` row are
//! inserted together in one `BEGIN IMMEDIATE` transaction, so a run never exists without a job
//! and a job never without a run. The payload holds ids and the fixed scanner key only.
//!
//! Queueing is idempotent per (platform image, trigger, scanner) for `first_pull` and
//! `tag_moved`: a repeated pull job adds nothing the second time. A `db_update` rescan is skipped
//! only while the scanner has a queued or running run for the platform.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::scans as db;
use crate::error::AppError;
use crate::services::ids;
use crate::services::issue_lifecycle::enabled_scanner_keys;

/// The triggers a scan run records (`scan_runs.trigger`).
pub const TRIGGERS: [&str; 3] = ["first_pull", "tag_moved", "db_update"];

/// The payload of a `scan` job: ids and the scanner key only (section 9). Never a path, a
/// registry string or a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPayload {
    pub kind: String,
    pub run_id: String,
    pub platform_id: String,
    pub scanner: String,
}

impl ScanPayload {
    pub fn new(run_id: &str, platform_id: &str, scanner: &str) -> Self {
        Self {
            kind: "scan".to_owned(),
            run_id: run_id.to_owned(),
            platform_id: platform_id.to_owned(),
            scanner: scanner.to_owned(),
        }
    }

    pub fn to_text(&self) -> Result<String, AppError> {
        serde_json::to_string(self).map_err(|_| AppError::InternalError)
    }
}

/// Queues one scan per enabled scanner for the platform image `platform_id`, if the image is
/// `stored`. Returns the number of scans queued. A scanner that already has a run for this
/// platform and trigger is skipped. `source_id` links the jobs to the source whose pull stored
/// the image, so the Sync jobs list and the sync-failed alert can name it.
pub async fn queue_scans(
    pool: &SqlitePool,
    platform_id: &str,
    source_id: Option<&str>,
    trigger: &str,
    now: i64,
) -> Result<usize, AppError> {
    if !TRIGGERS.contains(&trigger) {
        return Err(AppError::InternalError);
    }
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    // Runs whose job was deleted with its source can never start. They would hold their image
    // against eviction for ever, so they are failed here.
    db::fail_orphan_runs(&mut tx, now).await?;
    // An image that is no longer stored (evicted between its pull and this call) has nothing to
    // scan.
    if db::platform_state_in(&mut tx, platform_id)
        .await?
        .as_deref()
        != Some("stored")
    {
        tx.commit().await.map_err(|_| AppError::InternalError)?;
        return Ok(0);
    }
    let enabled = enabled_scanner_keys(&mut tx).await?;
    // A first pull or a moved tag is scanned once per platform and trigger. A database rescan
    // happens again after every newer database, so it skips only a scanner whose run is still
    // waiting or running.
    let known = if trigger == "db_update" {
        db::scanners_with_open_run(&mut tx, platform_id).await?
    } else {
        db::scanners_with_run(&mut tx, platform_id, trigger).await?
    };
    let mut queued = 0usize;
    for scanner in enabled.iter().filter(|key| !known.contains(key)) {
        let job_id = ids::new_id()?;
        let run_id = ids::new_id()?;
        let payload = ScanPayload::new(&run_id, platform_id, scanner).to_text()?;
        crate::db::sync_jobs::enqueue_in(&mut tx, &job_id, source_id, &payload, now).await?;
        db::insert_queued_run(&mut tx, &run_id, platform_id, scanner, trigger, &job_id).await?;
        queued += 1;
    }
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(queued)
}
