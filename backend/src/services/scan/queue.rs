//! Queueing scans (`specs/spinoff-local-scan.md`, section 6 step 4, and section 8 for the
//! `db_update` trigger).
//!
//! One `scan` job per (platform image, enabled scanner). The job and its `scan_runs` row are
//! inserted together in one `BEGIN IMMEDIATE` transaction, so a run never exists without a job
//! and a job never without a run. The payload holds ids, the fixed scanner key, and the image
//! (repository, digest, tag) with the trigger, so the Jobs list can show them.
//!
//! Queueing is idempotent per (platform image, trigger, scanner) for `first_pull` and
//! `tag_moved`: a repeated pull job adds nothing the second time. A `db_update` rescan and a
//! `manual` forced scan (#335) are skipped only while the scanner has a queued or running run for
//! the platform, so a platform already scanned is scanned again.

use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, SqlitePool};

use crate::db::scans as db;
use crate::db::scans::PlatformImage;
use crate::error::AppError;
use crate::services::ids;
use crate::services::issue_lifecycle::enabled_scanner_keys;

/// The triggers a scan run records (`scan_runs.trigger`).
pub const TRIGGERS: [&str; 4] = ["first_pull", "tag_moved", "db_update", "manual"];

/// The payload of a `scan` job: ids, the scanner key, and the image it is about (repository,
/// digest, tag) with the trigger. The image fields are what the Jobs list shows. They are
/// `serde(default)` so a job queued before they existed still reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPayload {
    pub kind: String,
    pub run_id: String,
    pub platform_id: String,
    pub scanner: String,
    #[serde(default)]
    pub repo_full_name: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub trigger: Option<String>,
}

impl ScanPayload {
    pub fn new(
        run_id: &str,
        platform_id: &str,
        scanner: &str,
        image: &PlatformImage,
        trigger: &str,
    ) -> Self {
        Self {
            kind: "scan".to_owned(),
            run_id: run_id.to_owned(),
            platform_id: platform_id.to_owned(),
            scanner: scanner.to_owned(),
            repo_full_name: Some(image.repo_full_name.clone()),
            tag: image.tag.clone(),
            digest: Some(image.digest.clone()),
            trigger: Some(trigger.to_owned()),
        }
    }

    pub fn to_text(&self) -> Result<String, AppError> {
        serde_json::to_string(self).map_err(|_| AppError::InternalError)
    }
}

/// Queues one scan per enabled scanner for the platform image `platform_id`, if the image is
/// `stored`. Returns the number of scans queued. A scanner that already has a run for this
/// platform and trigger is skipped. `source_id` links the jobs to the source whose pull stored
/// the image, so the Jobs list and the job-failed alert can name it.
pub async fn queue_scans(
    pool: &SqlitePool,
    platform_id: &str,
    source_id: Option<&str>,
    trigger: &str,
    now: i64,
) -> Result<usize, AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let queued = queue_scans_in(&mut tx, platform_id, source_id, trigger, None, now).await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(queued)
}

/// [`queue_scans`] on a connection the caller holds, so the queueing can join a larger
/// transaction (the database refresh stores the new build time in the same one). `only` limits
/// the queueing to one scanner key; `None` queues every enabled scanner.
pub async fn queue_scans_in(
    conn: &mut SqliteConnection,
    platform_id: &str,
    source_id: Option<&str>,
    trigger: &str,
    only: Option<&str>,
    now: i64,
) -> Result<usize, AppError> {
    let open_only = matches!(trigger, "db_update" | "manual");
    queue_scans_with(conn, platform_id, source_id, trigger, only, open_only, now).await
}

/// Queues a rescan for a tag that moved to a digest already known (#391). The trigger is
/// `tag_moved`, and only a scanner with a queued or running run for the platform is skipped:
/// a digest scanned for another tag, even under `tag_moved`, is scanned again so the moved
/// tag's findings are rebuilt. A digest not yet stored queues nothing (its pull job does it).
pub async fn queue_moved_rescan_in(
    conn: &mut SqliteConnection,
    platform_id: &str,
    source_id: &str,
    now: i64,
) -> Result<usize, AppError> {
    queue_scans_with(
        conn,
        platform_id,
        Some(source_id),
        "tag_moved",
        None,
        true,
        now,
    )
    .await
}

async fn queue_scans_with(
    conn: &mut SqliteConnection,
    platform_id: &str,
    source_id: Option<&str>,
    trigger: &str,
    only: Option<&str>,
    open_only: bool,
    now: i64,
) -> Result<usize, AppError> {
    if !TRIGGERS.contains(&trigger) {
        return Err(AppError::InternalError);
    }
    // Runs whose job was deleted with its source can never start. They would hold their image
    // against eviction for ever, so they are failed here.
    db::fail_orphan_runs(conn, now).await?;
    // An image that is no longer stored (evicted between its pull and this call) has nothing to
    // scan.
    if db::platform_state_in(conn, platform_id).await?.as_deref() != Some("stored") {
        return Ok(0);
    }
    let enabled = enabled_scanner_keys(conn).await?;
    // A first pull or a moved tag is scanned once per platform and trigger. A database rescan
    // happens again after every newer database, and a forced scan whenever the user asks, so
    // both skip only a scanner whose run is still waiting or running.
    let known = if open_only {
        db::scanners_with_open_run(conn, platform_id).await?
    } else {
        db::scanners_with_run(conn, platform_id, trigger).await?
    };
    let mut queued = 0usize;
    let mut image = None;
    for scanner in enabled
        .iter()
        .filter(|key| !known.contains(key) && only.is_none_or(|one| one == key.as_str()))
    {
        if image.is_none() {
            image = db::platform_image_in(conn, platform_id, source_id).await?;
        }
        // The platform was read as stored above, so its row and image exist.
        let Some(image) = image.as_ref() else {
            return Err(AppError::InternalError);
        };
        let job_id = ids::new_id()?;
        let run_id = ids::new_id()?;
        let payload = ScanPayload::new(&run_id, platform_id, scanner, image, trigger).to_text()?;
        crate::db::jobs::enqueue_in(conn, &job_id, source_id, &payload, now).await?;
        db::insert_queued_run(conn, &run_id, platform_id, scanner, trigger, &job_id).await?;
        queued += 1;
    }
    Ok(queued)
}
