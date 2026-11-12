//! Manual pull and forced scan of one tag of a source (#335). The routes act on the image the tag
//! points at now (`db::scans::current_tag_image`); the frontend sends the image's first tag
//! (decision Q-A).
//!
//! - Pull: one `pull` job with trigger `manual` per platform of the image. An `evicted` platform
//!   goes back to `queued` first. A platform that is `pulling` or `evicting` refuses the whole
//!   request with `409`. A platform whose pull job is still queued or running is skipped. A
//!   stored platform is downloaded again and verified by the job, and only its `pulled_at`
//!   changes (decision Q-B). The pull queues no forced scan: the job maps `manual` to
//!   `first_pull`, so an image already scanned is not scanned again.
//! - Scan: one `manual` scan run per stored platform and enabled scanner, through
//!   [`queue_scans_in`]. It runs again for a digest already scanned, and queues nothing for a
//!   scanner whose run is still queued or running.
//!
//! Each action is one `BEGIN IMMEDIATE` transaction with its audit row. The audit details hold
//! the source id, the tag and the count, never a digest, path or registry string.

use sqlx::SqlitePool;

use crate::db::scans::{self as scans_db, TagImage};
use crate::db::storage as storage_db;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::discovery::PullPayload;
use crate::services::ids;
use crate::services::scan::queue::queue_scans_in;
use crate::services::storage::job::MANUAL_TRIGGER;

/// The two actions, with their limiter word and audit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagAction {
    Pull,
    Scan,
}

impl TagAction {
    /// The word in the limiter key `tag:{action}:{source}:{tag}`.
    pub fn key(self) -> &'static str {
        match self {
            TagAction::Pull => "pull",
            TagAction::Scan => "scan",
        }
    }

    fn audit_action(self) -> &'static str {
        match self {
            TagAction::Pull => "source.tag_pull",
            TagAction::Scan => "source.tag_scan",
        }
    }
}

const BUSY: &str = "The image is being pulled or evicted. Try again when it has finished.";

/// Runs `action` for `tag` of `source_id` and returns the number of jobs queued. `NotFound` when
/// the source no longer observes the tag.
pub async fn run(
    pool: &SqlitePool,
    actor: &Actor,
    source_id: &str,
    tag: &str,
    action: TagAction,
    now: i64,
) -> Result<usize, AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    // Read again inside the transaction, so the rows acted on are the ones locked.
    let image = scans_db::current_tag_image(&mut tx, source_id, tag)
        .await?
        .ok_or(AppError::NotFound)?;
    let queued = match action {
        TagAction::Pull => queue_pulls(&mut tx, source_id, tag, &image, now).await?,
        TagAction::Scan => {
            let mut queued = 0usize;
            for platform in &image.platforms {
                queued +=
                    queue_scans_in(&mut tx, &platform.id, Some(source_id), "manual", None, now)
                        .await?;
            }
            queued
        }
    };
    audit::record(
        &mut tx,
        actor,
        action.audit_action(),
        &format!("source:{source_id}"),
        Some(&serde_json::json!({ "source_id": source_id, "tag": tag, "queued": queued })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(queued)
}

/// Refuses a pull while a platform of the image is `pulling` or `evicting` (`409`). The route
/// calls it before the limiter, so a refused request uses no slot, and the action calls it again
/// inside its transaction.
pub fn check_pullable(image: &TagImage) -> Result<(), AppError> {
    if image
        .platforms
        .iter()
        .any(|p| matches!(p.state.as_str(), "pulling" | "evicting"))
    {
        return Err(AppError::Conflict(BUSY.to_owned()));
    }
    Ok(())
}

async fn queue_pulls(
    conn: &mut sqlx::SqliteConnection,
    source_id: &str,
    tag: &str,
    image: &TagImage,
    now: i64,
) -> Result<usize, AppError> {
    check_pullable(image)?;
    let mut queued = 0usize;
    for platform in &image.platforms {
        if storage_db::has_open_pull_in(conn, &platform.id).await? {
            continue;
        }
        if platform.state == "evicted" {
            storage_db::requeue_evicted_in(conn, &platform.id).await?;
        }
        let payload = PullPayload {
            kind: "pull".to_owned(),
            platform_id: platform.id.clone(),
            digest: platform.platform_digest.clone(),
            trigger: MANUAL_TRIGGER.to_owned(),
            repo_full_name: Some(image.repository.clone()),
            tag: Some(tag.to_owned()),
        };
        let text = serde_json::to_string(&payload).map_err(|_| AppError::InternalError)?;
        let job_id = ids::new_id()?;
        crate::db::jobs::enqueue_in(conn, &job_id, Some(source_id), &text, now).await?;
        queued += 1;
    }
    Ok(queued)
}
