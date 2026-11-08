//! Removal of the data of a tag Harbor no longer has (`specs/integrations.md`, "Removing deleted
//! artifacts"; #249).
//!
//! Two paths use it: a poll or pull that finds a tracked tag missing from a complete artifact
//! listing, and a sync, resolve or scan job that gets a `404` for the artifact. Removal is per tag.
//! One transaction removes the tag's findings, sync reports, jobs and, when no other tag still
//! holds the digest, the scanner reports, and writes one `artifact.remove` audit row. GitHub
//! issues and uploaded SARIF are never touched. The audit row holds the mapping id, the tag and the
//! count, and no secret.

use std::collections::HashSet;

use serde_json::json;
use sqlx::SqlitePool;

use crate::db::artifact_removal as removal_db;
use crate::db::mappings::{self as mapping_db, MappingRow};
use crate::db::sync_jobs::ClaimedJob;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::resolve::NOTE_ARTIFACT_GONE;
use crate::services::sync::MSG_DATABASE;
use crate::worker::JobOutcome;

/// Removes one tag's data in one transaction and audits it. `current_job` is the running job that
/// found the tag missing, which is deleted with the rest. Returns the rows removed; a tag with
/// nothing stored writes no audit row.
pub async fn remove_tag(
    pool: &SqlitePool,
    mapping: &MappingRow,
    tag: &str,
    current_job: Option<&str>,
) -> Result<u64, AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let removed = removal_db::remove_tag(
        &mut tx,
        &mapping.id,
        &mapping.harbor_repository,
        tag,
        current_job,
    )
    .await?;
    if removed > 0 {
        audit::record(
            &mut tx,
            &Actor::system(),
            "artifact.remove",
            &format!("mapping:{}", mapping.id),
            Some(&json!({ "mapping_id": mapping.id, "tag": tag, "removed": removed })),
        )
        .await?;
    }
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(removed)
}

/// The outcome of a job that got a `404` for its artifact: the tag's data is removed and the job
/// is `done` with no note. The job row itself is deleted, so the worker's done mark changes
/// nothing. A database fault is a failed attempt, so the job retries.
pub async fn job_artifact_gone(
    pool: &SqlitePool,
    mapping: &MappingRow,
    tag: &str,
    job_id: &str,
) -> JobOutcome {
    match remove_tag(pool, mapping, tag, Some(job_id)).await {
        Ok(_) => JobOutcome::Done,
        Err(_) => JobOutcome::Failed(MSG_DATABASE.to_owned()),
    }
}

/// Turns the `404` signal of a sync or scanner-scan job into the removal. Those handlers return
/// `DoneWithNote(NOTE_ARTIFACT_GONE)` where Harbor answers `404` for the artifact, deep inside
/// calls that hold no pool; the dispatcher passes the outcome through here once, after a scan
/// has restored its scanner. Any other outcome is returned unchanged. The job's mapping is read
/// from the database and its tag from the payload, never from Harbor.
pub async fn settle_gone(pool: &SqlitePool, job: &ClaimedJob, outcome: JobOutcome) -> JobOutcome {
    if outcome != JobOutcome::DoneWithNote(NOTE_ARTIFACT_GONE.to_owned()) {
        return outcome;
    }
    let Some(tag) = serde_json::from_str::<serde_json::Value>(&job.payload)
        .ok()
        .and_then(|value| {
            value
                .get("tag")
                .and_then(|tag| tag.as_str().map(str::to_owned))
        })
    else {
        return JobOutcome::Done;
    };
    let mapping = {
        let Ok(mut conn) = pool.acquire().await else {
            return JobOutcome::Failed(MSG_DATABASE.to_owned());
        };
        match mapping_db::find_by_id(&mut conn, &job.mapping_id).await {
            Ok(Some(mapping)) => mapping,
            Ok(None) => return JobOutcome::Done,
            Err(_) => return JobOutcome::Failed(MSG_DATABASE.to_owned()),
        }
    };
    job_artifact_gone(pool, &mapping, &tag, &job.id).await
}

/// Like [`job_artifact_gone`], for a resolve job: it has no tag, so every tag whose newest report
/// points at the gone `digest` is removed. Another tag of the mapping is not touched. The resolve
/// job itself stays and ends `done`.
pub async fn resolve_artifact_gone(
    pool: &SqlitePool,
    mapping: &MappingRow,
    digest: &str,
) -> JobOutcome {
    let tags = {
        let Ok(mut conn) = pool.acquire().await else {
            return JobOutcome::Failed(MSG_DATABASE.to_owned());
        };
        match removal_db::tags_at_digest(&mut conn, &mapping.id, &mapping.harbor_repository, digest)
            .await
        {
            Ok(tags) => tags,
            Err(_) => return JobOutcome::Failed(MSG_DATABASE.to_owned()),
        }
    };
    for tag in &tags {
        if remove_tag(pool, mapping, tag, None).await.is_err() {
            return JobOutcome::Failed(MSG_DATABASE.to_owned());
        }
    }
    JobOutcome::Done
}

/// Removes every tracked tag of the mapping that is not in `listed`, the tags of a complete
/// artifact listing. `started` is the poll's start time: data created at or after it does not
/// make its tag tracked. Returns how many tags were removed.
pub async fn remove_missing_tags(
    pool: &SqlitePool,
    mapping: &MappingRow,
    listed: &HashSet<String>,
    started: i64,
) -> Result<u64, AppError> {
    let tracked = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        removal_db::tracked_tags(&mut conn, &mapping.id, &mapping.harbor_repository, started)
            .await?
    };
    let mut tags_removed = 0u64;
    for tag in tracked.iter().filter(|tag| !listed.contains(*tag)) {
        if remove_tag(pool, mapping, tag, None).await? > 0 {
            tags_removed += 1;
        }
    }
    Ok(tags_removed)
}
