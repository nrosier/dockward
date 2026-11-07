//! The resolve job: one digest, no tag, expanded into sync jobs (#132, `specs/integrations.md`,
//! "Untagged event (resolve job)").
//!
//! Harbor's `SCANNING_COMPLETED` event may carry a digest and no tag. The webhook stores one
//! resolve job and returns, with no Harbor call. This module is the worker side. It reads the
//! digest's tags from Harbor, keeps the newest [`MAX_TAGS_PER_DIGEST`] by tag `push_time`, and
//! queues one sync job per kept tag, all in one `BEGIN IMMEDIATE` transaction together with the
//! resolve job's own `done` mark, so a crash or error leaves no sync jobs and a retry cannot
//! queue twice.
//!
//! Order inside [`run`], with no network before step 4: parse the payload, re-check the digest,
//! load the mapping, load the Harbor credential scoped by the mapping's user, then call Harbor.
//! The Harbor URL is built from the mapping, never from the payload's repository.
//!
//! Every message in a [`JobOutcome`] is fixed text. No Harbor body, URL, header or credential
//! reaches `sync_jobs.last_error`, the payload, the log or the alert.

use std::cmp::Ordering;

use serde_json::Value;
use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::db::mappings as mapping_db;
use crate::db::sync_jobs::{self, ClaimedJob, MAX_DEFERRAL_SECS};
use crate::error::AppError;
use crate::services::acceptance::parse_rfc3339;
use crate::services::credentials::base_for_join;
use crate::services::harbor_client::{
    ArtifactTag, HarborReply, artifact_url, artifacts_list_url, page_has_tagged_parent,
    parse_artifact_tags, valid_digest,
};
use crate::services::harbor_webhook::ScanEvent;
use crate::services::ids;
use crate::services::pickers::valid_image_tag;
use crate::services::poller::{MAX_PAGES, PAGE_SIZE, harbor_login};
use crate::services::sync::{Clock, HarborFetch, MSG_DATABASE, MSG_GONE, MSG_INTERNAL};
use crate::worker::JobOutcome;

/// Most tags kept per digest, newest by tag `push_time`. The poller applies the same cut.
pub const MAX_TAGS_PER_DIGEST: usize = 10;

/// How long a rate-limited resolve job waits when Harbor sends no `Retry-After`: 5 minutes.
pub const DEFAULT_RATE_LIMIT_WAIT_SECS: i64 = 300;

pub const MSG_UNKNOWN_KIND: &str = "the job kind is not known";
const MSG_BAD_PAYLOAD: &str = "the job payload is not valid";
const MSG_BAD_DIGEST: &str = "the digest is not valid";
const MSG_BAD_NAMES: &str = "the Harbor names are not valid";
const MSG_UNREACHABLE: &str = "Harbor could not be reached";
const MSG_REJECTED: &str = "Harbor rejected the robot account credentials";
const MSG_UNREADABLE: &str = "Harbor returned an artifact that could not be read";
const MSG_NO_TAGS: &str = "digest has no tags to sync";
/// The note kept on a child digest that a tagged index covers. Catalog key
/// `sync.note.coveredByParent`.
pub const NOTE_COVERED_BY_PARENT: &str = "covered by parent index";
/// The note kept on a job whose image was deleted from Harbor after the job was queued. Catalog
/// key `sync.note.artifactGone`.
pub const NOTE_ARTIFACT_GONE: &str = "artifact no longer in Harbor";
const MSG_RATE_LIMITED: &str = "Harbor rate limit reached";

/// What kind of work a job's payload describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    /// No `kind`, or `"sync"`: the Harbor-to-GitHub sync.
    Sync,
    /// `"resolve"`: expand a digest into sync jobs.
    Resolve,
    /// `"scan"`: a scheduled scan of the newest tagged image (#191).
    Scan,
    /// Any other `kind`. The job fails for good.
    Unknown,
}

/// Reads `kind` from the payload leniently (not a tagged serde enum, so a payload with extra
/// or missing members still reads). A payload that is not a JSON object has no `kind`, so it is
/// a sync job, and the sync handler reports the bad payload as before.
pub fn job_kind(payload: &str) -> JobKind {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(payload) else {
        return JobKind::Sync;
    };
    match map.get("kind") {
        None => JobKind::Sync,
        Some(Value::String(kind)) if kind == "sync" => JobKind::Sync,
        Some(Value::String(kind)) if kind == "resolve" => JobKind::Resolve,
        Some(Value::String(kind)) if kind == "scan" => JobKind::Scan,
        Some(_) => JobKind::Unknown,
    }
}

/// A tag's sort key: its `push_time` as (Unix seconds, nanoseconds), or `None` when it is
/// missing or not an RFC 3339 time. `None` sorts last.
fn push_key(push_time: Option<&str>) -> Option<(i64, u32)> {
    let text = push_time?;
    let seconds = parse_rfc3339(text)?;
    // `parse_rfc3339` drops the fraction, and Harbor sends milliseconds, so read it here to
    // order tags pushed inside one second.
    let nanos = text
        .as_bytes()
        .get(19..)
        .and_then(|rest| rest.strip_prefix(b"."))
        .map(|rest| {
            let digits: Vec<u8> = rest
                .iter()
                .take_while(|c| c.is_ascii_digit())
                .take(9)
                .copied()
                .collect();
            let value: u32 = std::str::from_utf8(&digits)
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(0);
            value * 10u32.pow(9 - digits.len() as u32)
        })
        .unwrap_or(0);
    Some((seconds, nanos))
}

/// A tag's `push_time` in Unix milliseconds, or `None` when it is missing or not RFC 3339.
/// The sync stores it on the report so the issue lifecycle can find the newest digest.
pub(crate) fn push_millis(push_time: Option<&str>) -> Option<i64> {
    let (seconds, nanos) = push_key(push_time)?;
    seconds
        .checked_mul(1_000)?
        .checked_add(i64::from(nanos / 1_000_000))
}

/// The tags to sync for one digest: names that are valid OCI tags, de-duplicated, ordered by
/// `push_time` newest first (a missing time last, equal times by name ascending), cut to the
/// newest `max`. The resolve job and the poller both use it, so the two paths agree.
pub fn newest_tags(tags: Vec<ArtifactTag>, max: usize) -> Vec<String> {
    let mut keyed: Vec<(Option<(i64, u32)>, String)> = tags
        .into_iter()
        .filter(|tag| valid_image_tag(&tag.name))
        .map(|tag| (push_key(tag.push_time.as_deref()), tag.name))
        .collect();
    keyed.sort_by(|a, b| match b.0.cmp(&a.0) {
        Ordering::Equal => a.1.cmp(&b.1),
        other => other,
    });
    // After the sort the first of a repeated name is its newest, so keeping it is enough.
    let mut seen = std::collections::HashSet::new();
    keyed.retain(|(_, name)| seen.insert(name.clone()));
    keyed.truncate(max);
    keyed.into_iter().map(|(_, name)| name).collect()
}

fn failed(message: &str) -> JobOutcome {
    JobOutcome::Failed(message.to_owned())
}

/// Maps a Harbor answer to the body, or to the job outcome. Same classification as the sync
/// handler's `harbor_body`, plus the rate limit, which defers. The text is fixed.
pub(crate) fn body_or_outcome(reply: HarborReply, now: i64) -> Result<Vec<u8>, JobOutcome> {
    match reply.status {
        200 => Ok(reply.body),
        429 => {
            let wait = match reply.retry_after {
                Some(seconds) => i64::try_from(seconds).unwrap_or(MAX_DEFERRAL_SECS),
                None => DEFAULT_RATE_LIMIT_WAIT_SECS,
            }
            .clamp(0, MAX_DEFERRAL_SECS);
            Err(JobOutcome::Deferred {
                until: now.saturating_add(wait),
                reason: MSG_RATE_LIMITED.to_owned(),
            })
        }
        401 | 403 => Err(failed(MSG_REJECTED)),
        other => Err(JobOutcome::Failed(format!(
            "Harbor returned status {other}"
        ))),
    }
}

/// Pages through the repository's top-level artifacts and reports whether a tagged index lists
/// `digest` as a child. A lookup that fails is an error outcome, never "not covered" and never
/// done.
async fn covered_by_parent<H: HarborFetch, C: Clock>(
    harbor: &H,
    base: &reqwest::Url,
    mapping: &mapping_db::MappingRow,
    username: &str,
    secret: &[u8],
    digest: &str,
    clock: &C,
) -> Result<bool, JobOutcome> {
    for page in 1..=MAX_PAGES {
        let url = artifacts_list_url(
            base,
            &mapping.harbor_project,
            &mapping.harbor_repository,
            page,
            PAGE_SIZE,
        )
        .map_err(|_| failed(MSG_BAD_NAMES))?;
        let reply = harbor
            .fetch(&url, username, secret, &[])
            .await
            .map_err(|_| failed(MSG_UNREACHABLE))?;
        let body = body_or_outcome(reply, clock.now())?;
        if page_has_tagged_parent(&body, digest).map_err(|_| failed(MSG_UNREADABLE))? {
            return Ok(true);
        }
        // A short page is the last one.
        let count = serde_json::from_slice::<Vec<Value>>(&body)
            .map(|items| items.len())
            .unwrap_or(0);
        if count < PAGE_SIZE as usize {
            break;
        }
    }
    Ok(false)
}

/// Runs one claimed resolve job and returns the outcome for the worker.
pub async fn run<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
) -> JobOutcome {
    match resolve(pool, key, harbor, clock, job).await {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

async fn resolve<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
) -> Result<JobOutcome, JobOutcome> {
    // (a) The payload.
    let digest = match serde_json::from_str::<Value>(&job.payload) {
        Ok(value) => value
            .get("digest")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Err(_) => None,
    }
    .ok_or_else(|| JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned()))?;
    // (b) The digest goes into a URL path, so it is checked again here. A stored payload is not
    // trusted: a restore or a hand edit could have put anything in it.
    if !valid_digest(&digest) {
        return Err(JobOutcome::Permanent(MSG_BAD_DIGEST.to_owned()));
    }

    // (c) The mapping.
    let mut conn = pool.acquire().await.map_err(|_| failed(MSG_DATABASE))?;
    let mapping = mapping_db::find_by_id(&mut conn, &job.mapping_id)
        .await
        .map_err(|_| failed(MSG_DATABASE))?
        .ok_or_else(|| failed(MSG_GONE))?;
    drop(conn);

    // (d) The Harbor credential, scoped by the mapping's user.
    let (username, secret) =
        harbor_login(pool, key, &mapping)
            .await
            .map_err(|error| match error {
                AppError::NotFound => failed(MSG_GONE),
                _ => failed(MSG_INTERNAL),
            })?;

    // (e) The artifact URL, from the mapping and never from the payload.
    let base = base_for_join(&mapping.harbor_base_url).map_err(|_| failed(MSG_INTERNAL))?;
    let url = artifact_url(
        &base,
        &mapping.harbor_project,
        &mapping.harbor_repository,
        &digest,
    )
    .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .fetch(&url, &username, &secret, &[])
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    // A 404 on the digest itself means the image was deleted after the job was queued: final.
    if reply.status == 404 {
        return Ok(JobOutcome::DoneWithNote(NOTE_ARTIFACT_GONE.to_owned()));
    }
    let body = body_or_outcome(reply, clock.now())?;

    // (f) to (h) The tags.
    let tags = parse_artifact_tags(&body).map_err(|_| failed(MSG_UNREADABLE))?;
    let kept = newest_tags(tags, MAX_TAGS_PER_DIGEST);
    if kept.is_empty() {
        // A child digest of a tagged index has no tag of its own. The parent's scan event
        // syncs the parent's tags, so this job is done. Any lookup error keeps the retry.
        if covered_by_parent(harbor, &base, &mapping, &username, &secret, &digest, clock).await? {
            return Ok(JobOutcome::DoneWithNote(NOTE_COVERED_BY_PARENT.to_owned()));
        }
        return Err(failed(MSG_NO_TAGS));
    }

    // (i) The fan-out. Ids and payloads are made before the transaction opens, so no work
    // that can fail for a reason other than the database happens while the lock is held.
    let repo_full_name = format!("{}/{}", mapping.harbor_project, mapping.harbor_repository);
    let mut children: Vec<(String, String, String)> = Vec::with_capacity(kept.len());
    for tag in kept {
        let payload = serde_json::to_string(&ScanEvent {
            repo_full_name: repo_full_name.clone(),
            digest: digest.clone(),
            tag: tag.clone(),
        })
        .map_err(|_| failed(MSG_INTERNAL))?;
        children.push((
            ids::new_id().map_err(|_| failed(MSG_INTERNAL))?,
            tag,
            payload,
        ));
    }

    let now = clock.now();
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| failed(MSG_DATABASE))?;
    match fan_out(&mut tx, job, &mapping.id, &digest, &children, now).await {
        Ok(true) => tx.commit().await.map_err(|_| failed(MSG_DATABASE))?,
        // The job is no longer running (finished by an earlier run, re-queued, or its mapping
        // was deleted). Nothing was written. Roll back and report done with no children.
        Ok(false) => {
            let _ = tx.rollback().await;
        }
        Err(_) => {
            // An explicit rollback releases the write lock now, rather than when the pooled
            // connection is next used.
            let _ = tx.rollback().await;
            return Err(failed(MSG_DATABASE));
        }
    }
    Ok(JobOutcome::Done)
}

/// The work inside the transaction. Marks the resolve job `done` first, under a guard on
/// `status = 'running'`. When that changes no row it returns `false` and inserts nothing.
/// Otherwise it inserts a sync job for each tag that has no `queued` or `running` job for the
/// same mapping, digest and tag. A `done`, `failed` or previously synced pair does not block.
async fn fan_out(
    conn: &mut sqlx::SqliteConnection,
    job: &ClaimedJob,
    mapping_id: &str,
    digest: &str,
    children: &[(String, String, String)],
    now: i64,
) -> Result<bool, AppError> {
    if sync_jobs::finish_running_in(conn, &job.id, now).await? == 0 {
        return Ok(false);
    }
    for (id, tag, payload) in children {
        if sync_jobs::has_pending_pair(conn, mapping_id, digest, tag).await? {
            continue;
        }
        sync_jobs::enqueue_in(conn, id, mapping_id, payload, now).await?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
