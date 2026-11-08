//! The scheduled Harbor scan (#191, `specs/integrations.md`, "Scheduled scan").
//!
//! A mapping may have a schedule: off (the default), daily, or weekly, at a UTC time. Two parts
//! run it:
//!
//! - The scheduler ([`run`], [`tick`]) checks every minute which mappings have a slot due. For
//!   each due slot it queues one scan job (`{"kind":"scan","repo_full_name","trigger":"schedule"}`)
//!   and records the slot, in one `BEGIN IMMEDIATE` transaction, so a slot fires once. Missed
//!   slots (the server was down) fire once, as the latest due slot, never once per missed slot.
//!   It makes no Harbor call.
//! - The scan job ([`run_job`]) runs on the worker. It finds the newest tagged artifact by push
//!   time (the source suggestion rule), skips it when a scan of that digest is already running,
//!   asks Harbor to scan it (`POST .../artifacts/{digest}/scan`, robot permission Scan: Create),
//!   and queues one sync job for the digest and its newest tag with `"trigger":"schedule"`. The
//!   sync job waits for the report with the existing "report not yet" backoff, and on success
//!   records which CVE ids are new against the last stored result for the same digest.
//!
//! Every message in a [`JobOutcome`] is fixed text. No Harbor body, URL, header or credential
//! reaches `sync_jobs.last_error`, the payload, the log or an alert.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tokio::sync::watch;

use crate::auth::crypto::DerivedKey;
use crate::db::mappings::{self as mapping_db, MappingRow};
use crate::db::sync_jobs::{self, ClaimedJob};
use crate::error::AppError;
use crate::services::artifact_removal;
use crate::services::credentials::base_for_join;
use crate::services::harbor_client::{
    SCAN_REQUEST_BODY, artifact_url, newest_tagged_url, parse_artifact_digest,
    parse_artifact_list_dated, scan_url, valid_digest,
};
use crate::services::ids;
use crate::services::poller::harbor_login;
use crate::services::resolve::{body_or_outcome, newest_tags};
use crate::services::scanner_scan;
use crate::services::sync::{Clock, HarborFetch, MSG_DATABASE, MSG_GONE, MSG_INTERNAL};
use crate::worker::{JobOutcome, now_secs};

/// Schedule values (`repo_mappings.scan_schedule`).
pub const SCHEDULE_OFF: &str = "off";
pub const SCHEDULE_DAILY: &str = "daily";
pub const SCHEDULE_WEEKLY: &str = "weekly";
/// The `trigger` of jobs the schedule queues.
pub const TRIGGER_SCHEDULE: &str = "schedule";

/// How often the scheduler looks for due slots.
const TICK: Duration = Duration::from_secs(60);
const DAY: i64 = 86_400;
const WEEK: i64 = 7 * DAY;

/// Fixed notes and messages. The notes are catalog keys `sync.note.noTaggedImage` and
/// `sync.note.scanAlreadyRunning` in the UI.
pub const NOTE_NO_TAGGED_IMAGE: &str = "no tagged image to scan";
pub const NOTE_SCAN_RUNNING: &str = "a scan of this image is already running";
pub const MSG_SCAN_FORBIDDEN: &str =
    "Harbor refused to start the scan; grant the robot account the Scan permission";
const MSG_UNREACHABLE: &str = "Harbor could not be reached";
const MSG_REJECTED: &str = "Harbor rejected the robot account credentials";
const MSG_BAD_NAMES: &str = "the Harbor names are not valid";
const MSG_UNREADABLE: &str = "Harbor returned an artifact list that could not be read";

/// The members of a `scan` payload the job reads. A scan started from the mapping page names one
/// `tag` and has `"trigger":"manual"` (#224, no chosen scanner); a scheduled one has neither.
#[derive(Debug, Default, Deserialize)]
struct ScanPayload {
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    trigger: Option<String>,
}

/// The `trigger` of jobs a user starts from the mapping page.
pub const TRIGGER_MANUAL: &str = "manual";

/// The most recent slot at or before `now` (Unix seconds, UTC) for a schedule, or `None` when
/// the schedule is off or not known. `minute` is the minute of the UTC day (0 to 1439) and
/// `weekday` the ISO weekday (1 Monday to 7 Sunday), read only for `weekly`.
pub fn latest_slot(schedule: &str, minute: i64, weekday: i64, now: i64) -> Option<i64> {
    let offset = minute.clamp(0, 1439) * 60;
    let day = now.div_euclid(DAY);
    match schedule {
        SCHEDULE_DAILY => {
            let today = day * DAY + offset;
            Some(if today <= now { today } else { today - DAY })
        }
        SCHEDULE_WEEKLY => {
            // 1970-01-01 was a Thursday, ISO weekday 4.
            let today_weekday = (day + 3).rem_euclid(7) + 1;
            let back = (today_weekday - weekday.clamp(1, 7)).rem_euclid(7);
            let slot = (day - back) * DAY + offset;
            Some(if slot <= now { slot } else { slot - WEEK })
        }
        _ => None,
    }
}

/// The slot to run now for a mapping, or `None` when nothing is due. A slot is due when it is
/// later than the last slot handled. `scan_last_slot` is set to the save time whenever the
/// schedule changes, so a slot from before the save never fires.
pub fn due_slot(mapping: &MappingRow, now: i64) -> Option<i64> {
    let slot = latest_slot(
        &mapping.scan_schedule,
        mapping.scan_minute,
        mapping.scan_weekday,
        now,
    )?;
    match mapping.scan_last_slot {
        Some(last) if slot <= last => None,
        _ => Some(slot),
    }
}

/// One scheduler pass. Queues a scan job for each mapping with a due slot and no scan job
/// already queued or running. Returns how many were queued. A database error on one mapping is
/// logged with the mapping id only and does not stop the others.
pub async fn tick(pool: &SqlitePool, now: i64) -> Result<u64, AppError> {
    let mappings = mapping_db::list_scheduled(pool).await?;
    let mut queued = 0u64;
    for mapping in &mappings {
        let Some(slot) = due_slot(mapping, now) else {
            continue;
        };
        match queue_slot(pool, mapping, slot, now).await {
            Ok(true) => queued += 1,
            Ok(false) => {}
            Err(_) => {
                tracing::warn!(mapping_id = %mapping.id, "queueing a scheduled scan failed");
            }
        }
    }
    Ok(queued)
}

/// Records `slot` for the mapping and queues one scan job, in one transaction. Returns whether
/// a job was queued. The slot is recorded even when a scan job is still pending, so one slot
/// never queues twice and a pending job is never doubled.
async fn queue_slot(
    pool: &SqlitePool,
    mapping: &MappingRow,
    slot: i64,
    now: i64,
) -> Result<bool, AppError> {
    let id = ids::new_id()?;
    let payload = json!({
        "kind": "scan",
        "repo_full_name": format!("{}/{}", mapping.harbor_project, mapping.harbor_repository),
        "trigger": TRIGGER_SCHEDULE,
    })
    .to_string();
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    if mapping_db::claim_scan_slot(&mut tx, mapping, slot).await? == 0 {
        // The mapping changed or another pass took the slot. Nothing to do.
        let _ = tx.rollback().await;
        return Ok(false);
    }
    let pending = sync_jobs::has_pending_scan_job(&mut tx, &mapping.id).await?;
    if !pending {
        sync_jobs::enqueue_in(&mut tx, &id, &mapping.id, &payload, now).await?;
    }
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(!pending)
}

/// Runs the scheduler every minute until `stop` turns true.
pub async fn run(pool: SqlitePool, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        match tick(&pool, now_secs()).await {
            Ok(0) => {}
            Ok(queued) => tracing::info!(queued, "scheduled scans queued"),
            Err(_) => tracing::warn!("the scan scheduler could not read the mappings"),
        }
    }
}

fn failed(message: &str) -> JobOutcome {
    JobOutcome::Failed(message.to_owned())
}

/// Maps Harbor's answer to the scan request. `202` (and any `2xx`) started the scan: Harbor has
/// already replaced the digest's old report with an empty placeholder before it answers
/// (`src/pkg/scan/vulnerability/vul.go`, `MakePlaceHolder`), so the sync queued next reads an
/// empty report and waits with the "report not yet" backoff, never the previous scan's report.
/// `409` means Harbor already runs a scan of this artifact, so this run is skipped. `404` means
/// the image was deleted. A rate limit defers. A refusal is a failure with fixed text, retried
/// by the existing backoff (`specs/backend.md`): `403` names the Scan permission, `401` the
/// credentials, as on the other Harbor calls.
fn scan_answer(reply: crate::services::harbor_client::HarborReply, now: i64) -> Flow<()> {
    match reply.status {
        200..=299 => Ok(()),
        409 => Err(JobOutcome::DoneWithNote(NOTE_SCAN_RUNNING.to_owned())),
        401 => Err(failed(MSG_REJECTED)),
        403 => Err(failed(MSG_SCAN_FORBIDDEN)),
        429 => body_or_outcome(reply, now).map(|_| ()),
        other => Err(JobOutcome::Failed(format!(
            "Harbor refused to start the scan (status {other})"
        ))),
    }
}

type Flow<T> = Result<T, JobOutcome>;

/// Runs one claimed scan job and returns the outcome for the worker.
pub async fn run_job<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
) -> JobOutcome {
    match scan(pool, key, harbor, clock, job).await {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

async fn scan<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
) -> Flow<JobOutcome> {
    // The mapping, then the Harbor credential scoped by the mapping's user. The Harbor names
    // come from the mapping, never from the payload.
    let mut conn = pool.acquire().await.map_err(|_| failed(MSG_DATABASE))?;
    let mapping = mapping_db::find_by_id(&mut conn, &job.mapping_id)
        .await
        .map_err(|_| failed(MSG_DATABASE))?
        .ok_or_else(|| failed(MSG_GONE))?;
    drop(conn);
    let (username, secret) =
        harbor_login(pool, key, &mapping)
            .await
            .map_err(|error| match error {
                AppError::NotFound => failed(MSG_GONE),
                _ => failed(MSG_INTERNAL),
            })?;
    let base = base_for_join(&mapping.harbor_base_url).map_err(|_| failed(MSG_INTERNAL))?;

    let requested: ScanPayload = serde_json::from_str(&job.payload).unwrap_or_default();
    let trigger = if requested.trigger.as_deref() == Some(TRIGGER_MANUAL) {
        TRIGGER_MANUAL
    } else {
        TRIGGER_SCHEDULE
    };
    let (digest, tag) = match requested.tag.as_deref().filter(|tag| !tag.is_empty()) {
        // A tag the user chose: resolve it to its digest. A `404` is final.
        Some(tag) => {
            let url = artifact_url(
                &base,
                &mapping.harbor_project,
                &mapping.harbor_repository,
                tag,
            )
            .map_err(|_| failed(MSG_BAD_NAMES))?;
            let reply = harbor
                .fetch(&url, &username, &secret, &[])
                .await
                .map_err(|_| failed(MSG_UNREACHABLE))?;
            if reply.status == 404 {
                return Ok(artifact_removal::job_artifact_gone(pool, &mapping, tag, &job.id).await);
            }
            let body = body_or_outcome(reply, clock.now())?;
            let digest = parse_artifact_digest(&body).map_err(|_| failed(MSG_UNREADABLE))?;
            if !valid_digest(&digest) {
                return Err(failed(MSG_UNREADABLE));
            }
            (digest, tag.to_owned())
        }
        // The newest tagged artifact by push time.
        None => {
            let list =
                newest_tagged_url(&base, &mapping.harbor_project, &mapping.harbor_repository)
                    .map_err(|_| failed(MSG_BAD_NAMES))?;
            let reply = harbor
                .fetch(&list, &username, &secret, &[])
                .await
                .map_err(|_| failed(MSG_UNREACHABLE))?;
            let body = body_or_outcome(reply, clock.now())?;
            let artifacts = parse_artifact_list_dated(&body).map_err(|_| failed(MSG_UNREADABLE))?;
            let Some((digest, tags)) = artifacts.into_iter().next() else {
                return Ok(JobOutcome::DoneWithNote(NOTE_NO_TAGGED_IMAGE.to_owned()));
            };
            // The digest goes into a URL path, so it must be `sha256:<64 hex>`.
            if !valid_digest(&digest) {
                return Err(failed(MSG_UNREADABLE));
            }
            let Some(tag) = newest_tags(tags, 1).into_iter().next() else {
                return Ok(JobOutcome::DoneWithNote(NOTE_NO_TAGGED_IMAGE.to_owned()));
            };
            (digest, tag)
        }
    };

    // A scheduled run over several scanners: one `scanner_scan` job per enabled scanner, one at a
    // time per project through the project lock (#224 d5). With one enabled scanner, or when the
    // robot cannot list scanners, the plain scan below runs as in #191.
    if trigger == TRIGGER_SCHEDULE
        && let Some(enabled) = enabled_scanners(pool, harbor, clock, &mapping, &username, &secret)
            .await?
            .filter(|enabled| enabled.len() > 1)
    {
        let jobs = fan_out_payloads(&mapping, &tag, &enabled);
        scanner_scan::queue_scanner_jobs(pool, &mapping, &jobs, Some(&job.id), clock.now())
            .await
            .map_err(|_| failed(MSG_DATABASE))?;
        return Ok(JobOutcome::Done);
    }

    // A scheduled scan of this digest is still waiting for its report: do not start another.
    let mut conn = pool.acquire().await.map_err(|_| failed(MSG_DATABASE))?;
    let running = sync_jobs::has_pending_scheduled_sync(&mut conn, &mapping.id, &digest)
        .await
        .map_err(|_| failed(MSG_DATABASE))?;
    drop(conn);
    if running {
        return Ok(JobOutcome::DoneWithNote(NOTE_SCAN_RUNNING.to_owned()));
    }

    // Start the scan. Harbor answers 409 when its own scan of the digest is still running.
    let url = scan_url(
        &base,
        &mapping.harbor_project,
        &mapping.harbor_repository,
        &digest,
    )
    .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .post_json(&url, &username, &secret, SCAN_REQUEST_BODY, &[])
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    if reply.status == 404 {
        // The image was deleted: remove the tag's data (#249).
        return Ok(artifact_removal::job_artifact_gone(pool, &mapping, &tag, &job.id).await);
    }
    scan_answer(reply, clock.now())?;

    // One sync job for the scanned digest and its newest tag, committed with this job's done
    // mark, so a retry after a crash cannot queue it twice.
    queue_sync(pool, job, &mapping, &digest, &tag, trigger, clock.now()).await?;
    Ok(JobOutcome::Done)
}

/// The UUIDs of the enabled scanners (not `disabled`) of the project, by UUID, after a read that
/// also stores them and drops the reports of a scanner Harbor no longer has. `None` when the robot
/// cannot list scanners.
async fn enabled_scanners<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    mapping: &MappingRow,
    username: &str,
    secret: &[u8],
) -> Flow<Option<Vec<String>>> {
    let listed =
        scanner_scan::refresh_scanners(pool, harbor, clock, mapping, username, secret).await?;
    Ok(listed.map(|scanners| {
        let mut uuids: Vec<String> = scanners
            .into_iter()
            .filter(|scanner| !scanner.disabled)
            .map(|scanner| scanner.uuid)
            .collect();
        uuids.sort();
        uuids.dedup();
        uuids
    }))
}

/// One `(tag, scanner, payload)` per enabled scanner for a scheduled run.
fn fan_out_payloads(
    mapping: &MappingRow,
    tag: &str,
    scanner_uuids: &[String],
) -> Vec<(String, String, String)> {
    scanner_uuids
        .iter()
        .map(|uuid| {
            let payload = json!({
                "kind": "scanner_scan",
                "repo_full_name":
                    format!("{}/{}", mapping.harbor_project, mapping.harbor_repository),
                "tag": tag,
                "scanner_uuid": uuid,
                "trigger": TRIGGER_SCHEDULE,
            })
            .to_string();
            (tag.to_owned(), uuid.clone(), payload)
        })
        .collect()
}

async fn queue_sync(
    pool: &SqlitePool,
    job: &ClaimedJob,
    mapping: &MappingRow,
    digest: &str,
    tag: &str,
    trigger: &str,
    now: i64,
) -> Flow<()> {
    let id = ids::new_id().map_err(|_| failed(MSG_INTERNAL))?;
    let payload = json!({
        "repo_full_name": format!("{}/{}", mapping.harbor_project, mapping.harbor_repository),
        "digest": digest,
        "tag": tag,
        "trigger": trigger,
    })
    .to_string();
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| failed(MSG_DATABASE))?;
    let written: Result<bool, AppError> = async {
        if sync_jobs::finish_running_in(&mut tx, &job.id, now).await? == 0 {
            return Ok(false);
        }
        if !sync_jobs::has_pending_pair(&mut tx, &mapping.id, digest, tag).await? {
            sync_jobs::enqueue_in(&mut tx, &id, &mapping.id, &payload, now).await?;
        }
        Ok(true)
    }
    .await;
    match written {
        Ok(true) => tx.commit().await.map_err(|_| failed(MSG_DATABASE)),
        Ok(false) => {
            let _ = tx.rollback().await;
            Ok(())
        }
        Err(_) => {
            let _ = tx.rollback().await;
            Err(failed(MSG_DATABASE))
        }
    }
}

/// The distinct CVE ids of a Harbor report, sorted.
pub fn report_cve_ids(report: &Value) -> Vec<String> {
    let mut ids: Vec<String> = report
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The ids in `current` that are not in `previous` (a JSON array of ids, the last stored
/// result for the digest). With no previous result every id is new. A previous value that is
/// not a JSON array of strings counts as no previous result.
pub fn new_cve_ids(current: &[String], previous: Option<&str>) -> Vec<String> {
    let before: Vec<String> = previous
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_default();
    current
        .iter()
        .filter(|id| !before.contains(id))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests;
