//! A scan with one chosen Harbor scanner, and the switch that makes it possible (#224,
//! `specs/integrations.md`, "Scanner reports and scan launch", and `specs/backend.md`,
//! "Per-project scanner lock").
//!
//! Harbor's scan and report calls use only the project's current scanner, so a chosen scanner is
//! made the project's scanner for the length of the scan (design A, #224 d11). One `scanner_scan`
//! job runs these steps:
//!
//! 1. Resolve the tag to its digest.
//! 2. Take the project lock (one scan per Harbor project at a time). A held lock defers the job.
//! 3. Read the project scanner, record it once as the previous scanner, and switch to the chosen
//!    one, unless it is already set. A scan with no chosen scanner keeps the current one.
//! 4. Check the scan state of the chosen scanner's report. Start a scan when no final report
//!    exists. Wait (a deferral, at most 5 minutes from the first poll) until it is final.
//! 5. Fetch the report while the chosen scanner is the project's, and store it under
//!    (mapping, digest, scanner UUID). A new scan by the same scanner replaces its report.
//! 6. Restore the previous scanner. The restore always runs once the scan steps have ended. It is
//!    skipped only while the job defers to wait for the report. A failed restore is not hidden:
//!    the job queues a `scanner_restore` job and hands it the lock, which stays held until a
//!    restore succeeds.
//!
//! Every message is fixed text. No Harbor body, URL, header, token or scanner `url` reaches a job
//! row, a log or an alert.

use serde::Deserialize;
use serde_json::json;
use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::db::mappings::{self as mapping_db, MappingRow};
use crate::db::scanner_reports::{self as scanner_db, NewProjectLock, ProjectScannerLockRow};
use crate::db::sync_jobs::{self, ClaimedJob};
use crate::error::AppError;
use crate::services::credentials::base_for_join;
use crate::services::harbor_client::{
    HarborReply, PROJECT_NAME_HEADER, ReportState, SCAN_REQUEST_BODY, SCANNER_MAX_PAGES,
    SCANNER_PAGE_SIZE, ScanStatus, ScannerRegistration, TRIVY_REPORT_MIME, artifact_overview_url,
    artifact_url, overview_status, parse_artifact_digest, parse_report, parse_scanner,
    parse_scanner_list, project_scanner_url, scan_url, scanner_candidates_url, set_scanner_body,
    valid_digest, vulnerabilities_url,
};
use crate::services::ids;
use crate::services::poller::harbor_login;
use crate::services::resolve::{self, body_or_outcome};
use crate::services::scanner_store::{
    self, Candidates, ReadFinding, ReportKey, ScannerSnapshot, report_findings,
};
use crate::services::sync::{Clock, HarborFetch, MSG_DATABASE, MSG_GONE, MSG_INTERNAL};
use crate::worker::{JobOutcome, now_secs};

/// The report wait ceiling: 5 minutes from the first poll (`specs/integrations.md`, step 6).
pub const WAIT_CEILING_SECS: i64 = 5 * 60;
/// Poll deferrals: 5 s, then 10 s, then every 15 s, as the SARIF processing wait does.
const POLL_DELAYS: [i64; 3] = [5, 10, 15];
/// How long a job waits for the project lock to be released (`specs/backend.md`).
pub const LOCK_WAIT_SECS: i64 = 30;

/// Fixed messages (`specs/integrations.md`, "Failure and messages").
pub const MSG_SWITCH_FORBIDDEN: &str =
    "Harbor refused to switch the project scanner; grant the robot account the Scanner permissions";
pub const MSG_SCAN_FORBIDDEN: &str =
    "Harbor refused to start the scan; grant the robot account the Scan permission";
pub const MSG_SCANNER_FAILED: &str = "scanner failed the scan";
pub const MSG_NOT_YET: &str = "Harbor report not available yet";
pub const MSG_RESTORE_FAILED: &str = "Harbor project scanner could not be restored";
pub const MSG_SCANNER_GONE: &str = "scanner no longer in Harbor";
/// Refuses a scanner job with no chosen scanner. Such a job is a plain scan, which this module does
/// not run (it takes no lock, so the path would hold nothing).
pub const MSG_NO_CHOSEN: &str = "the scanner scan has no chosen scanner";
pub const NOTE_PREVIOUS_GONE: &str = "previous scanner no longer in Harbor";
pub const NOTE_CHANGED_ELSEWHERE: &str = "project scanner was changed by someone else";
const MSG_WAITING_LOCK: &str = "waiting for the project lock";
const MSG_WAITING_REPORT: &str = "waiting for the scan report";
const MSG_UNREACHABLE: &str = "Harbor could not be reached";
const MSG_REJECTED: &str = "Harbor rejected the robot account credentials";
const MSG_BAD_NAMES: &str = "the Harbor names are not valid";
const MSG_UNREADABLE: &str = "Harbor returned an artifact that could not be read";
const MSG_PAYLOAD: &str = "the job payload is not valid";
const MSG_RATE_LIMITED: &str = "Harbor rate limit reached";

/// The `scanner_scan` payload (`specs/backend.md`). A missing `scanner_uuid` means the project's
/// current scanner, with no switch.
#[derive(Debug, Deserialize)]
struct Payload {
    tag: String,
    #[serde(default)]
    scanner_uuid: Option<String>,
    #[serde(default)]
    fetch_only: bool,
    /// Who started the scan: `manual`, `schedule` or `webhook`. It goes on to the sync job.
    #[serde(default)]
    trigger: Option<String>,
}

type Flow<T> = Result<T, JobOutcome>;

fn failed(message: &str) -> JobOutcome {
    JobOutcome::Failed(message.to_owned())
}

fn database() -> JobOutcome {
    failed(MSG_DATABASE)
}

fn defer(now: i64, secs: i64, reason: &str) -> JobOutcome {
    JobOutcome::Deferred {
        until: now.saturating_add(secs),
        reason: reason.to_owned(),
    }
}

/// Maps a Harbor answer to the body. `401` is the credentials, `403` is `forbidden`, a rate limit
/// defers, and any other non-2xx answer is `Harbor returned status N` (`specs/integrations.md`).
fn checked_body(reply: HarborReply, now: i64, forbidden: &str) -> Flow<Vec<u8>> {
    match reply.status {
        200..=299 => Ok(reply.body),
        401 => Err(failed(MSG_REJECTED)),
        403 => Err(failed(forbidden)),
        _ => Err(body_or_outcome(reply, now)
            .err()
            .unwrap_or_else(|| failed(MSG_UNREACHABLE))),
    }
}

/// Runs one claimed `scanner_scan` job and returns the outcome for the worker.
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

/// The mapping, its Harbor credential and the Harbor base URL for one job. The Harbor names come
/// from the mapping, never from the payload.
struct Session {
    mapping: MappingRow,
    username: String,
    secret: zeroize::Zeroizing<Vec<u8>>,
    base: reqwest::Url,
}

async fn session(pool: &SqlitePool, key: &DerivedKey, mapping_id: &str) -> Flow<Session> {
    let mut conn = pool.acquire().await.map_err(|_| database())?;
    let mapping = mapping_db::find_by_id(&mut conn, mapping_id)
        .await
        .map_err(|_| database())?
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
    Ok(Session {
        mapping,
        username,
        secret,
        base,
    })
}

/// The result of the scan steps. A wait keeps the switch and defers. Anything else ends the scan,
/// and the restore runs before the job returns.
enum Pass {
    Defer(JobOutcome),
    Finish(JobOutcome),
}

async fn scan<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
) -> Flow<JobOutcome> {
    let payload: Payload = serde_json::from_str(&job.payload).map_err(|_| failed(MSG_PAYLOAD))?;
    // Only a chosen scanner takes the project lock (`specs/backend.md`). A job with none is a plain
    // scan, which this job does not run: refused before any lock or Harbor call.
    let Some(chosen) = payload
        .scanner_uuid
        .as_deref()
        .filter(|uuid| !uuid.is_empty())
    else {
        return Err(JobOutcome::Permanent(MSG_NO_CHOSEN.to_owned()));
    };
    let session = session(pool, key, &job.mapping_id).await?;

    // Step 2: the lock. A held lock defers without using an attempt, and nothing is switched.
    acquire_lock(pool, job, &session, chosen, clock.now()).await?;

    // Steps 1 and 3 to 5 run with the lock held. Every outcome except a wait deferral goes on to the
    // restore, so a failure in any step (even the tag lookup) still puts the scanner back.
    let pass = match scan_steps(pool, harbor, clock, job, &session, &payload, chosen).await {
        Ok(pass) => pass,
        Err(outcome) => Pass::Finish(outcome),
    };
    match pass {
        Pass::Defer(outcome) => Ok(outcome),
        Pass::Finish(outcome) => {
            // A database fault during the restore leaves the lock state unknown, so it wins.
            match restore_after_scan(pool, harbor, clock, job, &session).await {
                Some(failure) => Ok(failure),
                None => Ok(outcome),
            }
        }
    }
}

/// Step 1: resolves a tag to its digest (`GET .../artifacts/{tag}`). A `404` is final.
async fn resolve_tag<H: HarborFetch, C: Clock>(
    harbor: &H,
    clock: &C,
    session: &Session,
    tag: &str,
) -> Flow<String> {
    let mapping = &session.mapping;
    let url = artifact_url(
        &session.base,
        &mapping.harbor_project,
        &mapping.harbor_repository,
        tag,
    )
    .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .fetch(&url, &session.username, &session.secret, &[])
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    if reply.status == 404 {
        return Err(JobOutcome::DoneWithNote(
            resolve::NOTE_ARTIFACT_GONE.to_owned(),
        ));
    }
    let body = checked_body(reply, clock.now(), MSG_SCAN_FORBIDDEN)?;
    let digest = parse_artifact_digest(&body).map_err(|_| failed(MSG_UNREADABLE))?;
    if !valid_digest(&digest) {
        return Err(failed(MSG_UNREADABLE));
    }
    Ok(digest)
}

/// Takes the project lock for this job. A held lock defers the job and nothing is switched.
/// Re-entry by the job that holds the lock (after a deferral or a restart) continues.
async fn acquire_lock(
    pool: &SqlitePool,
    job: &ClaimedJob,
    session: &Session,
    chosen: &str,
    now: i64,
) -> Flow<()> {
    let mapping = &session.mapping;
    let lock = NewProjectLock {
        job_id: &job.id,
        mapping_id: Some(&mapping.id),
        chosen_scanner_uuid: chosen,
        previous_scanner_uuid: None,
        state: "switched",
        acquired_at: now,
    };
    let acquired = scanner_db::try_acquire_project_lock(
        pool,
        &mapping.harbor_base_url,
        &mapping.harbor_project,
        &lock,
    )
    .await
    .map_err(|_| database())?;
    if acquired {
        return Ok(());
    }
    let held =
        scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
            .await
            .map_err(|_| database())?;
    match held {
        Some(row) if row.job_id == job.id => Ok(()),
        _ => Err(defer(now, LOCK_WAIT_SECS, MSG_WAITING_LOCK)),
    }
}

/// Steps 3 and 4 with the lock held, and step 5 when the report is final. Returns `Pass::Defer`
/// while the job waits for the report, and `Pass::Finish` with the outcome of the scan otherwise.
async fn scan_steps<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
    session: &Session,
    payload: &Payload,
    chosen: &str,
) -> Flow<Pass> {
    let mapping = &session.mapping;
    let now = clock.now();
    let row = scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
        .await
        .map_err(|_| database())?
        .filter(|row| row.job_id == job.id)
        .ok_or_else(|| defer(now, LOCK_WAIT_SECS, MSG_WAITING_LOCK))?;

    // Step 1: the digest the tag points at now. A `404` is final and the restore still runs.
    let digest = resolve_tag(harbor, clock, session, &payload.tag).await?;

    // Step 3: the project's scanner. Recorded once, so a restart restores the same scanner.
    let current = read_project_scanner(pool, harbor, clock, session).await?;
    if row.previous_scanner_uuid.is_none() {
        let recorded = scanner_db::set_lock_previous(
            pool,
            &mapping.harbor_base_url,
            &mapping.harbor_project,
            &job.id,
            &current.uuid,
        )
        .await
        .map_err(|_| database())?;
        if !recorded {
            return Err(failed(MSG_INTERNAL));
        }
    }
    if current.uuid != chosen {
        check_chosen_scanner(pool, harbor, clock, session, chosen).await?;
        set_scanner(harbor, clock, session, chosen).await?;
    }

    // Step 4: the state of the chosen scanner's report. Once a wait has started, a scan that was
    // already started is not started again: an unclear state keeps waiting.
    let waiting = row.wait_started_at.is_some();
    let status = artifact_status(harbor, clock, session, &digest).await?;
    match status {
        ScanStatus::Success => {}
        // A fetch-only job never starts a scan, and does not wait (`specs/integrations.md`).
        _ if payload.fetch_only => return Err(failed(MSG_NOT_YET)),
        ScanStatus::InProgress => {}
        ScanStatus::Failed if waiting => return Err(failed(MSG_SCANNER_FAILED)),
        ScanStatus::Other if waiting => {}
        ScanStatus::Failed | ScanStatus::Other => {
            start_scan(harbor, clock, session, &digest).await?;
        }
    }
    if status != ScanStatus::Success {
        return wait_for_report(pool, clock, job, session).await;
    }

    // Step 5: store the report of the chosen scanner.
    fetch_and_store(pool, harbor, clock, session, &digest, chosen, payload).await?;
    Ok(Pass::Finish(JobOutcome::Done))
}

/// The 5-minute wait. The first poll starts the clock; a poll past the ceiling fails.
async fn wait_for_report<C: Clock>(
    pool: &SqlitePool,
    clock: &C,
    job: &ClaimedJob,
    session: &Session,
) -> Flow<Pass> {
    let mapping = &session.mapping;
    let now = clock.now();
    scanner_db::set_lock_wait_started(
        pool,
        &mapping.harbor_base_url,
        &mapping.harbor_project,
        &job.id,
        now,
    )
    .await
    .map_err(|_| database())?;
    let started =
        scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
            .await
            .map_err(|_| database())?
            .and_then(|row| row.wait_started_at)
            .unwrap_or(now);
    let waited = now.saturating_sub(started);
    if waited >= WAIT_CEILING_SECS {
        return Ok(Pass::Finish(failed(MSG_NOT_YET)));
    }
    Ok(Pass::Defer(defer(
        now,
        poll_delay(waited),
        MSG_WAITING_REPORT,
    )))
}

/// The delay before the next poll, from the seconds already waited: 5 s, 10 s, then 15 s.
fn poll_delay(waited: i64) -> i64 {
    let index = match waited {
        w if w < 5 => 0,
        w if w < 15 => 1,
        _ => 2,
    };
    POLL_DELAYS[index]
}

/// Call 1: the project's scanner (`GET .../scanner`), or the system default. Its UUID and name are
/// upserted into `harbor_scanners`. Only these fields are read.
async fn read_project_scanner<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    session: &Session,
) -> Flow<ScannerRegistration> {
    let url = project_scanner_url(&session.base, &session.mapping.harbor_project)
        .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .fetch(
            &url,
            &session.username,
            &session.secret,
            &[PROJECT_NAME_HEADER],
        )
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    let body = checked_body(reply, clock.now(), MSG_SWITCH_FORBIDDEN)?;
    let scanner = parse_scanner(&body).map_err(|_| failed(MSG_UNREADABLE))?;
    upsert_scanners(pool, session, std::slice::from_ref(&scanner), clock.now()).await?;
    Ok(scanner)
}

/// Writes the scanner registrations a successful read returned (`harbor_scanners`, #224 d12).
async fn upsert_scanners(
    pool: &SqlitePool,
    session: &Session,
    scanners: &[ScannerRegistration],
    now: i64,
) -> Flow<()> {
    scanner_store::apply_candidates(
        pool,
        &session.mapping.harbor_base_url,
        &Candidates {
            scanners: scanners.to_vec(),
            complete: false,
        },
        now,
    )
    .await
    .map(|_| ())
    .map_err(|_| database())
}

/// Call 2: every registration the robot can see (`GET .../scanner/candidates`), up to the page cap.
/// It needs Scanner Create (#224 d12). A `403` is the switch refusal, which retries. A complete
/// list also marks the scanners Harbor no longer has as removed (`scanner_store::apply_candidates`).
async fn list_scanners<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    session: &Session,
) -> Flow<Vec<ScannerRegistration>> {
    let Some(candidates) = read_candidates(harbor, clock, session).await? else {
        return Err(failed(MSG_SWITCH_FORBIDDEN));
    };
    scanner_store::apply_candidates(
        pool,
        &session.mapping.harbor_base_url,
        &candidates,
        clock.now(),
    )
    .await
    .map_err(|_| database())?;
    Ok(candidates.scanners)
}

/// Reads every page of call 2. `None` is a `403` (the robot has no Scanner Create). The list is
/// complete when it ended on a short page, so a list cut at the page cap never marks a scanner as
/// removed.
async fn read_candidates<H: HarborFetch, C: Clock>(
    harbor: &H,
    clock: &C,
    session: &Session,
) -> Flow<Option<Candidates>> {
    let mut all = Vec::new();
    let mut complete = false;
    for page in 1..=SCANNER_MAX_PAGES {
        let url = scanner_candidates_url(&session.base, &session.mapping.harbor_project, page)
            .map_err(|_| failed(MSG_BAD_NAMES))?;
        let reply = harbor
            .fetch(
                &url,
                &session.username,
                &session.secret,
                &[PROJECT_NAME_HEADER],
            )
            .await
            .map_err(|_| failed(MSG_UNREACHABLE))?;
        if reply.status == 403 {
            return Ok(None);
        }
        let body = checked_body(reply, clock.now(), MSG_SWITCH_FORBIDDEN)?;
        let scanners = parse_scanner_list(&body).map_err(|_| failed(MSG_UNREADABLE))?;
        let last_page = scanners.len() < SCANNER_PAGE_SIZE as usize;
        all.extend(scanners);
        if last_page {
            complete = true;
            break;
        }
    }
    Ok(Some(Candidates {
        scanners: all,
        complete,
    }))
}

/// A session built from the parts a caller outside this module already holds.
fn borrowed_session(
    mapping: &MappingRow,
    username: &str,
    secret: &[u8],
) -> Result<Session, JobOutcome> {
    Ok(Session {
        mapping: mapping.clone(),
        username: username.to_owned(),
        secret: zeroize::Zeroizing::new(secret.to_vec()),
        base: base_for_join(&mapping.harbor_base_url).map_err(|_| failed(MSG_INTERNAL))?,
    })
}

/// The enabled scanners of the mapping's Harbor project, for a scheduled run and for a webhook
/// name refresh (call 2). The read is stored (`harbor_scanners`), and a complete list marks the
/// scanners Harbor no longer has as removed and drops their reports. `None` is a `403`: the robot
/// cannot list scanners, so the caller keeps the single-scanner behaviour.
pub(crate) async fn refresh_scanners<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    mapping: &MappingRow,
    username: &str,
    secret: &[u8],
) -> Flow<Option<Vec<ScannerRegistration>>> {
    let session = borrowed_session(mapping, username, secret)?;
    let Some(candidates) = read_candidates(harbor, clock, &session).await? else {
        return Ok(None);
    };
    scanner_store::apply_candidates(pool, &mapping.harbor_base_url, &candidates, clock.now())
        .await
        .map_err(|_| database())?;
    Ok(Some(candidates.scanners))
}

/// Call 1 for a caller outside this module: the project's current scanner, stored in
/// `harbor_scanners`. `None` is a `403`: the robot has no Scanner Read (`specs/integrations.md`,
/// "Webhook and poll jobs"), and the report is stored under the unknown scanner.
pub(crate) async fn current_scanner<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    mapping: &MappingRow,
    username: &str,
    secret: &[u8],
) -> Flow<Option<ScannerRegistration>> {
    let session = borrowed_session(mapping, username, secret)?;
    let url = project_scanner_url(&session.base, &mapping.harbor_project)
        .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .fetch(&url, username, secret, &[PROJECT_NAME_HEADER])
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    if reply.status == 403 {
        return Ok(None);
    }
    let body = checked_body(reply, clock.now(), MSG_SWITCH_FORBIDDEN)?;
    let scanner = parse_scanner(&body).map_err(|_| failed(MSG_UNREADABLE))?;
    upsert_scanners(pool, &session, std::slice::from_ref(&scanner), clock.now()).await?;
    Ok(Some(scanner))
}

/// Queues one fetch-only `scanner_scan` job for a scanner matched from a webhook event, unless one
/// for the same (mapping, tag, scanner) is already `queued` or `running` (#224 d10). A fetch-only
/// job never starts a scan (`specs/integrations.md`, "Webhook and poll jobs").
pub(crate) async fn queue_fetch_only(
    pool: &SqlitePool,
    mapping: &MappingRow,
    tag: &str,
    scanner_uuid: &str,
    now: i64,
) -> Result<(), AppError> {
    let payload = json!({
        "kind": "scanner_scan",
        "repo_full_name": format!("{}/{}", mapping.harbor_project, mapping.harbor_repository),
        "tag": tag,
        "scanner_uuid": scanner_uuid,
        "fetch_only": true,
        "trigger": "webhook",
    })
    .to_string();
    queue_scanner_jobs(
        pool,
        mapping,
        &[(tag.to_owned(), scanner_uuid.to_owned(), payload)],
        None,
        now,
    )
    .await
    .map(|_| ())
}

/// Inserts `scanner_scan` jobs (tag, scanner, payload) in one `BEGIN IMMEDIATE` transaction, each
/// deduped by (mapping, tag, scanner) against `queued` and `running` jobs. With `finish` the
/// queuing job is marked `done` in the same transaction, guarded on `status = 'running'`, so a retry
/// after a crash cannot queue twice. Returns `false` when that guard changed no row (nothing was
/// written), else `true`.
pub(crate) async fn queue_scanner_jobs(
    pool: &SqlitePool,
    mapping: &MappingRow,
    jobs: &[(String, String, String)],
    finish: Option<&str>,
    now: i64,
) -> Result<bool, AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let written: Result<bool, AppError> = async {
        if let Some(job_id) = finish
            && sync_jobs::finish_running_in(&mut tx, job_id, now).await? == 0
        {
            return Ok(false);
        }
        for (tag, scanner_uuid, payload) in jobs {
            if sync_jobs::has_pending_scanner_scan(&mut tx, &mapping.id, tag, scanner_uuid).await? {
                continue;
            }
            let id = ids::new_id()?;
            sync_jobs::enqueue_in(&mut tx, &id, &mapping.id, payload, now).await?;
        }
        Ok(true)
    }
    .await;
    match written {
        Ok(true) => {
            tx.commit().await.map_err(|_| AppError::InternalError)?;
            Ok(true)
        }
        Ok(false) => {
            let _ = tx.rollback().await;
            Ok(false)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Before a switch, the chosen scanner must be listed and enabled. A missing or disabled one is
/// final: `scanner no longer in Harbor`, done with that note (`specs/integrations.md`).
async fn check_chosen_scanner<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    session: &Session,
    chosen: &str,
) -> Flow<()> {
    let listed = list_scanners(pool, harbor, clock, session).await?;
    match listed.iter().find(|scanner| scanner.uuid == chosen) {
        Some(scanner) if !scanner.disabled => Ok(()),
        _ => Err(JobOutcome::DoneWithNote(MSG_SCANNER_GONE.to_owned())),
    }
}

/// Call 3: sets the project scanner to `uuid` (`PUT .../scanner`, `{"uuid"}`). A `404` means the
/// scanner is not in Harbor.
async fn set_scanner<H: HarborFetch, C: Clock>(
    harbor: &H,
    clock: &C,
    session: &Session,
    uuid: &str,
) -> Flow<()> {
    let reply = put_scanner(harbor, session, uuid).await?;
    if reply.status == 404 {
        return Err(JobOutcome::DoneWithNote(MSG_SCANNER_GONE.to_owned()));
    }
    checked_body(reply, clock.now(), MSG_SWITCH_FORBIDDEN).map(|_| ())
}

async fn put_scanner<H: HarborFetch>(
    harbor: &H,
    session: &Session,
    uuid: &str,
) -> Flow<HarborReply> {
    let url = project_scanner_url(&session.base, &session.mapping.harbor_project)
        .map_err(|_| failed(MSG_BAD_NAMES))?;
    harbor
        .put_json(
            &url,
            &session.username,
            &session.secret,
            &set_scanner_body(uuid),
            &[PROJECT_NAME_HEADER],
        )
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))
}

/// Call 5: the scan state of the chosen scanner's report, from the artifact overview.
async fn artifact_status<H: HarborFetch, C: Clock>(
    harbor: &H,
    clock: &C,
    session: &Session,
    digest: &str,
) -> Flow<ScanStatus> {
    let mapping = &session.mapping;
    let url = artifact_overview_url(
        &session.base,
        &mapping.harbor_project,
        &mapping.harbor_repository,
        digest,
    )
    .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .fetch(&url, &session.username, &session.secret, &[])
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    if reply.status == 404 {
        return Err(JobOutcome::DoneWithNote(
            resolve::NOTE_ARTIFACT_GONE.to_owned(),
        ));
    }
    let body = checked_body(reply, clock.now(), MSG_SCAN_FORBIDDEN)?;
    overview_status(&body).map_err(|_| failed(MSG_UNREADABLE))
}

/// Call 4: starts the scan (`POST .../artifacts/{digest}/scan`, `scan_type` vulnerability). A `409`
/// means a scan is already running, which is not an error here: the wait is the aim.
async fn start_scan<H: HarborFetch, C: Clock>(
    harbor: &H,
    clock: &C,
    session: &Session,
    digest: &str,
) -> Flow<()> {
    let mapping = &session.mapping;
    let url = scan_url(
        &session.base,
        &mapping.harbor_project,
        &mapping.harbor_repository,
        digest,
    )
    .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .post_json(
            &url,
            &session.username,
            &session.secret,
            SCAN_REQUEST_BODY,
            &[PROJECT_NAME_HEADER],
        )
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    match reply.status {
        409 => Ok(()),
        404 => Err(JobOutcome::DoneWithNote(
            resolve::NOTE_ARTIFACT_GONE.to_owned(),
        )),
        _ => checked_body(reply, clock.now(), MSG_SCAN_FORBIDDEN).map(|_| ()),
    }
}

/// Step 5: reads the chosen scanner's report while it is the project's scanner, and stores it.
async fn fetch_and_store<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    session: &Session,
    digest: &str,
    chosen: &str,
    payload: &Payload,
) -> Flow<()> {
    let mapping = &session.mapping;
    let url = vulnerabilities_url(
        &session.base,
        &mapping.harbor_project,
        &mapping.harbor_repository,
        digest,
    )
    .map_err(|_| failed(MSG_BAD_NAMES))?;
    let reply = harbor
        .fetch(
            &url,
            &session.username,
            &session.secret,
            &[("X-Accept-Vulnerabilities", TRIVY_REPORT_MIME)],
        )
        .await
        .map_err(|_| failed(MSG_UNREACHABLE))?;
    // A `404` on the report is "not ready" and retries (`specs/integrations.md`).
    if reply.status == 404 {
        return Err(failed(MSG_NOT_YET));
    }
    let body = checked_body(reply, clock.now(), MSG_SCAN_FORBIDDEN)?;
    let report = match parse_report(&body).map_err(|_| failed(MSG_UNREADABLE))? {
        ReportState::Ready(report) => report,
        ReportState::NotYet => return Err(failed(MSG_NOT_YET)),
    };
    let snapshot = ScannerSnapshot::from_report(&report, None);
    let findings = report_findings(&report);
    let sync = SyncAfterStore {
        tag: &payload.tag,
        trigger: sync_trigger(payload.trigger.as_deref()),
    };
    store_report(
        pool,
        mapping,
        digest,
        chosen,
        &snapshot,
        &findings,
        &sync,
        clock.now(),
    )
    .await
}

/// The sync job queued with the store (step 8): the tag and the trigger it carries.
struct SyncAfterStore<'a> {
    tag: &'a str,
    trigger: &'a str,
}

/// The trigger of the sync job. Only the known triggers pass; any other value is `manual`, so a
/// payload cannot put free text on a job row.
fn sync_trigger(trigger: Option<&str>) -> &'static str {
    match trigger {
        Some("schedule") => "schedule",
        Some("webhook") => "webhook",
        Some("poll") => "poll",
        _ => "manual",
    }
}

/// Stores the report of (mapping, digest, scanner) in one transaction. A new scan by the same
/// scanner replaces its own report, and no other scanner's report is touched. A chosen scan never
/// replaces the `unknown` report (`specs/integrations.md`, "Webhook and poll jobs").
#[allow(clippy::too_many_arguments)]
async fn store_report(
    pool: &SqlitePool,
    mapping: &MappingRow,
    digest: &str,
    scanner_uuid: &str,
    snapshot: &ScannerSnapshot,
    findings: &[ReadFinding],
    sync: &SyncAfterStore<'_>,
    now: i64,
) -> Flow<()> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| database())?;
    let written: Result<(), AppError> = async {
        scanner_store::write_report(
            &mut tx,
            &ReportKey {
                mapping_id: &mapping.id,
                digest,
                scanner_uuid,
            },
            snapshot,
            findings,
            false,
            now,
        )
        .await?;
        queue_sync_after_store(&mut tx, mapping, digest, scanner_uuid, sync, now).await
    }
    .await;
    match written {
        Ok(()) => tx.commit().await.map_err(|_| database()),
        Err(_) => {
            let _ = tx.rollback().await;
            Err(database())
        }
    }
}

/// Step 8: queues the sync job that uploads the SARIF of the stored reports and runs the issue
/// rules, in the transaction of the store. It is deduped like the resolve job's (no `queued` or
/// `running` job for the same mapping, digest and tag): a job that exists already reads the stored
/// reports when it runs, so it picks this report up.
async fn queue_sync_after_store(
    tx: &mut sqlx::SqliteConnection,
    mapping: &MappingRow,
    digest: &str,
    scanner_uuid: &str,
    sync: &SyncAfterStore<'_>,
    now: i64,
) -> Result<(), AppError> {
    if sync_jobs::has_pending_pair(tx, &mapping.id, digest, sync.tag).await? {
        return Ok(());
    }
    let id = ids::new_id()?;
    let payload = json!({
        "repo_full_name": format!("{}/{}", mapping.harbor_project, mapping.harbor_repository),
        "digest": digest,
        "tag": sync.tag,
        "scanner_uuid": scanner_uuid,
        "trigger": sync.trigger,
    })
    .to_string();
    sync_jobs::enqueue_in(tx, &id, &mapping.id, &payload, now).await
}

/// Step 6, after the scan steps. Returns `None` when the lock was released or handed to a restore
/// job. Returns the outcome to use when a database write fails, because the lock state is unknown.
async fn restore_after_scan<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
    session: &Session,
) -> Option<JobOutcome> {
    let mapping = &session.mapping;
    let row =
        match scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
            .await
        {
            Ok(Some(row)) if row.job_id == job.id => row,
            // Not this job's lock: nothing of ours to put back.
            Ok(_) => return None,
            Err(_) => return Some(database()),
        };
    match restore_target(pool, harbor, clock, session, &row).await {
        RestoreResult::Restored | RestoreResult::Noted(_) => {
            release_lock(pool, mapping, &job.id).await.err()
        }
        // The lock goes to a restore job, which retries on the backoff. The scan's own outcome
        // stands.
        RestoreResult::Failed | RestoreResult::RateLimited(_) => {
            hand_over_to_restore(pool, mapping, &job.id).await.err()
        }
    }
}

/// What one restore attempt ended with.
#[derive(Debug, PartialEq, Eq)]
enum RestoreResult {
    /// The project's scanner is the previous one now, or there was none to put back.
    Restored,
    /// Ended with a note. The lock is released (`specs/integrations.md`).
    Noted(&'static str),
    /// The restore failed. It is retried and the lock is kept.
    Failed,
    /// Harbor rate-limited the restore. It is retried after this Unix time.
    RateLimited(i64),
}

/// Restores the project scanner to the previous one recorded on the lock row. It reads the current
/// scanner first. A scanner that is neither the chosen nor the previous one is a change by someone
/// else, and is not overwritten. A refused `PUT` for a previous scanner that is no longer listed is
/// a note, not a failure.
async fn restore_target<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    harbor: &H,
    clock: &C,
    session: &Session,
    row: &ProjectScannerLockRow,
) -> RestoreResult {
    let Some(previous) = row.previous_scanner_uuid.as_deref() else {
        return RestoreResult::Restored;
    };
    let current = match read_project_scanner(pool, harbor, clock, session).await {
        Ok(scanner) => scanner,
        Err(JobOutcome::Deferred { until, .. }) => return RestoreResult::RateLimited(until),
        Err(_) => return RestoreResult::Failed,
    };
    if current.uuid == previous {
        return RestoreResult::Restored;
    }
    if current.uuid != row.chosen_scanner_uuid {
        return RestoreResult::Noted(NOTE_CHANGED_ELSEWHERE);
    }
    let reply = match put_scanner(harbor, session, previous).await {
        Ok(reply) => reply,
        Err(_) => return RestoreResult::Failed,
    };
    match reply.status {
        200..=299 => RestoreResult::Restored,
        429 => match body_or_outcome(reply, clock.now()) {
            Err(JobOutcome::Deferred { until, .. }) => RestoreResult::RateLimited(until),
            _ => RestoreResult::Failed,
        },
        _ => match list_scanners(pool, harbor, clock, session).await {
            // Refused, and the previous scanner is gone from Harbor: nothing to restore to.
            Ok(list) if !list.iter().any(|scanner| scanner.uuid == previous) => {
                RestoreResult::Noted(NOTE_PREVIOUS_GONE)
            }
            _ => RestoreResult::Failed,
        },
    }
}

/// Releases the lock this job holds.
async fn release_lock(pool: &SqlitePool, mapping: &MappingRow, job_id: &str) -> Flow<()> {
    scanner_db::release_project_lock(
        pool,
        &mapping.harbor_base_url,
        &mapping.harbor_project,
        job_id,
    )
    .await
    .map(|_| ())
    .map_err(|_| database())
}

/// Queues a `scanner_restore` job and moves the lock to it, in one transaction, so the lock is
/// never unowned and the restore is never lost. The restore job retries on the backoff.
async fn hand_over_to_restore(pool: &SqlitePool, mapping: &MappingRow, job_id: &str) -> Flow<()> {
    let restore_id = ids::new_id().map_err(|_| failed(MSG_INTERNAL))?;
    let payload = json!({
        "kind": "scanner_restore",
        "repo_full_name": format!("{}/{}", mapping.harbor_project, mapping.harbor_repository),
    })
    .to_string();
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| database())?;
    let written = async {
        sync_jobs::enqueue_in(&mut tx, &restore_id, &mapping.id, &payload, now_secs()).await?;
        scanner_db::hand_over_lock(
            &mut tx,
            &mapping.harbor_base_url,
            &mapping.harbor_project,
            job_id,
            &restore_id,
        )
        .await
    }
    .await;
    match written {
        Ok(true) => tx.commit().await.map_err(|_| database()),
        _ => {
            let _ = tx.rollback().await;
            Err(database())
        }
    }
}

/// Runs a `scanner_restore` job (`specs/integrations.md`, "Restore (d11)"). It restores the project
/// scanner from the lock row it was handed. A failure after the last attempt keeps the lock, and a
/// success releases it.
pub async fn run_restore_job<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
) -> JobOutcome {
    match restore_job(pool, key, harbor, clock, job).await {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

async fn restore_job<H: HarborFetch, C: Clock>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    clock: &C,
    job: &ClaimedJob,
) -> Flow<JobOutcome> {
    let session = session(pool, key, &job.mapping_id).await?;
    let mapping = &session.mapping;
    let row = scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
        .await
        .map_err(|_| database())?;
    // A restore job without the lock has nothing to put back.
    let Some(row) = row.filter(|row| row.job_id == job.id) else {
        return Ok(JobOutcome::Done);
    };
    match restore_target(pool, harbor, clock, &session, &row).await {
        RestoreResult::Restored => {
            release_lock(pool, mapping, &job.id).await?;
            Ok(JobOutcome::Done)
        }
        RestoreResult::Noted(note) => {
            release_lock(pool, mapping, &job.id).await?;
            Ok(JobOutcome::DoneWithNote(note.to_owned()))
        }
        RestoreResult::Failed => Ok(failed(MSG_RESTORE_FAILED)),
        RestoreResult::RateLimited(until) => Ok(JobOutcome::Deferred {
            until,
            reason: MSG_RATE_LIMITED.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests;
