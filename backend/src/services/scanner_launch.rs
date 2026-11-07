//! Listing Harbor scanners for a mapping and starting a tag scan (#224; `specs/api.md`, "Scanners
//! and tag scans"; `specs/integrations.md`, "Scanner choice and listing").
//!
//! `GET .../scanners` reads the project scanner (call 1) and the candidates (call 2) with the
//! mapping's credential on the server and caches a successful read for 5 minutes per Harbor
//! credential and project. `POST .../tags/:tag/scan` queues one job and returns. It makes no
//! Harbor call of its own beyond the list read. With more than one enabled scanner a scanner must
//! be chosen and the job is a `scanner_scan`. With one scanner, or when the robot lacks Scanner
//! Create or Read, the job is a plain `scan` of the tag with the project's current scanner and no
//! switch, so a robot without Scanner Create can still scan.
//!
//! No scanner `url`, `auth` or credential is read (`ScannerRegistration` has no field for them),
//! and every message is fixed text.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde::Serialize;
use serde_json::json;
use sqlx::SqlitePool;

use crate::api::hardening::RateLimiter;
use crate::auth::crypto::DerivedKey;
use crate::db::mappings::MappingRow;
use crate::db::scanner_reports::{self as scanner_db, HarborScannerUpsert};
use crate::db::sync_jobs;
use crate::error::{AppError, ErrorDetail};
use crate::services::audit::{self, Actor};
use crate::services::credentials::base_for_join;
use crate::services::harbor_client::{
    HarborReply, PROJECT_NAME_HEADER, SCANNER_MAX_PAGES, SCANNER_PAGE_SIZE, ScannerRegistration,
    parse_scanner, parse_scanner_list, project_scanner_url, scanner_candidates_url,
};
use crate::services::pickers::PickerFail;
use crate::services::poller::harbor_login;
use crate::services::sync::HarborFetch;
use crate::services::{ids, scheduled_scan};

/// Scanner list reads per user per minute (shared with the picker limit, `specs/api.md`).
const LIST_LIMIT: u32 = 60;
/// One tag scan per (mapping, tag, scanner) per 5 minutes.
const SCAN_COOLDOWN: Duration = Duration::from_secs(300);
/// A successful list read is reused for 5 minutes.
const CACHE_TTL: Duration = Duration::from_secs(300);
/// The most entries the list cache holds.
const CACHE_MAX: usize = 500;

const MSG_LIST_LIMIT: &str = "Too many scanner requests. Try again in a minute.";
const MSG_SCAN_COOLDOWN: &str = "A scan was started a moment ago. Try again in a few minutes.";
const MSG_HARBOR_IDENTITY: &str =
    "The Harbor credential does not work. Test it on the Account page.";
const MSG_HARBOR_RATE: &str = "Harbor rate limit reached. Try again later.";
const MSG_CHOOSE: &str = "Choose a scanner.";
const MSG_NOT_AVAILABLE: &str = "That scanner is not available in Harbor.";
const MSG_BAD_TAG: &str = "The tag is not valid.";
const MSG_IN_PROGRESS: &str = "A scan with this scanner is already in progress.";
const MSG_RESTORE_PENDING: &str =
    "The Harbor project scanner is waiting to be restored. Try again when it has been.";

/// One scanner of the list response. Never the scanner URL, auth or credential.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Scanner {
    pub uuid: String,
    pub name: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub is_current: bool,
}

/// The project lock as the mapping page shows it: the scanner name and the lock state.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SwitchState {
    pub scanner_name: String,
    pub state: String,
}

/// The `GET .../scanners` response.
#[derive(Debug, Serialize)]
pub struct ScannerList {
    pub scanner_choice: &'static str,
    pub scanners: Vec<Scanner>,
    pub switch: Option<SwitchState>,
}

/// The `POST .../scan` response.
#[derive(Debug, Serialize)]
pub struct Queued {
    pub job_id: String,
    pub scanner_uuid: Option<String>,
    pub queued: bool,
}

/// What one successful Harbor read gave: the enabled scanners and the project's current one.
#[derive(Debug, Clone)]
struct Read {
    choice: &'static str,
    scanners: Vec<Scanner>,
}

type Cache = HashMap<String, (Instant, Read)>;

/// The in-memory state of the scanner routes: the list cache and the two limits. Held in
/// `AppState`. A restart clears it.
#[derive(Clone)]
pub struct ScannerLaunchState {
    cache: Arc<Mutex<Cache>>,
    pub list_limiter: RateLimiter,
    pub scan_limiter: RateLimiter,
}

impl Default for ScannerLaunchState {
    fn default() -> Self {
        Self::new()
    }
}

impl ScannerLaunchState {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            list_limiter: RateLimiter::new(LIST_LIMIT, Duration::from_secs(60)),
            scan_limiter: RateLimiter::new(1, SCAN_COOLDOWN),
        }
    }

    fn cached(&self, key: &str) -> Option<Read> {
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache
            .get(key)
            .filter(|(at, _)| at.elapsed() < CACHE_TTL)
            .map(|(_, read)| read.clone())
    }

    fn store(&self, key: String, read: Read) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
        if cache.len() >= CACHE_MAX
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(key, (Instant::now(), read));
    }
}

fn fixed(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    detail: Option<ErrorDetail>,
    retry_after: Option<u64>,
) -> PickerFail {
    PickerFail::Fixed {
        status,
        code,
        message,
        detail,
        retry_after,
    }
}

fn upstream() -> PickerFail {
    PickerFail::App(AppError::UpstreamUnreachable)
}

fn rate_limited(message: &'static str, wait: u64) -> PickerFail {
    fixed(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        message,
        None,
        Some(wait.max(1)),
    )
}

/// `422 validation_failed` with a fixed message.
fn invalid(message: &'static str) -> PickerFail {
    fixed(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        message,
        None,
        None,
    )
}

/// True for a Harbor tag: 1 to 128 characters of letters, digits, `_`, `.`, `-`, starting with a
/// letter, digit or `_` (Harbor's `^[\w][\w.-]{0,127}$`; UNVERIFIED against the Harbor source).
pub fn valid_tag(tag: &str) -> bool {
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    tag.chars().count() <= 128
        && (first.is_ascii_alphanumeric() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Maps a Harbor answer of the list calls to its body. `401` is the identity error and `429` the
/// rate limit. `Ok(None)` is a `403`, which is not an error here (`unavailable`).
fn read_body(reply: HarborReply) -> Result<Option<Vec<u8>>, PickerFail> {
    match reply.status {
        200 => Ok(Some(reply.body)),
        403 => Ok(None),
        401 => Err(fixed(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            MSG_HARBOR_IDENTITY,
            Some(ErrorDetail::HarborIdentity),
            None,
        )),
        429 => Err(rate_limited(
            MSG_HARBOR_RATE,
            reply.retry_after.unwrap_or(60).min(3_600),
        )),
        _ => Err(upstream()),
    }
}

/// Reads call 1 and call 2 with the mapping's credential. A `403` on either leaves the choice
/// `unavailable`. Only a successful read is cached by the caller.
async fn read_harbor<H: HarborFetch>(
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    mapping: &MappingRow,
) -> Result<Read, PickerFail> {
    let (username, secret) = harbor_login(pool, key, mapping).await?;
    let base = base_for_join(&mapping.harbor_base_url)?;
    let unavailable = Read {
        choice: "unavailable",
        scanners: Vec::new(),
    };

    let mut registrations: Vec<ScannerRegistration> = Vec::new();
    for page in 1..=SCANNER_MAX_PAGES {
        let url = scanner_candidates_url(&base, &mapping.harbor_project, page)?;
        let reply = harbor
            .fetch(&url, &username, &secret, &[PROJECT_NAME_HEADER])
            .await
            .map_err(|_| upstream())?;
        let Some(body) = read_body(reply)? else {
            return Ok(unavailable);
        };
        let list = parse_scanner_list(&body).map_err(|_| upstream())?;
        let last = list.len() < SCANNER_PAGE_SIZE as usize;
        registrations.extend(list);
        if last {
            break;
        }
    }

    // Call 1 names the current scanner. Without Scanner Read it is unknown, and nothing is current.
    let url = project_scanner_url(&base, &mapping.harbor_project)?;
    let reply = harbor
        .fetch(&url, &username, &secret, &[PROJECT_NAME_HEADER])
        .await
        .map_err(|_| upstream())?;
    let current = match read_body(reply)? {
        Some(body) => Some(parse_scanner(&body).map_err(|_| upstream())?),
        None => None,
    };

    let now = crate::worker::now_secs();
    for scanner in registrations.iter().chain(current.iter()) {
        scanner_db::upsert_scanner(
            pool,
            &HarborScannerUpsert {
                harbor_base_url: &mapping.harbor_base_url,
                uuid: &scanner.uuid,
                name: &scanner.name,
                vendor: scanner.vendor.as_deref(),
                version: scanner.version.as_deref(),
                disabled: scanner.disabled,
                seen_at: now,
            },
        )
        .await?;
    }

    let mut scanners: Vec<Scanner> = registrations
        .into_iter()
        .filter(|scanner| !scanner.disabled)
        .map(|scanner| Scanner {
            is_current: current.as_ref().is_some_and(|c| c.uuid == scanner.uuid),
            uuid: scanner.uuid,
            name: scanner.name,
            vendor: scanner.vendor,
            version: scanner.version,
        })
        .collect();
    scanners.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.uuid.cmp(&b.uuid))
    });
    let choice = match scanners.len() {
        0 => "unavailable",
        1 => "single",
        _ => "available",
    };
    Ok(Read { choice, scanners })
}

/// The cached read, or a fresh one that is then cached.
async fn read_cached<H: HarborFetch>(
    state: &ScannerLaunchState,
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    mapping: &MappingRow,
) -> Result<Read, PickerFail> {
    let cache_key = format!("{}|{}", mapping.harbor_cred_id, mapping.harbor_project);
    if let Some(read) = state.cached(&cache_key) {
        return Ok(read);
    }
    let read = read_harbor(pool, key, harbor, mapping).await?;
    if read.choice != "unavailable" {
        state.store(cache_key, read.clone());
    }
    Ok(read)
}

/// The lock row of the mapping's Harbor project as the page shows it.
async fn switch_state(
    pool: &SqlitePool,
    mapping: &MappingRow,
) -> Result<Option<SwitchState>, AppError> {
    let Some(lock) =
        scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
            .await?
    else {
        return Ok(None);
    };
    let name = scanner_db::list_scanners(pool, &mapping.harbor_base_url)
        .await?
        .into_iter()
        .find(|row| row.uuid == lock.chosen_scanner_uuid)
        .map(|row| row.name)
        .unwrap_or_default();
    Ok(Some(SwitchState {
        scanner_name: name,
        state: lock.state,
    }))
}

/// `GET /api/v1/mappings/:id/scanners` for a mapping the caller may read.
pub async fn list<H: HarborFetch>(
    state: &ScannerLaunchState,
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    user_id: &str,
    mapping: &MappingRow,
) -> Result<ScannerList, PickerFail> {
    state
        .list_limiter
        .check(&format!("scanners:{user_id}"), Instant::now())
        .map_err(|wait| rate_limited(MSG_LIST_LIMIT, wait))?;
    let read = read_cached(state, pool, key, harbor, mapping).await?;
    Ok(ScannerList {
        scanner_choice: read.choice,
        scanners: read.scanners,
        switch: switch_state(pool, mapping).await?,
    })
}

/// `POST /api/v1/mappings/:id/tags/:tag/scan` for a mapping the caller may start a scan on.
///
/// Order of checks (`specs/api.md`): the tag, the scanner choice, `409` conflicts, then the
/// cooldown, so a refused request never uses the cooldown. The job and the `mapping.scan` audit
/// row are written in one transaction.
#[allow(clippy::too_many_arguments)]
pub async fn start_scan<H: HarborFetch>(
    state: &ScannerLaunchState,
    pool: &SqlitePool,
    key: &DerivedKey,
    harbor: &H,
    actor: &Actor,
    mapping: &MappingRow,
    tag: &str,
    requested: Option<&str>,
    now: i64,
) -> Result<Queued, PickerFail> {
    if !valid_tag(tag) {
        return Err(invalid(MSG_BAD_TAG));
    }
    let read = read_cached(state, pool, key, harbor, mapping).await?;
    let chosen: Option<String> = match read.choice {
        "available" => {
            let uuid = requested
                .filter(|uuid| !uuid.is_empty())
                .ok_or_else(|| PickerFail::App(AppError::InvalidRequest(MSG_CHOOSE.to_owned())))?;
            if !read.scanners.iter().any(|scanner| scanner.uuid == uuid) {
                return Err(invalid(MSG_NOT_AVAILABLE));
            }
            Some(uuid.to_owned())
        }
        // One scanner, or none readable: the project's current scanner, no switch.
        _ => None,
    };

    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let pending = match &chosen {
        Some(uuid) => {
            sync_jobs::has_pending_scanner_scan(&mut conn, &mapping.id, tag, uuid).await?
        }
        None => sync_jobs::has_pending_scan_job(&mut conn, &mapping.id).await?,
    };
    drop(conn);
    if pending {
        return Err(fixed(
            StatusCode::CONFLICT,
            "conflict",
            MSG_IN_PROGRESS,
            None,
            None,
        ));
    }
    if chosen.is_some() {
        let lock =
            scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
                .await?;
        if lock.is_some_and(|row| row.state == "restore_pending") {
            return Err(fixed(
                StatusCode::CONFLICT,
                "conflict",
                MSG_RESTORE_PENDING,
                None,
                None,
            ));
        }
    }

    state
        .scan_limiter
        .check(
            &format!(
                "scan:{}:{}:{}",
                mapping.id,
                tag,
                chosen.as_deref().unwrap_or("")
            ),
            Instant::now(),
        )
        .map_err(|wait| rate_limited(MSG_SCAN_COOLDOWN, wait))?;

    let job_id = ids::new_id()?;
    let repo_full_name = format!("{}/{}", mapping.harbor_project, mapping.harbor_repository);
    let payload = match &chosen {
        Some(uuid) => json!({
            "kind": "scanner_scan",
            "repo_full_name": repo_full_name,
            "tag": tag,
            "scanner_uuid": uuid,
            "trigger": scheduled_scan::TRIGGER_MANUAL,
        }),
        None => json!({
            "kind": "scan",
            "repo_full_name": repo_full_name,
            "tag": tag,
            "trigger": scheduled_scan::TRIGGER_MANUAL,
        }),
    }
    .to_string();
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let written: Result<(), AppError> = async {
        sync_jobs::enqueue_in(&mut tx, &job_id, &mapping.id, &payload, now).await?;
        audit::record(
            &mut tx,
            actor,
            "mapping.scan",
            &format!("mapping:{}", mapping.id),
            Some(&json!({
                "mapping_id": mapping.id,
                "tag": tag,
                "scanner_uuid": chosen,
            })),
        )
        .await
    }
    .await;
    match written {
        Ok(()) => tx.commit().await.map_err(|_| AppError::InternalError)?,
        Err(error) => {
            let _ = tx.rollback().await;
            return Err(error.into());
        }
    }
    Ok(Queued {
        job_id,
        scanner_uuid: chosen,
        queued: true,
    })
}

#[cfg(test)]
mod tests;
