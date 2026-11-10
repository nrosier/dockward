//! `GET /api/v1/mappings/:id/tags/:tag/scans` (`specs/api.md`, "Scanners and tag scans"; #224).
//!
//! One `TagScan` per scanner that matters for the tag: every enabled scanner HarborGate has seen
//! for the Harbor, and every scanner that has a stored report for the tag's digest or a
//! `scanner_scan` job for the tag. The state is read from the database only (the latest job and the
//! stored report); the route never calls Harbor and has no rate limit.
//!
//! `note` is a fixed catalog key chosen from the job's fixed `last_error` text. Free text, and
//! anything from a Harbor body, is never returned.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::mappings::MappingRow;
// TODO(spinoff part 2): bridge. db::scanner_reports was deleted or ported to scan_runs in Step 1a; this Harbor-pipeline caller is removed or rewritten in part 3.
use crate::db::scanner_reports::{self as scanner_db, TagScanJob, UNKNOWN_SCANNER_UUID};
use crate::error::AppError;
// TODO(spinoff part 2): bridge. merged_view::unlinked_name and UNKNOWN_SCANNER_NAME was deleted or ported to scan_runs in Step 1a; this Harbor-pipeline caller is removed or rewritten in part 3.
use crate::services::merged_view::{UNKNOWN_SCANNER_NAME, unlinked_name};
use crate::services::resolve::NOTE_ARTIFACT_GONE;
use crate::services::scanner_launch::valid_tag;
use crate::services::scanner_scan::{
    MSG_RESTORE_FAILED, MSG_SCAN_FORBIDDEN, MSG_SCANNER_FAILED, MSG_SCANNER_GONE,
    MSG_SWITCH_FORBIDDEN, NOTE_CHANGED_ELSEWHERE, NOTE_PREVIOUS_GONE,
};
use crate::services::sync::NOTE_SCANNER_UNMATCHED;
use crate::services::time;

/// One scanner's state for a tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TagScan {
    pub scanner_uuid: String,
    pub scanner_name: String,
    /// True when `scanner_uuid` is `unknown` and `scanner_name` is the report's own name, so the UI
    /// marks it as not linked to a Harbor registration (#277).
    pub unlinked: bool,
    /// `queued`, `running`, `waiting`, `ok`, `failed` or `none`.
    pub state: &'static str,
    /// A catalog key (`sync.note.*`), or `None`.
    pub note: Option<&'static str>,
    pub job_id: Option<String>,
    pub updated_at: Option<String>,
}

/// The catalog key for a job's fixed `last_error` text, or `None` for any other text.
fn note_key(last_error: Option<&str>) -> Option<&'static str> {
    let text = last_error?;
    let known: [(&str, &'static str); 8] = [
        (MSG_SWITCH_FORBIDDEN, "sync.note.scannerForbidden"),
        (MSG_SCAN_FORBIDDEN, "sync.note.scanForbidden"),
        (MSG_SCANNER_GONE, "sync.note.scannerGone"),
        (MSG_SCANNER_FAILED, "sync.note.scannerFailed"),
        (MSG_RESTORE_FAILED, "sync.note.restoreFailed"),
        (NOTE_PREVIOUS_GONE, "sync.note.previousScannerGone"),
        (NOTE_CHANGED_ELSEWHERE, "sync.note.scannerChangedElsewhere"),
        (NOTE_SCANNER_UNMATCHED, "sync.note.scannerUnmatched"),
    ];
    if text == NOTE_ARTIFACT_GONE {
        return Some("sync.note.artifactGone");
    }
    known
        .iter()
        .find(|(message, _)| *message == text)
        .map(|(_, key)| *key)
}

/// The scanners and their state for one tag of a mapping the caller may read.
pub async fn list(
    pool: &SqlitePool,
    mapping: &MappingRow,
    tag: &str,
) -> Result<Vec<TagScan>, AppError> {
    if !valid_tag(tag) {
        return Err(AppError::NotFound);
    }
    let registry = scanner_db::list_scanners(pool, &mapping.harbor_base_url).await?;
    let digest =
        scanner_db::latest_digest_for_tag(pool, &mapping.id, &mapping.harbor_repository, tag)
            .await?;
    let reports = match &digest {
        Some(digest) => scanner_db::reports_for_digest(pool, &mapping.id, digest).await?,
        None => Vec::new(),
    };
    let jobs = scanner_db::scanner_jobs_for_tag(pool, &mapping.id, tag).await?;
    let lock =
        scanner_db::get_project_lock(pool, &mapping.harbor_base_url, &mapping.harbor_project)
            .await?;

    // The newest job per scanner (the query is newest first).
    let mut latest: HashMap<&str, &TagScanJob> = HashMap::new();
    for job in &jobs {
        latest.entry(job.scanner_uuid.as_str()).or_insert(job);
    }
    let report_of: HashMap<&str, &scanner_db::ScannerReportRow> = reports
        .iter()
        .map(|report| (report.scanner_uuid.as_str(), report))
        .collect();

    // The scanners to list: enabled and not removed, plus any with a report or a job.
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for row in &registry {
        let listed = !row.disabled && row.removed_at.is_none();
        if listed
            || report_of.contains_key(row.uuid.as_str())
            || latest.contains_key(row.uuid.as_str())
        {
            names.insert(row.uuid.clone(), row.name.clone());
        }
    }
    for report in &reports {
        names.entry(report.scanner_uuid.clone()).or_insert_with(|| {
            report
                .scanner_name
                .clone()
                .filter(|name| !name.is_empty())
                .unwrap_or_default()
        });
    }
    for job in &jobs {
        names.entry(job.scanner_uuid.clone()).or_default();
    }

    let mut items: Vec<TagScan> = Vec::with_capacity(names.len());
    for (uuid, name) in names {
        let job = latest.get(uuid.as_str()).copied();
        let report = report_of.get(uuid.as_str()).copied();
        let (scanner_name, unlinked) = if uuid == UNKNOWN_SCANNER_UUID {
            match report.and_then(unlinked_name) {
                Some(own) => (own.to_owned(), true),
                None => (UNKNOWN_SCANNER_NAME.to_owned(), false),
            }
        } else {
            (name, false)
        };
        let waiting = job.is_some_and(|job| {
            lock.as_ref().is_some_and(|lock| {
                lock.job_id == job.id
                    && lock.wait_started_at.is_some()
                    && matches!(job.status.as_str(), "queued" | "running")
            })
        });
        let (state, note) = match job {
            Some(_) if waiting => ("waiting", None),
            Some(job) if job.status == "queued" => ("queued", None),
            Some(job) if job.status == "running" => ("running", None),
            Some(job) if job.status == "failed" => ("failed", note_key(job.last_error.as_deref())),
            Some(job) if report.is_none() && note_key(job.last_error.as_deref()).is_some() => {
                // Done with a note and no report: a scanner that is gone, or a tag that is.
                ("failed", note_key(job.last_error.as_deref()))
            }
            Some(job) if report.is_some() => ("ok", note_key(job.last_error.as_deref())),
            None if report.is_some() => ("ok", None),
            _ => ("none", None),
        };
        let stamp = match (job, report) {
            (Some(job), _) if state != "ok" => job.updated_at,
            (_, Some(report)) => Some(report.stored_at),
            (Some(job), None) => job.updated_at,
            (None, None) => None,
        };
        items.push(TagScan {
            scanner_uuid: uuid,
            scanner_name,
            unlinked,
            state,
            note,
            job_id: job.map(|job| job.id.clone()),
            updated_at: stamp.map(time::rfc3339).transpose()?,
        });
    }

    // By name (case-insensitive), then UUID, with the unknown scanner last.
    items.sort_by(|a, b| {
        (a.scanner_uuid == UNKNOWN_SCANNER_UUID)
            .cmp(&(b.scanner_uuid == UNKNOWN_SCANNER_UUID))
            .then_with(|| {
                a.scanner_name
                    .to_lowercase()
                    .cmp(&b.scanner_name.to_lowercase())
            })
            .then_with(|| a.scanner_uuid.cmp(&b.scanner_uuid))
    });
    Ok(items)
}
