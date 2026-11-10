//! Storing a scanner's report, and the scanner registry upkeep around it (#224,
//! `specs/integrations.md`, "Scanner reports and scan launch").
//!
//! Three writers share this module:
//! - the chosen-scan job (`scanner_scan`) stores the report of the scanner it switched to;
//! - the normal sync (webhook, poll, resolve fan-out) stores the report of the project's current
//!   scanner, and the first such store with a known scanner replaces the migrated `unknown` report
//!   of the digest (a chosen scan never does);
//! - a complete scanner list read marks the scanners Harbor no longer has as removed and deletes
//!   their reports, recomputing the merged findings in the same transaction.
//!
//! Only names, versions, CVE ids, package names and counts pass through here. No scanner URL, auth
//! value or token is read, stored or logged.

use serde_json::{Value, json};
use sqlx::{SqliteConnection, SqlitePool};

use crate::db::mappings::{self as mapping_db, MappingRow};
// TODO(spinoff part 2): bridge. db::scanner_reports was deleted or ported to scan_runs in Step 1a; this Harbor-pipeline caller is removed or rewritten in part 3.
use crate::db::scanner_reports::{
    self as scanner_db, HarborScannerUpsert, NewScannerFinding, NewScannerReport,
    UNKNOWN_SCANNER_UUID,
};
use crate::db::sync_jobs;
use crate::error::AppError;
use crate::services::harbor_client::ScannerRegistration;
use crate::services::{findings, ids, merged_view, sarif};

/// The scanner snapshot stored with a report: the report's own `scanner` object.
pub struct ScannerSnapshot {
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub version: Option<String>,
}

impl ScannerSnapshot {
    /// Reads the snapshot from a report's `scanner` object. `fallback_name` is used when the report
    /// names no scanner (the name Harbor gave the project's current scanner).
    pub fn from_report(report: &Value, fallback_name: Option<&str>) -> Self {
        let text = |key: &str| report.get("scanner").and_then(|s| text_field(s, key));
        Self {
            name: text("name").or_else(|| fallback_name.map(str::to_owned)),
            vendor: text("vendor"),
            version: text("version"),
        }
    }
}

/// One finding read from the report, ready to store.
pub struct ReadFinding {
    cve_id: String,
    package: String,
    version: Option<String>,
    fixed_in_version: Option<String>,
    severity: &'static str,
    cvss_v3: Option<f64>,
    description: Option<String>,
}

/// Reads the vulnerability items of a Trivy report into findings, one per (CVE id, package), as the
/// table key requires. An item with no id is skipped.
pub fn report_findings(report: &Value) -> Vec<ReadFinding> {
    let mut seen = std::collections::HashSet::new();
    report
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|item| {
            let cve_id = text_field(item, "id")?;
            let package = text_field(item, "package").unwrap_or_default();
            if !seen.insert((cve_id.clone(), package.clone())) {
                return None;
            }
            Some(ReadFinding {
                cve_id,
                package,
                version: text_field(item, "version"),
                fixed_in_version: text_field(item, "fix_version"),
                severity: sarif::normalize_severity(
                    item.get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown"),
                ),
                cvss_v3: item
                    .pointer("/preferred_cvss/score_v3")
                    .and_then(Value::as_f64),
                description: text_field(item, "description")
                    .map(|text| text.chars().take(4_000).collect()),
            })
        })
        .collect()
}

/// A non-empty string member, or `None`.
fn text_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Where a report is stored: the mapping, the image digest and the scanner.
pub struct ReportKey<'a> {
    pub mapping_id: &'a str,
    pub digest: &'a str,
    /// A Harbor registration UUID, or `UNKNOWN_SCANNER_UUID`.
    pub scanner_uuid: &'a str,
}

/// Writes the report of (mapping, digest, scanner) on `conn`: a new report by the same scanner
/// replaces its own, and no other scanner's report is touched. With `replace_unknown` the migrated
/// `unknown` report of the digest is deleted in the same transaction. Only a normal sync with a
/// known current scanner sets it; a chosen scan never does.
pub async fn write_report(
    conn: &mut SqliteConnection,
    key: &ReportKey<'_>,
    snapshot: &ScannerSnapshot,
    findings: &[ReadFinding],
    replace_unknown: bool,
    now: i64,
) -> Result<(), AppError> {
    let ReportKey {
        mapping_id,
        digest,
        scanner_uuid,
    } = *key;
    let report_id = ids::new_id()?;
    let rows: Vec<NewScannerFinding<'_>> = findings
        .iter()
        .map(|finding| NewScannerFinding {
            cve_id: &finding.cve_id,
            package: &finding.package,
            version: finding.version.as_deref(),
            fixed_in_version: finding.fixed_in_version.as_deref(),
            severity: finding.severity,
            cvss_v3: finding.cvss_v3,
            description: finding.description.as_deref(),
        })
        .collect();
    let report = NewScannerReport {
        id: &report_id,
        mapping_id,
        image_digest: digest,
        scanner_uuid,
        scanner_name: snapshot.name.as_deref(),
        scanner_vendor: snapshot.vendor.as_deref(),
        scanner_version: snapshot.version.as_deref(),
        image_push_time: None,
        stored_at: now,
    };
    if replace_unknown && scanner_uuid != UNKNOWN_SCANNER_UUID {
        scanner_db::delete_unknown_report(conn, mapping_id, digest).await?;
    }
    scanner_db::replace_report(conn, &report, &rows).await
}

/// The scanner a normal sync read the report from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The project's current scanner, named by Harbor (needs Scanner Read).
    Known { uuid: String, name: String },
    /// The robot cannot read the project scanner, so the report cannot be tied to a registration.
    Unknown,
}

/// Stores the report a normal sync read from Harbor, in one `BEGIN IMMEDIATE` transaction. A known
/// scanner replaces the digest's `unknown` report; the unknown identity replaces only its own.
pub async fn store_normal(
    pool: &SqlitePool,
    mapping_id: &str,
    digest: &str,
    identity: &Identity,
    report: &Value,
    now: i64,
) -> Result<(), AppError> {
    // The unknown identity keeps the report's own scanner object too (#277): the name, vendor and
    // version are stored, and the uuid stays `unknown`, so it is never tied to a registration.
    let (uuid, fallback, replace_unknown) = match identity {
        Identity::Known { uuid, name } => (uuid.as_str(), Some(name.as_str()), true),
        Identity::Unknown => (UNKNOWN_SCANNER_UUID, None, false),
    };
    let snapshot = ScannerSnapshot::from_report(report, fallback);
    let rows = report_findings(report);
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let key = ReportKey {
        mapping_id,
        digest,
        scanner_uuid: uuid,
    };
    let written = write_report(&mut tx, &key, &snapshot, &rows, replace_unknown, now).await;
    match written {
        Ok(()) => tx.commit().await.map_err(|_| AppError::InternalError),
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// A scanner list read from Harbor (call 2). `complete` is true only when the read ended on a short
/// page, so every registration was seen. Only a complete list may mark a scanner as removed.
pub struct Candidates {
    pub scanners: Vec<ScannerRegistration>,
    pub complete: bool,
}

/// Writes what a scanner list read returned: upserts every registration, and, for a complete list,
/// marks the Harbor's other known scanners `removed_at`, deletes their reports and recomputes the
/// merged findings of the affected digests, all in one `BEGIN IMMEDIATE` transaction
/// (`specs/integrations.md`, "Scheduled scans"). A removal that changes a digest's findings queues
/// one sync job per affected tag, so the SARIF and the issues follow. Returns how many scanners
/// were newly marked removed.
pub async fn apply_candidates(
    pool: &SqlitePool,
    harbor_base_url: &str,
    candidates: &Candidates,
    now: i64,
) -> Result<usize, AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let written = apply_in(&mut tx, harbor_base_url, candidates, now).await;
    match written {
        Ok(count) => {
            tx.commit().await.map_err(|_| AppError::InternalError)?;
            Ok(count)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

async fn apply_in(
    conn: &mut SqliteConnection,
    harbor_base_url: &str,
    candidates: &Candidates,
    now: i64,
) -> Result<usize, AppError> {
    for scanner in &candidates.scanners {
        scanner_db::upsert_scanner_in(
            conn,
            &HarborScannerUpsert {
                harbor_base_url,
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
    // An empty list is never taken as "every scanner is gone": Harbor always has a default scanner,
    // so an empty answer is a fault, and acting on it would delete every report.
    if !candidates.complete || candidates.scanners.is_empty() {
        return Ok(0);
    }
    let listed: Vec<&str> = candidates
        .scanners
        .iter()
        .map(|scanner| scanner.uuid.as_str())
        .collect();
    let listed_json = serde_json::to_string(&listed).map_err(|_| AppError::InternalError)?;
    let removed =
        scanner_db::mark_missing_removed(conn, harbor_base_url, &listed_json, now).await?;
    if removed.is_empty() {
        return Ok(0);
    }
    let removed_json = serde_json::to_string(&removed).map_err(|_| AppError::InternalError)?;
    let affected =
        scanner_db::delete_reports_of_scanners(conn, harbor_base_url, &removed_json).await?;
    for (mapping_id, digest) in affected {
        recompute_digest(conn, harbor_base_url, &mapping_id, &digest, now).await?;
    }
    Ok(removed.len())
}

/// Recomputes the tracked tags' findings of one digest from the reports that remain, and queues one
/// sync job per tag. A digest with no report left is not recomputed: an absent report is no
/// evidence that a CVE is fixed, and it would close issues on no data.
async fn recompute_digest(
    conn: &mut SqliteConnection,
    harbor_base_url: &str,
    mapping_id: &str,
    digest: &str,
    now: i64,
) -> Result<(), AppError> {
    if scanner_db::report_count(conn, mapping_id, digest).await? == 0 {
        return Ok(());
    }
    let Some(mapping) = mapping_db::find_by_id(conn, mapping_id).await? else {
        return Ok(());
    };
    // TODO(spinoff part 2): bridge. merged_view::load_in (now takes an image id) was deleted or ported to scan_runs in Step 1a; this Harbor-pipeline caller is removed or rewritten in part 3.
    let merged = merged_view::load_in(conn, mapping_id, harbor_base_url, digest).await?;
    let report = merged_view::first_per_cve(&merged_view::to_report(&merged.findings));
    for tag in scanner_db::synced_tags_for_digest(conn, mapping_id, digest).await? {
        findings::apply_scan_in(
            conn,
            mapping_id,
            &mapping.harbor_repository,
            &tag,
            &report,
            now,
        )
        .await?;
        queue_merged_sync(conn, &mapping, digest, &tag, now).await?;
    }
    Ok(())
}

/// Queues the sync job that uploads the SARIF of the merged stored reports and runs the issue
/// rules. Deduped on (mapping, digest, tag) against `queued` and `running` sync jobs.
async fn queue_merged_sync(
    conn: &mut SqliteConnection,
    mapping: &MappingRow,
    digest: &str,
    tag: &str,
    now: i64,
) -> Result<(), AppError> {
    if sync_jobs::has_pending_pair(conn, &mapping.id, digest, tag).await? {
        return Ok(());
    }
    let payload = json!({
        "repo_full_name": format!("{}/{}", mapping.harbor_project, mapping.harbor_repository),
        "digest": digest,
        "tag": tag,
        "scanner_uuid": "merged",
    })
    .to_string();
    sync_jobs::enqueue_in(conn, &ids::new_id()?, &mapping.id, &payload, now).await
}
