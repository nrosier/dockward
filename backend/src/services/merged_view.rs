//! The merged view of the stored scanner reports of one digest (#224 d2, d6, d14;
//! `specs/cve-lifecycle.md`, "Merged view").
//!
//! A digest has one stored report per Harbor scanner. A finding is the same finding when its CVE
//! id and package name are equal (exact, case-sensitive). The merged view has one finding per
//! (CVE id, package), with the scanners that report it. The SARIF converter, the issue body and
//! the close rule read this view, never one scanner's report.
//!
//! Only names, versions, CVE ids and counts pass through here. No scanner URL or credential is
//! ever read (`db::scanner_reports` has no field for them).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{Value, json};
use sqlx::{SqliteConnection, SqlitePool};

use crate::db::scanner_reports::{
    self as scanner_db, ScannerFindingRow, ScannerReportRow, UNKNOWN_SCANNER_UUID,
};
use crate::error::AppError;
use crate::services::sarif::normalize_severity;

/// The name shown for a report that cannot be tied to a Harbor scanner (`cves.scanner.unknown`).
pub const UNKNOWN_SCANNER_NAME: &str = "Unknown scanner";

/// Appended to the report's own scanner name for an `unknown` report that has one (#277). The UI
/// uses the catalog key `mapping.scan.notLinked`; this is the backend text for the issue body and
/// the SARIF, which are not UI text.
pub const NOT_LINKED_SUFFIX: &str = " (not linked to a Harbor registration)";

/// The report's own scanner name of an `unknown` report, or `None` when it has none.
pub fn unlinked_name(report: &ScannerReportRow) -> Option<&str> {
    if report.scanner_uuid != UNKNOWN_SCANNER_UUID {
        return None;
    }
    report
        .scanner_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Highest first, as in `specs/cve-lifecycle.md`.
const SEVERITY_ORDER: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/// A scanner that has a stored report for the digest: its UUID and the name to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerRef {
    pub uuid: String,
    pub name: String,
}

/// One finding of the merged view.
#[derive(Debug, Clone, PartialEq)]
pub struct MergedFinding {
    pub cve_id: String,
    pub package: String,
    pub version: Option<String>,
    pub fixed_in_version: Option<String>,
    pub severity: &'static str,
    pub cvss_v3: Option<f64>,
    pub description: Option<String>,
    /// The scanners that report this (CVE id, package), in the merged-view order.
    pub scanners: Vec<ScannerRef>,
}

/// The merged view of one digest: the scanners that reported, in order, and the findings sorted
/// by CVE id then package.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MergedDigest {
    pub scanners: Vec<ScannerRef>,
    pub findings: Vec<MergedFinding>,
}

fn severity_rank(severity: &str) -> usize {
    SEVERITY_ORDER
        .iter()
        .position(|known| *known == severity)
        .unwrap_or(SEVERITY_ORDER.len())
}

/// The scanners of `reports`, ordered by name (case-insensitive), then UUID, with `unknown`
/// last. A name is the current `harbor_scanners.name`, else the report's own snapshot. An
/// `unknown` report shows its own name marked as not linked, else "Unknown scanner" (#277).
pub fn order_scanners(
    reports: &[ScannerReportRow],
    current_names: &HashMap<String, String>,
) -> Vec<ScannerRef> {
    let mut scanners: Vec<ScannerRef> = reports
        .iter()
        .map(|report| {
            let name = if report.scanner_uuid == UNKNOWN_SCANNER_UUID {
                unlinked_name(report).map_or_else(
                    || UNKNOWN_SCANNER_NAME.to_owned(),
                    |name| format!("{name}{NOT_LINKED_SUFFIX}"),
                )
            } else {
                current_names
                    .get(&report.scanner_uuid)
                    .cloned()
                    .or_else(|| report.scanner_name.clone().filter(|name| !name.is_empty()))
                    .unwrap_or_else(|| UNKNOWN_SCANNER_NAME.to_owned())
            };
            ScannerRef {
                uuid: report.scanner_uuid.clone(),
                name,
            }
        })
        .collect();
    scanners.sort_by(|a, b| {
        (a.uuid == UNKNOWN_SCANNER_UUID)
            .cmp(&(b.uuid == UNKNOWN_SCANNER_UUID))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.uuid.cmp(&b.uuid))
    });
    scanners.dedup_by(|a, b| a.uuid == b.uuid);
    scanners
}

/// Merges the findings of every report by (CVE id, package).
///
/// - Severity is the highest of the scanners' severities; the CVSS v3 score is the highest present.
/// - The installed and fixed-in versions come from the first scanner (in order) that has one.
/// - The description comes from the first scanner holding the highest severity, else the first
///   non-empty one.
pub fn merge(rows: &[ScannerFindingRow], scanners: &[ScannerRef]) -> Vec<MergedFinding> {
    let position: HashMap<&str, usize> = scanners
        .iter()
        .enumerate()
        .map(|(index, scanner)| (scanner.uuid.as_str(), index))
        .collect();
    let mut groups: BTreeMap<(&str, &str), Vec<&ScannerFindingRow>> = BTreeMap::new();
    for row in rows {
        // A row from a scanner outside the list has no report in this view and is ignored.
        if position.contains_key(row.scanner_uuid.as_str()) {
            groups
                .entry((row.cve_id.as_str(), row.package.as_str()))
                .or_default()
                .push(row);
        }
    }
    groups
        .into_iter()
        .map(|((cve_id, package), mut members)| {
            members.sort_by_key(|row| position.get(row.scanner_uuid.as_str()).copied());
            let severity = members
                .iter()
                .map(|row| normalize_severity(&row.severity))
                .min_by_key(|severity| severity_rank(severity))
                .unwrap_or("UNKNOWN");
            let from_top = members
                .iter()
                .find(|row| normalize_severity(&row.severity) == severity);
            let description = from_top
                .and_then(|row| row.description.clone())
                .or_else(|| members.iter().find_map(|row| row.description.clone()));
            MergedFinding {
                cve_id: cve_id.to_owned(),
                package: package.to_owned(),
                version: members.iter().find_map(|row| row.version.clone()),
                fixed_in_version: members.iter().find_map(|row| row.fixed_in_version.clone()),
                severity,
                cvss_v3: members
                    .iter()
                    .filter_map(|row| row.cvss_v3)
                    .fold(None, |best: Option<f64>, score| {
                        Some(best.map_or(score, |best| best.max(score)))
                    }),
                description,
                scanners: members
                    .iter()
                    .filter_map(|row| position.get(row.scanner_uuid.as_str()).copied())
                    .filter_map(|index| scanners.get(index).cloned())
                    .collect(),
            }
        })
        .collect()
}

/// Reads the stored reports of (mapping, digest) and merges them.
pub async fn load(
    pool: &SqlitePool,
    mapping_id: &str,
    harbor_base_url: &str,
    digest: &str,
) -> Result<MergedDigest, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    load_in(&mut conn, mapping_id, harbor_base_url, digest).await
}

/// [`load`] on a connection the caller holds, so it sees that transaction's own writes.
pub async fn load_in(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    harbor_base_url: &str,
    digest: &str,
) -> Result<MergedDigest, AppError> {
    let reports = scanner_db::reports_for_digest_in(conn, mapping_id, digest).await?;
    if reports.is_empty() {
        return Ok(MergedDigest::default());
    }
    let current: HashMap<String, String> = scanner_db::list_scanners_in(conn, harbor_base_url)
        .await?
        .into_iter()
        .map(|row| (row.uuid, row.name))
        .collect();
    let scanners = order_scanners(&reports, &current);
    let rows = scanner_db::findings_for_digest_in(conn, mapping_id, digest).await?;
    let findings = merge(&rows, &scanners);
    Ok(MergedDigest { scanners, findings })
}

/// The merged findings as a Harbor-style report (`{"vulnerabilities": [...]}`), the shape the
/// SARIF converter and the findings store read. Each item also carries `scanner_names`, which the
/// converter writes as the `harborgate/scannerCount` and `harborgate/scannerNames` properties.
pub fn to_report(findings: &[MergedFinding]) -> Value {
    let items: Vec<Value> = findings
        .iter()
        .map(|finding| {
            let mut item = json!({
                "id": finding.cve_id,
                "package": finding.package,
                "severity": finding.severity,
                "scanner_names": names_of(&finding.scanners),
                "scanner_count": finding.scanners.len(),
            });
            if let Some(version) = &finding.version {
                item["version"] = json!(version);
            }
            if let Some(fixed) = &finding.fixed_in_version {
                item["fix_version"] = json!(fixed);
            }
            if let Some(description) = &finding.description {
                item["description"] = json!(description);
            }
            if let Some(score) = finding.cvss_v3 {
                item["preferred_cvss"] = json!({ "score_v3": score });
            }
            item
        })
        .collect();
    json!({ "vulnerabilities": items })
}

/// The scanner names, unique, in the given order.
pub fn names_of(scanners: &[ScannerRef]) -> Vec<String> {
    let mut seen = HashSet::new();
    scanners
        .iter()
        .filter(|scanner| seen.insert(scanner.name.clone()))
        .map(|scanner| scanner.name.clone())
        .collect()
}

/// The report with only the first item of each CVE id. `cve_findings` has one row per CVE id,
/// and its package is the first by the merged-view order (`specs/cve-lifecycle.md`, "Per tag").
pub fn first_per_cve(report: &Value) -> Value {
    let mut seen = HashSet::new();
    let items: Vec<Value> = report
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|item| {
            let id = item.get("id").and_then(Value::as_str).unwrap_or("");
            seen.insert(id.to_owned())
        })
        .cloned()
        .collect();
    json!({ "vulnerabilities": items })
}

/// The scanners per CVE id over the whole merged view, in the merged-view order.
pub fn scanners_by_cve(digest: &MergedDigest) -> HashMap<String, Vec<ScannerRef>> {
    let mut by_cve: HashMap<String, Vec<ScannerRef>> = HashMap::new();
    for finding in &digest.findings {
        let entry = by_cve.entry(finding.cve_id.clone()).or_default();
        for scanner in &finding.scanners {
            if !entry.iter().any(|known| known.uuid == scanner.uuid) {
                entry.push(scanner.clone());
            }
        }
    }
    let position: HashMap<&str, usize> = digest
        .scanners
        .iter()
        .enumerate()
        .map(|(index, scanner)| (scanner.uuid.as_str(), index))
        .collect();
    for scanners in by_cve.values_mut() {
        scanners.sort_by_key(|scanner| position.get(scanner.uuid.as_str()).copied());
    }
    by_cve
}

/// A scanner name as one inline code span, so it cannot break the line or mention a user.
fn code_span(text: &str) -> String {
    format!("`{}`", text.replace(['\r', '\n', '`'], " ").trim())
}

/// The issue body line `Found by <n> scanner(s): <names>` (`specs/integrations.md`, "GitHub
/// issues"). `None` when no scanner is known, or when the only one is the unknown scanner (the
/// line is omitted then, `specs/database.md`).
pub fn found_by_line(scanners: &[ScannerRef]) -> Option<String> {
    if scanners.is_empty() || scanners.iter().all(|s| s.uuid == UNKNOWN_SCANNER_UUID) {
        return None;
    }
    let count = scanners.len();
    let names: Vec<String> = scanners.iter().map(|s| code_span(&s.name)).collect();
    Some(format!(
        "Found by {count} scanner{}: {}",
        if count == 1 { "" } else { "s" },
        names.join(", ")
    ))
}

/// The close and reopen comment text for the names of the scanners that report a CVE, or `None`
/// when no scanner is known.
pub fn names_text(scanners: &[ScannerRef]) -> Option<String> {
    let names = names_of(scanners);
    if names.is_empty() {
        None
    } else {
        Some(names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner(uuid: &str, name: &str) -> ScannerRef {
        ScannerRef {
            uuid: uuid.to_owned(),
            name: name.to_owned(),
        }
    }

    fn row(uuid: &str, cve: &str, package: &str, severity: &str) -> ScannerFindingRow {
        ScannerFindingRow {
            report_id: format!("r-{uuid}"),
            scanner_uuid: uuid.to_owned(),
            cve_id: cve.to_owned(),
            package: package.to_owned(),
            version: Some("1.0".to_owned()),
            fixed_in_version: None,
            severity: severity.to_owned(),
            cvss_v3: None,
            description: None,
        }
    }

    fn report_row(uuid: &str, name: Option<&str>) -> ScannerReportRow {
        ScannerReportRow {
            id: format!("r-{uuid}"),
            scanner_uuid: uuid.to_owned(),
            scanner_name: name.map(str::to_owned),
            scanner_vendor: None,
            scanner_version: None,
            image_push_time: None,
            stored_at: 1,
        }
    }

    #[test]
    fn scanners_are_ordered_by_name_then_uuid_with_unknown_last() {
        let reports = vec![
            report_row("unknown", None),
            report_row("u-2", Some("trivy")),
            report_row("u-1", Some("Grype")),
            report_row("u-0", Some("Trivy")),
        ];
        let current = HashMap::new();
        let names: Vec<String> = order_scanners(&reports, &current)
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["Grype", "Trivy", "trivy", UNKNOWN_SCANNER_NAME]);
    }

    /// #277: an `unknown` report shows its own scanner name, marked as not linked; with no name it
    /// is "Unknown scanner". A known UUID with no name keeps the old label.
    #[test]
    fn an_unknown_report_shows_its_own_name_marked_as_not_linked() {
        let current = HashMap::new();
        let named = order_scanners(&[report_row("unknown", Some("Grype"))], &current);
        assert_eq!(named[0].uuid, UNKNOWN_SCANNER_UUID);
        assert_eq!(named[0].name, "Grype (not linked to a Harbor registration)");
        let blank = order_scanners(&[report_row("unknown", Some("  "))], &current);
        assert_eq!(blank[0].name, UNKNOWN_SCANNER_NAME);
        let none = order_scanners(&[report_row("unknown", None)], &current);
        assert_eq!(none[0].name, UNKNOWN_SCANNER_NAME);
        let known = order_scanners(&[report_row("u-1", None)], &current);
        assert_eq!(known[0].name, UNKNOWN_SCANNER_NAME);
        let known_named = order_scanners(&[report_row("u-1", Some("Trivy"))], &current);
        assert_eq!(known_named[0].name, "Trivy");
        // Still last, and still no `Found by` line for the unknown scanner alone.
        let both = order_scanners(
            &[
                report_row("unknown", Some("Aqua")),
                report_row("u-1", Some("Trivy")),
            ],
            &current,
        );
        assert_eq!(both[1].uuid, UNKNOWN_SCANNER_UUID);
        assert_eq!(found_by_line(&named), None);
    }

    #[test]
    fn a_current_name_wins_over_the_report_snapshot() {
        let reports = vec![report_row("u-1", Some("Old name"))];
        let mut current = HashMap::new();
        current.insert("u-1".to_owned(), "New name".to_owned());
        assert_eq!(order_scanners(&reports, &current)[0].name, "New name");
    }

    #[test]
    fn the_same_cve_and_package_from_two_scanners_is_one_finding_with_count_two() {
        let scanners = vec![scanner("u-1", "Grype"), scanner("u-2", "Trivy")];
        let rows = vec![
            row("u-1", "CVE-1", "openssl", "Medium"),
            row("u-2", "CVE-1", "openssl", "HIGH"),
            row("u-2", "CVE-2", "zlib", "LOW"),
        ];
        let merged = merge(&rows, &scanners);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].cve_id, "CVE-1");
        assert_eq!(merged[0].severity, "HIGH", "the highest severity");
        assert_eq!(names_of(&merged[0].scanners), ["Grype", "Trivy"]);
        assert_eq!(merged[1].scanners.len(), 1);
        assert_eq!(names_of(&merged[1].scanners), ["Trivy"]);
    }

    #[test]
    fn the_same_cve_in_another_package_is_a_separate_finding() {
        let scanners = vec![scanner("u-1", "Grype"), scanner("u-2", "Trivy")];
        let rows = vec![
            row("u-1", "CVE-1", "openssl", "HIGH"),
            row("u-2", "CVE-1", "libssl", "HIGH"),
        ];
        let merged = merge(&rows, &scanners);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(|finding| finding.scanners.len() == 1));
    }

    #[test]
    fn a_cve_fixed_in_one_scanner_only_has_a_fixed_in_version() {
        // #265: fix available when at least one scanner reports a fixed version.
        let mut with_fix = row("u-2", "CVE-1", "zlib", "HIGH");
        with_fix.fixed_in_version = Some("1.3".to_owned());
        let rows = vec![row("u-1", "CVE-1", "zlib", "HIGH"), with_fix];
        let merged = merge(&rows, &[scanner("u-1", "Grype"), scanner("u-2", "Trivy")]);
        assert_eq!(merged[0].fixed_in_version.as_deref(), Some("1.3"));
    }

    #[test]
    fn found_by_line_counts_and_names_the_scanners() {
        let two = vec![scanner("u-1", "Grype"), scanner("u-2", "Trivy")];
        assert_eq!(
            found_by_line(&two).as_deref(),
            Some("Found by 2 scanners: `Grype`, `Trivy`")
        );
        let one = vec![scanner("u-2", "Trivy")];
        assert_eq!(
            found_by_line(&one).as_deref(),
            Some("Found by 1 scanner: `Trivy`")
        );
        let unknown = vec![scanner(UNKNOWN_SCANNER_UUID, UNKNOWN_SCANNER_NAME)];
        assert_eq!(
            found_by_line(&unknown),
            None,
            "omitted for the unknown scanner"
        );
        assert_eq!(found_by_line(&[]), None);
    }

    #[test]
    fn first_per_cve_keeps_the_first_package_of_each_id() {
        let report = json!({"vulnerabilities": [
            {"id": "CVE-1", "package": "a"},
            {"id": "CVE-1", "package": "b"},
            {"id": "CVE-2", "package": "c"},
        ]});
        let unique = first_per_cve(&report);
        let items = unique["vulnerabilities"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["package"], "a");
    }
}
