//! The merged view of the stored scan runs of one image (#224 d2, d6, d14;
//! `specs/cve-lifecycle.md`, "Merged view"; `specs/spinoff-local-scan.md`, sections 9 and 12;
//! decision 50).
//!
//! An image has one latest `done` scan run per (platform image, scanner). A finding is the same
//! finding when its CVE id and package name are equal (exact, case-sensitive). The merged view
//! has one finding per (CVE id, package), with the scanners that report it and the platforms it
//! was found on. The SARIF converter, the issue body and the close rule read this view, never one
//! scanner's run.
//!
//! Only names, versions, CVE ids and counts pass through here. No path, URL or credential is ever
//! read (`db::scan_runs` has no field for them).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{Value, json};
use sqlx::{SqliteConnection, SqlitePool};

use crate::db::scan_runs::{self as runs_db, ScannerFindingRow};
use crate::error::AppError;
use crate::services::sarif::normalize_severity;

/// Highest first, as in `specs/cve-lifecycle.md`.
const SEVERITY_ORDER: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/// A scanner that has a `done` run for the image: its fixed key and the name to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerRef {
    /// The fixed key stored in `scan_runs.scanner`: `grype` or `trivy`.
    pub key: String,
    /// The name shown in the UI, the issue body and the SARIF properties.
    pub name: String,
}

impl ScannerRef {
    /// The reference for a stored scanner key. The two known keys have a capitalised name; any
    /// other key (the CHECK constraint makes it impossible) is shown as it is.
    pub fn from_key(key: &str) -> Self {
        let name = match key {
            "grype" => "Grype",
            "trivy" => "Trivy",
            other => other,
        };
        Self {
            key: key.to_owned(),
            name: name.to_owned(),
        }
    }
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
    /// The platforms (`os/arch[/variant]`) that report it, sorted and unique.
    pub platforms: Vec<String>,
}

/// The merged view of one image: the scanners that reported, in order, and the findings sorted
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

/// The scanners of `keys`, ordered by name (case-insensitive), then key, without duplicates.
pub fn order_scanners(keys: &[String]) -> Vec<ScannerRef> {
    let mut scanners: Vec<ScannerRef> = keys.iter().map(|key| ScannerRef::from_key(key)).collect();
    scanners.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.key.cmp(&b.key))
    });
    scanners.dedup_by(|a, b| a.key == b.key);
    scanners
}

/// Merges the findings of every run by (CVE id, package).
///
/// - Severity is the highest of the scanners' severities; the CVSS v3 score is the highest present.
/// - The installed and fixed-in versions come from the first scanner (in order) that has one.
/// - The description comes from the first scanner holding the highest severity, else the first
///   non-empty one.
pub fn merge(rows: &[ScannerFindingRow], scanners: &[ScannerRef]) -> Vec<MergedFinding> {
    let position: HashMap<&str, usize> = scanners
        .iter()
        .enumerate()
        .map(|(index, scanner)| (scanner.key.as_str(), index))
        .collect();
    let mut groups: BTreeMap<(&str, &str), Vec<&ScannerFindingRow>> = BTreeMap::new();
    for row in rows {
        // A row from a scanner outside the list has no run in this view and is ignored.
        if position.contains_key(row.scanner.as_str()) {
            groups
                .entry((row.cve_id.as_str(), row.package.as_str()))
                .or_default()
                .push(row);
        }
    }
    groups
        .into_iter()
        .map(|((cve_id, package), mut members)| {
            // Stable, so the platform order inside one scanner is the order of the rows.
            members.sort_by_key(|row| position.get(row.scanner.as_str()).copied());
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
            let mut scanner_refs: Vec<ScannerRef> = Vec::new();
            for row in &members {
                if let Some(scanner) = position
                    .get(row.scanner.as_str())
                    .and_then(|index| scanners.get(*index))
                    && !scanner_refs.iter().any(|known| known.key == scanner.key)
                {
                    scanner_refs.push(scanner.clone());
                }
            }
            let mut platforms: Vec<String> =
                members.iter().map(|row| row.platform.clone()).collect();
            platforms.sort();
            platforms.dedup();
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
                scanners: scanner_refs,
                platforms,
            }
        })
        .collect()
}

/// Reads the latest `done` runs of the image `image_id` and merges them.
pub async fn load(pool: &SqlitePool, image_id: &str) -> Result<MergedDigest, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    load_in(&mut conn, image_id).await
}

/// [`load`] on a connection the caller holds, so it sees that transaction's own writes. An
/// image with no `done` run gives an empty view. A scanner whose latest run found nothing is
/// still listed: a clean run is a result.
pub async fn load_in(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<MergedDigest, AppError> {
    let keys = runs_db::done_scanners_in(conn, image_id).await?;
    if keys.is_empty() {
        return Ok(MergedDigest::default());
    }
    let scanners = order_scanners(&keys);
    let rows = runs_db::latest_done_findings_in(conn, image_id).await?;
    let findings = merge(&rows, &scanners);
    Ok(MergedDigest { scanners, findings })
}

/// The merged findings as a report (`{"vulnerabilities": [...]}`), the shape the SARIF converter
/// and the findings store read. Each item also carries `scanner_names`, which the converter
/// writes as the `harborgate/scannerCount` and `harborgate/scannerNames` properties, and
/// `platforms`.
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
                "platforms": finding.platforms,
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

/// The scanners per CVE id over the whole merged view, in the merged-view order.
pub fn scanners_by_cve(digest: &MergedDigest) -> HashMap<String, Vec<ScannerRef>> {
    let mut by_cve: HashMap<String, Vec<ScannerRef>> = HashMap::new();
    for finding in &digest.findings {
        let entry = by_cve.entry(finding.cve_id.clone()).or_default();
        for scanner in &finding.scanners {
            if !entry.iter().any(|known| known.key == scanner.key) {
                entry.push(scanner.clone());
            }
        }
    }
    let position: HashMap<&str, usize> = digest
        .scanners
        .iter()
        .enumerate()
        .map(|(index, scanner)| (scanner.key.as_str(), index))
        .collect();
    for scanners in by_cve.values_mut() {
        scanners.sort_by_key(|scanner| position.get(scanner.key.as_str()).copied());
    }
    by_cve
}

/// A scanner name as one inline code span, so it cannot break the line or mention a user.
fn code_span(text: &str) -> String {
    format!("`{}`", text.replace(['\r', '\n', '`'], " ").trim())
}

/// The issue body line `Found by <n> scanner(s): <names>` (`specs/integrations.md`, "GitHub
/// issues"). `None` when no scanner is known.
pub fn found_by_line(scanners: &[ScannerRef]) -> Option<String> {
    if scanners.is_empty() {
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
    use crate::db;

    fn scanner(key: &str, name: &str) -> ScannerRef {
        ScannerRef {
            key: key.to_owned(),
            name: name.to_owned(),
        }
    }

    fn row(scanner: &str, cve: &str, package: &str, severity: &str) -> ScannerFindingRow {
        ScannerFindingRow {
            scanner: scanner.to_owned(),
            platform: "linux/amd64".to_owned(),
            cve_id: cve.to_owned(),
            package: package.to_owned(),
            version: Some("1.0".to_owned()),
            fixed_in_version: None,
            severity: severity.to_owned(),
            cvss_v3: None,
            description: None,
        }
    }

    #[test]
    fn scanners_are_ordered_by_name_then_key_without_duplicates() {
        let keys: Vec<String> = ["trivy", "grype", "trivy"]
            .iter()
            .map(|key| (*key).to_owned())
            .collect();
        let names: Vec<String> = order_scanners(&keys).into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["Grype", "Trivy"]);
    }

    #[test]
    fn the_same_cve_and_package_from_two_scanners_is_one_finding_with_count_two() {
        let scanners = vec![scanner("grype", "Grype"), scanner("trivy", "Trivy")];
        let rows = vec![
            row("grype", "CVE-1", "openssl", "Medium"),
            row("trivy", "CVE-1", "openssl", "HIGH"),
            row("trivy", "CVE-2", "zlib", "LOW"),
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
        let scanners = vec![scanner("grype", "Grype"), scanner("trivy", "Trivy")];
        let rows = vec![
            row("grype", "CVE-1", "openssl", "HIGH"),
            row("trivy", "CVE-1", "libssl", "HIGH"),
        ];
        let merged = merge(&rows, &scanners);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(|finding| finding.scanners.len() == 1));
    }

    #[test]
    fn a_cve_fixed_in_one_scanner_only_has_a_fixed_in_version() {
        // #265: fix available when at least one scanner reports a fixed version.
        let mut with_fix = row("trivy", "CVE-1", "zlib", "HIGH");
        with_fix.fixed_in_version = Some("1.3".to_owned());
        let rows = vec![row("grype", "CVE-1", "zlib", "HIGH"), with_fix];
        let merged = merge(
            &rows,
            &[scanner("grype", "Grype"), scanner("trivy", "Trivy")],
        );
        assert_eq!(merged[0].fixed_in_version.as_deref(), Some("1.3"));
    }

    /// Spinoff: two platforms of one image give one finding that names both, and one scanner
    /// that reports on both platforms is counted once.
    #[test]
    fn platforms_are_merged_into_one_finding_and_one_scanner_count() {
        let mut arm = row("grype", "CVE-1", "zlib", "HIGH");
        arm.platform = "linux/arm64".to_owned();
        let rows = vec![row("grype", "CVE-1", "zlib", "HIGH"), arm];
        let merged = merge(&rows, &[scanner("grype", "Grype")]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].scanners.len(), 1);
        assert_eq!(merged[0].platforms, ["linux/amd64", "linux/arm64"]);
    }

    #[test]
    fn found_by_line_counts_and_names_the_scanners() {
        let two = vec![scanner("grype", "Grype"), scanner("trivy", "Trivy")];
        assert_eq!(
            found_by_line(&two).as_deref(),
            Some("Found by 2 scanners: `Grype`, `Trivy`")
        );
        let one = vec![scanner("trivy", "Trivy")];
        assert_eq!(
            found_by_line(&one).as_deref(),
            Some("Found by 1 scanner: `Trivy`")
        );
        assert_eq!(found_by_line(&[]), None);
    }

    async fn seed(pool: &SqlitePool) -> Result<(), AppError> {
        for sql in [
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES ('i1', 'hub-default-ghcr', 'o/app', 'sha256:a', 1)",
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
             VALUES ('p1', 'i1', 'linux/amd64', 'sha256:p1', 'stored')",
            // Grype: an old run with CVE-OLD, a newer run with CVE-NEW.
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r-old', 'p1', 'grype', 'first_pull', 'done', 10)",
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r-new', 'p1', 'grype', 'db_update', 'done', 20)",
            // A failed run after the done one does not replace it.
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r-failed', 'p1', 'grype', 'db_update', 'failed', 30)",
            // Trivy: a clean run.
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r-trivy', 'p1', 'trivy', 'first_pull', 'done', 15)",
            "INSERT INTO scanner_findings (run_id, cve_id, package, severity)
             VALUES ('r-old', 'CVE-OLD', 'zlib', 'HIGH')",
            "INSERT INTO scanner_findings (run_id, cve_id, package, severity)
             VALUES ('r-new', 'CVE-NEW', 'zlib', 'CRITICAL')",
        ] {
            sqlx::query(sql)
                .execute(pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        }
        Ok(())
    }

    /// The view reads the latest `done` run per (platform, scanner): an older run is history, a
    /// failed run never counts, and a scanner whose run found nothing is still listed.
    #[tokio::test]
    async fn load_reads_the_latest_done_run_of_each_scanner() -> Result<(), AppError> {
        let dir = std::env::temp_dir().join(format!("dockward-merged-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|_| AppError::InternalError)?;
        let pool = db::open(&dir).await?;
        seed(&pool).await?;
        let view = load(&pool, "i1").await?;
        assert_eq!(names_of(&view.scanners), ["Grype", "Trivy"]);
        assert_eq!(view.findings.len(), 1);
        assert_eq!(view.findings[0].cve_id, "CVE-NEW");
        assert_eq!(names_of(&view.findings[0].scanners), ["Grype"]);
        assert_eq!(load(&pool, "no-such-image").await?, MergedDigest::default());
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
