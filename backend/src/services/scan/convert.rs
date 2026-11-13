//! The convert step (`specs/spinoff-local-scan.md`, section 6 step 5; `specs/cve-lifecycle.md`,
//! "Merged view").
//!
//! After a scan run finishes, the merged `cve_findings` of every tag whose current image holds
//! the platform are recomputed from the merged view of that image. The caller runs this inside
//! the transaction that stores the run's findings, so a reader never sees the run without its
//! tags' rows.
//!
//! Rules:
//! - The merged view reads the latest `done` run per (platform image, scanner). A failed run is
//!   never `done`, so it changes nothing here.
//! - `cve_findings` has one row per (source, tag, CVE id). A CVE with several packages in one tag
//!   is one row: the package, versions and text come from the first finding in the merged order
//!   (CVE id, then package), and the severity is the highest over its packages.
//! - A CVE the tag had `open` that no scanner of the image reports any more becomes `fixed`.
//!   Whether a GitHub issue may close is decided later by the issue rules, which wait for every
//!   enabled scanner (#224 d14), so a missing scanner never closes one.

use std::collections::HashSet;

use sqlx::SqliteConnection;

use crate::db::findings::{self, Finding};
use crate::db::scans as scans_db;
use crate::error::AppError;
use crate::services::ids;
use crate::services::merged_view::{self, MergedFinding};

/// Highest first, as in `specs/cve-lifecycle.md`.
const SEVERITY_ORDER: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

fn rank(severity: &str) -> usize {
    SEVERITY_ORDER
        .iter()
        .position(|known| *known == severity)
        .unwrap_or(SEVERITY_ORDER.len())
}

/// One CVE of the merged view, reduced to the row `cve_findings` stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveRow {
    pub cve_id: String,
    pub package: Option<String>,
    pub severity: &'static str,
    pub fixed_in_version: Option<String>,
    pub description: Option<String>,
    pub alias: Option<String>,
    /// The keys of the scanners that report the CVE (any package), in the merged-view order (#366).
    pub scanners: Vec<String>,
}

/// One row per CVE id from the merged findings, which arrive sorted by (CVE id, package).
pub fn per_cve(findings: &[MergedFinding]) -> Vec<CveRow> {
    let mut rows: Vec<CveRow> = Vec::new();
    for finding in findings {
        if let Some(last) = rows.last_mut()
            && last.cve_id == finding.cve_id
        {
            if rank(finding.severity) < rank(last.severity) {
                last.severity = finding.severity;
            }
            let keys: Vec<String> = last
                .scanners
                .iter()
                .cloned()
                .chain(finding.scanners.iter().map(|scanner| scanner.key.clone()))
                .collect();
            last.scanners = merged_view::order_scanners(&keys)
                .into_iter()
                .map(|scanner| scanner.key)
                .collect();
            continue;
        }
        rows.push(CveRow {
            cve_id: finding.cve_id.clone(),
            package: Some(finding.package.clone()).filter(|package| !package.is_empty()),
            severity: finding.severity,
            fixed_in_version: finding.fixed_in_version.clone(),
            description: finding.description.clone(),
            alias: finding.alias.clone(),
            scanners: finding
                .scanners
                .iter()
                .map(|scanner| scanner.key.clone())
                .collect(),
        });
    }
    rows
}

/// Recomputes the `cve_findings` of every tag whose current image is `image_id`. Returns the
/// number of tags updated.
pub async fn recompute_image(
    conn: &mut SqliteConnection,
    image_id: &str,
    now: i64,
) -> Result<usize, AppError> {
    let tags = scans_db::current_tags_of_image_all(conn, image_id).await?;
    if tags.is_empty() {
        return Ok(0);
    }
    let merged = merged_view::load_in(conn, image_id).await?;
    let rows = per_cve(&merged.findings);
    let reported: HashSet<&str> = rows.iter().map(|row| row.cve_id.as_str()).collect();
    for tag in &tags {
        for row in &rows {
            let id = ids::new_id()?;
            findings::upsert(
                conn,
                &Finding {
                    id: &id,
                    source_id: &tag.source_id,
                    image_tag: &tag.tag,
                    cve_id: &row.cve_id,
                    package: row.package.as_deref(),
                    severity: row.severity,
                    fixed_in_version: row.fixed_in_version.as_deref(),
                    description: row.description.as_deref(),
                    alias: row.alias.as_deref(),
                    now,
                },
            )
            .await?;
            findings::set_scanners(
                conn,
                &tag.source_id,
                &tag.tag,
                &row.cve_id,
                &row.scanners.join(","),
            )
            .await?;
        }
        for cve_id in scans_db::open_cve_ids(conn, &tag.source_id, &tag.tag).await? {
            if !reported.contains(cve_id.as_str()) {
                scans_db::mark_fixed(conn, &tag.source_id, &tag.tag, &cve_id).await?;
            }
        }
    }
    Ok(tags.len())
}
