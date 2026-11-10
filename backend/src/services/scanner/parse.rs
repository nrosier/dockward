//! Strict readers for the Trivy and Grype JSON reports (`specs/spinoff-local-scan.md`, section 7;
//! decision 29 for the verified field names; decision 2 of the earlier design for the merge key).
//!
//! Every field a finding needs is required. A missing one fails the whole parse with
//! `scanner output not recognised`, so a partial report is never stored. Unknown fields are
//! ignored. A report whose top level is not an object fails. Trivy's `Results` may be absent when
//! there are no findings (decision 29), and that is read as no findings.
//!
//! This module holds no database code and no process code.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;
use serde_json::Value;

use crate::error::{AppError, ScannerFault};

/// The only Trivy `SchemaVersion` the reader accepts (decision 29; the Trivy reporting docs).
pub const TRIVY_SCHEMA_VERSION: u64 = 2;

/// One finding in a scanner report, ready to store. One per (CVE id, package). The merge key of
/// `scanner_findings` is `(run_id, cve_id, package)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub cve_id: String,
    pub package: String,
    pub version: Option<String>,
    pub fixed_in_version: Option<String>,
    /// One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
    pub severity: &'static str,
    pub cvss_v3: Option<f64>,
    /// At most 4,000 characters.
    pub description: Option<String>,
}

/// A parsed scanner report: the scanner's own version (stored with the run, section 7) and the
/// findings merged by (CVE id, package).
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub scanner_version: String,
    pub findings: Vec<Finding>,
}

/// Maximum stored description length in characters (`scanner_findings.description`).
pub const MAX_DESCRIPTION_CHARS: usize = 4_000;

/// Normalises a scanner severity to the stored upper-case set. `Negligible` maps to `LOW`
/// (`specs/spinoff-local-scan.md`, section 7). Anything else is `UNKNOWN`.
pub fn normalize_severity(value: &str) -> &'static str {
    match value.to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" => "MEDIUM",
        "LOW" | "NEGLIGIBLE" => "LOW",
        _ => "UNKNOWN",
    }
}

/// Cuts a description to [`MAX_DESCRIPTION_CHARS`] characters.
fn cut_description(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    Some(text.chars().take(MAX_DESCRIPTION_CHARS).collect())
}

fn not_recognised() -> AppError {
    AppError::Scanner(ScannerFault::OutputNotRecognised)
}

/// Merges findings by (CVE id, package), keeping the first occurrence in input order.
pub fn merge_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashSet<(String, String)> = HashSet::with_capacity(findings.len());
    let mut out = Vec::with_capacity(findings.len());
    for finding in findings {
        let key = (finding.cve_id.clone(), finding.package.clone());
        if seen.insert(key) {
            out.push(finding);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Trivy
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyTop {
    schema_version: Option<u64>,
    #[serde(rename = "Trivy")]
    trivy: TrivyInfo,
    #[serde(default)]
    results: Option<Vec<TrivyResult>>,
}

#[derive(Deserialize)]
struct TrivyInfo {
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyResult {
    #[serde(default)]
    vulnerabilities: Option<Vec<TrivyVuln>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    installed_version: String,
    #[serde(rename = "FixedVersion", default)]
    fixed_version: Option<String>,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "CVSS", default)]
    cvss: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    description: Option<String>,
}

/// Reads a Trivy `image` JSON report. `SchemaVersion` must be 2, and `Trivy.Version` must be
/// present. A missing `Results` means no findings.
pub fn parse_trivy(body: &[u8]) -> Result<Report, AppError> {
    let top: TrivyTop = serde_json::from_slice(body).map_err(|_| not_recognised())?;
    if top.schema_version != Some(TRIVY_SCHEMA_VERSION) || top.trivy.version.is_empty() {
        return Err(not_recognised());
    }
    let mut findings = Vec::new();
    for result in top.results.unwrap_or_default() {
        for vuln in result.vulnerabilities.unwrap_or_default() {
            findings.push(trivy_finding(vuln)?);
        }
    }
    Ok(Report {
        scanner_version: top.trivy.version,
        findings: merge_findings(findings),
    })
}

fn trivy_finding(vuln: TrivyVuln) -> Result<Finding, AppError> {
    if vuln.vulnerability_id.is_empty() || vuln.pkg_name.is_empty() {
        return Err(not_recognised());
    }
    let cvss_v3 = vuln.cvss.as_ref().and_then(|sources| {
        sources
            .values()
            .filter_map(|source| source.get("V3Score").and_then(Value::as_f64))
            .fold(None, |best: Option<f64>, score| match best {
                Some(current) if current >= score => Some(current),
                _ => Some(score),
            })
    });
    Ok(Finding {
        cve_id: vuln.vulnerability_id,
        package: vuln.pkg_name,
        version: Some(vuln.installed_version).filter(|v| !v.is_empty()),
        fixed_in_version: vuln.fixed_version.filter(|v| !v.is_empty()),
        severity: normalize_severity(&vuln.severity),
        cvss_v3,
        description: cut_description(vuln.description.as_deref().unwrap_or_default()),
    })
}

// ---------------------------------------------------------------------------
// Grype
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GrypeTop {
    matches: Vec<GrypeMatch>,
    descriptor: GrypeDescriptor,
}

#[derive(Deserialize)]
struct GrypeDescriptor {
    version: String,
}

#[derive(Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVuln,
    artifact: GrypeArtifact,
    #[serde(rename = "relatedVulnerabilities", default)]
    related: Vec<GrypeRelated>,
}

#[derive(Deserialize)]
struct GrypeVuln {
    id: String,
    severity: String,
    #[serde(default)]
    fix: Option<GrypeFix>,
    #[serde(default)]
    cvss: Vec<GrypeCvss>,
}

#[derive(Deserialize)]
struct GrypeFix {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct GrypeCvss {
    #[serde(default)]
    metrics: Option<GrypeMetrics>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct GrypeMetrics {
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
}

#[derive(Deserialize)]
struct GrypeArtifact {
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct GrypeRelated {
    id: String,
    #[serde(default)]
    description: Option<String>,
}

/// Reads a Grype JSON report. The top level must be an object with a `matches` array and a
/// `descriptor.version`, and every match needs `vulnerability` (with `id` and `severity`) and
/// `artifact` (with `name` and `version`). An empty `matches` is no findings.
pub fn parse_grype(body: &[u8]) -> Result<Report, AppError> {
    let top: GrypeTop = serde_json::from_slice(body).map_err(|_| not_recognised())?;
    if top.descriptor.version.is_empty() {
        return Err(not_recognised());
    }
    let mut findings = Vec::with_capacity(top.matches.len());
    for item in top.matches {
        findings.push(grype_finding(item)?);
    }
    Ok(Report {
        scanner_version: top.descriptor.version,
        findings: merge_findings(findings),
    })
}

fn grype_finding(item: GrypeMatch) -> Result<Finding, AppError> {
    let vuln = item.vulnerability;
    if vuln.id.is_empty() || item.artifact.name.is_empty() {
        return Err(not_recognised());
    }
    // The description is on the related record, not the primary one (decision 29). The first
    // related record with a description is used.
    let description = item
        .related
        .iter()
        .find(|related| related.id == vuln.id)
        .or_else(|| item.related.first())
        .and_then(|related| related.description.as_deref())
        .and_then(cut_description);
    let cvss_v3 = vuln
        .cvss
        .iter()
        .find(|c| c.version.as_deref().is_some_and(|v| v.starts_with('3')))
        .and_then(|c| c.metrics.as_ref())
        .and_then(|m| m.base_score);
    let fixed_in_version = vuln
        .fix
        .as_ref()
        .and_then(|fix| fix.versions.first().cloned())
        .filter(|v| !v.is_empty());
    Ok(Finding {
        cve_id: vuln.id,
        package: item.artifact.name,
        version: Some(item.artifact.version).filter(|v| !v.is_empty()),
        fixed_in_version,
        severity: normalize_severity(&vuln.severity),
        cvss_v3,
        description,
    })
}

#[cfg(test)]
mod tests;
