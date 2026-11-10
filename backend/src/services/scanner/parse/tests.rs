use super::*;
use crate::error::{AppError, ScannerFault};

const TRIVY_FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/scanner/trivy-layout.json");
const GRYPE_FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/scanner/grype-layout.json");

fn fault(err: AppError) -> ScannerFault {
    match err {
        AppError::Scanner(fault) => fault,
        other => panic!("expected a scanner fault, got {other:?}"),
    }
}

fn parse_trivy_ok(body: &[u8]) -> Report {
    match parse_trivy(body) {
        Ok(report) => report,
        Err(err) => panic!("expected a Trivy report, got {err:?}"),
    }
}

fn parse_grype_ok(body: &[u8]) -> Report {
    match parse_grype(body) {
        Ok(report) => report,
        Err(err) => panic!("expected a Grype report, got {err:?}"),
    }
}

#[test]
fn trivy_fixture_parses_findings_and_version() {
    let report = parse_trivy_ok(TRIVY_FIXTURE);
    assert_eq!(report.scanner_version, "0.76.2");
    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    assert_eq!(finding.cve_id, "CVE-2026-4738");
    assert_eq!(finding.package, "zlib");
    assert_eq!(finding.version.as_deref(), Some("1.3.2-r1"));
    assert_eq!(finding.fixed_in_version.as_deref(), Some("1.4-r0"));
    assert_eq!(finding.severity, "MEDIUM");
    assert!(finding.description.is_some());
}

#[test]
fn grype_fixture_parses_matches_and_version() {
    let report = parse_grype_ok(GRYPE_FIXTURE);
    assert_eq!(report.scanner_version, "0.121.2");
    assert_eq!(report.findings.len(), 2);

    let zlib = &report.findings[0];
    assert_eq!(zlib.cve_id, "CVE-2026-4738");
    assert_eq!(zlib.package, "zlib");
    assert_eq!(zlib.severity, "CRITICAL");
    assert_eq!(zlib.fixed_in_version.as_deref(), Some("1.4-r0"));
    assert_eq!(
        zlib.cvss_v3, None,
        "the fixture's score is CVSS 4.0, not 3.x"
    );
    assert!(
        zlib.description
            .as_deref()
            .is_some_and(|text| text.starts_with("Improper Restriction")),
        "the description comes from the related record"
    );

    let busybox = &report.findings[1];
    assert_eq!(busybox.package, "busybox");
    assert_eq!(busybox.severity, "MEDIUM");
    assert_eq!(
        busybox.fixed_in_version, None,
        "an empty fix list is no fix"
    );
    assert_eq!(busybox.cvss_v3, Some(6.5));
}

#[test]
fn trivy_wrong_schema_version_is_refused() {
    for body in [
        r#"{"SchemaVersion":1,"Trivy":{"Version":"0.76.2"}}"#,
        r#"{"SchemaVersion":3,"Trivy":{"Version":"0.76.2"}}"#,
        r#"{"Trivy":{"Version":"0.76.2"}}"#,
    ] {
        assert_eq!(
            fault(
                parse_trivy(body.as_bytes())
                    .err()
                    .unwrap_or(AppError::InternalError)
            ),
            ScannerFault::OutputNotRecognised,
            "{body}"
        );
    }
}

#[test]
fn trivy_missing_required_field_is_refused() {
    // Missing InstalledVersion.
    let body = r#"{"SchemaVersion":2,"Trivy":{"Version":"0.76.2"},"Results":[{"Target":"t",
        "Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","Severity":"HIGH"}]}]}"#;
    assert_eq!(
        fault(
            parse_trivy(body.as_bytes())
                .err()
                .unwrap_or(AppError::InternalError)
        ),
        ScannerFault::OutputNotRecognised
    );
}

#[test]
fn trivy_missing_trivy_version_is_refused() {
    let body = r#"{"SchemaVersion":2,"Results":[]}"#;
    assert_eq!(
        fault(
            parse_trivy(body.as_bytes())
                .err()
                .unwrap_or(AppError::InternalError)
        ),
        ScannerFault::OutputNotRecognised
    );
}

#[test]
fn trivy_without_results_is_no_findings() {
    let report = parse_trivy_ok(br#"{"SchemaVersion":2,"Trivy":{"Version":"0.76.2"}}"#);
    assert!(report.findings.is_empty());
    assert_eq!(report.scanner_version, "0.76.2");
}

#[test]
fn trivy_merges_duplicate_cve_and_package() {
    let body = r#"{"SchemaVersion":2,"Trivy":{"Version":"0.76.2"},"Results":[{"Target":"t",
        "Vulnerabilities":[
          {"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH"},
          {"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH"},
          {"VulnerabilityID":"CVE-1","PkgName":"q","InstalledVersion":"1","Severity":"HIGH"}
        ]}]}"#;
    let report = parse_trivy_ok(body.as_bytes());
    assert_eq!(report.findings.len(), 2, "one per (CVE id, package)");
}

#[test]
fn grype_missing_matches_is_refused() {
    let body = r#"{"descriptor":{"version":"0.121.2"}}"#;
    assert_eq!(
        fault(
            parse_grype(body.as_bytes())
                .err()
                .unwrap_or(AppError::InternalError)
        ),
        ScannerFault::OutputNotRecognised
    );
}

#[test]
fn grype_missing_artifact_name_is_refused() {
    let body = r#"{"descriptor":{"version":"0.121.2"},"matches":[{
        "vulnerability":{"id":"CVE-1","severity":"High"},
        "artifact":{"version":"1"}}]}"#;
    assert_eq!(
        fault(
            parse_grype(body.as_bytes())
                .err()
                .unwrap_or(AppError::InternalError)
        ),
        ScannerFault::OutputNotRecognised
    );
}

#[test]
fn grype_missing_vulnerability_is_refused() {
    let body = r#"{"descriptor":{"version":"0.121.2"},"matches":[{
        "artifact":{"name":"p","version":"1"}}]}"#;
    assert_eq!(
        fault(
            parse_grype(body.as_bytes())
                .err()
                .unwrap_or(AppError::InternalError)
        ),
        ScannerFault::OutputNotRecognised
    );
}

#[test]
fn grype_empty_matches_is_no_findings() {
    let report = parse_grype_ok(br#"{"descriptor":{"version":"0.121.2"},"matches":[]}"#);
    assert!(report.findings.is_empty());
}

#[test]
fn malformed_json_is_refused_by_both_readers() {
    let body = b"{\"SchemaVersion\":2,";
    assert_eq!(
        fault(parse_trivy(body).err().unwrap_or(AppError::InternalError)),
        ScannerFault::OutputNotRecognised
    );
    assert_eq!(
        fault(parse_grype(body).err().unwrap_or(AppError::InternalError)),
        ScannerFault::OutputNotRecognised
    );
}

#[test]
fn top_level_array_is_refused() {
    assert_eq!(
        fault(parse_grype(b"[]").err().unwrap_or(AppError::InternalError)),
        ScannerFault::OutputNotRecognised
    );
}

#[test]
fn severity_maps_to_the_stored_set() {
    assert_eq!(normalize_severity("critical"), "CRITICAL");
    assert_eq!(normalize_severity("Negligible"), "LOW");
    assert_eq!(normalize_severity("Medium"), "MEDIUM");
    assert_eq!(normalize_severity("unknown"), "UNKNOWN");
    assert_eq!(normalize_severity("whatever"), "UNKNOWN");
}

#[test]
fn description_is_cut_to_the_stored_length() {
    let long = "x".repeat(MAX_DESCRIPTION_CHARS + 10);
    let cut = cut_description(&long).unwrap_or_default();
    assert_eq!(cut.chars().count(), MAX_DESCRIPTION_CHARS);
}
