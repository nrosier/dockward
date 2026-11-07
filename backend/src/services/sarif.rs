//! Converts a Harbor (Trivy) vulnerability report to SARIF 2.1.0
//! (`specs/integrations.md`, "SARIF conversion and upload", "Converter rules").
//!
//! Pure: the report JSON goes in, the SARIF JSON comes out. No network and no database.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// The `$schema` value written at the top of every document.
pub const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// The fingerprint key. The value is stable across image rebuilds and tags.
pub const FINGERPRINT_KEY: &str = "harborgate/v1";

/// Upper-cases a Trivy severity (`Critical` becomes `CRITICAL`). Unknown values map to
/// `UNKNOWN`, so a new Trivy severity cannot break the converter.
pub fn normalize_severity(value: &str) -> &'static str {
    match value.to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" => "MEDIUM",
        "LOW" => "LOW",
        _ => "UNKNOWN",
    }
}

/// The `security-severity` fallback when there is no CVSS v3 score (Trivy's own mapping).
pub fn fallback_score(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "9.5",
        "HIGH" => "8.0",
        "MEDIUM" => "5.5",
        "LOW" => "2.0",
        _ => "0.0",
    }
}

/// `partialFingerprints["harborgate/v1"]`: SHA-256 of `<vulnerability id>|<package>`.
pub fn fingerprint(vuln_id: &str, package: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{vuln_id}|{package}").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `automationDetails.id` (SARIF 2.1.0 run property): `harborgate/<project>/<repository>/`.
/// The trailing `/` keeps the whole path as the category (`specs/integrations.md`).
pub fn automation_id(project: &str, repository: &str) -> String {
    format!("harborgate/{project}/{repository}/")
}

/// Converts the report. `project` and `repository` name the Harbor repository. Returns the
/// SARIF document as a JSON value, ready to serialize.
pub fn convert(report: &Value, project: &str, repository: &str) -> Result<Value, AppError> {
    let vulns = report
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(AppError::UpstreamUnreachable)?;

    // One rule per vulnerability id. The first occurrence supplies the text.
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results: Vec<Value> = Vec::new();
    let location_uri = format!("{project}/{repository}");

    for vuln in vulns {
        let id = vuln.get("id").and_then(Value::as_str).unwrap_or("UNKNOWN");
        let package = vuln.get("package").and_then(Value::as_str).unwrap_or("");
        let version = vuln.get("version").and_then(Value::as_str).unwrap_or("");
        let severity = normalize_severity(
            vuln.get("severity")
                .and_then(Value::as_str)
                .unwrap_or("Unknown"),
        );
        let description = vuln
            .get("description")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .unwrap_or(id);
        let score = vuln
            .get("preferred_cvss")
            .and_then(|cvss| cvss.get("score_v3"))
            .and_then(Value::as_f64)
            .map(|value| format!("{value:.1}"))
            .unwrap_or_else(|| fallback_score(severity).to_owned());

        rules.entry(id.to_owned()).or_insert_with(|| {
            json!({
                "id": id,
                "shortDescription": { "text": id },
                "fullDescription": { "text": description },
                "help": { "text": description },
                "properties": { "security-severity": score }
            })
        });

        let fix = vuln
            .get("fix_version")
            .and_then(Value::as_str)
            .unwrap_or("");
        let fix_text = if fix.is_empty() {
            "No fixed version is available yet.".to_owned()
        } else {
            format!("Fixed in {fix}.")
        };
        results.push(json!({
            "ruleId": id,
            "message": {
                "text": format!("{id} in {package} {version} ({severity}). {fix_text}")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": location_uri },
                    "region": { "startLine": 1, "startColumn": 1, "endColumn": 1 }
                }
            }],
            "partialFingerprints": { FINGERPRINT_KEY: fingerprint(id, package) }
        }));
    }

    Ok(json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "HarborGate",
                    "rules": rules.into_values().collect::<Vec<Value>>()
                }
            },
            "automationDetails": { "id": automation_id(project, repository) },
            "results": results
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spec-derived report. Values are fake and use the Trivy field names the spec records.
    fn report() -> Value {
        json!({
            "generated_at": "2026-11-03T00:00:00Z",
            "vulnerabilities": [
                {
                    "id": "CVE-2026-0001",
                    "package": "libfake",
                    "version": "1.0.0",
                    "fix_version": "1.0.1",
                    "severity": "Critical",
                    "description": "A fake critical flaw.",
                    "preferred_cvss": { "score_v3": 9.8 }
                },
                {
                    "id": "CVE-2026-0002",
                    "package": "libother",
                    "version": "2.0.0",
                    "severity": "High",
                    "description": "A fake high flaw."
                }
            ]
        })
    }

    #[test]
    fn document_has_schema_version_one_run_and_driver_name() {
        let doc = convert(&report(), "proj", "app").unwrap();
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["$schema"], SARIF_SCHEMA);
        assert_eq!(doc["runs"].as_array().unwrap().len(), 1);
        assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "HarborGate");
    }

    #[test]
    fn automation_id_keeps_the_repository_path_as_category() {
        let doc = convert(&report(), "proj", "team/app").unwrap();
        assert_eq!(
            doc["runs"][0]["automationDetails"]["id"],
            "harborgate/proj/team/app/"
        );
    }

    /// #185: the category is `harborgate/<project>/<repository>`, one per Harbor repository,
    /// so two mappings on one GitHub repository upload under two different categories.
    #[test]
    fn category_is_per_harbor_repository() {
        let category = |id: &str| id.rsplit_once('/').map(|(c, _)| c.to_owned()).unwrap();
        let api = convert(&report(), "proj", "api").unwrap();
        let web = convert(&report(), "proj", "web").unwrap();
        let api_id = api["runs"][0]["automationDetails"]["id"].as_str().unwrap();
        let web_id = web["runs"][0]["automationDetails"]["id"].as_str().unwrap();
        assert_eq!(category(api_id), "harborgate/proj/api");
        assert_eq!(category(web_id), "harborgate/proj/web");
        assert_ne!(category(api_id), category(web_id));
    }

    #[test]
    fn cvss_v3_score_is_used_when_present() {
        let doc = convert(&report(), "proj", "app").unwrap();
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let critical = rules.iter().find(|r| r["id"] == "CVE-2026-0001").unwrap();
        assert_eq!(critical["properties"]["security-severity"], "9.8");
    }

    #[test]
    fn severity_fallback_applies_without_a_cvss_score() {
        let doc = convert(&report(), "proj", "app").unwrap();
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let high = rules.iter().find(|r| r["id"] == "CVE-2026-0002").unwrap();
        assert_eq!(high["properties"]["security-severity"], "8.0");
    }

    #[test]
    fn rule_has_the_required_text_fields() {
        let doc = convert(&report(), "proj", "app").unwrap();
        let rule = &doc["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule["shortDescription"]["text"].is_string());
        assert!(rule["fullDescription"]["text"].is_string());
        assert!(rule["help"]["text"].is_string());
    }

    #[test]
    fn result_location_is_the_repository_at_line_one_column_one() {
        let doc = convert(&report(), "proj", "app").unwrap();
        let loc = &doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "proj/app");
        assert_eq!(loc["region"]["startLine"], 1);
        assert_eq!(loc["region"]["startColumn"], 1);
    }

    #[test]
    fn fingerprint_is_stable_and_uses_the_v1_key() {
        let a = convert(&report(), "proj", "app").unwrap();
        let b = convert(&report(), "proj", "app").unwrap();
        let fp_a = &a["runs"][0]["results"][0]["partialFingerprints"][FINGERPRINT_KEY];
        let fp_b = &b["runs"][0]["results"][0]["partialFingerprints"][FINGERPRINT_KEY];
        assert_eq!(fp_a, fp_b);
        assert_eq!(fp_a.as_str().unwrap().len(), 64);
    }

    #[test]
    fn fingerprint_depends_only_on_vulnerability_id_and_package() {
        // The hash input is "<id>|<package>". A tag or digest is not an input, so an image
        // rebuild or a new tag keeps the same fingerprint for the same finding.
        assert_eq!(
            fingerprint("CVE-2026-0001", "libfake"),
            hex_sha256("CVE-2026-0001|libfake")
        );
        assert_ne!(
            fingerprint("CVE-2026-0001", "libfake"),
            fingerprint("CVE-2026-0001", "libother")
        );
    }

    fn hex_sha256(text: &str) -> String {
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn title_case_severity_is_upper_cased_and_unknown_is_safe() {
        assert_eq!(normalize_severity("Critical"), "CRITICAL");
        assert_eq!(normalize_severity("medium"), "MEDIUM");
        assert_eq!(normalize_severity("bogus"), "UNKNOWN");
    }

    #[test]
    fn a_report_without_vulnerabilities_is_an_error() {
        assert!(convert(&json!({}), "proj", "app").is_err());
    }

    #[test]
    fn duplicate_ids_share_one_rule() {
        let mut doc_report = report();
        let copy = doc_report["vulnerabilities"][0].clone();
        doc_report["vulnerabilities"]
            .as_array_mut()
            .unwrap()
            .push(copy);
        let doc = convert(&doc_report, "proj", "app").unwrap();
        assert_eq!(
            doc["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 3);
    }

    /// The vendored OASIS SARIF 2.1.0 schema (errata 01), draft-04.
    fn schema() -> Value {
        serde_json::from_str(include_str!("../../tests/schemas/sarif-schema-2.1.0.json"))
            .expect("the vendored SARIF schema is valid JSON")
    }

    /// Validates `doc` against the vendored schema and returns every error, one per line.
    /// An empty list means the document is valid.
    fn schema_errors(doc: &Value) -> Vec<String> {
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft4)
            .build(&schema())
            .unwrap_or_else(|err| panic!("the vendored SARIF schema does not compile: {err}"));
        validator
            .iter_errors(doc)
            .map(|err| format!("{err} (at {})", err.instance_path()))
            .collect()
    }

    fn assert_schema_valid(doc: &Value) {
        let errors = schema_errors(doc);
        assert!(
            errors.is_empty(),
            "SARIF output failed schema validation:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn output_validates_against_the_sarif_schema() {
        // Fixture 1: one CVE with a CVSS v3 score.
        let single = json!({
            "vulnerabilities": [{
                "id": "CVE-2026-0001",
                "package": "libfake",
                "version": "1.0.0",
                "fix_version": "1.0.1",
                "severity": "Critical",
                "description": "A fake critical flaw.",
                "preferred_cvss": { "score_v3": 9.8 }
            }]
        });
        assert_schema_valid(&convert(&single, "proj", "app").unwrap());

        // Fixture 2: several CVEs, one of them a duplicate id, with and without a fix.
        let mut several = report();
        let copy = several["vulnerabilities"][0].clone();
        several["vulnerabilities"]
            .as_array_mut()
            .unwrap()
            .push(copy);
        assert_schema_valid(&convert(&several, "proj", "team/app").unwrap());
    }

    #[test]
    fn empty_report_validates_against_the_sarif_schema() {
        let empty = json!({ "vulnerabilities": [] });
        assert_schema_valid(&convert(&empty, "proj", "app").unwrap());
    }

    #[test]
    fn schema_rejects_a_broken_document() {
        // Removing the required `version` must fail. This proves the validator really runs.
        let mut doc = convert(&report(), "proj", "app").unwrap();
        doc.as_object_mut().unwrap().remove("version");
        assert!(
            !schema_errors(&doc).is_empty(),
            "a SARIF document without `version` passed validation"
        );
    }
}
