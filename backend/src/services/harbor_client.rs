//! Harbor API reads for one sync: the artifact labels and the vulnerability report
//! (`specs/integrations.md`, Harbor API and OCI labels).
//!
//! Every request goes through the checked outbound client (`TargetClass::Harbor`), so
//! the HTTPS and address checks apply. The response parsing is pure and is tested
//! against spec-derived fixtures (see the tests).

use std::collections::BTreeMap;

use reqwest::Url;
use serde::Deserialize;

use crate::error::AppError;
use crate::services::credential_probe::{encode_repository_path, encode_segment};

/// MIME type the vulnerability endpoint is asked for, and the key of the response object.
pub const TRIVY_REPORT_MIME: &str = "application/vnd.security.vulnerability.report; version=1.1";

/// Fetches one GET from Harbor through the checked client, with the robot's basic
/// auth. Returns the status and the body. The secret is held in a local buffer only.
pub struct HarborGet {
    client: crate::services::outbound::OutboundClient,
}

impl HarborGet {
    pub fn new(allow_private: bool) -> Result<Self, AppError> {
        let client = crate::services::outbound::client(
            crate::services::outbound::TargetClass::Harbor,
            allow_private,
        )
        .map_err(|_| AppError::InternalError)?;
        Ok(Self { client })
    }

    /// Sends `GET url` with HTTP Basic auth and the given extra headers.
    pub async fn get(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<(u16, Vec<u8>), AppError> {
        let secret = std::str::from_utf8(secret).map_err(|_| AppError::InternalError)?;
        let mut request = self
            .client
            .get(url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(username, Some(secret));
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        let response = request
            .send()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?
            .to_vec();
        Ok((status, body))
    }
}

/// OCI label carrying the commit SHA. Required.
pub const LABEL_REVISION: &str = "org.opencontainers.image.revision";
/// OCI label naming the source repository. Checked against the mapping when present.
pub const LABEL_SOURCE: &str = "org.opencontainers.image.source";
/// HarborGate branch label. Overrides the mapping's `default_branch` when present.
pub const LABEL_BRANCH: &str = "io.github.nrosier.harborgate.branch";

/// The labels HarborGate reads from one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArtifactLabels {
    pub revision: Option<String>,
    pub source: Option<String>,
    pub branch: Option<String>,
}

/// The shape of `GET .../artifacts/{reference}`, reduced to the config labels.
#[derive(Debug, Deserialize)]
struct ArtifactBody {
    #[serde(default)]
    extra_attrs: Option<ExtraAttrs>,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct ExtraAttrs {
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
}

/// Reads the labels from an artifact JSON body. Labels may sit at the top level or under
/// `extra_attrs` in Harbor's responses, so both are read, with the top level winning.
pub fn parse_labels(body: &[u8]) -> Result<ArtifactLabels, AppError> {
    let parsed: ArtifactBody = serde_json::from_slice(body).map_err(|_| AppError::InternalError)?;
    let mut merged: BTreeMap<String, String> = parsed
        .extra_attrs
        .and_then(|attrs| attrs.labels)
        .unwrap_or_default();
    for (key, value) in parsed.labels.unwrap_or_default() {
        merged.insert(key, value);
    }
    Ok(ArtifactLabels {
        revision: merged.get(LABEL_REVISION).cloned(),
        source: merged.get(LABEL_SOURCE).cloned(),
        branch: merged.get(LABEL_BRANCH).cloned(),
    })
}

/// Builds the artifact URL for a digest. Every name segment is encoded, and the
/// repository components are joined with `%252F` (`specs/integrations.md`).
pub fn artifact_url(
    base: &Url,
    project: &str,
    repository: &str,
    digest: &str,
) -> Result<Url, AppError> {
    let path = format!(
        "api/v2.0/projects/{}/repositories/{}/artifacts/{}",
        encode_segment(project),
        encode_repository_path(repository),
        encode_segment(digest)
    );
    base.join(&path).map_err(|_| invalid_name())
}

/// Builds the vulnerability report URL for a digest. Encoding as in [`artifact_url`].
pub fn vulnerabilities_url(
    base: &Url,
    project: &str,
    repository: &str,
    digest: &str,
) -> Result<Url, AppError> {
    let path = format!(
        "api/v2.0/projects/{}/repositories/{}/artifacts/{}/additions/vulnerabilities",
        encode_segment(project),
        encode_repository_path(repository),
        encode_segment(digest)
    );
    base.join(&path).map_err(|_| invalid_name())
}

fn invalid_name() -> AppError {
    AppError::ValidationFailed("the Harbor project or repository name is not valid.".to_owned())
}

/// What the vulnerability endpoint answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportState {
    /// The report for the Trivy MIME type is present.
    Ready(serde_json::Value),
    /// `{}`: the report is not visible yet. Retried with backoff.
    NotYet,
}

/// Reads the MIME-keyed vulnerability response. `{}` is `NotYet`. The report is taken
/// by its MIME key, so another key is `NotYet` too (`specs/integrations.md`).
pub fn parse_report(body: &[u8]) -> Result<ReportState, AppError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    let object = value.as_object().ok_or(AppError::UpstreamUnreachable)?;
    match object.get(TRIVY_REPORT_MIME) {
        Some(report) => Ok(ReportState::Ready(report.clone())),
        None => Ok(ReportState::NotYet),
    }
}

/// Fails the sync when the commit SHA label is missing (`specs/integrations.md`).
pub fn require_revision(labels: &ArtifactLabels) -> Result<&str, AppError> {
    labels
        .revision
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::ValidationFailed(
                "the image has no org.opencontainers.image.revision label, so the commit is unknown."
                    .to_owned(),
            )
        })
}

/// Compares the `source` label with the mapping's GitHub target, case-insensitively and
/// ignoring a trailing `/` or `.git` (`specs/integrations.md`). Absent means proceed.
pub fn check_source(labels: &ArtifactLabels, owner: &str, repo: &str) -> Result<(), AppError> {
    let Some(source) = labels.source.as_deref() else {
        return Ok(());
    };
    let normalized = normalize_source(source);
    let expected = normalize_source(&format!("https://github.com/{owner}/{repo}"));
    if normalized == expected {
        Ok(())
    } else {
        Err(AppError::ValidationFailed(
            "the image source label does not match this mapping's GitHub repository.".to_owned(),
        ))
    }
}

fn normalize_source(value: &str) -> String {
    let lowered = value.trim().to_ascii_lowercase();
    let trimmed = lowered.trim_end_matches('/');
    trimmed.strip_suffix(".git").unwrap_or(trimmed).to_owned()
}

/// The branch to upload to: the HarborGate label, otherwise the mapping's default branch.
pub fn branch_for(labels: &ArtifactLabels, default_branch: &str) -> String {
    labels
        .branch
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(default_branch)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spec-derived artifact body. Harbor's real response was not captured here; this
    /// follows the shape recorded in `specs/integrations.md`. Values are fake.
    const ARTIFACT: &str = r#"{
        "digest": "sha256:aaaa",
        "extra_attrs": {"labels": {
            "org.opencontainers.image.revision": "0123456789abcdef0123456789abcdef01234567",
            "org.opencontainers.image.source": "https://github.com/octo/app"
        }},
        "labels": {"io.github.nrosier.harborgate.branch": "release"}
    }"#;

    #[test]
    fn labels_are_read_from_both_places() {
        let labels = parse_labels(ARTIFACT.as_bytes()).unwrap();
        assert_eq!(
            labels.revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            labels.source.as_deref(),
            Some("https://github.com/octo/app")
        );
        assert_eq!(labels.branch.as_deref(), Some("release"));
    }

    #[test]
    fn missing_revision_fails_with_a_clear_error() {
        let body = r#"{"extra_attrs": {"labels": {}}}"#;
        let labels = parse_labels(body.as_bytes()).unwrap();
        let err = require_revision(&labels).unwrap_err();
        assert!(matches!(err, AppError::ValidationFailed(ref msg) if msg.contains("revision")));
    }

    #[test]
    fn source_label_must_match_the_mapping_ignoring_case_and_suffixes() {
        let labels = ArtifactLabels {
            source: Some("HTTPS://github.com/Octo/App.git/".to_owned()),
            ..Default::default()
        };
        assert!(check_source(&labels, "octo", "app").is_ok());
        let other = ArtifactLabels {
            source: Some("https://github.com/octo/other".to_owned()),
            ..Default::default()
        };
        assert!(check_source(&other, "octo", "app").is_err());
    }

    #[test]
    fn absent_source_label_proceeds() {
        assert!(check_source(&ArtifactLabels::default(), "octo", "app").is_ok());
    }

    #[test]
    fn branch_label_overrides_the_default_branch() {
        let labels = parse_labels(ARTIFACT.as_bytes()).unwrap();
        assert_eq!(branch_for(&labels, "main"), "release");
        assert_eq!(branch_for(&ArtifactLabels::default(), "main"), "main");
    }

    /// A captured-shape report: the MIME-keyed object from `specs/integrations.md`.
    const REPORT: &str = r#"{
        "application/vnd.security.vulnerability.report; version=1.1": {
            "generated_at": "2026-11-03T00:00:00Z",
            "scanner": {"name": "Trivy"},
            "severity": "Critical",
            "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "Critical", "fix_version": "1.2.4"}]
        }
    }"#;

    #[test]
    fn report_is_taken_by_its_mime_key() {
        match parse_report(REPORT.as_bytes()).unwrap() {
            ReportState::Ready(report) => {
                assert_eq!(report["vulnerabilities"][0]["fix_version"], "1.2.4");
            }
            ReportState::NotYet => panic!("expected a report"),
        }
    }

    #[test]
    fn empty_object_means_not_yet() {
        assert_eq!(parse_report(b"{}").unwrap(), ReportState::NotYet);
    }

    #[test]
    fn another_mime_key_means_not_yet() {
        let body = r#"{"application/other": {}}"#;
        assert_eq!(parse_report(body.as_bytes()).unwrap(), ReportState::NotYet);
    }

    #[test]
    fn repository_slash_is_encoded_twice_in_both_urls() {
        let base = Url::parse("https://harbor.example.com").unwrap();
        let artifact = artifact_url(&base, "proj", "team/app", "sha256:aaaa").unwrap();
        assert_eq!(
            artifact.as_str(),
            "https://harbor.example.com/api/v2.0/projects/proj/repositories/team%252Fapp/artifacts/sha256%3Aaaaa"
        );
        let report = vulnerabilities_url(&base, "proj", "team/app", "sha256:aaaa").unwrap();
        assert_eq!(
            report.as_str(),
            "https://harbor.example.com/api/v2.0/projects/proj/repositories/team%252Fapp/artifacts/sha256%3Aaaaa/additions/vulnerabilities"
        );
    }
}
