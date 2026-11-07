//! Harbor API reads for one sync: the artifact labels and the vulnerability report
//! (`specs/integrations.md`, Harbor API and OCI labels).
//!
//! Every request goes through the checked outbound client (`TargetClass::Harbor`), so
//! the HTTPS and address checks apply. The response parsing is pure and is tested
//! against spec-derived fixtures (see the tests).

use std::collections::BTreeMap;

use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::AppError;
use crate::services::credential_probe::{encode_repository_path, encode_segment};

/// MIME type the vulnerability endpoint is asked for, and the key of the response object.
pub const TRIVY_REPORT_MIME: &str = "application/vnd.security.vulnerability.report; version=1.1";

/// What one Harbor GET answered: the status, the body, and the `Retry-After` header when
/// Harbor sent one as a whole number of seconds (#132). A rate-limited resolve job reads it
/// to decide how long to wait. The header is not read for any other purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarborReply {
    pub status: u16,
    pub body: Vec<u8>,
    pub retry_after: Option<u64>,
}

impl HarborReply {
    /// A reply with no `Retry-After` header.
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            retry_after: None,
        }
    }
}

/// Reads a `Retry-After` value as delta-seconds (RFC 9110 section 10.2.3). The HTTP-date form
/// and anything that is not a plain non-negative integer is `None`, so it counts as absent.
pub fn parse_retry_after(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse().ok()
}

/// Fetches one GET from Harbor through the checked client, with the robot's basic
/// auth. Returns the status, the body and `Retry-After`. The secret is held in a local
/// buffer only.
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
    ) -> Result<HarborReply, AppError> {
        let secret = std::str::from_utf8(secret).map_err(|_| AppError::InternalError)?;
        let mut request = self
            .client
            .get(url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(username, Some(secret));
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        read_reply("GET", url, request).await
    }

    /// Sends `POST url` with HTTP Basic auth, a JSON body and the given extra headers. Used to
    /// start a scan (#191, #224). Returns the status, the body and `Retry-After`, like
    /// [`HarborGet::get`].
    pub async fn post_json(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        let secret = std::str::from_utf8(secret).map_err(|_| AppError::InternalError)?;
        let mut request = self
            .client
            .post(url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(username, Some(secret))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec());
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        read_reply("POST", url, request).await
    }

    /// Sends `PUT url` with HTTP Basic auth, a JSON body and the given extra headers. Used only to
    /// set the project scanner (#224). Returns the status, the body and `Retry-After`, like
    /// [`HarborGet::get`].
    pub async fn put_json(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        let secret = std::str::from_utf8(secret).map_err(|_| AppError::InternalError)?;
        let mut request = self
            .client
            .put(url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(username, Some(secret))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec());
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        read_reply("PUT", url, request).await
    }
}

/// Sends one prepared request and reads the status, `Retry-After` and body. Both the GET and the
/// POST go through it, so the logging and the response handling stay in one place.
async fn read_reply(
    method: &str,
    url: &Url,
    request: reqwest::RequestBuilder,
) -> Result<HarborReply, AppError> {
    let sent = request.send().await;
    crate::services::app_log::log_outbound(
        method,
        url,
        sent.as_ref().ok().map(|r| r.status().as_u16()),
    );
    let response = sent.map_err(|_| AppError::UpstreamUnreachable)?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after);
    let body = response
        .bytes()
        .await
        .map_err(|_| AppError::UpstreamUnreachable)?
        .to_vec();
    Ok(HarborReply {
        status,
        body,
        retry_after,
    })
}

/// The body of a scan request: a vulnerability scan (Harbor swagger, `scanArtifact`, `ScanType`).
pub const SCAN_REQUEST_BODY: &[u8] = br#"{"scan_type":"vulnerability"}"#;

/// Builds the scan URL for a digest (`POST .../artifacts/{reference}/scan`, Harbor swagger
/// `scanArtifact`). Encoding as in [`artifact_url`].
pub fn scan_url(
    base: &Url,
    project: &str,
    repository: &str,
    digest: &str,
) -> Result<Url, AppError> {
    let path = format!(
        "api/v2.0/projects/{}/repositories/{}/artifacts/{}/scan",
        encode_segment(project),
        encode_repository_path(repository),
        encode_segment(digest)
    );
    base.join(&path).map_err(|_| invalid_name())
}

/// Header Harbor needs on project paths, so a numeric project name is read as a name and not an
/// id (swagger `isResourceName`, #224).
pub const PROJECT_NAME_HEADER: (&str, &str) = ("X-Is-Resource-Name", "true");

/// The most scanner registrations read from the candidates list: 100 per page, at most 10 pages,
/// the same cap as the other Harbor lists (`specs/integrations.md`, "Scanner choice and listing").
pub const SCANNER_PAGE_SIZE: u32 = 100;
pub const SCANNER_MAX_PAGES: u32 = 10;

/// Builds the project scanner URL (`GET` and `PUT .../projects/{p}/scanner`, #224).
pub fn project_scanner_url(base: &Url, project: &str) -> Result<Url, AppError> {
    let path = format!("api/v2.0/projects/{}/scanner", encode_segment(project));
    base.join(&path).map_err(|_| invalid_name())
}

/// Builds the scanner candidates URL for one page (`GET .../scanner/candidates`, #224).
pub fn scanner_candidates_url(base: &Url, project: &str, page: u32) -> Result<Url, AppError> {
    let path = format!(
        "api/v2.0/projects/{}/scanner/candidates",
        encode_segment(project)
    );
    let mut url = base.join(&path).map_err(|_| invalid_name())?;
    url.query_pairs_mut()
        .append_pair("page", &page.to_string())
        .append_pair("page_size", &SCANNER_PAGE_SIZE.to_string());
    Ok(url)
}

/// Builds the artifact URL with `with_scan_overview=true`, which carries `scan_overview` (#224).
pub fn artifact_overview_url(
    base: &Url,
    project: &str,
    repository: &str,
    digest: &str,
) -> Result<Url, AppError> {
    let mut url = artifact_url(base, project, repository, digest)?;
    url.query_pairs_mut()
        .append_pair("with_scan_overview", "true");
    Ok(url)
}

/// The body of `PUT .../projects/{p}/scanner` (`{"uuid"}`, swagger `setScannerOfProject`).
pub fn set_scanner_body(uuid: &str) -> Vec<u8> {
    json!({ "uuid": uuid }).to_string().into_bytes()
}

/// One Harbor scanner registration, as HarborGate reads it. Only these fields are read: `url`,
/// `auth` and `access_credential` have no field here, so they cannot be stored or logged
/// (`specs/integrations.md`, "Harbor calls").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerRegistration {
    pub uuid: String,
    pub name: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub disabled: bool,
}

#[derive(Debug, Deserialize)]
struct RawScanner {
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

impl RawScanner {
    /// A registration with no UUID cannot be keyed, so it is `None`.
    fn into_registration(self) -> Option<ScannerRegistration> {
        let uuid = self.uuid.filter(|uuid| !uuid.is_empty())?;
        Some(ScannerRegistration {
            uuid,
            name: self.name.unwrap_or_default(),
            vendor: self.vendor,
            version: self.version,
            disabled: self.disabled.unwrap_or(false),
        })
    }
}

/// Reads one scanner registration (`GET .../scanner`). A body with no UUID is a failure.
pub fn parse_scanner(body: &[u8]) -> Result<ScannerRegistration, AppError> {
    let raw: RawScanner =
        serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    raw.into_registration().ok_or(AppError::UpstreamUnreachable)
}

/// Reads one page of scanner registrations (`GET .../scanner/candidates`). Entries with no UUID
/// are skipped. A body that is not a JSON array is a failure.
pub fn parse_scanner_list(body: &[u8]) -> Result<Vec<ScannerRegistration>, AppError> {
    let raw: Vec<RawScanner> =
        serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    Ok(raw
        .into_iter()
        .filter_map(RawScanner::into_registration)
        .collect())
}

/// The scan state of the vulnerability report for the project's current scanner (#224).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    /// `Success`: the report is final and can be read.
    Success,
    /// `Pending`, `Running` or `Scheduled`: the scan is not done.
    InProgress,
    /// `Error` or `Stopped`: the scan did not finish.
    Failed,
    /// No overview for this MIME type, or a status string HarborGate does not know. The status
    /// strings are UNVERIFIED against live Harbor (`specs/integrations.md`), so this is not an error.
    Other,
}

/// Reads the scan state of the Trivy MIME type from an artifact body fetched with
/// `with_scan_overview=true` (`scan_overview[<mime>].scan_status`). Matching is case-insensitive.
pub fn overview_status(body: &[u8]) -> Result<ScanStatus, AppError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    let status = value
        .pointer("/scan_overview")
        .and_then(|overview| overview.get(TRIVY_REPORT_MIME))
        .and_then(|entry| entry.get("scan_status"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    Ok(match status.as_deref() {
        Some("success") => ScanStatus::Success,
        Some("pending" | "running" | "scheduled") => ScanStatus::InProgress,
        Some("error" | "stopped") => ScanStatus::Failed,
        _ => ScanStatus::Other,
    })
}

/// The artifact's digest from an artifact body (`GET .../artifacts/{reference}`). A tag
/// resolves to the digest it points at now.
pub fn parse_artifact_digest(body: &[u8]) -> Result<String, AppError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    value
        .get("digest")
        .and_then(Value::as_str)
        .filter(|digest| valid_digest(digest))
        .map(str::to_owned)
        .ok_or(AppError::UpstreamUnreachable)
}

/// Builds the list URL for the newest tagged artifact of a repository: one item, sorted by
/// push time, newest first, tagged only. The same query as the source suggestion
/// (`specs/integrations.md`, "Source suggestion").
pub fn newest_tagged_url(base: &Url, project: &str, repository: &str) -> Result<Url, AppError> {
    let mut url = artifacts_list_url(base, project, repository, 1, 1)?;
    url.query_pairs_mut()
        .append_pair("sort", "-push_time")
        .append_pair("q", "tags=*");
    Ok(url)
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

/// Copies the string members of `value` into `into` when `value` is a JSON object. Anything
/// else (missing, `null`, or Harbor's own label array at the top level) adds nothing.
fn merge_string_map(into: &mut BTreeMap<String, String>, value: Option<&Value>) {
    if let Some(Value::Object(map)) = value {
        for (key, value) in map {
            if let Value::String(text) = value {
                into.insert(key.clone(), text.clone());
            }
        }
    }
}

/// Reads the labels from an artifact JSON body. Harbor stores the image config, including
/// its OCI `Labels`, in `extra_attrs.config` (`specs/integrations.md`, verified against a
/// live Harbor on 2026-11-06). The older `extra_attrs.labels` and a top-level object are
/// also read, later ones winning. Harbor's top-level `labels` is normally `null` or an array
/// of Harbor label objects, which carry no OCI labels and are ignored. An image index has no
/// `extra_attrs`; see [`index_image_child`].
pub fn parse_labels(body: &[u8]) -> Result<ArtifactLabels, AppError> {
    let parsed: Value = serde_json::from_slice(body).map_err(|_| AppError::InternalError)?;
    if !parsed.is_object() {
        return Err(AppError::InternalError);
    }
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    merge_string_map(&mut merged, parsed.pointer("/extra_attrs/config/Labels"));
    merge_string_map(&mut merged, parsed.pointer("/extra_attrs/labels"));
    merge_string_map(&mut merged, parsed.get("labels"));
    Ok(ArtifactLabels {
        revision: merged.get(LABEL_REVISION).cloned(),
        source: merged.get(LABEL_SOURCE).cloned(),
        branch: merged.get(LABEL_BRANCH).cloned(),
    })
}

/// For an image index (a multi-platform push, as `docker buildx` makes by default), the
/// digest of the first child that is a real image: not a BuildKit attestation manifest
/// (`vnd.docker.reference.type` = `attestation-manifest`) and not platform `unknown`. The
/// index itself has no image config, so its labels live on this child. `None` when the
/// body is not an index or no child qualifies, or the child digest is not a valid digest.
pub fn index_image_child(body: &[u8]) -> Option<String> {
    let parsed: Value = serde_json::from_slice(body).ok()?;
    let references = parsed.get("references")?.as_array()?;
    references
        .iter()
        .filter(|reference| {
            reference
                .pointer("/annotations/vnd.docker.reference.type")
                .and_then(Value::as_str)
                != Some("attestation-manifest")
        })
        .filter(|reference| {
            reference.pointer("/platform/os").and_then(Value::as_str) != Some("unknown")
        })
        .filter_map(|reference| reference.get("child_digest").and_then(Value::as_str))
        .find(|digest| valid_digest(digest))
        .map(str::to_owned)
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

/// Builds the artifact list URL for one repository page. The repository is encoded as in
/// [`artifact_url`]. `page` starts at 1.
pub fn artifacts_list_url(
    base: &Url,
    project: &str,
    repository: &str,
    page: u32,
    page_size: u32,
) -> Result<Url, AppError> {
    let path = format!(
        "api/v2.0/projects/{}/repositories/{}/artifacts",
        encode_segment(project),
        encode_repository_path(repository)
    );
    let mut url = base.join(&path).map_err(|_| invalid_name())?;
    url.query_pairs_mut()
        .append_pair("page", &page.to_string())
        .append_pair("page_size", &page_size.to_string());
    Ok(url)
}

#[derive(Debug, Deserialize)]
struct ListedArtifact {
    digest: String,
    #[serde(default)]
    tags: Option<Vec<ListedTag>>,
}

#[derive(Debug, Deserialize)]
struct ListedTag {
    name: String,
}

/// Reads an artifact list page: each artifact's `digest` and its `tags[].name`. An
/// artifact with no tags (`null` or missing) has an empty tag list.
pub fn parse_artifact_list(body: &[u8]) -> Result<Vec<(String, Vec<String>)>, AppError> {
    let listed: Vec<ListedArtifact> =
        serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    Ok(listed
        .into_iter()
        .map(|artifact| {
            let tags = artifact
                .tags
                .unwrap_or_default()
                .into_iter()
                .map(|tag| tag.name)
                .collect();
            (artifact.digest, tags)
        })
        .collect())
}

/// One tag of an artifact: its name and Harbor's `push_time` (RFC 3339 text) when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactTag {
    pub name: String,
    pub push_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TaggedArtifact {
    #[serde(default)]
    tags: Option<Vec<DatedTag>>,
}

#[derive(Debug, Deserialize)]
struct DatedTag {
    name: String,
    #[serde(default)]
    push_time: Option<String>,
}

impl From<DatedTag> for ArtifactTag {
    fn from(tag: DatedTag) -> Self {
        Self {
            name: tag.name,
            push_time: tag.push_time,
        }
    }
}

/// Reads the tags of one artifact body (`GET .../artifacts/{digest}`): each tag's `name` and
/// `push_time`. `tags` missing or `null` is an empty list. Names are not validated here.
pub fn parse_artifact_tags(body: &[u8]) -> Result<Vec<ArtifactTag>, AppError> {
    let artifact: TaggedArtifact =
        serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    Ok(artifact
        .tags
        .unwrap_or_default()
        .into_iter()
        .map(ArtifactTag::from)
        .collect())
}

#[derive(Debug, Deserialize)]
struct DatedArtifact {
    digest: String,
    #[serde(default)]
    tags: Option<Vec<DatedTag>>,
}

/// Like [`parse_artifact_list`], but each tag keeps its `push_time`, so the poller can cut a
/// digest to its newest tags (#132).
pub fn parse_artifact_list_dated(body: &[u8]) -> Result<Vec<(String, Vec<ArtifactTag>)>, AppError> {
    let listed: Vec<DatedArtifact> =
        serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    Ok(listed
        .into_iter()
        .map(|artifact| {
            let tags = artifact
                .tags
                .unwrap_or_default()
                .into_iter()
                .map(ArtifactTag::from)
                .collect();
            (artifact.digest, tags)
        })
        .collect())
}

/// True when an artifact list page holds a tagged artifact (an image index) whose `references`
/// name `digest` as a `child_digest`. An untagged parent does not count: its own tags are what
/// the parent's scan event syncs (#132, `specs/integrations.md`, "Covered by a parent index").
pub fn page_has_tagged_parent(body: &[u8], digest: &str) -> Result<bool, AppError> {
    let listed: Vec<Value> =
        serde_json::from_slice(body).map_err(|_| AppError::UpstreamUnreachable)?;
    Ok(listed.iter().any(|artifact| {
        let tagged = artifact
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| !tags.is_empty());
        tagged
            && artifact
                .get("references")
                .and_then(Value::as_array)
                .is_some_and(|references| {
                    references.iter().any(|reference| {
                        reference.get("child_digest").and_then(Value::as_str) == Some(digest)
                    })
                })
    }))
}

/// True for `sha256:` followed by exactly 64 lowercase hex digits: the form Harbor returns,
/// and a strict check that keeps a digest safe as a URL path segment (#132).
pub fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
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
pub fn check_source(
    labels: &ArtifactLabels,
    web_url: &str,
    owner: &str,
    repo: &str,
) -> Result<(), AppError> {
    let Some(source) = labels.source.as_deref() else {
        return Ok(());
    };
    let normalized = normalize_source(source);
    let expected = normalize_source(&format!("{web_url}/{owner}/{repo}"));
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

    /// An older assumed shape (`extra_attrs.labels` and a top-level object), still read.
    /// Values are fake. See `LIVE_IMAGE` for the shape a real Harbor returns.
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

    /// The shape a live Harbor returned on 2026-11-06 for an image manifest (keys and types
    /// captured, values fake): the OCI labels sit in `extra_attrs.config.Labels`, and the
    /// top-level `labels` is `null`.
    const LIVE_IMAGE: &str = r#"{
        "digest": "sha256:aaaa",
        "labels": null,
        "tags": null,
        "media_type": "application/vnd.oci.image.config.v1+json",
        "extra_attrs": {
            "architecture": "amd64", "os": "linux", "author": "", "created": "2026-11-06T00:00:00Z",
            "config": {"Cmd": ["/app"], "Labels": {
                "org.opencontainers.image.revision": "0123456789abcdef0123456789abcdef01234567",
                "org.opencontainers.image.source": "https://github.com/octo/app"
            }}
        }
    }"#;

    #[test]
    fn labels_are_read_from_the_image_config() {
        let labels = parse_labels(LIVE_IMAGE.as_bytes()).unwrap();
        assert_eq!(
            labels.revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            labels.source.as_deref(),
            Some("https://github.com/octo/app")
        );
        assert_eq!(labels.branch, None);
    }

    #[test]
    fn harbor_label_array_at_the_top_level_is_ignored() {
        let body = r#"{"labels": [{"id": 1, "name": "prod"}],
            "extra_attrs": {"config": {"Labels": {"org.opencontainers.image.revision": "abc"}}}}"#;
        let labels = parse_labels(body.as_bytes()).unwrap();
        assert_eq!(labels.revision.as_deref(), Some("abc"));
        assert!(parse_labels(b"[]").is_err());
    }

    /// The live shape of a buildx image index (2026-11-06): no `extra_attrs`, an amd64 image
    /// child and a BuildKit attestation child on platform `unknown`.
    fn live_index(image_child: &str, attestation_child: &str) -> String {
        format!(
            r#"{{"digest": "sha256:{}", "labels": null, "tags": [{{"name": "latest"}}],
            "media_type": "application/vnd.oci.image.index.v1+json",
            "references": [
                {{"child_digest": "{attestation_child}", "platform": {{"os": "unknown", "architecture": "unknown"}},
                  "annotations": {{"vnd.docker.reference.type": "attestation-manifest"}}}},
                {{"child_digest": "{image_child}", "platform": {{"os": "linux", "architecture": "amd64", "OsFeatures": null}}}}
            ]}}"#,
            "c".repeat(64)
        )
    }

    #[test]
    fn an_index_has_no_labels_and_names_its_image_child() {
        let image = format!("sha256:{}", "a".repeat(64));
        let attestation = format!("sha256:{}", "b".repeat(64));
        let body = live_index(&image, &attestation);
        assert_eq!(parse_labels(body.as_bytes()).unwrap().revision, None);
        assert_eq!(index_image_child(body.as_bytes()), Some(image));
    }

    #[test]
    fn no_image_child_without_a_valid_reference() {
        assert_eq!(index_image_child(LIVE_IMAGE.as_bytes()), None);
        assert_eq!(index_image_child(br#"{"references": null}"#), None);
        let body = live_index("sha256:../../x", &format!("sha256:{}", "b".repeat(64)));
        assert_eq!(index_image_child(body.as_bytes()), None);
        assert_eq!(index_image_child(b"not json"), None);
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
        assert!(check_source(&labels, "https://github.com", "octo", "app").is_ok());
        let other = ArtifactLabels {
            source: Some("https://github.com/octo/other".to_owned()),
            ..Default::default()
        };
        assert!(check_source(&other, "https://github.com", "octo", "app").is_err());
    }

    #[test]
    fn absent_source_label_proceeds() {
        assert!(
            check_source(
                &ArtifactLabels::default(),
                "https://github.com",
                "octo",
                "app"
            )
            .is_ok()
        );
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
    fn retry_after_reads_whole_seconds_only() {
        assert_eq!(parse_retry_after("252"), Some(252));
        assert_eq!(parse_retry_after(" 30 "), Some(30));
        assert_eq!(parse_retry_after("0"), Some(0));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-5"), None);
        assert_eq!(parse_retry_after("1.5"), None);
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("99999999999999999999999"), None);
    }

    #[test]
    fn artifact_tags_keep_name_and_push_time() {
        let body = r#"{"digest":"sha256:x","tags":[
            {"name":"v1","push_time":"2026-11-05T10:00:00.000Z","id":1},
            {"name":"v2"}]}"#;
        let tags = parse_artifact_tags(body.as_bytes()).unwrap();
        assert_eq!(
            tags,
            vec![
                ArtifactTag {
                    name: "v1".to_owned(),
                    push_time: Some("2026-11-05T10:00:00.000Z".to_owned())
                },
                ArtifactTag {
                    name: "v2".to_owned(),
                    push_time: None
                },
            ]
        );
        assert!(parse_artifact_tags(br#"{"tags":null}"#).unwrap().is_empty());
        assert!(parse_artifact_tags(b"{}").unwrap().is_empty());
        assert!(parse_artifact_tags(b"not json").is_err());
    }

    #[test]
    fn digest_must_be_sha256_and_64_lowercase_hex() {
        assert!(valid_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_digest("sha256:aaaa"));
        assert!(!valid_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!valid_digest(&format!("sha256:{}", "a".repeat(65))));
        assert!(!valid_digest(&format!("sha512:{}", "a".repeat(64))));
        assert!(!valid_digest(&"a".repeat(64)));
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
