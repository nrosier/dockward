//! Credential test probes. The Harbor robot test calls `GET /api/v2.0/users/current`:
//! `412` means a working robot account, `401` a wrong, disabled, or expired robot, and
//! `200` a human account (rejected). The GitHub probes check the repository and code
//! scanning access. Sources: `specs/integrations.md` (Test button), `specs/api.md`
//! (Credentials), `specs/security.md` (GitHub token scope).
//!
//! Every request goes through [`OutboundClient`], so the address check applies.

use reqwest::Url;

use crate::error::AppError;
use crate::services::outbound::{self, OutboundClient, TargetClass};

/// One check in the test response: `{"name","ok","detail","warning"?}`. `warning` is
/// present only when a check passed with a caveat (`specs/api.md`, Credentials).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<&'static str>,
}

/// The status a probe got back. The request itself is the only network effect.
#[allow(async_fn_in_trait)]
pub trait HarborProbe {
    /// Sends the robot test and returns the HTTP status code.
    async fn users_current(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
    ) -> Result<u16, AppError>;
    /// Sends `GET /api/v2.0/projects/{project}/repositories/{repository}/artifacts?page_size=1`
    /// and returns the HTTP status. Names are encoded, and a `/` in the repository is
    /// encoded twice (`specs/integrations.md`, Harbor API).
    async fn artifacts_status(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
        project: &str,
        repository: &str,
    ) -> Result<u16, AppError>;
}

/// Production probe: the guarded client, HTTP Basic with the robot credential.
pub struct OutboundHarborProbe {
    client: OutboundClient,
}

impl OutboundHarborProbe {
    pub fn new(allow_private: bool) -> Result<Self, AppError> {
        let client = outbound::client(TargetClass::Harbor, allow_private)
            .map_err(|_| AppError::InternalError)?;
        Ok(Self { client })
    }
}

impl HarborProbe for OutboundHarborProbe {
    async fn users_current(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
    ) -> Result<u16, AppError> {
        let url = base
            .join("api/v2.0/users/current")
            .map_err(|_| AppError::InternalError)?;
        self.send_get(&url, username, secret).await
    }

    async fn artifacts_status(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
        project: &str,
        repository: &str,
    ) -> Result<u16, AppError> {
        let url = artifacts_url(base, project, repository)?;
        self.send_get(&url, username, secret).await
    }
}

impl OutboundHarborProbe {
    async fn send_get(&self, url: &Url, username: &str, secret: &[u8]) -> Result<u16, AppError> {
        let secret = std::str::from_utf8(secret).map_err(|_| AppError::InternalError)?;
        let sent = self
            .client
            .get(url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(username, Some(secret))
            .send()
            .await;
        let status = sent.as_ref().ok().map(|r| r.status().as_u16());
        crate::services::app_log::log_outbound("GET", url, status);
        let response = sent.map_err(|_| AppError::UpstreamUnreachable)?;
        Ok(response.status().as_u16())
    }
}

/// Checks a Harbor project or repository name against Harbor's naming rule. The name
/// splits on `/`, and each component is lowercase alphanumerics separated by single
/// `.`, `_`, or `-`. The whole name is 1 to 255 bytes. Anything else is refused before
/// a request is made (`specs/integrations.md`, Harbor API).
pub fn valid_harbor_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    name.split('/').all(valid_harbor_component)
}

/// One component of a Harbor name: `[a-z0-9]+([._-][a-z0-9]+)*`. An empty component is
/// refused, so a leading, trailing, or doubled `/` fails.
fn valid_harbor_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let is_separator = |b: u8| b == b'.' || b == b'_' || b == b'-';
    // The first and last byte are alphanumeric. Every separator sits between two of them.
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    let mut previous_separator = false;
    for &byte in bytes {
        if is_separator(byte) {
            if previous_separator {
                return false;
            }
            previous_separator = true;
        } else if is_alnum(byte) {
            previous_separator = false;
        } else {
            return false;
        }
    }
    true
}

/// Builds the artifacts URL. The project is encoded as one segment. The repository is
/// encoded per component, and the components are joined with `%252F`, which is the
/// double encoding Harbor requires (`specs/integrations.md`).
pub fn artifacts_url(base: &Url, project: &str, repository: &str) -> Result<Url, AppError> {
    let path = format!(
        "api/v2.0/projects/{}/repositories/{}/artifacts?page_size=1",
        encode_segment(project),
        encode_repository_path(repository)
    );
    base.join(&path).map_err(|_| {
        AppError::ValidationFailed("the Harbor project or repository name is not valid.".to_owned())
    })
}

/// Encodes a repository name for a URL path. Each `/`-separated component is encoded on
/// its own, and the components are joined with `%252F`, so the name keeps its slashes
/// through Harbor's double encoding.
pub fn encode_repository_path(repository: &str) -> String {
    repository
        .split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("%252F")
}

/// Percent-encodes one path segment. Unreserved characters are kept as they are.
pub fn encode_segment(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// Maps the `users/current` status to the test result. Only `412` passes.
pub fn harbor_check(status: u16) -> Check {
    let (ok, detail) = match status {
        412 => (true, "the robot account credential works".to_owned()),
        401 => (
            false,
            "the robot secret is wrong, or the robot is disabled or expired".to_owned(),
        ),
        200 => (
            false,
            "the credentials belong to a human account; only robot accounts are accepted"
                .to_owned(),
        ),
        other => (false, format!("unexpected status {other} from Harbor")),
    };
    Check {
        name: "harbor_robot",
        ok,
        detail,
        warning: None,
    }
}

/// GitHub's REST API root. The host is fixed, so the outbound check is about the
/// address only (`specs/security.md`, "GitHub token scope").
const GITHUB_API: &str = "https://api.github.com/";

/// What GitHub answered: the status, the error `message` (used to classify `403` and
/// `404`), and the `X-Accepted-GitHub-Permissions` header naming the permission the
/// endpoint needs. None of these hold the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubResponse {
    pub status: u16,
    pub message: String,
    pub accepted_permissions: Option<String>,
}

/// Sends one authenticated GET to the GitHub API and returns the answer.
#[allow(async_fn_in_trait)]
pub trait GithubProbe {
    /// `path` is relative to `https://api.github.com/`. `token` is the PAT bytes.
    async fn get(&self, path: &str, token: &[u8]) -> Result<GithubResponse, AppError>;
}

/// Production GitHub probe: the guarded client with a bearer token.
pub struct OutboundGithubProbe {
    client: OutboundClient,
}

impl OutboundGithubProbe {
    pub fn new() -> Result<Self, AppError> {
        let client =
            outbound::client(TargetClass::GitHub, false).map_err(|_| AppError::InternalError)?;
        Ok(Self { client })
    }
}

/// Largest error body read for classification. GitHub's error bodies are small.
const MAX_GITHUB_BODY: usize = 64 * 1024;

impl GithubProbe for OutboundGithubProbe {
    async fn get(&self, path: &str, token: &[u8]) -> Result<GithubResponse, AppError> {
        let base = Url::parse(GITHUB_API).map_err(|_| AppError::InternalError)?;
        let url = base.join(path).map_err(|_| AppError::InternalError)?;
        let token = std::str::from_utf8(token).map_err(|_| AppError::InternalError)?;
        let sent = self
            .client
            .get(&url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .bearer_auth(token)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .header("user-agent", "HarborGate")
            .send()
            .await;
        crate::services::app_log::log_outbound(
            "GET",
            &url,
            sent.as_ref().ok().map(|r| r.status().as_u16()),
        );
        let response = sent.map_err(|_| AppError::UpstreamUnreachable)?;
        let status = response.status().as_u16();
        let accepted_permissions = response
            .headers()
            .get("x-accepted-github-permissions")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .bytes()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?;
        let message = if body.len() <= MAX_GITHUB_BODY {
            serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("message")
                        .and_then(|m| m.as_str())
                        .map(str::to_owned)
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(GithubResponse {
            status,
            message,
            accepted_permissions,
        })
    }
}

/// Owner and repository names: ASCII letters, digits, `-`, `_`, and `.`, 1 to 100
/// characters, and not `.` or `..`. Anything else is refused before a request is made.
pub fn valid_github_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Path of the repository probe, `GET /repos/{owner}/{repo}` (Metadata read).
pub fn github_repo_path(owner: &str, repo: &str) -> String {
    format!("repos/{owner}/{repo}")
}

/// Path of the code scanning probe (Code scanning alerts read).
pub fn github_code_scanning_path(owner: &str, repo: &str) -> String {
    format!("repos/{owner}/{repo}/code-scanning/alerts?per_page=1")
}

/// Classifies the repository probe (`specs/security.md`, "GitHub token scope").
pub fn github_repo_check(response: &GithubResponse) -> Check {
    let (ok, detail) = match response.status {
        200 => (true, "the token can read the repository".to_owned()),
        401 => (false, "the token is invalid or expired".to_owned()),
        404 => (
            false,
            "the token cannot see the repository, or the owner or name is wrong".to_owned(),
        ),
        403 => (false, missing_permission_detail(response)),
        other => (false, format!("unexpected status {other} from GitHub")),
    };
    Check {
        name: "github_repo",
        ok,
        detail,
        warning: None,
    }
}

/// Path of the issues probe, `GET /repos/{owner}/{repo}/issues?per_page=1` (Issues read).
pub fn github_issues_path(owner: &str, repo: &str) -> String {
    format!("repos/{owner}/{repo}/issues?per_page=1")
}

/// Warning code for a token without the Issues permission (`specs/security.md`).
pub const ISSUES_PERMISSION_MISSING: &str = "issues_permission_missing";

/// Classifies the issues probe. `200` passes. A `403` passes with the
/// `issues_permission_missing` warning, because SARIF upload does not need Issues.
/// `401` and `404` fail as in [`github_repo_check`]. Mapping save applies its own,
/// stricter rule to the same response (`specs/security.md`, "GitHub token scope").
pub fn github_issues_check(response: &GithubResponse) -> Check {
    match response.status {
        200 => Check {
            name: "github_issues",
            ok: true,
            detail: "the token can read issues".to_owned(),
            warning: None,
        },
        403 => Check {
            name: "github_issues",
            ok: true,
            detail: format!(
                "the Issues permission is needed for automatic and manual issues; {}",
                missing_permission_detail(response)
            ),
            warning: Some(ISSUES_PERMISSION_MISSING),
        },
        401 => Check {
            name: "github_issues",
            ok: false,
            detail: "the token is invalid or expired".to_owned(),
            warning: None,
        },
        404 => Check {
            name: "github_issues",
            ok: false,
            detail: "the token cannot see the repository, or the owner or name is wrong".to_owned(),
            warning: None,
        },
        other => Check {
            name: "github_issues",
            ok: false,
            detail: format!("unexpected status {other} from GitHub"),
            warning: None,
        },
    }
}

/// Result of the code scanning probe. `Unavailable` means the repository cannot receive
/// code scanning uploads, which is not the same as a missing permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeScanningState {
    Ready,
    NoAnalysisYet,
    Unavailable,
    Failed,
}

/// Classifies the code scanning response. `404` with "no analysis found" is healthy.
/// A `403` naming disabled code scanning is unavailable, not a missing permission.
pub fn code_scanning_state(response: &GithubResponse) -> CodeScanningState {
    let message = response.message.to_ascii_lowercase();
    match response.status {
        200 => CodeScanningState::Ready,
        404 if message.contains("no analysis found") => CodeScanningState::NoAnalysisYet,
        403 if message.contains("code scanning is not enabled")
            || message.contains("advanced security must be enabled")
            || message.contains("code security must be enabled") =>
        {
            CodeScanningState::Unavailable
        }
        _ => CodeScanningState::Failed,
    }
}

/// The check row for the code scanning probe, built from [`code_scanning_state`].
pub fn github_code_scanning_check(response: &GithubResponse) -> Check {
    let (ok, detail) = match code_scanning_state(response) {
        CodeScanningState::Ready => (true, "code scanning alerts are readable".to_owned()),
        CodeScanningState::NoAnalysisYet => (
            true,
            "code scanning is enabled; no analysis has been uploaded yet".to_owned(),
        ),
        CodeScanningState::Unavailable => (
            false,
            "code scanning is unavailable for this repository".to_owned(),
        ),
        CodeScanningState::Failed => match response.status {
            403 => (false, missing_permission_detail(response)),
            404 => (
                false,
                "the token cannot see the repository, or the owner or name is wrong".to_owned(),
            ),
            other => (false, format!("unexpected status {other} from GitHub")),
        },
    };
    Check {
        name: "github_code_scanning",
        ok,
        detail,
        warning: None,
    }
}

/// Detail for a `403` that means a missing permission. The accepted permission is
/// copied from the header, and the raw message is kept.
fn missing_permission_detail(response: &GithubResponse) -> String {
    let needed = response
        .accepted_permissions
        .as_deref()
        .unwrap_or("unknown");
    format!(
        "missing permission (GitHub needs: {needed}): {}",
        response.message
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_412_passes() {
        assert!(harbor_check(412).ok);
        assert!(!harbor_check(401).ok);
        assert!(!harbor_check(200).ok);
        assert!(!harbor_check(500).ok);
    }

    #[test]
    fn repository_slash_is_encoded_twice() {
        let base = Url::parse("https://harbor.example.com").unwrap();
        let url = artifacts_url(&base, "proj", "team/app").unwrap();
        assert!(
            url.as_str()
                .contains("/repositories/team%252Fapp/artifacts"),
            "{url}"
        );
        assert!(url.as_str().ends_with("?page_size=1"));
    }

    #[test]
    fn harbor_names_are_validated() {
        // Valid: lowercase alphanumerics, with single `.`, `_`, or `-` between them.
        assert!(valid_harbor_name("proj"));
        assert!(valid_harbor_name("my-proj.v2_x"));
        assert!(valid_harbor_name("team/app"));
        assert!(valid_harbor_name("a/b/c"));
        // Refused: empty, uppercase, a `/` in a project, separators at the edges or doubled.
        assert!(!valid_harbor_name(""));
        assert!(!valid_harbor_name("Proj"));
        assert!(!valid_harbor_name("-proj"));
        assert!(!valid_harbor_name("proj-"));
        assert!(!valid_harbor_name("a..b"));
        assert!(!valid_harbor_name("a--b"));
        assert!(!valid_harbor_name("a//b"));
        assert!(!valid_harbor_name("/a"));
        assert!(!valid_harbor_name("a/"));
        assert!(!valid_harbor_name("a?b"));
        assert!(!valid_harbor_name("a#b"));
        assert!(!valid_harbor_name("a%b"));
        assert!(!valid_harbor_name("a b"));
        // Length: 255 bytes is the most a name may have.
        let at_limit = "a".repeat(255);
        assert!(valid_harbor_name(&at_limit));
        assert!(!valid_harbor_name(&format!("{at_limit}a")));
    }

    #[test]
    fn repository_components_are_encoded() {
        // Each component is encoded on its own, and the components join with %252F.
        assert_eq!(encode_repository_path("team/app"), "team%252Fapp");
        assert_eq!(encode_repository_path("a/b/c"), "a%252Fb%252Fc");
        let base = Url::parse("https://harbor.example.com").unwrap();
        let url = artifacts_url(&base, "proj", "team/app").unwrap();
        assert!(
            url.as_str()
                .contains("/repositories/team%252Fapp/artifacts"),
            "{url}"
        );
    }

    #[test]
    fn project_name_is_percent_encoded() {
        let base = Url::parse("https://harbor.example.com").unwrap();
        let url = artifacts_url(&base, "my proj", "app").unwrap();
        assert!(url.as_str().contains("/projects/my%20proj/"), "{url}");
    }

    fn github(status: u16, message: &str, needed: Option<&str>) -> GithubResponse {
        GithubResponse {
            status,
            message: message.to_owned(),
            accepted_permissions: needed.map(str::to_owned),
        }
    }

    #[test]
    fn github_repo_200_passes_and_401_fails() {
        assert!(github_repo_check(&github(200, "", None)).ok);
        assert!(!github_repo_check(&github(401, "Bad credentials", None)).ok);
    }

    #[test]
    fn github_repo_404_means_not_visible() {
        let check = github_repo_check(&github(404, "Not Found", None));
        assert!(!check.ok);
        assert_eq!(check.name, "github_repo");
        assert!(check.detail.contains("cannot see the repository"));
    }

    #[test]
    fn github_403_without_code_scanning_text_is_a_missing_permission() {
        let response = github(
            403,
            "Resource not accessible by personal access token",
            Some("metadata=read"),
        );
        let check = github_repo_check(&response);
        assert!(!check.ok);
        assert!(check.detail.contains("missing permission"));
        assert!(check.detail.contains("metadata=read"));
    }

    #[test]
    fn code_scanning_200_and_no_analysis_yet_are_healthy() {
        assert!(github_code_scanning_check(&github(200, "", None)).ok);
        let check = github_code_scanning_check(&github(404, "no analysis found", None));
        assert!(check.ok);
        assert!(check.detail.contains("no analysis"));
    }

    #[test]
    fn code_scanning_disabled_403_is_unavailable_not_missing_permission() {
        for message in [
            "Code scanning is not enabled for this repository.",
            "Advanced Security must be enabled for this repository to use code scanning.",
            "Code security must be enabled for this repository",
        ] {
            let check = github_code_scanning_check(&github(403, message, Some("x")));
            assert!(!check.ok, "{message}");
            assert!(check.detail.contains("unavailable"), "{message}");
        }
    }

    #[test]
    fn code_scanning_other_403_is_a_missing_permission() {
        let check = github_code_scanning_check(&github(
            403,
            "Resource not accessible by personal access token",
            Some("security_events=read"),
        ));
        assert!(!check.ok);
        assert!(check.detail.contains("security_events=read"));
    }

    #[test]
    fn github_names_are_checked_before_a_request() {
        assert!(valid_github_name("octo-org"));
        assert!(valid_github_name("my.repo_1"));
        assert!(!valid_github_name(""));
        assert!(!valid_github_name(".."));
        assert!(!valid_github_name("a/b"));
        assert!(!valid_github_name("a?b=c"));
    }

    #[test]
    fn github_paths_use_the_decided_endpoints() {
        assert_eq!(github_repo_path("octo", "app"), "repos/octo/app");
        assert_eq!(
            github_code_scanning_path("octo", "app"),
            "repos/octo/app/code-scanning/alerts?per_page=1"
        );
    }

    #[test]
    fn issues_403_is_a_warning_not_a_failure() {
        let check = github_issues_check(&github(
            403,
            "Resource not accessible by personal access token",
            Some("issues=read"),
        ));
        assert_eq!(check.name, "github_issues");
        assert!(check.ok, "a 403 on issues must not fail the test");
        assert_eq!(check.warning, Some("issues_permission_missing"));
        assert!(check.detail.contains("Issues permission"));
        assert!(check.detail.contains("issues=read"));
    }

    #[test]
    fn issues_200_is_ok_without_warning() {
        let check = github_issues_check(&github(200, "", None));
        assert_eq!(check.name, "github_issues");
        assert!(check.ok);
        assert_eq!(check.warning, None);
    }

    #[test]
    fn github_issues_path_uses_the_decided_endpoint() {
        assert_eq!(
            github_issues_path("octo", "app"),
            "repos/octo/app/issues?per_page=1"
        );
    }

    #[test]
    fn warning_is_omitted_from_json_when_absent() {
        let plain = harbor_check(412);
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("warning").is_none(), "{json}");
        let warned = github_issues_check(&github(403, "", None));
        let json = serde_json::to_value(&warned).unwrap();
        assert_eq!(json["warning"], "issues_permission_missing");
    }

    #[test]
    fn human_account_is_rejected_with_a_reason() {
        let check = harbor_check(200);
        assert_eq!(check.name, "harbor_robot");
        assert!(check.detail.contains("human account"));
    }
}
