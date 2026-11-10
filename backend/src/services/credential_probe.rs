//! Credential test probes. The GitHub probes check the repository, code scanning and issues
//! access. Sources: `specs/integrations.md` (Test button), `specs/api.md` (Credentials),
//! `specs/security.md` (GitHub token scope).
//!
//! Every request goes through [`OutboundClient`], so the address check applies.

use reqwest::Url;

use crate::error::AppError;
use crate::services::github_url::GithubTarget;
use crate::services::outbound::{self, OutboundClient};

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
    /// `path` is relative to the configured GitHub API base URL. `token` is the PAT bytes.
    async fn get(&self, path: &str, token: &[u8]) -> Result<GithubResponse, AppError>;
}

/// Production GitHub probe: the guarded client with a bearer token.
pub struct OutboundGithubProbe {
    client: OutboundClient,
    target: GithubTarget,
}

impl OutboundGithubProbe {
    pub fn new(target: GithubTarget) -> Result<Self, AppError> {
        let client =
            outbound::github_client(target.clone()).map_err(|_| AppError::InternalError)?;
        Ok(Self { client, target })
    }
}

/// Largest error body read for classification. GitHub's error bodies are small.
const MAX_GITHUB_BODY: usize = 64 * 1024;

/// Raw answer of one GitHub GET: the classified response and the body bytes (empty when
/// the body is over [`MAX_GITHUB_BODY`]).
struct RawGithub {
    response: GithubResponse,
    body: Vec<u8>,
}

impl OutboundGithubProbe {
    /// The URL of `path` under the live GitHub API base (`specs/integrations.md`, "GitHub
    /// base URL"). It is read on every request, so an admin change applies at once.
    fn request_url(&self, path: &str) -> Result<Url, AppError> {
        self.target
            .current()
            .api_url(path)
            .ok_or(AppError::InternalError)
    }

    async fn send(&self, path: &str, token: &[u8]) -> Result<RawGithub, AppError> {
        let url = self.request_url(path)?;
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
        if body.len() > MAX_GITHUB_BODY {
            return Ok(RawGithub {
                response: GithubResponse {
                    status,
                    message: String::new(),
                    accepted_permissions,
                },
                body: Vec::new(),
            });
        }
        let message = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        Ok(RawGithub {
            response: GithubResponse {
                status,
                message,
                accepted_permissions,
            },
            body: body.to_vec(),
        })
    }
}

impl GithubProbe for OutboundGithubProbe {
    async fn get(&self, path: &str, token: &[u8]) -> Result<GithubResponse, AppError> {
        Ok(self.send(path, token).await?.response)
    }
}

/// Path of the repository list call, `GET /user/repos?per_page=1`. GitHub's default
/// order applies, so the single item is the first repository the token can see.
pub const GITHUB_FIRST_REPO_PATH: &str = "user/repos?per_page=1";

/// The answer of the repository list call: the status classification and, on `200`,
/// the first repository as `(owner, repo)` (`None` when the list is empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRepository {
    pub response: GithubResponse,
    pub repository: Option<(String, String)>,
}

/// Lists the first repository the token can see (`specs/api.md`, Test button).
#[allow(async_fn_in_trait)]
pub trait GithubRepoLister {
    async fn first_repository(&self, token: &[u8]) -> Result<FirstRepository, AppError>;
}

impl GithubRepoLister for OutboundGithubProbe {
    async fn first_repository(&self, token: &[u8]) -> Result<FirstRepository, AppError> {
        let raw = self.send(GITHUB_FIRST_REPO_PATH, token).await?;
        let repository = if raw.response.status == 200 {
            first_repository_of(&raw.body)
        } else {
            None
        };
        Ok(FirstRepository {
            response: raw.response,
            repository,
        })
    }
}

/// Reads `[{"name","owner":{"login"}}, ...]` and returns the first `(owner, repo)`.
/// Only these two fields are read.
pub fn first_repository_of(body: &[u8]) -> Option<(String, String)> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let first = value.as_array()?.first()?;
    let owner = first.get("owner")?.get("login")?.as_str()?;
    let name = first.get("name")?.as_str()?;
    Some((owner.to_owned(), name.to_owned()))
}

/// Catalog key of the detail for a token that sees no repository. The frontend shows
/// the text (`specs/api.md`, Test button).
pub const NO_REPOSITORY_KEY: &str = "credentials.test.noRepository";

/// The check for a token that sees no repository.
pub fn github_no_repository_check() -> Check {
    Check {
        name: "github_repository_visible",
        ok: false,
        detail: NO_REPOSITORY_KEY.to_owned(),
        warning: None,
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
        let plain = github_repo_check(&github(200, "", None));
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("warning").is_none(), "{json}");
        let warned = github_issues_check(&github(403, "", None));
        let json = serde_json::to_value(&warned).unwrap();
        assert_eq!(json["warning"], "issues_permission_missing");
    }

    /// #184: every GitHub credential test request (first repository, repository, code
    /// scanning, issues) goes to `https://api.github.com` while the setting is empty, and to
    /// the custom API base with its path once the admin sets one, with no rebuild of the probe.
    /// Clearing the setting returns to the default.
    #[test]
    fn credential_test_requests_follow_the_configured_base_url() {
        use crate::services::github_url::GithubUrls;
        let target = GithubTarget::default();
        let probe = OutboundGithubProbe::new(target.clone()).unwrap();
        let paths = [
            GITHUB_FIRST_REPO_PATH.to_owned(),
            github_repo_path("octo", "app"),
            github_code_scanning_path("octo", "app"),
            github_issues_path("octo", "app"),
        ];
        let urls = |probe: &OutboundGithubProbe| -> Vec<String> {
            paths
                .iter()
                .map(|path| probe.request_url(path).unwrap().to_string())
                .collect()
        };

        for url in urls(&probe) {
            assert!(url.starts_with("https://api.github.com/"), "{url}");
        }

        target.set(GithubUrls::from_stored("https://ghes.example.com/api/v3", "").unwrap());
        let custom = urls(&probe);
        for url in &custom {
            assert!(url.starts_with("https://ghes.example.com/api/v3/"), "{url}");
        }
        assert_eq!(
            custom[0],
            "https://ghes.example.com/api/v3/user/repos?per_page=1"
        );
        assert_eq!(custom[1], "https://ghes.example.com/api/v3/repos/octo/app");

        target.set(GithubUrls::from_stored("", "").unwrap());
        for url in urls(&probe) {
            assert!(url.starts_with("https://api.github.com/"), "{url}");
        }
    }
}
