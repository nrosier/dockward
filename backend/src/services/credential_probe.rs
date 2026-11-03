//! The Harbor robot test. `GET /api/v2.0/users/current` answers `412` for a robot
//! account, `401` for a wrong, disabled, or expired robot, and `200` for a human
//! account (which is rejected). Sources: `specs/integrations.md` (Test button),
//! `specs/api.md` (Credentials, Test button).
//!
//! Every request goes through [`OutboundClient`], so the address check applies.

use reqwest::Url;

use crate::error::AppError;
use crate::services::outbound::{self, OutboundClient, TargetClass};

/// One check in the test response: `{"name","ok","detail"}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
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
        let response = self
            .client
            .get(url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(username, Some(secret))
            .send()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?;
        Ok(response.status().as_u16())
    }
}

/// Builds the artifacts URL. Each name is percent-encoded, and a `/` inside the
/// repository name is encoded twice, as Harbor requires (`specs/integrations.md`).
pub fn artifacts_url(base: &Url, project: &str, repository: &str) -> Result<Url, AppError> {
    let encoded_repo = repository.replace('/', "%252F");
    let path = format!(
        "api/v2.0/projects/{}/repositories/{}/artifacts?page_size=1",
        encode_segment(project),
        encoded_repo
    );
    base.join(&path).map_err(|_| {
        AppError::ValidationFailed("the Harbor project or repository name is not valid.".to_owned())
    })
}

/// Percent-encodes one path segment. Unreserved characters are kept as they are.
fn encode_segment(text: &str) -> String {
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
    }
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
    fn project_name_is_percent_encoded() {
        let base = Url::parse("https://harbor.example.com").unwrap();
        let url = artifacts_url(&base, "my proj", "app").unwrap();
        assert!(url.as_str().contains("/projects/my%20proj/"), "{url}");
    }

    #[test]
    fn human_account_is_rejected_with_a_reason() {
        let check = harbor_check(200);
        assert_eq!(check.name, "harbor_robot");
        assert!(check.detail.contains("human account"));
    }
}
