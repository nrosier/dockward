//! Upstream transport for the mapping pickers (`specs/integrations.md`, "Mapping pickers").
//!
//! One GET per call, to Harbor (robot basic auth) or GitHub (bearer token), through the
//! guarded outbound client, so HTTPS, the address check and the no-redirect rule apply.
//! The answer keeps only what the picker logic needs: the status, the rate-limit headers,
//! `X-Total-Count`, the `Link` next URL and the body. No request header is kept, so the
//! secret never leaves this module. Tests replace the transport with recorded answers.

use std::future::Future;
use std::pin::Pin;

use reqwest::Url;

use crate::error::AppError;
use crate::services::github_scanning::{API_HOST, parse_link_next};
use crate::services::outbound::{self, OutboundClient, TargetClass};

/// Largest body that is kept. A page of 100 GitHub repositories is far below this.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// The future a transport call returns, boxed so the transport can be a trait object.
pub type UpstreamFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UpstreamResponse, AppError>> + Send + 'a>>;

/// How a request authenticates. The secret is borrowed for the call only.
#[derive(Clone, Copy)]
pub enum UpstreamAuth<'a> {
    /// Harbor: HTTP Basic with the robot name and secret.
    Harbor { username: &'a str, secret: &'a [u8] },
    /// GitHub: the fine-grained token as a bearer token.
    Github { token: &'a [u8] },
}

/// What the upstream answered. It never holds a request header or the secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub status: u16,
    /// `retry-after`, in seconds.
    pub retry_after: Option<i64>,
    /// `x-ratelimit-remaining` (GitHub).
    pub ratelimit_remaining: Option<i64>,
    /// `x-ratelimit-reset`, Unix seconds (GitHub).
    pub ratelimit_reset: Option<i64>,
    /// `x-total-count` (Harbor).
    pub total_count: Option<i64>,
    /// The `rel="next"` URL of the `link` header (GitHub).
    pub link_next: Option<String>,
    /// The body; empty when it was over the size cap.
    pub body: Vec<u8>,
}

/// Sends one picker GET. The production transport uses the guarded clients; tests use
/// recorded answers and never open a socket.
pub trait PickerHttp: Send + Sync {
    fn get<'a>(&'a self, url: &'a Url, auth: UpstreamAuth<'a>) -> UpstreamFuture<'a>;
}

/// True when `url` is on the GitHub API host, over HTTPS, with no userinfo or port. The
/// token is sent only to such a URL, including `Link` next URLs taken from a response.
pub fn is_github_api_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(API_HOST)
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
}

/// The production transport: one guarded client per service.
pub struct OutboundPickerHttp {
    harbor: OutboundClient,
    github: OutboundClient,
}

impl OutboundPickerHttp {
    /// `allow_private_harbor` is `HARBORGATE_ALLOW_PRIVATE_HARBOR`.
    pub fn new(allow_private_harbor: bool) -> Result<Self, AppError> {
        let harbor = outbound::client(TargetClass::Harbor, allow_private_harbor)
            .map_err(|_| AppError::InternalError)?;
        let github =
            outbound::client(TargetClass::GitHub, false).map_err(|_| AppError::InternalError)?;
        Ok(Self { harbor, github })
    }

    async fn send(&self, url: &Url, auth: UpstreamAuth<'_>) -> Result<UpstreamResponse, AppError> {
        let builder = match auth {
            UpstreamAuth::Harbor { username, secret } => {
                let secret = std::str::from_utf8(secret).map_err(|_| AppError::InternalError)?;
                self.harbor
                    .get(url)
                    .map_err(|_| AppError::UpstreamUnreachable)?
                    .basic_auth(username, Some(secret))
            }
            UpstreamAuth::Github { token } => {
                if !is_github_api_url(url) {
                    return Err(AppError::UpstreamUnreachable);
                }
                let token = std::str::from_utf8(token).map_err(|_| AppError::InternalError)?;
                self.github
                    .get(url)
                    .map_err(|_| AppError::UpstreamUnreachable)?
                    .bearer_auth(token)
                    .header("accept", "application/vnd.github+json")
                    .header("x-github-api-version", "2022-11-28")
                    .header("user-agent", "HarborGate")
            }
        };
        let sent = builder.send().await;
        crate::services::app_log::log_outbound(
            "GET",
            url,
            sent.as_ref().ok().map(|r| r.status().as_u16()),
        );
        let response = sent.map_err(|_| AppError::UpstreamUnreachable)?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|text| text.trim().parse::<i64>().ok())
        };
        let retry_after = header("retry-after");
        let ratelimit_remaining = header("x-ratelimit-remaining");
        let ratelimit_reset = header("x-ratelimit-reset");
        let total_count = header("x-total-count");
        let link_next = response
            .headers()
            .get("link")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_link_next);
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?;
        let body = if bytes.len() <= MAX_BODY {
            bytes.to_vec()
        } else {
            Vec::new()
        };
        Ok(UpstreamResponse {
            status,
            retry_after,
            ratelimit_remaining,
            ratelimit_reset,
            total_count,
            link_next,
            body,
        })
    }
}

impl PickerHttp for OutboundPickerHttp {
    fn get<'a>(&'a self, url: &'a Url, auth: UpstreamAuth<'a>) -> UpstreamFuture<'a> {
        Box::pin(self.send(url, auth))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_github_api_host_gets_the_token() {
        let ok = Url::parse("https://api.github.com/user/repos?page=2").unwrap();
        assert!(is_github_api_url(&ok));
        for bad in [
            "http://api.github.com/user/repos",
            "https://evil.example.com/user/repos",
            "https://user:pw@api.github.com/user/repos",
            "https://api.github.com:8443/user/repos",
        ] {
            assert!(!is_github_api_url(&Url::parse(bad).unwrap()), "{bad}");
        }
    }
}
