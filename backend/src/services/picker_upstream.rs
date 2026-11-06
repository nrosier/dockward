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
use crate::services::github_scanning::parse_link_next;
use crate::services::github_url::GithubTarget;
use crate::services::outbound::{self, OutboundClient, TargetClass};

/// Largest body that is kept. A page of 100 GitHub repositories is far below this.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// A body that is read one chunk at a time. The production source is the HTTP response;
/// tests use a fake stream.
trait ChunkSource {
    /// The next chunk, or `None` at the end.
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, AppError>;
}

impl ChunkSource for reqwest::Response {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, AppError> {
        self.chunk()
            .await
            .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
            .map_err(|_| AppError::UpstreamUnreachable)
    }
}

/// Reads a body chunk by chunk and refuses it as soon as it is over `max`, so an oversized
/// or endless body is never buffered whole. A declared length over `max` is refused before
/// any read. A refused body is the fixed `upstream_unreachable` error.
async fn read_capped(
    source: &mut impl ChunkSource,
    declared: Option<u64>,
    max: usize,
) -> Result<Vec<u8>, AppError> {
    if declared.is_some_and(|length| length > max as u64) {
        return Err(AppError::UpstreamUnreachable);
    }
    let mut body = Vec::new();
    while let Some(chunk) = source.next_chunk().await? {
        if body.len().saturating_add(chunk.len()) > max {
            return Err(AppError::UpstreamUnreachable);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

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
    /// The body. A body over the size cap is refused with `upstream_unreachable`.
    pub body: Vec<u8>,
}

/// Sends one picker GET. The production transport uses the guarded clients; tests use
/// recorded answers and never open a socket.
pub trait PickerHttp: Send + Sync {
    fn get<'a>(&'a self, url: &'a Url, auth: UpstreamAuth<'a>) -> UpstreamFuture<'a>;
}

/// The production transport: one guarded client per service.
pub struct OutboundPickerHttp {
    harbor: OutboundClient,
    github: OutboundClient,
    target: GithubTarget,
}

impl OutboundPickerHttp {
    /// `allow_private_harbor` is `HARBORGATE_ALLOW_PRIVATE_HARBOR`.
    pub fn new(allow_private_harbor: bool, target: GithubTarget) -> Result<Self, AppError> {
        let harbor = outbound::client(TargetClass::Harbor, allow_private_harbor)
            .map_err(|_| AppError::InternalError)?;
        let github =
            outbound::github_client(target.clone()).map_err(|_| AppError::InternalError)?;
        Ok(Self {
            harbor,
            github,
            target,
        })
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
                // The token goes only to the configured API host and base path.
                if !self.target.current().is_api_url(url) {
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
        let mut response = response;
        let declared = response.content_length();
        let body = read_capped(&mut response, declared, MAX_BODY).await?;
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
        let urls = crate::services::github_url::GithubUrls::default();
        let ok = Url::parse("https://api.github.com/user/repos?page=2").unwrap();
        assert!(urls.is_api_url(&ok));
        for bad in [
            "http://api.github.com/user/repos",
            "https://evil.example.com/user/repos",
            "https://user:pw@api.github.com/user/repos",
            "https://api.github.com:8443/user/repos",
        ] {
            assert!(!urls.is_api_url(&Url::parse(bad).unwrap()), "{bad}");
        }
    }

    /// A fake body of `chunks` chunks of `size` bytes; `pulled` counts the chunks read.
    struct Fake {
        chunks: usize,
        size: usize,
        pulled: usize,
    }

    impl ChunkSource for Fake {
        async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, AppError> {
            if self.pulled >= self.chunks {
                return Ok(None);
            }
            self.pulled += 1;
            Ok(Some(vec![7u8; self.size]))
        }
    }

    #[tokio::test]
    async fn a_declared_length_over_the_cap_is_refused_before_any_read() {
        let mut fake = Fake {
            chunks: 1,
            size: 1,
            pulled: 0,
        };
        let result = read_capped(&mut fake, Some(11), 10).await;
        assert_eq!(result, Err(AppError::UpstreamUnreachable));
        assert_eq!(fake.pulled, 0, "no chunk was read");
    }

    #[tokio::test]
    async fn a_stream_past_the_cap_is_refused_without_buffering_it_all() {
        // A stream of a million 4-byte chunks with no declared length: it is refused at
        // the chunk that passes the cap, long before the end.
        let mut fake = Fake {
            chunks: 1_000_000,
            size: 4,
            pulled: 0,
        };
        let result = read_capped(&mut fake, None, 10).await;
        assert_eq!(result, Err(AppError::UpstreamUnreachable));
        assert_eq!(fake.pulled, 3, "stopped at the chunk that passed the cap");
    }

    #[tokio::test]
    async fn a_normal_body_is_read_whole_and_exactly_the_cap_is_kept() {
        let mut fake = Fake {
            chunks: 2,
            size: 2,
            pulled: 0,
        };
        assert_eq!(read_capped(&mut fake, Some(4), 10).await, Ok(vec![7; 4]));
        let mut exact = Fake {
            chunks: 1,
            size: 4,
            pulled: 0,
        };
        assert_eq!(
            read_capped(&mut exact, None, 4).await.map(|b| b.len()),
            Ok(4)
        );
    }
}
