//! The HTTP transport of the registry client: the challenge flow, the redirect loop, the
//! manifest, blob and tag requests, the bounded rate-limit retry, and the byte and digest
//! checks while streaming.
//!
//! Every request goes through [`RegistryClient::send`], which checks the URL with the address
//! policy before it is sent. Redirects are followed by hand, so each hop is checked, and the
//! `Authorization` header is dropped when the origin changes.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, LINK, LOCATION, RETRY_AFTER, WWW_AUTHENTICATE,
};
use reqwest::{Method, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::AppError;
use crate::services::registry::grammar::{
    Reference, hub_name, is_sha256_digest, parse_reference, pull_host, validate_repository,
};
use crate::services::registry::manifest::{self, MANIFEST_ACCEPT, Parsed};
use crate::services::registry::policy::{AddressPolicy, PolicyResolver};

/// The connect timeout for every registry request (`specs/spinoff-local-scan.md`, section 3).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The total time limit for one request. Blob bodies are streamed, so this bounds one request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// The maximum number of redirect hops: reqwest's default limit, kept as an explicit constant.
pub const MAX_REDIRECTS: usize = 10;
/// The byte cap for a manifest or index body. Clients should accept at least 4 MiB.
pub const MANIFEST_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Upper bound on tag-list pages followed in one listing.
pub const MAX_TAG_PAGES: usize = 100;
/// Tags per listing page, sent as `n`.
pub const TAG_PAGE_SIZE: usize = 100;
/// Byte cap for a token response body.
const TOKEN_MAX_BYTES: usize = 64 * 1024;
/// Default token lifetime when the token service omits `expires_in` (distribution token spec).
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(60);
/// The longest token lifetime the client keeps. A longer value is capped.
const MAX_TOKEN_TTL: Duration = Duration::from_secs(300);
/// A `429` is retried inside the client only when its wait is at most this long and the retry
/// count is below [`MAX_429_RETRIES`]. Longer waits return `RateLimited` to the caller, which
/// defers the job (`specs/spinoff-local-scan.md`, section 3).
pub const MAX_IN_CLIENT_WAIT: Duration = Duration::from_secs(10);
/// The number of in-client `429` retries for one request.
pub const MAX_429_RETRIES: usize = 2;
/// The wait used when a `429` carries no usable `Retry-After`.
const DEFAULT_RETRY_WAIT: Duration = Duration::from_secs(1);
/// The user agent sent with every request. It names no secret.
const USER_AGENT: &str = "localscan-registry-client/0.1";

/// A hub credential passed in for one pull. It is held only in the [`PullSession`] of that
/// pull and zeroized when the session ends. It is never logged and never formatted.
pub struct Credential {
    pub username: String,
    pub token: String,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(redacted)")
    }
}

/// A bearer token from a token service, with its expiry. Zeroized on drop.
struct BearerToken {
    value: String,
    expires_at: Instant,
}

impl Drop for BearerToken {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken(redacted)")
    }
}

/// The result of one tag listing. A listing that stopped at the page cap is `complete: false`.
/// The caller records nothing for the missing tail and retries at the next hourly run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tags {
    pub tags: Vec<String>,
    pub complete: bool,
}

/// The registry client. It owns one reqwest client and the address policy, and it holds no
/// credential and no token. Those live in a [`PullSession`].
pub struct RegistryClient {
    http: reqwest::Client,
    policy: AddressPolicy,
}

impl RegistryClient {
    /// Builds the client. Fails only if reqwest cannot be built; the error carries no detail.
    pub fn new(policy: AddressPolicy) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            // No idle pooling: a reused socket skips the resolver, so every request connects
            // through the checked resolver and the address check holds per connection.
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(PolicyResolver(policy.clone())))
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| AppError::UpstreamUnreachable)?;
        Ok(Self { http, policy })
    }

    /// A session for one pull or one listing on one repository of one hub. `hub` is the stored
    /// host (`docker.io` for Docker Hub). The repository name is checked here, before any request.
    pub fn session(
        &self,
        hub: &str,
        repository: &str,
        credential: Option<Credential>,
    ) -> Result<PullSession<'_>, AppError> {
        validate_repository(repository)?;
        let pull_host = pull_host(hub).to_owned();
        let scheme = if self.policy.allows_plain_http(hub_name(&pull_host)) {
            "http"
        } else {
            "https"
        };
        Ok(PullSession {
            client: self,
            base: format!("{scheme}://{pull_host}"),
            repository: repository.to_owned(),
            credential,
            token: None,
        })
    }

    /// Sends one request, following redirects. Returns the final response.
    async fn send(
        &self,
        method: Method,
        start: Url,
        accept: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<reqwest::Response, AppError> {
        let mut url = start;
        let mut auth = authorization.map(str::to_owned);
        let mut hops = 0usize;
        let mut retries = 0usize;
        loop {
            self.policy.check_url(&url).await?;
            let mut request = self.http.request(method.clone(), url.clone());
            if let Some(accept) = accept {
                request = request.header(ACCEPT, accept);
            }
            if let Some(value) = auth.as_deref() {
                request = request.header(AUTHORIZATION, value);
            }
            let response = request
                .send()
                .await
                .map_err(|_| AppError::UpstreamUnreachable)?;
            let status = response.status();
            if status == StatusCode::TOO_MANY_REQUESTS && retries < MAX_429_RETRIES {
                let wait = retry_after(response.headers()).unwrap_or(DEFAULT_RETRY_WAIT);
                if wait <= MAX_IN_CLIENT_WAIT {
                    retries += 1;
                    tokio::time::sleep(wait).await;
                    continue;
                }
            }
            if !status.is_redirection() {
                return Ok(response);
            }
            hops += 1;
            if hops > MAX_REDIRECTS {
                return Err(AppError::UpstreamUnreachable);
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(AppError::UpstreamUnreachable)?;
            let next = url
                .join(location)
                .map_err(|_| AppError::UpstreamUnreachable)?;
            if url.origin() != next.origin() {
                auth = None;
            }
            url = next;
        }
    }
}

/// Reads `Retry-After` in seconds. An HTTP-date or an unusable value gives `None`.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// One pull or listing for one repository on one hub. The token is kept in memory only, and
/// both the token and the credential are zeroized when the session is dropped.
pub struct PullSession<'a> {
    client: &'a RegistryClient,
    /// `scheme://host[:port]`, the pull endpoint. Set once in [`RegistryClient::session`].
    base: String,
    repository: String,
    credential: Option<Credential>,
    token: Option<BearerToken>,
}

impl fmt::Debug for PullSession<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullSession")
            .field("repository", &self.repository)
            .finish_non_exhaustive()
    }
}

impl PullSession<'_> {
    /// `GET /v2/` with no token. Returns the status only: `200` or `401` both show that the
    /// host speaks the registry API.
    pub async fn ping(&mut self) -> Result<StatusCode, AppError> {
        let url = self.url("/v2/")?;
        let response = self.client.send(Method::GET, url, None, None).await?;
        Ok(response.status())
    }

    /// Fetches the manifest or index for `reference` (an exact tag or a `sha256:` digest).
    pub async fn manifest(&mut self, reference: &str) -> Result<Parsed, AppError> {
        let target = match parse_reference(reference)? {
            Reference::Tag(tag) => tag,
            Reference::Digest(digest) => digest,
        };
        let path = format!("/v2/{}/manifests/{target}", self.repository);
        let body = self
            .get_body(&path, MANIFEST_ACCEPT, MANIFEST_MAX_BYTES)
            .await?;
        manifest::parse(&body.content_type, &body.bytes)
    }

    /// Lists the tags of the repository, following `Link: rel="next"` pages. A next link that
    /// names another host or another path is not followed, and the listing ends there, so it
    /// is reported as incomplete. The listing stops at [`MAX_TAG_PAGES`] pages.
    pub async fn list_tags(&mut self) -> Result<Tags, AppError> {
        let mut tags = Vec::new();
        let mut path = format!("/v2/{}/tags/list?n={TAG_PAGE_SIZE}", self.repository);
        for _ in 0..MAX_TAG_PAGES {
            let body = self
                .get_body(&path, "application/json", MANIFEST_MAX_BYTES)
                .await?;
            let page: TagPage = serde_json::from_slice(&body.bytes)
                .map_err(|_| AppError::UpstreamContentInvalid)?;
            tags.extend(page.tags.unwrap_or_default());
            match body.next_link {
                NextLink::Path(next) => path = next,
                NextLink::Absent => {
                    return Ok(Tags {
                        tags,
                        complete: true,
                    });
                }
                NextLink::Refused => {
                    return Ok(Tags {
                        tags,
                        complete: false,
                    });
                }
            }
        }
        Ok(Tags {
            tags,
            complete: false,
        })
    }

    /// Streams the blob `digest` into `sink`. The stream may write at most `budget_bytes`, which
    /// is the bytes the image has left under its pull cap. A stream longer than `expected_size`
    /// (the descriptor size) is a content error, and so is a stream that ends short. The SHA-256
    /// of the stream must equal `digest`. On error the bytes already written are the caller's
    /// to discard, so the caller writes into a temporary location.
    pub async fn blob_to<S: BlobSink>(
        &mut self,
        digest: &str,
        expected_size: u64,
        budget_bytes: u64,
        sink: &mut S,
    ) -> Result<(), AppError> {
        if !is_sha256_digest(digest) {
            return Err(AppError::UpstreamContentInvalid);
        }
        if expected_size > budget_bytes {
            return Err(AppError::ImageTooLarge);
        }
        let path = format!("/v2/{}/blobs/{digest}", self.repository);
        let mut response = self.get(&path, None).await?;
        let mut hasher = Sha256::new();
        let mut seen: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?
        {
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > budget_bytes {
                return Err(AppError::ImageTooLarge);
            }
            if seen > expected_size {
                return Err(AppError::UpstreamContentInvalid);
            }
            hasher.update(&chunk);
            sink.write_chunk(&chunk)?;
        }
        if seen != expected_size {
            return Err(AppError::UpstreamContentInvalid);
        }
        if sha256_digest_text(&hasher.finalize()) != digest {
            return Err(AppError::UpstreamContentInvalid);
        }
        Ok(())
    }

    /// Fetches a path and reads its body up to `max_bytes`, with its content type and the
    /// `Link` next target.
    async fn get_body(
        &mut self,
        path: &str,
        accept: &str,
        max_bytes: usize,
    ) -> Result<Body, AppError> {
        let response = self.get(path, Some(accept)).await?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        let next_link = match response
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
        {
            Some(header) => next_link(header),
            None => NextLink::Absent,
        };
        let bytes = read_capped(response, max_bytes).await?;
        Ok(Body {
            bytes,
            content_type,
            next_link,
        })
    }

    /// A GET with the challenge flow. A `401` with no valid token is answered once: the
    /// challenge is read, a token is fetched, and the request is retried. A `401` that follows
    /// a valid token, or a second `401`, is `UpstreamAuthRejected`.
    async fn get(
        &mut self,
        path: &str,
        accept: Option<&str>,
    ) -> Result<reqwest::Response, AppError> {
        let url = self.url(path)?;
        let auth = self.auth_header();
        let first = self
            .client
            .send(Method::GET, url.clone(), accept, auth.as_deref())
            .await?;
        if first.status() != StatusCode::UNAUTHORIZED {
            return classify(first);
        }
        if auth.is_some() {
            return Err(AppError::UpstreamAuthRejected);
        }
        let challenge = first
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or(AppError::UpstreamAuthRejected)?;
        drop(first);
        self.token = Some(self.fetch_token(&challenge).await?);
        let auth = self.auth_header();
        let retry = self
            .client
            .send(Method::GET, url, accept, auth.as_deref())
            .await?;
        if retry.status() == StatusCode::UNAUTHORIZED {
            return Err(AppError::UpstreamAuthRejected);
        }
        classify(retry)
    }

    /// Requests a token from the realm in the challenge, with the Basic credential when one
    /// exists. The scope is `repository:<name>:pull`; the scope in the challenge is ignored.
    /// The realm is checked by the address policy like any other URL.
    async fn fetch_token(&self, challenge: &str) -> Result<BearerToken, AppError> {
        let params = parse_challenge(challenge)?;
        let realm = params.realm.ok_or(AppError::UpstreamAuthRejected)?;
        let mut url = Url::parse(&realm).map_err(|_| AppError::UpstreamAuthRejected)?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = &params.service {
                query.append_pair("service", service);
            }
            query.append_pair("scope", &format!("repository:{}:pull", self.repository));
        }
        let basic = self.basic_header();
        let response = self
            .client
            .send(Method::GET, url, Some("application/json"), basic.as_deref())
            .await?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(AppError::UpstreamAuthRejected);
        }
        if !status.is_success() {
            return Err(map_status(status));
        }
        let body = read_capped(response, TOKEN_MAX_BYTES).await?;
        let parsed: TokenBody =
            serde_json::from_slice(&body).map_err(|_| AppError::UpstreamContentInvalid)?;
        let value = parsed
            .token
            .or(parsed.access_token)
            .filter(|token| !token.is_empty())
            .ok_or(AppError::UpstreamContentInvalid)?;
        let ttl = parsed
            .expires_in
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TOKEN_TTL)
            .min(MAX_TOKEN_TTL);
        Ok(BearerToken {
            value,
            expires_at: Instant::now() + ttl,
        })
    }

    /// The `Authorization` value for a registry request: the bearer token while it is valid.
    fn auth_header(&self) -> Option<String> {
        self.token
            .as_ref()
            .filter(|token| token.expires_at > Instant::now())
            .map(|token| format!("Bearer {}", token.value))
    }

    /// The `Authorization` value for the token request: Basic, when a credential exists.
    fn basic_header(&self) -> Option<String> {
        self.credential.as_ref().map(|credential| {
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", credential.username, credential.token))
            )
        })
    }

    /// `base` joined with a `/v2/...` path. The path is built from validated parts.
    fn url(&self, path: &str) -> Result<Url, AppError> {
        Url::parse(&format!("{}{path}", self.base)).map_err(|_| AppError::UpstreamUnreachable)
    }
}

/// The body of a successful response, read up to a cap.
struct Body {
    bytes: Vec<u8>,
    content_type: String,
    next_link: NextLink,
}

/// A destination for streamed blob bytes. A pull writes into its temporary directory.
pub trait BlobSink {
    fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), AppError>;
}

impl BlobSink for Vec<u8> {
    fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), AppError> {
        self.extend_from_slice(chunk);
        Ok(())
    }
}

/// The free-disk guard before a pull (`specs/spinoff-local-scan.md`, sections 4 and 13). The
/// caller measures the free bytes of the store volume and passes them with the configured
/// minimum. Below the minimum is `InsufficientDisk`, which the job maps to `not enough disk
/// space`. Measuring the volume is the caller's job, so this client does no filesystem call.
pub fn disk_guard(free_bytes: u64, min_free_bytes: u64) -> Result<(), AppError> {
    if free_bytes >= min_free_bytes {
        Ok(())
    } else {
        Err(AppError::InsufficientDisk)
    }
}

/// The `sha256:` digest text of a 32-byte hash, as lowercase hex.
fn sha256_digest_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(7 + bytes.len() * 2);
    text.push_str("sha256:");
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Maps a success response, or the error for its status.
fn classify(response: reqwest::Response) -> Result<reqwest::Response, AppError> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        Err(map_status(status))
    }
}

/// The error for a non-success status (`specs/spinoff-local-scan.md`, section 6). The body and
/// headers are discarded, so no registry text reaches an error.
fn map_status(status: StatusCode) -> AppError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => AppError::UpstreamAuthRejected,
        StatusCode::NOT_FOUND => AppError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => AppError::RateLimited,
        other => AppError::UpstreamStatus(other.as_u16()),
    }
}

async fn read_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, AppError> {
    let mut out = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::UpstreamUnreachable)?
    {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(AppError::UpstreamContentInvalid);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[derive(Deserialize)]
struct TagPage {
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TokenBody {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

/// The parameters of a `Bearer` challenge that the client uses.
#[derive(Debug, Default, PartialEq, Eq)]
struct Challenge {
    realm: Option<String>,
    service: Option<String>,
}

/// Parses `Bearer realm="...",service="...",scope="..."`.
fn parse_challenge(header: &str) -> Result<Challenge, AppError> {
    let text = header.trim();
    let rest = text
        .strip_prefix("Bearer ")
        .or_else(|| text.strip_prefix("bearer "))
        .ok_or(AppError::UpstreamAuthRejected)?;
    let mut challenge = Challenge::default();
    for part in split_params(rest) {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "realm" => challenge.realm = Some(value),
            "service" => challenge.service = Some(value),
            _ => {}
        }
    }
    Ok(challenge)
}

/// Splits a parameter list on commas that are outside quotes.
fn split_params(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                parts.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

/// The paging state a response's `Link` header gives.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NextLink {
    /// No `rel="next"` entry: this is the last page.
    Absent,
    /// A `rel="next"` target as a `/v2/...` path with its query.
    Path(String),
    /// A `rel="next"` target that is absolute, names another host, or is not under `/v2/`.
    /// It is not followed, so the listing is incomplete.
    Refused,
}

/// Reads the `rel="next"` entry of a `Link` header.
fn next_link(header: &str) -> NextLink {
    for part in header.split(',') {
        let part = part.trim();
        if !part.contains("rel=\"next\"") {
            continue;
        }
        let target = part.split(';').next().unwrap_or("").trim();
        let Some(target) = target
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
        else {
            return NextLink::Refused;
        };
        return if target.starts_with("/v2/") && !target.contains("//") {
            NextLink::Path(target.to_owned())
        } else {
            NextLink::Refused
        };
    }
    NextLink::Absent
}

#[cfg(test)]
mod tests;
