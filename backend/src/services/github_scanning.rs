//! GitHub code scanning client: gzip and base64 a SARIF document, upload it, and read its
//! processing status (`specs/integrations.md`, SARIF conversion and upload).
//!
//! Each call makes one request and classifies the answer into [`ScanError`]. The worker
//! owns the wait, the retry, and the `sync_reports` write. Every request goes through
//! [`OutboundClient`], so the address check applies. The token is sent only as a bearer
//! header and never appears in an error message.

use std::fmt;
use std::future::Future;
use std::io::Write;

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use reqwest::Url;
use serde_json::Value;

use crate::error::AppError;
use crate::services::credential_probe::valid_github_name;
use crate::services::outbound::{self, OutboundClient, TargetClass};

/// Largest gzip-compressed SARIF that GitHub accepts in one upload.
pub const MAX_COMPRESSED_BYTES: usize = 10 * 1024 * 1024;

/// Seconds to wait when a rate-limited answer gives no retry time.
const DEFAULT_WAIT_SECS: i64 = 60;

/// Largest response body that is parsed. GitHub's bodies used here are small.
const MAX_BODY: usize = 64 * 1024;

/// GitHub's REST API root. The host is fixed (`specs/security.md`, "GitHub token scope").
const GITHUB_API: &str = "https://api.github.com/";

/// The `tool_name` sent with each upload.
const TOOL_NAME: &str = "HarborGate";

/// Why a GitHub code scanning call failed. The `Display` text never includes the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// The gzip-compressed SARIF is over 10 MB. Nothing was uploaded.
    TooLarge,
    /// GitHub rejected the token (`401`).
    Unauthorized,
    /// A `403` that is not a rate limit, with GitHub's message.
    Forbidden(String),
    /// The repository or the SARIF was not found (`404`).
    NotFound,
    /// GitHub is rate limiting. `until` is Unix seconds when the call may be retried.
    RateLimited { until: i64 },
    /// GitHub refused the request as malformed (`400`), with GitHub's message.
    Rejected(String),
    /// GitHub failed (`5xx`), or the answer could not be used.
    Upstream(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::TooLarge => {
                f.write_str("the SARIF is over 10 MB compressed; nothing was uploaded")
            }
            ScanError::Unauthorized => f.write_str("GitHub rejected the token"),
            ScanError::Forbidden(message) => write!(f, "GitHub refused the request: {message}"),
            ScanError::NotFound => {
                f.write_str("GitHub could not find the repository or the SARIF upload")
            }
            ScanError::RateLimited { until } => {
                write!(
                    f,
                    "GitHub rate limit reached; retry after {until} (Unix seconds)"
                )
            }
            ScanError::Rejected(message) => write!(f, "GitHub rejected the request: {message}"),
            ScanError::Upstream(message) => write!(f, "GitHub failed: {message}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Gzips the SARIF document and base64-encodes the result, the `sarif` field of the
/// upload. Fails with [`ScanError::TooLarge`] when the compressed bytes are over
/// [`MAX_COMPRESSED_BYTES`].
pub fn encode_sarif(doc: &Value) -> Result<String, ScanError> {
    let json = serde_json::to_vec(doc).map_err(|_| encoding_failed())?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&json).map_err(|_| encoding_failed())?;
    let gzipped = encoder.finish().map_err(|_| encoding_failed())?;
    if gzipped.len() > MAX_COMPRESSED_BYTES {
        return Err(ScanError::TooLarge);
    }
    Ok(STANDARD.encode(gzipped))
}

fn encoding_failed() -> ScanError {
    ScanError::Rejected("the SARIF could not be encoded".to_owned())
}

/// What GitHub answered: the status, the rate-limit headers that matter, and the parsed
/// JSON body. None of these hold the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResponse {
    pub status: u16,
    /// `retry-after`, in seconds.
    pub retry_after: Option<i64>,
    /// `x-ratelimit-remaining`.
    pub ratelimit_remaining: Option<i64>,
    /// `x-ratelimit-reset`, in Unix seconds.
    pub ratelimit_reset: Option<i64>,
    /// The parsed body, or `null` when it is missing, not JSON, or too large.
    pub body: Value,
}

/// Sends one authenticated request to the GitHub API. The production impl uses the guarded
/// client. Tests use recorded responses and never open a socket.
pub trait ScanHttp {
    /// POSTs `body` as JSON to `path`, which is relative to `https://api.github.com/`.
    fn post(
        &self,
        path: &str,
        token: &[u8],
        body: &Value,
    ) -> impl Future<Output = Result<ScanResponse, ScanError>> + Send;
    /// GETs `path`, which is relative to `https://api.github.com/`.
    fn get(
        &self,
        path: &str,
        token: &[u8],
    ) -> impl Future<Output = Result<ScanResponse, ScanError>> + Send;
}

/// Production HTTP: the guarded client borrowed from [`GithubScanning`].
struct LiveHttp<'a> {
    client: &'a OutboundClient,
}

impl ScanHttp for LiveHttp<'_> {
    async fn post(
        &self,
        path: &str,
        token: &[u8],
        body: &Value,
    ) -> Result<ScanResponse, ScanError> {
        let url = api_url(path)?;
        let builder = self.client.post(&url).map_err(|_| transport())?;
        let response = authorized(builder, token)?
            .json(body)
            .send()
            .await
            .map_err(|_| transport())?;
        read_response(response).await
    }

    async fn get(&self, path: &str, token: &[u8]) -> Result<ScanResponse, ScanError> {
        let url = api_url(path)?;
        let builder = self.client.get(&url).map_err(|_| transport())?;
        let response = authorized(builder, token)?
            .send()
            .await
            .map_err(|_| transport())?;
        read_response(response).await
    }
}

fn api_url(path: &str) -> Result<Url, ScanError> {
    let base = Url::parse(GITHUB_API).map_err(|_| transport())?;
    base.join(path).map_err(|_| transport())
}

/// Adds the bearer token and the headers the credential probes use.
fn authorized(
    builder: reqwest::RequestBuilder,
    token: &[u8],
) -> Result<reqwest::RequestBuilder, ScanError> {
    let token = std::str::from_utf8(token).map_err(|_| ScanError::Unauthorized)?;
    Ok(builder
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
        .header("user-agent", "HarborGate"))
}

async fn read_response(response: reqwest::Response) -> Result<ScanResponse, ScanError> {
    let retry_after = header_i64(&response, "retry-after");
    let ratelimit_remaining = header_i64(&response, "x-ratelimit-remaining");
    let ratelimit_reset = header_i64(&response, "x-ratelimit-reset");
    let status = response.status().as_u16();
    let bytes = response.bytes().await.map_err(|_| transport())?;
    let body = if bytes.len() <= MAX_BODY {
        serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Ok(ScanResponse {
        status,
        retry_after,
        ratelimit_remaining,
        ratelimit_reset,
        body,
    })
}

fn header_i64(response: &reqwest::Response, name: &str) -> Option<i64> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse::<i64>().ok())
}

/// A failure to reach GitHub, or a response that could not be read.
fn transport() -> ScanError {
    ScanError::Upstream("GitHub could not be reached".to_owned())
}

/// Classifies a non-success response (`specs/integrations.md`, rate limits):
/// `401` is Unauthorized; a `403` with `x-ratelimit-remaining: 0` or a `retry-after`
/// header, and any `429`, is RateLimited; any other `403` is Forbidden; `404` is NotFound;
/// `413` is TooLarge; `400` is Rejected; any other status is Upstream.
pub fn classify(response: &ScanResponse, now: i64) -> ScanError {
    let message = response
        .body
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    match response.status {
        401 => ScanError::Unauthorized,
        403 if response.retry_after.is_some() || response.ratelimit_remaining == Some(0) => {
            ScanError::RateLimited {
                until: rate_limit_until(response, now),
            }
        }
        403 => ScanError::Forbidden(message),
        404 => ScanError::NotFound,
        413 => ScanError::TooLarge,
        429 => ScanError::RateLimited {
            until: rate_limit_until(response, now),
        },
        400 => ScanError::Rejected(message),
        status => ScanError::Upstream(format!("GitHub returned status {status}")),
    }
}

/// When to retry a rate-limited call: `retry-after` seconds from now, else the
/// `x-ratelimit-reset` time, else 60 seconds from now.
fn rate_limit_until(response: &ScanResponse, now: i64) -> i64 {
    if let Some(seconds) = response.retry_after {
        now.saturating_add(seconds)
    } else if let Some(reset) = response.ratelimit_reset {
        reset
    } else {
        now.saturating_add(DEFAULT_WAIT_SECS)
    }
}

/// Owner and repository names must pass the same check as the credential probes, before
/// any request is made.
fn check_names(owner: &str, repo: &str) -> Result<(), ScanError> {
    if valid_github_name(owner) && valid_github_name(repo) {
        Ok(())
    } else {
        Err(ScanError::Rejected(
            "the owner or repository name is not valid".to_owned(),
        ))
    }
}

/// The fields of one upload. `git_ref` is the full ref, `refs/heads/<branch>`, and
/// `sarif_b64` is the output of [`encode_sarif`].
pub struct Upload<'a> {
    pub owner: &'a str,
    pub repo: &'a str,
    pub commit_sha: &'a str,
    pub git_ref: &'a str,
    pub sarif_b64: &'a str,
}

/// Uploads a SARIF and returns GitHub's SARIF id. Makes one request; it does not poll.
pub async fn upload_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    upload: &Upload<'_>,
    now: i64,
) -> Result<String, ScanError> {
    check_names(upload.owner, upload.repo)?;
    let path = format!(
        "repos/{}/{}/code-scanning/sarifs",
        upload.owner, upload.repo
    );
    let body = serde_json::json!({
        "commit_sha": upload.commit_sha,
        "ref": upload.git_ref,
        "sarif": upload.sarif_b64,
        "tool_name": TOOL_NAME,
    });
    let response = http.post(&path, token, &body).await?;
    if response.status != 202 {
        return Err(classify(&response, now));
    }
    response
        .body
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ScanError::Upstream("GitHub did not return a SARIF id".to_owned()))
}

/// What GitHub says about a SARIF upload's processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processing {
    Pending,
    Complete,
    /// Processing failed. GitHub's `errors` list is kept as given.
    Failed(Vec<String>),
}

/// Reads the processing status of one upload. Makes one request; it does not poll.
pub async fn status_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    sarif_id: &str,
    now: i64,
) -> Result<Processing, ScanError> {
    check_names(owner, repo)?;
    if sarif_id.is_empty()
        || !sarif_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(ScanError::Rejected("the SARIF id is not valid".to_owned()));
    }
    let path = format!("repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}");
    let response = http.get(&path, token).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    match response
        .body
        .get("processing_status")
        .and_then(Value::as_str)
    {
        Some("pending") => Ok(Processing::Pending),
        Some("complete") => Ok(Processing::Complete),
        Some("failed") => {
            let errors = response
                .body
                .get("errors")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            Ok(Processing::Failed(errors))
        }
        _ => Err(ScanError::Upstream(
            "GitHub returned an unknown processing status".to_owned(),
        )),
    }
}

/// The GitHub code scanning client. Built on the guarded outbound client for
/// `api.github.com`.
pub struct GithubScanning {
    client: OutboundClient,
}

impl GithubScanning {
    pub fn new() -> Result<Self, AppError> {
        let client =
            outbound::client(TargetClass::GitHub, false).map_err(|_| AppError::InternalError)?;
        Ok(Self { client })
    }

    /// Uploads an encoded SARIF and returns GitHub's SARIF id. See [`upload_with`].
    pub async fn upload(
        &self,
        token: &[u8],
        fields: &Upload<'_>,
        now: i64,
    ) -> Result<String, ScanError> {
        let http = LiveHttp {
            client: &self.client,
        };
        upload_with(&http, token, fields, now).await
    }

    /// Reads the processing status of an upload. See [`status_with`].
    pub async fn status(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        sarif_id: &str,
        now: i64,
    ) -> Result<Processing, ScanError> {
        let http = LiveHttp {
            client: &self.client,
        };
        status_with(&http, token, owner, repo, sarif_id, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Read;
    use std::sync::Mutex;

    /// Answers every request with the same response, and records each path and body.
    struct Recorded {
        reply: ScanResponse,
        sent: Mutex<Vec<(String, Value)>>,
    }

    impl Recorded {
        fn new(reply: ScanResponse) -> Self {
            Self {
                reply,
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(String, Value)> {
            self.sent
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone()
        }
    }

    impl ScanHttp for Recorded {
        async fn post(
            &self,
            path: &str,
            _token: &[u8],
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            self.sent
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((path.to_owned(), body.clone()));
            Ok(self.reply.clone())
        }

        async fn get(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            self.sent
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((path.to_owned(), Value::Null));
            Ok(self.reply.clone())
        }
    }

    fn reply(status: u16, body: Value) -> ScanResponse {
        ScanResponse {
            status,
            retry_after: None,
            ratelimit_remaining: None,
            ratelimit_reset: None,
            body,
        }
    }

    fn sample_upload() -> Upload<'static> {
        Upload {
            owner: "octo",
            repo: "app",
            commit_sha: "0123abc",
            git_ref: "refs/heads/main",
            sarif_b64: "payload",
        }
    }

    async fn upload_reply(response: ScanResponse, now: i64) -> Result<String, ScanError> {
        let fake = Recorded::new(response);
        upload_with(&fake, b"token", &sample_upload(), now).await
    }

    #[test]
    fn encode_gzips_then_base64s() {
        let doc = json!({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "HarborGate"}}}]
        });
        let encoded = encode_sarif(&doc).unwrap();
        let gzipped = STANDARD.decode(&encoded).unwrap();
        let mut json = Vec::new();
        flate2::read::GzDecoder::new(gzipped.as_slice())
            .read_to_end(&mut json)
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&json).unwrap(), doc);
    }

    #[test]
    fn over_ten_megabytes_compressed_is_too_large() {
        // Random base64 characters barely compress, so 16 million of them gzip to well
        // over 10 MB. The output is not compressible below the limit.
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let text: String = (0..16_000_000)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                char::from(ALPHABET[((state >> 33) % 64) as usize])
            })
            .collect();
        let doc = json!({"runs": [{"results": [text]}]});
        assert!(matches!(encode_sarif(&doc), Err(ScanError::TooLarge)));
    }

    #[tokio::test]
    async fn upload_202_returns_the_sarif_id() {
        let fake = Recorded::new(reply(202, json!({"id": "abc-123"})));
        let id = upload_with(&fake, b"token", &sample_upload(), 1000).await;
        assert_eq!(id, Ok("abc-123".to_owned()));
        let sent = fake.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "repos/octo/app/code-scanning/sarifs");
        assert_eq!(sent[0].1["commit_sha"], "0123abc");
        assert_eq!(sent[0].1["ref"], "refs/heads/main");
        assert_eq!(sent[0].1["sarif"], "payload");
        assert_eq!(sent[0].1["tool_name"], "HarborGate");
    }

    #[tokio::test]
    async fn upload_403_missing_permission_is_forbidden() {
        let response = reply(
            403,
            json!({"message": "Resource not accessible by personal access token"}),
        );
        assert_eq!(
            upload_reply(response, 1000).await,
            Err(ScanError::Forbidden(
                "Resource not accessible by personal access token".to_owned()
            ))
        );
    }

    #[tokio::test]
    async fn upload_403_with_zero_remaining_is_rate_limited_until_reset() {
        let response = ScanResponse {
            ratelimit_remaining: Some(0),
            ratelimit_reset: Some(1900),
            ..reply(403, json!({"message": "API rate limit exceeded"}))
        };
        assert_eq!(
            upload_reply(response, 1000).await,
            Err(ScanError::RateLimited { until: 1900 })
        );
    }

    #[tokio::test]
    async fn upload_429_uses_retry_after() {
        let response = ScanResponse {
            retry_after: Some(42),
            ..reply(429, json!({"message": "secondary rate limit"}))
        };
        assert_eq!(
            upload_reply(response, 1000).await,
            Err(ScanError::RateLimited { until: 1042 })
        );
    }

    #[tokio::test]
    async fn upload_413_is_too_large() {
        assert_eq!(
            upload_reply(reply(413, json!({})), 1000).await,
            Err(ScanError::TooLarge)
        );
    }

    #[tokio::test]
    async fn status_failed_returns_github_errors() {
        let fake = Recorded::new(reply(
            200,
            json!({
                "processing_status": "failed",
                "errors": ["rule id is missing", "too many results"]
            }),
        ));
        let processing = status_with(&fake, b"token", "octo", "app", "abc-123", 1000).await;
        assert_eq!(
            processing,
            Ok(Processing::Failed(vec![
                "rule id is missing".to_owned(),
                "too many results".to_owned(),
            ]))
        );
        assert_eq!(
            fake.sent()[0].0,
            "repos/octo/app/code-scanning/sarifs/abc-123"
        );
    }

    #[tokio::test]
    async fn status_pending_and_complete() {
        let pending = Recorded::new(reply(200, json!({"processing_status": "pending"})));
        assert_eq!(
            status_with(&pending, b"token", "octo", "app", "abc-123", 1000).await,
            Ok(Processing::Pending)
        );
        let complete = Recorded::new(reply(200, json!({"processing_status": "complete"})));
        assert_eq!(
            status_with(&complete, b"token", "octo", "app", "abc-123", 1000).await,
            Ok(Processing::Complete)
        );
    }
}
