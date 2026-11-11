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
use serde_json::{Value, json};

use crate::error::AppError;
use std::sync::Arc;

use crate::services::credential_probe::valid_github_name;
use crate::services::github_url::{GithubTarget, GithubUrls};
use crate::services::outbound::{self, OutboundClient};
use crate::services::publish::Clock;

/// Largest gzip-compressed SARIF that GitHub accepts in one upload.
pub const MAX_COMPRESSED_BYTES: usize = 10 * 1024 * 1024;

/// Seconds to wait when a rate-limited answer gives no retry time. Also the picker fallback
/// (`services/pickers.rs`).
pub const DEFAULT_WAIT_SECS: i64 = 60;

/// Largest response body that is parsed. The upload calls return small bodies, but a page of
/// 100 issues can carry 100 bodies of up to 65,536 characters each (GitHub's limit), about
/// 6.5 MB. A 64 KiB cap turned such a page into `null`, so the cap is 8 MiB. Only one
/// response is held at a time.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// The `tool_name` sent with each upload.
const TOOL_NAME: &str = "Dockward";

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
    /// A list ran past its deadline between pages. Only the paged list calls return this.
    DeadlineExceeded,
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
            ScanError::DeadlineExceeded => f.write_str("the GitHub list ran past its deadline"),
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
    /// The URL of the `rel="next"` page in the `link` header, if there is one.
    pub link_next: Option<String>,
    /// The parsed body, or `null` when it is missing, not JSON, or too large.
    pub body: Value,
}

/// Sends one authenticated request to the GitHub API. The production impl uses the guarded
/// client. Tests use recorded responses and never open a socket.
pub trait ScanHttp {
    /// POSTs `body` as JSON to `path`, which is relative to the configured API base URL.
    fn post(
        &self,
        path: &str,
        token: &[u8],
        body: &Value,
    ) -> impl Future<Output = Result<ScanResponse, ScanError>> + Send;
    /// PATCHes `body` as JSON to `path`, which is relative to the configured API base URL.
    fn patch(
        &self,
        path: &str,
        token: &[u8],
        body: &Value,
    ) -> impl Future<Output = Result<ScanResponse, ScanError>> + Send;
    /// GETs `path`, which is relative to the configured API base URL.
    fn get(
        &self,
        path: &str,
        token: &[u8],
    ) -> impl Future<Output = Result<ScanResponse, ScanError>> + Send;
    /// DELETEs `path`, which is relative to the configured API base URL. No body is sent.
    fn delete(
        &self,
        path: &str,
        token: &[u8],
    ) -> impl Future<Output = Result<ScanResponse, ScanError>> + Send;
    /// The GitHub URLs the requests go to. A `Link` next URL is checked against them. Test
    /// fakes keep the default, `https://api.github.com`.
    fn urls(&self) -> Arc<GithubUrls> {
        Arc::new(GithubUrls::default())
    }
}

/// Production HTTP: the guarded client borrowed from [`GithubScanning`].
pub(crate) struct LiveHttp<'a> {
    pub(crate) client: &'a OutboundClient,
    /// The configured URLs, read once per call so one call uses one consistent base.
    pub(crate) urls: Arc<GithubUrls>,
}

impl ScanHttp for LiveHttp<'_> {
    async fn post(
        &self,
        path: &str,
        token: &[u8],
        body: &Value,
    ) -> Result<ScanResponse, ScanError> {
        let url = api_url(&self.urls, path)?;
        let builder = self.client.post(&url).map_err(|_| transport())?;
        let sent = authorized(builder, token)?.json(body).send().await;
        logged_response("POST", &url, sent).await
    }

    async fn patch(
        &self,
        path: &str,
        token: &[u8],
        body: &Value,
    ) -> Result<ScanResponse, ScanError> {
        let url = api_url(&self.urls, path)?;
        let builder = self.client.patch(&url).map_err(|_| transport())?;
        let sent = authorized(builder, token)?.json(body).send().await;
        logged_response("PATCH", &url, sent).await
    }

    async fn get(&self, path: &str, token: &[u8]) -> Result<ScanResponse, ScanError> {
        let url = api_url(&self.urls, path)?;
        let builder = self.client.get(&url).map_err(|_| transport())?;
        let sent = authorized(builder, token)?.send().await;
        logged_response("GET", &url, sent).await
    }

    async fn delete(&self, path: &str, token: &[u8]) -> Result<ScanResponse, ScanError> {
        let url = api_url(&self.urls, path)?;
        let builder = self.client.delete(&url).map_err(|_| transport())?;
        let sent = authorized(builder, token)?.send().await;
        logged_response("DELETE", &url, sent).await
    }

    fn urls(&self) -> Arc<GithubUrls> {
        Arc::clone(&self.urls)
    }
}

/// Logs the request at `debug` (method, URL path, status; `app_log::log_outbound`) and
/// reads the response.
async fn logged_response(
    method: &str,
    url: &Url,
    sent: Result<reqwest::Response, reqwest::Error>,
) -> Result<ScanResponse, ScanError> {
    crate::services::app_log::log_outbound(
        method,
        url,
        sent.as_ref().ok().map(|r| r.status().as_u16()),
    );
    read_response(sent.map_err(|_| transport())?).await
}

/// The request URL: the configured API base plus `path`. The token is sent with every
/// request, so a path that would leave the API host or the base path is refused.
fn api_url(urls: &GithubUrls, path: &str) -> Result<Url, ScanError> {
    urls.api_url(path).ok_or_else(transport)
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
        .header("user-agent", "Dockward"))
}

async fn read_response(response: reqwest::Response) -> Result<ScanResponse, ScanError> {
    let retry_after = header_i64(&response, "retry-after");
    let ratelimit_remaining = header_i64(&response, "x-ratelimit-remaining");
    let ratelimit_reset = header_i64(&response, "x-ratelimit-reset");
    let link_next = response
        .headers()
        .get("link")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_link_next);
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
        link_next,
        body,
    })
}

/// The URL marked `rel="next"` in a `link` header value, such as
/// `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=9>; rel="last"`.
pub fn parse_link_next(header: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let (target, params) = part.split_once(';')?;
        let is_next = params
            .split(';')
            .any(|param| param.trim().replace(' ', "") == "rel=\"next\"");
        let url = target.trim().strip_prefix('<')?.strip_suffix('>')?;
        is_next.then(|| url.to_owned())
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
pub(crate) fn check_names(owner: &str, repo: &str) -> Result<(), ScanError> {
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

/// The most pages the analysis and alert lists read (100 items each) before they give up.
const MAX_LIST_PAGES: usize = 100;

/// The dismissal reasons GitHub accepts for a code scanning alert.
pub const DISMISSAL_REASONS: &[&str] =
    &["false positive", "won't fix", "used in tests", "mitigated"];

/// One code scanning analysis, as far as the legacy retirement needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// GitHub's analysis id. Parsed as `u64`, so it is only ever formatted into a path.
    pub id: u64,
    pub git_ref: Option<String>,
    pub category: Option<String>,
    pub tool_name: Option<String>,
    pub deletable: bool,
    /// `created_at` as GitHub sends it (ISO 8601, so text order is time order).
    pub created_at: Option<String>,
    /// The API path of the `confirm_delete_url` the answer carried, when it passes
    /// [`confirm_path`]. A link on any other host is dropped and never fetched.
    pub confirm_path: Option<String>,
}

/// One code scanning alert, as far as the carry-over needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The alert number. Parsed as `u64`, so it is only ever formatted into a path.
    pub number: u64,
    pub rule_id: String,
    pub state: String,
    pub dismissed_reason: Option<String>,
    pub dismissed_comment: Option<String>,
    /// `most_recent_instance.category`.
    pub category: Option<String>,
}

/// The query of an alert list: the tool, the state and the full ref.
#[derive(Debug, Clone, Copy)]
pub struct AlertQuery<'a> {
    pub tool_name: &'a str,
    pub state: &'a str,
    pub git_ref: &'a str,
}

/// The dismissal sent with a PATCH: a reason from [`DISMISSAL_REASONS`] and an optional comment.
#[derive(Debug, Clone, Copy)]
pub struct Dismissal<'a> {
    pub reason: &'a str,
    pub comment: Option<&'a str>,
}

fn bad_answer() -> ScanError {
    ScanError::Upstream("GitHub returned an unexpected answer".to_owned())
}

/// A query value from our own code (a tool name, a state, a ref). Anything outside a small
/// set of characters is refused, so no value can add a parameter.
fn query_value(text: &str) -> Result<&str, ScanError> {
    if !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
    {
        Ok(text)
    } else {
        Err(ScanError::Rejected("a query value is not valid".to_owned()))
    }
}

/// The API path of a `confirm_delete_url`, for the analysis of `owner`/`repo` that is being
/// deleted. The link must be https on the configured API host, under its base path, and its path
/// must be exactly `repos/{owner}/{repo}/code-scanning/analyses/{id}` (owner and repo compared
/// case-insensitively, `id` a `u64`) with the single query `confirm_delete`. This is the shape
/// GitHub documents for "Delete a code scanning analysis". Any other link gives `None`, and the
/// caller never fetches it.
pub(crate) fn confirm_path_for(
    urls: &GithubUrls,
    owner: &str,
    repo: &str,
    link: &str,
) -> Option<String> {
    let path = urls.relative_path(link)?;
    urls.api_url(&path)?;
    let (route, query) = path.split_once('?')?;
    if query != "confirm_delete" {
        return None;
    }
    let mut parts = route.split('/');
    let (
        Some("repos"),
        Some(link_owner),
        Some(link_repo),
        Some("code-scanning"),
        Some("analyses"),
        Some(id),
        None,
    ) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    )
    else {
        return None;
    };
    let same_name = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    if !same_name(link_owner, owner) || !same_name(link_repo, repo) || id.parse::<u64>().is_err() {
        return None;
    }
    Some(path)
}

/// Reads the `confirm_delete_url` of a delete answer for `owner`/`repo`: none when it is absent
/// or `null`, the validated path when it passes [`confirm_path_for`], and an error otherwise.
pub(crate) fn confirm_answer_for(
    urls: &GithubUrls,
    owner: &str,
    repo: &str,
    body: &Value,
) -> Result<Option<String>, ScanError> {
    match body.get("confirm_delete_url") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(link)) => confirm_path_for(urls, owner, repo, link)
            .map(Some)
            .ok_or_else(|| {
                ScanError::Upstream("GitHub sent a confirm link for another analysis".to_owned())
            }),
        Some(_) => Err(bad_answer()),
    }
}

fn parse_analysis(
    urls: &GithubUrls,
    owner: &str,
    repo: &str,
    item: &Value,
) -> Result<Analysis, ScanError> {
    let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned);
    Ok(Analysis {
        id: item
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(bad_answer)?,
        git_ref: text(item.get("ref")),
        category: text(item.get("category")),
        tool_name: text(item.get("tool").and_then(|tool| tool.get("name"))),
        deletable: item
            .get("deletable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        created_at: text(item.get("created_at")),
        confirm_path: text(item.get("confirm_delete_url"))
            .and_then(|link| confirm_path_for(urls, owner, repo, &link)),
    })
}

fn parse_alert(item: &Value) -> Result<Alert, ScanError> {
    let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned);
    Ok(Alert {
        number: item
            .get("number")
            .and_then(Value::as_u64)
            .ok_or_else(bad_answer)?,
        rule_id: text(item.get("rule").and_then(|rule| rule.get("id"))).ok_or_else(bad_answer)?,
        state: text(item.get("state")).ok_or_else(bad_answer)?,
        dismissed_reason: text(item.get("dismissed_reason")),
        dismissed_comment: text(item.get("dismissed_comment")),
        category: text(
            item.get("most_recent_instance")
                .and_then(|instance| instance.get("category")),
        ),
    })
}

/// Reads every page of a list, following `link: rel="next"` through the URLs' own check. A next
/// link to another host is refused and never fetched. The clock is checked before each page
/// request, so a list that passes `deadline` between pages stops with
/// [`ScanError::DeadlineExceeded`] and requests no further page.
async fn list_pages<H: ScanHttp, C: Clock, T>(
    http: &H,
    token: &[u8],
    first: String,
    clock: &C,
    deadline: i64,
    parse: impl Fn(&Value) -> Result<T, ScanError>,
) -> Result<Vec<T>, ScanError> {
    let mut path = first;
    let mut found = Vec::new();
    for _ in 0..MAX_LIST_PAGES {
        if clock.now() >= deadline {
            return Err(ScanError::DeadlineExceeded);
        }
        let response = http.get(&path, token).await?;
        if response.status != 200 {
            return Err(classify(&response, clock.now()));
        }
        let items = response.body.as_array().ok_or_else(bad_answer)?;
        for item in items {
            found.push(parse(item)?);
        }
        match response.link_next.as_deref() {
            Some(link) => {
                path = http.urls().relative_path(link).ok_or_else(|| {
                    ScanError::Upstream("GitHub sent a next link to another host".to_owned())
                })?;
            }
            None => return Ok(found),
        }
    }
    Err(ScanError::Upstream(
        "GitHub returned too many pages".to_owned(),
    ))
}

/// Lists the code scanning analyses of one tool, all pages. See [`Analysis`]. `deadline` is
/// Unix seconds; see [`list_pages`].
pub async fn list_analyses_with<H: ScanHttp, C: Clock>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    tool_name: &str,
    clock: &C,
    deadline: i64,
) -> Result<Vec<Analysis>, ScanError> {
    check_names(owner, repo)?;
    let tool = query_value(tool_name)?;
    let first =
        format!("repos/{owner}/{repo}/code-scanning/analyses?tool_name={tool}&per_page=100");
    let urls = http.urls();
    list_pages(http, token, first, clock, deadline, |item| {
        parse_analysis(&urls, owner, repo, item)
    })
    .await
}

/// DELETEs one analysis with `confirm_delete=true`. Returns the validated path of the next
/// confirm-delete link, or `None` when the delete is complete. See [`follow_confirm_with`].
pub async fn delete_analysis_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    id: u64,
    now: i64,
) -> Result<Option<String>, ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/code-scanning/analyses/{id}?confirm_delete=true");
    let response = http.delete(&path, token).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    confirm_answer_for(&http.urls(), owner, repo, &response.body)
}

/// DELETEs a confirm-delete path returned by [`delete_analysis_with`] or by an earlier call
/// here. The path is checked again before the request. Returns the next path, or `None`.
pub async fn follow_confirm_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    link: &str,
    now: i64,
) -> Result<Option<String>, ScanError> {
    let urls = http.urls();
    let path = confirm_path_for(&urls, owner, repo, link).ok_or_else(|| {
        ScanError::Upstream("GitHub sent a confirm link for another analysis".to_owned())
    })?;
    let response = http.delete(&path, token).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    confirm_answer_for(&urls, owner, repo, &response.body)
}

/// Lists the code scanning alerts for a tool, state and ref, all pages. See [`Alert`]. `deadline`
/// is Unix seconds; see [`list_pages`].
pub async fn list_alerts_with<H: ScanHttp, C: Clock>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    query: AlertQuery<'_>,
    clock: &C,
    deadline: i64,
) -> Result<Vec<Alert>, ScanError> {
    check_names(owner, repo)?;
    let tool = query_value(query.tool_name)?;
    let state = query_value(query.state)?;
    let git_ref = query_value(query.git_ref)?;
    let first = format!(
        "repos/{owner}/{repo}/code-scanning/alerts?tool_name={tool}&state={state}&ref={git_ref}&per_page=100"
    );
    list_pages(http, token, first, clock, deadline, parse_alert).await
}

/// PATCHes one alert to `dismissed`. The reason must be one of [`DISMISSAL_REASONS`].
pub async fn dismiss_alert_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    dismissal: Dismissal<'_>,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    if !DISMISSAL_REASONS.contains(&dismissal.reason) {
        return Err(ScanError::Rejected(
            "the dismissal reason is not allowed".to_owned(),
        ));
    }
    let path = format!("repos/{owner}/{repo}/code-scanning/alerts/{number}");
    let body = json!({
        "state": "dismissed",
        "dismissed_reason": dismissal.reason,
        "dismissed_comment": dismissal.comment,
    });
    let response = http.patch(&path, token, &body).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// The GitHub code scanning client. Built on the guarded outbound client for the configured
/// GitHub API base URL.
pub struct GithubScanning {
    client: OutboundClient,
    target: GithubTarget,
}

impl GithubScanning {
    pub fn new(target: GithubTarget) -> Result<Self, AppError> {
        let client =
            outbound::github_client(target.clone()).map_err(|_| AppError::InternalError)?;
        Ok(Self { client, target })
    }

    fn http(&self) -> LiveHttp<'_> {
        LiveHttp {
            client: &self.client,
            urls: self.target.current(),
        }
    }

    /// Uploads an encoded SARIF and returns GitHub's SARIF id. See [`upload_with`].
    pub async fn upload(
        &self,
        token: &[u8],
        fields: &Upload<'_>,
        now: i64,
    ) -> Result<String, ScanError> {
        upload_with(&self.http(), token, fields, now).await
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
        status_with(&self.http(), token, owner, repo, sarif_id, now).await
    }

    /// Lists the analyses of one tool, all pages. See [`list_analyses_with`].
    pub async fn list_analyses<C: Clock>(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        tool_name: &str,
        clock: &C,
        deadline: i64,
    ) -> Result<Vec<Analysis>, ScanError> {
        list_analyses_with(&self.http(), token, owner, repo, tool_name, clock, deadline).await
    }

    /// DELETEs one analysis. See [`delete_analysis_with`].
    pub async fn delete_analysis(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        id: u64,
        now: i64,
    ) -> Result<Option<String>, ScanError> {
        delete_analysis_with(&self.http(), token, owner, repo, id, now).await
    }

    /// Follows a confirm-delete link of `owner`/`repo`. See [`follow_confirm_with`].
    pub async fn follow_confirm(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        link: &str,
        now: i64,
    ) -> Result<Option<String>, ScanError> {
        follow_confirm_with(&self.http(), token, owner, repo, link, now).await
    }

    /// Lists the alerts of one tool, state and ref, all pages. See [`list_alerts_with`].
    pub async fn list_alerts<C: Clock>(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        query: AlertQuery<'_>,
        clock: &C,
        deadline: i64,
    ) -> Result<Vec<Alert>, ScanError> {
        list_alerts_with(&self.http(), token, owner, repo, query, clock, deadline).await
    }

    /// Dismisses one alert. See [`dismiss_alert_with`].
    pub async fn dismiss_alert(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        dismissal: Dismissal<'_>,
        now: i64,
    ) -> Result<(), ScanError> {
        dismiss_alert_with(&self.http(), token, owner, repo, number, dismissal, now).await
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

        async fn patch(
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

        async fn delete(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
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
            link_next: None,
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
    fn api_url_never_leaves_the_api_host() {
        let urls = GithubUrls::default();
        assert_eq!(
            api_url(&urls, "repos/octo/app/issues?page=2").map(String::from),
            Ok("https://api.github.com/repos/octo/app/issues?page=2".to_owned())
        );
        for path in [
            "//evil.example/x",
            "///evil.example/x",
            "https://evil.example/x",
            "http://api.github.com/x",
            "https://api.github.com@evil.example/x",
            "https://api.github.com:8443/x",
        ] {
            assert!(api_url(&urls, path).is_err(), "{path} should be refused");
        }
    }

    #[test]
    fn link_header_next_is_parsed() {
        let header = "<https://api.github.com/repositories/1/issues?page=2>; rel=\"next\", <https://api.github.com/repositories/1/issues?page=5>; rel=\"last\"";
        assert_eq!(
            parse_link_next(header),
            Some("https://api.github.com/repositories/1/issues?page=2".to_owned())
        );
        assert_eq!(
            parse_link_next("<https://api.github.com/x?page=1>; rel=\"prev\""),
            None
        );
        assert_eq!(parse_link_next(""), None);
    }

    #[test]
    fn encode_gzips_then_base64s() {
        let doc = json!({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Dockward"}}}]
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
        assert_eq!(sent[0].1["tool_name"], "Dockward");
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

    /// A clock whose value a test sets. The list reads it before each page, so a value set
    /// between two page requests lands between pages.
    struct PagedClock {
        now: Mutex<i64>,
    }

    impl PagedClock {
        fn at(now: i64) -> Self {
            Self {
                now: Mutex::new(now),
            }
        }

        fn set(&self, now: i64) {
            *self.now.lock().unwrap_or_else(|p| p.into_inner()) = now;
        }
    }

    impl Clock for PagedClock {
        fn now(&self) -> i64 {
            *self.now.lock().unwrap_or_else(|p| p.into_inner())
        }

        async fn sleep(&self, _duration: std::time::Duration) {}
    }

    /// Serves two pages of analyses. Page 1 links to page 2. Each page request is recorded, and
    /// `move_clock_after` moves the clock once a page has been served.
    struct TwoPages<'a> {
        clock: &'a PagedClock,
        /// The clock value to set after the page with this index (0 or 1) is served.
        move_clock_after: Option<(usize, i64)>,
        requested: Mutex<Vec<String>>,
    }

    impl TwoPages<'_> {
        fn requested(&self) -> Vec<String> {
            self.requested
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }

    impl ScanHttp for TwoPages<'_> {
        async fn post(
            &self,
            _path: &str,
            _token: &[u8],
            _body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            Err(ScanError::Upstream("unused".to_owned()))
        }

        async fn patch(
            &self,
            _path: &str,
            _token: &[u8],
            _body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            Err(ScanError::Upstream("unused".to_owned()))
        }

        async fn get(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            let index = {
                let mut requested = self.requested.lock().unwrap_or_else(|p| p.into_inner());
                requested.push(path.to_owned());
                requested.len() - 1
            };
            let (body, link_next) = if index == 0 {
                (
                    json!([{"id": 1, "ref": "refs/heads/main", "tool": {"name": "harborgate"}}]),
                    Some("https://api.github.com/repos/octo/app/code-scanning/analyses?page=2"),
                )
            } else {
                (
                    json!([{"id": 2, "ref": "refs/heads/main", "tool": {"name": "harborgate"}}]),
                    None,
                )
            };
            if let Some((after, value)) = self.move_clock_after
                && after == index
            {
                self.clock.set(value);
            }
            Ok(ScanResponse {
                status: 200,
                retry_after: None,
                ratelimit_remaining: None,
                ratelimit_reset: None,
                link_next: link_next.map(str::to_owned),
                body,
            })
        }

        async fn delete(&self, _path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            Err(ScanError::Upstream("a list makes no DELETE".to_owned()))
        }
    }

    #[tokio::test]
    async fn a_list_past_its_deadline_between_pages_stops_before_the_next_page() {
        // The clock reads 1000 before page 1 and passes the deadline of 1500 once page 1 is
        // served. Page 2 must not be requested.
        let clock = PagedClock::at(1000);
        let http = TwoPages {
            clock: &clock,
            move_clock_after: Some((0, 1600)),
            requested: Mutex::new(Vec::new()),
        };
        let outcome =
            list_analyses_with(&http, b"token", "octo", "app", "harborgate", &clock, 1500).await;
        assert_eq!(outcome, Err(ScanError::DeadlineExceeded));
        assert_eq!(
            http.requested().len(),
            1,
            "page 2 is never requested once the deadline has passed"
        );
    }

    #[tokio::test]
    async fn a_list_that_finishes_inside_its_deadline_completes_every_page() {
        // The clock stays inside the budget through both pages.
        let clock = PagedClock::at(1000);
        let http = TwoPages {
            clock: &clock,
            move_clock_after: Some((0, 1400)),
            requested: Mutex::new(Vec::new()),
        };
        let outcome =
            list_analyses_with(&http, b"token", "octo", "app", "harborgate", &clock, 1500).await;
        let ids: Vec<u64> = outcome
            .unwrap_or_else(|err| panic!("list failed: {err}"))
            .iter()
            .map(|analysis| analysis.id)
            .collect();
        assert_eq!(ids, vec![1, 2]);
        assert_eq!(http.requested().len(), 2, "both pages are requested");
    }
}
