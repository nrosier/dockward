//! Mapping pickers (`specs/integrations.md`, "Mapping pickers"; `specs/api.md`, Pickers).
//!
//! Live Harbor project and repository lists and the GitHub repository list, fetched on the
//! server with the caller's own credential, cached in memory for 5 minutes, filtered by the
//! caller's hidden items, and paged. Also the source suggestion and the hide list.
//!
//! Secrets: the decrypted credential lives in a local buffer for one call. Responses hold
//! names only. Upstream bodies, headers and URLs are never returned or logged; every error
//! is a fixed text.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::api::hardening::RateLimiter;
use crate::auth::crypto::DerivedKey;
use crate::db::credentials::CredentialRow;
use crate::db::picker_hidden::{self as db, HiddenRow};
use crate::error::{AppError, ErrorDetail};
use crate::services::credential_probe::{encode_segment, valid_github_name, valid_harbor_name};
use crate::services::credentials::{self, SERVICE_GITHUB, SERVICE_HARBOR};
use crate::services::github_scanning::DEFAULT_WAIT_SECS;
use crate::services::harbor_client::{artifact_url, artifacts_list_url, parse_artifact_list};
use crate::services::pagination::Pagination;
use crate::services::picker_upstream::{
    OutboundPickerHttp, PickerHttp, UpstreamAuth, UpstreamResponse, is_github_api_url,
};
use crate::services::time;
use crate::worker::now_secs;

/// How long a list or suggestion stays cached (`specs/integrations.md`).
pub const CACHE_TTL: Duration = Duration::from_secs(300);
/// Most cache entries; the oldest is evicted first.
pub const MAX_ENTRIES: usize = 500;
/// Upstream page size. 100 is Harbor's maximum.
pub const UPSTREAM_PAGE_SIZE: u32 = 100;
/// Most upstream pages one fill reads (1,000 items).
pub const MAX_PAGES: u32 = 10;
/// Most hidden items per user.
pub const HIDDEN_CAP: i64 = 1000;
/// Longest search text.
pub const MAX_Q_CHARS: usize = 100;
/// Longest upstream rate-limit wait that is honoured.
const MAX_BLOCK_SECS: i64 = 3600;
/// Picker list and suggestion requests per user per minute (`specs/api.md`, Pickers).
pub const USER_LIMIT: u32 = 60;

const MSG_USER_LIMIT: &str = "Too many picker requests. Try again in a minute.";
const MSG_WRONG_TYPE: &str = "This credential is the wrong type for this list.";
const MSG_HARBOR_IDENTITY: &str =
    "The Harbor credential does not work. Test it on the Account page.";
const MSG_GITHUB_INVALID: &str = "The GitHub token is not valid. Test it on the Account page.";
const MSG_GITHUB_FORBIDDEN: &str =
    "The GitHub token cannot list repositories. Check its permissions.";
const MSG_HARBOR_RATE: &str = "Harbor rate limit reached. Try again later.";
const MSG_GITHUB_RATE: &str = "GitHub rate limit reached. Try again later.";
const MSG_REPO_LIST_FORBIDDEN: &str = "The Harbor robot cannot list repositories in this project. Grant it Repository List and Repository Read.";
const MSG_ARTIFACT_FORBIDDEN: &str = "The Harbor robot cannot read artifacts in this repository. Grant it Artifact List and Artifact Read.";
const MSG_PROJECT_NOT_FOUND: &str = "Harbor project not found.";
const MSG_REPOSITORY_NOT_FOUND: &str = "Harbor repository not found.";
const MSG_BAD_NAME: &str = "The Harbor project or repository name is not valid.";

/// A failure of a picker call. `App` is a normal error; `Fixed` carries its own status,
/// code, fixed message and optional `detail` code (the custom `404` text, the `422` answers
/// with their detail, and the `429` messages with `Retry-After`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerFail {
    App(AppError),
    Fixed {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        detail: Option<ErrorDetail>,
        retry_after: Option<u64>,
    },
}

impl From<AppError> for PickerFail {
    fn from(err: AppError) -> Self {
        PickerFail::App(err)
    }
}

fn invalid(message: &'static str) -> PickerFail {
    PickerFail::App(AppError::ValidationFailed(message.to_owned()))
}

/// A `422 validation_failed` with a fixed `detail` code, so the client can pick the fix.
fn invalid_with(message: &'static str, detail: ErrorDetail) -> PickerFail {
    PickerFail::Fixed {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        code: "validation_failed",
        message,
        detail: Some(detail),
        retry_after: None,
    }
}

fn not_found(message: &'static str) -> PickerFail {
    PickerFail::Fixed {
        status: StatusCode::NOT_FOUND,
        code: "not_found",
        message,
        detail: None,
        retry_after: None,
    }
}

fn rate_limited(message: &'static str, wait: u64) -> PickerFail {
    PickerFail::Fixed {
        status: StatusCode::TOO_MANY_REQUESTS,
        code: "rate_limited",
        message,
        detail: None,
        retry_after: Some(wait.max(1)),
    }
}

fn upstream() -> PickerFail {
    PickerFail::App(AppError::UpstreamUnreachable)
}

/// `{"name"}`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HarborProject {
    pub name: String,
}

/// `{"project","repository","full_name"}`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HarborRepository {
    pub project: String,
    pub repository: String,
    pub full_name: String,
}

/// `{"owner","repo","full_name","private","archived"}`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitHubRepository {
    pub owner: String,
    pub repo: String,
    pub full_name: String,
    pub private: bool,
    pub archived: bool,
}

/// One upstream list as cached: the items and whether the fetch cap cut it.
#[derive(Debug, PartialEq, Eq)]
pub struct Listing<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

/// What the source suggestion read from the image label. The label value is not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuggestionOutcome {
    Found {
        owner: String,
        repo: String,
        image_tag: String,
    },
    None(&'static str),
}

#[derive(Clone)]
enum Cached {
    Projects(Arc<Listing<HarborProject>>),
    Repositories(Arc<Listing<HarborRepository>>),
    Github(Arc<Listing<GitHubRepository>>),
    Suggestion(Arc<SuggestionOutcome>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    credential: String,
    list: &'static str,
    project: String,
    search: String,
}

struct Slot {
    value: tokio::sync::Mutex<Option<(Instant, Cached)>>,
}

struct CacheMap {
    slots: HashMap<CacheKey, (Arc<Slot>, u64)>,
    next_seq: u64,
}

/// The in-memory cache: per credential, 5 minutes, at most 500 entries (oldest evicted
/// first), one shared fill per key, and nothing cached on error.
pub struct PickerCache {
    map: Mutex<CacheMap>,
    /// Per credential, how many times it was dropped. A fill stores its result only if the
    /// number is the one captured before the credential was loaded, so a request that
    /// loaded the old credential cannot cache its old view after an update.
    generations: Mutex<HashMap<String, u64>>,
    ttl: Duration,
    max_entries: usize,
    /// Seconds added to the clock. Tests move time forward with it.
    skew_secs: std::sync::atomic::AtomicU64,
}

impl PickerCache {
    fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            map: Mutex::new(CacheMap {
                slots: HashMap::new(),
                next_seq: 0,
            }),
            generations: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
            skew_secs: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn now(&self) -> Instant {
        Instant::now()
            + Duration::from_secs(self.skew_secs.load(std::sync::atomic::Ordering::Relaxed))
    }

    #[cfg(test)]
    fn advance(&self, secs: u64) {
        self.skew_secs
            .fetch_add(secs, std::sync::atomic::Ordering::Relaxed);
    }

    fn slot(&self, key: &CacheKey) -> Arc<Slot> {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((slot, _)) = map.slots.get(key) {
            return Arc::clone(slot);
        }
        if map.slots.len() >= self.max_entries {
            let oldest = map
                .slots
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                map.slots.remove(&oldest);
            }
        }
        let seq = map.next_seq;
        map.next_seq += 1;
        let slot = Arc::new(Slot {
            value: tokio::sync::Mutex::new(None),
        });
        map.slots.insert(key.clone(), (Arc::clone(&slot), seq));
        slot
    }

    /// The current generation of a credential. Capture it before loading the credential.
    fn generation(&self, credential: &str) -> u64 {
        self.generations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(credential)
            .copied()
            .unwrap_or(0)
    }

    /// The cached value, or the result of `fill`. Concurrent callers for one key wait on
    /// the same slot, so one upstream fill serves them all. A failed fill is not stored,
    /// and neither is a fill whose credential was dropped since `generation` was captured
    /// (its result still goes to the caller that asked).
    async fn get_or_fill<F>(
        &self,
        key: CacheKey,
        generation: u64,
        fill: F,
    ) -> Result<Cached, PickerFail>
    where
        F: std::future::Future<Output = Result<Cached, PickerFail>>,
    {
        let slot = self.slot(&key);
        let mut guard = slot.value.lock().await;
        if let Some((at, value)) = guard.as_ref()
            && self.now().duration_since(*at) < self.ttl
        {
            return Ok(value.clone());
        }
        let value = fill.await?;
        if self.generation(&key.credential) == generation {
            *guard = Some((self.now(), value.clone()));
        }
        Ok(value)
    }

    /// Drops every entry of one credential.
    fn drop_credential(&self, credential: &str) {
        // Both steps run under the map lock, slots first, then the generation. `slot()`
        // takes the same lock, so a reader that sees the new generation also finds the
        // slots already gone and cannot pick up a slot filled before the drop.
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.slots.retain(|key, _| key.credential != credential);
        *self
            .generations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(credential.to_owned())
            .or_insert(0) += 1;
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().map_or(0, |map| map.slots.len())
    }
}

/// Everything the picker routes share: the transport, the per-user limiter, the cache and
/// the upstream rate-limit blocks. Held in `AppState`.
#[derive(Clone)]
pub struct PickerState {
    http: Arc<dyn PickerHttp>,
    /// 60 requests per minute per user across the three lists and the suggestion.
    pub limiter: RateLimiter,
    cache: Arc<PickerCache>,
    /// Credential id to the Unix second until which no call is made with it.
    blocks: Arc<Mutex<HashMap<String, i64>>>,
}

impl PickerState {
    /// The production state. `allow_private_harbor` is `HARBORGATE_ALLOW_PRIVATE_HARBOR`.
    pub fn outbound(allow_private_harbor: bool) -> Result<Self, AppError> {
        Ok(Self::new(Arc::new(OutboundPickerHttp::new(
            allow_private_harbor,
        )?)))
    }

    /// State over any transport, such as a test fake.
    pub fn new(http: Arc<dyn PickerHttp>) -> Self {
        Self::with_cache(http, CACHE_TTL, MAX_ENTRIES)
    }

    fn with_cache(http: Arc<dyn PickerHttp>, ttl: Duration, max_entries: usize) -> Self {
        Self {
            http,
            limiter: RateLimiter::new(USER_LIMIT, Duration::from_secs(60)),
            cache: Arc::new(PickerCache::new(ttl, max_entries)),
            blocks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Forgets the cache entries and the rate-limit block of a credential. Called when the
    /// credential is updated or deleted.
    pub fn drop_credential(&self, credential: &str) {
        self.cache.drop_credential(credential);
        self.blocks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(credential);
    }

    /// How many cache entries and rate-limit blocks are held. Tests use it to see a drop.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        let blocks = self.blocks.lock().map_or(0, |blocks| blocks.len());
        (self.cache.len(), blocks)
    }

    fn check_user_limit(&self, user_id: &str) -> Result<(), PickerFail> {
        self.limiter
            .check(&format!("picker:{user_id}"), Instant::now())
            .map_err(|wait| rate_limited(MSG_USER_LIMIT, wait))
    }

    fn check_block(
        &self,
        credential: &str,
        message: &'static str,
        now: i64,
    ) -> Result<(), PickerFail> {
        let blocks = self.blocks.lock().unwrap_or_else(|p| p.into_inner());
        match blocks.get(credential) {
            Some(until) if *until > now => Err(rate_limited(
                message,
                u64::try_from(until - now).unwrap_or(1),
            )),
            _ => Ok(()),
        }
    }

    fn set_block(
        &self,
        credential: &str,
        message: &'static str,
        wait: i64,
        now: i64,
    ) -> PickerFail {
        let until = now.saturating_add(wait);
        self.blocks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(credential.to_owned(), until);
        rate_limited(message, u64::try_from(wait).unwrap_or(1))
    }
}

/// Seconds to wait after a rate-limited answer: `retry-after`, else the reset time, else
/// `DEFAULT_WAIT_SECS` (60, shared with the SARIF upload deferral); at least 1 and at most one hour.
fn wait_secs(response: &UpstreamResponse, now: i64) -> i64 {
    let wait = if let Some(seconds) = response.retry_after {
        seconds
    } else if let Some(reset) = response.ratelimit_reset {
        reset.saturating_sub(now)
    } else {
        DEFAULT_WAIT_SECS
    };
    wait.clamp(1, MAX_BLOCK_SECS)
}

/// Raw list query values (`page`, `page_size`, `sort`, `order`, `q`).
#[derive(Debug, Default, Clone)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub q: Option<String>,
}

/// The list response: the `Lists` shape plus `truncated`.
#[derive(Debug, Serialize)]
pub struct PickerPage<T> {
    pub items: Vec<T>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
    pub truncated: bool,
}

/// Validates the paging values and the search text. Picker lists sort ascending by name
/// unless `order=desc` is given (`specs/api.md`, Pickers).
fn parse_query(
    query: &ListQuery,
    sorts: &[&str],
) -> Result<(Pagination, Option<String>), AppError> {
    let mut paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        sorts,
    )?;
    if query.order.is_none() {
        paging.ascending = true;
    }
    let q = match query.q.as_deref() {
        None | Some("") => None,
        Some(text) if text.chars().count() > MAX_Q_CHARS => {
            return Err(AppError::InvalidRequest(format!(
                "q can have at most {MAX_Q_CHARS} characters."
            )));
        }
        Some(text) if text.chars().any(char::is_control) => {
            return Err(AppError::InvalidRequest(
                "q must not contain control characters.".to_owned(),
            ));
        }
        Some(text) => Some(text.to_owned()),
    };
    Ok((paging, q))
}

/// Sorts by `key`, then returns the requested page.
fn page_of<T>(
    mut items: Vec<T>,
    key: impl Fn(&T) -> &str,
    paging: &Pagination,
    truncated: bool,
) -> PickerPage<T> {
    items.sort_by(|a, b| {
        let ordering = key(a).cmp(key(b));
        if paging.ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let offset = usize::try_from(paging.offset()).unwrap_or(usize::MAX);
    let size = usize::try_from(paging.page_size).unwrap_or(usize::MAX);
    let items = items.into_iter().skip(offset).take(size).collect();
    PickerPage {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
        truncated,
    }
}

/// A Harbor credential ready for calls. The secret is zeroized on drop.
struct HarborCtx {
    id: String,
    /// The cache generation captured before the credential was loaded.
    generation: u64,
    base: Url,
    base_text: String,
    username: String,
    secret: zeroize::Zeroizing<Vec<u8>>,
}

struct GithubCtx {
    id: String,
    generation: u64,
    token: zeroize::Zeroizing<Vec<u8>>,
}

fn harbor_ctx(
    key: &DerivedKey,
    row: &CredentialRow,
    generation: u64,
) -> Result<HarborCtx, PickerFail> {
    let base_text = row.base_url.clone().ok_or(AppError::InternalError)?;
    let base = credentials::base_for_join(&base_text)?;
    let username = row.username.clone().ok_or(AppError::InternalError)?;
    let secret = credentials::decrypt_token(key, row)?;
    Ok(HarborCtx {
        id: row.id.clone(),
        generation,
        base,
        base_text,
        username,
        secret,
    })
}

fn github_ctx(
    key: &DerivedKey,
    row: &CredentialRow,
    generation: u64,
) -> Result<GithubCtx, PickerFail> {
    Ok(GithubCtx {
        id: row.id.clone(),
        generation,
        token: credentials::decrypt_token(key, row)?,
    })
}

/// Loads the caller's credential and checks its type. Another user's credential and an
/// unknown id are `404`; the wrong type is `422`.
async fn load_credential(
    pool: &SqlitePool,
    user_id: &str,
    id: &str,
    want: &str,
) -> Result<CredentialRow, PickerFail> {
    let row = credentials::load_owned(pool, user_id, id).await?;
    if row.service_type != want {
        return Err(invalid_with(
            MSG_WRONG_TYPE,
            ErrorDetail::WrongCredentialType,
        ));
    }
    Ok(row)
}

#[derive(Deserialize)]
struct NamedItem {
    name: String,
}

/// Harbor search text: trimmed and lowercased. `None` when the text holds a character that
/// cannot occur in a Harbor name (the caller then returns an empty list, no request).
fn harbor_search(q: Option<&str>) -> Result<Option<String>, ()> {
    let Some(text) = q else {
        return Ok(None);
    };
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Ok(None);
    }
    let ok = text.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'/')
    });
    if ok { Ok(Some(text)) } else { Err(()) }
}

impl PickerState {
    /// One Harbor GET. A `429` sets the block and returns the rate-limit failure.
    async fn harbor_get(&self, ctx: &HarborCtx, url: &Url) -> Result<UpstreamResponse, PickerFail> {
        let now = now_secs();
        self.check_block(&ctx.id, MSG_HARBOR_RATE, now)?;
        let response = self
            .http
            .get(
                url,
                UpstreamAuth::Harbor {
                    username: &ctx.username,
                    secret: &ctx.secret,
                },
            )
            .await?;
        if response.status == 429 {
            return Err(self.set_block(&ctx.id, MSG_HARBOR_RATE, wait_secs(&response, now), now));
        }
        Ok(response)
    }

    /// One GitHub GET. A `429`, or a `403` with `x-ratelimit-remaining: 0` or `retry-after`,
    /// sets the block and returns the rate-limit failure.
    async fn github_get(&self, ctx: &GithubCtx, url: &Url) -> Result<UpstreamResponse, PickerFail> {
        let now = now_secs();
        self.check_block(&ctx.id, MSG_GITHUB_RATE, now)?;
        let response = self
            .http
            .get(url, UpstreamAuth::Github { token: &ctx.token })
            .await?;
        let limited = response.status == 429
            || (response.status == 403
                && (response.retry_after.is_some() || response.ratelimit_remaining == Some(0)));
        if limited {
            return Err(self.set_block(&ctx.id, MSG_GITHUB_RATE, wait_secs(&response, now), now));
        }
        Ok(response)
    }

    /// The robot identity check: `GET users/current` must answer `412`. A `4xx` refusal or a
    /// `200` is refused with the fixed message (a wrong robot secret otherwise runs as
    /// anonymous); a `5xx` is `502 upstream_unreachable`.
    async fn harbor_identity(&self, ctx: &HarborCtx) -> Result<(), PickerFail> {
        let url = ctx
            .base
            .join("api/v2.0/users/current")
            .map_err(|_| AppError::InternalError)?;
        let response = self.harbor_get(ctx, &url).await?;
        match response.status {
            412 => Ok(()),
            // A `4xx` refusal, or a `200` that is not a robot identity: the credential does
            // not work (`specs/integrations.md`, "Errors and rate limits").
            200 | 400..=499 => Err(invalid_with(
                MSG_HARBOR_IDENTITY,
                ErrorDetail::HarborIdentity,
            )),
            // A `5xx` or any other status says nothing about the credential.
            _ => Err(upstream()),
        }
    }

    /// Reads the Harbor pages of `make_url` (at most 10 of 100). Returns the names and
    /// whether the cap cut the list. The list is truncated only when the 10th page was full
    /// and a further item exists: `X-Total-Count` above the items read, or, with no header,
    /// an 11th page that is not empty. Exactly 1,000 items is not truncated.
    async fn harbor_pages(
        &self,
        ctx: &HarborCtx,
        make_url: impl Fn(u32) -> Result<Url, AppError>,
        classify: fn(u16) -> PickerFail,
    ) -> Result<(Vec<String>, bool), PickerFail> {
        let mut names = Vec::new();
        let mut truncated = false;
        for page in 1..=MAX_PAGES {
            let url = make_url(page)?;
            let response = self.harbor_get(ctx, &url).await?;
            if response.status != 200 {
                return Err(classify(response.status));
            }
            let items: Vec<NamedItem> =
                serde_json::from_slice(&response.body).map_err(|_| upstream())?;
            let count = items.len();
            names.extend(items.into_iter().map(|item| item.name));
            if count < UPSTREAM_PAGE_SIZE as usize {
                break;
            }
            if page == MAX_PAGES {
                let fetched = i64::try_from(names.len()).unwrap_or(i64::MAX);
                truncated = match response.total_count {
                    Some(total) => total > fetched,
                    None => {
                        // No header: ask for the page after the cap; any item means more.
                        let probe = make_url(MAX_PAGES + 1)?;
                        let response = self.harbor_get(ctx, &probe).await?;
                        if response.status != 200 {
                            return Err(classify(response.status));
                        }
                        let more: Vec<NamedItem> =
                            serde_json::from_slice(&response.body).map_err(|_| upstream())?;
                        !more.is_empty()
                    }
                };
            }
        }
        Ok((names, truncated))
    }
}

fn classify_projects(_status: u16) -> PickerFail {
    upstream()
}

fn classify_repositories(status: u16) -> PickerFail {
    match status {
        403 => invalid_with(MSG_REPO_LIST_FORBIDDEN, ErrorDetail::RobotScope),
        404 => not_found(MSG_PROJECT_NOT_FOUND),
        _ => upstream(),
    }
}

fn classify_artifacts(status: u16) -> PickerFail {
    match status {
        403 => invalid_with(MSG_ARTIFACT_FORBIDDEN, ErrorDetail::RobotScope),
        404 => not_found(MSG_REPOSITORY_NOT_FOUND),
        _ => upstream(),
    }
}

/// The caller's hidden names for one list, as a set.
async fn hidden_set(
    pool: &SqlitePool,
    user_id: &str,
    source: &str,
    base_url: Option<&str>,
) -> Result<HashSet<String>, AppError> {
    Ok(db::names(pool, user_id, source, base_url)
        .await?
        .into_iter()
        .collect())
}

fn empty_page<T>(paging: &Pagination) -> PickerPage<T> {
    PickerPage {
        items: Vec::new(),
        page: paging.page,
        page_size: paging.page_size,
        total: 0,
        truncated: false,
    }
}

/// Everything a list call needs from the route.
pub struct Caller<'a> {
    pub pool: &'a SqlitePool,
    pub key: &'a DerivedKey,
    pub user_id: &'a str,
}

impl PickerState {
    /// `GET /credentials/:id/harbor-projects`.
    pub async fn harbor_projects(
        &self,
        caller: &Caller<'_>,
        credential_id: &str,
        query: &ListQuery,
    ) -> Result<PickerPage<HarborProject>, PickerFail> {
        let generation = self.cache.generation(credential_id);
        let row =
            load_credential(caller.pool, caller.user_id, credential_id, SERVICE_HARBOR).await?;
        self.check_user_limit(caller.user_id)?;
        let (paging, q) = parse_query(query, &["name"])?;
        let Ok(search) = harbor_search(q.as_deref()) else {
            return Ok(empty_page(&paging));
        };
        let ctx = harbor_ctx(caller.key, &row, generation)?;
        let cache_key = CacheKey {
            credential: ctx.id.clone(),
            list: "harbor_projects",
            project: String::new(),
            search: search.clone().unwrap_or_default(),
        };
        let cached = self
            .cache
            .get_or_fill(cache_key, ctx.generation, async {
                self.harbor_identity(&ctx).await?;
                let (names, truncated) = self
                    .harbor_pages(
                        &ctx,
                        |page| {
                            let mut url = ctx
                                .base
                                .join("api/v2.0/projects")
                                .map_err(|_| AppError::InternalError)?;
                            {
                                let mut pairs = url.query_pairs_mut();
                                pairs
                                    .append_pair("page", &page.to_string())
                                    .append_pair("page_size", &UPSTREAM_PAGE_SIZE.to_string())
                                    .append_pair("sort", "name");
                                if let Some(text) = &search {
                                    pairs.append_pair("name", text);
                                }
                            }
                            Ok(url)
                        },
                        classify_projects,
                    )
                    .await?;
                let items = names
                    .into_iter()
                    .filter(|name| !name.contains('/') && valid_harbor_name(name))
                    .map(|name| HarborProject { name })
                    .collect();
                Ok(Cached::Projects(Arc::new(Listing { items, truncated })))
            })
            .await?;
        let Cached::Projects(listing) = cached else {
            return Err(AppError::InternalError.into());
        };
        let hidden =
            hidden_set(caller.pool, caller.user_id, "harbor", Some(&ctx.base_text)).await?;
        let items: Vec<HarborProject> = listing
            .items
            .iter()
            .filter(|item| !hidden.contains(&item.name))
            .cloned()
            .collect();
        Ok(page_of(
            items,
            |item| item.name.as_str(),
            &paging,
            listing.truncated,
        ))
    }

    /// `GET /credentials/:id/harbor-projects/:project/repositories`.
    pub async fn harbor_repositories(
        &self,
        caller: &Caller<'_>,
        credential_id: &str,
        project: &str,
        query: &ListQuery,
    ) -> Result<PickerPage<HarborRepository>, PickerFail> {
        let generation = self.cache.generation(credential_id);
        let row =
            load_credential(caller.pool, caller.user_id, credential_id, SERVICE_HARBOR).await?;
        self.check_user_limit(caller.user_id)?;
        let (paging, q) = parse_query(query, &["name"])?;
        if project.contains('/') || !valid_harbor_name(project) {
            return Err(invalid(MSG_BAD_NAME));
        }
        let Ok(search) = harbor_search(q.as_deref()) else {
            return Ok(empty_page(&paging));
        };
        let ctx = harbor_ctx(caller.key, &row, generation)?;
        let hidden =
            hidden_set(caller.pool, caller.user_id, "harbor", Some(&ctx.base_text)).await?;
        // Hiding a project also hides its repositories from the picker.
        if hidden.contains(project) {
            return Ok(empty_page(&paging));
        }
        let cache_key = CacheKey {
            credential: ctx.id.clone(),
            list: "harbor_repositories",
            project: project.to_owned(),
            search: search.clone().unwrap_or_default(),
        };
        let cached = self
            .cache
            .get_or_fill(cache_key, ctx.generation, async {
                self.harbor_identity(&ctx).await?;
                let (names, truncated) = self
                    .harbor_pages(
                        &ctx,
                        |page| {
                            let mut url = ctx
                                .base
                                .join(&format!(
                                    "api/v2.0/projects/{}/repositories",
                                    encode_segment(project)
                                ))
                                .map_err(|_| AppError::InternalError)?;
                            {
                                let mut pairs = url.query_pairs_mut();
                                pairs
                                    .append_pair("page", &page.to_string())
                                    .append_pair("page_size", &UPSTREAM_PAGE_SIZE.to_string())
                                    .append_pair("sort", "name");
                                if let Some(text) = &search {
                                    pairs.append_pair("q", &format!("name=~{text}"));
                                }
                            }
                            Ok(url)
                        },
                        classify_repositories,
                    )
                    .await?;
                let prefix = format!("{project}/");
                let items = names
                    .into_iter()
                    .filter_map(|full| {
                        let repository = full.strip_prefix(&prefix)?.to_owned();
                        valid_harbor_name(&repository).then(|| HarborRepository {
                            project: project.to_owned(),
                            full_name: full,
                            repository,
                        })
                    })
                    .collect();
                Ok(Cached::Repositories(Arc::new(Listing { items, truncated })))
            })
            .await?;
        let Cached::Repositories(listing) = cached else {
            return Err(AppError::InternalError.into());
        };
        let items: Vec<HarborRepository> = listing
            .items
            .iter()
            .filter(|item| !hidden.contains(&item.full_name))
            .cloned()
            .collect();
        Ok(page_of(
            items,
            |item| item.full_name.as_str(),
            &paging,
            listing.truncated,
        ))
    }
}

#[derive(Deserialize)]
struct GithubItem {
    name: String,
    owner: GithubOwner,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    archived: bool,
}

#[derive(Deserialize)]
struct GithubOwner {
    login: String,
}

/// GitHub owner names: 1 to 39 ASCII letters, digits or `-`.
pub fn valid_github_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 39
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl PickerState {
    /// The GitHub repository list of one credential, cached. Pages follow the `Link`
    /// header, at most 10; a longer list is cut and marked truncated.
    async fn github_listing(
        &self,
        ctx: &GithubCtx,
    ) -> Result<Arc<Listing<GitHubRepository>>, PickerFail> {
        let cache_key = CacheKey {
            credential: ctx.id.clone(),
            list: "github_repositories",
            project: String::new(),
            search: String::new(),
        };
        let cached = self
            .cache
            .get_or_fill(cache_key, ctx.generation, async {
                let mut url = Url::parse("https://api.github.com/user/repos")
                    .map_err(|_| AppError::InternalError)?;
                url.query_pairs_mut()
                    .append_pair("per_page", &UPSTREAM_PAGE_SIZE.to_string())
                    .append_pair("page", "1")
                    .append_pair("sort", "full_name")
                    .append_pair("direction", "asc");
                let mut items = Vec::new();
                let mut truncated = false;
                for page in 1..=MAX_PAGES {
                    let response = self.github_get(ctx, &url).await?;
                    match response.status {
                        200 => {}
                        401 => {
                            return Err(invalid_with(MSG_GITHUB_INVALID, ErrorDetail::GithubToken));
                        }
                        403 => {
                            return Err(invalid_with(
                                MSG_GITHUB_FORBIDDEN,
                                ErrorDetail::GithubToken,
                            ));
                        }
                        _ => return Err(upstream()),
                    }
                    let parsed: Vec<GithubItem> =
                        serde_json::from_slice(&response.body).map_err(|_| upstream())?;
                    for item in parsed {
                        if valid_github_owner(&item.owner.login) && valid_github_name(&item.name) {
                            items.push(GitHubRepository {
                                full_name: format!("{}/{}", item.owner.login, item.name),
                                owner: item.owner.login,
                                repo: item.name,
                                private: item.private,
                                archived: item.archived,
                            });
                        }
                    }
                    let Some(next) = response.link_next else {
                        break;
                    };
                    if page == MAX_PAGES {
                        truncated = true;
                        break;
                    }
                    url = Url::parse(&next).map_err(|_| upstream())?;
                    // The token goes only to the API host, whatever the `Link` header says.
                    if !is_github_api_url(&url) {
                        return Err(upstream());
                    }
                }
                Ok(Cached::Github(Arc::new(Listing { items, truncated })))
            })
            .await?;
        match cached {
            Cached::Github(listing) => Ok(listing),
            _ => Err(AppError::InternalError.into()),
        }
    }

    /// `GET /credentials/:id/github-repositories`.
    pub async fn github_repositories(
        &self,
        caller: &Caller<'_>,
        credential_id: &str,
        query: &ListQuery,
    ) -> Result<PickerPage<GitHubRepository>, PickerFail> {
        let generation = self.cache.generation(credential_id);
        let row =
            load_credential(caller.pool, caller.user_id, credential_id, SERVICE_GITHUB).await?;
        self.check_user_limit(caller.user_id)?;
        let (paging, q) = parse_query(query, &["full_name"])?;
        let ctx = github_ctx(caller.key, &row, generation)?;
        let listing = self.github_listing(&ctx).await?;
        let hidden = hidden_set(caller.pool, caller.user_id, "github", None).await?;
        let needle = q.map(|text| text.to_ascii_lowercase());
        let items: Vec<GitHubRepository> = listing
            .items
            .iter()
            .filter(|item| !hidden.contains(&item.full_name.to_ascii_lowercase()))
            .filter(|item| {
                needle
                    .as_deref()
                    .is_none_or(|n| item.full_name.to_ascii_lowercase().contains(n))
            })
            .cloned()
            .collect();
        Ok(page_of(
            items,
            |item| item.full_name.as_str(),
            &paging,
            listing.truncated,
        ))
    }
}

/// The result of reading an `org.opencontainers.image.source` label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelParse {
    Github {
        owner: String,
        repo: String,
    },
    /// A URL on another host.
    NotGithub,
    Invalid,
}

/// Parses the source label strictly (`specs/integrations.md`, "Source suggestion"): an
/// `https://github.com/<owner>/<repo>` URL, host compared case-insensitively, one trailing
/// `/` or `.git` ignored. Userinfo, a port, a query, a fragment, a deeper path or a name
/// that fails the GitHub name check give `Invalid`. The label text is never kept.
pub fn parse_source_label(label: &str) -> LabelParse {
    let Ok(url) = Url::parse(label.trim()) else {
        return LabelParse::Invalid;
    };
    let Some(host) = url.host_str() else {
        return LabelParse::Invalid;
    };
    if !host.eq_ignore_ascii_case("github.com") {
        return LabelParse::NotGithub;
    }
    // `Url` drops a default port, so an explicit `:443` is caught on the text.
    let explicit_port = label.to_ascii_lowercase().contains("github.com:");
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || explicit_port
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return LabelParse::Invalid;
    }
    let path = url.path().trim_start_matches('/');
    let path = path.strip_suffix('/').unwrap_or(path);
    let mut parts = path.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return LabelParse::Invalid;
    };
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if valid_github_owner(owner) && valid_github_name(repo) {
        LabelParse::Github {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        }
    } else {
        LabelParse::Invalid
    }
}

/// True for `sha256:` followed by exactly 64 lowercase hex digits.
fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[derive(Deserialize)]
struct ArtifactDetail {
    #[serde(default)]
    extra_attrs: Option<ExtraAttrs>,
}

#[derive(Deserialize)]
struct ExtraAttrs {
    #[serde(default)]
    config: Option<ImageConfig>,
}

#[derive(Deserialize)]
struct ImageConfig {
    #[serde(default, rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

/// Whether `tag` is a valid OCI image tag. The OCI distribution spec grammar is
/// `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`: 1 to 128 characters, the first a letter, digit or
/// underscore, the rest also allowing `.` and `-`.
fn valid_image_tag(tag: &str) -> bool {
    let mut bytes = tag.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    tag.len() <= 128
        && (first.is_ascii_alphanumeric() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// The `suggestion` object of the response.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Suggestion {
    pub github_owner: String,
    pub github_repo: String,
    pub image_tag: String,
    pub github_listed: Option<bool>,
}

/// `{"suggestion": ... or null, "reason": null or a reason}`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SuggestionResponse {
    pub suggestion: Option<Suggestion>,
    pub reason: Option<&'static str>,
}

/// Raw suggestion query values.
#[derive(Debug, Default, Clone)]
pub struct SuggestionQuery {
    pub project: Option<String>,
    pub repository: Option<String>,
    pub github_cred_id: Option<String>,
}

const LABEL_SOURCE: &str = "org.opencontainers.image.source";

impl PickerState {
    /// `GET /credentials/:id/source-suggestion`. Reads the newest tagged artifact's image
    /// labels and suggests a GitHub repository. Stores nothing; never returns the label.
    pub async fn source_suggestion(
        &self,
        caller: &Caller<'_>,
        credential_id: &str,
        query: &SuggestionQuery,
    ) -> Result<SuggestionResponse, PickerFail> {
        let generation = self.cache.generation(credential_id);
        let row =
            load_credential(caller.pool, caller.user_id, credential_id, SERVICE_HARBOR).await?;
        // The GitHub credential's generation is captured before it is loaded, too.
        let github_row = match query.github_cred_id.as_deref() {
            Some(id) => {
                let github_generation = self.cache.generation(id);
                let row = load_credential(caller.pool, caller.user_id, id, SERVICE_GITHUB).await?;
                Some((row, github_generation))
            }
            None => None,
        };
        self.check_user_limit(caller.user_id)?;
        let (Some(project), Some(repository)) = (
            query.project.as_deref().filter(|v| !v.is_empty()),
            query.repository.as_deref().filter(|v| !v.is_empty()),
        ) else {
            return Err(AppError::InvalidRequest(
                "project and repository are required.".to_owned(),
            )
            .into());
        };
        if project.contains('/') || !valid_harbor_name(project) || !valid_harbor_name(repository) {
            return Err(invalid(MSG_BAD_NAME));
        }
        let ctx = harbor_ctx(caller.key, &row, generation)?;
        let cache_key = CacheKey {
            credential: ctx.id.clone(),
            list: "source_suggestion",
            project: project.to_owned(),
            search: repository.to_owned(),
        };
        let cached = self
            .cache
            .get_or_fill(cache_key, ctx.generation, async {
                let outcome = self.read_source_label(&ctx, project, repository).await?;
                Ok(Cached::Suggestion(Arc::new(outcome)))
            })
            .await?;
        let Cached::Suggestion(outcome) = cached else {
            return Err(AppError::InternalError.into());
        };
        match outcome.as_ref() {
            SuggestionOutcome::None(reason) => Ok(SuggestionResponse {
                suggestion: None,
                reason: Some(reason),
            }),
            SuggestionOutcome::Found {
                owner,
                repo,
                image_tag,
            } => {
                let github_listed = match &github_row {
                    Some((github_row, github_generation)) => {
                        let github = github_ctx(caller.key, github_row, *github_generation)?;
                        let listing = self.github_listing(&github).await?;
                        let wanted = format!("{owner}/{repo}").to_ascii_lowercase();
                        Some(
                            listing
                                .items
                                .iter()
                                .any(|item| item.full_name.to_ascii_lowercase() == wanted),
                        )
                    }
                    None => None,
                };
                Ok(SuggestionResponse {
                    suggestion: Some(Suggestion {
                        github_owner: owner.clone(),
                        github_repo: repo.clone(),
                        image_tag: image_tag.clone(),
                        github_listed,
                    }),
                    reason: None,
                })
            }
        }
    }

    /// Finds the newest tagged artifact and parses its source label.
    async fn read_source_label(
        &self,
        ctx: &HarborCtx,
        project: &str,
        repository: &str,
    ) -> Result<SuggestionOutcome, PickerFail> {
        self.harbor_identity(ctx).await?;
        let mut list_url = artifacts_list_url(&ctx.base, project, repository, 1, 1)?;
        list_url
            .query_pairs_mut()
            .append_pair("sort", "-push_time")
            .append_pair("q", "tags=*");
        let response = self.harbor_get(ctx, &list_url).await?;
        if response.status != 200 {
            return Err(classify_artifacts(response.status));
        }
        let artifacts = parse_artifact_list(&response.body).map_err(|_| upstream())?;
        let Some((digest, tags)) = artifacts.into_iter().next() else {
            return Ok(SuggestionOutcome::None("no_tagged_artifact"));
        };
        let Some(image_tag) = tags.into_iter().next() else {
            return Ok(SuggestionOutcome::None("no_tagged_artifact"));
        };
        // The tag goes back to the client and into the cache, so it must be a real OCI tag.
        if !valid_image_tag(&image_tag) {
            return Ok(SuggestionOutcome::None("invalid_label"));
        }
        // Defence in depth: the digest goes into a URL path, so it must be `sha256:<64 hex>`.
        if !valid_digest(&digest) {
            return Err(upstream());
        }
        let detail_url = artifact_url(&ctx.base, project, repository, &digest)?;
        let response = self.harbor_get(ctx, &detail_url).await?;
        if response.status != 200 {
            return Err(classify_artifacts(response.status));
        }
        let detail: ArtifactDetail =
            serde_json::from_slice(&response.body).map_err(|_| upstream())?;
        let label = detail
            .extra_attrs
            .and_then(|attrs| attrs.config)
            .and_then(|config| config.labels)
            .and_then(|labels| labels.get(LABEL_SOURCE).cloned());
        let Some(label) = label else {
            return Ok(SuggestionOutcome::None("no_label"));
        };
        Ok(match parse_source_label(&label) {
            LabelParse::Github { owner, repo } => SuggestionOutcome::Found {
                owner,
                repo,
                image_tag,
            },
            LabelParse::NotGithub => SuggestionOutcome::None("not_github"),
            LabelParse::Invalid => SuggestionOutcome::None("invalid_label"),
        })
    }
}

/// `HiddenItem`: `{"id","source","full_name","harbor_base_url","created_at"}`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HiddenItem {
    pub id: String,
    pub source: String,
    pub full_name: String,
    pub harbor_base_url: Option<String>,
    pub created_at: String,
}

impl HiddenItem {
    fn from_row(row: HiddenRow) -> Result<Self, AppError> {
        Ok(Self {
            id: row.id,
            source: row.source,
            full_name: row.full_name,
            harbor_base_url: row.harbor_base_url,
            created_at: time::rfc3339(row.created_at)?,
        })
    }
}

/// The `POST /pickers/hidden` body.
#[derive(Debug, Deserialize)]
pub struct HideRequest {
    pub source: String,
    pub full_name: String,
    #[serde(default)]
    pub harbor_base_url: Option<String>,
}

/// Raw hidden-list query values.
#[derive(Debug, Default, Clone)]
pub struct HiddenQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub source: Option<String>,
}

/// The hidden-list response: the `Lists` shape.
pub type HiddenPage = crate::services::pagination::Page<HiddenItem>;

/// Hides an item for `user_id`. Returns the item and whether it was created (`201`) or
/// already existed (`200`). Makes no upstream call and does not check the item exists.
pub async fn hide(
    pool: &SqlitePool,
    user_id: &str,
    request: HideRequest,
    allow_private_harbor: bool,
) -> Result<(HiddenItem, bool), AppError> {
    let (source, base_url, full_name) = match request.source.as_str() {
        "harbor" => {
            let Some(base) = request.harbor_base_url.as_deref() else {
                return Err(AppError::ValidationFailed(
                    "harbor_base_url is required for Harbor items.".to_owned(),
                ));
            };
            let base = credentials::normalize_base_url(base, allow_private_harbor)?;
            if !valid_harbor_name(&request.full_name) {
                return Err(AppError::ValidationFailed(MSG_BAD_NAME.to_owned()));
            }
            ("harbor", Some(base), request.full_name)
        }
        "github" => {
            if request.harbor_base_url.is_some() {
                return Err(AppError::ValidationFailed(
                    "harbor_base_url is only for Harbor items.".to_owned(),
                ));
            }
            let valid = request
                .full_name
                .split_once('/')
                .is_some_and(|(owner, repo)| valid_github_owner(owner) && valid_github_name(repo));
            if !valid {
                return Err(AppError::ValidationFailed(
                    "full_name must be <owner>/<repo> with valid GitHub names.".to_owned(),
                ));
            }
            ("github", None, request.full_name.to_ascii_lowercase())
        }
        _ => {
            return Err(AppError::ValidationFailed(
                "source must be harbor or github.".to_owned(),
            ));
        }
    };
    if let Some(existing) = db::find(pool, user_id, source, base_url.as_deref(), &full_name).await?
    {
        return Ok((HiddenItem::from_row(existing)?, false));
    }
    let id = crate::services::ids::new_id()?;
    let written = db::insert_capped(
        pool,
        &id,
        user_id,
        source,
        base_url.as_deref(),
        &full_name,
        now_secs(),
        HIDDEN_CAP,
    )
    .await?;
    match db::find(pool, user_id, source, base_url.as_deref(), &full_name).await? {
        Some(row) => Ok((HiddenItem::from_row(row)?, written)),
        None => Err(AppError::ValidationFailed(
            "You can hide at most 1,000 items.".to_owned(),
        )),
    }
}

/// One page of the user's hidden items, newest first by default.
pub async fn list_hidden(
    pool: &SqlitePool,
    user_id: &str,
    query: &HiddenQuery,
) -> Result<HiddenPage, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        &["created_at", "full_name"],
    )?;
    let source = match query.source.as_deref() {
        None => None,
        Some(value @ ("harbor" | "github")) => Some(value),
        Some(_) => {
            return Err(AppError::InvalidRequest(
                "source must be harbor or github.".to_owned(),
            ));
        }
    };
    let rows = db::list(
        pool,
        &db::ListFilter {
            user_id,
            source,
            sort: &paging.sort,
            sort_sign: if paging.ascending { 1 } else { -1 },
            limit: paging.page_size,
            offset: paging.offset(),
        },
    )
    .await?;
    let total = db::count(pool, user_id, source).await?;
    let items = rows
        .into_iter()
        .map(HiddenItem::from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::services::pagination::Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

/// Restores (deletes) one of the user's hidden items. Another user's item is `404`.
pub async fn restore(pool: &SqlitePool, user_id: &str, id: &str) -> Result<(), AppError> {
    if db::delete_owned(pool, user_id, id).await? == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
