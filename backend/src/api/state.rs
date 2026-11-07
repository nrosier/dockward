//! Shared application state for handlers and extractors.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use reqwest::Url;
use sqlx::SqlitePool;

use crate::api::hardening::RateLimiter;
use crate::auth::crypto::DerivedKey;
use crate::error::AppError;
use crate::services::credential_probe::{HarborProbe, OutboundHarborProbe};
use crate::services::harbor_client::{HarborGet, HarborReply};
use crate::services::oidc_jwt::JwksCache;
use crate::services::sync::HarborFetch;
use crate::services::throttle::LoginThrottle;

/// The future a probe call returns. It is boxed so the probe can be a trait object.
pub type ProbeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// Object-safe view of `HarborProbe`. `HarborProbe` uses `async fn`, which cannot be a
/// trait object, so this trait returns boxed futures. The production probe and the test
/// fakes implement it.
pub trait DynHarborProbe: Send + Sync {
    /// Sends the robot test and returns the HTTP status code.
    fn users_current<'a>(
        &'a self,
        base: &'a Url,
        username: &'a str,
        secret: &'a [u8],
    ) -> ProbeFuture<'a, u16>;

    /// Sends the repository artifacts request and returns the HTTP status code.
    fn artifacts_status<'a>(
        &'a self,
        base: &'a Url,
        username: &'a str,
        secret: &'a [u8],
        project: &'a str,
        repository: &'a str,
    ) -> ProbeFuture<'a, u16>;
}

impl DynHarborProbe for OutboundHarborProbe {
    fn users_current<'a>(
        &'a self,
        base: &'a Url,
        username: &'a str,
        secret: &'a [u8],
    ) -> ProbeFuture<'a, u16> {
        Box::pin(HarborProbe::users_current(self, base, username, secret))
    }

    fn artifacts_status<'a>(
        &'a self,
        base: &'a Url,
        username: &'a str,
        secret: &'a [u8],
        project: &'a str,
        repository: &'a str,
    ) -> ProbeFuture<'a, u16> {
        Box::pin(HarborProbe::artifacts_status(
            self, base, username, secret, project, repository,
        ))
    }
}

/// The Harbor probe that `AppState` holds. It implements `HarborProbe`, so the generic
/// service code takes it. Production uses the outbound probe; tests inject a fake.
#[derive(Clone)]
pub struct HarborProbeHandle(Arc<dyn DynHarborProbe>);

impl HarborProbeHandle {
    /// The production probe: the guarded outbound client. `allow_private` is
    /// `HARBORGATE_ALLOW_PRIVATE_HARBOR`.
    pub fn outbound(allow_private: bool) -> Result<Self, AppError> {
        Ok(Self::new(Arc::new(OutboundHarborProbe::new(
            allow_private,
        )?)))
    }

    /// Wraps any probe, such as a test fake.
    pub fn new(probe: Arc<dyn DynHarborProbe>) -> Self {
        Self(probe)
    }
}

impl HarborProbe for HarborProbeHandle {
    async fn users_current(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
    ) -> Result<u16, AppError> {
        self.0.users_current(base, username, secret).await
    }

    async fn artifacts_status(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
        project: &str,
        repository: &str,
    ) -> Result<u16, AppError> {
        self.0
            .artifacts_status(base, username, secret, project, repository)
            .await
    }
}

/// Object-safe view of `HarborFetch`, for the same reason as `DynHarborProbe`: the
/// `HarborFetch` future cannot be a trait object, so this trait returns a boxed future.
pub trait DynHarborFetch: Send + Sync {
    /// Sends `GET url` with the robot's basic auth. Returns the status, the body and `Retry-After`.
    fn fetch<'a>(
        &'a self,
        url: &'a Url,
        username: &'a str,
        secret: &'a [u8],
        extra_headers: &'a [(&'a str, &'a str)],
    ) -> ProbeFuture<'a, HarborReply>;
}

impl DynHarborFetch for HarborGet {
    fn fetch<'a>(
        &'a self,
        url: &'a Url,
        username: &'a str,
        secret: &'a [u8],
        extra_headers: &'a [(&'a str, &'a str)],
    ) -> ProbeFuture<'a, HarborReply> {
        Box::pin(self.get(url, username, secret, extra_headers))
    }
}

/// The Harbor reader that `AppState` holds for the manual scan pull. It implements
/// `HarborFetch`, so the poller code takes it. Production uses the guarded `HarborGet`;
/// router tests inject a fake, so no live Harbor is needed.
#[derive(Clone)]
pub struct HarborFetchHandle(Arc<dyn DynHarborFetch>);

impl HarborFetchHandle {
    /// The production reader. `allow_private` is `HARBORGATE_ALLOW_PRIVATE_HARBOR`.
    pub fn outbound(allow_private: bool) -> Result<Self, AppError> {
        Ok(Self::new(Arc::new(HarborGet::new(allow_private)?)))
    }

    /// Wraps any reader, such as a test fake.
    pub fn new(fetch: Arc<dyn DynHarborFetch>) -> Self {
        Self(fetch)
    }
}

impl HarborFetch for HarborFetchHandle {
    async fn fetch(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        self.0.fetch(url, username, secret, extra_headers).await
    }
}

/// Pool and derived session key. The session key is kept behind an `Arc` because
/// the derived key is not `Clone`.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub session_key: Arc<DerivedKey>,
    pub csrf_key: Arc<DerivedKey>,
    /// `HARBORGATE_PUBLIC_URL`, the origin that login and setup requests must match.
    pub public_url: String,
    /// Failed-login delay per (account, client IP).
    pub login_throttle: LoginThrottle,
    /// Login attempts per client IP: 10 per minute (`specs/security.md`, Hardening).
    pub login_limiter: RateLimiter,
    /// Derived credential key. It decrypts the OIDC client secret.
    pub credentials_key: Arc<DerivedKey>,
    /// `HARBORGATE_ALLOW_PRIVATE_OIDC`. The private-range opt-out for OIDC targets.
    pub allow_private_oidc: bool,
    /// The JWKS cache for ID token verification.
    pub jwks: Arc<JwksCache>,
    /// `HARBORGATE_ALLOW_PRIVATE_HARBOR`. The private-range opt-out for Harbor targets.
    pub allow_private_harbor: bool,
    /// `HARBORGATE_ALLOW_PRIVATE_ALERTS`. The private-range opt-out for alert webhook targets.
    pub allow_private_alerts: bool,
    /// Webhook requests per mapping: 60 per minute (`specs/security.md`, Hardening).
    /// Keyed by mapping id.
    pub webhook_token_limiter: RateLimiter,
    /// Failed webhook authentications per client IP: 30 per minute.
    pub webhook_failure_limiter: RateLimiter,
    /// Derived backup key. It seals and opens backup files (`specs/security.md`, Derived keys).
    pub backup_key: Arc<DerivedKey>,
    /// `HARBORGATE_DATA_DIR`. The temporary `VACUUM INTO` copy is written here.
    pub data_dir: PathBuf,
    /// `HARBORGATE_BACKUP_DIR`. Encrypted backups are written here.
    pub backup_dir: PathBuf,
    /// The GitHub Issues client, built once. The manual issue route uses it.
    pub issues_client: Arc<crate::services::github_issues::GithubIssues>,
    /// The Harbor probe for mapping create and update. Production uses the outbound probe;
    /// router tests inject a fake, so no live Harbor is needed.
    pub harbor_probe: HarborProbeHandle,
    /// The application log buffer and the global level controller
    /// (`specs/security.md`, Application log).
    pub app_log: Arc<crate::services::app_log::AppLog>,
    /// The Harbor reader for the manual scan pull (`POST /api/v1/mappings/:id/pull`).
    pub harbor_fetch: HarborFetchHandle,
    /// Manual scan pulls per mapping: 1 per 5 minutes, in memory (`specs/security.md`,
    /// Hardening). Keyed by mapping id.
    pub pull_limiter: RateLimiter,
    /// The scanner list cache and the tag scan limits (`specs/api.md`, "Scanners and tag scans").
    pub scanner_launch: crate::services::scanner_launch::ScannerLaunchState,
    /// The mapping picker transport, per-user limit, list cache and upstream rate-limit
    /// blocks (`specs/api.md`, Pickers). Router tests inject a fake transport.
    pub pickers: crate::services::pickers::PickerState,
    /// The live GitHub API base URL and web URL (`specs/integrations.md`, "GitHub base URL").
    /// Every GitHub client holds a clone, so an admin change applies without a restart.
    pub github: crate::services::github_url::GithubTarget,
}
