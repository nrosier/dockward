//! Shared application state for handlers and extractors.

use std::path::PathBuf;
use std::sync::Arc;

use sqlx::SqlitePool;

use crate::api::hardening::RateLimiter;
use crate::auth::crypto::DerivedKey;
use crate::services::oidc_jwt::JwksCache;
use crate::services::throttle::LoginThrottle;

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
}
