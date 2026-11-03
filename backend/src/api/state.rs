//! Shared application state for handlers and extractors.

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::api::hardening::RateLimiter;
use crate::auth::crypto::DerivedKey;
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
}
