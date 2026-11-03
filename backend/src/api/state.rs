//! Shared application state for handlers and extractors.

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;

/// Pool and derived session key. The session key is kept behind an `Arc` because
/// the derived key is not `Clone`.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub session_key: Arc<DerivedKey>,
}
