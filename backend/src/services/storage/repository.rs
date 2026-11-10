//! The repository the store works through (`specs/spinoff-local-scan.md`, sections 4 and 9).
//!
//! [`StoreRepository`] is the seam between the storage rules and SQLite. The production
//! implementation is [`SqlStoreRepository`], which calls `db::storage`. Tests use the same
//! implementation against a temporary database, so the rules are tested on real SQL.

use std::future::Future;

use sqlx::SqlitePool;

use crate::db::storage::{self, EvictionClaim};
use crate::error::AppError;

/// Everything the store needs from the database.
pub trait StoreRepository: Send + Sync {
    /// Moves a `queued` or `failed` platform to `pulling`.
    fn begin_pull(&self, platform_id: &str) -> impl Future<Output = Result<(), AppError>> + Send;
    /// Moves a `queued` or `pulling` platform to `failed`.
    fn mark_failed(&self, platform_id: &str) -> impl Future<Output = Result<(), AppError>> + Send;
    /// Marks a `pulling` platform `stored` and claims the oldest eligible images above the
    /// maximum, in one immediate transaction.
    fn store_and_claim(
        &self,
        platform_id: &str,
        size_bytes: i64,
        pulled_at: i64,
        max_stored: i64,
    ) -> impl Future<Output = Result<Vec<EvictionClaim>, AppError>> + Send;
    /// Claims the oldest eligible images above the maximum, in one immediate transaction.
    fn claim_over_limit(
        &self,
        max_stored: i64,
        protect: Option<String>,
    ) -> impl Future<Output = Result<Vec<EvictionClaim>, AppError>> + Send;
    /// Records a completed eviction and its audit row, in one immediate transaction.
    fn finish_eviction(
        &self,
        claim: &EvictionClaim,
        evicted_at: i64,
        audit_id: &str,
        details: &str,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
    /// Moves a `queued` scan run to `running` while its platform image is `stored`.
    fn start_scan(
        &self,
        run_id: &str,
        platform_id: &str,
        started_at: i64,
    ) -> impl Future<Output = Result<bool, AppError>> + Send;
    /// The state of one platform row.
    fn platform_state(
        &self,
        platform_id: &str,
    ) -> impl Future<Output = Result<Option<String>, AppError>> + Send;
    /// Every platform in `evicting`.
    fn evicting_claims(&self) -> impl Future<Output = Result<Vec<EvictionClaim>, AppError>> + Send;
    /// The ids of every platform in `pulling`.
    fn pulling_ids(&self) -> impl Future<Output = Result<Vec<String>, AppError>> + Send;
    /// The ids of every platform in `stored` or `evicting`.
    fn live_ids(&self) -> impl Future<Output = Result<Vec<String>, AppError>> + Send;
    /// A `system_config` value, or `None` when unset.
    fn setting(&self, key: &str) -> impl Future<Output = Result<Option<String>, AppError>> + Send;
}

/// The production repository: `db::storage` on one pool.
#[derive(Clone)]
pub struct SqlStoreRepository {
    pool: SqlitePool,
}

impl SqlStoreRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl StoreRepository for SqlStoreRepository {
    async fn begin_pull(&self, platform_id: &str) -> Result<(), AppError> {
        storage::begin_pull(&self.pool, platform_id).await
    }

    async fn mark_failed(&self, platform_id: &str) -> Result<(), AppError> {
        storage::mark_failed(&self.pool, platform_id).await
    }

    async fn store_and_claim(
        &self,
        platform_id: &str,
        size_bytes: i64,
        pulled_at: i64,
        max_stored: i64,
    ) -> Result<Vec<EvictionClaim>, AppError> {
        storage::store_and_claim(&self.pool, platform_id, size_bytes, pulled_at, max_stored).await
    }

    async fn claim_over_limit(
        &self,
        max_stored: i64,
        protect: Option<String>,
    ) -> Result<Vec<EvictionClaim>, AppError> {
        storage::claim_over_limit(&self.pool, max_stored, protect.as_deref()).await
    }

    async fn finish_eviction(
        &self,
        claim: &EvictionClaim,
        evicted_at: i64,
        audit_id: &str,
        details: &str,
    ) -> Result<(), AppError> {
        storage::finish_eviction(&self.pool, claim, evicted_at, audit_id, details).await
    }

    async fn start_scan(
        &self,
        run_id: &str,
        platform_id: &str,
        started_at: i64,
    ) -> Result<bool, AppError> {
        storage::start_scan(&self.pool, run_id, platform_id, started_at).await
    }

    async fn platform_state(&self, platform_id: &str) -> Result<Option<String>, AppError> {
        storage::platform_state(&self.pool, platform_id).await
    }

    async fn evicting_claims(&self) -> Result<Vec<EvictionClaim>, AppError> {
        storage::evicting_claims(&self.pool).await
    }

    async fn pulling_ids(&self) -> Result<Vec<String>, AppError> {
        storage::pulling_ids(&self.pool).await
    }

    async fn live_ids(&self) -> Result<Vec<String>, AppError> {
        storage::stored_or_evicting_ids(&self.pool).await
    }

    async fn setting(&self, key: &str) -> Result<Option<String>, AppError> {
        storage::setting(&self.pool, key).await
    }
}
