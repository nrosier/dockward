//! The daily vulnerability database refresh (`specs/spinoff-local-scan.md`, section 8; decisions 4
//! and 17).
//!
//! One `db_update` run per scanner. It downloads the database, reads the build time of the
//! database now in use, and compares it with the value stored for that scanner. A newer database
//! stores the new build time and queues one rescan of every stored platform image by digest, in
//! the same transaction. An unchanged database queues nothing. A failed refresh leaves the old
//! database in use (the stored build time is not moved).
//!
//! The tool work (the update command and the build-time read) is behind [`DatabaseTool`]. The
//! storage work is behind [`RefreshStore`]. Neither trait is implemented here: the production
//! implementations live in `services/` and `db/`, and the tests use fakes. Nothing in this module
//! writes SQL.

use std::future::Future;

use crate::error::AppError;
use crate::services::scanner::Scanner;

/// What a refresh found after the update step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The database is newer than the stored one. `rescans` platform images were queued.
    Updated { built_at: i64, rescans: usize },
    /// The database is not newer than the stored one. Nothing was queued.
    Unchanged,
}

/// The update and build-time read for one scanner. Production runs the pinned executable with
/// the update arguments and the cache variables of section 7. A test substitutes a fake.
pub trait DatabaseTool: Send + Sync {
    /// Downloads or refreshes the database. The error is the fixed text of the failure.
    fn update(&self, scanner: Scanner) -> impl Future<Output = Result<(), AppError>> + Send;

    /// The build time of the database now in use, as Unix seconds.
    fn built_at(&self, scanner: Scanner) -> impl Future<Output = Result<i64, AppError>> + Send;
}

/// The storage the refresh needs.
///
/// `stored_platform_digests` returns the digest of every platform image in state `stored`, and
/// of no other state (an evicted image cannot be rescanned, section 8). `commit_newer` runs in
/// one transaction: it stores the new build time for the scanner and queues one `scan` job
/// (trigger `db_update`) for each digest it is given. `record_run` writes the `job_runs` row of
/// the refresh (`job_kind = 'db_update'`, section 8); it holds counts and the fixed error text only.
pub trait RefreshStore: Send + Sync {
    /// Writes the `job_runs` row of one refresh. `error` is `None` on success.
    fn record_run(
        &self,
        scanner: Scanner,
        error: Option<&str>,
    ) -> impl Future<Output = Result<(), AppError>> + Send;

    /// The stored build time for `scanner`, or `None` when none is stored yet.
    fn stored_built_at(
        &self,
        scanner: Scanner,
    ) -> impl Future<Output = Result<Option<i64>, AppError>> + Send;

    /// The platform digests of every image in state `stored`.
    fn stored_platform_digests(&self)
    -> impl Future<Output = Result<Vec<String>, AppError>> + Send;

    /// Stores `built_at` for `scanner` and queues one rescan per digest, in one transaction.
    /// Returns the number queued.
    fn commit_newer(
        &self,
        scanner: Scanner,
        built_at: i64,
        digests: &[String],
    ) -> impl Future<Output = Result<usize, AppError>> + Send;
}

/// Runs one refresh for one scanner.
///
/// Order: update the database, read its build time, compare with the stored value, and commit
/// only when it is newer. A rescan is queued once per distinct stored platform digest. A failure
/// at any step returns its error and changes nothing stored.
pub async fn refresh<T, S>(
    tool: &T,
    store: &S,
    scanner: Scanner,
) -> Result<RefreshOutcome, AppError>
where
    T: DatabaseTool,
    S: RefreshStore,
{
    let outcome = refresh_steps(tool, store, scanner).await;
    // The run is recorded on success and on failure. The stored text is always one of the fixed
    // fault strings, never a tool message.
    let error = match &outcome {
        Ok(_) => None,
        Err(AppError::Scanner(fault)) => Some(fault.text()),
        Err(_) => Some(crate::error::ScannerFault::Failed.text()),
    };
    store.record_run(scanner, error).await?;
    outcome
}

async fn refresh_steps<T, S>(
    tool: &T,
    store: &S,
    scanner: Scanner,
) -> Result<RefreshOutcome, AppError>
where
    T: DatabaseTool,
    S: RefreshStore,
{
    tool.update(scanner).await?;
    let built_at = tool.built_at(scanner).await?;
    let stored = store.stored_built_at(scanner).await?;
    if let Some(current) = stored
        && built_at <= current
    {
        return Ok(RefreshOutcome::Unchanged);
    }
    let digests = distinct(store.stored_platform_digests().await?);
    let rescans = store.commit_newer(scanner, built_at, &digests).await?;
    Ok(RefreshOutcome::Updated { built_at, rescans })
}

/// Sorts and removes duplicate digests, so each stored platform image is queued once.
fn distinct(mut digests: Vec<String>) -> Vec<String> {
    digests.sort();
    digests.dedup();
    digests
}

#[cfg(test)]
mod tests;
