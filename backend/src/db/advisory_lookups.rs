//! The advisory lookup cache (#379, migration 0016): one row per GHSA or GO id that an advisory
//! source answered for. A failed lookup is never stored.

use sqlx::SqliteConnection;

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// The stored answer for `advisory_id`: `None` when the id was never answered, `Some(None)` when
/// the advisory publishes no CVE id, `Some(Some(cve))` otherwise.
pub async fn get(
    conn: &mut SqliteConnection,
    advisory_id: &str,
) -> Result<Option<Option<String>>, AppError> {
    sqlx::query_scalar!(
        "SELECT cve_id FROM advisory_lookups WHERE advisory_id = ?",
        advisory_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// Stores the answer of `source` (`osv` or `github`) for `advisory_id`. The first answer is kept.
pub async fn put(
    conn: &mut SqliteConnection,
    advisory_id: &str,
    cve_id: Option<&str>,
    source: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT OR IGNORE INTO advisory_lookups (advisory_id, cve_id, looked_up_at, source)
         VALUES (?, ?, ?, ?)",
        advisory_id,
        cve_id,
        now,
        source
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}
