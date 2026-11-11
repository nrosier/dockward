//! SQL for the daily database refresh (`specs/spinoff-local-scan.md`, section 8): the stored
//! build time of a scanner's database and the `stored` platform images a newer database rescans.
//! Rows hold ids, scanner keys and Unix times only.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// The build time stored for `scanner`'s database, or `None` when none is stored yet.
pub async fn stored_built_at(pool: &SqlitePool, scanner: &str) -> Result<Option<i64>, AppError> {
    let row = sqlx::query_scalar!(
        "SELECT built_at FROM scanner_databases WHERE scanner = ?",
        scanner
    )
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    Ok(row.flatten())
}

/// The distinct platform digests of every image in state `stored`. An evicted image has no
/// layout and cannot be rescanned, so no other state is listed.
pub async fn stored_platform_digests(pool: &SqlitePool) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT platform_digest AS "platform_digest!" FROM image_platforms
           WHERE state = 'stored' ORDER BY platform_digest"#
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The ids of the `stored` platform rows with `digest`. Read inside the refresh transaction, so
/// an eviction between the digest list and the commit is seen.
pub async fn stored_platform_ids_with_digest(
    conn: &mut SqliteConnection,
    digest: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM image_platforms
           WHERE state = 'stored' AND platform_digest = ? ORDER BY id"#,
        digest
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// Stores the build time of a scanner's database and when it was checked. The stored scanner
/// version is kept.
pub async fn store_built_at(
    conn: &mut SqliteConnection,
    scanner: &str,
    built_at: i64,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO scanner_databases (scanner, built_at, checked_at) VALUES (?, ?, ?)
         ON CONFLICT (scanner) DO UPDATE SET built_at = excluded.built_at,
                                             checked_at = excluded.checked_at",
        scanner,
        built_at,
        now
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// True while a job with exactly `payload` is `queued` or `running`.
pub async fn open_job_exists(pool: &SqlitePool, payload: &str) -> Result<bool, AppError> {
    let count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM jobs
           WHERE payload = ? AND status IN ('queued', 'running')"#,
        payload
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    Ok(count > 0)
}
