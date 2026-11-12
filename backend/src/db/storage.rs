//! SQL for the image store (`specs/spinoff-local-scan.md`, sections 4 and 9): the pull state
//! transitions, the eviction claim and the eviction record.
//!
//! The claim and every transition that changes eviction eligibility run in `BEGIN IMMEDIATE`,
//! so two writers cannot choose the same image, and a scan that starts while its image is
//! `stored` cannot interleave with an eviction. The statements use `sqlx::query` with bound
//! parameters: the spinoff tables are not in the compile-time schema until the clean migration
//! lands (Step 1), so `sqlx::query!` cannot check them yet.

use sqlx::pool::PoolConnection;
use sqlx::{Sqlite, SqliteConnection, SqlitePool};

use crate::db::audit::{self, NewAudit};
use crate::error::AppError;

/// One stored platform image chosen for eviction, with the fields its audit row names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictionClaim {
    pub platform_id: String,
    pub hub_host: String,
    pub repository: String,
    pub platform_digest: String,
}

/// The columns of [`EvictionClaim`] in the order the claim queries select them.
type ClaimRow = (String, String, String, String);

/// Selects the oldest eligible stored platform: not the protected one, and with no queued or
/// running scan run (`specs/spinoff-local-scan.md`, section 4). Ties break by smallest id.
const OLDEST_ELIGIBLE_SQL: &str = "SELECT ip.id, h.host, i.repository, ip.platform_digest
    FROM image_platforms ip
    JOIN images i ON i.id = ip.image_id
    JOIN hubs h ON h.id = i.hub_id
    WHERE ip.state = 'stored'
      AND ip.id <> ?
      AND NOT EXISTS (
          SELECT 1 FROM scan_runs sr
          WHERE sr.image_platform_id = ip.id AND sr.status IN ('queued', 'running'))
    ORDER BY ip.pulled_at ASC, ip.id ASC
    LIMIT 1";

/// Maps any driver error to the generic internal error. The driver text is never kept.
fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// Requires exactly one row to have changed. A guarded transition that matched no row means
/// another writer moved the row first, so the caller must not continue.
fn expect_one(rows: u64) -> Result<(), AppError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(AppError::InternalError)
    }
}

/// Starts an immediate write transaction on `conn`.
async fn begin_immediate(conn: &mut SqliteConnection) -> Result<(), AppError> {
    sqlx::query("BEGIN IMMEDIATE")
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(db_err)
}

/// Rolls back and returns the connection. A connection whose rollback fails is closed rather
/// than returned to the pool with an open transaction.
async fn rollback(mut conn: PoolConnection<Sqlite>) {
    if sqlx::query("ROLLBACK").execute(&mut *conn).await.is_err() {
        drop(conn.detach());
    }
}

/// Commits when `outcome` is `Ok` and rolls back otherwise. The outcome is returned unchanged.
async fn end_transaction<T>(
    mut conn: PoolConnection<Sqlite>,
    outcome: Result<T, AppError>,
) -> Result<T, AppError> {
    match outcome {
        Ok(value) => {
            if sqlx::query("COMMIT").execute(&mut *conn).await.is_ok() {
                return Ok(value);
            }
            rollback(conn).await;
            Err(AppError::InternalError)
        }
        Err(err) => {
            rollback(conn).await;
            Err(err)
        }
    }
}

/// Moves a `queued` or `failed` platform (a retry) to `pulling`. Refused for any other state.
pub async fn begin_pull(pool: &SqlitePool, platform_id: &str) -> Result<(), AppError> {
    let done = sqlx::query(
        "UPDATE image_platforms SET state = 'pulling'
         WHERE id = ? AND state IN ('queued', 'failed')",
    )
    .bind(platform_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    expect_one(done.rows_affected())
}

/// Moves a `queued` or `pulling` platform to `failed`. Refused for any other state.
pub async fn mark_failed(pool: &SqlitePool, platform_id: &str) -> Result<(), AppError> {
    let done = sqlx::query(
        "UPDATE image_platforms SET state = 'failed'
         WHERE id = ? AND state IN ('queued', 'pulling')",
    )
    .bind(platform_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    expect_one(done.rows_affected())
}

/// Marks a `pulling` platform `stored` with its size and pull time, then claims the oldest
/// eligible images while the stored count is above `max_stored`. All of it is one
/// `BEGIN IMMEDIATE` transaction, so the count and the claims agree. The platform just stored
/// is never claimed.
pub async fn store_and_claim(
    pool: &SqlitePool,
    platform_id: &str,
    size_bytes: i64,
    pulled_at: i64,
    max_stored: i64,
) -> Result<Vec<EvictionClaim>, AppError> {
    let mut conn = pool.acquire().await.map_err(db_err)?;
    begin_immediate(&mut conn).await?;
    let outcome = store_in_tx(&mut conn, platform_id, size_bytes, pulled_at, max_stored).await;
    end_transaction(conn, outcome).await
}

async fn store_in_tx(
    conn: &mut SqliteConnection,
    platform_id: &str,
    size_bytes: i64,
    pulled_at: i64,
    max_stored: i64,
) -> Result<Vec<EvictionClaim>, AppError> {
    let done = sqlx::query(
        "UPDATE image_platforms SET state = 'stored', size_bytes = ?, pulled_at = ?
         WHERE id = ? AND state = 'pulling'",
    )
    .bind(size_bytes)
    .bind(pulled_at)
    .bind(platform_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    expect_one(done.rows_affected())?;
    claim_in_tx(conn, max_stored, Some(platform_id)).await
}

/// Claims the oldest eligible stored images while the stored count is above `max_stored`, in
/// one `BEGIN IMMEDIATE` transaction. Used when a scan run ends and at startup.
pub async fn claim_over_limit(
    pool: &SqlitePool,
    max_stored: i64,
    protect: Option<&str>,
) -> Result<Vec<EvictionClaim>, AppError> {
    let mut conn = pool.acquire().await.map_err(db_err)?;
    begin_immediate(&mut conn).await?;
    let outcome = claim_in_tx(&mut conn, max_stored, protect).await;
    end_transaction(conn, outcome).await
}

/// The claim loop, run inside an open immediate transaction. Each claim moves one `stored` row
/// to `evicting`. The loop stops when the count reaches the maximum or no image is eligible, so
/// it cannot run past the number of stored rows.
async fn claim_in_tx(
    conn: &mut SqliteConnection,
    max_stored: i64,
    protect: Option<&str>,
) -> Result<Vec<EvictionClaim>, AppError> {
    let protect = protect.unwrap_or("");
    let (mut stored,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM image_platforms WHERE state = 'stored'")
            .fetch_one(&mut *conn)
            .await
            .map_err(db_err)?;
    let mut claims = Vec::new();
    while stored > max_stored {
        let candidate: Option<ClaimRow> = sqlx::query_as(OLDEST_ELIGIBLE_SQL)
            .bind(protect)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_err)?;
        let Some(row) = candidate else {
            break;
        };
        let claim = claim_from_row(row);
        let done = sqlx::query(
            "UPDATE image_platforms SET state = 'evicting' WHERE id = ? AND state = 'stored'",
        )
        .bind(&claim.platform_id)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        expect_one(done.rows_affected())?;
        claims.push(claim);
        stored -= 1;
    }
    Ok(claims)
}

fn claim_from_row((platform_id, hub_host, repository, platform_digest): ClaimRow) -> EvictionClaim {
    EvictionClaim {
        platform_id,
        hub_host,
        repository,
        platform_digest,
    }
}

/// Every platform in `evicting`. Startup repair completes these.
pub async fn evicting_claims(pool: &SqlitePool) -> Result<Vec<EvictionClaim>, AppError> {
    let rows: Vec<ClaimRow> = sqlx::query_as(
        "SELECT ip.id, h.host, i.repository, ip.platform_digest
         FROM image_platforms ip
         JOIN images i ON i.id = ip.image_id
         JOIN hubs h ON h.id = i.hub_id
         WHERE ip.state = 'evicting'
         ORDER BY ip.id",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    Ok(rows.into_iter().map(claim_from_row).collect())
}

/// The ids of every platform in `pulling`. A pull that was in progress at a crash is one of these.
pub async fn pulling_ids(pool: &SqlitePool) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar::<_, String>(
        "SELECT id FROM image_platforms WHERE state = 'pulling' ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The ids of every platform in `stored` or `evicting`. A layout directory with any other
/// name is an orphan at startup.
pub async fn stored_or_evicting_ids(pool: &SqlitePool) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar::<_, String>(
        "SELECT id FROM image_platforms WHERE state IN ('stored', 'evicting') ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// Records a completed eviction: the row becomes `evicted` with its time, and the `image.evict`
/// audit row is written in the same transaction. `details` is already-serialized JSON.
pub async fn finish_eviction(
    pool: &SqlitePool,
    claim: &EvictionClaim,
    evicted_at: i64,
    audit_id: &str,
    details: &str,
) -> Result<(), AppError> {
    let mut conn = pool.acquire().await.map_err(db_err)?;
    begin_immediate(&mut conn).await?;
    let outcome = finish_in_tx(&mut conn, claim, evicted_at, audit_id, details).await;
    end_transaction(conn, outcome).await
}

async fn finish_in_tx(
    conn: &mut SqliteConnection,
    claim: &EvictionClaim,
    evicted_at: i64,
    audit_id: &str,
    details: &str,
) -> Result<(), AppError> {
    let done = sqlx::query(
        "UPDATE image_platforms SET state = 'evicted', evicted_at = ?
         WHERE id = ? AND state = 'evicting'",
    )
    .bind(evicted_at)
    .bind(&claim.platform_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    expect_one(done.rows_affected())?;
    audit::insert(
        &mut *conn,
        NewAudit {
            id: audit_id,
            actor_user_id: None,
            actor_username: "system",
            action: "image.evict",
            target: &claim.platform_id,
            details: Some(details),
        },
    )
    .await
}

/// Moves a `queued` scan run to `running`, but only while its platform image is `stored`
/// (`specs/spinoff-local-scan.md`, section 4). Returns `false` when the run is not queued or the
/// image is no longer stored, so the caller fails the run with the fixed text. One statement
/// carries both the check and the move, so an eviction that commits first is seen, and a scan
/// that commits first keeps its image from being claimed.
pub async fn start_scan(
    pool: &SqlitePool,
    run_id: &str,
    platform_id: &str,
    started_at: i64,
) -> Result<bool, AppError> {
    let done = sqlx::query(
        "UPDATE scan_runs SET status = 'running', started_at = ?
         WHERE id = ? AND status = 'queued' AND image_platform_id = ?
           AND EXISTS (
               SELECT 1 FROM image_platforms ip
               WHERE ip.id = scan_runs.image_platform_id AND ip.state = 'stored')",
    )
    .bind(started_at)
    .bind(run_id)
    .bind(platform_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}

/// The state of one platform row, or `None` when there is no such row.
pub async fn platform_state(
    pool: &SqlitePool,
    platform_id: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar::<_, String>("SELECT state FROM image_platforms WHERE id = ?")
        .bind(platform_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

/// A value of `system_config`, or `None` when the key is not set.
pub async fn setting(pool: &SqlitePool, key: &str) -> Result<Option<String>, AppError> {
    crate::db::config::get(pool, key).await
}

/// Test fixtures for the image store. The schema is the spinoff's section 9 definitions for the
/// tables the store uses, plus the kept `audit_log` and `system_config` columns. It is applied to
/// a temporary database inside each test, because the clean migration has not landed (Step 1).
#[cfg(test)]
pub mod testing {
    use sqlx::SqlitePool;

    use crate::error::AppError;

    pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    is_encrypted BOOLEAN DEFAULT FALSE,
    updated_at INTEGER DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    details TEXT
);
CREATE TABLE IF NOT EXISTS hubs (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL UNIQUE,
    pull_endpoint TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('default', 'custom')),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (pull_endpoint IS NULL OR kind = 'custom')
);
CREATE TABLE IF NOT EXISTS images (
    id TEXT PRIMARY KEY,
    hub_id TEXT NOT NULL REFERENCES hubs(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,
    digest TEXT NOT NULL,
    is_index BOOLEAN NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (hub_id, repository, digest)
);
CREATE TABLE IF NOT EXISTS image_platforms (
    id TEXT PRIMARY KEY,
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    platform_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'pulling', 'stored', 'evicting', 'evicted', 'failed')),
    size_bytes INTEGER,
    pulled_at INTEGER,
    evicted_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (image_id, platform_digest)
);
CREATE INDEX IF NOT EXISTS idx_image_platforms_evict ON image_platforms (state, pulled_at, id);
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    image_platform_id TEXT NOT NULL REFERENCES image_platforms(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL CHECK (scanner IN ('grype', 'trivy')),
    scanner_version TEXT,
    db_built_at INTEGER,
    trigger TEXT NOT NULL CHECK (trigger IN ('first_pull', 'tag_moved', 'db_update')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
    job_id TEXT,
    started_at INTEGER,
    finished_at INTEGER,
    error TEXT
);
CREATE TABLE IF NOT EXISTS scanner_findings (
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    package TEXT NOT NULL DEFAULT '',
    version TEXT,
    fixed_in_version TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    cvss_v3 REAL,
    description TEXT,
    alias TEXT,
    PRIMARY KEY (run_id, cve_id, package)
);
CREATE TABLE IF NOT EXISTS vulnerability_aliases (
    alias TEXT PRIMARY KEY,
    primary_id TEXT NOT NULL
);
"#;

    fn fail<E>(_: E) -> AppError {
        AppError::InternalError
    }

    pub async fn insert_hub(pool: &SqlitePool, id: &str, host: &str) -> Result<(), AppError> {
        sqlx::query("INSERT INTO hubs (id, host, kind) VALUES (?, ?, 'default')")
            .bind(id)
            .bind(host)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(fail)
    }

    pub async fn insert_image(
        pool: &SqlitePool,
        id: &str,
        hub_id: &str,
        repository: &str,
        digest: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO images (id, hub_id, repository, digest, is_index) VALUES (?, ?, ?, ?, 1)",
        )
        .bind(id)
        .bind(hub_id)
        .bind(repository)
        .bind(digest)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(fail)
    }

    /// Inserts one platform row. `pulled_at` is set only for a `stored` row.
    pub async fn insert_platform(
        pool: &SqlitePool,
        id: &str,
        image_id: &str,
        platform_digest: &str,
        state: &str,
        pulled_at: Option<i64>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, pulled_at)
             VALUES (?, ?, 'linux/amd64', ?, ?, ?)",
        )
        .bind(id)
        .bind(image_id)
        .bind(platform_digest)
        .bind(state)
        .bind(pulled_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(fail)
    }

    pub async fn insert_scan_run(
        pool: &SqlitePool,
        id: &str,
        platform_id: &str,
        status: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status)
             VALUES (?, ?, 'grype', 'first_pull', ?)",
        )
        .bind(id)
        .bind(platform_id)
        .bind(status)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(fail)
    }

    pub async fn insert_finding(
        pool: &SqlitePool,
        run_id: &str,
        cve: &str,
    ) -> Result<(), AppError> {
        sqlx::query("INSERT INTO scanner_findings (run_id, cve_id, severity) VALUES (?, ?, 'HIGH')")
            .bind(run_id)
            .bind(cve)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(fail)
    }

    pub async fn set_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), AppError> {
        sqlx::query("INSERT INTO system_config (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(fail)
    }

    /// The number of rows in `table`. `table` is a fixed test literal, never user input.
    pub async fn count_rows(pool: &SqlitePool, sql: &'static str) -> Result<i64, AppError> {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(pool)
            .await
            .map_err(fail)
    }

    /// The number of `image.evict` audit rows, and the number of distinct targets among them.
    pub async fn eviction_audit_counts(pool: &SqlitePool) -> Result<(i64, i64), AppError> {
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COUNT(DISTINCT target) FROM audit_log WHERE action = 'image.evict'",
        )
        .fetch_one(pool)
        .await
        .map_err(fail)
    }

    /// The `details` text of every `image.evict` audit row.
    pub async fn eviction_audit_details(pool: &SqlitePool) -> Result<Vec<String>, AppError> {
        sqlx::query_scalar::<_, String>(
            "SELECT details FROM audit_log WHERE action = 'image.evict' ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .map_err(fail)
    }
}
