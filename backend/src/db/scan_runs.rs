//! SQL for `scan_runs` and `scanner_findings` as the merged view and the issue rules read them
//! (`specs/spinoff-local-scan.md`, sections 9 and 12). Runs are append-only history; the
//! latest `done` run per (platform image, scanner) is the one that counts. Rows hold CVE facts
//! and scanner keys only, never a secret.
//!
//! Every function takes a connection so the caller can group them in one transaction.

use sqlx::SqliteConnection;

use crate::error::AppError;

/// One finding of a latest `done` run, with the scanner and the platform that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannerFindingRow {
    /// `grype` or `trivy`.
    pub scanner: String,
    /// `os/arch[/variant]`.
    pub platform: String,
    pub cve_id: String,
    pub package: String,
    pub version: Option<String>,
    pub fixed_in_version: Option<String>,
    pub severity: String,
    pub cvss_v3: Option<f64>,
    pub description: Option<String>,
    pub alias: Option<String>,
}

/// Every finding of the latest `done` run per (platform image, scanner) of `image_id`. The
/// latest run is the one with the latest `finished_at`, then the later insert.
pub async fn latest_done_findings_in(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<ScannerFindingRow>, AppError> {
    sqlx::query_as!(
        ScannerFindingRow,
        r#"SELECT r.scanner AS "scanner!", p.platform AS "platform!", f.cve_id AS "cve_id!",
                  f.package AS "package!", f.version, f.fixed_in_version,
                  f.severity AS "severity!", f.cvss_v3, f.description, f.alias
           FROM image_platforms p
           JOIN scan_runs r ON r.image_platform_id = p.id AND r.status = 'done'
           JOIN scanner_findings f ON f.run_id = r.id
           WHERE p.image_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM scan_runs r2
                 WHERE r2.image_platform_id = r.image_platform_id AND r2.scanner = r.scanner
                   AND r2.status = 'done'
                   AND (COALESCE(r2.finished_at, 0) > COALESCE(r.finished_at, 0)
                        OR (COALESCE(r2.finished_at, 0) = COALESCE(r.finished_at, 0)
                            AND r2.rowid > r.rowid)))
           ORDER BY f.cve_id, f.package, r.scanner, p.platform"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The scanners that have at least one `done` run for a platform of `image_id`, whether or not
/// the run found anything. A clean run is still a result.
pub async fn done_scanners_in(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT r.scanner AS "scanner!"
           FROM scan_runs r JOIN image_platforms p ON p.id = r.image_platform_id
           WHERE p.image_id = ? AND r.status = 'done'
           ORDER BY r.scanner"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The ids of every platform image of `image_id`, whatever its state: an evicted platform
/// counts through its last `done` run.
pub async fn platform_ids_in(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM image_platforms WHERE image_id = ? ORDER BY id"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Every (platform image id, scanner) pair of `image_id` that has a `done` run.
pub async fn done_pairs_in(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<(String, String)>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT DISTINCT r.image_platform_id AS "platform_id!", r.scanner AS "scanner!"
           FROM scan_runs r JOIN image_platforms p ON p.id = r.image_platform_id
           WHERE p.image_id = ? AND r.status = 'done'"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| (row.platform_id, row.scanner))
        .collect())
}

/// The raw `scanners.enabled` value of `system_config`, or `None` when the key is not set.
pub async fn enabled_scanners_setting_in(
    conn: &mut SqliteConnection,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT value AS "value!" FROM system_config WHERE key = 'scanners.enabled'"#
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}
