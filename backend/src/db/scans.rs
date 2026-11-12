//! SQL for the scan job and the convert step (`specs/spinoff-local-scan.md`, section 6 steps 4
//! and 5, and section 9): queueing a scan run and its job, moving a run through its states,
//! storing the findings of a run, and finding the tags whose current image holds a platform.
//!
//! Rows hold ids, scanner keys, CVE facts and the fixed error texts only. No path, registry
//! string, scanner stderr or secret is ever bound here.
//!
//! Every function takes a connection so the caller can group them in one transaction.

use sqlx::SqliteConnection;

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// A scan run with the platform image it scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    pub id: String,
    pub image_platform_id: String,
    pub image_id: String,
    pub scanner: String,
    /// `queued`, `running`, `done` or `failed`.
    pub status: String,
}

/// The run `run_id`, or `None` when there is no such row.
pub async fn find_run(
    conn: &mut SqliteConnection,
    run_id: &str,
) -> Result<Option<RunRow>, AppError> {
    sqlx::query_as!(
        RunRow,
        r#"SELECT r.id AS "id!", r.image_platform_id AS "image_platform_id!",
                  p.image_id AS "image_id!", r.scanner AS "scanner!", r.status AS "status!"
           FROM scan_runs r JOIN image_platforms p ON p.id = r.image_platform_id
           WHERE r.id = ?"#,
        run_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// The state of a platform row, or `None` when there is no such row.
pub async fn platform_state_in(
    conn: &mut SqliteConnection,
    platform_id: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT state AS "state!" FROM image_platforms WHERE id = ?"#,
        platform_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// The scanners that already have a run for `platform_id` with `trigger`. Queueing skips them, so
/// a repeated pull job cannot queue the same scan twice.
pub async fn scanners_with_run(
    conn: &mut SqliteConnection,
    platform_id: &str,
    trigger: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT scanner AS "scanner!" FROM scan_runs
           WHERE image_platform_id = ? AND trigger = ?"#,
        platform_id,
        trigger
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// The scanners with a `queued` or `running` run for `platform_id`.
pub async fn scanners_with_open_run(
    conn: &mut SqliteConnection,
    platform_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT scanner AS "scanner!" FROM scan_runs
           WHERE image_platform_id = ? AND status IN ('queued', 'running')"#,
        platform_id
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// Adds a `queued` run linked to its job. A queued run protects its image from eviction.
pub async fn insert_queued_run(
    conn: &mut SqliteConnection,
    run_id: &str,
    platform_id: &str,
    scanner: &str,
    trigger: &str,
    job_id: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, job_id)
         VALUES (?, ?, ?, ?, 'queued', ?)",
        run_id,
        platform_id,
        scanner,
        trigger,
        job_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// Puts a `failed` or `running` run back to `queued` for a retry of its job (a `running` run is
/// one a stopped process left behind). Returns the rows changed.
pub async fn requeue_run(conn: &mut SqliteConnection, run_id: &str) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE scan_runs SET status = 'queued', error = NULL, started_at = NULL, finished_at = NULL
         WHERE id = ? AND status IN ('failed', 'running')",
        run_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(db_err)
}

/// Ends a run as `failed` with one fixed text. Only a `queued` or `running` run changes.
pub async fn finish_failed(
    conn: &mut SqliteConnection,
    run_id: &str,
    error: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE scan_runs SET status = 'failed', error = ?, finished_at = ?
         WHERE id = ? AND status IN ('queued', 'running')",
        error,
        now,
        run_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// Ends a `running` run as `done`, with the scanner's version and the build time of the database
/// it used. A run that is no longer `running` is an error, so the caller rolls back.
pub async fn finish_done(
    conn: &mut SqliteConnection,
    run_id: &str,
    scanner_version: &str,
    db_built_at: Option<i64>,
    now: i64,
) -> Result<(), AppError> {
    let done = sqlx::query!(
        "UPDATE scan_runs SET status = 'done', error = NULL, scanner_version = ?,
                db_built_at = ?, finished_at = ?
         WHERE id = ? AND status = 'running'",
        scanner_version,
        db_built_at,
        now,
        run_id
    )
    .execute(conn)
    .await
    .map_err(db_err)?;
    if done.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AppError::InternalError)
    }
}

/// One finding of a run, ready to store.
pub struct NewFinding<'a> {
    pub cve_id: &'a str,
    pub package: &'a str,
    pub version: Option<&'a str>,
    pub fixed_in_version: Option<&'a str>,
    pub severity: &'a str,
    pub cvss_v3: Option<f64>,
    pub description: Option<&'a str>,
    pub alias: Option<&'a str>,
}

/// Stores one finding of a run. The key is `(run_id, cve_id, package)`.
pub async fn insert_finding(
    conn: &mut SqliteConnection,
    run_id: &str,
    finding: &NewFinding<'_>,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO scanner_findings
            (run_id, cve_id, package, version, fixed_in_version, severity, cvss_v3, description, alias)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (run_id, cve_id, package) DO NOTHING",
        run_id,
        finding.cve_id,
        finding.package,
        finding.version,
        finding.fixed_in_version,
        finding.severity,
        finding.cvss_v3,
        finding.description,
        finding.alias
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// The primary id recorded for `alias` in `vulnerability_aliases` (#337), or `None`.
pub async fn alias_primary(
    conn: &mut SqliteConnection,
    alias: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar!(
        "SELECT primary_id FROM vulnerability_aliases WHERE alias = ?",
        alias
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// Records that `alias` names `primary_id` (#337). The first record of an alias is kept.
pub async fn record_alias(
    conn: &mut SqliteConnection,
    alias: &str,
    primary_id: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT OR IGNORE INTO vulnerability_aliases (alias, primary_id) VALUES (?, ?)",
        alias,
        primary_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// The build time stored for a scanner's database, or `None` when none is stored.
pub async fn database_built_at(
    conn: &mut SqliteConnection,
    scanner: &str,
) -> Result<Option<i64>, AppError> {
    let row = sqlx::query_scalar!(
        "SELECT built_at FROM scanner_databases WHERE scanner = ?",
        scanner
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)?;
    Ok(row.flatten())
}

/// A (source, tag) whose current image holds the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagRef {
    pub source_id: String,
    pub tag: String,
}

/// The (source, tag) pairs whose current observation is `image_id`: for each tag of a source the
/// observation with the latest `first_seen_at` is the current one (decision 49), so a tag that
/// has moved to another digest no longer belongs to this image.
pub async fn current_tags_of_image_all(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<TagRef>, AppError> {
    sqlx::query_as!(
        TagRef,
        r#"SELECT o.source_id AS "source_id!", o.tag AS "tag!" FROM tag_observations o
           WHERE o.image_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM tag_observations n
                 WHERE n.source_id = o.source_id AND n.tag = o.tag
                   AND (n.first_seen_at > o.first_seen_at
                        OR (n.first_seen_at = o.first_seen_at AND n.rowid > o.rowid)))
           ORDER BY o.source_id, o.tag"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// The CVE ids that are `open` for a tag of a source.
pub async fn open_cve_ids(
    conn: &mut SqliteConnection,
    source_id: &str,
    tag: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT cve_id AS "cve_id!" FROM cve_findings
           WHERE source_id = ? AND image_tag = ? AND status = 'open'"#,
        source_id,
        tag
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// Marks one `open` row of a tag `fixed`: no scanner of its image reports the CVE any more.
pub async fn mark_fixed(
    conn: &mut SqliteConnection,
    source_id: &str,
    tag: &str,
    cve_id: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE cve_findings SET status = 'fixed'
         WHERE source_id = ? AND image_tag = ? AND cve_id = ? AND status = 'open'",
        source_id,
        tag,
        cve_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// True while any run of any platform of `image_id` is `queued` or `running`.
pub async fn image_has_open_runs(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM scan_runs r JOIN image_platforms p ON p.id = r.image_platform_id
               WHERE p.image_id = ? AND r.status IN ('queued', 'running')
           ) AS "open!: i64""#,
        image_id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.open != 0)
}

/// Puts a `running` run back to `queued` after a failed attempt that the job will retry, and
/// keeps the attempt's fixed error text. A queued run still protects its image from eviction.
pub async fn release_run(
    conn: &mut SqliteConnection,
    run_id: &str,
    error: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE scan_runs SET status = 'queued', error = ?, started_at = NULL
         WHERE id = ? AND status = 'running'",
        error,
        run_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// Fails every `queued` or `running` run whose job no longer exists (`job_id` is NULL
/// after the job was deleted, for example with its source). Such a run can never start, and
/// would keep its image from eviction. Returns the number failed.
pub async fn fail_orphan_runs(conn: &mut SqliteConnection, now: i64) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE scan_runs SET status = 'failed', error = 'scan job was removed', finished_at = ?
         WHERE job_id IS NULL AND status IN ('queued', 'running')",
        now
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(db_err)
}

/// The image a platform belongs to, for the payload of a job: the repository, the image digest,
/// and the tag `source_id` observed for that image (newest observation first). `tag` is `None`
/// when the source never observed the image, for example a database refresh with no source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformImage {
    pub repo_full_name: String,
    pub digest: String,
    pub tag: Option<String>,
}

/// The [`PlatformImage`] of a platform, or `None` when the platform row does not exist.
pub async fn platform_image_in(
    conn: &mut SqliteConnection,
    platform_id: &str,
    source_id: Option<&str>,
) -> Result<Option<PlatformImage>, AppError> {
    let image_id = sqlx::query_scalar!(
        r#"SELECT image_id AS "image_id!" FROM image_platforms WHERE id = ?"#,
        platform_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;
    match image_id {
        Some(image_id) => image_in(conn, &image_id, source_id).await,
        None => Ok(None),
    }
}

/// The [`PlatformImage`] of an image, or `None` when the image row does not exist.
pub async fn image_in(
    conn: &mut SqliteConnection,
    image_id: &str,
    source_id: Option<&str>,
) -> Result<Option<PlatformImage>, AppError> {
    let row = sqlx::query!(
        r#"SELECT i.repository AS "repository!", i.digest AS "digest!",
                  (SELECT o.tag FROM tag_observations o
                    WHERE o.image_id = i.id AND o.source_id = ?
                    ORDER BY o.first_seen_at DESC, o.rowid DESC LIMIT 1) AS "tag?"
           FROM images i
           WHERE i.id = ?"#,
        source_id,
        image_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)?;
    Ok(row.map(|row| PlatformImage {
        repo_full_name: row.repository,
        digest: row.digest,
        tag: row.tag,
    }))
}
