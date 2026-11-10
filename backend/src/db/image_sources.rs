//! SQL for the source routes (`specs/spinoff-local-scan.md`, sections 5, 9 and 10): the
//! `image_sources` rows, the one `source_credentials` row per source, the tags a source has
//! observed, and the image list. Rows hold ids, names and ciphertext only; the encrypted token is
//! returned as stored and only the service decrypts it.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// One source with the flag that says whether it has a credential. No secret.
#[derive(Debug, Clone)]
pub struct SourceFull {
    pub id: String,
    pub user_id: String,
    pub hub_id: String,
    pub hub_host: String,
    pub repository: String,
    pub tag_value: String,
    pub github_cred_id: String,
    pub github_owner: String,
    pub github_repo: String,
    pub default_branch: String,
    pub auto_create_issues: bool,
    pub min_issue_severity: String,
    pub last_discovery_at: Option<i64>,
    pub has_credential: bool,
}

/// The fields a create or an update writes.
#[derive(Debug, Clone)]
pub struct SourceWrite<'a> {
    pub hub_id: &'a str,
    pub repository: &'a str,
    pub tag_value: &'a str,
    pub github_cred_id: &'a str,
    pub github_owner: &'a str,
    pub github_repo: &'a str,
    pub default_branch: &'a str,
    pub auto_create_issues: bool,
    pub min_issue_severity: &'a str,
}

fn duplicate(err: sqlx::Error) -> AppError {
    match err {
        sqlx::Error::Database(ref found) if found.is_unique_violation() => AppError::Conflict(
            "a source with this hub, repository and tag value already exists.".to_owned(),
        ),
        _ => AppError::InternalError,
    }
}

/// One page of sources. `user_id` limits the list to one owner; `None` lists every source.
pub async fn list(
    pool: &SqlitePool,
    user_id: Option<&str>,
    sort: &str,
    sort_sign: i64,
    limit: i64,
    offset: i64,
) -> Result<Vec<SourceFull>, AppError> {
    sqlx::query_as!(
        SourceFull,
        r#"SELECT s.id AS "id!", s.user_id AS "user_id!", s.hub_id AS "hub_id!", h.host AS "hub_host!",
                  s.repository AS "repository!", s.tag_value AS "tag_value!",
                  s.github_cred_id AS "github_cred_id!", s.github_owner AS "github_owner!",
                  s.github_repo AS "github_repo!", s.default_branch AS "default_branch!",
                  s.auto_create_issues AS "auto_create_issues!: bool",
                  s.min_issue_severity AS "min_issue_severity!", s.last_discovery_at,
                  EXISTS (SELECT 1 FROM source_credentials c WHERE c.source_id = s.id)
                      AS "has_credential!: bool"
           FROM image_sources s JOIN hubs h ON h.id = s.hub_id
           WHERE (? IS NULL OR s.user_id = ?)
           ORDER BY
             CASE WHEN ? = 'repository' AND ? = 1 THEN s.repository END ASC,
             CASE WHEN ? = 'repository' AND ? = -1 THEN s.repository END DESC,
             CASE WHEN ? = 'created_at' AND ? = 1 THEN s.created_at END ASC,
             CASE WHEN ? = 'created_at' AND ? = -1 THEN s.created_at END DESC,
             s.id ASC
           LIMIT ? OFFSET ?"#,
        user_id,
        user_id,
        sort,
        sort_sign,
        sort,
        sort_sign,
        sort,
        sort_sign,
        sort,
        sort_sign,
        limit,
        offset
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The number of sources in the same scope as [`list`].
pub async fn count(pool: &SqlitePool, user_id: Option<&str>) -> Result<i64, AppError> {
    sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM image_sources WHERE (? IS NULL OR user_id = ?)"#,
        user_id,
        user_id
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

/// One source by id, whoever owns it.
pub async fn find(conn: &mut SqliteConnection, id: &str) -> Result<Option<SourceFull>, AppError> {
    sqlx::query_as!(
        SourceFull,
        r#"SELECT s.id AS "id!", s.user_id AS "user_id!", s.hub_id AS "hub_id!", h.host AS "hub_host!",
                  s.repository AS "repository!", s.tag_value AS "tag_value!",
                  s.github_cred_id AS "github_cred_id!", s.github_owner AS "github_owner!",
                  s.github_repo AS "github_repo!", s.default_branch AS "default_branch!",
                  s.auto_create_issues AS "auto_create_issues!: bool",
                  s.min_issue_severity AS "min_issue_severity!", s.last_discovery_at,
                  EXISTS (SELECT 1 FROM source_credentials c WHERE c.source_id = s.id)
                      AS "has_credential!: bool"
           FROM image_sources s JOIN hubs h ON h.id = s.hub_id WHERE s.id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// Inserts a source. The same hub, repository and tag value is `409`.
pub async fn insert(
    conn: &mut SqliteConnection,
    id: &str,
    user_id: &str,
    write: &SourceWrite<'_>,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO image_sources
            (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner,
             github_repo, default_branch, auto_create_issues, min_issue_severity)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        user_id,
        write.hub_id,
        write.repository,
        write.tag_value,
        write.github_cred_id,
        write.github_owner,
        write.github_repo,
        write.default_branch,
        write.auto_create_issues,
        write.min_issue_severity
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(duplicate)
}

/// Updates the editable fields of a source. Nothing already recorded is touched.
pub async fn update(
    conn: &mut SqliteConnection,
    id: &str,
    write: &SourceWrite<'_>,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE image_sources SET hub_id = ?, repository = ?, tag_value = ?, github_cred_id = ?,
                github_owner = ?, github_repo = ?, default_branch = ?, auto_create_issues = ?,
                min_issue_severity = ?
         WHERE id = ?",
        write.hub_id,
        write.repository,
        write.tag_value,
        write.github_cred_id,
        write.github_owner,
        write.github_repo,
        write.default_branch,
        write.auto_create_issues,
        write.min_issue_severity,
        id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(duplicate)
}

/// Deletes the source row. The cascades remove its observations, findings, publish reports,
/// acceptances, jobs and credential row.
pub async fn delete(conn: &mut SqliteConnection, id: &str) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM image_sources WHERE id = ?", id)
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(db_err)
}

/// True while a job of the source is running.
pub async fn has_running_job(conn: &mut SqliteConnection, id: &str) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (SELECT 1 FROM sync_jobs WHERE source_id = ? AND status = 'running')
               AS "running!: bool""#,
        id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.running)
}

/// The images a source has observed, before a delete.
pub async fn observed_image_ids(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT image_id AS "image_id!" FROM tag_observations WHERE source_id = ?"#,
        id
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// True when some source still observes the image.
pub async fn image_observed(conn: &mut SqliteConnection, image_id: &str) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (SELECT 1 FROM tag_observations WHERE image_id = ?) AS "seen!: bool""#,
        image_id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.seen)
}

/// The platform ids of an image, which name its layout directories.
pub async fn platform_ids(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM image_platforms WHERE image_id = ?"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// Deletes an image. Its platforms and scan runs go with it.
pub async fn delete_image(conn: &mut SqliteConnection, image_id: &str) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM images WHERE id = ?", image_id)
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(db_err)
}

/// The open GitHub issues the source's findings point at: `(cve_id, issue number)`. They stay
/// open when the source is deleted and are listed in the audit row.
pub async fn open_issues(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Vec<(String, i64)>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT DISTINCT g.cve_id AS "cve_id!", g.github_issue_number AS "number!: i64"
           FROM cve_findings f JOIN github_issues g ON g.id = f.github_issue_id
           WHERE f.source_id = ? AND g.status = 'open'
           ORDER BY g.cve_id"#,
        id
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)?;
    Ok(rows.into_iter().map(|r| (r.cve_id, r.number)).collect())
}

/// The tags the source has observed, each once, in order.
pub async fn observed_tags(pool: &SqlitePool, id: &str) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT tag AS "tag!" FROM tag_observations WHERE source_id = ? ORDER BY tag"#,
        id
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The id of the source's credential row, if it has one.
pub async fn credential_id(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM source_credentials WHERE source_id = ?"#,
        source_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// Inserts or replaces the source's credential. The row id is kept on replace, because the
/// ciphertext is bound to it.
pub async fn upsert_credential(
    conn: &mut SqliteConnection,
    id: &str,
    source_id: &str,
    username: &str,
    encrypted_token: &str,
    expires_at: Option<i64>,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO source_credentials (id, source_id, username, encrypted_token, expires_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(source_id) DO UPDATE SET
             username = excluded.username,
             encrypted_token = excluded.encrypted_token,
             expires_at = excluded.expires_at",
        id,
        source_id,
        username,
        encrypted_token,
        expires_at
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// Removes the source's credential row. Returns the rows removed.
pub async fn delete_credential(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "DELETE FROM source_credentials WHERE source_id = ?",
        source_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(db_err)
}

/// The username and expiry of the source's credential.
pub async fn credential_info(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Option<(String, Option<i64>)>, AppError> {
    let row = sqlx::query!(
        r#"SELECT username AS "username!", expires_at FROM source_credentials WHERE source_id = ?"#,
        source_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)?;
    Ok(row.map(|r| (r.username, r.expires_at)))
}

/// One image of the list, before its platforms are read.
#[derive(Debug, Clone)]
pub struct ImageHead {
    pub id: String,
    pub digest: String,
    pub is_index: bool,
    pub hub_host: String,
    pub repository: String,
}

/// One page of images that some source observes. `user_id` limits to that owner's sources,
/// `source_id` to one source, `state` to images with a platform in that state.
pub async fn images(
    pool: &SqlitePool,
    user_id: Option<&str>,
    source_id: Option<&str>,
    state: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ImageHead>, AppError> {
    sqlx::query_as!(
        ImageHead,
        r#"SELECT i.id AS "id!", i.digest AS "digest!", i.is_index AS "is_index!: bool",
                  h.host AS "hub_host!", i.repository AS "repository!"
           FROM images i JOIN hubs h ON h.id = i.hub_id
           WHERE EXISTS (SELECT 1 FROM tag_observations o JOIN image_sources s ON s.id = o.source_id
                         WHERE o.image_id = i.id AND (? IS NULL OR s.user_id = ?)
                           AND (? IS NULL OR s.id = ?))
             AND (? IS NULL OR EXISTS (SELECT 1 FROM image_platforms p
                                       WHERE p.image_id = i.id AND p.state = ?))
           ORDER BY i.created_at DESC, i.id ASC
           LIMIT ? OFFSET ?"#,
        user_id,
        user_id,
        source_id,
        source_id,
        state,
        state,
        limit,
        offset
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The number of images in the same scope as [`images`].
pub async fn count_images(
    pool: &SqlitePool,
    user_id: Option<&str>,
    source_id: Option<&str>,
    state: Option<&str>,
) -> Result<i64, AppError> {
    sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM images i
           WHERE EXISTS (SELECT 1 FROM tag_observations o JOIN image_sources s ON s.id = o.source_id
                         WHERE o.image_id = i.id AND (? IS NULL OR s.user_id = ?)
                           AND (? IS NULL OR s.id = ?))
             AND (? IS NULL OR EXISTS (SELECT 1 FROM image_platforms p
                                       WHERE p.image_id = i.id AND p.state = ?))"#,
        user_id,
        user_id,
        source_id,
        source_id,
        state,
        state
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

/// The tags that point at an image, within the same scope as [`images`].
pub async fn image_tags(
    pool: &SqlitePool,
    image_id: &str,
    user_id: Option<&str>,
    source_id: Option<&str>,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT o.tag AS "tag!"
           FROM tag_observations o JOIN image_sources s ON s.id = o.source_id
           WHERE o.image_id = ? AND (? IS NULL OR s.user_id = ?) AND (? IS NULL OR s.id = ?)
           ORDER BY o.tag"#,
        image_id,
        user_id,
        user_id,
        source_id,
        source_id
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// One platform of an image.
#[derive(Debug, Clone)]
pub struct PlatformRow {
    pub id: String,
    pub platform: String,
    pub state: String,
    pub size_bytes: Option<i64>,
    pub pulled_at: Option<i64>,
}

/// The platforms of an image, in order. `state` limits them to one state.
pub async fn image_platforms(
    pool: &SqlitePool,
    image_id: &str,
    state: Option<&str>,
) -> Result<Vec<PlatformRow>, AppError> {
    sqlx::query_as!(
        PlatformRow,
        r#"SELECT id AS "id!", platform AS "platform!", state AS "state!", size_bytes, pulled_at
           FROM image_platforms
           WHERE image_id = ? AND (? IS NULL OR state = ?)
           ORDER BY platform, id"#,
        image_id,
        state,
        state
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The latest scan run of one platform and scanner.
#[derive(Debug, Clone)]
pub struct RunRow {
    pub image_platform_id: String,
    pub scanner: String,
    pub status: String,
    pub scanner_version: Option<String>,
    pub error: Option<String>,
    pub db_built_at: Option<i64>,
}

/// The latest run (the last inserted) per platform and scanner of an image.
pub async fn latest_runs(pool: &SqlitePool, image_id: &str) -> Result<Vec<RunRow>, AppError> {
    sqlx::query_as!(
        RunRow,
        r#"SELECT r.image_platform_id AS "image_platform_id!", r.scanner AS "scanner!",
                  r.status AS "status!", r.scanner_version, r.error, r.db_built_at
           FROM scan_runs r JOIN image_platforms p ON p.id = r.image_platform_id
           WHERE p.image_id = ?
             AND r.rowid = (SELECT MAX(r2.rowid) FROM scan_runs r2
                            WHERE r2.image_platform_id = r.image_platform_id
                              AND r2.scanner = r.scanner)
           ORDER BY r.image_platform_id, r.scanner"#,
        image_id
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// True while a platform of the image is being pulled or evicted, or a scan of it is running.
pub async fn image_busy(conn: &mut SqliteConnection, image_id: &str) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT (EXISTS (SELECT 1 FROM image_platforms
                           WHERE image_id = ? AND state IN ('pulling', 'evicting'))
                   OR EXISTS (SELECT 1 FROM scan_runs r JOIN image_platforms p
                                  ON p.id = r.image_platform_id
                              WHERE p.image_id = ? AND r.status = 'running')) AS "busy!: bool""#,
        image_id,
        image_id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.busy)
}
