//! SQL for tag discovery and manifest resolution (`specs/spinoff-local-scan.md`, sections 5, 6
//! and 9): the sources on a repository, the images and tag observations, and the platform rows.
//!
//! Every write takes a connection so the caller can group them in one `BEGIN IMMEDIATE`
//! transaction. Rows hold ids, digests, tags and platform names only, never a secret. The
//! encrypted credential row is returned as stored; the service decrypts it.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// One source on a repository, with the hub fields the registry client needs.
#[derive(Debug, Clone)]
pub struct RepositorySource {
    pub id: String,
    pub tag_value: String,
    pub hub_host: String,
    pub pull_endpoint: Option<String>,
}

/// The sources on `(hub_id, repository)`, ordered by id. `only` limits the result to one source.
pub async fn sources_for_repository(
    conn: &mut SqliteConnection,
    hub_id: &str,
    repository: &str,
    only: Option<&str>,
) -> Result<Vec<RepositorySource>, AppError> {
    sqlx::query_as!(
        RepositorySource,
        r#"SELECT s.id AS "id!", s.tag_value AS "tag_value!", h.host AS "hub_host!",
                  h.pull_endpoint AS "pull_endpoint?"
           FROM image_sources s JOIN hubs h ON h.id = s.hub_id
           WHERE s.hub_id = ? AND s.repository = ? AND (? IS NULL OR s.id = ?)
           ORDER BY s.id"#,
        hub_id,
        repository,
        only,
        only
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// The owner, hub and repository of a source, for the manual scan route.
#[derive(Debug, Clone)]
pub struct SourceTarget {
    pub user_id: String,
    pub hub_id: String,
    pub repository: String,
}

/// The target of one source, whoever owns it.
pub async fn source_target(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Option<SourceTarget>, AppError> {
    sqlx::query_as!(
        SourceTarget,
        r#"SELECT user_id AS "user_id!", hub_id AS "hub_id!", repository AS "repository!"
           FROM image_sources WHERE id = ?"#,
        source_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// One distinct `(hub, repository)` with the lowest source id on it, which owns the job row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryTarget {
    pub hub_id: String,
    pub repository: String,
    pub first_source_id: String,
}

/// Every distinct `(hub, repository)` that has at least one source.
pub async fn distinct_repositories(pool: &SqlitePool) -> Result<Vec<RepositoryTarget>, AppError> {
    sqlx::query_as!(
        RepositoryTarget,
        r#"SELECT hub_id AS "hub_id!", repository AS "repository!",
                  MIN(id) AS "first_source_id!: String"
           FROM image_sources GROUP BY hub_id, repository ORDER BY hub_id, repository"#
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The status of the newest job whose payload text equals `payload`, if any.
pub async fn latest_job_status(
    conn: &mut SqliteConnection,
    payload: &str,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        r#"SELECT status AS "status!" FROM sync_jobs WHERE payload = ?
           ORDER BY created_at DESC, rowid DESC LIMIT 1"#,
        payload
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)?;
    Ok(row.map(|row| row.status))
}

/// A source's stored credential, still encrypted.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub id: String,
    pub username: String,
    pub encrypted_token: String,
}

/// The credential row of a source, if it has one.
pub async fn source_credential(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Option<StoredCredential>, AppError> {
    sqlx::query_as!(
        StoredCredential,
        r#"SELECT id AS "id!", username AS "username!", encrypted_token AS "encrypted_token!"
           FROM source_credentials WHERE source_id = ?"#,
        source_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// `INSERT ... ON CONFLICT DO NOTHING` for an image. True when a row was added.
pub async fn insert_image(
    conn: &mut SqliteConnection,
    id: &str,
    hub_id: &str,
    repository: &str,
    digest: &str,
    is_index: bool,
    now: i64,
) -> Result<bool, AppError> {
    let done = sqlx::query!(
        "INSERT INTO images (id, hub_id, repository, digest, is_index, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (hub_id, repository, digest) DO NOTHING",
        id,
        hub_id,
        repository,
        digest,
        is_index,
        now
    )
    .execute(conn)
    .await
    .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}

/// The id of the image `(hub_id, repository, digest)`, if it is known.
pub async fn find_image_id(
    conn: &mut SqliteConnection,
    hub_id: &str,
    repository: &str,
    digest: &str,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id AS "id!" FROM images WHERE hub_id = ? AND repository = ? AND digest = ?"#,
        hub_id,
        repository,
        digest
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)?;
    Ok(row.map(|row| row.id))
}

/// True when the source already observed `tag` pointing at an image other than `image_id`. That
/// makes a new image for the tag a moved tag (decision 17).
pub async fn tag_has_other_image(
    conn: &mut SqliteConnection,
    source_id: &str,
    tag: &str,
    image_id: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM tag_observations
           WHERE source_id = ? AND tag = ? AND image_id <> ?"#,
        source_id,
        tag,
        image_id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.n > 0)
}

/// `INSERT ... ON CONFLICT DO NOTHING` for a tag observation. True when a row was added.
pub async fn insert_observation(
    conn: &mut SqliteConnection,
    source_id: &str,
    tag: &str,
    image_id: &str,
    now: i64,
) -> Result<bool, AppError> {
    let done = sqlx::query!(
        "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (source_id, tag, image_id) DO NOTHING",
        source_id,
        tag,
        image_id,
        now,
        now
    )
    .execute(conn)
    .await
    .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}

/// Marks an existing observation as seen again.
pub async fn touch_observation(
    conn: &mut SqliteConnection,
    source_id: &str,
    tag: &str,
    image_id: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE tag_observations SET last_seen_at = ?
         WHERE source_id = ? AND tag = ? AND image_id = ?",
        now,
        source_id,
        tag,
        image_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// Stamps `last_discovery_at` on a source.
pub async fn touch_source(
    conn: &mut SqliteConnection,
    source_id: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE image_sources SET last_discovery_at = ? WHERE id = ?",
        now,
        source_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// An image with the hub fields needed to reach its registry.
#[derive(Debug, Clone)]
pub struct ImageRow {
    pub hub_host: String,
    pub pull_endpoint: Option<String>,
    pub repository: String,
    pub digest: String,
}

/// One image by id.
pub async fn find_image(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Option<ImageRow>, AppError> {
    sqlx::query_as!(
        ImageRow,
        r#"SELECT h.host AS "hub_host!", h.pull_endpoint AS "pull_endpoint?",
                  i.repository AS "repository!", i.digest AS "digest!"
           FROM images i JOIN hubs h ON h.id = i.hub_id WHERE i.id = ?"#,
        image_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// `INSERT ... ON CONFLICT DO NOTHING` for a platform row in state `queued`. True when a row was
/// added. A row that exists in any state (queued, pulling, stored, evicting, evicted, failed)
/// is left as it is, so discovery never re-queues it.
pub async fn insert_platform(
    conn: &mut SqliteConnection,
    id: &str,
    image_id: &str,
    platform: &str,
    platform_digest: &str,
    now: i64,
) -> Result<bool, AppError> {
    let done = sqlx::query!(
        "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, created_at)
         VALUES (?, ?, ?, ?, 'queued', ?)
         ON CONFLICT (image_id, platform_digest) DO NOTHING",
        id,
        image_id,
        platform,
        platform_digest,
        now
    )
    .execute(conn)
    .await
    .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}
