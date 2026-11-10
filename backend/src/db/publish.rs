//! SQL for the publish step (`specs/spinoff-local-scan.md`, section 6 steps 6 and 7): which
//! sources an ended image is the newest image of, whether an image still has work in flight, and
//! the observation a publish names in its report.
//!
//! Rows hold ids, tags and digests only. No secret is ever bound here.
//!
//! Every function takes a connection so the caller can group them in one transaction.

use sqlx::SqliteConnection;

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// The newest tag observation of a source (decision 49): the one with the latest
/// `first_seen_at`, the later insert on a tie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewestObservation {
    pub image_id: String,
    pub tag: String,
    /// The top-level digest of the image (`images.digest`).
    pub digest: String,
}

/// The newest observation of `source_id`, or `None` when discovery has observed nothing.
pub async fn newest_observation(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Option<NewestObservation>, AppError> {
    sqlx::query_as!(
        NewestObservation,
        r#"SELECT o.image_id AS "image_id!", o.tag AS "tag!", i.digest AS "digest!"
           FROM tag_observations o JOIN images i ON i.id = o.image_id
           WHERE o.source_id = ?
           ORDER BY o.first_seen_at DESC, o.rowid DESC
           LIMIT 1"#,
        source_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// The sources whose newest observation (decision 49) is an observation of `image_id`. Only
/// these publish for the image; the others hold it as an older image and upload nothing.
pub async fn sources_with_newest_image(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT o.source_id AS "source_id!" FROM tag_observations o
           WHERE o.image_id = ?
             AND o.rowid = (SELECT o2.rowid FROM tag_observations o2
                            WHERE o2.source_id = o.source_id
                            ORDER BY o2.first_seen_at DESC, o2.rowid DESC LIMIT 1)
           ORDER BY o.source_id"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// True while a platform of `image_id` is still waiting to be pulled: its row is `queued` or
/// `pulling`, or a `pull` job for it is `queued` or `running` (a failed attempt that will retry
/// leaves the row `failed`, but its job still waits). Such a platform has not ended, so the
/// image is not ready to publish.
pub async fn image_has_pending_pull(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM image_platforms p
               WHERE p.image_id = ?1
                 AND (p.state IN ('queued', 'pulling')
                      OR EXISTS (
                          SELECT 1 FROM sync_jobs j
                          WHERE j.status IN ('queued', 'running')
                            AND json_extract(j.payload, '$.kind') = 'pull'
                            AND json_extract(j.payload, '$.platform_id') = p.id))
           ) AS "pending!: i64""#,
        image_id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.pending != 0)
}

/// True when a `publish` job with exactly this payload is `queued` or `running`. A second job
/// for the same source and image adds nothing.
pub async fn open_publish_job_exists(
    conn: &mut SqliteConnection,
    payload: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM sync_jobs WHERE payload = ? AND status IN ('queued', 'running')
           ) AS "open!: i64""#,
        payload
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.open != 0)
}

/// The platform images of `image_id` that have a `done` run, the one that finished first first.
/// The first scanned platform is the one whose stored config supplies the labels.
pub async fn scanned_platform_ids(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT p.id AS "id!"
           FROM image_platforms p JOIN scan_runs r ON r.image_platform_id = p.id
           WHERE p.image_id = ? AND r.status = 'done'
           GROUP BY p.id
           ORDER BY MIN(COALESCE(r.finished_at, 0)), p.id"#,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

/// The image a platform row belongs to.
pub async fn image_of_platform(
    conn: &mut SqliteConnection,
    platform_id: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT image_id AS "image_id!" FROM image_platforms WHERE id = ?"#,
        platform_id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}
