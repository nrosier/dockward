//! SQL for the `alert_pending` table (#458): CVE changes the convert step found and no alert has
//! been sent for yet. Rows hold ids, a tag and a CVE id, never a secret or an upstream body.
//!
//! The convert step records a change in the transaction that stores its scan run. When every run
//! of the image has ended, the scan alerts take the rows of the image ([`take_new`],
//! [`take_fixed`]) and delete them, so a change is sent at most once.

use sqlx::SqliteConnection;

use crate::error::AppError;

/// The event of a CVE that no row of its source had before this scan.
pub const NEW: &str = "new_high_or_critical";
/// The event of a CVE the tag had `open` that the image no longer reports.
pub const FIXED: &str = "cve_fixed";

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// Records one change. A change already recorded for the same image, source, tag and CVE adds
/// nothing.
pub async fn record(
    conn: &mut SqliteConnection,
    event: &str,
    image_id: &str,
    source_id: &str,
    image_tag: &str,
    cve_id: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO alert_pending (event, image_id, source_id, image_tag, cve_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (event, image_id, source_id, image_tag, cve_id) DO NOTHING",
        event,
        image_id,
        source_id,
        image_tag,
        cve_id,
        now
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// True when no row of `source_id`, on any tag, names `cve_id`: the source never reported it.
pub async fn source_never_reported(
    conn: &mut SqliteConnection,
    source_id: &str,
    cve_id: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (SELECT 1 FROM cve_findings WHERE source_id = ? AND cve_id = ?)
           AS "seen!: i64""#,
        source_id,
        cve_id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.seen == 0)
}

/// One pending change, with the severity its `cve_findings` row has now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCve {
    pub source_id: String,
    pub image_tag: String,
    pub cve_id: String,
    pub severity: String,
}

/// Takes the new CVEs of `image_id` and deletes their rows. Only CVEs that are still `open` and
/// HIGH or CRITICAL now are returned: the severity is the merged one at the end of the scan, so a
/// CVE that a later scanner raised to HIGH counts, and one that went away before the end does not.
/// Ordered by source, then CRITICAL before HIGH, then CVE id, then tag.
pub async fn take_new(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<PendingCve>, AppError> {
    let rows = sqlx::query_as!(
        PendingCve,
        r#"SELECT p.source_id AS "source_id!", p.image_tag AS "image_tag!",
                  p.cve_id AS "cve_id!", f.severity AS "severity!"
           FROM alert_pending p
           JOIN cve_findings f
             ON f.source_id = p.source_id AND f.image_tag = p.image_tag AND f.cve_id = p.cve_id
           WHERE p.image_id = ? AND p.event = 'new_high_or_critical'
             AND f.status = 'open' AND f.severity IN ('CRITICAL', 'HIGH')
           ORDER BY p.source_id, CASE f.severity WHEN 'CRITICAL' THEN 0 ELSE 1 END,
                    p.cve_id, p.image_tag"#,
        image_id
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    sqlx::query!(
        "DELETE FROM alert_pending WHERE image_id = ? AND event = 'new_high_or_critical'",
        image_id
    )
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(rows)
}

/// Takes the fixed CVEs of `image_id` and deletes their rows. Only CVEs whose row is still
/// `fixed` are returned, so a CVE that one scanner dropped and another reported again before the
/// scan ended is not sent. Ordered by source, CVE id and tag.
pub async fn take_fixed(
    conn: &mut SqliteConnection,
    image_id: &str,
) -> Result<Vec<PendingCve>, AppError> {
    let rows = sqlx::query_as!(
        PendingCve,
        r#"SELECT p.source_id AS "source_id!", p.image_tag AS "image_tag!",
                  p.cve_id AS "cve_id!", f.severity AS "severity!"
           FROM alert_pending p
           JOIN cve_findings f
             ON f.source_id = p.source_id AND f.image_tag = p.image_tag AND f.cve_id = p.cve_id
           WHERE p.image_id = ? AND p.event = 'cve_fixed' AND f.status = 'fixed'
           ORDER BY p.source_id, p.cve_id, p.image_tag"#,
        image_id
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    sqlx::query!(
        "DELETE FROM alert_pending WHERE image_id = ? AND event = 'cve_fixed'",
        image_id
    )
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(rows)
}
