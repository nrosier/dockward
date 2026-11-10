//! SQL for the `cve_acceptances` table (`specs/database.md`, `specs/cve-lifecycle.md`,
//! "Acceptance"). An acceptance is active when `revoked_at IS NULL` and the expiry is empty
//! or after `now`. Rows hold a reason and user names only, never secrets.
//!
//! Every function takes a connection so the caller can group them in one transaction.

use sqlx::SqliteConnection;

use crate::error::AppError;

/// One acceptance, as far as the accept route answers with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceRow {
    pub id: String,
    pub mapping_id: String,
    pub cve_id: String,
    pub reason: String,
    pub created_by_username: String,
    pub created_at: Option<i64>,
    pub expires_at: Option<i64>,
}

/// A new acceptance. It starts active.
pub struct NewAcceptance<'a> {
    pub id: &'a str,
    pub mapping_id: &'a str,
    pub cve_id: &'a str,
    pub reason: &'a str,
    pub created_by: &'a str,
    pub created_by_username: &'a str,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// The active acceptance of the CVE in the mapping, if one exists.
pub async fn active(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    cve_id: &str,
    now: i64,
) -> Result<Option<AcceptanceRow>, AppError> {
    sqlx::query_as!(
        AcceptanceRow,
        r#"SELECT id AS "id!", source_id AS "mapping_id!", cve_id AS "cve_id!",
                  reason AS "reason!", created_by_username AS "created_by_username!",
                  created_at, expires_at
           FROM cve_acceptances
           WHERE source_id = ? AND cve_id = ? AND revoked_at IS NULL
             AND (expires_at IS NULL OR expires_at > ?)"#,
        mapping_id,
        cve_id,
        now
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Ids of acceptances of the CVE in the mapping whose expiry has passed and that are not
/// revoked yet. They still hold the partial unique index, so a new acceptance revokes them
/// first. The index allows at most one.
pub async fn expired_unrevoked(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    cve_id: &str,
    now: i64,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM cve_acceptances
           WHERE source_id = ? AND cve_id = ? AND revoked_at IS NULL
             AND expires_at IS NOT NULL AND expires_at <= ?"#,
        mapping_id,
        cve_id,
        now
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Stores a new active row. Returns `false` and changes nothing when the mapping already has
/// an unrevoked acceptance for the CVE (the partial unique index).
pub async fn insert(
    conn: &mut SqliteConnection,
    row: &NewAcceptance<'_>,
) -> Result<bool, AppError> {
    sqlx::query!(
        "INSERT INTO cve_acceptances
            (id, source_id, cve_id, reason, created_by, created_by_username, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING",
        row.id,
        row.mapping_id,
        row.cve_id,
        row.reason,
        row.created_by,
        row.created_by_username,
        row.created_at,
        row.expires_at
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected() == 1)
    .map_err(|_| AppError::InternalError)
}

/// Soft revoke: sets `revoked_at` and `revoked_by`. The row is kept. Returns `false` when the
/// row is already revoked.
pub async fn revoke(
    conn: &mut SqliteConnection,
    id: &str,
    by_user: &str,
    now: i64,
) -> Result<bool, AppError> {
    sqlx::query!(
        "UPDATE cve_acceptances SET revoked_at = ?, revoked_by = ?
         WHERE id = ? AND revoked_at IS NULL",
        now,
        by_user,
        id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected() == 1)
    .map_err(|_| AppError::InternalError)
}
