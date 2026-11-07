//! SQL for the `github_issues` table and the reads the issue lifecycle needs from
//! `cve_findings` and `cve_acceptances` (`specs/database.md`, `specs/cve-lifecycle.md`,
//! "GitHub issue rules"). Rows hold issue numbers and URLs only, never secrets.
//!
//! Every function takes a connection so the caller can group them in one transaction.

use sqlx::SqliteConnection;

use crate::error::AppError;

/// One tracked GitHub issue: one row per (repository, CVE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRow {
    pub id: String,
    pub github_owner: String,
    pub github_repo: String,
    pub cve_id: String,
    pub github_issue_number: i64,
    pub github_issue_url: String,
    /// `open` or `closed`.
    pub status: String,
    /// True when the issue was closed by hand on GitHub while the CVE was still reported.
    pub closed_manually: bool,
}

/// A new row. It starts `open`.
pub struct NewIssue<'a> {
    pub id: &'a str,
    pub github_owner: &'a str,
    pub github_repo: &'a str,
    pub cve_id: &'a str,
    pub github_issue_number: i64,
    pub github_issue_url: &'a str,
}

/// The row for this repository and CVE, if one exists.
pub async fn find(
    conn: &mut SqliteConnection,
    owner: &str,
    repo: &str,
    cve_id: &str,
) -> Result<Option<IssueRow>, AppError> {
    sqlx::query_as!(
        IssueRow,
        r#"SELECT id AS "id!", github_owner AS "github_owner!", github_repo AS "github_repo!",
                  cve_id AS "cve_id!", github_issue_number AS "github_issue_number!: i64",
                  github_issue_url AS "github_issue_url!", status AS "status!",
                  closed_manually AS "closed_manually!: bool"
           FROM github_issues
           WHERE github_owner = ? AND github_repo = ? AND cve_id = ?"#,
        owner,
        repo,
        cve_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Stores a new `open` row. Returns `false` and changes nothing when the repository already
/// has a row for the CVE (`UNIQUE (github_owner, github_repo, cve_id)`): two writers racing
/// for the same CVE are not an error, and the caller re-reads the winner's row.
pub async fn insert(conn: &mut SqliteConnection, row: &NewIssue<'_>) -> Result<bool, AppError> {
    sqlx::query!(
        "INSERT INTO github_issues
            (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url, status)
         VALUES (?, ?, ?, ?, ?, ?, 'open')
         ON CONFLICT (github_owner, github_repo, cve_id) DO NOTHING",
        row.id,
        row.github_owner,
        row.github_repo,
        row.cve_id,
        row.github_issue_number,
        row.github_issue_url
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected() == 1)
    .map_err(|_| AppError::InternalError)
}

/// Sets the row's status to `open` or `closed`. It clears `closed_manually`: the status is
/// now HarborGate's own.
pub async fn set_status(
    conn: &mut SqliteConnection,
    id: &str,
    status: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE github_issues SET status = ?, closed_manually = 0 WHERE id = ?",
        status,
        id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Marks the row `closed` because the issue was closed by hand on GitHub.
pub async fn mark_closed_manually(conn: &mut SqliteConnection, id: &str) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE github_issues SET status = 'closed', closed_manually = 1 WHERE id = ?",
        id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// The newest scanned digest of the mapping's repository, or `None` when the mapping has no
/// successful report. The same choice as [`newest_digest_tags`].
pub async fn newest_digest(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT image_digest AS "image_digest!" FROM sync_reports
           WHERE mapping_id = ? AND harbor_repository = ? AND sarif_status = 'success'
           ORDER BY image_push_time IS NULL, image_push_time DESC, synced_at DESC, rowid DESC
           LIMIT 1"#,
        mapping_id,
        repo
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The image tags of the newest scanned digest of the mapping's repository, or `None` when
/// the mapping has no successful report. The newest digest is the one with the latest
/// `image_push_time` among successful reports (a report without a push time ranks below any
/// report with one, then by `synced_at`, then by insert order). Its tags are the tags of
/// every successful report for that digest.
pub async fn newest_digest_tags(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
) -> Result<Option<Vec<String>>, AppError> {
    let newest = sqlx::query_scalar!(
        r#"SELECT image_digest AS "image_digest!" FROM sync_reports
           WHERE mapping_id = ? AND harbor_repository = ? AND sarif_status = 'success'
           ORDER BY image_push_time IS NULL, image_push_time DESC, synced_at DESC, rowid DESC
           LIMIT 1"#,
        mapping_id,
        repo
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    let Some(digest) = newest else {
        return Ok(None);
    };
    let tags = sqlx::query_scalar!(
        r#"SELECT DISTINCT image_tag AS "image_tag!" FROM sync_reports
           WHERE mapping_id = ? AND harbor_repository = ? AND sarif_status = 'success'
             AND image_digest = ?"#,
        mapping_id,
        repo,
        digest
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(Some(tags))
}

/// Points every `cve_findings` row of this CVE in the mapping at the issue row. Returns
/// the number of rows changed; rows that already point there are not counted.
pub async fn link_findings(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    cve_id: &str,
    issue_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE cve_findings SET github_issue_id = ?
         WHERE mapping_id = ? AND cve_id = ?
           AND (github_issue_id IS NULL OR github_issue_id <> ?)",
        issue_id,
        mapping_id,
        cve_id,
        issue_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// One tag's row for a CVE, as far as the lifecycle needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub cve_id: String,
    pub image_tag: String,
    pub package: Option<String>,
    pub severity: String,
    pub fixed_in_version: Option<String>,
    /// `open` or `fixed`.
    pub status: String,
    pub last_seen_at: Option<i64>,
    pub description: Option<String>,
}

/// Every finding of the mapping, one row per tag and CVE.
pub async fn findings_for_mapping(
    conn: &mut SqliteConnection,
    mapping_id: &str,
) -> Result<Vec<FindingRow>, AppError> {
    sqlx::query_as!(
        FindingRow,
        r#"SELECT cve_id AS "cve_id!", image_tag AS "image_tag!", package,
                  severity AS "severity!", fixed_in_version, status AS "status!", last_seen_at,
                  description
           FROM cve_findings WHERE mapping_id = ?
           ORDER BY cve_id, image_tag"#,
        mapping_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The findings of one CVE in the mapping, one row per tag.
pub async fn findings_for_cve(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    cve_id: &str,
) -> Result<Vec<FindingRow>, AppError> {
    sqlx::query_as!(
        FindingRow,
        r#"SELECT cve_id AS "cve_id!", image_tag AS "image_tag!", package,
                  severity AS "severity!", fixed_in_version, status AS "status!", last_seen_at,
                  description
           FROM cve_findings WHERE mapping_id = ? AND cve_id = ?
           ORDER BY image_tag"#,
        mapping_id,
        cve_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// A mapping that targets the same GitHub repository as another one (#185).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingMapping {
    pub id: String,
    pub harbor_base_url: String,
    pub harbor_repository: String,
}

/// The other mappings that target the same GitHub repository as `mapping_id`. They share its
/// `github_issues` rows (#185).
pub async fn sibling_mappings(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    owner: &str,
    repo: &str,
) -> Result<Vec<SiblingMapping>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", harbor_base_url AS "harbor_base_url!",
                  harbor_repository AS "harbor_repository!" FROM repo_mappings
           WHERE github_owner = ? AND github_repo = ? AND id <> ?
           ORDER BY id"#,
        owner,
        repo,
        mapping_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| SiblingMapping {
            id: row.id,
            harbor_base_url: row.harbor_base_url,
            harbor_repository: row.harbor_repository,
        })
        .collect())
}

/// CVE ids of the mapping with an active acceptance: not revoked, and with no expiry or an
/// expiry after `now`.
pub async fn accepted_cves(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    now: i64,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT cve_id AS "cve_id!" FROM cve_acceptances
           WHERE mapping_id = ? AND revoked_at IS NULL
             AND (expires_at IS NULL OR expires_at > ?)"#,
        mapping_id,
        now
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[tokio::test]
    async fn second_insert_for_the_same_cve_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("harborgate-gi-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let first = NewIssue {
            id: "gi1",
            github_owner: "octo",
            github_repo: "app",
            cve_id: "CVE-2026-0001",
            github_issue_number: 1,
            github_issue_url: "https://github.com/octo/app/issues/1",
        };
        let second = NewIssue {
            id: "gi2",
            github_issue_number: 2,
            github_issue_url: "https://github.com/octo/app/issues/2",
            ..first_copy(&first)
        };
        assert!(insert(&mut conn, &first).await.unwrap());
        assert!(!insert(&mut conn, &second).await.unwrap());
        let kept = find(&mut conn, "octo", "app", "CVE-2026-0001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.id, "gi1", "the first writer's row is kept");
        drop(conn);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn first_copy<'a>(row: &NewIssue<'a>) -> NewIssue<'a> {
        NewIssue {
            id: row.id,
            github_owner: row.github_owner,
            github_repo: row.github_repo,
            cve_id: row.cve_id,
            github_issue_number: row.github_issue_number,
            github_issue_url: row.github_issue_url,
        }
    }
}
