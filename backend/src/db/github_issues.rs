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
/// now Dockward's own.
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

/// The newest scanned image of the source, or `None` when none of the source's observed images
/// has a `done` scan run. Decision 49: the newest image is the tag observation with the latest
/// `first_seen_at` (the later insert on a tie), so a tag that moves to a new digest becomes
/// newest on the next discovery. An image that no scanner has finished is not yet "scanned".
pub async fn newest_image(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT o.image_id AS "image_id!" FROM tag_observations o
           WHERE o.source_id = ?
             AND EXISTS (
                 SELECT 1 FROM image_platforms p
                 JOIN scan_runs r ON r.image_platform_id = p.id AND r.status = 'done'
                 WHERE p.image_id = o.image_id)
           ORDER BY o.first_seen_at DESC, o.rowid DESC
           LIMIT 1"#,
        source_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The tags whose current image is `image_id`: for each tag of the source, the observation with
/// the latest `first_seen_at` is the current one, and a tag that has since moved to another
/// digest no longer belongs to this image.
pub async fn current_tags_of_image(
    conn: &mut SqliteConnection,
    source_id: &str,
    image_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT o.tag AS "tag!" FROM tag_observations o
           WHERE o.source_id = ? AND o.image_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM tag_observations n
                 WHERE n.source_id = o.source_id AND n.tag = o.tag
                   AND (n.first_seen_at > o.first_seen_at
                        OR (n.first_seen_at = o.first_seen_at AND n.rowid > o.rowid)))
           ORDER BY o.tag"#,
        source_id,
        image_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The image tags of the newest scanned image of the source, or `None` when the source has no
/// scanned image (then every tracked tag counts).
pub async fn newest_image_tags(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Option<Vec<String>>, AppError> {
    let Some(image_id) = newest_image(&mut *conn, source_id).await? else {
        return Ok(None);
    };
    Ok(Some(
        current_tags_of_image(conn, source_id, &image_id).await?,
    ))
}

/// Points every `cve_findings` row of this CVE in the source at the issue row. Returns
/// the number of rows changed; rows that already point there are not counted.
pub async fn link_findings(
    conn: &mut SqliteConnection,
    source_id: &str,
    cve_id: &str,
    issue_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE cve_findings SET github_issue_id = ?
         WHERE source_id = ? AND cve_id = ?
           AND (github_issue_id IS NULL OR github_issue_id <> ?)",
        issue_id,
        source_id,
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

/// Every finding of the source, one row per tag and CVE.
pub async fn findings_for_source(
    conn: &mut SqliteConnection,
    source_id: &str,
) -> Result<Vec<FindingRow>, AppError> {
    sqlx::query_as!(
        FindingRow,
        r#"SELECT cve_id AS "cve_id!", image_tag AS "image_tag!", package,
                  severity AS "severity!", fixed_in_version, status AS "status!", last_seen_at,
                  description
           FROM cve_findings WHERE source_id = ?
           ORDER BY cve_id, image_tag"#,
        source_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The findings of one CVE in the source, one row per tag.
pub async fn findings_for_cve(
    conn: &mut SqliteConnection,
    source_id: &str,
    cve_id: &str,
) -> Result<Vec<FindingRow>, AppError> {
    sqlx::query_as!(
        FindingRow,
        r#"SELECT cve_id AS "cve_id!", image_tag AS "image_tag!", package,
                  severity AS "severity!", fixed_in_version, status AS "status!", last_seen_at,
                  description
           FROM cve_findings WHERE source_id = ? AND cve_id = ?
           ORDER BY image_tag"#,
        source_id,
        cve_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// A source that targets the same GitHub repository as another one (decision 47).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingSource {
    pub id: String,
}

/// The other sources that target the same GitHub repository as `source_id`. They share its
/// `github_issues` rows (decision 47).
pub async fn sibling_sources(
    conn: &mut SqliteConnection,
    source_id: &str,
    owner: &str,
    repo: &str,
) -> Result<Vec<SiblingSource>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!" FROM image_sources
           WHERE github_owner = ? AND github_repo = ? AND id <> ?
           ORDER BY id"#,
        owner,
        repo,
        source_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| SiblingSource { id: row.id })
        .collect())
}

/// CVE ids of the source with an active acceptance: not revoked, and with no expiry or an
/// expiry after `now`.
pub async fn accepted_cves(
    conn: &mut SqliteConnection,
    source_id: &str,
    now: i64,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT cve_id AS "cve_id!" FROM cve_acceptances
           WHERE source_id = ? AND revoked_at IS NULL
             AND (expires_at IS NULL OR expires_at > ?)"#,
        source_id,
        now
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Deletes the `github_issues` rows of a GitHub repository that no other source of that
/// repository reports with an `open` finding. Rows are shared by every source that targets the
/// repository (decision 47), so a row still reported elsewhere stays. Nothing is changed on
/// GitHub. Run it before the source row is deleted.
#[allow(dead_code)] // Used by the source delete route (Step 1 part 2); the lifecycle tests use it.
pub async fn delete_unreported_elsewhere(
    conn: &mut SqliteConnection,
    source_id: &str,
    github_owner: &str,
    github_repo: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "DELETE FROM github_issues
         WHERE github_owner = ? AND github_repo = ?
           AND NOT EXISTS (
               SELECT 1 FROM cve_findings f
               JOIN image_sources s ON s.id = f.source_id
               WHERE s.id <> ? AND s.github_owner = github_issues.github_owner
                 AND s.github_repo = github_issues.github_repo
                 AND f.cve_id = github_issues.cve_id AND f.status = 'open')",
        github_owner,
        github_repo,
        source_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[tokio::test]
    async fn second_insert_for_the_same_cve_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("dockward-gi-dup-{}", std::process::id()));
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
