//! Reads of `image_sources` for the CVE lifecycle (`specs/spinoff-local-scan.md`, section 9).
//! A source replaces the Harbor mapping. The hub host is joined in, because it names the image
//! in issue text (decision 36). Owner-scoped, so another user's source is indistinguishable from
//! a missing one (`404`).

use sqlx::SqliteConnection;

use crate::error::AppError;

/// One source as the issue lifecycle reads it. No secret is held here: the GitHub credential is
/// referenced by id only.
#[derive(Debug, Clone)]
pub struct SourceRow {
    pub id: String,
    pub user_id: String,
    /// The hub's host (`hubs.host`), the only name a hub has.
    pub hub_host: String,
    pub repository: String,
    pub tag_value: String,
    pub github_cred_id: String,
    pub github_owner: String,
    pub github_repo: String,
    pub default_branch: String,
    pub auto_create_issues: bool,
    /// `CRITICAL` or `HIGH`.
    pub min_issue_severity: String,
}

/// The source `id` if `user_id` owns it.
pub async fn find_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
) -> Result<Option<SourceRow>, AppError> {
    sqlx::query_as!(
        SourceRow,
        r#"SELECT s.id AS "id!", s.user_id AS "user_id!", h.host AS "hub_host!",
                  s.repository AS "repository!", s.tag_value AS "tag_value!",
                  s.github_cred_id AS "github_cred_id!", s.github_owner AS "github_owner!",
                  s.github_repo AS "github_repo!", s.default_branch AS "default_branch!",
                  s.auto_create_issues AS "auto_create_issues!: bool",
                  s.min_issue_severity AS "min_issue_severity!"
           FROM image_sources s JOIN hubs h ON h.id = s.hub_id
           WHERE s.id = ? AND s.user_id = ?"#,
        id,
        user_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The source `id`, whoever owns it. For the worker, which acts for the system.
pub async fn find_by_id(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<SourceRow>, AppError> {
    sqlx::query_as!(
        SourceRow,
        r#"SELECT s.id AS "id!", s.user_id AS "user_id!", h.host AS "hub_host!",
                  s.repository AS "repository!", s.tag_value AS "tag_value!",
                  s.github_cred_id AS "github_cred_id!", s.github_owner AS "github_owner!",
                  s.github_repo AS "github_repo!", s.default_branch AS "default_branch!",
                  s.auto_create_issues AS "auto_create_issues!: bool",
                  s.min_issue_severity AS "min_issue_severity!"
           FROM image_sources s JOIN hubs h ON h.id = s.hub_id
           WHERE s.id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}
