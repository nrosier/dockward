//! SQL for the GitHub re-key bookkeeping tables `issue_rekeys` and `analysis_retirements`
//! (migration 0002, #311). Owner and repository names are matched case-insensitively because
//! GitHub treats them that way. Rows hold names and counts only, never secrets. Nothing here logs.

use sqlx::SqlitePool;

use crate::error::AppError;

/// The stored result of the one-time issue re-key of a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuesDone {
    /// `renamed`, `absent` or `kept`.
    pub label_result: String,
    /// Number of old open issues that were re-keyed.
    pub issues_rekeyed: i64,
}

/// The stored re-key result for this repository, if the re-key has completed.
pub async fn issues_done(
    pool: &SqlitePool,
    owner: &str,
    repo: &str,
) -> Result<Option<IssuesDone>, AppError> {
    sqlx::query_as!(
        IssuesDone,
        r#"SELECT label_result AS "label_result!", issues_rekeyed AS "issues_rekeyed!: i64"
           FROM issue_rekeys
           WHERE github_owner = ? AND github_repo = ?"#,
        owner,
        repo
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Stores the issue re-key result for a repository. An existing row is kept unchanged
/// (`ON CONFLICT DO NOTHING`): the first completed re-key is the record.
pub async fn insert_issues_done(
    pool: &SqlitePool,
    owner: &str,
    repo: &str,
    label_result: &str,
    issues: u32,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO issue_rekeys
            (github_owner, github_repo, label_result, issues_rekeyed, completed_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (github_owner, github_repo) DO NOTHING",
        owner,
        repo,
        label_result,
        i64::from(issues),
        now
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Whether the old analyses of this repository and legacy category have been retired.
pub async fn analyses_done(
    pool: &SqlitePool,
    owner: &str,
    repo: &str,
    legacy_category: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS \"n!: i64\"
         FROM analysis_retirements
         WHERE github_owner = ? AND github_repo = ? AND legacy_category = ?",
        owner,
        repo,
        legacy_category
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n > 0)
}

/// Stores the analysis retirement result for a repository and legacy category. An existing
/// row is kept unchanged (`ON CONFLICT DO NOTHING`).
pub async fn insert_analyses_done(
    pool: &SqlitePool,
    owner: &str,
    repo: &str,
    legacy_category: &str,
    deleted: u32,
    carried: u32,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO analysis_retirements
            (github_owner, github_repo, legacy_category, analyses_deleted, dismissals_carried,
             completed_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (github_owner, github_repo, legacy_category) DO NOTHING",
        owner,
        repo,
        legacy_category,
        i64::from(deleted),
        i64::from(carried),
        now
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::test_pool;

    #[tokio::test]
    async fn issues_done_round_trips_an_insert() -> Result<(), AppError> {
        let pool = test_pool().await?;
        assert_eq!(issues_done(&pool, "octo", "repo").await?, None);

        insert_issues_done(&pool, "octo", "repo", "renamed", 3, 1_700_000_000).await?;
        assert_eq!(
            issues_done(&pool, "octo", "repo").await?,
            Some(IssuesDone {
                label_result: "renamed".to_owned(),
                issues_rekeyed: 3,
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn second_issues_insert_keeps_the_first_row() -> Result<(), AppError> {
        let pool = test_pool().await?;
        insert_issues_done(&pool, "octo", "repo", "kept", 5, 1).await?;
        insert_issues_done(&pool, "octo", "repo", "renamed", 9, 2).await?;
        assert_eq!(
            issues_done(&pool, "octo", "repo").await?,
            Some(IssuesDone {
                label_result: "kept".to_owned(),
                issues_rekeyed: 5,
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn issues_done_matches_owner_and_repo_case_insensitively() -> Result<(), AppError> {
        let pool = test_pool().await?;
        insert_issues_done(&pool, "octo", "Repo", "absent", 0, 1).await?;
        assert!(issues_done(&pool, "Octo", "repo").await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn analyses_done_round_trips_an_insert() -> Result<(), AppError> {
        let pool = test_pool().await?;
        assert!(!analyses_done(&pool, "octo", "repo", "harborgate/hub/repo/tag").await?);

        insert_analyses_done(&pool, "octo", "repo", "harborgate/hub/repo/tag", 4, 2, 1).await?;
        assert!(analyses_done(&pool, "octo", "repo", "harborgate/hub/repo/tag").await?);
        assert!(!analyses_done(&pool, "octo", "repo", "harborgate/hub/repo/other").await?);
        Ok(())
    }

    #[tokio::test]
    async fn second_analyses_insert_is_a_no_op() -> Result<(), AppError> {
        let pool = test_pool().await?;
        insert_analyses_done(&pool, "octo", "repo", "harborgate/hub/repo/tag", 4, 2, 1).await?;
        insert_analyses_done(&pool, "octo", "repo", "harborgate/hub/repo/tag", 7, 0, 2).await?;

        let row = sqlx::query!(
            "SELECT analyses_deleted AS \"analyses_deleted!: i64\",
                    dismissals_carried AS \"dismissals_carried!: i64\"
             FROM analysis_retirements WHERE github_owner = 'octo'"
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(row.analyses_deleted, 4);
        assert_eq!(row.dismissals_carried, 2);
        Ok(())
    }

    #[tokio::test]
    async fn analyses_done_matches_owner_and_repo_case_insensitively() -> Result<(), AppError> {
        let pool = test_pool().await?;
        insert_analyses_done(&pool, "octo", "repo", "harborgate/hub/repo/tag", 1, 0, 1).await?;
        assert!(analyses_done(&pool, "OCTO", "Repo", "harborgate/hub/repo/tag").await?);
        Ok(())
    }
}
