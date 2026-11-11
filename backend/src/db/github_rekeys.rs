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

/// One stored carry-over: a rule whose new open alerts are dismissed with this reason and comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCarry {
    pub rule_id: String,
    pub reason: String,
    pub comment: Option<String>,
    /// True once the dismissals of this rule have all been written.
    pub applied: bool,
}

/// The stored plan for a repository and legacy category, if one was written: the refs the legacy
/// analyses ran on, and one row per carried rule. `None` when no plan exists yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPlan {
    pub refs: Vec<String>,
    pub carries: Vec<PlannedCarry>,
}

/// The stored carry-over plan, or `None` when no plan has been written for this key.
pub async fn carryover_plan(
    pool: &SqlitePool,
    owner: &str,
    repo: &str,
    legacy_category: &str,
) -> Result<Option<StoredPlan>, AppError> {
    let refs: Vec<String> = sqlx::query_scalar!(
        "SELECT git_ref FROM carryover_refs
         WHERE github_owner = ? AND github_repo = ? AND legacy_category = ?
         ORDER BY git_ref",
        owner,
        repo,
        legacy_category
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    let rows = sqlx::query!(
        "SELECT rule_id, reason, comment, applied AS \"applied!: i64\"
         FROM alert_carryovers
         WHERE github_owner = ? AND github_repo = ? AND legacy_category = ?
         ORDER BY rule_id",
        owner,
        repo,
        legacy_category
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    if rows.is_empty() && refs.is_empty() {
        return Ok(None);
    }
    let carries = rows
        .into_iter()
        .map(|row| PlannedCarry {
            rule_id: row.rule_id,
            reason: row.reason,
            comment: row.comment,
            applied: row.applied != 0,
        })
        .collect();
    Ok(Some(StoredPlan { refs, carries }))
}

/// Stores a carry-over plan before the first delete. Existing rows are kept unchanged
/// (`ON CONFLICT DO NOTHING`), so a plan is written once.
pub async fn insert_carryover_plan(
    pool: &SqlitePool,
    owner: &str,
    repo: &str,
    legacy_category: &str,
    refs: &[String],
    carries: &[PlannedCarry],
    now: i64,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    for git_ref in refs {
        sqlx::query!(
            "INSERT INTO carryover_refs (github_owner, github_repo, legacy_category, git_ref)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (github_owner, github_repo, legacy_category, git_ref) DO NOTHING",
            owner,
            repo,
            legacy_category,
            git_ref
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::InternalError)?;
    }
    for carry in carries {
        sqlx::query!(
            "INSERT INTO alert_carryovers
                (github_owner, github_repo, legacy_category, rule_id, reason, comment, planned_at,
                 applied)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0)
             ON CONFLICT (github_owner, github_repo, legacy_category, rule_id) DO NOTHING",
            owner,
            repo,
            legacy_category,
            carry.rule_id,
            carry.reason,
            carry.comment,
            now
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::InternalError)?;
    }
    tx.commit().await.map_err(|_| AppError::InternalError)
}

/// Records that the dismissals of one carried rule have all been written.
pub async fn mark_carry_applied(
    pool: &SqlitePool,
    owner: &str,
    repo: &str,
    legacy_category: &str,
    rule_id: &str,
) -> Result<(), AppError> {
    let result = sqlx::query!(
        "UPDATE alert_carryovers SET applied = 1
         WHERE github_owner = ? AND github_repo = ? AND legacy_category = ? AND rule_id = ?",
        owner,
        repo,
        legacy_category,
        rule_id
    )
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    // A carry-over with no stored plan row must not count as applied.
    if result.rows_affected() != 1 {
        return Err(AppError::InternalError);
    }
    Ok(())
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
    async fn mark_carry_applied_fails_when_no_plan_row_matches() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let result =
            mark_carry_applied(&pool, "octo", "repo", "harborgate/hub/repo/tag", "rule-x").await;
        assert_eq!(result, Err(AppError::InternalError));
        Ok(())
    }

    #[tokio::test]
    async fn mark_carry_applied_succeeds_for_a_stored_plan_row() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let carries = vec![PlannedCarry {
            rule_id: "rule-x".to_owned(),
            reason: "wont_fix".to_owned(),
            comment: None,
            applied: false,
        }];
        insert_carryover_plan(
            &pool,
            "octo",
            "repo",
            "harborgate/hub/repo/tag",
            &["refs/heads/main".to_owned()],
            &carries,
            1,
        )
        .await?;
        mark_carry_applied(&pool, "octo", "repo", "harborgate/hub/repo/tag", "rule-x").await?;
        let plan = carryover_plan(&pool, "octo", "repo", "harborgate/hub/repo/tag")
            .await?
            .ok_or(AppError::InternalError)?;
        assert!(plan.carries[0].applied);
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
