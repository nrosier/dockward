//! CVE routes. This file holds the manual issue route only (`specs/api.md`, CVEs); the read
//! routes and the accept routes belong to other issues.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::issue_lifecycle::{self, IssueApi};
use crate::services::sessions::AuthUser;
use crate::worker::now_secs;

/// The answer of `POST /api/v1/cves/:id/issue`.
#[derive(Debug, Serialize)]
pub struct IssueCreated {
    pub github_issue_url: String,
    pub github_issue_number: i64,
}

/// `POST /api/v1/cves/:id/issue`. `:id` is `<mapping_id>:<cve_id>`. The caller must own the
/// mapping. Returns `201`; `404` for an unknown or foreign mapping or CVE; `409` when an
/// open issue exists (the body names its URL) or the CVE has an active acceptance; `422`
/// when the highest open severity is not CRITICAL or HIGH; `502` when GitHub fails.
pub async fn issue(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<IssueCreated>), AppError> {
    issue_with(&state, &user, &id, state.issues_client.as_ref()).await
}

/// The route's work with the GitHub client passed in, so tests use a fake.
async fn issue_with<G: IssueApi>(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    gh: &G,
) -> Result<(StatusCode, Json<IssueCreated>), AppError> {
    let created = issue_lifecycle::create_manual_for_user(
        &state.pool,
        &state.credentials_key,
        gh,
        &user.id,
        id,
        now_secs(),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(IssueCreated {
            github_issue_url: created.url,
            github_issue_number: created.number,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::api::admin::test_support::{
        seed_github, seed_harbor, seed_mapping, seed_user, test_state,
    };
    use crate::db;
    use crate::models::role::Role;
    use crate::services::issue_lifecycle::test_support::{FakeGithub, FakeIssues};

    fn user(id: &str) -> AuthUser {
        AuthUser {
            id: id.to_owned(),
            username: id.to_owned(),
            role: Role::User,
        }
    }

    async fn finding(state: &AppState, tag: &str, cve: &str, severity: &str) {
        let mut conn = state.pool.acquire().await.unwrap();
        db::findings::upsert(
            &mut conn,
            &db::findings::Finding {
                id: &crate::services::ids::new_id(),
                mapping_id: "m1",
                harbor_repository: "m1",
                image_tag: tag,
                cve_id: cve,
                package: Some("openssl"),
                severity,
                fixed_in_version: None,
                description: None,
                now: 10,
            },
        )
        .await
        .unwrap();
    }

    async fn setup(name: &str) -> (AppState, std::path::PathBuf, Arc<FakeGithub>, FakeIssues) {
        let (state, dir) = test_state(name).await;
        seed_user(&state.pool, "u1", "user").await;
        seed_user(&state.pool, "u2", "user").await;
        seed_harbor(&state.pool, "u1", "ch", "harbor", None).await;
        seed_github(&state.pool, "u1", "cg", "github").await;
        seed_mapping(&state.pool, "u1", "m1", "ch", "cg", "octo", "app").await;
        let github = Arc::new(FakeGithub::default());
        (state, dir, github.clone(), FakeIssues(github))
    }

    async fn call(
        state: &AppState,
        who: &str,
        id: &str,
        gh: &FakeIssues,
    ) -> Result<(StatusCode, Json<IssueCreated>), AppError> {
        issue_with(state, &user(who), id, gh).await
    }

    #[tokio::test]
    async fn manual_issue_409_when_open_and_422_when_ineligible() {
        let (state, dir, github, gh) = setup("manual").await;
        finding(&state, "v1", "CVE-2026-0001", "CRITICAL").await;
        finding(&state, "v1", "CVE-2026-0002", "MEDIUM").await;
        finding(&state, "v1", "CVE-2026-0003", "HIGH").await;

        // 422: MEDIUM can never get an issue. Nothing is sent to GitHub.
        let medium = call(&state, "u1", "m1:CVE-2026-0002", &gh)
            .await
            .unwrap_err();
        assert_eq!(medium.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(github.requests(), 0);

        // 201: a HIGH CVE gets an issue although the mapping's minimum is CRITICAL.
        let (status, Json(high)) = call(&state, "u1", "m1:CVE-2026-0003", &gh).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(high.github_issue_number, 1);

        // 201, then 409 with the URL of the open issue, and no second create.
        let (_, Json(first)) = call(&state, "u1", "m1:CVE-2026-0001", &gh).await.unwrap();
        assert_eq!(
            first.github_issue_url,
            "https://github.com/octo/app/issues/2"
        );
        let again = call(&state, "u1", "m1:CVE-2026-0001", &gh)
            .await
            .unwrap_err();
        assert_eq!(again.status(), StatusCode::CONFLICT);
        assert!(again.message().contains(&first.github_issue_url));
        assert_eq!(github.creates().len(), 2);

        // The highest open severity across tags decides: MEDIUM on v1 and HIGH on v2 is eligible.
        finding(&state, "v2", "CVE-2026-0002", "HIGH").await;
        let (status, _) = call(&state, "u1", "m1:CVE-2026-0002", &gh).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);

        // 404: another tenant's mapping, an unknown CVE, and a malformed id.
        for (who, id) in [
            ("u2", "m1:CVE-2026-0001"),
            ("u1", "m1:CVE-2026-9999"),
            ("u1", "no-colon"),
        ] {
            let error = call(&state, who, id, &gh).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::NOT_FOUND);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn manual_issue_reopens_a_closed_issue_and_never_duplicates() {
        let (state, dir, github, gh) = setup("manual-reopen").await;
        finding(&state, "v1", "CVE-2026-0001", "CRITICAL").await;
        let (_, Json(created)) = call(&state, "u1", "m1:CVE-2026-0001", &gh).await.unwrap();
        sqlx::query("UPDATE github_issues SET status = 'closed'")
            .execute(&state.pool)
            .await
            .unwrap();
        github.with(|s| s.issues[0].open = false);

        let (status, Json(reopened)) = call(&state, "u1", "m1:CVE-2026-0001", &gh).await.unwrap();

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(reopened.github_issue_number, created.github_issue_number);
        assert_eq!(github.creates().len(), 1, "no second issue");
        assert!(github.with(|s| s.issues[0].open));
        let stored: String = sqlx::query_scalar("SELECT status FROM github_issues")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(stored, "open");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn manual_issue_is_refused_with_409_while_the_cve_is_accepted() {
        let (state, dir, github, gh) = setup("manual-accepted").await;
        finding(&state, "v1", "CVE-2026-0001", "CRITICAL").await;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, mapping_id, cve_id, reason, created_by, created_by_username)
             VALUES ('a1', 'm1', 'CVE-2026-0001', 'accepted for the test', 'u1', 'u1')",
        )
        .execute(&state.pool)
        .await
        .unwrap();

        let refused = call(&state, "u1", "m1:CVE-2026-0001", &gh)
            .await
            .unwrap_err();

        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert_eq!(github.requests(), 0);

        // Once the acceptance is revoked, the same call works.
        sqlx::query("UPDATE cve_acceptances SET revoked_at = 5, revoked_by = 'u1'")
            .execute(&state.pool)
            .await
            .unwrap();
        let (status, _) = call(&state, "u1", "m1:CVE-2026-0001", &gh).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
