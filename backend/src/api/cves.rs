//! CVE routes (`specs/api.md`, CVEs): the read routes `GET /mappings/:id/cves`, `GET /cves`
//! and `GET /cves/:id`, the manual issue route, and the accept and un-accept routes.
//!
//! Every handler takes `AuthUser`, so a missing or invalid session is `401`. Tenancy is
//! enforced in the services: another tenant's mapping or CVE is `404`.

use axum::{
    Json,
    extract::{
        Path, Query, State,
        rejection::{PathRejection, QueryRejection},
    },
    http::StatusCode,
};
use serde::Serialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::acceptance::{self, AcceptInput, Acceptance, Caller};
use crate::services::cves::{self, CveDetail, CveSummary, ListParams, Reader};
use crate::services::issue_lifecycle::{self, IssueApi};
use crate::services::pagination::Page;
use crate::services::sessions::AuthUser;
use crate::worker::now_secs;

fn reader_of(user: &AuthUser) -> Reader<'_> {
    Reader {
        user_id: &user.id,
        is_admin: user.role == Role::Admin,
    }
}

/// The query string, or a fixed `400` for one that cannot be parsed. The service decides
/// when to return that error, after the mapping check.
fn params_of(query: Result<Query<ListParams>, QueryRejection>) -> Result<ListParams, AppError> {
    query
        .map(|Query(params)| params)
        .map_err(|_| AppError::InvalidRequest("The query string is not valid.".to_owned()))
}

/// A path id that cannot be decoded names no object, so it is `404` like an unknown one.
fn path_of(path: Result<Path<String>, PathRejection>) -> Result<String, AppError> {
    path.map(|Path(id)| id).map_err(|_| AppError::NotFound)
}

/// `GET /api/v1/mappings/:id/cves`. One `CveSummary` per CVE of the mapping. A user reads
/// only their own mapping (another tenant's is `404`); an admin reads any. Returns `200`;
/// `400` for a bad list parameter; `404` for an unknown or foreign mapping.
pub async fn list_for_mapping(
    State(state): State<AppState>,
    user: AuthUser,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<ListParams>, QueryRejection>,
) -> Result<Json<Page<CveSummary>>, AppError> {
    let mapping_id = path_of(path)?;
    let page = cves::list(
        &state.pool,
        &reader_of(&user),
        Some(&mapping_id),
        params_of(query),
        now_secs(),
    )
    .await?;
    Ok(Json(page))
}

/// `GET /api/v1/cves`. The caller's CVEs across their mappings, or one mapping with
/// `mapping_id`. Admins may add `scope=all` (`403` for anyone else). Returns `200`; `400` for
/// a bad list parameter; `404` for an unknown or foreign `mapping_id`.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    query: Result<Query<ListParams>, QueryRejection>,
) -> Result<Json<Page<CveSummary>>, AppError> {
    let page = cves::list(
        &state.pool,
        &reader_of(&user),
        None,
        params_of(query),
        now_secs(),
    )
    .await?;
    Ok(Json(page))
}

/// `GET /api/v1/cves/:id`. `:id` is `<mapping_id>:<cve_id>`. Returns `200` with the
/// `CveDetail`; `404` for a malformed id, an unknown or foreign mapping, or a CVE the mapping
/// has no row for.
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<CveDetail>, AppError> {
    let id = path_of(path)?;
    Ok(Json(
        cves::detail(&state.pool, &reader_of(&user), &id, now_secs()).await?,
    ))
}

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

/// The answer of `POST /api/v1/cves/:id/accept`.
#[derive(Debug, Serialize)]
pub struct Accepted {
    pub acceptance: Acceptance,
}

/// `POST /api/v1/cves/:id/accept`. `:id` is `<mapping_id>:<cve_id>`; the body is
/// `{"reason","expires_at"}`. The caller must own the mapping. Returns `201`; `400` for a body
/// that is not JSON; `404` for an unknown or foreign mapping or CVE; `409` when the CVE is
/// already accepted; `422` for an empty reason or a past expiry.
pub async fn accept(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Accepted>), AppError> {
    accept_with(&state, &user, &id, &body, state.issues_client.as_ref()).await
}

/// The route's work with the GitHub client passed in, so tests use a fake.
async fn accept_with<G: IssueApi>(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    body: &[u8],
    gh: &G,
) -> Result<(StatusCode, Json<Accepted>), AppError> {
    let input: AcceptInput = serde_json::from_slice(body)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))?;
    let acceptance = acceptance::accept(
        &state.pool,
        &state.credentials_key,
        gh,
        &Caller {
            id: &user.id,
            username: &user.username,
        },
        id,
        input,
        now_secs(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(Accepted { acceptance })))
}

/// `POST /api/v1/cves/:id/unaccept`. The caller must own the mapping. Returns `204`; `404`
/// for an unknown or foreign mapping or when no acceptance is active.
pub async fn unaccept(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    acceptance::unaccept(
        &state.pool,
        &Caller {
            id: &user.id,
            username: &user.username,
        },
        &id,
        now_secs(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
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
    async fn accept_call(
        state: &AppState,
        who: &str,
        id: &str,
        body: &str,
        gh: &FakeIssues,
    ) -> Result<(StatusCode, Json<Accepted>), AppError> {
        accept_with(state, &user(who), id, body.as_bytes(), gh).await
    }

    #[tokio::test]
    async fn another_tenant_cannot_accept() {
        let (state, dir, github, gh) = setup("accept-tenant").await;
        finding(&state, "v1", "CVE-2026-0001", "CRITICAL").await;
        let body = r#"{"reason":"not theirs to accept"}"#;

        // Another tenant gets 404 on accept and on unaccept, and nothing is written.
        let foreign = accept_call(&state, "u2", "m1:CVE-2026-0001", body, &gh)
            .await
            .unwrap_err();
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        let foreign_unaccept = acceptance::unaccept(
            &state.pool,
            &Caller {
                id: "u2",
                username: "u2",
            },
            "m1:CVE-2026-0001",
            now_secs(),
        )
        .await
        .unwrap_err();
        assert_eq!(foreign_unaccept.status(), StatusCode::NOT_FOUND);
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cve_acceptances")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        let audits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!((rows, audits), (0, 0));
        assert_eq!(github.requests(), 0);

        // The owner can: 201 with the acceptance, then the foreign user still cannot undo it.
        let (status, Json(accepted)) = accept_call(&state, "u1", "m1:CVE-2026-0001", body, &gh)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(accepted.acceptance.cve_id, "CVE-2026-0001");
        let still = acceptance::unaccept(
            &state.pool,
            &Caller {
                id: "u2",
                username: "u2",
            },
            "m1:CVE-2026-0001",
            now_secs(),
        )
        .await
        .unwrap_err();
        assert_eq!(still.status(), StatusCode::NOT_FOUND);
        let active: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM cve_acceptances WHERE revoked_at IS NULL")
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(active, 1);

        // A body that is not JSON is 400, for the owner.
        let bad = accept_call(&state, "u1", "m1:CVE-2026-0001", "not json", &gh)
            .await
            .unwrap_err();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Read routes (#32) ----

    const AT: i64 = 1_000_000_000;

    fn admin(id: &str) -> AuthUser {
        AuthUser {
            id: id.to_owned(),
            username: id.to_owned(),
            role: Role::Admin,
        }
    }

    /// Stores one tag row of a CVE, seen at `at`. The mapping's Harbor repository is the
    /// mapping id (see `seed_mapping`).
    async fn seen(state: &AppState, mapping: &str, tag: &str, cve: &str, severity: &str, at: i64) {
        store(
            state,
            &db::findings::Finding {
                id: &crate::services::ids::new_id(),
                mapping_id: mapping,
                harbor_repository: mapping,
                image_tag: tag,
                cve_id: cve,
                package: Some("openssl"),
                severity,
                fixed_in_version: None,
                description: None,
                now: at,
            },
        )
        .await;
    }

    async fn store(state: &AppState, finding: &db::findings::Finding<'_>) {
        let mut conn = state.pool.acquire().await.unwrap();
        db::findings::upsert(&mut conn, finding).await.unwrap();
    }

    /// Marks one tag row `fixed`.
    async fn fix(state: &AppState, mapping: &str, tag: &str, cve: &str) {
        let done = sqlx::query(
            "UPDATE cve_findings SET status = 'fixed'
             WHERE mapping_id = ? AND image_tag = ? AND cve_id = ?",
        )
        .bind(mapping)
        .bind(tag)
        .bind(cve)
        .execute(&state.pool)
        .await
        .unwrap();
        assert_eq!(done.rows_affected(), 1);
    }

    /// Stores a `sync_reports` row for a tag, which makes the tag tracked when `sarif_status`
    /// is `success`.
    async fn report(
        state: &AppState,
        mapping: &str,
        tag: &str,
        synced_at: i64,
        sarif_status: &str,
    ) {
        sqlx::query(
            "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
                                       vulnerability_summary, sarif_status, synced_at)
             VALUES (?, ?, ?, ?, 'sha256:00', '{}', ?, ?)",
        )
        .bind(crate::services::ids::new_id())
        .bind(mapping)
        .bind(mapping)
        .bind(tag)
        .bind(sarif_status)
        .bind(synced_at)
        .execute(&state.pool)
        .await
        .unwrap();
    }

    fn query(q: &str) -> Result<Query<ListParams>, QueryRejection> {
        let uri: axum::http::Uri = format!("/q?{q}").parse().unwrap();
        Query::try_from_uri(&uri)
    }

    /// `GET /api/v1/mappings/:mapping/cves?<q>` as `who`.
    async fn by_mapping(
        state: &AppState,
        who: &AuthUser,
        mapping: &str,
        q: &str,
    ) -> Result<Page<CveSummary>, AppError> {
        list_for_mapping(
            State(state.clone()),
            who.clone(),
            Ok(Path(mapping.to_owned())),
            query(q),
        )
        .await
        .map(|Json(page)| page)
    }

    /// `GET /api/v1/cves?<q>` as `who`.
    async fn all_cves(
        state: &AppState,
        who: &AuthUser,
        q: &str,
    ) -> Result<Page<CveSummary>, AppError> {
        list(State(state.clone()), who.clone(), query(q))
            .await
            .map(|Json(page)| page)
    }

    /// `GET /api/v1/cves/:id` as `who`.
    async fn one(state: &AppState, who: &AuthUser, id: &str) -> Result<CveDetail, AppError> {
        get(State(state.clone()), who.clone(), Ok(Path(id.to_owned())))
            .await
            .map(|Json(detail)| detail)
    }

    fn item<'a>(page: &'a Page<CveSummary>, cve: &str) -> &'a CveSummary {
        page.items
            .iter()
            .find(|item| item.cve_id == cve)
            .unwrap_or_else(|| panic!("{cve} is not in the page"))
    }

    #[tokio::test]
    async fn one_cve_on_three_tags_is_one_summary() {
        let (state, dir, _, _) = setup("read-three-tags").await;
        for (tag, severity, at) in [
            ("v1", "HIGH", 100),
            ("v2", "CRITICAL", 200),
            ("v3", "MEDIUM", 300),
        ] {
            report(&state, "m1", tag, at, "success").await;
            seen(&state, "m1", tag, "CVE-2026-0001", severity, at).await;
        }
        fix(&state, "m1", "v3", "CVE-2026-0001").await;
        seen(&state, "m1", "v1", "CVE-2026-0002", "LOW", 100).await;

        for page in [
            by_mapping(&state, &user("u1"), "m1", "").await.unwrap(),
            all_cves(&state, &user("u1"), "").await.unwrap(),
        ] {
            assert_eq!(page.total, 2, "one CVE on three tags counts once");
            assert_eq!(page.items.len(), 2);
            let cve = item(&page, "CVE-2026-0001");
            assert_eq!(cve.id, "m1:CVE-2026-0001");
            assert_eq!(cve.mapping_id, "m1");
            assert_eq!(cve.severity, "CRITICAL", "the highest severity across tags");
            assert_eq!(cve.status, "open", "open while any tag is open");
            assert_eq!(cve.first_seen_at.as_deref(), Some("1970-01-01T00:01:40Z"));
            assert_eq!(cve.last_seen_at.as_deref(), Some("1970-01-01T00:05:00Z"));
        }

        // Fixed on every tag: the summary is fixed.
        fix(&state, "m1", "v1", "CVE-2026-0001").await;
        fix(&state, "m1", "v2", "CVE-2026-0001").await;
        let page = by_mapping(&state, &user("u1"), "m1", "status=fixed")
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].cve_id, "CVE-2026-0001");
        assert_eq!(page.items[0].status, "fixed");
        let open = by_mapping(&state, &user("u1"), "m1", "status=open")
            .await
            .unwrap();
        assert_eq!(
            (open.total, open.items[0].cve_id.as_str()),
            (1, "CVE-2026-0002")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn page_size_201_is_400() {
        let (state, dir, _, _) = setup("read-page-size").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "HIGH", AT).await;

        for q in ["page_size=201", "page_size=0", "page_size=ten", "page=0"] {
            let mapped = by_mapping(&state, &user("u1"), "m1", q).await.unwrap_err();
            assert_eq!(mapped.status(), StatusCode::BAD_REQUEST, "{q}");
            let listed = all_cves(&state, &user("u1"), q).await.unwrap_err();
            assert_eq!(listed.status(), StatusCode::BAD_REQUEST, "{q}");
        }
        let max = by_mapping(&state, &user("u1"), "m1", "page_size=200")
            .await
            .unwrap();
        assert_eq!((max.page_size, max.total), (200, 1));
        let default = all_cves(&state, &user("u1"), "").await.unwrap();
        assert_eq!((default.page, default.page_size), (1, 50));
        let beyond = all_cves(&state, &user("u1"), "page=2&page_size=1")
            .await
            .unwrap();
        assert!(beyond.items.is_empty());
        assert_eq!(beyond.total, 1, "total counts every page");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_sort_is_400() {
        let (state, dir, _, _) = setup("read-sort").await;
        seen(&state, "m1", "v1", "CVE-2026-0002", "CRITICAL", 300).await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "LOW", 200).await;
        seen(&state, "m1", "v1", "CVE-2026-0003", "HIGH", 100).await;

        for q in ["sort=package", "sort=id", "sort=severity;DROP", "order=up"] {
            let error = by_mapping(&state, &user("u1"), "m1", q).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{q}");
            let error = all_cves(&state, &user("u1"), q).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{q}");
        }

        let ids = |page: Page<CveSummary>| -> Vec<String> {
            page.items.into_iter().map(|item| item.cve_id).collect()
        };
        for (q, expected) in [
            ("", ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"]),
            (
                "sort=severity&order=asc",
                ["CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0002"],
            ),
            (
                "sort=cve_id&order=asc",
                ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
            ),
            (
                "sort=cve_id",
                ["CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001"],
            ),
            (
                "sort=first_seen_at&order=asc",
                ["CVE-2026-0003", "CVE-2026-0001", "CVE-2026-0002"],
            ),
            (
                "sort=last_seen_at",
                ["CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0003"],
            ),
        ] {
            let page = by_mapping(&state, &user("u1"), "m1", q).await.unwrap();
            assert_eq!(ids(page), expected, "{q}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn detail_lists_tags_and_acceptance() {
        let (state, dir, _, _) = setup("read-detail").await;
        for (tag, at, fixed_in) in [
            ("v1", AT, Some("3.0.1")),
            ("v2", AT + 60, None),
            ("v3", AT + 120, Some("3.0.2")),
        ] {
            report(&state, "m1", tag, at, "success").await;
            store(
                &state,
                &db::findings::Finding {
                    id: &crate::services::ids::new_id(),
                    mapping_id: "m1",
                    harbor_repository: "m1",
                    image_tag: tag,
                    cve_id: "CVE-2026-0001",
                    package: Some("openssl"),
                    severity: "HIGH",
                    fixed_in_version: fixed_in,
                    description: None,
                    now: at,
                },
            )
            .await;
        }
        fix(&state, "m1", "v2", "CVE-2026-0001").await;

        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        let tags: Vec<(&str, &str, Option<&str>, Option<&str>)> = detail
            .tags
            .iter()
            .map(|tag| {
                (
                    tag.image_tag.as_str(),
                    tag.status.as_str(),
                    tag.last_scan_at.as_deref(),
                    tag.fixed_in_version.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            tags,
            [
                ("v3", "open", Some("2001-09-09T01:48:40Z"), Some("3.0.2")),
                ("v2", "fixed", Some("2001-09-09T01:47:40Z"), None),
                ("v1", "open", Some("2001-09-09T01:46:40Z"), Some("3.0.1")),
            ],
            "the tags that report the CVE, most recently scanned first"
        );
        assert!(detail.acceptance.is_none());
        assert!(!detail.summary.accepted);
        assert_eq!(detail.summary.fixed_in_version.as_deref(), Some("3.0.2"));

        // An active acceptance shows on the detail and in the list filters.
        sqlx::query(
            "INSERT INTO cve_acceptances (id, mapping_id, cve_id, reason, created_by, created_by_username, created_at)
             VALUES ('a1', 'm1', 'CVE-2026-0001', 'vendor fix scheduled', 'u1', 'u1', ?)",
        )
        .bind(AT)
        .execute(&state.pool)
        .await
        .unwrap();
        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        let acceptance = detail.acceptance.as_ref().expect("the active acceptance");
        assert_eq!(acceptance.reason, "vendor fix scheduled");
        assert_eq!(acceptance.created_by, "u1");
        assert_eq!(acceptance.expires_at, None);
        assert!(detail.summary.accepted);
        let accepted = by_mapping(&state, &user("u1"), "m1", "accepted=true")
            .await
            .unwrap();
        assert_eq!(accepted.total, 1);
        let others = by_mapping(&state, &user("u1"), "m1", "accepted=false")
            .await
            .unwrap();
        assert_eq!(others.total, 0);

        // A revoked or an expired acceptance is not active.
        sqlx::query("UPDATE cve_acceptances SET revoked_at = 5, revoked_by = 'u1'")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO cve_acceptances (id, mapping_id, cve_id, reason, created_by, created_by_username, expires_at)
             VALUES ('a2', 'm1', 'CVE-2026-0001', 'expired', 'u1', 'u1', 10)",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        assert!(detail.acceptance.is_none());
        assert!(!detail.summary.accepted);

        // At most 10 tags.
        for n in 4..=12 {
            seen(
                &state,
                "m1",
                &format!("v{n}"),
                "CVE-2026-0001",
                "HIGH",
                AT + n,
            )
            .await;
        }
        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        assert_eq!(detail.tags.len(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn other_tenant_is_404() {
        let (state, dir, _, _) = setup("read-tenant").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", AT).await;
        let other = user("u2");

        // Another tenant's mapping is 404 on every read route, even with a bad parameter:
        // the owner check comes first.
        for q in ["", "page_size=201", "sort=bogus", "severity=nope", "page=x"] {
            let error = by_mapping(&state, &other, "m1", q).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::NOT_FOUND, "{q}");
            let error = all_cves(&state, &other, &format!("mapping_id=m1&{q}"))
                .await
                .unwrap_err();
            assert_eq!(error.status(), StatusCode::NOT_FOUND, "{q}");
        }
        let broken = list_for_mapping(
            State(state.clone()),
            other.clone(),
            Ok(Path("m1".to_owned())),
            query("page=1&page=2"),
        )
        .await
        .unwrap_err();
        assert_eq!(broken.status(), StatusCode::NOT_FOUND);
        // The query string really is unparsable (a repeated key), and the same request from the
        // owner is 400. On `GET /cves` the `mapping_id` is inside that query string, so the
        // ownership check cannot run and the answer is 400 for any mapping, existing or not.
        assert!(query("page=1&page=2").is_err());
        let owner_broken = list_for_mapping(
            State(state.clone()),
            user("u1"),
            Ok(Path("m1".to_owned())),
            query("page=1&page=2"),
        )
        .await
        .unwrap_err();
        assert_eq!(owner_broken.status(), StatusCode::BAD_REQUEST);
        for mapping in ["m1", "m9"] {
            let error = list(
                State(state.clone()),
                other.clone(),
                query(&format!("mapping_id={mapping}&page=1&page=2")),
            )
            .await
            .unwrap_err();
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{mapping}");
        }
        let error = one(&state, &other, "m1:CVE-2026-0001").await.unwrap_err();
        assert_eq!(error.status(), StatusCode::NOT_FOUND);
        assert_eq!(error.message(), AppError::NotFound.message());

        // The answer is the same as for a mapping or CVE that does not exist.
        for id in [
            "m9:CVE-2026-0001",
            "m1:CVE-2026-9999",
            "no-colon",
            "m1:CVE-1\n-->",
        ] {
            let error = one(&state, &user("u1"), id).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::NOT_FOUND, "{id:?}");
        }
        let error = by_mapping(&state, &user("u1"), "m9", "").await.unwrap_err();
        assert_eq!(error.status(), StatusCode::NOT_FOUND);

        // Their own list holds none of it.
        let own = all_cves(&state, &other, "").await.unwrap();
        assert_eq!((own.total, own.items.len()), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scope_all_is_admin_only() {
        let (state, dir, _, _) = setup("read-scope").await;
        seed_user(&state.pool, "a1", "admin").await;
        seed_harbor(&state.pool, "u2", "ch2", "harbor", None).await;
        seed_github(&state.pool, "u2", "cg2", "github").await;
        seed_mapping(&state.pool, "u2", "m2", "ch2", "cg2", "octo", "other").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", AT).await;
        seen(&state, "m2", "v1", "CVE-2026-0001", "HIGH", AT).await;

        let refused = all_cves(&state, &user("u1"), "scope=all")
            .await
            .unwrap_err();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let unknown = all_cves(&state, &admin("a1"), "scope=mine")
            .await
            .unwrap_err();
        assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

        // One CVE in two mappings is two summaries.
        let everything = all_cves(&state, &admin("a1"), "scope=all").await.unwrap();
        let mut ids: Vec<&str> = everything
            .items
            .iter()
            .map(|item| item.id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, ["m1:CVE-2026-0001", "m2:CVE-2026-0001"]);
        assert_eq!(everything.total, 2);

        // Without the scope an admin sees their own mappings (none here), and a user sees only
        // theirs.
        assert_eq!(all_cves(&state, &admin("a1"), "").await.unwrap().total, 0);
        let mine = all_cves(&state, &user("u2"), "").await.unwrap();
        assert_eq!(
            (mine.total, mine.items[0].id.as_str()),
            (1, "m2:CVE-2026-0001")
        );

        // An admin may read any tenant's mapping and CVE (`specs/api.md`, Verification).
        let page = by_mapping(&state, &admin("a1"), "m1", "").await.unwrap();
        assert_eq!(page.total, 1);
        let page = all_cves(&state, &admin("a1"), "mapping_id=m2")
            .await
            .unwrap();
        assert_eq!((page.total, page.items[0].severity.as_str()), (1, "HIGH"));
        let detail = one(&state, &admin("a1"), "m2:CVE-2026-0001").await.unwrap();
        assert_eq!(detail.summary.mapping_id, "m2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn timestamps_are_rfc3339_utc() {
        let (state, dir, _, _) = setup("read-time").await;
        report(&state, "m1", "v1", AT + 60, "success").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", AT).await;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, mapping_id, cve_id, reason, created_by, created_by_username, created_at, expires_at)
             VALUES ('a1', 'm1', 'CVE-2026-0001', 'until the fix', 'u1', 'u1', ?, 4102444800)",
        )
        .bind(AT)
        .execute(&state.pool)
        .await
        .unwrap();

        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        let listed = serde_json::to_value(&page).unwrap();
        assert_eq!(listed["items"][0]["first_seen_at"], "2001-09-09T01:46:40Z");
        assert_eq!(listed["items"][0]["last_seen_at"], "2001-09-09T01:46:40Z");

        let detail =
            serde_json::to_value(one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap())
                .unwrap();
        assert_eq!(detail["first_seen_at"], "2001-09-09T01:46:40Z");
        assert_eq!(detail["tags"][0]["last_scan_at"], "2001-09-09T01:47:40Z");
        assert_eq!(detail["acceptance"]["created_at"], "2001-09-09T01:46:40Z");
        assert_eq!(detail["acceptance"]["expires_at"], "2100-01-01T00:00:00Z");

        // A tag with no successful sync has no last scan date.
        seen(&state, "m1", "v2", "CVE-2026-0001", "CRITICAL", AT + 5).await;
        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        let unscanned = detail
            .tags
            .iter()
            .find(|tag| tag.image_tag == "v2")
            .unwrap();
        assert_eq!(unscanned.last_scan_at, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn summary_counts_open_and_tracked_tags() {
        let (state, dir, _, _) = setup("read-tag-counts").await;
        for (n, tag) in ["v1", "v2", "v3", "v4"].into_iter().enumerate() {
            report(&state, "m1", tag, AT + n as i64, "success").await;
        }
        // A failed upload does not track a tag.
        report(&state, "m1", "v9", AT + 9, "failed").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "HIGH", AT).await;
        seen(&state, "m1", "v2", "CVE-2026-0001", "HIGH", AT).await;
        seen(&state, "m1", "v3", "CVE-2026-0001", "HIGH", AT).await;
        fix(&state, "m1", "v3", "CVE-2026-0001").await;

        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        let cve = item(&page, "CVE-2026-0001");
        assert_eq!(
            (cve.open_tags, cve.tracked_tags),
            (2, 4),
            "v4 has no CVEs and is tracked"
        );

        // Tracked tags are at most 10.
        for n in 10..20 {
            report(&state, "m1", &format!("v{n}"), AT + n, "success").await;
        }
        let page = all_cves(&state, &user("u1"), "").await.unwrap();
        let cve = item(&page, "CVE-2026-0001");
        assert_eq!((cve.open_tags, cve.tracked_tags), (2, 10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn summary_carries_issue_number_and_status() {
        let (state, dir, _, _) = setup("read-issues").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", AT).await;
        seen(&state, "m1", "v1", "CVE-2026-0002", "HIGH", AT).await;
        seen(&state, "m1", "v1", "CVE-2026-0003", "MEDIUM", AT).await;
        sqlx::query(
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url, status)
             VALUES ('g1', 'octo', 'app', 'CVE-2026-0001', 7, 'https://github.com/octo/app/issues/7', 'open'),
                    ('g2', 'octo', 'app', 'CVE-2026-0002', 8, 'https://github.com/octo/app/issues/8', 'closed'),
                    ('g3', 'octo', 'elsewhere', 'CVE-2026-0003', 9, 'https://github.com/octo/elsewhere/issues/9', 'open')",
        )
        .execute(&state.pool)
        .await
        .unwrap();

        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        let issue = |cve: &str| {
            let item = item(&page, cve);
            (
                item.github_issue_url.clone(),
                item.github_issue_number,
                item.github_issue_status.clone(),
            )
        };
        assert_eq!(
            issue("CVE-2026-0001"),
            (
                Some("https://github.com/octo/app/issues/7".to_owned()),
                Some(7),
                Some("open".to_owned())
            )
        );
        assert_eq!(
            issue("CVE-2026-0002"),
            (
                Some("https://github.com/octo/app/issues/8".to_owned()),
                Some(8),
                Some("closed".to_owned())
            )
        );
        // Another repository's issue for the same CVE is not this mapping's.
        assert_eq!(issue("CVE-2026-0003"), (None, None, None));
        let json = serde_json::to_value(item(&page, "CVE-2026-0003")).unwrap();
        assert!(json["github_issue_status"].is_null());
        assert!(json["github_issue_number"].is_null());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn detail_includes_description() {
        let (state, dir, _, _) = setup("read-description").await;
        report(&state, "m1", "v1", AT, "success").await;
        report(&state, "m1", "v2", AT + 60, "success").await;
        // Harbor-supplied text is untrusted: it is returned as JSON data, unchanged.
        let newest = "Newer text <b>bold</b> --> \u{7}";
        for (tag, description, fixed_in) in [("v2", newest, "3.0.2"), ("v1", "Older text", "3.0.1")]
        {
            store(
                &state,
                &db::findings::Finding {
                    id: &crate::services::ids::new_id(),
                    mapping_id: "m1",
                    harbor_repository: "m1",
                    image_tag: tag,
                    cve_id: "CVE-2026-0001",
                    package: Some("openssl"),
                    severity: "HIGH",
                    fixed_in_version: Some(fixed_in),
                    description: Some(description),
                    now: AT + 120,
                },
            )
            .await;
        }
        seen(&state, "m1", "v1", "CVE-2026-0002", "LOW", AT).await;

        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        assert_eq!(
            detail.description.as_deref(),
            Some(newest),
            "from the most recently scanned tag"
        );
        assert_eq!(detail.summary.fixed_in_version.as_deref(), Some("3.0.2"));
        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains(r#""description":"Newer text <b>bold</b> --> \u0007""#));
        assert!(
            !json.bytes().any(|b| b.is_ascii_control()),
            "control characters are escaped"
        );

        let none = one(&state, &user("u1"), "m1:CVE-2026-0002").await.unwrap();
        assert_eq!(none.description, None);
        assert!(serde_json::to_value(&none).unwrap()["description"].is_null());

        // The list carries no description.
        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        assert!(
            serde_json::to_value(&page).unwrap()["items"][0]
                .get("description")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_filters_by_severity_and_q() {
        let (state, dir, _, _) = setup("read-filters").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", AT).await;
        seen(&state, "m1", "v1", "GHSA-abcd-0002", "HIGH", AT).await;
        seen(&state, "m1", "v2", "CVE-2026-0003", "LOW", AT).await;
        seen(&state, "m1", "v3", "CVE-2026-0003", "HIGH", AT).await;
        // An id the `<mapping_id>:<cve_id>` route cannot carry is not listed.
        seen(&state, "m1", "v1", "CVE-1 -->", "CRITICAL", AT).await;
        // SQLite's GLOB stops at a NUL byte, so an id with NUL, a line break and `-->` must be
        // left out by a separate check. Harbor JSON can carry \u0000.
        seen(&state, "m1", "v1", "CVE-1\u{0}\n-->", "CRITICAL", AT).await;
        seen(&state, "m1", "v1", "RHSA-2023:1234", "MEDIUM", AT).await;

        let ids = |page: &Page<CveSummary>| -> Vec<String> {
            let mut ids: Vec<String> = page.items.iter().map(|item| item.cve_id.clone()).collect();
            ids.sort_unstable();
            ids
        };
        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        assert_eq!(
            ids(&page),
            [
                "CVE-2026-0001",
                "CVE-2026-0003",
                "GHSA-abcd-0002",
                "RHSA-2023:1234"
            ]
        );
        assert_eq!(page.total, 4);
        let stored: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM cve_findings WHERE cve_id LIKE 'CVE-1%'")
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(
            stored, 2,
            "both unsafe ids are stored, so the list must hide them"
        );
        let everywhere = all_cves(&state, &user("u1"), "").await.unwrap();
        assert_eq!(everywhere.total, 4);
        assert!(
            everywhere
                .items
                .iter()
                .all(|item| !item.cve_id.starts_with("CVE-1"))
        );
        // The severity filter matches the highest severity across tags.
        let high = by_mapping(&state, &user("u1"), "m1", "severity=HIGH")
            .await
            .unwrap();
        assert_eq!(ids(&high), ["CVE-2026-0003", "GHSA-abcd-0002"]);
        assert_eq!(high.total, 2);
        let low = by_mapping(&state, &user("u1"), "m1", "severity=LOW")
            .await
            .unwrap();
        assert_eq!(low.total, 0);
        // `q` matches the CVE id or the package, ignoring ASCII case.
        let ghsa = all_cves(&state, &user("u1"), "q=ghsa").await.unwrap();
        assert_eq!(
            (ids(&ghsa), ghsa.total),
            (vec!["GHSA-abcd-0002".to_owned()], 1)
        );
        let package = all_cves(&state, &user("u1"), "q=OpenSSL").await.unwrap();
        assert_eq!(package.total, 4);
        let none = all_cves(&state, &user("u1"), "q=%25").await.unwrap();
        assert_eq!(none.total, 0, "% is plain text, not a wildcard");
        for q in [
            "severity=high",
            "status=accepted",
            "accepted=yes",
            &format!("q={}", "a".repeat(101)),
        ] {
            let error = all_cves(&state, &user("u1"), q).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{q}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
