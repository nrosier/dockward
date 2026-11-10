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
pub async fn list_for_source(
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

/// `GET /api/v1/mappings/:id/tags`. The CVE view's tag set of the mapping as
/// `{"items": [{"image_tag","last_scan_at","open_cves"}]}`, most recently scanned first, at
/// most 10. Same access as the CVE list: the owner or any admin; another tenant's or an
/// unknown mapping is `404`. Returns `200`.
pub async fn tags_for_source(
    State(state): State<AppState>,
    user: AuthUser,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mapping_id = path_of(path)?;
    let items = cves::source_tags(&state.pool, &reader_of(&user), &mapping_id).await?;
    Ok(Json(serde_json::json!({ "items": items })))
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
/// mapping. Any open severity may get an issue (#129). Returns `201`; `404` for an unknown or
/// foreign mapping or CVE; `409` when an open issue exists (the body names its URL) or the
/// CVE has an active acceptance; `422` when no tracked tag reports the CVE as open; `502` when
/// GitHub fails.
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
    use crate::api::admin::test_support::{seed_github, seed_source, seed_user, test_state};
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
                id: &crate::services::ids::new_id().unwrap_or_default(),
                source_id: "m1",
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
        seed_github(&state.pool, "u1", "cg", "github").await;
        seed_source(&state.pool, "u1", "m1", "cg", "octo", "app").await;
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
    async fn manual_issue_any_severity_and_409_when_open() {
        let (state, dir, github, gh) = setup("manual").await;
        finding(&state, "v1", "CVE-2026-0001", "CRITICAL").await;
        finding(&state, "v1", "CVE-2026-0002", "MEDIUM").await;
        finding(&state, "v1", "CVE-2026-0003", "HIGH").await;

        // 201: MEDIUM may get an issue by hand since #129, although it never does automatically.
        let (status, Json(medium)) = call(&state, "u1", "m1:CVE-2026-0002", &gh).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(medium.github_issue_number, 1);

        // 201: a HIGH CVE gets an issue although the mapping's minimum is CRITICAL.
        let (status, Json(high)) = call(&state, "u1", "m1:CVE-2026-0003", &gh).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(high.github_issue_number, 2);

        // 201, then 409 with the URL of the open issue, and no second create.
        let (_, Json(first)) = call(&state, "u1", "m1:CVE-2026-0001", &gh).await.unwrap();
        assert_eq!(
            first.github_issue_url,
            "https://github.com/octo/app/issues/3"
        );
        let again = call(&state, "u1", "m1:CVE-2026-0001", &gh)
            .await
            .unwrap_err();
        assert_eq!(again.status(), StatusCode::CONFLICT);
        assert!(again.message().contains(&first.github_issue_url));
        assert_eq!(github.creates().len(), 3);

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

    /// #129: LOW and UNKNOWN get an issue by hand. The title carries the highest open
    /// severity over all five, and the issue has the same marker and label as any other.
    #[tokio::test]
    async fn manual_issue_is_allowed_for_low_and_unknown() {
        let (state, dir, github, gh) = setup("manual-low").await;
        finding(&state, "v1", "CVE-2026-0010", "LOW").await;
        finding(&state, "v1", "CVE-2026-0011", "UNKNOWN").await;
        // UNKNOWN on v1 and LOW on v2: the highest open severity is LOW.
        finding(&state, "v1", "CVE-2026-0012", "UNKNOWN").await;
        finding(&state, "v2", "CVE-2026-0012", "LOW").await;

        for id in ["m1:CVE-2026-0010", "m1:CVE-2026-0011", "m1:CVE-2026-0012"] {
            let (status, _) = call(&state, "u1", id, &gh).await.unwrap();
            assert_eq!(status, StatusCode::CREATED, "{id}");
        }
        let creates = github.creates();
        let titles: Vec<&str> = creates
            .iter()
            .map(|body| body["title"].as_str().unwrap())
            .collect();
        assert_eq!(
            titles,
            [
                "CVE-2026-0010 openssl",
                "CVE-2026-0011 openssl",
                "CVE-2026-0012 openssl",
            ]
        );
        let expected = [
            serde_json::json!(["harborgate", "areai:security", "low"]),
            serde_json::json!(["harborgate", "areai:security"]),
            serde_json::json!(["harborgate", "areai:security", "low"]),
        ];
        for (body, labels) in creates.iter().zip(expected) {
            assert_eq!(body["labels"], labels);
            assert!(
                body["body"]
                    .as_str()
                    .unwrap()
                    .starts_with("<!-- harborgate:CVE-2026-00")
            );
        }
        // The second click is 409 with the URL, never a second issue.
        let again = call(&state, "u1", "m1:CVE-2026-0010", &gh)
            .await
            .unwrap_err();
        assert_eq!(again.status(), StatusCode::CONFLICT);
        assert!(
            again
                .message()
                .contains("https://github.com/octo/app/issues/1")
        );
        assert_eq!(github.creates().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A CVE that no tracked tag reports as open is `422`, at any severity, with no GitHub
    /// call.
    #[tokio::test]
    async fn manual_issue_is_refused_for_a_cve_fixed_on_every_tag() {
        let (state, dir, github, gh) = setup("manual-fixed").await;
        finding(&state, "v1", "CVE-2026-0001", "CRITICAL").await;
        finding(&state, "v2", "CVE-2026-0001", "LOW").await;
        sqlx::query("UPDATE cve_findings SET status = 'fixed'")
            .execute(&state.pool)
            .await
            .unwrap();

        let refused = call(&state, "u1", "m1:CVE-2026-0001", &gh)
            .await
            .unwrap_err();

        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            refused.message(),
            "Only a CVE that is open on a tracked tag can get an issue."
        );
        assert_eq!(github.requests(), 0);
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
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username)
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
                id: &crate::services::ids::new_id().unwrap_or_default(),
                source_id: mapping,
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
        drop(conn);
        // A tag with no observation yet is observed on the shared scanned image, so it is a
        // newest-image tag (#196). A test that wants another image observes the tag first.
        observe(
            state,
            finding.source_id,
            finding.image_tag,
            "sha256:00",
            finding.now,
            finding.now,
            "done",
        )
        .await;
    }

    /// Observes `tag` of `source` on the image `digest`, once per (source, tag), and gives the
    /// image a scan run in `status` finished at `finished`. `seen` is the observation's
    /// `first_seen_at`. The newest image of a source is the one with the latest observation
    /// among its scanned images (decision 49).
    async fn observe(
        state: &AppState,
        source: &str,
        tag: &str,
        digest: &str,
        seen: i64,
        finished: i64,
        status: &str,
    ) {
        let image = format!("img-{source}-{digest}");
        let platform = format!("plat-{image}");
        sqlx::query(
            "INSERT OR IGNORE INTO images (id, hub_id, repository, digest, is_index)
             VALUES (?, 'hub-default-ghcr', ?, ?, 0)",
        )
        .bind(&image)
        .bind(source)
        .bind(digest)
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO image_platforms (id, image_id, platform, platform_digest, state)
             VALUES (?, ?, 'linux/amd64', ?, 'stored')",
        )
        .bind(&platform)
        .bind(&image)
        .bind(digest)
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES (?, ?, 'grype', 'first_pull', ?, ?)",
        )
        .bind(format!("run-{image}-{tag}"))
        .bind(&platform)
        .bind(status)
        .bind(finished)
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
             SELECT ?1, ?2, ?3, ?4, ?4
             WHERE NOT EXISTS (SELECT 1 FROM tag_observations WHERE source_id = ?1 AND tag = ?2)",
        )
        .bind(source)
        .bind(tag)
        .bind(&image)
        .bind(seen)
        .execute(&state.pool)
        .await
        .unwrap();
    }

    /// Marks one tag row `fixed`.
    async fn fix(state: &AppState, mapping: &str, tag: &str, cve: &str) {
        let done = sqlx::query(
            "UPDATE cve_findings SET status = 'fixed'
             WHERE source_id = ? AND image_tag = ? AND cve_id = ?",
        )
        .bind(mapping)
        .bind(tag)
        .bind(cve)
        .execute(&state.pool)
        .await
        .unwrap();
        assert_eq!(done.rows_affected(), 1);
    }

    /// Scans a tag: a `success` observes it on the shared scanned image (it is tracked, with
    /// a scan finished at `synced_at`); any other status is a failed scan on its own image,
    /// which does not track the tag.
    async fn report(
        state: &AppState,
        mapping: &str,
        tag: &str,
        synced_at: i64,
        sarif_status: &str,
    ) {
        if sarif_status == "success" {
            observe(
                state,
                mapping,
                tag,
                "sha256:00",
                synced_at,
                synced_at,
                "done",
            )
            .await;
        } else {
            let digest = format!("sha256:failed-{tag}");
            observe(state, mapping, tag, &digest, synced_at, synced_at, "failed").await;
        }
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
        list_for_source(
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
            assert_eq!(cve.source_id, "m1");
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
                    id: &crate::services::ids::new_id().unwrap_or_default(),
                    source_id: "m1",
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
                ("v2", "fixed", Some("2001-09-09T01:48:40Z"), None),
                ("v1", "open", Some("2001-09-09T01:48:40Z"), Some("3.0.1")),
            ],
            "the tags that report the CVE, most recently scanned first; tags on one image share its scan time, and the tag seen last comes first"
        );
        assert!(detail.acceptance.is_none());
        assert!(!detail.summary.accepted);
        assert_eq!(detail.summary.fixed_in_version.as_deref(), Some("3.0.2"));

        // An active acceptance shows on the detail and in the list filters.
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username, created_at)
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
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username, expires_at)
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
            let error = all_cves(&state, &other, &format!("source_id=m1&{q}"))
                .await
                .unwrap_err();
            assert_eq!(error.status(), StatusCode::NOT_FOUND, "{q}");
        }
        let broken = list_for_source(
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
        let owner_broken = list_for_source(
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
                query(&format!("source_id={mapping}&page=1&page=2")),
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
        seed_github(&state.pool, "u2", "cg2", "github").await;
        seed_source(&state.pool, "u2", "m2", "cg2", "octo", "other").await;
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
        let page = all_cves(&state, &admin("a1"), "source_id=m2")
            .await
            .unwrap();
        assert_eq!((page.total, page.items[0].severity.as_str()), (1, "HIGH"));
        let detail = one(&state, &admin("a1"), "m2:CVE-2026-0001").await.unwrap();
        assert_eq!(detail.summary.source_id, "m2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Scans a tag on a digest first seen at `pushed`, before its findings are stored.
    async fn report_on(state: &AppState, mapping: &str, tag: &str, digest: &str, pushed: i64) {
        observe(state, mapping, tag, digest, pushed, pushed, "done").await;
    }

    /// The walley case (#196): `latest` is the newest digest and clean, `0.4` is older and
    /// still open. The list and its total skip the CVE, the tag filter on the older tag matches
    /// nothing, and the detail route still shows the older tag, marked older.
    #[tokio::test]
    async fn a_cve_open_only_on_an_older_tag_is_not_listed_but_stays_in_the_tag_table() {
        let (state, dir, _, _) = setup("older-only").await;
        report_on(&state, "m1", "0.4", "sha256:old", 1000).await;
        report_on(&state, "m1", "latest", "sha256:new", 2000).await;
        seen(&state, "m1", "0.4", "CVE-2026-0001", "CRITICAL", 100).await;

        for page in [
            by_mapping(&state, &user("u1"), "m1", "").await.unwrap(),
            all_cves(&state, &user("u1"), "").await.unwrap(),
            by_mapping(&state, &user("u1"), "m1", "tag=0.4")
                .await
                .unwrap(),
        ] {
            assert_eq!(page.total, 0);
            assert!(page.items.is_empty());
        }

        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        assert_eq!(detail.summary.status, "fixed");
        assert_eq!(detail.summary.open_tags, 0);
        assert_eq!(detail.summary.tracked_tags, 1);
        assert!(detail.older_tags_only);
        assert_eq!(detail.tags.len(), 1);
        assert_eq!(detail.tags[0].image_tag, "0.4");
        assert_eq!(detail.tags[0].status, "open");
        assert!(!detail.tags[0].newest_digest);

        // The newest digest reports it: listed, open, and no older-only notice.
        seen(&state, "m1", "latest", "CVE-2026-0001", "HIGH", 200).await;
        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(item(&page, "CVE-2026-0001").status, "open");
        assert_eq!(item(&page, "CVE-2026-0001").severity, "HIGH");
        let detail = one(&state, &user("u1"), "m1:CVE-2026-0001").await.unwrap();
        assert!(!detail.older_tags_only);
        assert_eq!(detail.tags.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn timestamps_are_rfc3339_utc() {
        let (state, dir, _, _) = setup("read-time").await;
        report(&state, "m1", "v1", AT + 60, "success").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", AT).await;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username, created_at, expires_at)
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
        sqlx::query("DELETE FROM tag_observations WHERE source_id = 'm1' AND tag = 'v2'")
            .execute(&state.pool)
            .await
            .unwrap();
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

    /// `GET /api/v1/mappings/:mapping/tags` as `who`, as the JSON body.
    async fn tag_list(
        state: &AppState,
        who: &AuthUser,
        mapping: &str,
    ) -> Result<serde_json::Value, AppError> {
        tags_for_source(
            State(state.clone()),
            who.clone(),
            Ok(Path(mapping.to_owned())),
        )
        .await
        .map(|Json(body)| body)
    }

    #[tokio::test]
    async fn mapping_tags_are_the_cve_view_tag_set() {
        let (state, dir, _, _) = setup("tag-list").await;
        for (n, tag) in ["v1", "v2", "v3"].into_iter().enumerate() {
            report(&state, "m1", tag, AT + n as i64, "success").await;
        }
        // A failed report does not track a tag.
        report(&state, "m1", "bad", AT + 50, "failed").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "HIGH", AT).await;
        seen(&state, "m1", "v1", "CVE-2026-0002", "LOW", AT).await;
        seen(&state, "m1", "v3", "CVE-2026-0001", "HIGH", AT).await;
        fix(&state, "m1", "v1", "CVE-2026-0002").await;

        let body = tag_list(&state, &user("u1"), "m1").await.unwrap();
        let items = body["items"].as_array().unwrap();
        let shown: Vec<(&str, i64)> = items
            .iter()
            .map(|i| {
                (
                    i["image_tag"].as_str().unwrap(),
                    i["open_cves"].as_i64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [("v3", 1), ("v2", 0), ("v1", 1)],
            "newest scan first"
        );
        assert_eq!(items[0]["last_scan_at"], "2001-09-09T01:46:42Z");
        assert_eq!(
            items[0].as_object().unwrap().len(),
            3,
            "names and counts only"
        );

        // The CVE list counts the same tags.
        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        assert_eq!(
            item(&page, "CVE-2026-0001").tracked_tags,
            items.len() as i64
        );

        // More than 10 tags: both views stop at 10 and agree on which.
        for n in 0..12 {
            report(&state, "m1", &format!("w{n}"), AT + 100 + n, "success").await;
        }
        let body = tag_list(&state, &user("u1"), "m1").await.unwrap();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 10);
        assert_eq!(items[0]["image_tag"], "w11");
        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        assert_eq!(item(&page, "CVE-2026-0001").tracked_tags, 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mapping_tags_follow_the_mapping_access_check() {
        let (state, dir, _, _) = setup("tag-list-access").await;
        report(&state, "m1", "v1", AT, "success").await;

        // Another tenant gets the same answer as for an unknown mapping, and the CVE list.
        let foreign = tag_list(&state, &user("u2"), "m1").await.unwrap_err();
        let unknown = tag_list(&state, &user("u2"), "nope").await.unwrap_err();
        let cves = by_mapping(&state, &user("u2"), "m1", "").await.unwrap_err();
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        assert_eq!(unknown.status(), foreign.status());
        assert_eq!(cves.status(), foreign.status());
        assert_eq!(format!("{foreign:?}"), format!("{unknown:?}"));

        // The owner and an admin read it; a tagless mapping gives an empty list.
        assert_eq!(
            tag_list(&state, &user("u1"), "m1").await.unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            tag_list(&state, &admin("a1"), "m1").await.unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
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
                    id: &crate::services::ids::new_id().unwrap_or_default(),
                    source_id: "m1",
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
            "status=closed",
            "accepted=yes",
            &format!("q={}", "a".repeat(101)),
        ] {
            let error = all_cves(&state, &user("u1"), q).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{q}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- All severities and filters (#129) ----

    /// Stores one tag row with its own package.
    async fn seen_pkg(
        state: &AppState,
        mapping: &str,
        tag: &str,
        cve: &str,
        severity: &str,
        package: &str,
    ) {
        store(
            state,
            &db::findings::Finding {
                id: &crate::services::ids::new_id().unwrap_or_default(),
                source_id: mapping,
                image_tag: tag,
                cve_id: cve,
                package: Some(package),
                severity,
                fixed_in_version: None,
                description: None,
                now: AT,
            },
        )
        .await;
    }

    /// The sorted CVE ids of every page of `GET /cves?<q>`, read one item per page, and the
    /// `total` of the single-page read. Asserts that `total` matches both reads.
    async fn every_page(state: &AppState, who: &AuthUser, q: &str) -> (Vec<String>, i64) {
        let sep = if q.is_empty() { "" } else { "&" };
        let whole = all_cves(state, who, &format!("{q}{sep}page_size=200"))
            .await
            .unwrap();
        let mut ids: Vec<String> = whole.items.iter().map(|item| item.id.clone()).collect();
        ids.sort_unstable();
        assert_eq!(
            whole.total,
            ids.len() as i64,
            "total matches the items for {q:?}"
        );
        let mut paged = Vec::new();
        for page in 1..=(whole.total + 1) {
            let one = all_cves(state, who, &format!("{q}{sep}page_size=1&page={page}"))
                .await
                .unwrap();
            assert_eq!(
                one.total, whole.total,
                "total is the same on page {page} of {q:?}"
            );
            paged.extend(one.items.into_iter().map(|item| item.id));
        }
        paged.sort_unstable();
        assert_eq!(paged, ids, "the pages hold exactly the items of {q:?}");
        (ids, whole.total)
    }

    #[tokio::test]
    async fn every_severity_is_listed_and_each_filter_matches_its_total() {
        let (state, dir, _, _) = setup("read-all-filters").await;
        seed_source(&state.pool, "u1", "m2", "cg", "octo", "second").await;
        sqlx::query("UPDATE image_sources SET repository = 'team/m2' WHERE id = 'm2'")
            .execute(&state.pool)
            .await
            .unwrap();
        // Another tenant's mapping with matching values must never appear.
        seed_github(&state.pool, "u2", "cg2", "github").await;
        seed_source(&state.pool, "u2", "m3", "cg2", "octo", "third").await;

        seen_pkg(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", "openssl").await;
        seen_pkg(&state, "m1", "v1", "CVE-2026-0002", "HIGH", "zlib").await;
        seen_pkg(&state, "m1", "v2", "CVE-2026-0003", "MEDIUM", "openssl").await;
        seen_pkg(&state, "m1", "v2", "CVE-2026-0004", "LOW", "busybox").await;
        seen_pkg(&state, "m1", "v1", "CVE-2026-0005", "UNKNOWN", "busybox").await;
        // Fixed LOW on m1.
        seen_pkg(&state, "m1", "v1", "CVE-2026-0006", "LOW", "zlib").await;
        fix(&state, "m1", "v1", "CVE-2026-0006").await;
        // Accepted MEDIUM on m2 (project `team`, repository `m2`).
        seen_pkg(&state, "m2", "v9", "CVE-2026-0007", "MEDIUM", "openssl").await;
        seen_pkg(&state, "m2", "v9", "CVE-2026-0008", "UNKNOWN", "OpenSSL").await;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username)
             VALUES ('a1', 'm2', 'CVE-2026-0007', 'accepted for the test', 'u1', 'u1')",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        seen_pkg(&state, "m3", "v1", "CVE-2026-0001", "LOW", "openssl").await;

        let ids = |list: &[&str]| -> Vec<String> {
            let mut ids: Vec<String> = list.iter().map(|id| (*id).to_owned()).collect();
            ids.sort_unstable();
            ids
        };
        let me = user("u1");
        // The default is every severity, open, fixed and accepted alike.
        let (all, total) = every_page(&state, &me, "").await;
        assert_eq!(total, 8);
        assert_eq!(
            all,
            ids(&[
                "m1:CVE-2026-0001",
                "m1:CVE-2026-0002",
                "m1:CVE-2026-0003",
                "m1:CVE-2026-0004",
                "m1:CVE-2026-0005",
                "m1:CVE-2026-0006",
                "m2:CVE-2026-0007",
                "m2:CVE-2026-0008",
            ])
        );
        for (q, expected) in [
            ("severity=LOW", vec!["m1:CVE-2026-0004", "m1:CVE-2026-0006"]),
            (
                "severity=UNKNOWN",
                vec!["m1:CVE-2026-0005", "m2:CVE-2026-0008"],
            ),
            (
                "severity=LOW,UNKNOWN",
                vec![
                    "m1:CVE-2026-0004",
                    "m1:CVE-2026-0005",
                    "m1:CVE-2026-0006",
                    "m2:CVE-2026-0008",
                ],
            ),
            (
                "severity=CRITICAL,HIGH",
                vec!["m1:CVE-2026-0001", "m1:CVE-2026-0002"],
            ),
            ("status=fixed", vec!["m1:CVE-2026-0006"]),
            ("status=accepted", vec!["m2:CVE-2026-0007"]),
            (
                "status=fixed,accepted",
                vec!["m1:CVE-2026-0006", "m2:CVE-2026-0007"],
            ),
            (
                "status=open&accepted=false",
                vec![
                    "m1:CVE-2026-0001",
                    "m1:CVE-2026-0002",
                    "m1:CVE-2026-0003",
                    "m1:CVE-2026-0004",
                    "m1:CVE-2026-0005",
                    "m2:CVE-2026-0008",
                ],
            ),
            (
                "status=open,fixed,accepted",
                all.iter().map(String::as_str).collect(),
            ),
            // Exact and case-sensitive: `OpenSSL` is not `openssl`.
            (
                "package=openssl",
                vec!["m1:CVE-2026-0001", "m1:CVE-2026-0003", "m2:CVE-2026-0007"],
            ),
            ("package=OpenSSL", vec!["m2:CVE-2026-0008"]),
            ("package=", all.iter().map(String::as_str).collect()),
            // A fixed row still matches its tag.
            (
                "tag=v1",
                vec![
                    "m1:CVE-2026-0001",
                    "m1:CVE-2026-0002",
                    "m1:CVE-2026-0005",
                    "m1:CVE-2026-0006",
                ],
            ),
            ("tag=v9", vec!["m2:CVE-2026-0007", "m2:CVE-2026-0008"]),
            ("tag=nope", vec![]),
            (
                "namespace=team",
                vec!["m2:CVE-2026-0007", "m2:CVE-2026-0008"],
            ),
            (
                "repository=ghcr.io/team/m2",
                vec!["m2:CVE-2026-0007", "m2:CVE-2026-0008"],
            ),
            ("namespace=proj&repository=ghcr.io/team/m2", vec![]),
            ("severity=MEDIUM&namespace=team", vec!["m2:CVE-2026-0007"]),
            (
                "severity=LOW&tag=v2&package=busybox",
                vec!["m1:CVE-2026-0004"],
            ),
            ("q=busybox&severity=UNKNOWN", vec!["m1:CVE-2026-0005"]),
        ] {
            let (got, total) = every_page(&state, &me, q).await;
            assert_eq!(got, ids(&expected), "{q}");
            assert_eq!(total, expected.len() as i64, "{q}");
        }
        // The path route takes the same filters.
        let page = by_mapping(&state, &me, "m2", "status=accepted")
            .await
            .unwrap();
        assert_eq!((page.total, page.items.len()), (1, 1));
        // The tenancy of the filters: another user sees only their own LOW.
        let (theirs, _) = every_page(&state, &user("u2"), "severity=LOW&package=openssl").await;
        assert_eq!(theirs, ["m3:CVE-2026-0001"]);
        // open_severity is the highest open severity, null once every tag is fixed.
        let fixed = one(&state, &me, "m1:CVE-2026-0006").await.unwrap();
        assert_eq!(fixed.summary.open_severity, None);
        let low = one(&state, &me, "m1:CVE-2026-0004").await.unwrap();
        assert_eq!(low.summary.open_severity.as_deref(), Some("LOW"));
        // Bad values are 400 with fixed text, never echoed.
        for q in [
            "severity=LOW,",
            "severity=low",
            "severity=",
            "status=open,closed",
            "status=",
            "tag=v1%0A",
            &format!("package={}", "p".repeat(257)),
        ] {
            let error = all_cves(&state, &me, q).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{q}");
            assert!(
                !error.message().contains("closed") && !error.message().contains("ppp"),
                "{q}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The open severity ignores fixed rows: CRITICAL fixed on v1 and LOW open on v2 lists as
    /// CRITICAL (`severity`) with `open_severity` LOW, so the UI asks for confirmation.
    #[tokio::test]
    async fn open_severity_uses_open_rows_only() {
        let (state, dir, _, _) = setup("read-open-severity").await;
        seen(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", AT).await;
        seen(&state, "m1", "v2", "CVE-2026-0001", "LOW", AT).await;
        fix(&state, "m1", "v1", "CVE-2026-0001").await;
        let page = by_mapping(&state, &user("u1"), "m1", "").await.unwrap();
        let cve = item(&page, "CVE-2026-0001");
        assert_eq!(cve.severity, "CRITICAL");
        assert_eq!(cve.open_severity.as_deref(), Some("LOW"));
        let json = serde_json::to_value(&page).unwrap();
        assert_eq!(json["items"][0]["open_severity"], "LOW");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #265: the `fix` filter follows the Fixed in value of the summary.
    #[tokio::test]
    async fn fix_filter_follows_the_fixed_in_column() {
        let (state, dir, _, _) = setup("read-fix-filter").await;
        // 1 CRITICAL fixed in 2.0, 2 HIGH with no fix version, 3 HIGH fixed in 1.5.
        let rows = [
            ("CVE-2026-0001", "CRITICAL", Some("2.0")),
            ("CVE-2026-0002", "HIGH", None),
            ("CVE-2026-0003", "HIGH", Some("1.5")),
        ];
        for (cve, severity, fixed) in rows {
            store(
                &state,
                &db::findings::Finding {
                    id: &crate::services::ids::new_id().unwrap_or_default(),
                    source_id: "m1",
                    image_tag: "v1",
                    cve_id: cve,
                    package: Some("zlib"),
                    severity,
                    fixed_in_version: fixed,
                    description: None,
                    now: AT,
                },
            )
            .await;
        }
        let me = user("u1");
        async fn ids(state: &AppState, me: &AuthUser, q: &str) -> Vec<String> {
            let (ids, _) = every_page(state, me, q).await;
            ids.into_iter()
                .map(|id| id.replace("CVE-2026-000", ""))
                .collect()
        }
        assert_eq!(ids(&state, &me, "fix=available").await, ["m1:1", "m1:3"]);
        // Unknown in the column is No fix.
        assert_eq!(ids(&state, &me, "fix=none").await, ["m1:2"]);
        assert_eq!(ids(&state, &me, "fix=available,none").await.len(), 3);
        assert_eq!(ids(&state, &me, "").await.len(), 3);
        // The filter combines with severity by AND.
        assert_eq!(
            ids(&state, &me, "fix=available&severity=HIGH").await,
            ["m1:3"]
        );
        assert_eq!(
            ids(&state, &me, "fix=none&severity=CRITICAL").await,
            Vec::<String>::new()
        );
        // The path route takes it too, and `total` matches.
        let page = by_mapping(&state, &me, "m1", "fix=available")
            .await
            .unwrap();
        assert_eq!(page.total, 2);
        // A bad value is 400.
        let error = all_cves(&state, &me, "fix=maybe").await.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #257: the control bar parameters.
    #[tokio::test]
    async fn control_bar_filters() {
        let (state, dir, _, _) = setup("read-control-bar").await;
        seed_source(&state.pool, "u1", "m2", "cg", "octo", "second").await;
        sqlx::query("UPDATE image_sources SET repository = 'team/m2' WHERE id = 'm2'")
            .execute(&state.pool)
            .await
            .unwrap();
        seed_github(&state.pool, "u2", "cg2", "github").await;
        seed_source(&state.pool, "u2", "m3", "cg2", "octo", "third").await;

        // m1: 1 CRITICAL open with an open issue, 2 HIGH open with a closed issue,
        // 3 MEDIUM open and accepted, 4 LOW fixed, 5 LOW open with no issue.
        seen_pkg(&state, "m1", "v1", "CVE-2026-0001", "CRITICAL", "glibc").await;
        seen_pkg(&state, "m1", "v2", "CVE-2026-0001", "CRITICAL", "glibc").await;
        seen_pkg(&state, "m1", "v1", "CVE-2026-0002", "HIGH", "zlib").await;
        seen_pkg(&state, "m1", "v1", "CVE-2026-0003", "MEDIUM", "curl").await;
        seen_pkg(&state, "m1", "v1", "CVE-2026-0004", "LOW", "zlib").await;
        fix(&state, "m1", "v1", "CVE-2026-0004").await;
        seen_pkg(&state, "m1", "v1", "CVE-2026-0005", "LOW", "per%cent_pkg").await;
        // m2 (project `team`): one HIGH open.
        seen_pkg(&state, "m2", "v1", "CVE-2026-0006", "HIGH", "curl").await;
        // Another tenant: same CVE id and package, must never show.
        seen_pkg(&state, "m3", "v1", "CVE-2026-0001", "CRITICAL", "glibc").await;
        sqlx::query(
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url, status)
             VALUES ('g1', 'octo', 'app', 'CVE-2026-0001', 7, 'https://github.com/octo/app/issues/7', 'open'),
                    ('g2', 'octo', 'app', 'CVE-2026-0002', 8, 'https://github.com/octo/app/issues/8', 'closed')",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username)
             VALUES ('a1', 'm1', 'CVE-2026-0003', 'accepted for the test', 'u1', 'u1')",
        )
        .execute(&state.pool)
        .await
        .unwrap();

        let me = user("u1");
        // The short ids ("m1:1") of every page of `GET /cves?<q>`; `every_page` also checks
        // that `total` matches the items.
        async fn ids(state: &AppState, me: &AuthUser, q: &str) -> Vec<String> {
            let (ids, _) = every_page(state, me, q).await;
            ids.into_iter()
                .map(|id| id.replace("CVE-2026-000", ""))
                .collect()
        }
        let none: Vec<String> = Vec::new();
        // has_issue: open and closed issues count; the groups AND.
        assert_eq!(ids(&state, &me, "has_issue=true").await, ["m1:1", "m1:2"]);
        assert_eq!(
            ids(&state, &me, "has_issue=false").await,
            ["m1:3", "m1:4", "m1:5", "m2:6"]
        );
        assert_eq!(
            ids(&state, &me, "has_issue=true&severity=HIGH").await,
            ["m1:2"]
        );
        assert_eq!(
            ids(&state, &me, "has_issue=false&status=open").await,
            ["m1:5", "m2:6"]
        );
        assert_eq!(
            ids(&state, &me, "has_issue=true&status=accepted").await,
            none
        );
        // Open excludes accepted; Accepted is separate; both shows both sets.
        assert_eq!(
            ids(&state, &me, "status=open").await,
            ["m1:1", "m1:2", "m1:5", "m2:6"]
        );
        assert_eq!(ids(&state, &me, "status=accepted").await, ["m1:3"]);
        assert_eq!(
            ids(&state, &me, "status=open,accepted").await,
            ["m1:1", "m1:2", "m1:3", "m1:5", "m2:6"]
        );
        // OR within a group, AND across groups.
        assert_eq!(
            ids(&state, &me, "severity=CRITICAL,LOW&status=open").await,
            ["m1:1", "m1:5"]
        );
        assert_eq!(
            ids(&state, &me, "severity=CRITICAL,LOW&status=open,fixed").await,
            ["m1:1", "m1:4", "m1:5"]
        );
        assert_eq!(
            ids(&state, &me, "severity=HIGH&status=open&namespace=team").await,
            ["m2:6"]
        );
        // q matches id, package, project and repository; `%` and `_` are literal.
        assert_eq!(ids(&state, &me, "q=glibc").await, ["m1:1"]);
        assert_eq!(ids(&state, &me, "q=team").await, ["m2:6"]);
        assert_eq!(ids(&state, &me, "q=M2").await, ["m2:6"]);
        assert_eq!(ids(&state, &me, "q=2026-0004").await, ["m1:4"]);
        assert_eq!(ids(&state, &me, "q=%25").await, ["m1:5"]);
        assert_eq!(ids(&state, &me, "q=_").await, ["m1:5"]);
        assert_eq!(ids(&state, &me, "q=%25cve").await, none);
        assert_eq!(
            ids(&state, &me, "q=curl&has_issue=false").await,
            ["m1:3", "m2:6"]
        );
        // The namespace is the first path segment of the repository (decision 38); the
        // repository filter is `<hub host>/<repository>`; the removed Harbor names are not read.
        assert_eq!(ids(&state, &me, "namespace=team").await, ["m2:6"]);
        assert_eq!(
            ids(&state, &me, "repository=ghcr.io/team/m2").await,
            ["m2:6"]
        );
        assert_eq!(ids(&state, &me, "source_id=m2").await, ["m2:6"]);
        assert_eq!(
            ids(&state, &me, "namespace=Team").await,
            none,
            "case-sensitive"
        );
        assert_eq!(
            ids(&state, &me, "namespace=te").await,
            none,
            "exact, not a prefix"
        );
        assert_eq!(
            ids(&state, &me, "project=team&harbor_project=team&mapping=m2")
                .await
                .len(),
            6,
            "project, harbor_project and mapping are not read"
        );
        assert_eq!(ids(&state, &me, "tag=v2").await, ["m1:1"]);
        // Old accepted parameters select the Accepted and Open pills.
        assert_eq!(
            ids(&state, &me, "accepted=true").await,
            ids(&state, &me, "status=accepted").await
        );
        assert_eq!(
            ids(&state, &me, "accepted=false&status=open").await,
            ids(&state, &me, "status=open").await
        );
        assert_eq!(
            ids(&state, &me, "accepted=false").await,
            ["m1:1", "m1:2", "m1:4", "m1:5", "m2:6"]
        );
        // `status` wins over `accepted` when both are sent.
        assert_eq!(
            ids(&state, &me, "status=accepted&accepted=false").await,
            ["m1:3"]
        );
        // n of m: CVE 1 is open on two of the two tracked tags, CVE 2 on one of two.
        let page = all_cves(&state, &me, "source_id=m1").await.unwrap();
        let counts = |cve: &str| {
            let item = item(&page, cve);
            (item.open_tags, item.tracked_tags)
        };
        assert_eq!(counts("CVE-2026-0001"), (2, 2));
        assert_eq!(counts("CVE-2026-0002"), (1, 2));
        assert_eq!(counts("CVE-2026-0004"), (0, 2));
        // Access: another tenant's source is 404; a bad has_issue is 400.
        for q in ["source_id=m3", "source_id=nope"] {
            let error = all_cves(&state, &me, q).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::NOT_FOUND, "{q}");
        }
        let error = all_cves(&state, &me, "has_issue=maybe").await.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        // The other tenant sees only their own row; the path route ignores `source_id`.
        assert_eq!(
            every_page(&state, &user("u2"), "has_issue=false").await.0,
            ["m3:CVE-2026-0001"]
        );
        let path = by_mapping(&state, &me, "m1", "source_id=m2").await.unwrap();
        assert_eq!(path.total, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
