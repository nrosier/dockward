//! Job routes (`specs/api.md`, Jobs). Every handler takes `AuthUser`, so a missing
//! or invalid session is `401`. Tenancy is enforced in the service: another tenant's job or
//! source is `404` (or an empty page for a foreign `source_id` filter).

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::jobs::{self, Job, ListQuery};
use crate::services::pagination::Page;
use crate::services::sessions::AuthUser;
use crate::worker::now_secs;

/// Raw query values for `GET /api/v1/jobs`.
#[derive(Debug, Deserialize)]
pub struct JobListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub scope: Option<String>,
    pub status: Option<String>,
    pub source_id: Option<String>,
    /// `true` leaves out jobs that produced nothing new. Off when absent.
    pub hide_empty: Option<bool>,
}

/// `GET /api/v1/jobs`. `scope=all` is honored for admins only; another role gets `403`.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<JobListParams>,
) -> Result<Json<Page<Job>>, AppError> {
    let all_users = match params.scope.as_deref() {
        None => false,
        Some("all") if user.role == Role::Admin => true,
        Some("all") => return Err(AppError::Forbidden),
        Some(_) => return Err(AppError::InvalidRequest("scope must be all.".to_owned())),
    };
    let query = ListQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        status: params.status,
        source_id: params.source_id,
        hide_empty: params.hide_empty.unwrap_or(false),
        all_users,
    };
    Ok(Json(jobs::list(&state.pool, &user.id, &query).await?))
}

/// Reads the purge `scope` query: none is the caller's own sources, `all` is admin only.
fn purge_scope(user: &AuthUser, scope: Option<&str>) -> Result<bool, AppError> {
    match scope {
        None => Ok(false),
        Some("all") if user.role == Role::Admin => Ok(true),
        Some("all") => Err(AppError::Forbidden),
        Some(_) => Err(AppError::InvalidRequest("scope must be all.".to_owned())),
    }
}

/// Query for the purge routes.
#[derive(Debug, Deserialize)]
pub struct PurgeParams {
    pub scope: Option<String>,
}

/// `GET /api/v1/jobs/failed-count`: what a purge would delete now.
pub async fn failed_count(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<PurgeParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let all_users = purge_scope(&user, params.scope.as_deref())?;
    let count = jobs::failed_count(&state.pool, &user.id, all_users).await?;
    Ok(Json(serde_json::json!({ "count": count })))
}

/// `POST /api/v1/jobs/purge-failed`: deletes the caller's failed jobs.
pub async fn purge_failed(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<PurgeParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let all_users = purge_scope(&user, params.scope.as_deref())?;
    let actor = Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    };
    let deleted = jobs::purge_failed(&state.pool, &actor, all_users).await?;
    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

/// `GET /api/v1/jobs/:id`. An admin reads any job; a user reads only their own.
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Job>, AppError> {
    let is_admin = user.role == Role::Admin;
    Ok(Json(jobs::get(&state.pool, &user.id, is_admin, &id).await?))
}

/// Query for `GET /api/v1/jobs/:id/log`. `attempt` picks an attempt (the latest when absent);
/// `after` is the id of the last line the caller has.
#[derive(Debug, Deserialize)]
pub struct JobLogParams {
    pub attempt: Option<i64>,
    pub after: Option<i64>,
}

/// `GET /api/v1/jobs/:id/log` (#308). An admin reads any job's log; a user reads only a job of
/// their own source. A `db_update` job is admin only. Another user's or a missing job is `404`.
pub async fn log(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<JobLogParams>,
) -> Result<Json<crate::services::job_log::JobLog>, AppError> {
    let is_admin = user.role == Role::Admin;
    let query = crate::services::job_log::LogQuery {
        attempt: params.attempt,
        after: params.after,
    };
    Ok(Json(
        crate::services::job_log::get(&state.pool, &user.id, is_admin, &id, &query).await?,
    ))
}

/// `POST /api/v1/jobs/:id/retry`. The source owner or an admin. Returns `200`
/// with the `Job`. Only a `failed` job can be retried (`409` otherwise).
pub async fn retry(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Job>, AppError> {
    let is_admin = user.role == Role::Admin;
    let actor = Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    };
    let job = jobs::retry(&state.pool, &actor, is_admin, &id, now_secs()).await?;
    Ok(Json(job))
}

#[cfg(test)]
mod tests {
    use crate::db;
    use crate::services::jobs::{self, ListQuery};

    async fn fresh_pool(name: &str) -> (sqlx::SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("dockward-api-jobs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// One user `owner` with source `m1`, which has a job `job-1` with `payload`.
    async fn seed_job(pool: &sqlx::SqlitePool, payload: &str) {
        sqlx::query(
            "INSERT INTO users (id, username, role, token_version) VALUES ('owner', 'owner', 'user', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('c2', 'owner', 'g', 'v1:fake')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('m1', 'owner', 'hub-default-ghcr', 'p/r', '*', 'c2', 'o', 'g')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, attempts, payload, created_at, updated_at)
             VALUES ('job-1', 'm1', 'done', 1, ?, 1000, 2000)",
        )
        .bind(payload)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn job_includes_its_report() {
        let (pool, dir) = fresh_pool("report").await;
        seed_job(
            &pool,
            r#"{"repo_full_name":"p/r","digest":"sha256:aa","tag":"v1"}"#,
        )
        .await;
        sqlx::query(
            "INSERT INTO publish_reports (id, source_id, job_id, image_tag, image_digest, commit_sha, vulnerability_summary, sarif_status, synced_at)
             VALUES ('rep-1', 'm1', 'job-1', 'v1', 'sha256:aa', 'abc123', '{\"critical\": 0, \"high\": 2}', 'success', 3000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        let report = job.report.expect("the linked report is included");
        assert_eq!(report.image_tag, "v1");
        assert_eq!(report.image_digest, "sha256:aa");
        assert_eq!(report.commit_sha.as_deref(), Some("abc123"));
        assert_eq!(report.sarif_status, "success");
        assert_eq!(report.synced_at.as_deref(), Some("1970-01-01T00:50:00Z"));
        assert_eq!(report.vulnerability_summary["high"], 2);
        assert_eq!(job.updated_at.as_deref(), Some("1970-01-01T00:33:20Z"));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn job_has_trigger_and_image_from_payload() {
        let (pool, dir) = fresh_pool("image").await;
        seed_job(
            &pool,
            r#"{"trigger":"discovery","repo_full_name":"p/r","digest":"sha256:aa","tag":"v1"}"#,
        )
        .await;

        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        assert_eq!(job.trigger, "discovery");
        assert_eq!(job.image.repo_full_name.as_deref(), Some("p/r"));
        assert_eq!(job.image.tag.as_deref(), Some("v1"));
        assert_eq!(job.image.digest.as_deref(), Some("sha256:aa"));
        assert!(job.report.is_none(), "no report is linked yet");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_pull_job_has_kind_pull_no_tag_and_no_report() {
        let (pool, dir) = fresh_pool("pull-kind").await;
        seed_job(&pool, r#"{"kind":"pull","digest":"sha256:aa"}"#).await;

        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        assert_eq!(job.kind.as_deref(), Some("pull"));
        assert_eq!(job.image.tag, None);
        assert_eq!(job.image.digest.as_deref(), Some("sha256:aa"));
        assert!(job.report.is_none());
        let json = serde_json::to_value(&job).unwrap();
        assert_eq!(json["kind"], "pull");
        assert!(json["image"]["tag"].is_null());
        assert!(json["report"].is_null());
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_payload_with_an_unknown_or_no_kind_has_a_null_kind() {
        let (pool, dir) = fresh_pool("unknown-kind").await;
        seed_job(&pool, r#"{"digest":"sha256:aa","tag":"v1"}"#).await;

        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        assert_eq!(job.kind, None);
        assert_eq!(job.image.tag.as_deref(), Some("v1"));
        sqlx::query(r#"UPDATE jobs SET payload = '{"kind":"other","tag":"v1"}'"#)
            .execute(&pool)
            .await
            .unwrap();
        let odd = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        assert_eq!(odd.kind, None);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_database_refresh_job_has_no_source_and_no_owner() {
        let (pool, dir) = fresh_pool("db-update").await;
        seed_job(&pool, "{}").await;
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, attempts, payload, created_at, updated_at)
             VALUES ('job-db', NULL, 'done', 1, '{\"kind\":\"db_update\"}', 1000, 2000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let admin = jobs::get(&pool, "admin", true, "job-db").await.unwrap();
        assert_eq!(admin.source_id, None);
        assert_eq!(admin.kind.as_deref(), Some("db_update"));
        assert!(matches!(
            jobs::get(&pool, "owner", false, "job-db").await,
            Err(crate::error::AppError::NotFound)
        ));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_job_with_no_trigger_lists_as_scheduled() {
        let (pool, dir) = fresh_pool("trigger").await;
        seed_job(
            &pool,
            r#"{"repo_full_name":"p/r","digest":"sha256:aa","tag":"v1"}"#,
        )
        .await;

        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        assert_eq!(job.trigger, "scheduled");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn manual_and_pull_triggers_are_unchanged() {
        let (pool, dir) = fresh_pool("triggers-kept").await;
        seed_job(&pool, r#"{"kind":"pull","trigger":"manual"}"#).await;
        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        assert_eq!(job.trigger, "manual");
        for trigger in ["first_pull", "tag_moved"] {
            sqlx::query("UPDATE jobs SET payload = ? WHERE id = 'job-1'")
                .bind(format!(r#"{{"kind":"pull","trigger":"{trigger}"}}"#))
                .execute(&pool)
                .await
                .unwrap();
            let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
            assert_eq!(job.trigger, trigger);
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn long_error_text_is_capped_at_500_characters() {
        let (pool, dir) = fresh_pool("cap").await;
        seed_job(&pool, "{}").await;
        let long = "x".repeat(5_000);
        sqlx::query("UPDATE jobs SET last_error = ? WHERE id = 'job-1'")
            .bind(&long)
            .execute(&pool)
            .await
            .unwrap();

        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        assert_eq!(job.last_error.map(|text| text.chars().count()), Some(500));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn report_text_fields_are_capped_at_500_characters() {
        let (pool, dir) = fresh_pool("report-cap").await;
        seed_job(&pool, "{}").await;
        let long = "y".repeat(5_000);
        sqlx::query(
            "INSERT INTO publish_reports (id, source_id, job_id, image_tag, image_digest, commit_sha, vulnerability_summary, sarif_status)
             VALUES ('rep-cap', 'm1', 'job-1', ?, ?, ?, '{}', 'success')",
        )
        .bind(&long)
        .bind(&long)
        .bind(&long)
        .execute(&pool)
        .await
        .unwrap();

        let job = jobs::get(&pool, "owner", false, "job-1").await.unwrap();
        let report = job.report.expect("the linked report is included");
        assert_eq!(report.image_tag.chars().count(), 500);
        assert_eq!(report.image_digest.chars().count(), 500);
        assert_eq!(
            report.commit_sha.map(|text| text.chars().count()),
            Some(500)
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_rejects_an_unknown_status_before_sql() {
        let (pool, dir) = fresh_pool("status").await;
        seed_job(&pool, "{}").await;
        let result = jobs::list(
            &pool,
            "owner",
            &ListQuery {
                status: Some("success".to_owned()),
                ..ListQuery::default()
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::error::AppError::InvalidRequest(_))
        ));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
