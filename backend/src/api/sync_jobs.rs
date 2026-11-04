//! Sync job routes (`specs/api.md`, Sync jobs). Every handler takes `AuthUser`, so a missing
//! or invalid session is `401`. Tenancy is enforced in the service: another tenant's job or
//! mapping is `404` (or an empty page for a foreign `mapping_id` filter).

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::pagination::Page;
use crate::services::sessions::AuthUser;
use crate::services::sync_jobs::{self, ListQuery, SyncJob};
use crate::worker::now_secs;

/// Raw query values for `GET /api/v1/sync-jobs`.
#[derive(Debug, Deserialize)]
pub struct SyncJobListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub scope: Option<String>,
    pub status: Option<String>,
    pub mapping_id: Option<String>,
}

/// `GET /api/v1/sync-jobs`. `scope=all` is honored for admins only; another role gets `403`.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<SyncJobListParams>,
) -> Result<Json<Page<SyncJob>>, AppError> {
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
        mapping_id: params.mapping_id,
        all_users,
    };
    Ok(Json(sync_jobs::list(&state.pool, &user.id, &query).await?))
}

/// `GET /api/v1/sync-jobs/:id`. An admin reads any job; a user reads only their own.
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<SyncJob>, AppError> {
    let is_admin = user.role == Role::Admin;
    Ok(Json(
        sync_jobs::get(&state.pool, &user.id, is_admin, &id).await?,
    ))
}

/// `POST /api/v1/sync-jobs/:id/retry`. The mapping owner or an admin. Returns `200`
/// with the `SyncJob`. Only a `failed` job can be retried (`409` otherwise).
pub async fn retry(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<SyncJob>, AppError> {
    let is_admin = user.role == Role::Admin;
    let actor = Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    };
    let job = sync_jobs::retry(&state.pool, &actor, is_admin, &id, now_secs()).await?;
    Ok(Json(job))
}

#[cfg(test)]
mod tests {
    use crate::db;
    use crate::services::sync_jobs::{self, ListQuery};

    async fn fresh_pool(name: &str) -> (sqlx::SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "harborgate-api-sync-jobs-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// One user `owner` with mapping `m1`, which has a job `job-1` with `payload`.
    async fn seed_job(pool: &sqlx::SqlitePool, payload: &str) {
        sqlx::query(
            "INSERT INTO users (id, username, role, token_version) VALUES ('owner', 'owner', 'user', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES ('c1', 'owner', 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake'),
                    ('c2', 'owner', 'github', 'g', NULL, NULL, 'v1:fake')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
             VALUES ('m1', 'owner', 'c1', 'c2', 'https://harbor.example.com', 'p', 'r', 'o', 'g', 'h1', 'h2')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
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
            "INSERT INTO sync_reports (id, mapping_id, sync_job_id, harbor_repository, image_tag, image_digest, commit_sha, vulnerability_summary, sarif_status, synced_at)
             VALUES ('rep-1', 'm1', 'job-1', 'r', 'v1', 'sha256:aa', 'abc123', '{\"critical\": 0, \"high\": 2}', 'success', 3000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let job = sync_jobs::get(&pool, "owner", false, "job-1")
            .await
            .unwrap();
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
            r#"{"trigger":"poll","repo_full_name":"p/r","digest":"sha256:aa","tag":"v1"}"#,
        )
        .await;

        let job = sync_jobs::get(&pool, "owner", false, "job-1")
            .await
            .unwrap();
        assert_eq!(job.trigger, "poll");
        assert_eq!(job.image.repo_full_name.as_deref(), Some("p/r"));
        assert_eq!(job.image.tag.as_deref(), Some("v1"));
        assert_eq!(job.image.digest.as_deref(), Some("sha256:aa"));
        assert!(job.report.is_none(), "no report is linked yet");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn payload_without_trigger_is_webhook() {
        let (pool, dir) = fresh_pool("trigger").await;
        seed_job(
            &pool,
            r#"{"repo_full_name":"p/r","digest":"sha256:aa","tag":"v1"}"#,
        )
        .await;

        let job = sync_jobs::get(&pool, "owner", false, "job-1")
            .await
            .unwrap();
        assert_eq!(job.trigger, "webhook");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn long_error_text_is_capped_at_500_characters() {
        let (pool, dir) = fresh_pool("cap").await;
        seed_job(&pool, "{}").await;
        let long = "x".repeat(5_000);
        sqlx::query("UPDATE sync_jobs SET last_error = ? WHERE id = 'job-1'")
            .bind(&long)
            .execute(&pool)
            .await
            .unwrap();

        let job = sync_jobs::get(&pool, "owner", false, "job-1")
            .await
            .unwrap();
        assert_eq!(job.last_error.map(|text| text.chars().count()), Some(500));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_rejects_an_unknown_status_before_sql() {
        let (pool, dir) = fresh_pool("status").await;
        seed_job(&pool, "{}").await;
        let result = sync_jobs::list(
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
