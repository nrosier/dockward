//! Mapping routes (`specs/api.md`, Mappings). Every handler takes `AuthUser`, so a missing
//! or invalid session returns `401`. Ownership is enforced in the service, so another
//! user's mapping is `404`.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::api::hardening::{RateLimiter, too_many_requests};
use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::credential_probe::OutboundGithubProbe;
use crate::services::dashboard::{self, OpenCves};
use crate::services::mappings::{self, Created, ListQuery, Mapping, MappingPatch, NewMapping};
use crate::services::pagination::Page;
use crate::services::poller;
use crate::services::sessions::AuthUser;
use crate::services::sync_jobs::{self, LastSync};
use crate::worker::now_secs;

/// One `GET /mappings` item: the `Mapping` fields plus `open_cves` and `last_sync`
/// (`specs/api.md`, Mappings; decided on #35). `open_cves` covers every severity with a
/// `total` (#129). `GET /mappings/:id` does not carry them.
#[derive(Debug, Serialize)]
pub struct MappingListItem {
    #[serde(flatten)]
    pub mapping: Mapping,
    pub open_cves: OpenCves,
    pub last_sync: Option<LastSync>,
}

/// Adds `open_cves` and `last_sync` to each item of a list page. Each item uses the same
/// per-mapping queries as the dashboard, so the numbers agree.
async fn with_list_extras(
    pool: &SqlitePool,
    page: Page<Mapping>,
    now: i64,
) -> Result<Page<MappingListItem>, AppError> {
    let mut items = Vec::with_capacity(page.items.len());
    for mapping in page.items {
        let open_cves = dashboard::open_cves_for_mapping(pool, &mapping.id, now).await?;
        let last_sync = sync_jobs::last_sync(pool, &mapping.id).await?;
        items.push(MappingListItem {
            mapping,
            open_cves,
            last_sync,
        });
    }
    Ok(Page {
        items,
        page: page.page,
        page_size: page.page_size,
        total: page.total,
    })
}

/// Manual scan pulls allowed per mapping in one cooldown window (`specs/security.md`).
const PULL_LIMIT: u32 = 1;
/// The manual scan pull cooldown: 5 minutes per mapping (decided on #131).
const PULL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);

/// A fresh manual pull cooldown, held in memory. The router state holds one.
pub fn new_pull_limiter() -> RateLimiter {
    RateLimiter::new(PULL_LIMIT, PULL_COOLDOWN)
}

/// The `POST /api/v1/mappings/:id/pull` response: how many sync jobs were queued.
#[derive(Debug, Serialize)]
pub struct Pulled {
    pub queued: u64,
}

/// Raw query values for `GET /api/v1/mappings`.
#[derive(Debug, Deserialize)]
pub struct MappingListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub scope: Option<String>,
}

/// Parses a JSON body into `T`. A malformed body becomes `400 invalid_request`.
fn parse_body<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}

fn actor_of(user: &AuthUser) -> Actor {
    Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    }
}

/// `GET /api/v1/mappings`. `scope=all` is honored for admins only.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<MappingListParams>,
) -> Result<Json<Page<MappingListItem>>, AppError> {
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
        all_users,
    };
    let page = mappings::list(&state.pool, &user.id, &query).await?;
    Ok(Json(with_list_extras(&state.pool, page, now_secs()).await?))
}

/// `POST /api/v1/mappings`. Returns `201` with the mapping and the two values shown once.
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let input: NewMapping = parse_body(&body)?;
    let actor = actor_of(&user);
    let github_probe = OutboundGithubProbe::new(state.github.clone())?;
    let created: Created = mappings::create(
        &state.pool,
        &state.credentials_key,
        &state.harbor_probe,
        &github_probe,
        &actor,
        &user.id,
        &state.public_url,
        input,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// `PUT /api/v1/mappings/:id`. Takes any subset of the create fields. Returns `200` with
/// the updated mapping. Owner only. The webhook token and auth secret are not changed.
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Mapping>, AppError> {
    let patch: MappingPatch = parse_body(&body)?;
    let actor = actor_of(&user);
    let github_probe = OutboundGithubProbe::new(state.github.clone())?;
    let probes = mappings::Probes {
        harbor: &state.harbor_probe,
        github: &github_probe,
    };
    let updated = mappings::update(
        &state.pool,
        &state.credentials_key,
        probes,
        &actor,
        &user.id,
        &id,
        patch,
    )
    .await?;
    Ok(Json(updated))
}

/// `GET /api/v1/mappings/:id`.
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Mapping>, AppError> {
    Ok(Json(
        mappings::load_owned(&state.pool, &user.id, &id).await?,
    ))
}

/// `DELETE /api/v1/mappings/:id`. Returns `204`. Owner only.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let actor = actor_of(&user);
    mappings::delete(&state.pool, &actor, &user.id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/mappings/:id/rotate-webhook-token`. Owner only.
pub async fn rotate_webhook_token(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor = actor_of(&user);
    let url = mappings::rotate_webhook_token(&state.pool, &actor, &user.id, &state.public_url, &id)
        .await?;
    Ok(Json(serde_json::json!({ "webhook_url": url })))
}

/// `POST /api/v1/mappings/:id/rotate-auth-secret`. Owner only.
pub async fn rotate_auth_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor = actor_of(&user);
    let secret = mappings::rotate_auth_secret(&state.pool, &actor, &user.id, &id).await?;
    Ok(Json(serde_json::json!({ "auth_secret": secret })))
}

/// `POST /api/v1/mappings/:id/pull`. The mapping owner or an admin (`specs/security.md`,
/// Tenancy). Runs the scheduled poll for this mapping now and returns `{"queued": n}`.
/// One pull per mapping per 5 minutes; the cooldown is checked after access, so another
/// tenant's mapping is `404`, and it is used even when the pull then fails at Harbor.
pub async fn pull(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let is_admin = user.role == Role::Admin;
    let mapping = poller::find_pullable(&state.pool, &user.id, is_admin, &id).await?;
    if let Err(retry) = state.pull_limiter.check(
        &format!("mapping:{}", mapping.id),
        std::time::Instant::now(),
    ) {
        return Ok(too_many_requests(retry));
    }
    let queued = poller::pull_mapping(
        &state.pool,
        &state.credentials_key,
        &state.harbor_fetch,
        &actor_of(&user),
        &mapping,
        now_secs(),
    )
    .await?;
    Ok(Json(Pulled { queued }).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::services::mappings as mapping_service;

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "harborgate-api-mappings-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// Two mappings for one user. `m1` has one open CVE of each severity and a job; `m2` has
    /// nothing.
    async fn seed(pool: &SqlitePool) {
        sqlx::query("INSERT INTO users (id, username, role, token_version) VALUES ('owner', 'owner', 'user', 0)")
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
        for (id, repo) in [("m1", "app"), ("m2", "other")] {
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
                 VALUES (?, 'owner', 'c1', 'c2', 'https://harbor.example.com', 'p', ?, 'o', ?, ?, ?)",
            )
            .bind(id)
            .bind(id)
            .bind(repo)
            .bind(format!("t-{id}"))
            .bind(format!("s-{id}"))
            .execute(pool)
            .await
            .unwrap();
        }
        for (cve, severity) in [
            ("CVE-2026-0001", "CRITICAL"),
            ("CVE-2026-0002", "HIGH"),
            ("CVE-2026-0003", "MEDIUM"),
            ("CVE-2026-0004", "LOW"),
            ("CVE-2026-0005", "UNKNOWN"),
        ] {
            sqlx::query(
                "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, severity, status)
                 VALUES (?, 'm1', 'm1', 'v1', ?, ?, 'open')",
            )
            .bind(format!("f-{cve}"))
            .bind(cve)
            .bind(severity)
            .execute(pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
             VALUES ('job-1', 'm1', 'failed', 8, '{}', 1000, 5000)",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    fn item_for<'a>(page: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == id)
            .unwrap()
    }

    #[tokio::test]
    async fn list_items_carry_open_cves_and_last_sync() {
        let (pool, dir) = fresh_pool("list-extras").await;
        seed(&pool).await;
        let page = mapping_service::list(&pool, "owner", &mapping_service::ListQuery::default())
            .await
            .unwrap();
        let now = crate::worker::now_secs();
        let page = with_list_extras(&pool, page, now).await.unwrap();
        let json = serde_json::to_value(&page).unwrap();

        let busy = item_for(&json, "m1");
        assert_eq!(
            busy["open_cves"],
            serde_json::json!({
                "critical": 1, "high": 1, "medium": 1, "low": 1, "unknown": 1, "total": 5
            })
        );
        assert_eq!(busy["last_sync"]["status"], "failed");
        assert_eq!(busy["last_sync"]["updated_at"], "1970-01-01T01:23:20Z");
        // The Mapping fields are still flat on the item.
        assert_eq!(busy["harbor_repository"], "m1");

        let quiet = item_for(&json, "m2");
        assert_eq!(
            quiet["open_cves"],
            serde_json::json!({
                "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0
            })
        );
        assert!(quiet["last_sync"].is_null());

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
