//! `GET` and `PUT /api/v1/admin/github-url`: the instance GitHub API base URL and web URL
//! (`specs/api.md`, Admin; `specs/security.md`, "GitHub base URL"). Admin only. An empty
//! value means the default. No audit row is written: `github.url_change` is not in the
//! audit vocabulary yet.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::api::auth::AdminUser;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::github_url::{self, StoredUrls};

/// The response of both routes: each value as stored, or `""` when empty.
#[derive(Debug, Serialize)]
pub struct GithubUrlView {
    pub api_base_url: String,
    pub web_url: String,
}

impl From<StoredUrls> for GithubUrlView {
    fn from(stored: StoredUrls) -> Self {
        Self {
            api_base_url: stored.api_base_url,
            web_url: stored.web_url,
        }
    }
}

/// The request body of `PUT`. Both fields are required; `""` selects the default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubUrlBody {
    pub api_base_url: String,
    pub web_url: String,
}

/// `GET /api/v1/admin/github-url`.
pub async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<GithubUrlView>, AppError> {
    Ok(Json(github_url::load_stored(&state.pool).await?.into()))
}

/// `PUT /api/v1/admin/github-url`. Validates both values, stores them, and applies them to
/// every GitHub client at once. An invalid value is `422 validation_failed` with the fixed
/// message `settings.github_url_invalid`; the value is never echoed.
pub async fn put_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
    body: axum::body::Bytes,
) -> Result<Json<GithubUrlView>, AppError> {
    let body: GithubUrlBody = serde_json::from_slice(&body)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))?;
    let (stored, urls) = github_url::save(&state.pool, &body.api_base_url, &body.web_url).await?;
    state.github.set(urls);
    Ok(Json(stored.into()))
}
