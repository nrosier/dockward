//! Mapping picker routes (`specs/api.md`, Pickers; #126). Every handler takes `AuthUser`,
//! so a missing or invalid session returns `401`.
//!
//! Rate limits, declared per route (`specs/api.md`, Pickers):
//! - `GET /credentials/:id/harbor-projects`, `GET /credentials/:id/harbor-projects/:project/repositories`,
//!   `GET /credentials/:id/github-repositories`, `GET /credentials/:id/source-suggestion`:
//!   one shared limit of 60 per minute per user, checked after the tenancy check
//!   (`PickerState::limiter`). Over it: `429` with `Retry-After`.
//! - `GET`, `POST /pickers/hidden` and `DELETE /pickers/hidden/:id`: no limit. They touch only
//!   the caller's own rows (capped at 1,000) and make no upstream call.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::pickers::{
    self, Caller, HiddenQuery, HideRequest, ListQuery, PickerFail, SuggestionQuery,
};
use crate::services::sessions::AuthUser;

/// Raw list query values for the three picker lists.
#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub q: Option<String>,
}

impl From<ListParams> for ListQuery {
    fn from(params: ListParams) -> Self {
        ListQuery {
            page: params.page,
            page_size: params.page_size,
            sort: params.sort,
            order: params.order,
            q: params.q,
        }
    }
}

/// Raw query values for the source suggestion.
#[derive(Debug, Deserialize)]
pub struct SuggestionParams {
    pub project: Option<String>,
    pub repository: Option<String>,
    pub github_cred_id: Option<String>,
}

/// Raw query values for `GET /pickers/hidden`.
#[derive(Debug, Deserialize)]
pub struct HiddenParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub source: Option<String>,
}

/// Renders a picker failure in the error envelope. Fixed failures carry their own status,
/// code, message and `Retry-After`; nothing upstream is included.
pub fn fail_response(fail: PickerFail) -> Response {
    match fail {
        PickerFail::App(err) => err.into_response(),
        PickerFail::Fixed {
            status,
            code,
            message,
            retry_after,
        } => {
            let body = serde_json::json!({ "error": { "code": code, "message": message } });
            let mut response = (status, Json(body)).into_response();
            if let Some(wait) = retry_after
                && let Ok(value) = HeaderValue::from_str(&wait.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
    }
}

fn respond<T: serde::Serialize>(result: Result<T, PickerFail>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(fail) => fail_response(fail),
    }
}

fn caller<'a>(state: &'a AppState, user: &'a AuthUser) -> Caller<'a> {
    Caller {
        pool: &state.pool,
        key: &state.credentials_key,
        user_id: &user.id,
    }
}

/// `GET /api/v1/credentials/:id/harbor-projects`. Credential owner only.
pub async fn harbor_projects(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<ListParams>,
) -> Response {
    let query = params.into();
    respond(
        state
            .pickers
            .harbor_projects(&caller(&state, &user), &id, &query)
            .await,
    )
}

/// `GET /api/v1/credentials/:id/harbor-projects/:project/repositories`. Credential owner only.
pub async fn harbor_repositories(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, project)): Path<(String, String)>,
    Query(params): Query<ListParams>,
) -> Response {
    let query = params.into();
    respond(
        state
            .pickers
            .harbor_repositories(&caller(&state, &user), &id, &project, &query)
            .await,
    )
}

/// `GET /api/v1/credentials/:id/github-repositories`. Credential owner only.
pub async fn github_repositories(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<ListParams>,
) -> Response {
    let query = params.into();
    respond(
        state
            .pickers
            .github_repositories(&caller(&state, &user), &id, &query)
            .await,
    )
}

/// `GET /api/v1/credentials/:id/source-suggestion`. Owner of both credentials.
pub async fn source_suggestion(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<SuggestionParams>,
) -> Response {
    let query = SuggestionQuery {
        project: params.project,
        repository: params.repository,
        github_cred_id: params.github_cred_id,
    };
    respond(
        state
            .pickers
            .source_suggestion(&caller(&state, &user), &id, &query)
            .await,
    )
}

/// `GET /api/v1/pickers/hidden`. The caller's own items only.
pub async fn list_hidden(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<HiddenParams>,
) -> Result<Json<pickers::HiddenPage>, AppError> {
    let query = HiddenQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        source: params.source,
    };
    Ok(Json(
        pickers::list_hidden(&state.pool, &user.id, &query).await?,
    ))
}

/// `POST /api/v1/pickers/hidden`. `201` when hidden now, `200` when already hidden.
pub async fn hide(
    State(state): State<AppState>,
    user: AuthUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let request: HideRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))?;
    let (item, created) =
        pickers::hide(&state.pool, &user.id, request, state.allow_private_harbor).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(item)).into_response())
}

/// `DELETE /api/v1/pickers/hidden/:id`. Returns `204`. Another user's item is `404`.
pub async fn restore(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    pickers::restore(&state.pool, &user.id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
