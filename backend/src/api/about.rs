//! `GET /api/v1/about` (`specs/api.md`, About). The handler takes `AuthUser`, so a missing or
//! invalid session is `401`.

use axum::{Json, extract::State};

use crate::api::state::AppState;
use crate::services::about::About;
use crate::services::sessions::AuthUser;

/// The dockward version and the bundled Trivy and Grype versions, read at startup. A scanner
/// version that could not be read is `null`.
pub async fn get(State(state): State<AppState>, _user: AuthUser) -> Json<About> {
    Json((*state.about).clone())
}
