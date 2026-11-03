//! Authentication extractor and the logout routes. Sources: `specs/api.md` (Auth),
//! `specs/security.md` (Sessions).

use axum::{
    extract::{FromRequestParts, State},
    http::{StatusCode, header::SET_COOKIE, request::Parts},
    response::{IntoResponse, Response},
};

use crate::api::state::AppState;
use crate::auth::session::{self, SESSION_COOKIE};
use crate::error::AppError;
use crate::services::{sessions, sessions::AuthUser};

/// Extracts the authenticated user from the session cookie. Any failure is `401`
/// `unauthenticated`, so an expired, forged, or revoked token reveals nothing else.
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = session::read_cookie(&parts.headers, SESSION_COOKIE)
            .ok_or(AppError::Unauthenticated)?;
        let now = session::now_unix()?;
        sessions::authenticate(&state.pool, &state.session_key, token, now).await
    }
}

/// Requires an `admin` session. Role is read from the database on this request.
pub struct AdminUser(pub AuthUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        match user.role {
            crate::models::role::Role::Admin => Ok(AdminUser(user)),
            crate::models::role::Role::User => Err(AppError::Forbidden),
        }
    }
}

/// `POST /api/v1/auth/logout`. Clears the browser cookie. The JWT stays valid
/// until `exp` (`specs/security.md`).
pub async fn logout(_user: AuthUser) -> Response {
    cleared(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/auth/logout-all`. Increments `token_version`, which revokes every
/// session of the user, and clears the browser cookie.
pub async fn logout_all(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Response, AppError> {
    sessions::revoke_all(&state.pool, &user.id).await?;
    Ok(cleared(StatusCode::NO_CONTENT))
}

fn cleared(status: StatusCode) -> Response {
    let mut response = status.into_response();
    if let Ok(value) = session::clear_cookie().parse() {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}
