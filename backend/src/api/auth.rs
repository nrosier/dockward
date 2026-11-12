//! Authentication extractor and the logout routes. Sources: `specs/api.md` (Auth),
//! `specs/security.md` (Sessions).

use std::fmt;

use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{HeaderMap, StatusCode, header::SET_COOKIE, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::api::hardening::{ClientIp, too_many_requests};
use crate::api::state::AppState;
use crate::auth::csrf;
use crate::auth::session::{self, SESSION_COOKIE};
use crate::error::AppError;
use crate::models::user::User;
use crate::services::auth as local_auth;
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

const REDACTED: &str = "<redacted>";

#[derive(Deserialize)]
pub struct SetupBody {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
}

impl fmt::Debug for SetupBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupBody")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &REDACTED)
            .finish()
    }
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for LoginBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginBody")
            .field("username", &self.username)
            .field("password", &REDACTED)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub user: User,
}

#[derive(Debug, Serialize)]
pub struct SetupStatus {
    pub setup_required: bool,
    pub oidc_enabled: bool,
}

/// Parses a JSON body into `T`. A malformed body becomes `400 invalid_request`
/// with the standard envelope.
fn parse_body<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}

/// Builds a response that sets the session and CSRF cookies for `user_id`.
pub fn session_response(
    state: &AppState,
    user: &crate::db::users::UserRow,
    status: StatusCode,
    body: UserResponse,
) -> Result<Response, AppError> {
    let now = session::now_unix()?;
    let role = crate::models::role::Role::parse(&user.role).ok_or(AppError::InternalError)?;
    let token = session::issue(
        &state.session_key,
        &user.id,
        role.as_str(),
        user.token_version,
        now,
    )?;
    let csrf_value = csrf::issue(&state.csrf_key)?;
    let mut response = (status, Json(body)).into_response();
    for cookie in [session::set_cookie(&token), csrf::set_cookie(&csrf_value)] {
        let value = cookie.parse().map_err(|_| AppError::InternalError)?;
        response.headers_mut().append(SET_COOKIE, value);
    }
    Ok(response)
}

/// `GET /api/v1/auth/setup-status`. Public. Reports whether first-run setup is open and
/// whether OIDC sign-in is fully configured.
pub async fn setup_status(State(state): State<AppState>) -> Result<Json<SetupStatus>, AppError> {
    let setup_required = local_auth::setup_required(&state.pool).await?;
    let oidc_enabled = crate::services::oidc::load_settings(&state.pool)
        .await?
        .is_complete();
    Ok(Json(SetupStatus {
        setup_required,
        oidc_enabled,
    }))
}

/// `POST /api/v1/auth/setup`. Public, same-origin only. Creates the first local admin
/// and signs them in. Closed for good once any user exists.
pub async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<Response, AppError> {
    local_auth::check_same_origin(&headers, &state.public_url)?;
    let body: SetupBody = parse_body(&bytes)?;
    let username = body.username.trim();
    if username.is_empty() {
        return Err(AppError::ValidationFailed(
            "Username is required.".to_owned(),
        ));
    }
    let id = local_auth::create_first_admin(
        &state.pool,
        username,
        body.email.as_deref(),
        &body.password,
    )
    .await?;
    let user = crate::db::users::find_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::InternalError)?;
    let view = User::try_from(user.clone())?;
    session_response(
        &state,
        &user,
        StatusCode::CREATED,
        UserResponse { user: view },
    )
}

/// `POST /api/v1/auth/login`. Public, same-origin only. Failures are one generic
/// `401 invalid_credentials`.
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    bytes: axum::body::Bytes,
) -> Result<Response, AppError> {
    local_auth::check_same_origin(&headers, &state.public_url)?;
    let body: LoginBody = parse_body(&bytes)?;
    let ip_text = ip.to_string();
    let now = state.login_throttle.now();
    // The per-IP rate limit runs first, so a flood cannot reach the password check.
    if let Err(retry_after) = state.login_limiter.check(&ip_text, now) {
        return Ok(too_many_requests(retry_after));
    }
    // A pair inside its delay is refused without a password check. The response is the
    // generic 401 that a wrong password gets, so throttle state is not revealed.
    if state
        .login_throttle
        .is_blocked(&body.username, &ip_text, now)
    {
        return Err(AppError::InvalidCredentials);
    }
    match local_auth::login(&state.pool, &body.username, &body.password).await {
        Ok(user) => {
            state
                .login_throttle
                .record_success(&body.username, &ip_text);
            // A user with TOTP on gets a challenge and no session. The session is issued by
            // `POST /api/v1/auth/totp/verify` after a valid code (`api/totp.rs`).
            if crate::services::totp::is_enabled(&state.pool, &user.id).await? {
                return totp_challenge(&state, &user);
            }
            let view = User::try_from(user.clone())?;
            session_response(&state, &user, StatusCode::OK, UserResponse { user: view })
        }
        Err(AppError::InvalidCredentials) => {
            state
                .login_throttle
                .record_failure(&body.username, &ip_text, now);
            Err(AppError::InvalidCredentials)
        }
        Err(other) => Err(other),
    }
}

/// The answer to a correct password for a user with TOTP on: `{"totp_required": true}` and the
/// short-lived challenge cookie. No session cookie and no CSRF cookie.
fn totp_challenge(
    state: &AppState,
    user: &crate::db::users::UserRow,
) -> Result<Response, AppError> {
    let token = crate::auth::totp::issue_challenge(
        &state.session_key,
        &user.id,
        user.token_version,
        session::now_unix()?,
    )?;
    let mut response = Json(serde_json::json!({ "totp_required": true })).into_response();
    let cookie = crate::auth::totp::challenge_set_cookie(&token)
        .parse()
        .map_err(|_| AppError::InternalError)?;
    response.headers_mut().append(SET_COOKIE, cookie);
    Ok(response)
}

#[derive(Deserialize)]
pub struct PasswordBody {
    pub current_password: String,
    pub new_password: String,
}

impl fmt::Debug for PasswordBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordBody")
            .field("current_password", &REDACTED)
            .field("new_password", &REDACTED)
            .finish()
    }
}

/// `GET /api/v1/account/me`. The signed-in user.
pub async fn account_me(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<UserResponse>, AppError> {
    let row = crate::db::users::find_by_id(&state.pool, &user.id)
        .await?
        .ok_or(AppError::Unauthenticated)?;
    Ok(Json(UserResponse {
        user: User::try_from(row)?,
    }))
}

/// `POST /api/v1/account/password`. Returns `204` with a fresh session cookie for
/// this session. Other sessions of the user are signed out.
pub async fn account_password(
    State(state): State<AppState>,
    user: AuthUser,
    bytes: axum::body::Bytes,
) -> Result<Response, AppError> {
    let body: PasswordBody = parse_body(&bytes)?;
    let row = crate::services::account::change_password(
        &state.pool,
        &user.id,
        &body.current_password,
        &body.new_password,
    )
    .await?;
    // Reissue the cookie with the new token_version so this session stays signed in.
    let mut response = session_response(
        &state,
        &row,
        StatusCode::NO_CONTENT,
        UserResponse {
            user: User::try_from(row.clone())?,
        },
    )?;
    *response.body_mut() = axum::body::Body::empty();
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test password built at run time, so no password literal sits in the source.
    fn runtime_password(label: &str) -> String {
        format!(
            "test-pw-{label}-{}",
            crate::services::ids::new_id().unwrap_or_default()
        )
    }

    #[test]
    fn setup_body_debug_redacts_password() {
        let setup_pw = runtime_password("setup");
        let body = SetupBody {
            username: "fake-admin".to_owned(),
            email: Some("fake@example.test".to_owned()),
            password: setup_pw.clone(),
        };
        let out = format!("{body:?}");
        assert!(!out.contains(&setup_pw), "password leaked: {out}");
        assert!(out.contains("fake-admin"), "username missing: {out}");
        assert!(out.contains("fake@example.test"), "email missing: {out}");
    }

    #[test]
    fn login_body_debug_redacts_password() {
        let login_pw = runtime_password("login");
        let body = LoginBody {
            username: "fake-user".to_owned(),
            password: login_pw.clone(),
        };
        let out = format!("{body:?}");
        assert!(!out.contains(&login_pw), "password leaked: {out}");
        assert!(out.contains("fake-user"), "username missing: {out}");
    }

    #[test]
    fn password_body_debug_redacts_both_passwords() {
        let current_pw = runtime_password("current");
        let new_pw = runtime_password("new");
        let body = PasswordBody {
            current_password: current_pw.clone(),
            new_password: new_pw.clone(),
        };
        let out = format!("{body:?}");
        assert!(!out.contains(&current_pw), "current password leaked: {out}");
        assert!(!out.contains(&new_pw), "new password leaked: {out}");
        assert!(out.contains("PasswordBody"), "struct name missing: {out}");
        assert!(
            out.contains("<redacted>"),
            "redaction marker missing: {out}"
        );
    }
}
