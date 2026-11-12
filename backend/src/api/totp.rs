//! TOTP routes (#341): the account enrolment routes, the sign-in code step and the admin reset.
//! Sources: `specs/api.md` (Auth, Account, Admin), `specs/security.md` ("Two-factor sign-in
//! (TOTP)"). A code, a secret or a recovery code is never logged and never part of an error.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::fmt;

use crate::api::auth::{AdminUser, UserResponse, session_response};
use crate::api::hardening::{ClientIp, too_many_requests};
use crate::api::state::AppState;
use crate::auth::session::{self, read_cookie};
use crate::auth::totp as codes;
use crate::error::AppError;
use crate::models::user::User;
use crate::services::audit::Actor;
use crate::services::sessions::AuthUser;
use crate::services::{auth as local_auth, totp};

/// Seconds a locked account waits: the window of `AppState::totp_limiter` (15 minutes).
const LOCKOUT_RETRY_SECS: u64 = 15 * 60;

#[derive(Deserialize)]
pub struct CodeBody {
    pub code: String,
}

impl fmt::Debug for CodeBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeBody")
            .field("code", &"<redacted>")
            .finish()
    }
}

fn parse_body(bytes: &[u8]) -> Result<CodeBody, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}

fn actor_of(user: &AuthUser) -> Actor {
    Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    }
}

/// Counts one wrong code for `user_id`. The fifth wrong code in the window locks the account
/// and writes the `user.totp_lockout` audit row, once.
async fn record_wrong_code(state: &AppState, actor: &Actor) -> Result<(), AppError> {
    let Some(user_id) = actor.user_id.as_deref() else {
        return Ok(());
    };
    let now = state.login_throttle.now();
    let counted = state.totp_limiter.check(user_id, now).is_ok();
    if counted && state.totp_limiter.is_exhausted(user_id, now) {
        totp::record_lockout(&state.pool, actor, totp::LOCKOUT_FAILURES).await?;
    }
    Ok(())
}

/// `GET /api/v1/account/totp`. Whether TOTP is on for the caller. Nothing else.
pub async fn status(State(state): State<AppState>, user: AuthUser) -> Result<Response, AppError> {
    let enabled = totp::is_enabled(&state.pool, &user.id).await?;
    Ok(Json(json!({ "enabled": enabled })).into_response())
}

/// `POST /api/v1/account/totp/enrol`. Returns the secret and the otpauth URI, once. The secret
/// is stored sealed and disabled until `confirm`. `403` for an OIDC account, `409` when TOTP is
/// already on.
pub async fn enrol(State(state): State<AppState>, user: AuthUser) -> Result<Response, AppError> {
    let row = crate::db::users::find_by_id(&state.pool, &user.id)
        .await?
        .ok_or(AppError::Unauthenticated)?;
    let enrolment = totp::enrol(&state.pool, &state.credentials_key, &row).await?;
    Ok(Json(json!({
        "secret": enrolment.secret,
        "otpauth_uri": enrolment.otpauth_uri,
    }))
    .into_response())
}

/// `POST /api/v1/account/totp/confirm` with `{"code"}`. A valid current code turns TOTP on and
/// returns the recovery codes, once. A wrong code is `422 validation_failed`.
pub async fn confirm(
    State(state): State<AppState>,
    user: AuthUser,
    bytes: axum::body::Bytes,
) -> Result<Response, AppError> {
    let body = parse_body(&bytes)?;
    let actor = actor_of(&user);
    let now = state.login_throttle.now();
    if state.totp_limiter.is_exhausted(&user.id, now) {
        return Ok(too_many_requests(LOCKOUT_RETRY_SECS));
    }
    match totp::confirm(
        &state.pool,
        &state.credentials_key,
        &actor,
        &body.code,
        session::now_unix()?,
    )
    .await
    {
        Ok(recovery_codes) => Ok(Json(json!({ "recovery_codes": recovery_codes })).into_response()),
        Err(err @ AppError::ValidationFailed(_)) => {
            record_wrong_code(&state, &actor).await?;
            Err(err)
        }
        Err(other) => Err(other),
    }
}

/// `POST /api/v1/account/totp/disable` with `{"code"}`. Needs a valid current code.
pub async fn disable(
    State(state): State<AppState>,
    user: AuthUser,
    bytes: axum::body::Bytes,
) -> Result<Response, AppError> {
    let body = parse_body(&bytes)?;
    let actor = actor_of(&user);
    let now = state.login_throttle.now();
    if state.totp_limiter.is_exhausted(&user.id, now) {
        return Ok(too_many_requests(LOCKOUT_RETRY_SECS));
    }
    match totp::disable(
        &state.pool,
        &state.credentials_key,
        &actor,
        &body.code,
        session::now_unix()?,
    )
    .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT.into_response()),
        Err(err @ AppError::ValidationFailed(_)) => {
            record_wrong_code(&state, &actor).await?;
            Err(err)
        }
        Err(other) => Err(other),
    }
}

/// `POST /api/v1/auth/totp/verify` with `{"code"}` and the challenge cookie. Public, same-origin
/// only. Every failure is the `401 invalid_credentials` a wrong password gets: a missing,
/// forged or expired challenge, an unknown user and a wrong code alike. A locked account gets
/// `429` with `Retry-After`. The code may be a 6-digit TOTP code or a recovery code.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Extension(ClientIp(ip)): axum::extract::Extension<ClientIp>,
    bytes: axum::body::Bytes,
) -> Result<Response, AppError> {
    local_auth::check_same_origin(&headers, &state.public_url)?;
    let body = parse_body(&bytes)?;
    let ip_text = ip.to_string();
    let now = state.login_throttle.now();
    if let Err(retry_after) = state.login_limiter.check(&ip_text, now) {
        return Ok(too_many_requests(retry_after));
    }
    let unix = session::now_unix()?;
    let token =
        read_cookie(&headers, codes::CHALLENGE_COOKIE).ok_or(AppError::InvalidCredentials)?;
    let (user_id, version) = codes::verify_challenge(&state.session_key, token, unix)?;
    if state.totp_limiter.is_exhausted(&user_id, now) {
        return Ok(too_many_requests(LOCKOUT_RETRY_SECS));
    }
    let row = crate::db::users::find_by_id(&state.pool, &user_id)
        .await?
        .ok_or(AppError::InvalidCredentials)?;
    if row.token_version != version {
        return Err(AppError::InvalidCredentials);
    }
    let accepted = totp::verify_sign_in(
        &state.pool,
        &state.credentials_key,
        &user_id,
        &body.code,
        unix,
    )
    .await?;
    if !accepted {
        let actor = Actor {
            user_id: Some(row.id.clone()),
            username: row.username.clone(),
        };
        record_wrong_code(&state, &actor).await?;
        state
            .login_throttle
            .record_failure(&row.username, &ip_text, now);
        return Err(AppError::InvalidCredentials);
    }
    state.login_throttle.record_success(&row.username, &ip_text);
    let view = User::try_from(row.clone())?;
    let mut response = session_response(&state, &row, StatusCode::OK, UserResponse { user: view })?;
    let cleared = codes::challenge_clear_cookie()
        .parse()
        .map_err(|_| AppError::InternalError)?;
    response.headers_mut().append(SET_COOKIE, cleared);
    Ok(response)
}

/// `DELETE /api/v1/admin/users/:id/totp`. Clears the user's TOTP and recovery codes and audits
/// `user.totp_reset` with the user's id only. `404` for an unknown user.
pub async fn admin_reset(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    totp::admin_reset(&state.pool, &actor_of(&admin), &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, Response, StatusCode, header::SET_COOKIE};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use crate::auth::totp::{base32_decode, code_at, step_at};
    use crate::services::audit::Actor;
    use crate::tests::{LogSink, session_cookie, test_router, with_peer};
    use crate::{auth, config, services};

    const ORIGIN: &str = "https://dockward.example.com";

    struct Fx {
        router: Router,
        pool: sqlx::SqlitePool,
        dir: std::path::PathBuf,
        password: String,
        csrf: String,
    }

    fn key() -> auth::crypto::DerivedKey {
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        auth::crypto::credentials_key(&root).unwrap()
    }

    fn now() -> i64 {
        auth::session::now_unix().unwrap()
    }

    /// The code `ahead` steps from the current one. One step either side is accepted.
    fn code_for(secret_b32: &str, ahead: i64) -> String {
        code_at(&base32_decode(secret_b32).unwrap(), step_at(now()) + ahead).unwrap()
    }

    /// A router over a fresh database with local user `u1` (password known) and admin `a1`.
    async fn fx(name: &str) -> Fx {
        let (router, pool, dir) = test_router(name).await;
        let password = format!("test-pw-{}", services::ids::new_id().unwrap());
        let hash = auth::password::hash_password(&password).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, "u1", "test-user", None, &hash, "user")
            .await
            .unwrap();
        crate::db::users::insert_local(&mut conn, "a1", "test-admin", None, &hash, "admin")
            .await
            .unwrap();
        drop(conn);
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        Fx {
            router,
            pool,
            dir,
            password,
            csrf,
        }
    }

    impl Fx {
        fn cookie(&self, user: &str, role: &str) -> String {
            format!(
                "{}; {}={}",
                session_cookie(user, role, 0),
                auth::csrf::CSRF_COOKIE,
                self.csrf
            )
        }

        /// A session request. Returns the status, headers' cookies and the parsed body text.
        async fn call(
            &self,
            method: &str,
            uri: &str,
            cookie: &str,
            body: Value,
        ) -> (StatusCode, Value, String) {
            let request = with_peer(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .header("x-csrf-token", &self.csrf),
            )
            .body(Body::from(body.to_string()))
            .unwrap();
            let response = self.router.clone().oneshot(request).await.unwrap();
            read(response).await
        }

        /// A public sign-in request (same-origin, no CSRF token).
        async fn public(&self, uri: &str, cookie: Option<&str>, body: Value) -> Response<Body> {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("origin", ORIGIN)
                    .header("content-type", "application/json"),
            );
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            self.router
                .clone()
                .oneshot(builder.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap()
        }

        async fn login(&self, password: &str) -> Response<Body> {
            self.public(
                "/api/v1/auth/login",
                None,
                json!({"username": "test-user", "password": password}),
            )
            .await
        }

        /// Turns TOTP on for `u1` through the service. Returns the secret and recovery codes.
        async fn enable_totp(&self) -> (String, Vec<String>) {
            let row = crate::db::users::find_by_id(&self.pool, "u1")
                .await
                .unwrap()
                .unwrap();
            let enrolment = services::totp::enrol(&self.pool, &key(), &row)
                .await
                .unwrap();
            let actor = Actor {
                user_id: Some("u1".to_owned()),
                username: "test-user".to_owned(),
            };
            let codes = services::totp::confirm(
                &self.pool,
                &key(),
                &actor,
                &code_for(&enrolment.secret, 0),
                now(),
            )
            .await
            .unwrap();
            (enrolment.secret, codes)
        }

        async fn finish(self) {
            self.pool.close().await;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn read(response: Response<Body>) -> (StatusCode, Value, String) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::Null),
            text,
        )
    }

    fn set_cookie(response: &Response<Body>, name: &str) -> Option<String> {
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .find_map(|value| {
                let pair = value.to_str().ok()?.split(';').next()?;
                let (key, val) = pair.split_once('=')?;
                (key == name && !val.is_empty()).then(|| val.to_owned())
            })
    }

    fn challenge_cookie(response: &Response<Body>) -> String {
        format!(
            "{}={}",
            auth::totp::CHALLENGE_COOKIE,
            set_cookie(response, auth::totp::CHALLENGE_COOKIE).expect("a challenge cookie")
        )
    }

    #[tokio::test]
    async fn a_totp_user_gets_no_session_until_the_code_is_checked() {
        let fx = fx("totp-no-session").await;
        let (secret, _) = fx.enable_totp().await;

        let response = fx.login(&fx.password).await;
        let status = response.status();
        let session = set_cookie(&response, auth::session::SESSION_COOKIE);
        let csrf = set_cookie(&response, auth::csrf::CSRF_COOKIE);
        let challenge = challenge_cookie(&response);
        let (_, body, _) = read(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"totp_required": true}));
        assert!(session.is_none(), "a session was issued before the code");
        assert!(csrf.is_none(), "a CSRF cookie was issued before the code");

        // The challenge alone opens nothing.
        let (me, _, _) = fx
            .call("GET", "/api/v1/account/me", &challenge, Value::Null)
            .await;
        assert_eq!(me, StatusCode::UNAUTHORIZED);

        // A password-only account is unchanged: no TOTP, no challenge.
        let verified = fx
            .public(
                "/api/v1/auth/totp/verify",
                Some(&challenge),
                json!({"code": code_for(&secret, 1)}),
            )
            .await;
        assert_eq!(verified.status(), StatusCode::OK);
        assert!(set_cookie(&verified, auth::session::SESSION_COOKIE).is_some());
        fx.finish().await;
    }

    #[tokio::test]
    async fn wrong_code_has_the_same_shape_as_a_wrong_password() {
        let fx = fx("totp-same-shape").await;
        let (secret, _) = fx.enable_totp().await;

        let wrong_password = fx
            .login(&format!("not-the-password-{}", std::process::id()))
            .await;
        let (pw_status, pw_body, _) = read(wrong_password).await;

        let challenge = challenge_cookie(&fx.login(&fx.password).await);
        let wrong = ["000000", "111111", "222222"]
            .into_iter()
            .find(|c| (-1..=1).all(|d| code_for(&secret, d) != *c))
            .unwrap();
        let wrong_code = fx
            .public(
                "/api/v1/auth/totp/verify",
                Some(&challenge),
                json!({"code": wrong}),
            )
            .await;
        let no_session = set_cookie(&wrong_code, auth::session::SESSION_COOKIE).is_none();
        let (code_status, code_body, _) = read(wrong_code).await;

        // No challenge, a forged challenge and a malformed body look the same too.
        let (none_status, none_body, _) = read(
            fx.public("/api/v1/auth/totp/verify", None, json!({"code": wrong}))
                .await,
        )
        .await;
        let forged = format!("{}=forged.token.value", auth::totp::CHALLENGE_COOKIE);
        let (forged_status, forged_body, _) = read(
            fx.public(
                "/api/v1/auth/totp/verify",
                Some(&forged),
                json!({"code": wrong}),
            )
            .await,
        )
        .await;
        fx.finish().await;

        assert!(no_session);
        assert_eq!(pw_status, StatusCode::UNAUTHORIZED);
        assert_eq!(code_status, pw_status);
        assert_eq!(
            code_body, pw_body,
            "the wrong-code body differs from a wrong password"
        );
        assert_eq!((none_status, &none_body), (pw_status, &pw_body));
        assert_eq!((forged_status, &forged_body), (pw_status, &pw_body));
        assert_eq!(pw_body["error"]["code"], "invalid_credentials");
    }

    #[tokio::test]
    async fn correct_code_issues_a_session() {
        let fx = fx("totp-correct").await;
        let (secret, _) = fx.enable_totp().await;
        let challenge = challenge_cookie(&fx.login(&fx.password).await);

        let response = fx
            .public(
                "/api/v1/auth/totp/verify",
                Some(&challenge),
                json!({"code": code_for(&secret, 1)}),
            )
            .await;
        let status = response.status();
        let session = set_cookie(&response, auth::session::SESSION_COOKIE).unwrap();
        let csrf = set_cookie(&response, auth::csrf::CSRF_COOKIE);
        let cleared = response.headers().get_all(SET_COOKIE).iter().any(|v| {
            v.to_str().is_ok_and(|v| {
                v.starts_with(&format!("{}=; Max-Age=0", auth::totp::CHALLENGE_COOKIE))
            })
        });
        let (_, body, text) = read(response).await;

        let (me, me_body, _) = fx
            .call(
                "GET",
                "/api/v1/account/me",
                &format!("{}={session}", auth::session::SESSION_COOKIE),
                Value::Null,
            )
            .await;
        fx.finish().await;

        assert_eq!(status, StatusCode::OK);
        assert!(csrf.is_some());
        assert!(cleared, "the challenge cookie must be cleared");
        assert_eq!(body["user"]["username"], "test-user");
        assert!(!text.contains("password_hash"));
        assert_eq!(me, StatusCode::OK);
        assert_eq!(me_body["user"]["id"], "u1");
    }

    #[tokio::test]
    async fn repeated_wrong_codes_lock_the_account_and_audit_it() {
        let fx = fx("totp-lockout").await;
        let (secret, _) = fx.enable_totp().await;
        let challenge = challenge_cookie(&fx.login(&fx.password).await);
        let wrong = ["000000", "111111", "222222"]
            .into_iter()
            .find(|c| (-1..=1).all(|d| code_for(&secret, d) != *c))
            .unwrap();

        let mut statuses = Vec::new();
        for _ in 0..5 {
            let response = fx
                .public(
                    "/api/v1/auth/totp/verify",
                    Some(&challenge),
                    json!({"code": wrong}),
                )
                .await;
            statuses.push(response.status());
        }
        // Locked: even the right code is refused, with Retry-After.
        let locked = fx
            .public(
                "/api/v1/auth/totp/verify",
                Some(&challenge),
                json!({"code": code_for(&secret, 1)}),
            )
            .await;
        let locked_status = locked.status();
        let retry = locked.headers().get("retry-after").cloned();
        let no_session = set_cookie(&locked, auth::session::SESSION_COOKIE).is_none();

        let audit: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT action, target, details, actor_user_id FROM audit_log WHERE action = 'user.totp_lockout'",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        fx.finish().await;

        assert!(
            statuses.iter().all(|s| *s == StatusCode::UNAUTHORIZED),
            "{statuses:?}"
        );
        assert_eq!(locked_status, StatusCode::TOO_MANY_REQUESTS);
        assert!(retry.is_some(), "429 must carry Retry-After");
        assert!(no_session, "a locked account got a session");
        assert_eq!(
            audit.len(),
            1,
            "the lockout is audited once, not per refused request"
        );
        assert_eq!(audit[0].1, "user:u1");
        assert_eq!(audit[0].2.as_deref(), Some(r#"{"failures":5}"#));
        assert_eq!(audit[0].3.as_deref(), Some("u1"));
    }

    #[tokio::test]
    async fn oidc_user_sign_in_is_unchanged() {
        let fx = fx("totp-oidc").await;
        sqlx::query(
            "INSERT INTO users (id, username, role, auth_provider) VALUES ('o1', 'test-oidc', 'user', 'oidc')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        // A local password cannot sign an OIDC account in, with or without a TOTP step.
        let (login, body, _) = read(
            fx.public(
                "/api/v1/auth/login",
                None,
                json!({"username": "test-oidc", "password": fx.password}),
            )
            .await,
        )
        .await;
        // Its session works, and TOTP enrolment is not offered to it.
        let cookie = fx.cookie("o1", "user");
        let (enrol, _, _) = fx
            .call("POST", "/api/v1/account/totp/enrol", &cookie, Value::Null)
            .await;
        let (me, _, _) = fx
            .call("GET", "/api/v1/account/me", &cookie, Value::Null)
            .await;
        let (status, status_body, _) = fx
            .call("GET", "/api/v1/account/totp", &cookie, Value::Null)
            .await;
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        // A local user without TOTP signs in exactly as before.
        let plain = fx.login(&fx.password).await;
        let plain_status = plain.status();
        let plain_session = set_cookie(&plain, auth::session::SESSION_COOKIE).is_some();
        fx.finish().await;

        assert_eq!(login, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "invalid_credentials");
        assert_eq!(enrol, StatusCode::FORBIDDEN);
        assert_eq!(me, StatusCode::OK);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(status_body, json!({"enabled": false}));
        assert_eq!(rows, 0);
        assert_eq!(plain_status, StatusCode::OK);
        assert!(plain_session);
    }

    #[tokio::test]
    async fn the_secret_and_codes_are_absent_from_logs_and_responses() {
        let fx = fx("totp-secrets").await;
        let sink = LogSink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let cookie = fx.cookie("u1", "user");
        let admin = fx.cookie("a1", "admin");
        let mut after_enrol: Vec<String> = Vec::new();

        // 1. Enrolment returns the secret, once.
        let (status, enrol, enrol_text) = fx
            .call("POST", "/api/v1/account/totp/enrol", &cookie, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK);
        let secret = enrol["secret"].as_str().unwrap().to_owned();
        let uri = enrol["otpauth_uri"].as_str().unwrap().to_owned();
        assert!(uri.starts_with("otpauth://totp/Dockward:test-user?secret="));
        assert_eq!(base32_decode(&secret).unwrap().len(), 20);
        let stored: String =
            sqlx::query_scalar("SELECT secret_encrypted FROM totp_secrets WHERE user_id = 'u1'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert!(stored.starts_with("v1:") && !stored.contains(&secret));
        let _ = enrol_text;

        // 2. A wrong code does not enable. The right one does and returns the codes once.
        let wrong = ["000000", "111111", "222222"]
            .into_iter()
            .find(|c| (-1..=1).all(|d| code_for(&secret, d) != *c))
            .unwrap();
        let (bad, bad_body, bad_text) = fx
            .call(
                "POST",
                "/api/v1/account/totp/confirm",
                &cookie,
                json!({"code": wrong}),
            )
            .await;
        assert_eq!(bad, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(bad_body["error"]["code"], "validation_failed");
        after_enrol.push(bad_text);
        let (ok, confirm, confirm_text) = fx
            .call(
                "POST",
                "/api/v1/account/totp/confirm",
                &cookie,
                json!({"code": code_for(&secret, 0)}),
            )
            .await;
        assert_eq!(ok, StatusCode::OK);
        let codes: Vec<String> = confirm["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(codes.len(), 10);
        assert!(
            !confirm_text.contains(&secret),
            "confirm returned the secret again"
        );

        // 3. Everything after enrolment: status, me, sign-in, verify (wrong and right),
        //    a repeated enrol, the admin list and the audit log.
        for (method, uri, who) in [
            ("GET", "/api/v1/account/totp", &cookie),
            ("GET", "/api/v1/account/me", &cookie),
            ("POST", "/api/v1/account/totp/enrol", &cookie),
            ("GET", "/api/v1/admin/users", &admin),
            ("GET", "/api/v1/admin/audit-log", &admin),
        ] {
            after_enrol.push(fx.call(method, uri, who, Value::Null).await.2);
        }
        let login = fx.login(&fx.password).await;
        let challenge = challenge_cookie(&login);
        after_enrol.push(read(login).await.2);
        for code in [wrong.to_owned(), code_for(&secret, 1)] {
            let response = fx
                .public(
                    "/api/v1/auth/totp/verify",
                    Some(&challenge),
                    json!({"code": code}),
                )
                .await;
            after_enrol.push(read(response).await.2);
        }
        let reset = fx
            .call("DELETE", "/api/v1/admin/users/u1/totp", &admin, Value::Null)
            .await;
        assert_eq!(reset.0, StatusCode::NO_CONTENT);
        let denied = fx
            .call(
                "DELETE",
                "/api/v1/admin/users/u1/totp",
                &cookie,
                Value::Null,
            )
            .await;
        assert_eq!(denied.0, StatusCode::FORBIDDEN);
        after_enrol.push(denied.2);

        let audit: Vec<String> = sqlx::query_scalar(
            "SELECT COALESCE(actor_username, '') || ' ' || action || ' ' || target || ' ' || COALESCE(details, '') FROM audit_log",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
        let all_responses = after_enrol.join("\n");
        fx.finish().await;

        for leak in [&secret, &uri] {
            assert!(
                !all_responses.contains(leak.as_str()),
                "the secret appears in a later response"
            );
            assert!(
                !logs.contains(leak.as_str()),
                "the secret appears in the logs"
            );
        }
        let mut sensitive: Vec<String> = codes.clone();
        sensitive.extend(codes.iter().map(|c| c.replace('-', "")));
        sensitive.push(code_for(&secret, 1));
        sensitive.push(stored.clone());
        for needle in &sensitive {
            assert!(
                !all_responses.contains(needle.as_str()),
                "a code or ciphertext appears in a later response"
            );
            assert!(
                !logs.contains(needle.as_str()),
                "a code or ciphertext appears in the logs"
            );
            assert!(
                !audit.join("\n").contains(needle.as_str()),
                "a code or ciphertext appears in the audit log"
            );
        }
        assert!(
            !logs.contains(&fx_password_marker()),
            "a password appears in the logs"
        );
        assert!(audit.iter().any(|a| a.contains("user.totp_enable")));
        assert!(audit.iter().any(|a| a.contains("user.totp_reset user:u1")));
    }

    /// The test passwords all start with this marker, so one check covers them.
    fn fx_password_marker() -> String {
        "test-pw-".to_owned()
    }
}
