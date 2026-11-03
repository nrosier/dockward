//! Credential routes (`specs/api.md`, Credentials). Every handler takes `AuthUser`,
//! so a missing or invalid session returns `401`. Ownership is enforced in the
//! service, so another user's credential is `404`.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::credential_probe::{self, HarborProbe, OutboundHarborProbe};
use crate::services::credentials::{self, Credential, CredentialPatch, ListQuery, NewCredential};
use crate::services::pagination::Page;
use crate::services::sessions::AuthUser;

/// Raw query values for `GET /api/v1/credentials`.
#[derive(Debug, Deserialize)]
pub struct CredentialListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub service_type: Option<String>,
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

/// `GET /api/v1/credentials`. `scope=all` is honored for admins only.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<CredentialListParams>,
) -> Result<Json<Page<Credential>>, AppError> {
    let all_users = match params.scope.as_deref() {
        None => false,
        Some("all") if user.role == Role::Admin => true,
        Some("all") => return Err(AppError::Forbidden),
        Some(_) => {
            return Err(AppError::InvalidRequest("scope must be all.".to_owned()));
        }
    };
    let query = ListQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        service_type: params.service_type,
        all_users,
    };
    Ok(Json(
        credentials::list(&state.pool, &user.id, &query).await?,
    ))
}

/// `POST /api/v1/credentials`. Returns `201`.
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let input: NewCredential = parse_body(&body)?;
    let actor = actor_of(&user);
    let created = credentials::create(
        &state.pool,
        &state.credentials_key,
        &actor,
        &user.id,
        input,
        state.allow_private_harbor,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// `PUT /api/v1/credentials/:id`. Owner only.
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Credential>, AppError> {
    let patch: CredentialPatch = parse_body(&body)?;
    let actor = actor_of(&user);
    let updated = credentials::update(
        &state.pool,
        &state.credentials_key,
        &actor,
        &user.id,
        &id,
        patch,
        state.allow_private_harbor,
    )
    .await?;
    Ok(Json(updated))
}

/// `DELETE /api/v1/credentials/:id`. Returns `204`. Owner only.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let actor = actor_of(&user);
    credentials::delete(&state.pool, &actor, &user.id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/credentials/:id/test`. Owner only. Runs the Harbor robot check
/// from the server. GitHub probes need a repository, which this route does not
/// receive, so a GitHub credential is refused with `422` until that input is
/// decided (see the closing comment on the issue).
pub async fn test(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = credentials::load_owned(&state.pool, &user.id, &id).await?;
    if row.service_type != credentials::SERVICE_HARBOR {
        return Err(AppError::ValidationFailed(
            "the GitHub probe needs a repository, which this route does not take yet.".to_owned(),
        ));
    }
    let probe = OutboundHarborProbe::new(state.allow_private_harbor)?;
    let check = run_harbor_probe(&state, &probe, &row).await?;
    let ok = check.ok;
    Ok(Json(serde_json::json!({ "ok": ok, "checks": [check] })))
}

/// Runs the probe for one stored Harbor credential. The decrypted secret lives only
/// in the local buffer and is never logged or returned.
pub async fn run_harbor_probe<P: HarborProbe>(
    state: &AppState,
    probe: &P,
    row: &crate::db::credentials::CredentialRow,
) -> Result<credential_probe::Check, AppError> {
    let base_text = row.base_url.as_deref().ok_or(AppError::InternalError)?;
    let base = reqwest::Url::parse(base_text).map_err(|_| AppError::InternalError)?;
    let username = row.username.as_deref().ok_or(AppError::InternalError)?;
    let secret = credentials::decrypt_token(&state.credentials_key, row)?;
    let status = probe.users_current(&base, username, &secret).await?;
    Ok(credential_probe::harbor_check(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::credentials::CredentialRow;

    /// A probe that returns a fixed status, so each Harbor response can be checked
    /// without a socket. The status values are the recorded Harbor responses.
    struct FixedStatus(u16);

    impl HarborProbe for FixedStatus {
        async fn users_current(
            &self,
            _base: &reqwest::Url,
            _username: &str,
            _secret: &[u8],
        ) -> Result<u16, AppError> {
            Ok(self.0)
        }

        async fn artifacts_status(
            &self,
            _base: &reqwest::Url,
            _username: &str,
            _secret: &[u8],
            _project: &str,
            _repository: &str,
        ) -> Result<u16, AppError> {
            Ok(self.0)
        }
    }

    /// A stored Harbor row whose token is encrypted under `key`, as the service
    /// writes it. The plaintext is a fixed fake value.
    fn row_with_token(key: &crate::auth::crypto::DerivedKey) -> CredentialRow {
        let encrypted = crate::auth::crypto::encrypt(
            key,
            &crate::auth::crypto::aad("user_credentials", "encrypted_token", "cred-1"),
            b"test-robot-secret-value",
        )
        .unwrap();
        CredentialRow {
            id: "cred-1".to_owned(),
            service_type: "harbor".to_owned(),
            label: "h".to_owned(),
            base_url: Some("https://harbor.example.com".to_owned()),
            username: Some("robot$harborgate".to_owned()),
            encrypted_token: encrypted,
            expires_at: None,
            created_at: None,
        }
    }

    #[tokio::test]
    async fn credential_row_debug_hides_the_ciphertext() {
        let state = test_state("debug").await;
        let row = row_with_token(&state.credentials_key);
        assert!(!format!("{row:?}").contains(&row.encrypted_token));
    }

    #[tokio::test]
    async fn recorded_harbor_statuses_map_to_checks() {
        // 412 is a working robot; 401 is wrong, disabled, or expired; 200 is a human.
        let state = test_state("probe").await;
        let row = row_with_token(&state.credentials_key);
        for (status, ok) in [(412u16, true), (401, false), (200, false), (503, false)] {
            let check = run_harbor_probe(&state, &FixedStatus(status), &row)
                .await
                .unwrap();
            assert_eq!(check.ok, ok, "status {status}");
            assert_eq!(check.name, "harbor_robot");
        }
    }

    async fn test_state(name: &str) -> AppState {
        let root =
            crate::config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .unwrap();
        // The probe reads the credentials key only. The pool is not used here.
        let dir = std::env::temp_dir().join(format!(
            "harborgate-api-creds-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        AppState {
            pool,
            session_key: std::sync::Arc::new(crate::auth::crypto::session_key(&root).unwrap()),
            csrf_key: std::sync::Arc::new(crate::auth::crypto::csrf_key(&root).unwrap()),
            public_url: "https://harborgate.example.com".to_owned(),
            login_throttle: crate::services::throttle::LoginThrottle::new(),
            login_limiter: crate::api::hardening::RateLimiter::new(
                10,
                std::time::Duration::from_secs(60),
            ),
            credentials_key: std::sync::Arc::new(
                crate::auth::crypto::credentials_key(&root).unwrap(),
            ),
            allow_private_oidc: false,
            allow_private_harbor: false,
            jwks: std::sync::Arc::new(crate::services::oidc_jwt::JwksCache::new()),
        }
    }
}
