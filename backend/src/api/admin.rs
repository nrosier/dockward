//! Admin routes. Every handler takes `AdminUser`, so a non-admin gets `403` and a
//! missing or invalid session gets `401`.

use std::fmt;
use std::net::IpAddr;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::api::auth::AdminUser;
use crate::api::credentials::run_harbor_probe;
use crate::api::hardening::{ClientIp, ClientIpSource};
use crate::api::state::AppState;
use crate::auth::session;
use crate::db::credentials as credential_rows;
use crate::db::credentials::CredentialRow;
use crate::db::mappings as mapping_rows;
use crate::error::AppError;
use crate::models::role::Role;
use crate::models::user::User;
use crate::services::audit::{self, AuditEntry, AuditQuery};
use crate::services::credential_probe::{
    self, GithubProbe, HarborProbe, OutboundGithubProbe, OutboundHarborProbe,
};
use crate::services::credentials;
use crate::services::health::{self, GithubAnswers, HealthReport};
use crate::services::pagination::Page;
use crate::services::users as user_service;

/// Raw query values for `GET /api/v1/admin/audit-log`.
#[derive(Debug, Deserialize)]
pub struct AuditLogParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub action: Option<String>,
    pub actor_user_id: Option<String>,
}

/// `GET /api/v1/admin/audit-log`. Paginated, with `action` and `actor_user_id` filters.
pub async fn audit_log(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(params): Query<AuditLogParams>,
) -> Result<Json<Page<AuditEntry>>, AppError> {
    let query = AuditQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        action: params.action,
        actor_user_id: params.actor_user_id,
    };
    Ok(Json(audit::list(&state.pool, &query).await?))
}

/// Body for `POST /api/v1/admin/users`. Local accounts only.
#[derive(Deserialize)]
pub struct CreateUserBody {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub role: String,
}

const REDACTED: &str = "<redacted>";

impl fmt::Debug for CreateUserBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateUserBody")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &REDACTED)
            .field("role", &self.role)
            .finish()
    }
}

/// Body for `PUT /api/v1/admin/users/:id/role`.
#[derive(Debug, Deserialize)]
pub struct RoleBody {
    pub role: String,
}

/// Parses a JSON body into `T`. A malformed body becomes `400 invalid_request`.
fn parse_body<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}

/// `GET /api/v1/admin/users`. Every user, oldest first.
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<User>>, AppError> {
    let rows = user_service::list(&state.pool).await?;
    let users = rows
        .into_iter()
        .map(User::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(users))
}

/// `POST /api/v1/admin/users`. Creates a local user. Returns `201`.
pub async fn create_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let body: CreateUserBody = parse_body(&body)?;
    let role = user_service::parse_role(&body.role)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    let id = user_service::create_local(
        &state.pool,
        &actor,
        &body.username,
        body.email.as_deref(),
        &body.password,
        role,
    )
    .await?;
    let row = crate::db::users::find_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::InternalError)?;
    Ok((StatusCode::CREATED, Json(User::try_from(row)?)).into_response())
}

/// `DELETE /api/v1/admin/users/:id`. Returns `204`, or `409` for the self and last-admin cases.
pub async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    user_service::delete_user(&state.pool, &actor, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/v1/admin/users/:id/role`. Returns the updated `User`.
pub async fn set_role(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<User>, AppError> {
    let body: RoleBody = parse_body(&body)?;
    let role: Role = user_service::parse_role(&body.role)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    user_service::change_role(&state.pool, &actor, &id, role).await?;
    let row = crate::db::users::find_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(User::try_from(row)?))
}

/// The `request` block of the health response: the caller's client IP and where it came
/// from (`specs/api.md`, Health). It shows only the caller's own address.
#[derive(Debug, Serialize)]
pub struct RequestInfo {
    pub client_ip: String,
    pub source: &'static str,
}

/// `GET /api/v1/admin/health` body: the report plus the caller's `request` block.
#[derive(Serialize)]
pub struct HealthBody {
    #[serde(flatten)]
    pub report: HealthReport,
    pub request: RequestInfo,
}

/// `GET /api/v1/admin/health`. Admin only. Runs the probes one after another.
/// Nothing is cached on the server.
pub async fn health(
    State(state): State<AppState>,
    _admin: AdminUser,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Extension(source): Extension<ClientIpSource>,
) -> Result<Json<HealthBody>, AppError> {
    let harbor = OutboundHarborProbe::new(state.allow_private_harbor)?;
    let github = OutboundGithubProbe::new()?;
    Ok(Json(
        health_body(&state, &harbor, &github, client_ip, source).await?,
    ))
}

/// Builds the health body from the given probes. Generic over the probes, so tests pass
/// fakes and make no network call.
pub async fn health_body<H: HarborProbe, G: GithubProbe>(
    state: &AppState,
    harbor: &H,
    github: &G,
    client_ip: IpAddr,
    source: ClientIpSource,
) -> Result<HealthBody, AppError> {
    let now = session::now_unix()?;
    let report = report(state, harbor, github, now).await?;
    Ok(HealthBody {
        report,
        request: RequestInfo {
            client_ip: client_ip.to_string(),
            source: source.as_str(),
        },
    })
}

/// Runs the Harbor and GitHub checks and the robot account list. Harbor gets one check
/// per Harbor credential. GitHub gets one check per mapping target, probed with that
/// mapping's GitHub credential. Probes run one after another.
pub async fn report<H: HarborProbe, G: GithubProbe>(
    state: &AppState,
    harbor: &H,
    github: &G,
    now: i64,
) -> Result<HealthReport, AppError> {
    let harbor_rows = credential_rows::all_harbor(&state.pool).await?;
    let mut harbor_checks = Vec::with_capacity(harbor_rows.len());
    let mut robot_accounts = Vec::with_capacity(harbor_rows.len());
    for row in &harbor_rows {
        let outcome = run_harbor_probe(state, harbor, row).await;
        harbor_checks.push(health::harbor_health(&row.id, &row.label, outcome)?);
        robot_accounts.push(health::robot_account(
            &row.id,
            &row.label,
            row.expires_at,
            now,
        )?);
    }

    let targets = mapping_rows::all_targets(&state.pool).await?;
    let mut github_checks = Vec::with_capacity(targets.len());
    for target in &targets {
        let cred = load_github_credential(state, target).await?;
        let token = credentials::decrypt_token(&state.credentials_key, &cred)?;
        let owner = target.github_owner.as_str();
        let repo = target.github_repo.as_str();
        let answers = GithubAnswers {
            repo: github
                .get(&credential_probe::github_repo_path(owner, repo), &token)
                .await,
            code_scanning: github
                .get(
                    &credential_probe::github_code_scanning_path(owner, repo),
                    &token,
                )
                .await,
            issues: github
                .get(&credential_probe::github_issues_path(owner, repo), &token)
                .await,
        };
        github_checks.push(health::github_health(
            &cred.id,
            &cred.label,
            owner,
            repo,
            answers,
        )?);
    }

    Ok(HealthReport {
        harbor: harbor_checks,
        github: github_checks,
        robot_accounts,
    })
}

/// Loads the GitHub credential a mapping target uses. The credential always belongs to
/// the mapping's owner, so the owner-scoped lookup is the right one.
async fn load_github_credential(
    state: &AppState,
    target: &mapping_rows::TargetRow,
) -> Result<CredentialRow, AppError> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|_| AppError::InternalError)?;
    credential_rows::find_owned(&mut conn, &target.user_id, &target.github_cred_id)
        .await?
        .ok_or(AppError::InternalError)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Fakes and seeding for the health tests. No socket is opened: the probes answer
    //! from fixed values, and the database is a fresh local file per test.

    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use sqlx::SqlitePool;

    use crate::api::hardening::RateLimiter;
    use crate::api::state::AppState;
    use crate::auth::crypto::{self, DerivedKey};
    use crate::config;
    use crate::db::credentials::{self as credential_rows, CredentialRow};
    use crate::db::mappings::{self as mapping_rows, MappingRow};
    use crate::error::AppError;
    use crate::services::credential_probe::{GithubProbe, GithubResponse, HarborProbe};

    /// A fake robot secret. It is written into the test database encrypted, and the
    /// health body must never contain it.
    pub const FAKE_ROBOT_TOKEN: &str = "test-robot-secret-value";
    /// A fake GitHub token, for the same check on the GitHub side.
    pub const FAKE_GITHUB_TOKEN: &str = "test-github-token-value";

    /// Harbor fake that answers one status for every credential.
    pub struct FixedHarbor(pub u16);

    impl HarborProbe for FixedHarbor {
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

    /// GitHub fake with the recorded answers: repository `200`, code scanning `404`
    /// "no analysis found", issues `403`. It records every path it was asked for.
    #[derive(Default)]
    pub struct FixedGithub {
        pub calls: Mutex<Vec<String>>,
    }

    impl GithubProbe for FixedGithub {
        async fn get(&self, path: &str, _token: &[u8]) -> Result<GithubResponse, AppError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(path.to_owned());
            }
            let response = if path.contains("code-scanning") {
                GithubResponse {
                    status: 404,
                    message: "no analysis found".to_owned(),
                    accepted_permissions: None,
                }
            } else if path.contains("/issues") {
                GithubResponse {
                    status: 403,
                    message: "Resource not accessible by personal access token".to_owned(),
                    accepted_permissions: Some("issues=read".to_owned()),
                }
            } else {
                GithubResponse {
                    status: 200,
                    message: String::new(),
                    accepted_permissions: None,
                }
            };
            Ok(response)
        }
    }

    /// Test root key: 32 zero bytes, base64. Test value only.
    const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// The credentials key, derived the same way the app derives it.
    pub fn credentials_key() -> DerivedKey {
        let root = config::parse_encryption_key(ROOT).unwrap();
        crypto::credentials_key(&root).unwrap()
    }

    /// A fresh migrated database under a per-test directory, and the state built on it.
    pub async fn test_state(name: &str) -> (AppState, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "harborgate-admin-health-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        let root = config::parse_encryption_key(ROOT).unwrap();
        let state = AppState {
            pool,
            session_key: Arc::new(crypto::session_key(&root).unwrap()),
            csrf_key: Arc::new(crypto::csrf_key(&root).unwrap()),
            public_url: "https://harborgate.example.com".to_owned(),
            login_throttle: crate::services::throttle::LoginThrottle::new(),
            login_limiter: RateLimiter::new(10, std::time::Duration::from_secs(60)),
            credentials_key: Arc::new(crypto::credentials_key(&root).unwrap()),
            allow_private_oidc: false,
            allow_private_harbor: false,
            jwks: Arc::new(crate::services::oidc_jwt::JwksCache::new()),
            webhook_token_limiter: crate::api::webhooks::new_token_limiter(),
            webhook_failure_limiter: crate::api::webhooks::new_failure_limiter(),
        };
        (state, dir)
    }

    /// Inserts a local user with a placeholder hash. No login happens in these tests.
    pub async fn seed_user(pool: &SqlitePool, id: &str, role: &str) {
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, id, id, None, "not-a-real-hash", role)
            .await
            .unwrap();
    }

    /// Inserts a Harbor credential whose token is encrypted under the credentials key.
    pub async fn seed_harbor(
        pool: &SqlitePool,
        user_id: &str,
        id: &str,
        label: &str,
        expires_at: Option<i64>,
    ) {
        let encrypted = encrypt(id, FAKE_ROBOT_TOKEN);
        let row = CredentialRow {
            id: id.to_owned(),
            service_type: "harbor".to_owned(),
            label: label.to_owned(),
            base_url: Some("https://harbor.example.com".to_owned()),
            username: Some("robot$harborgate".to_owned()),
            encrypted_token: encrypted,
            expires_at,
            created_at: None,
        };
        let mut conn = pool.acquire().await.unwrap();
        credential_rows::insert(&mut conn, &row, user_id)
            .await
            .unwrap();
    }

    /// Inserts a GitHub credential whose token is encrypted under the credentials key.
    pub async fn seed_github(pool: &SqlitePool, user_id: &str, id: &str, label: &str) {
        let row = CredentialRow {
            id: id.to_owned(),
            service_type: "github".to_owned(),
            label: label.to_owned(),
            base_url: None,
            username: None,
            encrypted_token: encrypt(id, FAKE_GITHUB_TOKEN),
            expires_at: None,
            created_at: None,
        };
        let mut conn = pool.acquire().await.unwrap();
        credential_rows::insert(&mut conn, &row, user_id)
            .await
            .unwrap();
    }

    /// Inserts a mapping from `harbor_cred` to `github_cred` for one GitHub target.
    /// The Harbor repository is named after the mapping, so each mapping is unique.
    pub async fn seed_mapping(
        pool: &SqlitePool,
        user_id: &str,
        mapping_id: &str,
        harbor_cred: &str,
        github_cred: &str,
        github_owner: &str,
        github_repo: &str,
    ) {
        let row = MappingRow {
            id: mapping_id.to_owned(),
            user_id: user_id.to_owned(),
            harbor_cred_id: harbor_cred.to_owned(),
            github_cred_id: github_cred.to_owned(),
            harbor_base_url: "https://harbor.example.com".to_owned(),
            harbor_project: "proj".to_owned(),
            harbor_repository: mapping_id.to_owned(),
            github_owner: github_owner.to_owned(),
            github_repo: github_repo.to_owned(),
            webhook_token_hash: format!("hash-token-{mapping_id}"),
            webhook_auth_secret_hash: format!("hash-secret-{mapping_id}"),
            auto_create_issues: None,
            min_issue_severity: None,
            default_branch: "main".to_owned(),
            created_at: None,
        };
        let mut conn = pool.acquire().await.unwrap();
        mapping_rows::insert(&mut conn, &row).await.unwrap();
    }

    fn encrypt(id: &str, token: &str) -> String {
        let aad = crypto::aad("user_credentials", "encrypted_token", id);
        crypto::encrypt(&credentials_key(), &aad, token.as_bytes()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sends one `GET /api/v1/admin/health` through the full app router with the given
    /// session token. The router is the real one, so the admin check is the real check.
    async fn get_health(state: crate::api::state::AppState, cookie: Option<&str>) -> (u16, String) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::Request;
        use tower::ServiceExt;

        let mut builder = Request::builder().uri("/api/v1/admin/health");
        if let Some(token) = cookie {
            builder = builder.header(
                "cookie",
                format!("{}={token}", crate::auth::session::SESSION_COOKIE),
            );
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))));
        let response = crate::app(Vec::new(), state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Issues a session token for a seeded user, as login does.
    fn session_for(state: &crate::api::state::AppState, user_id: &str, role: &str) -> String {
        let now = crate::auth::session::now_unix().unwrap();
        crate::auth::session::issue(&state.session_key, user_id, role, 0, now).unwrap()
    }

    /// The health route returns `401` with no session, `403` for a regular user, and
    /// `200` for an admin. No credential is seeded, so no probe makes a request.
    #[tokio::test]
    async fn health_is_admin_only() {
        use crate::api::admin::test_support as fake;

        let (state, dir) = fake::test_state("health-admin-only").await;
        fake::seed_user(&state.pool, "u-admin", "admin").await;
        fake::seed_user(&state.pool, "u-user", "user").await;
        let admin_token = session_for(&state, "u-admin", "admin");
        let user_token = session_for(&state, "u-user", "user");

        let (anonymous, _) = get_health(state.clone(), None).await;
        let (regular, _) = get_health(state.clone(), Some(&user_token)).await;
        let (admin, body) = get_health(state.clone(), Some(&admin_token)).await;
        state.pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anonymous, 401);
        assert_eq!(regular, 403);
        assert_eq!(admin, 200, "{body}");
        assert!(body.contains("\"request\""), "{body}");
        assert!(body.contains("\"source\""), "{body}");
    }

    /// The health body never contains a stored token. Harbor and GitHub credentials are
    /// seeded with known fake tokens, and the serialized body is checked for both.
    #[tokio::test]
    async fn health_body_contains_no_token() {
        use crate::api::admin::test_support as fake;
        use std::net::IpAddr;

        let (state, dir) = fake::test_state("health-no-token").await;
        fake::seed_user(&state.pool, "u-a", "user").await;
        fake::seed_harbor(&state.pool, "u-a", "h-a", "harbor", Some(4_000_000_000)).await;
        fake::seed_github(&state.pool, "u-a", "g-a", "github").await;
        fake::seed_mapping(&state.pool, "u-a", "m-a", "h-a", "g-a", "octo", "app").await;

        let body = health_body(
            &state,
            &fake::FixedHarbor(412),
            &fake::FixedGithub::default(),
            "203.0.113.9".parse::<IpAddr>().unwrap(),
            ClientIpSource::Peer,
        )
        .await
        .unwrap();
        let json = serde_json::to_string(&body).unwrap();
        state.pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!json.contains(fake::FAKE_ROBOT_TOKEN), "{json}");
        assert!(!json.contains(fake::FAKE_GITHUB_TOKEN), "{json}");
        assert!(json.contains("\"client_ip\":\"203.0.113.9\""), "{json}");
        assert!(json.contains("\"source\":\"peer\""), "{json}");
    }

    #[test]
    fn create_user_body_debug_redacts_password() {
        let body = CreateUserBody {
            username: "fake-new-user".to_owned(),
            email: Some("new@example.test".to_owned()),
            password: "FAKE_PASSWORD_CREATE_1".to_owned(),
            role: "user".to_owned(),
        };
        let out = format!("{body:?}");
        assert!(
            !out.contains("FAKE_PASSWORD_CREATE_1"),
            "password leaked: {out}"
        );
        assert!(out.contains("fake-new-user"), "username missing: {out}");
        assert!(out.contains("new@example.test"), "email missing: {out}");
        assert!(out.contains("user"), "role missing: {out}");
    }
}
