use std::time::Duration;

use std::sync::Arc;

use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::watch;

mod api;
#[allow(dead_code)] // Crypto helpers are used by the credential and backup paths in later issues.
mod auth;
mod config;
#[allow(dead_code)] // Pool is consumed by handlers and workers added in later issues.
mod db;
#[allow(dead_code)] // Used by handlers and services added in later issues.
mod error;
mod models;
mod services;
mod worker;

const BIND_ADDR: &str = "0.0.0.0:8080";

/// Upper bound on the graceful drain after a stop signal. It sits inside Docker's
/// default 10-second stop timeout, so `docker stop` exits well before SIGKILL.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health { status: "ok" })
}

pub(crate) fn app(trusted_proxies: Vec<config::Cidr>, state: api::state::AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/auth/setup-status", get(api::auth::setup_status))
        .route("/api/v1/auth/setup", post(api::auth::setup))
        .route("/api/v1/auth/login", post(api::auth::login))
        .route("/api/v1/account/me", get(api::auth::account_me))
        .route(
            "/api/v1/account/password",
            post(api::auth::account_password),
        )
        .route("/api/v1/auth/oidc/start", get(api::oidc::start))
        .route("/api/v1/auth/oidc/callback", get(api::oidc::callback))
        .route("/api/v1/auth/logout", post(api::auth::logout))
        .route("/api/v1/auth/logout-all", post(api::auth::logout_all))
        .route(
            "/api/v1/credentials",
            get(api::credentials::list).post(api::credentials::create),
        )
        .route(
            "/api/v1/credentials/{id}",
            axum::routing::put(api::credentials::update).delete(api::credentials::delete),
        )
        .route(
            "/api/v1/credentials/{id}/test",
            post(api::credentials::test),
        )
        .route(
            "/api/v1/mappings",
            get(api::mappings::list).post(api::mappings::create),
        )
        .route(
            "/api/v1/mappings/{id}",
            get(api::mappings::get).delete(api::mappings::delete),
        )
        .route(
            "/api/v1/mappings/{id}/rotate-webhook-token",
            post(api::mappings::rotate_webhook_token),
        )
        .route(
            "/api/v1/mappings/{id}/rotate-auth-secret",
            post(api::mappings::rotate_auth_secret),
        )
        .route("/api/v1/sync-jobs/{id}/retry", post(api::sync_jobs::retry))
        .route(
            "/api/v1/webhooks/harbor/{mapping_token}",
            post(api::webhooks::receive),
        )
        .route("/api/v1/admin/audit-log", get(api::admin::audit_log))
        .route(
            "/api/v1/admin/oidc",
            get(api::oidc::get_settings).put(api::oidc::put_settings),
        )
        .route(
            "/api/v1/admin/users",
            get(api::admin::list_users).post(api::admin::create_user),
        )
        .route(
            "/api/v1/admin/users/{id}",
            axum::routing::delete(api::admin::delete_user),
        )
        .route(
            "/api/v1/admin/users/{id}/role",
            axum::routing::put(api::admin::set_role),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::csrf::guard,
        ))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            api::hardening::TrustedProxies(std::sync::Arc::new(trusted_proxies)),
            api::hardening::resolve_client_ip,
        ))
        .layer(axum::middleware::from_fn(api::hardening::access_log))
        .layer(axum::middleware::from_fn(api::hardening::security_headers))
}

/// Resolves on the first SIGTERM or Ctrl+C.
async fn shutdown_signal(mut terminate: Signal) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Logs go to stdout. The access log records route templates, so tokens in paths stay out.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Refuse to start without a valid key or settings. This runs before the port is bound.
    let encryption_key = config::load_encryption_key()?;
    let settings = config::load_settings()?;
    let pool = db::open(&settings.data_dir)
        .await
        .map_err(|_| "could not open or migrate the database in HARBORGATE_DATA_DIR")?;
    let session_key = Arc::new(
        auth::crypto::session_key(&encryption_key)
            .map_err(|_| "could not derive the session key")?,
    );
    let csrf_key = Arc::new(
        auth::crypto::csrf_key(&encryption_key).map_err(|_| "could not derive the CSRF key")?,
    );
    let credentials_key = Arc::new(
        auth::crypto::credentials_key(&encryption_key)
            .map_err(|_| "could not derive the credentials key")?,
    );
    let state = api::state::AppState {
        pool,
        session_key,
        csrf_key,
        public_url: settings.public_url.clone(),
        login_throttle: services::throttle::LoginThrottle::new(),
        login_limiter: api::hardening::RateLimiter::new(10, Duration::from_secs(60)),
        credentials_key,
        allow_private_oidc: settings.allow_private_oidc,
        allow_private_harbor: settings.allow_private_harbor,
        jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
        webhook_token_limiter: api::webhooks::new_token_limiter(),
        webhook_failure_limiter: api::webhooks::new_failure_limiter(),
    };
    let terminate = signal(SignalKind::terminate())?;
    let listener = TcpListener::bind(BIND_ADDR).await?;

    // Jobs left `running` by a previous process go back to `queued` before the worker
    // starts (`specs/backend.md`, Durable job queue).
    let requeued = db::sync_jobs::requeue_running(&state.pool, worker::now_secs())
        .await
        .map_err(|_| "could not re-queue running sync jobs")?;
    if requeued > 0 {
        tracing::info!(requeued, "re-queued sync jobs left running at startup");
    }

    // The stop flag flips to true on the first signal. The server stops accepting
    // connections and drains in-flight requests. A separate timer caps the drain.
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal(terminate).await;
        let _ = stop_tx.send(true);
    });

    // The worker stops taking jobs on the same signal. A job it already took finishes.
    let worker_pool = state.pool.clone();
    let worker_stop = stop_rx.clone();
    let worker_task = tokio::spawn(async move {
        worker::run(worker_pool, Arc::new(worker::NoopHandler), worker_stop).await;
    });

    let mut graceful = stop_rx.clone();
    let router = app(settings.trusted_proxies.clone(), state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = graceful.wait_for(|stopped| *stopped).await;
    });
    let drain_limit = async move {
        let mut limit = stop_rx;
        let _ = limit.wait_for(|stopped| *stopped).await;
        tokio::time::sleep(DRAIN_TIMEOUT).await;
    };

    tokio::select! {
        result = serve => result?,
        _ = drain_limit => {}
    }
    // Give the worker its turn to finish the job it holds, within the drain limit.
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, worker_task).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admin audit route rejects a request with no session cookie with 401.
    #[tokio::test]
    async fn admin_audit_log_requires_a_session() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!("harborgate-app-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let session_key = Arc::new(auth::crypto::session_key(&root).unwrap());
        let csrf_key = Arc::new(auth::crypto::csrf_key(&root).unwrap());
        let state = api::state::AppState {
            pool: pool.clone(),
            session_key,
            csrf_key,
            public_url: "https://harborgate.example.com".to_owned(),
            login_throttle: services::throttle::LoginThrottle::new(),
            login_limiter: api::hardening::RateLimiter::new(10, Duration::from_secs(60)),
            credentials_key: Arc::new(auth::crypto::credentials_key(&root).unwrap()),
            allow_private_oidc: false,
            allow_private_harbor: false,
            jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
            webhook_token_limiter: api::webhooks::new_token_limiter(),
            webhook_failure_limiter: api::webhooks::new_failure_limiter(),
        };
        let response = app(Vec::new(), state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/audit-log")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A router over a fresh database, with the session and CSRF keys derived from
    /// the test key. Test values only.
    async fn test_router(name: &str) -> (Router, sqlx::SqlitePool, std::path::PathBuf) {
        test_router_with_throttle(name, services::throttle::LoginThrottle::new()).await
    }

    /// Like `test_router`, with the given login throttle (for example a frozen clock).
    async fn test_router_with_throttle(
        name: &str,
        login_throttle: services::throttle::LoginThrottle,
    ) -> (Router, sqlx::SqlitePool, std::path::PathBuf) {
        let (router, pool, dir, _) =
            test_router_with_limiters(name, login_throttle, api::webhooks::new_token_limiter())
                .await;
        (router, pool, dir)
    }

    /// The full test router. The caller keeps a handle on the webhook token limiter.
    /// `RateLimiter` clones share one map, so the handle sees what the router records.
    async fn test_router_with_limiters(
        name: &str,
        login_throttle: services::throttle::LoginThrottle,
        webhook_token_limiter: api::hardening::RateLimiter,
    ) -> (
        Router,
        sqlx::SqlitePool,
        std::path::PathBuf,
        api::hardening::RateLimiter,
    ) {
        let dir = std::env::temp_dir().join(format!("harborgate-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let handle = webhook_token_limiter.clone();
        let state = api::state::AppState {
            pool: pool.clone(),
            session_key: Arc::new(auth::crypto::session_key(&root).unwrap()),
            csrf_key: Arc::new(auth::crypto::csrf_key(&root).unwrap()),
            public_url: "https://harborgate.example.com".to_owned(),
            login_throttle,
            login_limiter: api::hardening::RateLimiter::new(10, Duration::from_secs(60)),
            credentials_key: Arc::new(auth::crypto::credentials_key(&root).unwrap()),
            allow_private_oidc: false,
            allow_private_harbor: false,
            jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
            webhook_token_limiter,
            webhook_failure_limiter: api::webhooks::new_failure_limiter(),
        };
        (app(Vec::new(), state), pool, dir, handle)
    }

    fn with_peer(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))))
    }

    /// A state-changing `/api` route returns `403 csrf_invalid` with no token, and with
    /// a header that does not match the cookie. A matching token passes the guard.
    #[tokio::test]
    async fn state_changing_route_needs_a_matching_csrf_token() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("csrf-route").await;
        let k = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let good = auth::csrf::issue(&k).unwrap();
        let cookie = format!("__Host-harborgate_csrf={good}");

        let missing = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie),
        )
        .body(Body::empty())
        .unwrap();
        let mismatch = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie)
                .header("x-csrf-token", "other.value"),
        )
        .body(Body::empty())
        .unwrap();
        let matching = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie)
                .header("x-csrf-token", &good),
        )
        .body(Body::empty())
        .unwrap();

        let r1 = router.clone().oneshot(missing).await.unwrap();
        let r2 = router.clone().oneshot(mismatch).await.unwrap();
        let r3 = router.oneshot(matching).await.unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r1.status(), StatusCode::FORBIDDEN);
        assert_eq!(r2.status(), StatusCode::FORBIDDEN);
        // The matching token passes the guard. The logout handler then returns 401,
        // because no session cookie is present, so the response is not 403.
        assert_eq!(r3.status(), StatusCode::UNAUTHORIZED);
    }

    /// Posts one login from `peer`. Test values only. The password is obviously fake.
    async fn post_login(
        router: &Router,
        peer: [u8; 4],
        username: &str,
        password: &str,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let body = format!(r#"{{"username":"{username}","password":"{password}"}}"#);
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("origin", "https://harborgate.example.com")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                peer, 8080,
            ))))
            .body(Body::from(body))
            .unwrap();
        router.clone().oneshot(request).await.unwrap()
    }

    /// Five wrong passwords, then the sixth attempt is refused inside the delay with
    /// the same 401 as a wrong password. The same account from another IP still gets a
    /// password check and is not delayed. Time is frozen, so the result does not depend
    /// on scheduling.
    #[tokio::test]
    async fn failed_login_delay_is_per_account_and_client_ip() {
        use axum::http::StatusCode;

        // A frozen clock: real time never advances, so the sixth attempt is always inside
        // the 1-second wait, under any CPU load.
        let frozen = std::time::Instant::now();
        let throttle = services::throttle::LoginThrottle::with_clock(Arc::new(move || frozen));
        let (router, pool, dir) = test_router_with_throttle("login-throttle", throttle).await;
        services::auth::create_first_admin(&pool, "test-admin", None, "test-password-fifteen")
            .await
            .unwrap();

        for _ in 0..5 {
            let r = post_login(
                &router,
                [192, 0, 2, 10],
                "test-admin",
                "test-wrong-password-xyz",
            )
            .await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }
        // Inside the 1-second wait: refused without a password check, same 401 body.
        let blocked = post_login(
            &router,
            [192, 0, 2, 10],
            "test-admin",
            "test-password-fifteen",
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
        let blocked_body = axum::body::to_bytes(blocked.into_body(), 4096)
            .await
            .unwrap();
        let wrong = post_login(
            &router,
            [198, 51, 100, 7],
            "test-admin",
            "test-wrong-password-xyz",
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let wrong_body = axum::body::to_bytes(wrong.into_body(), 4096).await.unwrap();
        // Responses for a blocked attempt and a wrong password look the same.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&blocked_body).unwrap()["error"]["code"],
            "invalid_credentials"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wrong_body).unwrap()["error"]["code"],
            "invalid_credentials"
        );
        // Another IP is not delayed: the right password signs in.
        let other_ip = post_login(
            &router,
            [198, 51, 100, 7],
            "test-admin",
            "test-password-fifteen",
        )
        .await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(other_ip.status(), StatusCode::OK);
    }

    /// The eleventh login from one IP in a minute gets 429 with Retry-After.
    #[tokio::test]
    async fn login_rate_limit_is_ten_per_minute_per_ip() {
        use axum::http::StatusCode;

        let (router, pool, dir) = test_router("login-rate").await;
        services::auth::create_first_admin(&pool, "test-admin", None, "test-password-fifteen")
            .await
            .unwrap();
        for n in 0..10 {
            let r = post_login(
                &router,
                [203, 0, 113, 5],
                &format!("test-nobody-{n}"),
                "test-wrong-password-xyz",
            )
            .await;
            assert_eq!(
                r.status(),
                StatusCode::UNAUTHORIZED,
                "attempt {n} should reach the password check"
            );
        }
        let limited = post_login(
            &router,
            [203, 0, 113, 5],
            "test-nobody-x",
            "test-wrong-password-xyz",
        )
        .await;
        let retry = limited.headers().get("retry-after").cloned();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry.is_some(), "429 must carry Retry-After");
    }

    /// Login and setup are exempt from the CSRF token. Without a token they must not
    /// return `csrf_invalid`, so they reach their own checks (here the same-origin
    /// check passes and the body is rejected instead). Both routes are tested.
    #[tokio::test]
    async fn login_and_setup_are_exempt_from_the_csrf_token() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("csrf-exempt").await;
        let body = r#"{"username":"test-x","password":"test-password-fifteen"}"#;
        let login = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("origin", "https://harborgate.example.com")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::from(body))
            .unwrap();
        let setup = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/setup")
            .header("origin", "https://harborgate.example.com")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::from(body))
            .unwrap();
        let login_status = router.clone().oneshot(login).await.unwrap().status();
        let setup_status = router.oneshot(setup).await.unwrap().status();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        // The request reaches the route: login finds no user (401) and setup creates one (201).
        assert_eq!(login_status, StatusCode::UNAUTHORIZED);
        assert_eq!(setup_status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn healthz_returns_ok_json() {
        let Json(body) = healthz().await;
        assert_eq!(
            serde_json::to_string(&body).ok().as_deref(),
            Some(r#"{"status":"ok"}"#)
        );
    }

    /// Inserts a user, two credentials, and one mapping whose token and secret are the
    /// given fake values, hashed the way the save path hashes them.
    async fn webhook_fixture(pool: &sqlx::SqlitePool, token: &str, secret: &str) {
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, token_version)
             VALUES ('wu', 'wu', NULL, 'user', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES ('wc1', 'wu', 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake'),
                    ('wc2', 'wu', 'github', 'g', NULL, NULL, 'v1:fake')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch)
             VALUES ('wm1', 'wu', 'wc1', 'wc2', 'https://harbor.example.com', 'proj', 'app', 'o', 'g', ?, ?, 0, 'CRITICAL', 'main')",
        )
        .bind(services::mappings::digest(token))
        .bind(services::mappings::digest(secret))
        .execute(pool)
        .await
        .unwrap();
    }

    /// A default-format vulnerability event for `proj/app`.
    const WEBHOOK_BODY: &str = r#"{"type":"SCANNING_COMPLETED","event_data":{"repository":{"repo_full_name":"proj/app"},"resources":[{"digest":"sha256:aaaa"}],"scan":{"scan_type":"vulnerability"}}}"#;

    fn webhook_request(
        token: &str,
        auth: Option<&str>,
        body: &str,
    ) -> axum::http::Request<axum::body::Body> {
        let mut builder = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/api/v1/webhooks/harbor/{token}"))
                .header("content-type", "application/json"),
        );
        if let Some(value) = auth {
            builder = builder.header("authorization", value);
        }
        builder
            .body(axum::body::Body::from(body.to_owned()))
            .unwrap()
    }

    /// The webhook route is exempt from the CSRF guard: a POST with no CSRF token is not
    /// refused with `403 csrf_invalid`. This is the route-level exemption, not the helper.
    #[tokio::test]
    async fn webhook_route_is_exempt_from_the_csrf_guard() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("webhook-csrf").await;
        webhook_fixture(&pool, "tok-csrf-fake", "sec-csrf-fake").await;
        let response = router
            .oneshot(webhook_request(
                "tok-csrf-fake",
                Some("Bearer sec-csrf-fake"),
                WEBHOOK_BODY,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_token_and_wrong_secret_return_the_same_401() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("webhook-401").await;
        webhook_fixture(&pool, "tok-401-fake", "sec-401-fake").await;
        let unknown = router
            .clone()
            .oneshot(webhook_request(
                "tok-no-such-fake",
                Some("Bearer sec-401-fake"),
                WEBHOOK_BODY,
            ))
            .await
            .unwrap();
        let wrong = router
            .oneshot(webhook_request(
                "tok-401-fake",
                Some("Bearer sec-wrong-fake"),
                WEBHOOK_BODY,
            ))
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let a = axum::body::to_bytes(unknown.into_body(), 4096)
            .await
            .unwrap();
        let b = axum::body::to_bytes(wrong.into_body(), 4096).await.unwrap();
        assert_eq!(a, b, "the two 401 bodies must match");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn oversize_body_returns_413() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("webhook-413").await;
        webhook_fixture(&pool, "tok-413-fake", "sec-413-fake").await;
        let big = "x".repeat(api::webhooks::MAX_BODY_BYTES + 1);
        let response = router
            .oneshot(webhook_request(
                "tok-413-fake",
                Some("Bearer sec-413-fake"),
                &big,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn another_repository_returns_202_and_stores_nothing() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("webhook-other").await;
        webhook_fixture(&pool, "tok-other-fake", "sec-other-fake").await;
        let other = WEBHOOK_BODY.replace("proj/app", "proj/other");
        let response = router
            .oneshot(webhook_request(
                "tok-other-fake",
                Some("Bearer sec-other-fake"),
                &other,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, 0);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Requests with unknown tokens create no per-token budget entry, so a flood of random
    /// tokens cannot grow the map. A request with a real token does create one entry, which
    /// shows the count can move at all.
    #[tokio::test]
    async fn unknown_token_creates_no_budget_entry() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let limiter = api::webhooks::new_token_limiter();
        let (router, pool, dir, budget) = test_router_with_limiters(
            "webhook-no-budget",
            services::throttle::LoginThrottle::new(),
            limiter,
        )
        .await;
        webhook_fixture(&pool, "tok-nob-fake", "sec-nob-fake").await;
        assert_eq!(budget.len(), 0);
        // Five unknown tokens: each is a 401, and none may create an entry.
        for n in 0..5 {
            let response = router
                .clone()
                .oneshot(webhook_request(
                    &format!("tok-unknown-{n}-fake"),
                    Some("Bearer sec-nob-fake"),
                    WEBHOOK_BODY,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(budget.len(), 0, "an unknown token created a budget entry");
        // Positive control: a real token is charged once, under its mapping id.
        let response = router
            .oneshot(webhook_request(
                "tok-nob-fake",
                Some("Bearer sec-nob-fake"),
                WEBHOOK_BODY,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(budget.len(), 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
