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
    };
    let terminate = signal(SignalKind::terminate())?;
    let listener = TcpListener::bind(BIND_ADDR).await?;

    // The stop flag flips to true on the first signal. The server stops accepting
    // connections and drains in-flight requests. A separate timer caps the drain.
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal(terminate).await;
        let _ = stop_tx.send(true);
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
        let dir = std::env::temp_dir().join(format!("harborgate-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
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
        };
        (app(Vec::new(), state), pool, dir)
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
}
