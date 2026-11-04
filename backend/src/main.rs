use std::time::Duration;

use std::path::Path;
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
mod cli;
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
        .route("/api/v1/admin/health", get(api::admin::health))
        .route("/api/v1/admin/backup", post(api::admin::backup))
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

    let args: Vec<String> = std::env::args().collect();
    let command = match cli::parse(args.get(1..).unwrap_or_default()) {
        Ok(command) => command,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    match command {
        cli::Command::Serve => serve().await,
        cli::Command::Restore(file) => {
            if let Err(message) = run_restore(&file).await {
                eprintln!("{message}");
                std::process::exit(1);
            }
            Ok(())
        }
        cli::Command::RotateKey => {
            // Implemented in #41.
            eprintln!("rotate-key is not implemented");
            std::process::exit(1);
        }
    }
}

/// The offline restore command. It never binds the HTTP port, and it refuses to run
/// while the app holds the port.
async fn run_restore(file: &Path) -> Result<(), String> {
    ensure_app_stopped()?;
    let encryption_key = config::load_encryption_key().map_err(|err| err.to_string())?;
    let settings = config::load_settings().map_err(|err| err.to_string())?;
    restore_database(&encryption_key, &settings.data_dir, file).await?;
    println!("Restored the database from {}.", file.display());
    Ok(())
}

/// Fails when something already listens on the app port. The listener is dropped at
/// once, so the port is free again for the app.
fn ensure_app_stopped() -> Result<(), String> {
    match std::net::TcpListener::bind(BIND_ADDR) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(_) => Err("stop HarborGate before restoring".to_owned()),
    }
}

/// The backup `created_at` for the `restore.run` audit row (decided on issue #58).
/// It is the UTC timestamp in the file name `harborgate-<yyyymmddThhmmssZ>.hgbk`.
/// A file that does not match that pattern falls back to its modification time.
/// Returns `None` when neither is available.
fn backup_created_at(file: &Path) -> Option<String> {
    let from_name = file
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(timestamp_from_file_name);
    from_name.or_else(|| {
        let modified = std::fs::metadata(file)
            .and_then(|meta| meta.modified())
            .ok()?;
        let secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        services::time::rfc3339(i64::try_from(secs).ok()?).ok()
    })
}

/// Parses `harborgate-<yyyymmddThhmmssZ>.hgbk` into an RFC 3339 string. A stamp that
/// is not a real calendar instant returns `None`.
fn timestamp_from_file_name(name: &str) -> Option<String> {
    let stamp = name.strip_prefix("harborgate-")?.strip_suffix(".hgbk")?;
    let bytes = stamp.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = stamp.get(range)?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
    let (hour, minute, second) = (number(9..11)?, number(11..13)?, number(13..15)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let unix = days * 86_400 + hour * 3600 + minute * 60 + second;
    let text = services::time::rfc3339(unix).ok()?;
    // A day that does not exist (such as 30 February) rolls over to another date, so
    // the round trip no longer matches the stamp.
    let expected = format!(
        "{}-{}-{}T{}:{}:{}Z",
        stamp.get(0..4)?,
        stamp.get(4..6)?,
        stamp.get(6..8)?,
        stamp.get(9..11)?,
        stamp.get(11..13)?,
        stamp.get(13..15)?
    );
    (text == expected).then_some(text)
}

/// Removes the plaintext temporary database and any SQLite side files it left. A
/// missing file is not an error.
fn remove_temp_files(temp_path: &Path) {
    let _ = std::fs::remove_file(temp_path);
    for suffix in ["-wal", "-shm"] {
        let mut side = temp_path.as_os_str().to_owned();
        side.push(suffix);
        let _ = std::fs::remove_file(side);
    }
}

/// Replaces `<data_dir>/harborgate.db` with the database in the backup `file`.
///
/// The live database is untouched unless the backup passes every check: the GCM tag
/// (`backup::open`), then `PRAGMA integrity_check` and the migrations on a temporary
/// copy in `data_dir`. Only then are the live `-wal` and `-shm` files removed and the
/// copy renamed over the live file (same directory, so the rename is atomic). The
/// `restore.run` audit row is appended to the restored database last. The temporary
/// copy holds the whole database in plain text and is removed on every path.
///
/// Errors are messages for the operator and name no key or file content.
async fn restore_database(
    encryption_key: &config::EncryptionKey,
    data_dir: &Path,
    file: &Path,
) -> Result<(), String> {
    let file_name = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "the backup path has no usable file name".to_owned())?
        .to_owned();
    let created_at = backup_created_at(file);
    let sealed = std::fs::read(file).map_err(|err| {
        format!(
            "could not read the backup file ({:?}); nothing was changed",
            err.kind()
        )
    })?;
    let backup_key = auth::crypto::backup_key(encryption_key)
        .map_err(|_| "could not derive the backup key".to_owned())?;
    let plain = services::backup::open(&backup_key, &sealed).map_err(|_| {
        "the backup file failed verification; check the file and that HARBORGATE_ENCRYPTION_KEY \
         is the key that created it. The live database was not changed."
            .to_owned()
    })?;
    drop(sealed);

    let temp_path = data_dir.join(format!("restore-{}.tmp", services::ids::new_id()));
    let staged = stage_and_swap(data_dir, &temp_path, &plain).await;
    remove_temp_files(&temp_path);
    drop(plain);
    staged?;

    // The database is replaced. Append the audit row to the restored database.
    let pool = db::open(data_dir).await.map_err(|_| {
        "the database was restored, but it could not be reopened to record the audit row".to_owned()
    })?;
    let details = serde_json::json!({ "file": file_name, "created_at": created_at });
    let recorded = record_restore(&pool, &file_name, &details).await;
    pool.close().await;
    recorded.map_err(|_| {
        "the database was restored, but the restore.run audit row could not be written".to_owned()
    })
}

/// Writes the plaintext to `temp_path`, checks it, and swaps it in for the live file.
async fn stage_and_swap(data_dir: &Path, temp_path: &Path, plain: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Owner-only: the file holds the whole database in plain text.
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp_path)
        .map_err(|_| "could not create the temporary file in HARBORGATE_DATA_DIR".to_owned())?;
    out.write_all(plain)
        .and_then(|()| out.sync_all())
        .map_err(|_| "could not write the temporary file in HARBORGATE_DATA_DIR".to_owned())?;
    drop(out);

    let checked = check_candidate(temp_path).await;
    checked?;

    let live = db::database_path(data_dir);
    let live_text = live.to_string_lossy().into_owned();
    for suffix in ["-wal", "-shm"] {
        let side = std::path::PathBuf::from(format!("{live_text}{suffix}"));
        match std::fs::remove_file(&side) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(
                    "could not remove the old write-ahead log; the live database was not replaced"
                        .to_owned(),
                );
            }
        }
    }
    std::fs::rename(temp_path, &live).map_err(|_| "could not replace the live database".to_owned())
}

/// Opens the candidate database, runs `PRAGMA integrity_check` (expects `ok`) and the
/// migrations, then closes it so SQLite checkpoints and removes its own log files.
async fn check_candidate(temp_path: &Path) -> Result<(), String> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(db::connect_options(temp_path))
        .await
        .map_err(|_| "the backup does not contain a usable database".to_owned())?;
    // A PRAGMA result has no column type the `query!` macro can check, so this read
    // is a plain query.
    let verdict = sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
        .fetch_one(&pool)
        .await;
    let result = match verdict {
        Ok(text) if text == "ok" => db::migrate(&pool).await.map_err(|_| {
            "the backup database could not be migrated; it may come from a newer HarborGate"
                .to_owned()
        }),
        _ => Err("the backup database failed the integrity check".to_owned()),
    };
    pool.close().await;
    result
}

/// Appends the `restore.run` audit row (actor `cli`) in one transaction.
async fn record_restore(
    pool: &sqlx::SqlitePool,
    file_name: &str,
    details: &serde_json::Value,
) -> Result<(), error::AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| error::AppError::InternalError)?;
    services::audit::record(
        &mut tx,
        &services::audit::Actor::cli(),
        "restore.run",
        &format!("backup:{file_name}"),
        Some(details),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| error::AppError::InternalError)
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    // Refuse to start without a valid key or settings. This runs before the port is bound.
    let encryption_key = config::load_encryption_key()?;
    let settings = config::load_settings()?;
    auth::password::warm_dummy_hash().map_err(|_| "could not compute the dummy password hash")?;
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
    let backup_key = Arc::new(
        auth::crypto::backup_key(&encryption_key).map_err(|_| "could not derive the backup key")?,
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
        backup_key,
        data_dir: settings.data_dir.clone(),
        backup_dir: settings.backup_dir.clone(),
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
            backup_key: Arc::new(auth::crypto::backup_key(&root).unwrap()),
            data_dir: dir.clone(),
            backup_dir: dir.join("backups"),
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
            backup_key: Arc::new(auth::crypto::backup_key(&root).unwrap()),
            data_dir: dir.clone(),
            backup_dir: dir.join("backups"),
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

    /// Thirty failed authentications from one IP are each `401`. The thirty-first request
    /// from that IP is `429` with `Retry-After`, even with valid credentials, because the
    /// per-IP failure budget is checked before anything else.
    #[tokio::test]
    async fn webhook_ip_failure_limit_returns_429_through_the_router() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("webhook-ip-429").await;
        webhook_fixture(&pool, "tok-ip-fake", "sec-ip-fake").await;
        for n in 0..30 {
            let response = router
                .clone()
                .oneshot(webhook_request(
                    &format!("tok-ip-unknown-{n}-fake"),
                    Some("Bearer sec-ip-fake"),
                    WEBHOOK_BODY,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "failure {n}");
        }
        let limited = router
            .oneshot(webhook_request(
                "tok-ip-fake",
                Some("Bearer sec-ip-fake"),
                WEBHOOK_BODY,
            ))
            .await
            .unwrap();
        let retry = limited.headers().get("retry-after").cloned();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry.is_some(), "429 must carry Retry-After");
    }

    /// Sixty requests with a valid token and secret are each `202`. The sixty-first
    /// request for the same mapping is `429` with `Retry-After`.
    #[tokio::test]
    async fn webhook_token_budget_returns_429_through_the_router() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("webhook-budget-429").await;
        webhook_fixture(&pool, "tok-budget-fake", "sec-budget-fake").await;
        for n in 0..60 {
            let response = router
                .clone()
                .oneshot(webhook_request(
                    "tok-budget-fake",
                    Some("Bearer sec-budget-fake"),
                    WEBHOOK_BODY,
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::ACCEPTED,
                "request {n} should be within the budget"
            );
        }
        let limited = router
            .oneshot(webhook_request(
                "tok-budget-fake",
                Some("Bearer sec-budget-fake"),
                WEBHOOK_BODY,
            ))
            .await
            .unwrap();
        let retry = limited.headers().get("retry-after").cloned();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry.is_some(), "429 must carry Retry-After");
    }

    /// `GET /api/v1/admin/audit-log` filters by `action` and `actor_user_id`, and pages with
    /// `page` and `page_size`, through the router. Five rows: two actions, two actors.
    #[tokio::test]
    async fn audit_log_filters_and_pages_over_http() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("audit-http").await;
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, "adm-1", "test-admin", None, "h", "admin")
            .await
            .unwrap();
        db::users::insert_local(&mut conn, "act-2", "test-regular", None, "h", "user")
            .await
            .unwrap();
        let first = services::audit::Actor {
            user_id: Some("adm-1".to_owned()),
            username: "test-admin".to_owned(),
        };
        let second = services::audit::Actor {
            user_id: Some("act-2".to_owned()),
            username: "test-regular".to_owned(),
        };
        for (actor, action, target) in [
            (&first, "user.create", "user:a"),
            (&second, "user.create", "user:b"),
            (&first, "mapping.create", "mapping:c"),
            (&second, "mapping.create", "mapping:d"),
            (&first, "mapping.create", "mapping:e"),
        ] {
            services::audit::record(&mut conn, actor, action, target, None)
                .await
                .unwrap();
        }
        drop(conn);
        let cookie = session_cookie("adm-1", "admin", 0);

        let (status, all) = get_json(&router, "/api/v1/admin/audit-log", &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(all["total"], 5);

        let (status, by_action) = get_json(
            &router,
            "/api/v1/admin/audit-log?action=user.create",
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(by_action["total"], 2);
        let actions = by_action["items"].as_array().unwrap();
        assert!(
            actions.iter().all(|item| item["action"] == "user.create"),
            "action filter let another action through"
        );

        let (status, by_actor) = get_json(
            &router,
            "/api/v1/admin/audit-log?actor_user_id=act-2",
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(by_actor["total"], 2);
        let actors = by_actor["items"].as_array().unwrap();
        assert!(
            actors.iter().all(|item| item["actor_user_id"] == "act-2"),
            "actor filter let another actor through"
        );

        // Paging: pages of two over five rows give 2, 2, 1, then an empty page. The
        // three pages together hold every row exactly once.
        let mut seen = Vec::new();
        for (page, expected) in [(1, 2), (2, 2), (3, 1), (4, 0)] {
            let uri = format!("/api/v1/admin/audit-log?page={page}&page_size=2");
            let (status, body) = get_json(&router, &uri, &cookie).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["page"], page);
            assert_eq!(body["page_size"], 2);
            assert_eq!(body["total"], 5);
            let items = body["items"].as_array().unwrap();
            assert_eq!(items.len(), expected, "page {page} size");
            seen.extend(items.iter().map(|item| item["id"].clone()));
        }
        let distinct: std::collections::HashSet<String> =
            seen.iter().map(|id| id.to_string()).collect();
        assert_eq!(distinct.len(), 5, "paging repeated or dropped a row");

        // Filter and paging together: three mapping rows, page two holds the last one.
        let (status, filtered) = get_json(
            &router,
            "/api/v1/admin/audit-log?action=mapping.create&page=2&page_size=2",
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(filtered["total"], 3);
        assert_eq!(filtered["items"].as_array().unwrap().len(), 1);

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Login and setup refuse a cross-site request with `403 csrf_invalid`, on both routes:
    /// a foreign `Origin`, a cross-site `Sec-Fetch-Site` with no `Origin`, and neither
    /// header. The database is empty, so a request that got past the check would reach the
    /// handler and return `401` (login) or `201` (setup). A `403` shows the check refused it.
    #[tokio::test]
    async fn login_and_setup_refuse_cross_site_requests() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("cross-site").await;
        let body = format!(
            r#"{{"username":"test-x","password":"{}"}}"#,
            runtime_password()
        );
        let mut failures = Vec::new();
        for uri in ["/api/v1/auth/login", "/api/v1/auth/setup"] {
            for (label, origin, fetch_site) in [
                ("foreign origin", Some("https://evil.example.com"), None),
                (
                    "cross-site fetch metadata, no origin",
                    None,
                    Some("cross-site"),
                ),
                ("neither header", None, None),
            ] {
                let mut builder = with_peer(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json"),
                );
                if let Some(value) = origin {
                    builder = builder.header("origin", value);
                }
                if let Some(value) = fetch_site {
                    builder = builder.header("sec-fetch-site", value);
                }
                let request = builder.body(Body::from(body.clone())).unwrap();
                let response = router.clone().oneshot(request).await.unwrap();
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                failures.push((uri, label, status, json["error"]["code"].clone()));
            }
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        for (uri, label, status, code) in failures {
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {label}");
            assert_eq!(code, "csrf_invalid", "{uri}: {label}");
        }
    }

    /// Two sessions of one user, each from a real login. After `POST /api/v1/account/password`
    /// with session A, session B gets `401` on `GET /api/v1/account/me`. The cookie issued by
    /// the password change response gets `200`.
    #[tokio::test]
    async fn password_change_signs_out_other_sessions_over_http() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("password-http").await;
        let current = runtime_password();
        let next = runtime_password();
        services::auth::create_first_admin(&pool, "test-admin", None, &current)
            .await
            .unwrap();
        let login_a = post_login(&router, [192, 0, 2, 20], "test-admin", &current).await;
        assert_eq!(login_a.status(), StatusCode::OK);
        let login_b = post_login(&router, [192, 0, 2, 20], "test-admin", &current).await;
        assert_eq!(login_b.status(), StatusCode::OK);
        let session_a = set_cookie_value(&login_a, auth::session::SESSION_COOKIE).unwrap();
        let session_b = set_cookie_value(&login_b, auth::session::SESSION_COOKIE).unwrap();
        let csrf = set_cookie_value(&login_a, auth::csrf::CSRF_COOKIE).unwrap();
        assert_ne!(session_a, session_b, "two logins must give two sessions");

        let change = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/account/password")
                .header("content-type", "application/json")
                .header(
                    "cookie",
                    format!(
                        "{}={session_a}; {}={csrf}",
                        auth::session::SESSION_COOKIE,
                        auth::csrf::CSRF_COOKIE
                    ),
                )
                .header("x-csrf-token", &csrf),
        )
        .body(Body::from(format!(
            r#"{{"current_password":"{current}","new_password":"{next}"}}"#
        )))
        .unwrap();
        let changed = router.clone().oneshot(change).await.unwrap();
        assert_eq!(changed.status(), StatusCode::NO_CONTENT);
        let session_c = set_cookie_value(&changed, auth::session::SESSION_COOKIE).unwrap();

        let (status_b, _) = get_json(
            &router,
            "/api/v1/account/me",
            &format!("{}={session_b}", auth::session::SESSION_COOKIE),
        )
        .await;
        let (status_c, _) = get_json(
            &router,
            "/api/v1/account/me",
            &format!("{}={session_c}", auth::session::SESSION_COOKIE),
        )
        .await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(status_b, StatusCode::UNAUTHORIZED, "other session survived");
        assert_eq!(status_c, StatusCode::OK, "the fresh session must work");
    }

    /// A test password drawn from the OS RNG at run time, so no password literal sits in
    /// the source. Length is well over the 15-character minimum.
    fn runtime_password() -> String {
        format!("test-pw-{}", services::ids::new_id())
    }

    /// A signed session cookie for `user_id`, issued the way login issues one. Test key only.
    fn session_cookie(user_id: &str, role: &str, token_version: i64) -> String {
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let key = auth::crypto::session_key(&root).unwrap();
        let now = auth::session::now_unix().unwrap();
        let token = auth::session::issue(&key, user_id, role, token_version, now).unwrap();
        format!("{}={token}", auth::session::SESSION_COOKIE)
    }

    /// A GET with the given `cookie` header. Returns the status and the parsed JSON body.
    async fn get_json(
        router: &Router,
        uri: &str,
        cookie: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let request = with_peer(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("cookie", cookie),
        )
        .body(Body::empty())
        .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The value of the `Set-Cookie` named `name` on `response`, without its attributes.
    fn set_cookie_value(
        response: &axum::http::Response<axum::body::Body>,
        name: &str,
    ) -> Option<String> {
        response
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let pair = value.to_str().ok()?.split(';').next()?;
                let (key, val) = pair.split_once('=')?;
                (key == name).then(|| val.to_owned())
            })
    }

    // Base64 of 32 zero bytes, and of 32 bytes of 0x01. Test values only.
    const RESTORE_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const OTHER_KEY_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    /// 2001-09-09T01:46:40Z, the instant in the backup file name below.
    const BACKUP_AT: i64 = 1_000_000_000;

    fn restore_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("harborgate-restore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn add_user(pool: &sqlx::SqlitePool, username: &str) {
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, username, username, None, "test-hash", "user")
            .await
            .unwrap();
    }

    async fn usernames(data_dir: &Path) -> Vec<String> {
        let pool = db::open(data_dir).await.unwrap();
        let names: Vec<String> = sqlx::query_scalar("SELECT username FROM users ORDER BY username")
            .fetch_all(&pool)
            .await
            .unwrap();
        pool.close().await;
        names
    }

    async fn restore_audit_count(data_dir: &Path) -> i64 {
        let pool = db::open(data_dir).await.unwrap();
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'restore.run'")
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        count
    }

    /// A live data directory holding user `live`, and a backup directory holding a
    /// backup of a database with user `backed-up`, sealed under `RESTORE_KEY_B64`.
    /// Returns (live data dir, backup file path).
    async fn live_and_backup(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let live = restore_dir(&format!("{name}-live"));
        let source = restore_dir(&format!("{name}-source"));
        let backups = restore_dir(&format!("{name}-backups"));

        let live_pool = db::open(&live).await.unwrap();
        add_user(&live_pool, "live").await;
        live_pool.close().await;

        let source_pool = db::open(&source).await.unwrap();
        add_user(&source_pool, "backed-up").await;
        let root = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let key = auth::crypto::backup_key(&root).unwrap();
        let file_name = services::backup::create(&source_pool, &key, &source, &backups, BACKUP_AT)
            .await
            .unwrap();
        source_pool.close().await;
        (live, backups.join(file_name))
    }

    fn stray_temp_files(data_dir: &Path) -> Vec<String> {
        std::fs::read_dir(data_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("restore-"))
            .collect()
    }

    #[tokio::test]
    async fn restore_replaces_the_database_and_appends_restore_run() {
        let (live, backup) = live_and_backup("replace").await;
        assert_eq!(usernames(&live).await, vec!["live"]);
        let root = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();

        restore_database(&root, &live, &backup).await.unwrap();

        assert_eq!(usernames(&live).await, vec!["backed-up"]);
        assert!(stray_temp_files(&live).is_empty(), "temporary copy left");

        let pool = db::open(&live).await.unwrap();
        let row: (String, String, Option<String>, String) = sqlx::query_as(
            "SELECT actor_username, action, actor_user_id, details FROM audit_log
             WHERE action = 'restore.run'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        pool.close().await;
        assert_eq!(row.0, "cli");
        assert_eq!(row.1, "restore.run");
        assert_eq!(row.2, None);
        let details: serde_json::Value = serde_json::from_str(&row.3).unwrap();
        assert_eq!(
            details,
            serde_json::json!({
                "file": "harborgate-20010909T014640Z.hgbk",
                "created_at": "2001-09-09T01:46:40Z",
            })
        );
    }

    /// The decided source of `created_at`: the file name first, then the file's
    /// modification time.
    #[test]
    fn backup_created_at_prefers_the_name_then_the_modification_time() {
        assert_eq!(
            timestamp_from_file_name("harborgate-20010909T014640Z.hgbk").as_deref(),
            Some("2001-09-09T01:46:40Z")
        );
        assert_eq!(
            timestamp_from_file_name("harborgate-20010230T014640Z.hgbk"),
            None
        );
        assert_eq!(timestamp_from_file_name("renamed.hgbk"), None);

        let dir = restore_dir("created-at");
        let renamed = dir.join("renamed.hgbk");
        std::fs::write(&renamed, b"x").unwrap();
        let fallback = backup_created_at(&renamed).unwrap();
        assert!(
            fallback.ends_with('Z') && fallback.len() == 20,
            "{fallback}"
        );
        assert_eq!(backup_created_at(&dir.join("missing.hgbk")), None);
    }

    #[tokio::test]
    async fn bad_tag_leaves_the_live_database_untouched() {
        let (live, backup) = live_and_backup("bad-tag").await;
        let mut bytes = std::fs::read(&backup).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&backup, bytes).unwrap();
        let root = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();

        let result = restore_database(&root, &live, &backup).await;

        assert!(result.is_err(), "a tampered backup was restored");
        assert_eq!(usernames(&live).await, vec!["live"]);
        assert_eq!(restore_audit_count(&live).await, 0);
        assert!(stray_temp_files(&live).is_empty(), "temporary copy left");
    }

    #[tokio::test]
    async fn wrong_key_leaves_the_live_database_untouched() {
        let (live, backup) = live_and_backup("wrong-key").await;
        let other = config::parse_encryption_key(OTHER_KEY_B64).unwrap();

        let result = restore_database(&other, &live, &backup).await;

        assert!(result.is_err(), "a backup restored under the wrong key");
        assert_eq!(usernames(&live).await, vec!["live"]);
        assert_eq!(restore_audit_count(&live).await, 0);
        assert!(stray_temp_files(&live).is_empty(), "temporary copy left");
    }
}
