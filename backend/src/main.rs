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
use tokio::task::JoinHandle;
use tokio::time::Instant;

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
        .route("/assets/{*path}", get(api::static_files::asset))
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
        .route("/api/v1/cves/{id}/issue", post(api::cves::issue))
        .route(
            "/api/v1/webhooks/harbor/{mapping_token}",
            post(api::webhooks::receive),
        )
        .route("/api/v1/admin/audit-log", get(api::admin::audit_log))
        .route("/api/v1/admin/health", get(api::admin::health))
        .route("/api/v1/admin/backup", post(api::admin::backup))
        .route(
            "/api/v1/admin/alert-channels",
            get(api::admin::list_alert_channels).post(api::admin::create_alert_channel),
        )
        .route(
            "/api/v1/admin/alert-channels/{id}",
            axum::routing::put(api::admin::update_alert_channel),
        )
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
        .fallback(api::static_files::spa)
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
            if let Err(message) = run_rotate_key().await {
                eprintln!("{message}");
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

/// The offline key rotation command. It never binds the HTTP port, refuses to run
/// while the app holds the port, and prints only the number of rows it rewrote.
async fn run_rotate_key() -> Result<(), String> {
    ensure_app_stopped("rotating the key")?;
    let old_key = config::load_old_encryption_key().map_err(|err| err.to_string())?;
    let new_key = config::load_encryption_key().map_err(|err| err.to_string())?;
    let settings = config::load_settings().map_err(|err| err.to_string())?;
    match rotate_database(&settings.data_dir, &old_key, &new_key).await {
        Ok(rows) => {
            println!("Re-encrypted {rows} stored values under the new key.");
            Ok(())
        }
        Err(failure) => Err(failure.message().to_owned()),
    }
}

/// Why a rotation did not run or did not finish. Each variant has a fixed message.
#[derive(Debug, PartialEq, Eq)]
enum RotateFailure {
    NoDatabase,
    SameKey,
    CouldNotOpen,
    Failed,
}

impl RotateFailure {
    fn message(&self) -> &'static str {
        match self {
            RotateFailure::NoDatabase => {
                "no database was found in HARBORGATE_DATA_DIR; nothing was changed"
            }
            RotateFailure::SameKey => {
                "HARBORGATE_OLD_ENCRYPTION_KEY and HARBORGATE_ENCRYPTION_KEY are the same key; \
                 nothing was changed"
            }
            RotateFailure::CouldNotOpen => "could not open the database; nothing was changed",
            RotateFailure::Failed => {
                "the rotation failed and the database was not changed. Check that \
                 HARBORGATE_OLD_ENCRYPTION_KEY is the key that wrote the data, and that this \
                 image version is the one the app last ran on."
            }
        }
    }
}

/// Re-encrypts the database in `data_dir` from `old_key` to `new_key`. The database is
/// opened without running migrations: a failed rotation must leave the file exactly as
/// it was, and the command must run with the image version the app last ran on.
async fn rotate_database(
    data_dir: &Path,
    old_key: &config::EncryptionKey,
    new_key: &config::EncryptionKey,
) -> Result<u64, RotateFailure> {
    let old = auth::crypto::credentials_key(old_key).map_err(|_| RotateFailure::Failed)?;
    let new = auth::crypto::credentials_key(new_key).map_err(|_| RotateFailure::Failed)?;
    if services::harbor_webhook::constant_time_eq(old.as_bytes(), new.as_bytes()) {
        return Err(RotateFailure::SameKey);
    }
    let path = db::database_path(data_dir);
    if !path.is_file() {
        return Err(RotateFailure::NoDatabase);
    }
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(db::connect_options(&path))
        .await
        .map_err(|_| RotateFailure::CouldNotOpen)?;
    let rotated = services::key_rotation::rotate(&pool, &old, &new).await;
    pool.close().await;
    rotated.map_err(|_| RotateFailure::Failed)
}

/// The offline restore command. It never binds the HTTP port, and it refuses to run
/// while the app holds the port.
async fn run_restore(file: &Path) -> Result<(), String> {
    ensure_app_stopped("restoring")?;
    let encryption_key = config::load_encryption_key().map_err(|err| err.to_string())?;
    let settings = config::load_settings().map_err(|err| err.to_string())?;
    restore_database(&encryption_key, &settings.data_dir, file).await?;
    println!("Restored the database from {}.", file.display());
    Ok(())
}

/// Fails when something already listens on the app port. The listener is dropped at
/// once, so the port is free again for the app.
fn ensure_app_stopped(activity: &str) -> Result<(), String> {
    match std::net::TcpListener::bind(BIND_ADDR) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(_) => Err(format!("stop HarborGate before {activity}")),
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
        allow_private_alerts: settings.allow_private_alerts,
        jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
        webhook_token_limiter: api::webhooks::new_token_limiter(),
        webhook_failure_limiter: api::webhooks::new_failure_limiter(),
        backup_key,
        data_dir: settings.data_dir.clone(),
        backup_dir: settings.backup_dir.clone(),
        issues_client: Arc::new(
            services::github_issues::GithubIssues::new()
                .map_err(|_| "could not build the GitHub issues client")?,
        ),
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
    // connections and drains in-flight requests. The instant of the signal is sent first,
    // so one 8-second budget (`drain`) covers the server and the background tasks.
    let (stop_tx, stop_rx) = watch::channel(false);
    let (stop_at_tx, mut stop_at_rx) = watch::channel(None::<Instant>);
    tokio::spawn(async move {
        shutdown_signal(terminate).await;
        let _ = stop_at_tx.send(Some(Instant::now()));
        let _ = stop_tx.send(true);
    });

    // The worker stops taking jobs on the same signal. A job it already took finishes.
    let worker_pool = state.pool.clone();
    let worker_stop = stop_rx.clone();
    let sync_handler = services::sync::SyncHandler::new(
        state.pool.clone(),
        state.credentials_key.clone(),
        state.allow_private_harbor,
    )
    .map_err(|_| "could not build the sync job handler")?;
    let worker_task = tokio::spawn(async move {
        worker::run(worker_pool, Arc::new(sync_handler), worker_stop).await;
    });

    // Backup polling queues jobs for tagged artifacts without a successful sync.
    let poller_task = tokio::spawn(services::poller::run(
        state.pool.clone(),
        state.credentials_key.clone(),
        state.allow_private_harbor,
        stop_rx.clone(),
    ));

    // Retention deletes rows past their age limit, 5 minutes after start and then daily.
    let retention_task = tokio::spawn(services::retention::run(
        state.pool.clone(),
        stop_rx.clone(),
    ));

    let mut graceful = stop_rx.clone();
    let router = app(settings.trusted_proxies.clone(), state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = graceful.wait_for(|stopped| *stopped).await;
    });
    let tasks = vec![worker_task, poller_task, retention_task];

    let mut serve = Box::pin(std::future::IntoFuture::into_future(serve));
    let first = tokio::select! {
        result = &mut serve => Phase::Served(result),
        at = stop_instant(&mut stop_at_rx) => Phase::Stopped(at),
    };
    match first {
        Phase::Stopped(stop_at) => drain(serve, tasks, stop_at).await?,
        Phase::Served(result) => {
            // The server ended on its own, as with a listener error: exit at once.
            result?;
            let stop_at = (*stop_at_rx.borrow()).unwrap_or_else(Instant::now);
            drain(std::future::ready(Ok(())), tasks, stop_at).await?;
        }
    }
    Ok(())
}

/// What ended first: the server, or the stop signal.
enum Phase {
    Served(std::io::Result<()>),
    Stopped(Instant),
}

/// Resolves with the instant of the stop signal. A closed channel counts as now.
async fn stop_instant(stop_at: &mut watch::Receiver<Option<Instant>>) -> Instant {
    match stop_at.wait_for(|at| at.is_some()).await {
        Ok(at) => (*at).unwrap_or_else(Instant::now),
        Err(_) => Instant::now(),
    }
}

/// Drains within one `DRAIN_TIMEOUT` counted from `stop_at`, the instant of the stop
/// signal. The server and then each background task wait only until that one deadline, so
/// a stop never takes longer than the budget. A task that is still running at the deadline
/// is left to the process exit, and its job is re-queued at the next start.
async fn drain(
    serve: impl Future<Output = std::io::Result<()>>,
    tasks: Vec<JoinHandle<()>>,
    stop_at: Instant,
) -> std::io::Result<()> {
    let deadline = stop_at + DRAIN_TIMEOUT;
    let served = tokio::time::timeout_at(deadline, serve).await;
    for task in tasks {
        let _ = tokio::time::timeout_at(deadline, task).await;
    }
    served.unwrap_or(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Real time, no clock pausing: `stop_at` lies 7 s in the past, so about 1 s of the
    /// 8 s budget remains and each drain test takes about 1 s.
    fn stop_seven_seconds_ago() -> Instant {
        Instant::now() - Duration::from_secs(7)
    }

    /// A server that never ends and a worker that sleeps 20 s: `drain` still returns at
    /// the end of the one budget, not after a second 8 s.
    #[tokio::test]
    async fn drain_never_exceeds_the_budget() {
        let worker = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(20)).await;
        });
        let started = Instant::now();
        let result = drain(
            std::future::pending::<std::io::Result<()>>(),
            vec![worker],
            stop_seven_seconds_ago(),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(result.is_ok());
        assert!(
            elapsed >= Duration::from_millis(900),
            "returned before the budget ended: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "waited past the single budget: {elapsed:?}"
        );
    }

    /// The server ends at once, so the worker gets only what remains of the budget: a
    /// worker that needs 3 s is cut off at about 1 s, and one that needs 0.3 s finishes.
    #[tokio::test]
    async fn worker_gets_only_the_remaining_budget() {
        let slow_done = Arc::new(AtomicBool::new(false));
        let slow_flag = slow_done.clone();
        let slow = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            slow_flag.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let result = drain(
            std::future::ready(Ok(())),
            vec![slow],
            stop_seven_seconds_ago(),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(result.is_ok());
        assert!(
            elapsed < Duration::from_millis(2500),
            "the worker got more than the remaining budget: {elapsed:?}"
        );
        assert!(
            !slow_done.load(Ordering::SeqCst),
            "the slow worker should have been cut off"
        );

        let quick_done = Arc::new(AtomicBool::new(false));
        let quick_flag = quick_done.clone();
        let quick = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            quick_flag.store(true, Ordering::SeqCst);
        });
        let result = drain(
            std::future::ready(Ok(())),
            vec![quick],
            stop_seven_seconds_ago(),
        )
        .await;
        assert!(result.is_ok());
        assert!(
            quick_done.load(Ordering::SeqCst),
            "a worker inside the remaining budget must finish"
        );
    }

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
            allow_private_alerts: false,
            jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
            webhook_token_limiter: api::webhooks::new_token_limiter(),
            webhook_failure_limiter: api::webhooks::new_failure_limiter(),
            backup_key: Arc::new(auth::crypto::backup_key(&root).unwrap()),
            data_dir: dir.clone(),
            backup_dir: dir.join("backups"),
            issues_client: std::sync::Arc::new(
                crate::services::github_issues::GithubIssues::new().unwrap(),
            ),
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
            allow_private_alerts: false,
            jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
            webhook_token_limiter,
            webhook_failure_limiter: api::webhooks::new_failure_limiter(),
            backup_key: Arc::new(auth::crypto::backup_key(&root).unwrap()),
            data_dir: dir.clone(),
            backup_dir: dir.join("backups"),
            issues_client: std::sync::Arc::new(
                crate::services::github_issues::GithubIssues::new().unwrap(),
            ),
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

    #[tokio::test]
    async fn rotate_key_refuses_a_missing_database() {
        let empty = restore_dir("rotate-missing");
        let old = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let new = config::parse_encryption_key(OTHER_KEY_B64).unwrap();

        let result = rotate_database(&empty, &old, &new).await;

        assert_eq!(result, Err(RotateFailure::NoDatabase));
        assert!(
            !db::database_path(&empty).exists(),
            "the command created a database"
        );
    }

    /// The migrations history and the schema of the latest migration, as plain rows.
    async fn schema_state(pool: &sqlx::SqlitePool) -> (Vec<i64>, i64) {
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(pool)
                .await
                .unwrap();
        let description_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('cve_findings') WHERE name = 'description'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        (versions, description_columns)
    }

    /// A database that is one migration behind would be changed by `db::open`. The
    /// rotation must leave the migrations history and the schema as they were.
    #[tokio::test]
    async fn rotate_key_does_not_migrate_the_database() {
        let dir = restore_dir("rotate-schema");
        let pool = db::open(&dir).await.unwrap();
        sqlx::query("ALTER TABLE cve_findings DROP COLUMN description")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 2")
            .execute(&pool)
            .await
            .unwrap();
        let before = schema_state(&pool).await;
        pool.close().await;
        assert!(
            before == (vec![1], 0),
            "the setup did not remove migration 2"
        );

        let old = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let new = config::parse_encryption_key(OTHER_KEY_B64).unwrap();
        let rows = rotate_database(&dir, &old, &new).await;
        assert_eq!(rows, Ok(0), "an empty database did not rotate");

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_with(db::connect_options(&db::database_path(&dir)))
            .await
            .unwrap();
        assert!(
            schema_state(&pool).await == before,
            "the rotation changed the migrations or the schema"
        );
        let audits: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'key.rotate'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(audits, 1, "the rotation was not audited");
        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rotate_key_with_equal_keys_reports_same_key() {
        let dir = restore_dir("rotate-same");
        db::open(&dir).await.unwrap().close().await;
        let old = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let new = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();

        let result = rotate_database(&dir, &old, &new).await;

        assert_eq!(result, Err(RotateFailure::SameKey));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `POST /api/v1/cves/{id}/issue` through the router: no CSRF token is `403`, a CSRF
    /// token with no session is `401`, and another user's mapping in the percent-encoded
    /// `<mapping_id>%3A<cve_id>` form is `404`. No GitHub call is made in any case.
    #[tokio::test]
    async fn cve_issue_route_checks_csrf_session_and_tenancy() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("cve-issue-route").await;
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES ('rc1', 'owner-1', 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake'),
                    ('rc2', 'owner-1', 'github', 'g', NULL, NULL, 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
             VALUES ('rm1', 'owner-1', 'rc1', 'rc2', 'https://harbor.example.com', 'proj', 'app', 'octo', 'app', 'h1', 'h2')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, severity, status)
             VALUES ('rf1', 'rm1', 'app', 'v1', 'CVE-2026-0001', 'CRITICAL', 'open')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let key = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let other_session = session_cookie("other-2", "user", 0);
        let uri = "/api/v1/cves/rm1%3ACVE-2026-0001/issue";
        let post = |cookie: String, token: Option<&str>| {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::empty()).unwrap()
        };

        let no_csrf = router
            .clone()
            .oneshot(post(format!("{other_session}; {csrf_cookie}"), None))
            .await
            .unwrap();
        let no_session = router
            .clone()
            .oneshot(post(csrf_cookie.clone(), Some(&csrf)))
            .await
            .unwrap();
        let foreign = router
            .clone()
            .oneshot(post(format!("{other_session}; {csrf_cookie}"), Some(&csrf)))
            .await
            .unwrap();
        // The owner's call reaches the route with the decoded id. Its stored token is not
        // real, so decryption fails before any GitHub call; what matters is that it is not 404.
        let owner_session = session_cookie("owner-1", "user", 0);
        let owner = router
            .oneshot(post(format!("{owner_session}; {csrf_cookie}"), Some(&csrf)))
            .await
            .unwrap();
        let issues: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM github_issues")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        assert_ne!(owner.status(), StatusCode::NOT_FOUND);
        assert_eq!(issues, 0);
    }
}
