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
        // Picker lists and suggestion: 60 per minute per user, shared (`specs/api.md`, Pickers).
        .route(
            "/api/v1/credentials/{id}/harbor-projects",
            get(api::pickers::harbor_projects),
        )
        .route(
            "/api/v1/credentials/{id}/harbor-projects/{project}/repositories",
            get(api::pickers::harbor_repositories),
        )
        .route(
            "/api/v1/credentials/{id}/github-repositories",
            get(api::pickers::github_repositories),
        )
        .route(
            "/api/v1/credentials/{id}/source-suggestion",
            get(api::pickers::source_suggestion),
        )
        // Hidden items: no limit, own rows only, no upstream call (`specs/api.md`, Pickers).
        .route(
            "/api/v1/pickers/hidden",
            get(api::pickers::list_hidden).post(api::pickers::hide),
        )
        .route(
            "/api/v1/pickers/hidden/{id}",
            axum::routing::delete(api::pickers::restore),
        )
        .route(
            "/api/v1/mappings",
            get(api::mappings::list).post(api::mappings::create),
        )
        .route(
            "/api/v1/mappings/{id}",
            get(api::mappings::get)
                .put(api::mappings::update)
                .delete(api::mappings::delete),
        )
        .route(
            "/api/v1/mappings/{id}/rotate-webhook-token",
            post(api::mappings::rotate_webhook_token),
        )
        .route(
            "/api/v1/mappings/{id}/rotate-auth-secret",
            post(api::mappings::rotate_auth_secret),
        )
        .route("/api/v1/mappings/{id}/pull", post(api::mappings::pull))
        // Scanner list: 60 per minute per user. Tag scan: 1 per 5 minutes per (mapping, tag,
        // scanner). Both declared in `services::scanner_launch` (`specs/api.md`).
        .route("/api/v1/mappings/{id}/scanners", get(api::scanners::list))
        .route(
            "/api/v1/mappings/{id}/tags/{tag}/scan",
            post(api::scanners::scan),
        )
        // No rate limit: it reads only the database (`specs/api.md`, "Scanners and tag scans").
        .route(
            "/api/v1/mappings/{id}/tags/{tag}/scans",
            get(api::scanners::scans),
        )
        .route(
            "/api/v1/mappings/{id}/cves",
            get(api::cves::list_for_mapping),
        )
        .route(
            "/api/v1/mappings/{id}/tags",
            get(api::cves::tags_for_mapping),
        )
        .route(
            "/api/v1/project-webhooks",
            post(api::project_webhooks::create),
        )
        .route(
            "/api/v1/project-webhooks/{id}",
            get(api::project_webhooks::get),
        )
        .route(
            "/api/v1/project-webhooks/{id}/rotate-token",
            post(api::project_webhooks::rotate_token),
        )
        .route(
            "/api/v1/project-webhooks/{id}/rotate-secret",
            post(api::project_webhooks::rotate_secret),
        )
        .route(
            "/api/v1/project-webhooks/{id}/unmatched",
            get(api::project_webhooks::unmatched),
        )
        .route("/api/v1/sync-jobs", get(api::sync_jobs::list))
        .route("/api/v1/sync-jobs/{id}", get(api::sync_jobs::get))
        .route("/api/v1/sync-jobs/{id}/retry", post(api::sync_jobs::retry))
        .route("/api/v1/dashboard/summary", get(api::dashboard::summary))
        .route("/api/v1/cves", get(api::cves::list))
        .route("/api/v1/cves/{id}", get(api::cves::get))
        .route("/api/v1/cves/{id}/issue", post(api::cves::issue))
        .route("/api/v1/cves/{id}/accept", post(api::cves::accept))
        .route("/api/v1/cves/{id}/unaccept", post(api::cves::unaccept))
        .route(
            "/api/v1/webhooks/harbor/{mapping_token}",
            post(api::webhooks::receive),
        )
        .route(
            "/api/v1/webhooks/harbor/project/{project_token}",
            post(api::webhooks::receive_project),
        )
        .route("/api/v1/admin/audit-log", get(api::admin::audit_log))
        .route("/api/v1/admin/jobs", get(api::admin::admin_jobs))
        .route("/api/v1/admin/health", get(api::admin::health))
        .route("/api/v1/admin/backup", post(api::admin::backup))
        .route("/api/v1/admin/logs", get(api::admin::logs))
        .route(
            "/api/v1/admin/log-level",
            get(api::admin::get_log_level).put(api::admin::put_log_level),
        )
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
            "/api/v1/admin/github-url",
            get(api::github_url::get_settings).put(api::github_url::put_settings),
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
    // Logs go to stdout and to the admin's in-memory buffer. Every start is at `info`;
    // `RUST_LOG` is ignored (`specs/security.md`, Application log). The access log
    // records route templates, so tokens in paths stay out.
    let app_log = services::app_log::install()?;

    let args: Vec<String> = std::env::args().collect();
    let command = match cli::parse(args.get(1..).unwrap_or_default()) {
        Ok(command) => command,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    match command {
        cli::Command::Serve => serve(app_log).await,
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

    let restore_id = services::ids::new_id().map_err(|_| {
        "could not draw a random name for the restore; nothing was changed".to_owned()
    })?;
    let temp_path = data_dir.join(format!("restore-{restore_id}.tmp"));
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

async fn serve(app_log: Arc<services::app_log::AppLog>) -> Result<(), Box<dyn std::error::Error>> {
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
    let github = services::github_url::load_target(&pool)
        .await
        .map_err(|_| "could not read the GitHub base URL settings")?;
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
            services::github_issues::GithubIssues::new(github.clone())
                .map_err(|_| "could not build the GitHub issues client")?,
        ),
        harbor_probe: api::state::HarborProbeHandle::outbound(settings.allow_private_harbor)
            .map_err(|_| "could not build the Harbor probe")?,
        app_log,
        harbor_fetch: api::state::HarborFetchHandle::outbound(settings.allow_private_harbor)
            .map_err(|_| "could not build the Harbor client")?,
        pull_limiter: api::mappings::new_pull_limiter(),
        scanner_launch: Default::default(),
        pickers: services::pickers::PickerState::outbound(
            settings.allow_private_harbor,
            github.clone(),
        )
        .map_err(|_| "could not build the picker client")?,
        github,
    };
    let terminate = signal(SignalKind::terminate())?;
    let listener = TcpListener::bind(BIND_ADDR).await?;
    // Startup line: version, bind address and non-secret settings only. The encryption key,
    // tokens and secrets are never logged.
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        bind = BIND_ADDR,
        public_url = %settings.public_url,
        data_dir = %settings.data_dir.display(),
        backup_dir = %settings.backup_dir.display(),
        // Named without "private": the application log drops fields whose names hold
        // an audit secret fragment (`specs/security.md`, Application log).
        harbor_range_opt_out = settings.allow_private_harbor,
        oidc_range_opt_out = settings.allow_private_oidc,
        alerts_range_opt_out = settings.allow_private_alerts,
        "HarborGate starting"
    );

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
        state.allow_private_alerts,
        state.github.clone(),
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

    // The scan scheduler queues a scan job for each mapping whose scheduled slot is due (#191).
    let schedule_task = tokio::spawn(services::scheduled_scan::run(
        state.pool.clone(),
        stop_rx.clone(),
    ));

    let mut graceful = stop_rx.clone();
    let router = app(settings.trusted_proxies.clone(), state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = graceful.wait_for(|stopped| *stopped).await;
    });
    let tasks = vec![worker_task, poller_task, retention_task, schedule_task];

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
                crate::services::github_issues::GithubIssues::new(Default::default()).unwrap(),
            ),
            harbor_probe: crate::api::state::HarborProbeHandle::outbound(false).unwrap(),
            app_log: std::sync::Arc::new(crate::services::app_log::AppLog::detached(
                crate::services::app_log::REVERT_AFTER,
            )),
            harbor_fetch: crate::api::state::HarborFetchHandle::outbound(false).unwrap(),
            pull_limiter: crate::api::mappings::new_pull_limiter(),
            scanner_launch: Default::default(),
            pickers: crate::services::pickers::PickerState::outbound(false, Default::default())
                .unwrap(),
            github: Default::default(),
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

    /// A Harbor probe that answers every artifacts request with `200`. No socket.
    struct ReadableHarbor;

    impl api::state::DynHarborProbe for ReadableHarbor {
        fn users_current<'a>(
            &'a self,
            _base: &'a reqwest::Url,
            _username: &'a str,
            _secret: &'a [u8],
        ) -> api::state::ProbeFuture<'a, u16> {
            Box::pin(async { Ok(200) })
        }

        fn artifacts_status<'a>(
            &'a self,
            _base: &'a reqwest::Url,
            _username: &'a str,
            _secret: &'a [u8],
            _project: &'a str,
            _repository: &'a str,
        ) -> api::state::ProbeFuture<'a, u16> {
            Box::pin(async { Ok(200) })
        }
    }

    /// `PUT /api/v1/mappings/:id` through the router. Checks session (`401`), CSRF
    /// (`403`), tenancy (`404` for another user's mapping), and the owner's `200` for a
    /// changed `harbor_repository`. The Harbor probe is a fake, so no live Harbor is used.
    #[tokio::test]
    async fn mapping_put_route_checks_session_csrf_tenancy_and_owner_update() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let probe = api::state::HarborProbeHandle::new(Arc::new(ReadableHarbor));
        let (router, pool, dir, _) = test_router_with_probe(
            "mapping-put-route",
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
            probe,
        )
        .await;
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        drop(conn);
        let owner_actor = services::audit::Actor {
            user_id: Some("owner-1".to_owned()),
            username: "owner-1".to_owned(),
        };
        let harbor_cred = services::credentials::create(
            &pool,
            &auth::crypto::credentials_key(&root).unwrap(),
            &owner_actor,
            "owner-1",
            services::credentials::NewCredential {
                service_type: services::credentials::SERVICE_HARBOR.to_owned(),
                label: "h".to_owned(),
                base_url: Some("https://harbor.example.com".to_owned()),
                username: Some("robot$hg".to_owned()),
                token: "test-harbor-secret".to_owned(),
                expires_at: None,
            },
            false,
        )
        .await
        .unwrap();
        let github_cred = services::credentials::create(
            &pool,
            &auth::crypto::credentials_key(&root).unwrap(),
            &owner_actor,
            "owner-1",
            services::credentials::NewCredential {
                service_type: services::credentials::SERVICE_GITHUB.to_owned(),
                label: "g".to_owned(),
                base_url: None,
                username: None,
                token: "test-github-secret".to_owned(),
                expires_at: None,
            },
            false,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
             VALUES ('rm1', 'owner-1', ?, ?, 'https://harbor.example.com', 'proj', 'app', 'octo', 'app', 'h1', 'h2')",
        )
        .bind(&harbor_cred.id)
        .bind(&github_cred.id)
        .execute(&pool)
        .await
        .unwrap();

        let key = auth::crypto::csrf_key(&root).unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let body = r#"{"harbor_repository":"app-two"}"#;
        let put = |cookie: Option<&str>, token: Option<&str>, uri: &str| {
            let mut builder = with_peer(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/json"),
            );
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::from(body)).unwrap()
        };

        // No session, with a matching CSRF cookie and token, so the CSRF guard passes and
        // the session check decides: 401.
        let anonymous = router
            .clone()
            .oneshot(put(Some(&csrf_cookie), Some(&csrf), "/api/v1/mappings/rm1"))
            .await
            .unwrap()
            .status();
        // A session but no CSRF token: 403.
        let no_csrf = router
            .clone()
            .oneshot(put(Some(&owner), None, "/api/v1/mappings/rm1"))
            .await
            .unwrap()
            .status();
        // Another user's mapping: 404, with the CSRF token present.
        let foreign = router
            .clone()
            .oneshot(put(Some(&other), Some(&csrf), "/api/v1/mappings/rm1"))
            .await
            .unwrap()
            .status();
        // The owner, with the token: 200 and the new repository.
        let owned = router
            .oneshot(put(Some(&owner), Some(&csrf), "/api/v1/mappings/rm1"))
            .await
            .unwrap();
        let owned_status = owned.status();
        let owned_body = axum::body::to_bytes(owned.into_body(), 64 * 1024)
            .await
            .unwrap();
        let stored: String =
            sqlx::query_scalar("SELECT harbor_repository FROM repo_mappings WHERE id = 'rm1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anonymous, StatusCode::UNAUTHORIZED);
        assert_eq!(no_csrf, StatusCode::FORBIDDEN);
        assert_eq!(foreign, StatusCode::NOT_FOUND);
        assert_eq!(owned_status, StatusCode::OK, "owner update was refused");
        assert_eq!(stored, "app-two");
        let json: serde_json::Value = serde_json::from_slice(&owned_body).unwrap();
        assert_eq!(json["harbor_repository"], "app-two");
        assert!(json.get("webhook_url").is_none());
        assert!(json.get("auth_secret").is_none());
    }

    /// The picker routes through the router (#126). Checks session (`401`), tenancy (`404`
    /// for another user's credential), the wrong type (`422`), the upstream rate limit (`429`
    /// with `Retry-After`), CSRF on the hide routes, hide `201` then `200`, restore `204`, the
    /// cache drop on `PUT /credentials/:id`, and that the sentinel secret never appears in a
    /// response body. The upstream is a recorded fake; no live Harbor or GitHub is used.
    #[tokio::test]
    async fn picker_routes_check_session_tenancy_csrf_cache_and_secrets() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use services::pickers::tests::{Recorded, SENTINEL, ok, robot_ok, status};
        use std::sync::atomic::Ordering;
        use tower::ServiceExt;

        let fake = Arc::new(Recorded::default());
        robot_ok(&fake);
        fake.on(
            |url: &reqwest::Url| url.path() == "/api/v2.0/projects",
            ok(r#"[{"name":"alpha"},{"name":"beta"}]"#),
        );
        let mut limited = status(429);
        limited.retry_after = Some(30);
        fake.on(|url: &reqwest::Url| url.path() == "/user/repos", limited);
        let (router, pool, dir, _) = test_router_full(
            "picker-routes",
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
            api::state::HarborProbeHandle::new(Arc::new(ReadableHarbor)),
            api::state::HarborFetchHandle::outbound(false).unwrap(),
            services::pickers::PickerState::new(fake.clone()),
        )
        .await;
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        drop(conn);
        let mut ids = Vec::new();
        for (service, base_url, username) in [
            (
                services::credentials::SERVICE_HARBOR,
                Some("https://harbor.example.com"),
                Some("robot$hg"),
            ),
            (services::credentials::SERVICE_GITHUB, None, None),
        ] {
            let created = services::credentials::create(
                &pool,
                &auth::crypto::credentials_key(&root).unwrap(),
                &services::audit::Actor {
                    user_id: Some("owner-1".to_owned()),
                    username: "owner-1".to_owned(),
                },
                "owner-1",
                services::credentials::NewCredential {
                    service_type: service.to_owned(),
                    label: service.to_owned(),
                    base_url: base_url.map(str::to_owned),
                    username: username.map(str::to_owned),
                    token: SENTINEL.to_owned(),
                    expires_at: None,
                },
                false,
            )
            .await
            .unwrap();
            ids.push(created.id);
        }
        let (harbor, github) = (ids[0].clone(), ids[1].clone());

        let key = auth::crypto::csrf_key(&root).unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let send = |method: &str, uri: String, cookie: &str, token: Option<&str>, body: &str| {
            let mut builder = with_peer(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("cookie", cookie)
                    .header("content-type", "application/json"),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            let request = builder.body(Body::from(body.to_owned())).unwrap();
            let router = router.clone();
            async move {
                let response = router.oneshot(request).await.unwrap();
                let status = response.status();
                let retry = response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .map(|v| v.to_str().unwrap().to_owned());
                let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                (status, retry, String::from_utf8_lossy(&bytes).into_owned())
            }
        };
        let projects = format!("/api/v1/credentials/{harbor}/harbor-projects");
        let mut bodies = Vec::new();

        let anonymous = send("GET", projects.clone(), &csrf_cookie, None, "").await;
        let foreign = send("GET", projects.clone(), &other, None, "").await;
        let owned = send("GET", projects.clone(), &owner, None, "").await;
        let wrong_type = send(
            "GET",
            format!("/api/v1/credentials/{github}/harbor-projects"),
            &owner,
            None,
            "",
        )
        .await;
        let rate = send(
            "GET",
            format!("/api/v1/credentials/{github}/github-repositories"),
            &owner,
            None,
            "",
        )
        .await;
        let hide_body = r#"{"source":"harbor","full_name":"alpha","harbor_base_url":"https://harbor.example.com"}"#;
        let no_csrf = send(
            "POST",
            "/api/v1/pickers/hidden".to_owned(),
            &owner,
            None,
            hide_body,
        )
        .await;
        let hidden = send(
            "POST",
            "/api/v1/pickers/hidden".to_owned(),
            &owner,
            Some(&csrf),
            hide_body,
        )
        .await;
        let hidden_again = send(
            "POST",
            "/api/v1/pickers/hidden".to_owned(),
            &owner,
            Some(&csrf),
            hide_body,
        )
        .await;
        let github_with_base = send(
            "POST",
            "/api/v1/pickers/hidden".to_owned(),
            &owner,
            Some(&csrf),
            r#"{"source":"github","full_name":"octo/app","harbor_base_url":"https://harbor.example.com"}"#,
        )
        .await;
        let filtered = send("GET", projects.clone(), &owner, None, "").await;
        let calls_before_put = fake.calls.load(Ordering::SeqCst);
        let put = send(
            "PUT",
            format!("/api/v1/credentials/{harbor}"),
            &owner,
            Some(&csrf),
            r#"{"label":"renamed"}"#,
        )
        .await;
        let after_put = send("GET", projects.clone(), &owner, None, "").await;
        let calls_after_put = fake.calls.load(Ordering::SeqCst);
        let item: serde_json::Value = serde_json::from_str(&hidden.2).unwrap();
        let item_id = item["id"].as_str().unwrap().to_owned();
        let foreign_restore = send(
            "DELETE",
            format!("/api/v1/pickers/hidden/{item_id}"),
            &other,
            Some(&csrf),
            "",
        )
        .await;
        let restored = send(
            "DELETE",
            format!("/api/v1/pickers/hidden/{item_id}"),
            &owner,
            Some(&csrf),
            "",
        )
        .await;
        let listed = send("GET", "/api/v1/pickers/hidden".to_owned(), &owner, None, "").await;
        for response in [
            &anonymous,
            &foreign,
            &owned,
            &wrong_type,
            &rate,
            &no_csrf,
            &hidden,
            &hidden_again,
            &github_with_base,
            &filtered,
            &put,
            &after_put,
            &foreign_restore,
            &restored,
            &listed,
        ] {
            bodies.push(response.2.clone());
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anonymous.0, StatusCode::UNAUTHORIZED);
        assert_eq!(foreign.0, StatusCode::NOT_FOUND);
        assert_eq!(owned.0, StatusCode::OK, "{}", owned.2);
        let page: serde_json::Value = serde_json::from_str(&owned.2).unwrap();
        assert_eq!(page["total"], 2);
        assert_eq!(page["truncated"], false);
        assert_eq!(page["items"][0], serde_json::json!({"name": "alpha"}));
        assert_eq!(wrong_type.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(rate.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rate.1.as_deref(), Some("30"));
        assert!(
            rate.2
                .contains("GitHub rate limit reached. Try again later.")
        );
        assert_eq!(no_csrf.0, StatusCode::FORBIDDEN);
        assert_eq!(hidden.0, StatusCode::CREATED, "{}", hidden.2);
        assert_eq!(item["harbor_base_url"], "https://harbor.example.com");
        assert_eq!(hidden_again.0, StatusCode::OK);
        assert_eq!(github_with_base.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            github_with_base
                .2
                .contains("harbor_base_url is only for Harbor items.")
        );
        let page: serde_json::Value = serde_json::from_str(&filtered.2).unwrap();
        assert_eq!(page["total"], 1, "the hidden project is left out");
        assert_eq!(put.0, StatusCode::OK);
        assert_eq!(after_put.0, StatusCode::OK);
        assert_eq!(
            calls_after_put - calls_before_put,
            2,
            "the credential update dropped the cache, so the list was fetched again"
        );
        assert_eq!(foreign_restore.0, StatusCode::NOT_FOUND);
        assert_eq!(restored.0, StatusCode::NO_CONTENT);
        let listed: serde_json::Value = serde_json::from_str(&listed.2).unwrap();
        assert_eq!(listed["total"], 0);
        for body in bodies {
            assert!(!body.contains(SENTINEL), "the sentinel leaked: {body}");
            assert!(
                !body.contains("upstream detail"),
                "an upstream body leaked: {body}"
            );
        }
    }

    /// An admin session gets `404` on another user's credential for every picker route
    /// (`specs/api.md`, Pickers: there is no admin exception), and a credential update
    /// clears the credential's upstream rate-limit block (#126).
    #[tokio::test]
    async fn picker_routes_give_an_admin_404_and_an_update_clears_the_block() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use services::pickers::tests::{Recorded, SENTINEL, ok, robot_ok, status};
        use std::sync::atomic::Ordering;
        use tower::ServiceExt;

        let fake = Arc::new(Recorded::default());
        robot_ok(&fake);
        fake.on(
            |url: &reqwest::Url| url.path() == "/api/v2.0/projects",
            ok(r#"[{"name":"alpha"}]"#),
        );
        let mut limited = status(429);
        limited.retry_after = Some(300);
        fake.on(|url: &reqwest::Url| url.path() == "/user/repos", limited);
        let (router, pool, dir, _) = test_router_full(
            "picker-admin-404",
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
            api::state::HarborProbeHandle::new(Arc::new(ReadableHarbor)),
            api::state::HarborFetchHandle::outbound(false).unwrap(),
            services::pickers::PickerState::new(fake.clone()),
        )
        .await;
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, "owner-1", "owner-1", None, "h", "user")
            .await
            .unwrap();
        db::users::insert_local(&mut conn, "admin-3", "admin-3", None, "h", "admin")
            .await
            .unwrap();
        drop(conn);
        let mut ids = Vec::new();
        for (service, base_url, username) in [
            (
                services::credentials::SERVICE_HARBOR,
                Some("https://harbor.example.com"),
                Some("robot$hg"),
            ),
            (services::credentials::SERVICE_GITHUB, None, None),
        ] {
            let created = services::credentials::create(
                &pool,
                &auth::crypto::credentials_key(&root).unwrap(),
                &services::audit::Actor {
                    user_id: Some("owner-1".to_owned()),
                    username: "owner-1".to_owned(),
                },
                "owner-1",
                services::credentials::NewCredential {
                    service_type: service.to_owned(),
                    label: service.to_owned(),
                    base_url: base_url.map(str::to_owned),
                    username: username.map(str::to_owned),
                    token: SENTINEL.to_owned(),
                    expires_at: None,
                },
                false,
            )
            .await
            .unwrap();
            ids.push(created.id);
        }
        let (harbor, github) = (ids[0].clone(), ids[1].clone());
        let key = auth::crypto::csrf_key(&root).unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let admin = format!("{}; {csrf_cookie}", session_cookie("admin-3", "admin", 0));
        let send = |method: &str, uri: String, cookie: &str, body: &str| {
            let request = with_peer(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf.as_str())
                    .header("content-type", "application/json"),
            )
            .body(Body::from(body.to_owned()))
            .unwrap();
            let router = router.clone();
            async move { router.oneshot(request).await.unwrap().status() }
        };

        // Admin on the owner's credential: 404 on all four routes, and no upstream call.
        for uri in [
            format!("/api/v1/credentials/{harbor}/harbor-projects"),
            format!("/api/v1/credentials/{harbor}/harbor-projects/proj/repositories"),
            format!("/api/v1/credentials/{github}/github-repositories"),
            format!("/api/v1/credentials/{harbor}/source-suggestion?project=proj&repository=app"),
        ] {
            assert_eq!(
                send("GET", uri.clone(), &admin, "").await,
                StatusCode::NOT_FOUND,
                "{uri}"
            );
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);

        // Set a block with a GitHub 429, and check it holds without a call.
        let github_list = format!("/api/v1/credentials/{github}/github-repositories");
        assert_eq!(
            send("GET", github_list.clone(), &owner, "").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            send("GET", github_list.clone(), &owner, "").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "the block made no call"
        );

        // Updating the credential clears the block, so the next request calls upstream.
        assert_eq!(
            send(
                "PUT",
                format!("/api/v1/credentials/{github}"),
                &owner,
                r#"{"label":"renamed"}"#
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            send("GET", github_list, &owner, "").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            2,
            "the update cleared the block, so upstream was called again"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Deleting a user through `DELETE /admin/users/:id` drops the picker cache entries and
    /// the rate-limit block of each credential the user owned (#126).
    #[tokio::test]
    async fn deleting_a_user_drops_their_picker_cache_and_blocks() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use services::pickers::tests::{Recorded, SENTINEL, ok, robot_ok, status};
        use tower::ServiceExt;

        let fake = Arc::new(Recorded::default());
        robot_ok(&fake);
        fake.on(
            |url: &reqwest::Url| url.path() == "/api/v2.0/projects",
            ok(r#"[{"name":"alpha"}]"#),
        );
        let mut limited = status(429);
        limited.retry_after = Some(300);
        fake.on(|url: &reqwest::Url| url.path() == "/user/repos", limited);
        let pickers = services::pickers::PickerState::new(fake.clone());
        let (router, pool, dir, _) = test_router_full(
            "picker-user-delete",
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
            api::state::HarborProbeHandle::new(Arc::new(ReadableHarbor)),
            api::state::HarborFetchHandle::outbound(false).unwrap(),
            pickers.clone(),
        )
        .await;
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, "owner-1", "owner-1", None, "h", "user")
            .await
            .unwrap();
        db::users::insert_local(&mut conn, "admin-3", "admin-3", None, "h", "admin")
            .await
            .unwrap();
        drop(conn);
        let mut ids = Vec::new();
        for (service, base_url, username) in [
            (
                services::credentials::SERVICE_HARBOR,
                Some("https://harbor.example.com"),
                Some("robot$hg"),
            ),
            (services::credentials::SERVICE_GITHUB, None, None),
        ] {
            let created = services::credentials::create(
                &pool,
                &auth::crypto::credentials_key(&root).unwrap(),
                &services::audit::Actor {
                    user_id: Some("owner-1".to_owned()),
                    username: "owner-1".to_owned(),
                },
                "owner-1",
                services::credentials::NewCredential {
                    service_type: service.to_owned(),
                    label: service.to_owned(),
                    base_url: base_url.map(str::to_owned),
                    username: username.map(str::to_owned),
                    token: SENTINEL.to_owned(),
                    expires_at: None,
                },
                false,
            )
            .await
            .unwrap();
            ids.push(created.id);
        }
        let key = auth::crypto::csrf_key(&root).unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let admin = format!("{}; {csrf_cookie}", session_cookie("admin-3", "admin", 0));
        let send = |method: &str, uri: String, cookie: &str, token: Option<&str>| {
            let mut builder = with_peer(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            let request = builder.body(Body::empty()).unwrap();
            let router = router.clone();
            async move { router.oneshot(request).await.unwrap().status() }
        };

        // One cached Harbor list, and a GitHub rate-limit block.
        let listed = send(
            "GET",
            format!("/api/v1/credentials/{}/harbor-projects", ids[0]),
            &owner,
            None,
        )
        .await;
        let limited = send(
            "GET",
            format!("/api/v1/credentials/{}/github-repositories", ids[1]),
            &owner,
            None,
        )
        .await;
        assert_eq!(listed, StatusCode::OK);
        assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
        // Two slots (the Harbor list, and the empty slot of the rate-limited GitHub fill) and
        // one block.
        assert_eq!(pickers.held(), (2, 1), "entries and a block are held");

        let deleted = send(
            "DELETE",
            "/api/v1/admin/users/owner-1".to_owned(),
            &admin,
            Some(&csrf),
        )
        .await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(deleted, StatusCode::NO_CONTENT);
        assert_eq!(
            pickers.held(),
            (0, 0),
            "the deleted user's cache entry and block were dropped"
        );
    }

    /// A Harbor reader that answers the artifact list from recorded bodies. Page 1 of a
    /// repository has its body; later pages are empty. An unknown repository answers `500`.
    /// No socket is opened.
    struct RecordedHarbor;

    impl api::state::DynHarborFetch for RecordedHarbor {
        fn fetch<'a>(
            &'a self,
            url: &'a reqwest::Url,
            _username: &'a str,
            _secret: &'a [u8],
            _extra_headers: &'a [(&'a str, &'a str)],
        ) -> api::state::ProbeFuture<'a, services::harbor_client::HarborReply> {
            let repository = url
                .path()
                .split('/')
                .rev()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let first_page = url.query().unwrap_or_default().starts_with("page=1&");
            Box::pin(async move {
                let body = match repository.as_str() {
                    "app" => r#"[{"digest": "sha256:aaaa", "tags": [{"name": "v1"}]}]"#,
                    "two" => {
                        r#"[{"digest": "sha256:bbbb", "tags": [{"name": "v1"}, {"name": "v2"}]}]"#
                    }
                    _ => {
                        return Ok(services::harbor_client::HarborReply::new(
                            500,
                            b"harbor exploded".to_vec(),
                        ));
                    }
                };
                if first_page {
                    Ok(services::harbor_client::HarborReply::new(
                        200,
                        body.as_bytes().to_vec(),
                    ))
                } else {
                    Ok(services::harbor_client::HarborReply::new(
                        200,
                        b"[]".to_vec(),
                    ))
                }
            })
        }
    }

    /// `POST /api/v1/mappings/:id/pull` through the router (#131). Checks session (`401`),
    /// CSRF (`403`), tenancy (another user `404`, the owner and an admin `200`), the
    /// 5-minute cooldown (`429` with `Retry-After`), a Harbor error (`502` with fixed text,
    /// which still uses the cooldown), and the `mapping.pull` audit row. Harbor is a fake.
    #[tokio::test]
    async fn mapping_pull_route_checks_session_csrf_tenancy_and_cooldown() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let fetch = api::state::HarborFetchHandle::new(Arc::new(RecordedHarbor));
        let (router, pool, dir, _) = test_router_with_fetch(
            "mapping-pull-route",
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
            api::state::HarborProbeHandle::new(Arc::new(ReadableHarbor)),
            fetch,
        )
        .await;
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [
            ("owner-1", "user"),
            ("other-2", "user"),
            ("admin-3", "admin"),
        ] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        let owner_actor = services::audit::Actor {
            user_id: Some("owner-1".to_owned()),
            username: "owner-1".to_owned(),
        };
        let mut cred_ids = Vec::new();
        for (service, base_url, username) in [
            (
                services::credentials::SERVICE_HARBOR,
                Some("https://harbor.example.com"),
                Some("robot$hg"),
            ),
            (services::credentials::SERVICE_GITHUB, None, None),
        ] {
            let created = services::credentials::create(
                &pool,
                &auth::crypto::credentials_key(&root).unwrap(),
                &owner_actor,
                "owner-1",
                services::credentials::NewCredential {
                    service_type: service.to_owned(),
                    label: service.to_owned(),
                    base_url: base_url.map(str::to_owned),
                    username: username.map(str::to_owned),
                    token: "test-fake-secret".to_owned(),
                    expires_at: None,
                },
                false,
            )
            .await
            .unwrap();
            cred_ids.push(created.id);
        }
        // rm1 (repository app), rm2 (two) and rm3 (broken, Harbor answers 500).
        for (id, repository) in [("rm1", "app"), ("rm2", "two"), ("rm3", "broken")] {
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
                 VALUES (?, 'owner-1', ?, ?, 'https://harbor.example.com', 'proj', ?, 'octo', ?, ?, ?)",
            )
            .bind(id)
            .bind(&cred_ids[0])
            .bind(&cred_ids[1])
            .bind(repository)
            .bind(repository)
            .bind(format!("{id}-token"))
            .bind(format!("{id}-secret"))
            .execute(&pool)
            .await
            .unwrap();
        }

        let key = auth::crypto::csrf_key(&root).unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let admin = format!("{}; {csrf_cookie}", session_cookie("admin-3", "admin", 0));
        let pull = |cookie: &str, token: Option<&str>, id: &str| {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/mappings/{id}/pull"))
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::empty()).unwrap()
        };
        let send = |request: Request<Body>| {
            let router = router.clone();
            async move {
                let response = router.oneshot(request).await.unwrap();
                let status = response.status();
                let retry_after = response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .map(|value| value.to_str().unwrap().to_owned());
                let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                    .await
                    .unwrap();
                let json: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                (status, retry_after, json)
            }
        };

        // No session, CSRF passes: 401.
        let anonymous = send(pull(&csrf_cookie, Some(&csrf), "rm1")).await;
        // A session but no CSRF token: 403.
        let no_csrf = send(pull(&owner, None, "rm1")).await;
        // Another user: 404, and the cooldown is not used.
        let foreign = send(pull(&other, Some(&csrf), "rm1")).await;
        let missing = send(pull(&owner, Some(&csrf), "nope")).await;
        // The owner: 200, one job queued.
        let owned = send(pull(&owner, Some(&csrf), "rm1")).await;
        // The owner again within 5 minutes: 429 with Retry-After.
        let again = send(pull(&owner, Some(&csrf), "rm1")).await;
        // An admin on the owner's other mapping: 200, two jobs (one per tag).
        let by_admin = send(pull(&admin, Some(&csrf), "rm2")).await;
        // Harbor fails: 502 with fixed text, and the cooldown is still used.
        let broken = send(pull(&owner, Some(&csrf), "rm3")).await;
        let broken_again = send(pull(&owner, Some(&csrf), "rm3")).await;

        let jobs: Vec<(String, String)> =
            sqlx::query_as("SELECT mapping_id, payload FROM sync_jobs ORDER BY mapping_id, id")
                .fetch_all(&pool)
                .await
                .unwrap();
        let audits: Vec<(Option<String>, String, Option<String>)> = sqlx::query_as(
            "SELECT actor_user_id, target, details FROM audit_log
             WHERE action = 'mapping.pull' ORDER BY target",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anonymous.0, StatusCode::UNAUTHORIZED);
        assert_eq!(no_csrf.0, StatusCode::FORBIDDEN);
        assert_eq!(foreign.0, StatusCode::NOT_FOUND);
        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(
            owned.0,
            StatusCode::OK,
            "owner pull was refused: {:?}",
            owned.2
        );
        assert_eq!(owned.2, serde_json::json!({ "queued": 1 }));
        assert_eq!(again.0, StatusCode::TOO_MANY_REQUESTS);
        let wait: u64 = again.1.expect("429 carries Retry-After").parse().unwrap();
        assert!((1..=300).contains(&wait), "Retry-After was {wait}");
        assert_eq!(by_admin.0, StatusCode::OK, "admin pull was refused");
        assert_eq!(by_admin.2, serde_json::json!({ "queued": 2 }));
        assert_eq!(broken.0, StatusCode::BAD_GATEWAY);
        assert_eq!(broken.2["error"]["code"], "upstream_unreachable");
        let text = broken.2.to_string();
        assert!(
            !text.contains("exploded"),
            "the Harbor answer leaked: {text}"
        );
        assert!(
            !text.contains("harbor.example.com"),
            "the URL leaked: {text}"
        );
        assert_eq!(broken_again.0, StatusCode::TOO_MANY_REQUESTS);

        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[0].0, "rm1");
        let payload: serde_json::Value = serde_json::from_str(&jobs[0].1).unwrap();
        assert_eq!(payload["trigger"], "poll");
        assert_eq!(payload["digest"], "sha256:aaaa");

        // One audit row per pull that finished, none for the Harbor failure.
        assert_eq!(audits.len(), 2);
        assert_eq!(audits[0].0.as_deref(), Some("owner-1"));
        assert_eq!(audits[0].1, "mapping:rm1");
        let details: serde_json::Value =
            serde_json::from_str(audits[0].2.as_deref().unwrap()).unwrap();
        assert_eq!(
            details,
            serde_json::json!({ "mapping_id": "rm1", "queued": 1 })
        );
        assert_eq!(audits[1].0.as_deref(), Some("admin-3"));
        assert_eq!(audits[1].1, "mapping:rm2");
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
        let outbound = api::state::HarborProbeHandle::outbound(false).unwrap();
        test_router_with_probe(name, login_throttle, webhook_token_limiter, outbound).await
    }

    /// The full test router with the given Harbor probe. A router test that changes a
    /// Harbor repository passes a fake here, so no live Harbor is called.
    async fn test_router_with_probe(
        name: &str,
        login_throttle: services::throttle::LoginThrottle,
        webhook_token_limiter: api::hardening::RateLimiter,
        harbor_probe: api::state::HarborProbeHandle,
    ) -> (
        Router,
        sqlx::SqlitePool,
        std::path::PathBuf,
        api::hardening::RateLimiter,
    ) {
        let fetch = api::state::HarborFetchHandle::outbound(false).unwrap();
        test_router_with_fetch(
            name,
            login_throttle,
            webhook_token_limiter,
            harbor_probe,
            fetch,
        )
        .await
    }

    /// The full test router with the given Harbor probe and Harbor reader. The manual
    /// pull router test passes a fake reader here, so no live Harbor is called.
    async fn test_router_with_fetch(
        name: &str,
        login_throttle: services::throttle::LoginThrottle,
        webhook_token_limiter: api::hardening::RateLimiter,
        harbor_probe: api::state::HarborProbeHandle,
        harbor_fetch: api::state::HarborFetchHandle,
    ) -> (
        Router,
        sqlx::SqlitePool,
        std::path::PathBuf,
        api::hardening::RateLimiter,
    ) {
        test_router_full(
            name,
            login_throttle,
            webhook_token_limiter,
            harbor_probe,
            harbor_fetch,
            services::pickers::PickerState::outbound(false, Default::default()).unwrap(),
        )
        .await
    }

    /// The full test router with every injectable part. The picker router tests pass a
    /// fake picker transport here, so no live Harbor or GitHub is called.
    pub(crate) async fn test_router_full(
        name: &str,
        login_throttle: services::throttle::LoginThrottle,
        webhook_token_limiter: api::hardening::RateLimiter,
        harbor_probe: api::state::HarborProbeHandle,
        harbor_fetch: api::state::HarborFetchHandle,
        pickers: services::pickers::PickerState,
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
                crate::services::github_issues::GithubIssues::new(Default::default()).unwrap(),
            ),
            harbor_probe,
            app_log: std::sync::Arc::new(crate::services::app_log::AppLog::detached(
                crate::services::app_log::REVERT_AFTER,
            )),
            harbor_fetch,
            pull_limiter: api::mappings::new_pull_limiter(),
            scanner_launch: Default::default(),
            github: pickers.github_target(),
            pickers,
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

    /// One project webhook on `proj` with two mappings: `proj/app` and `proj/other`. The
    /// project token and secret are the given fake values.
    async fn project_fixture(pool: &sqlx::SqlitePool, token: &str, secret: &str) {
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, token_version)
             VALUES ('pu', 'pu', NULL, 'user', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES ('pc1', 'pu', 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake'),
                    ('pc2', 'pu', 'github', 'g', NULL, NULL, 'v1:fake')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO project_webhooks (id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash)
             VALUES ('pw1', 'pu', 'https://harbor.example.com', 'proj', ?, ?)",
        )
        .bind(services::mappings::digest(token))
        .bind(services::mappings::digest(secret))
        .execute(pool)
        .await
        .unwrap();
        for (id, repo) in [("pm-app", "app"), ("pm-other", "other")] {
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch)
                 VALUES (?, 'pu', 'pc1', 'pc2', 'https://harbor.example.com', 'proj', ?, 'o', ?, ?, ?, 0, 'CRITICAL', 'main')",
            )
            .bind(id)
            .bind(repo)
            .bind(repo)
            .bind(services::mappings::digest(&format!("mt-{id}")))
            .bind(services::mappings::digest(&format!("ms-{id}")))
            .execute(pool)
            .await
            .unwrap();
        }
    }

    /// A project webhook request to `project_token`, with the given body and auth value.
    fn project_request(
        project_token: &str,
        auth: Option<&str>,
        body: &str,
    ) -> axum::http::Request<axum::body::Body> {
        let mut builder = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/api/v1/webhooks/harbor/project/{project_token}"))
                .header("content-type", "application/json"),
        );
        if let Some(value) = auth {
            builder = builder.header("authorization", value);
        }
        builder
            .body(axum::body::Body::from(body.to_owned()))
            .unwrap()
    }

    /// The event for repository `repo` on project `proj`.
    fn repo_event(repo: &str) -> String {
        full_name_event(&format!("proj/{repo}"))
    }

    /// The event for an exact `repo_full_name`, whatever its project.
    fn full_name_event(full_name: &str) -> String {
        format!(
            r#"{{"type":"SCANNING_COMPLETED","event_data":{{"repository":{{"repo_full_name":"{full_name}"}},"resources":[{{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tag":"v1"}}],"scan":{{"scan_type":"vulnerability"}}}}}}"#
        )
    }

    /// A default-format vulnerability event for `proj/app`.
    /// It is untagged, so it stores one resolve job (#132).
    const WEBHOOK_BODY: &str = r#"{"type":"SCANNING_COMPLETED","event_data":{"repository":{"repo_full_name":"proj/app"},"resources":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"scan":{"scan_type":"vulnerability"}}}"#;

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

    /// A JSON request with optional cookie and CSRF header. Returns status and parsed body.
    async fn send_json(
        router: &Router,
        method: &str,
        uri: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        body: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let mut builder = with_peer(
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json"),
        );
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        if let Some(token) = csrf {
            builder = builder.header("x-csrf-token", token);
        }
        let request = builder
            .body(axum::body::Body::from(body.to_owned()))
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

    /// The project webhook management routes through the router (#132): session (`401`),
    /// CSRF (`403`), create (`201`), duplicate (`409`), unowned mapping (`404`), admin read
    /// (`200`) but admin rotate (`403`), owner rotation with the old token refused and the new
    /// one accepted, the unmatched list, and the per-mapping URL still `202`.
    #[tokio::test]
    async fn project_webhook_routes_check_session_csrf_owner_and_admin() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("project-webhook-api").await;
        webhook_fixture(&pool, "map-tok-fake", "map-sec-fake").await;
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [("pa", "admin"), ("px", "user")] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("wu", "user", 0));
        let admin = format!("{}; {csrf_cookie}", session_cookie("pa", "admin", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("px", "user", 0));
        let body = r#"{"mapping_id":"wm1"}"#;
        let create = "/api/v1/project-webhooks";

        let (anonymous, _) = send_json(
            &router,
            "POST",
            create,
            Some(&csrf_cookie),
            Some(&csrf),
            body,
        )
        .await;
        let (no_csrf, _) = send_json(&router, "POST", create, Some(&owner), None, body).await;
        let (foreign, _) =
            send_json(&router, "POST", create, Some(&other), Some(&csrf), body).await;
        let (created_status, created) =
            send_json(&router, "POST", create, Some(&owner), Some(&csrf), body).await;
        let (duplicate, dup_body) =
            send_json(&router, "POST", create, Some(&owner), Some(&csrf), body).await;
        assert_eq!(anonymous, StatusCode::UNAUTHORIZED);
        assert_eq!(no_csrf, StatusCode::FORBIDDEN);
        assert_eq!(foreign, StatusCode::NOT_FOUND);
        assert_eq!(created_status, StatusCode::CREATED);
        assert_eq!(duplicate, StatusCode::CONFLICT);
        assert_eq!(dup_body["error"]["code"], "conflict");
        let id = created["id"].as_str().unwrap().to_owned();
        let url = created["webhook_url"].as_str().unwrap().to_owned();
        let auth_secret = created["auth_secret"].as_str().unwrap().to_owned();
        assert!(url.starts_with("https://harborgate.example.com/api/v1/webhooks/harbor/project/"));
        let old_token = url.rsplit('/').next().unwrap().to_owned();

        // The per-mapping URL keeps working after a project webhook exists.
        let per_mapping = router
            .clone()
            .oneshot(webhook_request(
                "map-tok-fake",
                Some("Bearer map-sec-fake"),
                WEBHOOK_BODY,
            ))
            .await
            .unwrap()
            .status();
        assert_eq!(per_mapping, StatusCode::ACCEPTED);
        // The project URL accepts the shown values.
        let via_project = router
            .clone()
            .oneshot(project_request(
                &old_token,
                Some(&auth_secret),
                &repo_event("app"),
            ))
            .await
            .unwrap()
            .status();
        assert_eq!(via_project, StatusCode::ACCEPTED);

        // Reads: no session 401, owner and admin 200, another user 403. No values in GET.
        let item = format!("/api/v1/project-webhooks/{id}");
        let (read_anon, _) = get_json(&router, &item, &csrf_cookie).await;
        let (read_other, _) = get_json(&router, &item, &other).await;
        let (read_admin, admin_view) = get_json(&router, &item, &admin).await;
        let (read_owner, owner_view) = get_json(&router, &item, &owner).await;
        assert_eq!(read_anon, StatusCode::UNAUTHORIZED);
        assert_eq!(read_other, StatusCode::FORBIDDEN);
        assert_eq!(read_admin, StatusCode::OK);
        assert_eq!(read_owner, StatusCode::OK);
        assert_eq!(admin_view["owner"], "wu");
        assert_eq!(admin_view["mappings"], serde_json::json!(["app"]));
        assert!(owner_view["rotated_at"].is_null());
        let text = owner_view.to_string();
        assert!(!text.contains(&old_token) && !text.contains(&auth_secret));

        // Rotation: CSRF-less 403, admin 403, other 403, owner 200.
        let rotate = format!("/api/v1/project-webhooks/{id}/rotate-token");
        let (rot_no_csrf, _) = send_json(&router, "POST", &rotate, Some(&owner), None, "").await;
        let (rot_admin, _) =
            send_json(&router, "POST", &rotate, Some(&admin), Some(&csrf), "").await;
        let (rot_other, _) =
            send_json(&router, "POST", &rotate, Some(&other), Some(&csrf), "").await;
        let (rot_anon, _) = send_json(
            &router,
            "POST",
            &rotate,
            Some(&csrf_cookie),
            Some(&csrf),
            "",
        )
        .await;
        let (rot_owner, rotated) =
            send_json(&router, "POST", &rotate, Some(&owner), Some(&csrf), "").await;
        assert_eq!(rot_no_csrf, StatusCode::FORBIDDEN);
        assert_eq!(rot_admin, StatusCode::FORBIDDEN);
        assert_eq!(rot_other, StatusCode::FORBIDDEN);
        assert_eq!(rot_anon, StatusCode::UNAUTHORIZED);
        assert_eq!(rot_owner, StatusCode::OK);
        assert_eq!(rotated["mappings"], serde_json::json!(["app"]));
        let new_token = rotated["webhook_url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let old_refused = router
            .clone()
            .oneshot(project_request(
                &old_token,
                Some(&auth_secret),
                &repo_event("app"),
            ))
            .await
            .unwrap()
            .status();
        assert_eq!(old_refused, StatusCode::UNAUTHORIZED);

        let secret_uri = format!("/api/v1/project-webhooks/{id}/rotate-secret");
        let (sec_admin, _) =
            send_json(&router, "POST", &secret_uri, Some(&admin), Some(&csrf), "").await;
        let (sec_owner, secret) =
            send_json(&router, "POST", &secret_uri, Some(&owner), Some(&csrf), "").await;
        assert_eq!(sec_admin, StatusCode::FORBIDDEN);
        assert_eq!(sec_owner, StatusCode::OK);
        let new_secret = secret["auth_secret"].as_str().unwrap().to_owned();
        let old_secret = router
            .clone()
            .oneshot(project_request(
                &new_token,
                Some(&auth_secret),
                &repo_event("app"),
            ))
            .await
            .unwrap()
            .status();
        let both_new = router
            .clone()
            .oneshot(project_request(
                &new_token,
                Some(&new_secret),
                &repo_event("stranger"),
            ))
            .await
            .unwrap()
            .status();
        assert_eq!(old_secret, StatusCode::UNAUTHORIZED);
        assert_eq!(both_new, StatusCode::ACCEPTED);

        // The unmatched event is listed for the owner and an admin, and refused for others.
        let list = format!("/api/v1/project-webhooks/{id}/unmatched?page_size=10");
        let (list_owner, page) = get_json(&router, &list, &owner).await;
        let (list_admin, _) = get_json(&router, &list, &admin).await;
        let (list_other, _) = get_json(&router, &list, &other).await;
        let (list_anon, _) = get_json(&router, &list, &csrf_cookie).await;
        assert_eq!(list_owner, StatusCode::OK);
        assert_eq!(list_admin, StatusCode::OK);
        assert_eq!(list_other, StatusCode::FORBIDDEN);
        assert_eq!(list_anon, StatusCode::UNAUTHORIZED);
        assert_eq!(page["total"], 1);
        assert_eq!(page["page_size"], 10);
        assert_eq!(page["items"][0]["repository"], "proj/stranger");
        assert_eq!(page["items"][0]["count"], 1);

        let (missing, _) = get_json(&router, "/api/v1/project-webhooks/nope", &owner).await;
        assert_eq!(missing, StatusCode::NOT_FOUND);

        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE action LIKE 'project_webhook.%' ORDER BY rowid",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            actions,
            vec![
                "project_webhook.create",
                "project_webhook.token_rotate",
                "project_webhook.secret_rotate"
            ]
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `rotate-secret` needs a CSRF token (`403`) and the owner (`403` for another user), and
    /// neither refused call changes the stored secret (#145).
    #[tokio::test]
    async fn rotate_secret_needs_csrf_and_the_owner() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("project-rotate-secret").await;
        webhook_fixture(&pool, "map-tok-fake", "map-sec-fake").await;
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, "px", "px", None, "h", "user")
            .await
            .unwrap();
        drop(conn);
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("wu", "user", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("px", "user", 0));
        let (created_status, created) = send_json(
            &router,
            "POST",
            "/api/v1/project-webhooks",
            Some(&owner),
            Some(&csrf),
            r#"{"mapping_id":"wm1"}"#,
        )
        .await;
        assert_eq!(created_status, StatusCode::CREATED);
        let id = created["id"].as_str().unwrap().to_owned();
        let uri = format!("/api/v1/project-webhooks/{id}/rotate-secret");
        let before: String =
            sqlx::query_scalar("SELECT secret_hash FROM project_webhooks WHERE id = ?")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let (no_csrf, _) = send_json(&router, "POST", &uri, Some(&owner), None, "").await;
        let (non_owner, _) = send_json(&router, "POST", &uri, Some(&other), Some(&csrf), "").await;
        assert_eq!(no_csrf, StatusCode::FORBIDDEN);
        assert_eq!(non_owner, StatusCode::FORBIDDEN);
        let after: String =
            sqlx::query_scalar("SELECT secret_hash FROM project_webhooks WHERE id = ?")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(before, after);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A project event for a mapped repository is routed to that mapping and queues a job.
    #[tokio::test]
    async fn project_event_routes_to_the_matching_mapping() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("project-route").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        let response = router
            .oneshot(project_request(
                "proj-tok-fake",
                Some("Bearer proj-sec-fake"),
                &repo_event("app"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let jobs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sync_jobs WHERE mapping_id = 'pm-app'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(jobs, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An event for a repository with no mapping is counted and queues nothing: the project
    /// webhook does not silently drop it, and it does not create a job for another mapping.
    #[tokio::test]
    async fn unmatched_project_event_is_counted_and_queues_nothing() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("project-unmatched").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        let response = router
            .oneshot(project_request(
                "proj-tok-fake",
                Some("Bearer proj-sec-fake"),
                &repo_event("stranger"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(jobs, 0);
        let count: i64 = sqlx::query_scalar(
            "SELECT count FROM project_webhook_unmatched WHERE repository = 'proj/stranger'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A wrong project secret is refused, even for an event that would be unmatched, so an
    /// unknown sender cannot fill the unmatched count.
    #[tokio::test]
    async fn project_wrong_secret_is_refused_before_counting() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("project-secret").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        for repo in ["app", "stranger"] {
            let response = router
                .clone()
                .oneshot(project_request(
                    "proj-tok-fake",
                    Some("Bearer wrong-secret"),
                    &repo_event(repo),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let unmatched: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM project_webhook_unmatched")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(unmatched, 0);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn post_project(
        router: &Router,
        auth: Option<&str>,
        body: &str,
    ) -> axum::http::StatusCode {
        use tower::ServiceExt;
        router
            .clone()
            .oneshot(project_request("proj-tok-fake", auth, body))
            .await
            .unwrap()
            .status()
    }

    async fn table_count(pool: &sqlx::SqlitePool, table: &str) -> i64 {
        let sql = match table {
            "sync_jobs" => "SELECT COUNT(*) FROM sync_jobs",
            _ => "SELECT COUNT(*) FROM project_webhook_unmatched",
        };
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    /// Project scope (#145): an event for another Harbor project is `202`, stores nothing and
    /// is not counted, even when a mapping of that name exists on the project. A `proj/app`
    /// event still routes.
    #[tokio::test]
    async fn project_event_for_another_project_is_ignored() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("project-scope").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        let auth = Some("Bearer proj-sec-fake");
        for name in ["otherproj/app", "otherproj/stranger", "proj2/app", "app"] {
            let status = post_project(&router, auth, &full_name_event(name)).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{name}");
        }
        assert_eq!(table_count(&pool, "sync_jobs").await, 0);
        assert_eq!(table_count(&pool, "project_webhook_unmatched").await, 0);
        let status = post_project(&router, auth, &full_name_event("proj/app")).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(table_count(&pool, "sync_jobs").await, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The job for a routed event carries the mapping's own repository name (#145).
    #[tokio::test]
    async fn project_event_job_uses_the_mapping_repository_name() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("project-route-name").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        let status = post_project(
            &router,
            Some("Bearer proj-sec-fake"),
            &full_name_event("proj/other"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let payload: String =
            sqlx::query_scalar("SELECT payload FROM sync_jobs WHERE mapping_id = 'pm-other'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(payload.contains("proj/other"), "{payload}");
        assert_eq!(table_count(&pool, "sync_jobs").await, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unmatched name rule (#145): bad names are ignored with `202`, a valid one is counted.
    #[tokio::test]
    async fn unmatched_names_are_validated_before_storing() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("project-name-rule").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        let auth = Some("Bearer proj-sec-fake");
        let too_long = format!("proj/{}", "a".repeat(251));
        let bad = [
            "proj/Stranger".to_owned(),
            "proj/has space".to_owned(),
            too_long,
            "proj/a/b".to_owned(),
            "proj/".to_owned(),
        ];
        for name in &bad {
            let status = post_project(&router, auth, &full_name_event(name)).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{name}");
        }
        assert_eq!(table_count(&pool, "project_webhook_unmatched").await, 0);
        let at_limit = format!("proj/{}", "a".repeat(250));
        for name in ["proj/stranger.v2_x-y", at_limit.as_str()] {
            let status = post_project(&router, auth, &full_name_event(name)).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{name}");
        }
        assert_eq!(table_count(&pool, "project_webhook_unmatched").await, 2);
        let count: i64 = sqlx::query_scalar(
            "SELECT count FROM project_webhook_unmatched WHERE repository = 'proj/stranger.v2_x-y'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A token-only caller gets `401` for any body, so a `400` does not reveal a valid token
    /// (#145).
    #[tokio::test]
    async fn project_secret_is_checked_before_the_body() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("project-secret-first").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        for body in ["{}", "not json", r#"{"type":"SCANNING_COMPLETED"}"#] {
            assert_eq!(
                post_project(&router, Some("Bearer wrong-secret"), body).await,
                StatusCode::UNAUTHORIZED,
                "{body}"
            );
            assert_eq!(
                post_project(&router, None, body).await,
                StatusCode::UNAUTHORIZED,
                "{body}"
            );
        }
        // With the right secret, a body with no repository is still a 400.
        assert_eq!(
            post_project(&router, Some("Bearer proj-sec-fake"), "{}").await,
            StatusCode::BAD_REQUEST
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A wrong secret does not consume a mapping's request budget (#145).
    #[tokio::test]
    async fn wrong_project_secret_does_not_charge_the_mapping_budget() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir, budget) = test_router_with_limiters(
            "project-budget",
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
        )
        .await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        let status = post_project(&router, Some("Bearer wrong"), &repo_event("app")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(budget.len(), 0);
        let ok = router
            .clone()
            .oneshot(project_request(
                "proj-tok-fake",
                Some("Bearer proj-sec-fake"),
                &repo_event("app"),
            ))
            .await
            .unwrap()
            .status();
        assert_eq!(ok, StatusCode::ACCEPTED);
        assert_eq!(budget.len(), 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unknown project token is refused with the same 401 as a wrong secret.
    #[tokio::test]
    async fn unknown_project_token_is_refused() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("project-unknown").await;
        project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
        let response = router
            .oneshot(project_request(
                "no-such-token",
                Some("Bearer proj-sec-fake"),
                &repo_event("app"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Harbor reader and probe that count every call. The webhook routes must never call
    /// Harbor (#132), so these must stay at zero.
    #[derive(Default)]
    struct CountingHarbor(std::sync::atomic::AtomicUsize);

    impl api::state::DynHarborFetch for CountingHarbor {
        fn fetch<'a>(
            &'a self,
            _url: &'a reqwest::Url,
            _username: &'a str,
            _secret: &'a [u8],
            _extra_headers: &'a [(&'a str, &'a str)],
        ) -> api::state::ProbeFuture<'a, services::harbor_client::HarborReply> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(services::harbor_client::HarborReply::new(500, Vec::new())) })
        }
    }

    impl api::state::DynHarborProbe for CountingHarbor {
        fn users_current<'a>(
            &'a self,
            _base: &'a reqwest::Url,
            _username: &'a str,
            _secret: &'a [u8],
        ) -> api::state::ProbeFuture<'a, u16> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(500) })
        }

        fn artifacts_status<'a>(
            &'a self,
            _base: &'a reqwest::Url,
            _username: &'a str,
            _secret: &'a [u8],
            _project: &'a str,
            _repository: &'a str,
        ) -> api::state::ProbeFuture<'a, u16> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(500) })
        }
    }

    /// A test router whose Harbor reader and probe count calls. Returns the counter too.
    async fn counting_router(
        name: &str,
    ) -> (
        Router,
        sqlx::SqlitePool,
        std::path::PathBuf,
        Arc<CountingHarbor>,
    ) {
        let harbor = Arc::new(CountingHarbor::default());
        let (router, pool, dir, _) = test_router_with_fetch(
            name,
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
            api::state::HarborProbeHandle::new(harbor.clone()),
            api::state::HarborFetchHandle::new(harbor.clone()),
        )
        .await;
        (router, pool, dir, harbor)
    }

    /// Every stored job: (mapping id, payload as JSON).
    async fn stored_jobs(pool: &sqlx::SqlitePool) -> Vec<(String, serde_json::Value)> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT mapping_id, payload FROM sync_jobs ORDER BY rowid")
                .fetch_all(pool)
                .await
                .unwrap();
        rows.into_iter()
            .map(|(mapping, payload)| (mapping, serde_json::from_str(&payload).unwrap()))
            .collect()
    }

    const VALID_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A vulnerability event for `proj/{repo}` in either format, with an optional tag.
    fn scan_event(cloud: bool, repo: &str, digest: &str, tag: Option<&str>) -> String {
        let mut resource = serde_json::json!({ "digest": digest });
        if let Some(tag) = tag {
            resource["tag"] = serde_json::json!(tag);
        }
        let data = serde_json::json!({
            "repository": {"repo_full_name": format!("proj/{repo}")},
            "resources": [resource],
            "scan": {"scan_type": "vulnerability"},
        });
        if cloud {
            serde_json::json!({"specversion":"1.0","type":"harbor.scan.completed","source":"harbor","data":data})
        } else {
            serde_json::json!({"type":"SCANNING_COMPLETED","event_data":data})
        }
        .to_string()
    }

    /// Sends `body` to the mapping route (`project` false) or the project route (`true`), with
    /// the fixtures' fake token and secret. Returns the status.
    async fn send_event(router: &Router, project: bool, body: &str) -> axum::http::StatusCode {
        use tower::ServiceExt;
        let request = if project {
            project_request("proj-tok-fake", Some("Bearer proj-sec-fake"), body)
        } else {
            webhook_request("map-tok-fake", Some("Bearer map-sec-fake"), body)
        };
        router.clone().oneshot(request).await.unwrap().status()
    }

    /// An untagged event with a valid digest stores ONE resolve job and returns 202 on both
    /// routes and in both formats, and Harbor is never called (#132).
    #[tokio::test]
    async fn untagged_valid_digest_queues_one_resolve_job_with_no_harbor_call_on_both_routes() {
        use axum::http::StatusCode;
        for project in [false, true] {
            for cloud in [false, true] {
                let name = format!("resolve-202-{project}-{cloud}");
                let (router, pool, dir, harbor) = counting_router(&name).await;
                if project {
                    project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
                } else {
                    webhook_fixture(&pool, "map-tok-fake", "map-sec-fake").await;
                }
                let body = scan_event(cloud, "app", VALID_DIGEST, None);
                assert_eq!(
                    send_event(&router, project, &body).await,
                    StatusCode::ACCEPTED
                );
                let jobs = stored_jobs(&pool).await;
                assert_eq!(jobs.len(), 1, "{name}");
                assert_eq!(jobs[0].0, if project { "pm-app" } else { "wm1" });
                assert_eq!(
                    jobs[0].1,
                    serde_json::json!({"kind":"resolve","repo_full_name":"proj/app","digest":VALID_DIGEST})
                );
                assert_eq!(
                    harbor.0.load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "the webhook called Harbor ({name})"
                );
                pool.close().await;
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }

    /// A tagged event stores one sync job as before, with no lookup and no `kind`.
    #[tokio::test]
    async fn tagged_event_queues_one_sync_job_with_no_lookup() {
        use axum::http::StatusCode;
        for project in [false, true] {
            let (router, pool, dir, harbor) = counting_router(&format!("tagged-{project}")).await;
            if project {
                project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
            } else {
                webhook_fixture(&pool, "map-tok-fake", "map-sec-fake").await;
            }
            let body = scan_event(false, "app", VALID_DIGEST, Some("v1"));
            assert_eq!(
                send_event(&router, project, &body).await,
                StatusCode::ACCEPTED
            );
            let jobs = stored_jobs(&pool).await;
            assert_eq!(jobs.len(), 1);
            assert_eq!(
                jobs[0].1,
                serde_json::json!({"repo_full_name":"proj/app","digest":VALID_DIGEST,"tag":"v1"})
            );
            assert_eq!(harbor.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            pool.close().await;
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A missing or invalid digest on any vulnerability event returns 400 and stores nothing,
    /// tagged or not, on both routes (#132).
    #[tokio::test]
    async fn invalid_digest_on_any_vulnerability_event_returns_400_and_stores_nothing() {
        use axum::http::StatusCode;
        let upper = format!("sha256:{}", "A".repeat(64));
        let short = format!("sha256:{}", "a".repeat(63));
        for project in [false, true] {
            let (router, pool, dir, harbor) =
                counting_router(&format!("bad-digest-{project}")).await;
            if project {
                project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
            } else {
                webhook_fixture(&pool, "map-tok-fake", "map-sec-fake").await;
            }
            for digest in ["sha256:aaaa", upper.as_str(), short.as_str()] {
                for tag in [None, Some("v1")] {
                    for cloud in [false, true] {
                        let body = scan_event(cloud, "app", digest, tag);
                        assert_eq!(
                            send_event(&router, project, &body).await,
                            StatusCode::BAD_REQUEST,
                            "{digest} {tag:?} cloud={cloud} project={project}"
                        );
                    }
                }
            }
            // No digest at all.
            let missing = scan_event(false, "app", "x", Some("v1")).replace(r#""digest":"x","#, "");
            assert!(!missing.contains("digest"), "fixture");
            assert_eq!(
                send_event(&router, project, &missing).await,
                StatusCode::BAD_REQUEST
            );
            assert!(stored_jobs(&pool).await.is_empty());
            assert_eq!(harbor.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            pool.close().await;
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A non-vulnerability event and an event for another repository stay `202` with nothing
    /// stored, even with a digest that would be invalid.
    #[tokio::test]
    async fn non_vulnerability_and_other_repo_events_stay_202_ignored() {
        use axum::http::StatusCode;
        for project in [false, true] {
            let (router, pool, dir, harbor) = counting_router(&format!("ignored-{project}")).await;
            if project {
                project_fixture(&pool, "proj-tok-fake", "proj-sec-fake").await;
            } else {
                webhook_fixture(&pool, "map-tok-fake", "map-sec-fake").await;
            }
            for digest in [VALID_DIGEST, "sha256:aaaa"] {
                let sbom = scan_event(false, "app", digest, None).replace("vulnerability", "sbom");
                assert_eq!(
                    send_event(&router, project, &sbom).await,
                    StatusCode::ACCEPTED
                );
                let push = scan_event(false, "app", digest, None)
                    .replace("SCANNING_COMPLETED", "PUSH_ARTIFACT");
                assert_eq!(
                    send_event(&router, project, &push).await,
                    StatusCode::ACCEPTED
                );
            }
            if !project {
                // On the mapping route, another repository of the project is ignored.
                let other = scan_event(false, "other", "sha256:aaaa", None);
                assert_eq!(
                    send_event(&router, project, &other).await,
                    StatusCode::ACCEPTED
                );
            }
            assert!(stored_jobs(&pool).await.is_empty());
            assert_eq!(harbor.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            pool.close().await;
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The value the create and rotate responses return is the full `Authorization` header.
    /// Pasted into Harbor unchanged, it must be accepted. The test uses the header form as
    /// the service returns it, so the `Bearer ` prefix is part of the contract.
    #[tokio::test]
    async fn shown_auth_header_value_is_accepted_when_pasted_unchanged() {
        use axum::http::StatusCode;
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("pasted-auth").await;
        let token = "tok-pasted-fake";
        let bare = "sec-pasted-fake";
        // The stored digest is of the bare secret, as the service writes it.
        webhook_fixture(&pool, token, bare).await;
        // Harbor sends the Auth Header exactly as entered: the shown value, unchanged.
        let shown = format!("Bearer {bare}");
        let response = router
            .oneshot(webhook_request(token, Some(&shown), WEBHOOK_BODY))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
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
        format!("test-pw-{}", services::ids::new_id().unwrap_or_default())
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
        // Migration 2 is removed; migrations 3 (project webhooks, #132), 4 (picker hidden
        // items, #126), 5 (project webhook rotated_at, #145), 6 (newest-digest close, #196)
        // 7 (many mappings per GitHub repository, #185), 8 (scan schedule, #191) and 9 (scanner
        // reports, #224) are still applied.
        assert!(
            before == (vec![1, 3, 4, 5, 6, 7, 8, 9], 0),
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

    /// #129: the manual issue route for a LOW and an UNKNOWN CVE keeps every guard of the
    /// CRITICAL route. A missing `X-CSRF-Token` is `403`, no session is `401`, another user and
    /// an admin who does not own the mapping get `404`, and nothing is stored. The owner gets
    /// past routing and tenancy (the fake stored token fails before any GitHub call).
    #[tokio::test]
    async fn low_and_unknown_cve_issue_route_is_owner_only_with_csrf() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("cve-issue-route-low").await;
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [
            ("owner-1", "user"),
            ("other-2", "user"),
            ("admin-3", "admin"),
        ] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
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
             VALUES ('rf1', 'rm1', 'app', 'v1', 'CVE-2026-0004', 'LOW', 'open'),
                    ('rf2', 'rm1', 'app', 'v1', 'CVE-2026-0005', 'UNKNOWN', 'open')",
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
        let mut results = Vec::new();
        for cve in ["CVE-2026-0004", "CVE-2026-0005"] {
            let uri = format!("/api/v1/cves/rm1%3A{cve}/issue");
            let post = |cookie: String, token: Option<&str>| {
                let mut builder = with_peer(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .header("cookie", cookie),
                );
                if let Some(token) = token {
                    builder = builder.header("x-csrf-token", token);
                }
                builder.body(Body::empty()).unwrap()
            };
            let owner_session = session_cookie("owner-1", "user", 0);
            let other_session = session_cookie("other-2", "user", 0);
            let admin_session = session_cookie("admin-3", "admin", 0);
            let status = |request: Request<Body>| {
                let router = router.clone();
                async move { router.oneshot(request).await.unwrap().status() }
            };
            results.push((
                cve,
                status(post(format!("{owner_session}; {csrf_cookie}"), None)).await,
                status(post(csrf_cookie.clone(), Some(&csrf))).await,
                status(post(format!("{other_session}; {csrf_cookie}"), Some(&csrf))).await,
                status(post(format!("{admin_session}; {csrf_cookie}"), Some(&csrf))).await,
                status(post(format!("{owner_session}; {csrf_cookie}"), Some(&csrf))).await,
            ));
        }
        let issues: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM github_issues")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        for (cve, no_csrf, no_session, foreign, admin, owner) in results {
            assert_eq!(no_csrf, StatusCode::FORBIDDEN, "{cve}");
            assert_eq!(no_session, StatusCode::UNAUTHORIZED, "{cve}");
            assert_eq!(foreign, StatusCode::NOT_FOUND, "{cve}");
            assert_eq!(
                admin,
                StatusCode::NOT_FOUND,
                "{cve}: admins cannot log issues for others"
            );
            assert_ne!(owner, StatusCode::NOT_FOUND, "{cve}");
            assert_ne!(owner, StatusCode::UNPROCESSABLE_ENTITY, "{cve}");
        }
        assert_eq!(issues, 0);
    }

    /// `POST /api/v1/cves/:id/accept` and `/unaccept` through the full router: a missing
    /// `X-CSRF-Token` is `403`, a CSRF token with no session is `401`, and another user's
    /// mapping in the percent-encoded `<mapping_id>%3A<cve_id>` form is `404` with nothing
    /// stored. The owner gets `201` and then `204`.
    #[tokio::test]
    async fn cve_accept_routes_check_csrf_session_and_tenancy() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("cve-accept-route").await;
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
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let post = |action: &str, cookie: &str, token: Option<&str>| {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/cves/rm1%3ACVE-2026-0001/{action}"))
                    .header("cookie", cookie)
                    .header("content-type", "application/json"),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            let body = if action == "accept" {
                Body::from(r#"{"reason":"vendor fix scheduled","expires_at":null}"#)
            } else {
                Body::empty()
            };
            builder.body(body).unwrap()
        };

        let mut statuses = Vec::new();
        for (action, cookie, token) in [
            ("accept", other.as_str(), None),
            ("unaccept", other.as_str(), None),
            ("accept", csrf_cookie.as_str(), Some(csrf.as_str())),
            ("unaccept", csrf_cookie.as_str(), Some(csrf.as_str())),
            ("accept", other.as_str(), Some(csrf.as_str())),
            ("unaccept", other.as_str(), Some(csrf.as_str())),
        ] {
            let response = router
                .clone()
                .oneshot(post(action, cookie, token))
                .await
                .unwrap();
            statuses.push(response.status());
        }
        let stored_before_owner: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cve_acceptances")
            .fetch_one(&pool)
            .await
            .unwrap();
        let owner_accept = router
            .clone()
            .oneshot(post("accept", &owner, Some(&csrf)))
            .await
            .unwrap()
            .status();
        let foreign_unaccept_after = router
            .clone()
            .oneshot(post("unaccept", &other, Some(&csrf)))
            .await
            .unwrap()
            .status();
        let owner_unaccept = router
            .oneshot(post("unaccept", &owner, Some(&csrf)))
            .await
            .unwrap()
            .status();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            statuses,
            [
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
            ]
        );
        assert_eq!(stored_before_owner, 0);
        assert_eq!(owner_accept, StatusCode::CREATED);
        assert_eq!(foreign_unaccept_after, StatusCode::NOT_FOUND);
        assert_eq!(owner_unaccept, StatusCode::NO_CONTENT);
    }

    /// The CVE read routes through the full router: no session is `401` on all three, another
    /// user's mapping is `404` (also in the percent-encoded `<mapping_id>%3A<cve_id>` form, and
    /// as the `mapping_id` filter), and the owner gets `200` with no CSRF token, because a GET
    /// needs none. `scope=all` from a user is `403`; an admin may read the owner's CVEs.
    #[tokio::test]
    async fn cve_read_routes_check_session_and_tenancy() {
        let (router, pool, dir) = test_router("cve-read-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [
            ("owner-1", "user"),
            ("other-2", "user"),
            ("admin-3", "admin"),
        ] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
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
             VALUES ('rf1', 'rm1', 'app', 'v1', 'CVE-2026-0001', 'CRITICAL', 'open'),
                    ('rf2', 'rm1', 'app', 'v2', 'CVE-2026-0001', 'HIGH', 'open'),
                    ('rf3', 'rm1', 'app', 'v3', 'CVE-2026-0001', 'LOW', 'fixed')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let owner = session_cookie("owner-1", "user", 0);
        let other = session_cookie("other-2", "user", 0);
        let admin = session_cookie("admin-3", "admin", 0);
        let mapping_list = "/api/v1/mappings/rm1/cves";
        let all_list = "/api/v1/cves";
        let filtered = "/api/v1/cves?mapping_id=rm1";
        let detail = "/api/v1/cves/rm1%3ACVE-2026-0001";

        let mut statuses = Vec::new();
        for (uri, cookie) in [
            (mapping_list, ""),
            (all_list, ""),
            (detail, ""),
            (mapping_list, other.as_str()),
            (filtered, other.as_str()),
            (detail, other.as_str()),
            ("/api/v1/mappings/rm1/cves?page_size=201", other.as_str()),
            ("/api/v1/cves?scope=all", other.as_str()),
            ("/api/v1/mappings/rm1/cves?page_size=201", owner.as_str()),
        ] {
            statuses.push(get_json(&router, uri, cookie).await.0);
        }
        let (owner_list, owner_page) = get_json(&router, mapping_list, &owner).await;
        let (owner_all, owner_all_page) = get_json(&router, all_list, &owner).await;
        let (other_all, other_page) = get_json(&router, all_list, &other).await;
        let (owner_detail, owner_body) = get_json(&router, detail, &owner).await;
        let (admin_detail, _) = get_json(&router, detail, &admin).await;
        let (admin_all, admin_page) = get_json(&router, "/api/v1/cves?scope=all", &admin).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        use axum::http::StatusCode;
        assert_eq!(
            statuses,
            [
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::FORBIDDEN,
                StatusCode::BAD_REQUEST,
            ]
        );
        assert_eq!(owner_list, StatusCode::OK);
        assert_eq!(
            owner_page["total"], 1,
            "one CVE on three tags is one summary"
        );
        assert_eq!(owner_page["items"][0]["id"], "rm1:CVE-2026-0001");
        assert_eq!(owner_page["items"][0]["severity"], "CRITICAL");
        assert_eq!(owner_page["items"][0]["open_tags"], 2);
        assert_eq!(
            (owner_all, owner_all_page["total"].clone()),
            (StatusCode::OK, 1.into())
        );
        assert_eq!(
            (other_all, other_page["total"].clone()),
            (StatusCode::OK, 0.into())
        );
        assert_eq!(owner_detail, StatusCode::OK);
        assert_eq!(owner_body["cve_id"], "CVE-2026-0001");
        assert_eq!(owner_body["tags"].as_array().map(Vec::len), Some(3));
        assert!(owner_body["acceptance"].is_null());
        assert_eq!(admin_detail, StatusCode::OK);
        assert_eq!(
            (admin_all, admin_page["total"].clone()),
            (StatusCode::OK, 1.into())
        );
    }

    /// The read routes of this issue through the full router. A `GET` with no session is
    /// `401`. A `GET` is not CSRF-guarded, so a missing token does not turn it into `403`.
    /// A regular user gets `403` for `scope=all` and `404` for another tenant's job, and the
    /// owner's own job is `200`. The admin jobs route is `401`, then `403`, then `200`.
    #[tokio::test]
    async fn read_routes_check_session_tenancy_and_scope() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("read-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2", "admin-3"] {
            let role = if id == "admin-3" { "admin" } else { "user" };
            db::users::insert_local(&mut conn, id, id, None, "h", role)
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
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
             VALUES ('job-owner', 'rm1', 'failed', 8, '{}', 1000, 2000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        db::job_runs::insert(
            &pool,
            &db::job_runs::JobRun {
                id: "run-1".to_owned(),
                job_kind: "poll".to_owned(),
                started_at: 1_000,
                finished_at: None,
                status: "failed".to_owned(),
                processed_count: 0,
                error_summary: Some("x".repeat(2_000)),
            },
        )
        .await
        .unwrap();

        let owner = session_cookie("owner-1", "user", 0);
        let other = session_cookie("other-2", "user", 0);
        let admin = session_cookie("admin-3", "admin", 0);
        let get = |uri: &str, cookie: Option<&str>| {
            let mut builder = with_peer(Request::builder().method("GET").uri(uri));
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            builder.body(Body::empty()).unwrap()
        };

        // Anonymous requests are 401 on every new route.
        for uri in [
            "/api/v1/sync-jobs",
            "/api/v1/sync-jobs/job-owner",
            "/api/v1/dashboard/summary",
            "/api/v1/admin/jobs",
        ] {
            let response = router.clone().oneshot(get(uri, None)).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }

        // Tenancy: the owner reads the job, another user gets 404 with no oracle.
        let (owner_status, _) = get_json(&router, "/api/v1/sync-jobs/job-owner", &owner).await;
        let (other_status, other_body) =
            get_json(&router, "/api/v1/sync-jobs/job-owner", &other).await;
        let (missing_status, missing_body) =
            get_json(&router, "/api/v1/sync-jobs/no-such-job", &other).await;
        assert_eq!(owner_status, StatusCode::OK);
        assert_eq!(other_status, StatusCode::NOT_FOUND);
        assert_eq!(missing_status, StatusCode::NOT_FOUND);
        assert_eq!(
            other_body, missing_body,
            "a foreign job must look like a missing one"
        );

        // A foreign mapping_id filter is an empty page, not 404.
        let (foreign_status, foreign_page) =
            get_json(&router, "/api/v1/sync-jobs?mapping_id=rm1", &other).await;
        assert_eq!(foreign_status, StatusCode::OK);
        assert_eq!(foreign_page["total"], 0);

        // scope=all is admin only.
        let (user_all, _) = get_json(&router, "/api/v1/sync-jobs?scope=all", &other).await;
        let (admin_all, admin_page) =
            get_json(&router, "/api/v1/sync-jobs?scope=all", &admin).await;
        assert_eq!(user_all, StatusCode::FORBIDDEN);
        assert_eq!(admin_all, StatusCode::OK);
        assert_eq!(admin_page["total"], 1);
        let (user_summary_all, _) =
            get_json(&router, "/api/v1/dashboard/summary?scope=all", &other).await;
        assert_eq!(user_summary_all, StatusCode::FORBIDDEN);

        // The admin jobs route: a regular user is 403, an admin is 200 and the error text is capped.
        let (user_jobs, _) = get_json(&router, "/api/v1/admin/jobs", &owner).await;
        let (admin_jobs, admin_jobs_body) = get_json(&router, "/api/v1/admin/jobs", &admin).await;
        assert_eq!(user_jobs, StatusCode::FORBIDDEN);
        assert_eq!(admin_jobs, StatusCode::OK);
        let capped = admin_jobs_body["items"][0]["error_summary"]
            .as_str()
            .unwrap()
            .chars()
            .count();
        assert_eq!(capped, 500);

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The CSRF guard applies to every state-changing route. The retry route is `POST`, so
    /// a missing `X-CSRF-Token` is `403 csrf_invalid` before the handler runs, and the
    /// failed job stays failed. With a matching token and the owner's session it is `200`.
    #[tokio::test]
    async fn sync_job_retry_checks_csrf_session_and_tenancy() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("retry-route").await;
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
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
             VALUES ('job-1', 'rm1', 'failed', 8, '{}', 1000, 2000)",
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
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let post = |cookie: &str, token: Option<&str>| {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sync-jobs/job-1/retry")
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::empty()).unwrap()
        };

        let no_csrf = router.clone().oneshot(post(&owner, None)).await.unwrap();
        let foreign = router
            .clone()
            .oneshot(post(&other, Some(&csrf)))
            .await
            .unwrap();
        let still_failed: String =
            sqlx::query_scalar("SELECT status FROM sync_jobs WHERE id = 'job-1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let owner_retry = router.oneshot(post(&owner, Some(&csrf))).await.unwrap();
        let owner_status = owner_retry.status();
        let retry_body = axum::body::to_bytes(owner_retry.into_body(), 64 * 1024)
            .await
            .unwrap();
        let retried: serde_json::Value = serde_json::from_slice(&retry_body).unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        assert_eq!(still_failed, "failed");
        assert_eq!(owner_status, StatusCode::OK);
        assert_eq!(retried["status"], "queued");
        assert!(retried["created_at"].as_str().unwrap().ends_with('Z'));
    }

    /// The application log routes: no session is `401`, a regular user is `403` on
    /// both routes, a PUT without a CSRF token is `403 csrf_invalid`, an invalid level
    /// is `422` with fixed text that does not echo the value, and an admin change is
    /// `200` and audited as `log.level_change` with `{"old","new"}` only.
    #[tokio::test]
    async fn admin_log_routes_check_role_csrf_and_level() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("app-log-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, "admin-1", "admin-1", None, "h", "admin")
            .await
            .unwrap();
        db::users::insert_local(&mut conn, "user-1", "user-1", None, "h", "user")
            .await
            .unwrap();
        drop(conn);
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let admin = format!("{}; {csrf_cookie}", session_cookie("admin-1", "admin", 0));
        let user = format!("{}; {csrf_cookie}", session_cookie("user-1", "user", 0));
        let put = |cookie: &str, token: Option<&str>, body: &str| {
            let mut builder = with_peer(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/log-level")
                    .header("content-type", "application/json")
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::from(body.to_owned())).unwrap()
        };
        let debug = r#"{"level":"debug"}"#;

        let (anon_logs, _) = get_json(&router, "/api/v1/admin/logs", &csrf_cookie).await;
        let (user_logs, _) = get_json(&router, "/api/v1/admin/logs", &user).await;
        let (user_level, _) = get_json(&router, "/api/v1/admin/log-level", &user).await;
        let anon_put = router
            .clone()
            .oneshot(put(&csrf_cookie, Some(&csrf), debug))
            .await
            .unwrap()
            .status();
        let user_put = router
            .clone()
            .oneshot(put(&user, Some(&csrf), debug))
            .await
            .unwrap()
            .status();
        let no_csrf = router
            .clone()
            .oneshot(put(&admin, None, debug))
            .await
            .unwrap();
        let no_csrf_status = no_csrf.status();
        let no_csrf_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(no_csrf.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let invalid = router
            .clone()
            .oneshot(put(&admin, Some(&csrf), r#"{"level":"verbose-xyz"}"#))
            .await
            .unwrap();
        let invalid_status = invalid.status();
        let invalid_text = String::from_utf8(
            axum::body::to_bytes(invalid.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let ok = router
            .clone()
            .oneshot(put(&admin, Some(&csrf), debug))
            .await
            .unwrap();
        let ok_status = ok.status();
        let ok_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ok.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let (level_status, level_body) = get_json(&router, "/api/v1/admin/log-level", &admin).await;
        let (logs_status, logs_body) =
            get_json(&router, "/api/v1/admin/logs?level=warn&q=x", &admin).await;
        let (bad_filter, _) = get_json(&router, "/api/v1/admin/logs?level=loud", &admin).await;
        let audit: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT action, actor_username, target, details FROM audit_log ORDER BY rowid",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anon_logs, StatusCode::UNAUTHORIZED);
        assert_eq!(anon_put, StatusCode::UNAUTHORIZED);
        assert_eq!(user_logs, StatusCode::FORBIDDEN);
        assert_eq!(user_level, StatusCode::FORBIDDEN);
        assert_eq!(user_put, StatusCode::FORBIDDEN);
        assert_eq!(no_csrf_status, StatusCode::FORBIDDEN);
        assert_eq!(no_csrf_body["error"]["code"], "csrf_invalid");
        assert_eq!(invalid_status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(invalid_text.contains("level must be info, debug, or trace."));
        assert!(
            !invalid_text.contains("verbose-xyz"),
            "the value was echoed"
        );
        assert_eq!(ok_status, StatusCode::OK);
        assert_eq!(ok_body["level"], "debug");
        assert!(ok_body["reverts_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(level_status, StatusCode::OK);
        assert_eq!(level_body["level"], "debug");
        assert_eq!(logs_status, StatusCode::OK);
        assert!(logs_body["items"].is_array());
        assert_eq!(logs_body["level"], "debug");
        assert_eq!(bad_filter, StatusCode::BAD_REQUEST);
        // Only the admin's change is audited; refused requests write nothing.
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].0, "log.level_change");
        assert_eq!(audit[0].1, "admin-1");
        assert_eq!(audit[0].2, "log_level");
        let details: serde_json::Value =
            serde_json::from_str(audit[0].3.as_deref().unwrap()).unwrap();
        assert_eq!(details, serde_json::json!({"old": "info", "new": "debug"}));
    }
    /// A `MakeWriter` into a shared buffer, to read what the log layer wrote.
    #[derive(Clone, Default)]
    struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The admin GitHub URL routes (#184). Covers: (1) an empty value stores the default and
    /// reads back as `""`; (2) an https URL with a path `/api/v3` is accepted and used as the
    /// prefix of a repository call; (3) every invalid shape is `422 validation_failed` with
    /// `settings.github_url_invalid`; (4) a non-admin gets `403` and an anonymous caller `401`;
    /// (5) a token-like sentinel in the request is absent from every error body and log line;
    /// (6) a path in `web_url` is `422`.
    #[tokio::test]
    async fn admin_github_url_routes() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("github-url-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [("ga", "admin"), ("gu", "user")] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let admin = format!("{}; {csrf_cookie}", session_cookie("ga", "admin", 0));
        let user = format!("{}; {csrf_cookie}", session_cookie("gu", "user", 0));
        let uri = "/api/v1/admin/github-url";
        const TOKEN: &str = "ghp_SENTINEL-github-token-9c1d";

        let sink = LogSink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // (4) access control.
        let (anon, _) = get_json(&router, uri, &csrf_cookie).await;
        let (forbidden_get, _) = get_json(&router, uri, &user).await;
        let (forbidden_put, _) = send_json(
            &router,
            "PUT",
            uri,
            Some(&user),
            Some(&csrf),
            r#"{"api_base_url":"","web_url":""}"#,
        )
        .await;
        assert_eq!(anon, StatusCode::UNAUTHORIZED);
        assert_eq!(forbidden_get, StatusCode::FORBIDDEN);
        assert_eq!(forbidden_put, StatusCode::FORBIDDEN);

        // (1) empty means the default.
        let (status, body) = get_json(&router, uri, &admin).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"api_base_url": "", "web_url": ""}));
        let (status, body) = send_json(
            &router,
            "PUT",
            uri,
            Some(&admin),
            Some(&csrf),
            r#"{"api_base_url":"","web_url":""}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"api_base_url": "", "web_url": ""}));

        // (3) and (6) invalid values are 422 with the fixed message and are not stored.
        let invalid_api = [
            "http://ghes.example.com/api/v3",
            "https://user:pw@ghes.example.com/api/v3",
            "https://ghes.example.com:8443/api/v3",
            "https://ghes.example.com/api/v3?x=1",
            "https://ghes.example.com/api/v3#f",
            "https://ghes.example.com/api/../v3",
            "https://ghes.example.com/api//v3",
            "https://ghes.example.com/api%2Fv3",
            "https://ghes.example.com/api%2fv3",
        ];
        for bad in invalid_api {
            let payload = serde_json::json!({"api_base_url": bad, "web_url": ""}).to_string();
            let (status, body) =
                send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
            assert_eq!(body["error"]["code"], "validation_failed", "{bad}");
            assert_eq!(
                body["error"]["message"], "settings.github_url_invalid",
                "{bad}"
            );
        }
        // (6) a path in web_url.
        let payload =
            serde_json::json!({"api_base_url": "", "web_url": "https://ghes.example.com/x"})
                .to_string();
        let (status, body) =
            send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["message"], "settings.github_url_invalid");
        // (5) a token in userinfo is refused and never echoed or logged.
        let payload = serde_json::json!({
            "api_base_url": format!("https://{TOKEN}@ghes.example.com/api/v3"),
            "web_url": ""
        })
        .to_string();
        let (status, body) =
            send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!body.to_string().contains(TOKEN), "{body}");
        let (_, unchanged) = get_json(&router, uri, &admin).await;
        assert_eq!(
            unchanged,
            serde_json::json!({"api_base_url": "", "web_url": ""})
        );

        // (2) a path is accepted, stored, and read back.
        let payload = serde_json::json!({
            "api_base_url": "https://ghes.example.com/api/v3",
            "web_url": "https://ghes.example.com"
        })
        .to_string();
        let (status, body) =
            send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({
                "api_base_url": "https://ghes.example.com/api/v3",
                "web_url": "https://ghes.example.com"
            })
        );
        let (_, read) = get_json(&router, uri, &admin).await;
        assert_eq!(read, body);

        // The router is a clone of the one that holds the target, so the request path of a
        // repository call under the saved base is the prefix plus the REST path.
        let stored = services::github_url::load_stored(&pool).await.unwrap();
        let urls =
            services::github_url::GithubUrls::from_stored(&stored.api_base_url, &stored.web_url)
                .unwrap();
        let call = urls
            .api_url(&services::credential_probe::github_repo_path("octo", "app"))
            .unwrap();
        assert_eq!(call.host_str(), Some("ghes.example.com"));
        assert_eq!(call.path(), "/api/v3/repos/octo/app");

        // Clearing returns to the default.
        let (status, _) = send_json(
            &router,
            "PUT",
            uri,
            Some(&admin),
            Some(&csrf),
            r#"{"api_base_url":"","web_url":""}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let audit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'github%'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            audit, 0,
            "no audit row is written for the GitHub URL change"
        );

        let logged = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            !logged.contains(TOKEN),
            "the token reached the log: {logged}"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// Test (2) of #184 end to end: after the admin saves `https://ghes.example.com/api/v3`, the
    /// repository list request goes to that host with `/api/v3` as the path prefix, and the
    /// default `https://api.github.com/user/repos` is used before and (from cache) after.
    #[tokio::test]
    async fn github_base_url_with_a_path_prefixes_the_repository_call() {
        use axum::http::StatusCode;
        use services::pickers::tests::{Recorded, SENTINEL, ok};
        let fake = Arc::new(Recorded::default());
        fake.on(|_: &reqwest::Url| true, ok(r#"[]"#));
        let (router, pool, dir, _) = test_router_full(
            "github-base-prefix",
            services::throttle::LoginThrottle::new(),
            api::webhooks::new_token_limiter(),
            api::state::HarborProbeHandle::new(Arc::new(ReadableHarbor)),
            api::state::HarborFetchHandle::outbound(false).unwrap(),
            services::pickers::PickerState::new(fake.clone()),
        )
        .await;
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [("owner-1", "admin")] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        let created = services::credentials::create(
            &pool,
            &auth::crypto::credentials_key(&root).unwrap(),
            &services::audit::Actor {
                user_id: Some("owner-1".to_owned()),
                username: "owner-1".to_owned(),
            },
            "owner-1",
            services::credentials::NewCredential {
                service_type: services::credentials::SERVICE_GITHUB.to_owned(),
                label: "gh".to_owned(),
                base_url: None,
                username: None,
                token: SENTINEL.to_owned(),
                expires_at: None,
            },
            false,
        )
        .await
        .unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let cookie = format!(
            "{}; {}={csrf}",
            session_cookie("owner-1", "admin", 0),
            auth::csrf::CSRF_COOKIE
        );
        let list = format!("/api/v1/credentials/{}/github-repositories", created.id);
        let put = |body: &'static str| {
            let router = router.clone();
            let cookie = cookie.clone();
            let csrf = csrf.clone();
            async move {
                send_json(
                    &router,
                    "PUT",
                    "/api/v1/admin/github-url",
                    Some(&cookie),
                    Some(&csrf),
                    body,
                )
                .await
                .0
            }
        };

        let (status, _) = get_json(&router, &list, &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            put(r#"{"api_base_url":"https://ghes.example.com/api/v3","web_url":""}"#).await,
            StatusCode::OK
        );
        let (status, _) = get_json(&router, &list, &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            put(r#"{"api_base_url":"","web_url":""}"#).await,
            StatusCode::OK
        );
        let (status, _) = get_json(&router, &list, &cookie).await;
        assert_eq!(status, StatusCode::OK);

        let urls = fake.urls.lock().unwrap().clone();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        // The third call returns to the default base and is served from the cache entry of
        // the first call, which is keyed by the base URL, so no third request is sent.
        assert_eq!(urls.len(), 2, "{urls:?}");
        assert!(
            urls[0].starts_with("https://api.github.com/user/repos?"),
            "{}",
            urls[0]
        );
        assert!(
            urls[1].starts_with("https://ghes.example.com/api/v3/user/repos?"),
            "{}",
            urls[1]
        );
    }
}
