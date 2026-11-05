//! The application log: the in-memory ring buffer the admin reads, the secret field
//! redaction shared with stdout, and the global level controller with its automatic
//! revert (`specs/security.md`, Application log; `specs/backend.md`, Application log).
//!
//! Log lines are never written to `audit_log`. Only a level change is audited.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::task::JoinHandle;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::{Writer, debug_fn};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

use crate::error::AppError;
use crate::services::audit::{self, Actor};

/// Lines kept in the buffer. The oldest line is dropped first.
pub const MAX_LINES: usize = 500;
/// Characters kept per line, including the truncation marker.
pub const MAX_LINE_CHARS: usize = 1000;
/// Ends a line that was cut at [`MAX_LINE_CHARS`].
pub const TRUNCATED_MARKER: &str = "… [truncated]";
/// A level above `info` reverts to `info` after this long.
pub const REVERT_AFTER: Duration = Duration::from_secs(30 * 60);
/// The crate's own tracing target. `debug` and `trace` apply below it only.
const OWN_TARGET: &str = "harborgate";
/// Longest accepted text search, in characters.
const MAX_QUERY_CHARS: usize = 200;
/// Shown instead of a value that looks like a ciphertext or a password hash.
const REDACTED_VALUE: &str = "[redacted]";
/// The fixed text for an invalid level. The value is never echoed.
const INVALID_LEVEL: &str = "level must be info, debug, or trace.";

/// The global level an admin can set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// Parses the wire value. Anything else is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// The filter for this level. Every target stays at `info`; only HarborGate's own
    /// target is raised, so dependency crates never log below `info`.
    pub fn targets(self) -> Targets {
        let own = match self {
            Self::Info => LevelFilter::INFO,
            Self::Debug => LevelFilter::DEBUG,
            Self::Trace => LevelFilter::TRACE,
        };
        Targets::new()
            .with_default(LevelFilter::INFO)
            .with_target(OWN_TARGET, own)
    }
}

/// True when a field with this name must never be logged: it contains an audit secret
/// fragment or names key material. Shared with the audit `details` check.
pub fn is_secret_field(name: &str) -> bool {
    audit::is_secret_key_name(name)
}

/// Writes one field in the log line format: the message bare, other fields as
/// ` name=value`. Secret-named fields are dropped, and a value that looks like a
/// ciphertext or an Argon2 hash is replaced.
fn push_field(out: &mut dyn fmt::Write, name: &str, value: &dyn fmt::Debug) -> fmt::Result {
    if is_secret_field(name) {
        return Ok(());
    }
    let text = format!("{value:?}");
    let bare = text.trim_start_matches('"');
    let shown = if bare.starts_with(crate::auth::crypto::V1_PREFIX) || bare.starts_with("$argon2") {
        REDACTED_VALUE
    } else {
        text.as_str()
    };
    if name == "message" {
        out.write_str(shown)
    } else {
        write!(out, " {name}={shown}")
    }
}

fn write_stdout_field(
    writer: &mut Writer<'_>,
    field: &Field,
    value: &dyn fmt::Debug,
) -> fmt::Result {
    push_field(writer, field.name(), value)
}

/// One buffered log line, as returned by `GET /api/v1/admin/logs`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LogLine {
    pub seq: u64,
    pub timestamp: String,
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

struct BufferState {
    lines: VecDeque<LogLine>,
    next_seq: u64,
}

/// The bounded in-memory buffer. Clones share one buffer.
#[derive(Clone)]
pub struct LogBuffer {
    state: Arc<Mutex<BufferState>>,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(BufferState {
                lines: VecDeque::with_capacity(MAX_LINES),
                next_seq: 1,
            })),
        }
    }

    /// The tracing layer that copies each enabled event into this buffer.
    pub fn layer(&self) -> BufferLayer {
        BufferLayer {
            buffer: self.clone(),
        }
    }

    /// Appends one line, cut to [`MAX_LINE_CHARS`], and drops the oldest past
    /// [`MAX_LINES`]. A poisoned lock drops the line rather than panic.
    fn push(&self, level: &'static str, target: &str, message: String) {
        let timestamp = crate::auth::session::now_unix()
            .and_then(crate::services::time::rfc3339)
            .unwrap_or_default();
        let message = truncate_line(message);
        if let Ok(mut state) = self.state.lock() {
            let seq = state.next_seq;
            state.next_seq = seq.saturating_add(1);
            if state.lines.len() >= MAX_LINES {
                state.lines.pop_front();
            }
            state.lines.push_back(LogLine {
                seq,
                timestamp,
                level,
                target: target.to_owned(),
                message,
            });
        }
    }

    /// Lines at or above `min_rank` severity whose message or target contains `needle`
    /// (already lowercased), oldest first.
    fn select(&self, min_rank: u8, needle: Option<&str>) -> Result<Vec<LogLine>, AppError> {
        let state = self.state.lock().map_err(|_| AppError::InternalError)?;
        Ok(state
            .lines
            .iter()
            .filter(|line| level_rank(line.level) <= min_rank)
            .filter(|line| match needle {
                None => true,
                Some(needle) => {
                    line.message.to_lowercase().contains(needle)
                        || line.target.to_lowercase().contains(needle)
                }
            })
            .cloned()
            .collect())
    }
}

/// Cuts a line longer than [`MAX_LINE_CHARS`] characters and ends it with the marker.
fn truncate_line(text: String) -> String {
    if text.chars().count() <= MAX_LINE_CHARS {
        return text;
    }
    let keep = MAX_LINE_CHARS - TRUNCATED_MARKER.chars().count();
    let mut cut: String = text.chars().take(keep).collect();
    cut.push_str(TRUNCATED_MARKER);
    cut
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        _ => "trace",
    }
}

/// Severity rank: `error` is 1, `trace` is 5.
fn level_rank(name: &str) -> u8 {
    match name {
        "error" => 1,
        "warn" => 2,
        "info" => 3,
        "debug" => 4,
        _ => 5,
    }
}

/// Builds the message text of one event with the shared field rules.
struct LineVisitor {
    text: String,
}

impl Visit for LineVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = push_field(&mut self.text, field.name(), value);
    }
}

/// The tracing layer behind [`LogBuffer::layer`].
pub struct BufferLayer {
    buffer: LogBuffer,
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Format before taking the lock, so a field's `Debug` cannot re-enter it.
        let mut visitor = LineVisitor {
            text: String::new(),
        };
        event.record(&mut visitor);
        let meta = event.metadata();
        self.buffer
            .push(level_name(meta.level()), meta.target(), visitor.text);
    }
}

/// Logs one outbound Harbor or GitHub request at `debug`: the method, the URL path, and
/// the status code. Only `url.path()` is logged, so the query string, the userinfo and
/// the host never reach the log. Never use this for OIDC or alert webhook URLs.
pub fn log_outbound(method: &str, url: &Url, status: Option<u16>) {
    match status {
        Some(status) => {
            tracing::debug!(method, path = %url.path(), status, "outbound request");
        }
        None => {
            tracing::debug!(method, path = %url.path(), "outbound request failed to send");
        }
    }
}

/// Switches the live filter. Production reloads the subscriber; tests record calls.
pub type ApplyLevel = Arc<dyn Fn(LogLevel) -> Result<(), AppError> + Send + Sync>;

struct LevelState {
    level: LogLevel,
    reverts_at: Option<i64>,
    generation: u64,
    timer: Option<JoinHandle<()>>,
}

struct LevelInner {
    apply: ApplyLevel,
    revert_after: Duration,
    state: tokio::sync::Mutex<LevelState>,
}

/// The current level and when it reverts, as returned by the level routes.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LevelStatus {
    pub level: &'static str,
    pub reverts_at: Option<String>,
}

/// Holds the global level and the revert timer. Clones share one controller.
#[derive(Clone)]
pub struct LevelController {
    inner: Arc<LevelInner>,
}

impl LevelController {
    /// Starts at `info`. `revert_after` is [`REVERT_AFTER`] in production.
    pub fn new(apply: ApplyLevel, revert_after: Duration) -> Self {
        Self {
            inner: Arc::new(LevelInner {
                apply,
                revert_after,
                state: tokio::sync::Mutex::new(LevelState {
                    level: LogLevel::Info,
                    reverts_at: None,
                    generation: 0,
                    timer: None,
                }),
            }),
        }
    }

    pub async fn status(&self) -> Result<LevelStatus, AppError> {
        let state = self.inner.state.lock().await;
        status_of(&state)
    }

    /// Sets the level for `actor` and audits `log.level_change`. A level above `info`
    /// (re)starts the revert timer; `info` cancels it. If the audit row cannot be
    /// written, the level is not changed.
    pub async fn set(
        &self,
        pool: &SqlitePool,
        actor: &Actor,
        new: LogLevel,
    ) -> Result<LevelStatus, AppError> {
        let mut state = self.inner.state.lock().await;
        let old = state.level;
        let now = crate::auth::session::now_unix()?;
        let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
        record_change(&mut tx, actor, old, new).await?;
        (self.inner.apply)(new)?;
        if tx.commit().await.is_err() {
            let _ = (self.inner.apply)(old);
            return Err(AppError::InternalError);
        }
        state.level = new;
        state.generation = state.generation.wrapping_add(1);
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        if new == LogLevel::Info {
            state.reverts_at = None;
        } else {
            let after = self.inner.revert_after;
            let secs = i64::try_from(after.as_millis().div_ceil(1000))
                .map_err(|_| AppError::InternalError)?;
            state.reverts_at = Some(now.saturating_add(secs));
            let controller = self.clone();
            let pool = pool.clone();
            let generation = state.generation;
            state.timer = Some(tokio::spawn(async move {
                tokio::time::sleep(after).await;
                controller.revert(&pool, generation).await;
            }));
        }
        status_of(&state)
    }

    /// The automatic revert to `info`, audited with the actor `system`. A timer whose
    /// generation is stale (a later change happened) does nothing.
    async fn revert(&self, pool: &SqlitePool, generation: u64) {
        let mut state = self.inner.state.lock().await;
        if state.generation != generation || state.level == LogLevel::Info {
            return;
        }
        let old = state.level;
        if (self.inner.apply)(LogLevel::Info).is_err() {
            tracing::warn!("could not revert the log level to info");
            return;
        }
        state.level = LogLevel::Info;
        state.reverts_at = None;
        state.timer = None;
        state.generation = state.generation.wrapping_add(1);
        let recorded = async {
            let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
            record_change(&mut tx, &Actor::system(), old, LogLevel::Info).await?;
            tx.commit().await.map_err(|_| AppError::InternalError)
        }
        .await;
        if recorded.is_err() {
            tracing::warn!("the log level reverted to info, but the audit row was not written");
        } else {
            tracing::info!(old = old.as_str(), "log level reverted to info");
        }
    }
}

async fn record_change(
    conn: &mut sqlx::SqliteConnection,
    actor: &Actor,
    old: LogLevel,
    new: LogLevel,
) -> Result<(), AppError> {
    let details = serde_json::json!({"old": old.as_str(), "new": new.as_str()});
    audit::record(conn, actor, "log.level_change", "log_level", Some(&details)).await
}

fn status_of(state: &LevelState) -> Result<LevelStatus, AppError> {
    let reverts_at = match state.reverts_at {
        Some(at) => Some(crate::services::time::rfc3339(at)?),
        None => None,
    };
    Ok(LevelStatus {
        level: state.level.as_str(),
        reverts_at,
    })
}

/// The buffer and the level controller, held by `AppState`.
pub struct AppLog {
    pub buffer: LogBuffer,
    pub level: LevelController,
}

impl AppLog {
    /// A log not attached to any subscriber: level changes only update the state.
    /// For tests and for router setups that do not install a subscriber.
    #[cfg(test)]
    pub fn detached(revert_after: Duration) -> Self {
        Self {
            buffer: LogBuffer::new(),
            level: LevelController::new(Arc::new(|_| Ok(())), revert_after),
        }
    }
}

/// Installs the global subscriber: a reloadable filter at `info` (`RUST_LOG` is
/// ignored), the stdout formatter and the buffer, both with secret fields dropped.
pub fn install() -> Result<Arc<AppLog>, Box<dyn std::error::Error>> {
    let (filter, handle) = tracing_subscriber::reload::Layer::new(LogLevel::Info.targets());
    let buffer = LogBuffer::new();
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().fmt_fields(debug_fn(write_stdout_field)))
        .with(buffer.layer())
        .try_init()?;
    let apply: ApplyLevel = Arc::new(move |level: LogLevel| {
        handle
            .reload(level.targets())
            .map_err(|_| AppError::InternalError)
    });
    Ok(Arc::new(AppLog {
        buffer,
        level: LevelController::new(apply, REVERT_AFTER),
    }))
}

/// The body of `GET /api/v1/admin/logs`.
#[derive(Debug, Serialize)]
pub struct LogsView {
    pub items: Vec<LogLine>,
    pub level: &'static str,
    pub reverts_at: Option<String>,
}

/// Reads the buffer with the optional minimum level and text search.
pub async fn read(
    log: &AppLog,
    min_level: Option<&str>,
    query: Option<&str>,
) -> Result<LogsView, AppError> {
    let min_rank = match min_level {
        None => 5,
        Some(name @ ("error" | "warn" | "info" | "debug" | "trace")) => level_rank(name),
        Some(_) => {
            return Err(AppError::InvalidRequest(
                "level must be error, warn, info, debug, or trace.".to_owned(),
            ));
        }
    };
    let needle = match query {
        Some(text) if text.chars().count() > MAX_QUERY_CHARS => {
            return Err(AppError::InvalidRequest(format!(
                "q must be at most {MAX_QUERY_CHARS} characters."
            )));
        }
        Some(text) if !text.is_empty() => Some(text.to_lowercase()),
        _ => None,
    };
    let items = log.buffer.select(min_rank, needle.as_deref())?;
    let status = log.level.status().await?;
    Ok(LogsView {
        items,
        level: status.level,
        reverts_at: status.reverts_at,
    })
}

/// Parses the level for `PUT /api/v1/admin/log-level`, with fixed error text.
pub fn parse_level(text: &str) -> Result<LogLevel, AppError> {
    LogLevel::parse(text).ok_or_else(|| AppError::ValidationFailed(INVALID_LEVEL.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tracing_subscriber::Registry;

    const SENTINEL: &str = "SENTINEL-test-fake-secret-7f3a";

    fn buffer_subscriber(buffer: &LogBuffer) -> impl Subscriber + Send + Sync {
        Registry::default().with(buffer.layer())
    }

    fn all_text(buffer: &LogBuffer) -> String {
        buffer
            .select(5, None)
            .unwrap()
            .iter()
            .map(|l| format!("{} {} {}", l.level, l.target, l.message))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn secret_named_fields_never_reach_the_buffer() {
        let buffer = LogBuffer::new();
        tracing::subscriber::with_default(buffer_subscriber(&buffer), || {
            tracing::info!(api_token = SENTINEL, mapping = "m-1", "first");
            tracing::warn!(client_secret = %SENTINEL, "second");
            tracing::error!(password = ?SENTINEL, "third");
            tracing::info!(
                Authorization = SENTINEL,
                session_cookie = SENTINEL,
                "fourth"
            );
            tracing::info!(
                encryption_key = SENTINEL,
                key = SENTINEL,
                private_value = SENTINEL,
                "fifth"
            );
            tracing::info!(
                note = "v1:AAAAciphertext",
                hash = "$argon2id$v=19$m=1",
                "sixth"
            );
        });
        let text = all_text(&buffer);
        assert!(!text.contains(SENTINEL), "the sentinel leaked: {text}");
        for name in [
            "api_token",
            "client_secret",
            "password",
            "Authorization",
            "session_cookie",
            "encryption_key",
            "private_value",
        ] {
            assert!(!text.contains(name), "field {name} leaked: {text}");
        }
        assert!(!text.contains("v1:AAAA"));
        assert!(!text.contains("$argon2"));
        assert!(text.contains("first mapping=\"m-1\""), "{text}");
        assert!(
            text.contains("sixth note=[redacted] hash=[redacted]"),
            "{text}"
        );
        assert_eq!(buffer.select(5, None).unwrap().len(), 6);
    }

    /// A `MakeWriter` into a shared byte buffer, to read the stdout formatter's output.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stdout_formatter_drops_secret_fields_too() {
        let out = Captured::default();
        let writer = out.clone();
        let subscriber = Registry::default().with(
            tracing_subscriber::fmt::layer()
                .fmt_fields(debug_fn(write_stdout_field))
                .with_writer(move || writer.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(github_token = SENTINEL, repo = "octo/app", "uploaded");
        });
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("uploaded repo=\"octo/app\""), "{text}");
        assert!(!text.contains(SENTINEL), "{text}");
        assert!(!text.contains("github_token"), "{text}");
    }

    #[test]
    fn outbound_log_has_method_path_and_status_only() {
        let buffer = LogBuffer::new();
        let url = Url::parse(&format!(
            "https://robot:{SENTINEL}@harbor.example.com/api/v2.0/projects/p/repositories?q=x&token={SENTINEL}"
        ))
        .unwrap();
        tracing::subscriber::with_default(buffer_subscriber(&buffer), || {
            log_outbound("GET", &url, Some(200));
            log_outbound("POST", &url, None);
        });
        let lines = buffer.select(5, None).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].level, "debug");
        let text = all_text(&buffer);
        assert!(!text.contains(SENTINEL), "{text}");
        assert!(!text.contains("robot"), "{text}");
        assert!(!text.contains("harbor.example.com"), "{text}");
        assert!(!text.contains('?'), "{text}");
        assert!(
            text.contains("path=/api/v2.0/projects/p/repositories"),
            "{text}"
        );
        assert!(text.contains("method=\"GET\""), "{text}");
        assert!(text.contains("status=200"), "{text}");
    }

    #[test]
    fn long_lines_are_cut_at_1000_characters_with_a_marker() {
        let buffer = LogBuffer::new();
        let long = "é".repeat(1500);
        tracing::subscriber::with_default(buffer_subscriber(&buffer), || {
            tracing::info!("{long}");
            tracing::info!("{}", "x".repeat(MAX_LINE_CHARS));
        });
        let lines = buffer.select(5, None).unwrap();
        assert_eq!(lines[0].message.chars().count(), MAX_LINE_CHARS);
        assert!(lines[0].message.ends_with(TRUNCATED_MARKER));
        assert_eq!(lines[1].message.chars().count(), MAX_LINE_CHARS);
        assert!(!lines[1].message.ends_with(TRUNCATED_MARKER));
    }

    #[test]
    fn buffer_keeps_the_newest_500_lines() {
        let buffer = LogBuffer::new();
        tracing::subscriber::with_default(buffer_subscriber(&buffer), || {
            for i in 0..600 {
                tracing::info!("line {i}");
            }
        });
        let lines = buffer.select(5, None).unwrap();
        assert_eq!(lines.len(), MAX_LINES);
        assert_eq!(lines[0].seq, 101);
        assert_eq!(lines[0].message, "line 100");
        assert_eq!(lines[MAX_LINES - 1].message, "line 599");
    }

    #[tokio::test]
    async fn read_filters_by_minimum_level_and_text() {
        let log = AppLog::detached(REVERT_AFTER);
        tracing::subscriber::with_default(buffer_subscriber(&log.buffer), || {
            tracing::error!("Upstream unreachable");
            tracing::info!("sync done");
            tracing::debug!("upstream detail");
        });
        let warn = read(&log, Some("warn"), None).await.unwrap();
        assert_eq!(warn.items.len(), 1);
        let harbor = read(&log, None, Some("UPSTREAM")).await.unwrap();
        assert_eq!(harbor.items.len(), 2);
        let info_harbor = read(&log, Some("info"), Some("upstream")).await.unwrap();
        assert_eq!(info_harbor.items.len(), 1);
        assert_eq!(warn.level, "info");
        assert!(read(&log, Some("verbose"), None).await.is_err());
        assert!(read(&log, None, Some(&"a".repeat(201))).await.is_err());
    }

    #[test]
    fn level_targets_keep_dependencies_at_info() {
        let filter = LogLevel::Trace.targets();
        assert!(filter.would_enable("harborgate::services::sync", &Level::TRACE));
        assert!(!filter.would_enable("hyper::proto", &Level::DEBUG));
        assert!(!filter.would_enable("sqlx::query", &Level::DEBUG));
        assert!(filter.would_enable("reqwest", &Level::INFO));
        let info = LogLevel::Info.targets();
        assert!(!info.would_enable("harborgate::api", &Level::DEBUG));
        assert!(info.would_enable("harborgate::api", &Level::INFO));
    }

    #[test]
    fn invalid_level_is_rejected_with_fixed_text() {
        assert_eq!(parse_level("debug"), Ok(LogLevel::Debug));
        let err = parse_level("<script>").unwrap_err();
        assert_eq!(err, AppError::ValidationFailed(INVALID_LEVEL.to_owned()));
        assert!(parse_level("warn").is_err());
        assert!(parse_level("DEBUG").is_err());
    }

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("harborgate-applog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (crate::db::open(&dir).await.unwrap(), dir)
    }

    async fn audit_rows(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
        sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT action, actor_username, details FROM audit_log ORDER BY rowid",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    fn recording() -> (ApplyLevel, Arc<Mutex<Vec<LogLevel>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let apply: ApplyLevel = Arc::new(move |level| {
            sink.lock().unwrap().push(level);
            Ok(())
        });
        (apply, seen)
    }

    async fn wait_for_info(controller: &LevelController) -> bool {
        for _ in 0..100 {
            if controller.status().await.unwrap().level == "info" {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    fn admin() -> Actor {
        Actor {
            user_id: None,
            username: "test-admin".to_owned(),
        }
    }

    #[tokio::test]
    async fn raised_level_reverts_after_the_injected_duration_and_is_audited() {
        let (pool, dir) = fresh_pool("revert").await;
        let (apply, seen) = recording();
        let controller = LevelController::new(apply, Duration::from_millis(200));
        let status = controller
            .set(&pool, &admin(), LogLevel::Debug)
            .await
            .unwrap();
        assert_eq!(status.level, "debug");
        assert!(status.reverts_at.is_some());
        assert!(wait_for_info(&controller).await, "the level did not revert");
        assert_eq!(controller.status().await.unwrap().reverts_at, None);
        let rows = audit_rows(&pool).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(*seen.lock().unwrap(), vec![LogLevel::Debug, LogLevel::Info]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "log.level_change");
        assert_eq!(rows[0].1, "test-admin");
        let first: serde_json::Value = serde_json::from_str(rows[0].2.as_deref().unwrap()).unwrap();
        assert_eq!(first, serde_json::json!({"old": "info", "new": "debug"}));
        assert_eq!(rows[1].0, "log.level_change");
        assert_eq!(rows[1].1, "system");
        let second: serde_json::Value =
            serde_json::from_str(rows[1].2.as_deref().unwrap()).unwrap();
        assert_eq!(second, serde_json::json!({"old": "debug", "new": "info"}));
    }

    #[tokio::test]
    async fn a_later_change_restarts_the_timer() {
        let (pool, dir) = fresh_pool("restart").await;
        let (apply, _) = recording();
        let controller = LevelController::new(apply, Duration::from_millis(1000));
        controller
            .set(&pool, &admin(), LogLevel::Debug)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        controller
            .set(&pool, &admin(), LogLevel::Trace)
            .await
            .unwrap();
        // The first timer would have fired at 1000 ms; the new one fires at 1600 ms.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let still = controller.status().await.unwrap().level;
        let reverted = wait_for_info(&controller).await;
        let rows = audit_rows(&pool).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(still, "trace", "the old timer reverted a newer change");
        assert!(reverted);
        // Two user changes and one system revert, never a second revert.
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2].1, "system");
    }

    #[tokio::test]
    async fn setting_info_cancels_the_timer() {
        let (pool, dir) = fresh_pool("cancel").await;
        let (apply, seen) = recording();
        let controller = LevelController::new(apply, Duration::from_millis(100));
        controller
            .set(&pool, &admin(), LogLevel::Debug)
            .await
            .unwrap();
        let status = controller
            .set(&pool, &admin(), LogLevel::Info)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rows = audit_rows(&pool).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(status.reverts_at, None);
        assert_eq!(rows.len(), 2, "a cancelled timer still wrote a revert");
        assert_eq!(*seen.lock().unwrap(), vec![LogLevel::Debug, LogLevel::Info]);
    }
}
