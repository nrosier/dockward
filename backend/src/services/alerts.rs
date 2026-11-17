//! The alert dispatcher: sends job failures, new HIGH or CRITICAL CVE summaries and fixed CVEs
//! to every enabled channel whose event set holds the event, at most once per 24 hours per dedupe
//! key and channel.
//! Sources: `specs/alerts.md` (Routing, Triggers, Deduplication, Decisions: scope is all
//! tenants), `specs/database.md` (the `alert_deliveries` write rule).
//!
//! Scan alerts (#458): the convert step records new and fixed CVEs in `alert_pending`. When the
//! scan run that ends the last open run of an image is done, [`Notifier::scan_alerts`] takes those
//! rows and sends one summary of the new HIGH and CRITICAL CVEs per source (key
//! `scan:<scan id>:<source id>`), and one alert per fixed CVE (key `cve_fixed:<CVE id>:<scan id>`).
//! The scan id is the id of that last scan run. A fixed alert never touches GitHub: the issue rules
//! own the fixed note, and an issue is never closed by Dockward.
//!
//! Order for one channel: decrypt the config, claim the dedupe key with the
//! `alert_deliveries` upsert, then send. A failed send deletes the claim, so a later
//! trigger can try again. [`Notifier::notify`] never fails its caller: every error is
//! logged as fixed text, and nothing from the channel config, the URL, a header, the SMTP
//! password, or a response is logged or stored.
//!
//! Sending goes through [`alert_send`], which uses the guarded outbound client and
//! `resolve_checked` on every send. This module does not bypass either.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sqlx::SqlitePool;

use crate::auth::crypto::{self, DerivedKey};
use crate::db::alert_channels::ChannelRow;
use crate::db::alert_deliveries as deliveries;
use crate::db::alert_pending::{self as pending, PendingCve};
use crate::db::publish as publish_db;
use crate::db::scans as scans_db;
use crate::db::sources::{self, SourceRow};
use crate::error::AppError;
use crate::services::alert_channels::{SmtpConfig, WebhookConfig};
use crate::services::alert_send::{self, Alert, AlertEvent, ListedCve, SUMMARY_LIMIT, SendError};
use crate::services::ids;
use crate::services::issue_lifecycle;

/// The error text on a `job_failed` alert. Fixed, so no stored error text can leak.
const JOB_FAILED_TEXT: &str = "the sync job failed after all retries";
/// Used for the mapping names when the mapping no longer exists.
const UNKNOWN: &str = "unknown";

/// Runs `task` in the background. A panic in it is logged as fixed text, so a panic after
/// a claim was written is not silent. These tasks are not tracked by the shutdown drain, so
/// an alert in flight at shutdown can be dropped, and a claim written just before its send
/// would then suppress a retry for 24 hours.
fn spawn_logged(task: impl Future<Output = ()> + Send + 'static) {
    let handle = tokio::spawn(task);
    tokio::spawn(async move {
        if handle.await.is_err() {
            tracing::warn!("an alert task stopped before it finished");
        }
    });
}

/// A fixed log text for a send error, so no text derived from the channel config is logged.
fn reason(error: &SendError) -> &'static str {
    match error {
        SendError::Blocked => "target is a blocked address",
        SendError::Target => "target is not allowed or did not resolve",
        SendError::Config => "channel config is invalid",
        SendError::Status(_) => "webhook answered with a non-2xx status",
        SendError::Timeout => "timed out",
        SendError::Tls => "failed the TLS check",
        SendError::Rejected { .. } => "smtp server rejected the message",
        SendError::Connection => "failed to connect",
    }
}

/// A decrypted channel config. Both configs print `<redacted>` for their secrets.
#[derive(Debug, Clone)]
pub enum ChannelConfig {
    Smtp(SmtpConfig),
    Webhook(WebhookConfig),
}

/// The future a sender returns.
pub type SendFuture = Pin<Box<dyn Future<Output = Result<(), SendError>> + Send>>;

/// Delivers one alert over one channel. The production sender calls `alert_send`; tests
/// pass a recording one.
type SendFn = dyn Fn(ChannelConfig, Alert) -> SendFuture + Send + Sync;

/// Sends alerts to the enabled channels. Cheap to clone.
#[derive(Clone)]
pub struct Notifier {
    pool: SqlitePool,
    credentials_key: Arc<DerivedKey>,
    send: Arc<SendFn>,
}

impl Notifier {
    /// The production notifier. `allow_private` is `DOCKWARD_ALLOW_PRIVATE_ALERTS`.
    pub fn new(pool: SqlitePool, credentials_key: Arc<DerivedKey>, allow_private: bool) -> Self {
        Self::with_sender(pool, credentials_key, move |config, alert| {
            Box::pin(async move {
                match config {
                    ChannelConfig::Webhook(config) => {
                        alert_send::send_webhook(&config, &alert, allow_private).await
                    }
                    ChannelConfig::Smtp(config) => {
                        alert_send::send_smtp(&config, &alert, allow_private).await
                    }
                }
            })
        })
    }

    /// A notifier with a given sender. Production code uses [`Notifier::new`].
    pub fn with_sender(
        pool: SqlitePool,
        credentials_key: Arc<DerivedKey>,
        send: impl Fn(ChannelConfig, Alert) -> SendFuture + Send + Sync + 'static,
    ) -> Self {
        Self {
            pool,
            credentials_key,
            send: Arc::new(send),
        }
    }

    /// Sends `alert` to every enabled channel whose event set holds `alert.event` and that has
    /// not had `dedupe_key` in the last 24 hours. `now` is Unix seconds. It never fails the
    /// caller.
    pub async fn notify(&self, alert: &Alert, dedupe_key: &str, now: i64) {
        let channels =
            match deliveries::list_enabled_channels(&self.pool, alert.event.as_str()).await {
                Ok(channels) => channels,
                Err(_) => {
                    tracing::warn!("alert channels could not be read");
                    return;
                }
            };
        for channel in &channels {
            self.deliver(channel, alert, dedupe_key, now).await;
        }
    }

    /// One channel: decrypt, claim, send, and release the claim if the send fails.
    async fn deliver(&self, channel: &ChannelRow, alert: &Alert, dedupe_key: &str, now: i64) {
        let Ok(config) = self.open(channel) else {
            tracing::warn!(channel_id = %channel.id, "alert channel config could not be read");
            return;
        };
        let claimed = match self.claim(&channel.id, dedupe_key, now).await {
            Ok(claimed) => claimed,
            Err(_) => {
                tracing::warn!(channel_id = %channel.id, "alert delivery could not be recorded");
                return;
            }
        };
        if !claimed {
            return;
        }
        if let Err(error) = (self.send)(config, alert.clone()).await {
            tracing::warn!(
                channel_id = %channel.id,
                reason = reason(&error),
                "alert delivery failed"
            );
            if self.release(&channel.id, dedupe_key, now).await.is_err() {
                tracing::warn!(channel_id = %channel.id, "alert delivery claim could not be released");
            }
        }
    }

    /// Decrypts and parses the channel config. The plaintext is zeroed on drop.
    fn open(&self, channel: &ChannelRow) -> Result<ChannelConfig, AppError> {
        // The AAD is the one `alert_channels` seals with: it binds the config to its row.
        let aad = crypto::aad("alert_channels", "config_encrypted", &channel.id);
        let plain = crypto::decrypt(&self.credentials_key, &aad, &channel.config_encrypted)?;
        match channel.kind.as_str() {
            "smtp" => serde_json::from_slice(&plain)
                .map(ChannelConfig::Smtp)
                .map_err(|_| AppError::InternalError),
            "webhook" => serde_json::from_slice(&plain)
                .map(ChannelConfig::Webhook)
                .map_err(|_| AppError::InternalError),
            _ => Err(AppError::InternalError),
        }
    }

    async fn claim(&self, channel_id: &str, dedupe_key: &str, now: i64) -> Result<bool, AppError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        let id = ids::new_id()?;
        deliveries::claim(&mut conn, &id, channel_id, dedupe_key, now).await
    }

    async fn release(&self, channel_id: &str, dedupe_key: &str, now: i64) -> Result<(), AppError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        deliveries::release(&mut conn, channel_id, dedupe_key, now).await
    }

    /// The scan alerts of the scan that `run_id` ended, on a background task. See
    /// [`Notifier::scan_alerts`].
    pub fn spawn_scan_alerts(&self, run_id: &str, now: i64) {
        let notifier = self.clone();
        let run_id = run_id.to_owned();
        spawn_logged(async move {
            if notifier.scan_alerts(&run_id, now).await.is_err() {
                tracing::warn!("the scan alerts could not be read");
            }
        });
    }

    /// Sends the alerts of a finished scan. `run_id` is the scan run that just ended. While any
    /// run or pull of its image is open the scan has not ended, and nothing is sent. Otherwise the
    /// pending changes of the image are taken (and deleted) in one transaction, so a change is
    /// sent at most once, and then:
    /// - one `new_high_or_critical` summary per source, listing up to [`SUMMARY_LIMIT`] CVE ids
    ///   then "and N more", keyed `scan:<run id>:<source id>`;
    /// - one `cve_fixed` alert per CVE, keyed `cve_fixed:<CVE id>:<run id>`. While an enabled
    ///   scanner has no `done` run for the image the fixes are held: their rows stay pending for
    ///   the next complete scan (a failed scanner never reports a fix).
    ///
    /// A failed send is logged and not sent again for this scan. Only a database error is
    /// returned.
    pub async fn scan_alerts(&self, run_id: &str, now: i64) -> Result<(), AppError> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| AppError::InternalError)?;
        let Some(run) = scans_db::find_run(&mut tx, run_id).await? else {
            return Ok(());
        };
        let image_id = run.image_id;
        if scans_db::image_has_open_runs(&mut tx, &image_id).await?
            || publish_db::image_has_pending_pull(&mut tx, &image_id).await?
        {
            return Ok(());
        }
        let new = pending::take_new(&mut tx, &image_id).await?;
        let enabled = issue_lifecycle::enabled_scanner_keys(&mut tx).await?;
        let fixed_held =
            issue_lifecycle::image_awaits_scanner(&mut tx, &image_id, &enabled).await?;
        // Held fixes stay pending, so the next complete scan of the image sends them.
        let fixed = if fixed_held {
            Vec::new()
        } else {
            pending::take_fixed(&mut tx, &image_id).await?
        };
        tx.commit().await.map_err(|_| AppError::InternalError)?;

        for (source_id, cves) in by_source(new) {
            let Some(source) = self.source(&source_id).await else {
                continue;
            };
            let alert = summary_alert(&source, &cves, now);
            let dedupe_key = format!("scan:{run_id}:{source_id}");
            self.notify(&alert, &dedupe_key, now).await;
        }
        for (source_id, cves) in by_source(fixed) {
            let Some(source) = self.source(&source_id).await else {
                continue;
            };
            let mut seen: Vec<&str> = Vec::new();
            for cve in &cves {
                // One alert per CVE: the first tag of the source names it.
                if seen.contains(&cve.cve_id.as_str()) {
                    continue;
                }
                seen.push(&cve.cve_id);
                let alert = fixed_alert(&source, cve, now);
                let dedupe_key = format!("cve_fixed:{}:{run_id}", cve.cve_id);
                self.notify(&alert, &dedupe_key, now).await;
            }
        }
        Ok(())
    }

    async fn source(&self, source_id: &str) -> Option<SourceRow> {
        let mut conn = self.pool.acquire().await.ok()?;
        sources::find_by_id(&mut conn, source_id)
            .await
            .ok()
            .flatten()
    }

    /// Alerts for a job that was given up, on a background task. The dedupe key is
    /// `job_failed:<job_id>`. The payload has the mapping names and fixed text only.
    pub fn spawn_job_failed(&self, job_id: &str, mapping_id: &str, now: i64) {
        let notifier = self.clone();
        let job_id = job_id.to_owned();
        let mapping_id = mapping_id.to_owned();
        spawn_logged(async move {
            let alert = notifier.job_failed_alert(&mapping_id, now).await;
            let dedupe_key = format!("job_failed:{job_id}");
            notifier.notify(&alert, &dedupe_key, now).await;
        });
    }

    async fn job_failed_alert(&self, mapping_id: &str, now: i64) -> Alert {
        let found = match self.pool.acquire().await {
            Ok(mut conn) => sources::find_by_id(&mut conn, mapping_id)
                .await
                .ok()
                .flatten(),
            Err(_) => None,
        };
        let (harbor, github) = match found {
            Some(source) => (
                format!("{}/{}", source.hub_host, source.repository),
                format!("{}/{}", source.github_owner, source.github_repo),
            ),
            None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
        };
        Alert {
            event: AlertEvent::JobFailed,
            occurred_at: now,
            mapping_id: mapping_id.to_owned(),
            harbor,
            github,
            cve_id: None,
            severity: None,
            image_tag: None,
            error: Some(JOB_FAILED_TEXT.to_owned()),
            cves: Vec::new(),
            more: 0,
        }
    }
}

/// Groups pending rows by source, keeping the order they arrived in.
fn by_source(rows: Vec<PendingCve>) -> Vec<(String, Vec<PendingCve>)> {
    let mut groups: Vec<(String, Vec<PendingCve>)> = Vec::new();
    for row in rows {
        match groups.last_mut() {
            Some((source_id, list)) if *source_id == row.source_id => list.push(row),
            _ => groups.push((row.source_id.clone(), vec![row])),
        }
    }
    groups
}

/// The names of a source in an alert: `<hub host>/<repository>` and `<owner>/<repo>`.
fn names(source: &SourceRow) -> (String, String) {
    (
        format!("{}/{}", source.hub_host, source.repository),
        format!("{}/{}", source.github_owner, source.github_repo),
    )
}

/// One summary of the new HIGH and CRITICAL CVEs of a source. A CVE on several tags is listed
/// once, under the first tag. The payload has names, the tag, CVE ids and severities only.
fn summary_alert(source: &SourceRow, rows: &[PendingCve], now: i64) -> Alert {
    let mut cves: Vec<ListedCve> = Vec::new();
    for row in rows {
        if !cves.iter().any(|cve| cve.id == row.cve_id) {
            cves.push(ListedCve {
                id: row.cve_id.clone(),
                severity: row.severity.clone(),
            });
        }
    }
    let more = cves.len().saturating_sub(SUMMARY_LIMIT);
    cves.truncate(SUMMARY_LIMIT);
    let (harbor, github) = names(source);
    Alert {
        event: AlertEvent::NewHighOrCritical,
        occurred_at: now,
        mapping_id: source.id.clone(),
        harbor,
        github,
        cve_id: None,
        severity: None,
        image_tag: rows.first().map(|row| row.image_tag.clone()),
        error: None,
        cves,
        more,
    }
}

/// The alert for one fixed CVE.
fn fixed_alert(source: &SourceRow, row: &PendingCve, now: i64) -> Alert {
    let (harbor, github) = names(source);
    Alert {
        event: AlertEvent::CveFixed,
        occurred_at: now,
        mapping_id: source.id.clone(),
        harbor,
        github,
        cve_id: Some(row.cve_id.clone()),
        severity: Some(row.severity.clone()),
        image_tag: Some(row.image_tag.clone()),
        error: None,
        cves: Vec::new(),
        more: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;
    use crate::config::parse_encryption_key;
    use crate::services::alert_channels;
    use crate::services::audit::Actor;

    // Test values only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const DAY: i64 = 86_400;
    const ALL: [&str; 3] = ["job_failed", "new_high_or_critical", "cve_fixed"];

    fn key() -> Arc<DerivedKey> {
        Arc::new(crypto::credentials_key(&parse_encryption_key(TEST_KEY_B64).unwrap()).unwrap())
    }

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("dockward-alerts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, "admin-1", "test-admin", None, "h", "admin")
            .await
            .unwrap();
        (pool, dir)
    }

    /// A webhook channel whose URL ends in `name`, taking `events`.
    async fn channel_for(pool: &SqlitePool, enabled: bool, name: &str, events: &[&str]) -> String {
        let actor = Actor {
            user_id: Some("admin-1".to_owned()),
            username: "test-admin".to_owned(),
        };
        let events: Vec<String> = events.iter().map(|e| (*e).to_owned()).collect();
        alert_channels::create(
            pool,
            &key(),
            &actor,
            false,
            "webhook",
            enabled,
            Some(&events),
            json!({"url": format!("https://hooks.example.test/services/{name}")}),
        )
        .await
        .unwrap()
        .id
    }

    async fn webhook_channel(pool: &SqlitePool, enabled: bool) -> String {
        channel_for(pool, enabled, "FAKE_URL_TOKEN_1", &ALL).await
    }

    fn alert(mapping_id: &str, event: AlertEvent) -> Alert {
        Alert {
            event,
            occurred_at: 1_000,
            mapping_id: mapping_id.to_owned(),
            harbor: "proj/repo".to_owned(),
            github: "acme/app".to_owned(),
            cve_id: None,
            severity: None,
            image_tag: Some("v1".to_owned()),
            error: None,
            cves: Vec::new(),
            more: 0,
        }
    }

    fn failed(mapping_id: &str) -> Alert {
        alert(mapping_id, AlertEvent::JobFailed)
    }

    /// A sender that counts calls, records the channel URL suffix and the alert of each, and
    /// answers with the next scripted result (`Ok` when the script is empty).
    #[derive(Clone, Default)]
    struct Recorder {
        calls: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<(String, Alert)>>>,
        script: Arc<Mutex<Vec<Result<(), SendError>>>>,
    }

    impl Recorder {
        fn failing_once() -> Self {
            let recorder = Self::default();
            recorder
                .script
                .lock()
                .unwrap()
                .push(Err(SendError::Connection));
            recorder
        }

        fn notifier(&self, pool: &SqlitePool) -> Notifier {
            let recorder = self.clone();
            Notifier::with_sender(pool.clone(), key(), move |config, alert| {
                let recorder = recorder.clone();
                let name = match &config {
                    ChannelConfig::Webhook(c) => {
                        c.url.rsplit('/').next().unwrap_or_default().to_owned()
                    }
                    ChannelConfig::Smtp(_) => "smtp".to_owned(),
                };
                Box::pin(async move {
                    recorder.calls.fetch_add(1, Ordering::SeqCst);
                    recorder.seen.lock().unwrap().push((name, alert));
                    let mut script = recorder.script.lock().unwrap();
                    if script.is_empty() {
                        Ok(())
                    } else {
                        script.remove(0)
                    }
                })
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn seen(&self) -> Vec<(String, Alert)> {
            self.seen.lock().unwrap().clone()
        }
    }

    async fn delivery_rows(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM alert_deliveries")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn keys(pool: &SqlitePool) -> Vec<String> {
        sqlx::query_scalar("SELECT dedupe_key FROM alert_deliveries ORDER BY dedupe_key")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn job_failure_alerts_once_per_job_per_24h() {
        let (pool, dir) = fresh_pool("per-job").await;
        webhook_channel(&pool, true).await;
        webhook_channel(&pool, true).await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);

        // The same job twice: the dedupe key is the job id.
        notifier
            .notify(&failed("map-1"), "job_failed:j1", 10_000)
            .await;
        notifier
            .notify(&failed("map-1"), "job_failed:j1", 10_060)
            .await;
        // Once per channel, and the repeat adds nothing.
        assert_eq!(recorder.calls(), 2);
        assert_eq!(delivery_rows(&pool).await, 2);

        // The control: another job is a different key and is sent.
        notifier
            .notify(&failed("map-1"), "job_failed:j2", 10_120)
            .await;
        assert_eq!(recorder.calls(), 4);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn noop_upsert_sends_nothing() {
        let (pool, dir) = fresh_pool("noop-upsert").await;
        let channel_id = webhook_channel(&pool, true).await;

        // The claim itself: the second call changes no row and keeps the first `sent_at`.
        let mut conn = pool.acquire().await.unwrap();
        assert!(
            deliveries::claim(&mut conn, "d1", &channel_id, "job_failed:j1", 1_000)
                .await
                .unwrap()
        );
        assert!(
            !deliveries::claim(&mut conn, "d2", &channel_id, "job_failed:j1", 2_000)
                .await
                .unwrap(),
            "a claim inside the window changed a row"
        );
        drop(conn);
        let sent_at: i64 = sqlx::query_scalar("SELECT sent_at FROM alert_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sent_at, 1_000);
        assert_eq!(delivery_rows(&pool).await, 1);

        // The dispatcher on top of it sends nothing for that key.
        let recorder = Recorder::default();
        recorder
            .notifier(&pool)
            .notify(&failed("map-1"), "job_failed:j1", 3_000)
            .await;
        assert_eq!(recorder.calls(), 0);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn after_24h_it_sends_again() {
        let (pool, dir) = fresh_pool("after-24h").await;
        webhook_channel(&pool, true).await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);
        let item = failed("map-1");

        notifier.notify(&item, "job_failed:j1", 5_000).await;
        assert_eq!(recorder.calls(), 1);
        // Exactly 24 hours later is still inside the window.
        notifier.notify(&item, "job_failed:j1", 5_000 + DAY).await;
        assert_eq!(recorder.calls(), 1);
        // One second more is outside it.
        notifier
            .notify(&item, "job_failed:j1", 5_000 + DAY + 1)
            .await;
        assert_eq!(recorder.calls(), 2);
        // The window restarts from the new send.
        notifier
            .notify(&item, "job_failed:j1", 5_000 + DAY + 2)
            .await;
        assert_eq!(recorder.calls(), 2);
        assert_eq!(delivery_rows(&pool).await, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn failed_send_releases_the_claim() {
        let (pool, dir) = fresh_pool("failed-send").await;
        webhook_channel(&pool, true).await;
        let recorder = Recorder::failing_once();
        let notifier = recorder.notifier(&pool);
        let item = failed("map-1");

        notifier.notify(&item, "job_failed:j1", 5_000).await;
        assert_eq!(recorder.calls(), 1);
        assert_eq!(
            delivery_rows(&pool).await,
            0,
            "a failed send kept its claim"
        );

        // The next trigger inside the 24 hours retries and now succeeds.
        notifier.notify(&item, "job_failed:j1", 5_060).await;
        assert_eq!(recorder.calls(), 2);
        assert_eq!(delivery_rows(&pool).await, 1);
        // A success is kept: nothing more is sent.
        notifier.notify(&item, "job_failed:j1", 5_120).await;
        assert_eq!(recorder.calls(), 2);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn disabled_channel_gets_nothing() {
        let (pool, dir) = fresh_pool("disabled").await;
        webhook_channel(&pool, false).await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);
        let item = failed("map-1");

        notifier.notify(&item, "job_failed:j1", 5_000).await;
        assert_eq!(recorder.calls(), 0);
        assert_eq!(delivery_rows(&pool).await, 0);

        // The control: an enabled channel added next to it gets the alert.
        webhook_channel(&pool, true).await;
        notifier.notify(&item, "job_failed:j1", 5_001).await;
        assert_eq!(recorder.calls(), 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_channel_receives_only_its_ticked_events() {
        let (pool, dir) = fresh_pool("routing").await;
        channel_for(&pool, true, "FAILURES", &["job_failed"]).await;
        channel_for(&pool, true, "CVES", &["new_high_or_critical", "cve_fixed"]).await;
        channel_for(&pool, true, "NOTHING", &[]).await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);

        notifier
            .notify(&failed("map-1"), "job_failed:j1", 5_000)
            .await;
        notifier
            .notify(
                &alert("map-1", AlertEvent::NewHighOrCritical),
                "scan:r1:map-1",
                5_000,
            )
            .await;
        notifier
            .notify(
                &alert("map-1", AlertEvent::CveFixed),
                "cve_fixed:CVE-1:r1",
                5_000,
            )
            .await;

        let seen: Vec<(String, AlertEvent)> = recorder
            .seen()
            .into_iter()
            .map(|(name, alert)| (name, alert.event))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("FAILURES".to_owned(), AlertEvent::JobFailed),
                ("CVES".to_owned(), AlertEvent::NewHighOrCritical),
                ("CVES".to_owned(), AlertEvent::CveFixed),
            ]
        );
        // The channel with no ticked event got nothing, and nothing was claimed for it.
        assert_eq!(delivery_rows(&pool).await, 3);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_sender_gets_the_decrypted_config() {
        let (pool, dir) = fresh_pool("decrypted").await;
        webhook_channel(&pool, true).await;
        let seen: Arc<Mutex<Vec<bool>>> = Arc::default();
        let log = seen.clone();
        let notifier = Notifier::with_sender(pool.clone(), key(), move |config, _alert| {
            let matched = matches!(
                &config,
                ChannelConfig::Webhook(c) if c.url == "https://hooks.example.test/services/FAKE_URL_TOKEN_1"
            );
            log.lock().unwrap().push(matched);
            Box::pin(async { Ok(()) })
        });
        notifier
            .notify(&failed("map-1"), "job_failed:j1", 5_000)
            .await;
        assert_eq!(seen.lock().unwrap().clone(), vec![true]);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The scan alerts. One source `s1` on `ghcr.io/proj/app` targeting `acme/app`, image `img1`
    // with one platform `p1` and a `done` run of both scanners (`r-grype`, `r-trivy`).

    async fn exec(pool: &SqlitePool, sql: &'static str) {
        sqlx::query(sql).execute(pool).await.unwrap();
    }

    async fn scan_fixture(pool: &SqlitePool) {
        for sql in [
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('c1', 'admin-1', 'g', 'v1:fake')",
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id,
                 github_owner, github_repo, auto_create_issues, min_issue_severity)
             VALUES ('s1', 'admin-1', 'hub-default-ghcr', 'proj/app', '*', 'c1', 'acme', 'app', 1, 'CRITICAL')",
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES ('img1', 'hub-default-ghcr', 'proj/app', 'sha256:one', 0)",
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, pulled_at)
             VALUES ('p1', 'img1', 'linux/amd64', 'sha256:p1', 'stored', 1)",
            "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
             VALUES ('s1', 'v1', 'img1', 1, 1)",
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r-grype', 'p1', 'grype', 'first_pull', 'done', 10)",
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r-trivy', 'p1', 'trivy', 'first_pull', 'done', 11)",
        ] {
            exec(pool, sql).await;
        }
    }

    /// A `cve_findings` row of `s1:v1` and its pending change, as the convert step writes them.
    async fn change(pool: &SqlitePool, event: &str, cve: &str, severity: &str) {
        let status = if event == pending::FIXED {
            "fixed"
        } else {
            "open"
        };
        sqlx::query(
            "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, status)
             VALUES (?, 's1', 'v1', ?, ?, ?)
             ON CONFLICT (source_id, image_tag, cve_id) DO UPDATE SET
                severity = excluded.severity, status = excluded.status",
        )
        .bind(format!("f-{cve}"))
        .bind(cve)
        .bind(severity)
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        pending::record(&mut conn, event, "img1", "s1", "v1", cve, 1)
            .await
            .unwrap();
    }

    async fn pending_rows(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_pending")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn one_summary_per_scan_per_channel_with_ten_then_and_n_more() {
        let (pool, dir) = fresh_pool("summary").await;
        scan_fixture(&pool).await;
        channel_for(&pool, true, "A", &["new_high_or_critical"]).await;
        channel_for(&pool, true, "B", &["new_high_or_critical", "job_failed"]).await;
        channel_for(&pool, true, "OFF", &["job_failed", "cve_fixed"]).await;
        // 12 new HIGH or CRITICAL CVEs, and a new MEDIUM one that does not count.
        for n in 1..=12 {
            let severity = if n % 4 == 0 { "CRITICAL" } else { "HIGH" };
            change(&pool, pending::NEW, &format!("CVE-2026-{n:04}"), severity).await;
        }
        change(&pool, pending::NEW, "CVE-2026-0999", "MEDIUM").await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);

        notifier.scan_alerts("r-trivy", 5_000).await.unwrap();
        let seen = recorder.seen();
        let mut names: Vec<&str> = seen.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["A", "B"], "one summary per channel that takes it");
        let summary = &seen[0].1;
        assert_eq!(summary.event, AlertEvent::NewHighOrCritical);
        assert_eq!(summary.cves.len(), SUMMARY_LIMIT);
        assert_eq!(summary.more, 2);
        // CRITICAL first, then HIGH, each by id.
        assert_eq!(summary.cves[0].id, "CVE-2026-0004");
        assert_eq!(summary.cves[0].severity, "CRITICAL");
        assert!(summary.cves.iter().all(|cve| cve.id != "CVE-2026-0999"));
        assert_eq!(summary.image_tag.as_deref(), Some("v1"));
        assert_eq!(summary.harbor, "ghcr.io/proj/app");
        assert!(
            summary.text().ends_with(" and 2 more."),
            "{}",
            summary.text()
        );
        assert_eq!(keys(&pool).await, ["scan:r-trivy:s1", "scan:r-trivy:s1"]);
        assert_eq!(pending_rows(&pool).await, 0, "the changes were not taken");

        // The same scan again, and a second identical scan, send nothing new.
        notifier.scan_alerts("r-trivy", 5_010).await.unwrap();
        notifier.scan_alerts("r-grype", 5_020).await.unwrap();
        assert_eq!(recorder.calls(), 2);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn nothing_is_sent_while_a_run_of_the_image_is_open() {
        let (pool, dir) = fresh_pool("open-run").await;
        scan_fixture(&pool).await;
        webhook_channel(&pool, true).await;
        change(&pool, pending::NEW, "CVE-2026-0001", "CRITICAL").await;
        exec(
            &pool,
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status)
             VALUES ('r-open', 'p1', 'grype', 'db_update', 'queued')",
        )
        .await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);
        notifier.scan_alerts("r-trivy", 5_000).await.unwrap();
        assert_eq!(recorder.calls(), 0);
        assert_eq!(pending_rows(&pool).await, 1, "a change was taken too early");

        // When the last run ends, the summary goes out once.
        exec(
            &pool,
            "UPDATE scan_runs SET status = 'done', finished_at = 20 WHERE id = 'r-open'",
        )
        .await;
        notifier.scan_alerts("r-open", 5_100).await.unwrap();
        assert_eq!(recorder.calls(), 1);
        assert_eq!(keys(&pool).await, ["scan:r-open:s1"]);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cve_fixed_is_sent_once_per_fix_and_never_touches_github() {
        let (pool, dir) = fresh_pool("fixed").await;
        scan_fixture(&pool).await;
        channel_for(&pool, true, "FIXES", &["cve_fixed"]).await;
        channel_for(
            &pool,
            true,
            "OTHER",
            &["job_failed", "new_high_or_critical"],
        )
        .await;
        // An open GitHub issue for the CVE: a fixed alert must leave it as it is.
        exec(
            &pool,
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number,
                 github_issue_url, status)
             VALUES ('gi1', 'acme', 'app', 'CVE-2026-0007', 7, 'https://github.test/acme/app/issues/7', 'open')",
        )
        .await;
        change(&pool, pending::FIXED, "CVE-2026-0007", "HIGH").await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);

        notifier.scan_alerts("r-trivy", 5_000).await.unwrap();
        let seen = recorder.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "FIXES");
        assert_eq!(seen[0].1.event, AlertEvent::CveFixed);
        assert_eq!(seen[0].1.cve_id.as_deref(), Some("CVE-2026-0007"));
        assert_eq!(keys(&pool).await, ["cve_fixed:CVE-2026-0007:r-trivy"]);
        // The notifier has no GitHub client. The issue row is untouched.
        let issue: (String, Option<i64>) =
            sqlx::query_as("SELECT status, fixed_noted_at FROM github_issues WHERE id = 'gi1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(issue, ("open".to_owned(), None));

        // The same fix is not sent again by a later scan.
        notifier.scan_alerts("r-grype", 5_100).await.unwrap();
        assert_eq!(recorder.calls(), 1);

        // A CVE reported again before the scan ended is not sent as fixed.
        change(&pool, pending::FIXED, "CVE-2026-0008", "HIGH").await;
        exec(
            &pool,
            "UPDATE cve_findings SET status = 'open' WHERE cve_id = 'CVE-2026-0008'",
        )
        .await;
        notifier.scan_alerts("r-grype", 5_200).await.unwrap();
        assert_eq!(recorder.calls(), 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failed_scanner_holds_the_fixed_alert() {
        let (pool, dir) = fresh_pool("fixed-held").await;
        scan_fixture(&pool).await;
        webhook_channel(&pool, true).await;
        exec(
            &pool,
            "UPDATE scan_runs SET status = 'failed' WHERE id = 'r-grype'",
        )
        .await;
        change(&pool, pending::FIXED, "CVE-2026-0007", "HIGH").await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);
        notifier.scan_alerts("r-trivy", 5_000).await.unwrap();
        assert_eq!(recorder.calls(), 0, "a fix was sent without every scanner");
        assert_eq!(pending_rows(&pool).await, 1, "a held fix was dropped");

        // The next complete scan sends the held fix once, under its own scan id.
        exec(
            &pool,
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r-grype-2', 'p1', 'grype', 'db_update', 'done', 30)",
        )
        .await;
        notifier.scan_alerts("r-grype-2", 5_100).await.unwrap();
        assert_eq!(recorder.calls(), 1);
        assert_eq!(keys(&pool).await, ["cve_fixed:CVE-2026-0007:r-grype-2"]);
        assert_eq!(pending_rows(&pool).await, 0);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
