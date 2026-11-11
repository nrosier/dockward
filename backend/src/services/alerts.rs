//! The alert dispatcher: sends job failures and new CRITICAL CVEs to every enabled
//! channel, at most once per 24 hours per dedupe key and channel.
//! Sources: `specs/alerts.md` (Triggers, Deduplication, Decisions: scope is all tenants),
//! `specs/database.md` (the `alert_deliveries` write rule).
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
use crate::db::sources::{self, SourceRow};
use crate::error::AppError;
use crate::services::alert_channels::{SmtpConfig, WebhookConfig};
use crate::services::alert_send::{self, Alert, AlertEvent, SendError};
use crate::services::ids;
use crate::worker::now_secs;

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

    /// Sends `alert` to every enabled channel that has not had `dedupe_key` in the last
    /// 24 hours. `now` is Unix seconds. It never fails the caller.
    pub async fn notify(&self, alert: &Alert, dedupe_key: &str, now: i64) {
        let channels = match deliveries::list_enabled_channels(&self.pool).await {
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

    /// Alerts for CVEs that are new CRITICAL findings in `source`, on a background task.
    /// The dedupe key is the CVE id alone, so the same CVE alerts once per 24 hours
    /// whatever the mapping. The payload has mapping names, the tag and the CVE id only.
    pub fn spawn_new_critical(&self, source: &SourceRow, tag: &str, cve_ids: &[String]) {
        if cve_ids.is_empty() {
            return;
        }
        let notifier = self.clone();
        let items: Vec<(Alert, String)> = cve_ids
            .iter()
            .map(|cve_id| {
                let alert = Alert {
                    event: AlertEvent::CriticalCve,
                    occurred_at: 0,
                    mapping_id: source.id.clone(),
                    harbor: format!("{}/{}", source.hub_host, source.repository),
                    github: format!("{}/{}", source.github_owner, source.github_repo),
                    cve_id: Some(cve_id.clone()),
                    severity: Some("CRITICAL".to_owned()),
                    image_tag: Some(tag.to_owned()),
                    error: None,
                };
                (alert, cve_id.clone())
            })
            .collect();
        spawn_logged(async move {
            for (mut alert, dedupe_key) in items {
                let now = now_secs();
                alert.occurred_at = now;
                notifier.notify(&alert, &dedupe_key, now).await;
            }
        });
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
        }
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

    async fn webhook_channel(pool: &SqlitePool, enabled: bool) -> String {
        let actor = Actor {
            user_id: Some("admin-1".to_owned()),
            username: "test-admin".to_owned(),
        };
        alert_channels::create(
            pool,
            &key(),
            &actor,
            false,
            "webhook",
            enabled,
            json!({"url": "https://hooks.example.test/services/FAKE_URL_TOKEN_1"}),
        )
        .await
        .unwrap()
        .id
    }

    fn alert(mapping_id: &str, cve: &str) -> Alert {
        Alert {
            event: AlertEvent::CriticalCve,
            occurred_at: 1_000,
            mapping_id: mapping_id.to_owned(),
            harbor: "proj/repo".to_owned(),
            github: "acme/app".to_owned(),
            cve_id: Some(cve.to_owned()),
            severity: Some("CRITICAL".to_owned()),
            image_tag: Some("v1".to_owned()),
            error: None,
        }
    }

    /// A sender that counts calls and answers with the next scripted result (`Ok` when the
    /// script is empty).
    #[derive(Clone, Default)]
    struct Recorder {
        calls: Arc<AtomicUsize>,
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
            Notifier::with_sender(pool.clone(), key(), move |_config, _alert| {
                let recorder = recorder.clone();
                Box::pin(async move {
                    recorder.calls.fetch_add(1, Ordering::SeqCst);
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
    }

    async fn delivery_rows(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM alert_deliveries")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn same_cve_alerts_once_per_24h_across_mappings() {
        let (pool, dir) = fresh_pool("across-mappings").await;
        webhook_channel(&pool, true).await;
        webhook_channel(&pool, true).await;
        let recorder = Recorder::default();
        let notifier = recorder.notifier(&pool);

        // The same CVE found in two mappings: the dedupe key is the CVE id alone.
        notifier
            .notify(&alert("map-1", "CVE-2026-0001"), "CVE-2026-0001", 10_000)
            .await;
        notifier
            .notify(&alert("map-2", "CVE-2026-0001"), "CVE-2026-0001", 10_060)
            .await;
        // Once per channel, and the second mapping adds nothing.
        assert_eq!(recorder.calls(), 2);
        assert_eq!(delivery_rows(&pool).await, 2);

        // The control: another CVE is a different key and is sent.
        notifier
            .notify(&alert("map-2", "CVE-2026-0002"), "CVE-2026-0002", 10_120)
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
            deliveries::claim(&mut conn, "d1", &channel_id, "CVE-1", 1_000)
                .await
                .unwrap()
        );
        assert!(
            !deliveries::claim(&mut conn, "d2", &channel_id, "CVE-1", 2_000)
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
            .notify(&alert("map-1", "CVE-1"), "CVE-1", 3_000)
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
        let item = alert("map-1", "CVE-1");

        notifier.notify(&item, "CVE-1", 5_000).await;
        assert_eq!(recorder.calls(), 1);
        // Exactly 24 hours later is still inside the window.
        notifier.notify(&item, "CVE-1", 5_000 + DAY).await;
        assert_eq!(recorder.calls(), 1);
        // One second more is outside it.
        notifier.notify(&item, "CVE-1", 5_000 + DAY + 1).await;
        assert_eq!(recorder.calls(), 2);
        // The window restarts from the new send.
        notifier.notify(&item, "CVE-1", 5_000 + DAY + 2).await;
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
        let item = alert("map-1", "CVE-1");

        notifier.notify(&item, "CVE-1", 5_000).await;
        assert_eq!(recorder.calls(), 1);
        assert_eq!(
            delivery_rows(&pool).await,
            0,
            "a failed send kept its claim"
        );

        // The next trigger inside the 24 hours retries and now succeeds.
        notifier.notify(&item, "CVE-1", 5_060).await;
        assert_eq!(recorder.calls(), 2);
        assert_eq!(delivery_rows(&pool).await, 1);
        // A success is kept: nothing more is sent.
        notifier.notify(&item, "CVE-1", 5_120).await;
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
        let item = alert("map-1", "CVE-1");

        notifier.notify(&item, "CVE-1", 5_000).await;
        assert_eq!(recorder.calls(), 0);
        assert_eq!(delivery_rows(&pool).await, 0);

        // The control: an enabled channel added next to it gets the alert.
        webhook_channel(&pool, true).await;
        notifier.notify(&item, "CVE-1", 5_001).await;
        assert_eq!(recorder.calls(), 1);
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
            .notify(&alert("map-1", "CVE-1"), "CVE-1", 5_000)
            .await;
        assert_eq!(seen.lock().unwrap().clone(), vec![true]);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn new_critical_alerts_use_the_cve_id_as_the_key() {
        let (pool, dir) = fresh_pool("new-critical").await;
        webhook_channel(&pool, true).await;
        let seen: Arc<Mutex<Vec<Alert>>> = Arc::default();
        let log = seen.clone();
        let notifier = Notifier::with_sender(pool.clone(), key(), move |_config, alert| {
            log.lock().unwrap().push(alert);
            Box::pin(async { Ok(()) })
        });
        let source = SourceRow {
            id: "map-1".to_owned(),
            user_id: "admin-1".to_owned(),
            hub_host: "ghcr.io".to_owned(),
            repository: "proj/app".to_owned(),
            tag_value: "*".to_owned(),
            github_cred_id: "c2".to_owned(),
            github_owner: "acme".to_owned(),
            github_repo: "app".to_owned(),
            default_branch: "main".to_owned(),
            auto_create_issues: false,
            min_issue_severity: "CRITICAL".to_owned(),
        };
        notifier.spawn_new_critical(&source, "v1", &["CVE-2026-0001".to_owned()]);
        for _ in 0..200 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let alerts = seen.lock().unwrap().clone();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event, AlertEvent::CriticalCve);
        assert_eq!(alerts[0].cve_id.as_deref(), Some("CVE-2026-0001"));
        assert_eq!(alerts[0].image_tag.as_deref(), Some("v1"));
        assert_eq!(alerts[0].harbor, "ghcr.io/proj/app");
        let dedupe: String = sqlx::query_scalar("SELECT dedupe_key FROM alert_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(dedupe, "CVE-2026-0001");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
