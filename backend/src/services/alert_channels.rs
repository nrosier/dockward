//! Admin alert channels: create, list, and update SMTP and webhook channels.
//! Sources: `specs/alerts.md` (Channels, Storage), `specs/api.md` (Admin),
//! `specs/security.md` (Encryption and keys, Outbound HTTP).
//!
//! The whole channel config is one JSON document, encrypted into
//! `alert_channels.config_encrypted` with the credentials key and an AAD that binds it
//! to its row. The config is write-only: no response carries it, and no audit row
//! carries a value from it. Sending is not done here (#57).

use std::collections::BTreeMap;
use std::fmt;

use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::auth::crypto::{self, DerivedKey};
use crate::db::alert_channels::{self as rows, ChannelRow};
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::ids;
use crate::services::outbound::{self, TargetClass};
use crate::services::pagination::{Page, Pagination};
use crate::services::time;

const REDACTED: &str = "<redacted>";

/// How the SMTP connection is secured. There is no plaintext option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Implicit,
    Starttls,
}

/// SMTP channel config. `tls` has no default, so a config without it does not parse.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

impl fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("password", &REDACTED)
            .field("from", &self.from)
            .field("to", &self.to)
            .finish()
    }
}

/// Webhook channel config. The URL can carry a token, and header values can carry an
/// auth secret, so `Debug` prints neither.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &REDACTED)
            .field("headers", &REDACTED)
            .finish()
    }
}

/// A channel as returned by the API. It has no `config` field, by construction.
#[derive(Debug, Clone, Serialize)]
pub struct Channel {
    pub id: String,
    pub kind: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<ChannelRow> for Channel {
    type Error = AppError;

    fn try_from(row: ChannelRow) -> Result<Self, AppError> {
        Ok(Self {
            created_at: time::rfc3339(row.created_at)?,
            updated_at: time::rfc3339(row.updated_at)?,
            id: row.id,
            kind: row.kind,
            enabled: row.enabled,
        })
    }
}

/// Query values for `GET /api/v1/admin/alert-channels`.
#[derive(Debug, Default)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

fn invalid(message: &str) -> AppError {
    AppError::ValidationFailed(message.to_owned())
}

/// A parsed and validated config, ready to encrypt.
enum Config {
    Smtp(SmtpConfig),
    Webhook(WebhookConfig),
}

impl Config {
    /// Parses `raw` as the config for `kind` and validates it. Every failure is a `422`
    /// with fixed text, because the parser's own messages could repeat a submitted value.
    fn parse(kind: &str, raw: serde_json::Value, allow_private: bool) -> Result<Self, AppError> {
        match kind {
            "smtp" => {
                let config: SmtpConfig = serde_json::from_value(raw).map_err(|_| {
                    invalid(
                        "The SMTP config needs host, port, tls (implicit or starttls), from and to.",
                    )
                })?;
                validate_smtp(&config)?;
                Ok(Self::Smtp(config))
            }
            "webhook" => {
                let config: WebhookConfig = serde_json::from_value(raw)
                    .map_err(|_| invalid("The webhook config needs a url and optional headers."))?;
                validate_webhook(&config, allow_private)?;
                Ok(Self::Webhook(config))
            }
            _ => Err(invalid("The kind must be smtp or webhook.")),
        }
    }

    /// The config as JSON bytes, zeroed on drop.
    fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let bytes = match self {
            Self::Smtp(config) => serde_json::to_vec(config),
            Self::Webhook(config) => serde_json::to_vec(config),
        };
        bytes
            .map(Zeroizing::new)
            .map_err(|_| AppError::InternalError)
    }
}

fn validate_smtp(config: &SmtpConfig) -> Result<(), AppError> {
    if config.host.trim().is_empty() {
        return Err(invalid("The SMTP host must not be empty."));
    }
    if config.port == 0 {
        return Err(invalid("The SMTP port must be between 1 and 65535."));
    }
    if !is_address(&config.from) {
        return Err(invalid("The from address must contain @."));
    }
    if config.to.is_empty() {
        return Err(invalid("At least one to address is required."));
    }
    if !config.to.iter().all(|address| is_address(address)) {
        return Err(invalid("Every to address must contain @."));
    }
    Ok(())
}

/// A deliberately light check: something on both sides of one `@`, no whitespace.
fn is_address(value: &str) -> bool {
    match value.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.is_empty()
                && !domain.contains('@')
                && !value.chars().any(char::is_whitespace)
        }
        None => false,
    }
}

fn validate_webhook(config: &WebhookConfig, allow_private: bool) -> Result<(), AppError> {
    let url = reqwest::Url::parse(&config.url)
        .map_err(|_| invalid("The webhook URL must be a valid https:// URL."))?;
    if url.host_str().is_none() {
        return Err(invalid("The webhook URL must be a valid https:// URL."));
    }
    outbound::check_target(&url, TargetClass::Alerts, allow_private).map_err(|_| {
        invalid("The webhook URL must be https:// and must not point to a private address.")
    })?;
    for (name, value) in &config.headers {
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("A webhook header name is not valid."))?;
        HeaderValue::from_str(value)
            .map_err(|_| invalid("A webhook header value is not valid."))?;
    }
    Ok(())
}

/// The AAD that binds a config ciphertext to its row.
fn config_aad(id: &str) -> String {
    crypto::aad("alert_channels", "config_encrypted", id)
}

fn seal(key: &DerivedKey, id: &str, config: &Config) -> Result<String, AppError> {
    let json = config.to_json()?;
    crypto::encrypt(key, &config_aad(id), &json)
}

/// Creates a channel. Returns `422` for an invalid kind or config. The row and the
/// `alert.config_change` audit row commit together.
pub async fn create(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    actor: &Actor,
    allow_private: bool,
    kind: &str,
    enabled: bool,
    config: serde_json::Value,
) -> Result<Channel, AppError> {
    let config = Config::parse(kind, config, allow_private)?;
    let id = ids::new_id()?;
    let sealed = seal(credentials_key, &id, &config)?;

    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    rows::insert(&mut tx, &id, kind, &sealed, enabled).await?;
    record_change(&mut tx, actor, &id, kind, &["kind", "enabled", "config"]).await?;
    let row = rows::find(&mut tx, &id)
        .await?
        .ok_or(AppError::InternalError)?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Channel::try_from(row)
}

/// Updates a channel. `config`, when given, replaces the stored config. Without it only
/// `enabled` changes. A missing channel is `404`. Nothing is written when nothing changed.
pub async fn update(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    actor: &Actor,
    allow_private: bool,
    id: &str,
    enabled: Option<bool>,
    config: Option<serde_json::Value>,
) -> Result<Channel, AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let current = rows::find(&mut tx, id).await?.ok_or(AppError::NotFound)?;

    let mut fields: Vec<&str> = Vec::new();
    let new_enabled = enabled.unwrap_or(current.enabled);
    if new_enabled != current.enabled {
        fields.push("enabled");
    }
    let sealed = match config {
        Some(raw) => {
            let parsed = Config::parse(&current.kind, raw, allow_private)?;
            fields.push("config");
            Some(seal(credentials_key, id, &parsed)?)
        }
        None => None,
    };

    if fields.is_empty() {
        return Channel::try_from(current);
    }
    if !rows::update(&mut tx, id, new_enabled, sealed.as_deref()).await? {
        return Err(AppError::NotFound);
    }
    record_change(&mut tx, actor, id, &current.kind, &fields).await?;
    let row = rows::find(&mut tx, id)
        .await?
        .ok_or(AppError::InternalError)?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Channel::try_from(row)
}

/// Writes `alert.config_change` with the channel id, its kind, and the names of the
/// changed fields. No value from the config is ever written.
async fn record_change(
    conn: &mut sqlx::SqliteConnection,
    actor: &Actor,
    id: &str,
    kind: &str,
    fields: &[&str],
) -> Result<(), AppError> {
    audit::record(
        conn,
        actor,
        "alert.config_change",
        &format!("alert_channel:{id}"),
        Some(&serde_json::json!({ "channel_id": id, "kind": kind, "fields": fields })),
    )
    .await
}

/// One page of channels, oldest or newest first by `created_at`.
pub async fn list(pool: &SqlitePool, query: &ListQuery) -> Result<Page<Channel>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        &["created_at"],
    )?;
    let sign = if paging.ascending { 1 } else { -1 };
    let total = rows::count(pool).await?;
    let items = rows::list(pool, sign, paging.page_size, paging.offset())
        .await?
        .into_iter()
        .map(Channel::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_encryption_key;
    use serde_json::json;

    // Test values only. Every secret below is obviously fake.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const FAKE_URL: &str = "https://hooks.example.test/services/FAKE_URL_TOKEN_1";
    const FAKE_HEADER: &str = "Bearer FAKE_HEADER_SECRET_1";
    const FAKE_PASSWORD: &str = "FAKE_SMTP_PASSWORD_1";

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "harborgate-alert-channels-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        // The audit row has a foreign key to its actor.
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, "admin-1", "test-admin", None, "h", "admin")
            .await
            .unwrap();
        drop(conn);
        (pool, dir)
    }

    fn key() -> DerivedKey {
        crypto::credentials_key(&parse_encryption_key(TEST_KEY_B64).unwrap()).unwrap()
    }

    fn actor() -> Actor {
        Actor {
            user_id: Some("admin-1".to_owned()),
            username: "test-admin".to_owned(),
        }
    }

    fn webhook_config() -> serde_json::Value {
        json!({"url": FAKE_URL, "headers": {"Authorization": FAKE_HEADER}})
    }

    fn smtp_config() -> serde_json::Value {
        json!({
            "host": "smtp.example.test", "port": 465, "tls": "implicit",
            "username": "mailer", "password": FAKE_PASSWORD,
            "from": "harborgate@example.test", "to": ["ops@example.test"]
        })
    }

    async fn make(
        pool: &SqlitePool,
        kind: &str,
        config: serde_json::Value,
    ) -> Result<Channel, AppError> {
        create(pool, &key(), &actor(), false, kind, true, config).await
    }

    async fn stored(pool: &SqlitePool, id: &str) -> String {
        let mut conn = pool.acquire().await.unwrap();
        rows::find(&mut conn, id)
            .await
            .unwrap()
            .unwrap()
            .config_encrypted
    }

    async fn channel_count(pool: &SqlitePool) -> i64 {
        rows::count(pool).await.unwrap()
    }

    #[tokio::test]
    async fn config_is_encrypted_and_bound_to_its_row() {
        let (pool, dir) = fresh_pool("encrypted").await;
        let first = make(&pool, "webhook", webhook_config()).await.unwrap();
        let second = make(&pool, "webhook", webhook_config()).await.unwrap();

        let ciphertext = stored(&pool, &first.id).await;
        assert!(ciphertext.starts_with("v1:"), "not a v1 ciphertext");
        assert!(!ciphertext.contains("FAKE_URL_TOKEN_1"));
        assert!(!ciphertext.contains("FAKE_HEADER_SECRET_1"));

        let plain = crypto::decrypt(&key(), &config_aad(&first.id), &ciphertext).unwrap();
        let text = String::from_utf8(plain.to_vec()).unwrap();
        assert!(text.contains(FAKE_URL), "decrypted config lost the url");

        // The same ciphertext does not open under another row's AAD.
        let moved = crypto::decrypt(&key(), &config_aad(&second.id), &ciphertext);
        assert!(moved.is_err(), "ciphertext opened under another row id");
        // And the two rows hold different ciphertexts for the same config.
        assert_ne!(ciphertext, stored(&pool, &second.id).await);

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn responses_never_carry_config() {
        let (pool, dir) = fresh_pool("responses").await;
        let hook = make(&pool, "webhook", webhook_config()).await.unwrap();
        let mail = make(&pool, "smtp", smtp_config()).await.unwrap();
        let updated = update(
            &pool,
            &key(),
            &actor(),
            false,
            &hook.id,
            Some(false),
            Some(webhook_config()),
        )
        .await
        .unwrap();
        let page = list(&pool, &ListQuery::default()).await.unwrap();

        let mut bodies = vec![
            serde_json::to_value(&hook).unwrap(),
            serde_json::to_value(&mail).unwrap(),
            serde_json::to_value(&updated).unwrap(),
        ];
        bodies.push(serde_json::to_value(&page).unwrap());
        for body in &bodies {
            let text = body.to_string();
            for secret in [
                "FAKE_URL_TOKEN_1",
                "FAKE_HEADER_SECRET_1",
                FAKE_PASSWORD,
                "hooks.example.test",
                "smtp.example.test",
                "\"config\"",
                "config_encrypted",
                "v1:",
            ] {
                assert!(
                    !text.contains(secret),
                    "a secret leaked into a response body"
                );
            }
        }
        let keys: Vec<&str> = bodies[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["created_at", "enabled", "id", "kind", "updated_at"],
            "unexpected response fields"
        );
        assert_eq!(page.total, 2);

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn plain_http_webhook_is_422() {
        let (pool, dir) = fresh_pool("plain-http").await;
        let plain = make(
            &pool,
            "webhook",
            json!({"url": "http://hooks.example.test/x"}),
        )
        .await;
        assert!(matches!(plain, Err(AppError::ValidationFailed(_))));
        // A private IP literal fails the outbound target check unless the opt-out is set.
        let private = make(&pool, "webhook", json!({"url": "https://127.0.0.1/hook"})).await;
        assert!(matches!(private, Err(AppError::ValidationFailed(_))));
        let bad_header = make(
            &pool,
            "webhook",
            json!({"url": FAKE_URL, "headers": {"bad name": "x"}}),
        )
        .await;
        assert!(matches!(bad_header, Err(AppError::ValidationFailed(_))));
        assert_eq!(
            channel_count(&pool).await,
            0,
            "a rejected channel was saved"
        );

        // The opt-out allows the private literal, so the check above is the one that fired.
        let allowed = create(
            &pool,
            &key(),
            &actor(),
            true,
            "webhook",
            true,
            json!({"url": "https://127.0.0.1/hook"}),
        )
        .await;
        assert!(allowed.is_ok());

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn smtp_without_tls_mode_is_422() {
        let (pool, dir) = fresh_pool("no-tls").await;
        let mut missing = smtp_config();
        missing.as_object_mut().unwrap().remove("tls");
        let mut plaintext = smtp_config();
        plaintext["tls"] = json!("none");
        let mut port_zero = smtp_config();
        port_zero["port"] = json!(0);
        let mut port_big = smtp_config();
        port_big["port"] = json!(70000);
        let mut no_to = smtp_config();
        no_to["to"] = json!([]);
        let mut bad_from = smtp_config();
        bad_from["from"] = json!("not-an-address");
        let mut bad_to = smtp_config();
        bad_to["to"] = json!(["ops@example.test", "nope"]);

        for (label, config) in [
            ("missing tls", missing),
            ("plaintext tls", plaintext),
            ("port 0", port_zero),
            ("port 70000", port_big),
            ("empty to", no_to),
            ("bad from", bad_from),
            ("bad to", bad_to),
        ] {
            let result = make(&pool, "smtp", config).await;
            assert!(
                matches!(result, Err(AppError::ValidationFailed(_))),
                "{label} was accepted"
            );
        }
        assert_eq!(channel_count(&pool).await, 0);

        // Both real modes are accepted.
        assert!(make(&pool, "smtp", smtp_config()).await.is_ok());
        let mut starttls = smtp_config();
        starttls["tls"] = json!("starttls");
        starttls["port"] = json!(587);
        assert!(make(&pool, "smtp", starttls).await.is_ok());

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_redacts_password_and_headers() {
        let smtp: SmtpConfig = serde_json::from_value(smtp_config()).unwrap();
        let hook: WebhookConfig = serde_json::from_value(webhook_config()).unwrap();
        let out = format!("{smtp:?} {hook:?}");
        assert!(
            !out.contains(FAKE_PASSWORD),
            "the password leaked into Debug output"
        );
        assert!(
            !out.contains("FAKE_URL_TOKEN_1"),
            "the url token leaked into Debug output"
        );
        assert!(
            !out.contains("FAKE_HEADER_SECRET_1"),
            "a header value leaked into Debug output"
        );
        assert!(
            out.contains("smtp.example.test"),
            "the host is missing from Debug output"
        );
        assert!(
            out.contains("<redacted>"),
            "no redaction marker in Debug output"
        );
        let row = ChannelRow {
            id: "c1".to_owned(),
            kind: "webhook".to_owned(),
            config_encrypted: "v1:FAKE_CIPHERTEXT".to_owned(),
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };
        assert!(!format!("{row:?}").contains("FAKE_CIPHERTEXT"));
    }

    #[tokio::test]
    async fn changes_are_audited_without_values() {
        let (pool, dir) = fresh_pool("audit").await;
        let hook = make(&pool, "webhook", webhook_config()).await.unwrap();
        let first = stored(&pool, &hook.id).await;

        // Only `enabled` changes: the stored config is untouched.
        update(&pool, &key(), &actor(), false, &hook.id, Some(false), None)
            .await
            .unwrap();
        assert_eq!(stored(&pool, &hook.id).await, first);
        // A config replacement changes the ciphertext.
        update(
            &pool,
            &key(),
            &actor(),
            false,
            &hook.id,
            None,
            Some(webhook_config()),
        )
        .await
        .unwrap();
        assert_ne!(stored(&pool, &hook.id).await, first);
        // Nothing changed: no write and no audit row.
        update(&pool, &key(), &actor(), false, &hook.id, Some(false), None)
            .await
            .unwrap();
        // An unknown channel is a 404.
        let missing = update(&pool, &key(), &actor(), false, "nope", Some(true), None).await;
        assert!(matches!(missing, Err(AppError::NotFound)));

        let audit_rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT action, target, details FROM audit_log ORDER BY created_at, rowid",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(audit_rows.len(), 3, "unexpected number of audit rows");
        let expected_fields = [
            vec!["kind", "enabled", "config"],
            vec!["enabled"],
            vec!["config"],
        ];
        for ((action, target, details), fields) in audit_rows.iter().zip(expected_fields) {
            assert_eq!(action, "alert.config_change");
            assert_eq!(target, &format!("alert_channel:{}", hook.id));
            let details = details.as_deref().unwrap();
            for secret in ["FAKE_URL_TOKEN_1", "FAKE_HEADER_SECRET_1", "hooks.example"] {
                assert!(
                    !details.contains(secret),
                    "a secret leaked into the audit details"
                );
            }
            let value: serde_json::Value = serde_json::from_str(details).unwrap();
            assert_eq!(value["channel_id"], hook.id.as_str());
            assert_eq!(value["kind"], "webhook");
            assert_eq!(value["fields"], json!(fields));
        }

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
