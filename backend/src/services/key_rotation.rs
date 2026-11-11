//! Offline key rotation: re-encrypts every stored ciphertext from the credential key
//! derived from `DOCKWARD_OLD_ENCRYPTION_KEY` to the one derived from
//! `DOCKWARD_ENCRYPTION_KEY`. See `specs/security.md` (Key rotation).
//!
//! Every value keeps its AAD and stays in the `v1:` format. All rewrites and the
//! `key.rotate` audit row share one transaction, so any failure leaves the database
//! as it was. Nothing here prints or returns key material, plaintext, or ciphertext.

use sqlx::SqlitePool;

use crate::auth::crypto::{self, DerivedKey};
use crate::db::key_rotation::{self as rows, SealedValue};
use crate::error::AppError;
use crate::services::audit::{self, Actor};

/// One encrypted column. The AAD of each value is `<table>:<column>:<row id>`.
pub struct EncryptedColumn {
    pub table: &'static str,
    pub column: &'static str,
}

/// Every column that holds a `v1:` ciphertext. Keep this table in step with the
/// encrypt call sites; `every_encrypt_call_site_is_covered` fails when a new call
/// site is added without a row here (and a matching step in `rotate`).
///
/// The row id in the AAD: `user_credentials` and `alert_channels` use the row id;
/// `system_config` uses the key name and only rows with `is_encrypted = 1`.
pub const ENCRYPTED_COLUMNS: [EncryptedColumn; 4] = [
    EncryptedColumn {
        table: "user_credentials",
        column: "encrypted_token",
    },
    EncryptedColumn {
        table: "system_config",
        column: "value",
    },
    EncryptedColumn {
        table: "alert_channels",
        column: "config_encrypted",
    },
    EncryptedColumn {
        table: "source_credentials",
        column: "encrypted_token",
    },
];

/// Re-encrypts every stored ciphertext from `old` to `new` in one transaction and
/// appends the `key.rotate` audit row (actor `cli`, `{"rows": n}`). Returns `n`.
///
/// Refuses when both keys are the same. A value that does not open with `old` fails
/// the whole call and nothing is written.
pub async fn rotate(
    pool: &SqlitePool,
    old: &DerivedKey,
    new: &DerivedKey,
) -> Result<u64, AppError> {
    if constant_time_eq(old.as_bytes(), new.as_bytes()) {
        return Err(AppError::InvalidRequest(
            "The old and new encryption keys are the same.".to_owned(),
        ));
    }
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;

    let mut count: u64 = 0;
    // The order follows `ENCRYPTED_COLUMNS`.
    let [credentials, config, channels, source_tokens] = &ENCRYPTED_COLUMNS;

    for row in rows::list_credential_tokens(&mut tx).await? {
        let sealed = reseal(old, new, credentials, &row)?;
        expect_one(rows::set_credential_token(&mut tx, &row.id, &sealed).await?)?;
        count += 1;
    }
    for row in rows::list_encrypted_config(&mut tx).await? {
        let sealed = reseal(old, new, config, &row)?;
        expect_one(rows::set_config_value(&mut tx, &row.id, &sealed).await?)?;
        count += 1;
    }
    for row in rows::list_alert_configs(&mut tx).await? {
        let sealed = reseal(old, new, channels, &row)?;
        expect_one(rows::set_alert_config(&mut tx, &row.id, &sealed).await?)?;
        count += 1;
    }
    for row in rows::list_source_credential_tokens(&mut tx).await? {
        let sealed = reseal(old, new, source_tokens, &row)?;
        expect_one(rows::set_source_credential_token(&mut tx, &row.id, &sealed).await?)?;
        count += 1;
    }

    audit::record(
        &mut tx,
        &Actor::cli(),
        "key.rotate",
        "encryption_key",
        Some(&serde_json::json!({ "rows": count })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(count)
}

/// The `system_config` key that records the label migration as done.
pub const LABELS_MIGRATED_KEY: &str = "migration.dockward_labels";

/// Why the label migration did not finish. It names the row that failed and nothing else.
#[derive(Debug)]
pub struct LabelMigrationFailure {
    pub table: &'static str,
    pub column: &'static str,
    pub row_id: String,
}

/// Seals one row under `current` when it still opens only with the pre-rename key.
/// Returns `None` when the row already opens with `current`. A row that opens with
/// neither key is reported as a failure.
fn migrate_row(
    legacy: &DerivedKey,
    current: &DerivedKey,
    column: &EncryptedColumn,
    row: &SealedValue,
) -> Result<Option<String>, LabelMigrationFailure> {
    let aad = crypto::aad(column.table, column.column, &row.id);
    if crypto::decrypt_exact(current, &aad, &row.value).is_ok() {
        return Ok(None);
    }
    let failure = || LabelMigrationFailure {
        table: column.table,
        column: column.column,
        row_id: row.id.clone(),
    };
    let plain = crypto::decrypt_exact(legacy, &aad, &row.value).map_err(|_| failure())?;
    crypto::encrypt(current, &aad, &plain)
        .map(Some)
        .map_err(|_| failure())
}

/// One-time startup migration of decision 56: reseals every stored ciphertext that opens
/// only with the pre-rename credential key (`legacy`) under the new one (`current`),
/// under the same AAD. All rewrites, the audit row (`key.migrate_labels`, `{"rows": n}`)
/// and the completion record share one transaction. A later call returns `Ok(None)`.
///
/// A row that opens with neither key fails the whole migration, nothing is written, and
/// the error names the row (table, column, id; never a value). The dual-read fallback
/// keeps the app working until the row is fixed and the migration runs again.
pub async fn migrate_labels(
    pool: &SqlitePool,
    legacy: &DerivedKey,
    current: &DerivedKey,
) -> Result<Option<u64>, MigrateError> {
    if crate::db::config::exists(pool, LABELS_MIGRATED_KEY)
        .await
        .map_err(|_| MigrateError::Other)?
    {
        return Ok(None);
    }
    let mut tx = pool.begin().await.map_err(|_| MigrateError::Other)?;
    let mut count: u64 = 0;
    let [credentials, config, channels, source_tokens] = &ENCRYPTED_COLUMNS;

    for row in rows::list_credential_tokens(&mut tx).await? {
        if let Some(sealed) = migrate_row(legacy, current, credentials, &row)? {
            expect_one(rows::set_credential_token(&mut tx, &row.id, &sealed).await?)?;
            count += 1;
        }
    }
    for row in rows::list_encrypted_config(&mut tx).await? {
        if let Some(sealed) = migrate_row(legacy, current, config, &row)? {
            expect_one(rows::set_config_value(&mut tx, &row.id, &sealed).await?)?;
            count += 1;
        }
    }
    for row in rows::list_alert_configs(&mut tx).await? {
        if let Some(sealed) = migrate_row(legacy, current, channels, &row)? {
            expect_one(rows::set_alert_config(&mut tx, &row.id, &sealed).await?)?;
            count += 1;
        }
    }
    for row in rows::list_source_credential_tokens(&mut tx).await? {
        if let Some(sealed) = migrate_row(legacy, current, source_tokens, &row)? {
            expect_one(rows::set_source_credential_token(&mut tx, &row.id, &sealed).await?)?;
            count += 1;
        }
    }

    if count > 0 {
        audit::record(
            &mut tx,
            &Actor::system(),
            "key.migrate_labels",
            "encryption_key",
            Some(&serde_json::json!({ "rows": count })),
        )
        .await?;
    }
    crate::db::config::upsert(&mut tx, LABELS_MIGRATED_KEY, "done", false).await?;
    tx.commit().await.map_err(|_| MigrateError::Other)?;
    Ok(Some(count))
}

/// The ways [`migrate_labels`] can fail.
#[derive(Debug)]
pub enum MigrateError {
    /// A stored value opens with neither key.
    Row(LabelMigrationFailure),
    Other,
}

impl From<AppError> for MigrateError {
    fn from(err: AppError) -> Self {
        let _ = err;
        Self::Other
    }
}

impl From<LabelMigrationFailure> for MigrateError {
    fn from(failure: LabelMigrationFailure) -> Self {
        Self::Row(failure)
    }
}

/// Opens `row` with the old key and seals it again with the new key, under the same AAD.
fn reseal(
    old: &DerivedKey,
    new: &DerivedKey,
    column: &EncryptedColumn,
    row: &SealedValue,
) -> Result<String, AppError> {
    let aad = crypto::aad(column.table, column.column, &row.id);
    let plain = crypto::decrypt(old, &aad, &row.value)?;
    crypto::encrypt(new, &aad, &plain)
}

fn expect_one(changed: u64) -> Result<(), AppError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(AppError::InternalError)
    }
}

/// Compares two equal-length byte strings without an early exit on the first difference.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::config::parse_encryption_key;

    // Test values only. Every secret below is obviously fake. Key A is 32 zero bytes
    // and key B is 32 bytes of 0x01, both base64.
    const KEY_A_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const KEY_B_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    const CONFIG_KEY: &str = "oidc.client_secret_encrypted";
    // (table, column, row id, fake plaintext), in `rotate` order.
    const SEEDS: [(&str, &str, &str, &str); 6] = [
        (
            "user_credentials",
            "encrypted_token",
            "cred-1",
            "FAKE_HARBOR_SECRET_1",
        ),
        (
            "user_credentials",
            "encrypted_token",
            "cred-2",
            "FAKE_GITHUB_TOKEN_2",
        ),
        (
            "system_config",
            "value",
            CONFIG_KEY,
            "FAKE_OIDC_CLIENT_SECRET_3",
        ),
        (
            "alert_channels",
            "config_encrypted",
            "chan-1",
            "{\"url\":\"FAKE_WEBHOOK_URL_4\"}",
        ),
        (
            "alert_channels",
            "config_encrypted",
            "chan-2",
            "{\"url\":\"FAKE_WEBHOOK_URL_5\"}",
        ),
        (
            "source_credentials",
            "encrypted_token",
            "srccred-1",
            "FAKE_REGISTRY_TOKEN_6",
        ),
    ];

    fn derived(b64: &str) -> DerivedKey {
        crypto::credentials_key(&parse_encryption_key(b64).unwrap()).unwrap()
    }

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dockward-key-rotation-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A database with every kind of encrypted value, sealed under key A.
    async fn seeded(name: &str) -> (SqlitePool, PathBuf) {
        let dir = unique_dir(name);
        let pool = crate::db::open(&dir).await.unwrap();
        let key = derived(KEY_A_B64);
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, "user-1", "test-user", None, "h", "admin")
            .await
            .unwrap();
        drop(conn);
        for (table, column, id, plain) in SEEDS {
            if table == "source_credentials" {
                continue;
            }
            let sealed =
                crypto::encrypt(&key, &crypto::aad(table, column, id), plain.as_bytes()).unwrap();
            let query = match table {
                "user_credentials" => sqlx::query(
                    "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
                     VALUES (?, 'user-1', 'fake label', ?)",
                ),
                "system_config" => sqlx::query(
                    "INSERT INTO system_config (key, value, is_encrypted) VALUES (?, ?, 1)",
                ),
                _ => sqlx::query(
                    "INSERT INTO alert_channels (id, kind, config_encrypted, enabled)
                     VALUES (?, 'webhook', ?, 1)",
                ),
            };
            query.bind(id).bind(sealed).execute(&pool).await.unwrap();
        }
        // The source and its credential come last: the credential row references the source.
        sqlx::query(
            "INSERT INTO image_sources
                (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('src-1', 'user-1', 'hub-default-ghcr', 'team/app', '1.0', 'cred-2', 'o', 'r')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let (table, column, id, plain) = SEEDS[SEEDS.len() - 1];
        let sealed =
            crypto::encrypt(&key, &crypto::aad(table, column, id), plain.as_bytes()).unwrap();
        sqlx::query(
            "INSERT INTO source_credentials (id, source_id, username, encrypted_token)
             VALUES (?, 'src-1', 'robot', ?)",
        )
        .bind(id)
        .bind(sealed)
        .execute(&pool)
        .await
        .unwrap();
        // A plain setting that rotation must not touch.
        sqlx::query(
            "INSERT INTO system_config (key, value, is_encrypted) VALUES ('oidc.client_id', 'fake-client-id', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        (pool, dir)
    }

    /// Every stored value that rotation may touch, in a fixed order.
    async fn snapshot(pool: &SqlitePool) -> Vec<String> {
        let sql = "SELECT encrypted_token FROM user_credentials ORDER BY id";
        let mut all: Vec<String> = sqlx::query_scalar(sql).fetch_all(pool).await.unwrap();
        let sql = "SELECT value FROM system_config ORDER BY key";
        all.extend(
            sqlx::query_scalar::<_, String>(sql)
                .fetch_all(pool)
                .await
                .unwrap(),
        );
        let sql = "SELECT encrypted_token FROM source_credentials ORDER BY id";
        all.extend(
            sqlx::query_scalar::<_, String>(sql)
                .fetch_all(pool)
                .await
                .unwrap(),
        );
        let sql = "SELECT config_encrypted FROM alert_channels ORDER BY id";
        all.extend(
            sqlx::query_scalar::<_, String>(sql)
                .fetch_all(pool)
                .await
                .unwrap(),
        );
        all
    }

    async fn stored(pool: &SqlitePool, table: &str, id: &str) -> String {
        let sql = match table {
            "user_credentials" => "SELECT encrypted_token FROM user_credentials WHERE id = ?",
            "system_config" => "SELECT value FROM system_config WHERE key = ?",
            "source_credentials" => "SELECT encrypted_token FROM source_credentials WHERE id = ?",
            _ => "SELECT config_encrypted FROM alert_channels WHERE id = ?",
        };
        sqlx::query_scalar(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn rotation_audit_rows(pool: &SqlitePool) -> Vec<(String, Option<String>)> {
        sqlx::query_as("SELECT actor_username, details FROM audit_log WHERE action = 'key.rotate'")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn all_encrypted_columns_are_rewritten() {
        let (pool, dir) = seeded("rewritten").await;
        let (old, new) = (derived(KEY_A_B64), derived(KEY_B_B64));
        let before = snapshot(&pool).await;

        let rows = rotate(&pool, &old, &new).await.unwrap();
        assert_eq!(rows, 6, "wrong row count");

        for (table, column, id, plain) in SEEDS {
            let ciphertext = stored(&pool, table, id).await;
            let aad = crypto::aad(table, column, id);
            let opened = crypto::decrypt(&new, &aad, &ciphertext).unwrap();
            assert!(
                opened.as_slice() == plain.as_bytes(),
                "a value does not open with the new key under its own AAD"
            );
            assert!(
                crypto::decrypt(&old, &aad, &ciphertext).is_err(),
                "a value still opens with the old key"
            );
            assert!(ciphertext.starts_with("v1:"), "a value left the v1 format");
        }
        // The setting that is not encrypted is untouched.
        let plain_setting: String =
            sqlx::query_scalar("SELECT value FROM system_config WHERE key = 'oidc.client_id'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(plain_setting == "fake-client-id", "a plain setting changed");
        assert!(
            snapshot(&pool).await != before,
            "no stored value was rewritten"
        );

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    fn legacy_of(b64: &str) -> DerivedKey {
        crypto::legacy_credentials_key(&parse_encryption_key(b64).unwrap()).unwrap()
    }

    /// `seeded`, but with every value sealed under the pre-rename label.
    async fn seeded_legacy(name: &str) -> (SqlitePool, PathBuf) {
        let (pool, dir) = seeded(name).await;
        let (key, legacy) = (derived(KEY_A_B64), legacy_of(KEY_A_B64));
        for (table, column, id, _) in SEEDS {
            let aad = crypto::aad(table, column, id);
            let plain = crypto::decrypt(&key, &aad, &stored(&pool, table, id).await).unwrap();
            let sealed = crypto::encrypt(&legacy, &aad, &plain).unwrap();
            let sql = match table {
                "user_credentials" => {
                    "UPDATE user_credentials SET encrypted_token = ? WHERE id = ?"
                }
                "system_config" => "UPDATE system_config SET value = ? WHERE key = ?",
                "source_credentials" => {
                    "UPDATE source_credentials SET encrypted_token = ? WHERE id = ?"
                }
                _ => "UPDATE alert_channels SET config_encrypted = ? WHERE id = ?",
            };
            sqlx::query(sql)
                .bind(sealed)
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
        (pool, dir)
    }

    #[tokio::test]
    async fn label_migration_reseals_every_row_and_runs_once() {
        let (pool, dir) = seeded_legacy("labels").await;
        let (legacy, current) = (legacy_of(KEY_A_B64), derived(KEY_A_B64));
        // Before: every row opens only through the fallback.
        for (table, column, id, _) in SEEDS {
            let aad = crypto::aad(table, column, id);
            let value = stored(&pool, table, id).await;
            assert!(crypto::decrypt_exact(&current, &aad, &value).is_err());
            assert!(crypto::decrypt(&current, &aad, &value).is_ok());
        }

        let rows = migrate_labels(&pool, &legacy, &current).await.unwrap();
        assert_eq!(rows, Some(6), "wrong row count");
        for (table, column, id, plain) in SEEDS {
            let aad = crypto::aad(table, column, id);
            let value = stored(&pool, table, id).await;
            let opened = crypto::decrypt_exact(&current, &aad, &value).unwrap();
            assert!(opened.as_slice() == plain.as_bytes());
        }
        let audits: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT actor_username, details FROM audit_log WHERE action = 'key.migrate_labels'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(audits.len() == 1);
        assert!(audits[0].1.as_deref() == Some("{\"rows\":6}"));

        // A second run changes nothing.
        let after_first = snapshot(&pool).await;
        assert_eq!(
            migrate_labels(&pool, &legacy, &current).await.unwrap(),
            None
        );
        assert!(snapshot(&pool).await == after_first);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'key.migrate_labels'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn label_migration_reports_a_row_that_opens_with_neither_key() {
        let (pool, dir) = seeded_legacy("labels-bad").await;
        sqlx::query("UPDATE alert_channels SET config_encrypted = 'v1:AAAA' WHERE id = 'chan-2'")
            .execute(&pool)
            .await
            .unwrap();
        let before = snapshot(&pool).await;
        let result = migrate_labels(&pool, &legacy_of(KEY_A_B64), &derived(KEY_A_B64)).await;
        match result {
            Err(MigrateError::Row(failure)) => {
                assert_eq!(failure.table, "alert_channels");
                assert_eq!(failure.row_id, "chan-2");
            }
            _ => panic!("the bad row was not reported"),
        }
        assert!(snapshot(&pool).await == before, "a failed run wrote rows");
        // Not recorded as done, so the next start tries again.
        assert!(
            !crate::db::config::exists(&pool, LABELS_MIGRATED_KEY)
                .await
                .unwrap()
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn label_migration_on_a_new_database_records_done_without_audit() {
        let dir = unique_dir("labels-empty");
        let pool = crate::db::open(&dir).await.unwrap();
        let rows = migrate_labels(&pool, &legacy_of(KEY_A_B64), &derived(KEY_A_B64)).await;
        assert_eq!(rows.unwrap(), Some(0));
        assert_eq!(
            migrate_labels(&pool, &legacy_of(KEY_A_B64), &derived(KEY_A_B64))
                .await
                .unwrap(),
            None
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn one_bad_row_rolls_back_everything() {
        let (pool, dir) = seeded("rollback").await;
        // The last channel is processed after every other row has been rewritten in the
        // transaction, so this proves the earlier rewrites are undone.
        sqlx::query("UPDATE alert_channels SET config_encrypted = 'v1:AAAA' WHERE id = 'chan-2'")
            .execute(&pool)
            .await
            .unwrap();
        let before = snapshot(&pool).await;

        let result = rotate(&pool, &derived(KEY_A_B64), &derived(KEY_B_B64)).await;
        assert!(result.is_err(), "a corrupted row did not stop the rotation");

        assert!(
            snapshot(&pool).await == before,
            "a stored value changed after a failed rotation"
        );
        assert!(
            rotation_audit_rows(&pool).await.is_empty(),
            "a failed rotation left an audit row"
        );

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn same_key_is_refused() {
        let (pool, dir) = seeded("same-key").await;
        let before = snapshot(&pool).await;

        // Two separately derived keys with the same value.
        let result = rotate(&pool, &derived(KEY_A_B64), &derived(KEY_A_B64)).await;
        assert!(
            matches!(result, Err(AppError::InvalidRequest(_))),
            "equal keys were not refused"
        );
        assert!(
            snapshot(&pool).await == before,
            "a stored value changed when the keys were equal"
        );
        assert!(
            rotation_audit_rows(&pool).await.is_empty(),
            "a refused rotation left an audit row"
        );

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rotation_is_audited_with_count_only() {
        let (pool, dir) = seeded("audit").await;
        rotate(&pool, &derived(KEY_A_B64), &derived(KEY_B_B64))
            .await
            .unwrap();

        let audit_rows = rotation_audit_rows(&pool).await;
        assert!(audit_rows.len() == 1, "expected exactly one key.rotate row");
        let (actor, details) = &audit_rows[0];
        assert!(actor == "cli", "the actor is not cli");
        let details = details.clone().unwrap_or_default();
        let parsed: serde_json::Value = serde_json::from_str(&details).unwrap();
        assert!(
            parsed == serde_json::json!({ "rows": 6 }),
            "details hold more than the row count"
        );

        // Nothing in the audit table carries key material, a secret, or a ciphertext.
        let everything: Vec<String> = sqlx::query_scalar(
            "SELECT COALESCE(actor_username, '') || target || COALESCE(details, '') FROM audit_log",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let joined = everything.join("\n");
        for needle in [KEY_A_B64, KEY_B_B64, "FAKE_", "v1:"] {
            assert!(!joined.contains(needle), "the audit log leaks a value");
        }

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Source text before the first top-level `#[cfg(test)]` item (a test module or a
    /// test-support module), so test helpers do not count.
    fn non_test_part(text: &str) -> &str {
        let end = if text.starts_with("#[cfg(test)]\n") {
            Some(0)
        } else {
            text.find("\n#[cfg(test)]\n")
        };
        end.map_or(text, |end| &text[..end])
    }

    fn count_call_sites(dir: &Path, own: &Path) -> usize {
        let needle = ["crypto", "::encrypt("].concat();
        let mut total = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                total += count_call_sites(&path, own);
            } else if path.extension().is_some_and(|ext| ext == "rs") && path != own {
                let text = std::fs::read_to_string(&path).unwrap();
                total += non_test_part(&text)
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .map(|line| line.matches(needle.as_str()).count())
                    .sum::<usize>();
            }
        }
        total
    }

    #[test]
    fn every_encrypt_call_site_is_covered() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // This file re-encrypts what the other sites wrote. It is not a new site.
        let own = src.join("services").join("key_rotation.rs");
        let sites = count_call_sites(&src, &own);
        assert!(
            sites == ENCRYPTED_COLUMNS.len(),
            "the number of encrypt call sites differs from ENCRYPTED_COLUMNS; \
             add the new column to ENCRYPTED_COLUMNS and to rotate"
        );
    }
}
