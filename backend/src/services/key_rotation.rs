//! Offline key rotation: re-encrypts every stored ciphertext from the credential key
//! derived from `HARBORGATE_OLD_ENCRYPTION_KEY` to the one derived from
//! `HARBORGATE_ENCRYPTION_KEY`. See `specs/security.md` (Key rotation).
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
            "harborgate-key-rotation-{name}-{}",
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
