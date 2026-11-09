//! Encrypted backups. The database is copied with `VACUUM INTO`, sealed with the
//! derived backup key, and written to `HARBORGATE_BACKUP_DIR`. The file format and
//! the rules are in `specs/security.md` (Backup and restore) and `specs/api.md`
//! (`POST /admin/backup`).
//!
//! File format: `HGBK1` (5 ASCII bytes) || nonce (12) || ciphertext || tag (16).
//! The header is the GCM additional authenticated data, so a changed header fails
//! verification.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, Generate, KeyInit, Nonce, Payload},
};
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::auth::crypto::DerivedKey;
use crate::db;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::ids;
use crate::services::time::rfc3339;

/// The plain header that identifies the backup format.
pub const MAGIC: &[u8; 5] = b"HGBK1";

const MAGIC_LEN: usize = 5;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Returned for any backup file that is malformed or does not verify. The message
/// is safe to show and names no key or internal detail.
fn not_verified() -> AppError {
    AppError::ValidationFailed("The backup file failed verification.".to_owned())
}

/// Encrypts `plain` and returns `MAGIC || nonce || ciphertext || tag`. The nonce is
/// fresh and random for every call.
pub fn seal(key: &DerivedKey, plain: &[u8]) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| AppError::InternalError)?;
    // A fresh 12-byte nonce from the OS CSPRNG for every call.
    let nonce = Nonce::<Aes256Gcm>::try_generate().map_err(|_| AppError::InternalError)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plain,
                aad: MAGIC.as_slice(),
            },
        )
        .map_err(|_| AppError::InternalError)?;

    let mut file = Vec::with_capacity(MAGIC_LEN + NONCE_LEN + ciphertext.len());
    file.extend_from_slice(MAGIC.as_slice());
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);
    Ok(file)
}

/// Checks the magic and the GCM tag, then returns the plaintext. Nothing is returned
/// unless both pass. The result is zeroed on drop.
#[allow(dead_code)] // Used by the offline restore command (#58).
pub fn open(key: &DerivedKey, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if file.len() < MAGIC_LEN + NONCE_LEN + TAG_LEN || !file.starts_with(MAGIC.as_slice()) {
        return Err(not_verified());
    }
    let (magic, rest) = file.split_at(MAGIC_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
    let nonce: &Nonce<Aes256Gcm> = nonce_bytes.try_into().map_err(|_| not_verified())?;

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| AppError::InternalError)?;
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: magic,
            },
        )
        .map_err(|_| not_verified())?;
    Ok(Zeroizing::new(plain))
}

/// The backup file name for `now`: `harborgate-<yyyymmddThhmmssZ>.hgbk` (UTC). The
/// name matches `^[A-Za-z0-9._-]+$` and has no path separator.
pub fn file_name_for(now: i64) -> Result<String, AppError> {
    let stamp = rfc3339(now)?.replace(['-', ':'], "");
    Ok(format!("harborgate-{stamp}.hgbk"))
}

/// Creates an encrypted backup in `backup_dir` and returns its file name.
///
/// Fails with `BackupDirUnavailable` when `backup_dir` is missing or not writable.
/// No fallback location is tried. The temporary copy in `data_dir` is removed on
/// every path, including errors. The backup file is created new and is never
/// overwritten.
pub async fn create(
    pool: &SqlitePool,
    key: &DerivedKey,
    data_dir: &Path,
    backup_dir: &Path,
    now: i64,
) -> Result<String, AppError> {
    check_backup_dir(backup_dir)?;
    let file_name = file_name_for(now)?;
    let temp_path = data_dir.join(format!("backup-{}.tmp", ids::new_id()?));

    let result = write_backup(pool, key, &temp_path, backup_dir, &file_name).await;
    // The temporary copy holds the whole database in plain text. Remove it on every
    // path. A missing file here is not an error.
    let _ = std::fs::remove_file(&temp_path);
    result.map(|()| file_name)
}

/// Writes the `backup.run` audit row for a backup that was just created. It commits
/// in its own transaction. The caller fails the request if this returns an error.
pub async fn record_run(pool: &SqlitePool, actor: &Actor, file: &str) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    audit::record(
        &mut tx,
        actor,
        "backup.run",
        &format!("backup:{file}"),
        Some(&serde_json::json!({"file": file})),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)
}

/// Copies, seals, and writes the backup. The caller removes `temp_path`.
async fn write_backup(
    pool: &SqlitePool,
    key: &DerivedKey,
    temp_path: &Path,
    backup_dir: &Path,
    file_name: &str,
) -> Result<(), AppError> {
    let temp_text = safe_path_text(temp_path)?;
    db::backup::vacuum_into(pool, &temp_text).await?;

    let plain = Zeroizing::new(std::fs::read(temp_path).map_err(|_| {
        tracing::error!("could not read the temporary backup copy");
        AppError::InternalError
    })?);
    let sealed = seal(key, &plain)?;
    drop(plain);

    let target = backup_dir.join(file_name);
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|_| {
            tracing::error!("could not create the backup file; it may already exist");
            AppError::InternalError
        })?;
    let written = out.write_all(&sealed).and_then(|()| out.sync_all());
    if written.is_err() {
        // This call created the file, so it removes the partial file. Never leave a
        // truncated backup behind.
        drop(out);
        let _ = std::fs::remove_file(&target);
        tracing::error!("could not write the backup file");
        return Err(AppError::InternalError);
    }
    Ok(())
}

/// Confirms `dir` exists and accepts a new file. The probe file is removed at once.
fn check_backup_dir(dir: &Path) -> Result<(), AppError> {
    let probe = dir.join(format!(".write-check-{}", ids::new_id()?));
    let writable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .is_ok();
    if writable {
        let _ = std::fs::remove_file(&probe);
        return Ok(());
    }
    tracing::error!(
        backup_dir = %dir.display(),
        "the backup directory is missing or not writable"
    );
    Err(AppError::BackupDirUnavailable)
}

/// The path as text for the `VACUUM INTO` statement. Only ASCII letters, digits,
/// `.`, `_`, `-`, and `/` are allowed, so no quote can reach the SQL.
fn safe_path_text(path: &Path) -> Result<String, AppError> {
    let text = path.to_str().ok_or(AppError::InternalError)?;
    let safe = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'));
    if !safe {
        tracing::error!("the data directory path has characters a backup cannot use");
        return Err(AppError::InternalError);
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_encryption_key;
    use sqlx::sqlite::SqlitePoolOptions;

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// Fixed instant: 2001-09-09T01:46:40Z.
    const NOW: i64 = 1_000_000_000;

    fn key() -> DerivedKey {
        let root = match parse_encryption_key(TEST_KEY_B64) {
            Ok(k) => k,
            Err(_) => panic!("test key must parse"),
        };
        match crate::auth::crypto::backup_key(&root) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        }
    }

    fn unique_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("harborgate-backup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn add_user(pool: &SqlitePool, id: &str, username: &str) {
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, id, username, None, "test-hash", "user")
            .await
            .unwrap();
    }

    #[test]
    fn each_seal_draws_a_fresh_nonce() {
        let key = key();
        let first = seal(&key, b"same").unwrap_or_default();
        let second = seal(&key, b"same").unwrap_or_default();
        // The nonce follows the 5-byte magic and is 12 bytes long.
        let nonce_range = MAGIC_LEN..MAGIC_LEN + NONCE_LEN;
        assert_eq!(
            first.get(nonce_range.clone()).map(<[u8]>::len),
            Some(NONCE_LEN)
        );
        assert_ne!(
            first.get(nonce_range.clone()),
            second.get(nonce_range),
            "two seals reused a nonce"
        );
    }

    #[test]
    fn seal_open_round_trip() {
        let key = key();
        let file = seal(&key, b"database bytes").unwrap();
        assert!(file.starts_with(MAGIC));
        let plain = open(&key, &file).unwrap();
        assert_eq!(plain.as_slice(), b"database bytes");
    }

    #[test]
    fn changed_magic_fails() {
        let key = key();
        let mut file = seal(&key, b"database bytes").unwrap();
        file[4] = b'2';
        assert!(open(&key, &file).is_err(), "a changed header was accepted");
    }

    #[test]
    fn tampered_byte_fails() {
        let key = key();
        let mut file = seal(&key, b"database bytes").unwrap();
        let middle = file.len() / 2;
        file[middle] ^= 0x01;
        assert!(open(&key, &file).is_err(), "a tampered byte was accepted");
    }

    /// A backup sealed under one key must not open under another. The key below
    /// derives from a different root (all 0x01 bytes, base64 `AQEB...`). The same
    /// derivation runs, so only the root differs. Test values only.
    #[test]
    fn wrong_key_fails() {
        const OTHER_KEY_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let sealing_key = key();
        let other_root = match parse_encryption_key(OTHER_KEY_B64) {
            Ok(k) => k,
            Err(_) => panic!("other test key must parse"),
        };
        let opening_key = match crate::auth::crypto::backup_key(&other_root) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        };
        let file = seal(&sealing_key, b"database bytes").unwrap();

        let result = open(&opening_key, &file);
        assert!(result.is_err(), "a backup opened under the wrong key");
        // `open` returns no plaintext on failure. The error carries no bytes.
        assert_eq!(result.err(), Some(not_verified()));
    }

    #[tokio::test]
    async fn backup_is_a_consistent_database() {
        let data = unique_dir("consistent-data");
        let backups = unique_dir("consistent-backups");
        let pool = db::open(&data).await.unwrap();
        add_user(&pool, "user-a", "alice").await;
        add_user(&pool, "user-b", "bob").await;

        let name = create(&pool, &key(), &data, &backups, NOW).await.unwrap();
        let sealed = std::fs::read(backups.join(&name)).unwrap();
        let plain = open(&key(), &sealed).unwrap();

        // Open the decrypted bytes as a SQLite database and count the users.
        let restored = unique_dir("consistent-restored");
        let restored_path = restored.join(db::DB_FILE_NAME);
        std::fs::write(&restored_path, plain.as_slice()).unwrap();
        let restored_pool = SqlitePoolOptions::new()
            .connect_with(db::connect_options(&restored_path))
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&restored_pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn missing_backup_dir_fails_without_fallback() {
        let data = unique_dir("missing-data");
        let pool = db::open(&data).await.unwrap();
        let missing = data.join("no-such-backup-dir");

        let result = create(&pool, &key(), &data, &missing, NOW).await;
        assert_eq!(result, Err(AppError::BackupDirUnavailable));
        assert!(!missing.exists(), "the missing directory was created");

        // No backup or temporary file was written anywhere under the data directory.
        let stray: Vec<_> = std::fs::read_dir(&data)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".hgbk") || n.starts_with("backup-"))
            .collect();
        assert!(stray.is_empty(), "stray backup files: {stray:?}");
    }

    #[tokio::test]
    async fn backup_succeeds_after_a_fresh_start_creates_the_directory() {
        let data = unique_dir("fresh-data");
        let pool = db::open(&data).await.unwrap();
        let backups = data.join("backups");
        assert!(!backups.exists());

        crate::config::prepare_backup_dir(&backups).unwrap();
        let name = create(&pool, &key(), &data, &backups, NOW).await.unwrap();
        assert!(backups.join(name).is_file());
    }

    #[tokio::test]
    async fn temp_file_is_removed_on_error() {
        let data = unique_dir("temp-data");
        let backups = unique_dir("temp-backups");
        let pool = db::open(&data).await.unwrap();
        add_user(&pool, "user-a", "alice").await;

        // A file already holds the name the backup would take, so creating the
        // backup fails after the temporary copy exists. The existing file must
        // survive untouched.
        let taken = backups.join("harborgate-20010909T014640Z.hgbk");
        std::fs::write(&taken, b"existing").unwrap();

        let result = create(&pool, &key(), &data, &backups, NOW).await;
        assert!(result.is_err(), "a name collision was not an error");

        let leftovers: Vec<_> = std::fs::read_dir(&data)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("backup-") && n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary copies left: {leftovers:?}");
        assert_eq!(std::fs::read(&taken).unwrap(), b"existing");
    }

    /// An `HGBK1` file recorded with the aes-gcm 0.10 build, as lowercase hex. The backup
    /// key is derived from the all-zero test root. The nonce is 0x2b repeated 12 times,
    /// and the plaintext is `database bytes`. Test values only.
    const KAT_HGBK1_HEX: &str = "4847424b312b2b2b2b2b2b2b2b2b2b2b2bb94ab0bc2c33bec3bcaf58cf15178f96bbc433e09b036161efdff639e857";

    fn hex_decode(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .filter_map(|i| text.get(i..i + 2))
            .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
            .collect()
    }

    #[test]
    fn hgbk1_file_from_the_old_build_still_restores() {
        let file = hex_decode(KAT_HGBK1_HEX);
        assert!(file.starts_with(MAGIC), "the recorded file lost its header");
        let plain = open(&key(), &file);
        assert!(
            matches!(plain, Ok(ref p) if p.as_slice() == b"database bytes"),
            "an HGBK1 file recorded with the old build no longer opens"
        );
    }

    #[test]
    fn file_name_matches_the_safe_pattern() {
        let name = file_name_for(NOW).unwrap();
        assert_eq!(name, "harborgate-20010909T014640Z.hgbk");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
            "unsafe character in {name}"
        );
        assert!(!name.contains('/'));
    }
}
