//! Key derivation and AES-256-GCM encryption for stored secrets.
//!
//! The raw `HARBORGATE_ENCRYPTION_KEY` is input key material only. Every key used
//! to encrypt or sign is derived from it with HKDF-SHA256 under a distinct label.
//! See `specs/security.md` (Encryption and keys, Derived keys).

use aes_gcm::{
    AeadCore, Aes256Gcm, Key,
    aead::{Aead, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::config::EncryptionKey;
use crate::error::AppError;

/// Ciphertext prefix for format version 1.
pub const V1_PREFIX: &str = "v1:";

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

const LABEL_CREDENTIALS: &[u8] = b"harborgate/credentials-v1";
const LABEL_SESSION: &[u8] = b"harborgate/session-v1";
const LABEL_BACKUP: &[u8] = b"harborgate/backup-v1";
const LABEL_CSRF: &[u8] = b"harborgate/csrf-v1";

/// A 32-byte derived key. It is zeroed on drop.
pub struct DerivedKey(Zeroizing<[u8; KEY_LEN]>);

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Derives a 32-byte key from the encryption key with HKDF-SHA256 (no salt) and the given label.
pub fn derive_key(root: &EncryptionKey, label: &[u8]) -> Result<DerivedKey, AppError> {
    let hk = Hkdf::<Sha256>::new(None, root.as_bytes());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(label, out.as_mut_slice())
        .map_err(|_| AppError::InternalError)?;
    Ok(DerivedKey(out))
}

/// The credential key used for every stored ciphertext.
pub fn credentials_key(root: &EncryptionKey) -> Result<DerivedKey, AppError> {
    derive_key(root, LABEL_CREDENTIALS)
}

/// The session signing key.
pub fn session_key(root: &EncryptionKey) -> Result<DerivedKey, AppError> {
    derive_key(root, LABEL_SESSION)
}

/// The backup encryption key.
pub fn backup_key(root: &EncryptionKey) -> Result<DerivedKey, AppError> {
    derive_key(root, LABEL_BACKUP)
}

/// The CSRF signing key.
pub fn csrf_key(root: &EncryptionKey) -> Result<DerivedKey, AppError> {
    derive_key(root, LABEL_CSRF)
}

/// Builds the AAD `<table>:<column>:<row id>` that binds a ciphertext to its row.
pub fn aad(table: &str, column: &str, row_id: &str) -> String {
    format!("{table}:{column}:{row_id}")
}

/// Encrypts `plaintext` with `key` and binds it to `aad`. Returns the `v1:` string.
pub fn encrypt(key: &DerivedKey, aad: &str, plaintext: &[u8]) -> Result<String, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| AppError::InternalError)?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    let encoded = base64_encode(&blob);
    blob.zeroize();
    Ok(format!("{V1_PREFIX}{encoded}"))
}

/// Decrypts a `v1:` string that was encrypted for `aad`. The result is zeroed on drop.
pub fn decrypt(key: &DerivedKey, aad: &str, stored: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let encoded = stored
        .strip_prefix(V1_PREFIX)
        .ok_or(AppError::InternalError)?;
    let blob = Zeroizing::new(base64_decode(encoded).ok_or(AppError::InternalError)?);
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::InternalError);
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let plaintext = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| AppError::InternalError)?;
    Ok(Zeroizing::new(plaintext))
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
}

fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(encoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_encryption_key;

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn root() -> EncryptionKey {
        match parse_encryption_key(TEST_KEY_B64) {
            Ok(k) => k,
            Err(_) => panic!("test key must parse"),
        }
    }

    fn cred() -> DerivedKey {
        match credentials_key(&root()) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        }
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let key = cred();
        let a = aad("user_credentials", "encrypted_token", "7");
        let stored = encrypt(&key, &a, b"ghp_example_token").unwrap_or_default();
        assert!(stored.starts_with(V1_PREFIX));
        let out = decrypt(&key, &a, &stored);
        assert!(matches!(out, Ok(ref v) if v.as_slice() == b"ghp_example_token"));
    }

    #[test]
    fn ciphertext_moved_to_another_row_fails() {
        let key = cred();
        let stored = encrypt(
            &key,
            &aad("user_credentials", "encrypted_token", "7"),
            b"secret",
        )
        .unwrap_or_default();
        assert!(
            decrypt(
                &key,
                &aad("user_credentials", "encrypted_token", "8"),
                &stored
            )
            .is_err()
        );
    }

    #[test]
    fn ciphertext_moved_to_another_column_fails() {
        let key = cred();
        let stored = encrypt(
            &key,
            &aad("user_credentials", "encrypted_token", "7"),
            b"secret",
        )
        .unwrap_or_default();
        assert!(decrypt(&key, &aad("user_credentials", "other_column", "7"), &stored).is_err());
    }

    #[test]
    fn ciphertext_moved_to_another_table_fails() {
        let key = cred();
        let stored = encrypt(
            &key,
            &aad("user_credentials", "encrypted_token", "7"),
            b"secret",
        )
        .unwrap_or_default();
        assert!(decrypt(&key, &aad("system_config", "encrypted_token", "7"), &stored).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let key = cred();
        let a = aad("system_config", "value", "oidc.client_secret_encrypted");
        let stored = encrypt(&key, &a, b"client-secret").unwrap_or_default();
        let encoded = stored.strip_prefix(V1_PREFIX).unwrap_or_default();
        let mut blob = base64_decode(encoded).unwrap_or_default();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let tampered = format!("{V1_PREFIX}{}", base64_encode(&blob));
        assert!(decrypt(&key, &a, &tampered).is_err());
    }

    #[test]
    fn fresh_nonce_per_encryption() {
        let key = cred();
        let a = aad("t", "c", "1");
        let first = encrypt(&key, &a, b"same").unwrap_or_default();
        let second = encrypt(&key, &a, b"same").unwrap_or_default();
        assert_ne!(first, second);
    }

    #[test]
    fn derived_keys_differ_per_label() {
        let root = root();
        let keys = [
            credentials_key(&root),
            session_key(&root),
            backup_key(&root),
            csrf_key(&root),
        ];
        let mut bytes = Vec::new();
        for k in keys {
            match k {
                Ok(k) => bytes.push(*k.as_bytes()),
                Err(_) => panic!("derivation must succeed"),
            }
        }
        for i in 0..bytes.len() {
            for j in (i + 1)..bytes.len() {
                assert_ne!(bytes[i], bytes[j], "labels {i} and {j} collide");
            }
        }
    }

    #[test]
    fn derived_key_is_not_the_raw_key() {
        let root = root();
        let derived = credentials_key(&root).unwrap_or_else(|_| panic!("derivation"));
        assert_ne!(derived.as_bytes(), root.as_bytes());
    }
}
