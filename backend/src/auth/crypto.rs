//! Key derivation and AES-256-GCM encryption for stored secrets.
//!
//! The raw `DOCKWARD_ENCRYPTION_KEY` is input key material only. Every key used
//! to encrypt or sign is derived from it with HKDF-SHA256 under a distinct label.
//! See `specs/security.md` (Encryption and keys, Derived keys).

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, Generate, KeyInit, Nonce, Payload},
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

const LABEL_CREDENTIALS: &[u8] = b"dockward/credentials-v1";
const LABEL_SESSION: &[u8] = b"dockward/session-v1";
const LABEL_BACKUP: &[u8] = b"dockward/backup-v1";
const LABEL_CSRF: &[u8] = b"dockward/csrf-v1";
/// The credential label before the rename (decisions 54 and 56). It is read only, as a
/// fallback for stored ciphertexts the startup migration has not resealed yet.
pub const LABEL_CREDENTIALS_LEGACY: &[u8] = b"harborgate/credentials-v1";

/// A 32-byte derived key. It is zeroed on drop. The credential key also carries the
/// pre-rename key as a read-only fallback, which [`decrypt`] tries after this key.
pub struct DerivedKey {
    key: Zeroizing<[u8; KEY_LEN]>,
    legacy: Option<Zeroizing<[u8; KEY_LEN]>>,
}

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

/// Derives a 32-byte key from the encryption key with HKDF-SHA256 (no salt) and the given label.
pub fn derive_key(root: &EncryptionKey, label: &[u8]) -> Result<DerivedKey, AppError> {
    let hk = Hkdf::<Sha256>::new(None, root.as_bytes());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(label, out.as_mut_slice())
        .map_err(|_| AppError::InternalError)?;
    Ok(DerivedKey {
        key: out,
        legacy: None,
    })
}

/// The credential key used for every stored ciphertext. [`decrypt`] falls back to the
/// pre-rename key when a value does not open with this one; [`encrypt`] never uses it.
pub fn credentials_key(root: &EncryptionKey) -> Result<DerivedKey, AppError> {
    let mut key = derive_key(root, LABEL_CREDENTIALS)?;
    key.legacy = Some(derive_key(root, LABEL_CREDENTIALS_LEGACY)?.key);
    Ok(key)
}

/// The pre-rename credential key, without a fallback. The label migration uses it.
pub fn legacy_credentials_key(root: &EncryptionKey) -> Result<DerivedKey, AppError> {
    derive_key(root, LABEL_CREDENTIALS_LEGACY)
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
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| AppError::InternalError)?;
    // A fresh 12-byte nonce from the OS CSPRNG for every call.
    let nonce = Nonce::<Aes256Gcm>::try_generate().map_err(|_| AppError::InternalError)?;
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
/// A credential key tries the current key first and then the pre-rename key.
pub fn decrypt(key: &DerivedKey, aad: &str, stored: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
    match decrypt_exact(key, aad, stored) {
        Ok(plain) => Ok(plain),
        Err(err) => match &key.legacy {
            Some(legacy) => open(legacy, aad, stored),
            None => Err(err),
        },
    }
}

/// Like [`decrypt`], but only with `key` itself: no fallback.
pub fn decrypt_exact(
    key: &DerivedKey,
    aad: &str,
    stored: &str,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    open(&key.key, aad, stored)
}

fn open(key: &[u8; KEY_LEN], aad: &str, stored: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let encoded = stored
        .strip_prefix(V1_PREFIX)
        .ok_or(AppError::InternalError)?;
    let blob = Zeroizing::new(base64_decode(encoded).ok_or(AppError::InternalError)?);
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::InternalError);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: &Nonce<Aes256Gcm> = nonce_bytes
        .try_into()
        .map_err(|_| AppError::InternalError)?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AppError::InternalError)?;
    let plaintext = cipher
        .decrypt(
            nonce,
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

    /// The first 12 bytes of each `v1:` value are the nonce. Two encryptions of the same
    /// plaintext under the same key and AAD must draw different nonces. A fixed nonce
    /// would make this fail.
    #[test]
    fn each_encryption_draws_a_fresh_nonce() {
        let key = cred();
        let a = aad("t", "c", "1");
        let nonce_of = |stored: &str| -> Vec<u8> {
            let encoded = stored.strip_prefix(V1_PREFIX).unwrap_or_default();
            base64_decode(encoded).unwrap_or_default()[..NONCE_LEN].to_vec()
        };
        let first = encrypt(&key, &a, b"same").unwrap_or_default();
        let second = encrypt(&key, &a, b"same").unwrap_or_default();
        assert_eq!(nonce_of(&first).len(), NONCE_LEN, "nonce is not 12 bytes");
        assert_ne!(
            nonce_of(&first),
            nonce_of(&second),
            "two encryptions reused a nonce"
        );
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

    /// Lowercase hex of `bytes`.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Known-answer vectors recorded with the hkdf 0.12 build. The root key is 32 zero
    /// bytes, the salt is absent, and each output is 32 bytes. Assertions print no
    /// key bytes. Test values only.
    const KAT_HKDF_CREDENTIALS: &str =
        "abcba23a3c0c5925919235d93ced37fcf41cc12a6bb30903def31c69bc9a250f";
    const KAT_HKDF_SESSION: &str =
        "ad161010832c5a8ad79a07d0239b13b7117d95a9505dbc566d10755f41675216";
    const KAT_HKDF_BACKUP: &str =
        "c4e40cb5e0b551c6facc945339d4bc403219c6eea73145d877582370a5ae7d57";
    const KAT_HKDF_CSRF: &str = "619cdafedd6038348d155862ceafae632ee5bdcdf35878938516265b22d7a3d1";

    #[test]
    fn hkdf_known_answers_per_label() {
        let root = root();
        let cases = [
            (LABEL_CREDENTIALS, KAT_HKDF_CREDENTIALS),
            (LABEL_SESSION, KAT_HKDF_SESSION),
            (LABEL_BACKUP, KAT_HKDF_BACKUP),
            (LABEL_CSRF, KAT_HKDF_CSRF),
        ];
        for (label, expected) in cases {
            let derived = match derive_key(&root, label) {
                Ok(k) => k,
                Err(_) => panic!("derivation must succeed"),
            };
            assert!(
                to_hex(derived.as_bytes()) == expected,
                "an HKDF output changed for a label"
            );
        }
    }

    /// The pre-rename credential label, recorded with the same build.
    const KAT_HKDF_CREDENTIALS_LEGACY: &str =
        "903052f15afc94615e653837fd963ea1308221f2a78e288ce35bee6d63d9ab7c";

    #[test]
    fn legacy_credentials_label_known_answer() {
        let derived = match derive_key(&root(), LABEL_CREDENTIALS_LEGACY) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        };
        assert!(to_hex(derived.as_bytes()) == KAT_HKDF_CREDENTIALS_LEGACY);
    }

    /// A value sealed under the old label opens through the fallback, the new key alone
    /// refuses it, and a new seal never uses the old key.
    #[test]
    fn old_label_ciphertext_opens_through_the_fallback() {
        let legacy = match legacy_credentials_key(&root()) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        };
        let a = aad("user_credentials", "encrypted_token", "9");
        let old = encrypt(&legacy, &a, b"fake-old-token").unwrap_or_default();
        let key = cred();
        let out = decrypt(&key, &a, &old);
        assert!(matches!(out, Ok(ref v) if v.as_slice() == b"fake-old-token"));
        assert!(decrypt_exact(&key, &a, &old).is_err());
        let fresh = encrypt(&key, &a, b"fake-new-token").unwrap_or_default();
        assert!(decrypt_exact(&key, &a, &fresh).is_ok());
        assert!(decrypt(&legacy, &a, &fresh).is_err());
        assert!(decrypt(&key, "user_credentials:encrypted_token:8", &old).is_err());
    }

    /// SHA-256 of "abc" and of the 56-byte NIST FIPS 180-2 message.
    const KAT_SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const KAT_SHA256_NIST_56: &str =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    /// A `v1:` value recorded with the aes-gcm 0.10 build. The credentials key is
    /// derived from the all-zero test root. The nonce is 0x2a repeated 12 times, and the
    /// row AAD is `user_credentials:encrypted_token:7`. The plaintext is
    /// `ghp_example_token`. Test values only.
    const KAT_V1_CIPHERTEXT: &str =
        "v1:KioqKioqKioqKioqOHCcMU+svq3pC6xXZLCeGTRz5JKQ5ggW19BUnTLaoKQy";
    const KAT_V1_AAD: &str = "user_credentials:encrypted_token:7";
    const KAT_V1_PLAINTEXT: &[u8] = b"ghp_example_token";

    #[test]
    fn v1_ciphertext_from_the_old_build_still_decrypts() {
        let key = cred();
        let out = decrypt(&key, KAT_V1_AAD, KAT_V1_CIPHERTEXT);
        assert!(
            matches!(out, Ok(ref v) if v.as_slice() == KAT_V1_PLAINTEXT),
            "a v1 value recorded with the old build no longer decrypts"
        );
    }

    #[test]
    fn v1_ciphertext_from_the_old_build_is_bound_to_its_row() {
        let key = cred();
        assert!(
            decrypt(
                &key,
                "user_credentials:encrypted_token:8",
                KAT_V1_CIPHERTEXT
            )
            .is_err()
        );
    }

    #[test]
    fn sha256_known_answers() {
        use sha2::Digest;
        assert!(
            to_hex(&Sha256::digest(b"abc")) == KAT_SHA256_ABC,
            "SHA-256 of abc changed"
        );
        let nist = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert!(
            to_hex(&Sha256::digest(nist)) == KAT_SHA256_NIST_56,
            "SHA-256 of the NIST message changed"
        );
    }
}
