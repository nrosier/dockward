use std::env::{self, VarError};
use std::fmt;

use base64::{engine::general_purpose::STANDARD, Engine};

/// Name of the environment variable that holds the base64-encoded 32-byte key.
pub const ENCRYPTION_KEY_VAR: &str = "HARBORGATE_ENCRYPTION_KEY";

/// Required length of the decoded encryption key in bytes (AES-256).
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// Startup configuration errors. Messages name the variable and the expected
/// format, and never include the value that was supplied.
#[derive(Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing,
    NotUnicode,
    InvalidBase64,
    WrongLength { decoded_len: usize },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Missing => write!(
                f,
                "{ENCRYPTION_KEY_VAR} is missing; set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
            ConfigError::NotUnicode => write!(
                f,
                "{ENCRYPTION_KEY_VAR} is not valid UTF-8; set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
            ConfigError::InvalidBase64 => write!(
                f,
                "{ENCRYPTION_KEY_VAR} is not valid base64 (standard alphabet); set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
            ConfigError::WrongLength { decoded_len } => write!(
                f,
                "{ENCRYPTION_KEY_VAR} must decode to exactly {ENCRYPTION_KEY_LEN} bytes, but decoded to {decoded_len} bytes; set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
        }
    }
}

// Debug matches Display so that returning this error from `main` prints only the message.
impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ConfigError {}

/// The 32-byte encryption key. It has no `Display` impl, and its `Debug` output is redacted.
#[allow(dead_code)] // Consumed by the encryption layer once it exists.
pub struct EncryptionKey([u8; ENCRYPTION_KEY_LEN]);

impl EncryptionKey {
    #[allow(dead_code)] // Consumed by the encryption layer once it exists.
    pub fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey(<redacted>)")
    }
}

/// Reads `HARBORGATE_ENCRYPTION_KEY` and returns the decoded 32-byte key.
pub fn load_encryption_key() -> Result<EncryptionKey, ConfigError> {
    load_encryption_key_with(|name| env::var(name))
}

/// Same as [`load_encryption_key`], with the variable lookup injected for testing.
pub fn load_encryption_key_with<F>(lookup: F) -> Result<EncryptionKey, ConfigError>
where
    F: FnOnce(&str) -> Result<String, VarError>,
{
    let raw = match lookup(ENCRYPTION_KEY_VAR) {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Err(ConfigError::Missing),
        Err(VarError::NotUnicode(_)) => return Err(ConfigError::NotUnicode),
    };
    parse_encryption_key(&raw)
}

/// Decodes a base64 (standard alphabet) string into an [`EncryptionKey`].
pub fn parse_encryption_key(encoded: &str) -> Result<EncryptionKey, ConfigError> {
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|_| ConfigError::InvalidBase64)?;
    let bytes: [u8; ENCRYPTION_KEY_LEN] =
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::WrongLength {
                decoded_len: decoded.len(),
            })?;
    Ok(EncryptionKey(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn valid_32_byte_key_is_accepted() {
        let key = parse_encryption_key(TEST_KEY_B64);
        assert!(matches!(&key, Ok(k) if k.as_bytes() == &[0u8; 32]));
    }

    #[test]
    fn missing_variable_is_rejected() {
        let result = load_encryption_key_with(|_| Err(VarError::NotPresent));
        assert_eq!(result.err(), Some(ConfigError::Missing));
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let result = parse_encryption_key("not base64!!");
        assert_eq!(result.err(), Some(ConfigError::InvalidBase64));
    }

    #[test]
    fn key_decoding_to_31_bytes_is_rejected() {
        // 31 zero bytes encoded as base64.
        let result = parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(
            result.err(),
            Some(ConfigError::WrongLength { decoded_len: 31 })
        );
    }

    #[test]
    fn key_decoding_to_33_bytes_is_rejected() {
        // 33 zero bytes encoded as base64.
        let result = parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(
            result.err(),
            Some(ConfigError::WrongLength { decoded_len: 33 })
        );
    }

    #[test]
    fn empty_value_is_rejected() {
        let result = parse_encryption_key("");
        assert_eq!(
            result.err(),
            Some(ConfigError::WrongLength { decoded_len: 0 })
        );
    }

    #[test]
    fn error_messages_do_not_contain_the_key_value() {
        let bad_inputs = [
            TEST_KEY_B64,
            "AAAA!!",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        ];
        for input in bad_inputs {
            if let Err(err) = parse_encryption_key(input) {
                let msg = err.to_string();
                assert!(!msg.contains(input), "error text leaked input: {msg}");
                assert!(msg.contains(ENCRYPTION_KEY_VAR));
            }
        }
        assert!(!ConfigError::Missing.to_string().contains(TEST_KEY_B64));
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = parse_encryption_key(TEST_KEY_B64);
        let rendered = match key {
            Ok(k) => format!("{k:?}"),
            Err(_) => String::new(),
        };
        assert_eq!(rendered, "EncryptionKey(<redacted>)");
    }
}
