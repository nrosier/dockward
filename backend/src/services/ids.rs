//! Opaque random identifiers for `TEXT` primary keys, and the one place that draws
//! random bytes from the operating system.

use std::fmt::Write;

use rand::{TryRng, rngs::SysRng};

use crate::error::AppError;

/// Fills `N` bytes from the operating system's CSPRNG (`SysRng`). A failure of the
/// system source returns `AppError::InternalError`. No fallback generator is used.
pub fn os_random_bytes<const N: usize>() -> Result<[u8; N], AppError> {
    let mut bytes = [0u8; N];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::InternalError)?;
    Ok(bytes)
}

/// Returns 128 random bits as 32 lowercase hex characters.
pub fn new_id() -> Result<String, AppError> {
    let bytes = os_random_bytes::<16>()?;
    Ok(bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_32_hex_chars_and_differ() {
        let a = new_id().unwrap_or_default();
        let b = new_id().unwrap_or_default();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn os_random_bytes_fill_the_requested_length() {
        let bytes = os_random_bytes::<32>().unwrap_or([0u8; 32]);
        assert_eq!(bytes.len(), 32);
    }
}
