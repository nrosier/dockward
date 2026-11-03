//! Opaque random identifiers for `TEXT` primary keys.

use std::fmt::Write;

use rand::RngCore;

/// Returns 128 random bits as 32 lowercase hex characters.
pub fn new_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_32_hex_chars_and_differ() {
        let a = new_id();
        let b = new_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
