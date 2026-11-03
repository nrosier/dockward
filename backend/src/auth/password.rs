//! Argon2id password hashing as a PHC string.
//!
//! Parameters follow `specs/security.md` (Passwords): memory 19456 KiB, 2
//! iterations, parallelism 1, a 16-byte salt from the OS CSPRNG.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::error::AppError;

const MEMORY_KIB: u32 = 19456;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

/// The fixed dummy PHC hash is generated once per process with the same
/// parameters. A login for an unknown user verifies against it, so its timing
/// matches a real failed login. Its password matches no account.
static DUMMY_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn dummy_hash() -> Result<&'static str, AppError> {
    if let Some(existing) = DUMMY_HASH.get() {
        return Ok(existing.as_str());
    }
    let generated = hash_password("harborgate-dummy-password-not-a-secret")?;
    Ok(DUMMY_HASH.get_or_init(|| generated).as_str())
}

fn hasher() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .map_err(|_| AppError::InternalError)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hashes `password` with a fresh 16-byte salt and returns the PHC string.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AppError::InternalError)?;
    Ok(hash.to_string())
}

/// Verifies `password` against a PHC string. Returns `Ok(false)` for a wrong
/// password, and `Err` only if the stored hash cannot be parsed.
pub fn verify_password(password: &str, phc: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(phc).map_err(|_| AppError::InternalError)?;
    Ok(hasher()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Runs one Argon2id verification against the fixed dummy hash. A login for an
/// unknown user calls this so that its timing matches a real failed login.
pub fn verify_dummy(password: &str) -> Result<(), AppError> {
    let _ = verify_password(password, dummy_hash()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_accepts_right_password() {
        let phc = hash_password("correct horse battery").unwrap_or_default();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(matches!(
            verify_password("correct horse battery", &phc),
            Ok(true)
        ));
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let phc = hash_password("correct horse battery").unwrap_or_default();
        assert!(matches!(
            verify_password("wrong password value", &phc),
            Ok(false)
        ));
    }

    #[test]
    fn salts_differ_between_hashes() {
        let a = hash_password("same password text").unwrap_or_default();
        let b = hash_password("same password text").unwrap_or_default();
        assert_ne!(a, b);
    }

    #[test]
    fn dummy_verification_runs_and_returns_ok() {
        assert!(verify_dummy("any password value").is_ok());
    }
}
