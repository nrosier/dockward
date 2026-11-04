//! Argon2id password hashing as a PHC string.
//!
//! Parameters follow `specs/security.md` (Passwords): memory 19456 KiB, 2
//! iterations, parallelism 1, a 16-byte salt from the OS CSPRNG.
//!
//! Argon2 is CPU and memory heavy, so every hash or verification runs on Tokio's
//! blocking pool. At most `MAX_CONCURRENT_HASHES` run at once. A caller waits for a
//! permit and never skips the work.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

use crate::error::AppError;
use crate::services::ids::os_random_bytes;

/// The 62 ASCII letters and digits. Used for the random dummy and test passwords.
const ALPHANUMERIC: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `len` random ASCII letters and digits from the OS CSPRNG. Each character is drawn
/// with rejection sampling, so every character of the 62 is equally likely.
fn random_alphanumeric(len: usize) -> Result<String, AppError> {
    // Bytes at or above this value are rejected, so the rest map evenly onto 62 symbols.
    const LIMIT: u8 = 248; // 62 * 4
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let byte = os_random_bytes::<1>()?[0];
        if byte < LIMIT {
            let index = usize::from(byte) % ALPHANUMERIC.len();
            out.push(char::from(ALPHANUMERIC[index]));
        }
    }
    Ok(out)
}

const MEMORY_KIB: u32 = 19456;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

/// Most Argon2 operations that may run at once, process-wide.
const MAX_CONCURRENT_HASHES: usize = 4;

static HASH_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_HASHES);

/// The fixed dummy PHC hash is generated once per process with the same
/// parameters. A login for an unknown user verifies against it, so its timing
/// matches a real failed login. Its password matches no account.
static DUMMY_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn dummy_hash() -> Result<&'static str, AppError> {
    if let Some(existing) = DUMMY_HASH.get() {
        return Ok(existing.as_str());
    }
    // A random value that no account can have, generated at runtime.
    let generated = hash_blocking(&random_alphanumeric(32)?)?;
    Ok(DUMMY_HASH.get_or_init(|| generated).as_str())
}

/// Computes the dummy hash now, at startup, so the first unknown-user login costs
/// the same as every other login.
pub fn warm_dummy_hash() -> Result<(), AppError> {
    dummy_hash().map(|_| ())
}

fn hasher() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .map_err(|_| AppError::InternalError)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Runs `work` on the blocking pool once a hash permit is free. The permit moves
/// into the blocking closure, so it is released only when the work finishes, even if
/// the caller stops waiting.
async fn run_blocking<T, F>(work: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    let permit = HASH_PERMITS
        .acquire()
        .await
        .map_err(|_| AppError::InternalError)?;
    let joined = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(test)]
        gauge::enter();
        let result = work();
        #[cfg(test)]
        gauge::leave();
        result
    })
    .await;
    joined.map_err(|_| AppError::InternalError)?
}

fn hash_blocking(password: &str) -> Result<String, AppError> {
    // A fresh 16-byte salt from the OS CSPRNG, as `specs/security.md` requires.
    let salt = os_random_bytes::<16>()?;
    let hash = hasher()?
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|_| AppError::InternalError)?;
    Ok(hash.to_string())
}

fn verify_blocking(password: &str, phc: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(phc).map_err(|_| AppError::InternalError)?;
    Ok(hasher()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn verify_dummy_blocking(password: &str) -> Result<(), AppError> {
    let _ = verify_blocking(password, dummy_hash()?);
    Ok(())
}

/// Hashes `password` with a fresh 16-byte salt and returns the PHC string.
pub async fn hash_password(password: &str) -> Result<String, AppError> {
    let password = password.to_owned();
    run_blocking(move || hash_blocking(&password)).await
}

/// Verifies `password` against a PHC string. Returns `Ok(false)` for a wrong
/// password, and `Err` only if the stored hash cannot be parsed.
pub async fn verify_password(password: &str, phc: &str) -> Result<bool, AppError> {
    #[cfg(test)]
    counter::count_verify();
    let password = password.to_owned();
    let phc = phc.to_owned();
    run_blocking(move || verify_blocking(&password, &phc)).await
}

/// Runs one Argon2id verification against the fixed dummy hash. A login for an
/// unknown user calls this so that its timing matches a real failed login.
pub async fn verify_dummy(password: &str) -> Result<(), AppError> {
    #[cfg(test)]
    counter::count_verify();
    let password = password.to_owned();
    run_blocking(move || verify_dummy_blocking(&password)).await
}

/// A random alphanumeric password of `len` characters, for tests only. It is generated
/// at runtime so that no password literal appears in the source.
#[cfg(test)]
pub(crate) fn random_test_password(len: usize) -> String {
    random_alphanumeric(len).unwrap_or_default()
}

/// Test-only count of Argon2id verifications. Thread-local, so parallel tests cannot
/// see each other's counts.
#[cfg(test)]
pub(crate) mod counter {
    use std::cell::Cell;

    thread_local! {
        static VERIFY_CALLS: Cell<u32> = const { Cell::new(0) };
    }

    /// Records one verification. Called from the async `verify_password` and
    /// `verify_dummy`, before the work goes to the blocking pool.
    pub(crate) fn count_verify() {
        VERIFY_CALLS.with(|c| c.set(c.get() + 1));
    }

    /// Argon2id verifications started on this thread since it started.
    pub(crate) fn verify_calls() -> u32 {
        VERIFY_CALLS.with(Cell::get)
    }
}

/// Test-only gauge of hash work in flight, process-wide. Counted inside the blocking
/// closure, after the permit is taken and until the work returns.
#[cfg(test)]
pub(crate) mod gauge {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn enter() {
        let now = IN_FLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK.fetch_max(now, Ordering::SeqCst);
    }

    pub(crate) fn leave() {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }

    /// The most hash work ever in flight at once, in this process.
    pub(crate) fn peak() -> usize {
        PEAK.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test values only. Passwords are generated at runtime, so none is a source literal.

    #[tokio::test]
    async fn hash_then_verify_accepts_right_password() {
        let right = random_test_password(20);
        let phc = hash_password(&right).await.unwrap_or_default();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(matches!(verify_password(&right, &phc).await, Ok(true)));
    }

    #[tokio::test]
    async fn verify_rejects_wrong_password() {
        let right = random_test_password(20);
        let wrong = random_test_password(20);
        let phc = hash_password(&right).await.unwrap_or_default();
        assert!(matches!(verify_password(&wrong, &phc).await, Ok(false)));
    }

    #[tokio::test]
    async fn salts_differ_between_hashes() {
        let same = random_test_password(20);
        let a = hash_password(&same).await.unwrap_or_default();
        let b = hash_password(&same).await.unwrap_or_default();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn dummy_verification_runs_and_returns_ok() {
        let any = random_test_password(20);
        assert!(verify_dummy(&any).await.is_ok());
    }

    /// A hash runs on the blocking pool, so a 1 ms timer on a single-threaded runtime
    /// finishes while the hash is still running.
    #[tokio::test]
    async fn hash_does_not_block_the_runtime() {
        let password = random_test_password(20);
        let hash = tokio::spawn(async move { hash_password(&password).await });
        let tick = tokio::spawn(tokio::time::sleep(std::time::Duration::from_millis(1)));
        tick.await.unwrap();
        assert!(
            !hash.is_finished(),
            "the hash finished before the timer, so it blocked the runtime"
        );
        assert!(hash.await.unwrap().is_ok());
    }

    /// Six hashes start together. The permit keeps the gauge at four or below.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn at_most_four_hashes_run_at_once() {
        let password = random_test_password(20);
        let mut handles = Vec::new();
        for _ in 0..6 {
            let password = password.clone();
            handles.push(tokio::spawn(async move { hash_password(&password).await }));
        }
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
        assert!(
            gauge::peak() <= MAX_CONCURRENT_HASHES,
            "more than {MAX_CONCURRENT_HASHES} hashes ran at once"
        );
    }

    /// A PHC Argon2id hash recorded with the argon2 0.5 build. It uses the project
    /// parameters (m=19456, t=2, p=1), a fixed 16-byte salt, and the test password
    /// `kat-password-0001`. Test values only.
    const KAT_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$0WguUnRpOPo63uGHPCE51k91B0aJq52FfSNXR92+N3M";
    const KAT_PASSWORD: &str = "kat-password-0001";

    #[tokio::test]
    async fn phc_hash_from_the_old_build_still_verifies() {
        assert!(
            matches!(verify_password(KAT_PASSWORD, KAT_PHC).await, Ok(true)),
            "a PHC hash recorded with the old build no longer verifies"
        );
    }

    #[tokio::test]
    async fn phc_hash_from_the_old_build_rejects_a_wrong_password() {
        assert!(matches!(
            verify_password("kat-password-0002", KAT_PHC).await,
            Ok(false)
        ));
    }

    /// A generated hash carries a 16-byte salt and the project parameters.
    #[tokio::test]
    async fn generated_salt_is_16_bytes() {
        let phc = hash_password(&random_test_password(20))
            .await
            .unwrap_or_default();
        let parsed =
            PasswordHash::new(&phc).unwrap_or_else(|_| panic!("generated hash must parse"));
        let Some(salt) = parsed.salt else {
            panic!("the generated hash has no salt");
        };
        // `Salt` derefs to the decoded bytes, so its length is the raw salt length.
        assert_eq!(salt.len(), 16, "the salt is not 16 bytes");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    }

    #[test]
    fn dummy_hash_is_ready_after_warm_up() {
        warm_dummy_hash().unwrap();
        assert!(DUMMY_HASH.get().is_some());
    }
}
