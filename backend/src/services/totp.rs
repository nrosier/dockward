//! Optional TOTP two-factor sign-in for local accounts (#341). Rules: `specs/security.md`
//! (Authentication, "Two-factor sign-in (TOTP)"), `specs/api.md` (Auth, Account, Admin).
//!
//! The secret is sealed with the credentials key and the AAD
//! `totp_secrets:secret_encrypted:<user_id>`, like every other stored secret. No new HKDF label
//! is needed: the AAD already separates it from every other ciphertext. Recovery codes are
//! shown once and stored as Argon2id hashes. Nothing here logs a secret, a code or a hash, and
//! audit rows hold ids and counts only.

use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::auth::crypto::{self, DerivedKey};
use crate::auth::{password, totp};
use crate::db::totp as rows;
use crate::db::users::{self, UserRow};
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::ids;

/// The issuer shown by authenticator apps.
pub const ISSUER: &str = "Dockward";
/// Recovery codes issued at confirmation.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Characters in one recovery code, before the dash that splits it for reading.
const RECOVERY_CODE_LEN: usize = 10;
/// Wrong codes in a row that lock an account's TOTP sign-in for the rest of the window.
pub const LOCKOUT_FAILURES: u32 = 5;

/// What enrolment returns, once. `Debug` never prints the secret.
pub struct Enrolment {
    pub secret: String,
    pub otpauth_uri: String,
}

impl std::fmt::Debug for Enrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrolment")
            .field("secret", &"<redacted>")
            .field("otpauth_uri", &"<redacted>")
            .finish()
    }
}

fn aad(user_id: &str) -> String {
    crypto::aad("totp_secrets", "secret_encrypted", user_id)
}

fn open_secret(
    key: &DerivedKey,
    user_id: &str,
    stored: &str,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    crypto::decrypt(key, &aad(user_id), stored)
}

/// A code is exactly 6 ASCII digits once spaces are removed.
fn totp_digits(input: &str) -> Option<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    (cleaned.len() == totp::DIGITS && cleaned.bytes().all(|b| b.is_ascii_digit()))
        .then_some(cleaned)
}

/// Recovery codes compare without case, dashes or spaces.
fn normalise_recovery(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// One recovery code, as shown: 10 base32 characters in two groups of five.
fn new_recovery_code() -> Result<String, AppError> {
    let text = totp::base32(&ids::os_random_bytes::<7>()?);
    let code = text
        .get(..RECOVERY_CODE_LEN)
        .ok_or(AppError::InternalError)?;
    let (left, right) = code.split_at(RECOVERY_CODE_LEN / 2);
    Ok(format!("{left}-{right}"))
}

/// Starts enrolment for a local user: a new secret, sealed and stored disabled. Repeating it
/// replaces a pending secret. An account that already has TOTP on gets `409`. OIDC accounts and
/// accounts with no local password get `403`.
pub async fn enrol(
    pool: &SqlitePool,
    key: &DerivedKey,
    user: &UserRow,
) -> Result<Enrolment, AppError> {
    if user.auth_provider != "local" || user.password_hash.is_none() {
        return Err(AppError::Forbidden);
    }
    let secret = Zeroizing::new(totp::new_secret()?);
    let sealed = crypto::encrypt(key, &aad(&user.id), secret.as_slice())?;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    if rows::upsert_pending(&mut conn, &user.id, &sealed).await? == 0 {
        return Err(AppError::Conflict(
            "Two-factor sign-in is already on.".to_owned(),
        ));
    }
    let secret_text = totp::base32(secret.as_slice());
    let otpauth_uri = totp::otpauth_uri(ISSUER, &user.username, &secret_text);
    Ok(Enrolment {
        secret: secret_text,
        otpauth_uri,
    })
}

/// Confirms a pending enrolment with a valid current code, turns TOTP on and returns the
/// recovery codes. This is the only time they exist in the clear.
pub async fn confirm(
    pool: &SqlitePool,
    key: &DerivedKey,
    actor: &Actor,
    code: &str,
    now: i64,
) -> Result<Vec<String>, AppError> {
    let user_id = actor.user_id.as_deref().ok_or(AppError::Forbidden)?;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let row = rows::find_secret(&mut conn, user_id)
        .await?
        .ok_or_else(|| AppError::Conflict("Start enrolment first.".to_owned()))?;
    if row.enabled {
        return Err(AppError::Conflict(
            "Two-factor sign-in is already on.".to_owned(),
        ));
    }
    let wrong = || AppError::ValidationFailed("That code is not valid.".to_owned());
    let digits = totp_digits(code).ok_or_else(wrong)?;
    let secret = open_secret(key, user_id, &row.secret_encrypted)?;
    let step = totp::check_code(secret.as_slice(), &digits, now, None)?.ok_or_else(wrong)?;
    drop(conn);

    // Argon2 runs before the transaction opens, so no write lock is held while it works.
    let mut plain = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut hashed = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let shown = new_recovery_code()?;
        hashed.push((
            ids::new_id()?,
            password::hash_password(&normalise_recovery(&shown)).await?,
        ));
        plain.push(shown);
    }

    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    if rows::enable(&mut tx, user_id, step).await? == 0 {
        return Err(AppError::Conflict(
            "Two-factor sign-in is already on.".to_owned(),
        ));
    }
    rows::delete_recovery_codes(&mut tx, user_id).await?;
    for (id, hash) in &hashed {
        rows::insert_recovery_code(&mut tx, id, user_id, hash).await?;
    }
    audit::record(
        &mut tx,
        actor,
        "user.totp_enable",
        &format!("user:{user_id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(plain)
}

/// Whether the user has TOTP switched on. A pending enrolment does not count.
pub async fn is_enabled(pool: &SqlitePool, user_id: &str) -> Result<bool, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    Ok(rows::find_secret(&mut conn, user_id)
        .await?
        .is_some_and(|row| row.enabled))
}

/// Checks a sign-in code: a 6-digit TOTP code, or else a recovery code. A TOTP code works once
/// per step and a recovery code works once. Returns `false` for anything that does not match.
pub async fn verify_sign_in(
    pool: &SqlitePool,
    key: &DerivedKey,
    user_id: &str,
    input: &str,
    now: i64,
) -> Result<bool, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let Some(row) = rows::find_secret(&mut conn, user_id).await? else {
        return Ok(false);
    };
    if !row.enabled {
        return Ok(false);
    }
    if let Some(digits) = totp_digits(input) {
        let secret = open_secret(key, user_id, &row.secret_encrypted)?;
        let Some(step) = totp::check_code(secret.as_slice(), &digits, now, row.totp_last_step)?
        else {
            return Ok(false);
        };
        // One statement moves the step forward, so two requests with one code cannot both win.
        return Ok(rows::advance_step(&mut conn, user_id, step).await? == 1);
    }
    let wanted = normalise_recovery(input);
    if wanted.len() != RECOVERY_CODE_LEN {
        return Ok(false);
    }
    let mut matched = None;
    for code in rows::unused_recovery_codes(&mut conn, user_id).await? {
        // Every unused hash is checked, so the work does not reveal which one matched.
        if password::verify_password(&wanted, &code.code_hash).await? && matched.is_none() {
            matched = Some(code.id);
        }
    }
    match matched {
        Some(id) => Ok(rows::mark_recovery_used(&mut conn, &id).await? == 1),
        None => Ok(false),
    }
}

/// Turns the caller's own TOTP off. It needs a valid current code, not a recovery code.
pub async fn disable(
    pool: &SqlitePool,
    key: &DerivedKey,
    actor: &Actor,
    code: &str,
    now: i64,
) -> Result<(), AppError> {
    let user_id = actor.user_id.as_deref().ok_or(AppError::Forbidden)?;
    let wrong = || AppError::ValidationFailed("That code is not valid.".to_owned());
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let row = rows::find_secret(&mut conn, user_id)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| AppError::Conflict("Two-factor sign-in is not on.".to_owned()))?;
    let digits = totp_digits(code).ok_or_else(wrong)?;
    let secret = open_secret(key, user_id, &row.secret_encrypted)?;
    let step =
        totp::check_code(secret.as_slice(), &digits, now, row.totp_last_step)?.ok_or_else(wrong)?;
    drop(conn);

    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    if rows::advance_step(&mut tx, user_id, step).await? != 1 {
        return Err(wrong());
    }
    rows::delete_recovery_codes(&mut tx, user_id).await?;
    rows::delete_secret(&mut tx, user_id).await?;
    audit::record(
        &mut tx,
        actor,
        "user.totp_disable",
        &format!("user:{user_id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)
}

/// An admin clears a user's TOTP, for a lost device and lost recovery codes. The audit row names
/// the user by id and holds no details. `404` when the user does not exist.
pub async fn admin_reset(pool: &SqlitePool, actor: &Actor, user_id: &str) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    if users::role_and_provider(&mut tx, user_id).await?.is_none() {
        return Err(AppError::NotFound);
    }
    rows::delete_recovery_codes(&mut tx, user_id).await?;
    rows::delete_secret(&mut tx, user_id).await?;
    audit::record(
        &mut tx,
        actor,
        "user.totp_reset",
        &format!("user:{user_id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)
}

/// Audits a lockout of TOTP sign-in. The actor is the locked user. `details` holds the failure
/// count and nothing else.
pub async fn record_lockout(
    pool: &SqlitePool,
    actor: &Actor,
    failures: u32,
) -> Result<(), AppError> {
    let user_id = actor.user_id.as_deref().ok_or(AppError::Forbidden)?;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    audit::record(
        &mut conn,
        actor,
        "user.totp_lockout",
        &format!("user:{user_id}"),
        Some(&serde_json::json!({ "failures": failures })),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::totp::{base32_decode, code_at, step_at};
    use crate::config::parse_encryption_key;

    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn key() -> DerivedKey {
        crate::auth::crypto::credentials_key(&parse_encryption_key(TEST_KEY_B64).unwrap()).unwrap()
    }

    /// A migrated database with one local user `u1` and one local admin `a1`.
    async fn fixture(name: &str) -> (SqlitePool, std::path::PathBuf, UserRow) {
        let dir = std::env::temp_dir().join(format!("dockward-totp-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, "u1", "test-user", None, "h", "user")
            .await
            .unwrap();
        crate::db::users::insert_local(&mut conn, "a1", "test-admin", None, "h", "admin")
            .await
            .unwrap();
        drop(conn);
        let row = crate::db::users::find_by_id(&pool, "u1")
            .await
            .unwrap()
            .unwrap();
        (pool, dir, row)
    }

    fn actor(id: &str, name: &str) -> Actor {
        Actor {
            user_id: Some(id.to_owned()),
            username: name.to_owned(),
        }
    }

    fn user_actor() -> Actor {
        actor("u1", "test-user")
    }

    /// A fixed instant, 10 seconds into a step, so no test depends on the wall clock or on a
    /// step boundary falling inside a slow Argon2 run.
    fn now() -> i64 {
        1_800_000_010
    }

    /// The code for the current step plus `ahead` steps.
    fn code_for(secret_b32: &str, ahead: i64) -> String {
        let secret = base32_decode(secret_b32).unwrap();
        code_at(&secret, step_at(now()) + ahead).unwrap()
    }

    /// Enrols and confirms `u1`. Returns the base32 secret and the recovery codes.
    async fn enrolled(pool: &SqlitePool, row: &UserRow) -> (String, Vec<String>) {
        let enrolment = enrol(pool, &key(), row).await.unwrap();
        let codes = confirm(
            pool,
            &key(),
            &user_actor(),
            &code_for(&enrolment.secret, 0),
            now(),
        )
        .await
        .unwrap();
        (enrolment.secret, codes)
    }

    async fn audit_actions(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
        sqlx::query_as("SELECT action, target, details FROM audit_log WHERE action LIKE 'user.totp_%' ORDER BY rowid")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn totp_tables_exist_and_recovery_codes_are_hashed() {
        let (pool, dir, row) = fixture("tables").await;
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'totp_%' ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(tables, ["totp_recovery_codes", "totp_secrets"]);
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('totp_secrets') ORDER BY name")
                .fetch_all(&pool)
                .await
                .unwrap();
        for wanted in [
            "created_at",
            "enabled",
            "enabled_at",
            "secret_encrypted",
            "totp_last_step",
            "user_id",
        ] {
            assert!(
                columns.iter().any(|c| c == wanted),
                "totp_secrets lacks {wanted}"
            );
        }

        let (_, codes) = enrolled(&pool, &row).await;
        let hashes: Vec<String> =
            sqlx::query_scalar("SELECT code_hash FROM totp_recovery_codes WHERE user_id = 'u1'")
                .fetch_all(&pool)
                .await
                .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(codes.len(), 10);
        assert_eq!(hashes.len(), 10);
        for hash in &hashes {
            assert!(
                hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
                "not an Argon2id hash"
            );
            for code in &codes {
                let plain = code.replace('-', "");
                assert!(
                    !hash.contains(code.as_str()) && !hash.contains(&plain),
                    "a hash holds a code"
                );
            }
        }
    }

    #[tokio::test]
    async fn enrol_stores_an_encrypted_disabled_secret() {
        let (pool, dir, row) = fixture("enrol").await;
        let enrolment = enrol(&pool, &key(), &row).await.unwrap();
        let (stored, enabled): (String, bool) = sqlx::query_as(
            "SELECT secret_encrypted, enabled FROM totp_secrets WHERE user_id = 'u1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let raw = base32_decode(&enrolment.secret).unwrap();
        let opened = crate::auth::crypto::decrypt(
            &key(),
            &crate::auth::crypto::aad("totp_secrets", "secret_encrypted", "u1"),
            &stored,
        )
        .unwrap();
        let moved = crate::auth::crypto::decrypt(
            &key(),
            &crate::auth::crypto::aad("totp_secrets", "secret_encrypted", "u2"),
            &stored,
        );
        let signing_in = is_enabled(&pool, "u1").await.unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            stored.starts_with("v1:"),
            "the secret is not a v1 ciphertext"
        );
        assert!(
            !stored.contains(&enrolment.secret),
            "the secret is stored in the clear"
        );
        assert!(!enabled, "enrolment must not enable TOTP");
        assert!(!signing_in, "a pending secret must not count as enabled");
        assert_eq!(raw.len(), 20);
        assert!(
            opened.as_slice() == raw.as_slice(),
            "the ciphertext does not hold the secret"
        );
        assert!(moved.is_err(), "the ciphertext is not bound to its row");
        assert!(
            enrolment
                .otpauth_uri
                .starts_with("otpauth://totp/Dockward:test-user?secret=")
        );
        assert!(enrolment.otpauth_uri.contains(&enrolment.secret));
        assert!(enrolment.otpauth_uri.contains("issuer=Dockward"));
    }

    #[tokio::test]
    async fn confirm_with_a_valid_code_enables_and_returns_recovery_codes_once() {
        let (pool, dir, row) = fixture("confirm").await;
        let enrolment = enrol(&pool, &key(), &row).await.unwrap();
        let codes = confirm(
            &pool,
            &key(),
            &user_actor(),
            &code_for(&enrolment.secret, 0),
            now(),
        )
        .await
        .unwrap();
        let enabled = is_enabled(&pool, "u1").await.unwrap();
        // A second confirmation, and a second enrolment, neither reveals codes nor re-keys.
        let again = confirm(
            &pool,
            &key(),
            &user_actor(),
            &code_for(&enrolment.secret, 1),
            now(),
        )
        .await;
        let re_enrol = enrol(&pool, &key(), &row).await;
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_recovery_codes")
            .fetch_one(&pool)
            .await
            .unwrap();
        let audit = audit_actions(&pool).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(enabled);
        assert_eq!(codes.len(), 10);
        let distinct: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(distinct.len(), 10, "recovery codes repeat");
        assert!(
            matches!(again, Err(AppError::Conflict(_))),
            "a second confirm must be refused"
        );
        assert!(
            matches!(re_enrol, Err(AppError::Conflict(_))),
            "enrolling over an enabled secret must be refused"
        );
        assert_eq!(rows, 10, "codes were issued twice");
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].0, "user.totp_enable");
        assert_eq!(audit[0].1, "user:u1");
    }

    #[tokio::test]
    async fn confirm_with_a_wrong_code_does_not_enable() {
        let (pool, dir, row) = fixture("confirm-wrong").await;
        let enrolment = enrol(&pool, &key(), &row).await.unwrap();
        let right = code_for(&enrolment.secret, 0);
        // A code that is wrong for the current window and the one step either side.
        let wrong = ["000000", "111111", "222222"]
            .into_iter()
            .find(|c| (-1..=1).all(|d| code_for(&enrolment.secret, d) != *c))
            .unwrap();
        let outcome = confirm(&pool, &key(), &user_actor(), wrong, now()).await;
        let malformed = confirm(&pool, &key(), &user_actor(), "12ab", now()).await;
        let enabled = is_enabled(&pool, "u1").await.unwrap();
        let codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_recovery_codes")
            .fetch_one(&pool)
            .await
            .unwrap();
        // The pending enrolment still confirms with the right code afterwards.
        let later = confirm(&pool, &key(), &user_actor(), &right, now()).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(matches!(outcome, Err(AppError::ValidationFailed(_))));
        assert!(matches!(malformed, Err(AppError::ValidationFailed(_))));
        assert!(!enabled);
        assert_eq!(codes, 0, "recovery codes were issued for a wrong code");
        assert!(later.is_ok());
    }

    #[tokio::test]
    async fn a_replayed_code_is_refused() {
        let (pool, dir, row) = fixture("replay").await;
        let (secret, _) = enrolled(&pool, &row).await;
        // The confirming code used the current step. The same code is refused at sign-in.
        let used_at_confirm = verify_sign_in(&pool, &key(), "u1", &code_for(&secret, 0), now())
            .await
            .unwrap();
        // The next step's code is accepted once, then refused.
        let next = code_for(&secret, 1);
        let first = verify_sign_in(&pool, &key(), "u1", &next, now())
            .await
            .unwrap();
        let second = verify_sign_in(&pool, &key(), "u1", &next, now())
            .await
            .unwrap();
        // An older step than the last accepted one is refused too.
        let older = verify_sign_in(&pool, &key(), "u1", &code_for(&secret, 0), now())
            .await
            .unwrap();
        let last_step: Option<i64> =
            sqlx::query_scalar("SELECT totp_last_step FROM totp_secrets WHERE user_id = 'u1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!used_at_confirm, "the confirming code was accepted again");
        assert!(first, "a fresh code was refused");
        assert!(!second, "a replayed code was accepted");
        assert!(!older, "an older step was accepted after a newer one");
        assert_eq!(
            last_step,
            Some(step_at(now()) + 1),
            "the newest accepted step is stored"
        );
    }

    #[tokio::test]
    async fn a_recovery_code_works_once() {
        let (pool, dir, row) = fixture("recovery").await;
        let (_, codes) = enrolled(&pool, &row).await;
        let first = verify_sign_in(&pool, &key(), "u1", &codes[0], now())
            .await
            .unwrap();
        let second = verify_sign_in(&pool, &key(), "u1", &codes[0], now())
            .await
            .unwrap();
        // Typed lowercase and without the dash, another code still works once.
        let loose = codes[1].replace('-', "").to_lowercase();
        let third = verify_sign_in(&pool, &key(), "u1", &loose, now())
            .await
            .unwrap();
        let wrong = verify_sign_in(&pool, &key(), "u1", "ZZZZZ-ZZZZZ", now())
            .await
            .unwrap();
        let used: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM totp_recovery_codes WHERE used_at IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(first, "a recovery code was refused");
        assert!(!second, "a recovery code worked twice");
        assert!(third, "a recovery code typed loosely was refused");
        assert!(!wrong);
        assert_eq!(used, 2);
    }

    #[tokio::test]
    async fn admin_reset_clears_totp_and_audits_it() {
        let (pool, dir, row) = fixture("reset").await;
        enrolled(&pool, &row).await;
        admin_reset(&pool, &actor("a1", "test-admin"), "u1")
            .await
            .unwrap();
        let enabled = is_enabled(&pool, "u1").await.unwrap();
        let secrets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets")
            .fetch_one(&pool)
            .await
            .unwrap();
        let codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_recovery_codes")
            .fetch_one(&pool)
            .await
            .unwrap();
        let missing = admin_reset(&pool, &actor("a1", "test-admin"), "no-such-user").await;
        let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT action, target, details, actor_user_id FROM audit_log WHERE action = 'user.totp_reset'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!enabled);
        assert_eq!((secrets, codes), (0, 0));
        assert_eq!(missing.err(), Some(AppError::NotFound));
        assert_eq!(rows.len(), 1, "the reset must be audited once");
        assert_eq!(rows[0].0, "user.totp_reset");
        assert_eq!(rows[0].1, "user:u1", "the target is the user's id only");
        assert_eq!(rows[0].2, None, "no details: ids only");
        assert_eq!(rows[0].3.as_deref(), Some("a1"));
    }

    #[tokio::test]
    async fn self_disable_needs_a_valid_code() {
        let (pool, dir, row) = fixture("disable").await;
        let (secret, _) = enrolled(&pool, &row).await;
        let wrong = ["000000", "111111", "222222"]
            .into_iter()
            .find(|c| (-1..=1).all(|d| code_for(&secret, d) != *c))
            .unwrap();
        let refused = disable(&pool, &key(), &user_actor(), wrong, now()).await;
        let still_enabled = is_enabled(&pool, "u1").await.unwrap();
        // The confirming code is spent, so it cannot disable either.
        let replayed = disable(&pool, &key(), &user_actor(), &code_for(&secret, 0), now()).await;
        let ok = disable(&pool, &key(), &user_actor(), &code_for(&secret, 1), now()).await;
        let after = is_enabled(&pool, "u1").await.unwrap();
        let leftovers: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM totp_secrets) + (SELECT COUNT(*) FROM totp_recovery_codes)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let audit = audit_actions(&pool).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(matches!(refused, Err(AppError::ValidationFailed(_))));
        assert!(still_enabled, "a wrong code disabled TOTP");
        assert!(matches!(replayed, Err(AppError::ValidationFailed(_))));
        assert!(ok.is_ok());
        assert!(!after);
        assert_eq!(leftovers, 0);
        assert_eq!(
            audit.last().map(|a| a.0.as_str()),
            Some("user.totp_disable")
        );
    }
}
