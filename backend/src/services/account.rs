//! The signed-in user's own account. Rules are in `specs/api.md` (Account) and
//! `specs/security.md` (Authentication, Sessions).

use sqlx::SqlitePool;

use crate::auth::password;
use crate::db::users;
use crate::error::AppError;
use crate::services::{auth as local_auth, sessions};

/// Changes the user's local password. Checks the current password, enforces the
/// 15 to 64 character rule, and increments `token_version`, which signs out every
/// other session. Returns the updated row so the caller can issue a fresh cookie for
/// the current session.
///
/// OIDC users have no local password and get `403`. A wrong current password is
/// `401 invalid_credentials`, and it does not change the stored hash.
pub async fn change_password(
    pool: &SqlitePool,
    user_id: &str,
    current: &str,
    new: &str,
) -> Result<users::UserRow, AppError> {
    let row = users::find_by_id(pool, user_id)
        .await?
        .ok_or(AppError::Unauthenticated)?;
    if row.auth_provider != "local" {
        return Err(AppError::Forbidden);
    }
    let stored = row.password_hash.clone().ok_or(AppError::Forbidden)?;
    if !password::verify_password(current, &stored).await? {
        return Err(AppError::InvalidCredentials);
    }
    local_auth::check_password_length(new)?;
    let new_hash = password::hash_password(new).await?;
    users::set_password_hash(pool, user_id, &new_hash).await?;
    sessions::revoke_all(pool, user_id).await?;
    users::find_by_id(pool, user_id)
        .await?
        .ok_or(AppError::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::crypto::session_key;
    use crate::auth::session::{issue, now_unix};
    use crate::config::parse_encryption_key;
    use crate::services::sessions::authenticate;

    // Test values only. Passwords are generated at runtime, so none is a source literal.
    static OLD: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| crate::auth::password::random_test_password(24));
    static NEW: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| crate::auth::password::random_test_password(24));
    static WRONG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| crate::auth::password::random_test_password(24));
    static SHORT: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| crate::auth::password::random_test_password(8));

    fn key() -> crate::auth::crypto::DerivedKey {
        let root = parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        session_key(&root).unwrap()
    }

    async fn seeded(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("harborgate-account-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        local_auth::create_first_admin(&pool, "test-admin", None, &OLD)
            .await
            .unwrap();
        (pool, dir)
    }

    async fn user_id(pool: &SqlitePool) -> String {
        sqlx::query_scalar!(r#"SELECT id AS "id!" FROM users WHERE username = 'test-admin'"#)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn password_change_signs_out_other_sessions_and_keeps_the_current_one() {
        let (pool, dir) = seeded("sessions").await;
        let k = key();
        let id = user_id(&pool).await;
        let now = now_unix().unwrap();
        // Two sessions issued before the change.
        let other = issue(&k, &id, "admin", 0, now).unwrap();
        let current = issue(&k, &id, "admin", 0, now).unwrap();

        let row = change_password(&pool, &id, &OLD, &NEW).await.unwrap();
        // The current session is replaced by one carrying the new token_version.
        let fresh = issue(&k, &id, "admin", row.token_version, now).unwrap();

        let other_result = authenticate(&pool, &k, &other, now).await;
        let current_result = authenticate(&pool, &k, &current, now).await;
        let fresh_result = authenticate(&pool, &k, &fresh, now).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            other_result.err(),
            Some(AppError::Unauthenticated),
            "other session must be revoked"
        );
        assert_eq!(
            current_result.err(),
            Some(AppError::Unauthenticated),
            "stale token is revoked too"
        );
        assert!(fresh_result.is_ok(), "the fresh session must work");
    }

    #[tokio::test]
    async fn new_password_is_the_one_that_works() {
        let (pool, dir) = seeded("new-pass").await;
        let id = user_id(&pool).await;
        change_password(&pool, &id, &OLD, &NEW).await.unwrap();
        let old_login = local_auth::login(&pool, "test-admin", &OLD).await;
        let new_login = local_auth::login(&pool, "test-admin", &NEW).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(old_login.err(), Some(AppError::InvalidCredentials));
        assert!(new_login.is_ok());
    }

    #[tokio::test]
    async fn wrong_current_password_is_refused_and_changes_nothing() {
        let (pool, dir) = seeded("wrong-current").await;
        let id = user_id(&pool).await;
        let result = change_password(&pool, &id, &WRONG, &NEW).await;
        let still_old = local_auth::login(&pool, "test-admin", &OLD).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result.err(), Some(AppError::InvalidCredentials));
        assert!(
            still_old.is_ok(),
            "a refused change must not alter the password"
        );
    }

    #[tokio::test]
    async fn short_new_password_is_refused_with_password_too_short() {
        let (pool, dir) = seeded("short-new").await;
        let id = user_id(&pool).await;
        let result = change_password(&pool, &id, &OLD, &SHORT).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result.err(), Some(AppError::PasswordTooShort));
    }

    #[tokio::test]
    async fn oidc_user_gets_forbidden() {
        let (pool, dir) = seeded("oidc").await;
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider, oidc_issuer, oidc_subject)
             VALUES ('test-oidc-id', 'test-oidc', 'user', 'oidc', 'https://idp.example.test', 'test-sub')"
        )
        .execute(&pool)
        .await
        .unwrap();
        let result = change_password(&pool, "test-oidc-id", &OLD, &NEW).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result.err(), Some(AppError::Forbidden));
    }
}
