//! Session validation and revocation. Token rules are in `auth::session`.
//! Revocation is per user through `users.token_version` (`specs/security.md`, Sessions).

use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::auth::session;
use crate::db::users;
use crate::error::AppError;
use crate::models::role::Role;

/// The authenticated caller for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUser {
    pub id: String,
    pub username: String,
    pub role: Role,
}

/// Validates a session token and returns the caller. The role and `token_version`
/// come from the database on every call. A stale `ver`, a missing user, or an
/// unknown stored role all return `401`.
pub async fn authenticate(
    pool: &SqlitePool,
    key: &DerivedKey,
    token: &str,
    now: i64,
) -> Result<AuthUser, AppError> {
    let claims = session::verify(key, token, now)?;
    let row = users::find_auth(pool, &claims.sub)
        .await?
        .ok_or(AppError::Unauthenticated)?;
    if row.token_version != claims.ver {
        return Err(AppError::Unauthenticated);
    }
    let role = Role::parse(&row.role).ok_or(AppError::Unauthenticated)?;
    Ok(AuthUser {
        id: row.id,
        username: row.username,
        role,
    })
}

/// Revokes every session of `user_id` by incrementing `token_version`.
pub async fn revoke_all(pool: &SqlitePool, user_id: &str) -> Result<(), AppError> {
    match users::bump_token_version(pool, user_id).await? {
        0 => Err(AppError::Unauthenticated),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::crypto::session_key;
    use crate::auth::session::{issue, now_unix};
    use crate::config::parse_encryption_key;

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn key() -> DerivedKey {
        let root = parse_encryption_key(TEST_KEY_B64).unwrap();
        session_key(&root).unwrap()
    }

    /// A fresh migrated database holding one admin, `test-admin`. Values are test-only.
    async fn seeded_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("harborgate-sessions-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider) VALUES ('u-1', 'test-admin', 'admin', 'local')"
        )
        .execute(&pool)
        .await
        .unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn token_issued_before_logout_all_is_rejected() {
        let (pool, dir) = seeded_pool("logout-all").await;
        let k = key();
        let now = now_unix().unwrap();
        let token = issue(&k, "u-1", "admin", 0, now).unwrap();
        assert!(authenticate(&pool, &k, &token, now).await.is_ok());

        revoke_all(&pool, "u-1").await.unwrap();
        assert_eq!(
            authenticate(&pool, &k, &token, now).await.err(),
            Some(AppError::Unauthenticated)
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn demoted_admin_loses_admin_on_the_next_request() {
        let (pool, dir) = seeded_pool("demote").await;
        let k = key();
        let now = now_unix().unwrap();
        // The JWT still says admin, and its version still matches.
        let token = issue(&k, "u-1", "admin", 0, now).unwrap();
        assert_eq!(
            authenticate(&pool, &k, &token, now).await.unwrap().role,
            Role::Admin
        );

        crate::db::users::set_role(&pool, "u-1", "user")
            .await
            .unwrap();
        let after = authenticate(&pool, &k, &token, now).await.unwrap();
        assert_eq!(after.role, Role::User, "role must come from the database");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deleted_user_token_is_rejected() {
        let (pool, dir) = seeded_pool("deleted").await;
        let k = key();
        let now = now_unix().unwrap();
        let token = issue(&k, "u-1", "admin", 0, now).unwrap();
        sqlx::query!("DELETE FROM users WHERE id = 'u-1'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            authenticate(&pool, &k, &token, now).await.err(),
            Some(AppError::Unauthenticated)
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
