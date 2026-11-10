//! Local authentication: first-run setup and local login, plus the same-origin
//! check both routes need. Sources: `specs/security.md` (Authentication, Hardening
//! "Login CSRF"), `specs/api.md` (Auth).

use axum::http::HeaderMap;
use sqlx::SqlitePool;

use crate::auth::password;
use crate::db::{config, setup, users};
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::ids;

/// Minimum local password length, in characters.
pub const MIN_PASSWORD_LEN: usize = 15;
/// Maximum local password length, in characters (`specs/security.md`, Authentication).
pub const MAX_PASSWORD_LEN: usize = 64;

/// `system_config` key that restricts regular users to OIDC sign-in.
pub const OIDC_ONLY_USERS_KEY: &str = "auth.oidc_only_users";

/// Refuses a local password outside 15 to 64 characters with `password_too_short`.
pub fn check_password_length(password: &str) -> Result<(), AppError> {
    let chars = password.chars().count();
    if (MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&chars) {
        Ok(())
    } else {
        Err(AppError::PasswordTooShort)
    }
}

/// Same-origin rule for login and setup (`specs/security.md`, Login CSRF). The
/// `Origin` header must equal `public_url`. When `Origin` is absent,
/// `Sec-Fetch-Site` must be `same-origin`. Anything else is `403 csrf_invalid`.
pub fn check_same_origin(headers: &HeaderMap, public_url: &str) -> Result<(), AppError> {
    if let Some(origin) = headers.get("origin") {
        return match origin.to_str() {
            Ok(value) if value == public_url => Ok(()),
            _ => Err(AppError::CsrfInvalid),
        };
    }
    match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        Some("same-origin") => Ok(()),
        _ => Err(AppError::CsrfInvalid),
    }
}

/// Whether the first-run setup is still open (no user exists yet).
pub async fn setup_required(pool: &SqlitePool) -> Result<bool, AppError> {
    Ok(!setup::any_user_exists(pool).await?)
}

/// Creates the first local admin. The insert succeeds only while `users` is empty,
/// so exactly one of several concurrent calls can win. The losers get `409 conflict`.
pub async fn create_first_admin(
    pool: &SqlitePool,
    username: &str,
    email: Option<&str>,
    password_plain: &str,
) -> Result<String, AppError> {
    check_password_length(password_plain)?;
    let hash = password::hash_password(password_plain).await?;
    let id = ids::new_id()?;
    if setup::insert_first_admin(pool, &id, username, email, &hash).await? {
        Ok(id)
    } else {
        Err(AppError::Conflict("Setup is already complete.".to_owned()))
    }
}

/// Local login. Admins always sign in with a password. Regular users sign in
/// unless `auth.oidc_only_users` is `true`. An unknown user, a wrong password, and
/// an OIDC-only refusal all return `401 invalid_credentials` after the same Argon2
/// work, so timing does not reveal which case happened.
pub async fn login(
    pool: &SqlitePool,
    username: &str,
    password_plain: &str,
) -> Result<users::UserRow, AppError> {
    let row = users::find_by_username(pool, username).await?;
    let Some(row) = row else {
        // Unknown user: same Argon2 cost as a real check, then the same error.
        password::verify_dummy(password_plain).await?;
        return Err(AppError::InvalidCredentials);
    };

    let Some(stored_hash) = row.password_hash.clone() else {
        // OIDC-only accounts have no local password. Same cost, same error.
        password::verify_dummy(password_plain).await?;
        return Err(AppError::InvalidCredentials);
    };

    let role = Role::parse(&row.role).ok_or(AppError::InvalidCredentials)?;
    let oidc_only = config::get(pool, OIDC_ONLY_USERS_KEY).await? == Some("true".to_owned());
    let restricted = oidc_only && role == Role::User;

    let password_ok = password::verify_password(password_plain, &stored_hash).await?;
    if !password_ok || restricted {
        return Err(AppError::InvalidCredentials);
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // Test values only. Passwords are generated at runtime, so none is a source literal.
    const URL: &str = "https://dockward.example.com";
    static PASSWORD: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| crate::auth::password::random_test_password(20));
    static WRONG: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| crate::auth::password::random_test_password(20));

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn password_length_bounds_are_15_to_64() {
        assert!(check_password_length(&"a".repeat(14)).is_err());
        assert!(check_password_length(&"a".repeat(15)).is_ok());
        assert!(check_password_length(&"a".repeat(64)).is_ok());
        assert!(check_password_length(&"a".repeat(65)).is_err());
    }

    #[test]
    fn same_origin_accepts_matching_origin_and_same_origin_fetch_metadata() {
        assert!(check_same_origin(&headers(&[("origin", URL)]), URL).is_ok());
        assert!(check_same_origin(&headers(&[("sec-fetch-site", "same-origin")]), URL).is_ok());
    }

    #[test]
    fn origin_matches_after_normalisation() {
        // An operator writes an uppercase host and the default port. The browser sends
        // `Origin` in canonical form, so the startup value must match it.
        let raw = "https://Dockward.Example.com:443/";
        let settings = crate::config::load_settings_with(|name| {
            if name == crate::config::PUBLIC_URL_VAR {
                Ok(raw.to_owned())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        })
        .unwrap();
        assert_eq!(settings.public_url, "https://dockward.example.com");
        let browser = headers(&[("origin", "https://dockward.example.com")]);
        assert!(check_same_origin(&browser, &settings.public_url).is_ok());
        // The raw operator value is not what a browser sends, so it must not be stored.
        assert_ne!(settings.public_url, raw.trim_end_matches('/'));
    }

    #[test]
    fn cross_site_origin_is_refused_with_csrf_invalid() {
        let cross = headers(&[("origin", "https://attacker.example.net")]);
        assert_eq!(check_same_origin(&cross, URL), Err(AppError::CsrfInvalid));
        // A cross-site Origin wins over a same-origin Sec-Fetch-Site.
        let mixed = headers(&[
            ("origin", "https://attacker.example.net"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert_eq!(check_same_origin(&mixed, URL), Err(AppError::CsrfInvalid));
        assert_eq!(
            check_same_origin(&headers(&[]), URL),
            Err(AppError::CsrfInvalid)
        );
        let cross_site = headers(&[("sec-fetch-site", "cross-site")]);
        assert_eq!(
            check_same_origin(&cross_site, URL),
            Err(AppError::CsrfInvalid)
        );
    }

    /// A fresh migrated database. Test values only.
    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("dockward-auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// An unknown user and a wrong password must do the same Argon2id work: one
    /// verification each, counted, with no wall-clock timing. Both return the same error.
    #[tokio::test]
    async fn unknown_user_and_wrong_password_do_equal_argon2_work() {
        let (pool, dir) = fresh_pool("equal-work").await;
        create_first_admin(&pool, "test-admin", None, &PASSWORD)
            .await
            .unwrap();

        let before = crate::auth::password::counter::verify_calls();
        let unknown = login(&pool, "test-nobody", &PASSWORD).await;
        let after_unknown = crate::auth::password::counter::verify_calls();
        let wrong = login(&pool, "test-admin", &WRONG).await;
        let after_wrong = crate::auth::password::counter::verify_calls();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(unknown.unwrap_err(), AppError::InvalidCredentials);
        assert_eq!(wrong.unwrap_err(), AppError::InvalidCredentials);
        assert_eq!(after_unknown - before, 1, "unknown user verify count");
        assert_eq!(
            after_wrong - after_unknown,
            1,
            "wrong password verify count"
        );
    }

    #[tokio::test]
    async fn concurrent_setup_creates_exactly_one_admin() {
        let (pool, dir) = fresh_pool("setup-race").await;
        let mut handles = Vec::new();
        for n in 0..8 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                create_first_admin(&pool, &format!("test-admin-{n}"), None, &PASSWORD).await
            }));
        }
        let mut created = 0;
        let mut conflicts = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => created += 1,
                Err(AppError::Conflict(_)) => conflicts += 1,
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        let count = sqlx::query!(r#"SELECT COUNT(*) AS "n: i64" FROM users"#)
            .fetch_one(&pool)
            .await
            .unwrap()
            .n;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(created, 1, "exactly one setup must win");
        assert_eq!(conflicts, 7);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn setup_is_closed_after_the_first_account() {
        let (pool, dir) = fresh_pool("setup-closed").await;
        create_first_admin(&pool, "test-admin", None, &PASSWORD)
            .await
            .unwrap();
        assert!(!setup_required(&pool).await.unwrap());
        let second = create_first_admin(&pool, "test-second", None, &PASSWORD).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(second, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn first_account_is_an_admin_with_a_local_provider() {
        let (pool, dir) = fresh_pool("setup-role").await;
        create_first_admin(&pool, "test-admin", None, &PASSWORD)
            .await
            .unwrap();
        let row =
            sqlx::query!(r#"SELECT role, auth_provider FROM users WHERE username = 'test-admin'"#)
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(row.role, "admin");
        assert_eq!(row.auth_provider, "local");
    }

    #[tokio::test]
    async fn login_succeeds_with_the_right_password_and_fails_generically_otherwise() {
        let (pool, dir) = fresh_pool("login").await;
        create_first_admin(&pool, "test-admin", None, &PASSWORD)
            .await
            .unwrap();
        let ok = login(&pool, "test-admin", &PASSWORD).await;
        let wrong = login(&pool, "test-admin", &WRONG).await;
        let unknown = login(&pool, "test-nobody", &PASSWORD).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ok.is_ok());
        assert_eq!(wrong.err(), Some(AppError::InvalidCredentials));
        assert_eq!(unknown.err(), Some(AppError::InvalidCredentials));
    }

    #[tokio::test]
    async fn oidc_only_toggle_blocks_regular_users_but_not_admins() {
        let (pool, dir) = fresh_pool("oidc-only").await;
        create_first_admin(&pool, "test-admin", None, &PASSWORD)
            .await
            .unwrap();
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash, role, auth_provider)
             VALUES ('test-user-id', 'test-user', ?, 'user', 'local')",
            "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .execute(&pool)
        .await
        .unwrap();
        // Use a real hash for the regular user so only the toggle can refuse it.
        let real = password::hash_password(&PASSWORD).await.unwrap();
        sqlx::query!(
            "UPDATE users SET password_hash = ? WHERE username = 'test-user'",
            real
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!("INSERT INTO system_config (key, value, is_encrypted) VALUES ('auth.oidc_only_users', 'true', 0)")
            .execute(&pool)
            .await
            .unwrap();
        let user = login(&pool, "test-user", &PASSWORD).await;
        let admin = login(&pool, "test-admin", &PASSWORD).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(user.err(), Some(AppError::InvalidCredentials));
        assert!(admin.is_ok(), "break-glass admin login must stay available");
    }
}
