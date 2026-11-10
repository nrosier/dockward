//! Admin user management: create local users, delete, and change roles. Rules are in
//! `specs/api.md` (Admin) and `specs/security.md` (Authentication). Each change
//! and its audit row run in one transaction, so a failed audit write rolls back the
//! change. The last-local-admin check and its write share a transaction, so two
//! concurrent demotions cannot both succeed.

use sqlx::SqlitePool;

use crate::auth::password;
use crate::db::users;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::{self, Actor};
use crate::services::{auth as local_auth, ids};

/// Creates a local user. Local accounts only: OIDC accounts are created by login.
/// `POST /api/v1/admin/users` returns `409` when the username is taken.
pub async fn create_local(
    pool: &SqlitePool,
    actor: &Actor,
    username: &str,
    email: Option<&str>,
    password_plain: &str,
    role: Role,
) -> Result<String, AppError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(AppError::ValidationFailed(
            "Username is required.".to_owned(),
        ));
    }
    local_auth::check_password_length(password_plain)?;
    let hash = password::hash_password(password_plain).await?;
    let id = ids::new_id()?;

    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    if users::find_by_username_tx(&mut tx, username)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "That username is already taken.".to_owned(),
        ));
    }
    users::insert_local(&mut tx, &id, username, email, &hash, role.as_str()).await?;
    audit::record(
        &mut tx,
        actor,
        "user.create",
        &format!("user:{id}"),
        Some(&serde_json::json!({"role": role.as_str()})),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(id)
}

/// Deletes a user in the order from `specs/database.md`: mappings, then credentials,
/// then the user row, all in one transaction. The rules are checked first:
/// - an admin cannot delete themselves (`409`);
/// - the last local admin cannot be deleted (`409`).
///
/// Returns the ids of the credentials that were deleted.
pub async fn delete_user(
    pool: &SqlitePool,
    actor: &Actor,
    user_id: &str,
) -> Result<Vec<String>, AppError> {
    if actor.user_id.as_deref() == Some(user_id) {
        return Err(AppError::Conflict(
            "You cannot delete your own account.".to_owned(),
        ));
    }
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let Some((role, provider, username)) = users::role_and_provider(&mut tx, user_id).await? else {
        return Err(AppError::NotFound);
    };
    if role == "admin" && provider == "local" && users::count_local_admins(&mut tx).await? <= 1 {
        return Err(AppError::Conflict(
            "The last local admin cannot be deleted.".to_owned(),
        ));
    }
    users::delete_mappings(&mut tx, user_id).await?;
    let credential_ids = users::credential_ids(&mut tx, user_id).await?;
    users::delete_credentials(&mut tx, user_id).await?;
    if users::delete_user_row(&mut tx, user_id).await? == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        actor,
        "user.delete",
        &format!("user:{user_id}"),
        Some(&serde_json::json!({"username": username, "role": role})),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(credential_ids)
}

/// Changes a local user's role. OIDC users' roles come only from the group claim, so
/// this returns `409` for them. The last local admin cannot be demoted (`409`).
pub async fn change_role(
    pool: &SqlitePool,
    actor: &Actor,
    user_id: &str,
    new_role: Role,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let Some((old_role, provider, username)) = users::role_and_provider(&mut tx, user_id).await?
    else {
        return Err(AppError::NotFound);
    };
    if provider != "local" {
        return Err(AppError::Conflict(
            "An OIDC user's role comes from the identity provider.".to_owned(),
        ));
    }
    if old_role == new_role.as_str() {
        return Ok(());
    }
    if old_role == "admin"
        && new_role == Role::User
        && users::count_local_admins(&mut tx).await? <= 1
    {
        return Err(AppError::Conflict(
            "The last local admin cannot be demoted.".to_owned(),
        ));
    }
    users::update_role(&mut tx, user_id, new_role.as_str()).await?;
    audit::record(
        &mut tx,
        actor,
        "user.role_change",
        &format!("user:{user_id}"),
        Some(&serde_json::json!({"username": username, "from": old_role, "to": new_role.as_str()})),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(())
}

/// Lists local and OIDC users, paged.
pub async fn list(pool: &SqlitePool) -> Result<Vec<users::UserRow>, AppError> {
    users::list_all(pool).await
}

/// Parses a role string from the API. Anything outside `admin` and `user` is a `422`.
pub fn parse_role(text: &str) -> Result<Role, AppError> {
    Role::parse(text)
        .ok_or_else(|| AppError::ValidationFailed("role must be admin or user.".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::UserRow;

    // Test values only. Passwords are obviously fake.
    fn password() -> String {
        format!(
            "pw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        )
    }

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("dockward-users-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        (pool, dir)
    }

    fn actor(id: &str, name: &str) -> Actor {
        Actor {
            user_id: Some(id.to_owned()),
            username: name.to_owned(),
        }
    }

    async fn role_of(pool: &SqlitePool, id: &str) -> String {
        let row: UserRow = crate::db::users::find_by_id(pool, id)
            .await
            .unwrap()
            .unwrap();
        row.role
    }

    async fn audit_actions(pool: &SqlitePool) -> Vec<String> {
        sqlx::query_scalar!("SELECT action FROM audit_log ORDER BY action")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    /// Seeds one local admin `a1` and returns its id.
    async fn seed_admin(pool: &SqlitePool) -> String {
        create_local(
            pool,
            &Actor::cli(),
            "test-admin",
            None,
            &password(),
            Role::Admin,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn last_local_admin_cannot_be_deleted_or_demoted() {
        let (pool, dir) = fresh_pool("last-admin").await;
        let admin = seed_admin(&pool).await;
        let other = actor("someone-else", "test-other");
        let delete = delete_user(&pool, &other, &admin).await;
        let demote = change_role(&pool, &other, &admin, Role::User).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(delete, Err(AppError::Conflict(_))),
            "last admin deleted: {delete:?}"
        );
        assert!(
            matches!(demote, Err(AppError::Conflict(_))),
            "last admin demoted: {demote:?}"
        );
    }

    #[tokio::test]
    async fn admin_cannot_delete_themselves() {
        let (pool, dir) = fresh_pool("self-delete").await;
        let admin = seed_admin(&pool).await;
        create_local(
            &pool,
            &Actor::cli(),
            "test-admin-two",
            None,
            &password(),
            Role::Admin,
        )
        .await
        .unwrap();
        let me = actor(&admin, "test-admin");
        let result = delete_user(&pool, &me, &admin).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn demoting_one_of_two_admins_is_allowed() {
        let (pool, dir) = fresh_pool("two-admins").await;
        let first = seed_admin(&pool).await;
        let second = create_local(
            &pool,
            &Actor::cli(),
            "test-admin-two",
            None,
            &password(),
            Role::Admin,
        )
        .await
        .unwrap();
        let result = change_role(&pool, &actor(&first, "test-admin"), &second, Role::User).await;
        let demoted_role = role_of(&pool, &second).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_ok());
        assert_eq!(demoted_role, "user");
    }

    #[tokio::test]
    async fn oidc_user_role_change_is_a_conflict() {
        let (pool, dir) = fresh_pool("oidc-role").await;
        let admin = seed_admin(&pool).await;
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider, oidc_issuer, oidc_subject)
             VALUES ('test-oidc-id', 'test-oidc', 'user', 'oidc', 'https://idp.example.test', 'test-sub')"
        )
        .execute(&pool)
        .await
        .unwrap();
        let result = change_role(
            &pool,
            &actor(&admin, "test-admin"),
            "test-oidc-id",
            Role::Admin,
        )
        .await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn create_local_rejects_duplicate_username_and_short_password() {
        let (pool, dir) = fresh_pool("create").await;
        let admin = seed_admin(&pool).await;
        let duplicate = create_local(
            &pool,
            &actor(&admin, "test-admin"),
            "test-admin",
            None,
            &password(),
            Role::User,
        )
        .await;
        let short = create_local(
            &pool,
            &actor(&admin, "test-admin"),
            "test-new",
            None,
            "short",
            Role::User,
        )
        .await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(duplicate, Err(AppError::Conflict(_))));
        assert_eq!(short.err(), Some(AppError::PasswordTooShort));
    }

    #[tokio::test]
    async fn deleting_a_user_with_mappings_and_acceptances_removes_their_data_and_keeps_attribution()
     {
        let (pool, dir) = fresh_pool("delete-owner").await;
        let admin = seed_admin(&pool).await;
        let victim = create_local(
            &pool,
            &actor(&admin, "test-admin"),
            "test-victim",
            None,
            &password(),
            Role::User,
        )
        .await
        .unwrap();
        // The victim owns a GitHub credential, a source that uses it, and an acceptance on that source.
        sqlx::query!(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('test-cred-g', ?, 'g', 'v1:test')",
            victim
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id,
                github_owner, github_repo)
             VALUES ('test-src', ?, 'hub-default-ghcr', 'o/walley', 'latest', 'test-cred-g', 'o', 'repo')",
            victim
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username)
             VALUES ('test-acc', 'test-src', 'CVE-2099-0001', 'test reason', ?, 'test-victim')",
            victim
        )
        .execute(&pool)
        .await
        .unwrap();

        let result = delete_user(&pool, &actor(&admin, "test-admin"), &victim).await;
        let sources = sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n: i64" FROM image_sources"#)
            .fetch_one(&pool)
            .await
            .unwrap();
        let creds = sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n: i64" FROM user_credentials"#)
            .fetch_one(&pool)
            .await
            .unwrap();
        // The acceptance is on the victim's source, so the source cascade removes it.
        let acceptances =
            sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n: i64" FROM cve_acceptances"#)
                .fetch_one(&pool)
                .await
                .unwrap();
        let actions = audit_actions(&pool).await;
        // The delete audit row keeps the victim's username snapshot after the user row is gone.
        let delete_row = sqlx::query!(
            "SELECT actor_username, target FROM audit_log WHERE action = 'user.delete'"
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_ok(), "delete failed: {result:?}");
        // The ids come back so the handler can drop each credential's picker cache.
        let mut deleted = result.unwrap_or_default();
        deleted.sort();
        assert_eq!(deleted, ["test-cred-g"]);
        assert_eq!(sources, 0);
        assert_eq!(creds, 0);
        assert_eq!(acceptances, 0);
        assert_eq!(delete_row.actor_username, "test-admin");
        assert_eq!(delete_row.target, format!("user:{victim}"));
        assert!(actions.contains(&"user.delete".to_owned()));
    }

    #[tokio::test]
    async fn changes_are_audited() {
        let (pool, dir) = fresh_pool("audited").await;
        let admin = seed_admin(&pool).await;
        let second = create_local(
            &pool,
            &actor(&admin, "test-admin"),
            "test-second",
            None,
            &password(),
            Role::User,
        )
        .await
        .unwrap();
        change_role(&pool, &actor(&admin, "test-admin"), &second, Role::Admin)
            .await
            .unwrap();
        let actions = audit_actions(&pool).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(actions.contains(&"user.create".to_owned()));
        assert!(actions.contains(&"user.role_change".to_owned()));
    }
}
