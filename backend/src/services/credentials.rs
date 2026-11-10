//! Credential CRUD. Tokens are encrypted with AES-256-GCM and bound to their row by
//! AAD, and they are never returned. Sources: `specs/api.md` (Credentials),
//! `specs/database.md` (`user_credentials`), `specs/security.md` (Outbound HTTP).

use serde::Serialize;
use sqlx::SqlitePool;

use crate::auth::crypto::{self, DerivedKey};
use crate::db::credentials::{self as db, CredentialRow, ListFilter};
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::{
    ids,
    pagination::{Page, Pagination},
    time,
};

/// The only `service_type`: `user_credentials` holds GitHub credentials only
/// (`specs/spinoff-local-scan.md`, section 9).
pub const SERVICE_GITHUB: &str = "github";

/// Sort keys the list route accepts. The first is the default.
const SORTS: &[&str] = &["label", "created_at", "expires_at"];

/// Maximum token length in bytes. A bound on input, not a format rule.
const MAX_TOKEN_BYTES: usize = 4096;

/// The `Credential` object (`specs/api.md`). It has no token field.
#[derive(Debug, Serialize)]
pub struct Credential {
    pub id: String,
    pub service_type: String,
    pub label: String,
    pub expires_at: Option<String>,
    pub created_at: Option<String>,
}

/// One item of the list route. The `Credential` fields are flattened in, and
/// `mapping_count` is the number of image sources that use the credential as their GitHub
/// credential (`specs/api.md`, Credentials). Other responses do not carry it.
#[derive(Debug, Serialize)]
pub struct CredentialListItem {
    #[serde(flatten)]
    pub credential: Credential,
    pub mapping_count: i64,
}

/// A create request. `token` is the plaintext secret: it is encrypted on write and
/// dropped. `Debug` is hand-written so the token is never printed.
#[derive(serde::Deserialize)]
pub struct NewCredential {
    #[serde(default = "default_service")]
    pub service_type: String,
    pub label: String,
    pub token: String,
    pub expires_at: Option<i64>,
}

fn default_service() -> String {
    SERVICE_GITHUB.to_owned()
}

impl std::fmt::Debug for NewCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewCredential")
            .field("service_type", &self.service_type)
            .field("label", &self.label)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A partial update. `None` leaves a field unchanged. `token` is the new secret.
#[derive(serde::Deserialize, Default)]
pub struct CredentialPatch {
    pub label: Option<String>,
    pub token: Option<String>,
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for CredentialPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialPatch")
            .field("label", &self.label)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Query parameters for the list route.
#[derive(Debug, Default)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub service_type: Option<String>,
    /// Admin only: list every user's credentials.
    pub all_users: bool,
}

fn validate_label(label: &str) -> Result<(), AppError> {
    if label.trim().is_empty() || label.len() > 200 {
        return Err(AppError::ValidationFailed(
            "label must be 1 to 200 characters.".to_owned(),
        ));
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), AppError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(AppError::ValidationFailed("token is required.".to_owned()));
    }
    Ok(())
}

fn validate_service(service: &str) -> Result<(), AppError> {
    if service != SERVICE_GITHUB {
        return Err(AppError::ValidationFailed(
            "service_type must be github.".to_owned(),
        ));
    }
    Ok(())
}

fn aad_for(id: &str) -> String {
    crypto::aad("user_credentials", "encrypted_token", id)
}

fn encrypt_token(key: &DerivedKey, id: &str, token: &str) -> Result<String, AppError> {
    crypto::encrypt(key, &aad_for(id), token.as_bytes())
}

/// Decrypts the stored token for a server-side call. The result is zeroized on drop
/// and is never returned to a client.
pub fn decrypt_token(
    key: &DerivedKey,
    row: &CredentialRow,
) -> Result<zeroize::Zeroizing<Vec<u8>>, AppError> {
    crypto::decrypt(key, &aad_for(&row.id), &row.encrypted_token)
}

fn to_response(row: CredentialRow) -> Result<Credential, AppError> {
    Ok(Credential {
        id: row.id,
        service_type: row.service_type,
        label: row.label,
        expires_at: row.expires_at.map(time::rfc3339).transpose()?,
        created_at: row.created_at.map(time::rfc3339).transpose()?,
    })
}

/// Creates a credential for `user_id`. Writes `credential.create` in the same
/// transaction.
pub async fn create(
    pool: &SqlitePool,
    key: &DerivedKey,
    actor: &Actor,
    user_id: &str,
    input: NewCredential,
) -> Result<Credential, AppError> {
    validate_service(&input.service_type)?;
    validate_label(&input.label)?;
    validate_token(&input.token)?;
    let id = ids::new_id()?;
    let row = CredentialRow {
        id: id.clone(),
        service_type: SERVICE_GITHUB.to_owned(),
        label: input.label.clone(),
        base_url: None,
        username: None,
        encrypted_token: encrypt_token(key, &id, &input.token)?,
        expires_at: input.expires_at,
        created_at: None,
    };
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    db::insert(&mut tx, &row, user_id).await?;
    audit::record(
        &mut tx,
        actor,
        "credential.create",
        &format!("credential:{id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    let stored = db::find_owned(
        &mut *pool.acquire().await.map_err(|_| AppError::InternalError)?,
        user_id,
        &id,
    )
    .await?
    .ok_or(AppError::InternalError)?;
    to_response(stored)
}

/// Returns one page of credentials, each with its `mapping_count` (image sources). `all_users` is
/// honored only for admins; the route checks the role before calling this.
pub async fn list(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListQuery,
) -> Result<Page<CredentialListItem>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        SORTS,
    )?;
    if let Some(service) = query.service_type.as_deref() {
        validate_service(service)?;
    }
    let scope = if query.all_users { None } else { Some(user_id) };
    let filter = ListFilter {
        user_id: scope,
        service_type: query.service_type.as_deref(),
        sort: &paging.sort,
        sort_sign: if paging.ascending { 1 } else { -1 },
        limit: paging.page_size,
        offset: paging.offset(),
    };
    let rows = db::list_owned(pool, &filter).await?;
    let total = db::count_owned(pool, scope, query.service_type.as_deref()).await?;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let mapping_count = db::mapping_refs(&mut conn, &row.id).await?;
        items.push(CredentialListItem {
            credential: to_response(row)?,
            mapping_count,
        });
    }
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

/// Updates one credential owned by `user_id`. A token change writes `credential.rotate`.
pub async fn update(
    pool: &SqlitePool,
    key: &DerivedKey,
    actor: &Actor,
    user_id: &str,
    id: &str,
    patch: CredentialPatch,
) -> Result<Credential, AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let current = db::find_owned(&mut tx, user_id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut next = current.clone();
    if let Some(label) = patch.label.as_deref() {
        validate_label(label)?;
        next.label = label.to_owned();
    }
    if let Some(expires) = patch.expires_at {
        next.expires_at = Some(expires);
    }
    let mut rotated = false;
    if let Some(token) = patch.token.as_deref() {
        validate_token(token)?;
        next.encrypted_token = encrypt_token(key, id, token)?;
        rotated = true;
    }
    db::update_owned(&mut tx, user_id, &next).await?;
    if rotated {
        audit::record(
            &mut tx,
            actor,
            "credential.rotate",
            &format!("credential:{id}"),
            None,
        )
        .await?;
    }
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    let stored = db::find_owned(
        &mut *pool.acquire().await.map_err(|_| AppError::InternalError)?,
        user_id,
        id,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    to_response(stored)
}

/// Deletes one credential owned by `user_id`. A credential in use returns `409`.
pub async fn delete(
    pool: &SqlitePool,
    actor: &Actor,
    user_id: &str,
    id: &str,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    if db::find_owned(&mut tx, user_id, id).await?.is_none() {
        return Err(AppError::NotFound);
    }
    if db::mapping_refs(&mut tx, id).await? > 0 {
        return Err(AppError::Conflict(
            "this credential is in use by an image source.".to_owned(),
        ));
    }
    let removed = db::delete_owned(&mut tx, user_id, id)
        .await
        .map_err(|err| match err {
            sqlx::Error::Database(_) => {
                AppError::Conflict("this credential is in use by an image source.".to_owned())
            }
            _ => AppError::InternalError,
        })?;
    if removed == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        actor,
        "credential.delete",
        &format!("credential:{id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(())
}

/// Loads one owned credential with its encrypted token, for the test button.
pub async fn load_owned(
    pool: &SqlitePool,
    user_id: &str,
    id: &str,
) -> Result<CredentialRow, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    db::find_owned(&mut conn, user_id, id)
        .await?
        .ok_or(AppError::NotFound)
}

#[cfg(test)]
mod tests {
    fn runtime_password() -> String {
        format!("test-{}", "password-fifteen")
    }

    use super::*;
    use crate::auth::crypto::{self as crypto_mod, DerivedKey};
    use crate::config;
    use crate::models::role::Role;
    use crate::services::users as user_service;

    // Test values only. The root key and the secrets are obviously fake.
    const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const TOKEN: &str = "test-github-secret-value";

    fn key() -> DerivedKey {
        let root = config::parse_encryption_key(ROOT).unwrap();
        crypto_mod::credentials_key(&root).unwrap()
    }

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("harborgate-creds-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        (pool, dir)
    }

    fn actor(id: &str) -> Actor {
        Actor {
            user_id: Some(id.to_owned()),
            username: format!("name-{id}"),
        }
    }

    async fn user(pool: &SqlitePool, name: &str) -> String {
        user_service::create_local(
            pool,
            &Actor::cli(),
            name,
            None,
            &runtime_password(),
            Role::User,
        )
        .await
        .unwrap()
    }

    fn github(label: &str) -> NewCredential {
        NewCredential {
            service_type: SERVICE_GITHUB.to_owned(),
            label: label.to_owned(),
            token: TOKEN.to_owned(),
            expires_at: None,
        }
    }

    #[test]
    fn debug_output_hides_the_token() {
        let input = github("label");
        assert!(!format!("{input:?}").contains(TOKEN));
        let patch = CredentialPatch {
            token: Some(TOKEN.to_owned()),
            ..CredentialPatch::default()
        };
        assert!(!format!("{patch:?}").contains(TOKEN));
    }

    #[tokio::test]
    async fn only_github_credentials_are_accepted() {
        let (pool, dir) = fresh_pool("service").await;
        let owner = user(&pool, "owner").await;
        let mut input = github("x");
        input.service_type = "harbor".to_owned();
        assert!(matches!(
            create(&pool, &key(), &actor(&owner), &owner, input).await,
            Err(AppError::ValidationFailed(_))
        ));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn create_stores_only_ciphertext_and_returns_no_token() {
        let (pool, dir) = fresh_pool("create").await;
        let owner = user(&pool, "owner").await;
        let created = create(&pool, &key(), &actor(&owner), &owner, github("primary"))
            .await
            .unwrap();
        let json = serde_json::to_string(&created).unwrap();
        assert!(!json.contains(TOKEN));
        let row = load_owned(&pool, &owner, &created.id).await.unwrap();
        assert!(row.encrypted_token.starts_with("v1:"));
        assert!(!row.encrypted_token.contains(TOKEN));
        let plain = decrypt_token(&key(), &row).unwrap();
        assert_eq!(plain.as_slice(), TOKEN.as_bytes());
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn another_user_gets_not_found_for_read_update_and_delete() {
        let (pool, dir) = fresh_pool("tenancy").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let created = create(&pool, &key(), &actor(&owner), &owner, github("mine"))
            .await
            .unwrap();
        assert!(matches!(
            load_owned(&pool, &other, &created.id).await,
            Err(AppError::NotFound)
        ));
        let patch = CredentialPatch {
            label: Some("stolen".to_owned()),
            ..CredentialPatch::default()
        };
        assert!(matches!(
            update(&pool, &key(), &actor(&other), &other, &created.id, patch).await,
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            delete(&pool, &actor(&other), &other, &created.id).await,
            Err(AppError::NotFound)
        ));
        let page = list(&pool, &other, &ListQuery::default()).await.unwrap();
        assert_eq!(page.total, 0);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn token_change_rotates_and_writes_audit() {
        let (pool, dir) = fresh_pool("rotate").await;
        let owner = user(&pool, "owner").await;
        let created = create(&pool, &key(), &actor(&owner), &owner, github("r"))
            .await
            .unwrap();
        let patch = CredentialPatch {
            token: Some("test-new-secret".to_owned()),
            ..CredentialPatch::default()
        };
        update(&pool, &key(), &actor(&owner), &owner, &created.id, patch)
            .await
            .unwrap();
        let row = load_owned(&pool, &owner, &created.id).await.unwrap();
        let plain = decrypt_token(&key(), &row).unwrap();
        assert_eq!(plain.as_slice(), b"test-new-secret");
        let rotated: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'credential.rotate'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rotated, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Inserts an image source that uses `github_cred`. The source table replaces the
    /// mapping table as the credential's user (`specs/spinoff-local-scan.md`, section 9).
    async fn insert_source(pool: &SqlitePool, id: &str, owner: &str, github_cred: &str) {
        sqlx::query(
            "INSERT INTO image_sources
                (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES (?, ?, 'hub-default-ghcr', ?, '*', ?, 'o', 'g')",
        )
        .bind(id)
        .bind(owner)
        .bind(format!("team/{id}"))
        .bind(github_cred)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delete_of_a_credential_in_use_returns_conflict() {
        let (pool, dir) = fresh_pool("delete-conflict").await;
        let owner = user(&pool, "owner").await;
        let cred = create(&pool, &key(), &actor(&owner), &owner, github("gh"))
            .await
            .unwrap();
        insert_source(&pool, "s1", &owner, &cred.id).await;
        assert!(matches!(
            delete(&pool, &actor(&owner), &owner, &cred.id).await,
            Err(AppError::Conflict(_))
        ));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_pages_and_filters_by_service_type() {
        let (pool, dir) = fresh_pool("list").await;
        let owner = user(&pool, "owner").await;
        for label in ["b", "a", "c"] {
            create(&pool, &key(), &actor(&owner), &owner, github(label))
                .await
                .unwrap();
        }
        let query = ListQuery {
            page_size: Some(2),
            sort: Some("label".to_owned()),
            order: Some("asc".to_owned()),
            ..ListQuery::default()
        };
        let page = list(&pool, &owner, &query).await.unwrap();
        assert_eq!(page.total, 3);
        let labels: Vec<&str> = page
            .items
            .iter()
            .map(|c| c.credential.label.as_str())
            .collect();
        assert_eq!(labels, vec!["a", "b"]);
        let github_only = ListQuery {
            service_type: Some(SERVICE_GITHUB.to_owned()),
            ..ListQuery::default()
        };
        assert_eq!(list(&pool, &owner, &github_only).await.unwrap().total, 3);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_counts_image_sources_per_credential() {
        let (pool, dir) = fresh_pool("source-count").await;
        let owner = user(&pool, "owner").await;
        let used = create(&pool, &key(), &actor(&owner), &owner, github("used"))
            .await
            .unwrap();
        let second = create(&pool, &key(), &actor(&owner), &owner, github("second"))
            .await
            .unwrap();
        let unused = create(&pool, &key(), &actor(&owner), &owner, github("unused"))
            .await
            .unwrap();
        insert_source(&pool, "s1", &owner, &used.id).await;
        insert_source(&pool, "s2", &owner, &used.id).await;
        insert_source(&pool, "s3", &owner, &second.id).await;
        let page = list(&pool, &owner, &ListQuery::default()).await.unwrap();
        let count_of = |id: &str| -> i64 {
            page.items
                .iter()
                .find(|item| item.credential.id == id)
                .map(|item| item.mapping_count)
                .unwrap()
        };
        assert_eq!(count_of(&used.id), 2);
        assert_eq!(count_of(&second.id), 1);
        assert_eq!(count_of(&unused.id), 0);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
