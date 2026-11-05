//! Project webhook management (#132): create, owner-only rotation, read, the unmatched list,
//! and the owner transfer on user deletion. Sources: `specs/api.md` (Project webhooks),
//! `specs/integrations.md` (Project webhook, one per Harbor project), `specs/security.md`
//! (Tenancy).
//!
//! The project token and secret are made like the mapping values (`mappings::new_secret`)
//! and only their SHA-256 digests are stored. They are returned once, at create and at
//! rotation. Every write and its audit row share one transaction.

use serde::Serialize;
use sqlx::{SqliteConnection, SqlitePool};

use crate::db::mappings as mapping_db;
use crate::db::project_webhooks::{self as db, NewProjectWebhook, ProjectWebhookRow};
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::{self, Actor};
use crate::services::mappings::{digest, new_secret};
use crate::services::pagination::{Page, Pagination};
use crate::services::sessions::AuthUser;
use crate::services::{ids, time};

/// Sort keys the unmatched list accepts. The first is the default (newest first).
const UNMATCHED_SORTS: &[&str] = &["last_seen_at", "count", "repository"];

/// The `ProjectWebhook` object with `mappings` (`specs/api.md`). It never has the URL, the
/// token, or the secret. `mappings` holds Harbor repository names only.
#[derive(Debug, Serialize)]
pub struct ProjectWebhook {
    pub id: String,
    pub harbor_base_url: String,
    pub harbor_project: String,
    pub owner: String,
    pub created_at: Option<String>,
    pub rotated_at: Option<String>,
    pub mappings: Vec<String>,
}

/// The create response. `webhook_url` and `auth_secret` are shown once.
#[derive(Serialize)]
pub struct Created {
    pub id: String,
    pub webhook_url: String,
    pub auth_secret: String,
}

impl std::fmt::Debug for Created {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Created")
            .field("id", &self.id)
            .field("webhook_url", &"<redacted>")
            .field("auth_secret", &"<redacted>")
            .finish()
    }
}

/// The token rotation response. `webhook_url` is shown once.
#[derive(Serialize)]
pub struct TokenRotated {
    pub webhook_url: String,
    pub mappings: Vec<String>,
}

impl std::fmt::Debug for TokenRotated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRotated")
            .field("webhook_url", &"<redacted>")
            .field("mappings", &self.mappings)
            .finish()
    }
}

/// The secret rotation response. `auth_secret` is shown once.
#[derive(Serialize)]
pub struct SecretRotated {
    pub auth_secret: String,
    pub mappings: Vec<String>,
}

impl std::fmt::Debug for SecretRotated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRotated")
            .field("auth_secret", &"<redacted>")
            .field("mappings", &self.mappings)
            .finish()
    }
}

/// One unmatched-event count, as the API returns it.
#[derive(Debug, Serialize)]
pub struct Unmatched {
    pub repository: String,
    pub count: i64,
    pub last_seen_at: String,
}

/// Paging values for the unmatched list.
#[derive(Debug, Default)]
pub struct UnmatchedQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

/// The project webhook URL for a token. The base is `HARBORGATE_PUBLIC_URL`, never the
/// request's `Host` header.
pub fn project_webhook_url(public_url: &str, token: &str) -> String {
    format!(
        "{}/api/v1/webhooks/harbor/project/{token}",
        public_url.trim_end_matches('/')
    )
}

fn actor_of(user: &AuthUser) -> Actor {
    Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    }
}

fn target_of(id: &str) -> String {
    format!("project_webhook:{id}")
}

/// Loads a project webhook for a read: the owner or an admin. Unknown is `404`, any other
/// user is `403` (`specs/api.md`).
async fn load_readable(
    conn: &mut SqliteConnection,
    user: &AuthUser,
    id: &str,
) -> Result<ProjectWebhookRow, AppError> {
    let row = db::find_by_id(conn, id).await?.ok_or(AppError::NotFound)?;
    if row.user_id != user.id && user.role != Role::Admin {
        return Err(AppError::Forbidden);
    }
    Ok(row)
}

/// Loads a project webhook for a rotation: the owner only. Admins get `403` too.
async fn load_owned(
    conn: &mut SqliteConnection,
    user: &AuthUser,
    id: &str,
) -> Result<ProjectWebhookRow, AppError> {
    let row = db::find_by_id(conn, id).await?.ok_or(AppError::NotFound)?;
    if row.user_id != user.id {
        return Err(AppError::Forbidden);
    }
    Ok(row)
}

fn conflict() -> AppError {
    AppError::Conflict("this Harbor project already has a project webhook.".to_owned())
}

/// Creates the project webhook for the Harbor base URL and project of `mapping_id`. The
/// caller must own that mapping (`404` otherwise). A project webhook that already exists for
/// that base URL and project is `409`. Writes `project_webhook.create`.
pub async fn create(
    pool: &SqlitePool,
    user: &AuthUser,
    public_url: &str,
    mapping_id: &str,
) -> Result<Created, AppError> {
    let id = ids::new_id()?;
    let token = new_secret()?;
    let secret = new_secret()?;
    let token_hash = digest(&token);
    let secret_hash = digest(&secret);

    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let mapping = mapping_db::find_owned(&mut tx, &user.id, mapping_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if db::find_by_project(&mut tx, &mapping.harbor_base_url, &mapping.harbor_project)
        .await?
        .is_some()
    {
        return Err(conflict());
    }
    db::insert(
        &mut tx,
        &NewProjectWebhook {
            id: &id,
            user_id: &user.id,
            harbor_base_url: &mapping.harbor_base_url,
            harbor_project: &mapping.harbor_project,
            token_hash: &token_hash,
            secret_hash: &secret_hash,
        },
    )
    .await
    .map_err(|err| match err {
        // A concurrent create for the same project lost the race: the same `409`.
        sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => conflict(),
        _ => AppError::InternalError,
    })?;
    audit::record(
        &mut tx,
        &actor_of(user),
        "project_webhook.create",
        &target_of(&id),
        Some(&serde_json::json!({ "mapping_id": mapping_id })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(Created {
        id,
        webhook_url: project_webhook_url(public_url, &token),
        // The value Harbor sends as the Authorization header, ready to paste, as for mappings.
        auth_secret: format!("Bearer {secret}"),
    })
}

/// Rotates the project token. Owner only (`403` for anyone else, admins included). The old
/// token stops working at once, because only the new digest is stored. Writes
/// `project_webhook.token_rotate`.
pub async fn rotate_token(
    pool: &SqlitePool,
    user: &AuthUser,
    public_url: &str,
    id: &str,
) -> Result<TokenRotated, AppError> {
    let token = new_secret()?;
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let row = load_owned(&mut tx, user, id).await?;
    if db::set_token_hash(&mut tx, id, &digest(&token), crate::worker::now_secs()).await? == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &actor_of(user),
        "project_webhook.token_rotate",
        &target_of(id),
        None,
    )
    .await?;
    let mappings =
        db::mapping_repositories(&mut tx, &row.harbor_base_url, &row.harbor_project).await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(TokenRotated {
        webhook_url: project_webhook_url(public_url, &token),
        mappings,
    })
}

/// Rotates the project secret. Owner only, as [`rotate_token`]. Writes
/// `project_webhook.secret_rotate`.
pub async fn rotate_secret(
    pool: &SqlitePool,
    user: &AuthUser,
    id: &str,
) -> Result<SecretRotated, AppError> {
    let secret = new_secret()?;
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let row = load_owned(&mut tx, user, id).await?;
    if db::set_secret_hash(&mut tx, id, &digest(&secret), crate::worker::now_secs()).await? == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &actor_of(user),
        "project_webhook.secret_rotate",
        &target_of(id),
        None,
    )
    .await?;
    let mappings =
        db::mapping_repositories(&mut tx, &row.harbor_base_url, &row.harbor_project).await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(SecretRotated {
        auth_secret: format!("Bearer {secret}"),
        mappings,
    })
}

/// Reads one project webhook with its mapping repository names. Owner or admin.
pub async fn get(pool: &SqlitePool, user: &AuthUser, id: &str) -> Result<ProjectWebhook, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let row = load_readable(&mut conn, user, id).await?;
    let mappings =
        db::mapping_repositories(&mut conn, &row.harbor_base_url, &row.harbor_project).await?;
    Ok(ProjectWebhook {
        id: row.id,
        harbor_base_url: row.harbor_base_url,
        harbor_project: row.harbor_project,
        owner: row.owner_username,
        created_at: row.created_at.map(time::rfc3339).transpose()?,
        rotated_at: row.rotated_at.map(time::rfc3339).transpose()?,
        mappings,
    })
}

/// One page of unmatched-event counts. Owner or admin. Rows whose repository now has a
/// mapping on the project are hidden. Default order: `last_seen_at`, newest first.
pub async fn unmatched(
    pool: &SqlitePool,
    user: &AuthUser,
    id: &str,
    query: &UnmatchedQuery,
) -> Result<Page<Unmatched>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        UNMATCHED_SORTS,
    )?;
    {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        load_readable(&mut conn, user, id).await?;
    }
    let filter = db::UnmatchedFilter {
        project_webhook_id: id,
        sort: &paging.sort,
        sort_sign: if paging.ascending { 1 } else { -1 },
        limit: paging.page_size,
        offset: paging.offset(),
    };
    let rows = db::list_unmatched(pool, &filter).await?;
    let total = db::count_unmatched(pool, id).await?;
    let items = rows
        .into_iter()
        .map(|row| {
            Ok(Unmatched {
                repository: row.repository,
                count: row.count,
                last_seen_at: time::rfc3339(row.last_seen_at)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

/// The user-deletion hook (`specs/integrations.md`, Owner account deleted). Run inside the
/// deletion transaction, before the `users` row is deleted. Each project webhook the user
/// owns moves to another user with a mapping on the same Harbor base URL and project, and
/// the move writes `project_webhook.owner_transfer`. A project webhook with no candidate is
/// left in place, so the `ON DELETE CASCADE` on `project_webhooks.user_id` deletes it with
/// the user row (and its unmatched counts with it). Returns the ids left to the cascade.
pub async fn transfer_on_user_delete(
    conn: &mut SqliteConnection,
    actor: &Actor,
    user_id: &str,
) -> Result<Vec<String>, AppError> {
    let mut dropped = Vec::new();
    for project in db::owned_by(conn, user_id).await? {
        let candidate = db::transfer_candidate(
            conn,
            &project.harbor_base_url,
            &project.harbor_project,
            user_id,
        )
        .await?;
        let Some(new_owner) = candidate else {
            dropped.push(project.id);
            continue;
        };
        if db::set_owner(conn, &project.id, &new_owner).await? == 0 {
            return Err(AppError::InternalError);
        }
        audit::record(
            conn,
            actor,
            "project_webhook.owner_transfer",
            &target_of(&project.id),
            Some(&serde_json::json!({
                "from_user_id": user_id,
                "to_user_id": new_owner,
            })),
        )
        .await?;
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::harbor_webhook::secret_matches;

    const BASE: &str = "https://harbor.example.com";

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "harborgate-project-webhooks-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        (pool, dir)
    }

    fn user(id: &str, role: Role) -> AuthUser {
        AuthUser {
            id: id.to_owned(),
            username: format!("name-{id}"),
            role,
        }
    }

    /// A user with a Harbor and a GitHub credential. Test values only.
    async fn add_user(pool: &SqlitePool, id: &str, role: &str) {
        sqlx::query("INSERT INTO users (id, username, role, token_version) VALUES (?, ?, ?, 0)")
            .bind(id)
            .bind(format!("name-{id}"))
            .bind(role)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES (?, ?, 'harbor', 'h', ?, 'robot$hg', 'v1:fake'),
                    (?, ?, 'github', 'g', NULL, NULL, 'v1:fake')",
        )
        .bind(format!("{id}-h"))
        .bind(id)
        .bind(BASE)
        .bind(format!("{id}-g"))
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn add_mapping(pool: &SqlitePool, id: &str, owner: &str, project: &str, repo: &str) {
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'o', ?, ?, ?)",
        )
        .bind(id)
        .bind(owner)
        .bind(format!("{owner}-h"))
        .bind(format!("{owner}-g"))
        .bind(BASE)
        .bind(project)
        .bind(repo)
        .bind(id)
        .bind(format!("t-{id}"))
        .bind(format!("s-{id}"))
        .execute(pool)
        .await
        .unwrap();
    }

    async fn stored_hashes(pool: &SqlitePool, id: &str) -> (String, String) {
        sqlx::query_as("SELECT token_hash, secret_hash FROM project_webhooks WHERE id = ?")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn audit_rows(pool: &SqlitePool, action: &str) -> Vec<(String, Option<String>)> {
        sqlx::query_as("SELECT target, details FROM audit_log WHERE action = ? ORDER BY rowid")
            .bind(action)
            .fetch_all(pool)
            .await
            .unwrap()
    }

    fn token_of(url: &str) -> &str {
        url.rsplit('/').next().unwrap()
    }

    #[tokio::test]
    async fn create_stores_digests_and_shows_values_once() {
        let (pool, dir) = fresh_pool("create").await;
        add_user(&pool, "u1", "user").await;
        add_mapping(&pool, "m1", "u1", "proj", "app").await;
        let created = create(
            &pool,
            &user("u1", Role::User),
            "https://hg.example.com/",
            "m1",
        )
        .await
        .unwrap();
        assert!(
            created
                .webhook_url
                .starts_with("https://hg.example.com/api/v1/webhooks/harbor/project/")
        );
        let token = token_of(&created.webhook_url);
        assert!(token.len() >= 43, "token shorter than 256 bits");
        let (token_hash, secret_hash) = stored_hashes(&pool, &created.id).await;
        assert_eq!(token_hash, digest(token));
        assert!(secret_matches(&secret_hash, Some(&created.auth_secret)));
        let rotated: Option<i64> =
            sqlx::query_scalar("SELECT rotated_at FROM project_webhooks WHERE id = ?")
                .bind(&created.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rotated, None);
        let debug = format!("{created:?}");
        assert!(!debug.contains(token) && debug.contains("<redacted>"));

        let rows = audit_rows(&pool, "project_webhook.create").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, format!("project_webhook:{}", created.id));
        let details = rows[0].1.clone().unwrap();
        assert!(!details.contains(token));
        assert!(details.contains("m1"));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn create_refuses_a_duplicate_project_and_an_unowned_mapping() {
        let (pool, dir) = fresh_pool("create-refused").await;
        add_user(&pool, "u1", "user").await;
        add_user(&pool, "u2", "user").await;
        add_user(&pool, "adm", "admin").await;
        add_mapping(&pool, "m1", "u1", "proj", "app").await;
        add_mapping(&pool, "m2", "u2", "proj", "other").await;
        create(&pool, &user("u1", Role::User), "https://hg", "m1")
            .await
            .unwrap();
        // Same project from another user's own mapping: 409.
        let dup = create(&pool, &user("u2", Role::User), "https://hg", "m2").await;
        assert!(matches!(dup, Err(AppError::Conflict(_))), "{dup:?}");
        // Another user's mapping, an admin, and an unknown id: 404.
        let foreign = create(&pool, &user("u2", Role::User), "https://hg", "m1").await;
        let admin = create(&pool, &user("adm", Role::Admin), "https://hg", "m1").await;
        let missing = create(&pool, &user("u1", Role::User), "https://hg", "nope").await;
        assert!(matches!(foreign, Err(AppError::NotFound)));
        assert!(matches!(admin, Err(AppError::NotFound)));
        assert!(matches!(missing, Err(AppError::NotFound)));
        assert_eq!(audit_rows(&pool, "project_webhook.create").await.len(), 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn owner_rotation_replaces_values_and_lists_affected_mappings() {
        let (pool, dir) = fresh_pool("rotate").await;
        add_user(&pool, "u1", "user").await;
        add_user(&pool, "u2", "user").await;
        add_mapping(&pool, "m1", "u1", "proj", "app").await;
        add_mapping(&pool, "m2", "u2", "proj", "other").await;
        add_mapping(&pool, "m3", "u1", "elsewhere", "skip").await;
        let owner = user("u1", Role::User);
        let created = create(&pool, &owner, "https://hg", "m1").await.unwrap();
        let old_token = token_of(&created.webhook_url).to_owned();

        let rotated = rotate_token(&pool, &owner, "https://hg", &created.id)
            .await
            .unwrap();
        assert_eq!(rotated.mappings, vec!["app".to_owned(), "other".to_owned()]);
        let new_token = token_of(&rotated.webhook_url).to_owned();
        assert_ne!(new_token, old_token);
        let (token_hash, _) = stored_hashes(&pool, &created.id).await;
        assert_eq!(token_hash, digest(&new_token));
        assert!(
            db::find_by_token_hash(&pool, &digest(&old_token))
                .await
                .unwrap()
                .is_none(),
            "old token still resolves"
        );

        let secret = rotate_secret(&pool, &owner, &created.id).await.unwrap();
        assert_eq!(secret.mappings, vec!["app".to_owned(), "other".to_owned()]);
        let (_, secret_hash) = stored_hashes(&pool, &created.id).await;
        assert!(secret_matches(&secret_hash, Some(&secret.auth_secret)));
        assert!(!secret_matches(&secret_hash, Some(&created.auth_secret)));
        assert!(!format!("{secret:?}").contains(&secret.auth_secret));
        assert!(!format!("{rotated:?}").contains(&new_token));

        let read = get(&pool, &owner, &created.id).await.unwrap();
        assert!(read.rotated_at.is_some());
        assert_eq!(
            audit_rows(&pool, "project_webhook.token_rotate").await,
            vec![(format!("project_webhook:{}", created.id), None)]
        );
        assert_eq!(
            audit_rows(&pool, "project_webhook.secret_rotate")
                .await
                .len(),
            1
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn non_owner_and_admin_cannot_rotate_but_admin_can_read() {
        let (pool, dir) = fresh_pool("rotate-refused").await;
        add_user(&pool, "u1", "user").await;
        add_user(&pool, "u2", "user").await;
        add_user(&pool, "adm", "admin").await;
        add_mapping(&pool, "m1", "u1", "proj", "app").await;
        add_mapping(&pool, "m2", "u2", "proj", "other").await;
        let created = create(&pool, &user("u1", Role::User), "https://hg", "m1")
            .await
            .unwrap();
        let before = stored_hashes(&pool, &created.id).await;
        for caller in [user("u2", Role::User), user("adm", Role::Admin)] {
            let token = rotate_token(&pool, &caller, "https://hg", &created.id).await;
            let secret = rotate_secret(&pool, &caller, &created.id).await;
            assert!(matches!(token, Err(AppError::Forbidden)), "{token:?}");
            assert!(matches!(secret, Err(AppError::Forbidden)), "{secret:?}");
        }
        assert_eq!(stored_hashes(&pool, &created.id).await, before);
        assert!(
            audit_rows(&pool, "project_webhook.token_rotate")
                .await
                .is_empty()
        );
        let missing = rotate_token(&pool, &user("u1", Role::User), "https://hg", "nope").await;
        assert!(matches!(missing, Err(AppError::NotFound)));

        // A mapping owner on the project who is not the webhook owner may not read it.
        let other = get(&pool, &user("u2", Role::User), &created.id).await;
        assert!(matches!(other, Err(AppError::Forbidden)));
        let read = get(&pool, &user("adm", Role::Admin), &created.id)
            .await
            .unwrap();
        assert_eq!(read.owner, "name-u1");
        assert_eq!(read.mappings, vec!["app".to_owned(), "other".to_owned()]);
        assert!(read.rotated_at.is_none());
        let json = serde_json::to_value(&read).unwrap();
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        for absent in [
            "webhook_url",
            "auth_secret",
            "token_hash",
            "secret_hash",
            "user_id",
        ] {
            assert!(!keys.iter().any(|k| *k == absent), "{absent} leaked");
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unmatched_pages_and_hides_repositories_once_mapped() {
        let (pool, dir) = fresh_pool("unmatched").await;
        add_user(&pool, "u1", "user").await;
        add_user(&pool, "u2", "user").await;
        add_user(&pool, "adm", "admin").await;
        add_mapping(&pool, "m1", "u1", "proj", "app").await;
        let owner = user("u1", Role::User);
        let created = create(&pool, &owner, "https://hg", "m1").await.unwrap();
        for (repo, seen) in [("proj/a", 100), ("proj/b", 300), ("proj/c", 200)] {
            db::record_unmatched(&pool, &created.id, repo, seen)
                .await
                .unwrap();
        }
        db::record_unmatched(&pool, &created.id, "proj/b", 400)
            .await
            .unwrap();

        let first = unmatched(
            &pool,
            &owner,
            &created.id,
            &UnmatchedQuery {
                page_size: Some(2),
                ..UnmatchedQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(first.total, 3);
        let names: Vec<&str> = first.items.iter().map(|i| i.repository.as_str()).collect();
        assert_eq!(names, vec!["proj/b", "proj/c"], "default is newest first");
        assert_eq!(first.items[0].count, 2);
        assert_eq!(first.items[0].last_seen_at, "1970-01-01T00:06:40Z");
        let second = unmatched(
            &pool,
            &owner,
            &created.id,
            &UnmatchedQuery {
                page: Some(2),
                page_size: Some(2),
                ..UnmatchedQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].repository, "proj/a");

        // Once another user maps `proj/b`, its row is hidden from the list and the total.
        add_mapping(&pool, "m2", "u2", "proj", "b").await;
        let after = unmatched(
            &pool,
            &user("adm", Role::Admin),
            &created.id,
            &UnmatchedQuery {
                sort: Some("repository".to_owned()),
                order: Some("asc".to_owned()),
                ..UnmatchedQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(after.total, 2);
        let names: Vec<&str> = after.items.iter().map(|i| i.repository.as_str()).collect();
        assert_eq!(names, vec!["proj/a", "proj/c"]);

        let foreign = unmatched(
            &pool,
            &user("u2", Role::User),
            &created.id,
            &UnmatchedQuery::default(),
        )
        .await;
        assert!(matches!(foreign, Err(AppError::Forbidden)));
        let bad_sort = unmatched(
            &pool,
            &owner,
            &created.id,
            &UnmatchedQuery {
                sort: Some("project_webhook_id".to_owned()),
                ..UnmatchedQuery::default()
            },
        )
        .await;
        assert!(matches!(bad_sort, Err(AppError::InvalidRequest(_))));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deleting_the_owner_transfers_to_a_mapping_user_on_the_project() {
        let (pool, dir) = fresh_pool("transfer").await;
        add_user(&pool, "adm", "admin").await;
        add_user(&pool, "u1", "user").await;
        add_user(&pool, "u2", "user").await;
        add_mapping(&pool, "m1", "u1", "proj", "app").await;
        add_mapping(&pool, "m2", "u2", "proj", "other").await;
        let created = create(&pool, &user("u1", Role::User), "https://hg", "m1")
            .await
            .unwrap();
        let hashes = stored_hashes(&pool, &created.id).await;
        let admin = Actor {
            user_id: Some("adm".to_owned()),
            username: "name-adm".to_owned(),
        };
        crate::services::users::delete_user(&pool, &admin, "u1")
            .await
            .unwrap();
        let owner: String = sqlx::query_scalar("SELECT user_id FROM project_webhooks WHERE id = ?")
            .bind(&created.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(owner, "u2");
        // The URL and secret are unchanged, so Harbor keeps working.
        assert_eq!(stored_hashes(&pool, &created.id).await, hashes);
        let rows = audit_rows(&pool, "project_webhook.owner_transfer").await;
        assert_eq!(rows.len(), 1);
        let details: serde_json::Value =
            serde_json::from_str(rows[0].1.as_deref().unwrap()).unwrap();
        assert_eq!(
            details,
            serde_json::json!({"from_user_id": "u1", "to_user_id": "u2"})
        );
        // The new owner can rotate now.
        assert!(
            rotate_secret(&pool, &user("u2", Role::User), &created.id)
                .await
                .is_ok()
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deleting_the_owner_with_no_candidate_deletes_the_project_webhook() {
        let (pool, dir) = fresh_pool("transfer-none").await;
        add_user(&pool, "adm", "admin").await;
        add_user(&pool, "u1", "user").await;
        add_user(&pool, "u2", "user").await;
        add_mapping(&pool, "m1", "u1", "proj", "app").await;
        // u2 maps a different project only: not a candidate.
        add_mapping(&pool, "m2", "u2", "elsewhere", "app").await;
        let created = create(&pool, &user("u1", Role::User), "https://hg", "m1")
            .await
            .unwrap();
        db::record_unmatched(&pool, &created.id, "proj/x", 1)
            .await
            .unwrap();
        let admin = Actor {
            user_id: Some("adm".to_owned()),
            username: "name-adm".to_owned(),
        };
        crate::services::users::delete_user(&pool, &admin, "u1")
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM project_webhooks")
            .fetch_one(&pool)
            .await
            .unwrap();
        let unmatched_left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM project_webhook_unmatched")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((left, unmatched_left), (0, 0));
        assert!(
            audit_rows(&pool, "project_webhook.owner_transfer")
                .await
                .is_empty()
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
