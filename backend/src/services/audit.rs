//! Audit log writer and list. Action vocabulary and `details` rules are in
//! `specs/database.md` (Audit action vocabulary) and `specs/security.md` (Secrets in logs).

use serde::Serialize;
use sqlx::{SqliteConnection, SqlitePool};

use crate::db::audit::{self, AuditFilter, AuditRecord, NewAudit};
use crate::error::AppError;
use crate::services::ids;
use crate::services::pagination::{Page, Pagination};

/// The only values `audit_log.action` may hold. Keep in step with `specs/database.md`.
pub const ACTIONS: &[&str] = &[
    "user.create",
    "user.delete",
    "user.role_change",
    "oidc.config_change",
    "credential.create",
    "credential.rotate",
    "credential.delete",
    "cve.accept",
    "cve.unaccept",
    "mapping.create",
    "mapping.update",
    "mapping.delete",
    "mapping.webhook_token_rotate",
    "mapping.auth_secret_rotate",
    "alert.config_change",
    "backup.run",
    "restore.run",
    "key.rotate",
    "retention.run",
    "sync_job.retry",
    "log.level_change",
];

/// Key names (lowercased) that mark a value as a secret. Any key that contains
/// one of these fragments is refused in `details`.
const SECRET_KEY_FRAGMENTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "cookie",
    "authorization",
    "private",
    "credential_value",
];

/// Who performed the action. The CLI uses `cli` with no user id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub user_id: Option<String>,
    pub username: String,
}

impl Actor {
    /// The offline CLI operator, as recorded by restore and key rotation.
    #[allow(dead_code)] // Used by the restore and key rotation commands in later milestones.
    pub fn cli() -> Self {
        Self {
            user_id: None,
            username: "cli".to_owned(),
        }
    }

    /// The background workers, as recorded by the retention run.
    pub fn system() -> Self {
        Self {
            user_id: None,
            username: "system".to_owned(),
        }
    }
}

/// One audit row as returned by the admin list. `details` is parsed JSON.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub id: String,
    pub actor_user_id: Option<String>,
    pub actor_username: String,
    pub action: String,
    pub target: String,
    pub created_at: Option<i64>,
    pub details: Option<serde_json::Value>,
}

/// Query values for `GET /api/v1/admin/audit-log`.
#[derive(Debug, Default)]
pub struct AuditQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub action: Option<String>,
    pub actor_user_id: Option<String>,
}

/// True when a key name marks a secret: it contains one of [`SECRET_KEY_FRAGMENTS`]
/// (ignoring case) or names key material (`key`, `*_key`, `key_*`). The application log
/// drops fields with these names (`services/app_log.rs`).
pub fn is_secret_key_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    let is_key_material =
        lowered == "key" || lowered.ends_with("_key") || lowered.starts_with("key_");
    is_key_material || SECRET_KEY_FRAGMENTS.iter().any(|f| lowered.contains(f))
}

/// Refuses an action that is not in [`ACTIONS`].
pub fn validate_action(action: &str) -> Result<(), AppError> {
    if ACTIONS.contains(&action) {
        Ok(())
    } else {
        Err(AppError::InternalError)
    }
}

/// Refuses `details` that carry a secret: a key whose name marks a secret, or a
/// string that looks like a stored ciphertext (`v1:`) or an Argon2 hash.
pub fn check_details(value: &serde_json::Value) -> Result<(), AppError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                if is_secret_key_name(key) {
                    return Err(AppError::InternalError);
                }
                check_details(nested)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => items.iter().try_for_each(check_details),
        serde_json::Value::String(text) => {
            if text.starts_with(crate::auth::crypto::V1_PREFIX) || text.starts_with("$argon2") {
                Err(AppError::InternalError)
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

/// Appends one audit row on `conn`. Pass the transaction connection so the audit
/// row commits or rolls back with the change it records. Any failure is an error,
/// and the caller must fail the action.
pub async fn record(
    conn: &mut SqliteConnection,
    actor: &Actor,
    action: &str,
    target: &str,
    details: Option<&serde_json::Value>,
) -> Result<(), AppError> {
    validate_action(action)?;
    let details_text = match details {
        Some(value) => {
            check_details(value)?;
            Some(serde_json::to_string(value).map_err(|_| AppError::InternalError)?)
        }
        None => None,
    };
    let id = ids::new_id()?;
    audit::insert(
        conn,
        NewAudit {
            id: &id,
            actor_user_id: actor.user_id.as_deref(),
            actor_username: &actor.username,
            action,
            target,
            details: details_text.as_deref(),
        },
    )
    .await
}

/// Returns one page of audit rows, filtered by action and actor.
pub async fn list(pool: &SqlitePool, query: &AuditQuery) -> Result<Page<AuditEntry>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        &["created_at"],
    )?;
    let filter = AuditFilter {
        action: query.action.as_deref(),
        actor_user_id: query.actor_user_id.as_deref(),
        sort_sign: if paging.ascending { 1 } else { -1 },
        limit: paging.page_size,
        offset: paging.offset(),
    };
    let total = audit::count(pool, &filter).await?;
    let rows = audit::list(pool, &filter).await?;
    let items = rows
        .into_iter()
        .map(entry_from_record)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

fn entry_from_record(row: AuditRecord) -> Result<AuditEntry, AppError> {
    let details = match row.details {
        Some(text) => Some(serde_json::from_str(&text).map_err(|_| AppError::InternalError)?),
        None => None,
    };
    Ok(AuditEntry {
        id: row.id,
        actor_user_id: row.actor_user_id,
        actor_username: row.actor_username,
        action: row.action,
        target: row.target,
        created_at: row.created_at,
        details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_action_is_rejected() {
        assert!(validate_action("user.create").is_ok());
        assert_eq!(
            validate_action("user.explode"),
            Err(AppError::InternalError)
        );
    }

    #[test]
    fn secret_keys_are_rejected_in_details() {
        assert!(check_details(&json!({"role": "admin", "count": 3})).is_ok());
        assert!(check_details(&json!({"api_token": "x"})).is_err());
        assert!(check_details(&json!({"client_secret": "x"})).is_err());
        assert!(check_details(&json!({"password": "x"})).is_err());
        assert!(check_details(&json!({"key": "x"})).is_err());
        assert!(check_details(&json!({"nested": {"Authorization": "x"}})).is_err());
    }

    #[test]
    fn ciphertext_and_hash_values_are_rejected_in_details() {
        assert!(check_details(&json!({"note": "v1:AAAA"})).is_err());
        assert!(check_details(&json!({"note": "$argon2id$v=19$m=19456"})).is_err());
        assert!(check_details(&json!({"list": ["ok", "v1:AAAA"]})).is_err());
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use serde_json::json;

    /// A migrated database in a fresh temp directory. Values are test-only.
    async fn fresh_pool(name: &str) -> Result<(SqlitePool, std::path::PathBuf), AppError> {
        let dir =
            std::env::temp_dir().join(format!("harborgate-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|_| AppError::InternalError)?;
        let pool = crate::db::open(&dir).await?;
        Ok((pool, dir))
    }

    #[tokio::test]
    async fn unknown_action_is_refused_and_writes_nothing() -> Result<(), AppError> {
        let (pool, dir) = fresh_pool("unknown").await?;
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        let result = record(&mut conn, &Actor::cli(), "user.explode", "user:x", None).await;
        drop(conn);
        let count = audit_count(&pool).await?;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err(), "unknown action was accepted");
        assert_eq!(count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn secret_details_are_refused_and_writes_nothing() -> Result<(), AppError> {
        let (pool, dir) = fresh_pool("secret").await?;
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        let secret = json!({"github_token": "test-fake-value"});
        let result = record(
            &mut conn,
            &Actor::cli(),
            "credential.rotate",
            "cred:1",
            Some(&secret),
        )
        .await;
        drop(conn);
        let count = audit_count(&pool).await?;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err(), "secret was accepted in details");
        assert_eq!(count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn record_writes_actor_snapshot_and_list_filters() -> Result<(), AppError> {
        let (pool, dir) = fresh_pool("list").await?;
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider) VALUES ('u-1', 'test-admin', 'admin', 'local')"
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        let actor = Actor {
            user_id: Some("u-1".to_owned()),
            username: "test-admin".to_owned(),
        };
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        record(
            &mut conn,
            &actor,
            "user.create",
            "user:u-2",
            Some(&json!({"role": "user"})),
        )
        .await?;
        record(
            &mut conn,
            &Actor::cli(),
            "key.rotate",
            "system",
            Some(&json!({"rows_rewritten": 3})),
        )
        .await?;
        drop(conn);

        let all = list(&pool, &AuditQuery::default()).await?;
        assert_eq!(all.total, 2);
        let by_action = list(
            &pool,
            &AuditQuery {
                action: Some("key.rotate".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await?;
        assert_eq!(by_action.total, 1);
        assert_eq!(by_action.items[0].actor_username, "cli");
        let by_actor = list(
            &pool,
            &AuditQuery {
                actor_user_id: Some("u-1".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await?;
        assert_eq!(by_actor.total, 1);
        assert_eq!(by_actor.items[0].actor_username, "test-admin");
        assert_eq!(by_actor.items[0].details, Some(json!({"role": "user"})));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    async fn audit_count(pool: &SqlitePool) -> Result<i64, AppError> {
        let row = sqlx::query!(r#"SELECT COUNT(*) AS "n: i64" FROM audit_log"#)
            .fetch_one(pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        Ok(row.n)
    }
}
