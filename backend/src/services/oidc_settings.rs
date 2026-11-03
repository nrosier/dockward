//! Admin OIDC settings: read and save. Sources: `specs/api.md` (`GET` and `PUT
//! /admin/oidc`), `specs/security.md` (OIDC, Local login). The client secret is
//! encrypted at rest and is never returned. The audit row never carries the secret.

use std::fmt;

use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::db::config;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::oidc::{self, OidcSettings};

/// Body of `PUT /api/v1/admin/oidc`. Every field is written as sent. `client_secret`
/// is optional: when absent, the stored secret is kept.
#[derive(Clone, serde::Deserialize)]
pub struct OidcSettingsBody {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub role_claim: Option<String>,
    pub admin_group: Option<String>,
    pub user_group: Option<String>,
    pub client_secret: Option<String>,
    pub oidc_only_users: bool,
}

const REDACTED: &str = "<redacted>";

impl fmt::Debug for OidcSettingsBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcSettingsBody")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("role_claim", &self.role_claim)
            .field("admin_group", &self.admin_group)
            .field("user_group", &self.user_group)
            .field("client_secret", &REDACTED)
            .field("oidc_only_users", &self.oidc_only_users)
            .finish()
    }
}

/// Reads the settings for the admin screen. Secrets are reported only as present.
pub async fn get(pool: &SqlitePool) -> Result<OidcSettings, AppError> {
    oidc::load_settings(pool).await
}

/// Validates and saves the settings in one transaction. Writes the audit row
/// `oidc.config_change` with the field names that changed, never the values of secrets.
pub async fn save(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    actor: &Actor,
    body: OidcSettingsBody,
) -> Result<OidcSettings, AppError> {
    // The issuer is stored exactly as entered. It must equal the token's `iss`, and a
    // parsed `Url` would add a trailing slash to a bare origin.
    let issuer = match clean(body.issuer_url.as_deref()) {
        Some(raw) => {
            oidc::parse_issuer(&raw)?;
            Some(raw)
        }
        None => None,
    };
    let client_id = clean(body.client_id.as_deref());
    let role_claim = clean(body.role_claim.as_deref());
    let admin_group = clean(body.admin_group.as_deref());
    let user_group = clean(body.user_group.as_deref());
    let new_secret = clean(body.client_secret.as_deref());

    let current = oidc::load_settings(pool).await?;
    let merged = OidcSettings {
        issuer_url: issuer.clone(),
        client_id: client_id.clone(),
        role_claim: role_claim.clone(),
        admin_group: admin_group.clone(),
        user_group: user_group.clone(),
        client_secret_set: new_secret.is_some() || current.client_secret_set,
        oidc_only_users: body.oidc_only_users,
    };
    if body.oidc_only_users && !merged.is_complete() {
        return Err(AppError::ValidationFailed(
            "Complete the OIDC settings before restricting regular users to OIDC sign-in."
                .to_owned(),
        ));
    }

    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let mut changed: Vec<&str> = Vec::new();
    write_plain(
        &mut tx,
        oidc::ISSUER_KEY,
        issuer.as_deref(),
        current.issuer_url.as_deref(),
        &mut changed,
    )
    .await?;
    write_plain(
        &mut tx,
        oidc::CLIENT_ID_KEY,
        client_id.as_deref(),
        current.client_id.as_deref(),
        &mut changed,
    )
    .await?;
    write_plain(
        &mut tx,
        oidc::ROLE_CLAIM_KEY,
        role_claim.as_deref(),
        current.role_claim.as_deref(),
        &mut changed,
    )
    .await?;
    write_plain(
        &mut tx,
        oidc::ADMIN_GROUP_KEY,
        admin_group.as_deref(),
        current.admin_group.as_deref(),
        &mut changed,
    )
    .await?;
    write_plain(
        &mut tx,
        oidc::USER_GROUP_KEY,
        user_group.as_deref(),
        current.user_group.as_deref(),
        &mut changed,
    )
    .await?;

    if let Some(secret) = new_secret.as_deref() {
        let sealed = oidc::seal_client_secret(credentials_key, secret)?;
        config::upsert(&mut tx, oidc::CLIENT_SECRET_KEY, &sealed, true).await?;
        changed.push("client_secret");
    }

    let only = if body.oidc_only_users {
        "true"
    } else {
        "false"
    };
    if current.oidc_only_users != body.oidc_only_users {
        changed.push("oidc_only_users");
    }
    config::upsert(&mut tx, oidc::ONLY_USERS_KEY, only, false).await?;

    if !changed.is_empty() {
        audit::record(
            &mut tx,
            actor,
            "oidc.config_change",
            "system_config:oidc",
            Some(&serde_json::json!({ "changed": changed })),
        )
        .await?;
    }
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    oidc::load_settings(pool).await
}

/// Writes a plain setting when it changed. An empty value deletes the row.
async fn write_plain(
    conn: &mut sqlx::SqliteConnection,
    key: &str,
    new: Option<&str>,
    old: Option<&str>,
    changed: &mut Vec<&'static str>,
) -> Result<(), AppError> {
    if new == old {
        return Ok(());
    }
    match new {
        Some(value) => config::upsert(conn, key, value, false).await?,
        None => config::delete(conn, key).await?,
    }
    changed.push(field_name(key));
    Ok(())
}

/// The API field name for a `system_config` key, used in the audit `changed` list.
fn field_name(key: &str) -> &'static str {
    match key {
        oidc::ISSUER_KEY => "issuer_url",
        oidc::CLIENT_ID_KEY => "client_id",
        oidc::ROLE_CLAIM_KEY => "role_claim",
        oidc::ADMIN_GROUP_KEY => "admin_group",
        oidc::USER_GROUP_KEY => "user_group",
        _ => "other",
    }
}

/// Trims a value and maps an empty string to `None`.
fn clean(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_settings_body_debug_redacts_client_secret() {
        let body = OidcSettingsBody {
            issuer_url: Some("https://issuer.example.test".to_owned()),
            client_id: Some("fake-client-id".to_owned()),
            role_claim: Some("groups".to_owned()),
            admin_group: Some("fake-admins".to_owned()),
            user_group: Some("fake-users".to_owned()),
            client_secret: Some("FAKE_CLIENT_SECRET_1".to_owned()),
            oidc_only_users: true,
        };
        let out = format!("{body:?}");
        assert!(
            !out.contains("FAKE_CLIENT_SECRET_1"),
            "client secret leaked: {out}"
        );
        assert!(
            out.contains("https://issuer.example.test"),
            "issuer missing: {out}"
        );
        assert!(out.contains("fake-client-id"), "client_id missing: {out}");
        assert!(out.contains("fake-admins"), "admin_group missing: {out}");
        assert!(out.contains("oidc_only_users: true"), "flag missing: {out}");
    }
}
