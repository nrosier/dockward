//! Hubs (`specs/spinoff-local-scan.md`, section 2; decisions 13, 44 and 45). A hub is a registry
//! host and has no other name. Defaults are fixed; an admin adds and removes custom hubs. An
//! entered host is an outbound destination for the whole instance, so its grammar and its
//! addresses are checked before it is stored (section 12).

use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db::hubs::{self as db, HubRow};
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::ids;
use crate::services::pagination::{Page, Pagination};
use crate::services::registry::grammar::validate_hub_host;
use crate::services::registry::transport::RegistryClient;

/// The `Hub` object: `id`, `host`, `pull_endpoint` or null, `kind`. No display name.
pub type Hub = HubRow;

/// `POST /api/v1/hubs` body.
#[derive(Debug, Deserialize)]
pub struct NewHub {
    pub host: String,
    #[serde(default)]
    pub pull_endpoint: Option<String>,
}

/// One page of hubs, defaults first.
pub async fn list(
    pool: &SqlitePool,
    page: Option<i64>,
    page_size: Option<i64>,
) -> Result<Page<Hub>, AppError> {
    let paging = Pagination::parse(page, page_size, None, None, &["host"])?;
    Ok(Page {
        items: db::list(pool, paging.page_size, paging.offset()).await?,
        page: paging.page,
        page_size: paging.page_size,
        total: db::count(pool).await?,
    })
}

fn refused() -> AppError {
    AppError::ValidationFailed("The hub host is not allowed or could not be resolved.".to_owned())
}

fn bad_endpoint() -> AppError {
    AppError::ValidationFailed("The pull endpoint is not valid.".to_owned())
}

/// Creates a custom hub. The host and the endpoint are checked against the grammar, then
/// resolved and checked against the address rules; a blocked or unresolvable address is `422`.
/// An endpoint equal to the host is stored as no endpoint.
pub async fn create(
    pool: &SqlitePool,
    client: &RegistryClient,
    actor: &Actor,
    admin_id: &str,
    input: NewHub,
) -> Result<Hub, AppError> {
    validate_hub_host(&input.host)?;
    let endpoint = match input.pull_endpoint.as_deref() {
        None | Some("") => None,
        Some(endpoint) if endpoint == input.host => None,
        Some(endpoint) => {
            validate_hub_host(endpoint).map_err(|_| bad_endpoint())?;
            Some(endpoint.to_owned())
        }
    };
    client
        .check_host(&input.host)
        .await
        .map_err(|_| refused())?;
    if let Some(endpoint) = &endpoint {
        client.check_host(endpoint).await.map_err(|_| refused())?;
    }
    let id = ids::new_id()?;
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    db::insert_custom(&mut tx, &id, &input.host, endpoint.as_deref(), admin_id).await?;
    audit::record(
        &mut tx,
        actor,
        "hub.create",
        &format!("hub:{id}"),
        Some(&serde_json::json!({ "host": input.host, "pull_endpoint": endpoint })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(Hub {
        id,
        host: input.host,
        pull_endpoint: endpoint,
        kind: "custom".to_owned(),
    })
}

/// Deletes a custom hub. A default hub, a hub an image source uses, and a hub with recorded
/// images are `409`. A missing hub is `404`.
pub async fn delete(pool: &SqlitePool, actor: &Actor, id: &str) -> Result<(), AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let hub = db::find(&mut tx, id).await?.ok_or(AppError::NotFound)?;
    if hub.kind == "default" {
        return Err(AppError::Conflict(
            "a default hub cannot be removed.".to_owned(),
        ));
    }
    if db::used_by_source(&mut tx, id).await? {
        return Err(AppError::Conflict(
            "an image source uses this hub.".to_owned(),
        ));
    }
    if db::delete_custom(&mut tx, id).await? == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        actor,
        "hub.delete",
        &format!("hub:{id}"),
        Some(&serde_json::json!({ "host": hub.host })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(())
}
