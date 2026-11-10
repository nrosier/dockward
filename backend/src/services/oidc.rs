//! OIDC login: settings, the authorization request, and the callback. Sources:
//! `specs/security.md` (OIDC, Outbound HTTP, Sessions), `specs/api.md` (Auth, Admin),
//! OpenID Connect Core 1.0, RFC 6749, RFC 7636.
//!
//! Decided (2026-11-03, issue #18):
//! - identity is `(oidc_issuer, oidc_subject)`; the username is `preferred_username`,
//!   falling back to `sub`, with a numeric suffix on a clash;
//! - when the group claim names both `oidc.admin_group` and `oidc.user_group`, the
//!   role is `admin`;
//! - the token request authenticates with `client_secret_basic` (HTTP Basic);
//! - the client secret is stored encrypted and is never returned by the API.

use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Url;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::auth::crypto::{self, DerivedKey};
use crate::db::{config, users};
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::{self, Actor};
use crate::services::ids;
use crate::services::oidc_jwt::{self, IdClaims, JwksCache};
use crate::services::outbound::{self, TargetClass};

/// `system_config` keys (`specs/database.md`).
pub const ISSUER_KEY: &str = "oidc.issuer_url";
pub const CLIENT_ID_KEY: &str = "oidc.client_id";
pub const CLIENT_SECRET_KEY: &str = "oidc.client_secret_encrypted";
pub const ROLE_CLAIM_KEY: &str = "oidc.role_claim";
pub const ADMIN_GROUP_KEY: &str = "oidc.admin_group";
pub const USER_GROUP_KEY: &str = "oidc.user_group";
pub const ONLY_USERS_KEY: &str = "auth.oidc_only_users";

/// Scopes requested at the authorization endpoint.
pub const SCOPE: &str = "openid profile";

/// The OIDC settings as stored. The client secret is not here. It is only read to
/// make the token request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OidcSettings {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub role_claim: Option<String>,
    pub admin_group: Option<String>,
    pub user_group: Option<String>,
    pub client_secret_set: bool,
    pub oidc_only_users: bool,
}

impl OidcSettings {
    /// The settings that must all be present before sign-in works: issuer, client id,
    /// client secret, role claim, and at least one group (`specs/api.md`, `PUT /admin/oidc`).
    pub fn is_complete(&self) -> bool {
        self.issuer_url.is_some()
            && self.client_id.is_some()
            && self.client_secret_set
            && self.role_claim.is_some()
            && (self.admin_group.is_some() || self.user_group.is_some())
    }
}

/// Reads every `oidc.*` key and the toggle. Missing rows are `None`. The secret is
/// reported only as present or absent.
pub async fn load_settings(pool: &SqlitePool) -> Result<OidcSettings, AppError> {
    Ok(OidcSettings {
        issuer_url: config::get(pool, ISSUER_KEY).await?,
        client_id: config::get(pool, CLIENT_ID_KEY).await?,
        role_claim: config::get(pool, ROLE_CLAIM_KEY).await?,
        admin_group: config::get(pool, ADMIN_GROUP_KEY).await?,
        user_group: config::get(pool, USER_GROUP_KEY).await?,
        client_secret_set: config::exists(pool, CLIENT_SECRET_KEY).await?,
        oidc_only_users: config::get(pool, ONLY_USERS_KEY).await? == Some("true".to_owned()),
    })
}

/// Parses an issuer URL: HTTPS, with no query, fragment, or user name.
pub fn parse_issuer(raw: &str) -> Result<Url, AppError> {
    let invalid =
        || AppError::ValidationFailed("The issuer URL must be a valid https:// URL.".to_owned());
    let url = Url::parse(raw).map_err(|_| invalid())?;
    if url.scheme() != "https" {
        return Err(AppError::ValidationFailed(
            "The issuer URL must use https://.".to_owned(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
        return Err(invalid());
    }
    Ok(url)
}

/// The OIDC discovery document. Only the fields this flow uses are read.
#[derive(Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// The token endpoint response. Only the ID token is used. `Debug` is hand-written so the
/// ID token is never printed.
#[derive(Deserialize)]
pub struct TokenResponse {
    pub id_token: String,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("id_token", &REDACTED)
            .finish()
    }
}

/// The network calls the flow makes. Production uses [`HttpProvider`]. Tests use a fake,
/// so no socket is opened.
#[allow(async_fn_in_trait)]
pub trait Provider {
    /// Fetches the discovery document for the configured issuer.
    async fn discovery(&self, issuer: &Url) -> Result<Discovery, AppError>;
    /// Fetches the JWKS at `jwks_uri`.
    async fn jwks(&self, jwks_uri: &Url) -> Result<JwkSet, AppError>;
    /// Exchanges an authorization code. The client secret is sent with HTTP Basic.
    async fn exchange_code(
        &self,
        token_endpoint: &Url,
        request: &CodeExchange<'_>,
    ) -> Result<TokenResponse, AppError>;
}

/// The inputs to the token request. `Debug` is hand-written so the client secret,
/// the authorization code, and the PKCE verifier never reach a log or a trace.
#[derive(Clone, Copy)]
pub struct CodeExchange<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
}

impl fmt::Debug for CodeExchange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeExchange")
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .field("code", &REDACTED)
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &REDACTED)
            .finish()
    }
}

/// The production provider, built on the guarded outbound client. Redirects are not
/// followed and every connection re-checks the resolved address.
pub struct HttpProvider {
    client: outbound::OutboundClient,
}

impl HttpProvider {
    /// A provider that also trusts `root`. Tests only, so a loopback TLS server can
    /// stand in for a provider through the production request path.
    #[cfg(test)]
    pub fn trusting(allow_private: bool, root: reqwest::Certificate) -> Result<Self, AppError> {
        let client = outbound::client_trusting(TargetClass::Oidc, allow_private, root)
            .map_err(|_| AppError::InternalError)?;
        Ok(Self { client })
    }

    pub fn new(allow_private: bool) -> Result<Self, AppError> {
        let client = outbound::client(TargetClass::Oidc, allow_private)
            .map_err(|_| AppError::InternalError)?;
        Ok(Self { client })
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &Url) -> Result<T, AppError> {
        let response = self
            .client
            .get(url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .send()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?;
        if !response.status().is_success() {
            return Err(AppError::UpstreamUnreachable);
        }
        response
            .json::<T>()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)
    }
}

impl Provider for HttpProvider {
    async fn discovery(&self, issuer: &Url) -> Result<Discovery, AppError> {
        let base = issuer.as_str().trim_end_matches('/');
        let url = Url::parse(&format!("{base}/.well-known/openid-configuration"))
            .map_err(|_| AppError::UpstreamUnreachable)?;
        self.get_json(&url).await
    }

    async fn jwks(&self, jwks_uri: &Url) -> Result<JwkSet, AppError> {
        self.get_json(jwks_uri).await
    }

    async fn exchange_code(
        &self,
        token_endpoint: &Url,
        request: &CodeExchange<'_>,
    ) -> Result<TokenResponse, AppError> {
        let response = self
            .client
            .post(token_endpoint)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(request.client_id, Some(request.client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", request.code),
                ("redirect_uri", request.redirect_uri),
                ("code_verifier", request.code_verifier),
            ])
            .send()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?;
        if !response.status().is_success() {
            return Err(AppError::Unauthenticated);
        }
        response
            .json::<TokenResponse>()
            .await
            .map_err(|_| AppError::Unauthenticated)
    }
}

/// The values for one sign-in attempt. They are kept in the `__Host-harborgate_oidc`
/// cookie (`specs/security.md`, Sessions). Each is 32 random bytes, base64url.
#[derive(Clone, PartialEq, Eq)]
pub struct Pending {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("state", &REDACTED)
            .field("nonce", &REDACTED)
            .field("verifier", &REDACTED)
            .finish()
    }
}

/// Placeholder printed in place of a secret-bearing field.
const REDACTED: &str = "<redacted>";

impl Pending {
    /// Draws the three values from the OS CSPRNG. A failure returns `AppError`.
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {
            state: random_token()?,
            nonce: random_token()?,
            verifier: random_token()?,
        })
    }

    /// The PKCE S256 challenge for this attempt's verifier (RFC 7636 section 4.2).
    pub fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.as_bytes()))
    }

    /// The cookie value: `state.nonce.verifier`. Base64url has no `.`, so the split is exact.
    pub fn to_cookie(&self) -> String {
        format!("{}.{}.{}", self.state, self.nonce, self.verifier)
    }

    /// Parses the cookie value. Returns `None` for any other shape.
    pub fn from_cookie(value: &str) -> Option<Self> {
        let mut parts = value.split('.');
        let state = parts.next()?;
        let nonce = parts.next()?;
        let verifier = parts.next()?;
        if parts.next().is_some() || [state, nonce, verifier].iter().any(|p| p.is_empty()) {
            return None;
        }
        Some(Self {
            state: state.to_owned(),
            nonce: nonce.to_owned(),
            verifier: verifier.to_owned(),
        })
    }
}

fn random_token() -> Result<String, AppError> {
    let bytes = ids::os_random_bytes::<32>()?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Builds the authorization request URL (OpenID Connect Core 3.1.2.1, RFC 7636 section 4.3).
pub fn authorization_url(
    authorization_endpoint: &Url,
    client_id: &str,
    redirect_uri: &str,
    pending: &Pending,
) -> Url {
    let mut url = authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", SCOPE)
        .append_pair("state", &pending.state)
        .append_pair("nonce", &pending.nonce)
        .append_pair("code_challenge", &pending.challenge())
        .append_pair("code_challenge_method", "S256");
    url
}

/// Maps the group claim to a role. The admin group wins when both groups are present.
/// `None` means the user has neither group and cannot sign in.
pub fn role_from_groups(
    groups: &[String],
    admin_group: Option<&str>,
    user_group: Option<&str>,
) -> Option<Role> {
    let has = |group: Option<&str>| {
        group.is_some_and(|wanted| groups.iter().any(|value| value == wanted))
    };
    if has(admin_group) {
        Some(Role::Admin)
    } else if has(user_group) {
        Some(Role::User)
    } else {
        None
    }
}

/// Reads the group values from the claim named `role_claim`. A string or an array of
/// strings is accepted. Any other shape yields no groups.
pub fn groups_from_claims(claims: &IdClaims, role_claim: &str) -> Vec<String> {
    match claims.extra.get(role_claim) {
        Some(serde_json::Value::String(text)) => vec![text.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The username base for a new OIDC user: `preferred_username`, else `sub`.
pub fn username_base(claims: &IdClaims) -> String {
    claims
        .preferred_username
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map_or_else(|| claims.sub.clone(), str::to_owned)
}

/// Returns `base` when free, otherwise `base-2`, `base-3`, and so on.
pub async fn free_username(
    conn: &mut sqlx::SqliteConnection,
    base: &str,
) -> Result<String, AppError> {
    if users::find_by_username_tx(conn, base).await?.is_none() {
        return Ok(base.to_owned());
    }
    for n in 2u32..=10_000 {
        let candidate = format!("{base}-{n}");
        if users::find_by_username_tx(conn, &candidate)
            .await?
            .is_none()
        {
            return Ok(candidate);
        }
    }
    Err(AppError::Conflict(
        "No free username is available.".to_owned(),
    ))
}

/// Starts a sign-in: fetches discovery and returns the authorization URL and the
/// pending values to store in the cookie.
pub async fn begin_login<P: Provider>(
    provider: &P,
    issuer_raw: &str,
    client_id: &str,
    redirect_uri: &str,
) -> Result<(Url, Pending), AppError> {
    let issuer = parse_issuer(issuer_raw)?;
    let doc = provider.discovery(&issuer).await?;
    check_discovery(issuer_raw, &doc)?;
    let endpoint = parse_endpoint(&doc.authorization_endpoint)?;
    let pending = Pending::new()?;
    let url = authorization_url(&endpoint, client_id, redirect_uri, &pending);
    Ok((url, pending))
}

/// The inputs the callback needs from the request and the settings.
#[derive(Clone, Copy)]
pub struct Callback<'a> {
    /// The `__Host-harborgate_oidc` cookie value, when present.
    pub cookie: Option<&'a str>,
    /// The `state` query value.
    pub state: &'a str,
    /// The `code` query value.
    pub code: &'a str,
    pub redirect_uri: &'a str,
    /// The decrypted client secret. It is used only for the token request.
    pub client_secret: &'a str,
}

impl fmt::Debug for Callback<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Callback")
            .field("cookie", &REDACTED)
            .field("state", &REDACTED)
            .field("code", &REDACTED)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_secret", &REDACTED)
            .finish()
    }
}

/// Completes a sign-in. Order: the cookie must parse, `state` must equal the cookie
/// value, the discovery endpoints must be HTTPS, the code is exchanged, the ID token
/// is verified, `nonce` must match, and the group claim must give a role. Any failure
/// is `401`, except a user with neither group, which is `403`.
pub async fn complete_callback<P: Provider>(
    pool: &SqlitePool,
    provider: &P,
    cache: &JwksCache,
    settings: &OidcSettings,
    callback: Callback<'_>,
) -> Result<users::UserRow, AppError> {
    let (issuer, client_id, role_claim) = configured(settings)?;
    // The configured string is the `iss` the token must carry. A parsed `Url` adds a
    // trailing slash to a bare origin, so the raw value is kept for the comparison.
    let issuer_raw = settings.issuer_url.clone().unwrap_or_default();
    let pending = callback
        .cookie
        .and_then(Pending::from_cookie)
        .ok_or(AppError::Unauthenticated)?;
    if pending.state != callback.state {
        return Err(AppError::Unauthenticated);
    }

    let doc = provider.discovery(&issuer).await?;
    check_discovery(&issuer_raw, &doc)?;
    let token_endpoint = parse_endpoint(&doc.token_endpoint)?;
    let jwks_uri = parse_endpoint(&doc.jwks_uri)?;

    let tokens = provider
        .exchange_code(
            &token_endpoint,
            &CodeExchange {
                client_id,
                client_secret: callback.client_secret,
                code: callback.code,
                redirect_uri: callback.redirect_uri,
                code_verifier: &pending.verifier,
            },
        )
        .await?;
    let claims = oidc_jwt::verify_id_token(
        provider,
        cache,
        &issuer_raw,
        &jwks_uri,
        client_id,
        &tokens.id_token,
    )
    .await?;
    if claims.nonce.as_deref() != Some(pending.nonce.as_str()) {
        return Err(AppError::Unauthenticated);
    }

    let groups = groups_from_claims(&claims, role_claim);
    let Some(role) = role_from_groups(
        &groups,
        settings.admin_group.as_deref(),
        settings.user_group.as_deref(),
    ) else {
        refuse_sign_in(pool, &issuer_raw, &claims).await?;
        return Err(AppError::Forbidden);
    };

    upsert_user(pool, &issuer_raw, &claims, role).await
}

/// A sign-in with no allowed group is refused. An existing user loses every session:
/// `token_version` is bumped and the change is audited as `user.role_change` (`to: null`),
/// in one transaction. A user who does not exist has no session, so nothing is written.
async fn refuse_sign_in(
    pool: &SqlitePool,
    issuer: &str,
    claims: &IdClaims,
) -> Result<(), AppError> {
    let mut tx = begin_sign_in(pool).await?;
    let Some(row) = users::find_by_oidc(&mut tx, issuer, &claims.sub).await? else {
        return Ok(());
    };
    users::bump_token_version_tx(&mut tx, &row.id).await?;
    let actor = Actor {
        user_id: Some(row.id.clone()),
        username: row.username.clone(),
    };
    audit::record(
        &mut tx,
        &actor,
        "user.role_change",
        &format!("user:{}", row.id),
        Some(&serde_json::json!({
            "username": row.username,
            "from": row.role,
            "to": null,
            "source": "oidc",
        })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(())
}

/// The settings a sign-in needs. Fails with `404` when OIDC is not fully configured.
fn configured(settings: &OidcSettings) -> Result<(Url, &str, &str), AppError> {
    if !settings.is_complete() {
        return Err(AppError::NotFound);
    }
    let issuer = settings.issuer_url.as_deref().ok_or(AppError::NotFound)?;
    let client_id = settings.client_id.as_deref().ok_or(AppError::NotFound)?;
    let role_claim = settings.role_claim.as_deref().ok_or(AppError::NotFound)?;
    Ok((parse_issuer(issuer)?, client_id, role_claim))
}

/// The discovery issuer must equal the configured issuer string exactly (OpenID Connect
/// Discovery 4.3). Decided (2026-11-03): exact string match, with no URL normalisation.
fn check_discovery(issuer_raw: &str, doc: &Discovery) -> Result<(), AppError> {
    if doc.issuer != issuer_raw {
        return Err(AppError::UpstreamUnreachable);
    }
    Ok(())
}

/// Parses an endpoint from discovery and requires `https://`.
fn parse_endpoint(raw: &str) -> Result<Url, AppError> {
    let url = Url::parse(raw).map_err(|_| AppError::UpstreamUnreachable)?;
    outbound::require_https(&url).map_err(|_| AppError::UpstreamUnreachable)?;
    Ok(url)
}

/// Begins a sign-in transaction as `BEGIN IMMEDIATE`. SQLite takes the database write
/// lock at the `BEGIN`, so a second first login for the same `sub` waits here until the
/// first one commits, and then reads the row it created. A deferred transaction reads
/// first and takes the write lock only on its first write. In WAL mode, if another
/// connection committed after that read, the upgrade fails at once with `SQLITE_BUSY`
/// (code 5). The busy timeout does not retry that case, so a deferred transaction
/// cannot wait for the lock and read the new row.
async fn begin_sign_in(
    pool: &SqlitePool,
) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, AppError> {
    pool.begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)
}

/// Finds the OIDC user for `(issuer, sub)`, creates it on first login, and sets its
/// role from the group claim. A role change is audited as `user.role_change`. The read
/// and the write run in one `BEGIN IMMEDIATE` transaction (see `begin_sign_in`).
async fn upsert_user(
    pool: &SqlitePool,
    issuer: &str,
    claims: &IdClaims,
    role: Role,
) -> Result<users::UserRow, AppError> {
    let mut tx = begin_sign_in(pool).await?;
    let existing = users::find_by_oidc(&mut tx, issuer, &claims.sub).await?;
    let row = match existing {
        Some(row) => set_role_if_changed(&mut tx, row, role).await?,
        None => {
            let id = ids::new_id()?;
            let username = free_username(&mut tx, &username_base(claims)).await?;
            users::insert_oidc(&mut tx, &id, &username, issuer, &claims.sub, role.as_str()).await?;
            users::UserRow {
                id,
                username,
                email: None,
                password_hash: None,
                role: role.as_str().to_owned(),
                auth_provider: "oidc".to_owned(),
                token_version: 0,
                created_at: None,
            }
        }
    };
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(row)
}

/// Sets the role from the group claim when it differs, and audits the change. Runs
/// inside the caller's transaction.
async fn set_role_if_changed(
    conn: &mut sqlx::SqliteConnection,
    row: users::UserRow,
    role: Role,
) -> Result<users::UserRow, AppError> {
    if row.role != role.as_str() {
        users::update_role(conn, &row.id, role.as_str()).await?;
        let actor = Actor {
            user_id: Some(row.id.clone()),
            username: row.username.clone(),
        };
        audit::record(
            conn,
            &actor,
            "user.role_change",
            &format!("user:{}", row.id),
            Some(&serde_json::json!({
                "username": row.username,
                "from": row.role,
                "to": role.as_str(),
                "source": "oidc",
            })),
        )
        .await?;
    }
    Ok(users::UserRow {
        role: role.as_str().to_owned(),
        ..row
    })
}

/// Encrypts the client secret for `system_config` (`is_encrypted = 1`).
pub fn seal_client_secret(key: &DerivedKey, secret: &str) -> Result<String, AppError> {
    crypto::encrypt(key, &client_secret_aad(), secret.as_bytes())
}

/// Decrypts the stored client secret. The bytes are zeroed on drop.
pub fn open_client_secret(
    key: &DerivedKey,
    stored: &str,
) -> Result<zeroize::Zeroizing<String>, AppError> {
    let plain = crypto::decrypt(key, &client_secret_aad(), stored)?;
    let text = std::str::from_utf8(&plain).map_err(|_| AppError::InternalError)?;
    Ok(zeroize::Zeroizing::new(text.to_owned()))
}

fn client_secret_aad() -> String {
    crypto::aad("system_config", "value", CLIENT_SECRET_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh `Pending` for a test. A failed OS draw fails the test.
    fn test_pending() -> Pending {
        match Pending::new() {
            Ok(p) => p,
            Err(_) => panic!("the OS random source must work in tests"),
        }
    }
    use crate::services::oidc_test_support::{
        FakeProvider, TEST_CLIENT_ID, TEST_ISSUER, TEST_REDIRECT, ec_jwk, es256_token, jwk_set,
        jwks_uri, rs256_token, rsa_jwk, test_keys, unix_now,
    };
    use serde_json::json;

    /// A migrated database. Test values only.
    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("dockward-oidc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        (pool, dir)
    }

    fn settings() -> OidcSettings {
        OidcSettings {
            issuer_url: Some(TEST_ISSUER.to_owned()),
            client_id: Some(TEST_CLIENT_ID.to_owned()),
            role_claim: Some("groups".to_owned()),
            admin_group: Some("test-admins".to_owned()),
            user_group: Some("test-users".to_owned()),
            client_secret_set: true,
            oidc_only_users: false,
        }
    }

    /// An ID token for `sub` with the given `nonce` and extra claims.
    fn id_token(sub: &str, nonce: &str, extra: serde_json::Value) -> String {
        let keys = test_keys();
        let mut claims = json!({
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "sub": sub,
            "exp": unix_now() + 600,
            "nonce": nonce,
        });
        if let (Some(map), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                map.insert(key.clone(), value.clone());
            }
        }
        rs256_token(&keys.rsa, "kid-rsa", &claims)
    }

    fn provider_for(token: String) -> FakeProvider {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        provider.set_id_token(token);
        provider
    }

    async fn run(
        pool: &SqlitePool,
        provider: &FakeProvider,
        pending: &Pending,
        state: &str,
    ) -> Result<users::UserRow, AppError> {
        complete_callback(
            pool,
            provider,
            &JwksCache::new(),
            &settings(),
            Callback {
                cookie: Some(&pending.to_cookie()),
                state,
                code: "test-code",
                redirect_uri: TEST_REDIRECT,
                client_secret: "test-client-secret",
            },
        )
        .await
    }

    #[test]
    fn pkce_challenge_matches_the_rfc_7636_example() {
        // RFC 7636 appendix B.
        let pending = Pending {
            state: "s".to_owned(),
            nonce: "n".to_owned(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned(),
        };
        assert_eq!(
            pending.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn authorization_url_carries_pkce_s256_state_and_nonce() {
        let endpoint = Url::parse("https://idp.example.com/authorize").unwrap();
        let pending = test_pending();
        let url = authorization_url(&endpoint, TEST_CLIENT_ID, TEST_REDIRECT, &pending);
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(pairs.get("state"), Some(&pending.state));
        assert_eq!(pairs.get("nonce"), Some(&pending.nonce));
        assert_eq!(pairs.get("code_challenge"), Some(&pending.challenge()));
        assert_eq!(pairs.get("response_type").map(String::as_str), Some("code"));
    }

    #[test]
    fn debug_output_redacts_the_client_secret_and_the_verifier() {
        // Fixed fake values. Nothing here is a real credential.
        const FAKE_SECRET: &str = "fake-client-secret-value";
        const FAKE_VERIFIER: &str = "fake-pkce-verifier-value";
        const FAKE_CODE: &str = "fake-auth-code-value";
        const FAKE_STATE: &str = "fake-state-value";
        const FAKE_NONCE: &str = "fake-nonce-value";

        let exchange = CodeExchange {
            client_id: "harborgate",
            client_secret: FAKE_SECRET,
            code: FAKE_CODE,
            redirect_uri: "https://harbor.example.com/auth/oidc/callback",
            code_verifier: FAKE_VERIFIER,
        };
        let exchange_text = format!("{exchange:?}");
        for secret in [FAKE_SECRET, FAKE_VERIFIER, FAKE_CODE] {
            assert!(
                !exchange_text.contains(secret),
                "CodeExchange Debug output leaked a secret"
            );
        }
        assert!(exchange_text.contains("<redacted>"));

        let pending = Pending {
            state: FAKE_STATE.to_owned(),
            nonce: FAKE_NONCE.to_owned(),
            verifier: FAKE_VERIFIER.to_owned(),
        };
        let pending_text = format!("{pending:?}");
        for secret in [FAKE_STATE, FAKE_NONCE, FAKE_VERIFIER] {
            assert!(
                !pending_text.contains(secret),
                "Pending Debug output leaked a secret"
            );
        }
        assert!(pending_text.contains("<redacted>"));
    }

    #[test]
    fn callback_debug_output_redacts_secret_code_and_cookie() {
        // Fixed fake values. Nothing here is a real credential.
        const FAKE_SECRET: &str = "fake-client-secret-value";
        const FAKE_CODE: &str = "fake-auth-code-value";
        const FAKE_COOKIE: &str = "fake-cookie-value";
        const FAKE_STATE: &str = "fake-state-value";

        let callback = Callback {
            cookie: Some(FAKE_COOKIE),
            state: FAKE_STATE,
            code: FAKE_CODE,
            redirect_uri: "https://harbor.example.com/auth/oidc/callback",
            client_secret: FAKE_SECRET,
        };
        let text = format!("{callback:?}");
        for secret in [FAKE_SECRET, FAKE_CODE, FAKE_COOKIE, FAKE_STATE] {
            assert!(
                !text.contains(secret),
                "Callback Debug output leaked a secret"
            );
        }
        assert!(text.contains("<redacted>"));
        assert!(text.contains("https://harbor.example.com/auth/oidc/callback"));
    }

    #[test]
    fn token_response_debug_redacts_id_token() {
        // Fixed fake value. Not a real token.
        const FAKE_ID_TOKEN: &str = "fake-id-token-value";

        let response = TokenResponse {
            id_token: FAKE_ID_TOKEN.to_owned(),
        };
        let text = format!("{response:?}");
        assert!(
            !text.contains(FAKE_ID_TOKEN),
            "TokenResponse Debug output leaked the ID token"
        );
        assert!(
            text.contains("TokenResponse"),
            "struct name missing: {text}"
        );
        assert!(
            text.contains("<redacted>"),
            "redaction marker missing: {text}"
        );
    }

    #[test]
    fn pending_cookie_round_trips_and_rejects_other_shapes() {
        let pending = test_pending();
        assert_eq!(Pending::from_cookie(&pending.to_cookie()), Some(pending));
        assert_eq!(Pending::from_cookie("only.two"), None);
        assert_eq!(Pending::from_cookie("a.b.c.d"), None);
        assert_eq!(Pending::from_cookie("a..c"), None);
    }

    #[test]
    fn issuer_must_be_https_without_query_or_fragment() {
        assert!(parse_issuer("https://idp.example.com/realms/test").is_ok());
        assert!(parse_issuer("http://idp.example.com").is_err());
        assert!(parse_issuer("https://idp.example.com/?x=1").is_err());
        assert!(parse_issuer("https://idp.example.com/#frag").is_err());
        assert!(parse_issuer("not a url").is_err());
    }

    #[test]
    fn admin_group_wins_when_both_groups_are_present() {
        let both = vec!["test-users".to_owned(), "test-admins".to_owned()];
        assert_eq!(
            role_from_groups(&both, Some("test-admins"), Some("test-users")),
            Some(Role::Admin)
        );
        let user_only = vec!["test-users".to_owned()];
        assert_eq!(
            role_from_groups(&user_only, Some("test-admins"), Some("test-users")),
            Some(Role::User)
        );
        let none = vec!["test-other".to_owned()];
        assert_eq!(
            role_from_groups(&none, Some("test-admins"), Some("test-users")),
            None
        );
    }

    #[test]
    fn group_claim_accepts_a_string_or_an_array() {
        let claims = |value: serde_json::Value| IdClaims {
            iss: TEST_ISSUER.to_owned(),
            sub: "test-subject".to_owned(),
            nonce: None,
            preferred_username: None,
            extra: serde_json::from_value(json!({ "groups": value })).unwrap(),
        };
        assert_eq!(
            groups_from_claims(&claims(json!("test-users")), "groups"),
            vec!["test-users".to_owned()]
        );
        assert_eq!(
            groups_from_claims(&claims(json!(["a", "b"])), "groups"),
            vec!["a".to_owned(), "b".to_owned()]
        );
        assert!(groups_from_claims(&claims(json!(42)), "groups").is_empty());
    }

    #[test]
    fn client_secret_round_trips_and_is_bound_to_its_row() {
        let key = crypto::credentials_key(
            &crate::config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .unwrap(),
        )
        .unwrap();
        let sealed = seal_client_secret(&key, "test-client-secret").unwrap();
        assert!(sealed.starts_with(crypto::V1_PREFIX));
        assert_eq!(
            open_client_secret(&key, &sealed).unwrap().as_str(),
            "test-client-secret"
        );
        // Moved to another row, the same ciphertext fails.
        let other = crypto::aad("system_config", "value", "oidc.other");
        assert!(crypto::decrypt(&key, &other, &sealed).is_err());
    }

    #[test]
    fn username_falls_back_from_preferred_username_to_sub() {
        let base = |preferred: Option<&str>| IdClaims {
            iss: TEST_ISSUER.to_owned(),
            sub: "test-subject-9".to_owned(),
            nonce: None,
            preferred_username: preferred.map(str::to_owned),
            extra: serde_json::Map::new(),
        };
        assert_eq!(username_base(&base(Some("test-alice"))), "test-alice");
        assert_eq!(username_base(&base(Some("  "))), "test-subject-9");
        assert_eq!(username_base(&base(None)), "test-subject-9");
    }

    #[tokio::test]
    async fn wrong_state_is_refused_before_any_token_request() {
        let (pool, dir) = fresh_pool("state").await;
        let provider = provider_for(id_token("test-sub", "n", json!({})));
        let pending = test_pending();
        let outcome = run(&pool, &provider, &pending, "test-other-state").await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(outcome.err(), Some(AppError::Unauthenticated));
        assert_eq!(
            provider.exchanges(),
            0,
            "no token request on a state mismatch"
        );
    }

    #[tokio::test]
    async fn wrong_nonce_is_refused() {
        let (pool, dir) = fresh_pool("nonce").await;
        let pending = test_pending();
        let provider = provider_for(id_token(
            "test-sub",
            "test-wrong-nonce",
            json!({"groups": ["test-users"]}),
        ));
        let outcome = run(&pool, &provider, &pending, &pending.state).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(outcome.err(), Some(AppError::Unauthenticated));
    }

    #[tokio::test]
    async fn concurrent_first_logins_create_one_user() {
        let (pool, dir) = fresh_pool("concurrent").await;
        let first = test_pending();
        let p1 = provider_for(id_token(
            "test-sub-race",
            &first.nonce,
            json!({"preferred_username": "test-race", "groups": ["test-users"]}),
        ));
        let second = test_pending();
        let p2 = provider_for(id_token(
            "test-sub-race",
            &second.nonce,
            json!({"preferred_username": "test-race", "groups": ["test-users"]}),
        ));
        let (a, b) = tokio::join!(
            run(&pool, &p1, &first, &first.state),
            run(&pool, &p2, &second, &second.state),
        );
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE oidc_subject = 'test-sub-race'")
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(a.is_ok(), "first concurrent login must succeed: {a:?}");
        assert!(b.is_ok(), "second concurrent login must succeed: {b:?}");
        assert_eq!(count, 1, "concurrent first logins must create one user");
    }

    #[tokio::test]
    async fn refused_existing_user_loses_their_sessions() {
        let (pool, dir) = fresh_pool("refused").await;
        let first = test_pending();
        let p1 = provider_for(id_token(
            "test-sub-refused",
            &first.nonce,
            json!({"preferred_username": "test-carol", "groups": ["test-users"]}),
        ));
        let created = run(&pool, &p1, &first, &first.state).await.unwrap();
        let key = crypto::session_key(
            &crate::config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .unwrap(),
        )
        .unwrap();
        let now = crate::auth::session::now_unix().unwrap();
        let token = crate::auth::session::issue(
            &key,
            &created.id,
            &created.role,
            created.token_version,
            now,
        )
        .unwrap();
        assert!(
            crate::services::sessions::authenticate(&pool, &key, &token, now)
                .await
                .is_ok(),
            "the session is valid before the refusal"
        );

        let second = test_pending();
        let p2 = provider_for(id_token(
            "test-sub-refused",
            &second.nonce,
            json!({"preferred_username": "test-carol", "groups": ["test-unrelated"]}),
        ));
        let refused = run(&pool, &p2, &second, &second.state).await;
        let after = crate::services::sessions::authenticate(&pool, &key, &token, now).await;
        let audit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'user.role_change'")
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(refused.err(), Some(AppError::Forbidden));
        assert_eq!(
            after.err(),
            Some(AppError::Unauthenticated),
            "the old session must fail after a refused sign-in"
        );
        assert_eq!(audit, 1, "the session revoke is audited once");
    }

    #[tokio::test]
    async fn refused_new_user_creates_no_row() {
        let (pool, dir) = fresh_pool("no-group").await;
        let pending = test_pending();
        let provider = provider_for(id_token(
            "test-sub-none",
            &pending.nonce,
            json!({"groups": ["test-unrelated"]}),
        ));
        let outcome = run(&pool, &provider, &pending, &pending.state).await;
        let count = sqlx::query!(r#"SELECT COUNT(*) AS "n: i64" FROM users"#)
            .fetch_one(&pool)
            .await
            .unwrap()
            .n;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(outcome.err(), Some(AppError::Forbidden));
        assert_eq!(count, 0, "no user is created without an allowed group");
    }

    #[tokio::test]
    async fn first_login_creates_the_user_and_role_changes_on_the_next_login() {
        let (pool, dir) = fresh_pool("role-change").await;
        let first = test_pending();
        let p1 = provider_for(id_token(
            "test-sub-r",
            &first.nonce,
            json!({"preferred_username": "test-alice", "groups": ["test-users"]}),
        ));
        let created = run(&pool, &p1, &first, &first.state).await.unwrap();
        assert_eq!(created.role, "user");
        assert_eq!(created.username, "test-alice");
        assert_eq!(created.auth_provider, "oidc");

        let second = test_pending();
        let p2 = provider_for(id_token(
            "test-sub-r",
            &second.nonce,
            json!({"preferred_username": "test-alice", "groups": ["test-admins"]}),
        ));
        let promoted = run(&pool, &p2, &second, &second.state).await.unwrap();
        assert_eq!(promoted.id, created.id, "the same user row is reused");
        assert_eq!(promoted.role, "admin");

        let audit = sqlx::query!(
            "SELECT COUNT(*) AS \"n: i64\" FROM audit_log WHERE action = 'user.role_change'"
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .n;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(audit, 1, "the role change is audited once");
    }

    #[tokio::test]
    async fn clashing_username_gets_a_numeric_suffix() {
        let (pool, dir) = fresh_pool("clash").await;
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider) VALUES ('test-local', 'test-bob', 'user', 'local')"
        )
        .execute(&pool)
        .await
        .unwrap();
        let pending = test_pending();
        let provider = provider_for(id_token(
            "test-sub-b",
            &pending.nonce,
            json!({"preferred_username": "test-bob", "groups": ["test-users"]}),
        ));
        let created = run(&pool, &provider, &pending, &pending.state).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(created.unwrap().username, "test-bob-2");
    }

    #[tokio::test]
    async fn es256_provider_signs_in_through_the_same_flow() {
        let (pool, dir) = fresh_pool("es256").await;
        let keys = test_keys();
        let pending = test_pending();
        let claims = json!({
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "sub": "test-sub-ec",
            "exp": unix_now() + 600,
            "nonce": pending.nonce,
            "groups": ["test-users"],
        });
        let token = es256_token(&keys.ec, "kid-ec", &claims);
        let provider = FakeProvider::with_jwks(jwk_set(vec![ec_jwk(&keys.ec, "kid-ec")]));
        provider.set_id_token(token);
        let outcome = run(&pool, &provider, &pending, &pending.state).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(outcome.is_ok(), "an ES256 ID token must sign in");
    }

    #[test]
    fn jwks_uri_and_discovery_checks_refuse_mismatches() {
        let good = Discovery {
            issuer: TEST_ISSUER.to_owned(),
            authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
            token_endpoint: "https://idp.example.com/token".to_owned(),
            jwks_uri: jwks_uri().to_string(),
        };
        assert!(check_discovery(TEST_ISSUER, &good).is_ok());
        let other = Discovery {
            issuer: "https://elsewhere.example.com".to_owned(),
            authorization_endpoint: good.authorization_endpoint.clone(),
            token_endpoint: good.token_endpoint.clone(),
            jwks_uri: good.jwks_uri.clone(),
        };
        assert_eq!(
            check_discovery(TEST_ISSUER, &other),
            Err(AppError::UpstreamUnreachable)
        );
        // Decided (2026-11-03): no URL normalisation. A trailing slash is a different string.
        let slashed = Discovery {
            issuer: format!("{TEST_ISSUER}/"),
            ..good
        };
        assert_eq!(
            check_discovery(TEST_ISSUER, &slashed),
            Err(AppError::UpstreamUnreachable)
        );
        assert!(parse_endpoint("http://idp.example.com/jwks").is_err());
    }
}

/// Discovery and JWKS fetches over a live loopback socket, through `HttpProvider`. The
/// loopback server has a generated test certificate. Nothing is printed.
#[cfg(test)]
mod provider_socket_tests {
    use super::*;
    use crate::services::outbound::socket_tests::{OK, loopback_tls_server};

    /// Builds a `200` response with a JSON body. The body is test data only.
    fn json_response(body: &str) -> &'static str {
        Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        )
    }

    #[tokio::test]
    async fn discovery_to_loopback_is_refused_without_the_opt_out() {
        let (port, root) = loopback_tls_server(OK).await;
        let provider = HttpProvider::trusting(false, root).unwrap();
        let issuer = Url::parse(&format!("https://127.0.0.1:{port}")).unwrap();
        let outcome = provider.discovery(&issuer).await;
        assert!(
            matches!(outcome, Err(AppError::UpstreamUnreachable)),
            "discovery to loopback must be refused by default"
        );
    }

    #[tokio::test]
    async fn discovery_to_loopback_is_fetched_only_with_the_opt_out() {
        // The body is fixed test data. `discovery` fetches it and parses the fields.
        let body = r#"{"issuer":"https://127.0.0.1","authorization_endpoint":"https://127.0.0.1/a","token_endpoint":"https://127.0.0.1/t","jwks_uri":"https://127.0.0.1/j"}"#;
        let (port, root) = loopback_tls_server(json_response(body)).await;
        let provider = HttpProvider::trusting(true, root).unwrap();
        let issuer = Url::parse(&format!("https://127.0.0.1:{port}")).unwrap();
        // The control: with the opt-out the loopback server answers and the body parses.
        assert!(
            provider.discovery(&issuer).await.is_ok(),
            "the opted-out discovery should succeed"
        );
    }

    #[tokio::test]
    async fn jwks_to_loopback_is_refused_without_the_opt_out() {
        let (port, root) = loopback_tls_server(OK).await;
        let provider = HttpProvider::trusting(false, root).unwrap();
        let jwks_uri = Url::parse(&format!("https://127.0.0.1:{port}/jwks")).unwrap();
        let outcome = provider.jwks(&jwks_uri).await;
        assert!(
            matches!(outcome, Err(AppError::UpstreamUnreachable)),
            "a JWKS fetch from loopback must be refused by default"
        );
    }

    #[tokio::test]
    async fn plain_http_discovery_sends_no_request() {
        // A plain TCP listener counts connections. Even with the opt-out, an http issuer
        // must not open a connection. This proves the end-to-end result. The scheme rule
        // itself is tested in `outbound::socket_tests`, because reqwest's `https_only`
        // also refuses the request, so this test alone does not isolate `check_target`.
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(listener) => listener,
            Err(err) => panic!("loopback bind failed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("loopback address unavailable: {err}"),
        };
        let provider = HttpProvider::new(true).unwrap();
        let issuer = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let outcome = provider.discovery(&issuer).await;
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept())
                .await
                .is_ok();
        assert!(matches!(outcome, Err(AppError::UpstreamUnreachable)));
        assert!(!accepted, "an http:// issuer must not open a connection");
    }
}
