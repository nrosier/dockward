//! ID token verification and the JWKS cache. Sources: `specs/security.md` (OIDC),
//! OpenID Connect Core 1.0 section 3.1.3.7 (ID token validation), RFC 7518 (JWA).
//!
//! Decided (2026-11-03, issue #18): only `RS256` and `ES256` signatures are accepted.
//! Keys come from the discovery document's `jwks_uri`, selected by `kid`.

use std::time::{Duration, Instant};

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet},
};
use reqwest::Url;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::error::AppError;
use crate::services::oidc::Provider;

/// Minimum time between JWKS fetches caused by a `kid` that the cache does not hold.
/// PROPOSED value (2026-11-03), to be confirmed in review: one minute.
pub const JWKS_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// The ID token claims this flow reads. `aud`, `exp`, and `iss` are checked by the
/// JWT library. `groups` and the other provider claims arrive in `extra`.
#[derive(Debug, Deserialize)]
pub struct IdClaims {
    #[allow(dead_code)] // `iss` is checked by the JWT library. It is parsed for completeness.
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The JWKS for one issuer, cached until the process restarts. An unknown `kid`
/// triggers a refresh, at most once per [`JWKS_REFRESH_MIN_INTERVAL`].
pub struct JwksCache {
    inner: Mutex<Option<CachedKeys>>,
}

struct CachedKeys {
    issuer: String,
    jwks_uri: String,
    keys: JwkSet,
    last_fetch: Instant,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Makes the cached fetch look older than the refresh interval, so the next unknown
    /// `kid` refreshes. Tests only.
    #[cfg(test)]
    pub async fn expire_for_test(&self) {
        let mut guard = self.inner.lock().await;
        if let Some(cached) = guard.as_mut() {
            cached.last_fetch = Instant::now()
                .checked_sub(JWKS_REFRESH_MIN_INTERVAL + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }

    /// Returns the key with `kid`. A cached key is returned without a fetch. When the
    /// key is unknown, the JWKS is fetched again only if the last fetch for this
    /// issuer is at least [`JWKS_REFRESH_MIN_INTERVAL`] old. The lock is held across
    /// the fetch, so concurrent logins share one refresh.
    pub async fn key<P: Provider>(
        &self,
        provider: &P,
        issuer: &str,
        jwks_uri: &Url,
        kid: &str,
    ) -> Result<Jwk, AppError> {
        let mut guard = self.inner.lock().await;
        let same_issuer = guard
            .as_ref()
            .is_some_and(|c| c.issuer == issuer && c.jwks_uri == jwks_uri.as_str());
        if same_issuer && let Some(cached) = guard.as_ref() {
            if let Some(jwk) = cached.keys.find(kid) {
                return Ok(jwk.clone());
            }
            if cached.last_fetch.elapsed() < JWKS_REFRESH_MIN_INTERVAL {
                return Err(AppError::Unauthenticated);
            }
        }

        let keys = provider.jwks(jwks_uri).await?;
        let found = keys.find(kid).cloned();
        *guard = Some(CachedKeys {
            issuer: issuer.to_owned(),
            jwks_uri: jwks_uri.as_str().to_owned(),
            keys,
            last_fetch: Instant::now(),
        });
        found.ok_or(AppError::Unauthenticated)
    }
}

/// Maps a JWS algorithm to an accepted one. Anything else, including `none` and the
/// HMAC algorithms, is refused.
fn allowed_algorithm(alg: Algorithm) -> Option<Algorithm> {
    match alg {
        Algorithm::RS256 | Algorithm::ES256 => Some(alg),
        _ => None,
    }
}

/// Whether a JWK can verify `alg`. An RSA key is needed for RS256, and a P-256 key for
/// ES256. A declared `alg` on the key must match the token's `alg`.
fn key_matches(jwk: &Jwk, alg: Algorithm) -> bool {
    if let Some(declared) = jwk.common.key_algorithm
        && Algorithm::try_from(declared).ok() != Some(alg)
    {
        return false;
    }
    match (alg, &jwk.algorithm) {
        (Algorithm::RS256, AlgorithmParameters::RSA(_)) => true,
        (Algorithm::ES256, AlgorithmParameters::EllipticCurve(params)) => {
            params.curve == EllipticCurve::P256
        }
        _ => false,
    }
}

/// Verifies an ID token's signature, `iss`, `aud`, `exp`, and `sub`, and returns its
/// claims. The caller checks `nonce` and the group claim. Every failure is
/// `401 unauthenticated`, so the response does not say which check failed.
pub async fn verify_id_token<P: Provider>(
    provider: &P,
    cache: &JwksCache,
    issuer: &str,
    jwks_uri: &Url,
    client_id: &str,
    token: &str,
) -> Result<IdClaims, AppError> {
    let header = decode_header(token).map_err(|_| AppError::Unauthenticated)?;
    let alg = allowed_algorithm(header.alg).ok_or(AppError::Unauthenticated)?;
    let kid = header.kid.ok_or(AppError::Unauthenticated)?;
    let jwk = cache.key(provider, issuer, jwks_uri, &kid).await?;
    if !key_matches(&jwk, alg) {
        return Err(AppError::Unauthenticated);
    }
    let key = DecodingKey::from_jwk(&jwk).map_err(|_| AppError::Unauthenticated)?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let data =
        decode::<IdClaims>(token, &key, &validation).map_err(|_| AppError::Unauthenticated)?;
    if data.claims.sub.is_empty() {
        return Err(AppError::Unauthenticated);
    }
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::oidc_test_support::{
        FakeProvider, TEST_CLIENT_ID, TEST_ISSUER, ec_jwk, es256_token, hs256_token, jwk_set,
        jwks_uri, rs256_token, rsa_jwk, test_keys, unix_now,
    };
    use serde_json::json;

    fn claims(extra: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
            "iss": TEST_ISSUER,
            "aud": TEST_CLIENT_ID,
            "sub": "test-subject-1",
            "exp": unix_now() + 600,
            "nonce": "test-nonce",
        });
        if let (Some(map), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                map.insert(key.clone(), value.clone());
            }
        }
        base
    }

    async fn verify(
        provider: &FakeProvider,
        cache: &JwksCache,
        token: &str,
    ) -> Result<IdClaims, AppError> {
        verify_id_token(
            provider,
            cache,
            TEST_ISSUER,
            &jwks_uri(),
            TEST_CLIENT_ID,
            token,
        )
        .await
    }

    #[tokio::test]
    async fn rs256_token_with_known_kid_verifies() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        let cache = JwksCache::new();
        let token = rs256_token(&keys.rsa, "kid-rsa", &claims(json!({})));
        let verified = verify(&provider, &cache, &token).await;
        assert!(verified.is_ok(), "a valid RS256 token must verify");
    }

    #[tokio::test]
    async fn es256_token_with_known_kid_verifies() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![ec_jwk(&keys.ec, "kid-ec")]));
        let cache = JwksCache::new();
        let token = es256_token(&keys.ec, "kid-ec", &claims(json!({})));
        let verified = verify(&provider, &cache, &token).await;
        assert!(verified.is_ok(), "a valid ES256 token must verify");
    }

    #[tokio::test]
    async fn hs256_token_is_refused_before_any_key_use() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        let cache = JwksCache::new();
        let token = hs256_token("kid-rsa", &claims(json!({})));
        assert_eq!(
            verify(&provider, &cache, &token).await.err(),
            Some(AppError::Unauthenticated)
        );
        assert_eq!(provider.jwks_fetches(), 0, "no key fetch for a refused alg");
    }

    #[tokio::test]
    async fn alg_none_token_is_refused() {
        let provider = FakeProvider::with_jwks(JwkSet { keys: Vec::new() });
        let cache = JwksCache::new();
        let token = format!(
            "{}.{}.",
            base64_json(&json!({"alg":"none","kid":"kid-x"})),
            base64_json(&claims(json!({})))
        );
        assert_eq!(
            verify(&provider, &cache, &token).await.err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn token_without_kid_is_refused() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        let cache = JwksCache::new();
        let token = rs256_token(&keys.rsa, "", &claims(json!({})));
        assert_eq!(
            verify(&provider, &cache, &token).await.err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn key_family_must_match_the_algorithm() {
        // An RS256 token whose kid names an EC key must not verify.
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![ec_jwk(&keys.ec, "kid-shared")]));
        let cache = JwksCache::new();
        let token = rs256_token(&keys.rsa, "kid-shared", &claims(json!({})));
        assert_eq!(
            verify(&provider, &cache, &token).await.err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn tampered_signature_is_refused() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        let cache = JwksCache::new();
        let token = rs256_token(&keys.rsa, "kid-rsa", &claims(json!({})));
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = base64_json(&claims(json!({"sub": "test-attacker"})));
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert_eq!(
            verify(&provider, &cache, &tampered).await.err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn wrong_audience_expired_and_wrong_issuer_are_refused() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        let cache = JwksCache::new();
        let wrong_aud = rs256_token(
            &keys.rsa,
            "kid-rsa",
            &claims(json!({"aud": "test-other-client"})),
        );
        let expired = rs256_token(
            &keys.rsa,
            "kid-rsa",
            &claims(json!({"exp": unix_now() - 3600})),
        );
        let wrong_iss = rs256_token(
            &keys.rsa,
            "kid-rsa",
            &claims(json!({"iss": "https://elsewhere.example.com"})),
        );
        for token in [wrong_aud, expired, wrong_iss] {
            assert_eq!(
                verify(&provider, &cache, &token).await.err(),
                Some(AppError::Unauthenticated)
            );
        }
    }

    #[tokio::test]
    async fn cached_kid_is_served_without_a_fetch() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        let cache = JwksCache::new();
        let token = rs256_token(&keys.rsa, "kid-rsa", &claims(json!({})));
        assert!(verify(&provider, &cache, &token).await.is_ok());
        assert!(verify(&provider, &cache, &token).await.is_ok());
        assert_eq!(provider.jwks_fetches(), 1, "one fetch serves both logins");
    }

    #[tokio::test]
    async fn unknown_kid_refreshes_at_most_once_per_minute() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-rsa")]));
        let cache = JwksCache::new();
        let unknown = rs256_token(&keys.rsa, "kid-missing", &claims(json!({})));
        for _ in 0..3 {
            assert_eq!(
                verify(&provider, &cache, &unknown).await.err(),
                Some(AppError::Unauthenticated)
            );
        }
        // The first call fetches. The next two are inside the minute, so they do not.
        assert_eq!(provider.jwks_fetches(), 1);
        // A kid that is cached still verifies without a refresh.
        let known = rs256_token(&keys.rsa, "kid-rsa", &claims(json!({})));
        assert!(verify(&provider, &cache, &known).await.is_ok());
        assert_eq!(provider.jwks_fetches(), 1);
    }

    #[tokio::test]
    async fn rotated_key_is_picked_up_on_the_next_refresh() {
        let keys = test_keys();
        let provider = FakeProvider::with_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-old")]));
        let cache = JwksCache::new();
        let fresh = rs256_token(&keys.rsa, "kid-old", &claims(json!({})));
        assert!(verify(&provider, &cache, &fresh).await.is_ok());
        // The provider rotates to a new kid. The cache is more than a minute old only
        // in production, so this test forces the age by replacing the cache entry.
        provider.set_jwks(jwk_set(vec![rsa_jwk(&keys.rsa, "kid-new")]));
        cache.expire_for_test().await;
        let rotated = rs256_token(&keys.rsa, "kid-new", &claims(json!({})));
        assert!(verify(&provider, &cache, &rotated).await.is_ok());
    }

    fn base64_json(value: &serde_json::Value) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(value.to_string())
    }
}
