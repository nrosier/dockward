//! Test-only helpers for the OIDC tests: generated RSA and EC test keys, token signing
//! for RS256, ES256, and HS256, and a fake provider with no network access. Every
//! key is generated at test time and never written to disk. Nothing here is logged.

use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize, PublicKeyComponents};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use reqwest::Url;
use serde_json::{Value, json};

use crate::error::AppError;
use crate::services::oidc::{CodeExchange, Discovery, Provider, TokenResponse};

/// Test issuer. Fixed fake value.
pub const TEST_ISSUER: &str = "https://idp.example.com";
/// Test client id. Fixed fake value.
pub const TEST_CLIENT_ID: &str = "test-client-id";
/// Test redirect URI. Fixed fake value.
pub const TEST_REDIRECT: &str = "https://harborgate.example.com/api/v1/auth/oidc/callback";

/// The generated test keys: a 2048-bit RSA key and a P-256 EC key.
pub struct TestKeys {
    pub rsa: RsaKeyPair,
    pub ec: EcdsaKeyPair,
}

/// Generates the test keys once per test process.
pub fn test_keys() -> &'static TestKeys {
    static KEYS: OnceLock<TestKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let rsa = match RsaKeyPair::generate(KeySize::Rsa2048) {
            Ok(key) => key,
            Err(_) => panic!("test RSA key generation failed"),
        };
        let rng = SystemRandom::new();
        let document = match EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng) {
            Ok(doc) => doc,
            Err(_) => panic!("test EC key generation failed"),
        };
        let ec = match EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref())
        {
            Ok(key) => key,
            Err(_) => panic!("test EC key parse failed"),
        };
        TestKeys { rsa, ec }
    })
}

/// The current Unix time in seconds.
pub fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(0),
        Err(_) => 0,
    }
}

/// The fixed JWKS URI on the test issuer.
pub fn jwks_uri() -> Url {
    match Url::parse("https://idp.example.com/jwks") {
        Ok(url) => url,
        Err(_) => panic!("test JWKS URI rejected"),
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// An RSA public JWK for `kid`, declared as RS256.
pub fn rsa_jwk(key: &RsaKeyPair, kid: &str) -> Jwk {
    let components = PublicKeyComponents::<Vec<u8>>::from(key.public_key());
    let value = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64(&components.n),
        "e": b64(&components.e),
    });
    jwk_from(value)
}

/// A P-256 public JWK for `kid`, declared as ES256.
pub fn ec_jwk(key: &EcdsaKeyPair, kid: &str) -> Jwk {
    let point = key.public_key().as_ref();
    // An uncompressed P-256 point is 0x04 || x (32 bytes) || y (32 bytes).
    let (x, y) = (&point[1..33], &point[33..65]);
    let value = json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": b64(x),
        "y": b64(y),
    });
    jwk_from(value)
}

fn jwk_from(value: Value) -> Jwk {
    match serde_json::from_value(value) {
        Ok(jwk) => jwk,
        Err(_) => panic!("test JWK did not parse"),
    }
}

/// A JWKS holding `keys`.
pub fn jwk_set(keys: Vec<Jwk>) -> JwkSet {
    JwkSet { keys }
}

fn sign_jwt(alg: &str, kid: &str, claims: &Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let mut header = json!({"alg": alg, "typ": "JWT"});
    if !kid.is_empty() {
        header["kid"] = json!(kid);
    }
    let signing_input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let signature = sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64(&signature))
}

/// An RS256 ID token signed with the test RSA key.
pub fn rs256_token(key: &RsaKeyPair, kid: &str, claims: &Value) -> String {
    sign_jwt("RS256", kid, claims, |message| {
        let mut signature = vec![0u8; key.public_modulus_len()];
        match key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message,
            &mut signature,
        ) {
            Ok(()) => signature,
            Err(_) => panic!("test RS256 signing failed"),
        }
    })
}

/// An ES256 ID token signed with the test P-256 key.
pub fn es256_token(key: &EcdsaKeyPair, kid: &str, claims: &Value) -> String {
    sign_jwt("ES256", kid, claims, |message| {
        match key.sign(&SystemRandom::new(), message) {
            Ok(signature) => signature.as_ref().to_vec(),
            Err(_) => panic!("test ES256 signing failed"),
        }
    })
}

/// An HS256 token. Only used to check that the verifier refuses a symmetric alg.
pub fn hs256_token(kid: &str, claims: &Value) -> String {
    sign_jwt("HS256", kid, claims, |message| {
        // A fixed, obviously fake secret. The token must still be refused.
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, b"test-hmac-secret");
        aws_lc_rs::hmac::sign(&key, message).as_ref().to_vec()
    })
}

#[derive(Default)]
struct FakeState {
    jwks: Option<JwkSet>,
    id_token: String,
    jwks_fetches: usize,
    exchanges: usize,
}

/// A provider that serves a fixed JWKS and a fixed ID token. It counts calls, so tests
/// can check when the network would have been used.
pub struct FakeProvider {
    state: Mutex<FakeState>,
}

impl FakeProvider {
    pub fn with_jwks(jwks: JwkSet) -> Self {
        Self {
            state: Mutex::new(FakeState {
                jwks: Some(jwks),
                ..FakeState::default()
            }),
        }
    }

    pub fn set_jwks(&self, jwks: JwkSet) {
        self.with_state(|s| s.jwks = Some(jwks));
    }

    pub fn set_id_token(&self, token: String) {
        self.with_state(|s| s.id_token = token);
    }

    pub fn jwks_fetches(&self) -> usize {
        self.with_state(|s| s.jwks_fetches)
    }

    pub fn exchanges(&self) -> usize {
        self.with_state(|s| s.exchanges)
    }

    fn with_state<T>(&self, f: impl FnOnce(&mut FakeState) -> T) -> T {
        match self.state.lock() {
            Ok(mut guard) => f(&mut guard),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }
}

impl Provider for FakeProvider {
    async fn discovery(&self, _issuer: &Url) -> Result<Discovery, AppError> {
        Ok(Discovery {
            issuer: TEST_ISSUER.to_owned(),
            authorization_endpoint: format!("{TEST_ISSUER}/authorize"),
            token_endpoint: format!("{TEST_ISSUER}/token"),
            jwks_uri: jwks_uri().to_string(),
        })
    }

    async fn jwks(&self, _jwks_uri: &Url) -> Result<JwkSet, AppError> {
        self.with_state(|s| {
            s.jwks_fetches += 1;
            s.jwks.clone().ok_or(AppError::UpstreamUnreachable)
        })
    }

    async fn exchange_code(
        &self,
        _token_endpoint: &Url,
        _request: &CodeExchange<'_>,
    ) -> Result<TokenResponse, AppError> {
        self.with_state(|s| {
            s.exchanges += 1;
            Ok(TokenResponse {
                id_token: s.id_token.clone(),
            })
        })
    }
}
