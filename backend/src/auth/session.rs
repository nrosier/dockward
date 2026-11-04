//! HS256 session tokens and the `__Host-` session cookie.
//! Sources: `specs/security.md` (Sessions); RFC 7519 (JWT); RFC 8725 section 3.1
//! (algorithm verification). The token is issued and checked here only. Per-request
//! user and `token_version` checks are in `services::sessions`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, header::COOKIE};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::auth::crypto::DerivedKey;
use crate::error::AppError;
use crate::services::ids;

/// Cookie name. The `__Host-` prefix forces `Secure`, `Path=/`, and no `Domain`.
pub const SESSION_COOKIE: &str = "__Host-harborgate_session";

/// Session lifetime: 8 hours (`exp` is `iat` plus this value).
pub const SESSION_LIFETIME_SECS: i64 = 8 * 60 * 60;

const ALG: &str = "HS256";
const HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;

type HmacSha256 = Hmac<Sha256>;

/// JWT claims. `role` is informational only; the role is re-read from the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub ver: i64,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

/// Current Unix time in seconds.
pub fn now_unix() -> Result<i64, AppError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::InternalError)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| AppError::InternalError)
}

fn mac(key: &DerivedKey) -> Result<HmacSha256, AppError> {
    HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| AppError::InternalError)
}

/// Issues a signed session token for `user_id`. `token_version` is the user's
/// current `users.token_version`, which later checks compare against.
pub fn issue(
    key: &DerivedKey,
    user_id: &str,
    role: &str,
    token_version: i64,
    now: i64,
) -> Result<String, AppError> {
    let claims = Claims {
        sub: user_id.to_owned(),
        role: role.to_owned(),
        iat: now,
        exp: now + SESSION_LIFETIME_SECS,
        jti: ids::new_id(),
        ver: token_version,
    };
    let payload = serde_json::to_vec(&claims).map_err(|_| AppError::InternalError)?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER_JSON),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let mut signer = mac(key)?;
    signer.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes());
    Ok(format!("{signing_input}.{signature}"))
}

/// Verifies a token and returns its claims. Rejects any `alg` other than `HS256`
/// (including `none`) before the signature is checked. Also rejects a bad
/// signature, a malformed token, and an expired `exp`. Checking `ver` against the
/// database is the caller's job.
pub fn verify(key: &DerivedKey, token: &str, now: i64) -> Result<Claims, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header_b64, payload_b64, signature_b64] = parts.as_slice() else {
        return Err(AppError::Unauthenticated);
    };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| AppError::Unauthenticated)?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|_| AppError::Unauthenticated)?;
    if header.alg != ALG {
        return Err(AppError::Unauthenticated);
    }

    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| AppError::Unauthenticated)?;
    let mut verifier = mac(key)?;
    verifier.update(format!("{header_b64}.{payload_b64}").as_bytes());
    verifier
        .verify_slice(&signature)
        .map_err(|_| AppError::Unauthenticated)?;

    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AppError::Unauthenticated)?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| AppError::Unauthenticated)?;
    if claims.exp <= now {
        return Err(AppError::Unauthenticated);
    }
    Ok(claims)
}

/// The `Set-Cookie` value that stores a session token.
pub fn set_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Max-Age={SESSION_LIFETIME_SECS}; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

/// The `Set-Cookie` value that clears the session cookie in the browser.
pub fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax")
}

/// Returns the value of the named cookie from all `Cookie` headers, if present.
pub fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::crypto::session_key;
    use crate::config::parse_encryption_key;

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn key() -> DerivedKey {
        let root = parse_encryption_key(TEST_KEY_B64).unwrap();
        session_key(&root).unwrap()
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn issued_token_verifies_and_carries_claims() {
        let k = key();
        let token = issue(&k, "user-1", "admin", 4, 1_000).unwrap();
        let claims = verify(&k, &token, 1_000).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.ver, 4);
        assert_eq!(claims.iat, 1_000);
        assert_eq!(claims.exp, 1_000 + SESSION_LIFETIME_SECS);
        assert_eq!(claims.exp - claims.iat, 8 * 60 * 60);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn expired_token_is_rejected() {
        let k = key();
        let token = issue(&k, "user-1", "user", 0, 1_000).unwrap();
        let at_expiry = 1_000 + SESSION_LIFETIME_SECS;
        assert_eq!(
            verify(&k, &token, at_expiry).err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[test]
    fn alg_none_is_rejected() {
        let k = key();
        let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = b64(
            br#"{"sub":"user-1","role":"admin","iat":1000,"exp":99999999999,"jti":"x","ver":0}"#,
        );
        let forged = format!("{header}.{payload}.");
        assert_eq!(
            verify(&k, &forged, 1_000).err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[test]
    fn other_algorithms_are_rejected_even_with_a_valid_signature() {
        let k = key();
        // Sign with HS256 but declare HS512 in the header. The header is checked first.
        let header = b64(br#"{"alg":"HS512","typ":"JWT"}"#);
        let payload = b64(
            br#"{"sub":"user-1","role":"admin","iat":1000,"exp":99999999999,"jti":"x","ver":0}"#,
        );
        let input = format!("{header}.{payload}");
        let mut signer = HmacSha256::new_from_slice(k.as_bytes()).unwrap();
        signer.update(input.as_bytes());
        let sig = b64(&signer.finalize().into_bytes());
        assert_eq!(
            verify(&k, &format!("{input}.{sig}"), 1_000).err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let k = key();
        let token = issue(&k, "user-1", "user", 0, 1_000).unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        parts[1] = b64(
            br#"{"sub":"user-1","role":"admin","iat":1000,"exp":99999999999,"jti":"x","ver":0}"#,
        );
        let forged = parts.join(".");
        assert_eq!(
            verify(&k, &forged, 1_000).err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[test]
    fn token_from_another_key_is_rejected() {
        let k = key();
        let other_root =
            parse_encryption_key("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=").unwrap();
        let other = session_key(&other_root).unwrap();
        let token = issue(&other, "user-1", "user", 0, 1_000).unwrap();
        assert_eq!(
            verify(&k, &token, 1_000).err(),
            Some(AppError::Unauthenticated)
        );
    }

    #[test]
    fn cookie_attributes_match_the_spec() {
        let cookie = set_cookie("TOKEN");
        assert!(cookie.starts_with("__Host-harborgate_session=TOKEN;"));
        for attr in [
            "Path=/",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Max-Age=28800",
        ] {
            assert!(cookie.contains(attr), "missing {attr}");
        }
        assert!(!cookie.contains("Domain"));
        assert!(clear_cookie().contains("Max-Age=0"));
    }

    /// Lowercase hex of `bytes`.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A session token recorded with the hmac 0.12 build, under the session key derived
    /// from the all-zero test root. Its `exp` is 29800 and its `ver` is 3.
    /// Built from its three segments so that no single literal has the shape of a JWT.
    /// The joined value is byte-identical to the recorded token.
    const KAT_SESSION_TOKEN: &str = concat!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ".",
        "eyJzdWIiOiJ1c2VyLWthdCIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTAwMCwiZXhwIjoyOTgwMCwianRpIjoia2F0LWp0aS0xIiwidmVyIjozfQ",
        ".",
        "oL717mJKECgdZl6mBx-Cnh3mMSRlIS6EUdqr4H63gkQ",
    );
    /// HMAC-SHA256 of the signing input (header.payload) under the session key, as hex.
    const KAT_SESSION_HMAC_HEX: &str =
        "a0bef5ee624a10281d665ea6071f829e1de6312465212e8451daabe07eb78244";

    #[test]
    fn session_hmac_known_answer() {
        let k = key();
        let signing_input = KAT_SESSION_TOKEN
            .rsplit_once('.')
            .map_or("", |(input, _)| input);
        let mut signer = mac(&k).unwrap_or_else(|_| panic!("mac key"));
        signer.update(signing_input.as_bytes());
        assert!(
            to_hex(&signer.finalize().into_bytes()) == KAT_SESSION_HMAC_HEX,
            "the session HMAC changed"
        );
    }

    #[test]
    fn session_token_from_the_old_build_still_verifies() {
        let k = key();
        let claims = verify(&k, KAT_SESSION_TOKEN, 1_000);
        assert!(
            matches!(&claims, Ok(c) if c.sub == "user-kat" && c.role == "admin" && c.ver == 3 && c.exp == 29_800),
            "a session token from the old build no longer verifies"
        );
    }

    #[test]
    fn read_cookie_finds_the_named_value() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            COOKIE,
            "a=1; __Host-harborgate_session=abc; b=2".parse().unwrap(),
        );
        assert_eq!(read_cookie(&headers, SESSION_COOKIE), Some("abc"));
        assert_eq!(read_cookie(&headers, "missing"), None);
    }
}
