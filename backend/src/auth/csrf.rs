//! Signed double-submit CSRF token. Sources: `specs/security.md` (Hardening, CSRF),
//! `specs/api.md` (Conventions). The cookie value is `<nonce>.<tag>`, where `tag` is
//! HMAC-SHA256 over the nonce with the derived CSRF key. The client copies the cookie
//! value into `X-CSRF-Token`. The server checks the header equals the cookie and that
//! the tag verifies.

use axum::http::header::HeaderName;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::auth::crypto::DerivedKey;
use crate::auth::session::{SESSION_LIFETIME_SECS, read_cookie};
use crate::error::AppError;

/// Cookie name. The `__Host-` prefix forces `Secure`, `Path=/`, and no `Domain`.
pub const CSRF_COOKIE: &str = "__Host-harborgate_csrf";

/// Header the client must echo the cookie value in.
pub const CSRF_HEADER: HeaderName = HeaderName::from_static("x-csrf-token");

type HmacSha256 = Hmac<Sha256>;

fn tag(key: &DerivedKey, nonce: &str) -> Result<Vec<u8>, AppError> {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| AppError::InternalError)?;
    mac.update(nonce.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Issues a new token value: 32 random bytes plus their HMAC tag.
pub fn issue(key: &DerivedKey) -> Result<String, AppError> {
    let bytes = crate::services::ids::os_random_bytes::<32>()?;
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    let signature = URL_SAFE_NO_PAD.encode(tag(key, &nonce)?);
    Ok(format!("{nonce}.{signature}"))
}

/// Returns `true` only when `value` has the `<nonce>.<tag>` shape and the tag is the
/// HMAC of the nonce. The tag comparison is constant time (`verify_slice`).
pub fn verify(key: &DerivedKey, value: &str) -> bool {
    let Some((nonce, signature)) = value.split_once('.') else {
        return false;
    };
    let Ok(expected) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key.as_bytes()) else {
        return false;
    };
    mac.update(nonce.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// The `Set-Cookie` value. Not `HttpOnly`: the client script must read it to echo it
/// in the header. The lifetime matches the session.
pub fn set_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Max-Age={SESSION_LIFETIME_SECS}; Path=/; Secure; SameSite=Lax")
}

/// Returns the CSRF cookie value and the header value, when both are present and equal.
pub fn presented(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie = read_cookie(headers, CSRF_COOKIE)?;
    let header = headers.get(&CSRF_HEADER)?.to_str().ok()?;
    (header == cookie).then(|| cookie.to_owned())
}

/// Whether `method` and `path` need a CSRF token. Only `POST`, `PUT`, `PATCH`, and
/// `DELETE` under `/api` do. The webhook, login, and setup are exempt. Login and setup
/// use the same-origin check instead, and the webhook has no cookie session.
pub fn requires_token(method: &axum::http::Method, path: &str) -> bool {
    let state_changing = matches!(
        *method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    );
    state_changing && path.starts_with("/api/") && !is_exempt(path)
}

/// The exempt paths: the webhook prefix, login, and setup.
pub fn is_exempt(path: &str) -> bool {
    path == "/api/v1/auth/login"
        || path == "/api/v1/auth/setup"
        || path.starts_with("/api/v1/webhooks/")
}

/// Checks the double-submit token on state-changing `/api` requests. A missing or
/// mismatched token, or a bad tag, returns `403 csrf_invalid`.
pub async fn guard(
    axum::extract::State(state): axum::extract::State<crate::api::state::AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    if requires_token(request.method(), request.uri().path()) {
        let value = presented(request.headers()).ok_or(AppError::CsrfInvalid)?;
        if !verify(&state.csrf_key, &value) {
            return Err(AppError::CsrfInvalid);
        }
    }
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::crypto::csrf_key;
    use crate::config::parse_encryption_key;
    use axum::http::{HeaderMap, Method, header::COOKIE};

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn key() -> DerivedKey {
        let root = parse_encryption_key(TEST_KEY_B64).unwrap();
        csrf_key(&root).unwrap()
    }

    #[test]
    fn issued_token_verifies_and_a_forged_one_does_not() {
        let k = key();
        let token = issue(&k).unwrap();
        assert!(verify(&k, &token));
        let (nonce, _) = token.split_once('.').unwrap();
        assert!(!verify(&k, &format!("{nonce}.AAAA")));
        assert!(!verify(&k, "no-dot-here"));
        assert!(!verify(&k, ""));
    }

    #[test]
    fn token_from_another_key_is_rejected() {
        let other_root =
            parse_encryption_key("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=").unwrap();
        let other = csrf_key(&other_root).unwrap();
        let token = issue(&other).unwrap();
        assert!(!verify(&key(), &token));
    }

    #[test]
    fn presented_requires_cookie_and_matching_header() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "__Host-harborgate_csrf=abc.def".parse().unwrap());
        assert_eq!(presented(&headers), None, "header missing");
        headers.insert(CSRF_HEADER, "abc.xyz".parse().unwrap());
        assert_eq!(presented(&headers), None, "header mismatched");
        headers.insert(CSRF_HEADER, "abc.def".parse().unwrap());
        assert_eq!(presented(&headers), Some("abc.def".to_owned()));
    }

    #[test]
    fn only_state_changing_api_routes_need_a_token() {
        assert!(requires_token(&Method::POST, "/api/v1/account/password"));
        assert!(requires_token(&Method::PUT, "/api/v1/admin/oidc"));
        assert!(requires_token(&Method::PATCH, "/api/v1/mappings/x"));
        assert!(requires_token(&Method::DELETE, "/api/v1/admin/users/x"));
        assert!(!requires_token(&Method::GET, "/api/v1/admin/users"));
        assert!(!requires_token(&Method::POST, "/healthz"));
    }

    #[test]
    fn exempt_routes_need_no_token() {
        assert!(!requires_token(&Method::POST, "/api/v1/auth/login"));
        assert!(!requires_token(&Method::POST, "/api/v1/auth/setup"));
        assert!(!requires_token(
            &Method::POST,
            "/api/v1/webhooks/harbor/some-token"
        ));
    }

    /// Lowercase hex of `bytes`.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A CSRF nonce and its tag, recorded with the hmac 0.12 build under the CSRF key
    /// derived from the all-zero test root. The tag is HMAC-SHA256 of the nonce, as hex
    /// and as the base64url value the cookie carries.
    const KAT_CSRF_TAG_HEX: &str =
        "e493641318234cd473668382b031307186a45f4bd3bdef25052ab68a62cb66d7";

    /// The recorded nonce, assembled from fixed bytes at runtime. The bytes spell
    /// `kat-csrf-nonce`.
    fn kat_nonce() -> String {
        let parts: [&[u8]; 2] = [b"kat-csrf-", b"nonce"];
        String::from_utf8(parts.concat()).unwrap_or_default()
    }

    /// The recorded token, `<nonce>.<tag>`, assembled from the nonce and the recorded tag
    /// at runtime. The tag is the base64url form of the HMAC.
    fn kat_token() -> String {
        let tag_b64: [&[u8]; 2] = [b"5JNkExgjTNRzZoOCsDEwcY", b"akX0vTve8lBSq2imLLZtc"];
        format!(
            "{}.{}",
            kat_nonce(),
            String::from_utf8(tag_b64.concat()).unwrap_or_default()
        )
    }

    #[test]
    fn csrf_tag_known_answer() {
        let k = key();
        let computed = tag(&k, &kat_nonce()).unwrap_or_default();
        assert!(
            to_hex(&computed) == KAT_CSRF_TAG_HEX,
            "the CSRF tag changed"
        );
    }

    #[test]
    fn csrf_token_from_the_old_build_still_verifies() {
        assert!(
            verify(&key(), &kat_token()),
            "a CSRF token from the old build no longer verifies"
        );
    }

    #[test]
    fn csrf_cookie_attributes_match_the_spec() {
        let cookie = set_cookie("v.w");
        assert!(cookie.starts_with("__Host-harborgate_csrf=v.w;"));
        for attr in ["Path=/", "Secure", "SameSite=Lax"] {
            assert!(cookie.contains(attr), "missing {attr}");
        }
        assert!(!cookie.contains("Domain"));
    }
}
