//! Serves the built frontend. Sources: `specs/security.md` ("Security headers": the HTML
//! policy and the per-response nonce) and `specs/frontend.md` ("Process rules").
//!
//! `index.html` is a template. Vite writes the placeholder [`NONCE_PLACEHOLDER`] into it
//! (`html.cspNonce`), and every HTML response swaps in a fresh nonce and sends the same
//! value in its `Content-Security-Policy` header. In debug builds `rust-embed` reads
//! `frontend/dist` from disk, so `npm run build` then `cargo run` serves the app.

use axum::{
    extract::Path,
    http::{HeaderValue, Method, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rust_embed::RustEmbed;

use crate::error::AppError;
use crate::services::ids::os_random_bytes;

/// The fixed value Vite writes for `html.cspNonce` in `vite.config.ts`.
pub const NONCE_PLACEHOLDER: &str = "HG_CSP_NONCE";

#[derive(RustEmbed)]
#[folder = "../frontend/dist/"]
#[allow_missing = true]
struct Assets;

/// A new nonce: 16 random bytes, base64 (standard alphabet). One per HTML response.
pub fn fresh_nonce() -> Result<String, AppError> {
    let bytes = os_random_bytes::<16>()?;
    Ok(STANDARD.encode(bytes))
}

/// Replaces every placeholder in the template with `nonce`.
pub fn render_index(template: &str, nonce: &str) -> String {
    template.replace(NONCE_PLACEHOLDER, nonce)
}

/// The HTML policy from `specs/security.md`. There is no `'unsafe-inline'`, no
/// `'unsafe-eval'`, and no `data:` source.
pub fn html_csp(nonce: &str) -> String {
    format!(
        "default-src 'self'; style-src 'self' 'nonce-{nonce}'; frame-ancestors 'none'; \
         base-uri 'none'; form-action 'self'; object-src 'none'"
    )
}

/// One HTML response: a fresh nonce in the body and in the CSP header, never cached.
pub fn spa_response(template: &str) -> Response {
    let Ok(nonce) = fresh_nonce() else {
        return AppError::InternalError.into_response();
    };
    let body = render_index(template, &nonce);
    let Ok(policy) = HeaderValue::from_str(&html_csp(&nonce)) else {
        return AppError::InternalError.into_response();
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    response
}

/// `GET /assets/{*path}`: a hashed build file, cacheable for a year.
pub async fn asset(Path(path): Path<String>) -> Response {
    let Some(file) = Assets::get(&format!("assets/{path}")) else {
        return AppError::NotFound.into_response();
    };
    let Ok(mime) = HeaderValue::from_str(file.metadata.mimetype()) else {
        return AppError::InternalError.into_response();
    };
    let mut response = file.data.into_owned().into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, mime);
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}

/// The router fallback. An `/api/` path or a non-`GET` request is a JSON 404. Anything
/// else is the single-page app, so client-side routes survive a reload.
pub async fn spa(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if method != Method::GET || path == "/api" || path.starts_with("/api/") {
        return AppError::NotFound.into_response();
    }
    let Some(file) = Assets::get("index.html") else {
        return AppError::NotFound.into_response();
    };
    match std::str::from_utf8(&file.data) {
        Ok(template) => spa_response(template),
        Err(_) => AppError::InternalError.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body};
    use tower::ServiceExt;

    /// What Vite emits, with the placeholder in the three places it appears.
    const TEMPLATE: &str = concat!(
        "<!doctype html><html><head>",
        "<meta property=\"csp-nonce\" nonce=\"HG_CSP_NONCE\">",
        "<script type=\"module\" src=\"/assets/a.js\" nonce=\"HG_CSP_NONCE\"></script>",
        "<link rel=\"stylesheet\" href=\"/assets/a.css\" nonce=\"HG_CSP_NONCE\">",
        "</head><body><div id=\"root\"></div></body></html>"
    );

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("test setup");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// The `<n>` of `'nonce-<n>'` in the response's CSP header.
    fn header_nonce(response: &Response) -> String {
        let policy = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok())
            .expect("test setup");
        let after = policy.split("'nonce-").nth(1).expect("test setup");
        after.split('\'').next().unwrap_or_default().to_owned()
    }

    #[tokio::test]
    async fn each_html_response_has_a_fresh_nonce() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let response = spa_response(TEMPLATE);
            let nonce = header_nonce(&response);
            // 16 bytes in standard base64 is 24 characters.
            assert_eq!(nonce.len(), 24);
            assert!(seen.insert(nonce), "a nonce was reused");
        }
    }

    #[tokio::test]
    async fn header_and_html_carry_the_same_nonce() {
        let response = spa_response(TEMPLATE);
        let nonce = header_nonce(&response);
        assert!(!nonce.is_empty());
        let body = body_text(response).await;
        // The meta, script, and link tags each carry it.
        assert_eq!(body.matches(&format!("nonce=\"{nonce}\"")).count(), 3);
    }

    #[tokio::test]
    async fn no_placeholder_is_left() {
        let response = spa_response(TEMPLATE);
        let body = body_text(response).await;
        assert!(!body.contains(NONCE_PLACEHOLDER));
        assert_eq!(
            render_index("a HG_CSP_NONCE b HG_CSP_NONCE", "x"),
            "a x b x"
        );
    }

    #[tokio::test]
    async fn html_is_no_store() {
        let response = spa_response(TEMPLATE);
        let value = |name| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        assert_eq!(value(header::CACHE_CONTROL).as_deref(), Some("no-store"));
        assert_eq!(
            value(header::CONTENT_TYPE).as_deref(),
            Some("text/html; charset=utf-8")
        );
        let policy = value(header::CONTENT_SECURITY_POLICY).expect("test setup");
        assert!(!policy.contains("unsafe-inline"));
        assert!(!policy.contains("unsafe-eval"));
        assert!(!policy.contains("data:"));
        assert!(policy.starts_with("default-src 'self'; style-src 'self' 'nonce-"));
        assert!(policy.ends_with(
            "'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
        ));
    }

    #[tokio::test]
    async fn unknown_api_path_is_a_json_404() {
        let app = Router::new().fallback(spa);
        for (method, uri) in [
            ("GET", "/api/v1/nope"),
            ("GET", "/api"),
            ("POST", "/some/page"),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("test setup");
            let response = app.clone().oneshot(request).await.expect("test setup");
            assert_eq!(response.status().as_u16(), 404, "{method} {uri}");
            let body = body_text(response).await;
            let json: serde_json::Value = serde_json::from_str(&body).expect("test setup");
            assert_eq!(json["error"]["code"], "not_found", "{method} {uri}");
        }
    }
}
