//! HTTP hardening shared by every route: security headers, the client IP rule,
//! a reusable fixed-window rate limiter, and an access log that records route
//! templates instead of raw URIs.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{HeaderName, HeaderValue, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::config::Cidr;
use crate::error::AppError;

/// Content-Security-Policy for every response. Decided in `specs/security.md`, "Hardening".
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

/// Adds the security headers to every response.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Resolves the client IP. The TCP peer is used unless it is inside a trusted proxy
/// range. In that case the client IP is the rightmost `X-Forwarded-For` address that
/// is not itself trusted. With no trusted proxies the header is ignored.
///
/// Entries that do not parse as an IP address are skipped. If nothing usable remains,
/// the peer address is returned.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[Cidr]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(peer) {
        return peer;
    }
    let Some(header_value) = forwarded_for else {
        return peer;
    };
    header_value
        .split(',')
        .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
        .rev()
        .find(|ip| !is_trusted(*ip))
        .unwrap_or(peer)
}

/// Most keys one limiter holds at once. A new key past this cap is refused (fail closed)
/// unless expired windows can be swept to make room.
pub const MAX_KEYS: usize = 100_000;
/// Expired windows are swept on every this-many-th call, even when the map is not full.
const SWEEP_EVERY: u64 = 1_024;

/// Fixed-window rate limiter keyed by a string. The clock is passed in, so tests are
/// deterministic. A rejected request returns the seconds until the window resets, for
/// `Retry-After`. Memory is bounded: expired windows are removed, and the key count
/// never exceeds [`MAX_KEYS`].
#[derive(Clone)]
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    buckets: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    /// Calls to `check`, shared by clones. Drives the periodic sweep.
    calls: Arc<AtomicU64>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            calls: Arc::new(AtomicU64::new(0)),
        }
    }

    /// True when `key` has used its whole budget in the current window. Does not record
    /// a request, so it can gate a request that is only counted when it fails.
    pub fn is_exhausted(&self, key: &str, now: Instant) -> bool {
        let Ok(buckets) = self.buckets.lock() else {
            return false;
        };
        match buckets.get(key) {
            Some((start, count)) => {
                now.duration_since(*start) < self.window && *count >= self.limit
            }
            None => false,
        }
    }

    /// Records one request for `key` at `now`. Returns `Ok(())` when it is allowed, or
    /// `Err(seconds)` with the wait before the next request is allowed. A new key that
    /// would exceed [`MAX_KEYS`] is refused with `Err`, and the window length is returned.
    pub fn check(&self, key: &str, now: Instant) -> Result<(), u64> {
        let mut buckets = self.buckets.lock().map_err(|_| 1_u64)?;
        let call = self.calls.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if call.is_multiple_of(SWEEP_EVERY) {
            self.sweep(&mut buckets, now);
        }
        if buckets.len() >= MAX_KEYS && !buckets.contains_key(key) {
            self.sweep(&mut buckets, now);
            if buckets.len() >= MAX_KEYS {
                return Err(self.window.as_secs().max(1));
            }
        }
        let entry = buckets.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 < self.limit {
            entry.1 += 1;
            return Ok(());
        }
        let elapsed = now.duration_since(entry.0);
        let remaining = self.window.saturating_sub(elapsed);
        Err(remaining.as_secs().max(1))
    }

    /// Removes every entry whose window has ended at `now`.
    fn sweep(&self, buckets: &mut HashMap<String, (Instant, u32)>, now: Instant) {
        let window = self.window;
        buckets.retain(|_, entry| now.duration_since(entry.0) < window);
    }

    /// The number of keys currently held. Test builds only.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buckets.lock().map_or(0, |buckets| buckets.len())
    }
}

/// Builds a `429 Too Many Requests` response with `Retry-After` in seconds.
pub fn too_many_requests(retry_after_secs: u64) -> Response {
    let mut response = AppError::RateLimited.into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// Logs one line per request: method, route template, status, and latency.
/// The raw URI is never logged, so path-embedded tokens stay out of the log.
pub async fn access_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let started = Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        method = %method,
        route = %route,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "request"
    );
    response
}

/// Resolved client IP for one request, stored as a request extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Shared state for the client-IP middleware: the trusted proxy ranges.
#[derive(Clone)]
pub struct TrustedProxies(pub Arc<Vec<Cidr>>);

/// Where the resolved client IP came from: the TCP peer, or a trusted
/// `X-Forwarded-For` entry. Shown on the admin health route so operators can check
/// `HARBORGATE_TRUSTED_PROXIES` (`specs/api.md`, Health).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIpSource {
    Peer,
    XForwardedFor,
}

impl ClientIpSource {
    /// The wire value: `peer` or `x-forwarded-for`.
    pub fn as_str(self) -> &'static str {
        match self {
            ClientIpSource::Peer => "peer",
            ClientIpSource::XForwardedFor => "x-forwarded-for",
        }
    }
}

/// Stores the resolved client IP and its source as request extensions.
pub async fn resolve_client_ip(
    State(trusted): State<TrustedProxies>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let forwarded = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    let ip = client_ip(peer.ip(), forwarded, &trusted.0);
    let source = if ip == peer.ip() {
        ClientIpSource::Peer
    } else {
        ClientIpSource::XForwardedFor
    };
    request.extensions_mut().insert(ClientIp(ip));
    request.extensions_mut().insert(source);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        match Cidr::parse(text) {
            Ok(value) => value,
            Err(reason) => panic!("test CIDR {text} rejected: {reason}"),
        }
    }

    /// Unwraps a test-only `Result`, panicking with its error text.
    trait TestResult<T> {
        fn expect_test_request(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestResult<T> for Result<T, E> {
        fn expect_test_request(self) -> T {
            match self {
                Ok(value) => value,
                Err(err) => panic!("test request setup failed: {err:?}"),
            }
        }
    }

    fn ip(text: &str) -> IpAddr {
        match text.parse() {
            Ok(value) => value,
            Err(err) => panic!("test IP {text} rejected: {err}"),
        }
    }

    #[test]
    fn untrusted_peer_ignores_spoofed_forwarded_for() {
        let trusted = [cidr("172.18.0.0/16")];
        // A client on the open internet sends a fake X-Forwarded-For. It must be ignored.
        let resolved = client_ip(ip("203.0.113.9"), Some("127.0.0.1"), &trusted);
        assert_eq!(resolved, ip("203.0.113.9"));
    }

    #[test]
    fn empty_trusted_list_ignores_forwarded_for() {
        let resolved = client_ip(ip("172.18.0.5"), Some("198.51.100.4"), &[]);
        assert_eq!(resolved, ip("172.18.0.5"));
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_entry() {
        let trusted = [cidr("172.18.0.0/16"), cidr("10.0.0.0/8")];
        // The chain is client, then an internal proxy, then the trusted peer.
        let resolved = client_ip(ip("172.18.0.2"), Some("198.51.100.7, 10.0.0.4"), &trusted);
        assert_eq!(resolved, ip("198.51.100.7"));
    }

    #[test]
    fn trusted_peer_without_header_uses_peer() {
        let trusted = [cidr("172.18.0.0/16")];
        assert_eq!(
            client_ip(ip("172.18.0.2"), None, &trusted),
            ip("172.18.0.2")
        );
    }

    #[test]
    fn forged_leftmost_entry_is_not_chosen() {
        let trusted = [cidr("172.18.0.0/16")];
        // The client prepends a fake address. Only the rightmost untrusted one counts.
        let resolved = client_ip(ip("172.18.0.2"), Some("127.0.0.1, 198.51.100.7"), &trusted);
        assert_eq!(resolved, ip("198.51.100.7"));
    }

    #[test]
    fn unparseable_entries_are_skipped() {
        let trusted = [cidr("172.18.0.0/16")];
        let resolved = client_ip(ip("172.18.0.2"), Some("198.51.100.7, not-an-ip"), &trusted);
        assert_eq!(resolved, ip("198.51.100.7"));
    }

    #[test]
    fn ipv6_client_through_trusted_proxy() {
        let trusted = [cidr("fd00:1::/48")];
        let resolved = client_ip(ip("fd00:1::2"), Some("2001:db8::9"), &trusted);
        assert_eq!(resolved, ip("2001:db8::9"));
    }

    #[test]
    fn limiter_allows_up_to_the_limit_then_rejects_with_retry_after() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        assert!(limiter.check("client", start).is_ok());
        assert!(limiter.check("client", start).is_ok());
        let wait = limiter.check("client", start);
        assert!(
            matches!(wait, Err(secs) if (1..=60).contains(&secs)),
            "{wait:?}"
        );
    }

    #[test]
    fn limiter_resets_after_the_window() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let start = Instant::now();
        assert!(limiter.check("client", start).is_ok());
        assert!(limiter.check("client", start).is_err());
        assert!(
            limiter
                .check("client", start + Duration::from_secs(61))
                .is_ok()
        );
    }

    #[test]
    fn limiter_keys_are_independent() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let start = Instant::now();
        assert!(limiter.check("a", start).is_ok());
        assert!(limiter.check("b", start).is_ok());
    }

    #[test]
    fn unique_keys_do_not_grow_the_map_past_the_cap() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let start = Instant::now();
        let mut refused = 0_usize;
        for n in 0..(MAX_KEYS + 500) {
            if limiter.check(&format!("flood-{n}"), start).is_err() {
                refused += 1;
            }
        }
        assert!(limiter.len() <= MAX_KEYS, "map grew to {}", limiter.len());
        // Every key past the cap is refused, and the map does not grow.
        assert_eq!(refused, 500);
        assert_eq!(limiter.len(), MAX_KEYS);
    }

    #[test]
    fn ended_windows_are_swept() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let start = Instant::now();
        for n in 0..100 {
            assert!(limiter.check(&format!("old-{n}"), start).is_ok());
        }
        assert_eq!(limiter.len(), 100);
        // Well after every window has ended, the sweep runs on the 1,024th call.
        let later = start + Duration::from_secs(120);
        for n in 0..SWEEP_EVERY {
            assert!(limiter.check(&format!("new-{n}"), later).is_ok());
        }
        // The 100 old keys were removed. Only the new keys remain.
        assert_eq!(limiter.len(), SWEEP_EVERY as usize);
    }

    #[test]
    fn too_many_requests_sets_retry_after() {
        let response = too_many_requests(42);
        assert_eq!(response.status().as_u16(), 429);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
    }

    #[tokio::test]
    async fn security_headers_are_present_on_responses() {
        use axum::{Router, body::Body, routing::get};
        use tower::ServiceExt;

        let app = Router::new()
            .route("/x", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers));

        // A 404 from the fallback must carry the headers too.
        for uri in ["/x", "/no-such-route"] {
            let request = axum::http::Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect_test_request();
            let response = app.clone().oneshot(request).await.expect_test_request();
            assert_security_headers(response.headers());
        }
    }

    /// Runs one request through `resolve_client_ip` and returns the stored source.
    /// The router echoes the extension, so the test reads what the middleware stored.
    async fn source_for(trusted: Vec<Cidr>, peer: &str, forwarded: Option<&str>) -> String {
        use axum::{Router, body::Body, routing::get};
        use tower::ServiceExt;

        async fn echo(axum::Extension(source): axum::Extension<ClientIpSource>) -> &'static str {
            source.as_str()
        }

        let app = Router::new()
            .route("/x", get(echo))
            .layer(axum::middleware::from_fn_with_state(
                TrustedProxies(Arc::new(trusted)),
                resolve_client_ip,
            ));
        let mut builder = axum::http::Request::builder().uri("/x");
        if let Some(value) = forwarded {
            builder = builder.header("x-forwarded-for", value);
        }
        let mut request = builder.body(Body::empty()).expect_test_request();
        let peer_addr = SocketAddr::new(ip(peer), 8080);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer_addr));
        let response = app.oneshot(request).await.expect_test_request();
        let bytes = axum::body::to_bytes(response.into_body(), 64)
            .await
            .expect_test_request();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn client_ip_source_is_peer_without_trusted_forwarding() {
        // No trusted proxies: the header is ignored and the source is the peer.
        let source = source_for(Vec::new(), "203.0.113.9", Some("127.0.0.1")).await;
        assert_eq!(source, "peer");
        // A trusted peer with no header also resolves to the peer.
        let source = source_for(vec![cidr("172.18.0.0/16")], "172.18.0.2", None).await;
        assert_eq!(source, "peer");
    }

    #[tokio::test]
    async fn client_ip_source_is_forwarded_from_trusted_proxy() {
        let trusted = vec![cidr("172.18.0.0/16")];
        let source = source_for(trusted, "172.18.0.2", Some("198.51.100.7")).await;
        assert_eq!(source, "x-forwarded-for");
    }

    fn assert_security_headers(headers: &axum::http::HeaderMap) {
        assert_eq!(
            headers
                .get(header::CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some(CONTENT_SECURITY_POLICY)
        );
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
    }
}
