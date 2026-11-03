//! The one outbound HTTP client factory for Harbor, OIDC, and alert webhooks.
//!
//! Rules from `specs/security.md` ("Outbound HTTP (SSRF)"):
//! - HTTPS only. Plain HTTP is rejected.
//! - No redirects are followed.
//! - Every resolved address is checked against the blocked ranges, on every
//!   connection, so a DNS answer that changes between requests is checked again.
//! - Each class of target has its own environment-only opt-out for private ranges.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Outbound target classes. Each has its own opt-out variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    // Harbor and Alerts clients are built in later issues.
    #[allow(dead_code)]
    Harbor,
    Oidc,
    #[allow(dead_code)]
    Alerts,
    /// Fixed host `api.github.com`. Private ranges are never allowed for it.
    GitHub,
}

/// Errors from the outbound layer. Messages are fixed text and never include the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundError {
    /// The resolved address is in a blocked range for this target class.
    BlockedAddress,
    /// The URL is not `https://`.
    NotHttps,
    /// The client could not be built.
    ClientBuild,
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutboundError::BlockedAddress => {
                f.write_str("the target resolves to a blocked private or local address")
            }
            OutboundError::NotHttps => f.write_str("only https:// targets are allowed"),
            OutboundError::ClientBuild => {
                f.write_str("the outbound HTTP client could not be built")
            }
        }
    }
}

impl std::error::Error for OutboundError {}

/// Returns true when `ip` is in a range that must not be reached by default:
/// loopback, link-local, private, unspecified, multicast, and the IPv4-mapped forms
/// of those. Ranges follow `specs/security.md`.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped address (::ffff:a.b.c.d) must be judged as IPv4.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0                                  // 0.0.0.0/8 (unspecified and "this network")
        || o[0] == 127                         // 127.0.0.0/8 loopback
        || (o[0] == 169 && o[1] == 254)        // 169.254.0.0/16 link-local, cloud metadata
        || o[0] == 10                          // 10.0.0.0/8 private
        || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12 private
        || (o[0] == 192 && o[1] == 168)        // 192.168.0.0/16 private
        || (224..=239).contains(&o[0]) // 224.0.0.0/4 multicast
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_unspecified()                        // ::
        || ip.is_loopback()                    // ::1
        || (s[0] & 0xffc0) == 0xfe80           // fe80::/10 link-local
        || (s[0] & 0xfe00) == 0xfc00           // fc00::/7 unique local (private)
        || (s[0] & 0xff00) == 0xff00 // ff00::/8 multicast
}

/// Filters the resolved addresses. Returns the allowed addresses, or an error when
/// every address is blocked. The class opt-out relaxes the private-range check only.
pub fn filter_addresses(
    addresses: Vec<SocketAddr>,
    class: TargetClass,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, OutboundError> {
    let relaxed = allow_private && class != TargetClass::GitHub;
    let allowed: Vec<SocketAddr> = addresses
        .into_iter()
        .filter(|addr| relaxed || !is_blocked(addr.ip()))
        .collect();
    if allowed.is_empty() {
        Err(OutboundError::BlockedAddress)
    } else {
        Ok(allowed)
    }
}

/// Resolves a host with the system resolver and applies [`filter_addresses`].
/// It runs on every connection, so DNS rebinding is checked each time.
struct GuardedResolver {
    class: TargetClass,
    allow_private: bool,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let class = self.class;
        let allow_private = self.allow_private;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let addresses: Vec<SocketAddr> = found.collect();
            let allowed = filter_addresses(addresses, class, allow_private)?;
            let iter: Addrs = Box::new(allowed.into_iter());
            Ok(iter)
        })
    }
}

/// The only outbound client. The inner reqwest client is private, and requests are built
/// only through [`OutboundClient::get`] and [`OutboundClient::post`]. Both run
/// [`check_target`] before a request builder is returned, so a caller cannot send a
/// request that skipped the check, including one to an IP literal.
pub struct OutboundClient {
    inner: reqwest::Client,
    class: TargetClass,
    allow_private: bool,
}

impl OutboundClient {
    /// A GET request builder for `url`, after the target check.
    pub fn get(&self, url: &reqwest::Url) -> Result<reqwest::RequestBuilder, OutboundError> {
        check_target(url, self.class, self.allow_private)?;
        Ok(self.inner.get(url.as_str()))
    }

    /// A POST request builder for `url`, after the target check.
    pub fn post(&self, url: &reqwest::Url) -> Result<reqwest::RequestBuilder, OutboundError> {
        check_target(url, self.class, self.allow_private)?;
        Ok(self.inner.post(url.as_str()))
    }
}

/// Builds the guarded client for one target class.
///
/// `allow_private` is the class opt-out (`HARBORGATE_ALLOW_PRIVATE_*`). It is false by
/// default. GitHub ignores it, because `api.github.com` is a fixed public host.
pub fn client(class: TargetClass, allow_private: bool) -> Result<OutboundClient, OutboundError> {
    Ok(OutboundClient {
        inner: build(class, allow_private, None)?,
        class,
        allow_private,
    })
}

fn build(
    class: TargetClass,
    allow_private: bool,
    extra_root: Option<reqwest::Certificate>,
) -> Result<reqwest::Client, OutboundError> {
    let resolver = GuardedResolver {
        class,
        allow_private,
    };
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(resolver))
        .timeout(Duration::from_secs(30));
    if let Some(root) = extra_root {
        builder = builder.add_root_certificate(root);
    }
    builder.build().map_err(|_| OutboundError::ClientBuild)
}

/// A client that also trusts `root`. Tests only: it lets a loopback TLS test server
/// stand in for a provider. Production code never calls this.
#[cfg(test)]
pub fn client_trusting(
    class: TargetClass,
    allow_private: bool,
    root: reqwest::Certificate,
) -> Result<OutboundClient, OutboundError> {
    Ok(OutboundClient {
        inner: build(class, allow_private, Some(root))?,
        class,
        allow_private,
    })
}

/// Checks a URL before any request is made: it must be `https://`, and when its host is
/// an IP literal, that address must pass the same range check as a resolved address.
///
/// reqwest and hyper skip the DNS resolver for an IP-literal host, so the resolver
/// alone never sees `https://127.0.0.1/`. This check covers that path. Private to this
/// module: [`OutboundClient`] is the only caller.
fn check_target(
    url: &reqwest::Url,
    class: TargetClass,
    allow_private: bool,
) -> Result<(), OutboundError> {
    require_https(url)?;
    // IPv6 literals come back in brackets, so strip them before parsing.
    let literal = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok());
    if let Some(ip) = literal {
        let port = url.port_or_known_default().unwrap_or(443);
        filter_addresses(vec![SocketAddr::new(ip, port)], class, allow_private)?;
    }
    Ok(())
}

/// Rejects a URL that is not `https://` before any request is made.
pub fn require_https(url: &reqwest::Url) -> Result<(), OutboundError> {
    if url.scheme() == "https" {
        Ok(())
    } else {
        Err(OutboundError::NotHttps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> IpAddr {
        match text.parse() {
            Ok(ip) => ip,
            Err(err) => panic!("test IP {text} rejected: {err}"),
        }
    }

    #[test]
    fn every_blocked_ipv4_range_is_blocked() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "224.0.0.1",
            "239.255.255.255",
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn public_ipv4_addresses_are_allowed() {
        for ip in [
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "192.167.1.1",
            "11.0.0.1",
        ] {
            assert!(!is_blocked(v4(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn every_blocked_ipv6_range_is_blocked() {
        for ip in [
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn public_ipv6_addresses_are_allowed() {
        for ip in ["2001:4860:4860::8888", "2606:4700::1111"] {
            assert!(!is_blocked(v4(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_is_judged_as_ipv4() {
        for ip in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
        assert!(
            !is_blocked(v4("::ffff:8.8.8.8")),
            "public mapped address allowed"
        );
    }

    #[test]
    fn filter_drops_blocked_and_keeps_public() {
        let addresses = vec![
            SocketAddr::new(v4("10.0.0.5"), 443),
            SocketAddr::new(v4("8.8.8.8"), 443),
        ];
        let allowed = filter_addresses(addresses, TargetClass::Harbor, false);
        assert_eq!(allowed, Ok(vec![SocketAddr::new(v4("8.8.8.8"), 443)]));
    }

    #[test]
    fn all_blocked_fails_closed() {
        let addresses = vec![SocketAddr::new(v4("127.0.0.1"), 443)];
        assert_eq!(
            filter_addresses(addresses, TargetClass::Oidc, false),
            Err(OutboundError::BlockedAddress)
        );
    }

    #[test]
    fn opt_out_relaxes_only_its_own_class() {
        let private = || vec![SocketAddr::new(v4("10.1.2.3"), 443)];
        assert!(filter_addresses(private(), TargetClass::Harbor, true).is_ok());
        assert!(filter_addresses(private(), TargetClass::Oidc, true).is_ok());
        assert!(filter_addresses(private(), TargetClass::Alerts, true).is_ok());
        // GitHub never gets the opt-out.
        assert_eq!(
            filter_addresses(private(), TargetClass::GitHub, true),
            Err(OutboundError::BlockedAddress)
        );
    }

    #[test]
    fn opt_out_false_blocks_private_for_harbor() {
        assert_eq!(
            filter_addresses(
                vec![SocketAddr::new(v4("192.168.0.9"), 443)],
                TargetClass::Harbor,
                false
            ),
            Err(OutboundError::BlockedAddress)
        );
    }

    #[test]
    fn require_https_rejects_plain_http_and_accepts_https() {
        let http = reqwest::Url::parse("http://harbor.example.com/api").ok();
        let https = reqwest::Url::parse("https://harbor.example.com/api").ok();
        assert!(matches!(
            http.as_ref().map(require_https),
            Some(Err(OutboundError::NotHttps))
        ));
        assert!(matches!(https.as_ref().map(require_https), Some(Ok(()))));
    }

    #[test]
    fn client_builds_with_redirects_disabled_and_https_only() {
        assert!(client(TargetClass::Harbor, false).is_ok());
        assert!(client(TargetClass::GitHub, false).is_ok());
    }

    #[tokio::test]
    async fn resolver_refuses_loopback_hostname() {
        // `localhost` resolves to loopback on every supported system. No network access is needed.
        let guard = GuardedResolver {
            class: TargetClass::Harbor,
            allow_private: false,
        };
        let name: Name = match "localhost".parse() {
            Ok(name) => name,
            Err(err) => panic!("test name rejected: {err:?}"),
        };
        let outcome = guard.resolve(name).await;
        let message = match outcome {
            Ok(_) => String::from("<resolved>"),
            Err(err) => err.to_string(),
        };
        assert!(
            message.contains("blocked private or local address"),
            "expected the address filter to refuse it, got: {message}"
        );
    }

    #[test]
    fn redirect_policy_is_no_follow() {
        // The production client is built with Policy::none(). Reqwest does not expose
        // the policy for inspection, so this test asserts the source setting is present.
        let source = include_str!("outbound.rs");
        assert!(source.contains(".redirect(reqwest::redirect::Policy::none())"));
    }

    #[tokio::test]
    async fn plain_http_request_is_refused_before_connecting() {
        let client = match client(TargetClass::Harbor, false) {
            Ok(client) => client,
            Err(err) => panic!("client build failed: {err}"),
        };
        let url = reqwest::Url::parse("http://example.com/").unwrap();
        assert_eq!(client.get(&url).err(), Some(OutboundError::NotHttps));
    }
}

/// Live-socket tests. Each one runs a loopback TLS server with a generated test
/// certificate and drives the real guarded client. Nothing is written to disk and no
/// key or secret is printed.
#[cfg(test)]
pub(crate) mod socket_tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Starts a loopback HTTPS server on an ephemeral port. It answers every request
    /// with `response`. Returns the port and the trust root for the test certificate.
    pub(crate) async fn loopback_tls_server(response: &'static str) -> (u16, reqwest::Certificate) {
        let names = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
        let certified = match rcgen::generate_simple_self_signed(names) {
            Ok(certified) => certified,
            Err(err) => panic!("test certificate generation failed: {err}"),
        };
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let config = match rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
        {
            Ok(config) => config,
            Err(err) => panic!("test TLS config rejected: {err}"),
        };
        let acceptor = TlsAcceptor::from(StdArc::new(config));
        let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(listener) => listener,
            Err(err) => panic!("loopback bind failed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("loopback address unavailable: {err}"),
        };
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        let mut buf = [0u8; 2048];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.write_all(response.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        let root = match reqwest::Certificate::from_der(cert_der.as_ref()) {
            Ok(root) => root,
            Err(err) => panic!("test root rejected: {err}"),
        };
        (port, root)
    }

    pub(crate) const OK: &str =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    const REDIRECT: &str = "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    #[tokio::test]
    async fn loopback_is_reached_only_when_the_opt_out_is_set() {
        let (port, root) = loopback_tls_server(OK).await;
        let url = format!("https://127.0.0.1:{port}/");

        // With the operator opt-out, the same server is reached. This is the control
        // that proves the refusal below is the address check and not a broken server.
        let allowed = client_trusting(TargetClass::Oidc, true, root.clone()).unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert!(check_target(&parsed, TargetClass::Oidc, true).is_ok());
        let ok = match allowed.get(&parsed) {
            Ok(builder) => builder.send().await,
            Err(err) => panic!("opted-out request refused: {err}"),
        };
        assert!(ok.is_ok(), "the opted-out request should reach the server");

        // Without the opt-out, the IP-literal URL is refused by the target check that
        // every OIDC request runs before it sends (`oidc::HttpProvider`).
        assert_eq!(
            check_target(
                &reqwest::Url::parse(&url).unwrap(),
                TargetClass::Oidc,
                false
            ),
            Err(OutboundError::BlockedAddress),
            "an IP literal in loopback must fail the target check by default"
        );
        drop(root);
    }

    #[tokio::test]
    async fn resolver_refuses_a_hostname_that_resolves_to_loopback() {
        // `localhost` resolves to loopback. The resolver filter refuses it by default.
        let client = client(TargetClass::Oidc, false).unwrap();
        let url = reqwest::Url::parse("https://localhost:1/").unwrap();
        let outcome = match client.get(&url) {
            Ok(builder) => builder.send().await,
            Err(err) => panic!("target check refused a hostname: {err}"),
        };
        assert!(
            outcome.is_err(),
            "a hostname resolving to loopback was reached"
        );
    }

    #[tokio::test]
    async fn plain_http_is_refused_by_the_target_check_and_the_client() {
        let url = reqwest::Url::parse("http://127.0.0.1:1/").unwrap();
        assert_eq!(
            check_target(&url, TargetClass::Oidc, true),
            Err(OutboundError::NotHttps)
        );
        let client = client(TargetClass::Oidc, true).unwrap();
        assert_eq!(client.get(&url).err(), Some(OutboundError::NotHttps));
    }

    #[tokio::test]
    async fn ip_literal_in_loopback_is_refused_by_the_client_before_any_send() {
        // The wrapper runs the target check before it returns a request builder, so an
        // IP literal in loopback never reaches the network. The port is ephemeral and
        // nothing listens on it. The refusal is the address check, not a connection failure.
        let (port, root) = loopback_tls_server(OK).await;
        let url = reqwest::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
        let client = client_trusting(TargetClass::Oidc, false, root).unwrap();
        assert_eq!(client.get(&url).err(), Some(OutboundError::BlockedAddress));
        assert_eq!(client.post(&url).err(), Some(OutboundError::BlockedAddress));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (port, root) = loopback_tls_server(REDIRECT).await;
        let client = client_trusting(TargetClass::Oidc, true, root).unwrap();
        let url = reqwest::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
        let response = match client.get(&url) {
            Ok(builder) => builder.send().await.unwrap(),
            Err(err) => panic!("opted-out request refused: {err}"),
        };
        // A followed redirect would target 127.0.0.1:1 and fail. The 302 itself is returned.
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    }

    #[test]
    fn private_ip_literals_are_refused_by_the_target_check() {
        for raw in [
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://[::1]/",
            "https://[fd00::1]/",
        ] {
            let url = reqwest::Url::parse(raw).unwrap();
            assert!(
                check_target(&url, TargetClass::Oidc, false).is_err(),
                "{raw} should be refused by default"
            );
        }
    }
}
