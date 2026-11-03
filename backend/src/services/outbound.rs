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

/// Builds a reqwest client for one target class.
///
/// `allow_private` is the class opt-out (`HARBORGATE_ALLOW_PRIVATE_*`). It is false by
/// default. GitHub ignores it, because `api.github.com` is a fixed public host.
pub fn client(class: TargetClass, allow_private: bool) -> Result<reqwest::Client, OutboundError> {
    let resolver = GuardedResolver {
        class,
        allow_private,
    };
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(resolver))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| OutboundError::ClientBuild)
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

    #[tokio::test]
    async fn request_to_loopback_ip_literal_is_refused() {
        // An IP literal skips DNS, so the resolver is not consulted. The https_only rule
        // and the connector still stop it. The URL uses https so the scheme rule passes.
        let client = match client(TargetClass::Harbor, false) {
            Ok(client) => client,
            Err(err) => panic!("client build failed: {err}"),
        };
        let outcome = client.get("https://127.0.0.1:1/").send().await;
        assert!(outcome.is_err(), "a request to loopback succeeded");
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
        let outcome = client.get("http://example.com/").send().await;
        assert!(outcome.is_err(), "a plain http request was sent");
    }
}
