//! The address and scheme policy of the registry client (`specs/spinoff-local-scan.md`,
//! sections 3 and 12; decisions 12 and 14).
//!
//! Two checks run. [`AddressPolicy::check_url`] runs before every request, including every
//! redirect hop, and covers IP-literal hosts that the resolver never sees. [`PolicyResolver`]
//! is the reqwest resolver, so the addresses checked are the ones that get connected to.
//! Both use the deny-list of the app ([`is_blocked`]).
//!
//! A host is refused when any address it resolves to is blocked. The opt-out is an
//! environment list of hub hosts (`LOCALSCAN_ALLOW_PRIVATE_REGISTRIES`). A listed host may use
//! private addresses. An entry written `http://host[:port]` may also use plain HTTP; a bare
//! entry is HTTPS only. The match is on the hop's own hostname, so a redirect to a host that is
//! not listed gets no relaxation, not even for plain HTTP.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::error::AppError;
use crate::services::outbound::is_blocked;
use crate::services::registry::grammar::{hub_name, validate_hub_host};

/// A boxed future that resolves a host name to its addresses.
pub type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;

/// Resolves a host name. The production implementation uses the system resolver. Tests
/// substitute a scripted answer, so no test reaches real DNS.
pub trait HostLookup: Send + Sync {
    fn lookup(&self, host: String) -> LookupFuture;
}

/// The system resolver.
pub struct SystemLookup;

impl HostLookup for SystemLookup {
    fn lookup(&self, host: String) -> LookupFuture {
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            Ok(found.map(|addr| addr.ip()).collect())
        })
    }
}

/// One entry of the environment opt-out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedHub {
    /// The hostname, lowercase, without the port.
    pub host: String,
    /// True when the entry was written `http://`, which allows plain HTTP for this host.
    pub plain_http: bool,
}

/// The address and scheme policy, shared by every request of one transport.
#[derive(Clone)]
pub struct AddressPolicy {
    named: Arc<Vec<NamedHub>>,
    lookup: Arc<dyn HostLookup>,
}

impl AddressPolicy {
    pub fn new(named: Vec<NamedHub>, lookup: Arc<dyn HostLookup>) -> Self {
        Self {
            named: Arc::new(named),
            lookup,
        }
    }

    /// The opt-out entry for `hostname`, if the host is named.
    pub fn named(&self, hostname: &str) -> Option<&NamedHub> {
        self.named.iter().find(|hub| hub.host == hostname)
    }

    /// True when `hostname` may be reached over plain HTTP.
    pub fn allows_plain_http(&self, hostname: &str) -> bool {
        self.named(hostname).is_some_and(|hub| hub.plain_http)
    }

    /// Checks one URL before a request is sent: the scheme, and every address the host
    /// resolves to. Any failure is `registry could not be reached` (`UpstreamUnreachable`),
    /// and the error never names the host or the address.
    pub async fn check_url(&self, url: &Url) -> Result<(), AppError> {
        let host = url.host_str().ok_or_else(refused)?;
        let named = self.named(host);
        match url.scheme() {
            "https" => {}
            "http" if named.is_some_and(|hub| hub.plain_http) => {}
            _ => return Err(refused()),
        }
        let literal = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok();
        let addresses = match literal {
            Some(ip) => vec![ip],
            None => self
                .lookup
                .lookup(host.to_owned())
                .await
                .map_err(|_| refused())?,
        };
        if addresses_allowed(&addresses, named.is_some()) {
            Ok(())
        } else {
            Err(refused())
        }
    }
}

/// True when the answer is non-empty and, unless the host is named, no address is blocked.
fn addresses_allowed(addresses: &[IpAddr], named: bool) -> bool {
    !addresses.is_empty() && (named || !addresses.iter().any(|ip| is_blocked(*ip)))
}

fn refused() -> AppError {
    AppError::UpstreamUnreachable
}

/// The reqwest resolver. reqwest calls it for every new connection, so a DNS answer that
/// changes between requests (rebinding) is checked again before the connect.
pub struct PolicyResolver(pub AddressPolicy);

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.0.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let named = policy.named(&host).is_some();
            let addresses = policy.lookup.lookup(host).await?;
            if !addresses_allowed(&addresses, named) {
                return Err(io::Error::other("address refused").into());
            }
            // Port 0: hyper fills in the port of the URL, as it does for the system resolver.
            let resolved: Addrs = Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(resolved)
        })
    }
}

/// Parses the environment opt-out: a comma-separated list of hub hosts, each optionally
/// prefixed `http://`. Each host must pass the hub host grammar. An empty value means the
/// opt-out is off.
pub fn parse_opt_out(value: &str) -> Result<Vec<NamedHub>, AppError> {
    let mut hubs = Vec::new();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let (plain_http, host) = match item.strip_prefix("http://") {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        validate_hub_host(host)?;
        hubs.push(NamedHub {
            host: hub_name(host).to_owned(),
            plain_http,
        });
    }
    Ok(hubs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_addresses_fail_unless_the_host_is_named() {
        let private = vec![IpAddr::from([10, 0, 0, 5])];
        assert!(!addresses_allowed(&private, false));
        assert!(addresses_allowed(&private, true));
    }

    #[test]
    fn one_blocked_address_refuses_the_whole_answer() {
        let mixed = vec![
            IpAddr::from([93, 184, 216, 34]),
            IpAddr::from([127, 0, 0, 1]),
        ];
        assert!(!addresses_allowed(&mixed, false));
    }

    #[test]
    fn an_empty_answer_is_refused() {
        assert!(!addresses_allowed(&[], false));
        assert!(!addresses_allowed(&[], true));
    }

    #[test]
    fn opt_out_parses_entries_and_plain_http_flag() {
        let hubs = parse_opt_out("http://localhost:5000, reg.example.com:443").ok();
        assert_eq!(
            hubs,
            Some(vec![
                NamedHub {
                    host: "localhost".to_owned(),
                    plain_http: true,
                },
                NamedHub {
                    host: "reg.example.com".to_owned(),
                    plain_http: false,
                },
            ])
        );
        assert_eq!(parse_opt_out("").ok(), Some(Vec::new()));
    }

    #[test]
    fn opt_out_refuses_schemes_paths_and_uppercase() {
        for bad in [
            "https://reg.example.com",
            "Reg.example.com",
            "reg.example.com/x",
        ] {
            assert!(parse_opt_out(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn plain_http_is_allowed_only_for_named_http_entries() {
        let policy = AddressPolicy::new(
            vec![NamedHub {
                host: "localhost".to_owned(),
                plain_http: true,
            }],
            Arc::new(NoLookup),
        );
        assert!(policy.allows_plain_http("localhost"));
        assert!(!policy.allows_plain_http("other.example.com"));
    }

    struct NoLookup;

    impl HostLookup for NoLookup {
        fn lookup(&self, _host: String) -> LookupFuture {
            Box::pin(async { Err(io::Error::other("no lookup in this test")) })
        }
    }
}
