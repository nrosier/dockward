//! Registry client tests against a local fake registry. No test contacts a real registry, and
//! no test uses a real credential. The fake registry is a loopback HTTP server that serves
//! scripted responses and records the requests it received. Plain HTTP and private addresses
//! are allowed only for the loopback host, through an explicit opt-out in each test.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::services::registry::manifest::{OCI_INDEX, OCI_MANIFEST, Parsed};
use crate::services::registry::policy::{HostLookup, LookupFuture, NamedHub, parse_opt_out};

/// A scripted DNS answer for hub hostnames. Each host has a queue of answers: every lookup
/// takes the front one, and the last one repeats. A name with no entry fails to resolve.
#[derive(Default)]
struct ScriptedLookup {
    answers: Mutex<HashMap<String, Vec<Vec<IpAddr>>>>,
}

impl ScriptedLookup {
    /// Sets one answer for `host`, returned by every lookup.
    fn set(&self, host: &str, addresses: Vec<IpAddr>) {
        self.sequence(host, vec![addresses]);
    }

    /// Sets the answers for `host` in the order the lookups happen.
    fn sequence(&self, host: &str, answers: Vec<Vec<IpAddr>>) {
        if let Ok(mut map) = self.answers.lock() {
            map.insert(host.to_owned(), answers);
        }
    }
}

impl HostLookup for ScriptedLookup {
    fn lookup(&self, host: String) -> LookupFuture {
        let answer = self.answers.lock().ok().and_then(|mut map| {
            let queue = map.get_mut(&host)?;
            if queue.len() > 1 {
                Some(queue.remove(0))
            } else {
                queue.first().cloned()
            }
        });
        Box::pin(async move { answer.ok_or_else(|| io::Error::other("no such host in this test")) })
    }
}

/// One scripted response: status, extra headers, and body.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// A request the fake registry saw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
}

/// The fake server. Routes are keyed by `path?query`. A route can hold several replies that
/// are served in order, and the last one repeats.
#[derive(Default)]
struct Script {
    routes: Mutex<HashMap<String, Vec<Reply>>>,
    seen: Mutex<Vec<Seen>>,
}

impl Script {
    fn route(&self, path: &str, replies: Vec<Reply>) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.insert(path.to_owned(), replies);
        }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    fn reply_for(&self, key: &str) -> Option<Reply> {
        let mut routes = self.routes.lock().ok()?;
        let replies = routes.get_mut(key)?;
        if replies.len() > 1 {
            Some(replies.remove(0))
        } else {
            replies.first().cloned()
        }
    }
}

/// Starts the fake server on loopback. Returns its `127.0.0.1:port` authority.
async fn serve(script: Arc<Script>) -> String {
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
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let script = Arc::clone(&script);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut filled = 0;
                loop {
                    let Ok(n) = socket.read(&mut buf[filled..]).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    filled += n;
                    if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") || filled == buf.len() {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..filled]).to_string();
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or("");
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let target = parts.next().unwrap_or("/").to_owned();
                let authorization = lines.find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_owned())
                });
                let path = target.split('?').next().unwrap_or("").to_owned();
                if let Ok(mut seen) = script.seen.lock() {
                    seen.push(Seen {
                        method,
                        path: path.clone(),
                        authorization: authorization.clone(),
                    });
                }
                let reply = script
                    .reply_for(&target)
                    .or_else(|| script.reply_for(&path));
                let reply = reply.unwrap_or_else(|| Reply::new(404, b"{}"));
                let mut out = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in &reply.headers {
                    out.push_str(&format!("{name}: {value}\r\n"));
                }
                out.push_str("\r\n");
                let _ = socket.write_all(out.as_bytes()).await;
                let _ = socket.write_all(&reply.body).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("127.0.0.1:{port}")
}

fn sha256_of(bytes: &[u8]) -> String {
    sha256_digest_text(&Sha256::digest(bytes))
}

/// A client whose only named hub is the loopback fake registry, with plain HTTP allowed.
fn client_for(loopback: &str, lookup: Arc<ScriptedLookup>) -> RegistryClient {
    let named = vec![NamedHub {
        host: loopback.split(':').next().unwrap_or("127.0.0.1").to_owned(),
        plain_http: true,
    }];
    let policy = AddressPolicy::new(named, lookup);
    match RegistryClient::new(policy) {
        Ok(client) => client,
        Err(err) => panic!("client build failed: {err:?}"),
    }
}

/// The hub string for a loopback authority. The client connects to it through `http://`, so
/// the hub is `127.0.0.1:<port>` and the opt-out names `127.0.0.1` with plain HTTP.
fn hub_of(loopback: &str) -> String {
    loopback.to_owned()
}

fn image_manifest(config: &[u8], layer: &[u8]) -> (Vec<u8>, String, String) {
    let config_digest = sha256_of(config);
    let layer_digest = sha256_of(layer);
    let body = format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}",
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},
            "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
        config.len(),
        layer.len()
    );
    (body.into_bytes(), config_digest, layer_digest)
}

#[tokio::test]
async fn anonymous_pull_of_a_manifest_and_blobs_verifies_digests() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let config = b"{\"config\":true}".to_vec();
    let layer = b"layer-bytes".to_vec();
    let (manifest_body, config_digest, layer_digest) = image_manifest(&config, &layer);
    script.route(
        "/v2/team/app/manifests/1.0",
        vec![Reply::new(200, &manifest_body).header("Content-Type", OCI_MANIFEST)],
    );
    script.route(
        &format!("/v2/team/app/blobs/{config_digest}"),
        vec![Reply::new(200, &config)],
    );
    script.route(
        &format!("/v2/team/app/blobs/{layer_digest}"),
        vec![Reply::new(200, &layer)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let parsed = session.manifest("1.0").await;
    let Ok(Parsed::Image {
        config: cfg,
        layers,
    }) = parsed
    else {
        panic!("manifest should parse: {parsed:?}");
    };
    let mut config_out = Vec::new();
    let mut layer_out = Vec::new();
    assert!(
        session
            .blob_to(&cfg.digest, cfg.size, u64::MAX, &mut config_out)
            .await
            .is_ok()
    );
    assert!(
        session
            .blob_to(&layers[0].digest, layers[0].size, u64::MAX, &mut layer_out)
            .await
            .is_ok()
    );
    assert_eq!(config_out, config);
    assert_eq!(layer_out, layer);
    assert!(
        script
            .requests()
            .iter()
            .all(|seen| seen.authorization.is_none())
    );
}

#[tokio::test]
async fn bearer_pull_fetches_a_token_once_and_sends_it_on_later_requests() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let config = b"cfg".to_vec();
    let (manifest_body, config_digest, _) = image_manifest(&config, b"x");
    let realm = format!("http://{loopback}/token");
    script.route(
        "/v2/team/app/manifests/1.0",
        vec![
            Reply::new(401, b"")
                .header(
                    "WWW-Authenticate",
                    &format!(
                        "Bearer realm=\"{realm}\",service=\"fake-registry\",scope=\"repository:team/app:pull\""
                    ),
                ),
            Reply::new(200, &manifest_body).header("Content-Type", OCI_MANIFEST),
        ],
    );
    script.route(
        "/token?service=fake-registry&scope=repository%3Ateam%2Fapp%3Apull",
        vec![Reply::new(200, br#"{"token":"tok-abc","expires_in":300}"#)],
    );
    script.route(
        &format!("/v2/team/app/blobs/{config_digest}"),
        vec![Reply::new(200, &config)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(
        &hub_of(&loopback),
        "team/app",
        Some(Credential {
            username: "robot-user".to_owned(),
            token: "pw-canary".to_owned(),
        }),
    ) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    assert!(session.manifest("1.0").await.is_ok());
    let mut out = Vec::new();
    let blob = session
        .blob_to(&config_digest, config.len() as u64, u64::MAX, &mut out)
        .await;
    assert!(blob.is_ok(), "blob after token: {blob:?}");
    let seen = script.requests();
    let token_calls: Vec<&Seen> = seen.iter().filter(|s| s.path == "/token").collect();
    assert_eq!(token_calls.len(), 1, "the token is fetched once");
    assert!(
        token_calls[0]
            .authorization
            .as_deref()
            .is_some_and(|value| value.starts_with("Basic ")),
        "the credential goes to the token realm as Basic"
    );
    let bearer_calls = seen
        .iter()
        .filter(|s| s.authorization.as_deref() == Some("Bearer tok-abc"))
        .count();
    assert!(bearer_calls >= 2, "later requests carry the bearer token");
}

#[tokio::test]
async fn tag_listing_follows_link_pages_until_the_last_page() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    script.route(
        "/v2/team/app/tags/list?n=100",
        vec![
            Reply::new(200, br#"{"name":"team/app","tags":["1.0","1.1"]}"#).header(
                "Link",
                "</v2/team/app/tags/list?n=100&last=1.1>; rel=\"next\"",
            ),
        ],
    );
    script.route(
        "/v2/team/app/tags/list?n=100&last=1.1",
        vec![Reply::new(200, br#"{"name":"team/app","tags":["2.0"]}"#)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let listed = session.list_tags().await;
    assert_eq!(
        listed.ok(),
        Some(Tags {
            tags: vec!["1.0".to_owned(), "1.1".to_owned(), "2.0".to_owned()],
            complete: true,
        })
    );
}

#[tokio::test]
async fn a_link_to_another_host_is_not_followed_and_the_listing_is_incomplete() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    script.route(
        "/v2/team/app/tags/list?n=100",
        vec![Reply::new(200, br#"{"tags":["1.0"]}"#).header(
            "Link",
            "<https://evil.example.com/v2/team/app/tags/list?last=1.0>; rel=\"next\"",
        )],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let listed = session.list_tags().await;
    assert_eq!(
        listed.ok(),
        Some(Tags {
            tags: vec!["1.0".to_owned()],
            complete: false,
        })
    );
    assert!(
        script
            .requests()
            .iter()
            .all(|seen| !seen.path.contains("evil")),
        "no request to the other host"
    );
}

#[tokio::test]
async fn redirect_to_another_host_drops_the_authorization_header() {
    // The first host is the loopback registry, which redirects to a second loopback server
    // on another port. Both are 127.0.0.1, so the opt-out names the address itself and the
    // second port is a different origin, which must lose Authorization.
    let first = Arc::new(Script::default());
    let second = Arc::new(Script::default());
    let first_addr = serve(Arc::clone(&first)).await;
    let second_addr = serve(Arc::clone(&second)).await;
    let config = b"blob".to_vec();
    let digest = sha256_of(&config);
    first.route(
        &format!("/v2/team/app/blobs/{digest}"),
        vec![
            Reply::new(307, b"").header("Location", &format!("http://{second_addr}/cdn/{digest}")),
        ],
    );
    second.route(&format!("/cdn/{digest}"), vec![Reply::new(200, &config)]);
    let client = client_for(&first_addr, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&first_addr), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    // A live token is attached to the first origin, so the first request carries it.
    session.token = Some(BearerToken {
        value: "tok-redirect".to_owned(),
        expires_at: Instant::now() + Duration::from_secs(60),
    });
    let mut out = Vec::new();
    let result = session
        .blob_to(&digest, config.len() as u64, u64::MAX, &mut out)
        .await;
    assert!(result.is_ok(), "redirected blob: {result:?}");
    assert_eq!(out, config);
    let first_hop = first.requests();
    assert_eq!(first_hop.len(), 1);
    assert_eq!(
        first_hop[0].authorization.as_deref(),
        Some("Bearer tok-redirect"),
        "the issuing origin receives the token"
    );
    let hop = second.requests();
    assert_eq!(hop.len(), 1);
    assert!(
        hop[0].authorization.is_none(),
        "the other origin receives no Authorization"
    );
}

#[tokio::test]
async fn redirect_to_a_private_address_is_refused_on_that_hop() {
    // A named hub redirects to an unnamed host that resolves to a private address. The hop
    // must be refused, even though the first host is named and plain HTTP is allowed.
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let config = b"blob".to_vec();
    let digest = sha256_of(&config);
    script.route(
        &format!("/v2/team/app/blobs/{digest}"),
        vec![Reply::new(302, b"").header("Location", "https://internal.corp.example/blob")],
    );
    let lookup = Arc::new(ScriptedLookup::default());
    lookup.set("internal.corp.example", vec![IpAddr::from([10, 1, 2, 3])]);
    let client = client_for(&loopback, Arc::clone(&lookup));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let mut out = Vec::new();
    let result = session
        .blob_to(&digest, config.len() as u64, u64::MAX, &mut out)
        .await;
    assert_eq!(result.err(), Some(AppError::UpstreamUnreachable));
    assert!(out.is_empty());
}

#[tokio::test]
async fn hub_host_that_re_resolves_to_a_private_address_is_refused_at_connect() {
    // The first lookup (the pre-request URL check) answers a public address, so the request
    // proceeds. The second lookup, made by the connect-time resolver, answers a private
    // address. That connect is refused, so the rebinding is caught at the connect.
    let lookup = Arc::new(ScriptedLookup::default());
    lookup.sequence(
        "registry.public.example",
        vec![
            vec![IpAddr::from([93, 184, 216, 34])],
            vec![IpAddr::from([10, 9, 8, 7])],
        ],
    );
    let policy = AddressPolicy::new(Vec::new(), Arc::clone(&lookup) as Arc<dyn HostLookup>);
    let client = match RegistryClient::new(policy) {
        Ok(client) => client,
        Err(err) => panic!("client: {err:?}"),
    };
    let mut session = match client.session("registry.public.example", "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let result = session.manifest("1.0").await;
    assert_eq!(result.err(), Some(AppError::UpstreamUnreachable));
}

#[tokio::test]
async fn a_digest_mismatch_is_rejected() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let expected = b"the real bytes".to_vec();
    let digest = sha256_of(&expected);
    let tampered = b"other bytes!!!".to_vec();
    script.route(
        &format!("/v2/team/app/blobs/{digest}"),
        vec![Reply::new(200, &tampered)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let mut out = Vec::new();
    let result = session
        .blob_to(&digest, tampered.len() as u64, u64::MAX, &mut out)
        .await;
    assert_eq!(result.err(), Some(AppError::UpstreamContentInvalid));
}

#[tokio::test]
async fn a_blob_over_the_pull_cap_is_refused() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let big = vec![7u8; 4096];
    let digest = sha256_of(&big);
    script.route(
        &format!("/v2/team/app/blobs/{digest}"),
        vec![Reply::new(200, &big)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let mut out = Vec::new();
    // The budget is smaller than the blob: the declared size is over the cap, refused before
    // any byte is read.
    let result = session
        .blob_to(&digest, big.len() as u64, 1024, &mut out)
        .await;
    assert_eq!(result.err(), Some(AppError::ImageTooLarge));
    assert!(out.is_empty());
}

#[tokio::test]
async fn a_stream_longer_than_its_descriptor_is_stopped_at_the_cap() {
    // The descriptor claims 8 bytes, the server streams 4096. The running count, not the
    // header, stops the stream.
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let big = vec![9u8; 4096];
    let digest = sha256_of(&big[..8]);
    script.route(
        &format!("/v2/team/app/blobs/{digest}"),
        vec![Reply::new(200, &big)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let mut out = Vec::new();
    let result = session.blob_to(&digest, 8, u64::MAX, &mut out).await;
    assert_eq!(result.err(), Some(AppError::UpstreamContentInvalid));
}

#[tokio::test]
async fn a_rate_limit_without_a_short_retry_returns_rate_limited() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    script.route(
        "/v2/team/app/manifests/1.0",
        vec![Reply::new(429, b"").header("Retry-After", "3600")],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let result = session.manifest("1.0").await;
    assert_eq!(result.err(), Some(AppError::RateLimited));
}

#[tokio::test]
async fn a_refused_credential_returns_auth_rejected_and_not_found_is_not_found() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    script.route(
        "/v2/team/app/manifests/1.0",
        vec![Reply::new(403, b"denied")],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    assert_eq!(
        session.manifest("1.0").await.err(),
        Some(AppError::UpstreamAuthRejected)
    );
    assert_eq!(
        session.manifest("missing").await.err(),
        Some(AppError::NotFound)
    );
}

#[tokio::test]
async fn an_invalid_repository_is_refused_before_any_request() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    assert!(
        client
            .session(&hub_of(&loopback), "Bad/Name", None)
            .is_err()
    );
    assert!(client.session(&hub_of(&loopback), "a:b", None).is_err());
    assert!(script.requests().is_empty());
}

#[tokio::test]
async fn plain_http_to_an_unnamed_host_is_refused_with_no_request() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    // No opt-out at all: the scheme check refuses before the connect.
    let policy = AddressPolicy::new(Vec::new(), Arc::new(ScriptedLookup::default()));
    let client = match RegistryClient::new(policy) {
        Ok(client) => client,
        Err(err) => panic!("client: {err:?}"),
    };
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    assert_eq!(
        session.manifest("1.0").await.err(),
        Some(AppError::UpstreamUnreachable)
    );
    assert!(script.requests().is_empty());
}

#[tokio::test]
async fn the_docker_hub_host_maps_to_registry_1_for_pulls() {
    assert_eq!(pull_host("docker.io"), "registry-1.docker.io");
    let policy = AddressPolicy::new(Vec::new(), Arc::new(ScriptedLookup::default()));
    let client = match RegistryClient::new(policy) {
        Ok(client) => client,
        Err(err) => panic!("client: {err:?}"),
    };
    let session = match client.session("docker.io", "library/alpine", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    assert_eq!(session.base, "https://registry-1.docker.io");
}

#[tokio::test]
async fn an_index_is_parsed_into_platforms_with_attestations_skipped() {
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let d1 = sha256_of(b"amd64");
    let d2 = sha256_of(b"attest");
    let index = format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_INDEX}","manifests":[
            {{"mediaType":"{OCI_MANIFEST}","digest":"{d1}","size":5,"platform":{{"os":"linux","architecture":"amd64"}}}},
            {{"mediaType":"{OCI_MANIFEST}","digest":"{d2}","size":6,"platform":{{"os":"unknown","architecture":"unknown"}}}}]}}"#
    );
    script.route(
        "/v2/team/app/manifests/1.0",
        vec![Reply::new(200, index.as_bytes()).header("Content-Type", OCI_INDEX)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let Ok(Parsed::Index(entries)) = session.manifest("1.0").await else {
        panic!("index should parse");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].platform.architecture, "amd64");
}

#[test]
fn credential_debug_and_token_never_show_the_secret() {
    let cred = Credential {
        username: "user".to_owned(),
        token: "secret-canary".to_owned(),
    };
    assert!(!format!("{cred:?}").contains("secret-canary"));
    let token = BearerToken {
        value: "secret-canary".to_owned(),
        expires_at: Instant::now(),
    };
    assert!(!format!("{token:?}").contains("secret-canary"));
}

#[tokio::test]
async fn a_streamed_overrun_past_an_honest_descriptor_is_stopped_by_the_running_count() {
    // The descriptor matches the real first blob, so the size check passes up front. The
    // server then sends more bytes than the descriptor declared on the same digest, which the
    // running count refuses while streaming.
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let honest = vec![3u8; 8];
    let digest = sha256_of(&honest);
    let mut overrun = honest.clone();
    overrun.extend_from_slice(&[4u8; 64]);
    script.route(
        &format!("/v2/team/app/blobs/{digest}"),
        vec![Reply::new(200, &overrun)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let mut out = Vec::new();
    let result = session.blob_to(&digest, 8, u64::MAX, &mut out).await;
    assert_eq!(result.err(), Some(AppError::UpstreamContentInvalid));
}

#[test]
fn a_pull_below_the_free_disk_minimum_is_refused_and_one_at_it_is_allowed() {
    let gib = 1024u64 * 1024 * 1024;
    assert_eq!(
        disk_guard(10 * gib - 1, 10 * gib).err(),
        Some(AppError::InsufficientDisk)
    );
    assert!(disk_guard(10 * gib, 10 * gib).is_ok());
}

#[tokio::test]
async fn an_image_over_the_cap_is_refused_before_its_first_byte() {
    // Two blobs share one pull budget of 1000 bytes. The first (600) fits. The second (600)
    // is over the 400 bytes that remain, so it is refused before any byte is read.
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    let first = vec![1u8; 600];
    let second = vec![2u8; 600];
    let first_digest = sha256_of(&first);
    let second_digest = sha256_of(&second);
    script.route(
        &format!("/v2/team/app/blobs/{first_digest}"),
        vec![Reply::new(200, &first)],
    );
    script.route(
        &format!("/v2/team/app/blobs/{second_digest}"),
        vec![Reply::new(200, &second)],
    );
    let client = client_for(&loopback, Arc::new(ScriptedLookup::default()));
    let mut session = match client.session(&hub_of(&loopback), "team/app", None) {
        Ok(session) => session,
        Err(err) => panic!("session: {err:?}"),
    };
    let cap = 1000u64;
    let mut out = Vec::new();
    let first_result = session.blob_to(&first_digest, 600, cap, &mut out).await;
    assert!(first_result.is_ok());
    let remaining = cap - 600;
    let mut second_out = Vec::new();
    let second_result = session
        .blob_to(&second_digest, 600, remaining, &mut second_out)
        .await;
    assert_eq!(second_result.err(), Some(AppError::ImageTooLarge));
    assert!(second_out.is_empty());
}

#[test]
fn opt_out_entries_are_matched_by_hostname_only() {
    let hubs = parse_opt_out("http://localhost:5000").ok();
    assert_eq!(
        hubs,
        Some(vec![NamedHub {
            host: "localhost".to_owned(),
            plain_http: true,
        }])
    );
}
