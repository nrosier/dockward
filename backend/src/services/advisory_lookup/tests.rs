//! Advisory lookup tests (#379). Two loopback TLS servers stand in for `api.osv.dev` and
//! `api.github.com`: no test reaches the real internet. Each server records the request heads it
//! receives.

use std::sync::{Arc, Mutex};

use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;

use super::*;
use crate::services::outbound::socket_tests::loopback_tls_server_with;

const GHSA: &str = "GHSA-jfh8-c2jp-5v3q";
const GHSA_CVE: &str = "CVE-2021-44228";
const GHSA_NONE: &str = "GHSA-gpwc-27cw-rh9r";
const GO: &str = "GO-2021-0113";
const GO_CVE: &str = "CVE-2021-38561";
const NOW: i64 = 1_800_000_000;

/// A fake advisory host: scripted answers by request path, and every request head it saw.
struct Fake {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    fn heads(&self) -> Vec<String> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    /// The request targets (`GET <target> HTTP/1.1` lines) in order.
    fn targets(&self) -> Vec<String> {
        self.heads()
            .iter()
            .filter_map(|head| head.split_whitespace().nth(1).map(str::to_owned))
            .collect()
    }
}

fn json(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Serves `routes` (`path`, full response) and answers anything else with a 404.
async fn serve(
    routes: Vec<(&'static str, String)>,
    root: &mut Option<reqwest::Certificate>,
) -> Fake {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = Arc::clone(&seen);
    let (port, cert) = loopback_tls_server_with(move |head| {
        if let Ok(mut seen) = record.lock() {
            seen.push(head.to_owned());
        }
        let target = head.split_whitespace().nth(1).unwrap_or("");
        routes
            .iter()
            .find(|(path, _)| *path == target)
            .map(|(_, response)| response.clone())
            .unwrap_or_else(|| json("404 Not Found", r#"{"message":"Not Found"}"#))
    })
    .await;
    // Both servers have their own certificate, and the client trusts one root. The first one
    // started is the trusted one, so the second reuses it by serving through a clone of it below.
    if root.is_none() {
        *root = Some(cert);
    }
    Fake { port, seen }
}

async fn pool() -> SqlitePool {
    let pool = match SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
    {
        Ok(pool) => pool,
        Err(err) => panic!("pool: {err}"),
    };
    if let Err(err) = crate::db::migrate(&pool).await {
        panic!("migrate: {err:?}");
    }
    pool
}

fn finding(id: &str) -> Finding {
    Finding {
        cve_id: id.to_owned(),
        package: "pkg".to_owned(),
        version: Some("1".to_owned()),
        fixed_in_version: None,
        severity: "HIGH",
        cvss_v3: None,
        description: None,
        alias: None,
    }
}

async fn alias_of(pool: &SqlitePool, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT primary_id FROM vulnerability_aliases WHERE alias = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or_else(|err| panic!("alias: {err}"))
}

async fn cached(pool: &SqlitePool, id: &str) -> Option<(Option<String>, String)> {
    sqlx::query_as("SELECT cve_id, source FROM advisory_lookups WHERE advisory_id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or_else(|err| panic!("cache: {err}"))
}

/// One server answers as both hosts: OSV paths start with `/v1/vulns/`, GitHub paths with
/// `/advisories/`, so a single fake with one trust root serves the two sources.
async fn lookup_with(routes: Vec<(&'static str, String)>) -> (AdvisoryLookup, Fake) {
    let mut root = None;
    let fake = serve(routes, &mut root).await;
    let Some(root) = root else {
        panic!("no root");
    };
    (AdvisoryLookup::local(fake.port, fake.port, root), fake)
}

fn osv_path(id: &str) -> &'static str {
    Box::leak(format!("/v1/vulns/{id}").into_boxed_str())
}

fn github_path(id: &str) -> &'static str {
    Box::leak(format!("/advisories/{id}").into_boxed_str())
}

#[tokio::test]
async fn a_ghsa_whose_advisory_names_a_cve_resolves_to_it() {
    let osv = json(
        "200 OK",
        &format!(r#"{{"id":"{GHSA}","aliases":["{GHSA_CVE}"]}}"#),
    );
    let (lookup, fake) = lookup_with(vec![(osv_path(GHSA), osv)]).await;
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GHSA)], NOW).await;
    assert_eq!(alias_of(&pool, GHSA).await.as_deref(), Some(GHSA_CVE));
    assert_eq!(
        cached(&pool, GHSA).await,
        Some((Some(GHSA_CVE.to_owned()), "osv".to_owned()))
    );
    // OSV answered, so GitHub was not asked.
    assert_eq!(fake.targets(), vec![osv_path(GHSA).to_owned()]);
}

#[tokio::test]
async fn a_go_id_resolves_through_osv_and_skips_github() {
    let osv = json(
        "200 OK",
        &format!(r#"{{"id":"{GO}","aliases":["{GO_CVE}","GHSA-ppp9-7jff-5vj2"]}}"#),
    );
    let (lookup, fake) = lookup_with(vec![(osv_path(GO), osv)]).await;
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GO)], NOW).await;
    assert_eq!(alias_of(&pool, GO).await.as_deref(), Some(GO_CVE));
    assert_eq!(fake.targets(), vec![osv_path(GO).to_owned()]);
}

#[tokio::test]
async fn a_ghsa_with_no_cve_stays_unresolved_and_the_answer_is_cached() {
    let osv = json("200 OK", &format!(r#"{{"id":"{GHSA_NONE}"}}"#));
    let (lookup, fake) = lookup_with(vec![(osv_path(GHSA_NONE), osv)]).await;
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GHSA_NONE)], NOW).await;
    assert_eq!(alias_of(&pool, GHSA_NONE).await, None);
    assert_eq!(
        cached(&pool, GHSA_NONE).await,
        Some((None, "osv".to_owned()))
    );
    // "None published" is an answer: a second scan does not ask again.
    lookup.resolve(&pool, &[finding(GHSA_NONE)], NOW + 1).await;
    assert_eq!(fake.targets().len(), 1);
}

#[tokio::test]
async fn osv_down_falls_back_to_github_for_a_ghsa() {
    let github = json(
        "200 OK",
        &format!(r#"{{"ghsa_id":"{GHSA}","cve_id":"{GHSA_CVE}"}}"#),
    );
    let (lookup, fake) = lookup_with(vec![
        (osv_path(GHSA), json("503 Service Unavailable", "{}")),
        (github_path(GHSA), github),
    ])
    .await;
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GHSA)], NOW).await;
    assert_eq!(alias_of(&pool, GHSA).await.as_deref(), Some(GHSA_CVE));
    assert_eq!(
        cached(&pool, GHSA).await,
        Some((Some(GHSA_CVE.to_owned()), "github".to_owned()))
    );
    assert_eq!(
        fake.targets(),
        vec![osv_path(GHSA).to_owned(), github_path(GHSA).to_owned()]
    );
}

#[tokio::test]
async fn github_says_no_cve_when_osv_does_not_know_the_id() {
    let github = json("200 OK", r#"{"cve_id":null}"#);
    let (lookup, _fake) = lookup_with(vec![(github_path(GHSA_NONE), github)]).await;
    let pool = pool().await;
    // OSV answers 404 for the id: no answer, so GitHub is asked.
    lookup.resolve(&pool, &[finding(GHSA_NONE)], NOW).await;
    assert_eq!(
        cached(&pool, GHSA_NONE).await,
        Some((None, "github".to_owned()))
    );
}

#[tokio::test]
async fn both_sources_down_leaves_the_id_unresolved_and_caches_nothing() {
    let (lookup, fake) = lookup_with(vec![
        (osv_path(GHSA), json("500 Internal Server Error", "{}")),
        (
            github_path(GHSA),
            json("403 Forbidden", r#"{"message":"rate limit"}"#),
        ),
    ])
    .await;
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GHSA)], NOW).await;
    assert_eq!(alias_of(&pool, GHSA).await, None);
    assert_eq!(cached(&pool, GHSA).await, None);
    assert_eq!(fake.targets().len(), 2);
    // The next scan asks again: a failure is not cached.
    lookup.resolve(&pool, &[finding(GHSA)], NOW + 1).await;
    assert_eq!(fake.targets().len(), 4);
}

#[tokio::test]
async fn an_unreachable_source_leaves_the_id_unresolved() {
    let mut root = None;
    let fake = serve(vec![], &mut root).await;
    let Some(root) = root else {
        panic!("no root");
    };
    // Port 9 (discard) has no listener on loopback.
    let lookup = AdvisoryLookup::local(9, 9, root);
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GHSA)], NOW).await;
    assert_eq!(alias_of(&pool, GHSA).await, None);
    assert_eq!(cached(&pool, GHSA).await, None);
    assert!(fake.targets().is_empty());
}

#[tokio::test]
async fn a_cached_id_is_not_requested_twice() {
    let osv = json("200 OK", &format!(r#"{{"aliases":["{GHSA_CVE}"]}}"#));
    let (lookup, fake) = lookup_with(vec![(osv_path(GHSA), osv)]).await;
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GHSA)], NOW).await;
    lookup.resolve(&pool, &[finding(GHSA)], NOW + 1).await;
    // Even with the alias row gone, the cache answers and restores it.
    if let Err(err) = sqlx::query("DELETE FROM vulnerability_aliases")
        .execute(&pool)
        .await
    {
        panic!("delete: {err}");
    }
    lookup.resolve(&pool, &[finding(GHSA)], NOW + 2).await;
    assert_eq!(fake.targets().len(), 1);
    assert_eq!(alias_of(&pool, GHSA).await.as_deref(), Some(GHSA_CVE));
}

#[tokio::test]
async fn an_id_the_scanner_already_resolved_is_not_looked_up() {
    let (lookup, fake) = lookup_with(vec![]).await;
    let pool = pool().await;
    let mut linked = finding("CVE-2021-44228");
    linked.alias = Some(GHSA.to_owned());
    let mut aliased = finding(GHSA);
    aliased.alias = Some(GHSA_CVE.to_owned());
    lookup
        .resolve(&pool, &[linked, aliased, finding("CVE-2020-1234")], NOW)
        .await;
    // An id already in the alias table is not looked up either.
    if let Err(err) =
        sqlx::query("INSERT INTO vulnerability_aliases (alias, primary_id) VALUES (?, ?)")
            .bind(GO)
            .bind(GO_CVE)
            .execute(&pool)
            .await
    {
        panic!("insert: {err}");
    }
    lookup.resolve(&pool, &[finding(GO)], NOW).await;
    assert!(fake.targets().is_empty());
}

#[tokio::test]
async fn the_request_carries_only_the_id() {
    let osv = json("200 OK", &format!(r#"{{"aliases":["{GHSA_CVE}"]}}"#));
    let (lookup, fake) = lookup_with(vec![(osv_path(GHSA), osv)]).await;
    let pool = pool().await;
    lookup.resolve(&pool, &[finding(GHSA)], NOW).await;
    let heads = fake.heads();
    assert_eq!(heads.len(), 1);
    let head = heads[0].to_lowercase();
    // A GET with the id as the whole path: no query, no body.
    assert!(head.starts_with(&format!(
        "get /v1/vulns/{} http/1.1\r\n",
        GHSA.to_lowercase()
    )));
    // The only headers are the ones the client and HTTP need: no credential of any kind.
    let names: Vec<&str> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect();
    for name in &names {
        assert!(
            ["host", "accept", "user-agent", "accept-encoding"].contains(name),
            "unexpected header {name}"
        );
    }
    assert!(!head.contains("authorization") && !head.contains("cookie"));
    // The ids of the scanned image never appear in it.
    assert!(!head.contains("pkg"));
}

#[tokio::test]
async fn an_id_with_an_unexpected_shape_is_never_put_in_a_url() {
    let (lookup, fake) = lookup_with(vec![]).await;
    let pool = pool().await;
    let odd = [
        "GHSA-only-0000-0000-x",
        "GHSA-UPPER-CASE-0000",
        "GHSA-../x",
        "GO-2021",
        "GO-2021-12?x=1",
        "GHSA-abcd-efgh-ijk%",
    ];
    let findings: Vec<Finding> = odd.iter().map(|id| finding(id)).collect();
    lookup.resolve(&pool, &findings, NOW).await;
    assert!(fake.targets().is_empty());
}

#[test]
fn id_shapes() {
    assert!(is_advisory_id("GHSA-jfh8-c2jp-5v3q"));
    assert!(is_advisory_id("GO-2021-0113"));
    assert!(!is_advisory_id("CVE-2021-44228"));
    assert!(!is_advisory_id("GHSA-jfh8-c2jp"));
    assert!(is_valid_cve("CVE-2021-44228"));
    assert!(!is_valid_cve("CVE-21-1"));
    assert!(!is_valid_cve("GHSA-jfh8-c2jp-5v3q"));
}
