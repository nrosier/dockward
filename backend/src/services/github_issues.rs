//! GitHub Issues client: list, create, comment on, and change the state of the issues the
//! CVE lifecycle manages (`specs/cve-lifecycle.md`, "Issue marker and re-adoption";
//! `specs/integrations.md`, "GitHub issues").
//!
//! This module only makes the calls. When to open or close an issue is decided elsewhere.
//! Each call goes through the same HTTP trait as [`github_scanning`](super::github_scanning),
//! so the address check applies and errors are the shared [`ScanError`]. The token is sent
//! only as a bearer header and never appears in an error message or an issue body.

use serde_json::{Value, json};

use crate::error::AppError;
use crate::services::github_scanning::{
    LiveHttp, ScanError, ScanHttp, ScanResponse, check_names, classify,
};
use crate::services::github_url::{GithubTarget, GithubUrls};
use crate::services::outbound::{self, OutboundClient};

/// The label on every issue HarborGate creates.
pub const LABEL: &str = "harborgate";

/// The most pages `list_open_labelled` reads (100 issues each) before it gives up. It stops
/// a bad `link` header from looping forever.
const MAX_PAGES: usize = 100;

/// One GitHub issue, as far as the lifecycle needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRef {
    pub number: u64,
    pub html_url: String,
    pub body: String,
}

/// The hidden marker that must be the first line of every issue body HarborGate creates.
pub fn marker(cve_id: &str) -> String {
    format!("<!-- harborgate:{cve_id} -->")
}

/// The issue whose body's first line is exactly the marker for `cve_id`. A marker anywhere
/// else in the body does not count.
pub fn find_marked<'a>(issues: &'a [IssueRef], cve_id: &str) -> Option<&'a IssueRef> {
    let wanted = marker(cve_id);
    issues
        .iter()
        .find(|issue| issue.body.lines().next() == Some(wanted.as_str()))
}

/// The body of a new issue: the marker on the first line, then a short Markdown table.
/// `fixed_in` is `None` when no fixed version is known. It holds no token and no URL.
pub fn issue_body(
    cve_id: &str,
    severity: &str,
    package: &str,
    fixed_in: Option<&str>,
    harbor_repo: &str,
) -> String {
    let fixed = fixed_in.unwrap_or("none yet");
    format!(
        "{}\n\n| Field | Value |\n| --- | --- |\n| CVE | {} |\n| Severity | {} |\n| Package | {} |\n| Fixed in | {} |\n| Harbor repository | {} |\n",
        marker(cve_id),
        cell(cve_id),
        cell(severity),
        cell(package),
        cell(fixed),
        cell(harbor_repo),
    )
}

/// Makes a value safe inside one Markdown table cell: no pipe and no line break.
fn cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_owned()
}

fn bad_answer() -> ScanError {
    ScanError::Upstream("GitHub returned an issue that could not be read".to_owned())
}

fn parse_issue(item: &Value) -> Result<IssueRef, ScanError> {
    let number = item
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(bad_answer)?;
    let html_url = item
        .get("html_url")
        .and_then(Value::as_str)
        .ok_or_else(bad_answer)?
        .to_owned();
    let body = item
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(IssueRef {
        number,
        html_url,
        body,
    })
}

/// The path (with query) of a `next` link, relative to the configured API base URL. The link
/// must be an `https` URL on the configured API host, under its base path, with no user info
/// and no port other than the default, and its path must have no empty segment. Anything else
/// is an error and is never fetched.
///
/// The empty-segment rule matters because the result is appended to the API base: a path
/// such as `//evil.example/x` would otherwise replace the host, and the bearer token would
/// be sent there.
fn next_path(urls: &GithubUrls, link: &str) -> Result<String, ScanError> {
    urls.relative_path(link)
        .ok_or_else(|| ScanError::Upstream("GitHub sent a next link to another host".to_owned()))
}

/// Lists every open issue with the `harborgate` label, following `link: rel="next"`.
/// Pull requests are skipped.
pub async fn list_open_labelled_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    now: i64,
) -> Result<Vec<IssueRef>, ScanError> {
    check_names(owner, repo)?;
    let mut path = format!("repos/{owner}/{repo}/issues?state=open&labels={LABEL}&per_page=100");
    let mut found = Vec::new();
    for _ in 0..MAX_PAGES {
        let response = http.get(&path, token).await?;
        if response.status != 200 {
            return Err(classify(&response, now));
        }
        let items = response.body.as_array().ok_or_else(bad_answer)?;
        for item in items {
            if item.get("pull_request").is_some() {
                continue;
            }
            found.push(parse_issue(item)?);
        }
        match response.link_next.as_deref() {
            Some(link) => path = next_path(&http.urls(), link)?,
            None => return Ok(found),
        }
    }
    Err(ScanError::Upstream(
        "GitHub returned too many pages of issues".to_owned(),
    ))
}

/// Creates an issue with the `harborgate` label and returns it.
pub async fn create_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    title: &str,
    body: &str,
    now: i64,
) -> Result<IssueRef, ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues");
    let payload = json!({"title": title, "body": body, "labels": [LABEL]});
    let response = http.post(&path, token, &payload).await?;
    if response.status != 201 {
        return Err(classify(&response, now));
    }
    parse_issue(&response.body)
}

/// Adds a comment to an issue.
pub async fn comment_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    body: &str,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}/comments");
    let response = http.post(&path, token, &json!({"body": body})).await?;
    if response.status != 201 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// Opens or closes an issue. Closing sends `state_reason: "completed"`.
pub async fn set_state_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    open: bool,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let payload = if open {
        json!({"state": "open"})
    } else {
        json!({"state": "closed", "state_reason": "completed"})
    };
    let response: ScanResponse = http.patch(&path, token, &payload).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// Reads one issue and returns whether it is open on GitHub (`state == "open"`). Used to
/// notice an issue that was closed by hand.
pub async fn is_open_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    now: i64,
) -> Result<bool, ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let response = http.get(&path, token).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    match response.body.get("state").and_then(Value::as_str) {
        Some("open") => Ok(true),
        Some("closed") => Ok(false),
        _ => Err(bad_answer()),
    }
}

/// The GitHub Issues client. Built on the guarded outbound client for the configured GitHub
/// API base URL.
pub struct GithubIssues {
    client: OutboundClient,
    target: GithubTarget,
}

impl GithubIssues {
    pub fn new(target: GithubTarget) -> Result<Self, AppError> {
        let client =
            outbound::github_client(target.clone()).map_err(|_| AppError::InternalError)?;
        Ok(Self { client, target })
    }

    fn http(&self) -> LiveHttp<'_> {
        LiveHttp {
            client: &self.client,
            urls: self.target.current(),
        }
    }

    /// Lists open issues with the `harborgate` label, all pages. See [`list_open_labelled_with`].
    pub async fn list_open_labelled(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        now: i64,
    ) -> Result<Vec<IssueRef>, ScanError> {
        list_open_labelled_with(&self.http(), token, owner, repo, now).await
    }

    /// Creates a labelled issue. See [`create_with`].
    pub async fn create(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        now: i64,
    ) -> Result<IssueRef, ScanError> {
        create_with(&self.http(), token, owner, repo, title, body, now).await
    }

    /// Comments on an issue. See [`comment_with`].
    pub async fn comment(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        comment_with(&self.http(), token, owner, repo, number, body, now).await
    }

    /// True when the issue is open on GitHub. See [`is_open_with`].
    pub async fn is_open(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> Result<bool, ScanError> {
        is_open_with(&self.http(), token, owner, repo, number, now).await
    }

    /// Opens or closes an issue. See [`set_state_with`].
    pub async fn set_state(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        open: bool,
        now: i64,
    ) -> Result<(), ScanError> {
        set_state_with(&self.http(), token, owner, repo, number, open, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    type Sent = (&'static str, String, Value);

    /// Answers each request with the next recorded response, and records the method, path
    /// and body of every request.
    struct Scripted {
        replies: Mutex<VecDeque<ScanResponse>>,
        sent: Mutex<Vec<Sent>>,
    }

    impl Scripted {
        fn new(replies: Vec<ScanResponse>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<Sent> {
            self.sent
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone()
        }

        fn answer(
            &self,
            method: &'static str,
            path: &str,
            body: Value,
        ) -> Result<ScanResponse, ScanError> {
            self.sent
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((method, path.to_owned(), body));
            self.replies
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .pop_front()
                .ok_or_else(|| ScanError::Upstream("no recorded response left".to_owned()))
        }
    }

    impl ScanHttp for Scripted {
        async fn post(
            &self,
            path: &str,
            _token: &[u8],
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            self.answer("POST", path, body.clone())
        }

        async fn patch(
            &self,
            path: &str,
            _token: &[u8],
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            self.answer("PATCH", path, body.clone())
        }

        async fn get(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            self.answer("GET", path, Value::Null)
        }
    }

    fn reply(status: u16, body: Value) -> ScanResponse {
        ScanResponse {
            status,
            retry_after: None,
            ratelimit_remaining: None,
            ratelimit_reset: None,
            link_next: None,
            body,
        }
    }

    fn issue(number: u64, body: &str) -> Value {
        json!({
            "number": number,
            "html_url": format!("https://github.com/octo/app/issues/{number}"),
            "body": body,
        })
    }

    fn ref_of(number: u64, body: &str) -> IssueRef {
        IssueRef {
            number,
            html_url: format!("https://github.com/octo/app/issues/{number}"),
            body: body.to_owned(),
        }
    }

    #[tokio::test]
    async fn list_follows_link_next_and_skips_pull_requests() {
        let page_one = ScanResponse {
            link_next: Some(
                "https://api.github.com/repositories/42/issues?state=open&labels=harborgate&per_page=100&page=2"
                    .to_owned(),
            ),
            ..reply(
                200,
                json!([
                    issue(1, "<!-- harborgate:CVE-2026-1 -->"),
                    {
                        "number": 2,
                        "html_url": "https://github.com/octo/app/pull/2",
                        "body": "a pull request",
                        "pull_request": {"url": "https://api.github.com/repos/octo/app/pulls/2"}
                    },
                ]),
            )
        };
        let page_two = reply(200, json!([issue(3, "<!-- harborgate:CVE-2026-3 -->")]));
        let fake = Scripted::new(vec![page_one, page_two]);

        let found = list_open_labelled_with(&fake, b"token", "octo", "app", 1000)
            .await
            .unwrap();

        assert_eq!(
            found,
            vec![
                ref_of(1, "<!-- harborgate:CVE-2026-1 -->"),
                ref_of(3, "<!-- harborgate:CVE-2026-3 -->"),
            ]
        );
        let paths: Vec<String> = fake.sent().into_iter().map(|(_, path, _)| path).collect();
        assert_eq!(
            paths,
            vec![
                "repos/octo/app/issues?state=open&labels=harborgate&per_page=100".to_owned(),
                "repositories/42/issues?state=open&labels=harborgate&per_page=100&page=2"
                    .to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn list_refuses_a_next_link_to_another_host() {
        let page = ScanResponse {
            link_next: Some("https://evil.example.com/issues?page=2".to_owned()),
            ..reply(200, json!([]))
        };
        let fake = Scripted::new(vec![page, reply(200, json!([]))]);
        let outcome = list_open_labelled_with(&fake, b"token", "octo", "app", 1000).await;
        assert!(matches!(outcome, Err(ScanError::Upstream(_))));
        assert_eq!(fake.sent().len(), 1, "the foreign link must not be fetched");
    }

    #[tokio::test]
    async fn list_never_requests_a_foreign_url_from_a_crafted_next_link() {
        for link in [
            // Empty segments that `Url::join` would read as a new host.
            "https://api.github.com///evil.example/x",
            "https://api.github.com//evil.example/x",
            // An embedded absolute URL in the path.
            "https://api.github.com/https://evil.example/",
            // User info and a non-default port.
            "https://api.github.com@evil.example/issues?page=2",
            "https://user:pw@api.github.com/issues?page=2",
            "https://api.github.com:8443/issues?page=2",
            // Wrong scheme, wrong host, a lookalike host, and rubbish.
            "http://api.github.com/issues?page=2",
            "https://api.github.com.evil.example/issues?page=2",
            "https://evil.example/issues?page=2",
            "//evil.example/x",
            "not a url",
        ] {
            let page = ScanResponse {
                link_next: Some(link.to_owned()),
                ..reply(200, json!([]))
            };
            let fake = Scripted::new(vec![page, reply(200, json!([]))]);
            let outcome = list_open_labelled_with(&fake, b"token", "octo", "app", 1000).await;
            assert!(
                matches!(outcome, Err(ScanError::Upstream(_))),
                "{link} should be refused"
            );
            assert_eq!(fake.sent().len(), 1, "{link} must not be requested");
        }
    }

    #[test]
    fn next_path_keeps_only_path_and_query() {
        assert_eq!(
            next_path(
                &GithubUrls::default(),
                "https://api.github.com/repositories/42/issues?page=2&per_page=100"
            ),
            Ok("repositories/42/issues?page=2&per_page=100".to_owned())
        );
        // The default port written out is the same host and port.
        assert_eq!(
            next_path(
                &GithubUrls::default(),
                "https://api.github.com:443/repositories/42/issues"
            ),
            Ok("repositories/42/issues".to_owned())
        );
    }

    #[test]
    fn marker_must_be_the_first_line() {
        let first = ref_of(1, "<!-- harborgate:CVE-2026-1 -->\n\nbody");
        let crlf = ref_of(2, "<!-- harborgate:CVE-2026-2 -->\r\nbody");
        let second_line = ref_of(3, "intro\n<!-- harborgate:CVE-2026-3 -->");
        let prefix_only = ref_of(4, "<!-- harborgate:CVE-2026-44 -->");
        let issues = vec![first, crlf, second_line, prefix_only];

        assert_eq!(
            find_marked(&issues, "CVE-2026-1").map(|i| i.number),
            Some(1)
        );
        assert_eq!(
            find_marked(&issues, "CVE-2026-2").map(|i| i.number),
            Some(2)
        );
        assert_eq!(find_marked(&issues, "CVE-2026-3"), None);
        // CVE-2026-4 is a prefix of CVE-2026-44, and must not match it.
        assert_eq!(find_marked(&issues, "CVE-2026-4"), None);
        assert_eq!(
            find_marked(&issues, "CVE-2026-44").map(|i| i.number),
            Some(4)
        );
    }

    #[tokio::test]
    async fn create_sends_the_harborgate_label() {
        let fake = Scripted::new(vec![reply(201, issue(7, "<!-- harborgate:CVE-2026-1 -->"))]);
        let created = create_with(
            &fake,
            b"token",
            "octo",
            "app",
            "CVE-2026-1 in libfoo",
            "<!-- harborgate:CVE-2026-1 -->",
            1000,
        )
        .await
        .unwrap();

        assert_eq!(created, ref_of(7, "<!-- harborgate:CVE-2026-1 -->"));
        let sent = fake.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "POST");
        assert_eq!(sent[0].1, "repos/octo/app/issues");
        assert_eq!(sent[0].2["labels"], json!(["harborgate"]));
        assert_eq!(sent[0].2["title"], "CVE-2026-1 in libfoo");
        assert_eq!(sent[0].2["body"], "<!-- harborgate:CVE-2026-1 -->");
    }

    #[tokio::test]
    async fn comment_posts_to_the_issue() {
        let fake = Scripted::new(vec![reply(201, json!({"id": 1}))]);
        comment_with(&fake, b"token", "octo", "app", 7, "back again", 1000)
            .await
            .unwrap();
        let sent = fake.sent();
        assert_eq!(sent[0].0, "POST");
        assert_eq!(sent[0].1, "repos/octo/app/issues/7/comments");
        assert_eq!(sent[0].2, json!({"body": "back again"}));
    }

    #[tokio::test]
    async fn close_sends_state_reason_completed() {
        let fake = Scripted::new(vec![reply(200, json!({})), reply(200, json!({}))]);
        set_state_with(&fake, b"token", "octo", "app", 7, false, 1000)
            .await
            .unwrap();
        set_state_with(&fake, b"token", "octo", "app", 7, true, 1000)
            .await
            .unwrap();

        let sent = fake.sent();
        assert_eq!(sent[0].0, "PATCH");
        assert_eq!(sent[0].1, "repos/octo/app/issues/7");
        assert_eq!(
            sent[0].2,
            json!({"state": "closed", "state_reason": "completed"})
        );
        // Reopening sends no state reason.
        assert_eq!(sent[1].2, json!({"state": "open"}));
    }

    #[tokio::test]
    async fn rate_limit_is_classified() {
        let limited = ScanResponse {
            ratelimit_remaining: Some(0),
            ratelimit_reset: Some(1900),
            ..reply(403, json!({"message": "API rate limit exceeded"}))
        };
        let fake = Scripted::new(vec![limited]);
        assert_eq!(
            list_open_labelled_with(&fake, b"token", "octo", "app", 1000).await,
            Err(ScanError::RateLimited { until: 1900 })
        );

        let secondary = ScanResponse {
            retry_after: Some(30),
            ..reply(429, json!({"message": "secondary rate limit"}))
        };
        let fake = Scripted::new(vec![secondary]);
        assert_eq!(
            create_with(&fake, b"token", "octo", "app", "t", "b", 1000).await,
            Err(ScanError::RateLimited { until: 1030 })
        );
    }

    #[tokio::test]
    async fn invalid_names_are_refused_before_any_request() {
        let fake = Scripted::new(vec![]);
        let outcome = list_open_labelled_with(&fake, b"token", "../octo", "app", 1000).await;
        assert!(matches!(outcome, Err(ScanError::Rejected(_))));
        assert!(fake.sent().is_empty());
    }

    #[test]
    fn body_starts_with_the_marker() {
        let body = issue_body(
            "CVE-2026-1",
            "CRITICAL",
            "libfoo",
            Some("1.2.4"),
            "library/app",
        );
        assert_eq!(body.lines().next(), Some("<!-- harborgate:CVE-2026-1 -->"));
        assert!(body.contains("| Severity | CRITICAL |"));
        assert!(body.contains("| Fixed in | 1.2.4 |"));
        assert!(body.contains("| Harbor repository | library/app |"));

        // The body it produces is found again by the marker lookup.
        let issues = vec![ref_of(1, &body)];
        assert_eq!(
            find_marked(&issues, "CVE-2026-1").map(|i| i.number),
            Some(1)
        );
    }

    #[test]
    fn body_cells_cannot_break_the_table() {
        let body = issue_body("CVE-2026-1", "HIGH", "a|b\nc", None, "library/app");
        assert!(body.contains("| Package | a\\|b c |"));
        assert!(body.contains("| Fixed in | none yet |"));
    }
}
