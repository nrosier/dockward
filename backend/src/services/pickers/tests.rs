//! Picker service tests. Upstream answers are recorded fixtures served by an in-memory fake
//! transport; no live Harbor or GitHub is called. Fixture bodies follow the shapes in
//! `specs/integrations.md` ("Mapping pickers"). All secrets are fake test values.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::services::audit::Actor;
use crate::services::credentials::NewCredential;
use crate::services::picker_upstream::UpstreamFuture;

/// A sentinel secret. It must never appear in any response body or error.
pub(crate) const SENTINEL: &str = "SENTINEL-picker-secret-7f3a";
const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const BASE: &str = "https://harbor.example.com";

/// One recorded route: a matcher on the URL text and the answer.
type Route = (Box<dyn Fn(&Url) -> bool + Send + Sync>, UpstreamResponse);

/// A fake transport answering from recorded responses. It counts calls, records each URL,
/// and records whether the auth carried the sentinel (to prove auth is sent upstream only).
#[derive(Default)]
pub(crate) struct Recorded {
    routes: Mutex<Vec<Route>>,
    pub calls: AtomicUsize,
    pub urls: Mutex<Vec<String>>,
    /// Optional delay, to test the shared fill.
    pub delay_ms: u64,
}

impl Recorded {
    pub(crate) fn on(
        &self,
        matcher: impl Fn(&Url) -> bool + Send + Sync + 'static,
        response: UpstreamResponse,
    ) {
        self.routes
            .lock()
            .unwrap()
            .push((Box::new(matcher), response));
    }

    fn urls(&self) -> Vec<String> {
        self.urls.lock().unwrap().clone()
    }
}

impl PickerHttp for Recorded {
    fn get<'a>(&'a self, url: &'a Url, auth: UpstreamAuth<'a>) -> UpstreamFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.urls.lock().unwrap().push(url.to_string());
            let secret = match auth {
                UpstreamAuth::Harbor { secret, .. } => secret,
                UpstreamAuth::Github { token } => token,
            };
            assert_eq!(
                secret,
                SENTINEL.as_bytes(),
                "the stored secret is sent upstream"
            );
            if self.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            }
            let routes = self.routes.lock().unwrap();
            for (matcher, response) in routes.iter() {
                if matcher(url) {
                    return Ok(response.clone());
                }
            }
            Ok(UpstreamResponse {
                status: 500,
                body: format!("unrecorded {url} {SENTINEL}").into_bytes(),
                ..Default::default()
            })
        })
    }
}

pub(crate) fn ok(body: &str) -> UpstreamResponse {
    UpstreamResponse {
        status: 200,
        body: body.as_bytes().to_vec(),
        ..Default::default()
    }
}

pub(crate) fn status(code: u16) -> UpstreamResponse {
    UpstreamResponse {
        status: code,
        // Upstream text that must never be echoed.
        body: format!(r#"{{"message":"upstream detail {SENTINEL}"}}"#).into_bytes(),
        ..Default::default()
    }
}

fn path_is(path: &'static str) -> impl Fn(&Url) -> bool + Send + Sync {
    move |url: &Url| url.path() == path
}

fn page_is(path: &'static str, page: u32) -> impl Fn(&Url) -> bool + Send + Sync {
    move |url: &Url| {
        url.path() == path
            && url
                .query_pairs()
                .any(|(k, v)| k == "page" && v == page.to_string())
    }
}

/// Recorded Harbor answer for the robot identity check.
pub(crate) fn robot_ok(fake: &Recorded) {
    fake.on(path_is("/api/v2.0/users/current"), status(412));
}

fn projects_body(names: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = names
        .map(|n| format!(r#"{{"project_id":1,"name":"{n}","public":false}}"#))
        .collect();
    format!("[{}]", items.join(","))
}

pub(crate) struct Fixture {
    pub pool: SqlitePool,
    pub key: DerivedKey,
    pub dir: std::path::PathBuf,
    pub harbor: String,
    pub github: String,
    pub other_harbor: String,
}

impl Fixture {
    pub(crate) async fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("harborgate-pickers-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        let root = crate::config::parse_encryption_key(ROOT).unwrap();
        let key = crate::auth::crypto::credentials_key(&root).unwrap();
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            crate::db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        drop(conn);
        let make = |user: &'static str, service: &'static str| {
            let pool = pool.clone();
            let key = &key;
            async move {
                crate::services::credentials::create(
                    &pool,
                    key,
                    &Actor {
                        user_id: Some(user.to_owned()),
                        username: user.to_owned(),
                    },
                    user,
                    NewCredential {
                        service_type: service.to_owned(),
                        label: service.to_owned(),
                        base_url: (service == SERVICE_HARBOR).then(|| BASE.to_owned()),
                        username: (service == SERVICE_HARBOR).then(|| "robot$hg".to_owned()),
                        token: SENTINEL.to_owned(),
                        expires_at: None,
                    },
                    false,
                )
                .await
                .unwrap()
                .id
            }
        };
        let harbor = make("owner-1", SERVICE_HARBOR).await;
        let github = make("owner-1", SERVICE_GITHUB).await;
        let other_harbor = make("other-2", SERVICE_HARBOR).await;
        Self {
            pool,
            key,
            dir,
            harbor,
            github,
            other_harbor,
        }
    }

    fn caller(&self) -> Caller<'_> {
        Caller {
            pool: &self.pool,
            key: &self.key,
            user_id: "owner-1",
        }
    }

    async fn close(self) {
        self.pool.close().await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn state(fake: Arc<Recorded>) -> PickerState {
    PickerState::new(fake)
}

fn expect_fixed(
    result: Result<impl std::fmt::Debug, PickerFail>,
) -> (StatusCode, &'static str, &'static str, Option<u64>) {
    match result {
        Err(PickerFail::Fixed {
            status,
            code,
            message,
            retry_after,
        }) => (status, code, message, retry_after),
        other => panic!("expected a fixed failure, got {other:?}"),
    }
}

#[tokio::test]
async fn harbor_projects_follow_pages_and_cap_at_ten() {
    let fx = Fixture::new("projects-paging").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    for page in 1..=10u32 {
        let start = (page - 1) * 100;
        let body = projects_body((start..start + 100).map(|i| format!("p{i:04}")));
        let mut response = ok(&body);
        response.total_count = Some(1500);
        fake.on(page_is("/api/v2.0/projects", page), response);
    }
    let picker = state(fake.clone());
    let page = picker
        .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.total, 1000);
    assert!(page.truncated, "a list cut at the cap is truncated");
    assert_eq!(page.items.len(), 50);
    assert_eq!(page.items[0].name, "p0000");
    // One identity call and ten pages; each page asks for 100 sorted by name.
    assert_eq!(fake.calls.load(Ordering::SeqCst), 11);
    let urls = fake.urls();
    assert!(urls[1].contains("page_size=100") && urls[1].contains("sort=name"));
    fx.close().await;
}

#[tokio::test]
async fn short_harbor_list_is_not_truncated_and_search_goes_to_harbor() {
    let fx = Fixture::new("projects-search").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(
        path_is("/api/v2.0/projects"),
        ok(&projects_body(
            ["alpha", "beta", "Bad/Name"].iter().map(|s| s.to_string()),
        )),
    );
    let picker = state(fake.clone());
    let query = ListQuery {
        q: Some("  ALP ".to_owned()),
        ..Default::default()
    };
    let page = picker
        .harbor_projects(&fx.caller(), &fx.harbor, &query)
        .await
        .unwrap();
    assert!(!page.truncated);
    // Invalid upstream names are skipped.
    let names: Vec<_> = page.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta"]);
    assert!(fake.urls()[1].contains("name=alp"), "{:?}", fake.urls());

    // Text that cannot be a Harbor name: empty list and no upstream call.
    let before = fake.calls.load(Ordering::SeqCst);
    let query = ListQuery {
        q: Some("a,b=~c".to_owned()),
        ..Default::default()
    };
    let page = picker
        .harbor_projects(&fx.caller(), &fx.harbor, &query)
        .await
        .unwrap();
    assert_eq!(page.total, 0);
    assert_eq!(fake.calls.load(Ordering::SeqCst), before);
    fx.close().await;
}

#[tokio::test]
async fn identity_412_passes_and_anything_else_is_refused() {
    for (code, ok_expected) in [(412u16, true), (401, false), (200, false), (500, false)] {
        let fx = Fixture::new(&format!("identity-{code}")).await;
        let fake = Arc::new(Recorded::default());
        fake.on(path_is("/api/v2.0/users/current"), status(code));
        fake.on(
            path_is("/api/v2.0/projects"),
            ok(r#"[{"name":"public-one"}]"#),
        );
        let picker = state(fake.clone());
        let result = picker
            .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
            .await;
        if ok_expected {
            assert_eq!(result.unwrap().items.len(), 1);
        } else {
            match result {
                Err(PickerFail::App(AppError::ValidationFailed(message))) => {
                    assert_eq!(message, MSG_HARBOR_IDENTITY);
                }
                other => panic!("status {code}: expected the identity refusal, got {other:?}"),
            }
            // The project list is never read after a refusal.
            assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        }
        fx.close().await;
    }
}

#[tokio::test]
async fn harbor_repository_list_maps_errors_and_strips_the_prefix() {
    let fx = Fixture::new("repos").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(
        path_is("/api/v2.0/projects/proj/repositories"),
        ok(r#"[{"name":"proj/app"},{"name":"proj/team/api"},{"name":"other/x"}]"#),
    );
    fake.on(
        path_is("/api/v2.0/projects/locked/repositories"),
        status(403),
    );
    fake.on(path_is("/api/v2.0/projects/gone/repositories"), status(404));
    fake.on(
        path_is("/api/v2.0/projects/broken/repositories"),
        status(503),
    );
    let picker = state(fake.clone());
    let page = picker
        .harbor_repositories(&fx.caller(), &fx.harbor, "proj", &ListQuery::default())
        .await
        .unwrap();
    let items: Vec<_> = page
        .items
        .iter()
        .map(|i| (i.repository.as_str(), i.full_name.as_str()))
        .collect();
    assert_eq!(items, [("app", "proj/app"), ("team/api", "proj/team/api")]);

    match picker
        .harbor_repositories(&fx.caller(), &fx.harbor, "locked", &ListQuery::default())
        .await
    {
        Err(PickerFail::App(AppError::ValidationFailed(m))) => {
            assert_eq!(m, MSG_REPO_LIST_FORBIDDEN)
        }
        other => panic!("{other:?}"),
    }
    let (code, _, message, _) = expect_fixed(
        picker
            .harbor_repositories(&fx.caller(), &fx.harbor, "gone", &ListQuery::default())
            .await,
    );
    assert_eq!(
        (code, message),
        (StatusCode::NOT_FOUND, MSG_PROJECT_NOT_FOUND)
    );
    assert!(matches!(
        picker
            .harbor_repositories(&fx.caller(), &fx.harbor, "broken", &ListQuery::default())
            .await,
        Err(PickerFail::App(AppError::UpstreamUnreachable))
    ));
    // A bad project name is refused before any request.
    let before = fake.calls.load(Ordering::SeqCst);
    assert!(matches!(
        picker
            .harbor_repositories(&fx.caller(), &fx.harbor, "Bad%2F", &ListQuery::default())
            .await,
        Err(PickerFail::App(AppError::ValidationFailed(_)))
    ));
    assert_eq!(fake.calls.load(Ordering::SeqCst), before);
    fx.close().await;
}

fn github_page(range: std::ops::Range<u32>, next: Option<u32>) -> UpstreamResponse {
    let items: Vec<String> = range
        .map(|i| {
            format!(
                r#"{{"name":"repo{i:04}","full_name":"octo/repo{i:04}","owner":{{"login":"octo"}},"private":{},"archived":false}}"#,
                i % 2 == 0
            )
        })
        .collect();
    let mut response = ok(&format!("[{}]", items.join(",")));
    response.link_next =
        next.map(|n| format!("https://api.github.com/user/repos?per_page=100&page={n}"));
    response
}

#[tokio::test]
async fn github_list_follows_link_next_and_marks_truncated_at_the_cap() {
    let fx = Fixture::new("github-paging").await;
    let fake = Arc::new(Recorded::default());
    for page in 1..=10u32 {
        let start = (page - 1) * 100;
        fake.on(
            page_is("/user/repos", page),
            github_page(start..start + 100, Some(page + 1)),
        );
    }
    let picker = state(fake.clone());
    let page = picker
        .github_repositories(&fx.caller(), &fx.github, &ListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.total, 1000);
    assert!(page.truncated, "more than 1,000 repositories: truncated");
    assert_eq!(fake.calls.load(Ordering::SeqCst), 10);
    assert_eq!(page.items[0].full_name, "octo/repo0000");
    assert!(page.items[0].private);

    // Search filters the cached list case-insensitively, without a new call.
    let query = ListQuery {
        q: Some("REPO0999".to_owned()),
        ..Default::default()
    };
    let found = picker
        .github_repositories(&fx.caller(), &fx.github, &query)
        .await
        .unwrap();
    assert_eq!(found.total, 1);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 10);
    fx.close().await;
}

#[tokio::test]
async fn github_list_stops_without_link_next() {
    let fx = Fixture::new("github-short").await;
    let fake = Arc::new(Recorded::default());
    fake.on(page_is("/user/repos", 1), github_page(0..100, Some(2)));
    fake.on(page_is("/user/repos", 2), github_page(100..130, None));
    let picker = state(fake.clone());
    let page = picker
        .github_repositories(&fx.caller(), &fx.github, &ListQuery::default())
        .await
        .unwrap();
    assert_eq!((page.total, page.truncated), (130, false));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    fx.close().await;
}

#[tokio::test]
async fn github_link_to_another_host_is_refused() {
    let fx = Fixture::new("github-link-host").await;
    let fake = Arc::new(Recorded::default());
    let mut first = github_page(0..100, None);
    first.link_next = Some("https://evil.example.com/user/repos?page=2".to_owned());
    fake.on(page_is("/user/repos", 1), first);
    let picker = state(fake.clone());
    assert!(matches!(
        picker
            .github_repositories(&fx.caller(), &fx.github, &ListQuery::default())
            .await,
        Err(PickerFail::App(AppError::UpstreamUnreachable))
    ));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    fx.close().await;
}

#[tokio::test]
async fn github_errors_use_fixed_text() {
    for (code, expected) in [(401u16, MSG_GITHUB_INVALID), (403, MSG_GITHUB_FORBIDDEN)] {
        let fx = Fixture::new(&format!("github-err-{code}")).await;
        let fake = Arc::new(Recorded::default());
        fake.on(path_is("/user/repos"), status(code));
        let picker = state(fake);
        match picker
            .github_repositories(&fx.caller(), &fx.github, &ListQuery::default())
            .await
        {
            Err(PickerFail::App(AppError::ValidationFailed(m))) => assert_eq!(m, expected),
            other => panic!("{other:?}"),
        }
        fx.close().await;
    }
}

#[tokio::test]
async fn github_rate_limit_returns_the_fixed_message_and_blocks_calls() {
    let fx = Fixture::new("github-rate").await;
    let fake = Arc::new(Recorded::default());
    let mut limited = status(403);
    limited.ratelimit_remaining = Some(0);
    limited.ratelimit_reset = Some(now_secs() + 120);
    fake.on(path_is("/user/repos"), limited);
    let picker = state(fake.clone());
    let (code, error_code, message, wait) = expect_fixed(
        picker
            .github_repositories(&fx.caller(), &fx.github, &ListQuery::default())
            .await,
    );
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error_code, "rate_limited");
    assert_eq!(message, MSG_GITHUB_RATE);
    let wait = wait.unwrap();
    assert!((100..=120).contains(&wait), "Retry-After {wait}");
    // A second request inside the window makes no call: no retry loop.
    let (_, _, message, _) = expect_fixed(
        picker
            .github_repositories(&fx.caller(), &fx.github, &ListQuery::default())
            .await,
    );
    assert_eq!(message, MSG_GITHUB_RATE);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    fx.close().await;
}

#[tokio::test]
async fn harbor_429_returns_the_fixed_message_with_retry_after_capped() {
    let fx = Fixture::new("harbor-rate").await;
    let fake = Arc::new(Recorded::default());
    let mut limited = status(429);
    limited.retry_after = Some(99_999);
    fake.on(path_is("/api/v2.0/users/current"), limited);
    let picker = state(fake.clone());
    let (code, _, message, wait) = expect_fixed(
        picker
            .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
            .await,
    );
    assert_eq!(
        (code, message),
        (StatusCode::TOO_MANY_REQUESTS, MSG_HARBOR_RATE)
    );
    assert_eq!(wait, Some(3600), "the wait is capped at one hour");
    expect_fixed(
        picker
            .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
            .await,
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    fx.close().await;
}

#[tokio::test]
async fn cache_hits_then_expires_after_five_minutes() {
    let fx = Fixture::new("cache-ttl").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(path_is("/api/v2.0/projects"), ok(r#"[{"name":"alpha"}]"#));
    let picker = state(fake.clone());
    let caller = fx.caller();
    let query = ListQuery::default();
    let run = || picker.harbor_projects(&caller, &fx.harbor, &query);
    run().await.unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    // A hit makes no call, not even the identity check.
    run().await.unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    picker.cache.advance(299);
    run().await.unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    picker.cache.advance(2);
    run().await.unwrap();
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        4,
        "the entry expired at 5 minutes"
    );
    fx.close().await;
}

#[tokio::test]
async fn errors_are_not_cached() {
    let fx = Fixture::new("cache-error").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(path_is("/api/v2.0/projects"), status(500));
    let picker = state(fake.clone());
    for _ in 0..2 {
        assert!(
            picker
                .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
                .await
                .is_err()
        );
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
    fx.close().await;
}

#[tokio::test]
async fn concurrent_requests_share_one_fill() {
    let fx = Fixture::new("cache-shared").await;
    let fake = Arc::new(Recorded {
        delay_ms: 50,
        ..Default::default()
    });
    robot_ok(&fake);
    fake.on(path_is("/api/v2.0/projects"), ok(r#"[{"name":"alpha"}]"#));
    let picker = state(fake.clone());
    let caller = fx.caller();
    let query = ListQuery::default();
    let (a, b, c) = tokio::join!(
        picker.harbor_projects(&caller, &fx.harbor, &query),
        picker.harbor_projects(&caller, &fx.harbor, &query),
        picker.harbor_projects(&caller, &fx.harbor, &query),
    );
    assert!(a.is_ok() && b.is_ok() && c.is_ok());
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        2,
        "one identity call and one page"
    );
    fx.close().await;
}

#[tokio::test]
async fn cache_is_bounded_and_evicts_the_oldest() {
    let cache = PickerCache::new(CACHE_TTL, 3);
    for i in 0..5 {
        let key = CacheKey {
            credential: "c".to_owned(),
            list: "harbor_projects",
            project: String::new(),
            search: format!("s{i}"),
        };
        cache
            .get_or_fill(key, async {
                Ok(Cached::Suggestion(Arc::new(SuggestionOutcome::None(
                    "no_label",
                ))))
            })
            .await
            .unwrap();
    }
    assert_eq!(cache.len(), 3);
    let map = cache.map.lock().unwrap();
    assert!(
        !map.slots
            .keys()
            .any(|k| k.search == "s0" || k.search == "s1")
    );
}

#[tokio::test]
async fn dropping_a_credential_clears_its_entries_and_block() {
    let fx = Fixture::new("cache-drop").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(path_is("/api/v2.0/projects"), ok(r#"[{"name":"alpha"}]"#));
    let picker = state(fake.clone());
    picker
        .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
        .await
        .unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    picker.drop_credential(&fx.harbor);
    picker
        .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
        .await
        .unwrap();
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        4,
        "the dropped entry is fetched again"
    );
    fx.close().await;
}

#[tokio::test]
async fn another_users_credential_is_404_and_wrong_type_is_422() {
    let fx = Fixture::new("tenancy").await;
    let fake = Arc::new(Recorded::default());
    let picker = state(fake.clone());
    assert!(matches!(
        picker
            .harbor_projects(&fx.caller(), &fx.other_harbor, &ListQuery::default())
            .await,
        Err(PickerFail::App(AppError::NotFound))
    ));
    assert!(matches!(
        picker
            .harbor_projects(&fx.caller(), "no-such-id", &ListQuery::default())
            .await,
        Err(PickerFail::App(AppError::NotFound))
    ));
    match picker
        .harbor_projects(&fx.caller(), &fx.github, &ListQuery::default())
        .await
    {
        Err(PickerFail::App(AppError::ValidationFailed(m))) => assert_eq!(m, MSG_WRONG_TYPE),
        other => panic!("{other:?}"),
    }
    match picker
        .github_repositories(&fx.caller(), &fx.harbor, &ListQuery::default())
        .await
    {
        Err(PickerFail::App(AppError::ValidationFailed(m))) => assert_eq!(m, MSG_WRONG_TYPE),
        other => panic!("{other:?}"),
    }
    let query = SuggestionQuery {
        project: Some("proj".to_owned()),
        repository: Some("app".to_owned()),
        github_cred_id: Some(fx.harbor.clone()),
    };
    assert!(matches!(
        picker
            .source_suggestion(&fx.caller(), &fx.harbor, &query)
            .await,
        Err(PickerFail::App(AppError::ValidationFailed(_)))
    ));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    fx.close().await;
}

#[tokio::test]
async fn user_limit_is_sixty_per_minute_and_checked_after_tenancy() {
    let fx = Fixture::new("user-limit").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(path_is("/api/v2.0/projects"), ok(r#"[{"name":"alpha"}]"#));
    let picker = state(fake);
    for _ in 0..60 {
        picker
            .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
            .await
            .unwrap();
    }
    let (code, _, message, wait) = expect_fixed(
        picker
            .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
            .await,
    );
    assert_eq!(
        (code, message),
        (StatusCode::TOO_MANY_REQUESTS, MSG_USER_LIMIT)
    );
    assert!(wait.is_some());
    // Another user's credential is still 404, never 429.
    assert!(matches!(
        picker
            .harbor_projects(&fx.caller(), &fx.other_harbor, &ListQuery::default())
            .await,
        Err(PickerFail::App(AppError::NotFound))
    ));
    fx.close().await;
}

#[test]
fn list_query_validation() {
    let long = ListQuery {
        q: Some("a".repeat(101)),
        ..Default::default()
    };
    assert!(matches!(
        parse_query(&long, &["name"]),
        Err(AppError::InvalidRequest(_))
    ));
    let control = ListQuery {
        q: Some("a\u{7}".to_owned()),
        ..Default::default()
    };
    assert!(matches!(
        parse_query(&control, &["name"]),
        Err(AppError::InvalidRequest(_))
    ));
    let sort = ListQuery {
        sort: Some("created_at".to_owned()),
        ..Default::default()
    };
    assert!(parse_query(&sort, &["name"]).is_err());
    let big = ListQuery {
        page_size: Some(201),
        ..Default::default()
    };
    assert!(parse_query(&big, &["name"]).is_err());
    let (paging, _) = parse_query(&ListQuery::default(), &["name"]).unwrap();
    assert!(paging.ascending, "name ascending by default");
}

#[test]
fn source_label_parsing_is_strict() {
    let github = |o: &str, r: &str| LabelParse::Github {
        owner: o.to_owned(),
        repo: r.to_owned(),
    };
    assert_eq!(
        parse_source_label("https://github.com/octo/app"),
        github("octo", "app")
    );
    assert_eq!(
        parse_source_label("https://GitHub.com/Octo/App.git"),
        github("Octo", "App")
    );
    assert_eq!(
        parse_source_label("https://github.com/octo/app/"),
        github("octo", "app")
    );
    assert_eq!(
        parse_source_label("https://gitlab.com/octo/app"),
        LabelParse::NotGithub
    );
    for bad in [
        "https://user:tok@github.com/octo/app",
        "https://tok@github.com/octo/app",
        "https://github.com:443/octo/app",
        "https://github.com:8443/octo/app",
        "https://github.com/octo/app?x=1",
        "https://github.com/octo/app#frag",
        "https://github.com/octo/app/tree/main",
        "https://github.com/octo",
        "http://github.com/octo/app",
        "https://github.com/octo/..",
        "https://github.com/bad_owner/app",
        "not a url",
        "",
    ] {
        assert_eq!(parse_source_label(bad), LabelParse::Invalid, "{bad}");
    }
}

fn artifact_routes(fake: &Recorded, label: Option<&str>) {
    robot_ok(fake);
    fake.on(
        path_is("/api/v2.0/projects/proj/repositories/app/artifacts"),
        ok(r#"[{"digest":"sha256:abcd","tags":[{"name":"v2"}]}]"#),
    );
    let labels = match label {
        Some(value) => format!(
            r#"{{"org.opencontainers.image.source":{}}}"#,
            serde_json::to_string(value).unwrap()
        ),
        None => r#"{"other":"x"}"#.to_owned(),
    };
    fake.on(
        path_is("/api/v2.0/projects/proj/repositories/app/artifacts/sha256%3Aabcd"),
        ok(&format!(
            r#"{{"digest":"sha256:abcd","extra_attrs":{{"config":{{"Labels":{labels}}}}}}}"#
        )),
    );
}

fn suggestion_query(github: Option<&str>) -> SuggestionQuery {
    SuggestionQuery {
        project: Some("proj".to_owned()),
        repository: Some("app".to_owned()),
        github_cred_id: github.map(str::to_owned),
    }
}

#[tokio::test]
async fn suggestion_reads_the_newest_tagged_artifact_and_checks_the_github_list() {
    let fx = Fixture::new("suggest-valid").await;
    let fake = Arc::new(Recorded::default());
    artifact_routes(&fake, Some("https://github.com/Octo/Repo0001.git"));
    fake.on(page_is("/user/repos", 1), github_page(0..5, None));
    let picker = state(fake.clone());
    let response = picker
        .source_suggestion(
            &fx.caller(),
            &fx.harbor,
            &suggestion_query(Some(&fx.github)),
        )
        .await
        .unwrap();
    assert_eq!(
        response,
        SuggestionResponse {
            suggestion: Some(Suggestion {
                github_owner: "Octo".to_owned(),
                github_repo: "Repo0001".to_owned(),
                image_tag: "v2".to_owned(),
                github_listed: Some(true),
            }),
            reason: None,
        }
    );
    let list_url = fake
        .urls()
        .into_iter()
        .find(|u| u.ends_with("/artifacts?page=1&page_size=1&sort=-push_time&q=tags%3D*"));
    assert!(list_url.is_some(), "{:?}", fake.urls());

    // Without a GitHub credential `github_listed` is null; the suggestion is cached.
    let before = fake.calls.load(Ordering::SeqCst);
    let response = picker
        .source_suggestion(&fx.caller(), &fx.harbor, &suggestion_query(None))
        .await
        .unwrap();
    assert_eq!(response.suggestion.unwrap().github_listed, None);
    assert_eq!(fake.calls.load(Ordering::SeqCst), before);
    fx.close().await;
}

#[tokio::test]
async fn suggestion_reasons_and_the_label_is_never_echoed() {
    let secret_label = format!("https://x:{SENTINEL}@github.com/octo/app");
    let cases: Vec<(Option<String>, &str)> = vec![
        (None, "no_label"),
        (Some("https://gitlab.com/octo/app".to_owned()), "not_github"),
        (Some(secret_label.clone()), "invalid_label"),
        (
            Some("https://github.com/octo/app/extra".to_owned()),
            "invalid_label",
        ),
    ];
    for (i, (label, reason)) in cases.into_iter().enumerate() {
        let fx = Fixture::new(&format!("suggest-reason-{i}")).await;
        let fake = Arc::new(Recorded::default());
        artifact_routes(&fake, label.as_deref());
        let picker = state(fake);
        let response = picker
            .source_suggestion(&fx.caller(), &fx.harbor, &suggestion_query(None))
            .await
            .unwrap();
        assert_eq!(response.suggestion, None);
        assert_eq!(response.reason, Some(reason));
        let text = serde_json::to_string(&response).unwrap();
        assert!(!text.contains(SENTINEL), "the label leaked: {text}");
        assert!(!text.contains("gitlab"), "the label leaked: {text}");
        fx.close().await;
    }
}

#[tokio::test]
async fn suggestion_without_a_tagged_artifact_and_missing_params() {
    let fx = Fixture::new("suggest-none").await;
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(
        path_is("/api/v2.0/projects/proj/repositories/app/artifacts"),
        ok("[]"),
    );
    let picker = state(fake);
    let response = picker
        .source_suggestion(&fx.caller(), &fx.harbor, &suggestion_query(None))
        .await
        .unwrap();
    assert_eq!(response.reason, Some("no_tagged_artifact"));
    let missing = SuggestionQuery {
        project: Some("proj".to_owned()),
        ..Default::default()
    };
    assert!(matches!(
        picker
            .source_suggestion(&fx.caller(), &fx.harbor, &missing)
            .await,
        Err(PickerFail::App(AppError::InvalidRequest(_)))
    ));
    fx.close().await;
}

fn hide_request(source: &str, full_name: &str, base: Option<&str>) -> HideRequest {
    HideRequest {
        source: source.to_owned(),
        full_name: full_name.to_owned(),
        harbor_base_url: base.map(str::to_owned),
    }
}

#[tokio::test]
async fn hide_harbor_with_base_url_filters_only_that_instance() {
    let fx = Fixture::new("hide-harbor").await;
    let (item, created) = hide(
        &fx.pool,
        "owner-1",
        hide_request("harbor", "alpha", Some("https://HARBOR.example.com:443/")),
        false,
    )
    .await
    .unwrap();
    assert!(created);
    assert_eq!(
        item.harbor_base_url.as_deref(),
        Some(BASE),
        "stored normalized"
    );
    // The same name on another Harbor instance is a separate row.
    let (_, created) = hide(
        &fx.pool,
        "owner-1",
        hide_request("harbor", "alpha", Some("https://other.example.com")),
        false,
    )
    .await
    .unwrap();
    assert!(created);
    // A repeat is 200 with the existing item.
    let (again, created) = hide(
        &fx.pool,
        "owner-1",
        hide_request("harbor", "alpha", Some(BASE)),
        false,
    )
    .await
    .unwrap();
    assert!(!created);
    assert_eq!(again.id, item.id);

    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(
        path_is("/api/v2.0/projects"),
        ok(r#"[{"name":"alpha"},{"name":"beta"}]"#),
    );
    let picker = state(fake.clone());
    let page = picker
        .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
        .await
        .unwrap();
    let names: Vec<_> = page.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["beta"]);
    assert_eq!(page.total, 1, "total counts after the hidden filter");
    // A hidden project hides its repository picker too, with no upstream call.
    let before = fake.calls.load(Ordering::SeqCst);
    let repos = picker
        .harbor_repositories(&fx.caller(), &fx.harbor, "alpha", &ListQuery::default())
        .await
        .unwrap();
    assert_eq!(repos.total, 0);
    assert_eq!(fake.calls.load(Ordering::SeqCst), before);

    // Restoring takes effect at once, without waiting for the cache.
    restore(&fx.pool, "owner-1", &item.id).await.unwrap();
    let page = picker
        .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.total, 2);
    fx.close().await;
}

#[tokio::test]
async fn hide_validation_rules() {
    let fx = Fixture::new("hide-rules").await;
    let refused = [
        hide_request("github", "octo/app", Some(BASE)),
        hide_request("harbor", "alpha", None),
        hide_request("harbor", "Alpha", Some(BASE)),
        hide_request("harbor", "alpha", Some("http://harbor.example.com")),
        hide_request("github", "octo", None),
        hide_request("github", "bad_owner/app", None),
        hide_request("gitlab", "octo/app", None),
    ];
    for request in refused {
        let label = format!("{} {}", request.source, request.full_name);
        assert!(
            matches!(
                hide(&fx.pool, "owner-1", request, false).await,
                Err(AppError::ValidationFailed(_))
            ),
            "{label}"
        );
    }
    match hide(
        &fx.pool,
        "owner-1",
        hide_request("github", "octo/app", Some(BASE)),
        false,
    )
    .await
    {
        Err(AppError::ValidationFailed(m)) => {
            assert_eq!(m, "harbor_base_url is only for Harbor items.")
        }
        other => panic!("{other:?}"),
    }
    // GitHub names are stored lowercased, so case variants are one row.
    let (first, _) = hide(
        &fx.pool,
        "owner-1",
        hide_request("github", "Octo/App", None),
        false,
    )
    .await
    .unwrap();
    let (second, created) = hide(
        &fx.pool,
        "owner-1",
        hide_request("github", "octo/app", None),
        false,
    )
    .await
    .unwrap();
    assert_eq!(first.full_name, "octo/app");
    assert_eq!((first.id, created), (second.id, false));
    assert_eq!(second.harbor_base_url, None);
    fx.close().await;
}

#[tokio::test]
async fn hidden_items_are_capped_per_user() {
    let fx = Fixture::new("hide-cap").await;
    for i in 0..HIDDEN_CAP {
        sqlx::query(
            "INSERT INTO picker_hidden_items (id, user_id, source, harbor_base_url, full_name)
             VALUES (?, 'owner-1', 'github', NULL, ?)",
        )
        .bind(format!("h{i}"))
        .bind(format!("octo/r{i}"))
        .execute(&fx.pool)
        .await
        .unwrap();
    }
    match hide(
        &fx.pool,
        "owner-1",
        hide_request("github", "octo/one-more", None),
        false,
    )
    .await
    {
        Err(AppError::ValidationFailed(m)) => assert!(m.contains("1,000")),
        other => panic!("{other:?}"),
    }
    // An item already hidden is still 200 at the cap.
    let (_, created) = hide(
        &fx.pool,
        "owner-1",
        hide_request("github", "octo/r5", None),
        false,
    )
    .await
    .unwrap();
    assert!(!created);
    // Another user is not affected by this user's cap.
    let (_, created) = hide(
        &fx.pool,
        "other-2",
        hide_request("github", "octo/one-more", None),
        false,
    )
    .await
    .unwrap();
    assert!(created);
    fx.close().await;
}

#[tokio::test]
async fn hidden_list_and_restore_are_owner_scoped() {
    let fx = Fixture::new("hide-list").await;
    let (mine, _) = hide(
        &fx.pool,
        "owner-1",
        hide_request("harbor", "alpha", Some(BASE)),
        false,
    )
    .await
    .unwrap();
    hide(
        &fx.pool,
        "owner-1",
        hide_request("github", "octo/app", None),
        false,
    )
    .await
    .unwrap();
    let (theirs, _) = hide(
        &fx.pool,
        "other-2",
        hide_request("github", "octo/app", None),
        false,
    )
    .await
    .unwrap();
    let page = list_hidden(&fx.pool, "owner-1", &HiddenQuery::default())
        .await
        .unwrap();
    assert_eq!(page.total, 2);
    let harbor_only = list_hidden(
        &fx.pool,
        "owner-1",
        &HiddenQuery {
            source: Some("harbor".to_owned()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(harbor_only.total, 1);
    assert_eq!(harbor_only.items[0].id, mine.id);
    assert!(
        list_hidden(
            &fx.pool,
            "owner-1",
            &HiddenQuery {
                source: Some("x".to_owned()),
                ..Default::default()
            }
        )
        .await
        .is_err()
    );
    assert_eq!(
        restore(&fx.pool, "owner-1", &theirs.id).await,
        Err(AppError::NotFound)
    );
    restore(&fx.pool, "other-2", &theirs.id).await.unwrap();
    fx.close().await;
}

#[tokio::test]
async fn the_check_constraint_ties_base_url_to_source() {
    let fx = Fixture::new("hide-check").await;
    for (source, base) in [("github", Some(BASE)), ("harbor", None)] {
        let result = sqlx::query(
            "INSERT INTO picker_hidden_items (id, user_id, source, harbor_base_url, full_name)
             VALUES ('x', 'owner-1', ?, ?, 'a/b')",
        )
        .bind(source)
        .bind(base)
        .execute(&fx.pool)
        .await;
        assert!(result.is_err(), "{source} with {base:?} was accepted");
    }
    fx.close().await;
}

#[tokio::test]
async fn the_sentinel_never_appears_in_any_response_or_error() {
    let fx = Fixture::new("sentinel").await;
    let mut seen = Vec::new();
    // Every upstream failure carries the sentinel in its body.
    for code in [401u16, 403, 404, 429, 500, 503] {
        let fake = Arc::new(Recorded::default());
        robot_ok(&fake);
        fake.on(path_is("/api/v2.0/projects"), status(code));
        fake.on(
            path_is("/api/v2.0/projects/proj/repositories"),
            status(code),
        );
        fake.on(path_is("/user/repos"), status(code));
        fake.on(
            path_is("/api/v2.0/projects/proj/repositories/app/artifacts"),
            status(code),
        );
        let picker = state(fake);
        let render = |fail: PickerFail| match fail {
            PickerFail::App(err) => format!("{err:?} {}", err.message()),
            PickerFail::Fixed { message, .. } => message.to_owned(),
        };
        if let Err(fail) = picker
            .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
            .await
        {
            seen.push(render(fail));
        }
        if let Err(fail) = picker
            .harbor_repositories(&fx.caller(), &fx.harbor, "proj", &ListQuery::default())
            .await
        {
            seen.push(render(fail));
        }
        if let Err(fail) = picker
            .github_repositories(&fx.caller(), &fx.github, &ListQuery::default())
            .await
        {
            seen.push(render(fail));
        }
        if let Err(fail) = picker
            .source_suggestion(&fx.caller(), &fx.harbor, &suggestion_query(None))
            .await
        {
            seen.push(render(fail));
        }
    }
    // A successful list too.
    let fake = Arc::new(Recorded::default());
    robot_ok(&fake);
    fake.on(path_is("/api/v2.0/projects"), ok(r#"[{"name":"alpha"}]"#));
    let page = state(fake)
        .harbor_projects(&fx.caller(), &fx.harbor, &ListQuery::default())
        .await
        .unwrap();
    seen.push(serde_json::to_string(&page).unwrap());
    assert!(seen.len() > 20);
    for text in &seen {
        assert!(!text.contains(SENTINEL), "the sentinel leaked: {text}");
        assert!(
            !text.contains("upstream detail"),
            "an upstream body leaked: {text}"
        );
        assert!(!text.contains("harbor.example.com"), "a URL leaked: {text}");
    }
    fx.close().await;
}
