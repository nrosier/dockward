//! The GitHub API base URL and web URL, an instance setting set by the admin
//! (`specs/integrations.md`, "GitHub base URL"; `specs/security.md`, "GitHub base URL").
//!
//! An empty value means the default: `https://api.github.com` for the API and
//! `https://github.com` for the web URL. The API base may carry a path, such as `/api/v3` for
//! GitHub Enterprise Server. It is used only as a prefix for every GitHub REST path.
//!
//! [`GithubTarget`] is the shared, live copy of the setting. Every GitHub client holds a clone,
//! so an admin change applies to the next request without a restart. Every request URL is built
//! by [`GithubUrls::api_url`] and checked by [`GithubUrls::is_api_url`], so a request never
//! goes to a host other than the configured one.

use std::sync::{Arc, RwLock};

use reqwest::Url;
use sqlx::SqlitePool;

use crate::db;
use crate::error::AppError;

/// `system_config` key of the custom API base URL.
pub const API_KEY: &str = "github.api_base_url";
/// `system_config` key of the custom web URL.
pub const WEB_KEY: &str = "github.web_url";
/// The API base URL used when the setting is empty.
pub const DEFAULT_API: &str = "https://api.github.com";
/// The web URL used when the setting is empty.
pub const DEFAULT_WEB: &str = "https://github.com";
/// The fixed validation message (catalog key `settings.github_url_invalid`).
pub const INVALID_MESSAGE: &str = "settings.github_url_invalid";

fn invalid() -> AppError {
    AppError::ValidationFailed(INVALID_MESSAGE.to_owned())
}

/// Splits `https://<authority><path>` and checks the authority. Returns the lowercase host and
/// the raw path (empty or starting with `/`). Query, fragment, userinfo, port, backslash,
/// whitespace and control characters are refused here, on the raw text, because the URL parser
/// would otherwise normalise them away.
fn split_https(raw: &str) -> Result<(String, &str), AppError> {
    let prefix = "https://";
    if raw.len() <= prefix.len() || !raw[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return Err(invalid());
    }
    let rest = &raw[prefix.len()..];
    if rest
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '?' | '#' | '\\'))
    {
        return Err(invalid());
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains(['@', ':', '%']) {
        return Err(invalid());
    }
    let parsed = Url::parse(&format!("https://{authority}")).map_err(|_| invalid())?;
    let host = authority.to_ascii_lowercase();
    if parsed.host_str() != Some(host.as_str())
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
    {
        return Err(invalid());
    }
    Ok((host, path))
}

/// Validates an API base URL and returns the value to store: `""` for empty, otherwise
/// `https://<host><path>` with no trailing slash.
pub fn validate_api_base(raw: &str) -> Result<String, AppError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(String::new());
    }
    let (host, path) = split_https(raw)?;
    let lowered = path.to_ascii_lowercase();
    if path.contains("//")
        || lowered.contains("..")
        || lowered.contains("%2f")
        || lowered.contains("%5c")
        || lowered.contains("%2e")
    {
        return Err(invalid());
    }
    let path = path.trim_end_matches('/');
    if !path.is_empty() {
        // The parser must keep the path as entered: no dot segment, no re-encoding.
        let parsed = Url::parse(&format!("https://{host}{path}")).map_err(|_| invalid())?;
        if parsed.path() != path {
            return Err(invalid());
        }
    }
    Ok(format!("https://{host}{path}"))
}

/// Validates a web URL and returns the value to store: `""` for empty, otherwise
/// `https://<host>`. A path other than a single `/` is refused.
pub fn validate_web(raw: &str) -> Result<String, AppError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(String::new());
    }
    let (host, path) = split_https(raw)?;
    if !(path.is_empty() || path == "/") {
        return Err(invalid());
    }
    Ok(format!("https://{host}"))
}

/// The resolved URLs: the stored values with the defaults filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubUrls {
    /// The API base with no trailing slash, such as `https://ghes.example.com/api/v3`.
    api_base: String,
    api_host: String,
    /// The path prefix of the API base: empty, or starting with `/` and with no trailing slash.
    api_path: String,
    web_url: String,
    web_host: String,
}

impl Default for GithubUrls {
    fn default() -> Self {
        Self {
            api_base: DEFAULT_API.to_owned(),
            api_host: "api.github.com".to_owned(),
            api_path: String::new(),
            web_url: DEFAULT_WEB.to_owned(),
            web_host: "github.com".to_owned(),
        }
    }
}

impl GithubUrls {
    /// Builds the URLs from the stored values. Empty means the default. A stored value that
    /// no longer validates is an error, so a damaged row can never send a token elsewhere.
    pub fn from_stored(api: &str, web: &str) -> Result<Self, AppError> {
        let mut urls = Self::default();
        let api = validate_api_base(api)?;
        if !api.is_empty() {
            let (host, path) = split_https(&api)?;
            urls.api_path = path.to_owned();
            urls.api_host = host;
            urls.api_base = api;
        }
        let web = validate_web(web)?;
        if !web.is_empty() {
            let (host, _) = split_https(&web)?;
            urls.web_host = host;
            urls.web_url = web;
        }
        Ok(urls)
    }

    /// The API base URL, with no trailing slash.
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// The admin-set API host, or `None` when the default is in use. Only this host is exempt
    /// from the private-range check (`specs/security.md`, "GitHub base URL"); the default
    /// `api.github.com` keeps the check.
    pub fn trusted_host(&self) -> Option<&str> {
        (self.api_base != DEFAULT_API).then_some(self.api_host.as_str())
    }

    /// The web URL, with no trailing slash.
    pub fn web_url(&self) -> &str {
        &self.web_url
    }

    /// The web host, lowercase.
    pub fn web_host(&self) -> &str {
        &self.web_host
    }

    /// The URL of a GitHub REST path. `path` is relative to the API base and may carry a query,
    /// such as `repos/octo/app/issues?per_page=1`. `None` when the path would leave the API
    /// base: a leading slash, an empty segment, a backslash, or a result that is not under the
    /// base path on the configured host.
    pub fn api_url(&self, path: &str) -> Option<Url> {
        let route = path.split_once('?').map_or(path, |(route, _)| route);
        let lowered = route.to_ascii_lowercase();
        if route.starts_with('/')
            || route.contains("//")
            || route.contains('\\')
            || route
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
            || lowered.contains("%2f")
            || lowered.contains("%5c")
            || lowered.contains("%2e")
        {
            return None;
        }
        let url = Url::parse(&format!("{}/{}", self.api_base, path)).ok()?;
        self.is_api_url(&url).then_some(url)
    }

    /// True when `url` is `https` on the configured API host, with no userinfo and no port, and
    /// its path is under the base path. The token is sent only to such a URL.
    pub fn is_api_url(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.host_str() == Some(self.api_host.as_str())
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.path().starts_with(&format!("{}/", self.api_path))
    }

    /// The path (with query) of a `Link` header URL, relative to the API base. The link must
    /// pass [`Self::is_api_url`] and its path must have no empty segment. Anything else is
    /// `None` and is never fetched.
    pub fn relative_path(&self, link: &str) -> Option<String> {
        let url = Url::parse(link).ok()?;
        if !self.is_api_url(&url) {
            return None;
        }
        let full = url.path();
        if full.contains("//") || full.contains("://") {
            return None;
        }
        let path = full.strip_prefix(&self.api_path)?.strip_prefix('/')?;
        if path.is_empty() {
            return None;
        }
        Some(match url.query() {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        })
    }
}

/// The shared, live GitHub URLs. Clones share one value, so [`GithubTarget::set`] reaches every
/// client that holds a clone.
#[derive(Debug, Clone, Default)]
pub struct GithubTarget(Arc<RwLock<Arc<GithubUrls>>>);

impl GithubTarget {
    /// A target holding `urls`.
    pub fn new(urls: GithubUrls) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(urls))))
    }

    /// The current URLs. A request reads this once, so it uses one consistent pair.
    pub fn current(&self) -> Arc<GithubUrls> {
        Arc::clone(&self.0.read().unwrap_or_else(|poison| poison.into_inner()))
    }

    /// Replaces the URLs for every holder of this target.
    pub fn set(&self, urls: GithubUrls) {
        *self.0.write().unwrap_or_else(|poison| poison.into_inner()) = Arc::new(urls);
    }
}

/// The stored values as entered, `""` when missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUrls {
    pub api_base_url: String,
    pub web_url: String,
}

/// Reads the stored values.
pub async fn load_stored(pool: &SqlitePool) -> Result<StoredUrls, AppError> {
    Ok(StoredUrls {
        api_base_url: db::config::get(pool, API_KEY).await?.unwrap_or_default(),
        web_url: db::config::get(pool, WEB_KEY).await?.unwrap_or_default(),
    })
}

/// Reads the stored values and resolves them. Used at startup.
pub async fn load_target(pool: &SqlitePool) -> Result<GithubTarget, AppError> {
    let stored = load_stored(pool).await?;
    Ok(GithubTarget::new(GithubUrls::from_stored(
        &stored.api_base_url,
        &stored.web_url,
    )?))
}

/// Validates both values and writes them in one transaction. No audit row is written: the
/// `github.url_change` action is not in the vocabulary yet (`specs/api.md`). Returns the stored
/// values and the resolved URLs.
pub async fn save(
    pool: &SqlitePool,
    api_base_url: &str,
    web_url: &str,
) -> Result<(StoredUrls, GithubUrls), AppError> {
    let api = validate_api_base(api_base_url)?;
    let web = validate_web(web_url)?;
    let urls = GithubUrls::from_stored(&api, &web)?;
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    db::config::upsert(&mut tx, API_KEY, &api, false).await?;
    db::config::upsert(&mut tx, WEB_KEY, &web, false).await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok((
        StoredUrls {
            api_base_url: api,
            web_url: web,
        },
        urls,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        match Url::parse(text) {
            Ok(url) => url,
            Err(err) => panic!("test URL {text} rejected: {err}"),
        }
    }

    #[test]
    fn empty_means_the_default_urls() {
        let urls = GithubUrls::from_stored("", "").unwrap();
        assert_eq!(urls, GithubUrls::default());
        assert_eq!(urls.api_base(), "https://api.github.com");
        assert_eq!(urls.web_url(), "https://github.com");
        assert_eq!(
            urls.api_url("repos/octo/app").map(String::from),
            Some("https://api.github.com/repos/octo/app".to_owned())
        );
        assert_eq!(validate_api_base("  ").unwrap(), "");
        assert_eq!(validate_web("").unwrap(), "");
    }

    #[test]
    fn a_path_is_a_prefix_for_every_request() {
        let urls = GithubUrls::from_stored("https://GHES.example.com/api/v3/", "").unwrap();
        assert_eq!(urls.api_base(), "https://ghes.example.com/api/v3");
        let repo = urls.api_url("repos/octo/app").unwrap();
        assert_eq!(repo.host_str(), Some("ghes.example.com"));
        assert_eq!(repo.path(), "/api/v3/repos/octo/app");
        let list = urls.api_url("user/repos?per_page=1").unwrap();
        assert_eq!(list.path(), "/api/v3/user/repos");
        assert_eq!(list.query(), Some("per_page=1"));
        // GHE.com has no path.
        let cloud = GithubUrls::from_stored("https://api.acme.ghe.com", "").unwrap();
        assert_eq!(
            cloud.api_url("repos/o/r").map(String::from),
            Some("https://api.acme.ghe.com/repos/o/r".to_owned())
        );
    }

    #[test]
    fn invalid_api_base_values_are_refused() {
        for bad in [
            "http://ghes.example.com",
            "ghes.example.com",
            "ftp://ghes.example.com",
            "https://",
            "https://user:pw@ghes.example.com/api/v3",
            "https://user@ghes.example.com",
            "https://@ghes.example.com",
            "https://ghes.example.com:8443/api/v3",
            "https://ghes.example.com:443",
            "https://ghes.example.com/api/v3?x=1",
            "https://ghes.example.com/api/v3#frag",
            "https://ghes.example.com/api/../v3",
            "https://ghes.example.com/api/v3/..",
            "https://ghes.example.com//api",
            "https://ghes.example.com/api//v3",
            "https://ghes.example.com/api%2Fv3",
            "https://ghes.example.com/api%2fv3",
            "https://ghes.example.com/api%5Cv3",
            "https://ghes.example.com/%2e%2e/v3",
            "https://ghes.example.com/api\\v3",
            "https://ghes.example.com/a b",
            "https://ghes.example.com\\@evil.example",
        ] {
            assert_eq!(
                validate_api_base(bad),
                Err(AppError::ValidationFailed(INVALID_MESSAGE.to_owned())),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn web_url_is_host_only() {
        assert_eq!(
            validate_web("https://GHES.example.com/").unwrap(),
            "https://ghes.example.com"
        );
        for bad in [
            "https://ghes.example.com/api/v3",
            "https://ghes.example.com/x",
            "http://ghes.example.com",
            "https://ghes.example.com:8443",
            "https://u:p@ghes.example.com",
            "https://ghes.example.com?x=1",
            "https://ghes.example.com#f",
        ] {
            assert_eq!(
                validate_web(bad),
                Err(AppError::ValidationFailed(INVALID_MESSAGE.to_owned())),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn api_url_never_leaves_the_configured_host_or_prefix() {
        for urls in [
            GithubUrls::default(),
            GithubUrls::from_stored("https://ghes.example.com/api/v3", "").unwrap(),
        ] {
            for path in [
                "//evil.example/x",
                "///evil.example/x",
                "/repos/x",
                "https://evil.example/x",
                "http://api.github.com/x",
                "https://api.github.com@evil.example/x",
                "https://api.github.com:8443/x",
                "../x",
                "repos/../../x",
                "repos\\x",
                "repos/%2e%2e/x",
                "repos/a%2Fb",
                "./x",
            ] {
                assert_eq!(urls.api_url(path), None, "{path} should be refused");
            }
        }
    }

    #[test]
    fn only_the_configured_host_gets_the_token() {
        let ok = url("https://api.github.com/user/repos?page=2");
        let urls = GithubUrls::default();
        assert!(urls.is_api_url(&ok));
        for bad in [
            "http://api.github.com/user/repos",
            "https://evil.example.com/user/repos",
            "https://user:pw@api.github.com/user/repos",
            "https://api.github.com:8443/user/repos",
            "https://api.github.com.evil.example/user/repos",
        ] {
            assert!(!urls.is_api_url(&url(bad)), "{bad}");
        }
        let ghes = GithubUrls::from_stored("https://ghes.example.com/api/v3", "").unwrap();
        assert!(ghes.is_api_url(&url("https://ghes.example.com/api/v3/user/repos")));
        assert!(!ghes.is_api_url(&url("https://ghes.example.com/other/user/repos")));
        assert!(!ghes.is_api_url(&url("https://ghes.example.com/api/v3x/user/repos")));
        assert!(!ghes.is_api_url(&url("https://api.github.com/api/v3/user/repos")));
    }

    #[test]
    fn relative_path_strips_the_base_path() {
        let ghes = GithubUrls::from_stored("https://ghes.example.com/api/v3", "").unwrap();
        assert_eq!(
            ghes.relative_path("https://ghes.example.com/api/v3/repositories/42/issues?page=2"),
            Some("repositories/42/issues?page=2".to_owned())
        );
        assert_eq!(
            ghes.relative_path("https://ghes.example.com/repositories/42/issues"),
            None
        );
        assert_eq!(ghes.relative_path("https://ghes.example.com/api/v3/"), None);
    }

    #[test]
    fn target_changes_reach_every_clone() {
        let target = GithubTarget::default();
        let held = target.clone();
        target.set(GithubUrls::from_stored("https://ghes.example.com/api/v3", "").unwrap());
        assert_eq!(held.current().api_base(), "https://ghes.example.com/api/v3");
    }
}
