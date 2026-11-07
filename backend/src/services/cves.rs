//! CVE read APIs (`specs/api.md`, CVEs; `specs/cve-lifecycle.md`, "Tracking per tag").
//!
//! One [`CveSummary`] per (mapping, CVE), aggregated across the tags the mapping tracks.
//! [`CveDetail`] adds the tags that report the CVE, the active acceptance and the
//! description.
//!
//! Tenancy: a user reads only their own mappings. Another tenant's mapping or CVE is `404`,
//! the same answer as an unknown one. An admin may read every tenant's CVEs. The owner check
//! runs before any other parameter is validated, and every parameter is validated before the
//! list query runs.
//!
//! The CVE id, package, fixed-in version and description come from Harbor and are untrusted.
//! They are returned as JSON string values only; nothing here builds markup or logs them.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::acceptances as acceptance_db;
use crate::db::findings::{self as db, CveListFilter, CveSummaryRow, CveTagRow};
use crate::error::AppError;
use crate::services::acceptance::Acceptance;
use crate::services::pagination::{Page, Pagination};
use crate::services::time;

/// Sort keys of both list routes. The first one is the default (`specs/api.md`, CVEs).
pub const SORTS: &[&str] = &["severity", "cve_id", "first_seen_at", "last_seen_at"];

/// The longest mapping id or CVE id in the route id, in bytes. Same as the issue and accept
/// routes.
const MAX_ID_BYTES: usize = 128;

/// The longest `q` search text, in characters.
pub const MAX_Q_CHARS: usize = 100;

/// The longest `package`, `tag`, `harbor_project` or `harbor_repository` filter, in
/// characters (`specs/api.md`, CVEs, list filters).
pub const MAX_FILTER_CHARS: usize = 256;

/// Every severity, highest first. The `severity` filter takes any of them.
pub const SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/// The values of the `status` filter. `accepted` matches an active acceptance.
const STATUSES: &[&str] = &["open", "fixed", "accepted"];

/// The caller of a read: who they are and whether they may read every tenant's data.
pub struct Reader<'a> {
    pub user_id: &'a str,
    pub is_admin: bool,
}

impl Reader<'_> {
    /// The owner the mapping check uses: `None` for an admin, who may read every mapping.
    fn owner_scope(&self) -> Option<&str> {
        if self.is_admin {
            None
        } else {
            Some(self.user_id)
        }
    }
}

/// Raw query values of both list routes, as strings, so nothing is rejected before the
/// mapping check. Every one is validated in [`list`]. `mapping_id` and `scope` are read by
/// `GET /cves` only.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ListParams {
    pub page: Option<String>,
    pub page_size: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub accepted: Option<String>,
    pub q: Option<String>,
    pub package: Option<String>,
    pub tag: Option<String>,
    pub harbor_project: Option<String>,
    pub harbor_repository: Option<String>,
    pub mapping_id: Option<String>,
    pub scope: Option<String>,
}

/// One CVE of one mapping (`specs/api.md`, CVEs, `CveSummary`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CveSummary {
    /// `<mapping_id>:<cve_id>`, the id of `GET /cves/:id` and the POST routes.
    pub id: String,
    pub mapping_id: String,
    pub cve_id: String,
    /// The highest severity across the tags.
    pub severity: String,
    /// The highest severity across the open tag rows, or `null` when every tag is fixed.
    /// A manual issue uses it; the UI asks for confirmation when it is `LOW` or `UNKNOWN`.
    pub open_severity: Option<String>,
    /// `open` when any tag's row is open, else `fixed`.
    pub status: String,
    pub package: Option<String>,
    pub first_seen_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub github_issue_url: Option<String>,
    /// True while an active acceptance exists.
    pub accepted: bool,
    pub fixed_in_version: Option<String>,
    pub open_tags: i64,
    pub tracked_tags: i64,
    pub github_issue_number: Option<i64>,
    /// `open`, `closed`, or `null` when the CVE has no issue.
    pub github_issue_status: Option<String>,
}

impl CveSummary {
    fn from_row(row: CveSummaryRow) -> Result<Self, AppError> {
        Ok(Self {
            id: format!("{}:{}", row.mapping_id, row.cve_id),
            mapping_id: row.mapping_id,
            cve_id: row.cve_id,
            severity: row.severity,
            open_severity: row.open_severity,
            status: row.status,
            package: row.package,
            first_seen_at: row.first_seen_at.map(time::rfc3339).transpose()?,
            last_seen_at: row.last_seen_at.map(time::rfc3339).transpose()?,
            github_issue_url: row.github_issue_url,
            accepted: row.accepted,
            fixed_in_version: row.fixed_in_version,
            open_tags: row.open_tags,
            tracked_tags: row.tracked_tags,
            github_issue_number: row.github_issue_number,
            github_issue_status: row.github_issue_status,
        })
    }
}

/// One tag that reports the CVE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CveTag {
    pub image_tag: String,
    pub status: String,
    /// The tag's latest successful sync, or `null` when it has none.
    pub last_scan_at: Option<String>,
    pub fixed_in_version: Option<String>,
}

/// `GET /cves/:id` (`specs/api.md`, CVEs, `CveDetail`).
#[derive(Debug, Serialize)]
pub struct CveDetail {
    #[serde(flatten)]
    pub summary: CveSummary,
    /// At most 10, most recently scanned first.
    pub tags: Vec<CveTag>,
    pub acceptance: Option<Acceptance>,
    /// The Harbor description from the most recently scanned tag's row, or `null`.
    pub description: Option<String>,
}

fn valid_cve_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

/// True for an id the mapping routes can hold: 1 to 128 bytes of ASCII letters, digits,
/// `.`, `_` and `-`.
fn valid_mapping_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Splits the route id `<mapping_id>:<cve_id>` with the rules of the issue and accept routes.
/// Any other shape, an empty part, a part over 128 bytes, or a character outside the allowed
/// set is `404`, before any database call.
fn split_id(id: &str) -> Result<(&str, &str), AppError> {
    match id.split_once(':') {
        Some((mapping_id, cve_id)) if valid_mapping_id(mapping_id) && valid_cve_id(cve_id) => {
            Ok((mapping_id, cve_id))
        }
        _ => Err(AppError::NotFound),
    }
}

/// `404` unless the mapping exists and the reader may read it. A malformed id is `404` too,
/// with no database call.
async fn check_mapping(
    pool: &SqlitePool,
    reader: &Reader<'_>,
    mapping_id: &str,
) -> Result<(), AppError> {
    if !valid_mapping_id(mapping_id) {
        return Err(AppError::NotFound);
    }
    if db::mapping_readable(pool, mapping_id, reader.owner_scope()).await? {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// The filters of a list, validated. Each failure is `400 invalid_request` with fixed text.
struct Filters {
    severities: Vec<&'static str>,
    statuses: Vec<&'static str>,
    accepted: Option<i64>,
    q: Option<String>,
    package: Option<String>,
    tag: Option<String>,
    harbor_project: Option<String>,
    harbor_repository: Option<String>,
}

/// A comma-separated list of known values, each kept once in the order of `known`. An
/// absent parameter is an empty list (no filter). An empty or unknown item is `400` with
/// `message`.
fn parse_list(
    value: Option<&str>,
    known: &'static [&'static str],
    message: &str,
) -> Result<Vec<&'static str>, AppError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let mut picked = vec![false; known.len()];
    for item in value.split(',') {
        let index = known
            .iter()
            .position(|candidate| *candidate == item)
            .ok_or_else(|| AppError::InvalidRequest(message.to_owned()))?;
        picked[index] = true;
    }
    Ok(known
        .iter()
        .zip(picked)
        .filter_map(|(value, on)| on.then_some(*value))
        .collect())
}

/// An exact-match text filter. Empty means no filter. Over [`MAX_FILTER_CHARS`] characters,
/// or a control character, is `400`.
fn parse_text(value: Option<&str>, name: &str) -> Result<Option<String>, AppError> {
    match value {
        None | Some("") => Ok(None),
        Some(text) if text.chars().count() > MAX_FILTER_CHARS => Err(AppError::InvalidRequest(
            format!("{name} can have at most {MAX_FILTER_CHARS} characters."),
        )),
        Some(text) if text.chars().any(char::is_control) => Err(AppError::InvalidRequest(format!(
            "{name} must not contain control characters."
        ))),
        Some(text) => Ok(Some(text.to_owned())),
    }
}

fn parse_filters(params: &ListParams) -> Result<Filters, AppError> {
    let severities = parse_list(
        params.severity.as_deref(),
        SEVERITIES,
        "severity must be a comma-separated list of CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN.",
    )?;
    let statuses = parse_list(
        params.status.as_deref(),
        STATUSES,
        "status must be a comma-separated list of open, fixed or accepted.",
    )?;
    let accepted = match params.accepted.as_deref() {
        None => None,
        Some("true") => Some(1),
        Some("false") => Some(0),
        Some(_) => {
            return Err(AppError::InvalidRequest(
                "accepted must be true or false.".to_owned(),
            ));
        }
    };
    let q = match params.q.as_deref() {
        None | Some("") => None,
        Some(text) if text.chars().count() > MAX_Q_CHARS => {
            return Err(AppError::InvalidRequest(format!(
                "q can have at most {MAX_Q_CHARS} characters."
            )));
        }
        Some(text) if text.chars().any(char::is_control) => {
            return Err(AppError::InvalidRequest(
                "q must not contain control characters.".to_owned(),
            ));
        }
        // SQLite's `lower()` folds ASCII only, so the search text is folded the same way.
        Some(text) => Some(text.to_ascii_lowercase()),
    };
    Ok(Filters {
        severities,
        statuses,
        accepted,
        q,
        package: parse_text(params.package.as_deref(), "package")?,
        tag: parse_text(params.tag.as_deref(), "tag")?,
        harbor_project: parse_text(params.harbor_project.as_deref(), "harbor_project")?,
        harbor_repository: parse_text(params.harbor_repository.as_deref(), "harbor_repository")?,
    })
}

/// `page` or `page_size` as a number. Anything else is `400`.
fn parse_number(value: Option<&str>, message: &str) -> Result<Option<i64>, AppError> {
    match value {
        None => Ok(None),
        Some(text) => text
            .parse::<i64>()
            .map(Some)
            .map_err(|_| AppError::InvalidRequest(message.to_owned())),
    }
}

/// One page of CVE summaries.
///
/// `path_mapping` is the `:id` of `GET /mappings/:id/cves`, and `None` for `GET /cves`.
/// `params` is the parsed query string, or the error for one that could not be parsed.
///
/// Order: the mapping check runs first (the path mapping, then the `mapping_id` filter), so
/// another tenant's mapping is `404` whatever else the request says. Then `scope=all` from a
/// non-admin is `403`. Then every parameter is validated: `400` for a bad one, including
/// `page_size` over 200 and an unknown `sort`. Only then does the list query run.
pub async fn list(
    pool: &SqlitePool,
    reader: &Reader<'_>,
    path_mapping: Option<&str>,
    params: Result<ListParams, AppError>,
    now: i64,
) -> Result<Page<CveSummary>, AppError> {
    if let Some(mapping_id) = path_mapping {
        check_mapping(pool, reader, mapping_id).await?;
    }
    let params = params?;
    let mapping_id = match path_mapping {
        Some(mapping_id) => Some(mapping_id),
        None => match params.mapping_id.as_deref() {
            Some(mapping_id) => {
                check_mapping(pool, reader, mapping_id).await?;
                Some(mapping_id)
            }
            None => None,
        },
    };
    let all_users = match (path_mapping, params.scope.as_deref()) {
        (Some(_), _) | (None, None) => false,
        (None, Some("all")) if reader.is_admin => true,
        (None, Some("all")) => return Err(AppError::Forbidden),
        (None, Some(_)) => return Err(AppError::InvalidRequest("scope must be all.".to_owned())),
    };
    let paging = Pagination::parse(
        parse_number(params.page.as_deref(), "page must be a whole number.")?,
        parse_number(
            params.page_size.as_deref(),
            "page_size must be a whole number.",
        )?,
        params.sort.as_deref(),
        params.order.as_deref(),
        SORTS,
    )?;
    let filters = parse_filters(&params)?;
    // A checked mapping needs no owner filter: an admin may read it, and a user owns it.
    let user_id = if mapping_id.is_some() || all_users {
        None
    } else {
        Some(reader.user_id)
    };
    let filter = CveListFilter {
        user_id,
        mapping_id,
        cve_id: None,
        severities: &filters.severities,
        statuses: &filters.statuses,
        accepted: filters.accepted,
        q: filters.q.as_deref(),
        package: filters.package.as_deref(),
        tag: filters.tag.as_deref(),
        harbor_project: filters.harbor_project.as_deref(),
        harbor_repository: filters.harbor_repository.as_deref(),
        sort: &paging.sort,
        sort_sign: if paging.ascending { 1 } else { -1 },
        limit: paging.page_size,
        offset: paging.offset(),
        now,
    };
    let rows = db::list_cves(pool, &filter).await?;
    let total = db::count_cves(pool, &filter).await?;
    let items = rows
        .into_iter()
        .map(CveSummary::from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

fn to_tag(row: &CveTagRow) -> Result<CveTag, AppError> {
    Ok(CveTag {
        image_tag: row.image_tag.clone(),
        status: row.status.clone(),
        last_scan_at: row.last_scan_at.map(time::rfc3339).transpose()?,
        fixed_in_version: row.fixed_in_version.clone(),
    })
}

/// One tag of `GET /mappings/:id/tags`. Names and counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MappingTag {
    pub image_tag: String,
    pub last_scan_at: String,
    pub open_cves: i64,
}

/// `GET /mappings/:id/tags`: the CVE view's tag set of the mapping, most recently scanned
/// first, at most 10. Another tenant's mapping and an unknown one are both `404`.
pub async fn mapping_tags(
    pool: &SqlitePool,
    reader: &Reader<'_>,
    mapping_id: &str,
) -> Result<Vec<MappingTag>, AppError> {
    check_mapping(pool, reader, mapping_id).await?;
    db::tracked_tags(pool, mapping_id)
        .await?
        .into_iter()
        .map(|row| {
            Ok(MappingTag {
                image_tag: row.image_tag,
                last_scan_at: time::rfc3339(row.last_scan_at)?,
                open_cves: row.open_cves,
            })
        })
        .collect()
}

/// `GET /cves/:id`. `id` is `<mapping_id>:<cve_id>`. A malformed id, another tenant's
/// mapping, and a CVE the mapping has no row for are all `404`.
pub async fn detail(
    pool: &SqlitePool,
    reader: &Reader<'_>,
    id: &str,
    now: i64,
) -> Result<CveDetail, AppError> {
    let (mapping_id, cve_id) = split_id(id)?;
    check_mapping(pool, reader, mapping_id).await?;
    let filter = CveListFilter {
        user_id: None,
        mapping_id: Some(mapping_id),
        cve_id: Some(cve_id),
        severities: &[],
        statuses: &[],
        accepted: None,
        q: None,
        package: None,
        tag: None,
        harbor_project: None,
        harbor_repository: None,
        sort: "cve_id",
        sort_sign: 1,
        limit: 1,
        offset: 0,
        now,
    };
    let row = db::list_cves(pool, &filter)
        .await?
        .into_iter()
        .next()
        .ok_or(AppError::NotFound)?;
    let summary = CveSummary::from_row(row)?;
    let tag_rows = db::cve_tags(pool, mapping_id, cve_id).await?;
    let description = tag_rows.first().and_then(|row| row.description.clone());
    let tags = tag_rows.iter().map(to_tag).collect::<Result<Vec<_>, _>>()?;
    let acceptance = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        acceptance_db::active(&mut conn, mapping_id, cve_id, now).await?
    };
    let acceptance = match acceptance {
        None => None,
        Some(row) => Some(Acceptance {
            id: row.id,
            mapping_id: row.mapping_id,
            cve_id: row.cve_id,
            reason: row.reason,
            created_by: row.created_by_username,
            created_at: row.created_at.map(time::rfc3339).transpose()?,
            expires_at: row.expires_at.map(time::rfc3339).transpose()?,
        }),
    };
    Ok(CveDetail {
        summary,
        tags,
        acceptance,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_id_follows_the_route_rules() {
        assert_eq!(
            split_id("m1:CVE-2026-0001").unwrap(),
            ("m1", "CVE-2026-0001")
        );
        assert_eq!(
            split_id("m1:RHSA-2023:1234").unwrap(),
            ("m1", "RHSA-2023:1234")
        );
        let long = format!("m1:{}", "A".repeat(129));
        for id in [
            "",
            "no-colon",
            ":CVE-1",
            "m1:",
            "m 1:CVE-1",
            "m1:CVE-1\n-->",
            "m1:CVE-1 -->",
            long.as_str(),
        ] {
            assert_eq!(split_id(id).unwrap_err(), AppError::NotFound, "id {id:?}");
        }
    }

    #[test]
    fn filters_reject_unknown_values() {
        let long = "x".repeat(MAX_FILTER_CHARS + 1);
        let bad = [
            ListParams {
                severity: Some("critical".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                severity: Some("HIGH,".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                severity: Some("".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                severity: Some("HIGH, LOW".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                status: Some("closed".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                status: Some("open,,fixed".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                accepted: Some("1".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                q: Some("x".repeat(MAX_Q_CHARS + 1)),
                ..ListParams::default()
            },
            ListParams {
                q: Some("CVE\u{0}".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                package: Some(long.clone()),
                ..ListParams::default()
            },
            ListParams {
                tag: Some("v1\n".to_owned()),
                ..ListParams::default()
            },
            ListParams {
                harbor_project: Some(long.clone()),
                ..ListParams::default()
            },
            ListParams {
                harbor_repository: Some("a\u{7}".to_owned()),
                ..ListParams::default()
            },
        ];
        for params in &bad {
            assert!(
                matches!(parse_filters(params), Err(AppError::InvalidRequest(_))),
                "{params:?}"
            );
        }
        let good = parse_filters(&ListParams {
            severity: Some("HIGH".to_owned()),
            status: Some("open".to_owned()),
            accepted: Some("false".to_owned()),
            q: Some("OpenSSL".to_owned()),
            package: Some("OpenSSL".to_owned()),
            tag: Some("v1.2".to_owned()),
            harbor_project: Some("proj".to_owned()),
            harbor_repository: Some("team/app".to_owned()),
            ..ListParams::default()
        })
        .unwrap();
        assert_eq!(good.severities, ["HIGH"]);
        assert_eq!(good.statuses, ["open"]);
        assert_eq!(good.accepted, Some(0));
        assert_eq!(good.q.as_deref(), Some("openssl"));
        assert_eq!(
            good.package.as_deref(),
            Some("OpenSSL"),
            "exact, not folded"
        );
        assert_eq!(good.tag.as_deref(), Some("v1.2"));
        assert_eq!(good.harbor_project.as_deref(), Some("proj"));
        assert_eq!(good.harbor_repository.as_deref(), Some("team/app"));
    }

    #[test]
    fn multi_value_filters_are_deduplicated_and_ordered() {
        let parsed = parse_filters(&ListParams {
            severity: Some("UNKNOWN,LOW,UNKNOWN,CRITICAL".to_owned()),
            status: Some("accepted,fixed,accepted".to_owned()),
            ..ListParams::default()
        })
        .unwrap();
        assert_eq!(parsed.severities, ["CRITICAL", "LOW", "UNKNOWN"]);
        assert_eq!(parsed.statuses, ["fixed", "accepted"]);
        // No parameter and an empty text filter mean no filter at all.
        let none = parse_filters(&ListParams {
            package: Some(String::new()),
            ..ListParams::default()
        })
        .unwrap();
        assert!(none.severities.is_empty() && none.statuses.is_empty());
        assert!(none.package.is_none());
        let every = parse_filters(&ListParams {
            severity: Some(SEVERITIES.join(",")),
            ..ListParams::default()
        })
        .unwrap();
        assert_eq!(every.severities, SEVERITIES);
    }
}
