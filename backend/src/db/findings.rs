//! SQL for the `cve_findings` table (`specs/database.md`, `specs/cve-lifecycle.md`,
//! "Tracking per tag"). One row per (source, image tag, CVE).
//! Rows hold CVE facts only, never secrets.
//!
//! Every function takes a connection so the caller can run them in one transaction.
//! None of them touches `github_issues`.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// One vulnerability of one tag, ready to store.
pub struct Finding<'a> {
    /// Primary key used when the row is new; an existing row keeps its own.
    pub id: &'a str,
    pub source_id: &'a str,
    pub image_tag: &'a str,
    pub cve_id: &'a str,
    pub package: Option<&'a str>,
    /// One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
    pub severity: &'a str,
    pub fixed_in_version: Option<&'a str>,
    /// At most 4,000 characters; `None` when the report has no text.
    pub description: Option<&'a str>,
    /// The other id of the CVE, such as its GHSA id (#337); `None` when there is none.
    pub alias: Option<&'a str>,
    /// Unix seconds of the scan.
    pub now: i64,
}

/// Stores a finding. A new row is `open`. An existing row for the same tag and CVE takes
/// the new facts, moves `last_seen_at` forward and goes back to `open` (a CVE that returns
/// on a tag reopens its row). `first_seen_at` is kept.
pub async fn upsert(conn: &mut SqliteConnection, finding: &Finding<'_>) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO cve_findings
            (id, source_id, image_tag, cve_id, package, severity,
             fixed_in_version, description, alias, first_seen_at, last_seen_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
         ON CONFLICT (source_id, image_tag, cve_id) DO UPDATE SET
            severity = excluded.severity,
            package = excluded.package,
            fixed_in_version = excluded.fixed_in_version,
            description = excluded.description,
            alias = excluded.alias,
            last_seen_at = excluded.last_seen_at,
            status = 'open'",
        finding.id,
        finding.source_id,
        finding.image_tag,
        finding.cve_id,
        finding.package,
        finding.severity,
        finding.fixed_in_version,
        finding.description,
        finding.alias,
        finding.now,
        finding.now
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// The primary id of `id` (#337): the CVE id recorded for a GHSA alias in
/// `vulnerability_aliases`, or `id` itself when it is not an alias.
pub async fn primary_id(conn: &mut SqliteConnection, id: &str) -> Result<String, AppError> {
    let found = sqlx::query_scalar!(
        "SELECT primary_id FROM vulnerability_aliases WHERE alias = ?",
        id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(found.unwrap_or_else(|| id.to_owned()))
}

/// Every alias recorded for the primary id (#337), in id order.
pub async fn aliases_of(pool: &SqlitePool, primary: &str) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT alias AS "alias!" FROM vulnerability_aliases WHERE primary_id = ? ORDER BY alias"#,
        primary
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// One tag of the CVE view's tag set, as `GET /mappings/:id/tags` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedTagRow {
    pub image_tag: String,
    /// The tag's latest `done` scan, Unix seconds.
    pub last_scan_at: i64,
    /// The tag's `cve_findings` rows that are `open`.
    pub open_cves: i64,
}

/// The mapping's tag set in the CVE view: the tags with a `done` scan run,
/// most recently scanned first, at most 10. This is the `tag_scans` and `tracked` rule of
/// [`list_cves`] (`tracked_tags` is the length of this list) with the order of
/// [`tags_by_recency`].
pub async fn tracked_tags(
    pool: &SqlitePool,
    source_id: &str,
) -> Result<Vec<TrackedTagRow>, AppError> {
    sqlx::query_as!(
        TrackedTagRow,
        r#"SELECT ts.image_tag AS "image_tag!: String", ts.scan_at AS "last_scan_at!: i64",
                  (SELECT COUNT(*) FROM cve_findings f
                   WHERE f.source_id = ts.source_id AND f.image_tag = ts.image_tag
                     AND f.status = 'open') AS "open_cves!: i64"
           FROM (
               SELECT source_id, image_tag, scan_at, seen_at, last_row
               FROM tag_scan_times WHERE source_id = ?1
           ) ts
           ORDER BY ts.scan_at DESC, ts.seen_at DESC, ts.last_row DESC
           LIMIT 10"#,
        source_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// True when the source exists and `user_id` owns it. `None` skips the owner check (an
/// admin, who may read every tenant's sources).
pub async fn source_readable(
    pool: &SqlitePool,
    source_id: &str,
    user_id: Option<&str>,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM image_sources WHERE id = ?1 AND (?2 IS NULL OR user_id = ?2)
           ) AS "found!: i64""#,
        source_id,
        user_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.found != 0)
}

/// What a CVE list selects and how it is ordered and paged. The service validates every
/// value before it gets here. `sort` is one of the keys in the query's `CASE` terms.
///
/// Every filter is a bound parameter. The multi-value filters go to SQLite as one JSON array
/// each, read with `json_each`, so no value is ever part of the SQL text.
pub struct CveListFilter<'a> {
    /// `None` reads every user's mappings: admin `scope=all`, or a mapping the service has
    /// already checked.
    pub user_id: Option<&'a str>,
    pub source_id: Option<&'a str>,
    /// Exactly one CVE (the detail route).
    pub cve_id: Option<&'a str>,
    /// Any of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `UNKNOWN`, matched against the highest
    /// severity. Empty means no severity filter.
    pub severities: &'a [&'a str],
    /// Any of `open` and `fixed` (matched against the aggregated status) and `accepted`
    /// (matched against an active acceptance). Empty means no status filter.
    pub statuses: &'a [&'a str],
    /// `Some(1)` keeps accepted CVEs, `Some(0)` the others.
    pub accepted: Option<i64>,
    /// Lowercase ASCII text searched in the CVE id, the package, and the source's
    /// namespace and repository (#257). A literal substring, so `%` and `_` are not wildcards.
    pub q: Option<&'a str>,
    /// The summary's `package` equals this.
    pub package: Option<&'a str>,
    /// The CVE has a row, open or fixed, for this image tag.
    pub tag: Option<&'a str>,
    /// The first path segment of the source's repository equals this (decision 38).
    pub namespace: Option<&'a str>,
    /// The source's `repository` (no hub host), the value the source list returns (#323).
    pub repository: Option<&'a str>,
    /// `Some(1)` keeps CVEs with a GitHub issue row, `Some(0)` those without (#257).
    pub has_issue: Option<i64>,
    /// Any of `available` (the summary's `fixed_in_version` is non-empty) and `none` (it is
    /// null or empty), #265. Empty means no filter.
    pub fixes: &'a [&'a str],
    /// `severity`, `cve_id`, `first_seen_at` or `last_seen_at`.
    pub sort: &'a str,
    /// `1` ascending, `-1` descending.
    pub sort_sign: i64,
    pub limit: i64,
    pub offset: i64,
    /// Unix seconds. An acceptance is active while its expiry is after this.
    pub now: i64,
    /// `1` also reads the rows of older tags, for the detail route only (#196): a CVE with no
    /// newest-digest row then comes back as `fixed`. `0` is the list view.
    pub include_older: i64,
}

/// A list filter as one JSON array for `json_each`, or `None` for an empty list (no filter).
fn json_list(values: &[&str]) -> Result<Option<String>, AppError> {
    if values.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(values)
        .map(Some)
        .map_err(|_| AppError::InternalError)
}

/// One CVE of one mapping, aggregated over the mapping's tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveSummaryRow {
    pub source_id: String,
    pub cve_id: String,
    pub severity: String,
    /// The highest severity among the open rows, `None` when every row is fixed.
    pub open_severity: Option<String>,
    pub status: String,
    pub package: Option<String>,
    pub fixed_in_version: Option<String>,
    /// The other id of the CVE (its GHSA id, #337), from the same tag row as `package` (#323).
    pub alias: Option<String>,
    pub first_seen_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub open_tags: i64,
    pub tracked_tags: i64,
    pub github_issue_url: Option<String>,
    pub github_issue_number: Option<i64>,
    pub github_issue_status: Option<String>,
    pub accepted: bool,
}

/// One page of CVE summaries, one per (mapping, CVE) (`specs/api.md`, CVEs;
/// `specs/cve-lifecycle.md`, "Tracking per tag").
///
/// `status` is `open` when any tag's row is open, else `fixed`. `severity` is the highest
/// over the tags, `first_seen_at` the earliest and `last_seen_at` the latest. `package` and
/// `fixed_in_version` come from the most recently scanned tag that reports the CVE: the
/// latest `done` scan run (`tag_scan_times.scan_at`), then the later `last_seen_at`. `open_tags`
/// counts the tags whose row is open. `tracked_tags` counts the mapping's tags with a
/// successful report, at most 10. The issue is the `github_issues` row of the mapping's
/// GitHub target. `accepted` means an active acceptance exists. `open_severity` is the
/// highest severity of the open rows only.
///
/// The filters in the outer `WHERE` and in `tag_rows` are the same text as in
/// [`count_cves`], so `total` always matches the items. Keep the two in step.
///
/// A CVE id that the `<source_id>:<cve_id>` route id cannot carry (over 128 bytes, or a
/// character outside letters, digits, `.`, `_`, `-` and `:`) is left out, so every listed
/// id can be opened. These are the same ids the issue routes refuse.
pub async fn list_cves(
    pool: &SqlitePool,
    filter: &CveListFilter<'_>,
) -> Result<Vec<CveSummaryRow>, AppError> {
    let severities = json_list(filter.severities)?;
    let statuses = json_list(filter.statuses)?;
    let fixes = json_list(filter.fixes)?;
    let rows = sqlx::query!(
        r#"WITH tag_scans AS (
               SELECT source_id, image_tag, scan_at, seen_at FROM tag_scan_times
           ),
           tracked AS (
               SELECT source_id, MIN(10, COUNT(*)) AS n FROM newest_digest_tags
               GROUP BY source_id
           ),
           tag_rows AS (
               SELECT f.source_id AS source_id, COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id) AS cve_id,
                      f.image_tag AS image_tag,
                      f.package AS package, f.fixed_in_version AS fixed_in_version,
                      COALESCE(f.alias, CASE WHEN f.cve_id <> COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id)
                                             THEN f.cve_id END) AS alias,
                      f.first_seen_at AS first_seen_at, f.last_seen_at AS last_seen_at,
                      f.status AS status,
                      CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END AS sev_rank,
                      (nd.image_tag IS NOT NULL) AS nd,
                      ROW_NUMBER() OVER (
                          PARTITION BY f.source_id, COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id)
                          ORDER BY (nd.image_tag IS NOT NULL) DESC, COALESCE(ts.scan_at, -1) DESC,
                                   COALESCE(ts.seen_at, -1) DESC, f.last_seen_at DESC, f.id DESC
                      ) AS rn
               FROM cve_findings f
               JOIN image_sources m ON m.id = f.source_id JOIN hubs h ON h.id = m.hub_id
               LEFT JOIN tag_scans ts
                    ON ts.source_id = f.source_id AND ts.image_tag = f.image_tag
               LEFT JOIN newest_digest_tags nd
                    ON nd.source_id = f.source_id AND nd.image_tag = f.image_tag
               WHERE (?1 IS NULL OR m.user_id = ?1)
                 AND (?17 = 1 OR nd.image_tag IS NOT NULL)
                 AND (?2 IS NULL OR f.source_id = ?2)
                 AND (?3 IS NULL OR COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id) = ?3)
                 AND (?15 IS NULL OR substr(m.repository, 1, instr(m.repository || '/', '/') - 1) = ?15)
                 AND (?16 IS NULL OR m.repository = ?16)
                 AND length(CAST(f.cve_id AS BLOB)) BETWEEN 1 AND 128
                 AND f.cve_id NOT GLOB '*[^A-Za-z0-9._:-]*'
                 AND instr(CAST(f.cve_id AS BLOB), x'00') = 0
           ),
           summary AS (
               SELECT source_id, cve_id,
                      COALESCE(MAX(CASE WHEN nd THEN sev_rank END), MAX(sev_rank)) AS sev_rank,
                      MAX(CASE WHEN nd AND status = 'open' THEN sev_rank END) AS open_rank,
                      MIN(first_seen_at) AS first_seen_at,
                      COALESCE(MAX(CASE WHEN nd THEN last_seen_at END), MAX(last_seen_at))
                          AS last_seen_at,
                      COUNT(DISTINCT CASE WHEN nd AND status = 'open' THEN image_tag END)
                          AS open_tags,
                      MAX(nd AND status = 'open') AS any_open,
                      MAX(CASE WHEN rn = 1 THEN package END) AS package,
                      MAX(CASE WHEN rn = 1 THEN fixed_in_version END) AS fixed_in_version,
                      MAX(CASE WHEN rn = 1 THEN alias END) AS alias
               FROM tag_rows
               GROUP BY source_id, cve_id
           ),
           items AS (
               SELECT s.source_id AS source_id, s.cve_id AS cve_id, s.sev_rank AS sev_rank,
                      CASE s.sev_rank WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH'
                           WHEN 3 THEN 'MEDIUM' WHEN 2 THEN 'LOW' ELSE 'UNKNOWN' END AS severity,
                      CASE s.open_rank WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH'
                           WHEN 3 THEN 'MEDIUM' WHEN 2 THEN 'LOW' WHEN 1 THEN 'UNKNOWN'
                           END AS open_severity,
                      CASE WHEN s.any_open = 1 THEN 'open' ELSE 'fixed' END AS status,
                      s.package AS package, s.fixed_in_version AS fixed_in_version,
                      s.alias AS alias,
                      (SELECT MIN(af.first_seen_at) FROM cve_findings af
                       WHERE af.source_id = s.source_id
                         AND COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = af.cve_id), af.cve_id) = s.cve_id)
                          AS first_seen_at,
                      s.last_seen_at AS last_seen_at,
                      s.open_tags AS open_tags, COALESCE(t.n, 0) AS tracked_tags,
                      gi.github_issue_url AS github_issue_url,
                      gi.github_issue_number AS github_issue_number,
                      gi.status AS github_issue_status,
                      substr(m.repository, 1, instr(m.repository || '/', '/') - 1) AS namespace,
                      h.host || '/' || m.repository AS repository,
                      EXISTS (
                          SELECT 1 FROM cve_acceptances ca
                          WHERE ca.source_id = s.source_id AND ca.cve_id = s.cve_id
                            AND ca.revoked_at IS NULL
                            AND (ca.expires_at IS NULL OR ca.expires_at > ?4)
                      ) AS accepted
               FROM summary s
               JOIN image_sources m ON m.id = s.source_id JOIN hubs h ON h.id = m.hub_id
               LEFT JOIN tracked t ON t.source_id = s.source_id
               LEFT JOIN github_issues gi ON gi.github_owner = m.github_owner
                    AND gi.github_repo = m.github_repo AND gi.cve_id = s.cve_id
           )
           SELECT source_id AS "source_id!: String", cve_id AS "cve_id!: String",
                  severity AS "severity!: String", open_severity AS "open_severity?: String",
                  status AS "status!: String",
                  package AS "package?: String", fixed_in_version AS "fixed_in_version?: String",
                  alias AS "alias?: String",
                  first_seen_at AS "first_seen_at?: i64", last_seen_at AS "last_seen_at?: i64",
                  open_tags AS "open_tags!: i64", tracked_tags AS "tracked_tags!: i64",
                  github_issue_url AS "github_issue_url?: String",
                  github_issue_number AS "github_issue_number?: i64",
                  github_issue_status AS "github_issue_status?: String",
                  accepted AS "accepted!: i64"
           FROM items
           WHERE (?5 IS NULL OR severity IN (SELECT value FROM json_each(?5)))
             AND (?6 IS NULL OR EXISTS (
                  SELECT 1 FROM json_each(?6) st
                  WHERE (st.value = 'fixed' AND items.status = 'fixed')
                     OR (st.value = 'open' AND items.status = 'open' AND items.accepted = 0)
                     OR (st.value = 'accepted' AND items.accepted = 1)))
             AND (?7 IS NULL OR accepted = ?7)
             AND (?8 IS NULL OR instr(lower(cve_id), ?8) > 0
                  OR instr(lower(COALESCE(package, '')), ?8) > 0
                  OR instr(lower(namespace), ?8) > 0
                  OR instr(lower(repository), ?8) > 0)
             AND (?18 IS NULL OR (?18 = 1) = (github_issue_number IS NOT NULL))
             AND (?19 IS NULL OR EXISTS (
                  SELECT 1 FROM json_each(?19) fx
                  WHERE (fx.value = 'available' AND COALESCE(items.fixed_in_version, '') <> '')
                     OR (fx.value = 'none' AND COALESCE(items.fixed_in_version, '') = '')))
             AND (?13 IS NULL OR package = ?13)
             AND (?14 IS NULL OR EXISTS (
                  SELECT 1 FROM cve_findings tf
                  JOIN newest_digest_tags tn
                       ON tn.source_id = tf.source_id AND tn.image_tag = tf.image_tag
                  WHERE tf.source_id = items.source_id
                    AND COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = tf.cve_id), tf.cve_id) = items.cve_id
                    AND tf.image_tag = ?14))
           ORDER BY
             CASE WHEN ?9 = 'severity' AND ?10 = 1 THEN sev_rank END ASC,
             CASE WHEN ?9 = 'severity' AND ?10 = -1 THEN sev_rank END DESC,
             CASE WHEN ?9 = 'cve_id' AND ?10 = 1 THEN cve_id END ASC,
             CASE WHEN ?9 = 'cve_id' AND ?10 = -1 THEN cve_id END DESC,
             CASE WHEN ?9 = 'first_seen_at' AND ?10 = 1 THEN first_seen_at END ASC,
             CASE WHEN ?9 = 'first_seen_at' AND ?10 = -1 THEN first_seen_at END DESC,
             CASE WHEN ?9 = 'last_seen_at' AND ?10 = 1 THEN last_seen_at END ASC,
             CASE WHEN ?9 = 'last_seen_at' AND ?10 = -1 THEN last_seen_at END DESC,
             cve_id ASC, source_id ASC
           LIMIT ?11 OFFSET ?12"#,
        filter.user_id,
        filter.source_id,
        filter.cve_id,
        filter.now,
        severities,
        statuses,
        filter.accepted,
        filter.q,
        filter.sort,
        filter.sort_sign,
        filter.limit,
        filter.offset,
        filter.package,
        filter.tag,
        filter.namespace,
        filter.repository,
        filter.include_older,
        filter.has_issue,
        fixes
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| CveSummaryRow {
            source_id: row.source_id,
            cve_id: row.cve_id.clone(),
            severity: row.severity,
            open_severity: row.open_severity,
            status: row.status,
            package: row.package,
            fixed_in_version: row.fixed_in_version,
            alias: row.alias.filter(|alias| *alias != row.cve_id),
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
            open_tags: row.open_tags,
            tracked_tags: row.tracked_tags,
            github_issue_url: row.github_issue_url,
            github_issue_number: row.github_issue_number,
            github_issue_status: row.github_issue_status,
            accepted: row.accepted != 0,
        })
        .collect())
}

/// The number of summaries [`list_cves`] matches for the same filter, over all pages.
/// `sort`, `limit` and `offset` are ignored. The predicates are the same text as in
/// [`list_cves`]; only the parameter numbers differ.
pub async fn count_cves(pool: &SqlitePool, filter: &CveListFilter<'_>) -> Result<i64, AppError> {
    let severities = json_list(filter.severities)?;
    let statuses = json_list(filter.statuses)?;
    let fixes = json_list(filter.fixes)?;
    let row = sqlx::query!(
        r#"WITH tag_rows AS (
               SELECT f.source_id AS source_id, COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id) AS cve_id,
                      f.image_tag AS image_tag,
                      f.package AS package, f.status AS status,
                      f.fixed_in_version AS fixed_in_version,
                      substr(m.repository, 1, instr(m.repository || '/', '/') - 1) AS namespace,
                      h.host || '/' || m.repository AS repository,
                      CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END AS sev_rank,
                      ROW_NUMBER() OVER (
                          PARTITION BY f.source_id, COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id)
                          ORDER BY COALESCE((
                              SELECT st.scan_at FROM tag_scan_times st
                              WHERE st.source_id = f.source_id AND st.image_tag = f.image_tag), -1) DESC,
                              COALESCE((
                              SELECT st.seen_at FROM tag_scan_times st
                              WHERE st.source_id = f.source_id AND st.image_tag = f.image_tag), -1) DESC,
                              f.last_seen_at DESC, f.id DESC
                      ) AS rn
               FROM cve_findings f
               JOIN image_sources m ON m.id = f.source_id JOIN hubs h ON h.id = m.hub_id
               JOIN newest_digest_tags nd
                    ON nd.source_id = f.source_id AND nd.image_tag = f.image_tag
               WHERE (?1 IS NULL OR m.user_id = ?1)
                 AND (?2 IS NULL OR f.source_id = ?2)
                 AND (?3 IS NULL OR COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id) = ?3)
                 AND (?11 IS NULL OR substr(m.repository, 1, instr(m.repository || '/', '/') - 1) = ?11)
                 AND (?12 IS NULL OR m.repository = ?12)
                 AND length(CAST(f.cve_id AS BLOB)) BETWEEN 1 AND 128
                 AND f.cve_id NOT GLOB '*[^A-Za-z0-9._:-]*'
                 AND instr(CAST(f.cve_id AS BLOB), x'00') = 0
           ),
           items AS (
               SELECT source_id, cve_id,
                      CASE MAX(sev_rank) WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH'
                           WHEN 3 THEN 'MEDIUM' WHEN 2 THEN 'LOW' ELSE 'UNKNOWN' END AS severity,
                      CASE WHEN MAX(status = 'open') = 1 THEN 'open' ELSE 'fixed' END AS status,
                      MAX(CASE WHEN rn = 1 THEN package END) AS package,
                      MAX(CASE WHEN rn = 1 THEN fixed_in_version END) AS fixed_in_version,
                      MAX(namespace) AS namespace,
                      MAX(repository) AS repository,
                      EXISTS (
                          SELECT 1 FROM github_issues gi
                          JOIN image_sources gm ON gm.id = tag_rows.source_id
                          WHERE gi.github_owner = gm.github_owner
                            AND gi.github_repo = gm.github_repo
                            AND gi.cve_id = tag_rows.cve_id
                      ) AS has_issue,
                      EXISTS (
                          SELECT 1 FROM cve_acceptances ca
                          WHERE ca.source_id = tag_rows.source_id
                            AND ca.cve_id = tag_rows.cve_id
                            AND ca.revoked_at IS NULL
                            AND (ca.expires_at IS NULL OR ca.expires_at > ?4)
                      ) AS accepted
               FROM tag_rows
               GROUP BY source_id, cve_id
           )
           SELECT COUNT(*) AS "total!: i64"
           FROM items
           WHERE (?5 IS NULL OR severity IN (SELECT value FROM json_each(?5)))
             AND (?6 IS NULL OR EXISTS (
                  SELECT 1 FROM json_each(?6) st
                  WHERE (st.value = 'fixed' AND items.status = 'fixed')
                     OR (st.value = 'open' AND items.status = 'open' AND items.accepted = 0)
                     OR (st.value = 'accepted' AND items.accepted = 1)))
             AND (?7 IS NULL OR accepted = ?7)
             AND (?8 IS NULL OR instr(lower(cve_id), ?8) > 0
                  OR instr(lower(COALESCE(package, '')), ?8) > 0
                  OR instr(lower(namespace), ?8) > 0
                  OR instr(lower(repository), ?8) > 0)
             AND (?13 IS NULL OR (?13 = 1) = (has_issue = 1))
             AND (?14 IS NULL OR EXISTS (
                  SELECT 1 FROM json_each(?14) fx
                  WHERE (fx.value = 'available' AND COALESCE(items.fixed_in_version, '') <> '')
                     OR (fx.value = 'none' AND COALESCE(items.fixed_in_version, '') = '')))
             AND (?9 IS NULL OR package = ?9)
             AND (?10 IS NULL OR EXISTS (
                  SELECT 1 FROM cve_findings tf
                  WHERE tf.source_id = items.source_id
                    AND COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = tf.cve_id), tf.cve_id) = items.cve_id
                    AND tf.image_tag = ?10))"#,
        filter.user_id,
        filter.source_id,
        filter.cve_id,
        filter.now,
        severities,
        statuses,
        filter.accepted,
        filter.q,
        filter.package,
        filter.tag,
        filter.namespace,
        filter.repository,
        filter.has_issue,
        fixes
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.total)
}

/// One tag that reports a CVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveTagRow {
    pub image_tag: String,
    /// `open` or `fixed`.
    pub status: String,
    pub fixed_in_version: Option<String>,
    /// The Harbor vulnerability description on this tag's row.
    pub description: Option<String>,
    /// The CVE id behind the primary id on this tag's row (#323).
    pub alias: Option<String>,
    /// The tag's latest `done` scan run (`tag_scan_times.scan_at`).
    pub last_scan_at: Option<i64>,
    /// True for a tag of the mapping's newest scanned digest (#196).
    pub newest_digest: bool,
}

/// The mapping's tags that report the CVE, most recently scanned first, at most 10. The
/// order matches [`list_cves`], so the first row is the tag the summary takes its
/// `package` and `fixed_in_version` from.
pub async fn cve_tags(
    pool: &SqlitePool,
    source_id: &str,
    cve_id: &str,
) -> Result<Vec<CveTagRow>, AppError> {
    sqlx::query_as!(
        CveTagRow,
        r#"SELECT f.image_tag AS "image_tag!: String", f.status AS "status!: String",
                  f.fixed_in_version AS "fixed_in_version?: String",
                  f.description AS "description?: String",
                  f.alias AS "alias?: String",
                  ts.scan_at AS "last_scan_at?: i64",
                  (nd.image_tag IS NOT NULL) AS "newest_digest!: bool"
           FROM cve_findings f
           LEFT JOIN newest_digest_tags nd
                  ON nd.source_id = f.source_id AND nd.image_tag = f.image_tag
           LEFT JOIN (
               SELECT image_tag, scan_at, seen_at FROM tag_scan_times WHERE source_id = ?1
           ) ts ON ts.image_tag = f.image_tag
           WHERE f.source_id = ?1
             AND COALESCE((SELECT va.primary_id FROM vulnerability_aliases va WHERE va.alias = f.cve_id), f.cve_id) = ?2
           ORDER BY COALESCE(ts.scan_at, -1) DESC, COALESCE(ts.seen_at, -1) DESC,
                    f.last_seen_at DESC, f.id DESC
           LIMIT 10"#,
        source_id,
        cve_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The image reference of a source's tag: `<hub host>/<repository>:<tag>` (#323). The host
/// and repository are the source's; `None` when the source does not exist.
pub async fn source_image(
    conn: &mut SqliteConnection,
    source_id: &str,
    image_tag: &str,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        r#"SELECT h.host AS "host!: String", m.repository AS "repository!: String"
           FROM image_sources m JOIN hubs h ON h.id = m.hub_id
           WHERE m.id = ?1"#,
        source_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| format!("{}/{}:{}", row.host, row.repository, image_tag)))
}

/// True when the source has at least one `cve_findings` row for the CVE.
pub async fn record_exists(
    conn: &mut SqliteConnection,
    source_id: &str,
    cve_id: &str,
) -> Result<bool, AppError> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM cve_findings WHERE source_id = ? AND cve_id = ? LIMIT 1"#,
        source_id,
        cve_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(found.is_some())
}

/// Removes every `cve_findings` row of the CVE in the source. Returns the row count. It never
/// touches `github_issues`.
pub async fn delete_for_source(
    conn: &mut SqliteConnection,
    source_id: &str,
    cve_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "DELETE FROM cve_findings WHERE source_id = ? AND cve_id = ?",
        source_id,
        cve_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Removes the `scanner_findings` of the CVE whose run scanned an image that the source
/// observes and that no other source observes. A run of an image shared with another source
/// still serves that source, so it is kept.
pub async fn delete_scanner_findings_for_source(
    conn: &mut SqliteConnection,
    source_id: &str,
    cve_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "DELETE FROM scanner_findings
         WHERE cve_id = ?
           AND run_id IN (
               SELECT r.id FROM scan_runs r
               JOIN image_platforms p ON p.id = r.image_platform_id
               WHERE EXISTS (SELECT 1 FROM tag_observations o
                             WHERE o.image_id = p.image_id AND o.source_id = ?)
                 AND NOT EXISTS (SELECT 1 FROM tag_observations o
                                 WHERE o.image_id = p.image_id AND o.source_id <> ?))",
        cve_id,
        source_id,
        source_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}
