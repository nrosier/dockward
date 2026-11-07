//! SQL for the `cve_findings` table (`specs/database.md`, `specs/cve-lifecycle.md`,
//! "Tracking per tag"). One row per (mapping, Harbor repository, image tag, CVE).
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
    pub mapping_id: &'a str,
    pub harbor_repository: &'a str,
    pub image_tag: &'a str,
    pub cve_id: &'a str,
    pub package: Option<&'a str>,
    /// One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
    pub severity: &'a str,
    pub fixed_in_version: Option<&'a str>,
    /// At most 4,000 characters; `None` when the report has no text.
    pub description: Option<&'a str>,
    /// Unix seconds of the scan.
    pub now: i64,
}

/// Stores a finding. A new row is `open`. An existing row for the same tag and CVE takes
/// the new facts, moves `last_seen_at` forward and goes back to `open` (a CVE that returns
/// on a tag reopens its row). `first_seen_at` is kept.
pub async fn upsert(conn: &mut SqliteConnection, finding: &Finding<'_>) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO cve_findings
            (id, mapping_id, harbor_repository, image_tag, cve_id, package, severity,
             fixed_in_version, description, first_seen_at, last_seen_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
         ON CONFLICT (mapping_id, harbor_repository, image_tag, cve_id) DO UPDATE SET
            severity = excluded.severity,
            package = excluded.package,
            fixed_in_version = excluded.fixed_in_version,
            description = excluded.description,
            last_seen_at = excluded.last_seen_at,
            status = 'open'",
        finding.id,
        finding.mapping_id,
        finding.harbor_repository,
        finding.image_tag,
        finding.cve_id,
        finding.package,
        finding.severity,
        finding.fixed_in_version,
        finding.description,
        finding.now,
        finding.now
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// True when the mapping has a row for this CVE on any tag, in any status.
pub async fn exists_for_mapping(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    cve_id: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM cve_findings WHERE mapping_id = ? AND cve_id = ?
           ) AS "found!: i64""#,
        mapping_id,
        cve_id
    )
    .fetch_one(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.found != 0)
}

/// The CVE ids open on one tag of a mapping, sorted. The scheduled scan reads them as the last
/// result of a digest whose report was stored before migration 0008 (#191).
pub async fn open_ids_for_tag(
    pool: &SqlitePool,
    mapping_id: &str,
    repo: &str,
    tag: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT cve_id AS "cve_id!" FROM cve_findings
           WHERE mapping_id = ? AND harbor_repository = ? AND image_tag = ? AND status = 'open'
           ORDER BY cve_id"#,
        mapping_id,
        repo,
        tag
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Marks the tag's `open` rows `fixed` when their CVE is not in `seen_ids`. The ids go to
/// SQLite as one JSON array, so the list length is not limited by the bind count. Returns
/// the number of rows changed.
pub async fn mark_missing_fixed(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    tag: &str,
    seen_ids: &[String],
) -> Result<u64, AppError> {
    let seen = serde_json::to_string(seen_ids).map_err(|_| AppError::InternalError)?;
    sqlx::query!(
        "UPDATE cve_findings SET status = 'fixed'
         WHERE mapping_id = ? AND harbor_repository = ? AND image_tag = ?
           AND status = 'open'
           AND cve_id NOT IN (SELECT value FROM json_each(?))",
        mapping_id,
        repo,
        tag,
        seen
    )
    .execute(conn)
    .await
    .map(|result| result.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// The mapping's tracked tags, newest first. A tag is tracked when it has a successful
/// `sync_reports` row, so a tag with zero CVEs counts. Its scan time is the latest
/// `synced_at` among its successful reports; ties go to the report stored last.
pub async fn tags_by_recency(
    conn: &mut SqliteConnection,
    mapping_id: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT image_tag AS "image_tag!"
           FROM sync_reports
           WHERE mapping_id = ? AND sarif_status = 'success'
           GROUP BY image_tag
           ORDER BY MAX(synced_at) DESC, MAX(rowid) DESC"#,
        mapping_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|row| row.image_tag).collect())
}

/// One tag of the CVE view's tag set, as `GET /mappings/:id/tags` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedTagRow {
    pub image_tag: String,
    /// The tag's latest successful `synced_at`, Unix seconds.
    pub last_scan_at: i64,
    /// The tag's `cve_findings` rows that are `open`.
    pub open_cves: i64,
}

/// The mapping's tag set in the CVE view: the tags with a successful `sync_reports` row,
/// most recently scanned first, at most 10. This is the `tag_scans` and `tracked` rule of
/// [`list_cves`] (`tracked_tags` is the length of this list) with the order of
/// [`tags_by_recency`].
pub async fn tracked_tags(
    pool: &SqlitePool,
    mapping_id: &str,
) -> Result<Vec<TrackedTagRow>, AppError> {
    sqlx::query_as!(
        TrackedTagRow,
        r#"SELECT ts.image_tag AS "image_tag!: String", ts.scan_at AS "last_scan_at!: i64",
                  (SELECT COUNT(*) FROM cve_findings f
                   WHERE f.mapping_id = ts.mapping_id AND f.image_tag = ts.image_tag
                     AND f.status = 'open') AS "open_cves!: i64"
           FROM (
               SELECT mapping_id, image_tag, MAX(synced_at) AS scan_at, MAX(rowid) AS last_row
               FROM sync_reports
               WHERE mapping_id = ?1 AND sarif_status = 'success'
               GROUP BY mapping_id, image_tag
           ) ts
           ORDER BY ts.scan_at DESC, ts.last_row DESC
           LIMIT 10"#,
        mapping_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Deletes a tag's `cve_findings` and `sync_reports`. It never touches `github_issues`;
/// their `sync_report_id` and the findings' `github_issue_id` are `ON DELETE SET NULL`.
/// Returns the number of rows deleted from both tables.
pub async fn delete_tag(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    tag: &str,
) -> Result<u64, AppError> {
    let findings = sqlx::query!(
        "DELETE FROM cve_findings
         WHERE mapping_id = ? AND harbor_repository = ? AND image_tag = ?",
        mapping_id,
        repo,
        tag
    )
    .execute(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    let reports = sqlx::query!(
        "DELETE FROM sync_reports
         WHERE mapping_id = ? AND harbor_repository = ? AND image_tag = ?",
        mapping_id,
        repo,
        tag
    )
    .execute(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(findings.rows_affected() + reports.rows_affected())
}

/// True when the mapping exists and `user_id` owns it. `None` skips the owner check (an
/// admin, who may read every tenant's mappings).
pub async fn mapping_readable(
    pool: &SqlitePool,
    mapping_id: &str,
    user_id: Option<&str>,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM repo_mappings WHERE id = ?1 AND (?2 IS NULL OR user_id = ?2)
           ) AS "found!: i64""#,
        mapping_id,
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
    pub mapping_id: Option<&'a str>,
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
    /// Lowercase ASCII text searched in the CVE id and the package.
    pub q: Option<&'a str>,
    /// The summary's `package` equals this.
    pub package: Option<&'a str>,
    /// The CVE has a row, open or fixed, for this image tag.
    pub tag: Option<&'a str>,
    /// The mapping's `harbor_project` equals this.
    pub harbor_project: Option<&'a str>,
    /// The mapping's `harbor_repository` equals this.
    pub harbor_repository: Option<&'a str>,
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
    pub mapping_id: String,
    pub cve_id: String,
    pub severity: String,
    /// The highest severity among the open rows, `None` when every row is fixed.
    pub open_severity: Option<String>,
    pub status: String,
    pub package: Option<String>,
    pub fixed_in_version: Option<String>,
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
/// latest successful `sync_reports.synced_at`, then the later `last_seen_at`. `open_tags`
/// counts the tags whose row is open. `tracked_tags` counts the mapping's tags with a
/// successful report, at most 10. The issue is the `github_issues` row of the mapping's
/// GitHub target. `accepted` means an active acceptance exists. `open_severity` is the
/// highest severity of the open rows only.
///
/// The filters in the outer `WHERE` and in `tag_rows` are the same text as in
/// [`count_cves`], so `total` always matches the items. Keep the two in step.
///
/// A CVE id that the `<mapping_id>:<cve_id>` route id cannot carry (over 128 bytes, or a
/// character outside letters, digits, `.`, `_`, `-` and `:`) is left out, so every listed
/// id can be opened. These are the same ids the issue routes refuse.
pub async fn list_cves(
    pool: &SqlitePool,
    filter: &CveListFilter<'_>,
) -> Result<Vec<CveSummaryRow>, AppError> {
    let severities = json_list(filter.severities)?;
    let statuses = json_list(filter.statuses)?;
    let rows = sqlx::query!(
        r#"WITH tag_scans AS (
               SELECT mapping_id, image_tag, MAX(synced_at) AS scan_at
               FROM sync_reports WHERE sarif_status = 'success'
               GROUP BY mapping_id, image_tag
           ),
           tracked AS (
               SELECT mapping_id, MIN(10, COUNT(*)) AS n FROM newest_digest_tags
               GROUP BY mapping_id
           ),
           tag_rows AS (
               SELECT f.mapping_id AS mapping_id, f.cve_id AS cve_id, f.image_tag AS image_tag,
                      f.package AS package, f.fixed_in_version AS fixed_in_version,
                      f.first_seen_at AS first_seen_at, f.last_seen_at AS last_seen_at,
                      f.status AS status,
                      CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END AS sev_rank,
                      (nd.image_tag IS NOT NULL) AS nd,
                      ROW_NUMBER() OVER (
                          PARTITION BY f.mapping_id, f.cve_id
                          ORDER BY (nd.image_tag IS NOT NULL) DESC, COALESCE(ts.scan_at, -1) DESC,
                                   f.last_seen_at DESC, f.id DESC
                      ) AS rn
               FROM cve_findings f
               JOIN repo_mappings m ON m.id = f.mapping_id
               LEFT JOIN tag_scans ts
                    ON ts.mapping_id = f.mapping_id AND ts.image_tag = f.image_tag
               LEFT JOIN newest_digest_tags nd
                    ON nd.mapping_id = f.mapping_id AND nd.image_tag = f.image_tag
               WHERE (?1 IS NULL OR m.user_id = ?1)
                 AND (?17 = 1 OR nd.image_tag IS NOT NULL)
                 AND (?2 IS NULL OR f.mapping_id = ?2)
                 AND (?3 IS NULL OR f.cve_id = ?3)
                 AND (?15 IS NULL OR m.harbor_project = ?15)
                 AND (?16 IS NULL OR m.harbor_repository = ?16)
                 AND length(CAST(f.cve_id AS BLOB)) BETWEEN 1 AND 128
                 AND f.cve_id NOT GLOB '*[^A-Za-z0-9._:-]*'
                 AND instr(CAST(f.cve_id AS BLOB), x'00') = 0
           ),
           summary AS (
               SELECT mapping_id, cve_id,
                      COALESCE(MAX(CASE WHEN nd THEN sev_rank END), MAX(sev_rank)) AS sev_rank,
                      MAX(CASE WHEN nd AND status = 'open' THEN sev_rank END) AS open_rank,
                      MIN(first_seen_at) AS first_seen_at,
                      COALESCE(MAX(CASE WHEN nd THEN last_seen_at END), MAX(last_seen_at))
                          AS last_seen_at,
                      COUNT(DISTINCT CASE WHEN nd AND status = 'open' THEN image_tag END)
                          AS open_tags,
                      MAX(nd AND status = 'open') AS any_open,
                      MAX(CASE WHEN rn = 1 THEN package END) AS package,
                      MAX(CASE WHEN rn = 1 THEN fixed_in_version END) AS fixed_in_version
               FROM tag_rows
               GROUP BY mapping_id, cve_id
           ),
           items AS (
               SELECT s.mapping_id AS mapping_id, s.cve_id AS cve_id, s.sev_rank AS sev_rank,
                      CASE s.sev_rank WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH'
                           WHEN 3 THEN 'MEDIUM' WHEN 2 THEN 'LOW' ELSE 'UNKNOWN' END AS severity,
                      CASE s.open_rank WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH'
                           WHEN 3 THEN 'MEDIUM' WHEN 2 THEN 'LOW' WHEN 1 THEN 'UNKNOWN'
                           END AS open_severity,
                      CASE WHEN s.any_open = 1 THEN 'open' ELSE 'fixed' END AS status,
                      s.package AS package, s.fixed_in_version AS fixed_in_version,
                      (SELECT MIN(af.first_seen_at) FROM cve_findings af
                       WHERE af.mapping_id = s.mapping_id AND af.cve_id = s.cve_id)
                          AS first_seen_at,
                      s.last_seen_at AS last_seen_at,
                      s.open_tags AS open_tags, COALESCE(t.n, 0) AS tracked_tags,
                      gi.github_issue_url AS github_issue_url,
                      gi.github_issue_number AS github_issue_number,
                      gi.status AS github_issue_status,
                      EXISTS (
                          SELECT 1 FROM cve_acceptances ca
                          WHERE ca.mapping_id = s.mapping_id AND ca.cve_id = s.cve_id
                            AND ca.revoked_at IS NULL
                            AND (ca.expires_at IS NULL OR ca.expires_at > ?4)
                      ) AS accepted
               FROM summary s
               JOIN repo_mappings m ON m.id = s.mapping_id
               LEFT JOIN tracked t ON t.mapping_id = s.mapping_id
               LEFT JOIN github_issues gi ON gi.github_owner = m.github_owner
                    AND gi.github_repo = m.github_repo AND gi.cve_id = s.cve_id
           )
           SELECT mapping_id AS "mapping_id!: String", cve_id AS "cve_id!: String",
                  severity AS "severity!: String", open_severity AS "open_severity?: String",
                  status AS "status!: String",
                  package AS "package?: String", fixed_in_version AS "fixed_in_version?: String",
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
                  WHERE st.value = items.status OR (st.value = 'accepted' AND items.accepted = 1)))
             AND (?7 IS NULL OR accepted = ?7)
             AND (?8 IS NULL OR instr(lower(cve_id), ?8) > 0
                  OR instr(lower(COALESCE(package, '')), ?8) > 0)
             AND (?13 IS NULL OR package = ?13)
             AND (?14 IS NULL OR EXISTS (
                  SELECT 1 FROM cve_findings tf
                  JOIN newest_digest_tags tn
                       ON tn.mapping_id = tf.mapping_id AND tn.image_tag = tf.image_tag
                  WHERE tf.mapping_id = items.mapping_id AND tf.cve_id = items.cve_id
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
             cve_id ASC, mapping_id ASC
           LIMIT ?11 OFFSET ?12"#,
        filter.user_id,
        filter.mapping_id,
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
        filter.harbor_project,
        filter.harbor_repository,
        filter.include_older
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| CveSummaryRow {
            mapping_id: row.mapping_id,
            cve_id: row.cve_id,
            severity: row.severity,
            open_severity: row.open_severity,
            status: row.status,
            package: row.package,
            fixed_in_version: row.fixed_in_version,
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
    let row = sqlx::query!(
        r#"WITH tag_rows AS (
               SELECT f.mapping_id AS mapping_id, f.cve_id AS cve_id, f.image_tag AS image_tag,
                      f.package AS package, f.status AS status,
                      CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END AS sev_rank,
                      ROW_NUMBER() OVER (
                          PARTITION BY f.mapping_id, f.cve_id
                          ORDER BY COALESCE((
                              SELECT MAX(sr.synced_at) FROM sync_reports sr
                              WHERE sr.mapping_id = f.mapping_id AND sr.image_tag = f.image_tag
                                AND sr.sarif_status = 'success'), -1) DESC,
                              f.last_seen_at DESC, f.id DESC
                      ) AS rn
               FROM cve_findings f
               JOIN repo_mappings m ON m.id = f.mapping_id
               JOIN newest_digest_tags nd
                    ON nd.mapping_id = f.mapping_id AND nd.image_tag = f.image_tag
               WHERE (?1 IS NULL OR m.user_id = ?1)
                 AND (?2 IS NULL OR f.mapping_id = ?2)
                 AND (?3 IS NULL OR f.cve_id = ?3)
                 AND (?11 IS NULL OR m.harbor_project = ?11)
                 AND (?12 IS NULL OR m.harbor_repository = ?12)
                 AND length(CAST(f.cve_id AS BLOB)) BETWEEN 1 AND 128
                 AND f.cve_id NOT GLOB '*[^A-Za-z0-9._:-]*'
                 AND instr(CAST(f.cve_id AS BLOB), x'00') = 0
           ),
           items AS (
               SELECT mapping_id, cve_id,
                      CASE MAX(sev_rank) WHEN 5 THEN 'CRITICAL' WHEN 4 THEN 'HIGH'
                           WHEN 3 THEN 'MEDIUM' WHEN 2 THEN 'LOW' ELSE 'UNKNOWN' END AS severity,
                      CASE WHEN MAX(status = 'open') = 1 THEN 'open' ELSE 'fixed' END AS status,
                      MAX(CASE WHEN rn = 1 THEN package END) AS package,
                      EXISTS (
                          SELECT 1 FROM cve_acceptances ca
                          WHERE ca.mapping_id = tag_rows.mapping_id
                            AND ca.cve_id = tag_rows.cve_id
                            AND ca.revoked_at IS NULL
                            AND (ca.expires_at IS NULL OR ca.expires_at > ?4)
                      ) AS accepted
               FROM tag_rows
               GROUP BY mapping_id, cve_id
           )
           SELECT COUNT(*) AS "total!: i64"
           FROM items
           WHERE (?5 IS NULL OR severity IN (SELECT value FROM json_each(?5)))
             AND (?6 IS NULL OR EXISTS (
                  SELECT 1 FROM json_each(?6) st
                  WHERE st.value = items.status OR (st.value = 'accepted' AND items.accepted = 1)))
             AND (?7 IS NULL OR accepted = ?7)
             AND (?8 IS NULL OR instr(lower(cve_id), ?8) > 0
                  OR instr(lower(COALESCE(package, '')), ?8) > 0)
             AND (?9 IS NULL OR package = ?9)
             AND (?10 IS NULL OR EXISTS (
                  SELECT 1 FROM cve_findings tf
                  WHERE tf.mapping_id = items.mapping_id AND tf.cve_id = items.cve_id
                    AND tf.image_tag = ?10))"#,
        filter.user_id,
        filter.mapping_id,
        filter.cve_id,
        filter.now,
        severities,
        statuses,
        filter.accepted,
        filter.q,
        filter.package,
        filter.tag,
        filter.harbor_project,
        filter.harbor_repository
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
    /// The tag's latest successful `sync_reports.synced_at`.
    pub last_scan_at: Option<i64>,
    /// True for a tag of the mapping's newest scanned digest (#196).
    pub newest_digest: bool,
}

/// The mapping's tags that report the CVE, most recently scanned first, at most 10. The
/// order matches [`list_cves`], so the first row is the tag the summary takes its
/// `package` and `fixed_in_version` from.
pub async fn cve_tags(
    pool: &SqlitePool,
    mapping_id: &str,
    cve_id: &str,
) -> Result<Vec<CveTagRow>, AppError> {
    sqlx::query_as!(
        CveTagRow,
        r#"SELECT f.image_tag AS "image_tag!: String", f.status AS "status!: String",
                  f.fixed_in_version AS "fixed_in_version?: String",
                  f.description AS "description?: String",
                  ts.scan_at AS "last_scan_at?: i64",
                  (nd.image_tag IS NOT NULL) AS "newest_digest!: bool"
           FROM cve_findings f
           LEFT JOIN newest_digest_tags nd
                  ON nd.mapping_id = f.mapping_id AND nd.image_tag = f.image_tag
           LEFT JOIN (
               SELECT image_tag, MAX(synced_at) AS scan_at
               FROM sync_reports WHERE mapping_id = ?1 AND sarif_status = 'success'
               GROUP BY image_tag
           ) ts ON ts.image_tag = f.image_tag
           WHERE f.mapping_id = ?1 AND f.cve_id = ?2
           ORDER BY COALESCE(ts.scan_at, -1) DESC, f.last_seen_at DESC, f.id DESC
           LIMIT 10"#,
        mapping_id,
        cve_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}
