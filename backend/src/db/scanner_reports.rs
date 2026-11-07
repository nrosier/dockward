//! SQL for the scanner tables of #224 (`specs/database.md`, migration 0009): `harbor_scanners`,
//! `scanner_reports`, `scanner_findings` and `project_scanner_locks`. Rows hold scanner names,
//! versions, CVE ids, package names and counts only. Never a token, a secret, or a scanner URL.
//!
//! Writes that must succeed or fail together take a connection, so the caller can group them in
//! one transaction (`replace_report` runs its delete and inserts on the connection it is given).

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// The scanner UUID of a report that cannot be tied to a Harbor registration. Migration 0009
/// gives every existing report this value.
pub const UNKNOWN_SCANNER_UUID: &str = "unknown";

/// A scanner registration as a successful scanner list read returned it.
pub struct HarborScannerUpsert<'a> {
    pub harbor_base_url: &'a str,
    /// The Harbor scanner registration UUID. The key.
    pub uuid: &'a str,
    pub name: &'a str,
    pub vendor: Option<&'a str>,
    pub version: Option<&'a str>,
    pub disabled: bool,
    /// Unix seconds of the read.
    pub seen_at: i64,
}

/// A scanner row as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarborScannerRow {
    pub uuid: String,
    pub name: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub disabled: bool,
    pub last_seen_at: i64,
    pub removed_at: Option<i64>,
}

/// A stored report of one (mapping, digest, scanner). Its fields are the scanner snapshot taken at
/// the fetch.
pub struct NewScannerReport<'a> {
    pub id: &'a str,
    pub mapping_id: &'a str,
    pub image_digest: &'a str,
    /// A Harbor registration UUID, or `UNKNOWN_SCANNER_UUID`.
    pub scanner_uuid: &'a str,
    pub scanner_name: Option<&'a str>,
    pub scanner_vendor: Option<&'a str>,
    pub scanner_version: Option<&'a str>,
    /// Harbor's push time of the tag, Unix milliseconds (as `sync_reports.image_push_time`).
    pub image_push_time: Option<i64>,
    /// Unix seconds; the retention clock.
    pub stored_at: i64,
}

/// One finding of a stored report, one row per (CVE id, package).
pub struct NewScannerFinding<'a> {
    pub cve_id: &'a str,
    /// `""` when the scanner gives no package.
    pub package: &'a str,
    pub version: Option<&'a str>,
    pub fixed_in_version: Option<&'a str>,
    /// One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
    pub severity: &'a str,
    pub cvss_v3: Option<f64>,
    /// At most 4,000 characters.
    pub description: Option<&'a str>,
}

/// A stored report row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerReportRow {
    pub id: String,
    pub scanner_uuid: String,
    pub scanner_name: Option<String>,
    pub scanner_vendor: Option<String>,
    pub scanner_version: Option<String>,
    pub image_push_time: Option<i64>,
    pub stored_at: i64,
}

/// A stored finding with the scanner that reported it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannerFindingRow {
    pub report_id: String,
    pub scanner_uuid: String,
    pub cve_id: String,
    pub package: String,
    pub version: Option<String>,
    pub fixed_in_version: Option<String>,
    pub severity: String,
    pub cvss_v3: Option<f64>,
    pub description: Option<String>,
}

/// A project scanner lock row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectScannerLockRow {
    pub job_id: String,
    pub mapping_id: Option<String>,
    pub chosen_scanner_uuid: String,
    pub previous_scanner_uuid: Option<String>,
    /// `switched` or `restore_pending`.
    pub state: String,
    pub acquired_at: i64,
    pub wait_started_at: Option<i64>,
}

/// Inserts a scanner, or updates its name, vendor, version, disabled flag and `last_seen_at` when
/// it is already known. A scanner that a successful read lists again is no longer removed, so
/// `removed_at` is cleared.
pub async fn upsert_scanner(
    pool: &SqlitePool,
    scanner: &HarborScannerUpsert<'_>,
) -> Result<(), AppError> {
    let disabled = i64::from(scanner.disabled);
    sqlx::query!(
        "INSERT INTO harbor_scanners
            (harbor_base_url, uuid, name, vendor, version, disabled, last_seen_at, removed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
         ON CONFLICT (harbor_base_url, uuid) DO UPDATE SET
            name = excluded.name,
            vendor = excluded.vendor,
            version = excluded.version,
            disabled = excluded.disabled,
            last_seen_at = excluded.last_seen_at,
            removed_at = NULL",
        scanner.harbor_base_url,
        scanner.uuid,
        scanner.name,
        scanner.vendor,
        scanner.version,
        disabled,
        scanner.seen_at
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// The scanners HarborGate has seen for one Harbor base URL, by UUID.
pub async fn list_scanners(
    pool: &SqlitePool,
    harbor_base_url: &str,
) -> Result<Vec<HarborScannerRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT uuid, name, vendor, version, disabled, last_seen_at, removed_at
           FROM harbor_scanners
           WHERE harbor_base_url = ?
           ORDER BY uuid"#,
        harbor_base_url
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| HarborScannerRow {
            uuid: row.uuid,
            name: row.name,
            vendor: row.vendor,
            version: row.version,
            disabled: row.disabled != 0,
            last_seen_at: row.last_seen_at,
            removed_at: row.removed_at,
        })
        .collect())
}

/// Stores the report of (mapping, digest, scanner) with its findings, replacing the report and
/// findings already stored for that scanner. Another scanner's report is not touched.
///
/// The delete and the inserts run on `conn`. The caller opens the transaction, so the replace and
/// any recompute it needs commit together.
pub async fn replace_report(
    conn: &mut SqliteConnection,
    report: &NewScannerReport<'_>,
    findings: &[NewScannerFinding<'_>],
) -> Result<(), AppError> {
    sqlx::query!(
        "DELETE FROM scanner_reports
         WHERE mapping_id = ? AND image_digest = ? AND scanner_uuid = ?",
        report.mapping_id,
        report.image_digest,
        report.scanner_uuid
    )
    .execute(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;

    sqlx::query!(
        "INSERT INTO scanner_reports
            (id, mapping_id, image_digest, scanner_uuid, scanner_name, scanner_vendor,
             scanner_version, image_push_time, stored_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        report.id,
        report.mapping_id,
        report.image_digest,
        report.scanner_uuid,
        report.scanner_name,
        report.scanner_vendor,
        report.scanner_version,
        report.image_push_time,
        report.stored_at
    )
    .execute(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;

    for finding in findings {
        sqlx::query!(
            "INSERT INTO scanner_findings
                (report_id, cve_id, package, version, fixed_in_version, severity, cvss_v3,
                 description)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            report.id,
            finding.cve_id,
            finding.package,
            finding.version,
            finding.fixed_in_version,
            finding.severity,
            finding.cvss_v3,
            finding.description
        )
        .execute(&mut *conn)
        .await
        .map_err(|_| AppError::InternalError)?;
    }
    Ok(())
}

/// The stored reports of one (mapping, digest), one per scanner, by scanner UUID.
pub async fn reports_for_digest(
    pool: &SqlitePool,
    mapping_id: &str,
    image_digest: &str,
) -> Result<Vec<ScannerReportRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", scanner_uuid, scanner_name, scanner_vendor, scanner_version,
                  image_push_time, stored_at
           FROM scanner_reports
           WHERE mapping_id = ? AND image_digest = ?
           ORDER BY scanner_uuid"#,
        mapping_id,
        image_digest
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| ScannerReportRow {
            id: row.id,
            scanner_uuid: row.scanner_uuid,
            scanner_name: row.scanner_name,
            scanner_vendor: row.scanner_vendor,
            scanner_version: row.scanner_version,
            image_push_time: row.image_push_time,
            stored_at: row.stored_at,
        })
        .collect())
}

/// The findings of every stored report of one (mapping, digest), each with its scanner. The
/// merged view (grouped by CVE id and package) is built from these rows by the caller.
pub async fn findings_for_digest(
    pool: &SqlitePool,
    mapping_id: &str,
    image_digest: &str,
) -> Result<Vec<ScannerFindingRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT sr.id AS "report_id!", sr.scanner_uuid AS "scanner_uuid!",
                  sf.cve_id AS "cve_id!", sf.package AS "package!", sf.version,
                  sf.fixed_in_version, sf.severity AS "severity!", sf.cvss_v3,
                  sf.description
           FROM scanner_findings AS sf
           JOIN scanner_reports AS sr ON sr.id = sf.report_id
           WHERE sr.mapping_id = ? AND sr.image_digest = ?
           ORDER BY sf.cve_id, sf.package, sr.scanner_uuid"#,
        mapping_id,
        image_digest
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| ScannerFindingRow {
            report_id: row.report_id,
            scanner_uuid: row.scanner_uuid,
            cve_id: row.cve_id,
            package: row.package,
            version: row.version,
            fixed_in_version: row.fixed_in_version,
            severity: row.severity,
            cvss_v3: row.cvss_v3,
            description: row.description,
        })
        .collect())
}

/// Takes the scan lock of a Harbor project for `job_id`. Returns `false` when another job holds
/// it. The primary key of `project_scanner_locks` makes the insert the check.
pub async fn try_acquire_project_lock(
    pool: &SqlitePool,
    harbor_base_url: &str,
    harbor_project: &str,
    lock: &NewProjectLock<'_>,
) -> Result<bool, AppError> {
    let result = sqlx::query!(
        "INSERT INTO project_scanner_locks
            (harbor_base_url, harbor_project, job_id, mapping_id, chosen_scanner_uuid,
             previous_scanner_uuid, state, acquired_at, wait_started_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
         ON CONFLICT (harbor_base_url, harbor_project) DO NOTHING",
        harbor_base_url,
        harbor_project,
        lock.job_id,
        lock.mapping_id,
        lock.chosen_scanner_uuid,
        lock.previous_scanner_uuid,
        lock.state,
        lock.acquired_at
    )
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(result.rows_affected() == 1)
}

/// The lock row of a Harbor project, if one is held.
pub async fn get_project_lock(
    pool: &SqlitePool,
    harbor_base_url: &str,
    harbor_project: &str,
) -> Result<Option<ProjectScannerLockRow>, AppError> {
    let row = sqlx::query!(
        r#"SELECT job_id, mapping_id, chosen_scanner_uuid, previous_scanner_uuid, state,
                  acquired_at, wait_started_at
           FROM project_scanner_locks
           WHERE harbor_base_url = ? AND harbor_project = ?"#,
        harbor_base_url,
        harbor_project
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| ProjectScannerLockRow {
        job_id: row.job_id,
        mapping_id: row.mapping_id,
        chosen_scanner_uuid: row.chosen_scanner_uuid,
        previous_scanner_uuid: row.previous_scanner_uuid,
        state: row.state,
        acquired_at: row.acquired_at,
        wait_started_at: row.wait_started_at,
    }))
}

/// Releases the lock of a Harbor project, only when `job_id` holds it. Returns `true` when a row
/// was removed.
pub async fn release_project_lock(
    pool: &SqlitePool,
    harbor_base_url: &str,
    harbor_project: &str,
    job_id: &str,
) -> Result<bool, AppError> {
    let result = sqlx::query!(
        "DELETE FROM project_scanner_locks
         WHERE harbor_base_url = ? AND harbor_project = ? AND job_id = ?",
        harbor_base_url,
        harbor_project,
        job_id
    )
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(result.rows_affected() == 1)
}

/// The values of a new project scanner lock.
pub struct NewProjectLock<'a> {
    pub job_id: &'a str,
    pub mapping_id: Option<&'a str>,
    pub chosen_scanner_uuid: &'a str,
    pub previous_scanner_uuid: Option<&'a str>,
    /// `switched` or `restore_pending`.
    pub state: &'a str,
    pub acquired_at: i64,
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    /// An in-memory pool with foreign keys on, migrated to `version` (or all migrations).
    async fn pool_at(version: Option<i64>) -> Result<SqlitePool, AppError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .in_memory(true)
                    .foreign_keys(true),
            )
            .await
            .map_err(|_| AppError::InternalError)?;
        let migrator = sqlx::migrate!("./migrations");
        match version {
            Some(v) => migrator.run_to(v, &pool).await,
            None => migrator.run(&pool).await,
        }
        .map_err(|_| AppError::InternalError)?;
        Ok(pool)
    }

    /// One user, a Harbor and a GitHub credential, and mapping `map-1`. Test values only.
    async fn seed_mapping(pool: &SqlitePool) -> Result<(), AppError> {
        for sql in [
            "INSERT INTO users (id, username, role, auth_provider) VALUES ('user-1', 'u', 'user', 'local')",
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, encrypted_token)
             VALUES ('cred-h', 'user-1', 'harbor', 'h', 'https://harbor.example.com', 'v1:test')",
            "INSERT INTO user_credentials (id, user_id, service_type, label, encrypted_token)
             VALUES ('cred-g', 'user-1', 'github', 'g', 'v1:test')",
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url,
                harbor_project, harbor_repository, github_owner, github_repo,
                webhook_token_hash, webhook_auth_secret_hash)
             VALUES ('map-1', 'user-1', 'cred-h', 'cred-g', 'https://harbor.example.com',
                'project', 'repo', 'owner', 'repo', 'hash-token-test', 'hash-secret-test')",
        ] {
            sqlx::query(sql)
                .execute(pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        }
        Ok(())
    }

    async fn insert_sync_job(pool: &SqlitePool, id: &str) -> Result<(), AppError> {
        sqlx::query("INSERT INTO sync_jobs (id, mapping_id, payload) VALUES (?, 'map-1', '{}')")
            .bind(id)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|_| AppError::InternalError)
    }

    fn finding<'a>(cve_id: &'a str, package: &'a str, severity: &'a str) -> NewScannerFinding<'a> {
        NewScannerFinding {
            cve_id,
            package,
            version: Some("1.0"),
            fixed_in_version: None,
            severity,
            cvss_v3: Some(7.5),
            description: Some("text"),
        }
    }

    fn report<'a>(id: &'a str, digest: &'a str, scanner: &'a str) -> NewScannerReport<'a> {
        NewScannerReport {
            id,
            mapping_id: "map-1",
            image_digest: digest,
            scanner_uuid: scanner,
            scanner_name: None,
            scanner_vendor: None,
            scanner_version: None,
            image_push_time: Some(1_000),
            stored_at: 500,
        }
    }

    async fn count_rows(pool: &SqlitePool, sql: &'static str) -> Result<i64, AppError> {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(pool)
            .await
            .map_err(|_| AppError::InternalError)
    }

    /// Migration 0009: one `unknown` report per (mapping, digest) with a successful sync, taken from
    /// the newest successful sync; the newest tag's open findings are copied; fixed rows and
    /// failed syncs are not; existing rows are kept.
    #[tokio::test]
    async fn migration_0009_gives_existing_digests_the_unknown_scanner() -> Result<(), AppError> {
        let pool = pool_at(Some(8)).await?;
        seed_mapping(&pool).await?;
        // Digest d1: tag a (older success), tag b (newest success), and a later failure that is ignored.
        // Digest d2: failure only, so no report. Digest d3: a clean image with no open findings.
        for sql in [
            "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
                vulnerability_summary, sarif_status, synced_at, image_push_time)
             VALUES ('sr-a', 'map-1', 'repo', 'a', 'd1', '{}', 'success', 100, 1000)",
            "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
                vulnerability_summary, sarif_status, synced_at, image_push_time)
             VALUES ('sr-b', 'map-1', 'repo', 'b', 'd1', '{}', 'success', 200, 2000)",
            "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
                vulnerability_summary, sarif_status, synced_at, image_push_time)
             VALUES ('sr-f', 'map-1', 'repo', 'b', 'd1', '{}', 'failed', 300, 3000)",
            "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
                vulnerability_summary, sarif_status, synced_at, image_push_time)
             VALUES ('sr-d2', 'map-1', 'repo', 'c', 'd2', '{}', 'failed', 400, 4000)",
            "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
                vulnerability_summary, sarif_status, synced_at, image_push_time)
             VALUES ('sr-d3', 'map-1', 'repo', 'd', 'd3', '{}', 'success', 450, NULL)",
            // Open on the newest tag (b): copied. Fixed on b: not copied. Open on the older tag (a): not copied.
            "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, package,
                severity, fixed_in_version, description, status)
             VALUES ('cf1', 'map-1', 'repo', 'b', 'CVE-1', 'pkg-x', 'HIGH', '1.2', 'desc', 'open')",
            "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, package,
                severity, status)
             VALUES ('cf2', 'map-1', 'repo', 'b', 'CVE-2', 'pkg-y', 'LOW', 'fixed')",
            "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, package,
                severity, status)
             VALUES ('cf3', 'map-1', 'repo', 'a', 'CVE-9', 'pkg-z', 'CRITICAL', 'open')",
        ] {
            sqlx::query(sql)
                .execute(&pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        }
        let sync_before = count_rows(&pool, "SELECT COUNT(*) FROM sync_reports").await?;
        let findings_before = count_rows(&pool, "SELECT COUNT(*) FROM cve_findings").await?;

        pool_migrate(&pool).await?;

        let reports = reports_for_digest(&pool, "map-1", "d1").await?;
        assert_eq!(reports.len(), 1, "one report per digest");
        assert_eq!(reports[0].scanner_uuid, UNKNOWN_SCANNER_UUID);
        assert_eq!(reports[0].scanner_name, None);
        assert_eq!(
            reports[0].image_push_time,
            Some(2_000),
            "newest success wins"
        );
        assert_eq!(reports[0].stored_at, 200);
        let findings = findings_for_digest(&pool, "map-1", "d1").await?;
        assert_eq!(
            findings.len(),
            1,
            "only the newest tag's open rows are copied"
        );
        assert_eq!(findings[0].cve_id, "CVE-1");
        assert_eq!(findings[0].package, "pkg-x");
        assert_eq!(findings[0].severity, "HIGH");
        assert_eq!(findings[0].fixed_in_version.as_deref(), Some("1.2"));
        assert_eq!(findings[0].description.as_deref(), Some("desc"));
        assert_eq!(findings[0].version, None);
        assert_eq!(findings[0].cvss_v3, None);

        assert!(reports_for_digest(&pool, "map-1", "d2").await?.is_empty());
        let clean = reports_for_digest(&pool, "map-1", "d3").await?;
        assert_eq!(clean.len(), 1, "a clean digest still gets a report");
        assert_eq!(clean[0].scanner_uuid, UNKNOWN_SCANNER_UUID);
        assert!(findings_for_digest(&pool, "map-1", "d3").await?.is_empty());

        assert_eq!(
            count_rows(&pool, "SELECT COUNT(*) FROM sync_reports").await?,
            sync_before,
            "no sync report lost"
        );
        assert_eq!(
            count_rows(&pool, "SELECT COUNT(*) FROM cve_findings").await?,
            findings_before,
            "no finding lost"
        );
        assert_eq!(
            count_rows(&pool, "SELECT COUNT(*) FROM harbor_scanners").await?,
            0
        );
        assert_eq!(
            count_rows(&pool, "SELECT COUNT(*) FROM project_scanner_locks").await?,
            0
        );
        Ok(())
    }

    /// Runs the pending migrations on a pool that is already at a version. Used after the seed.
    async fn pool_migrate(pool: &SqlitePool) -> Result<(), AppError> {
        sqlx::migrate!("./migrations")
            .run(pool)
            .await
            .map_err(|_| AppError::InternalError)
    }

    #[tokio::test]
    async fn one_report_per_mapping_digest_and_scanner() -> Result<(), AppError> {
        let pool = pool_at(None).await?;
        seed_mapping(&pool).await?;
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        replace_report(&mut conn, &report("r1", "sha256:a", "uuid-1"), &[]).await?;
        // A second scanner on the same digest is allowed.
        replace_report(&mut conn, &report("r2", "sha256:a", "uuid-2"), &[]).await?;
        // The same scanner again replaces its own row, so the count stays two.
        replace_report(&mut conn, &report("r3", "sha256:a", "uuid-1"), &[]).await?;
        drop(conn);
        let reports = reports_for_digest(&pool, "map-1", "sha256:a").await?;
        assert_eq!(reports.len(), 2);
        assert!(
            reports.iter().any(|r| r.id == "r3"),
            "the replacement row is kept"
        );
        assert!(
            !reports.iter().any(|r| r.id == "r1"),
            "the replaced row is gone"
        );
        Ok(())
    }

    #[tokio::test]
    async fn raw_duplicate_report_key_is_refused() -> Result<(), AppError> {
        let pool = pool_at(None).await?;
        seed_mapping(&pool).await?;
        let insert = |id: &'static str| {
            sqlx::query(
                "INSERT INTO scanner_reports (id, mapping_id, image_digest, scanner_uuid, stored_at)
                 VALUES (?, 'map-1', 'sha256:b', 'uuid-1', 1)",
            )
            .bind(id)
        };
        insert("x1")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert!(
            insert("x2").execute(&pool).await.is_err(),
            "duplicate key accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_keeps_other_scanners_findings() -> Result<(), AppError> {
        let pool = pool_at(None).await?;
        seed_mapping(&pool).await?;
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        replace_report(
            &mut conn,
            &report("r1", "sha256:c", "uuid-1"),
            &[finding("CVE-1", "pkg", "HIGH")],
        )
        .await?;
        replace_report(
            &mut conn,
            &report("r2", "sha256:c", "uuid-2"),
            &[finding("CVE-1", "pkg", "HIGH"), finding("CVE-2", "", "LOW")],
        )
        .await?;
        // Scanner 1 scans again with no findings: its row goes, scanner 2's findings stay.
        replace_report(&mut conn, &report("r3", "sha256:c", "uuid-1"), &[]).await?;
        drop(conn);
        let findings = findings_for_digest(&pool, "map-1", "sha256:c").await?;
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.scanner_uuid == "uuid-2"));
        Ok(())
    }

    #[tokio::test]
    async fn raw_duplicate_finding_key_is_refused() -> Result<(), AppError> {
        let pool = pool_at(None).await?;
        seed_mapping(&pool).await?;
        sqlx::query(
            "INSERT INTO scanner_reports (id, mapping_id, image_digest, scanner_uuid, stored_at)
             VALUES ('f1', 'map-1', 'sha256:d', 'uuid-1', 1)",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        let insert = |cve: &'static str, package: &'static str| {
            sqlx::query(
                "INSERT INTO scanner_findings (report_id, cve_id, package, severity)
                 VALUES ('f1', ?, ?, 'HIGH')",
            )
            .bind(cve)
            .bind(package)
        };
        insert("CVE-1", "pkg")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        // The same CVE in another package is a separate finding.
        insert("CVE-1", "other")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert!(insert("CVE-1", "pkg").execute(&pool).await.is_err());
        assert!(
            sqlx::query("INSERT INTO scanner_findings (report_id, cve_id, severity) VALUES ('f1', 'CVE-2', 'SEVERE')")
                .execute(&pool)
                .await
                .is_err(),
            "unknown severity accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn scanner_key_is_per_base_url() -> Result<(), AppError> {
        let pool = pool_at(None).await?;
        let scanner = |base: &'static str, name: &'static str| HarborScannerUpsert {
            harbor_base_url: base,
            uuid: "uuid-1",
            name,
            vendor: Some("Aqua"),
            version: Some("0.1"),
            disabled: false,
            seen_at: 10,
        };
        upsert_scanner(&pool, &scanner("https://a.example.com", "Trivy")).await?;
        upsert_scanner(&pool, &scanner("https://b.example.com", "Trivy")).await?;
        // A second read of the same registration updates the row, it does not add one.
        upsert_scanner(
            &pool,
            &HarborScannerUpsert {
                disabled: true,
                seen_at: 20,
                ..scanner("https://a.example.com", "Trivy renamed")
            },
        )
        .await?;
        assert_eq!(
            count_rows(&pool, "SELECT COUNT(*) FROM harbor_scanners").await?,
            2
        );
        let rows = list_scanners(&pool, "https://a.example.com").await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "Trivy renamed");
        assert!(rows[0].disabled);
        assert_eq!(rows[0].last_seen_at, 20);
        assert_eq!(rows[0].removed_at, None);
        Ok(())
    }

    #[tokio::test]
    async fn project_lock_is_held_by_one_job_at_a_time() -> Result<(), AppError> {
        let pool = pool_at(None).await?;
        seed_mapping(&pool).await?;
        insert_sync_job(&pool, "job-1").await?;
        insert_sync_job(&pool, "job-2").await?;
        let lock = |job: &'static str| NewProjectLock {
            job_id: job,
            mapping_id: Some("map-1"),
            chosen_scanner_uuid: "uuid-1",
            previous_scanner_uuid: None,
            state: "switched",
            acquired_at: 5,
        };
        let base = "https://harbor.example.com";
        assert!(try_acquire_project_lock(&pool, base, "project", &lock("job-1")).await?);
        assert!(!try_acquire_project_lock(&pool, base, "project", &lock("job-2")).await?);
        // Another project is a separate lock.
        assert!(try_acquire_project_lock(&pool, base, "other", &lock("job-2")).await?);
        let held = get_project_lock(&pool, base, "project").await?;
        assert_eq!(held.map(|row| row.job_id), Some("job-1".to_string()));
        // Only the holder releases it.
        assert!(!release_project_lock(&pool, base, "project", "job-2").await?);
        assert!(release_project_lock(&pool, base, "project", "job-1").await?);
        assert!(get_project_lock(&pool, base, "project").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_mapping_removes_its_scanner_rows() -> Result<(), AppError> {
        let pool = pool_at(None).await?;
        seed_mapping(&pool).await?;
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        replace_report(
            &mut conn,
            &report("r1", "sha256:e", "uuid-1"),
            &[finding("CVE-1", "pkg", "HIGH")],
        )
        .await?;
        drop(conn);
        sqlx::query("DELETE FROM repo_mappings WHERE id = 'map-1'")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(
            count_rows(&pool, "SELECT COUNT(*) FROM scanner_reports").await?,
            0
        );
        assert_eq!(
            count_rows(&pool, "SELECT COUNT(*) FROM scanner_findings").await?,
            0
        );
        Ok(())
    }
}
