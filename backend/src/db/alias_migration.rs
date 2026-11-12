//! Tests for migration 0007, which folds GHSA rows that carry a CVE alias into the CVE's record
//! (#337). Each test builds the schema as of 0006, seeds rows, then applies 0007.

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::error::AppError;

const EARLIER: [&str; 6] = [
    include_str!("../../migrations/0001_init.sql"),
    include_str!("../../migrations/0002_github_rekey.sql"),
    include_str!("../../migrations/0003_job_run_scanner.sql"),
    include_str!("../../migrations/0004_job_log.sql"),
    include_str!("../../migrations/0005_source_name.sql"),
    include_str!("../../migrations/0006_cve_alias.sql"),
];
const ALIASES: &str = include_str!("../../migrations/0007_vulnerability_aliases.sql");

fn fail<E>(_: E) -> AppError {
    AppError::InternalError
}

async fn run(pool: &SqlitePool, sql: &str) -> Result<(), AppError> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(fail)
}

/// A database at the 0006 schema with one user, one source and one scan run.
async fn pool_at_0006() -> Result<SqlitePool, AppError> {
    let options = SqliteConnectOptions::new()
        .in_memory(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(fail)?;
    for sql in EARLIER {
        run(&pool, sql).await?;
    }
    run(
        &pool,
        "INSERT INTO users (id, username, role, auth_provider) VALUES ('u1', 'tester', 'user', 'local');
         INSERT INTO user_credentials (id, user_id, label, encrypted_token) VALUES ('c1', 'u1', 'gh', 'v1:test');
         INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
           VALUES ('s1', 'u1', 'hub-default-ghcr', 'o/r', 'latest', 'c1', 'own', 'rep');
         INSERT INTO images (id, hub_id, repository, digest, is_index) VALUES ('i1', 'hub-default-ghcr', 'o/r', 'sha256:a', 0);
         INSERT INTO image_platforms (id, image_id, platform, platform_digest, state) VALUES ('p1', 'i1', 'linux/amd64', 'sha256:b', 'stored');
         INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status) VALUES ('r1', 'p1', 'grype', 'first_pull', 'done');",
    )
    .await?;
    Ok(pool)
}

async fn strings(pool: &SqlitePool, sql: &str) -> Result<Vec<String>, AppError> {
    let rows: Vec<(String,)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await
        .map_err(fail)?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

/// Every table 0007 touches, as sorted text rows.
async fn snapshot(pool: &SqlitePool) -> Result<Vec<String>, AppError> {
    let mut all = Vec::new();
    for sql in [
        "SELECT alias || '>' || primary_id FROM vulnerability_aliases ORDER BY 1",
        "SELECT id || '|' || source_id || '|' || image_tag || '|' || cve_id || '|' || severity || '|' || COALESCE(first_seen_at, '') || '|' || COALESCE(alias, '') || '|' || COALESCE(github_issue_id, '') FROM cve_findings ORDER BY 1",
        "SELECT run_id || '|' || cve_id || '|' || package || '|' || COALESCE(alias, '') FROM scanner_findings ORDER BY 1",
        "SELECT id || '|' || cve_id || '|' || status FROM github_issues ORDER BY 1",
        "SELECT id || '|' || cve_id || '|' || COALESCE(revoked_at, '') FROM cve_acceptances ORDER BY 1",
    ] {
        all.extend(strings(pool, sql).await?);
    }
    Ok(all)
}

fn finding(
    id: &str,
    tag: &str,
    cve: &str,
    sev: &str,
    seen: i64,
    alias: &str,
    issue: &str,
) -> String {
    format!(
        "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, first_seen_at, alias, github_issue_id)
         VALUES ('{id}', 's1', '{tag}', '{cve}', '{sev}', {seen}, {alias}, {issue});"
    )
}

fn issue(id: &str, cve: &str, number: i64) -> String {
    format!(
        "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url)
         VALUES ('{id}', 'own', 'rep', '{cve}', {number}, 'https://example.test/{number}');"
    )
}

#[tokio::test]
async fn ghsa_with_cve_alias_folds_into_the_cve_row() -> Result<(), AppError> {
    let pool = pool_at_0006().await?;
    let seed = [
        issue("gi-ghsa", "GHSA-aaaa-aaaa-aaaa", 1),
        issue("gi-cve", "CVE-2024-0001", 2),
        finding(
            "f-cve",
            "latest",
            "CVE-2024-0001",
            "MEDIUM",
            200,
            "NULL",
            "'gi-cve'",
        ),
        finding(
            "f-ghsa",
            "latest",
            "GHSA-aaaa-aaaa-aaaa",
            "HIGH",
            100,
            "'CVE-2024-0001'",
            "'gi-ghsa'",
        ),
        // A tag that has only the GHSA row is renamed, and its issue pointer follows the issue.
        finding(
            "f-only",
            "other",
            "GHSA-aaaa-aaaa-aaaa",
            "LOW",
            50,
            "'CVE-2024-0001'",
            "'gi-ghsa'",
        ),
        "INSERT INTO scanner_findings (run_id, cve_id, package, severity, alias) VALUES
           ('r1', 'CVE-2024-0001', 'pkg', 'LOW', NULL),
           ('r1', 'GHSA-aaaa-aaaa-aaaa', 'pkg', 'HIGH', 'CVE-2024-0001'),
           ('r1', 'GHSA-aaaa-aaaa-aaaa', 'pkg2', 'HIGH', 'CVE-2024-0001');"
            .to_owned(),
        "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username) VALUES
           ('a-cve', 's1', 'CVE-2024-0001', 'r', 'tester'),
           ('a-ghsa', 's1', 'GHSA-aaaa-aaaa-aaaa', 'r', 'tester');"
            .to_owned(),
    ]
    .join("\n");
    run(&pool, &seed).await?;

    run(&pool, ALIASES).await?;

    let findings = strings(
        &pool,
        "SELECT id || '|' || image_tag || '|' || cve_id || '|' || severity || '|' || first_seen_at || '|' || COALESCE(alias, '') || '|' || COALESCE(github_issue_id, '') FROM cve_findings ORDER BY id",
    )
    .await?;
    assert_eq!(
        findings,
        vec![
            "f-cve|latest|CVE-2024-0001|HIGH|100|GHSA-aaaa-aaaa-aaaa|gi-cve",
            "f-only|other|CVE-2024-0001|LOW|50|GHSA-aaaa-aaaa-aaaa|gi-cve",
        ]
    );
    assert_eq!(
        strings(
            &pool,
            "SELECT run_id || '|' || cve_id || '|' || package FROM scanner_findings ORDER BY 1"
        )
        .await?,
        vec!["r1|CVE-2024-0001|pkg", "r1|CVE-2024-0001|pkg2"]
    );
    assert_eq!(
        strings(&pool, "SELECT id || '|' || cve_id FROM github_issues").await?,
        vec!["gi-cve|CVE-2024-0001"]
    );
    assert_eq!(
        strings(&pool, "SELECT id || '|' || cve_id FROM cve_acceptances").await?,
        vec!["a-cve|CVE-2024-0001"]
    );
    Ok(())
}

#[tokio::test]
async fn ghsa_without_a_collision_is_renamed_to_the_cve_id() -> Result<(), AppError> {
    let pool = pool_at_0006().await?;
    let seed = [
        issue("gi-ghsa", "GHSA-bbbb-bbbb-bbbb", 7),
        finding(
            "f1",
            "latest",
            "GHSA-bbbb-bbbb-bbbb",
            "HIGH",
            100,
            "'CVE-2024-0002'",
            "'gi-ghsa'",
        ),
        // A GHSA id without a CVE alias is left alone.
        finding(
            "f2",
            "latest",
            "GHSA-zzzz-zzzz-zzzz",
            "LOW",
            100,
            "NULL",
            "NULL",
        ),
        "INSERT INTO scanner_findings (run_id, cve_id, package, severity, alias)
           VALUES ('r1', 'GHSA-bbbb-bbbb-bbbb', 'pkg', 'HIGH', 'CVE-2024-0002');"
            .to_owned(),
        "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username)
           VALUES ('a1', 's1', 'GHSA-bbbb-bbbb-bbbb', 'r', 'tester');"
            .to_owned(),
    ]
    .join("\n");
    run(&pool, &seed).await?;

    run(&pool, ALIASES).await?;

    assert_eq!(
        strings(&pool, "SELECT id || '|' || cve_id || '|' || COALESCE(alias, '') || '|' || COALESCE(github_issue_id, '') FROM cve_findings ORDER BY id").await?,
        vec![
            "f1|CVE-2024-0002|GHSA-bbbb-bbbb-bbbb|gi-ghsa",
            "f2|GHSA-zzzz-zzzz-zzzz||",
        ]
    );
    assert_eq!(
        strings(&pool, "SELECT cve_id || '|' || alias FROM scanner_findings").await?,
        vec!["CVE-2024-0002|GHSA-bbbb-bbbb-bbbb"]
    );
    assert_eq!(
        strings(
            &pool,
            "SELECT id || '|' || cve_id || '|' || github_issue_number FROM github_issues"
        )
        .await?,
        vec!["gi-ghsa|CVE-2024-0002|7"]
    );
    assert_eq!(
        strings(&pool, "SELECT id || '|' || cve_id FROM cve_acceptances").await?,
        vec!["a1|CVE-2024-0002"]
    );
    Ok(())
}

#[tokio::test]
async fn migration_twice_changes_nothing() -> Result<(), AppError> {
    let pool = pool_at_0006().await?;
    let seed = [
        issue("gi-ghsa", "GHSA-aaaa-aaaa-aaaa", 1),
        issue("gi-cve", "CVE-2024-0001", 2),
        finding(
            "f-cve",
            "latest",
            "CVE-2024-0001",
            "MEDIUM",
            200,
            "NULL",
            "'gi-cve'",
        ),
        finding(
            "f-ghsa",
            "latest",
            "GHSA-aaaa-aaaa-aaaa",
            "HIGH",
            100,
            "'CVE-2024-0001'",
            "'gi-ghsa'",
        ),
        finding(
            "f3",
            "latest",
            "GHSA-bbbb-bbbb-bbbb",
            "LOW",
            100,
            "'CVE-2024-0002'",
            "NULL",
        ),
        "INSERT INTO scanner_findings (run_id, cve_id, package, severity, alias) VALUES
           ('r1', 'GHSA-aaaa-aaaa-aaaa', 'pkg', 'HIGH', 'CVE-2024-0001'),
           ('r1', 'GHSA-bbbb-bbbb-bbbb', 'pkg', 'HIGH', 'CVE-2024-0002');"
            .to_owned(),
        "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username) VALUES
           ('a-cve', 's1', 'CVE-2024-0001', 'r', 'tester'),
           ('a-ghsa', 's1', 'GHSA-aaaa-aaaa-aaaa', 'r', 'tester');"
            .to_owned(),
    ]
    .join("\n");
    run(&pool, &seed).await?;

    run(&pool, ALIASES).await?;
    let once = snapshot(&pool).await?;
    assert!(!once.is_empty());
    run(&pool, ALIASES).await?;
    assert_eq!(snapshot(&pool).await?, once);
    Ok(())
}

#[tokio::test]
async fn alias_table_holds_each_ghsa_once() -> Result<(), AppError> {
    let pool = pool_at_0006().await?;
    let seed = [
        finding(
            "f1",
            "latest",
            "GHSA-aaaa-aaaa-aaaa",
            "HIGH",
            1,
            "'CVE-2024-0001'",
            "NULL",
        ),
        finding(
            "f2",
            "other",
            "GHSA-aaaa-aaaa-aaaa",
            "HIGH",
            1,
            "'CVE-2024-0001'",
            "NULL",
        ),
        finding("f3", "latest", "CVE-2024-0009", "HIGH", 1, "NULL", "NULL"),
        finding(
            "f4",
            "latest",
            "GHSA-none-none-none",
            "HIGH",
            1,
            "NULL",
            "NULL",
        ),
        "INSERT INTO scanner_findings (run_id, cve_id, package, severity, alias) VALUES
           ('r1', 'GHSA-aaaa-aaaa-aaaa', 'pkg', 'HIGH', 'CVE-2024-0001'),
           ('r1', 'GHSA-cccc-cccc-cccc', 'pkg', 'HIGH', 'CVE-2024-0003');"
            .to_owned(),
    ]
    .join("\n");
    run(&pool, &seed).await?;

    run(&pool, ALIASES).await?;

    assert_eq!(
        strings(
            &pool,
            "SELECT alias || '>' || primary_id FROM vulnerability_aliases ORDER BY alias"
        )
        .await?,
        vec![
            "GHSA-aaaa-aaaa-aaaa>CVE-2024-0001",
            "GHSA-cccc-cccc-cccc>CVE-2024-0003",
        ]
    );
    Ok(())
}
