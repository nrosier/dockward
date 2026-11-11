//! SQL for the `job_runs` table (`specs/database.md`). One row per housekeeping run
//! (`cleanup`, `retention`, `poll`). Rows hold counts and error text only, never secrets.

use sqlx::SqlitePool;

use crate::error::AppError;

/// One finished run. `error_summary` is `None` when `status` is `done`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRun {
    pub id: String,
    /// `cleanup`, `retention` or `poll`.
    pub job_kind: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    /// `done` or `failed`.
    pub status: String,
    pub processed_count: i64,
    pub error_summary: Option<String>,
    /// `trivy` or `grype` for a `db_update` run; `None` for every other kind.
    pub scanner: Option<String>,
}

/// Stores one run.
pub async fn insert(pool: &SqlitePool, run: &JobRun) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO job_runs
            (id, job_kind, started_at, finished_at, status, processed_count, error_summary, scanner)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        run.id,
        run.job_kind,
        run.started_at,
        run.finished_at,
        run.status,
        run.processed_count,
        run.error_summary,
        run.scanner
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Stores one run and the job it was recorded for (#308). The job link is set in the same insert.
pub async fn insert_for_job(pool: &SqlitePool, run: &JobRun, job_id: &str) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO job_runs
            (id, job_kind, started_at, finished_at, status, processed_count, error_summary, scanner, job_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        run.id,
        run.job_kind,
        run.started_at,
        run.finished_at,
        run.status,
        run.processed_count,
        run.error_summary,
        run.scanner,
        job_id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// How many characters of `error_summary` a read returns. The text is untrusted and may be
/// long, so the cut is made in SQL and a long text never leaves the database.
pub const MAX_ERROR_CHARS: i64 = 500;

/// One run as `GET /admin/jobs` returns it. `error_summary` is cut to [`MAX_ERROR_CHARS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRunView {
    pub id: String,
    pub job_kind: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub processed_count: i64,
    pub error_summary: Option<String>,
    pub scanner: Option<String>,
    /// The job the run was recorded for (#308), or `None` when it has none.
    pub job_id: Option<String>,
}

/// One page of runs, newest first (`ascending` flips it). `kind` is `None` for every kind.
/// The caller has checked `kind` against the allow-list.
pub async fn list(
    pool: &SqlitePool,
    kind: Option<&str>,
    ascending: bool,
    limit: i64,
    offset: i64,
) -> Result<Vec<JobRunView>, AppError> {
    let sign: i64 = if ascending { 1 } else { -1 };
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", job_kind AS "job_kind!", started_at AS "started_at!: i64",
                  finished_at AS "finished_at?: i64", status AS "status!",
                  processed_count AS "processed_count!: i64",
                  substr(CAST(error_summary AS TEXT), 1, ?) AS "error_summary?: String",
                  scanner AS "scanner?: String",
                  job_id AS "job_id?: String"
           FROM job_runs
           WHERE (? IS NULL OR job_kind = ?)
           ORDER BY
             CASE WHEN ? = 1 THEN started_at END ASC,
             CASE WHEN ? = -1 THEN started_at END DESC,
             id ASC
           LIMIT ? OFFSET ?"#,
        MAX_ERROR_CHARS,
        kind,
        kind,
        sign,
        sign,
        limit,
        offset
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| JobRunView {
            id: row.id,
            job_kind: row.job_kind,
            started_at: row.started_at,
            finished_at: row.finished_at,
            status: row.status,
            processed_count: row.processed_count,
            error_summary: row.error_summary,
            scanner: row.scanner,
            job_id: row.job_id,
        })
        .collect())
}

/// Counts runs for the same filter as [`list`].
pub async fn count(pool: &SqlitePool, kind: Option<&str>) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM job_runs WHERE (? IS NULL OR job_kind = ?)"#,
        kind,
        kind
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}
