//! Queue operations on `jobs` (`specs/backend.md`, Durable job queue).
//! Times are Unix seconds, matching `unixepoch()` in the schema.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// A job the worker can take. `payload` is the validated event, with no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedJob {
    pub id: String,
    pub source_id: Option<String>,
    pub attempts: i64,
    pub payload: String,
}

/// Adds a queued job for a source. `payload` must hold no secrets.
pub async fn enqueue(
    pool: &SqlitePool,
    id: &str,
    source_id: Option<&str>,
    payload: &str,
    now: i64,
) -> Result<(), AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    enqueue_in(&mut conn, id, source_id, payload, now).await
}

/// [`enqueue`] on a connection the caller holds, so the insert can join a transaction (the
/// resolve fan-out, #132).
pub async fn enqueue_in(
    conn: &mut SqliteConnection,
    id: &str,
    source_id: Option<&str>,
    payload: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO jobs (id, source_id, status, attempts, next_attempt_at, payload, created_at, updated_at)
         VALUES (?, ?, 'queued', 0, ?, ?, ?, ?)",
        id,
        source_id,
        now,
        payload,
        now,
        now
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Marks a job `done` only while it is still `running`. Returns the rows changed: zero means
/// the job is no longer running (it was re-queued, failed, or deleted), and the caller must
/// not act on its result. Runs on the caller's connection, inside its transaction.
pub async fn finish_running_in(
    conn: &mut SqliteConnection,
    id: &str,
    now: i64,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE jobs SET status = 'done', last_error = NULL, updated_at = ?
         WHERE id = ? AND status = 'running'",
        now,
        id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Latest deferral: a deferred job is due at most this many seconds after `now`.
pub const MAX_DEFERRAL_SECS: i64 = 60 * 60;

/// Moves each `running` job back to `queued`. The interrupted run counts as one attempt
/// (`specs/backend.md`, Durable job queue). When that attempt is the eighth, the job becomes
/// `failed` instead, with `last_error` set. The limit of 8 is `services::jobs::MAX_ATTEMPTS`;
/// this layer does not depend on services, so the value is written here too.
/// Returns how many jobs were re-queued or failed.
pub async fn requeue_running(pool: &SqlitePool, now: i64) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE jobs SET
            attempts = attempts + 1,
            status = CASE WHEN attempts + 1 >= 8 THEN 'failed' ELSE 'queued' END,
            next_attempt_at = CASE WHEN attempts + 1 >= 8 THEN NULL ELSE ? END,
            last_error = CASE WHEN attempts + 1 >= 8 THEN 'interrupted by restart' ELSE last_error END,
            updated_at = ?
         WHERE status = 'running'",
        now,
        now
    )
    .execute(pool)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Puts a job back in `queued` after a deferral. `attempts` and `last_error` are unchanged.
/// `next_attempt_at` is `until`, capped at `MAX_DEFERRAL_SECS` after `now`. Returns the
/// capped time the job is due.
pub async fn defer(pool: &SqlitePool, id: &str, until: i64, now: i64) -> Result<i64, AppError> {
    let next_attempt_at = until.min(now.saturating_add(MAX_DEFERRAL_SECS));
    sqlx::query!(
        "UPDATE jobs SET status = 'queued', next_attempt_at = ?, updated_at = ? WHERE id = ?",
        next_attempt_at,
        now,
        id
    )
    .execute(pool)
    .await
    .map(|_| next_attempt_at)
    .map_err(|_| AppError::InternalError)
}

/// Claims the oldest queued job that is due. The row becomes `running` in the same
/// statement, so two workers cannot take the same job. Returns `None` when nothing is due.
pub async fn claim_next(pool: &SqlitePool, now: i64) -> Result<Option<ClaimedJob>, AppError> {
    let row = sqlx::query!(
        r#"UPDATE jobs SET status = 'running', updated_at = ?
           WHERE id = (
               SELECT id FROM jobs
               WHERE status = 'queued' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
               ORDER BY next_attempt_at, created_at
               LIMIT 1
           )
           RETURNING id AS "id!", source_id AS "source_id?: String", attempts AS "attempts!: i64", payload AS "payload!""#,
        now,
        now
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| ClaimedJob {
        id: row.id,
        source_id: row.source_id,
        attempts: row.attempts,
        payload: row.payload,
    }))
}

/// Marks a job `done` after a successful run.
pub async fn mark_done(pool: &SqlitePool, id: &str, now: i64) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE jobs SET status = 'done', last_error = NULL, updated_at = ? WHERE id = ?",
        now,
        id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Marks a job `done` and stores a fixed note in `last_error`, so the Jobs view can say why
/// nothing was queued.
pub async fn mark_done_with_note(
    pool: &SqlitePool,
    id: &str,
    note: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE jobs SET status = 'done', last_error = ?, updated_at = ? WHERE id = ?",
        note,
        now,
        id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Records a failed attempt. `attempts` is the new total (the job's previous count plus
/// one). `status` is `queued` with `next_attempt_at` set, or `failed` when `give_up` is set.
pub async fn record_failure(
    conn: &mut SqliteConnection,
    id: &str,
    attempts: i64,
    next_attempt_at: Option<i64>,
    last_error: &str,
    give_up: bool,
    now: i64,
) -> Result<(), AppError> {
    let status = if give_up { "failed" } else { "queued" };
    sqlx::query!(
        "UPDATE jobs SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
         WHERE id = ?",
        status,
        attempts,
        next_attempt_at,
        last_error,
        now,
        id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Resets a `failed` job for another run: `queued`, `attempts` 0, no error, due now.
/// Returns the rows changed. Zero means the job was not `failed`. It takes a connection so
/// the caller can run the reset and its audit row in one transaction.
pub async fn reset_failed(
    conn: &mut SqliteConnection,
    id: &str,
    now: i64,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE jobs SET status = 'queued', attempts = 0, last_error = NULL, next_attempt_at = ?, updated_at = ?
         WHERE id = ? AND status = 'failed'",
        now,
        now,
        id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Counts the `failed` jobs a purge would delete, in scope. `all_users` covers every job;
/// otherwise only the jobs of the sources of `user_id`.
pub async fn count_purgeable_failed(
    pool: &SqlitePool,
    user_id: &str,
    all_users: bool,
) -> Result<i64, AppError> {
    let all = i64::from(all_users);
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n: i64" FROM jobs
         WHERE status = 'failed'
           AND (? = 1 OR source_id IN (SELECT id FROM image_sources WHERE user_id = ?))"#,
        all,
        user_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Deletes the `failed` jobs in scope and returns the row count.
/// The state is checked in this statement, so a job retried meanwhile is kept. It takes a
/// connection so the caller can run the delete and its audit row in one transaction.
pub async fn delete_purgeable_failed(
    conn: &mut SqliteConnection,
    user_id: &str,
    all_users: bool,
) -> Result<u64, AppError> {
    let all = i64::from(all_users);
    sqlx::query!(
        "DELETE FROM jobs
         WHERE status = 'failed'
           AND (? = 1 OR source_id IN (SELECT id FROM image_sources WHERE user_id = ?))",
        all,
        user_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// The user who owns the source of a job. The outer `None` means the job does not exist; the
/// inner `None` means it has no source (a `db_update` job), which no tenant owns.
pub async fn owner_of_job(pool: &SqlitePool, id: &str) -> Result<Option<Option<String>>, AppError> {
    let row = sqlx::query!(
        "SELECT m.user_id AS \"user_id?: String\" FROM jobs j
         LEFT JOIN image_sources m ON m.id = j.source_id
         WHERE j.id = ?",
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| row.user_id))
}

/// How many characters of `last_error`, of each payload field and of each report text field
/// (`image_tag`, `image_digest`, `commit_sha`) a read returns. The text is untrusted and may be
/// long, so the cut is made in SQL.
pub const MAX_TEXT_CHARS: i64 = 500;

/// One job with its newest linked report, as the read routes need it. Times are Unix
/// seconds. `last_error` and the payload fields are already cut to [`MAX_TEXT_CHARS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
    pub id: String,
    pub source_id: Option<String>,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    /// `payload.trigger`, or `None` when the payload has none.
    pub trigger: Option<String>,
    /// `payload.kind`, or `None` when the payload has none (a job).
    pub kind: Option<String>,
    pub repo_full_name: Option<String>,
    pub tag: Option<String>,
    pub digest: Option<String>,
    pub report: Option<ReportRow>,
}

/// The `publish_reports` row linked to a job. `error_message` is not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRow {
    pub image_tag: String,
    pub image_digest: String,
    pub commit_sha: Option<String>,
    /// JSON text, for example `{"critical": 0, "high": 2}`.
    pub vulnerability_summary: String,
    pub sarif_status: String,
    pub synced_at: Option<i64>,
}

/// Filters and paging for [`list_jobs`] and [`count_jobs`]. Every filter is optional.
/// `sort` is a fixed key chosen by the service from an allow-list.
pub struct JobFilter<'a> {
    /// `None` lists every user's jobs (admin `scope=all`).
    pub user_id: Option<&'a str>,
    pub id: Option<&'a str>,
    pub status: Option<&'a str>,
    pub source_id: Option<&'a str>,
    pub sort: &'a str,
    pub sort_sign: i64,
    pub limit: i64,
    pub offset: i64,
}

/// One page of jobs with their newest linked report (the highest `rowid` for the job).
/// `ORDER BY` uses CASE terms, so every sort key stays a compile-checked query.
pub async fn list_jobs(pool: &SqlitePool, filter: &JobFilter<'_>) -> Result<Vec<JobRow>, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    list_jobs_in(&mut conn, filter).await
}

/// [`list_jobs`] on a connection the caller holds, so a read can run inside a transaction.
pub async fn list_jobs_in(
    conn: &mut SqliteConnection,
    filter: &JobFilter<'_>,
) -> Result<Vec<JobRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT j.id AS "id!", j.source_id AS "source_id?: String", j.status AS "status!",
                  j.attempts AS "attempts!: i64", j.next_attempt_at AS "next_attempt_at?: i64",
                  substr(CAST(j.last_error AS TEXT), 1, ?) AS "last_error?: String",
                  j.created_at AS "created_at?: i64", j.updated_at AS "updated_at?: i64",
                  CASE WHEN json_valid(j.payload)
                       THEN substr(CAST(json_extract(j.payload, '$.trigger') AS TEXT), 1, ?) END AS "trigger?: String",
                  CASE WHEN json_valid(j.payload)
                       THEN substr(CAST(json_extract(j.payload, '$.kind') AS TEXT), 1, ?) END AS "kind?: String",
                  CASE WHEN json_valid(j.payload)
                       THEN substr(CAST(json_extract(j.payload, '$.repo_full_name') AS TEXT), 1, ?) END AS "repo_full_name?: String",
                  CASE WHEN json_valid(j.payload)
                       THEN substr(CAST(json_extract(j.payload, '$.tag') AS TEXT), 1, ?) END AS "tag?: String",
                  CASE WHEN json_valid(j.payload)
                       THEN substr(CAST(json_extract(j.payload, '$.digest') AS TEXT), 1, ?) END AS "digest?: String",
                  substr(CAST(r.image_tag AS TEXT), 1, ?) AS "report_image_tag?: String",
                  substr(CAST(r.image_digest AS TEXT), 1, ?) AS "report_image_digest?: String",
                  substr(CAST(r.commit_sha AS TEXT), 1, ?) AS "report_commit_sha?: String",
                  r.vulnerability_summary AS "report_summary?",
                  r.sarif_status AS "report_sarif_status?",
                  r.synced_at AS "report_synced_at?: i64"
           FROM jobs j
           LEFT JOIN image_sources m ON m.id = j.source_id
           LEFT JOIN publish_reports r
             ON r.rowid = (SELECT MAX(r2.rowid) FROM publish_reports r2 WHERE r2.job_id = j.id)
           WHERE (? IS NULL OR m.user_id = ?)
             AND (? IS NULL OR j.id = ?)
             AND (? IS NULL OR j.status = ?)
             AND (? IS NULL OR j.source_id = ?)
           ORDER BY
             CASE WHEN ? = 'created_at' AND ? = 1 THEN j.created_at END ASC,
             CASE WHEN ? = 'created_at' AND ? = -1 THEN j.created_at END DESC,
             CASE WHEN ? = 'updated_at' AND ? = 1 THEN j.updated_at END ASC,
             CASE WHEN ? = 'updated_at' AND ? = -1 THEN j.updated_at END DESC,
             j.id ASC
           LIMIT ? OFFSET ?"#,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        MAX_TEXT_CHARS,
        filter.user_id,
        filter.user_id,
        filter.id,
        filter.id,
        filter.status,
        filter.status,
        filter.source_id,
        filter.source_id,
        filter.sort,
        filter.sort_sign,
        filter.sort,
        filter.sort_sign,
        filter.sort,
        filter.sort_sign,
        filter.sort,
        filter.sort_sign,
        filter.limit,
        filter.offset
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let report = match (
                row.report_image_tag,
                row.report_image_digest,
                row.report_summary,
                row.report_sarif_status,
            ) {
                (Some(image_tag), Some(image_digest), Some(vulnerability_summary), Some(sarif)) => {
                    Some(ReportRow {
                        image_tag,
                        image_digest,
                        commit_sha: row.report_commit_sha,
                        vulnerability_summary,
                        sarif_status: sarif,
                        synced_at: row.report_synced_at,
                    })
                }
                _ => None,
            };
            JobRow {
                id: row.id,
                source_id: row.source_id,
                status: row.status,
                attempts: row.attempts,
                next_attempt_at: row.next_attempt_at,
                last_error: row.last_error,
                created_at: row.created_at,
                updated_at: row.updated_at,
                trigger: row.trigger,
                kind: row.kind,
                repo_full_name: row.repo_full_name,
                tag: row.tag,
                digest: row.digest,
                report,
            }
        })
        .collect())
}

/// Counts jobs for the same `user_id`, `status` and `source_id` filters as [`list_jobs`].
pub async fn count_jobs(
    pool: &SqlitePool,
    user_id: Option<&str>,
    status: Option<&str>,
    source_id: Option<&str>,
) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM jobs j
           LEFT JOIN image_sources m ON m.id = j.source_id
           WHERE (? IS NULL OR m.user_id = ?)
             AND (? IS NULL OR j.status = ?)
             AND (? IS NULL OR j.source_id = ?)"#,
        user_id,
        user_id,
        status,
        status,
        source_id,
        source_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// The status and update time of a source's most recently updated job, if it has one.
pub async fn latest_for_source(
    pool: &SqlitePool,
    source_id: &str,
) -> Result<Option<(String, Option<i64>)>, AppError> {
    let row = sqlx::query!(
        r#"SELECT status AS "status!", updated_at AS "updated_at?: i64"
           FROM jobs WHERE source_id = ?
           ORDER BY updated_at DESC, rowid DESC
           LIMIT 1"#,
        source_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|row| (row.status, row.updated_at)))
}

/// One job with its newest linked report, by id, with no tenancy filter. The caller has
/// already checked ownership.
pub async fn find(pool: &SqlitePool, id: &str) -> Result<Option<JobRow>, AppError> {
    let filter = JobFilter {
        user_id: None,
        id: Some(id),
        status: None,
        source_id: None,
        sort: "created_at",
        sort_sign: -1,
        limit: 1,
        offset: 0,
    };
    Ok(list_jobs(pool, &filter).await?.into_iter().next())
}

/// Like [`find`], on a connection the caller already holds, so the read runs inside its
/// transaction.
pub async fn find_in(conn: &mut SqliteConnection, id: &str) -> Result<Option<JobRow>, AppError> {
    let filter = JobFilter {
        user_id: None,
        id: Some(id),
        status: None,
        source_id: None,
        sort: "created_at",
        sort_sign: -1,
        limit: 1,
        offset: 0,
    };
    Ok(list_jobs_in(conn, &filter).await?.into_iter().next())
}
