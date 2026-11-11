# Backend

Purpose: backend module layout, service boundaries, the durable job queue, error handling, and Rust dev rules for dockward 0.2.0.

## Module layout

Under `backend/src/`, as built:

- `main.rs`: the router (every route in [api.md](api.md)) and startup.
- `config.rs`: settings from `DOCKWARD_*` environment variables, with the deprecated `HARBORGATE_*` fallback (release 0.2 only).
- `error.rs`: `AppError` and its `IntoResponse` mapping.
- `api/`: handlers. For example `auth.rs`, `oidc.rs`, `credentials.rs`, `sources.rs`, `hubs.rs`, `scan.rs`, `scan_settings.rs`, `jobs.rs`, `dashboard.rs`, `cves.rs`, `admin.rs`, `github_url.rs`, `hardening.rs`, `static_files.rs`.
- `auth/`: `crypto.rs` (AES-GCM and the HKDF labels), `csrf.rs`, `session.rs`.
- `db/`: SQLx queries, one module per table group (`sources.rs`, `hubs.rs`, `storage.rs`, `scans.rs`, `findings.rs`, `publish.rs`, `jobs.rs`, `job_runs.rs`, `retention.rs`, `github_issues.rs`, `acceptances.rs`, `backup.rs`, `key_rotation.rs`, and others).
- `services/`: business logic. The subdirectories are `discovery/`, `registry/`, `storage/`, `scan/`, `scanner/`, and `publish/`. Top-level modules include `jobs.rs`, `job_runs.rs`, `sarif.rs`, `github_issues.rs`, `github_scanning.rs`, `issue_lifecycle.rs`, `merged_view.rs`, `retention.rs`, `backup.rs`, `alerts.rs`, `alert_send.rs`, and `app_log.rs`.
- `worker/`: the one job loop.
- `migrations/0001_init.sql`: the only migration. It is the schema reference ([database.md](database.md)).

## Boundaries

- Business logic (discovery, the registry client, storage, scanning, SARIF, and the GitHub clients) lives in `services/`.
- Handlers live in `api/`. They validate input and call services.
- Database operations live in `db/`.

## Durable job queue

Decided (spinoff 58): the units of work are `discover`, `pull`, `scan`, `publish`, and `db_update`. Nothing else is queued. The table is `jobs`. `jobs.source_id` is NULL for a `db_update` job. The kind is in `payload`. `payload` holds ids and the tag only, never a token or a secret.

`job_runs` holds housekeeping history with kinds `cleanup`, `retention`, `discover`, and `db_update` (`backend/src/services/job_runs.rs`).

Outcomes. A job handler returns one of three outcomes:

- **Success**: the job is `done`.
- **Failure**: the job uses one attempt and follows the backoff below.
- **Deferred** until a time: the job returns to `queued` with `next_attempt_at` set, and `attempts` is unchanged. This is for a registry `429`, using its `Retry-After` header, capped at 1 hour (spinoff section 3).

Retry constants (Decided 2026-11-03, delegated; `backend/src/services/jobs.rs`):

- Base delay 30 seconds, doubling after each failed attempt, capped at 1 hour.
- At most 8 attempts. After failure number n (n < 8), `next_attempt_at` = now + min(30 s × 2^(n-1), 1 h). The delays after failures 1 to 7 are 30 s, 60 s, 120 s, 240 s, 480 s, 960 s, and 1920 s.
- The 8th failure sets `status` to `failed` and schedules nothing.

Other rules (Decided 2026-11-03, user or delegated, carried over from HarborGate):

- A job left `running` at startup is re-queued, and the restart counts as an attempt. On the 8th attempt it becomes `failed` with `last_error` `interrupted by restart`.
- On every worker loop iteration, a `running` job is re-queued the same way. No job is in flight at that point, because the worker awaits each handler before it takes the next step.
- A handler panic fails only its own job, with `last_error` `job handler panicked`. The worker continues.
- A write after the handler (`mark_done`, a failure record, or a deferral) that fails is retried 3 times, 1 second apart, before the worker returns the error. That is 4 writes in total.
- The worker claims one job at a time. A scan is one scanner process at a time. Rescans queue behind pulls and scans.
- Docker Hub refuses an anonymous pull for its rate limit: that is a failure with the fixed `last_error` `docker hub rate limit reached`, and it follows the backoff. It is not a deferral (spinoff section 6, decision 40).

Manual retry (`POST /api/v1/jobs/:id/retry`): sets `status` to `queued`, resets `attempts` to 0, clears `last_error`, and sets `next_attempt_at` to now. The job must be `failed` (`409` otherwise). The source's owner may retry it, and an admin may retry any tenant's job. Retry only re-queues work.

Purge (`POST /api/v1/jobs/purge-failed`): deletes `failed` rows in the caller's scope, in one transaction with its audit entry. Rules are in [api.md](api.md).

Retention: finished jobs and `job_runs` are kept 90 days. `alert_deliveries` are kept 30 days. `audit_log` is kept 365 days. `images`, `tag_observations`, and `image_platforms` are not under age retention. The table decisions are in [database.md](database.md).

Eviction and scans: a layout with a `queued` or `running` scan is never evicted, and neither is the image just pulled. A scan starts only if it can move its run to `running` while the image is `stored` (spinoff section 4).

## Process lifecycle

- The binary handles SIGTERM and Ctrl+C itself, through Axum's `with_graceful_shutdown` and the Tokio `signal` feature. `--init` or `init: true` stays recommended for reaping child processes.
- On a signal it stops accepting connections, finishes in-flight requests, and stops the worker from taking new jobs. It drains for at most 8 seconds, inside Docker's default 10-second stop timeout, then exits. A job still `running` at exit is re-queued at the next startup.
- At startup, a directory under `images/` with no `stored` or `evicting` row, and everything in `images/.tmp`, is deleted. An `evicting` row is completed (spinoff section 4).

## Application log

Decided (2026-11-05, user, #136). Rules are in [security.md](security.md), "Application log"; routes are in [api.md](api.md), Admin.

- `services/app_log.rs` owns the application log: the `tracing` layer that copies each event into a bounded in-memory ring buffer (500 lines, 1000 characters per line, secret-named fields dropped), and the level controller.
- `main.rs` installs one subscriber: a reloadable filter in front of the stdout formatter and the buffer layer. The filter starts at `info` for every target and ignores `RUST_LOG`. A level change sets `dockward` to the chosen level and keeps every other crate at `info`.
- Raising the level above `info` starts a timer that reverts to `info` after 30 minutes. A later change replaces it. The revert writes `log.level_change` with the actor `system`.
- The outbound registry and GitHub send sites call one helper that logs, at `debug`, the method, the URL path, and the status code. It logs only `url.path()`, so the query string and userinfo never reach the log.

## Error handling

- Use `Result<T, AppError>` and implement `IntoResponse` for `AppError`.
- No `unwrap()` or `expect()` in non-test code.
- Errors shown to users and in logs must be clear. Never include secrets in error text. A job's `last_error`, an alert, and the Jobs API carry only the fixed strings of spinoff section 6, never a registry body, URL, header, or scanner stderr.

## Database access

- Prefer compile-time checked `sqlx::query!` macros.
- Use `SqlitePool`. Keep async safety on the connection pool.
- After changing a query or a migration, run `cargo sqlx prepare`.
- Every connection sets `PRAGMA foreign_keys = ON`.

## SARIF

- Converted output must conform to SARIF 2.1.0 as expected by `POST /repos/{owner}/{repo}/code-scanning/sarifs`. See [integrations.md](integrations.md).
- Result keys and categories: see the CONFLICT below.

## Dev rules

1. Errors: `Result<T, AppError>` with `IntoResponse`. No `unwrap()` or `expect()` in non-test code.
2. Database: `sqlx::query!` where possible. `SqlitePool` for async safety.
3. SARIF: strict SARIF 2.1.0.
4. Decoupling: services in `services/`, handlers in `api/`, DB in `db/`.
5. Secrets: never in logs or Server-Sent Events streams. See [security.md](security.md).
6. Key material in memory: keys, derived keys, and decoded key bytes are zeroed on drop with the `zeroize` crate (Decided 2026-11-03).
7. Edition: the crate uses the Rust 2024 edition (Decided 2026-11-03). UNVERIFIED in this pass.

## CONFLICT

- CONFLICT: names. Decision 54 (2026-11-10) renames every name to `dockward`, including the issue marker (`dockward:<CVE id>`) and the Code Scanning category prefix. Decision 46 keeps `harborgate/<hub host>/<repository>/<tag>` as the category. The code at `origin/main` still uses the marker `<!-- harborgate:<CVE id> -->` (`backend/src/services/github_issues.rs`) and the SARIF keys `harborgate/v1`, `harborgate/scannerCount`, `harborgate/scannerNames`, and `harborgate/platforms` (`backend/src/services/sarif.rs`). Unresolved. Renaming the category or the marker creates new alerts or re-keys issues, so the user must decide.
