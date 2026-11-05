# Backend

Purpose: backend module layout, service boundaries, the durable job queue, error handling, and Rust dev rules.

## Module layout

Planned layout under `backend/src/`:

- `main.rs`
- `api/`: Axum routes and handlers. `auth.rs` (local login, OIDC flow, JWT cookies), `webhooks.rs` (Harbor webhook listener), `mappings.rs` (mapping CRUD), `reports.rs` (scan activity and SARIF logs), `issues.rs` (GitHub issue management).
- `auth/`: Argon2, AES-256-GCM crypto, OIDC claims.
- `db/`: SQLx models and queries.
- `models/`: shared structs and SARIF types.
- `services/`: Harbor API client, GitHub API client, Trivy-to-SARIF converter.
- `worker/`: Tokio background tasks for Harbor polling, the sync job runner, and retention cleanup.
- `migrations/`: SQLx SQLite migrations.

The current `backend/src/main.rs` is the only implemented file. Treat the layout above as the target.

## Boundaries

- Business logic (SARIF conversion, Harbor and GitHub HTTP clients) lives in `services/`.
- Handlers live in `api/`. They validate input and call services.
- Database operations live in `db/`.

## Durable job queue

- The webhook handler validates the request, stores a `sync_jobs` row, and returns. Decided (2026-11-05, user, #132): the row is a sync job (tag present) or a resolve job (untagged, digest only). The handler makes no outbound call.
- An in-process worker runs jobs with retries and exponential backoff.
- Jobs survive restarts.
- Decided (2026-11-03, delegated, #48): a job left in `running` at startup is re-queued and the restart counts as an attempt: `attempts` is incremented. When that attempt is the eighth, `status` becomes `failed` with `last_error` set to `interrupted by restart` and `next_attempt_at` cleared. Otherwise `status` is `queued`.
- Decided (2026-11-03, user, #48): on every worker loop iteration, any `running` job is re-queued the same way, counting one attempt. This recovers a job left `running` by a failed write after the handler. No job is in flight at that point, because the worker awaits each handler before it takes the next step.
- Decided (2026-11-03, delegated, #48): a handler panic fails only its own job, with `last_error` set to `job handler panicked`. The worker continues with the next job.
- Decided (2026-11-03, delegated, #48): a write after the handler (`mark_done`, a failure record, or a deferral) that fails is retried 3 times, 1 second apart, before the worker returns the error. That is 4 writes in total.
- `sync_jobs.payload` contains the validated event only. No tokens or header secrets.
- Retry state is held in `attempts`, `next_attempt_at`, and `last_error`.
- Decided (2026-11-03, user): a job handler returns one of three outcomes: success (the job is `done`), failure (backoff below, one attempt used), or deferred until a time (the job goes back to `queued` with `next_attempt_at` set to that time, capped at now + 1 hour, and `attempts` unchanged). Deferral is only for upstream rate limits ([integrations.md](integrations.md)).
- Decided (2026-11-03, delegated): retry constants: base delay 30 seconds, doubling after each failed attempt (30 s, 60 s, 120 s, and so on), capped at 1 hour, at most 8 attempts, then `status` is `failed`. Decided (2026-11-03, delegated): no external source; tune in deployment.
- Decided (2026-11-03, delegated): after failure number n (n = attempts, counted after the failure), `next_attempt_at` = now + min(30 s x 2^(n-1), 1 hour) while n < 8. Delays after failures 1 to 7 are 30 s, 60 s, 120 s, 240 s, 480 s, 960 s, and 1920 s. The 8th failure sets `status` to `failed` and schedules nothing. The 1-hour cap therefore does not apply under the 8-attempt limit; it stays as a guard if the limit changes.
- Decided (2026-11-05, user, #132): a resolve job uses the same three outcomes, the same retry constants and the same backoff as a sync job. Decided (2026-11-05, user, #132): a Harbor rate limit defers a resolve job like other jobs. The job waits for the Retry-After header Harbor sends, capped at 1 hour (the cap on any deferral, above and in [integrations.md](integrations.md)), and the deferral does not count toward the 8 attempts. Decided (2026-11-05, user, #132): when Harbor sends no Retry-After header, the job defers 5 minutes, the 1-hour cap still applies, and this deferral also does not count toward the 8 attempts. The worker resolves in one `BEGIN IMMEDIATE` transaction: dedupe check, sync job inserts, and the resolve job's `done` mark commit together, after the Harbor lookup has finished. A failed lookup or a digest with no tags is a failure outcome. After the 8th attempt the job is `failed` with a fixed `last_error` and raises the sync-failed alert. Rules and reasons are in [integrations.md](integrations.md), "Responses".
- Decided (2026-11-03, delegated): manual retry (`POST /api/v1/sync-jobs/:id/retry`) sets `status` to `queued`, resets `attempts` to 0, clears `last_error`, and sets `next_attempt_at` to now. See [api.md](api.md).

## Process lifecycle

- Decided (2026-11-03): the binary handles SIGTERM and Ctrl+C itself, through Axum's `with_graceful_shutdown` and the Tokio `signal` feature. It does not rely on an init process to deliver or act on signals. `--init` or `init: true` stays recommended for reaping child processes.
- On a signal it stops accepting connections, finishes in-flight requests, and stops the worker from taking new jobs. Decided (2026-11-03, delegated): drain for at most 8 seconds, inside Docker's default 10-second stop timeout, then exit. A job still `running` at exit is re-queued at the next startup (see "Durable job queue").

## Application log

Decided (2026-11-05, user, #136). Rules are in [security.md](security.md), "Application log"; routes are in [api.md](api.md), Admin.

- `services/app_log.rs` owns the application log: the `tracing` layer that copies each event into a bounded in-memory ring buffer (500 lines, 1000 characters per line, secret-named fields dropped), and the level controller.
- `main.rs` installs one subscriber: a reloadable `Targets` filter in front of the stdout formatter and the buffer layer. The filter starts at `info` for every target and ignores `RUST_LOG`. A level change sets `harborgate` to the chosen level and keeps the default (every other crate) at `info`.
- The level controller holds the reload handle, the current level, and the revert deadline. Raising the level above `info` spawns a Tokio timer; a later change replaces it. The timer duration is a constructor argument (30 minutes in production), so tests inject a short one. The revert writes `log.level_change` with the actor `system`.
- The outbound Harbor and GitHub send sites call one helper that logs, at `debug`, the method, the URL path, and the status code. The helper takes a `Url` and logs only `url.path()`, so the query string and userinfo never reach the log.

## Error handling

- Use `Result<T, AppError>` and implement `IntoResponse` for `AppError`.
- No `unwrap()` or `expect()` in non-test code.
- Errors shown to users and in logs must be clear. Never include secrets in error text.

## Database access

- Prefer compile-time checked `sqlx::query!` macros.
- Use `SqlitePool`. Keep async safety on the connection pool.
- After changing a query or a migration, run `cargo sqlx prepare`.

## SARIF

- Converted output must strictly conform to SARIF 2.1.0 as expected by `POST /repos/{owner}/{repo}/code-scanning/sarifs`. See [integrations.md](integrations.md).

## Dev rules

1. Errors: `Result<T, AppError>` with `IntoResponse`. No `unwrap()` or `expect()` in non-test code.
2. Database: `sqlx::query!` where possible. `SqlitePool` for async safety.
3. SARIF: strict SARIF 2.1.0.
4. Decoupling: services in `services/`, handlers in `api/`, DB in `db/`.
5. Secrets: never in logs or Server-Sent Events streams. See [security.md](security.md).
6. Key material in memory: Decided (2026-11-03): keys, derived keys, and decoded key bytes are zeroed on drop with the `zeroize` crate.
7. Edition: Decided (2026-11-03): the crate uses the Rust 2024 edition.
