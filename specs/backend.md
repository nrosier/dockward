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

- The webhook handler validates the request, stores a `sync_jobs` row, and returns.
- An in-process worker runs jobs with retries and exponential backoff.
- Jobs survive restarts.
- Decided: 2026-11-02. A job left in `running` at startup is re-queued: `status` is set back to `queued` and `attempts` is unchanged.
- `sync_jobs.payload` contains the validated event only. No tokens or header secrets.
- Retry state is held in `attempts`, `next_attempt_at`, and `last_error`.
- Decided (2026-11-03, delegated): retry constants: base delay 30 seconds, doubling after each failed attempt (30 s, 60 s, 120 s, and so on), capped at 1 hour, at most 8 attempts, then `status` is `failed`. Decided (2026-11-03, delegated): no external source; tune in deployment.
- Decided (2026-11-03, delegated): after failure number n (n = attempts, counted after the failure), `next_attempt_at` = now + min(30 s x 2^(n-1), 1 hour) while n < 8. Delays after failures 1 to 7 are 30 s, 60 s, 120 s, 240 s, 480 s, 960 s, and 1920 s. The 8th failure sets `status` to `failed` and schedules nothing. The 1-hour cap therefore does not apply under the 8-attempt limit; it stays as a guard if the limit changes.
- Decided (2026-11-03, delegated): manual retry (`POST /api/v1/sync-jobs/:id/retry`) sets `status` to `queued`, resets `attempts` to 0, clears `last_error`, and sets `next_attempt_at` to now. See [api.md](api.md).

## Process lifecycle

- Decided (2026-11-03): the binary handles SIGTERM and Ctrl+C itself, through Axum's `with_graceful_shutdown` and the Tokio `signal` feature. It does not rely on an init process to deliver or act on signals. `--init` or `init: true` stays recommended for reaping child processes.
- On a signal it stops accepting connections, finishes in-flight requests, and stops the worker from taking new jobs. Decided (2026-11-03, delegated): drain for at most 8 seconds, inside Docker's default 10-second stop timeout, then exit. A job still `running` at exit is re-queued at the next startup (see "Durable job queue").

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
