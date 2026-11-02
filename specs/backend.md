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
