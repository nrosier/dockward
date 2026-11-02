# HarborGate Development Guide

HarborGate is a local-first, multi-tenant security relay. It receives container vulnerability reports from Harbor (webhooks, with polling as backup), converts Trivy reports to SARIF 2.1.0, and pushes them to GitHub Code Scanning and Issues. The backend is Rust (Axum, SQLx on SQLite); the frontend is React and TypeScript (Vite). It ships as a single Docker container.

Status: in development. Only the skeleton exists (`backend/src/main.rs`, a stub React app). No features are implemented yet.

## Specs

This file is the general guide. Detailed build specifications live in [`specs/`](specs/README.md). Read the relevant spec before changing a component.

- [specs/README.md](specs/README.md): index and spec rules.
- [specs/architecture.md](specs/architecture.md): components, data flow, single-instance decision, tech stack.
- [specs/database.md](specs/database.md): schema reference and table decisions.
- [specs/backend.md](specs/backend.md): modules, durable job queue, error handling, dev rules.
- [specs/security.md](specs/security.md): encryption, key rotation, backup and restore, auth, sessions, hardening, tenancy.
- [specs/integrations.md](specs/integrations.md): Harbor webhook, Harbor API, polling, OCI labels, GitHub SARIF and issues.
- [specs/cve-lifecycle.md](specs/cve-lifecycle.md): per-tag CVE tracking, issue open/close/reopen, acceptance, retention.
- [specs/alerts.md](specs/alerts.md): SMTP and webhook alert rules.
- [specs/frontend.md](specs/frontend.md): app shell, pages, visual direction, status pills, i18n, house style.
- [specs/deployment.md](specs/deployment.md): Dockerfile, compose, Traefik, Cloudflare tunnel, volumes, releases.
- [specs/testing-and-ci.md](specs/testing-and-ci.md): test strategy, CI workflows, Renovate, repo hygiene.

## Non-negotiable rules

- Secrets are never logged, printed, traced, or sent over Server-Sent Events. This covers tokens, encryption keys, webhook URL tokens, and webhook auth header values.
- No `.unwrap()` or `.expect()` in non-test Rust code. Return `Result<T, AppError>`.
- Design before build: each frontend screen's design is approved by the user before implementation.
- All user-visible UI text lives in the string catalog. English only for now.
- Precedence: a spec beats the Astraya house style. If they cannot be reconciled, ask the user.
- Uncommitted work: never run `git stash`, `git restore`, `git checkout -- <path>`, `git reset --hard`, or `git clean` on another person's changes. Do not commit unless asked.

## Commands

```bash
# Backend (from backend/)
cargo watch -x run        # dev mode with reload
cargo sqlx prepare        # refresh SQLx offline metadata after query or migration changes
cargo test

# Frontend (from frontend/)
npm run dev               # Vite dev server with backend API proxy
npm run build             # production build

# Container (from repo root)
docker build -t harborgate:latest .
docker run -p 8080:8080 -v harborgate_data:/data harborgate:latest
```

## Repository layout

- `backend/`: Rust crate. `src/api/` (handlers), `src/services/` (Harbor, GitHub, SARIF), `src/db/` (SQL), `src/auth/`, `src/models/`, `src/worker/`, `migrations/`.
- `frontend/`: React app. `src/components/`, `src/pages/`, `src/hooks/`, `src/lib/`, `src/types/`.
- `docs/SETUP.md`: operator setup guide (Harbor, GitHub, connection, restore).
- `.github/`: CI workflows, issue templates, CODEOWNERS.
- `Dockerfile`, `docker-compose.yml`, `renovate.json`, `CHANGELOG.md`, `SECURITY.md`.

## Development rules

1. Errors: `Result<T, AppError>` with Axum's `IntoResponse`. No `unwrap()` or `expect()` outside tests.
2. Database: `sqlx::query!` macros where possible. Use `SqlitePool`.
3. SARIF: output must conform strictly to SARIF 2.1.0.
4. Layering: business logic in `services/`, handlers in `api/`, database access in `db/`.
5. Secrets: never in logs or Server-Sent Events. See the non-negotiable rules above.

## Releases

Create a semver tag `vMAJOR.MINOR.PATCH` and update `CHANGELOG.md` first. Pushing the tag runs the Docker publish job. See [specs/deployment.md](specs/deployment.md).
