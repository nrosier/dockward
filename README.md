# HarborGate

<p align="center">
  <a href="https://github.com/nrosier/harborgate/actions/workflows/docker.yml"><img alt="Docker" src="https://github.com/nrosier/harborgate/actions/workflows/docker.yml/badge.svg"></a>
  <a href="https://github.com/nrosier/harborgate/releases"><img alt="Version" src="https://img.shields.io/github/v/release/nrosier/harborgate"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/nrosier/harborgate"></a>
</p>

HarborGate is a planned local-first, multi-tenant security relay. It receives container vulnerability reports from Harbor, primarily through webhooks with polling as a backup, converts them to the SARIF 2.1.0 format, and pushes them to GitHub Code Scanning. It can also open GitHub Issues for high-severity findings. The backend is written in Rust (Axum) and the frontend in React (Vite and TypeScript).

## Status

**In development.** This repository currently contains only a skeleton: a stub backend (`backend/src/main.rs`) and a stub React app. No features are implemented yet. Nothing described under Features is implemented, runnable, or installable. The commands in the Development section are the planned workflow and will not work until the features are implemented.

## Features

The planned functionality, summarized from the specification:

- **Secure credential storage:** user credentials (GitHub tokens, Harbor robot tokens, OIDC client secrets) are encrypted at rest with AES-256-GCM.
- **Setup and login:** a first-run wizard creates the initial admin account, and OIDC sign-in can be configured from the admin UI. A local break-glass login remains available as a fallback.
- **Role-based access:** admins manage system configuration, users, and global logs. Regular users manage their own credentials, repository mappings, and Sync jobs.
- **Scoped webhook relay:** each repository mapping has its own webhook endpoint. On receipt, HarborGate fetches the vulnerability report from the Harbor REST API and converts Trivy output to SARIF.
- **GitHub delivery:** SARIF is gzipped, Base64-encoded, and submitted to the GitHub code-scanning API. The commit SHA comes only from the `org.opencontainers.image.revision` OCI label; the sync fails if it is missing. The branch comes from `org.opencontainers.image.ref.name` if present, otherwise from the mapping's default branch (default `main`).
- **Optional issue creation:** GitHub Issues are created automatically for CRITICAL and HIGH findings, or triggered manually. `min_issue_severity` defaults to CRITICAL and may be lowered to HIGH.
- **Dashboard and logs:** a web UI covers Dashboard, Mappings, CVEs, Sync jobs, and Account.

## Architecture

- **Backend:** Rust, Tokio, Axum, SQLx on SQLite (WAL mode), Reqwest, OpenID Connect, Argon2, and AES-GCM.
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI primitives, Lucide icons, TanStack Query v5, and Recharts.
- **Deployment:** a single Docker container. The frontend is built to static assets, and the Rust binary serves them, either embedded via `rust-embed` or from disk in development mode.
- **Layering:** HTTP handlers live in `api/`, business logic (SARIF conversion and the Harbor and GitHub API clients) in `services/`, and database access in `db/`.

The Dockerfile is planned as a multi-stage build (Node, then Rust, then a slim runtime image).

## Configuration

| Name | Purpose |
| --- | --- |
| `HARBORGATE_ENCRYPTION_KEY` | Encryption key for stored credentials. Set it through the environment; do not commit it. |

`HARBORGATE_ENCRYPTION_KEY` is required. The app refuses to start without it, and there is no file fallback. The data directory is intended to be a persistent volume.

## Development

The commands below are planned and are not yet valid, because the features are not implemented yet. Build and design details are in [`specs/`](specs/README.md).

```bash
# Backend (planned): run in development mode with file watching
cargo watch -x run

# Backend (planned): prepare SQLx offline metadata
cargo sqlx prepare

# Backend (planned): run tests
cargo test

# Frontend (planned): Vite dev server with backend API proxy
npm run dev

# Frontend (planned): production build
npm run build

# Docker (planned): build and run the single container
docker build -t harborgate:latest .
docker run -p 8080:8080 -v harborgate_data:/data harborgate:latest
```

## Documentation

[`CLAUDE.md`](CLAUDE.md) is the source of truth for this project. It contains:

- the full architecture and directory layout
- the functional requirements
- the development rules for contributors and agents, including error-handling and no-secrets-in-logs requirements

The detailed specifications are in [`specs/`](specs/README.md). The SQLite schema, including the `system_config`, `users`, `user_credentials`, `repo_mappings`, `sync_reports`, and `github_issues` tables, is in [`specs/database.md`](specs/database.md).

For operator setup (Harbor robot account, webhook, GitHub token, and OCI labels), see [`docs/SETUP.md`](docs/SETUP.md).

## License

HarborGate is licensed under the MIT License. See [`LICENSE`](./LICENSE) for the full text.
