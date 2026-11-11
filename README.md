# Dockward

<p align="center">
  <a href="https://github.com/nrosier/dockward/actions/workflows/docker.yml"><img alt="Docker" src="https://github.com/nrosier/dockward/actions/workflows/docker.yml/badge.svg"></a>
  <a href="https://github.com/nrosier/dockward/releases"><img alt="Version" src="https://img.shields.io/github/v/release/nrosier/dockward"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/nrosier/dockward"></a>
</p>

Dockward is a local-first, multi-tenant security relay. It receives container vulnerability reports from Harbor, primarily through webhooks with polling as a backup, converts them to the SARIF 2.1.0 format, and pushes them to GitHub Code Scanning. It can also open GitHub Issues for high-severity findings. The backend is written in Rust (Axum) and the frontend in React (Vite and TypeScript).

## Status

**In development.** The following is built and merged to `main`:

- First-run setup, local login, and OIDC sign-in, with sessions and CSRF protection.
- Encrypted credential storage, with the Harbor and GitHub credential tests.
- Repository mapping CRUD, with hashed webhook token and auth secret.
- The Harbor webhook receiver, which stores a durable sync job.
- The Harbor API client and the Trivy-to-SARIF 2.1.0 converter.
- The durable job queue and its worker.

The sync pipeline is not built yet. The worker completes each queued job without fetching a report or uploading SARIF. Not built yet: the GitHub SARIF upload, GitHub issues, Harbor polling, the CVE lifecycle, alerts, backup and restore, and the web UI (the frontend is still a stub). The [specs/](specs/README.md) describe the planned v1 behaviour.

## Features

The planned v1 functionality, summarized from the specification. Items listed here are not all built yet; see Status above.

- **Secure credential storage:** user credentials (GitHub tokens, Harbor robot tokens, OIDC client secrets) are encrypted at rest with AES-256-GCM.
- **Setup and login:** a first-run wizard creates the initial admin account, and OIDC sign-in can be configured from the admin UI. A local break-glass login remains available as a fallback.
- **Role-based access:** admins manage system configuration, users, and global logs. Regular users manage their own credentials, repository mappings, and Sync jobs.
- **Scoped webhook relay:** each repository mapping has its own webhook endpoint. On receipt, Dockward fetches the vulnerability report from the Harbor REST API and converts Trivy output to SARIF.
- **GitHub delivery:** SARIF is gzipped, Base64-encoded, and submitted to the GitHub code-scanning API. The commit SHA comes only from the `org.opencontainers.image.revision` OCI label; the sync fails if it is missing. The branch comes from the `io.github.nrosier.dockward.branch` label if present (the legacy `io.github.nrosier.harborgate.branch` label is still read, with a deprecation warning), otherwise from the mapping's default branch (default `main`).
- **Optional issue creation:** GitHub Issues are created automatically for CRITICAL and HIGH findings, or triggered manually. `min_issue_severity` defaults to CRITICAL and may be lowered to HIGH.
- **Dashboard and logs:** a web UI covers Dashboard, Mappings, CVEs, Sync jobs, and Account.

## Architecture

- **Backend:** Rust, Tokio, Axum, SQLx on SQLite (WAL mode), Reqwest, OpenID Connect, Argon2, and AES-GCM.
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI primitives, Lucide icons, TanStack Query v5, and Recharts.
- **Deployment:** a single Docker container. The frontend is built to static assets and embedded in the Rust binary via `rust-embed`. Dev mode may serve them from disk.
- **Layering:** HTTP handlers live in `api/`, business logic (SARIF conversion and the Harbor and GitHub API clients) in `services/`, and database access in `db/`.

The Dockerfile is a multi-stage build: Node builds the frontend, Rust builds the binary, and the runtime stage is `scratch` (the static binary, the CA bundle, `/data` and `/tmp`; no shell). The binary is built with `cargo auditable`, so image scans list its Rust crates.

## Configuration

Set these in a `.env` file kept out of git, and pass it to the container with `--env-file .env`. The compose file holds no values. Full rules are in [specs/deployment.md](specs/deployment.md).

| Name | Required | Default | Purpose |
| --- | --- | --- | --- |
| `DOCKWARD_ENCRYPTION_KEY` | Yes | none | Base64 of 32 random bytes. Encrypts stored credentials and derives the session and CSRF keys. The app refuses to start without it. Format in [specs/security.md](specs/security.md). |
| `DOCKWARD_PUBLIC_URL` | Yes | none | The external origin users open, for example `https://dockward.example.com`. Must be `https://`; `http://localhost` with any port is allowed for development. Used for the OIDC redirect URI, the webhook URLs, and the login origin check. The app refuses to start without it. |
| `DOCKWARD_TRUSTED_PROXIES` | No | empty | Comma-separated CIDRs (no host bits set) for the reverse proxies whose `X-Forwarded-For` header is trusted. Setup in [specs/deployment.md](specs/deployment.md), "Client IP behind Cloudflare and Traefik". |
| `DOCKWARD_DATA_DIR` | No | `/data` | Data directory, which holds the SQLite database. Keep it on a persistent volume. |
| `DOCKWARD_BACKUP_DIR` | No | `/data/backups` | Backup directory. See [specs/security.md](specs/security.md), "Backup and restore". |
| `DOCKWARD_ALLOW_PRIVATE_HARBOR` | No | `false` | Allows a Harbor address in a loopback, link-local, or private range. For private Harbor deployments only. See [specs/security.md](specs/security.md), "Outbound HTTP (SSRF)". |
| `DOCKWARD_ALLOW_PRIVATE_OIDC` | No | `false` | The same opt-out for the OIDC issuer and its endpoints. |
| `DOCKWARD_ALLOW_PRIVATE_ALERTS` | No | `false` | The same opt-out for alert SMTP and webhook hosts. |

Planned, not built yet: the key re-encryption command (`DOCKWARD_OLD_ENCRYPTION_KEY` and `DOCKWARD_ENCRYPTION_KEY`), which runs offline with the app stopped. See [specs/security.md](specs/security.md), "Key rotation".

## Development

The commands below run from the directory shown. Backend commands need no environment. Starting the app with `cargo watch -x run` needs `DOCKWARD_ENCRYPTION_KEY` and `DOCKWARD_PUBLIC_URL` set, as above. Build and design details are in [`specs/`](specs/README.md).

```bash
# Backend (from backend/): run in development mode with file watching
cargo watch -x run

# Backend (from backend/): prepare SQLx offline metadata
cargo sqlx prepare

# Backend (from backend/): run tests
cargo test

# Frontend (from frontend/): install dependencies once
npm ci --ignore-scripts

# Frontend (from frontend/): Vite dev server with backend API proxy
npm run dev

# Frontend (from frontend/): production build
npm run build

# Docker (from the repo root): build the image, then run it with the .env file
docker build -t dockward:latest .
docker run --init --env-file .env -p 8080:8080 -v dockward_data:/data dockward:latest
```

## Documentation

[`CLAUDE.md`](CLAUDE.md) is the general development guide for this project. The detailed specifications are in [`specs/`](specs/README.md), and they are the source of truth for behaviour. The SQLite schema, including the `system_config`, `users`, `user_credentials`, `repo_mappings`, `sync_reports`, and `github_issues` tables, is in [`specs/database.md`](specs/database.md).

For operator setup (Harbor robot account, webhook, GitHub token, OCI labels, and the public URL and trusted proxies), see [`docs/SETUP.md`](docs/SETUP.md).

## License

Dockward is licensed under the MIT License. See [`LICENSE`](./LICENSE) for the full text.
