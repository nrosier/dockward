# Dockward

<p align="center">
  <a href="https://github.com/nrosier/dockward/actions/workflows/docker.yml"><img alt="Docker" src="https://github.com/nrosier/dockward/actions/workflows/docker.yml/badge.svg"></a>
  <a href="https://github.com/nrosier/dockward/releases"><img alt="Version" src="https://img.shields.io/github/v/release/nrosier/dockward"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/nrosier/dockward"></a>
</p>

Dockward is a local-first, multi-tenant security relay. It discovers container images in registries (ghcr.io and docker.io by default, plus custom hubs), pulls them into local OCI layouts with no Docker daemon, scans them with pinned Trivy and Grype binaries, converts the results to SARIF 2.1.0, and publishes them to GitHub Code Scanning. It can also open GitHub Issues for high-severity findings. The backend is written in Rust (Axum) and the frontend in React (Vite and TypeScript).

## Status

Dockward 0.2.0 is the first release under the Dockward name. It replaces HarborGate and removes the Harbor integration entirely: there are no Harbor webhooks, no polling, no Harbor API client, and no sync jobs. Dockward starts with a fresh database (`dockward.db`); it does not migrate a HarborGate database.

The [specs/](specs/README.md) describe the v1 behaviour. [CHANGELOG.md](CHANGELOG.md) lists what changed in each release.

## Features

- **Image discovery:** an hourly discovery pass lists the tags of each configured repository. A new or moved tag queues one pull.
- **Local scanning:** images are pulled into local OCI layouts. Each platform of a multi-arch image is scanned, and attestation entries are skipped. Trivy and Grype run from pinned binaries in the image.
- **Daily database refresh:** the scanner vulnerability databases are refreshed once a day, and stored images are rescanned when a database is newer.
- **Secure credential storage:** registry credentials, GitHub tokens, and OIDC client secrets are encrypted at rest with AES-256-GCM.
- **Setup and login:** a first-run wizard creates the initial admin account, and OIDC sign-in can be configured from the admin UI. A local break-glass login remains available as a fallback.
- **Role-based access:** admins manage system configuration, hubs, users, and global logs. Regular users manage their own credentials and sources.
- **GitHub delivery:** SARIF is gzipped, Base64-encoded, and submitted to the GitHub code-scanning API. The commit SHA comes only from the `org.opencontainers.image.revision` OCI label; the publish fails if it is missing. The branch comes from the `io.github.nrosier.dockward.branch` label if present (the legacy `io.github.nrosier.harborgate.branch` label is still read, with a deprecation warning), otherwise from the source's default branch (default `main`).
- **Optional issue creation:** GitHub Issues are created automatically for CRITICAL and HIGH findings, or triggered manually. `min_issue_severity` defaults to CRITICAL and may be lowered to HIGH.
- **Web UI:** Dashboard, Sources, CVEs, Jobs, and Account, with admin pages for jobs, failed jobs, audit, health, log, settings, and backup.

## Architecture

- **Backend:** Rust, Tokio, Axum, SQLx on SQLite (WAL mode), Reqwest, OpenID Connect, Argon2, and AES-GCM.
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI primitives, Lucide icons, TanStack Query v5, and Recharts.
- **Deployment:** a single Docker container. The frontend is built to static assets and embedded in the Rust binary via `rust-embed`. Dev mode may serve them from disk.
- **Layering:** HTTP handlers live in `api/`, business logic (registry access, scanning, SARIF conversion, and the GitHub client) in `services/`, and database access in `db/`.

The Dockerfile is a multi-stage build: Node builds the frontend, Rust builds the binary, and the runtime stage is `scratch` (the static binary, the pinned scanner binaries, the CA bundle, `/data` and `/tmp`; no shell). The binary is built with `cargo auditable`, so image scans list its Rust crates.

## Configuration

Set these in a `.env` file kept out of git, and pass it to the container with `--env-file .env`. The compose file holds no values. Full rules are in [specs/deployment.md](specs/deployment.md).

| Name | Required | Default | Purpose |
| --- | --- | --- | --- |
| `DOCKWARD_ENCRYPTION_KEY` | Yes | none | Base64 of 32 random bytes. Encrypts stored credentials and derives the session, CSRF, and backup keys. The app refuses to start without it. Format in [specs/security.md](specs/security.md). |
| `DOCKWARD_PUBLIC_URL` | Yes | none | The external origin users open, for example `https://dockward.example.com`. Must be `https://`; `http://localhost` with any port is allowed for development. Used for the OIDC redirect URI and the login origin check. The app refuses to start without it. |
| `DOCKWARD_TRUSTED_PROXIES` | No | empty | Comma-separated CIDRs (no host bits set) for the reverse proxies whose `X-Forwarded-For` header is trusted. Setup in [specs/deployment.md](specs/deployment.md), "Client IP behind Cloudflare and Traefik". |
| `DOCKWARD_DATA_DIR` | No | `/data` | Data directory. Holds the SQLite database (`dockward.db`) and the scanner cache. Keep it on a persistent volume. |
| `DOCKWARD_BACKUP_DIR` | No | `/data/backups` | Backup directory. See [specs/security.md](specs/security.md), "Backup and restore". |
| `DOCKWARD_ALLOW_PRIVATE_OIDC` | No | `false` | Allows the OIDC issuer and its endpoints to resolve to a loopback, link-local, or private address. For private identity providers only. See [specs/security.md](specs/security.md), "Outbound HTTP (SSRF)". |
| `DOCKWARD_ALLOW_PRIVATE_ALERTS` | No | `false` | The same opt-out for alert SMTP and webhook hosts. |

Variables that begin `HARBORGATE_` are still read as a fallback for this release. Each one that is used logs a deprecation warning naming both variables, never the value. `DOCKWARD_*` wins when both are set. The fallback is removed after 0.2.

Key rotation is a command-line subcommand (`dockward rotate-key`) that runs with the app stopped, with `DOCKWARD_OLD_ENCRYPTION_KEY` and `DOCKWARD_ENCRYPTION_KEY` set. See [docs/SETUP.md](docs/SETUP.md), "Key rotation".

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

[`CLAUDE.md`](CLAUDE.md) is the general development guide for this project. The detailed specifications are in [`specs/`](specs/README.md), and they are the source of truth for behaviour.

For operator setup (registries and hubs, GitHub token, OCI labels, the public URL and trusted proxies, backup and restore, and key rotation), see [`docs/SETUP.md`](docs/SETUP.md).

## License

Dockward is licensed under the MIT License. See [`LICENSE`](./LICENSE) for the full text.
