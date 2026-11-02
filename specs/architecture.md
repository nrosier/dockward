# Architecture

Purpose: system overview, components, data flow, and deployment shape for HarborGate v1.

## Overview

- HarborGate is a local-first, multi-tenant security relay platform.
- It receives container vulnerability reports from Harbor (webhooks, with polling as backup), converts Trivy reports to SARIF 2.1.0, and pushes them to GitHub Code Scanning and Issues.

## Components

- **Axum API** (`backend/src/api/`): local and OIDC login, mapping CRUD, reports, issues, admin, webhook listener.
- **Services** (`backend/src/services/`): Harbor API client, GitHub API client, Trivy-to-SARIF converter.
- **Durable job queue**: `sync_jobs` table, drained by an in-process worker.
- **Background worker** (`backend/src/worker/`): Harbor polling every 15 minutes, retention cleanup.
- **SQLite database** in the `data` volume at `/data`, WAL mode.
- **Frontend SPA** (React, Vite, TypeScript), embedded in the binary.

## Data flow

1. Harbor sends a `SCANNING_COMPLETED` webhook (or the poller finds a new digest).
2. The handler validates the request, stores a `sync_jobs` row, and returns.
3. The worker takes the job and fetches the Trivy vulnerability JSON from the Harbor REST API using the stored user token.
4. The converter produces SARIF 2.1.0.
5. The SARIF is gzip-compressed, base64-encoded, and uploaded to GitHub Code Scanning.
6. Issues and `cve_findings` rows are updated (see [cve-lifecycle.md](cve-lifecycle.md)).
7. Alerts fire on sync failure or a new CRITICAL CVE (see [alerts.md](alerts.md)).

## Decisions

- Single instance only in v1: one process, one SQLite file in `/data`.
- Frontend and API are served from the same origin on port 8080.
- The frontend is embedded in the Rust binary via `rust-embed`. In production it is not copied to disk for runtime serving. Dev mode may serve it directly.
- No `/metrics` endpoint in v1.
- v1 includes all pages listed in [frontend.md](frontend.md).

## Tech stack

- Backend: Rust 1.99.1+, Tokio, Axum, SQLx (SQLite WAL), Reqwest, OpenIDConnect-rs, Argon2, AES-GCM.
- Frontend: React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI Primitives, Lucide React, TanStack Query v5, Recharts.
- Build: multi-stage Dockerfile (Node, then Rust, then runtime). See [deployment.md](deployment.md).
