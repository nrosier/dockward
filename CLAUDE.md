# HarborGate Development Guide (`CLAUDE.md`)

HarborGate is a local-first, multi-tenant security relay platform built with Rust (Axum) and React (Vite/TypeScript). It receives container vulnerability reports from Harbor (via webhooks or polling), translates them into standard SARIF format, and pushes them to GitHub Code Scanning and Issues.

---

## 1. Project Architecture & Tech Stack

### Monorepo / Single Container Architecture
- **Backend:** Rust 1.82+, Tokio, Axum, SQLx (SQLite WAL mode), Reqwest, OpenIDConnect-rs, Argon2, AES-GCM.
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI Primitives, Lucide React, TanStack Query v5, Recharts.
- **Deployment:** Single Docker container. Node builds frontend static assets (`/dist`), Rust builds the backend binary, and static assets are embedded into the Axum binary via `rust-embed` or served directly in dev mode.

```text
/
├── backend/
│   ├── Cargo.toml
│   ├── migrations/             # SQLx SQLite migrations
│   └── src/
│       ├── main.rs
│       ├── api/                # Axum routes & handlers
│       │   ├── auth.rs         # Local login, OIDC flow, JWT cookies
│       │   ├── webhooks.rs     # Harbor webhook listener (/api/v1/webhooks/harbor/:token)
│       │   ├── mappings.rs     # Repo mapping CRUD
│       │   ├── reports.rs      # Scan activity & SARIF logs
│       │   └── issues.rs       # GitHub issue management
│       ├── auth/               # Argon2, AES-256-GCM crypto, OIDC claims
│       ├── db/                 # SQLx models & queries
│       ├── models/             # Shared structs & SARIF converters
│       ├── services/           # Harbor API, GitHub API, SARIF converter
│       └── worker/             # Tokio background polling & DB cleanup tasks
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   └── src/
│       ├── components/         # Radix UI + Tailwind reusable components
│       ├── pages/              # Dashboard, Mappings, Logs, Settings, Login
│       ├── hooks/              # TanStack Query & Auth hooks
│       ├── lib/                # API client (fetch wrapper)
│       └── types/              # TypeScript interfaces
├── Dockerfile                  # Multi-stage build (Node -> Rust -> Alpine/Debian)
└── docker-compose.yml
```

---

## 2. Core Functional Requirements

### Security & Encryption
- AES-256-GCM encryption for stored user credentials (GitHub PATs, Harbor Robot Tokens, OIDC Secrets).
- Encryption key derived from `HARBORGATE_ENCRYPTION_KEY` env var, falling back to `/data/master.key` generated on first run.

### Authentication & Authorization
- **First-run setup wizard:** First created local account automatically becomes `Admin`.
- **OIDC Integration:** Configurable in Admin UI (Issuer URL, Client ID, Client Secret, Role/Group claim mapping).
- **Fallback Auth:** Break-glass local authentication remains available.
- **Role-Based Access:** `Admin` (system config, user management, global logs) vs `User` (own credentials, own repo mappings, own sync logs).

### Webhook & Relay Engine
- Scoped Webhook Endpoints: `/api/v1/webhooks/harbor/:mapping_token`
- Fetch vulnerability JSON from Harbor REST API using stored user token.
- Convert Trivy/Clair vulnerability reports to standard SARIF 2.1.0 schema.
- Gzip + Base64 encode SARIF payload and push to GitHub API (`POST /repos/{owner}/{repo}/code-scanning/sarifs`).
- Read OCI labels or mapping config to target branch and commit SHA.
- Optional: Auto-create or manually trigger GitHub Issues for `CRITICAL` / `HIGH` findings.

---

## 3. Database Schema (`migrations/0001_init.sql`)

```sql
-- System Configuration (OIDC, App Settings)
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    is_encrypted BOOLEAN DEFAULT FALSE,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user', -- 'admin' | 'user'
    auth_provider TEXT NOT NULL DEFAULT 'local', -- 'local' | 'oidc'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Service Credentials (Encrypted)
CREATE TABLE IF NOT EXISTS user_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_type TEXT NOT NULL, -- 'harbor' | 'github'
    label TEXT NOT NULL,
    base_url TEXT,
    encrypted_token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Repository Mappings
CREATE TABLE IF NOT EXISTS repo_mappings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    harbor_cred_id TEXT REFERENCES user_credentials(id),
    github_cred_id TEXT REFERENCES user_credentials(id),
    harbor_project TEXT NOT NULL,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    webhook_token TEXT UNIQUE NOT NULL,
    auto_create_issues BOOLEAN DEFAULT FALSE,
    min_issue_severity TEXT DEFAULT 'CRITICAL',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sync Reports & Logs
CREATE TABLE IF NOT EXISTS sync_reports (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    harbor_image TEXT NOT NULL,
    image_tag TEXT NOT NULL,
    commit_sha TEXT,
    vulnerability_summary TEXT NOT NULL, -- JSON string: {"critical": 0, "high": 2, ...}
    sarif_status TEXT NOT NULL, -- 'pending' | 'success' | 'failed'
    github_sarif_id TEXT,
    error_message TEXT,
    synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tracked GitHub Issues
CREATE TABLE IF NOT EXISTS github_issues (
    id TEXT PRIMARY KEY,
    sync_report_id TEXT NOT NULL REFERENCES sync_reports(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    github_issue_number INTEGER NOT NULL,
    github_issue_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- 'open' | 'closed'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. UI/UX Style Guidelines

* **Theme:** Dark mode default (`#0f172a` slate background, `#1e293b` cards/panels, `#334155` subtle borders).
* **Status Colors:**
  * Critical: Red (`#ef4444`)
  * High: Orange (`#f97316`)
  * Medium: Yellow (`#eab308`)
  * Success / Low: Emerald (`#10b981`) / Blue (`#3b82f6`)
* **Components:** Collapsible left sidebar, sticky header with environment status badges, data dense tables with inline status pills, copyable SHA badges (`font-mono`).

---

## 5. Build & Execution Commands

### Backend (Rust)

```bash
# Run in development mode (watches changes)
cargo watch -x run

# Prepare SQLx offline metadata for builds
cargo sqlx prepare

# Run tests
cargo test
```

### Frontend (React + Vite)

```bash
# Run Vite dev server with backend API proxy
npm run dev

# Production build
npm run build
```

### Docker Single Binary Container

```bash
docker build -t harborgate:latest .
docker run -p 8080:8080 -v harborgate_data:/data harborgate:latest
```

---

## 6. Development Rules & Guidelines for Claude

1. **Safety & Zero Panic:** Always handle errors gracefully in Rust using `Result<T, AppError>` and Axum's `IntoResponse`. Avoid `.unwrap()` or `.expect()` in non-test code.
2. **Database Queries:** Use compile-time checked `sqlx::query!` macros where possible. Always maintain async safety with SQLite connection pools (`SqlitePool`).
3. **SARIF Accuracy:** Ensure the converted SARIF JSON strictly conforms to the SARIF 2.1.0 specification expected by `POST /repos/{owner}/{repo}/code-scanning/sarifs`.
4. **Clean Decoupling:** Keep business logic (SARIF conversion, Harbor/GitHub API HTTP clients) strictly in `services/`, handlers in `api/`, and DB operations in `db/`.
5. **No Secrets in Logs:** Ensure GitHub PATs, Harbor tokens, and AES keys are NEVER printed in log files or Server-Sent Events streams.
