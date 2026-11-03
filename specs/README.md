# HarborGate Specs

Index of the detailed build specifications. CLAUDE.md is the general guide; this folder holds the detail. Each decision lives in exactly one spec file. When a decision changes, update the owning file and keep CLAUDE.md general.

## Files

- [architecture.md](architecture.md) - Overview, components, data flow, single-instance decision, tech stack.
- [database.md](database.md) - Schema reference (`migrations/0001_init.sql`) and table decisions.
- [api.md](api.md) - HTTP route contract: every route, auth level, request and response shape, status codes, error envelope, pagination. PROPOSED, awaiting approval.
- [backend.md](backend.md) - Modules, services, durable job queue, error handling, dev rules.
- [security.md](security.md) - Encryption, key handling and rotation, backup and restore, auth, sessions, hardening, tenancy, GitHub token scope.
- [integrations.md](integrations.md) - Harbor webhook, Harbor API, polling, GitHub SARIF upload, GitHub issues, OCI labels.
- [cve-lifecycle.md](cve-lifecycle.md) - CVE tracking per tag, tag limit, states, issue open/close/reopen, acceptance, retention.
- [alerts.md](alerts.md) - SMTP and outbound webhook alerts. The only place for alert rules.
- [frontend.md](frontend.md) - App shell, page map, screens, visual direction, status pills, i18n, house style, design-before-build.
- [deployment.md](deployment.md) - Dockerfile, compose, Traefik, Cloudflare tunnel, volumes, health endpoint, .gitignore, releases.
- [testing-and-ci.md](testing-and-ci.md) - Test strategy, CI workflows, Renovate, repo hygiene files.

## Rules

- CLAUDE.md is the general guide. specs/ holds the detail.
- Open items are marked OPEN: (unresolved questions) and PROPOSED: (awaiting approval). Do not decide them silently.
- Contradictions between files are recorded as `CONFLICT:` until the user resolves them.
