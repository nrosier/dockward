# Integrations

Purpose: Harbor webhook, Harbor API usage, polling, OCI labels, and GitHub SARIF upload and issues.

## Harbor webhook

- Endpoint: `/api/v1/webhooks/harbor/:mapping_token`.
- The mapping token is only in the URL path. It is never placed in a header or body.
- The URL token is redacted or omitted from access logs and traces.
- Trigger: Harbor event `SCANNING_COMPLETED` only.
- Payloads: accepts both Harbor's default JSON payload and the CloudEvents payload. The format is detected from the request. Both produce the same internal event.
- Each format has its own test fixture.
- Auth: each webhook must include a shared auth header whose value is a secret generated per mapping.
  - The secret is stored encrypted with AES-256-GCM and shown once.
  - The secret is rotatable.
  - Requests with a missing or wrong header are rejected.
  - Compare values in constant time.
  - The header value is never logged.
- Body size is capped. Requests are rate limited. See [security.md](security.md).
- Handling is durable: validate, store a `sync_jobs` row, return. See [backend.md](backend.md).

## Harbor API

- Fetch the vulnerability JSON from the Harbor REST API using the stored user token.
- The Trivy vulnerability report is the only scanner input. Clair is removed and is not supported.
- Decided: 2026-11-02. The Harbor base URL is stored per Harbor credential in `user_credentials.base_url`. Each mapping uses its credential's `base_url`.

## Polling

- Webhooks are the primary trigger.
- Backup polling runs every 15 minutes across all mapped Harbor projects.
- Polling skips any image whose digest was already synced.
- Note: "backup polling" here means Harbor polling. It is not the admin backup command. See [security.md](security.md).

## OCI labels

Read these from the Harbor artifact:

- Commit SHA: `org.opencontainers.image.revision`. Required. If missing, the sync is marked `failed` with a clear error. Never guess the SHA.
- Repository: `org.opencontainers.image.source`.
- Branch: `org.opencontainers.image.ref.name` if present. Otherwise the mapping's `default_branch` (default `main`).

## SARIF conversion and upload

- Convert the Trivy report to SARIF 2.1.0.
- Gzip, then base64-encode the SARIF payload.
- Upload with `POST /repos/{owner}/{repo}/code-scanning/sarifs`.
- SARIF category is set to the Harbor repository name for each image, so results stay separate.
- Validate output against SARIF 2.1.0 (see [testing-and-ci.md](testing-and-ci.md)).

## GitHub issues

- Auto-create issues for CRITICAL and HIGH findings. The `min_issue_severity` setting defaults to CRITICAL and may be lowered to HIGH.
- Manual issue creation is also supported.
- Issue lifecycle (one open issue per CVE per repo, close, reopen) is defined in [cve-lifecycle.md](cve-lifecycle.md).

## GitHub target

- A GitHub target (owner, repo, default branch) belongs to exactly one mapping.
- The app never moves a target between mappings. See [frontend.md](frontend.md) for the duplicate error.
