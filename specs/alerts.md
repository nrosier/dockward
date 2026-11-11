# Alerts

Purpose: the single home for alert rules. Covers admin-configured email (SMTP) and outbound webhook alerts.

## Channels

- Email over SMTP, configured by an admin.
  - Decided (2026-11-03, user): sent with the `lettre` crate (tokio and rustls with aws-lc-rs, default features off). TLS is required: implicit TLS (usually port 465) or STARTTLS that must succeed (usually 587). Plaintext SMTP is rejected when the channel is saved. The SMTP host is resolved first and checked against the outbound address rules ([security.md](security.md), Outbound HTTP, class `alerts`). Dockward then connects to the checked address and verifies the certificate against the configured hostname. Config: `{"host","port","tls": "implicit"|"starttls","username"?,"password"?,"from","to": [..]}`.
- Outbound webhook, configured by an admin.
  - Decided (2026-11-03, user): `POST` with `Content-Type: application/json` and the body `{"event": "job_failed"|"critical_cve", "occurred_at": <RFC 3339 UTC>, "mapping": {"id", "harbor": "<hub host>/<repository>", "github": "<owner>/<repo>"}, "cve_id"?, "severity"?, "image_tag"?, "error"?, "text"}`. Verified (2026-11-11, `backend/src/services/alert_send.rs`): the wire name for the failure event is `job_failed` (`AlertEvent::JobFailed`), and the object key is `mapping` with `harbor` holding the hub host and repository. `OPEN:` the key `harbor` and the name `mapping` still carry the old project naming, and `event` for a failed job was `sync_failed` in the earlier draft. See the open items below.
  - `text` is one human-readable sentence, so Slack and Teams incoming webhooks work unchanged. Config: `{"url", "headers"?: {name: value}}`, stored encrypted. The URL passes the outbound rules (HTTPS, address check, no redirects). Timeout 10 s; any `2xx` counts as delivered, and no delivery row is written otherwise.

## Triggers

- A job fails (event `job_failed`).
  - A job that ends `failed` raises this alert (`spawn_job_failed`, called from `backend/src/services/discovery/handler.rs`). The `text` names the job and the source. The `error` is a fixed string, never an upstream body, URL or header.
  - Final, not failed: a job that ends `done` with a note (for example `no tagged image to scan`) is not a failure and does not raise this alert. An image removed from the registry is final, not failed, and does not raise this alert (see [cve-lifecycle.md](cve-lifecycle.md), "Removing deleted images").
- A new CRITICAL CVE appears.
  - The send path exists (`spawn_new_critical` in `backend/src/services/alert_send.rs`, with the dedupe key the CVE id), but no production caller was found in `backend/src` (verified 2026-11-11: only tests call it). `OPEN:` whether the trigger is wired in 0.2.0. Until it is, no critical-CVE alert is sent.

## Storage

- Decided (2026-11-03, delegated): channels are rows in `alert_channels` (`id`, `kind` `smtp` or `webhook`, `config_encrypted`, `enabled`, `created_at`, `updated_at`). The whole channel config (host, port, user, password, URL, headers) is one JSON document encrypted into `config_encrypted` in the `v1:` format from [security.md](security.md).
- Decided (2026-11-03, delegated): sent alerts are recorded in `alert_deliveries` (`id`, `channel_id`, `dedupe_key`, `sent_at`) with `UNIQUE (channel_id, dedupe_key)`. Verified (2026-11-11, `backend/migrations/0001_init.sql`).
- `dedupe_key` is the CVE id alone for new CRITICAL CVE alerts, and `job_failed:<job id>` for job failures. See Deduplication below.
- The 24-hour window is enforced by checking `sent_at`, not by the constraint. See [database.md](database.md) for the write rule.
- Source: none external. The tables are a local design to implement the user's decided 24-hour dedupe.
- Channel secrets are never returned by the API after save. See [api.md](api.md).

## Payload rules

- Alert payloads must never include tokens, keys, registry or GitHub credentials, webhook URLs, or upstream response bodies.
- Payloads carry names, the tag, the CVE id, the severity and the fixed error text only.

## Secrets

- SMTP and webhook secrets are stored encrypted (AES-256-GCM). The encryption and rotation rules are owned by [security.md](security.md).

## Deduplication

- Decided: 2026-11-03. Alerts are deduplicated within 24 hours by key: the CVE id alone for new CRITICAL CVE alerts, and `job_failed:<job id>` for job failures. The same failure or CVE does not notify twice a day.
- Verified (2026-11-11, `backend/src/services/alerts.rs`): the job-failure key is `job_failed:{job_id}` and the window is 86,400 s (`DAY`).

## Decisions

- Decided (2026-11-03): alert scope is all tenants. Job failures and new CRITICAL CVEs for every source are sent to the admin-configured alert channels (SMTP and webhook). Source owners do NOT receive their own alerts in v1; they see failures in the app.
- Decided (2026-11-03): the dedupe key for a new CRITICAL CVE is the CVE id alone, globally across sources. At most one alert per CVE is sent in any 24-hour window, however many sources carry it.

## OPEN

- OPEN: the payload's `event` value for a failed job. The code sends `job_failed` (verified 2026-11-11). The earlier draft said `sync_failed`. The user confirms the wire name, because an existing webhook may match on it.
- OPEN: the payload key `mapping` and its `harbor` field. These carry a source (hub and repository). Rename to `source` and `hub` needs the user's decision and a note in the changelog.
