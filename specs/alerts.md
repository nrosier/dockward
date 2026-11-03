# Alerts

Purpose: the single home for alert rules. Covers admin-configured email (SMTP) and outbound webhook alerts.

## Channels

- Email over SMTP, configured by an admin.
  - Decided (2026-11-03, user): sent with the `lettre` crate (tokio and rustls with aws-lc-rs, default features off). TLS is required: implicit TLS (usually port 465) or STARTTLS that must succeed (usually 587). Plaintext SMTP is rejected when the channel is saved. The SMTP host is resolved first and checked against the outbound address rules ([security.md](security.md), Outbound HTTP, class `alerts`). HarborGate then connects to the checked address and verifies the certificate against the configured hostname. Config: `{"host","port","tls": "implicit"|"starttls","username"?,"password"?,"from","to": [..]}`.
- Outbound webhook, configured by an admin.
  - Decided (2026-11-03, user): `POST` with `Content-Type: application/json` and the body `{"event": "sync_failed"|"critical_cve", "occurred_at": <RFC 3339 UTC>, "mapping": {"id", "harbor": "<project>/<repository>", "github": "<owner>/<repo>"}, "cve_id"?, "severity"?, "image_tag"?, "error"?, "text"}`. `text` is one human-readable sentence, so Slack and Teams incoming webhooks work unchanged. Config: `{"url", "headers"?: {name: value}}`, stored encrypted. The URL passes the outbound rules (HTTPS, address check, no redirects). Timeout 10 s; any `2xx` counts as delivered, and no delivery row is written otherwise.

## Triggers

- A sync fails.
- A new CRITICAL CVE appears.

## Storage

- Decided (2026-11-03, delegated): channels are rows in `alert_channels` (`id`, `kind` `smtp` or `webhook`, `config_encrypted`, `enabled`, `created_at`, `updated_at`). The whole channel config (host, port, user, password, URL, headers) is one JSON document encrypted into `config_encrypted` in the `v1:` format from [security.md](security.md).
- Decided (2026-11-03, delegated): sent alerts are recorded in `alert_deliveries` (`id`, `channel_id`, `dedupe_key`, `sent_at`) with `UNIQUE (channel_id, dedupe_key)`.
- `dedupe_key` is the CVE id alone for new CRITICAL CVE alerts, and `sync_failed:<sync_job_id>` for sync failures. See Deduplication below.
- The 24-hour window is enforced by checking `sent_at`, not by the constraint. See [database.md](database.md) for the write rule.
- Source: none external. The tables are a local design to implement the user's decided 24-hour dedupe. The schema is in [database.md](database.md).
- Channel secrets are never returned by the API after save. See [api.md](api.md).

## Payload rules

- Alert payloads must never include tokens, keys, or webhook URLs.

## Secrets

- SMTP and webhook secrets are stored encrypted (AES-256-GCM). The encryption and rotation rules are owned by [security.md](security.md).

## Deduplication

- Decided: 2026-11-03. Alerts are deduplicated within 24 hours by key: the CVE id alone for new CRITICAL CVE alerts, and `sync_failed:<sync_job_id>` for sync failures. The same failure or CVE does not notify twice a day.

## Decisions

- Decided (2026-11-03): alert scope is all tenants. Sync failures and new CRITICAL CVEs for every mapping are sent to the admin-configured alert channels (SMTP and webhook). Mapping owners do NOT receive their own alerts in v1; they see failures in the app.
- Decided (2026-11-03): the dedupe key for a new CRITICAL CVE is the CVE id alone, globally across mappings. At most one alert per CVE is sent in any 24-hour window, however many mappings carry it. Sync-failure alerts use dedupe key `sync_failed:<sync_job_id>` with the same 24-hour window, so a single failing job alerts once per day.

## OPEN

None.
