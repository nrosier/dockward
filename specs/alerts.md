# Alerts

Purpose: the single home for alert rules. Covers admin-configured email (SMTP) and outbound webhook alerts.

## Channels

- Email over SMTP, configured by an admin.
  - Decided (2026-11-03, user): sent with the `lettre` crate (tokio and rustls with aws-lc-rs, default features off). TLS is required: implicit TLS (usually port 465) or STARTTLS that must succeed (usually 587). Plaintext SMTP is rejected when the channel is saved. The SMTP host is resolved first and checked against the outbound address rules ([security.md](security.md), Outbound HTTP, class `alerts`). Dockward then connects to the checked address and verifies the certificate against the configured hostname. Config: `{"host","port","tls": "implicit"|"starttls","username"?,"password"?,"from","to": [..]}`.
- Outbound webhook, configured by an admin.
  - Decided (2026-11-03, user): `POST` with `Content-Type: application/json` and the body `{"event": "job_failed"|"new_high_or_critical"|"cve_fixed", "occurred_at": <RFC 3339 UTC>, "mapping": {"id", "harbor": "<hub host>/<repository>", "github": "<owner>/<repo>"}, "cve_id"?, "severity"?, "image_tag"?, "cves"?: [{"id", "severity"}], "more"?, "error"?, "text"}`. `cves` and `more` are set on `new_high_or_critical` only; `cve_id` and `severity` on `cve_fixed`. Decided (2026-11-17, #458): the event names follow the routing below; the earlier `critical_cve` was never sent (it had no caller). Verified (2026-11-11, `backend/src/services/alert_send.rs`): the wire name for the failure event is `job_failed` (`AlertEvent::JobFailed`), and the object key is `mapping` with `harbor` holding the hub host and repository. `OPEN:` the key `harbor` and the name `mapping` still carry the old project naming, and `event` for a failed job was `sync_failed` in the earlier draft. See the open items below.
  - `text` is one human-readable sentence, so Slack and Teams incoming webhooks work unchanged. Config: `{"url", "headers"?: {name: value}}`, stored encrypted. The URL passes the outbound rules (HTTPS, address check, no redirects). Timeout 10 s; any `2xx` counts as delivered, and no delivery row is written otherwise.

## Routing

- Decided (2026-11-17, user, #458): each channel has an event set, the events ticked for it. A channel is sent only those events. One channel can take several events, and an empty set receives nothing.
- The events: `job_failed`, `new_high_or_critical`, `cve_fixed`. There is no separate new CRITICAL event: a CRITICAL CVE is covered by `new_high_or_critical`, so it is never sent twice. A CRITICAL-only channel is not supported.
- Routing is by event only. Every source's alerts go to the channels that take the event (see Decisions, all tenants).
- A channel created without an event set takes `job_failed`. Migration `0018_alert_routing.sql` gives every existing channel `["job_failed"]`, so it keeps the behaviour it had.
- The API refuses an unknown event name with `422`. The event set is not a secret and is returned with the channel. See [api.md](api.md).

## Triggers

- A job fails (event `job_failed`).
  - A job that ends `failed` raises this alert (`spawn_job_failed`, called from `backend/src/services/discovery/handler.rs`). The `text` names the job and the source. The `error` is a fixed string, never an upstream body, URL or header.
  - Final, not failed: a job that ends `done` with a note (for example `no tagged image to scan`) is not a failure and does not raise this alert. An image removed from the registry is final, not failed, and does not raise this alert (see [cve-lifecycle.md](cve-lifecycle.md), "Removing deleted images").
- New HIGH or CRITICAL CVEs appear (event `new_high_or_critical`).
  - Decided (2026-11-17, user, #458): ONE summary alert per scan per source per channel, listing the new CVEs: the first 10 by id with their severity (CRITICAL first, then HIGH, each by id), then "and N more".
  - New means no tag of the source had a row for the CVE before this scan. A CVE that returns after a fix, or that a new tag of the same source reports, is not new. Only CVEs whose merged severity is HIGH or CRITICAL when the scan ends count.
  - A scan of an image is several scan runs (one per enabled scanner and platform), each its own job. The convert step records each change in `alert_pending` in the transaction that stores its run. After a scan job, `Notifier::scan_alerts` (`backend/src/services/alerts.rs`, called from the job handler) sends nothing while any run or pull of the image is open. When the last one has ended, it takes the image's pending rows (and deletes them) in one transaction and sends. A second identical scan finds no new CVE and sends nothing.
- A CVE is fixed (event `cve_fixed`).
  - Sent when a CVE the tag had `open` is no longer reported on the latest scan of its image (the convert step marks the row `fixed`). One alert per CVE per source per fix.
  - Held while an enabled scanner has no `done` run for the image, as the issue rules do (#224 d14): a failed scanner never reports a fix. A held fix stays pending and is sent by the next complete scan of the image. A CVE that is reported again before the scan ends is not sent.
  - Note only: this alert never closes, comments on, or changes a GitHub issue. The notifier has no GitHub client. The fixed note on the issue belongs to the issue rules ([cve-lifecycle.md](cve-lifecycle.md)).
- A send that fails is logged as fixed text and is not retried for that scan: the pending rows were already taken. The dedupe claim is released, as for every alert.

## Storage

- Decided (2026-11-03, delegated): channels are rows in `alert_channels` (`id`, `kind` `smtp` or `webhook`, `config_encrypted`, `enabled`, `created_at`, `updated_at`). The whole channel config (host, port, user, password, URL, headers) is one JSON document encrypted into `config_encrypted` in the `v1:` format from [security.md](security.md).
- Decided (2026-11-03, delegated): sent alerts are recorded in `alert_deliveries` (`id`, `channel_id`, `dedupe_key`, `sent_at`) with `UNIQUE (channel_id, dedupe_key)`. Verified (2026-11-11, `backend/migrations/0001_init.sql`).
- `dedupe_key` is `job_failed:<job id>` for job failures, `scan:<scan id>:<source id>` for a new HIGH or CRITICAL summary, and `cve_fixed:<CVE id>:<scan id>` for a fixed CVE. See Deduplication below.
- Decided (2026-11-17, delegated, #458): `alert_channels.events` holds the event set as a JSON array, and `alert_pending` holds the CVE changes the convert step found until the scan ends. See [database.md](database.md).
- The 24-hour window is enforced by checking `sent_at`, not by the constraint. See [database.md](database.md) for the write rule.
- Source: none external. The tables are a local design to implement the user's decided 24-hour dedupe.
- Channel secrets are never returned by the API after save. See [api.md](api.md).
- Decided (2026-11-17, user): an SMTP channel's non-secret settings (host, port, tls, username, from, to) are returned to the admin edit form so it is not empty, with only `password_set` for the password. Saving with `"keep_password": true` keeps the stored password. Webhook settings stay write-only. An admin can send a fixed test mail from the SMTP form, before or after saving.

## Payload rules

- Alert payloads must never include tokens, keys, registry or GitHub credentials, webhook URLs, or upstream response bodies.
- Payloads carry names, the tag, the CVE id, the severity and the fixed error text only.

## Secrets

- SMTP and webhook secrets are stored encrypted (AES-256-GCM). The encryption and rotation rules are owned by [security.md](security.md).

## Deduplication

- Decided: 2026-11-03. Alerts are deduplicated within 24 hours by key and channel. The same key does not notify a channel twice a day.
- Keys:
  - `job_failed:<job id>` for a job failure.
  - Decided (2026-11-17, user, #458): `scan:<scan id>:<source id>` for a new HIGH or CRITICAL summary: one summary per scan. This replaces the per-CVE key (the CVE id alone) of the dropped new CRITICAL event.
  - `cve_fixed:<CVE id>:<scan id>` for a fixed CVE: once per CVE per fix.
- Decided (2026-11-17, spec author, #458): the scan id is the id of the scan run whose end left no run or pull of the image open, because a scan has no row of its own. The source id is part of the summary key because one image can be the newest image of several sources, and each source gets its own summary; with the scan id alone the second source's summary would be suppressed. The user can overturn this.
- Verified (2026-11-17, `backend/src/services/alerts.rs`): the window is 86,400 s (`DAY`), enforced by the `alert_deliveries` upsert.

## Decisions

- Decided (2026-11-03): alert scope is all tenants. Alerts for every source are sent to the admin-configured alert channels (SMTP and webhook) that take the event. Source owners do NOT receive their own alerts in v1; they see failures in the app.
- Decided (2026-11-17, user, #458): the per-CVE dedupe key for new CRITICAL CVEs (the CVE id alone, across sources) is replaced by the one summary per scan above.

## OPEN

- OPEN: the payload's `event` value for a failed job. The code sends `job_failed` (verified 2026-11-11). The earlier draft said `sync_failed`. The user confirms the wire name, because an existing webhook may match on it.
- OPEN: the payload key `mapping` and its `harbor` field. These carry a source (hub and repository). Rename to `source` and `hub` needs the user's decision and a note in the changelog.
