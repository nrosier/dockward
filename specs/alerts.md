# Alerts

Purpose: the single home for alert rules. Covers admin-configured email (SMTP) and outbound webhook alerts.

## Channels

- Email over SMTP, configured by an admin.
- Outbound webhook, configured by an admin.

## Triggers

- A sync fails.
- A new CRITICAL CVE appears.

## Payload rules

- Alert payloads must never include tokens, keys, or webhook URLs.

## Secrets

- SMTP and webhook secrets are stored encrypted (AES-256-GCM). The encryption and rotation rules are owned by [security.md](security.md).

## Deduplication

- Decided: 2026-11-02. Alerts are deduplicated per (alert kind, CVE or sync job id) within 24 hours, so the same failure or CVE does not notify twice a day.

## OPEN

- OPEN: which scope triggers an alert: the mapping's own syncs only, or all tenants for admins? Not decided.
