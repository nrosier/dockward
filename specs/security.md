# Security

Purpose: encryption, key handling, backup and restore, authentication, sessions, hardening, tenancy, and secret handling.

## Encryption and keys

- `HARBORGATE_ENCRYPTION_KEY` is read from the environment and is required. The app refuses to start without it.
- No file fallback for the key.
- AES-256-GCM encrypts stored user credentials (GitHub PATs, Harbor robot tokens, OIDC client secrets), alert SMTP and webhook secrets, and the per-mapping auth header secret.
- Losing `HARBORGATE_ENCRYPTION_KEY` makes stored credentials unrecoverable. Operators must back it up separately.
- The session signing key and the backup encryption key are derived from `HARBORGATE_ENCRYPTION_KEY`.

## Key rotation

- An admin re-encrypt command rewrites all stored credentials and SMTP or webhook secrets from the old key to the new key.
- Both keys are required during the step.
- The rewrite runs in a single transaction.
- Key values are never logged.

## Backup and restore

- Backup: an admin command uses the SQLite online backup API to write a consistent copy of the database.
- The backup is encrypted at rest with AES-256-GCM. The key is derived from `HARBORGATE_ENCRYPTION_KEY`.
- Default location: `/data/backups`. Operators may set another path with `HARBORGATE_BACKUP_DIR`.
- The command writes only to that path.
- If the directory is missing or not writable, the command fails with a clear error. The error is shown in the admin UI and logs. It never falls back to another location.
- Restore: start the app with the same `HARBORGATE_ENCRYPTION_KEY` that created the backup, then run the admin restore command.
- Restore steps are documented in `docs/SETUP.md`.

## Authentication

- **First-run setup:** the first local account created becomes `Admin`.
- **OIDC:** configured in the Admin UI. Settings: issuer URL, client ID, client secret (encrypted), role or group claim mapping. OIDC users get their role from the configured group claim.
- **Break-glass:** local login stays available for admins only. It is not available to `User` accounts.
- Roles: `Admin` (system config, user management, global logs, read-only view of all tenants) and `User` (own credentials, own mappings, own sync history).

## Sessions

- Signed JWT in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie.
- Signing key derived from `HARBORGATE_ENCRYPTION_KEY`.
- Expiry: 8 hours.
- Logout clears the cookie.
- No server-side revocation in v1.

## Hardening

- Rate limits on the webhook endpoint and the login endpoint.
- A request body size cap on the webhook endpoint.
- CSRF tokens on state-changing requests that use cookie sessions.
- `SameSite=Lax` alone is not sufficient.

## Tenancy

- Users see only their own credentials, mappings, and sync history.
- Admins may view all of it, read-only.
- Admins cannot change another user's credentials or mappings.

## Secrets in logs

- GitHub PATs, Harbor tokens, AES keys, the webhook URL token, and the webhook auth header value are never printed in logs, traces, or Server-Sent Events streams.
- The webhook URL token is redacted or omitted from access logs and traces.
- Audit `details` never contain tokens or key material.

## GitHub token scope

- Fine-grained personal access token only in v1. No GitHub App support.
- Required permissions:
  - Contents: read
  - Code scanning alerts: read and write
  - Issues: read and write, only when auto-created issues are enabled
- The Health page reports missing scopes. See [frontend.md](frontend.md).
