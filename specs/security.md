# Security

Purpose: encryption, key handling, backup and restore, authentication, sessions, hardening, tenancy, and secret handling.

Every value below that is not already decided by the user is marked `PROPOSED:` with a source. Open items are marked OPEN: (unresolved questions) and PROPOSED: (awaiting approval). `UNVERIFIED:` marks a claim whose source could not be confirmed.

## Encryption and keys

- `HARBORGATE_ENCRYPTION_KEY` is read from the environment and is required. The app refuses to start without it.
- No file fallback for the key.
- AES-256-GCM encrypts stored user credentials (GitHub PATs, Harbor robot secrets, OIDC client secrets), alert SMTP and webhook secrets, and the per-mapping auth header secret.
- Losing `HARBORGATE_ENCRYPTION_KEY` makes stored credentials unrecoverable. Operators must back it up separately.
- Session signing, backup, and CSRF keys are derived from `HARBORGATE_ENCRYPTION_KEY`. See "Derived keys" below.

### Encryption key format

- PROPOSED: `HARBORGATE_ENCRYPTION_KEY` is the base64 encoding of exactly 32 random bytes. The app refuses to start if the value does not decode to exactly 32 bytes.
- Source: AES-256 uses a 256-bit key (FIPS 197, https://csrc.nist.gov/pubs/fips/197/final). The 32-byte length follows from that. Base64 is the encoding that `openssl rand -base64 32` already produces in [docs/SETUP.md](../docs/SETUP.md).

### Ciphertext format and key version

- PROPOSED: every stored ciphertext is the string `v<key_version>:` followed by `base64(nonce || ciphertext || tag)`. For v1 the stored value is `v1:` + base64(12-byte nonce || ciphertext || 16-byte tag).
- `key_version` is 1 in v1. The prefix exists so that a later key rotation can identify which key wrote each value without a schema change.
- Nonce: a fresh random 96-bit nonce for every encryption. Never reuse a nonce with the same key.
- Source: NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: GCM (https://csrc.nist.gov/pubs/sp/800/38/d/final). It defines the GCM IV and authentication tag. UNVERIFIED: the exact section that recommends the 96-bit IV and the 128-bit (16-byte) full tag. The fetched copy was an HTML page whose body could not be parsed; confirm the section numbers before citing them in code comments.
- The 12-byte nonce and 16-byte tag are the GCM sizes from NIST SP 800-38D. They are not chosen values.

### Derived keys

- PROPOSED: the session signing key, the backup key, and the CSRF key are derived from `HARBORGATE_ENCRYPTION_KEY` with HKDF-SHA256 (RFC 5869).
  - Session: info label `harborgate/session-v1`, output length 32 bytes (HS256 key).
  - Backup: info label `harborgate/backup-v1`, output length 32 bytes (AES-256 key).
  - CSRF: info label `harborgate/csrf-v1`, output length 32 bytes (HMAC-SHA256 key). Decided (2026-11-03).
- Use no salt (RFC 5869 section 3.1 allows an absent salt). The input key material is already 32 random bytes, so the salt is not needed for extraction.
- Source: RFC 5869, HKDF (https://www.rfc-editor.org/rfc/rfc5869). Section 3.2 describes the `info` input for domain separation, which is why each derived key has its own label.
- The HS256 key length follows RFC 7518 section 3.2 ("a key of the same size as the hash output", 256 bits for SHA-256).

### Key rotation

- Decided (2026-11-03): key re-encryption is a CLI command only. It is not an HTTP route and is not in the admin UI. Keys are never typed into the browser.
- The command runs offline with the app stopped. Both keys are read from the environment for that one run: `HARBORGATE_OLD_ENCRYPTION_KEY` (the key that wrote the current values) and `HARBORGATE_ENCRYPTION_KEY` (the new key).
- The command decrypts every stored ciphertext with the old key and re-encrypts it with the new key. It writes `v1:` values, and the key version does not change until a v2 format exists.
- The rewrite runs in a single transaction. If any row fails to decrypt, the whole transaction rolls back and no row changes.
- After the rewrite, the command appends a `key.rotate` audit row, the same way restore does, with actor `cli`. The row holds the count of rows rewritten and no key material.
- Key values are never logged, printed, or traced.

## Backup and restore

- Decided (2026-11-03): backup is created from Settings > Backup and restore in the admin UI (`POST /api/v1/admin/backup`). The admin UI does not restore.
- Backup: the backup uses the SQLite online backup API to write a consistent copy of the database.
- PROPOSED: the backup file is encrypted with AES-256-GCM using the derived backup key and the ciphertext format above. The file begins with a plain header `HGBK1` (5 bytes, ASCII) that identifies the format, and is followed by the nonce, ciphertext, and tag.
- PROPOSED: restore verifies the GCM authentication tag over the whole file before it writes anything. The live database is replaced only after the tag verifies. A file that fails verification is rejected and the live database is untouched.
- Source for the authenticated-encryption behaviour: NIST SP 800-38D (https://csrc.nist.gov/pubs/sp/800/38/d/final). Source for the SQLite online backup API: https://www.sqlite.org/backup.html. UNVERIFIED: that the online backup API page is current for the SQLx version used; confirm in the implementation.
- Default location: `/data/backups`. Operators may set another path with `HARBORGATE_BACKUP_DIR`.
- The command writes only to that path.
- If the directory is missing or not writable, the command fails with a clear error. The error is shown in the admin UI and logs. It never falls back to another location.
- Restore: Decided (2026-11-03). Restore is an offline command-line subcommand, for example `harborgate restore <file>`, run with the app stopped. It is not an HTTP route and not in the admin UI. Run it with the same `HARBORGATE_ENCRYPTION_KEY` that created the backup.
- Decided (2026-11-03): after the offline restore replaces the database, the command appends one `restore.run` audit row to the restored database. `details` holds the backup file name, the backup `created_at`, and the actor, recorded as `cli` (the operator running the command). See "Audit action vocabulary" in [database.md](database.md).
- Restore steps are documented in `docs/SETUP.md`.

## Authentication

- **Passwords:** PROPOSED: Argon2id with memory 19456 KiB (19 MiB), 2 iterations, and parallelism 1.
  - Source: OWASP Password Storage Cheat Sheet, which recommends "Argon2id with a minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism" (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
  - Source: RFC 9106, Argon2 (https://www.rfc-editor.org/rfc/rfc9106). Section 4 covers parameter choice.
  - The salt is 16 bytes (128 bits) from a CSPRNG. RFC 9106 section 4 (Parameter Choice) recommends a 128-bit salt, and the OWASP cheat sheet requires a unique salt per password.
  - Store the output as a PHC string in `users.password_hash`.
- **Password length:** Decided (2026-11-03): minimum 15 characters. Maximum accepted length 64 characters, which is the smallest maximum the cited guidance allows (it says a maximum should be at least 64).
  - Source: OWASP Authentication Cheat Sheet, which says passwords shorter than 15 characters are weak when MFA is not enabled (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
  - Source for the maximum: OWASP Authentication Cheat Sheet, which cites NIST SP 800-63B for a maximum of "at least 64 characters" (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
  - The rule applies everywhere a local password is set: setup, change-password, and admin-created local users (`POST /api/v1/admin/users`).
  - Violations return `400` with code `password_too_short` on those routes in [api.md](api.md).
  - No composition rules. OWASP says there should be "no requirement for upper or lower case or numbers or special characters."
- **Account lockout:** PROPOSED: after 10 failed login attempts for an account, the account is locked for 15 minutes. The failure counter is kept per account, not per IP.
  - Source: OWASP Authentication Cheat Sheet, "Account Lockout" (the counter belongs to the account, and the lockout threshold and duration must be balanced against denial of service). The values 10 and 15 minutes are not in that source. The OWASP cheat sheet gives "ten minutes" only as an example. PROPOSED, no external number for the threshold; tune in deployment.
  - To prevent lockout abuse for other users, the lock must not block password reset flows. No password reset is in v1, so this has no effect yet.
- **First-run setup:** the first local account created becomes `Admin`.
  - Decided (2026-11-03): the setup route is closed permanently once the first account exists. It is allowed only while the `users` table is empty. The insert runs in a single transaction that inserts only if the table is empty, so concurrent setup requests cannot create two first admins.
  - Decided (2026-11-03): local accounts are created by an admin in Settings > Users. OIDC accounts are created just-in-time on the user's first successful OIDC login, with no admin pre-creation.
  - The setup page design needs user approval before build.
- **OIDC:** configured in the Admin UI. Settings are the `oidc.*` keys in [database.md](database.md). Client secret encrypted (`is_encrypted = 1`).
  - PROPOSED: the issuer URL must be HTTPS. Source: OpenID Connect Discovery 1.0 (https://openid.net/specs/openid-connect-discovery-1_0.html), which specifies the https scheme for the issuer. UNVERIFIED: the exact section number.
  - PROPOSED: the OIDC user is identified by `(oidc_issuer, oidc_subject)`, not by email. Source: OpenID Connect Core 1.0, section 2, `sub` (locally unique and never reassigned within the issuer).
  - PROPOSED: the flow uses the authorization code grant with PKCE (S256). Source: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749), RFC 7636 (PKCE, https://www.rfc-editor.org/rfc/rfc7636). The `state` value is verified on callback to prevent CSRF, per RFC 6749 section 10.12 (Cross-Site Request Forgery, confirmed in the RFC table of contents).
  - Role on each OIDC login: the role is re-read from the configured group claim (`oidc.role_claim`) at each login. The group value is matched against `oidc.admin_group` and `oidc.user_group`. A user with neither group cannot sign in.
- **Local session role:** Decided: a local session's role is looked up from `users.role` on each request. A demotion takes effect on the next request, not at the next login. This matches the rule that an admin is revoked when demoted within the 8-hour session lifetime.
- **Break-glass:** local login stays available for admins only. It is not available to `User` accounts.
  - Decided (2026-11-03): OIDC settings and break-glass are managed in the Admin UI, Settings > OIDC. Settings are stored in `system_config` (the `oidc.*` keys in [database.md](database.md)). The client secret is encrypted with AES-256-GCM (`is_encrypted = 1`). The toggle on the same screen restricts regular users to OIDC sign-in; admin break-glass login is always available. Every change is audited as `oidc.config_change`, with `details` that never include the secret. Route: `GET` and `PUT /api/v1/admin/oidc` ([api.md](api.md)). Break-glass local login stays available to admins at all times, including after OIDC is configured. The toggle restricts only regular users to OIDC sign-in and never disables admin break-glass.
- Roles: `Admin` (system config, user management, global logs, read-only view of all tenants) and `User` (own credentials, own mappings, own sync history).

## Sessions

- PROPOSED: the session is a signed JWT in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. The cookie name `harborgate_session` is PROPOSED; no external source applies.
- Signing: HS256 with the derived session key. Source: RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519). Section 4.1.4 defines `exp`. Section 4.1.7 defines `jti`.
- Claims: `sub` (user id), `role` (informational only, see "Local session role"), `iat`, `exp`, `jti`.
- Validation on every request: verify the signature, the `exp` claim, and `alg` equal to `HS256`. Reject `alg: none`. Source: RFC 7519 section 6 (https://www.rfc-editor.org/rfc/rfc7519). UNVERIFIED: the RFC 8725 (JWT Best Current Practices) guidance on pinning the algorithm; it was not fetched.
- Expiry: 8 hours. `exp` is `iat` + 8 hours. The 8-hour lifetime is a user decision.
- Logout clears the cookie.
- No server-side revocation in v1. Because revocation is not server-side, an admin who is demoted keeps a valid JWT until the next request, but the request's role comes from the database (see "Local session role"), so the demotion takes effect immediately for authorization.
- Source for cookie attributes: OWASP Session Management Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), which covers the `Secure` and `HttpOnly` attributes. UNVERIFIED: the `SameSite=Lax` choice is a user decision; the fetched cheat sheet text was not checked for SameSite guidance.

## Hardening

- PROPOSED: rate limits on the login endpoint: 10 attempts per minute per client IP. PROPOSED: no external standard; tune in deployment.
- PROPOSED: rate limits on the webhook endpoint: 60 requests per minute per mapping token. PROPOSED: no external standard; tune in deployment.
- Decided (2026-11-03): no default rate limit on authenticated routes beyond the login and webhook limits above.
- PROPOSED: rate-limited responses return 429 with a `Retry-After` header. Source: RFC 6585 section 4 (429 Too Many Requests, https://www.rfc-editor.org/rfc/rfc6585), and RFC 9110 section 10.2.3 (Retry-After, https://www.rfc-editor.org/rfc/rfc9110).
- PROPOSED: request body cap on the webhook endpoint is 64 KiB. Harbor webhook payloads are small. UNVERIFIED: no sample payload size is in the repo; confirm with a real payload before release. The cap is 413 Content Too Large above the limit (RFC 9110 section 15.5.14).
- CSRF: Decided (2026-11-03): signed double-submit cookie. The cookie `harborgate_csrf` holds a token. The client must send the same value in the `X-CSRF-Token` header on every `POST`, `PUT`, `PATCH`, and `DELETE` under `/api`. Exempt: the webhook (token in URL, no cookie session) and the login endpoint (no session yet). Missing or mismatched token returns 403.
  - Source: OWASP CSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), which describes the Double Submit Cookie pattern, and recommends a custom request header and verifying the origin.
  - The OWASP sheet says the signed double-submit variant is stronger. Decided (2026-11-03): the token is HMAC-SHA256 signed with the CSRF key derived via HKDF label `harborgate/csrf-v1` (see "Derived keys"). Decided (2026-11-03): the CSRF token is bound only to the signed cookie value (HMAC over the cookie with the CSRF key). The session `jti` is not part of the CSRF binding.
- `SameSite=Lax` alone is not sufficient.

## Tenancy

- Users see only their own credentials, mappings, and sync history.
- Admins may view all of it, read-only.
- Admins cannot change another user's credentials or mappings.
- Decided (2026-11-03): the one operational exception to read-only admin access is retry. An admin may retry failed sync jobs of any tenant (`POST /api/v1/sync-jobs/:id/retry`). Retry only re-queues work and changes no mapping or credential.
- A credential may be referenced only by a mapping owned by the same user. The application checks this on write.

## Secrets in logs

- GitHub PATs, Harbor robot secrets, AES keys, the webhook URL token, and the webhook auth header value are never printed in logs, traces, or Server-Sent Events streams.
- The webhook URL token is redacted or omitted from access logs and traces. Access logs record the route template `/api/v1/webhooks/harbor/:mapping_token`, not the value.
- Audit `details` never contain tokens or key material.
- Error messages never include a secret value. Source: CLAUDE.md non-negotiable rules.

## Outbound HTTP (SSRF)

- PROPOSED: the Harbor base URL must use HTTPS. Plain HTTP is rejected.
- PROPOSED: the resolved address of the Harbor host must not be in loopback, link-local, or private ranges, unless the operator sets `HARBORGATE_ALLOW_PRIVATE_HARBOR=true`. The default is `false`.
  - Blocked by default: `127.0.0.0/8`, `::1/128`, `169.254.0.0/16` (includes the cloud metadata address `169.254.169.254`), `fe80::/10`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `0.0.0.0/8`, and multicast `224.0.0.0/4`, `ff00::/8`.
  - Source: OWASP SSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), "Deny-list" table, and its advice to validate resolved IPs. The deny-list is a last resort. The sheet prefers allow-lists.
  - The check applies to every resolved address (IPv4 and IPv6) and must be repeated when DNS changes, to prevent DNS rebinding. Source: the same OWASP cheat sheet, on DNS rebinding.
  - Redirects are not followed for Harbor or GitHub requests. Source: the OWASP cheat sheet, which says to disable redirects in the HTTP client.
- Private Harbor deployments are a real case. The `HARBORGATE_ALLOW_PRIVATE_HARBOR` option exists for them. Decided (2026-11-03): it is an environment variable only, not an Admin UI setting. Default `false`.

## GitHub token scope

- Fine-grained personal access token only in v1. No GitHub App support.
- Required permissions:
  - Contents: read
  - Code scanning alerts: read and write
  - Issues: read and write, only when auto-created issues are enabled
- The Health page reports missing scopes. See [frontend.md](frontend.md).
- PROPOSED: the Health check reads the `X-Accepted-GitHub-Permissions` header or the `X-OAuth-Scopes` header from the `GET /user` response. Source: GitHub REST API docs, "Troubleshooting the REST API" (https://docs.github.com/en/rest), which documents `X-Accepted-GitHub-Permissions` as the permissions an endpoint needs. UNVERIFIED: whether `GET /user` returns `X-Accepted-GitHub-Permissions` for fine-grained tokens. The verified header is for the endpoint's required permissions, not the token's granted permissions. The check must test granted permissions by calling the endpoints the token needs, then read the result. See [api.md](api.md).

## OPEN

- Decided (2026-11-03): local passwords have a minimum of 15 characters (OWASP Authentication Cheat Sheet, accounts without MFA). Argon2id parameters are unchanged (19456 KiB, 2 iterations, parallelism 1).
- Decided (2026-11-03): backup runs from the admin UI (Settings > Backup and restore). Restore runs from the CLI only, with the app stopped. See "Backup and restore".
- Decided (2026-11-03): CSRF uses the signed double-submit variant. See "Hardening".
- Decided (2026-11-03): `HARBORGATE_ALLOW_PRIVATE_HARBOR` is environment-only. See "Outbound HTTP (SSRF)".
- Decided (2026-11-03): key re-encrypt is a CLI command only, run offline with the app stopped and both keys in the environment. It is not an HTTP route and not in the admin UI. It runs in one transaction and appends a `key.rotate` audit row (actor `cli`) after the rewrite. See "Key rotation".
- Decided (2026-11-03): the OIDC, user management, alert settings, and backup/restore screens live in a fifth Admin tab, "Settings", after Health. See [frontend.md](frontend.md) for the tabs.
- Decided (2026-11-03): user creation and first-run. Local accounts are created by an admin in Settings > Users, which also handles delete and role change. OIDC accounts are created on first successful login. The first local account on a fresh install is Admin, and the setup route closes permanently once any user exists. The setup page design needs user approval before build.
