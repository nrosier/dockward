# Security

Purpose: encryption, key handling, backup and restore, authentication, sessions, hardening, tenancy, and secret handling.

Decisions are marked `Decided (<date>)`. On 2026-11-03 the user delegated every remaining proposal; those decisions are marked `Decided (2026-11-03, delegated)`. `Verified (<date>)` marks a claim checked against the cited source on that date. `UNVERIFIED:` marks a claim that can only be checked against a live system or a later build.

## Encryption and keys

- `HARBORGATE_ENCRYPTION_KEY` is read from the environment and is required. The app refuses to start without it.
- No file fallback for the key.
- AES-256-GCM encrypts stored user credentials (GitHub PATs, Harbor robot secrets, OIDC client secrets) and alert SMTP and webhook secrets. Decided (2026-11-03): the per-mapping webhook token and auth header secret are not encrypted. Only their SHA-256 digests are stored. See [integrations.md](integrations.md).
- Losing `HARBORGATE_ENCRYPTION_KEY` makes stored credentials unrecoverable. Operators must back it up separately.
- The credential encryption key, the session signing key, the backup key, and the CSRF key are all derived from `HARBORGATE_ENCRYPTION_KEY`. Decided (2026-11-03): the raw key is input key material only and is never used directly to encrypt or sign. See "Derived keys" below.

### Encryption key format

- Decided (2026-11-03, delegated): `HARBORGATE_ENCRYPTION_KEY` is the base64 encoding of exactly 32 random bytes. The app refuses to start if the value does not decode to exactly 32 bytes.
- Source: AES-256 uses a 256-bit key (FIPS 197, https://csrc.nist.gov/pubs/fips/197/final). The 32-byte length follows from that. Base64 is the encoding that `openssl rand -base64 32` already produces in [docs/SETUP.md](../docs/SETUP.md).

### Ciphertext format and key version

- Decided (2026-11-03, delegated): every stored ciphertext is the string `v<key_version>:` followed by `base64(nonce || ciphertext || tag)`. For v1 the stored value is `v1:` + base64(12-byte nonce || ciphertext || 16-byte tag).
- `key_version` is 1 in v1. The prefix exists so that a later key rotation can identify which key wrote each value without a schema change.
- Nonce: a fresh random 96-bit nonce for every encryption. Never reuse a nonce with the same key.
- Decided (2026-11-03): values are encrypted with the derived credential key (HKDF label `harborgate/credentials-v1`), not with the raw `HARBORGATE_ENCRYPTION_KEY`.
- Decided (2026-11-03): each value is bound to where it is stored through GCM additional authenticated data (AAD). The AAD is the UTF-8 string `<table>:<column>:<row id>`, for example `user_credentials:encrypted_token:<id>`. For `system_config` the row id is the key, for example `system_config:value:oidc.client_secret_encrypted`. A ciphertext copied to another row, column, or table fails to decrypt. The AAD is not stored. It is rebuilt from the row on every read. Source: NIST SP 800-38D (https://csrc.nist.gov/pubs/sp/800/38/d/final), which defines the GCM additional authenticated data input.
- Source: NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: GCM (https://csrc.nist.gov/pubs/sp/800/38/d/final). It defines the GCM IV and authentication tag. Verified (2026-11-03) against the SP 800-38D PDF: section 5.2.1.1 recommends restricting IVs to 96 bits; section 5.2.1.2 lists the tag lengths 128, 120, 112, 104, and 96 bits (128 is the full 16-byte tag); section 8.2.2 defines the random (RBG-based) IV construction; and section 8.3 limits a key to 2^32 encryptions when IVs are random. Decided (2026-11-03, delegated): that limit is far above HarborGate's expected volume, and a key rotation (see "Key rotation") starts a new count.
- The 12-byte nonce and 16-byte tag are the GCM sizes from NIST SP 800-38D. They are not chosen values.

### Derived keys

- Decided (2026-11-03, delegated): the session signing key, the backup key, and the CSRF key are derived from `HARBORGATE_ENCRYPTION_KEY` with HKDF-SHA256 (RFC 5869).
  - Session: info label `harborgate/session-v1`, output length 32 bytes (HS256 key).
  - Backup: info label `harborgate/backup-v1`, output length 32 bytes (AES-256 key).
  - CSRF: info label `harborgate/csrf-v1`, output length 32 bytes (HMAC-SHA256 key). Decided (2026-11-03).
  - Credentials: info label `harborgate/credentials-v1`, output length 32 bytes (AES-256-GCM key for every stored ciphertext). Decided (2026-11-03).
- Use no salt (RFC 5869 section 3.1 allows an absent salt). The input key material is already 32 random bytes, so the salt is not needed for extraction.
- Source: RFC 5869, HKDF (https://www.rfc-editor.org/rfc/rfc5869). Section 3.2 describes the `info` input for domain separation, which is why each derived key has its own label.
- The HS256 key length follows RFC 7518 section 3.2 ("a key of the same size as the hash output", 256 bits for SHA-256).

### Key rotation

- Decided (2026-11-03): key re-encryption is a CLI command only. It is not an HTTP route and is not in the admin UI. Keys are never typed into the browser.
- The command runs offline with the app stopped. Both keys are read from the environment for that one run: `HARBORGATE_OLD_ENCRYPTION_KEY` (the key that wrote the current values) and `HARBORGATE_ENCRYPTION_KEY` (the new key).
- The command decrypts every stored ciphertext with the credential key derived from the old key and re-encrypts it with the credential key derived from the new key. The AAD of each value is unchanged. It writes `v1:` values, and the key version does not change until a v2 format exists. The webhook token and auth secret digests do not depend on the key and are not rewritten.
- The rewrite runs in a single transaction. If any row fails to decrypt, the whole transaction rolls back and no row changes.
- After the rewrite, the command appends a `key.rotate` audit row, the same way restore does, with actor `cli`. The row holds the count of rows rewritten and no key material.
- Key values are never logged, printed, or traced.

## Backup and restore

- Decided (2026-11-03): backup is created from Settings > Backup and restore in the admin UI (`POST /api/v1/admin/backup`). The admin UI does not restore.
- Backup: the backup writes a consistent copy of the database with `VACUUM INTO` (see the source note below).
- Decided (2026-11-03, delegated): the backup file is encrypted with AES-256-GCM using the derived backup key and the ciphertext format above. The file begins with a plain header `HGBK1` (5 bytes, ASCII) that identifies the format, and is followed by the nonce, ciphertext, and tag. Decided (2026-11-03, delegated): the header bytes are the GCM AAD, so a changed header fails verification. A backup can be restored only with the `HARBORGATE_ENCRYPTION_KEY` that created it. After a key rotation, older backups need the old key, so operators keep the old key for as long as they keep backups made with it.
- Decided (2026-11-03, delegated): restore verifies the GCM authentication tag over the whole file before it writes anything. The live database is replaced only after the tag verifies. A file that fails verification is rejected and the live database is untouched.
- Source for the authenticated-encryption behaviour: NIST SP 800-38D (https://csrc.nist.gov/pubs/sp/800/38/d/final). Decided (2026-11-03, delegated): the consistent copy is made with `VACUUM INTO '<temporary file>'`, which SQLite documents as producing "a consistent snapshot" of the database (https://www.sqlite.org/lang_vacuum.html, verified (2026-11-03)). SQLite's online backup API is not used, because SQLx does not expose it (verified (2026-11-03): the SQLx source has no `sqlite3_backup_init` binding). The temporary file is written in `HARBORGATE_DATA_DIR`, next to the live database, encrypted into `HARBORGATE_BACKUP_DIR`, then deleted.
- Default location: `/data/backups`. Operators may set another path with `HARBORGATE_BACKUP_DIR`.
- The command writes only to that path.
- If the directory is missing or not writable, the command fails with a clear error. The error is shown in the admin UI and logs. It never falls back to another location.
- Restore: Decided (2026-11-03). Restore is an offline command-line subcommand, for example `harborgate restore <file>`, run with the app stopped. It is not an HTTP route and not in the admin UI. Run it with the same `HARBORGATE_ENCRYPTION_KEY` that created the backup.
- Decided (2026-11-03): after the offline restore replaces the database, the command appends one `restore.run` audit row to the restored database. `details` holds the backup file name, the backup `created_at`, and the actor, recorded as `cli` (the operator running the command). See "Audit action vocabulary" in [database.md](database.md).
- Restore steps are documented in `docs/SETUP.md`.

## Authentication

- **Passwords:** Decided (2026-11-03, delegated): Argon2id with memory 19456 KiB (19 MiB), 2 iterations, and parallelism 1.
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
- **Failed-login throttling:** Decided (2026-11-03): there is no hard account lockout. The login route is public, so a lockout would let anyone who knows an admin's username block admin break-glass access.
  - Progressive delay, kept per (account, client IP) pair, so failures from one address do not delay the real user at another address. Decided (2026-11-03, delegated) values: after 5 consecutive failures for a pair, each further attempt must wait 2^(n-5) seconds after the previous failure (1 s, 2 s, 4 s, and so on), capped at 60 seconds. A successful login resets the counter. An attempt inside the wait returns the same `401 invalid_credentials` without checking the password. Decided (2026-11-03, delegated): no external source for the numbers; tune in deployment.
  - Per client IP: the login rate limit under "Hardening". The client IP is derived as described under "Client IP".
  - Source: OWASP Authentication Cheat Sheet, "Account Lockout" (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), which warns that lockout can be abused for denial of service. Verified (2026-11-03) in the cheat sheet source: it describes an exponential lockout that starts at about one second and doubles after each failure, and warns that lockout can be used to deny service to other users.
- **Equal-time failures:** Decided (2026-11-03): a login for an unknown username, for an OIDC-only user, or for a regular local user while local login is restricted still runs an Argon2id verification against a fixed dummy PHC hash with the same parameters. The response time then does not reveal whether the account exists. Source: OWASP Authentication Cheat Sheet, authentication and error messages (same URL).
- **First-run setup:** the first local account created becomes `Admin`.
  - Decided (2026-11-03): the setup route is closed permanently once the first account exists. It is allowed only while the `users` table is empty. The insert runs in a single transaction that inserts only if the table is empty, so concurrent setup requests cannot create two first admins.
  - Decided (2026-11-03): local accounts are created by an admin in Settings > Users. OIDC accounts are created just-in-time on the user's first successful OIDC login, with no admin pre-creation.
  - The setup page design needs user approval before build.
- **OIDC:** configured in the Admin UI. Settings are the `oidc.*` keys in [database.md](database.md). Client secret encrypted (`is_encrypted = 1`).
  - Decided (2026-11-03, delegated): the issuer URL must be HTTPS. Source: OpenID Connect Discovery 1.0 (https://openid.net/specs/openid-connect-discovery-1_0.html), which specifies the https scheme for the issuer. Verified (2026-11-03): section 3, OpenID Provider Metadata, `issuer`: "URL using the https scheme with no query or fragment components".
  - Decided (2026-11-03, delegated): the OIDC user is identified by `(oidc_issuer, oidc_subject)`, not by email. Source: OpenID Connect Core 1.0, section 2, `sub` (locally unique and never reassigned within the issuer).
  - Decided (2026-11-03, delegated): the flow uses the authorization code grant with PKCE (S256). Source: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749), RFC 7636 (PKCE, https://www.rfc-editor.org/rfc/rfc7636). The `state` value is verified on callback to prevent CSRF, per RFC 6749 section 10.12 (Cross-Site Request Forgery, confirmed in the RFC table of contents).
  - Decided (2026-11-03): the authorization request also carries a random `nonce`. The `state`, the PKCE verifier, and the `nonce` are kept in the short-lived `__Host-harborgate_oidc` cookie (see "Sessions"). The ID token's `nonce` claim must equal it, or the callback fails with 401. Source: OpenID Connect Core 1.0 (https://openid.net/specs/openid-connect-core-1_0.html), the `nonce` request parameter and ID token validation. Verified (2026-11-03): sections 3.1.2.1 (Authentication Request, `nonce`) and 3.1.3.7 (ID Token Validation).
  - Role on each OIDC login: the role is re-read from the configured group claim (`oidc.role_claim`) at each login. The group value is matched against `oidc.admin_group` and `oidc.user_group`. A user with neither group cannot sign in.
  - Decided (2026-11-03): for OIDC users the group claim is the only source of the role. An admin cannot change an OIDC user's role in the UI or the API. `PUT /api/v1/admin/users/:id/role` returns `409 conflict` for an OIDC user. Role changes for OIDC users are made in the identity provider and apply at that user's next login.
- **Local session role:** Decided: a local session's role is looked up from `users.role` on each request. A demotion takes effect on the next request, not at the next login. This matches the rule that an admin is revoked when demoted within the 8-hour session lifetime.
- **Local login:** Decided (2026-11-03): admins can always sign in with a local password (break-glass), including after OIDC is configured. Regular users with a local account can sign in locally unless the "OIDC only for regular users" toggle in Settings > OIDC is on. While the toggle is on, a `user` login with a local password gets `401 invalid_credentials`. The toggle never affects admins.
  - Decided (2026-11-03, delegated): the toggle is stored as the `system_config` key `auth.oidc_only_users` (see [database.md](database.md)). It can be turned on only while the OIDC settings are complete; otherwise `PUT /api/v1/admin/oidc` returns 422.
  - Decided (2026-11-03): OIDC settings and break-glass are managed in the Admin UI, Settings > OIDC. Settings are stored in `system_config` (the `oidc.*` keys in [database.md](database.md)). The client secret is encrypted with AES-256-GCM (`is_encrypted = 1`). The toggle on the same screen restricts regular users to OIDC sign-in; admin break-glass login is always available. Every change is audited as `oidc.config_change`, with `details` that never include the secret. Route: `GET` and `PUT /api/v1/admin/oidc` ([api.md](api.md)). Break-glass local login stays available to admins at all times, including after OIDC is configured. The toggle restricts only regular users to OIDC sign-in and never disables admin break-glass.
  - Decided (2026-11-03): OIDC is configured only when issuer, client ID, client secret, role claim, and at least one group (admin or user) are all set. Settings missing any of these leave OIDC unconfigured: start and callback return 404, and the toggle cannot be turned on.
  - Decided (2026-11-03): clearing an optional OIDC setting deletes its `system_config` row. No empty values are stored.
  - Decided (2026-11-03): the `user.role_change` audit entry written at OIDC login names the user as actor, with `details.source` set to `"oidc"`.
  - Decided (2026-11-03, delegated, #49): a sign-in refused for having no allowed group ends that user's existing sessions. For an existing user, the callback bumps `token_version` and writes `user.role_change` (`to: null`, `source: "oidc"`) in one transaction, so the old session fails with `401` at the next request. A user who does not exist has no session, so no row is created.
  - Decided (2026-11-03, delegated, #49): once OIDC is configured, every callback outcome is `302`. Success goes to `/`. A failure, or the provider's `error` parameter, goes to `/?oidc_error=<code>`, where `<code>` is the `AppError` code or `provider_error`. Provider text never goes in the URL. The `__Host-harborgate_oidc` cookie is cleared on every outcome. While OIDC is not configured, the callback returns `404`.
  - Decided (2026-11-03): the issuer is compared as an exact string against the configured value, both for the discovery `issuer` and the ID token `iss`. No URL normalisation (for example, no trailing-slash trimming).
  - Decided (2026-11-03): a JWKS refresh for an unknown `kid` happens at most once per minute (`JWKS_REFRESH_MIN_INTERVAL = 60s`).
- Roles: `Admin` (system config, user management, global logs, read-only view of all tenants) and `User` (own credentials, own mappings, own sync history).

## Sessions

- Decided (2026-11-03, delegated): the session is a signed JWT in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. The base cookie names are Decided (2026-11-03, delegated); no external source applies.
- Decided (2026-11-03): every HarborGate cookie uses the `__Host-` prefix. It is therefore `Secure`, has `Path=/`, and has no `Domain` attribute, and the browser rejects a cookie of that name set by a sibling subdomain. Names: `__Host-harborgate_session` (session), `__Host-harborgate_csrf` (CSRF), and `__Host-harborgate_oidc` (OIDC `state`, PKCE verifier, and `nonce`; lifetime 10 minutes, Decided 2026-11-03, delegated). Source: RFC 6265bis, draft 22, section 4.1.3.2, "The __Host- Prefix" (https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/, verified (2026-11-03)). Development over `http://localhost` works: MDN's `Set-Cookie` reference states that the `https:` requirement of `Secure` is ignored on localhost (verified (2026-11-03)).
- Signing: HS256 with the derived session key. Source: RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519). Section 4.1.4 defines `exp`. Section 4.1.7 defines `jti`.
- Claims: `sub` (user id), `role` (informational only, see "Local session role"), `iat`, `exp`, `jti`, and `ver` (the user's `users.token_version` when the token was issued).
- Validation on every request: verify the signature, the `exp` claim, `alg` equal to `HS256`, and `ver` equal to the user's current `users.token_version` (read in the same per-request user lookup as the role). Reject `alg: none`. Source: RFC 7519 section 6 (https://www.rfc-editor.org/rfc/rfc7519). RFC 8725 section 3.1, "Perform Algorithm Verification" (verified (2026-11-03)), requires the verifier to accept only an allowed set of algorithms and to use each key with exactly one algorithm. The derived session key is used only for HS256.
- Expiry: 8 hours. `exp` is `iat` + 8 hours. The 8-hour lifetime is a user decision.
- Logout clears the cookie.
- Decided (2026-11-03): revocation is per user through `users.token_version`. `POST /api/v1/auth/logout-all` and a password change both increment it, which invalidates every existing session of that user. The session that changed the password receives a fresh cookie. Deleting a user removes the row, so that user's sessions fail the per-request lookup.
- A single logout only clears the browser cookie. A copied JWT stays valid until `exp` or until the next `token_version` change. Decided (2026-11-03, delegated): no per-session `jti` denylist in v1.
- An admin who is demoted keeps a valid JWT, but the request's role comes from the database (see "Local session role"), so the demotion takes effect immediately for authorization.
- Source for cookie attributes: OWASP Session Management Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), which covers the `Secure` and `HttpOnly` attributes. Verified (2026-11-03): the cheat sheet's "SameSite Attribute" section describes `Strict` and `Lax`. `Lax` is used because the OIDC callback is a top-level cross-site navigation from the identity provider and must carry the `__Host-harborgate_oidc` cookie; `Strict` would drop it.

## Hardening

- Decided (2026-11-03, delegated): rate limits on the login endpoint: 10 attempts per minute per client IP. Decided (2026-11-03, delegated): no external standard; tune in deployment. The client IP is derived as in "Client IP" below.
- Client IP: Decided (2026-11-03): the client IP is the TCP peer address, unless the peer is inside `HARBORGATE_TRUSTED_PROXIES` (see [deployment.md](deployment.md)). In that case the client IP is the rightmost address in `X-Forwarded-For` that is not itself a trusted proxy. With the default empty list, `X-Forwarded-For` is ignored. Decided (2026-11-03, delegated): `CF-Connecting-IP` is not read; Traefik passes the client address on in `X-Forwarded-For`. Source: MDN, `X-Forwarded-For`, security and privacy concerns (https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For). Verified (2026-11-03): MDN states that any security-related use, such as rate limiting, "must only use IP addresses added by a trusted proxy". Verified (2026-11-03), header chain in the reference setup (Cloudflare edge, cloudflared, Traefik, HarborGate):
  - The Cloudflare edge sends `X-Forwarded-For` with the visitor IP. If the visitor already sent the header, the edge appends the address that connected to it. Either way, the rightmost entry from the edge is the address that connected to Cloudflare. Source: Cloudflare docs, HTTP request headers (https://developers.cloudflare.com/fundamentals/reference/http-headers/).
  - cloudflared does not change `X-Forwarded-For`. It only sets `X-Forwarded-Host` when an origin Host header is configured (`ingress/origin_proxy.go` in cloudflare/cloudflared).
  - Traefik deletes incoming `X-Forwarded-*` headers when the peer is not in the entry point's `forwardedHeaders.trustedIPs`, and then appends the peer address (`pkg/middlewares/forwardedheaders/forwarded_header.go` in traefik/traefik; Traefik docs, EntryPoints, `forwardedHeaders.trustedIPs`). With no trusted IPs set, HarborGate would see only cloudflared's address, and all visitors would share one rate-limit bucket.
  - Decided (2026-11-03, delegated): the reference setup requires two settings. The Traefik entry point trusts cloudflared's source address (`forwardedHeaders.trustedIPs`). `HARBORGATE_TRUSTED_PROXIES` lists Traefik's address and cloudflared's source address. HarborGate then receives `X-Forwarded-For: [visitor-sent entries,] <visitor IP>, <cloudflared IP>` from peer Traefik, and the rightmost entry that is not a trusted proxy is the visitor IP. Steps: [deployment.md](deployment.md), "Client IP behind Cloudflare and Traefik".
  - Decided (2026-11-03), as implemented in `backend/src/api/hardening.rs`: entries that do not parse as an IP address are skipped. If the header is missing, or every usable entry is a trusted proxy, the client IP is the TCP peer address.
  - The addresses themselves depend on the host, because Docker assigns network subnets dynamically. The operator confirms them with the client IP check on the Health page ([api.md](api.md), "Health"). The live smoke test records them once.
- Decided (2026-11-03, delegated): rate limits on the webhook endpoint: 60 requests per minute per mapping token, and 30 failed authentications (`401`) per minute per client IP, so requests with unknown tokens are limited too. No external standard; tune in deployment.
- Decided (2026-11-03): no default rate limit on authenticated routes beyond the login and webhook limits above.
- Decided (2026-11-03, delegated): rate-limited responses return 429 with a `Retry-After` header. Source: RFC 6585 section 4 (429 Too Many Requests, https://www.rfc-editor.org/rfc/rfc6585), and RFC 9110 section 10.2.3 (Retry-After, https://www.rfc-editor.org/rfc/rfc9110).
- Decided (2026-11-03, delegated): request body cap on the webhook endpoint is 64 KiB. Harbor webhook payloads are small. Verified (2026-11-03) in the Harbor source (`src/pkg/notifier/model/event.go`, `src/controller/event/handler/webhook/scan/scan.go`): a scan event carries one resource (digest, tag, resource URL, scan overview summary) and the repository fields. The live smoke test records the size of a real payload. The cap is 413 Content Too Large above the limit (RFC 9110 section 15.5.14).
- CSRF: Decided (2026-11-03): signed double-submit cookie. The cookie `__Host-harborgate_csrf` holds a token. The client must send the same value in the `X-CSRF-Token` header on every `POST`, `PUT`, `PATCH`, and `DELETE` under `/api`. Exempt: the webhook (token in URL, no cookie session) and the login and setup endpoints (no session yet), which use the same-origin check below instead. Missing or mismatched token returns 403.
  - Source: OWASP CSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), which describes the Double Submit Cookie pattern, and recommends a custom request header and verifying the origin.
  - The OWASP sheet says the signed double-submit variant is stronger. Decided (2026-11-03): the token is HMAC-SHA256 signed with the CSRF key derived via HKDF label `harborgate/csrf-v1` (see "Derived keys"). Decided (2026-11-03): the CSRF token is bound only to the signed cookie value (HMAC over the cookie with the CSRF key). The session `jti` is not part of the CSRF binding.
- `SameSite=Lax` alone is not sufficient.
- Login CSRF: Decided (2026-11-03): `POST /api/v1/auth/login` and `POST /api/v1/auth/setup` require a same-origin request. The `Origin` header must equal the origin of `HARBORGATE_PUBLIC_URL`. When `Origin` is absent, `Sec-Fetch-Site` must be `same-origin`. When neither header is present, or a value does not match, the response is `403 csrf_invalid`. This stops another site from signing a victim in to an attacker's account. Source: OWASP CSRF Prevention Cheat Sheet, login CSRF and verifying origin with standard headers (same URL as above); W3C Fetch Metadata Request Headers (https://www.w3.org/TR/fetch-metadata/).
- Security headers: Decided (2026-11-03): the backend sets these headers on every response, so they apply behind any proxy:
  - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, plus (Decided 2026-11-03, delegated) `base-uri 'none'; form-action 'self'; object-src 'none'`.
  - `X-Content-Type-Options: nosniff`.
  - `Referrer-Policy: no-referrer`.
  - `Strict-Transport-Security` is set by Traefik, not by the app, because the app cannot tell whether TLS ends in front of it.
  - Source: OWASP HTTP Headers Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
  - Verified (2026-11-03), styles under `default-src 'self'`:
    - The production build links CSS as files. The scaffold's `vite build` (Vite 8, `@tailwindcss/vite` 4) emits `<link rel="stylesheet" href="/assets/index-<hash>.css">` and an external module script, with no inline `<style>`, inline script, or `data:` URI.
    - React applies the `style` prop with CSSOM property setters (`style[name] = value`, `style.setProperty`), in `setValueForStyle` in react-dom 19.3.1 `react-dom-client`. Recharts 3.10.1 measures text with `Object.assign(span.style, ...)` (`es6/util/DOMUtils.js`). CSP does not block CSSOM property setters, only the `style` attribute in markup and `setAttribute("style")` and `cssText` (MDN, CSP `style-src`, https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src). Neither library needs `'unsafe-inline'`.
    - Radix UI does inject `<style>` elements, and `'self'` blocks them. The Select viewport (`@radix-ui/react-select` 2.4.1) and the ScrollArea viewport (`@radix-ui/react-scroll-area` 1.4.0) take a `nonce` prop. Dialog's scroll lock comes from `react-remove-scroll-bar` through `react-style-singleton` 2.2.3, which reads its nonce from `get-nonce`.
    - Vite inlines small assets as `data:` URIs by default, and `default-src 'self'` blocks those (Vite docs, Features, "Content Security Policy (CSP)").
  - Decided (2026-11-03, delegated): the HTML policy is `default-src 'self'; style-src 'self' 'nonce-<n>'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'`. `<n>` is 16 random bytes, base64-encoded, new for every HTML response. There is no `'unsafe-inline'` and no `'unsafe-eval'`. Scripts need no nonce, because every script is an external file.
    - Vite `html.cspNonce` is set to a fixed placeholder. Vite then adds `nonce` to its tags and emits `<meta property="csp-nonce" nonce="...">`. On every HTML response the backend replaces the placeholder in the embedded `index.html` and sends the same value in the CSP header. HTML responses carry `Cache-Control: no-store`. Hashed assets under `/assets/` stay cacheable.
    - The frontend reads the nonce from the meta element's `nonce` property, not `getAttribute`, because browsers hide the attribute value. It calls `setNonce` from `get-nonce` before the first render, and passes `nonce` to the Radix Select and ScrollArea viewports.
    - `build.assetsInlineLimit` is `0`, so the build has no `data:` URIs.
    - API and other non-HTML responses carry the policy without a nonce source.
    - Tests: a backend test checks that each HTML response has a fresh nonce, that the header and `index.html` carry the same value, and that no placeholder is left. The live smoke test opens each page and fails on any `securitypolicyviolation` event ([testing-and-ci.md](testing-and-ci.md)).

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

- Decided (2026-11-03, delegated): the Harbor base URL must use HTTPS. Plain HTTP is rejected.
- Decided (2026-11-03, delegated): the resolved address of the Harbor host must not be in loopback, link-local, or private ranges, unless the operator sets `HARBORGATE_ALLOW_PRIVATE_HARBOR=true`. The default is `false`.
  - Blocked by default: `127.0.0.0/8`, `::1/128`, `169.254.0.0/16` (includes the cloud metadata address `169.254.169.254`), `fe80::/10`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `0.0.0.0/8`, and multicast `224.0.0.0/4`, `ff00::/8`.
  - Source: OWASP SSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), "Deny-list" table, and its advice to validate resolved IPs. The deny-list is a last resort. The sheet prefers allow-lists.
  - The check applies to every resolved address (IPv4 and IPv6) and must be repeated when DNS changes, to prevent DNS rebinding. Source: the same OWASP cheat sheet, on DNS rebinding.
  - Redirects are not followed for Harbor or GitHub requests. Source: the OWASP cheat sheet, which says to disable redirects in the HTTP client.
- Private Harbor deployments are a real case. The `HARBORGATE_ALLOW_PRIVATE_HARBOR` option exists for them. Decided (2026-11-03): it is an environment variable only, not an Admin UI setting. Default `false`.
- Scope: Decided (2026-11-03): the rules in this section (HTTPS only, the resolved-address check, re-checking on DNS change, no redirects) apply to every outbound URL that an admin or user enters, not only to Harbor:
  - the Harbor base URL;
  - the OIDC issuer URL and every endpoint taken from its discovery document (authorization, token, JWKS, userinfo);
  - alert webhook URLs. The SMTP host gets the same address check.
  - Each class has its own environment-only opt-out, default `false`: `HARBORGATE_ALLOW_PRIVATE_HARBOR`, `HARBORGATE_ALLOW_PRIVATE_OIDC`, and `HARBORGATE_ALLOW_PRIVATE_ALERTS`. The last two names are Decided (2026-11-03, delegated).
  - GitHub requests go only to the fixed host `api.github.com`, which is not user-entered.

## GitHub token scope

- Fine-grained personal access token only in v1. No GitHub App support.
- Required permissions:
  - Metadata: read (always included in fine-grained tokens)
  - Code scanning alerts: read and write
  - Issues: read and write, for automatic and manual issue creation (`POST /api/v1/cves/:id/issue` is always available, so a token without it can still sync SARIF but cannot create issues)
- Verified (2026-11-03) against GitHub's "Permissions required for fine-grained personal access tokens": `POST /repos/{owner}/{repo}/code-scanning/sarifs` needs Code scanning alerts write; `GET .../code-scanning/sarifs/{sarif_id}` and `GET .../code-scanning/alerts` need Code scanning alerts read; `POST` and `GET /repos/{owner}/{repo}/issues` need Issues write and read; `GET /repos/{owner}/{repo}` needs Metadata read. Decided (2026-11-03, delegated): Contents: read is dropped, because no endpoint HarborGate calls needs it.
- The Health page reports missing scopes. See [frontend.md](frontend.md).
- Decided (2026-11-03, delegated): the Health check tests granted permissions by calling endpoints, not by reading headers. `X-Accepted-GitHub-Permissions` reports what an endpoint needs, not what the token has. The probes are `GET /repos/{owner}/{repo}` (Metadata read), `GET /repos/{owner}/{repo}/code-scanning/alerts?per_page=1` (Code scanning alerts read), and `GET /repos/{owner}/{repo}/issues?per_page=1` (Issues read). A `401` marks the token invalid and a `403` marks that permission missing. Write permissions cannot be probed without writing, so a missing write permission shows up as a failed upload or issue call in Sync jobs. See [api.md](api.md).
- Decided (2026-11-03, user, #21): the credential test always runs the issues probe. A `403` there is a warning, not a failure: the check is reported with `ok: true` and `warning: "issues_permission_missing"`, and the detail says the Issues permission is needed for automatic and manual issues. The test still passes, because SARIF upload does not need Issues. Saving a mapping with `auto_create_issues` on runs the same probe on the mapping's repository and rejects a `403` with `422 validation_failed` ("the GitHub token lacks the Issues permission needed for auto-created issues").
- Decided (2026-11-03, delegated): classifying probe responses. GitHub returns `403` both for a missing permission and for a repository where code scanning is unavailable. Neither case has a machine-readable code, so HarborGate matches the error `message`, ignoring case:
  - `403` with "Resource not accessible by personal access token": the permission is missing (GitHub docs, Troubleshooting the REST API, "Resource not accessible"). The `X-Accepted-GitHub-Permissions` response header names the permission the endpoint needs, and it is copied into `detail`.
  - Code scanning probe, `403` whose message contains "code scanning is not enabled", "advanced security must be enabled", or "code security must be enabled": code scanning is unavailable for the repository. This is reported as `code_scanning: "unavailable"`, not as a missing permission.
  - Code scanning probe, `404` with "no analysis found": the token can read alerts, but no analysis has been uploaded yet. This is healthy, `code_scanning: "no_analysis_yet"`.
  - Any other `404`: the token cannot see the repository, because it is not among the token's selected repositories or the owner or name is wrong.
  - Any other `403`: reported as a missing permission, with the raw message in `detail`.
  - Sources: the GitHub REST OpenAPI description (`code_scanning_forbidden_read`: "Response if GitHub Advanced Security is not enabled for this repository"; `404` "Resource not found"). The message texts match what GitHub's own `github/gh-gei` (`no analysis found`, analyses endpoint) and two independent clients (`flanksource/config-db`, `ArloL/drifty`) check for. GitHub can reword a message. An unmatched message falls back to the generic `403` or `404` rule, which surfaces an error and never hides one. The live smoke test records the real response bodies.
- Verified (2026-11-03): code scanning, and with it SARIF upload, is available only for public repositories on github.com and for organization-owned repositories on GitHub Team or Enterprise with GitHub Code Security enabled (GitHub docs, `data/reusables/gated-features/code-scanning.md`). A private repository owned by a personal account cannot receive uploads. Decided (2026-11-03, delegated): saving a mapping runs the code scanning probe and rejects `unavailable` with `422 code_scanning_unavailable`, so the problem shows when the mapping is set up, not at the first sync.

## OPEN

- Decided (2026-11-03): local passwords have a minimum of 15 characters (OWASP Authentication Cheat Sheet, accounts without MFA). Argon2id parameters are unchanged (19456 KiB, 2 iterations, parallelism 1).
- Decided (2026-11-03): backup runs from the admin UI (Settings > Backup and restore). Restore runs from the CLI only, with the app stopped. See "Backup and restore".
- Decided (2026-11-03): CSRF uses the signed double-submit variant. See "Hardening".
- Decided (2026-11-03): `HARBORGATE_ALLOW_PRIVATE_HARBOR` is environment-only. See "Outbound HTTP (SSRF)".
- Decided (2026-11-03): key re-encrypt is a CLI command only, run offline with the app stopped and both keys in the environment. It is not an HTTP route and not in the admin UI. It runs in one transaction and appends a `key.rotate` audit row (actor `cli`) after the rewrite. See "Key rotation".
- Decided (2026-11-03): the OIDC, user management, alert settings, and backup/restore screens live in a fifth Admin tab, "Settings", after Health. See [frontend.md](frontend.md) for the tabs.
- Decided (2026-11-03): user creation and first-run. Local accounts are created by an admin in Settings > Users, which also handles delete and role change. OIDC accounts are created on first successful login. The first local account on a fresh install is Admin, and the setup route closes permanently once any user exists. The setup page design needs user approval before build.
