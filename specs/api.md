# API

Purpose: the HTTP route contract between the frontend, Harbor, and the backend. One place for every route, its auth level, request and response shape, and status codes.

Decided (2026-11-03, delegated): this route contract is approved, with the changes recorded below. Nothing here is implemented. Where a value comes from a user decision elsewhere in `specs/`, the owning file is linked. Decisions are marked `Decided (<date>)`. On 2026-11-03 the user delegated every remaining proposal; those decisions are marked `Decided (2026-11-03, delegated)`. `Verified (<date>)` marks a claim checked against the cited source on that date. `UNVERIFIED:` marks a claim that can only be checked against a live system or a later build.

## Conventions

- Base path: `/api/v1`. Exceptions: `GET /healthz` (see [deployment.md](deployment.md)).
- Caching: every response under `/api/` carries `Cache-Control: no-store` (Decided 2026-11-04, #50; see [security.md](security.md), Hardening).
- Format: JSON request and response bodies, `Content-Type: application/json`. Decided (2026-11-03, delegated): no external source.
- Casing: Decided (2026-11-03, delegated): snake_case for all JSON fields.
- Timestamps: Decided (2026-11-03, delegated): RFC 3339 `date-time` strings in UTC, for example `2026-11-02T09:30:00Z`. Source: RFC 3339 section 5.6 (https://www.rfc-editor.org/rfc/rfc3339).
- IDs: opaque strings (the `TEXT` primary keys in [database.md](database.md)).
- Secrets are never returned. Credential tokens, the OIDC client secret, alert channel secrets, and the mapping auth secret are write-only. The only exceptions are the webhook URL and the auth secret. Each is returned once, at creation or rotation, and cannot be read again (Decided 2026-11-03, see [integrations.md](integrations.md)).
- Auth levels:
  - `public`: no session.
  - `session`: a valid session cookie. A `user` sees and changes only their own objects. An `admin` may read all objects and cannot change another user's credentials or mappings (see [security.md](security.md), Tenancy).
  - `admin`: a valid session whose role, looked up from `users.role` on this request, is `admin`.
- Decided (2026-11-03, delegated): a request for an object owned by another tenant returns `404`, not `403`, so existence is not revealed. No external source.
- CSRF: Decided (2026-11-03): signed double-submit cookie (HMAC key derived via HKDF label `harborgate/csrf-v1`). Cookie `__Host-harborgate_csrf`, header `X-CSRF-Token`, required on every `POST`, `PUT`, `PATCH`, and `DELETE` under `/api`, except the webhook, login, and setup. Login and setup use the same-origin check in [security.md](security.md) instead (Decided 2026-11-03). A missing or wrong token returns `403` with code `csrf_invalid`. Source: OWASP CSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html). Details are in [security.md](security.md). Decided (2026-11-03): the token is bound only to the signed cookie value; there is no session `jti` binding. The cookie is set at login and OIDC callback.
- Rate limits: login 10 per minute per IP, webhook 60 per minute per mapping token (both Decided (2026-11-03, delegated) in [security.md](security.md); no external standard; tune in deployment), manual scan pull 1 per 5 minutes per mapping (Decided 2026-11-05, user, #131; see Mappings). Every route declares its limit explicitly, because an undeclared limit means unlimited. Decided (2026-11-03): no default limit on authenticated routes beyond login, webhook, and (Decided 2026-11-05, #131) the manual scan pull.

### Error envelope

- Decided (2026-11-03, delegated): every non-2xx response has this body, with a snake_case `code` and a safe `message`:

```json
{"error": {"code": "<snake_case>", "message": "<safe text>"}}
```

- `message` never contains a secret, a token, a stack trace, or SQL. It follows the error-handling rule in [backend.md](backend.md).
- Codes (Decided 2026-11-03, delegated; no external source): `invalid_request` (400), `password_too_short` (400, Decided 2026-11-03, see [security.md](security.md)), `unauthenticated` (401), `invalid_credentials` (401), `forbidden` (403), `csrf_invalid` (403), `not_found` (404), `conflict` (409), `validation_failed` (422), `payload_too_large` (413), `rate_limited` (429), `internal_error` (500), `upstream_unreachable` (502), `code_scanning_unavailable` (422, Decided (2026-11-03, delegated): the GitHub repository cannot receive code scanning uploads, see [security.md](security.md), "GitHub token scope").
- Status code sources: RFC 9110 section 15.5 (client errors) and section 15.6 (server errors), https://www.rfc-editor.org/rfc/rfc9110. `429` is from RFC 6585.
- Alternative not adopted: RFC 9457 `application/problem+json` (https://www.rfc-editor.org/rfc/rfc9457). The user's envelope is used instead.
- Login failures return the same `401 invalid_credentials` for an unknown user, a wrong password, a login inside the failed-login delay, and a regular user blocked by the OIDC-only toggle, so the response does not reveal which. Source: OWASP Authentication Cheat Sheet, generic error messages (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

### Lists

- Decided (2026-11-03, delegated): list routes take `page` (1-based), `page_size`, `sort`, and `order` (`asc` or `desc`) query parameters. Pagination is page-based, not cursor-based.
- `page_size` defaults to 50 and has a maximum of 200. A larger value returns `400 invalid_request`. A `sort` value that is not in the route's allowed list returns `400 invalid_request`.
- Response shape: `{"items": [...], "page": 1, "page_size": 50, "total": 0}`.
- Source for the parameter names: Harbor API v2.0 swagger uses `page` and `page_size` (https://github.com/goharbor/harbor/blob/main/api/v2.0/swagger.yaml, verified in this session). The default 50 and maximum 200 are Decided (2026-11-03, delegated): no external source.

## Auth

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/auth/setup-status` | public | none | `{"setup_required": bool, "oidc_enabled": bool}` | 200 |
| POST | `/api/v1/auth/setup` | public | `{"username","email","password"}` | `{"user": User}`, sets session and CSRF cookies | 201, 400 (`password_too_short` if password is under 15 characters), 403 `csrf_invalid` (not same-origin), 409 `conflict` (setup already done), 422, 429 |
| POST | `/api/v1/auth/login` | public (CSRF token exempt, same-origin check) | `{"username","password"}` | `{"user": User}`, sets session and CSRF cookies | 200, 401 `invalid_credentials`, 403 `csrf_invalid` (not same-origin), 429 |
| POST | `/api/v1/auth/logout` | session | none | empty | 204, 401 |
| POST | `/api/v1/auth/logout-all` | session | none | empty, clears the session cookie; increments `users.token_version` (Decided 2026-11-03) | 204, 401 |
| GET | `/api/v1/auth/oidc/start` | public | none | redirect to the issuer authorization endpoint, sets a short-lived state cookie | 302, 404 (OIDC not configured) |
| GET | `/api/v1/auth/oidc/callback` | public | query `code`, `state`, or `error` (provider) | success: redirect to `/`, sets session and CSRF cookies. Failure: redirect to `/?oidc_error=<code>`, clears the sign-in cookie (Decided 2026-11-03, delegated, #49) | 302 (every outcome once OIDC is configured), 404 (OIDC not configured) |

- `User` is `{"id","username","email","role","auth_provider","created_at"}`. It never contains `password_hash`.
- Decided (2026-11-03): user creation. Local accounts are created by an admin in Settings > Users. Admins can also delete users and change roles there. OIDC accounts are created automatically on the user's first successful OIDC login (just-in-time provisioning), and their role comes from the configured group claim on each login. No admin pre-creation is needed. First run: the first local account created on a fresh install becomes `admin`. The setup page is shown only while no users exist. Once the first account exists, the setup route is closed permanently. Concurrent requests are handled by a single transaction that inserts only if the `users` table is empty. The setup page design needs user approval before build.
- `POST /auth/setup` is kept. It is allowed only while the `users` table is empty, runs in a single transaction that inserts only if the table is empty, and closes permanently after the first account is created (see [security.md](security.md)). It creates the first `admin`. The setup route above is the minimum the setup guide ([docs/SETUP.md](../docs/SETUP.md) section 5) needs.
- Local login: admins always; regular users unless the "OIDC only for regular users" toggle is on (Decided 2026-11-03, see [security.md](security.md)). While the toggle is on, a `user` account with a local password gets the same `401 invalid_credentials`.
- OIDC flow rules (authorization code with PKCE, `state`, role from the group claim) are in [security.md](security.md). Sources: OpenID Connect Core 1.0, RFC 6749, RFC 7636.

## Account

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/account/me` | session | none | `{"user": User}` | 200, 401 |
| POST | `/api/v1/account/password` | session | `{"current_password","new_password"}` | empty | 204, 400 `password_too_short` (new password under 15 characters), 401 `invalid_credentials`, 403 (OIDC user) |

- Password rules (Argon2id, minimum length) are in [security.md](security.md). Decided (2026-11-03): the minimum is 15 characters. The rule applies to `POST /auth/setup`, `POST /account/password`, and `POST /admin/users` (local passwords). A too-short password returns `400` with the error envelope and code `password_too_short`.
- Decided (2026-11-03): a successful `POST /account/password` increments `users.token_version`, which signs out every other session of the user, and sets a fresh session cookie on the response.
- Theme and language are client-side preferences in v1, stored in the browser (`localStorage`). Decided (2026-11-03). No route exists for them.

## Credentials

`Credential` is `{"id","service_type","label","base_url","username","expires_at","created_at"}`. It never contains the token.

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/credentials` | session | query `page`, `page_size`, `sort` (`label`, `created_at`, `expires_at`), `order`, `service_type`; admin may add `scope=all` | list of `Credential` | 200, 401, 403 |
| POST | `/api/v1/credentials` | session | `{"service_type","label","base_url","username","token","expires_at"}` | `Credential` | 201, 400, 422 (not HTTPS, blocked address) |
| PUT | `/api/v1/credentials/:id` | session (owner only) | any subset of `label`, `base_url`, `username`, `token`, `expires_at` | `Credential` | 200, 404, 409 `conflict` (`base_url` change while a mapping uses the credential), 422 |
| DELETE | `/api/v1/credentials/:id` | session (owner only) | none | empty | 204, 404, 409 `conflict` (in use by a mapping) |
| POST | `/api/v1/credentials/:id/test` | session (owner only) | Harbor: none. GitHub: `{"owner","repo"}` (Decided 2026-11-03: the repository is given per request, see below) | `{"ok": bool, "checks": [{"name","ok","detail","warning"?}]}` | 200, 404, 502 `upstream_unreachable` |

- Decided (2026-11-03, user, #35): items of `GET /credentials` add `"mapping_count"`, the number of mappings that use the credential as their Harbor or GitHub credential. The Account page shows it as "Used by". Other credential responses do not carry it.
- `base_url` and `username` apply to Harbor credentials. `base_url` must be HTTPS and must pass the address check in [security.md](security.md) (Outbound HTTP).
- `DELETE` returns `409` while a mapping references the credential (`ON DELETE RESTRICT`, [database.md](database.md)).
- Audit: create, update of the token, and delete write `credential.create`, `credential.rotate`, and `credential.delete`.
- Test button (Decided 2026-11-03, delegated):
  - Harbor: the robot test in [integrations.md](integrations.md), "Test button" (`GET /api/v2.0/users/current`, where `412` means the robot credential works).
  - GitHub: the endpoint probes in [security.md](security.md), "GitHub token scope".
  - Decided (2026-11-03): the GitHub test takes `owner` and `repo` in the request body, because a credential row has no repository. The probe checks code-scanning access on that repository and returns the same error codes as the spec. A GitHub credential with a missing or invalid `owner` or `repo` returns `422 validation_failed`.
  - The test sends the request from the server, so it passes through the same SSRF address check.

## Mappings

`Mapping` is `{"id","user_id","harbor_cred_id","github_cred_id","harbor_base_url","harbor_project","harbor_repository","github_owner","github_repo","default_branch","auto_create_issues","min_issue_severity","created_at"}`. Decided (2026-11-03): it never contains the webhook URL. The URL holds the secret token and is returned only once, in the create and rotate responses (see [integrations.md](integrations.md)).

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/mappings` | session | list params; `sort` (`harbor_repository`, `created_at`); admin may add `scope=all` | list of `Mapping` | 200, 401 |
| POST | `/api/v1/mappings` | session | `{"harbor_cred_id","github_cred_id","harbor_project","harbor_repository","github_owner","github_repo","default_branch","auto_create_issues","min_issue_severity"}` | `{"mapping": Mapping, "webhook_url": "<shown once>", "auth_secret": "<shown once>"}` | 201, 400, 404 (credential), 409 `conflict` (duplicate Harbor repository on the same Harbor instance, or duplicate GitHub target), 422 (including `code_scanning_unavailable`, and `validation_failed` when `auto_create_issues` is on and the token lacks the Issues permission) |
| GET | `/api/v1/mappings/:id` | session | none | `Mapping` | 200, 404 |
| PUT | `/api/v1/mappings/:id` | session (owner only) | any subset of the create fields except the credentials' owner | `Mapping` | 200, 404, 409, 422 |
| DELETE | `/api/v1/mappings/:id` | session (owner only) | none | empty | 204, 404 |
| POST | `/api/v1/mappings/:id/rotate-webhook-token` | session (owner only) | none | `{"webhook_url": "<new, shown once>"}` | 200, 404 |
| POST | `/api/v1/mappings/:id/rotate-auth-secret` | session (owner only) | none | `{"auth_secret": "<shown once>"}` | 200, 404 |
| POST | `/api/v1/mappings/:id/pull` | session (mapping owner, or any admin) | none | `{"queued": <n>}` | 200, 401, 403 `csrf_invalid`, 404, 429 (with `Retry-After`), 502 `upstream_unreachable` |

- Decided (2026-11-03, user, #35): items of `GET /mappings` add `"open_cves": {"critical","high"}` and `"last_sync": {"status","updated_at"} or null`. `open_cves` follows the dashboard counting rules in [cve-lifecycle.md](cve-lifecycle.md) for that one mapping. `last_sync` is the mapping's most recently updated `sync_jobs` row. `GET /mappings/:id` does not carry these fields.
- The duplicate error for the GitHub target is shown inline in the form ([frontend.md](frontend.md)). The `409` body names the conflicting mapping's label. Decided (2026-11-03, delegated): only if that mapping is owned by the caller; otherwise the message is generic, so another tenant's mapping is not revealed.
- Both credentials must be owned by the caller. A credential of another user returns `404`.
- `min_issue_severity` accepts `CRITICAL` or `HIGH`.
- Rotation audits `mapping.webhook_token_rotate` and `mapping.auth_secret_rotate`. The old value stops working immediately.
- Decided (2026-11-03): `DELETE` removes only HarborGate's own rows: `repo_mappings`, its `cve_findings`, `cve_acceptances`, `sync_jobs`, `sync_reports`, and its webhook token and auth secret. The `github_issues` rows for the mapping's GitHub target are deleted in the same transaction, matched by `github_owner` and `github_repo`. Open GitHub issues are NOT closed and are NOT changed on GitHub. The user must close each issue on GitHub manually. Only one mapping can exist per GitHub repository ([database.md](database.md)), so these rows belong to this mapping alone.
- Audit: the delete writes `mapping.delete`. Its `details` list the GitHub issue numbers left open. It never contains tokens or secrets.
- Manual pull (Decided 2026-11-05, user, #131): `POST /mappings/:id/pull` runs the scheduled poll for this one mapping, now. It uses the same code, page cap, and dedupe rule as backup polling ([integrations.md](integrations.md), Polling), so it queues only tagged `(digest, tag)` pairs that have no successful sync and no queued or running job, and never re-uploads a synced digest. A digest that Harbor is still scanning is queued and left to the existing "report not yet" backoff. `queued` is the number of jobs queued; it may be `0`. The jobs carry `"trigger": "poll"` and appear on the Sync jobs page.
  - Rate limit: one pull per mapping per 5 minutes, held in memory and keyed by mapping id. A pull that fails at Harbor still uses the 5 minutes. A restart clears the cooldown. Over the limit the route returns `429` with `Retry-After`. The cooldown is checked after the tenancy check, so another tenant's mapping is `404`, never `429`.
  - Who may pull: the mapping owner, and any admin, for any tenant's mapping. This is the second admin exception to read-only access, beside retry ([security.md](security.md), Tenancy).
  - A Harbor error (unreachable, a non-`200` answer, or a body that does not parse) fails only this pull, with `502 upstream_unreachable` and its fixed message. Jobs already queued from earlier pages of the same pull stay queued, as in the scheduled poll.
  - Audit: a pull that finishes writes `mapping.pull` with `details` `{"mapping_id","queued"}`. A pull that fails at Harbor writes no audit row. No URL, credential, or Harbor answer is recorded.

## CVEs

`{id}` identifies one CVE within one mapping, because acceptance and issues are per mapping and `cve_findings` has one row per tag. Decided (2026-11-03, delegated): `{id}` is `<mapping_id>:<cve_id>`, URL-encoded (`:` is `%3A`). Neither a UUID nor a CVE id contains a colon. No external source. Alternative: nest the routes under `/mappings/:mapping_id/cves/:cve_id`. The paths below follow the form the user gave for `POST /api/v1/cves/{id}/issue`.

`CveSummary` is `{"id","mapping_id","cve_id","severity","status","package","first_seen_at","last_seen_at","github_issue_url","accepted"}`. `status` is `open` or `fixed`, `accepted` is derived (see [cve-lifecycle.md](cve-lifecycle.md)). `CveDetail` adds `"tags": [{"image_tag","status","last_scan_at","fixed_in_version"}]` with up to 10 tags, and `"acceptance": {...} or null`.

Decided (2026-11-03, user, #35): `CveSummary` also has `"fixed_in_version"` (from the most recently scanned tag that reports the CVE; `null` when unknown), `"open_tags"` (tracked tags where the CVE is open), `"tracked_tags"` (tracked tags of the mapping, at most 10), `"github_issue_number"`, and `"github_issue_status"` (`open`, `closed`, or `null` when there is no issue). `CveDetail` also has `"description"` (the Harbor vulnerability description, or `null`; see [database.md](database.md), `cve_findings.description`).

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/mappings/:id/cves` | session | list params; `sort` (`severity`, `cve_id`, `first_seen_at`, `last_seen_at`), `severity`, `status`, `accepted`, `q` | list of `CveSummary` | 200, 404 |
| GET | `/api/v1/cves` | session | same as above plus `mapping_id`; admin may add `scope=all` | list of `CveSummary` | 200, 401 |
| GET | `/api/v1/cves/:id` | session | none | `CveDetail` | 200, 404 |
| POST | `/api/v1/cves/:id/accept` | session (mapping owner) | `{"reason","expires_at"}` | `{"acceptance": {...}}` | 201, 404, 409 (already accepted), 422 (empty reason, past expiry) |
| POST | `/api/v1/cves/:id/unaccept` | session (mapping owner) | none | empty | 204, 404 (no active acceptance) |
| POST | `/api/v1/cves/:id/issue` | session (mapping owner) | none | `{"github_issue_url","github_issue_number"}` | 201, 404, 409 (open issue exists, body has its URL), 422 (severity not eligible), 502 |

- Accept applies to the whole mapping. It does not close an open issue. It adds a comment (Decided 2026-11-03, delegated; [cve-lifecycle.md](cve-lifecycle.md)). Un-accept is a soft revoke.
- Both accept and un-accept are audited (`cve.accept`, `cve.unaccept`).
- `POST .../issue` creates an issue only for `CRITICAL` or `HIGH`. It reuses the closed issue for the same CVE and repo by reopening it, never creates a second one (lifecycle rules in [cve-lifecycle.md](cve-lifecycle.md)).
- Decided (2026-11-03, G28): the manual-issue button lives in the per-CVE page header, next to the GitHub issue link. See [frontend.md](frontend.md).
- A tag with zero findings has no `cve_findings` row, so it does not appear in `tags`. Decided (2026-11-03, delegated): the tag list shows only tags that report this CVE.

## Sync jobs

`SyncJob` is `{"id","mapping_id","status","attempts","next_attempt_at","last_error","created_at","updated_at","report": {...} or null}`. `report` is the linked `sync_reports` row (`image_tag`, `image_digest`, `commit_sha`, `vulnerability_summary`, `sarif_status`, `synced_at`).

Decided (2026-11-03, user, #35): `SyncJob` also has `"trigger"` (`webhook` or `poll`, read from `payload.trigger`; a payload without the field is `webhook`) and `"image": {"repo_full_name","tag","digest"}` from the job payload, so queued and running jobs show their image before a report exists.

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/sync-jobs` | session | list params; `sort` (`created_at`, `updated_at`), `status`, `mapping_id`; admin may add `scope=all` | list of `SyncJob` | 200, 401 |
| GET | `/api/v1/sync-jobs/:id` | session | none | `SyncJob` | 200, 404 |
| POST | `/api/v1/sync-jobs/:id/retry` | session (mapping owner, or any admin) | none | `SyncJob` | 200, 404, 409 (job is not `failed`) |

- Retry (Decided 2026-11-03, delegated): sets `status` to `queued`, resets `attempts` to 0, clears `last_error`, sets `next_attempt_at` to now. Retry constants are in [backend.md](backend.md). Decided (2026-11-03): the mapping owner may retry their own failed jobs; admins may retry any job, of any tenant.
- Decided (2026-11-03): `status` is `sync_jobs.status` (`queued`, `running`, `done`, `failed`). `report.sarif_status` is the SARIF upload result (`pending`, `success`, `failed`). The job status value is `done`, not `success`.
- The Failed syncs admin tab is this list with `status=failed&scope=all` (read-only for admins except retry, see below).
- Decided (2026-11-03): an admin may retry a failed job of any tenant. This is the first operational exception to read-only admin access (the second is the manual scan pull, see Mappings), because retry only re-queues work and changes no mapping or credential. The owner may also retry their own jobs. See [security.md](security.md), Tenancy.

## Dashboard

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/dashboard/summary` | session | admin may add `scope=all` | `{"open_cves": {"critical","high"}, "fixed_cves", "open_issues", "failed_syncs", "recent_syncs": [SyncJob]}` | 200, 401 |

- Counting rules (distinct CVEs, current snapshot) are in [cve-lifecycle.md](cve-lifecycle.md), Dashboard counts. `recent_syncs` holds the latest 10. The 10 matches the tag limit and is Decided (2026-11-03, delegated), with no external source. Failed rows can be retried with the route above.

## Admin

All routes below are `admin`.

| Method | Path | Request | Response | Codes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/admin/users` | list params; `sort` (`username`, `created_at`, `role`) | list of `User` | 200 |
| POST | `/api/v1/admin/users` | `{"username","email","password","role"}` | `User` | 201, 400 `password_too_short` (local accounts only: password under 15 characters), 409, 422 |
| DELETE | `/api/v1/admin/users/:id` | none | empty | 204, 404, 409 (last local admin, or self) |
| PUT | `/api/v1/admin/users/:id/role` | `{"role": "admin or user"}` | `User` | 200, 404, 409 (last local admin, or an OIDC user, whose role comes only from the group claim; Decided 2026-11-03) |
| GET | `/api/v1/admin/oidc` | none | `{"issuer_url","client_id","role_claim","admin_group","user_group","client_secret_set": bool,"oidc_only_users": bool}` | 200 |
| PUT | `/api/v1/admin/oidc` | same fields plus optional `client_secret` (write-only) | same as GET | 200, 422 (issuer not HTTPS, or `oidc_only_users` on while the OIDC settings are incomplete) |
| GET | `/api/v1/admin/alert-channels` | list params | list of `{"id","kind","enabled","created_at","updated_at"}` | 200 |
| POST | `/api/v1/admin/alert-channels` | `{"kind","enabled","config"}` | channel without `config` | 201, 422 |
| PUT | `/api/v1/admin/alert-channels/:id` | `{"enabled","config"}` (config write-only) | channel without `config` | 200, 404, 422 |
| GET | `/api/v1/admin/audit-log` | list params; `sort` (`created_at`), `action`, `actor_user_id` | list of `{"id","actor_user_id","actor_username","action","target","created_at","details"}` | 200 |
| GET | `/api/v1/admin/jobs` | list params; `kind` | list of housekeeping runs (cleanup, retention, polling) with counts and errors | 200 |
| POST | `/api/v1/admin/backup` | none | `{"file": "<name>", "path": "<dir>"}` | 201, 500 `internal_error` (directory missing or not writable) |
| GET | `/api/v1/admin/logs` | query `level` (minimum level: `error`, `warn`, `info`, `debug`, `trace`; default `trace`, all lines), `q` (case-insensitive text search, at most 200 characters) | `{"items": [LogLine], "level": "<current>", "reverts_at": "<date-time>" or null}`, oldest first | 200, 400 `invalid_request` (unknown `level`, `q` too long) |
| GET | `/api/v1/admin/log-level` | none | `{"level","reverts_at"}` | 200 |
| PUT | `/api/v1/admin/log-level` | `{"level": "info" or "debug" or "trace"}` | `{"level","reverts_at"}` | 200, 400 `invalid_request` (malformed body), 422 `validation_failed` (level not `info`, `debug`, or `trace`) |

- Application log (Decided 2026-11-05, user, #136): rules are in [security.md](security.md), "Application log". `LogLine` is `{"seq","timestamp","level","target","message"}`. `seq` increases by one per line since the start, so a client can tell lines apart. `message` holds the event message and its fields, with secret-named fields removed; it is at most 1000 characters, and a longer line ends with `… [truncated]`. The buffer holds at most 500 lines, so the list is not paginated. `reverts_at` is when a level above `info` returns to `info`, or `null` at `info`. An invalid level in `PUT` returns `422 validation_failed` with the fixed message "level must be info, debug, or trace." and never echoes the value. `PUT` is CSRF-protected like every state-changing route. A change audits `log.level_change` with `{"old","new"}`, also when the level does not change, and restarts the 30-minute timer.
- Rate limits for the application log routes: Decided (2026-11-05, #136): none. They are admin-session routes, and the rule above (no default limit on authenticated routes beyond login and webhook) applies. The buffer is bounded at 500 lines, so a read is cheap.
- Note (Decided 2026-11-03): key re-encryption is a CLI command, not an HTTP route. There is no `/admin/key/reencrypt` route and no key rotation button in the admin UI. Run it offline with the app stopped, with `HARBORGATE_OLD_ENCRYPTION_KEY` and `HARBORGATE_ENCRYPTION_KEY` set in the environment ([security.md](security.md)).

- Decided (2026-11-03): `POST /admin/users` creates local accounts only. OIDC users are created by the OIDC login flow (just-in-time) and do not appear via this POST. The `DELETE` and `PUT .../role` routes are used for both local and OIDC users.
- `DELETE /admin/users/:id` follows the deletion order in [database.md](database.md). Decided (2026-11-03, delegated): the last remaining local admin cannot be deleted or demoted (`409`). An OIDC login can demote an OIDC admin, because the group claim wins, so counting only local admins guarantees the instance always keeps a break-glass admin. First-run setup always creates a local admin. No external source.
- Audit: `user.create`, `user.delete`, `user.role_change`, `oidc.config_change`, `alert.config_change`, `backup.run`, `restore.run`, `key.rotate`, `log.level_change`.
- `PUT /admin/oidc` takes the client secret in the request body over TLS and stores it encrypted. It is never returned.
- Note (Decided 2026-11-03): restore is a CLI command, not an HTTP route. No admin restore route exists. Run `harborgate restore <file>` with the app stopped. There is no restore route and no restore button in the admin UI. The restore command verifies the `HGBK1` header and the GCM tag before it replaces the database ([security.md](security.md)).
- Backup: Decided (2026-11-03, delegated): the server names the file `harborgate-<UTC yyyymmddThhmmssZ>.hgbk`. `file` in the response is that name, which always matches `^[A-Za-z0-9._-]+$` and has no path separators. The handler writes only to `HARBORGATE_BACKUP_DIR`. The copy method (`VACUUM INTO`) is in [security.md](security.md).
- Decided (2026-11-03): key re-encrypt is CLI only, offline, with both keys read from the environment. It is not an HTTP route. Keys are never accepted from the request or typed into the browser ([security.md](security.md)).
- Decided (2026-11-03): backup is an admin UI route (`POST /admin/backup`). Restore is CLI only.
- Decided (2026-11-03): the OIDC, user management, alert settings, and backup/restore screens live in a fifth Admin tab, "Settings" (OIDC, Users, Alerts, Backup and restore), after Health. [frontend.md](frontend.md) defines the tabs. This file defines the routes, not the screens.
- Decided (2026-11-03): housekeeping run history is stored in the `job_runs` table, which holds counts and error text only. `GET /admin/jobs` reads it. See [database.md](database.md).

## Health

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/healthz` | public | none | `{"status": "ok"}` | 200 |
| GET | `/api/v1/admin/health` | admin | none | `{"harbor": [Check], "github": [Check], "robot_accounts": [{"credential_id","label","expires_at","days_left"}], "request": {"client_ip","source"}}` | 200 |

- `/healthz` is the liveness check used by the compose healthcheck and the docker-smoke check (decided in [deployment.md](deployment.md), "Health"). It is a process liveness check only. It returns 200 without touching SQLite, Harbor, or GitHub, so a Harbor outage does not mark the container unhealthy. Decided (2026-11-03, delegated), no external source. It is excluded from rate limits, because health checks must not be throttled.
- `Check` is `{"credential_id","label","reachable": bool,"missing_permissions": [string],"code_scanning": "ok" | "no_analysis_yet" | "unavailable" | null,"detail"}`. `code_scanning` is `null` for Harbor checks. The permission check and response classification are in [security.md](security.md), "GitHub token scope".
- Decided (2026-11-03, delegated, #35): `Check` also has `"ok": bool` (every probe passed and nothing is missing) and `"target"` (`"<owner>/<repo>"` for GitHub checks, `null` for Harbor). `harbor` has one `Check` per Harbor credential. `github` has one `Check` per mapping, probed with that mapping's GitHub credential against its target, because code scanning and permissions are per repository. `missing_permissions` uses the names `metadata`, `code_scanning_alerts`, and `issues`. `robot_accounts` lists every Harbor credential, soonest expiry first, with `expires_at` and `days_left` `null` when there is no expiry. The probes run one after another; the frontend fetches this route at most once every 10 minutes ([frontend.md](frontend.md)).
- `request` (Decided (2026-11-03, delegated)): the client IP HarborGate derived for this request, and `source`, which is `peer` or `x-forwarded-for`. Operators use it to check `HARBORGATE_TRUSTED_PROXIES` ([deployment.md](deployment.md), "Client IP behind Cloudflare and Traefik"). It shows only the caller's own address.
- The robot account warning window is 14 days before `expires_at` (Decided 2026-11-03, see [integrations.md](integrations.md)).

## Webhook

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/webhooks/harbor/:mapping_token` | public: URL token plus `Authorization` header (CSRF exempt) | Harbor default JSON or CloudEvents JSON body, up to 64 KiB | empty body | 202, 400, 401, 413, 429 |

- Format detection by `specversion`, the `Authorization` header contract, and the response code rules are in [integrations.md](integrations.md). The header is decided (2026-11-03): `Authorization: Bearer <secret>`.
- A wrong URL token and a wrong or missing `Authorization` value return the same `401` and the same body (Decided 2026-11-03, delegated).
- The route never echoes the token and never logs it. The access log records the route template.
- Handling: validate, store a `sync_jobs` row, return `202`. See [backend.md](backend.md).

## Verification

Required test scenarios for the planner (high level):

- Every route above returns `401` without a session, except those marked public.
- A `user` session gets `404` for another tenant's mapping, credential, CVE, and job. An `admin` session can read them and cannot change them.
- A state-changing request without `X-CSRF-Token` returns `403 csrf_invalid`. The webhook and login are exempt.
- The error envelope shape is the same on every error response, and no response body contains a token, key, `password_hash`, or webhook URL, except the documented shown-once fields.
- Pagination: `page_size` above 200 returns `400`, the default is 50, and `total` is the unfiltered match count.
- Webhook: both payload fixtures return `202` and store one job. A missing header and a wrong token return the identical `401`. An oversize body returns `413`. The 61st request in a minute returns `429`.
- Login: after 5 consecutive failures for one account from one client IP, the next attempt inside the delay returns `401 invalid_credentials` without a password check. The same account from another client IP is not delayed. The account is never locked ([security.md](security.md)).
- Login and setup with a cross-site `Origin`, or with neither `Origin` nor `Sec-Fetch-Site`, return `403 csrf_invalid`.
- A session issued before `logout-all` or a password change returns `401`.
- `PUT /admin/users/:id/role` on an OIDC user returns `409`.
- Application log: a regular user gets `403` on `GET /admin/logs` and `PUT /admin/log-level`; `PUT /admin/log-level` without a CSRF token returns `403 csrf_invalid`; an invalid level returns `422` with the fixed message.
- No response body ever contains a webhook URL except the create and rotate responses.
- Credential delete is blocked with `409` while a mapping uses it.
- Accept then un-accept then accept again succeeds. Accepting twice returns `409`.
- Retry of a `failed` job resets `attempts` to 0 and sets `status` to `queued`. Retry of a non-failed job returns `409`.
- Dashboard: one CVE on three tags of one mapping counts as 1 ([cve-lifecycle.md](cve-lifecycle.md)).
