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
- Rate limits: login 10 per minute per IP, webhook 60 per minute per mapping token (both Decided (2026-11-03, delegated) in [security.md](security.md); no external standard; tune in deployment), manual scan pull 1 per 5 minutes per mapping (Decided 2026-11-05, user, #131; see Mappings), tag scan 1 per 5 minutes per (mapping, tag, scanner) and scanner list 60 per minute per user (Decided 2026-11-07, delegated, #224; see Scanners and tag scans), picker lists and suggestion 60 per minute per user (Decided 2026-11-05, delegated, #126; see Pickers). Every route declares its limit explicitly, because an undeclared limit means unlimited. Decided (2026-11-03): no default limit on authenticated routes beyond login, webhook, (Decided 2026-11-05, #131) the manual scan pull, and (Decided 2026-11-05, delegated, #126) the picker lists and suggestion, and (Decided 2026-11-07, delegated, #224) the tag scan and the scanner list.

### Error envelope

- Decided (2026-11-03, delegated): every non-2xx response has this body, with a snake_case `code` and a safe `message`:

```json
{"error": {"code": "<snake_case>", "message": "<safe text>"}}
```

- Decided (2026-11-05, user, #126): the envelope may carry an optional fixed `detail` code, `{"error": {"code","message","detail"}}`, so a client can pick the fix when one `code` covers several causes. The only values are `harbor_identity`, `robot_scope`, `github_token`, `wrong_credential_type` and `harbor_repository_mapped`. The picker `422 validation_failed` answers set the first four (see [integrations.md](integrations.md), "Errors and rate limits"). Decided (2026-11-07, delegated, #180): the mapping create and update `409 conflict` for a duplicate Harbor repository sets `harbor_repository_mapped`. Every other error has no `detail` key.
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
| POST | `/api/v1/credentials/:id/test` | session (owner only) | Harbor: none. GitHub: none (empty) (Decided 2026-11-06, user, #178: the test picks the repository itself, see below) | `{"ok": bool, "checks": [{"name","ok","detail","warning"?}]}`, and for GitHub the response names the repository checked | 200, 404, 502 `upstream_unreachable` |

- Decided (2026-11-03, user, #35): items of `GET /credentials` add `"mapping_count"`, the number of mappings that use the credential as their Harbor or GitHub credential. The Account page shows it as "Used by". Other credential responses do not carry it.
- `base_url` and `username` apply to Harbor credentials. `base_url` must be HTTPS and must pass the address check in [security.md](security.md) (Outbound HTTP).
- `DELETE` returns `409` while a mapping references the credential (`ON DELETE RESTRICT`, [database.md](database.md)).
- Audit: create, update of the token, and delete write `credential.create`, `credential.rotate`, and `credential.delete`.
- Test button (Decided 2026-11-03, delegated):
  - Harbor: the robot test in [integrations.md](integrations.md), "Test button" (`GET /api/v2.0/users/current`, where `412` means the robot credential works).
  - GitHub: the endpoint probes in [security.md](security.md), "GitHub token scope".
  - Decided (2026-11-06, user, #178): the test picks the repository itself.
    1. The test takes no body and ignores any body.
    2. It calls `GET /user/repos` and takes the first repository returned for the token, in GitHub's default order.
    3. It runs the three existing probes (repo metadata, code scanning alerts, issues) on that repository.
    4. The result names the repository checked.
    5. If the token sees no repository, the response is `200` with `{"ok": false, "checks": [{"name": "github_repository_visible", "ok": false, "detail": "<catalog key credentials.test.noRepository>"}]}`. The fixed text is "The token cannot see any repository. Grant the token access to at least one repository." No raw GitHub message is added.
    6. The `422` rules for an empty body and an invalid `owner` or `repo` are removed, because the body is no longer read.
  - The test sends the request from the server, so it passes through the same SSRF address check.

## Mappings

`Mapping` is `{"id","user_id","harbor_cred_id","github_cred_id","harbor_base_url","harbor_project","harbor_repository","github_owner","github_repo","default_branch","auto_create_issues","min_issue_severity","created_at","scan_schedule","scan_time","scan_weekday"}`. Decided (2026-11-03): it never contains the webhook URL. The URL holds the secret token and is returned only once, in the create and rotate responses (see [integrations.md](integrations.md)).

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/mappings` | session | list params; `sort` (`harbor_repository`, `created_at`, and, decided 2026-11-06 user #190, `harbor_project`, `github_owner`, `github_repo`, `open_issues`, `last_sync_at`); `last_sync_at`: a mapping with no sync yet sorts last in both directions (decided 2026-11-06, user, #190); `open_issues`: compares the open issue counts per severity as a tuple, most severe first: critical, then high, then medium, then low; ties go to the next severity (example: 3 critical and 0 high sort before 2 critical and 9 high) (decided 2026-11-06, user, #190); admin may add `scope=all`. `open_issues` is counted at list time from the `cve_findings` and `github_issues` rows, not stored on the mapping (see [cve-lifecycle.md](cve-lifecycle.md)). Other `sort` values return `400 invalid_request`. | list of `Mapping` | 200, 401 |
| POST | `/api/v1/mappings` | session | `{"harbor_cred_id","github_cred_id","harbor_project","harbor_repository","github_owner","github_repo","default_branch","auto_create_issues","min_issue_severity","scan_schedule"?,"scan_time"?,"scan_weekday"?}` | `{"mapping": Mapping, "webhook_url": "<shown once>", "auth_secret": "<shown once>", "project_webhook_exists": <bool>}` | 201, 400, 404 (credential), 409 `conflict` with detail `harbor_repository_mapped` (the Harbor repository is already mapped on the same Harbor instance, by any user; Decided 2026-11-06, user, #185: a duplicate GitHub target is no longer refused), 422 (including `code_scanning_unavailable`, and `validation_failed` when `auto_create_issues` is on and the token lacks the Issues permission) |
| GET | `/api/v1/mappings/:id` | session | none | `Mapping` | 200, 404 |
| PUT | `/api/v1/mappings/:id` | session (owner only) | any subset of the create fields except the credentials' owner | `Mapping` plus `"project_webhook_exists": <bool>` | 200, 404, 409 (`conflict` with detail `harbor_repository_mapped` for a duplicate Harbor repository; plain `conflict` when the mapping changed during the update), 422 |
| DELETE | `/api/v1/mappings/:id` | session (owner only) | none | empty | 204, 404 |
| POST | `/api/v1/mappings/:id/rotate-webhook-token` | session (owner only) | none | `{"webhook_url": "<new, shown once>"}` | 200, 404 |
| POST | `/api/v1/mappings/:id/rotate-auth-secret` | session (owner only) | none | `{"auth_secret": "<shown once>"}` | 200, 404 |
| POST | `/api/v1/mappings/:id/pull` | session (mapping owner, or any admin) | none | `{"queued": <n>}` | 200, 401, 403 `csrf_invalid`, 404, 429 (with `Retry-After`), 502 `upstream_unreachable` |

- Decided (2026-11-03, user, #35): items of `GET /mappings` add `"open_cves": {"critical","high"}` and `"last_sync": {"status","updated_at"} or null`. `open_cves` follows the dashboard counting rules in [cve-lifecycle.md](cve-lifecycle.md) for that one mapping. Changed (2026-11-05, user, #129): `open_cves` is `{"critical","high","medium","low","unknown","total"}`, every severity with a breakdown. `total` is the sum of the five. The `critical` and `high` fields keep their meaning, so a client that reads only them still works. `last_sync` is the mapping's most recently updated `sync_jobs` row. `GET /mappings/:id` does not carry these fields.
- Duplicate rule (Decided 2026-11-06, user, #180): a Harbor repository can be mapped only once per Harbor instance, whichever user owns the existing mapping. The `409` for a duplicate Harbor repository is the same for every caller: `code` `conflict`, `detail` `harbor_repository_mapped`, and the fixed message "This Harbor repository is already mapped on this instance." It never names the other user, their mapping, or its id, even when the caller owns that mapping. The client shows catalog text chosen by `code` and `detail`, not the server message. Decided (2026-11-06, user, #185): the duplicate GitHub target error is removed. Several mappings may target one GitHub repository, from any user, instance-wide. A `409` remains only for the same Harbor repository.
- Both credentials must be owned by the caller. A credential of another user returns `404`.
- `min_issue_severity` accepts `CRITICAL` or `HIGH`. It governs automatic issues only; `MEDIUM` and lower are refused with `422` (unchanged by #129, Decided 2026-11-05, user).
- Rotation audits `mapping.webhook_token_rotate` and `mapping.auth_secret_rotate`. The old value stops working immediately.
- Decided (2026-11-03): `DELETE` removes only HarborGate's own rows: `repo_mappings`, its `cve_findings`, `cve_acceptances`, `sync_jobs`, `sync_reports`, and its webhook token and auth secret. The `github_issues` rows for the mapping's GitHub target are deleted in the same transaction, matched by `github_owner` and `github_repo`. Open GitHub issues are NOT closed and are NOT changed on GitHub. The user must close each issue on GitHub manually. A GitHub repository can be the target of several mappings (Decided 2026-11-06, user, #185), so these rows are shared: the delete removes them only when no remaining mapping targets that GitHub repository and reports the CVE, and it never closes or changes an issue ([database.md](database.md)). Rows still reported by a remaining mapping stay.
- Audit: the delete writes `mapping.delete`. Its `details` list the GitHub issue numbers left open. It never contains tokens or secrets.
- Scheduled scan (Decided 2026-11-06 and 2026-11-07, user, #191): `scan_schedule` is `off` (the default when absent), `daily` or `weekly`; `scan_time` is the UTC time `HH:MM` (`00:00` to `23:59`, default `00:00`); `scan_weekday` is the ISO weekday of a weekly run, `1` (Monday) to `7` (Sunday), default `1`. Another value is `422 validation_failed`. `PUT` accepts each field on its own; a change to any of the three is recorded in `mapping.update` `changed_fields`, needs no probe, and restarts the schedule from the save time, so a slot already past does not run. The rules are in [integrations.md](integrations.md), "Scheduled scan".
- Manual pull (Decided 2026-11-05, user, #131): `POST /mappings/:id/pull` runs the scheduled poll for this one mapping, now. It uses the same code, page cap, and dedupe rule as backup polling ([integrations.md](integrations.md), Polling), so it queues only tagged `(digest, tag)` pairs that have no successful sync and no queued or running job, and never re-uploads a synced digest. A digest that Harbor is still scanning is queued and left to the existing "report not yet" backoff. `queued` is the number of jobs queued; it may be `0`. The jobs carry `"trigger": "poll"` and appear on the Sync jobs page.
  - Rate limit: one pull per mapping per 5 minutes, held in memory and keyed by mapping id. A pull that fails at Harbor still uses the 5 minutes. A restart clears the cooldown. Over the limit the route returns `429` with `Retry-After`. The cooldown is checked after the tenancy check, so another tenant's mapping is `404`, never `429`.
  - Who may pull: the mapping owner, and any admin, for any tenant's mapping. This is the second admin exception to read-only access, beside retry ([security.md](security.md), Tenancy).
  - A Harbor error (unreachable, a non-`200` answer, or a body that does not parse) fails only this pull, with `502 upstream_unreachable` and its fixed message. Jobs already queued from earlier pages of the same pull stay queued, as in the scheduled poll.
  - Audit: a pull that finishes writes `mapping.pull` with `details` `{"mapping_id","queued"}`. A pull that fails at Harbor writes no audit row. No URL, credential, or Harbor answer is recorded.
- Project webhook check (Decided 2026-11-06, user, #179): the `POST /mappings` response adds `"project_webhook_exists": true|false`, and the `PUT /mappings/:id` response adds the same field. It is `true` when a `project_webhooks` row exists for the saved mapping's `harbor_base_url` and `harbor_project`, whoever owns it. It is read from the database only, with no Harbor call, and carries no id, owner, URL, or secret. `GET /mappings` and `GET /mappings/:id` do not carry it.

## Scanners and tag scans

Decided (2026-11-07, user, #224 d1, d8, d11, d12): the mapping page lists the Harbor scanners and starts a scan of one tag with a chosen scanner. Rules, Harbor calls and permissions are in [integrations.md](integrations.md), "Scanner reports and scan launch". Route names are delegated (Decided 2026-11-07, delegated, #224): they hang under the mapping, like `pull`.

`Scanner` is `{"uuid","name","vendor","version","is_current"}`: `is_current` is true for the scanner the Harbor project uses now. It never carries the scanner URL, auth or credential. `TagScan` is `{"scanner_uuid","scanner_name","state","note","job_id","updated_at"}`: `state` is `queued`, `running`, `waiting` (scan started, waiting for the report), `ok`, `failed` or `none`; `note` is a fixed catalog key (see below) or `null`.

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/mappings/:id/scanners` | session (mapping owner, or any admin read) | none | `{"scanner_choice": "available" or "single" or "unavailable", "scanners": [Scanner], "switch": {...} or null}` | 200, 401, 404, 422, 429, 502 |
| POST | `/api/v1/mappings/:id/tags/:tag/scan` | session (mapping owner, or any admin) | `{"scanner_uuid"?}` | `{"job_id","scanner_uuid","queued": true}` | 202, 400, 401, 403 `csrf_invalid`, 404, 409, 422, 429 (with `Retry-After`) |
| GET | `/api/v1/mappings/:id/tags/:tag/scans` | session (mapping owner, or any admin read) | none | `{"items": [TagScan]}` | 200, 401, 404 |

- `scanner_choice`: `available` when more than one enabled scanner is listed (the picker is shown); `single` when exactly one enabled scanner exists (no prompt); `unavailable` when the robot lacks Scanner Create or Read, so the list cannot be read (the UI shows `mapping.scan.noScannerAccess` and Scan runs with the current scanner). `scanners` is empty for `unavailable`. Order: by name, case-insensitive, then UUID. Disabled scanners are left out.
- `switch` is `{"scanner_name","state"}` when the project lock row exists for the mapping's Harbor project (`switched` or `restore_pending`), else `null`. It carries the scanner name only, no UUID of other projects, no job id of another tenant. It is read from the database; the list call reads Harbor, not the lock.
- `GET .../scanners` calls Harbor (call 2, and call 1 for `is_current`) with the mapping's credential on the server, and caches the result per Harbor credential and project for 5 minutes, in memory, as the pickers do ("Search, paging, and cache"). Only a successful read is cached. Harbor errors use the fixed text of "Errors and rate limits": `403` on the candidates call is not an error here (`unavailable`); a `401` or non-robot identity is `422 validation_failed` with detail `harbor_identity`; unreachable, `5xx`, a redirect or an unparseable body is `502 upstream_unreachable`; a Harbor rate limit is `429 rate_limited`.
- `POST .../scan`: `:tag` must be an existing tag in `cve_findings` or a tag Harbor returns for the repository; HarborGate checks it with the artifact read at job time, and a `404` there is a final job note (`artifact no longer in Harbor`). `:tag` is validated with the Harbor tag rule (1 to 128 characters of letters, digits, `_`, `.`, `-`, not starting with `.` or `-`; Harbor's tag pattern `^[\w][\w.-]{0,127}$`, to confirm against the Harbor source before build, UNVERIFIED) and percent-encoded; a bad tag is `422 validation_failed` and no request is made.
  - `scanner_uuid` is required when `scanner_choice` is `available`, otherwise `400 invalid_request` ("Choose a scanner."). It must be one of the enabled scanners from the latest list read (HarborGate re-reads call 2 when the cache is older than 5 minutes); an unknown UUID is `422 validation_failed` with the fixed message "That scanner is not available in Harbor." When `scanner_choice` is `single` or `unavailable`, `scanner_uuid` is ignored if given.
  - `409 conflict`: a `queued` or `running` `scanner_scan` job already exists for the same (mapping, tag, scanner), or the project lock holds an unrestored switch (`restore_pending`) so no new switch may start. Fixed messages: "A scan with this scanner is already in progress." and "The Harbor project scanner is waiting to be restored. Try again when it has been." The first leaves no job; neither makes a Harbor call.
  - `202` means the job was queued and nothing else. Progress is read from `GET .../scans` and the Sync jobs page. The route does not wait for Harbor.
  - Audit: `mapping.scan` with `details` `{"mapping_id","tag","scanner_uuid"}` (ids and the tag only, no values). Added to the vocabulary in [database.md](database.md).
- Rate limits (Decided 2026-11-07, delegated, #224; every route declares its limit): `GET .../scanners` shares the picker limit, 60 per minute per user, in memory ([api.md](api.md), Pickers), because it is a Harbor read for a user action; `POST .../scan`: one scan per (mapping, tag, scanner) per 5 minutes, the same cooldown as the manual pull (Decided 2026-11-05, user, #131), held in memory, cleared by a restart, checked after the tenancy check so another tenant's mapping is `404`, never `429`, over the limit `429 rate_limited` with `Retry-After` and "A scan was started a moment ago. Try again in a few minutes." A scan that fails still uses the 5 minutes (as for the pull). `GET .../scans`: no limit; it reads only the database. Reason: one scan switches the scanner of a shared Harbor project, so repeated clicks must not toggle it.
- Who may call: the mapping owner and any admin may start a scan. This is the third admin exception to read-only access, beside retry and the manual pull ([security.md](security.md), Tenancy), because a scan only queues work that uses the owner's credential on the server, and no credential value is shown. Reads are open to the owner and any admin.
- Fixed `note` keys on `TagScan`: `sync.note.scannerForbidden`, `sync.note.scanForbidden`, `sync.note.scannerGone`, `sync.note.scannerFailed`, `sync.note.restoreFailed`, `sync.note.previousScannerGone`, `sync.note.scannerChangedElsewhere`, `sync.note.scannerUnmatched`, plus the existing `sync.note.artifactGone`. The client shows catalog text chosen by the key; the server never sends free text from Harbor.

## Project webhooks

One project webhook per Harbor base URL and project. Its rules (owner, routing, rotation, transfer) are in [integrations.md](integrations.md), "Project webhook (one per Harbor project)". The receiver `POST /api/v1/webhooks/harbor/project/:project_token` is public and is not listed here. Decided (2026-11-05, user, #132).

- `ProjectWebhook` is `{"id","harbor_base_url","harbor_project","owner","created_at","rotated_at"}`, where `owner` is the owner's username for the owner and admins, and `rotated_at` is `null` until the first rotation. It never contains the URL, token, or secret.
- The `GET` response adds `"mappings"`: a list of Harbor repository names (`harbor_repository`) only. It never contains other users' usernames, targets, or mapping ids.
- Rotation and create responses carry the value once. A later `GET` never returns it.

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/project-webhooks` | session | `{"mapping_id"}`; the caller must own that mapping | `{"id","webhook_url": "<shown once>","auth_secret": "<shown once>"}` | 201, 400 (body not valid), 401, 404 (mapping not the caller's, or not found), 409 `conflict` (a project webhook already exists for that Harbor base URL and project) |
| GET | `/api/v1/project-webhooks/:id` | session (owner or admin, read) | none | `ProjectWebhook` with `mappings` | 200, 401, 403 (not owner or admin), 404 |
| POST | `/api/v1/project-webhooks/:id/rotate-token` | session (owner only) | none | `{"webhook_url": "<new, shown once>","mappings": [harbor_repository, ...]}` | 200, 401, 403 (any non-owner, including admins), 404 |
| POST | `/api/v1/project-webhooks/:id/rotate-secret` | session (owner only) | none | `{"auth_secret": "<new, shown once>","mappings": [harbor_repository, ...]}` | 200, 401, 403 (any non-owner, including admins), 404 |
| GET | `/api/v1/project-webhooks/:id/unmatched` | session (owner or admin, read) | list params; `sort` (`last_seen_at`, `count`, `repository`), default `last_seen_at` descending; any other `sort` value is `400 invalid_request` | paged list of `{"repository","count","last_seen_at"}`; rows for repositories that now have a mapping are hidden | 200, 400, 401, 403, 404 | Decided (2026-11-06, user, #145): an event for another Harbor project, or a repository name that fails the Harbor name rule or is over 255 characters, is not counted here.

- Audit: create writes `project_webhook.create`, token rotation writes `project_webhook.token_rotate`, secret rotation writes `project_webhook.secret_rotate`, and an owner change writes `project_webhook.owner_transfer`. Details hold ids only, never values ([database.md](database.md)).

## Pickers

Decided (2026-11-05, user, #126): the mapping form picks the Harbor project, the Harbor repository and the GitHub repository from live lists fetched with the credential the user picked, can suggest a GitHub repository from the image source label, and lets each user hide and restore list items for their own pickers. The upstream calls, the 5-minute cache, the hide model, the suggestion rule and the error mapping are in [integrations.md](integrations.md), "Mapping pickers". The table is in [database.md](database.md), `picker_hidden_items`. Built (backend, #126).

Decided (2026-11-05, delegated, #126): route names. The three lists and the suggestion hang under the credential they use (`/credentials/:id/...`), like the existing `/credentials/:id/test`, so the owner-only check is the credential's. Path words are hyphenated plurals, like `sync-jobs` and `rotate-webhook-token`. Hidden items are their own resource, `/pickers/hidden`, because they belong to the user, not to a credential. Reason: the decisions name the routes' purpose, not their paths.

`HarborProject` is `{"name"}`. `HarborRepository` is `{"project","repository","full_name","mapped"}`, where `full_name` is `<project>/<repository>` and `mapped` is `true` when a mapping on the same Harbor base URL already uses that repository, for any user (Decided 2026-11-06, user, #189; [integrations.md](integrations.md), "Hide and restore"). `mapped` names no mapping or owner. `GitHubRepository` is `{"owner","repo","full_name","private","archived"}`. `HiddenItem` is `{"id","source","full_name","harbor_base_url","created_at"}`, where `harbor_base_url` is `null` for `github` source. None of them carries a token, a URL with credentials, or an upstream header.

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/credentials/:id/harbor-projects` | session (credential owner only) | `page`, `page_size`, `order`; `sort` (`name`); `q` (search, at most 100 characters) | list of `HarborProject`, plus `"truncated": bool` | 200, 400, 401, 404, 422, 429, 502 |
| GET | `/api/v1/credentials/:id/harbor-projects/:project/repositories` | session (credential owner only) | `page`, `page_size`, `order`; `sort` (`name`); `q` (search, at most 100 characters) | list of `HarborRepository`, plus `"truncated": bool` | 200, 400, 401, 404, 422, 429, 502 |
| GET | `/api/v1/credentials/:id/github-repositories` | session (credential owner only) | `page`, `page_size`, `order`; `sort` (`full_name`); `q` (search, at most 100 characters) | list of `GitHubRepository`, plus `"truncated": bool` | 200, 400, 401, 404, 422, 429, 502 |
| GET | `/api/v1/credentials/:id/source-suggestion` | session (owner of both credentials) | `project`, `repository` (required); `github_cred_id` (optional) | `{"suggestion": {"github_owner","github_repo","image_tag","github_listed"} or null, "reason": null or "no_tagged_artifact" or "no_label" or "not_github" or "invalid_label"}` | 200, 400, 401, 404, 422, 429, 502 |
| GET | `/api/v1/pickers/hidden` | session (own items only) | `page`, `page_size`, `order`; `sort` (`created_at`, `full_name`); `source` (`harbor` or `github`) | list of `HiddenItem` | 200, 400, 401 |
| POST | `/api/v1/pickers/hidden` | session (own items only) | `{"source","full_name","harbor_base_url"}` (`harbor_base_url` required for `harbor`, rejected for `github`) | `HiddenItem` | 201 (hidden), 200 (already hidden, existing item), 400, 401, 403 `csrf_invalid`, 422 |
| DELETE | `/api/v1/pickers/hidden/:id` | session (own items only) | none | empty | 204, 401, 403 `csrf_invalid`, 404 |

- Who may call (Decided 2026-11-05, user, #126: lists use the caller's own credential; hide is per user, for the user's own pickers only):
  - The list and suggestion routes run only with a credential owned by the caller. Another user's credential, or an unknown id, returns `404`. There is no admin exception and no `scope=all`: an admin cannot list with another user's credential, because that would use the other user's token. This follows the rule that admins cannot use or change another user's credentials ([security.md](security.md), Tenancy).
  - `source-suggestion`: `:id` is the Harbor credential. `github_cred_id`, when given, must also be the caller's GitHub credential, otherwise `404`.
  - Hidden items: a user reads, adds, and removes only their own rows. Another user's item id returns `404`. Decided (2026-11-05, delegated, #126): admins have no `scope=all` here. Reason: hidden items are a personal preference and change no tenant data an admin needs to see.
- Credential type: a Harbor route called with a GitHub credential, or the GitHub route with a Harbor credential, returns `422 validation_failed` with "This credential is the wrong type for this list." (Decided 2026-11-05, delegated, #126. Reason: the credential exists and is the caller's, so `404` would be misleading.) The same applies to `:id` and `github_cred_id` on `source-suggestion`.
- Paging: the [Lists](#lists) rules apply (`page_size` default 50, maximum 200, an unknown `sort` is `400`). The response adds `"truncated"`, which is `true` when the upstream list was cut at the fetch cap (1,000 items; [integrations.md](integrations.md), "Search, paging, and cache"), so `total` may be less than what the credential can reach. Decided (2026-11-05, user, #126): `truncated` is `true` only when the cap stopped the read and a further item exists; a list of exactly 1,000 items with nothing after it is `false` (the exact rule per service is in [integrations.md](integrations.md), "Search, paging, and cache"). `total` counts items after the caller's hidden items are removed. Default `sort` is the name, ascending.
- Search: `q` is the text filter. Over 100 characters, or with a control character, it is `400 invalid_request` with a fixed message, as for the CVE list. For Harbor it is sent to Harbor as a name filter; for GitHub it filters the cached list by a case-insensitive substring of `full_name` ([integrations.md](integrations.md)).
- Hidden items are left out of the three lists. They are shown by `GET /pickers/hidden`, and `DELETE /pickers/hidden/:id` restores one.
- `:project` and the suggestion's `project` and `repository` must pass the Harbor name rule ([security.md](security.md), Outbound HTTP), otherwise `422 validation_failed` and no request is made. A missing `project` or `repository` is `400 invalid_request`.
- Hide request (Decided 2026-11-05, user, #126: hidden items are keyed by Harbor base URL; reasons in [integrations.md](integrations.md), "Hide and restore"): `source` is `harbor` or `github`. For `harbor`, `full_name` is a project (`<project>`) or a repository (`<project>/<repository>`) that passes the Harbor name rule, and `harbor_base_url` is required: the Harbor base URL the item is hidden on. The item is hidden only on that base URL. For `github`, `full_name` is `<owner>/<repo>` that passes the GitHub name check, stored lowercased, and `harbor_base_url` is rejected with `422 validation_failed` and the fixed text "harbor_base_url is only for Harbor items." A missing `harbor_base_url` for `harbor` is `422 validation_failed`. Hiding an item that is already hidden returns `200` with the existing item, so a double click is not an error. The 1,001st hidden item of a user is `422 validation_failed`. Hiding makes no upstream call.
- Suggestion: suggests only and stores nothing (Decided 2026-11-05, user, #126). No suggestion is `200` with `suggestion: null` and a `reason`. `image_tag` is the tag of the artifact the label was read from, so the user can see what the suggestion is based on. `github_listed` is `true` or `false` when `github_cred_id` is given (whether the suggested repository is in that credential's GitHub list), and `null` otherwise. The label value itself is never returned. Confirming a suggestion is a normal `POST` or `PUT /mappings`, with the usual probes.
- Errors (Decided 2026-11-05, user, #126: fixed text only; a rate limit shows a fixed message and nothing retries): the mapping from Harbor and GitHub answers to `404`, `422`, `429` and `502`, with each fixed message, is in [integrations.md](integrations.md), "Errors and rate limits". No upstream body, header, or URL is returned.
- Rate limits. Decided (2026-11-05, delegated, #126):
  - The three list routes and `source-suggestion` share one limit of 60 requests per minute per user, held in memory and keyed by user id; a restart clears it. Over the limit the route returns `429 rate_limited` with `Retry-After` and the fixed message "Too many picker requests. Try again in a minute." The check runs after the tenancy check, so another user's credential is `404`, never `429`. Reason: a typing user sends a request per search, and distinct search texts miss the cache and reach Harbor; 60 per minute covers typing with a client debounce while keeping one user from flooding Harbor or GitHub.
  - An upstream rate limit is a separate `429 rate_limited` with its own fixed message and the upstream wait as `Retry-After`; until that time HarborGate makes no call to that service with that credential ([integrations.md](integrations.md)).
  - `GET`, `POST /pickers/hidden` and `DELETE /pickers/hidden/:id`: no limit. They touch only the caller's own rows, make no upstream call, and the row count is capped at 1,000 per user.
- CSRF: `POST` and `DELETE /pickers/hidden` need `X-CSRF-Token`, like every state-changing route. The `GET` routes do not.
- Audit: none for the list, suggestion, hide, or restore routes (issue #126, "Auditing": hiding is a user preference). A mapping created or changed from a picked value or a suggestion is audited as `mapping.create` or `mapping.update`, like a typed one.

## CVEs

`{id}` identifies one CVE within one mapping, because acceptance and issues are per mapping and `cve_findings` has one row per tag. Decided (2026-11-03, delegated): `{id}` is `<mapping_id>:<cve_id>`, URL-encoded (`:` is `%3A`). Neither a UUID nor a CVE id contains a colon. No external source. Alternative: nest the routes under `/mappings/:mapping_id/cves/:cve_id`. The paths below follow the form the user gave for `POST /api/v1/cves/{id}/issue`.

`CveSummary` is `{"id","mapping_id","cve_id","severity","status","package","first_seen_at","last_seen_at","github_issue_url","accepted"}`. `status` is `open` or `fixed`, `accepted` is derived (see [cve-lifecycle.md](cve-lifecycle.md)). `CveDetail` adds `"tags": [{"image_tag","status","last_scan_at","fixed_in_version"}]` with up to 10 tags, and `"acceptance": {...} or null`.

Decided (2026-11-03, user, #35): `CveSummary` also has `"fixed_in_version"` (from the most recently scanned tag that reports the CVE; `null` when unknown), `"open_tags"` (tracked tags where the CVE is open), `"tracked_tags"` (tracked tags of the mapping, at most 10), `"github_issue_number"`, and `"github_issue_status"` (`open`, `closed`, or `null` when there is no issue). `CveDetail` also has `"description"` (the Harbor vulnerability description, or `null`; see [database.md](database.md), `cve_findings.description`).

Decided (2026-11-07, user, #224 d2): `CveSummary` and `CveDetail` also have `"scanner_count"` (integer, at least 1) and `"scanners"` (a list of `{"uuid","name"}`, ordered as in [cve-lifecycle.md](cve-lifecycle.md), "Merged view"), for the newest scanned digest that reports the CVE; for a fixed CVE they are those of its last open scan, `scanner_count` 0 and `scanners` empty if none is known. `CveDetail.tags[]` adds `"scanners"` (names for that tag's digest). `GET /cves` and `GET /mappings/:id/cves` add an optional filter `scanner` (a scanner UUID, exact match, one value): the CVE is reported by that scanner. A bad value (not a UUID or `unknown`, or over 64 characters) is `400 invalid_request`.

Decided (2026-11-05, delegated, #129): `CveSummary` also has `"open_severity"`, the highest severity across the CVE's `open` tag rows, or `null` when the CVE is fixed on every tag. It is the severity a manual issue is logged with ([integrations.md](integrations.md), "GitHub issues"), so the UI uses it to decide whether the manual-issue button needs a confirmation (LOW or UNKNOWN). `severity` stays the highest across all of the CVE's rows, open or fixed.

| Method | Path | Auth | Request | Response | Codes |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/mappings/:id/cves` | session | list params; `sort` (`severity`, `cve_id`, `first_seen_at`, `last_seen_at`), `severity`, `status`, `accepted`, `q`, `package`, `tag`, `harbor_project`, `harbor_repository` | list of `CveSummary` | 200, 400, 404 |
| GET | `/api/v1/cves` | session | same as above plus `mapping_id`; admin may add `scope=all` | list of `CveSummary` | 200, 400, 401, 403, 404 |
| GET | `/api/v1/cves/:id` | session | none | `CveDetail` | 200, 404 |
| POST | `/api/v1/cves/:id/accept` | session (mapping owner) | `{"reason","expires_at"}` | `{"acceptance": {...}}` | 201, 404, 409 (already accepted), 422 (empty reason, past expiry) |
| POST | `/api/v1/cves/:id/unaccept` | session (mapping owner) | none | empty | 204, 404 (no active acceptance) |
| POST | `/api/v1/cves/:id/issue` | session (mapping owner) | none | `{"github_issue_url","github_issue_number"}` | 201, 403 `csrf_invalid`, 404, 409 (open issue exists, body has its URL; or an active acceptance), 422 (the CVE is not open on any tracked tag), 502 |

- Accept applies to the whole mapping. It does not close an open issue. It adds a comment (Decided 2026-11-03, delegated; [cve-lifecycle.md](cve-lifecycle.md)). Un-accept is a soft revoke.
- Both accept and un-accept are audited (`cve.accept`, `cve.unaccept`).
- CVE list filters. Decided (2026-11-05, user, #129): the default list shows every severity (no severity filter is applied), and accepted and fixed CVEs are reached through `status`. Decided (2026-11-05, delegated, #129) for the exact semantics:
  - `severity`: one or more of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`, comma-separated (`severity=LOW,UNKNOWN`). Values are case-sensitive. A CVE matches when its `severity` (the highest across its tags) is any of them. A single value works as before.
  - `status`: one or more of `open`, `fixed`, `accepted`, comma-separated. `open` and `fixed` match the CVE's `status` field; `accepted` matches a CVE with an active acceptance (`accepted: true`), whatever its `status`. A CVE matches when any listed value matches (`status=fixed,accepted`).
  - `accepted` (`true` or `false`) is kept and is combined with `status` by AND, so `status=open&accepted=false` is the open CVEs that are not accepted.
  - `package`: the CVE's `package` field equals the value exactly (case-sensitive).
  - `tag`: the CVE has a row for that image tag, open or fixed. The summary is still aggregated over every tag.
  - `harbor_project` and `harbor_repository`: the mapping's Harbor project or repository equals the value exactly.
  - Different parameters combine by AND. Within one comma-separated parameter, values combine by OR. Repeated values are ignored. `package`, `tag`, `harbor_project` and `harbor_repository` take one value each and are not split on commas. An empty `package`, `tag`, `harbor_project`, `harbor_repository` or `q` means no filter.
  - A bad value returns `400 invalid_request` with a fixed message: an unknown or empty `severity` or `status` item, a `package`, `tag`, `harbor_project` or `harbor_repository` value over 256 characters, a `q` over 100 characters (unchanged), or a text value with a control character. Every filter value is a bound SQL parameter (multi-value lists are bound as one JSON array), never part of the SQL text.
  - `total` is computed with exactly the same predicates as `items`. `page_size` stays capped at 200. Tenancy is unchanged: the filters narrow the caller's own CVEs (or every tenant's with admin `scope=all`) and never widen them.
- `POST .../issue` creates an issue for a CVE of any severity that is open on at least one tracked tag (Changed 2026-11-05, user, #129; until then only `CRITICAL` or `HIGH`). A CVE fixed on every tag is `422`. The issue uses the highest open severity (`open_severity`). Automatic creation still uses only `CRITICAL` and `HIGH` ([integrations.md](integrations.md)). The LOW and UNKNOWN confirmation is a frontend step; the route takes no confirm flag. It reuses the closed issue for the same CVE and repo by reopening it, never creates a second one (lifecycle rules in [cve-lifecycle.md](cve-lifecycle.md)).
- Decided (2026-11-03, G28): the manual-issue button lives in the per-CVE page header, next to the GitHub issue link. See [frontend.md](frontend.md).
- A tag with zero findings has no `cve_findings` row, so it does not appear in `tags`. Decided (2026-11-03, delegated): the tag list shows only tags that report this CVE.

## Sync jobs

`SyncJob` is `{"id","mapping_id","kind","status","attempts","next_attempt_at","last_error","created_at","updated_at","report": {...} or null}`. `report` is the linked `sync_reports` row (`image_tag`, `image_digest`, `commit_sha`, `vulnerability_summary`, `sarif_status`, `synced_at`).

Decided (2026-11-03, user, #35): `SyncJob` also has `"trigger"` (`webhook` or `poll`, read from `payload.trigger`; a payload without the field is `webhook`) and `"image": {"repo_full_name","tag","digest"}` from the job payload, so queued and running jobs show their image before a report exists.

Decided (2026-11-07, user, #224): `kind` may also be `scanner_scan` or `scanner_restore` (payload `kind`). Their `image` is set from the payload (`scanner_restore` has `image.tag` and `image.digest` `null`), and `SyncJob` adds `"scanner": {"uuid","name"} or null` for `scanner_scan` jobs (`null` when the job uses the current scanner). `trigger` stays `webhook`, `poll`, `schedule` or, for a scan started from the mapping page, `manual`. Decided (2026-11-07, delegated, #224): `manual` is new, so the Sync jobs page can tell a scan a user started from one the scheduler did. A payload without `trigger` is still `webhook`. Retry works on a failed `scanner_scan` or `scanner_restore` job as on any job; retrying a `scanner_restore` job re-runs the restore with the lock row.

Decided (2026-11-07, #191): `trigger` may also be `schedule`, for a scan job and for the sync job a scheduled scan queues. `kind` may also be `scan` (payload `kind` `scan`); a scan job's `image.tag`, `image.digest` and `report` are `null`. `report` adds `"new_cve_ids"`: for a scheduled sync, the CVE ids not in the last stored result for the same digest (an empty list when nothing is new); `null` for every other trigger and for reports stored before migration 0008. A scan job's fixed notes and messages are in [integrations.md](integrations.md), "Scheduled scan".

Decided (2026-11-05, user, #132): `SyncJob` also has `"kind"` (`sync` or `resolve`, read from `payload.kind`; a payload without the field is `sync`). For a resolve job, `image.tag` is `null` and `report` is `null`, and `image.digest` is set. A failed resolve job has one of the fixed `last_error` strings in [integrations.md](integrations.md). Decided (2026-11-05, delegated, #132): the retry route works on a failed resolve job as on any job, because it only re-queues work.

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
| GET | `/api/v1/dashboard/summary` | session | admin may add `scope=all` | `{"open_cves": {"critical","high","medium","low","unknown","total"}, "fixed_cves", "open_issues", "failed_syncs", "recent_syncs": [SyncJob]}` | 200, 401 |

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
| GET | `/api/v1/admin/github-url` | none | `{"api_base_url","web_url"}`, each the stored value or `""` when empty (the default applies) | 200, 401, 403 |
| PUT | `/api/v1/admin/github-url` | `{"api_base_url","web_url"}`, each `""` (default) or an https URL with a host; `api_base_url` may have a path, `web_url` is host-only | same as GET | 200, 401, 403, 422 `settings.github_url_invalid` (a value that is not https with a host, or has userinfo, port, query, or fragment, a `web_url` with a path, or an `api_base_url` path that fails the traversal rule). Decided (2026-11-06, user, #184), shape and codes follow the `/admin/oidc` pattern above (422, not 400, for an invalid value). Decided (2026-11-06, user, #184): api_base_url may include a path, for example /api/v3, for GitHub Enterprise Server. Audit: `github.url_change` is not in the vocabulary, so no audit row is written yet; an admin change needs a vocabulary entry first. |
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
- Handling: validate, store a `sync_jobs` row, return `202`. See [backend.md](backend.md). Decided (2026-11-05, user, #132): an untagged event with a valid digest stores one resolve job and returns `202` with no Harbor call. Decided (2026-11-05, user, #132): a `SCANNING_COMPLETED` vulnerability event with a missing or invalid digest returns `400`, tagged or not.

## Verification

Required test scenarios for the planner (high level):

- Every route above returns `401` without a session, except those marked public.
- A `user` session gets `404` for another tenant's mapping, credential, CVE, and job. An `admin` session can read them and cannot change them.
- A state-changing request without `X-CSRF-Token` returns `403 csrf_invalid`. The webhook and login are exempt.
- The error envelope shape is the same on every error response, and no response body contains a token, key, `password_hash`, or webhook URL, except the documented shown-once fields.
- Pagination: `page_size` above 200 returns `400`, the default is 50, and `total` is the unfiltered match count.
- Webhook: both payload fixtures return `202` and store one job. Decided (2026-11-05, user, #132): an untagged event fixture (digest, no tag, in each format) returns `202` and stores exactly one resolve job (`kind` `resolve`, no tag), with no outbound request recorded; the same event with an invalid digest returns `400` and stores nothing. A missing header and a wrong token return the identical `401`. An oversize body returns `413`. The 61st request in a minute returns `429`.
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
- CVE list (#129): with no filter every severity is listed. Each filter (`severity` with one and several values, `status` with `open`, `fixed`, `accepted` and a combination, `package`, `tag`, `harbor_project`, `harbor_repository`) returns the expected CVEs, and `total` equals the number of items over all pages. A bad value is `400 invalid_request`.
- Pickers (#126): a list or suggestion with another user's credential is `404`, also for an admin; a credential of the wrong type is `422`; the 61st list request in a minute is `429`; a second list call inside 5 minutes makes no upstream request (recorded responses); a hidden item is absent from its list and from `total`, and appears again after restore; hiding never changes a mapping or another user's list; a Harbor `429` or GitHub rate limit returns `429` with the fixed message and no retry; no list, suggestion, or error body contains a token or an upstream body; a robot that answers `users/current` with `401` gets `422`, not a list of public projects.
- Manual issue (#129): a LOW or UNKNOWN open CVE gets an issue; an automatic run never creates one below the mapping's minimum; an active acceptance is `409`; an open issue is `409` with its URL; a closed issue is reopened; a CVE fixed on every tag is `422`.
