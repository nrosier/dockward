# Integrations

Purpose: Harbor webhook, Harbor API usage, polling, OCI labels, and GitHub SARIF upload and issues.

Every value not already decided by the user is marked `PROPOSED:` with a source. Open items are marked OPEN: (unresolved questions) and PROPOSED: (awaiting approval). `UNVERIFIED:` marks a claim whose source could not be confirmed. Route-level contracts are in [api.md](api.md).

## Harbor webhook

- Endpoint: `POST /api/v1/webhooks/harbor/:mapping_token`. Public (no session, no CSRF token). See [api.md](api.md).
- The mapping token is only in the URL path. It is never placed in a header or body.
- The URL token is redacted or omitted from access logs and traces.
- Trigger: Harbor event `SCANNING_COMPLETED` only.
  - Source: Harbor webhook documentation (https://goharbor.io/docs/latest/working-with-projects/project-configuration/configure-webhooks/), which lists "Artifact scan completed" with event type `SCANNING_COMPLETED`. Harbor source `src/controller/event/topic.go` defines the same string.
- Payloads: accepts both Harbor's default JSON payload and the CloudEvents payload. Both produce the same internal event.
  - Harbor offers a payload format choice of `Default` and `CloudEvents` (Harbor API swagger, `PayloadFormatType`; [docs/SETUP.md](../docs/SETUP.md) step 3c).
  - Each format has its own test fixture.

### Payload format detection

- PROPOSED: the format is detected from the parsed JSON body. If the top-level object has a `specversion` member, the body is CloudEvents. Otherwise it is Harbor's default JSON.
  - Source: CloudEvents JSON Event Format, which requires `specversion` as a REQUIRED attribute in the JSON event (https://github.com/cloudevents/spec/blob/main/cloudevents/formats/json-format.md; fetched in this session, section "Examples" and the attribute table).
  - Source for the default payload shape: Harbor source `src/pkg/notifier/formats/default.go` (top-level `type`, `occur_at`, `operator`, `event_data`). Harbor `src/pkg/notifier/formats/cloudevents.go` sets `Content-Type: application/cloudevents+json` for the CloudEvents form.
- Detection is based on the body, not on the `Content-Type` header. A header can be wrong or missing.
- If the body is valid JSON with neither a `specversion` member nor the Harbor default shape, the request returns 400.

### Auth header

- Harbor's webhook configuration has a single `auth_header` value (Harbor API swagger, `WebhookTargetObject.auth_header`, "The webhook auth header"). Harbor source `src/pkg/notifier/handler/notification/http_handler.go` sends that value as the HTTP `Authorization` header (`header.Set("Authorization", event.Target.AuthHeader)`).
- Decided (2026-11-03): `Authorization: Bearer <secret>`, see decision. Harbor sends the configured value as the `Authorization` header, so the `Bearer` scheme prefix is part of the value entered in Harbor. A custom auth header name is not used.
  - Source for Harbor sending the value as `Authorization`: Harbor source `http_handler.go` (fetched in this session). Source for the Bearer scheme: RFC 6750 section 2.1 (https://www.rfc-editor.org/rfc/rfc6750).
  - The `Authorization` header is sent with every webhook request. Harbor's UI text is "If your webhook listener implements authentication, enter the authentication header" (Harbor webhook docs, fetched in this session).
- Secret value: PROPOSED: 256 bits from a CSPRNG, encoded as base64url without padding (43 characters). Source for the 256-bit sizing: OWASP Session Management Cheat Sheet, "Session ID Entropy" (at least 64 bits required, and 256 bits is a stronger choice that the spec picks; https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). Source for base64url: RFC 4648 section 5 (https://www.rfc-editor.org/rfc/rfc4648).
- The secret is stored encrypted with AES-256-GCM (`v1:` format, see [security.md](security.md)) and shown once.
- The secret is rotatable. Rotation writes a new encrypted value and audits `mapping.auth_secret_rotate`.
- Compare values in constant time.
- Requests with a missing or wrong `Authorization` value are rejected with 401.
- The header value is never logged.

### Webhook URL token

- PROPOSED: `webhook_token` is a random value of at least 256 bits from a CSPRNG, encoded as base64url without padding.
  - Source: OWASP Session Management Cheat Sheet, "Session ID Entropy", which requires at least 64 bits of entropy from a strong CSPRNG (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). 256 bits is a stronger choice, which the spec makes deliberately.
- The URL is a secret. Anyone who has it can trigger syncs for that mapping. It is shown on the mapping screen and is not logged.
- Rotation is `POST /api/v1/mappings/:id/rotate-webhook-token`. The old token stops working immediately.

### Responses

- PROPOSED response codes for `POST /api/v1/webhooks/harbor/:mapping_token`:
  - `202 Accepted`: the body is valid and a `sync_jobs` row was stored. Source: RFC 9110 section 15.3.3 (202 Accepted, https://www.rfc-editor.org/rfc/rfc9110).
  - `401 Unauthorized`: the mapping token is unknown, or the `Authorization` value is missing or wrong. Both auth failures return the same 401 with the same body, so the response does not reveal which check failed. Source: OWASP Authentication Cheat Sheet, which requires generic error messages that do not distinguish the failure reason (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html). Source for 401: RFC 9110 section 15.5.2.
  - `400 Bad Request`: the body is not parseable JSON, or it matches neither format. Source: RFC 9110 section 15.5.1.
  - `413 Content Too Large`: the body is over the cap. Source: RFC 9110 section 15.5.14.
  - `429 Too Many Requests`: the rate limit is exceeded. Source: RFC 6585 section 4.
- The body cap and rate limits are in [security.md](security.md).
- Handling is durable: validate, store a `sync_jobs` row, return. See [backend.md](backend.md).
- Only events with `SCANNING_COMPLETED` create a job. Other event types return `202` and store nothing, so that Harbor does not retry them. PROPOSED, no external source (UNVERIFIED: Harbor's retry behaviour on non-2xx responses was not checked). The setup guide tells the user to select only this event, so this path should be rare.

## Harbor API

### Vulnerability report endpoint

- Endpoint used: `GET /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities`.
  - Source: Harbor API v2.0 swagger (https://github.com/goharbor/harbor/blob/main/api/v2.0/swagger.yaml), operation `getVulnerabilitiesAddition`, path `/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities`. Verified in this session.
- `{repository_name}` is the Harbor repository name. If it contains a slash, encode it twice (Harbor swagger, `repositoryName`: "If it contains slash, encode it twice over with URL encoding"). Example: `a/b` becomes `a%252Fb`.
- `{reference}` is the artifact digest (`sha256:...`). PROPOSED: use the digest, not a tag, because a tag can move between the event and the fetch. Harbor swagger, `reference`: "The reference can be digest or tag".
- Request header: `X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1` is the Trivy report MIME type. Harbor swagger, `acceptVulnerabilities`, lists `application/vnd.security.vulnerability.report; version=1.1` as the default. PROPOSED: send this value explicitly and reject a response with another content type. UNVERIFIED: that a Trivy-only install returns the Trivy report under this MIME type in the operator's Harbor version.
- Response: the swagger types the 200 body as a plain `string` with a `Content-Type` header, so the body schema is not defined in the swagger. UNVERIFIED: the exact report JSON shape for the Trivy MIME type; the converter fixture must come from a real Harbor response. The swagger `VulnerabilityItem` model (a different, summary-style object) has `cve_id`, `package`, `version`, `fixed_version`, `severity`, and `status`; the spec maps `fixed_version` to `cve_findings.fixed_in_version` on that basis, UNVERIFIED for the addition body.
- Status codes: 200 success, 400, 401, 403, 404 (artifact not found or no report), 500. Harbor swagger, `getVulnerabilitiesAddition`.
- 404 means the artifact has no report yet. The worker retries it with backoff (see [backend.md](backend.md)). It is not an immediate failure.

### Credentials and robot account

- Robot account username: `robot$<name>`. Source: Harbor robot account documentation (https://goharbor.io/docs/latest/administration/robot-accounts/, fetched in this session), "robot$ prefix". UNVERIFIED: the project-level `robot$<project>+<name>` form in [docs/SETUP.md](../docs/SETUP.md) section 3b is not confirmed by the fetched page. Copy the exact name Harbor shows.
- Robot account expiry: 30 days by default. Source: Harbor robot account documentation (fetched in this session; the default expiry text is confirmed). The system-wide duration is `robot_token_duration` in days (Harbor API swagger). A per-robot `duration` of `-1` means never expires (Harbor API swagger, `RobotCreate.duration`).
- The stored credential has `user_credentials.username` and `user_credentials.expires_at` (see [database.md](database.md)).
- Health: the app warns before `expires_at` (see [frontend.md](frontend.md)). Decided (2026-11-03): the warning window is 14 days before `expires_at`. The window is fixed in v1, not user-set.

### Harbor base URL and transport

- The Harbor base URL is stored per Harbor credential in `user_credentials.base_url`. Each mapping uses its credential's `base_url`. Decided: 2026-11-02.
- PROPOSED: the base URL must be `https://`. Plain HTTP is rejected on save.
- PROPOSED: the resolved address must not be loopback, link-local, or private, unless `HARBORGATE_ALLOW_PRIVATE_HARBOR=true`. The address check and the blocked ranges are in [security.md](security.md) under "Outbound HTTP (SSRF)".
  - Source: OWASP SSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- Redirects are not followed.
- Harbor API paths are relative to `base_url` and begin with `/api/v2.0/` (Harbor swagger `basePath: /api/v2.0`).

### Test button

- Harbor test: PROPOSED: `GET /api/v2.0/projects/{project_name}` with the robot credential, or a list call scoped to the mapping's project (`GET /api/v2.0/projects?name=<project>`). Both require authentication.
  - Verified: Harbor swagger `/users/current` returns 412 for robot accounts ("Returns 412 if the caller is authenticated via a non-local context such as a robot account"). So `/users/current` is not usable for the test.
  - Verified: `GET /api/v2.0/systeminfo` is documented as callable anonymously ("this can be called by anonymous request"), so it cannot prove the robot secret is valid. Not used for the test.
  - UNVERIFIED: that `GET /api/v2.0/projects?name=<project>` authenticates a robot account and returns the project. The swagger lists 401 for missing auth; the robot case was not run.

## Polling

- Webhooks are the primary trigger.
- Backup polling runs every 15 minutes across all mapped Harbor projects. The 15-minute interval is a user decision.
- Polling lists artifacts per mapping and uses the digest to decide whether to sync.
- Decided: polling skips an image whose digest already has a successful sync for that mapping and tag. "Successful" means `sync_jobs.status = 'done'` and `sarif_status = 'success'` on the linked report (Decided 2026-11-03 in [database.md](database.md)).
- Source for the artifact list endpoint: Harbor swagger, `GET /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts`, with `page` and `page_size` query parameters. The artifact object includes `digest`, `tags`, `push_time`, and `pull_time` (verified in this session).
- Note: "backup polling" here means Harbor polling. It is not the admin backup command. See [security.md](security.md).

## OCI labels

Read these from the Harbor artifact (`GET .../artifacts/{reference}` or the artifact's config labels):

- Commit SHA: `org.opencontainers.image.revision`. Required. If missing, the sync is marked `failed` with a clear error. Never guess the SHA.
- Repository: `org.opencontainers.image.source`.
- Branch: `org.opencontainers.image.ref.name` if present. Otherwise the mapping's `default_branch` (default `main`).
- Source for the label names: OCI Image Format Specification, annotations (https://github.com/opencontainers/image-spec/blob/main/annotations.md). UNVERIFIED: this page was not fetched in this session; the label names are taken from the user's existing spec and the setup guide.

## SARIF conversion and upload

- Convert the Trivy report to SARIF 2.1.0. Output must conform to the SARIF 2.1.0 schema (OASIS SARIF 2.1.0, https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
- Gzip, then base64-encode the SARIF payload.
- Upload with `POST /repos/{owner}/{repo}/code-scanning/sarifs`. The request body fields are `commit_sha`, `ref`, `sarif` (base64 gzip), and optional `checkout_uri`, `started_at`, `tool_name`, `validate`.
  - Source: GitHub REST API, "Code scanning" (https://docs.github.com/en/rest/code-scanning). UNVERIFIED: the field list was not fetched from the live GitHub docs in this session (the fetch returned only a partial page). Confirm before implementation.
- SARIF category is set to the Harbor repository name for each image, so results stay separate. UNVERIFIED: the mechanism. SARIF 2.1.0 has `runAutomationDetails.id` on each run, and GitHub documents a `category` concept for separating analyses; neither page was fetched in this session. Confirm whether the converter sets `runAutomationDetails.id` and what the upload endpoint expects.
- Validate output against SARIF 2.1.0 (see [testing-and-ci.md](testing-and-ci.md)).

## GitHub issues

- Auto-create issues for CRITICAL and HIGH findings. The `min_issue_severity` setting defaults to CRITICAL and may be lowered to HIGH (user decision).
- Only CRITICAL and HIGH create issues. MEDIUM, LOW, and UNKNOWN never do.
- Manual issue creation is also supported: `POST /api/v1/cves/:id/issue`. See [api.md](api.md).
- Issue lifecycle (one open issue per CVE per repo, close, reopen) is defined in [cve-lifecycle.md](cve-lifecycle.md).
- GitHub issues API permission: `Issues: read and write` (see [security.md](security.md)).

## GitHub target

- A GitHub repository (owner, repo) belongs to exactly one mapping, regardless of branch.
- Decided (2026-11-03): one mapping per GitHub repository. Two mappings for the same repo on different branches are not allowed. A user who needs two branches uses two GitHub repos. Enforced by `UNIQUE (github_owner, github_repo)` in [database.md](database.md).
- The app never moves a target between mappings. See [frontend.md](frontend.md) for the duplicate error.

- Decided (2026-11-03): the sync status definition used by the polling dedupe rule is `sync_jobs.status = 'done'` plus `sarif_status = 'success'`. See [database.md](database.md).
