# Integrations

Purpose: Harbor webhook, Harbor API usage, polling, OCI labels, and GitHub SARIF upload and issues.

Decisions are marked `Decided (<date>)`. On 2026-11-03 the user delegated every remaining proposal; those decisions are marked `Decided (2026-11-03, delegated)`. `Verified (<date>)` marks a claim checked against the cited source on that date. `UNVERIFIED:` marks a claim that can only be checked against a live system or a later build. Route-level contracts are in [api.md](api.md).

## Harbor webhook

- Endpoint: `POST /api/v1/webhooks/harbor/:mapping_token`. Public (no session, no CSRF token). See [api.md](api.md).
- The mapping token is only in the URL path. It is never placed in a header or body.
- The URL token is redacted or omitted from access logs and traces.
- Trigger: Harbor event `SCANNING_COMPLETED` only.
  - Source: Harbor webhook documentation (https://goharbor.io/docs/latest/working-with-projects/project-configuration/configure-webhooks/), which lists "Artifact scan completed" with event type `SCANNING_COMPLETED`. Harbor's web UI labels the same type "Scanning finished" (`src/portal/src/app/base/project/webhook/webhook.service.ts`, checked 2026-11-05). The type string is unchanged. Harbor source `src/controller/event/topic.go` defines the same string.
- Payloads: accepts both Harbor's default JSON payload and the CloudEvents payload. Both produce the same internal event.
  - Harbor offers a payload format choice of `Default` and `CloudEvents` (Harbor API swagger, `PayloadFormatType`; [docs/SETUP.md](../docs/SETUP.md) step 3c).
  - Each format has its own test fixture.

### Project webhook (one per Harbor project)

Decided (2026-11-05, user, #132): Harbor webhooks are set per project, so one project webhook serves every mapping in that project. The per-mapping URL stays valid, and the project webhook is the recommended setup for a project with more than one mapping.

- **Owner.** The project webhook belongs to the user who created the first mapping on that Harbor base URL and project (`harbor_base_url`, `harbor_project`). Other users' mappings on the same project are routed through it. They cannot change its URL or auth secret.
- **Endpoint.** `POST /api/v1/webhooks/harbor/project/:project_token`. Public, CSRF-exempt, like the mapping endpoint. The project token is a random value of at least 256 bits from a CSPRNG, base64url without padding, and only its SHA-256 digest is stored. It is shown once, when the project webhook is created.
- **Auth.** The same `Authorization: Bearer <secret>` rule as the mapping endpoint, with one project secret. Only the digest is stored, shown once.
- **Routing.** The event's `repository.repo_full_name` selects the mapping: the one mapping on that project whose `harbor_project`/`harbor_repository` equals the event's repository and whose `harbor_base_url` equals the project's. No mapping matches: the request returns `202` and stores nothing, and the event is recorded as unmatched (see below). More than one match cannot occur, because a mapping's Harbor repository is unique per Harbor instance.
- **Unmatched events.** An event for a repository with no mapping returns `202` and is counted, with its repository name, so the owner can see that Harbor sends events HarborGate does not map. Not silently dropped.
- **Rotation.** Only the project owner can rotate the project token or the project secret. Rotation shows the new URL and secret once and lists every mapping on the project that will use them. The old value stops working immediately.
- **Migration.** Existing per-mapping URLs keep working unchanged. A mapping whose Harbor project already has a project webhook shows the project URL as the recommended setup, and keeps its own URL until the owner switches Harbor to the project URL.
- **Scope of the trigger.** The same rules apply as for the mapping endpoint: `SCANNING_COMPLETED` only, `scan_type` `vulnerability`, a tag present, and a `repo_full_name` that matches a mapping. Only the routing step differs.

Status: decided here, not yet built. Building it needs the new route, the project table and its migration, the unmatched-event count, and the owner-only rotation.

### Payload format detection

- Decided (2026-11-03, delegated): the format is detected from the parsed JSON body. If the top-level object has a `specversion` member, the body is CloudEvents. Otherwise it is Harbor's default JSON.
  - Source: CloudEvents JSON Event Format, which requires `specversion` as a REQUIRED attribute in the JSON event (https://github.com/cloudevents/spec/blob/main/cloudevents/formats/json-format.md; fetched in this session, section "Examples" and the attribute table).
  - Source for the default payload shape: Harbor source `src/pkg/notifier/formats/default.go` (top-level `type`, `occur_at`, `operator`, `event_data`). Harbor `src/pkg/notifier/formats/cloudevents.go` sets `Content-Type: application/cloudevents+json` for the CloudEvents form.
- Detection is based on the body, not on the `Content-Type` header. A header can be wrong or missing.
- If the body is valid JSON with neither a `specversion` member nor the Harbor default shape, the request returns 400.

### Auth header

- Harbor's webhook configuration has a single `auth_header` value (Harbor API swagger, `WebhookTargetObject.auth_header`, "The webhook auth header"). Harbor source `src/pkg/notifier/handler/notification/http_handler.go` sends that value as the HTTP `Authorization` header (`header.Set("Authorization", event.Target.AuthHeader)`).
- Decided (2026-11-03): `Authorization: Bearer <secret>`, see decision. Harbor sends the configured value as the `Authorization` header, so the `Bearer` scheme prefix is part of the value entered in Harbor. A custom auth header name is not used.
  - Source for Harbor sending the value as `Authorization`: Harbor source `http_handler.go` (fetched in this session). Source for the Bearer scheme: RFC 6750 section 2.1 (https://www.rfc-editor.org/rfc/rfc6750).
  - The `Authorization` header is sent with every webhook request. Harbor's UI text is "If your webhook listener implements authentication, enter the authentication header" (Harbor webhook docs, fetched in this session).
- Secret value: Decided (2026-11-03, delegated): 256 bits from a CSPRNG, encoded as base64url without padding (43 characters). Source for the 256-bit sizing: OWASP Session Management Cheat Sheet, "Session ID Entropy" (at least 64 bits required, and 256 bits is a stronger choice that the spec picks; https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). Source for base64url: RFC 4648 section 5 (https://www.rfc-editor.org/rfc/rfc4648).
- Decided (2026-11-03): the secret itself is not stored. HarborGate stores only its SHA-256 digest (lowercase hex) in `repo_mappings.webhook_auth_secret_hash`. The secret is shown once, at creation and at rotation. To verify a request, the handler strips the `Bearer ` prefix, hashes the presented value, and compares the digests in constant time. A fast hash is enough because the value is 256 random bits and cannot be guessed offline; no external source.
- The secret is rotatable. Rotation writes a new digest and audits `mapping.auth_secret_rotate`.
- Compare values in constant time.
- Requests with a missing or wrong `Authorization` value are rejected with 401.
- The header value is never logged.

### Webhook URL token

- Decided (2026-11-03, delegated): the webhook token is a random value of at least 256 bits from a CSPRNG, encoded as base64url without padding.
  - Source: OWASP Session Management Cheat Sheet, "Session ID Entropy", which requires at least 64 bits of entropy from a strong CSPRNG (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). 256 bits is a stronger choice, which the spec makes deliberately.
- The URL is a secret. Anyone who has it can trigger syncs for that mapping. It is not logged.
- Decided (2026-11-03): only the SHA-256 digest (lowercase hex) of the token is stored, in `repo_mappings.webhook_token_hash` (UNIQUE). The full webhook URL is shown once, at mapping creation and at token rotation, and cannot be shown again. A lost URL is replaced by rotating the token. The handler hashes the path token and looks up the mapping by digest. The URL is built from `HARBORGATE_PUBLIC_URL` ([deployment.md](deployment.md)), never from the request's `Host` header.
- Rotation is `POST /api/v1/mappings/:id/rotate-webhook-token`. The old token stops working immediately.

### Responses

- Decided (2026-11-03, delegated) response codes for `POST /api/v1/webhooks/harbor/:mapping_token`:
  - `202 Accepted`: the body is valid and a `sync_jobs` row was stored. Source: RFC 9110 section 15.3.3 (202 Accepted, https://www.rfc-editor.org/rfc/rfc9110).
  - `401 Unauthorized`: the mapping token is unknown, or the `Authorization` value is missing or wrong. Both auth failures return the same 401 with the same body, so the response does not reveal which check failed. Source: OWASP Authentication Cheat Sheet, which requires generic error messages that do not distinguish the failure reason (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html). Source for 401: RFC 9110 section 15.5.2.
  - `400 Bad Request`: the body is not parseable JSON, or it matches neither format. Source: RFC 9110 section 15.5.1.
  - `413 Content Too Large`: the body is over the cap. Source: RFC 9110 section 15.5.14.
  - `429 Too Many Requests`: the rate limit is exceeded. Source: RFC 6585 section 4.
- The body cap and rate limits are in [security.md](security.md).
- Handling is durable: validate, store a `sync_jobs` row, return. See [backend.md](backend.md).
- Decided (2026-11-03, delegated): a job is created only when all three conditions hold. Otherwise the request returns `202` and stores nothing.
  - The top-level `type` is `SCANNING_COMPLETED` (default format) or `harbor.scan.completed` (CloudEvents). Verified (2026-11-03) in the Harbor source: `src/controller/event/topic.go` defines `SCANNING_COMPLETED`, and the type table in `src/pkg/notifier/formats/cloudevents.go` maps it to `harbor.scan.completed`.
  - The event's `scan.scan_type` is `vulnerability`. Harbor also sends `SCANNING_COMPLETED` for SBOM generation, with `scan_type` `sbom` (verified (2026-11-03), `src/pkg/scan/rest/v1/spec.go` and `src/controller/event/model/event.go`).
  - `repository.repo_full_name` equals `<harbor_project>/<harbor_repository>` of the mapping. Harbor webhooks are configured per project, so a webhook URL receives events for every repository in its project.
  - Decided (2026-11-03, user): the event has a tag (`resources[0].tag` is a non-empty string). An untagged event (pushed by digest) returns `202` and nothing is queued, because CVEs are tracked per tag and `image_tag` is NOT NULL.
  - Field paths: under `event_data` in the default format and under `data` in CloudEvents (verified (2026-11-03), `src/pkg/notifier/formats/default.go` and `cloudevents.go`). The artifact digest is `resources[0].digest`.
- Verified (2026-11-03) in `src/jobservice/job/impl/notification/webhook_job.go`: Harbor treats any response status outside 200 to 299 as a failure and retries the delivery, 3 times by default (`maxFails`, overridable by environment). Returning `202` for ignored events therefore stops needless retries.

## Harbor API

### Vulnerability report endpoint

- Endpoint used: `GET /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities`.
  - Source: Harbor API v2.0 swagger (https://github.com/goharbor/harbor/blob/main/api/v2.0/swagger.yaml), operation `getVulnerabilitiesAddition`, path `/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities`. Verified in this session.
- `{repository_name}` is the Harbor repository name. If it contains a slash, encode it twice (Harbor swagger, `repositoryName`: "If it contains slash, encode it twice over with URL encoding"). Example: `a/b` becomes `a%252Fb`.
- `{reference}` is the artifact digest (`sha256:...`). Decided (2026-11-03, delegated): use the digest, not a tag, because a tag can move between the event and the fetch. Harbor swagger, `reference`: "The reference can be digest or tag".
- Request header: `X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1` is the Trivy report MIME type. Harbor swagger, `acceptVulnerabilities`, lists `application/vnd.security.vulnerability.report; version=1.1` as the default. Decided (2026-11-03, delegated): send only this MIME type. Verified (2026-11-03): the Harbor Trivy adapter (`goharbor/harbor-scanner-trivy`, `pkg/http/api/v1/handler.go`) produces only this MIME type for vulnerability reports. The response `Content-Type` is always `application/json` (`src/server/v2.0/handler/artifact.go`), so the format is checked by the key of the response object, not by the header.
- Response, verified (2026-11-03) in `src/server/v2.0/handler/artifact.go` and `src/pkg/scan/vuln/report.go`: a JSON object keyed by MIME type, `{"application/vnd.security.vulnerability.report; version=1.1": Report}`. `Report` has `generated_at`, `scanner`, `severity`, and `vulnerabilities[]`. Each item has `id` (the CVE or advisory id), `package`, `version`, `fix_version`, `severity`, `status`, `description`, `links[]`, `preferred_cvss` (`score_v3`, `score_v2`, `vector_v3`, `vector_v2`), `cwe_ids[]`, `artifact_digests[]`, and `vendor_attributes`.
  - The field is `fix_version`, not `fixed_version` as in the swagger's summary `VulnerabilityItem`. `fix_version` maps to `cve_findings.fixed_in_version`.
  - Severity values are title case. The Trivy adapter emits only `Critical`, `High`, `Medium`, `Low`, and `Unknown` (verified (2026-11-03), `pkg/scan/transformer.go`). The converter upper-cases them.
  - The converter fixture is still captured from a real Harbor response, to cover adapter-version differences.
- Status codes: 200, 400, 401, 403, 404, and 500 (Harbor swagger, `getVulnerabilitiesAddition`). Verified (2026-11-03) in the handler: when the artifact has no report for the requested MIME type, Harbor returns `200` with an empty object `{}`. A `404` means the artifact digest does not exist.
- Decided (2026-11-03, delegated): an empty object and a `404` are both retried with backoff (see [backend.md](backend.md)), because the report or a just-pushed artifact may not be visible yet. Neither is an immediate failure.

### Credentials and robot account

- Robot account username: `robot$<name>`. Source: Harbor robot account documentation (https://goharbor.io/docs/latest/administration/robot-accounts/, fetched in this session), "robot$ prefix". Verified (2026-11-03) in `src/controller/robot/controller.go`: a project robot is named `<prefix><project>+<name>`. The prefix is Harbor's configurable robot name prefix, default `robot$`, so operators copy the exact name Harbor shows.
- Robot account expiry: 30 days by default. Source: Harbor robot account documentation (fetched in this session; the default expiry text is confirmed). The system-wide duration is `robot_token_duration` in days (Harbor API swagger). A per-robot `duration` of `-1` means never expires (Harbor API swagger, `RobotCreate.duration`).
- The stored credential has `user_credentials.username` and `user_credentials.expires_at` (see [database.md](database.md)).
- Health: the app warns before `expires_at` (see [frontend.md](frontend.md)). Decided (2026-11-03): the warning window is 14 days before `expires_at`. The window is fixed in v1, not user-set.

### Harbor base URL and transport

- The Harbor base URL is stored per Harbor credential in `user_credentials.base_url`. Each mapping uses its credential's `base_url`. Decided: 2026-11-02.
- Decided (2026-11-03, delegated): the base URL must be `https://`. Plain HTTP is rejected on save.
- Decided (2026-11-03, delegated): the resolved address must not be loopback, link-local, or private, unless `HARBORGATE_ALLOW_PRIVATE_HARBOR=true`. The address check and the blocked ranges are in [security.md](security.md) under "Outbound HTTP (SSRF)".
  - Source: OWASP SSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- Redirects are not followed.
- Harbor API paths are relative to `base_url` and begin with `/api/v2.0/` (Harbor swagger `basePath: /api/v2.0`).

### Test button

- Harbor test: Decided (2026-11-03, delegated): `GET /api/v2.0/users/current` with the robot's basic auth. `412` means the robot credential works. `401` means the secret is wrong, or the robot is disabled or expired. `200` means the credentials belong to a human user, which is rejected, because only robot accounts are accepted.
  - Reason, verified (2026-11-03) in the Harbor source: a wrong, disabled, or expired robot secret does not fail the request. The robot authenticator returns no security context (`src/server/middleware/security/robot.go`), so the request continues as anonymous. A project or artifact call can then succeed on a public project with a wrong secret. `users/current` returns `401` for anonymous callers and `412` for a robot (`src/server/v2.0/handler/user.go`).
  - Repository access is checked when a mapping is saved: `GET /api/v2.0/projects/{project}/repositories/{repository}/artifacts?page_size=1` must return `200`.
  - Verified: Harbor swagger `/users/current` returns 412 for robot accounts ("Returns 412 if the caller is authenticated via a non-local context such as a robot account"). That 412 is what makes it the test.
  - Verified: `GET /api/v2.0/systeminfo` is documented as callable anonymously ("this can be called by anonymous request"), so it cannot prove the robot secret is valid. Not used for the test.
  - The `projects?name=` call is not used: with a wrong secret it runs as anonymous and can still return a public project.

## Polling

- Webhooks are the primary trigger.
- Backup polling runs every 15 minutes across all mapped Harbor projects. The 15-minute interval is a user decision.
- Polling lists artifacts per mapping and uses the digest to decide whether to sync.
- Decided (2026-11-03, user): polling considers only artifacts with at least one tag, and queues one job per (digest, tag) pair. The job payload has the same shape as a webhook job: `{"repo_full_name","digest","tag"}`. Decided (2026-11-03, user, #35): a polling job's payload also has `"trigger": "poll"`. Webhook jobs omit the field, and readers treat a missing `trigger` as `webhook`. The sync handler ignores the field.
- Decided: polling skips an image whose digest already has a successful sync for that mapping and tag. "Successful" means `sync_jobs.status = 'done'` and `sarif_status = 'success'` on the linked report (Decided 2026-11-03 in [database.md](database.md)).
- Source for the artifact list endpoint: Harbor swagger, `GET /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts`, with `page` and `page_size` query parameters. The artifact object includes `digest`, `tags`, `push_time`, and `pull_time` (verified in this session).
- Note: "backup polling" here means Harbor polling. It is not the admin backup command. See [security.md](security.md).

## OCI labels

Read these from the Harbor artifact (`GET .../artifacts/{reference}` or the artifact's config labels):

- Commit SHA: `org.opencontainers.image.revision`. Required. If missing, the sync is marked `failed` with a clear error. Never guess the SHA.
- Repository: `org.opencontainers.image.source`. Decided (2026-11-03): when present, it must match the mapping's GitHub target, `https://github.com/<github_owner>/<github_repo>`, compared case-insensitively and ignoring a trailing `/` or `.git`. On a mismatch the sync is marked `failed` with a clear error and nothing is uploaded. Decided (2026-11-03, delegated): when the label is absent, the sync proceeds.
- Branch: Decided (2026-11-03): from the HarborGate label `io.github.nrosier.harborgate.branch` if present, otherwise the mapping's `default_branch` (default `main`). Decided (2026-11-03, delegated): the label name uses reverse-domain notation under the project's GitHub Pages domain `nrosier.github.io`. The OCI annotation rules say keys SHOULD use reverse domain notation (verified (2026-11-03)). `org.opencontainers.image.ref.name` is not read for the branch, because the OCI image spec defines it as the name of a reference, typically a tag such as `1.2.3`, not a branch.
- Source for the label names: OCI Image Format Specification, annotations (https://github.com/opencontainers/image-spec/blob/main/annotations.md). Verified (2026-11-03): the page defines `org.opencontainers.image.source` (URL to get the source code), `org.opencontainers.image.revision` (source control revision identifier), and `org.opencontainers.image.ref.name` ("Name of the reference for a target").

## SARIF conversion and upload

- Convert the Trivy report to SARIF 2.1.0. Output must conform to the SARIF 2.1.0 schema (OASIS SARIF 2.1.0, https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
- Gzip, then base64-encode the SARIF payload.
- Decided (2026-11-03): the upload's `ref` field is always the fully qualified `refs/heads/<branch>`, built from the branch rule under "OCI labels". Verified (2026-11-03) in GitHub's OpenAPI description (`github/rest-api-description`): `ref` is required and is "The full Git reference, formatted as `refs/heads/<branch name>`" (or a tag or pull request ref).
- Upload with `POST /repos/{owner}/{repo}/code-scanning/sarifs`. The request body fields are `commit_sha`, `ref`, `sarif` (base64 gzip), and optional `checkout_uri`, `started_at`, `tool_name`, `validate`.
  - Source: GitHub REST API, "Code scanning" (https://docs.github.com/en/rest/code-scanning). Verified (2026-11-03) in GitHub's OpenAPI description: `commit_sha`, `ref`, and `sarif` are required; `checkout_uri`, `started_at`, `tool_name`, and `validate` are optional. Responses: `202` (with an `id`), `400`, `403`, `404`, `413`, `503`.
  - Limits, verified in the same description and in GitHub's "SARIF support for code scanning": 20 runs per file; 25,000 results and 25,000 rules per run, of which only the top 5,000 results are kept; 1,000 locations per result; 20 tags per rule; at most 10 MB of gzip-compressed SARIF per upload; 1,000 upload requests per hour per user.
  - Decided (2026-11-03, delegated): after the upload, the worker polls `GET /repos/{owner}/{repo}/code-scanning/sarifs/{id}` until `processing_status` is `complete` or `failed` (verified (2026-11-03): the values are `pending`, `complete`, and `failed`). It records the result in `sync_reports.sarif_status`. A SARIF over 10 MB compressed fails the sync with a clear error, and nothing is uploaded.
  - Decided (2026-11-03, user), processing wait: the worker polls after 5 s and 10 s, then every 15 s, for at most 5 minutes in one attempt. `complete` sets `sarif_status = 'success'`. `failed` sets `sarif_status = 'failed'` and fails the job permanently, with GitHub's `errors` in `error_message` and no retry. Still `pending` after 5 minutes: the report keeps `github_sarif_id` with `sarif_status = 'pending'`, and the attempt fails with 'GitHub processing still pending'. The backoff retry polls the same `github_sarif_id` again instead of uploading a second time.
  - Decided (2026-11-03, user), rate limits: a GitHub `429`, or a `403` with `x-ratelimit-remaining: 0` or a `retry-after` header, defers the job. It is requeued at the time GitHub gives (`retry-after` seconds, or `x-ratelimit-reset`), capped at 1 hour, and `attempts` is not incremented, so rate limits never move a job to `failed`. See [backend.md](backend.md), Durable job queue.
- SARIF category: Decided (2026-11-03, delegated): each SARIF file has one run, with `runAutomationDetails.id` = `harborgate/<harbor_project>/<harbor_repository>/`. Verified (2026-11-03) in GitHub's "SARIF support for code scanning": the `id` is read as `category/run-id`, where the category is everything before the last `/`, and an `id` without a `/` has an empty category. The trailing `/` keeps the whole path as the category, including repository names that contain `/`.
- Converter rules: Decided (2026-11-03, delegated), using the properties GitHub marks as required (verified (2026-11-03), same page):
  - Top level: `$schema`, `version` `2.1.0`, and `runs[]`. The run has `tool.driver.name` `HarborGate` and `tool.driver.rules[]`.
  - Each rule has `id` (the vulnerability id), `shortDescription.text`, `fullDescription.text`, `help.text`, and `properties.security-severity`. Each result has `ruleId`, `message.text`, `locations[]`, and `partialFingerprints`.
  - Location: an image finding has no source file, so `physicalLocation.artifactLocation.uri` is `<harbor_project>/<harbor_repository>`, and the region is line 1, column 1 to 1. That is what Trivy's own SARIF writer does when a package has no file location (verified (2026-11-03), `aquasecurity/trivy`, `pkg/report/sarif.go`).
  - `partialFingerprints`: GitHub requires them, because API uploads without them can create duplicate alerts. The value is `{"harborgate/v1": sha256(<vulnerability id> + "|" + <package>)}`, which stays stable across image rebuilds and tags.
  - `security-severity`: the CVSS v3 score from `preferred_cvss.score_v3` when present, otherwise `9.5` (CRITICAL), `8.0` (HIGH), `5.5` (MEDIUM), `2.0` (LOW), or `0.0` (UNKNOWN). This is Trivy's own fallback (verified (2026-11-03), `severityToScore` in `pkg/report/sarif.go`).
- Validate output against SARIF 2.1.0 (see [testing-and-ci.md](testing-and-ci.md)).

## GitHub issues

- Auto-create issues for CRITICAL and HIGH findings. The `min_issue_severity` setting defaults to CRITICAL and may be lowered to HIGH (user decision).
- Automatic issues: only CRITICAL and HIGH create issues. MEDIUM, LOW, and UNKNOWN never create an issue automatically. Decided (2026-11-05, user, #129): this stays as it is; there is no per-mapping MEDIUM minimum, and `min_issue_severity` still accepts only `CRITICAL` or `HIGH`.
- Manual issue creation is also supported: `POST /api/v1/cves/:id/issue`. See [api.md](api.md). Decided (2026-11-05, user, #129): a manual issue may be logged for a CVE of any severity (CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN). This lifts the #30 HIGH-and-above restriction for manual logging only; automatic creation is unchanged.
- Decided (2026-11-05, user, #129): a manual issue for a CVE whose highest open severity (`open_severity` in [api.md](api.md)) is LOW or UNKNOWN asks the user for confirmation first. CRITICAL and HIGH stay one click. Decided (2026-11-05, delegated, #129): MEDIUM is not named by the user's decision, so it is one click as well; the user may change this when the screen design is approved. The confirmation is a frontend step: the server does not take a confirm flag, because the route is already owner-only and CSRF-protected and the confirmation guards against a mis-click, not an attacker. The server returns `open_severity` so the UI can decide when to ask.
- Decided (2026-11-05, user, #129): one issue per CVE, as before. Manual logging at any severity uses the same marker, label, re-adoption and create lock as automatic creation, so a second click or a concurrent sync never creates a duplicate.
- Every issue carries the HarborGate label and body marker used to re-adopt issues. The rule is in [cve-lifecycle.md](cve-lifecycle.md).
- Issue lifecycle (one open issue per CVE per repo, close, reopen) is defined in [cve-lifecycle.md](cve-lifecycle.md).
- GitHub issues API permission: `Issues: read and write` (see [security.md](security.md)).
- Decided (2026-11-04, user, #30): issue title, `<CVE-ID>: <package> (<SEVERITY>) in <harbor_project>/<harbor_repository>`. The package and severity come from the CVE's rows: the package from the most recently scanned open tag row, the severity the highest across open rows, over all five severities (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN; #129). A row with no package shows `unknown package`.
- Decided (2026-11-04, user, #30): the issue body is the marker line, the table (CVE, severity, package, fixed in, Harbor repository), and a line `Affected tags:` that lists every tag where the CVE is open. The package and fixed-in version come from the most recently scanned open tag row. The severity is the highest across open rows, the same as in the title. A row with no package shows `unknown package`, as in the title. The package is written as inline code, so a name such as `@scope/pkg` cannot @-mention a GitHub user or organisation. Source for the title limit: GitHub rejects a longer title with `title is too long (maximum is 256 characters)`, so the title is cut at 256 characters.
- Decided (2026-11-04, user, #30): the scan named in the close and reopen comments is `<harbor_project>/<harbor_repository>:<tag>` (no digest). The close comment is `No tracked tag reports this CVE since scan <scan>.` and the reopen comment is `CVE is back in scan <scan>`.
- Decided (2026-11-04, user, #30): the manual route follows [api.md](api.md): `:id` is `<mapping_id>:<cve_id>`. It is allowed when the CVE is open on at least one tracked tag of the mapping, ignoring `min_issue_severity` and `auto_create_issues` because the manual action overrides the automatic threshold. Changed (2026-11-05, user, #129): any open severity is allowed; until then only CRITICAL or HIGH was. A CVE that is fixed on every tag is refused with `422`. It returns `409` while an active acceptance exists or an open issue exists, and it reopens a closed issue instead of creating a second one, with the comment `CVE reopened manually from HarborGate.` (Decided 2026-11-04, delegated in review of #106; no external source).
- Brief #30, step 3: `auto_create_issues = false` skips only the creation of new issues. Existing issue rows still close and reopen by the lifecycle rules.
- Decided (2026-11-04, user, #30): a GitHub rate limit while the issues are updated after a scan is logged as fixed text (no secrets) and the sync job still finishes `Done`. The job is not deferred, because the report is already `success` and a retry would upload the SARIF again. The next sync or poll reconciles the issues. A database error during the issue updates is handled the same way. Decided (2026-11-04, review of #106): a `401` or `403` from GitHub stops the run at the first refusal and logs the fixed variant name (`Unauthorized` or `Forbidden`), because every later call would fail the same way. Another GitHub error on one CVE is logged as fixed text and the next CVE continues.
- Decided (2026-11-04, review of #106): one process-wide lock serialises "look for the row, look for a marked issue, create, store the row", so a sync and a manual request (or two manual requests) never create two issues for one CVE. HarborGate is single-instance ([architecture.md](architecture.md)). The store is `INSERT ... ON CONFLICT DO NOTHING`; when another writer stored the row first, its row wins and the request is not an error (the manual route answers `409` with that issue's URL).
- Decided (2026-11-04, review of #106): a CVE id gets an issue only when it is 1 to 128 ASCII letters, digits, `.`, `_`, `-` or `:`, so a Harbor-supplied id cannot break the first-line marker. The manual route's `<mapping_id>:<cve_id>` uses the same rule (no `:` in the mapping id), and anything else is `404` before any database call.

## GitHub target

- A GitHub repository (owner, repo) belongs to exactly one mapping, regardless of branch.
- Decided (2026-11-03): one mapping per GitHub repository. Two mappings for the same repo on different branches are not allowed. A user who needs two branches uses two GitHub repos. Enforced by `UNIQUE (github_owner, github_repo)` in [database.md](database.md).
- The app never moves a target between mappings. See [frontend.md](frontend.md) for the duplicate error.

- Decided (2026-11-03): the sync status definition used by the polling dedupe rule is `sync_jobs.status = 'done'` plus `sarif_status = 'success'`. See [database.md](database.md).
