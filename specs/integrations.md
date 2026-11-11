# Integrations

Purpose: how Dockward discovers images in container registries and pulls them, how the pinned scanners run, and how results go to GitHub (SARIF upload and issues). Harbor is removed in 0.2.0. There is no Harbor webhook, no polling of a Harbor API, no Harbor client, no project webhook and no sync job.

Decisions are marked `Decided (<date>, <who>)`. `Verified (<date>)` marks a claim checked against the cited source on that date. `UNVERIFIED:` marks a claim that only a live system or a later build can check. `OPEN:` marks a question the user has not answered. Route contracts are in [api.md](api.md). The engine design is in [spinoff-local-scan.md](spinoff-local-scan.md) and its binding decisions in [spinoff-decisions.md](spinoff-decisions.md).

## Scope

- Dockward discovers images (a registry tag list), pulls each platform image into a local OCI layout on disk, scans it with a pinned scanner binary run as a child process, converts the result to SARIF 2.1.0, and publishes to GitHub Code Scanning and issues.
- No Docker daemon is used. Dockward reads registries itself.
- Verified (2026-11-11): the source files `harbor_client.rs`, `harbor_webhook.rs`, `poller.rs`, `sync_jobs.rs`, `sync_reports.rs` and `project_webhooks.rs` do not exist in `backend/src`.

## Registry hubs

- A hub is a registry host. Table `hubs` (see [database.md](database.md)): `host` (unique), `kind` (`default` or `custom`), `pull_endpoint` (custom hubs only; `NULL` means the stored host is used).
- Verified (2026-11-11, `backend/src/db/mod.rs`, test `default_hubs_are_seeded`): a fresh install seeds `ghcr.io` and `docker.io`, both `kind = default`, with no pull endpoint.
- Custom hubs are added by an admin. A hub host is checked with the hub grammar (`services/registry/grammar.rs`, `validate_hub_host`), and a repository name is checked with `validate_repository` (at most 255 bytes). A tag is checked with `validate_tag` (at most 128 bytes). A digest is `sha256:` followed by 64 lowercase hex characters (`is_sha256_digest`).
- Source selection: a source is `(hub, repository, tag value)`. The tag value is an exact tag or a glob with `*` and `?` (pattern at most 128 bytes, `services/discovery/glob.rs`). `image_sources` holds the rows; `UNIQUE (hub_id, repository, tag_value)`.
- Each source has at most one registry credential (`source_credentials`, encrypted, see [security.md](security.md)). There is no hub-wide or namespace-wide credential.

### Discovery

- A `discover` job runs once per distinct hub and repository, covering every source on it. Verified (2026-11-11, `services/discovery/schedule.rs`): the schedule runs hourly (`INTERVAL` 3600 s), first run 60 s after start.
- It lists tags with `GET /v2/<repository>/tags/list?n=100`, following the `Link` header (`rel="next"`), at most 100 pages (`MAX_TAG_PAGES`, `services/registry/transport.rs`).
- Each tag matching a source's value is resolved to its manifest digest. The observation is stored in `tag_observations`.
- Caps per run (`services/discovery/mod.rs`): at most 50 new digests recorded (`MAX_NEW_DIGESTS_PER_RUN`) and at most 500 manifest fetches (`MAX_MANIFEST_FETCHES_PER_RUN`). Items beyond a cap are found by the next hourly run, because nothing is recorded for them.

### Pull

- A `pull` job fetches each platform image into an OCI layout under the data directory (`services/storage/pull.rs`). The index is read, the platform manifests are read, and the blobs are written by digest.
- Manifest media types accepted (`services/registry/manifest.rs`): OCI image index, Docker manifest list, OCI image manifest, Docker image manifest. Attestation manifests are recognised by the annotation `vnd.docker.reference.type` with value `attestation-manifest` and are not scanned as platforms.
- Manifest size cap: 4 MiB (`MANIFEST_MAX_BYTES`). Pull size cap and minimum free disk space are operator settings (`services/scan_settings.rs`): the pull cap range is 1 MiB to 1 TiB, the minimum-free range is 0 to 1 TiB. A pull that would break the disk guard does not start.
- Credentials: the source credential is sent as a bearer token obtained from the registry's token service, or as basic auth. The credential is held only in the pull session and zeroized when the session ends (`Credential`, `services/registry/transport.rs`). Its `Debug` output is `Credential(redacted)`. It is never logged.

### Address and transport rules

- HTTPS only. A plain `http://` endpoint is allowed only for a host listed in `DOCKWARD_ALLOW_PRIVATE_REGISTRIES` with the `http://host[:port]` form (`services/registry/policy.rs`).
- The resolved address is checked against the outbound deny-list before connecting, and again for every redirect hop (`AddressPolicy`, `is_blocked`). A host is refused when any resolved address is blocked. Private addresses are allowed only for a host in `DOCKWARD_ALLOW_PRIVATE_REGISTRIES`. The address rules are in [security.md](security.md), "Outbound HTTP (SSRF)".
- Redirects: followed, at most 10 (`MAX_REDIRECTS`), each hop checked.
- Timeouts (`services/registry/transport.rs`): connect 10 s, whole request 300 s. Token lifetime is 60 s by default, capped at 300 s.

### Rate limits

- Verified (2026-11-11, `services/registry/transport.rs`): a registry `429` is retried inside the client at most 2 times (`MAX_429_RETRIES`), and only when the wait is at most 10 s (`MAX_IN_CLIENT_WAIT`). The wait is `Retry-After` in seconds, or 1 s when the header is missing or unusable (an HTTP date counts as unusable).
- A longer wait, or a `429` after the retries, returns `RateLimited` to the caller. The job is deferred by 300 s (`RATE_LIMIT_DEFER_SECS`, `services/discovery/mod.rs`) and does not count as a failed attempt. The fixed text shown for an anonymous Docker Hub refusal is in the same module.
- Dockward never retries a rate-limited request in a loop.

## Scanners (Trivy and Grype)

- Two scanners, fixed keys `trivy` and `grype` (`services/scanner/mod.rs`, `Scanner`).
- Each runs as a child process from a fixed absolute path in the image: `/usr/local/bin/trivy` and `/usr/local/bin/grype`. Verified (2026-11-11).
- Out of process. Dockward never links a scanner library. The scanner's output is read from stdout, bounded by `scanner.output_max_bytes` (default 64 MiB) and killed at `scanner.timeout_s` (default 600 s) (`services/scanner/process.rs`, `services/scan/mod.rs`).

### Pinned binaries

- The Dockerfile copies the scanners from digest-pinned release images, never a floating tag: Trivy from `aquasec/trivy@sha256:8f6bb947...` (`/usr/local/bin/trivy`), Grype from `anchore/grype@sha256:13113eec...` (`/grype`). Both are static, so they run on `scratch`. See [deployment.md](deployment.md).
- Versions. Trivy 0.76.2 is the pinned version in the test fixtures (`backend/tests/fixtures/scanner/`), `services/scanner/parse/tests.rs` and `.github/workflows/security-scan.yml`. Grype 0.121.2 is the version in `services/scanner/db_update/tests.rs`, in the test fixtures and in the CI pin `GRYPE_VERSION` in `security-scan.yml`. Decision 29 verified Grype v0.121.2 at digest `6a36234d...`, which is not the digest the Dockerfile pins. The Dockerfile states no version, so the Grype version of the shipped image is not known from the repository (see the OPEN item below).

### Run arguments

Verified (2026-11-11, `services/scanner/mod.rs`, `scan_args`):

- Trivy: `image --input <layout dir> --format json --skip-db-update --skip-java-db-update`, JSON on stdout.
- Grype: `oci-dir:<layout dir> -o json`, JSON on stdout.

### Environment

Only an allow-list of variables is passed (`environment`, `services/scanner/mod.rs`). No secret is ever added, and `DOCKWARD_ENCRYPTION_KEY` and the old key are never read.

- Both: `HOME` = the scanner cache root, `LC_ALL=C.UTF-8`.
- Trivy: `TRIVY_CACHE_DIR` = the scanner's cache directory, `TRIVY_DISABLE_TELEMETRY=true`, `TRIVY_SKIP_VERSION_CHECK=true`.
- Grype: `GRYPE_DB_CACHE_DIR` = the scanner's cache directory, `GRYPE_CHECK_FOR_APP_UPDATE=false`. On a scan run, `GRYPE_DB_AUTO_UPDATE=false`, so a scan never downloads a database.

### Cache location

- The scanner cache root is `<data dir>/scanner-cache` (`services/scan/mod.rs`). Each scanner's database is under `<cache root>/<scanner key>`.
- `HOME` is set to the cache root so a scanner never writes into the container's home directory, which does not exist on `scratch`.

### Database update

- A `db_update` job runs per scanner on a 24-hour schedule, first run 120 s after start (`services/scanner/db_update.rs`, `INTERVAL` 86400 s). It is recorded in `job_runs` with `job_kind = 'db_update'`.
- Update commands (`update_args`): Trivy `image --download-db-only` and `image --download-java-db-only`; Grype `db update`. Both print nothing that is stored.
- The update is the only job that reaches the network for a scanner, and it reaches only the scanner's database location.
- Build time: read from the database metadata (Trivy `db/metadata.json`, Grype `db status -o json`). Source: [spinoff-local-scan.md](spinoff-local-scan.md), section 8.
- A failed update keeps the old database in use and fails the `db_update` job under the existing retry rules. A scan never starts without a database.
- UNVERIFIED: whether a scan that runs against a database older than the update window is acceptable. The spinoff does not set a limit.

## Scan and publish

- A `scan` job scans one stored platform image with each enabled scanner, and writes one `scan_runs` row per (platform image, scanner) with its state (`scanner_findings` holds the findings). Only `done` runs count for results.
- A `publish` job converts the merged result to SARIF, uploads it to GitHub, and updates the issues. See "GitHub SARIF upload" and "GitHub issues" below, and [cve-lifecycle.md](cve-lifecycle.md).
- Job kinds (`services/jobs.rs`, `JOB_KINDS`): `discover`, `pull`, `scan`, `publish`, `db_update`. `job_runs` also records `cleanup` and `retention` (`services/job_runs.rs`).
- Retry and backoff: [backend.md](backend.md), "Durable job queue".

## OCI labels

Read from the image config of the scanned platform image (`extra_attrs`-style config labels in the stored OCI config blob; the label names are in `services/publish/labels.rs`).

- Commit SHA: `org.opencontainers.image.revision`. Required. If missing, the publish job fails with a clear error. Never guess the SHA. Verified (2026-11-11, `LABEL_REVISION`).
- Repository: `org.opencontainers.image.source`. When present, it must match the source's GitHub target, `<github web URL>/<owner>/<repo>`, compared case-insensitively and ignoring a trailing `/` or `.git`. A mismatch fails the publish job with a clear error and uploads nothing. When absent, the publish proceeds (Decided 2026-11-03, delegated; kept).
- Branch: the label `io.github.nrosier.harborgate.branch` (`LABEL_BRANCH`) if present, otherwise the source's `default_branch` (default `main`). Verified (2026-11-11). `OPEN:` the label name still uses the old project name. Renaming it changes which images are read, so it needs the user's decision. The OCI annotation rule for keys (reverse domain) is met by the name as built.
- `org.opencontainers.image.ref.name` is not read for the branch. The OCI spec defines it as the name of a reference, typically a tag.

## GitHub base URL

- Decided (2026-11-06, user, #184): the GitHub API base URL and the GitHub web URL are instance settings, set by the admin. One pair for the whole instance.
- Empty means the default: `https://api.github.com` for the API and `https://github.com` for the web URL (`services/github_url.rs`, `DEFAULT_API`, `DEFAULT_WEB`). Verified (2026-11-11).
- Stored in `system_config` under the keys `github.api_base_url` and `github.web_url`. Not secret.
- A custom API base URL must be `https` with a host and may include a path. A custom web URL must be `https` with a host only. Any other value is rejected with the fixed validation message `settings.github_url_invalid`. Rules: [security.md](security.md), "GitHub base URL".
- Every GitHub request in this file uses the configured API base URL.

## GitHub SARIF upload

- The converter writes SARIF 2.1.0. The output must conform to the SARIF 2.1.0 schema. Validated per [testing-and-ci.md](testing-and-ci.md).
- Gzip, then base64-encode the SARIF payload (`encode_sarif`, `services/github_scanning.rs`).
- Upload: `POST /repos/{owner}/{repo}/code-scanning/sarifs`. Body fields: `commit_sha`, `ref`, `sarif` (base64 gzip), and optional `checkout_uri`, `started_at`, `tool_name`, `validate`. Responses `202` (with `id`), `400`, `403`, `404`, `413`, `503`. Source: GitHub REST API, Code scanning (verified 2026-11-03 in GitHub's OpenAPI description).
- `ref` is always `refs/heads/<branch>` (the branch rule above). Required by GitHub.
- Limits: 10 MB of gzip-compressed SARIF per upload (`MAX_COMPRESSED_BYTES`, verified in code). Larger fails the publish job with a clear error and uploads nothing. Other GitHub limits (20 runs per file, 25,000 results and rules per run, 1,000 upload requests per hour per user) are as documented by GitHub (verified 2026-11-03).
- Processing status: after the upload, poll `GET /repos/{owner}/{repo}/code-scanning/sarifs/{id}` until `processing_status` is `complete` or `failed` (values `pending`, `complete`, `failed`). The status is stored in `publish_reports`.
  - Decided (2026-11-03, user): the poll runs after 5 s and 10 s, then every 15 s, for at most 5 minutes in one attempt. `complete` is success. `failed` fails the job permanently with GitHub's `errors` in `error_message` and no retry. Still `pending` after 5 minutes keeps the `github_sarif_id` and fails the attempt. The retry polls the same id and does not upload again.
- Rate limits: a GitHub `429`, or a `403` with `x-ratelimit-remaining: 0` or a `retry-after` header, defers the job. It is requeued at the time GitHub gives (`retry-after` seconds, or `x-ratelimit-reset`), capped at 1 hour, and `attempts` is not incremented (Decided 2026-11-03, user). When neither is present, the default wait is 60 s (`DEFAULT_WAIT_SECS`, verified in code). `OPEN:` whether the 60 s default must match the 5-minute defer used for registries.

### SARIF document

- Verified (2026-11-11, `services/sarif.rs`): the tool driver name is `HarborGate`. `OPEN:` the driver name still uses the old project name. The user decides whether the rename is in 0.2.0.
- Run `automationDetails.id` is `harborgate/<hub host>/<repository>/<tag value>/` (`automation_id`). The trailing `/` keeps the whole path as the Code Scanning category (see below).
- Rule and result fields: each rule has `id`, `shortDescription.text`, `fullDescription.text`, `help.text`, and `properties.security-severity`. Each result has `ruleId`, `message.text`, `locations[]`, and `partialFingerprints`.
- `partialFingerprints["harborgate/v1"]` = SHA-256 of `<vulnerability id>|<package>` (`FINGERPRINT_KEY`). Stable across rebuilds and tags.
- Location: an image finding has no source file. `artifactLocation.uri` is `<hub host>/<repository>`, and the region is line 1, column 1 to 1.
- `security-severity`: the CVSS v3 score when present, otherwise `9.5` (CRITICAL), `8.0` (HIGH), `5.5` (MEDIUM), `2.0` (LOW), or `0.0` (UNKNOWN). This is Trivy's own fallback (verified 2026-11-03).
- One result per (CVE id, package), from the merged view ([cve-lifecycle.md](cve-lifecycle.md), "Merged view"), never one per scanner.
- Result property bag (verified 2026-11-11): `harborgate/scannerCount` (integer, at least 1), `harborgate/scannerNames` (unique names, merged-view order), and `harborgate/platforms` (`PLATFORMS_KEY`). The bag is an object, which the schema allows.
- Category: one Code Scanning category per source. The category is `harborgate/<hub host>/<repository>/<tag value>` (decision 46 of the spinoff; `automation_id`). Each source's alerts stay separate. Verified (2026-11-03) in GitHub's SARIF documentation: the category is everything before the last `/` of the run id, and the trailing `/` keeps the whole path.

## GitHub issues

- Auto-create issues for CRITICAL and HIGH findings. `min_issue_severity` is per source, default `CRITICAL`, may be lowered to `HIGH`, and accepts no other value (`image_sources`, verified in migration 0001).
- Automatic issues: only CRITICAL and HIGH. MEDIUM, LOW and UNKNOWN never create an issue automatically (Decided 2026-11-05, user, #129).
- Manual issue creation: `POST /api/v1/cves/:id/issue` ([api.md](api.md)). Any severity is allowed for a manual issue. A manual issue for a CVE whose highest open severity is LOW or UNKNOWN asks the user for confirmation in the UI first; the server does not take a confirm flag (Decided 2026-11-05, user, #129).
- One issue per CVE per GitHub repository. Manual and automatic creation share the marker, the labels, the re-adoption rule and one process-wide create lock (`services/issue_lifecycle.rs`). A second click or a concurrent publish never creates a duplicate.
- Labels: every issue carries `harborgate` (`LABEL`, verified) and `areai:security` (`SECURITY_LABEL`). The severity label is plain and lowercase: `critical`, `high`, `medium` or `low` (`severity_label`). A CVE whose severity is `UNKNOWN` gets no severity label. The labels are created in the repository when missing, and an existing label is not duplicated (Decided 2026-11-06, user, #192).
- Title: `<CVE id> <package>`, cut at 256 characters, because GitHub rejects longer titles (verified 2026-11-04). The package is the most recent open row's package; a row with no package shows `unknown package`.
- Body: the first line is the hidden marker `<!-- harborgate:<CVE id> -->`. Then a table (CVE, severity, package, fixed in, source), then `Found by N scanner(s): names` (names as inline code; `Found by 1 scanner: \`Trivy\``), then `Affected tags:` listing every tracked tag that still reports the CVE (Decided 2026-11-07, user, #196 and #224 d2). The package is inline code, so `@scope/pkg` cannot mention a user.
- Re-adoption: before creating an issue for a CVE with no `github_issues` row, the publish job lists open issues with the `harborgate` label (all pages, not the search API) and adopts one whose first line is the marker for that CVE. Closed issues are not adopted. An adopted issue whose title differs is renamed to the title above (Decided 2026-11-06, user, #192).
- CVE id rule: an id gets an issue only when it is 1 to 128 ASCII letters, digits, `.`, `_`, `-` or `:` (Decided 2026-11-04, review of #106). Anything else is refused, so an upstream id cannot break the marker.
- Errors: a GitHub `401` or `403` stops the run at the first refusal and logs the fixed variant name. Another GitHub error on one CVE is logged as fixed text and the next CVE continues. A rate limit during issue updates is logged as fixed text and the publish job still finishes (Decided 2026-11-04, user, #30). No upstream body reaches the log.
- Issue permission: `Issues: read and write` ([security.md](security.md), GitHub token scope).
- Issue closing, reopening and the comment texts are in [cve-lifecycle.md](cve-lifecycle.md), "GitHub issue rules". Verified (2026-11-11): the close comment is `No scanner reports this CVE since scan <scan>.`, the reopen comment is `CVE is back in scan <scan>, found by <names>.`, and the manual reopen comment is `CVE reopened manually from Dockward.`. The scan is named `<hub host>/<repository>:<tag>`.
- Hub-and-repository naming in comments and bodies is the same as the SARIF one.

## GitHub target

- One GitHub repository (owner, repo) may be the target of several sources, each for a different hub repository, regardless of branch (Decided 2026-11-06, user, #185). Each source's Code Scanning category is its own. Issues are shared per GitHub repository and CVE.
- The app never moves a target between sources.
- GitHub name check: `owner` is 1 to 39 ASCII letters, digits or `-`; `repo` is 1 to 100 ASCII letters, digits, `.`, `_` or `-`, and is not `.` or `..` (Decided 2026-11-05, delegated, #126).

## GitHub token and listing

- The GitHub credential is an encrypted `user_credentials` row (GitHub only). Token scope is in [security.md](security.md), "GitHub token scope".
- Source pickers and their routes are in [api.md](api.md). Lists are live per credential, names only, with a 5-minute in-memory cache, and never stored (Decided 2026-11-05, user, #126). Tokens never reach the browser.

## Secrets and logs

- Hub credentials, GitHub tokens, encryption keys, webhook URLs and alert headers are never logged, printed, traced, or sent over Server-Sent Events. Error bodies from registries, scanners and GitHub are never copied; only fixed strings are stored or shown. The full rule is in [security.md](security.md), "Secrets in logs".
- Scanner names, versions, CVE ids, package names and report contents are not secrets and may appear in the UI, the SARIF and the issue body.

## OPEN

- OPEN: the Grype version of the shipped image. The Dockerfile pins `anchore/grype@sha256:13113eec...` with no version comment. Decision 29 verified v0.121.2 at digest `6a36234d...`, and CI pins v0.121.2. The repository does not show which version `13113eec...` is. Decide whether to pin the verified digest, or record the version the digest is confirmed to be.
- OPEN: names still using the old project name. The driver name `HarborGate` (`services/sarif.rs`), the issue label and marker `harborgate`, the branch label `io.github.nrosier.harborgate.branch`, and the SARIF keys `harborgate/...`. Renaming changes what GitHub shows and how old issues are re-adopted, so the user decides.
- OPEN: the alert payload key `mapping.harbor` (see [alerts.md](alerts.md)). It holds a hub and repository, not a Harbor value.
- OPEN: the Rust config reads `DOCKWARD_ALLOW_PRIVATE_HARBOR` (`backend/src/config.rs`) but no service uses it (verified by search of `backend/src`). Remove or keep.
- UNVERIFIED: a live pull from `ghcr.io` and `docker.io` with a real credential, the anonymous Docker Hub rate-limit answer, and whether `docker.io` returns a `Retry-After` header on `429`. Only a live run can check these.
- UNVERIFIED: whether Trivy and Grype report the same `package` string for the same CVE (exact-match merge key). Answer by a live comparison.
