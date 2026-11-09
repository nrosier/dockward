# Spinoff: local image scanner (working name `localscan`, provisional)

Purpose: the build specification for a spinoff of HarborGate that drops Harbor entirely. The spinoff pulls container images from OCI registries ("hubs"), scans them locally with Grype and Trivy, and keeps the SARIF and GitHub output. The product name is not decided. `localscan` (provisional) is a working name used only inside this spec; it is not a package, crate, image, label or category name, and it must not be written into code, configuration or user-visible text until the user decides the name.

Branch: `spinoff-local-scan`. This branch must never be merged into `main`. Every spec file on this branch other than this one still describes HarborGate with Harbor; this file overrides them on this branch. Where this file and another spec file disagree, this file wins, and the table in section 1 names what it replaces. When the name is decided, this file is renamed and the identifiers listed in OPEN question 11 are changed together.

Decision marks follow [README.md](README.md). Every decision below dated 2026-11-09 comes from the user's spinoff decisions 1 to 9 (dialogue, 2026-11-09), recorded here as `spinoff decision N`:

1. The spinoff lives in this repository on the branch `spinoff-local-scan`, not on `main`.
2. Harbor is removed entirely. The user enters where an image is: a registry host, a repository, and a tag or tag pattern.
3. Several registries (hubs) are configurable. `ghcr.io` and `hub.docker.com` are included by default; custom registries can be added.
4. Credentials for each hub are stored encrypted per hub, with the same key scheme HarborGate uses today. Public images need no credential.
5. The tool pulls each tag the user defines and scans it locally with the included scanners, Grype and Trivy by default. Images are stored locally.
6. The user sets a maximum number of stored images. When it is exceeded, the oldest image is removed.
7. The user enters an exact tag or a pattern (for example `1.2.*`). Each matching tag is pulled and scanned once.
8. Output: keep the SARIF and GitHub output. SARIF is still uploaded to Code Scanning and GitHub issues are still opened, which needs GitHub credentials.
9. The name is not decided. Use `localscan` only inside the spec, marked provisional.

Anything this file adds beyond those nine decisions is marked `Decided (2026-11-09, spec author, spinoff)` with its reason, or `PROPOSED:` when it needs the user's approval, or is an OPEN question in section 9. Nothing in section 9 is decided.

## 1. Scope: what is removed, superseded and kept

### Removed (Harbor)

Decided (2026-11-09, user, dialogue, spinoff decision 2): there is no Harbor client, no Harbor webhook receiver, no Harbor poll, no project scanner call, no scheduled Harbor scan and no Harbor robot permission. Nothing in the spinoff contacts a Harbor instance, and the words Harbor, robot account, project webhook and `SCANNING_COMPLETED` do not appear in code, API, database or UI.

| Spec file | Section | Fate in the spinoff |
| --- | --- | --- |
| [architecture.md](architecture.md) | Overview, Components, Data flow steps 1 to 3 | Superseded by section 3 below. Steps 4 to 7 (convert, upload, issues, alerts) are kept, fed from local scan results. |
| [integrations.md](integrations.md) | Harbor webhook (all subsections: project webhook, payload format, auth header, URL token, responses) | Removed. |
| | Harbor API (vulnerability report endpoint, credentials and robot account, base URL and transport, test button) | Removed. The GitHub test button is kept ([api.md](api.md), Credentials). |
| | Polling | Removed. Replaced by tag discovery, section 5. |
| | Scheduled scan | Removed. No rescans in v1 (OPEN question 6). |
| | Scanner reports and scan launch (all, including the project lock, switch and restore, and "Grype report reader" for the Harbor adapter) | Removed. Replaced by section 3. The Harbor adapter's report shape no longer applies. |
| | OCI labels | Kept, reworded: labels are read from the locally pulled image config (section 3). |
| | SARIF conversion and upload | Kept, reworded (section 3). |
| | GitHub base URL, GitHub issues, GitHub target | Kept, reworded to images (section 3). |
| | Mapping pickers | Removed, except the GitHub repository list (`GET /user/repos`, search, 5-minute cache). Hide and restore is removed with `picker_hidden_items`. Decided (2026-11-09, spec author, spinoff): the GitHub list is kept because the source form still needs a GitHub target; the Harbor lists and the source suggestion have nothing to read. |
| [database.md](database.md) | `repo_mappings`, `project_webhooks`, `project_webhook_unmatched`, `picker_hidden_items`, `harbor_scanners`, `scanner_reports`, `project_scanner_locks`, `sync_reports` columns | Removed or replaced; see section 6. |
| | Decisions on migrations 0006, 0008, 0009, #185, #132, #249 | Removed (Harbor specific). The new schema is one fresh `0001` (section 6). |
| | Audit vocabulary: `mapping.*`, `project_webhook.*`, `mapping.scan`, `mapping.pull`, `artifact.remove`, `mapping.webhook_token_rotate`, `mapping.auth_secret_rotate` | Removed; replacements in section 6. |
| [backend.md](backend.md) | `webhooks.rs`, the Harbor polling task, resolve jobs, scan jobs (#191), `scanner_scan`, `scanner_restore`, the per-project scanner lock, Harbor rate-limit deferral | Removed. |
| [security.md](security.md) | Hardening: webhook rate limits and the 64 KiB webhook body cap; the manual pull limit (#131) | Removed. |
| | Tenancy: the manual-pull and tag-scan exceptions (#131, #224) | Replaced by section 8. |
| | Secrets in logs: the Harbor scanner paragraph | Removed. |
| | Outbound HTTP (SSRF): the Harbor base URL rules and `HARBORGATE_ALLOW_PRIVATE_HARBOR` | Replaced by the registry rules in section 2. |
| [cve-lifecycle.md](cve-lifecycle.md) | "Tracking per tag" (Harbor tag, digest, push time, last 10 tags), "Merged view" scanner identity by Harbor UUID, issue rules built on Harbor digests, Retention for `sync_reports` | Reworded; the table in section 6 gives the new wording. |
| [alerts.md](alerts.md) | Trigger "A sync fails" wording and the webhook payload field `mapping.harbor` | Reworded (section 8). |
| [api.md](api.md) | Mappings, Scanners and tag scans, Project webhooks, Pickers (Harbor routes), Webhook, the Harbor part of Health, Credentials `service_type=harbor` | Removed or replaced by section 7. |
| [frontend.md](frontend.md) | Mapping form, Tag scans on the mapping page, Project webhook proposal, pickers, the Harbor parts of Admin Health | Removed or replaced by section 7. |
| [deployment.md](deployment.md) | "the app spawns no processes", the `scratch` base image reasoning, `HARBORGATE_ALLOW_PRIVATE_HARBOR` | Superseded by section 3 and OPEN question 7. |
| `docs/SETUP.md` | Harbor, robot and webhook setup | Becomes stale on this branch. Not changed by this spec. |

### Kept unchanged

Decided (2026-11-09, user, dialogue, spinoff decisions 4 and 8): these rules carry over as written in their own files.

- Encryption and keys: `HARBORGATE_ENCRYPTION_KEY` format, AES-256-GCM, the `v1:` ciphertext format, the AAD rule `<table>:<column>:<row id>`, the HKDF labels (`harborgate/credentials-v1`, `harborgate/session-v1`, `harborgate/backup-v1`, `harborgate/csrf-v1`), key rotation by CLI, `zeroize` ([security.md](security.md), Encryption and keys).
- Backup and restore ([security.md](security.md)), with the schema check in section 6.
- Authentication, first-run setup, OIDC, roles, sessions, CSRF, login CSRF, security headers, client IP, login rate limit, `Cache-Control: no-store`.
- Secrets in logs, the application log, audit rules.
- SARIF 2.1.0 conversion and upload, the GitHub base URL setting, the GitHub token scope, GitHub issues (marker, labels, title, adoption, manual route, create lock), acceptance, dashboard counts, the alert channels.
- The durable job queue: `sync_jobs` rows, the three outcomes (success, failure, deferred), retry constants (30 s doubling, 8 attempts), restart recovery, manual retry, purge of failed jobs ([backend.md](backend.md)).
- Timestamps as `INTEGER` Unix seconds, `CHECK` constraints on enumerated columns, `PRAGMA foreign_keys = ON`.

The names `HARBORGATE_*`, the `__Host-harborgate_*` cookies, `harborgate/*` HKDF labels and the crate name `harborgate` are kept for now and are provisional with the product name (OPEN question 11). Decided (2026-11-09, spec author, spinoff): the HKDF labels in particular are not changed when the name changes unless the user says so, because spinoff decision 4 says "the same key scheme".

## 2. Hubs

### Configuration

- A hub is an OCI registry the instance can pull from. It has a canonical host (lowercase DNS name, optional `:port`, no scheme, no userinfo, no path), a display name, and a kind: `default` or `custom`.
- Decided (2026-11-09, user, dialogue, spinoff decision 3): the default set is `ghcr.io` and Docker Hub. Both exist after a fresh install, inserted by the `0001` migration. The host string stored for Docker Hub is OPEN question 1, because the user named `hub.docker.com` and the Docker documentation uses `registry-1.docker.io` for pulls.
- Decided (2026-11-09, user, dialogue, spinoff decision 3): custom hubs can be added and removed. Decided (2026-11-09, spec author, spinoff): adding and removing a hub is admin only, because a hub is an outbound destination for the whole instance and the SSRF rules treat an entered host as a risk (section 8). Removing a hub that an image source uses returns `409 conflict`. PROPOSED: default hubs cannot be removed (OPEN question 9).
- Transport: HTTPS only. Decided (2026-11-09, spec author, spinoff): this is the existing rule in [security.md](security.md), "Outbound HTTP (SSRF)", applied to registries. A plain-HTTP or private-address registry is OPEN question 8.
- A hub has no credential of its own. Credentials are per user and per hub (below).

### Authentication of a pull

- Decided (2026-11-09, user, dialogue, spinoff decision 4): a credential is stored per hub, encrypted with the existing scheme. A public image needs no credential, and the pull is anonymous.
- Decided (2026-11-09, spec author, spinoff): a credential belongs to one user and one hub (`hub_credentials`, section 6) and is used only for that user's image sources. Reason: existing tenancy ([security.md](security.md), Tenancy) says a user sees only their own credentials, and a shared instance credential would let one tenant pull another tenant's private images. Whether hubs and credentials should instead be instance-wide is OPEN question 3.
- A credential is a username and a token (a password or access token). The token is encrypted as a `v1:` ciphertext with AAD `hub_credentials:encrypted_token:<id>`. It is never returned by the API after save, never logged, and never sent to a scanner.
- The client requests only the `pull` action for the repository. Verified (2026-11-09) in the Docker registry token documentation (`distribution/distribution`, `docs/content/spec/auth/token.md`): the registry answers `401` with `Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:<name>:pull,push"`, and the client gets a token from the realm with Basic credentials. The scope for a scan-only client is `repository:<name>:pull`.
- Credential kinds per default hub:
  - `ghcr.io`: Verified (2026-11-09) in GitHub's Container registry documentation: "GitHub Packages only supports authentication using a personal access token (classic)", and `read:packages` is the scope that reads packages. So a pull credential for `ghcr.io` is a classic token with `read:packages`. This is a different token from the fine-grained GitHub token HarborGate uses for Code Scanning ([security.md](security.md), GitHub token scope), which is fine-grained only. The operator needs both when the images are private.
  - Docker Hub: a username and an access token. UNVERIFIED: the exact scopes Docker Hub access tokens offer. Source not read this session.
- Test button: `POST /api/v1/hubs/:id/credential/test` fetches `GET /v2/` and a token for a repository the caller names, and reports `ok`, never the token. Rate limited (section 7).

### Pull method

- Decided (2026-11-09, user, dialogue, spinoff decision 5, with the library below decided by the spec author): the OCI Distribution API over HTTPS. Endpoints used, from the OCI Distribution Specification (`opencontainers/distribution-spec`, `spec.md`, read 2026-11-09): `GET /v2/<name>/tags/list` with `n` and `last` for paging, `GET /v2/<name>/manifests/<reference>`, and `GET /v2/<name>/blobs/<digest>`.
- Verified (2026-11-09) in the same spec: a tag matches `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` (at most 128 characters), a repository name matches `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*`, registries MAY redirect any request, and clients SHOULD follow redirects but MUST NOT forward `Authorization` headers across host boundaries unless explicitly configured. A `Link` header MAY be sent when more tags exist.
- Library: `oci-client`, version 0.18.0. Verified (2026-11-09):
  - Source: `https://github.com/oras-project/rust-oci-client`, crate `oci-client` on crates.io, Apache-2.0.
  - Maintained: yes by these signs only. The 0.18.0 release is dated 2026-09-18 on crates.io (GitHub release 2026-09-28), the repository is not archived and its last push was 2026-11-06, its `Cargo.toml` declares `maintenance = { status = "actively-developed" }`, and releases came in 2024-10, 2025-05, 2026-01, 2026-03, 2026-05 and 2026-09. It has about 10.5 million downloads. "Maintained" here is an observation of activity on 2026-11-09, not a guarantee.
  - Fit: it depends on `reqwest ^0.13` with `rustls` (the backend already uses `reqwest 0.13` with `rustls`, `backend/Cargo.toml`). Methods: `list_tags(image, auth, n, last)`, `pull_image_manifest`, `pull_manifest_and_config`, `pull_blob`, `pull_blob_stream`. Auth type `RegistryAuth` is `Anonymous`, `Basic(user, password)` or `Bearer(token)`. `ClientConfig` has `protocol`, `accept_invalid_certificates`, `platform_resolver`, proxy, timeouts and `max_concurrent_download` (default 16).
  - Gaps against HarborGate's rules, from `src/client.rs` at tag v0.18.0 (a search for `redirect` and `dns` found no match): the client builds its own private `reqwest::Client` from `ClientConfig`, so the backend cannot supply its own redirect policy or DNS resolver. reqwest's default policy then follows up to 10 redirects (`Policy::limited(10)`, reqwest `src/redirect.rs`), and reqwest strips `Authorization` on a cross-host redirect (`remove_sensitive_headers`). So the "no redirects" and "check every resolved address, again on DNS change" rules of [security.md](security.md) cannot be enforced through `oci-client` as it is. This is a `CONFLICT:` recorded in OPEN question 2, because registries legitimately redirect blob downloads to another host and the existing rule forbids all redirects.
  - UNVERIFIED: whether `oci-client` performs the Docker token flow itself from `RegistryAuth::Basic`. A search for `www-authenticate` in `client.rs` found nothing; the code may be in `token_cache.rs`. Check at implementation.
  - UNVERIFIED: how `Reference` maps the host `docker.io` to the registry that is called (`oci-spec` `Reference::resolve_registry` exists; its mapping table was not read).
- No other registry library is named. Hand-written client on `reqwest` is the alternative in OPEN question 2.

## 3. Scan flow

Decided (2026-11-09, user, dialogue, spinoff decisions 5 and 8): pull, scan locally, convert, then upload and open issues as today.

1. **Discover** (section 5): list the source's tags, match the pattern, record each new tag once, queue a pull job per new tag.
2. **Pull**: resolve the tag to a manifest, choose a platform if it is an index (OPEN question 4), check the size bound (OPEN question 5), download the manifest, config and layer blobs into a temporary directory under the store, verify each blob's digest, then write them as an OCI image layout (`oci-layout`, `index.json`, `blobs/sha256/...`) and move the directory into place atomically. Only then is the image `stored`. A failed pull deletes the temporary directory.
3. **Evict** (section 4), in the same step as the commit that marks the image `stored`.
4. **Scan**: one `scan` job per enabled scanner, run one at a time (the single worker). Each scan runs a scanner binary on the stored directory and writes JSON to a file.
5. **Convert**: parse the JSON into `scanner_findings` rows (replacing the scanner's earlier rows for that image) and recompute the merged `cve_findings` for the tag in the same transaction, as in [cve-lifecycle.md](cve-lifecycle.md), "Merged view".
6. **Publish**: when every enabled scanner's run for the image has ended, one `publish` job reads the labels from the stored image config, builds the merged SARIF, uploads it, and runs the issue rules, exactly as the existing sync does after the report is stored. Decided (2026-11-09, spec author, spinoff): a scanner whose run failed after all attempts does not hold the SARIF back, and, by the existing rule ([cve-lifecycle.md](cve-lifecycle.md), "GitHub issue rules", #224 d14), it holds issue closing open. Reason: a partial result must never close an issue.

### Scanners

- Decided (2026-11-09, user, dialogue, spinoff decision 5): the included scanners are Grype and Trivy. Both are enabled by default. Which scanners are enabled is the system setting `scanners.enabled` (a list of `grype` and `trivy`, at least one). Whether more scanners can be added is OPEN question 10.
- Decided (2026-11-09, spec author, spinoff): scanners run **inside the same container** as pinned binaries, spawned by the backend. Reason: CLAUDE.md says the product ships as a single Docker container, and a sidecar would need a socket or shared volume, a second image to sign, and an inter-container protocol with no secrets rule. This replaces the sentence "the app spawns no processes" and the scratch-image reasoning in [deployment.md](deployment.md). Whether the base image can stay `scratch` is OPEN question 7.
- Version pinning: Decided (2026-11-09, spec author, spinoff) the binaries are installed in the Docker build from the official release at a pinned version and a pinned SHA-256 of the release archive, with a Renovate comment on the version line, the same mechanism as [testing-and-ci.md](testing-and-ci.md), "Pinning (d3) and updates". The pins already in that file are Grype `v0.121.2` and Trivy `v0.76.2`. Verified (2026-11-09) with the GitHub API: the latest releases are Grype `v0.121.3` (2026-11-09) and Trivy `v0.76.2` (2026-11-05); neither repository is archived. The implementation checks again and pins the newest, then records the SHA-256. The version in use is stored with every scan run.
- Decided (2026-11-09, spec author, spinoff): the readers are strict about shape. Trivy: `SchemaVersion` must be `2` (Verified 2026-11-09 in the Trivy reporting documentation, whose JSON example has `"SchemaVersion": 2`). Any other value fails the run with the fixed error `scanner output not recognised`. Grype: the report must be a JSON object with a `matches` array.

### Command line

- Output format: JSON for both, written to a file. Verified (2026-11-09): Grype's output formats include `json`, `sarif`, `table`, `cyclonedx` (`internal/format/format.go`); Trivy supports `--format json` and `--format sarif` with `--output <file>` (Trivy reporting documentation). Decided (2026-11-09, spec author, spinoff): JSON, not each scanner's own SARIF, because the merged view needs the fields per finding and one SARIF run per image must come from the merged list ([integrations.md](integrations.md), "SARIF conversion and upload", #224 d2, d6).
- Input: the stored OCI layout directory.
  - Trivy: Verified (2026-11-09) that Trivy supports directories compliant with the OCI Image Layout Specification, and `--input` takes an image archive. UNVERIFIED: whether `trivy image --input <layout directory>` is the exact call for a directory.
  - Grype: Verified (2026-11-09) in `anchore/stereoscope` `pkg/image/source.go` that the image sources include `oci-dir`, `oci-archive`, `docker-archive` and `oci-registry`. UNVERIFIED: the exact command-line spelling `oci-dir:<path>`.
- Offline scan: the scan step must not download anything. Trivy: `--skip-db-update`, `--skip-java-db-update`, `--skip-check-update` and `--offline-scan` exist (Trivy `db.md` and `air-gap.md`, read 2026-11-09). Grype: the database options include `auto-update` and `cache-dir` (`cmd/grype/cli/options/database.go`); UNVERIFIED: the environment variable or flag name that sets them. UNVERIFIED: how to disable Trivy's usage telemetry (the air-gap page says Trivy collects it).
- Vulnerability databases: a `db_update` job (no source) refreshes them into `HARBORGATE_DATA_DIR/scanner-cache`, outside the scan step. Verified (2026-11-09): Trivy publishes its database at `ghcr.io/aquasecurity/trivy-db` and mirrors at `mirror.gcr.io/aquasec`, and `--db-repository` can point elsewhere. The update command names and the Grype update URL are UNVERIFIED. How often the update runs is OPEN question 6. The database build time is stored with each scan run.
- Exit status handling is UNVERIFIED for both (whether a non-zero exit with a valid report is possible without `--fail-on` or `--exit-code`). Until checked, any non-zero exit is a failed scan with the fixed error `scanner failed`.

### Field mapping

- Common stored finding: CVE or advisory id, package, installed version, fixed-in version, severity (five values), CVSS v3 score, description (at most 4,000 characters), as `scanner_findings` ([database.md](database.md), `scanner_findings`, kept).
- Grype JSON. Verified (2026-11-09) in `grype/presenter/models`: each match has `vulnerability` (with `id`, `severity`, `description`, `cvss`), `relatedVulnerabilities`, `matchDetails`, and `artifact` (the package). UNVERIFIED: the exact field names for the package name, version and fixed version inside `artifact` and `vulnerability.fix`; the Harbor adapter's mapping in [integrations.md](integrations.md) ("Grype report reader") read the same fields from Grype's model and is the starting point, not a source for the native shape.
- Trivy JSON. UNVERIFIED in this session: `Results[].Vulnerabilities[]` with `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`, `Description`, `CVSS`. Capture a real report as the test fixture.
- Severity: compared case-insensitively and stored upper-case as `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`. `Negligible` maps to `LOW` and anything else to `UNKNOWN`, as already decided ([cve-lifecycle.md](cve-lifecycle.md), severity values; Decided 2026-11-07, user, #224 d19). Grype's native severity names are UNVERIFIED.
- Merge key and merged fields: unchanged ([cve-lifecycle.md](cve-lifecycle.md), "Merged view"). The scanner is identified by its fixed key (`grype`, `trivy`), not by a Harbor UUID, and its name is `Grype` or `Trivy` with the stored version. The `unknown` scanner and "not linked to a Harbor registration" wording are removed.
- SARIF: unchanged except the following. The `physicalLocation.artifactLocation.uri` is `<hub host>/<repository>`. The run id and Code Scanning category are `<tool prefix>/<hub host>/<repository>/`, with the same trailing-slash rule as today. The tool prefix is `harborgate` until the name is decided, and changing it later creates new alerts (OPEN question 11). The fingerprint `sha256(<id>|<package>)` is unchanged. One SARIF per publish job, never one per scanner.

### Labels (reworded OCI labels rule)

Decided (2026-11-09, spec author, spinoff): the rules in [integrations.md](integrations.md), "OCI labels", apply unchanged except that labels are read from the config blob of the stored image (`config.Labels`), not from Harbor. For an index, the labels are read from the platform image that was pulled. A missing `org.opencontainers.image.revision` fails the publish job with the existing clear error.

### Fixed error strings

Decided (2026-11-09, spec author, spinoff): same principle as the existing fixed Harbor errors. A job's `last_error`, an alert and the Sync jobs API carry only these strings, never a registry body, URL, header or scanner stderr.

| Cause | `last_error` |
| --- | --- |
| Registry cannot be reached, TLS or network error | `registry could not be reached` |
| Registry answers 401 or 403 | `registry rejected the credentials` |
| Repository or tag not found (404) | `image not found in registry` |
| Registry rate limit (429) | deferral, not an error (uses `Retry-After`, capped at 1 hour, `attempts` unchanged) |
| Any other non-2xx | `registry returned status N` |
| Blob digest does not match | `image content did not match its digest` |
| Pull exceeds the size bound | `image is larger than the allowed size` |
| Not enough free disk space for the pull | `not enough disk space` |
| Scanner timed out | `scanner timed out` |
| Scanner output over the cap | `scanner output too large` |
| Scanner exited non-zero | `scanner failed` |
| Scanner output unreadable | `scanner output not recognised` |
| Scanner database missing or too old | `scanner database not available` |

## 4. Local image store

- Location: `HARBORGATE_DATA_DIR/images` (default `/data/images`), one directory per pulled image, named by the `pulled_images.id` (a generated id, never a registry-supplied string). Temporary pulls go to `images/.tmp/<id>` and are renamed into place. Decided (2026-11-09, spec author, spinoff): the store is under the `data` volume so it survives restarts and shares the volume rules in [deployment.md](deployment.md). Scanner caches are in `scanner-cache`, outside the image count.
- Decided (2026-11-09, user, dialogue, spinoff decision 6): the user sets a maximum number of stored images. The setting is `images.max_stored`, a positive integer. Its scope and default are OPEN question 3. Layers are not shared between images in v1; each image is a full copy, so two tags of the same digest count as two images. PROPOSED: sharing blobs across images is not done in v1, to keep eviction a directory delete.
- Counting: only images in state `stored` count. Images that are `pulling` or already `evicted` do not.
- Eviction rule. Decided (2026-11-09, user, dialogue, spinoff decision 6): when the stored count exceeds the maximum, the oldest image is removed. "Oldest" is the smallest `pulled_at` (the time the pull finished and the row became `stored`), ties broken by the smallest `id`. Decided (2026-11-09, spec author, spinoff, following the task brief): never an image with a running scan. Decided (2026-11-09, spec author, spinoff): also never an image with a queued scan, and never the image that has just been pulled, because a queued scan would fail with the image gone. Reason: the user's rule protects a running scan, and a queued one is about to run.
- Procedure: one `BEGIN IMMEDIATE` transaction selects the oldest eligible image and sets its state to `evicting`; a scan job starts only if it can set its run to `running` while the image is `stored`, in a transaction, so the two cannot interleave. After commit the directory is deleted, then the state becomes `evicted` with `evicted_at` and `store_dir` cleared. This repeats until the count is at the maximum or no image is eligible. If none is eligible the store stays over the maximum and the check runs again whenever a scan run ends. Disk, not the count, is the real bound, so the pull checks free space first (OPEN question 5).
- Startup sweep: a directory under `images/` with no `stored` or `evicting` row, and anything in `images/.tmp`, is deleted at start. An `evicting` row at start is completed. Logged as fixed text.
- Decided (2026-11-09, spec author, spinoff): the `pulled_images` row of an evicted image is kept, with state `evicted`. Reason: the once-per-tag rule (section 5) depends on remembering that the tag was scanned; deleting the row would pull the tag again.
- Findings on eviction. PROPOSED: eviction deletes only the image directory. The `scan_runs`, `scanner_findings`, `cve_findings`, publish report, GitHub issues and uploaded SARIF are kept, and the UI shows the image as removed. Reasons: the limit exists for disk space and findings are small text; and with a small maximum the oldest image can be the only image of a source, whose CVE view would otherwise become empty and could close its issues. This is OPEN question 3 in part, because it also decides whether `cve_findings` need a retention rule now that the 10-tag limit is gone.
- Decided (2026-11-09, spec author, spinoff): a source that is deleted removes its `pulled_images`, directories and findings; GitHub issues stay open and are listed in the `source.delete` audit row, as today for a deleted mapping.

## 5. Tags and patterns

- Input. Decided (2026-11-09, user, dialogue, spinoff decisions 2 and 7): an image source is a hub, a repository and one tag value: an exact tag or a pattern. The repository must match the OCI repository name grammar above, and must not contain `:` or `@`. A digest reference is refused.
- Exact or pattern. Decided (2026-11-09, spec author, spinoff): the value is a pattern if it contains `*` or `?`, otherwise an exact tag. An exact tag must match the tag grammar (`[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`, from the OCI Distribution Specification, verified 2026-11-09). A pattern is at most 128 characters and uses only tag characters plus `*` and `?`.
- Glob semantics. Decided (2026-11-09, spec author, spinoff): the user's one example is `1.2.*`; the smallest glob that fits it is `*` for zero or more characters and `?` for exactly one, with every other character literal. `.` is a literal dot, not "any character". There are no character classes, no braces and no escapes, because `*` and `?` cannot occur in a tag. Matching is against the whole tag, case-sensitive, because tags are case-sensitive. Examples, for `1.2.*`: `1.2.0` matches, `1.2.3-rc1` matches, `1.2.` matches, `1.2` does not, `1.20.0` does not, `v1.2.0` does not. A pattern that needs more (character classes, regular expressions, exclusions) is OPEN question 10.
- Match rule. A source matches a registry tag when the tag equals the exact value, or matches the pattern. Matching is done by HarborGate on the full tag list, never by passing the pattern to the registry.
- Listing. `GET /v2/<name>/tags/list` with `n` and `last` for paging (verified, section 2), until the registry returns no more tags or the page cap is reached. The page size and cap are OPEN question 5. A listing that did not finish (error, cap reached) records nothing for the missing tail and is retried at the next discovery. How often discovery runs is OPEN question 6.
- Once per tag. Decided (2026-11-09, user, dialogue, spinoff decision 7): each matching tag is pulled and scanned once. Mechanism: `pulled_images` has `UNIQUE (source_id, tag)`. The discovery job inserts a row with `INSERT ... ON CONFLICT DO NOTHING` and queues a pull job for the tag only when the insert added a row, in the same `BEGIN IMMEDIATE` transaction, so two discovery runs cannot queue the same tag twice. The row stays for evicted images (section 4), for failed pulls and failed scans.
- Edits. Changing a source's pattern does not remove rows already recorded. New matches are pulled. Tags that no longer match are kept and not re-pulled. Deleting the source deletes the rows (section 4).
- A failed pull or scan, after the 8 attempts, leaves the tag recorded and is not retried by discovery. A manual retry of the failed job (`POST /api/v1/sync-jobs/:id/retry`, kept) re-runs it.
- Not decided: whether a tag that later points to a different digest is scanned again (OPEN question 6). Until answered, the tag is not scanned again, and the digest seen at pull time is stored.

## 6. Data model

### Fresh database

Decided (2026-11-09, spec author, spinoff, following the task brief that the spinoff starts a new schema; the user has not stated it among decisions 1 to 9, so the user can overturn it): the spinoff uses a fresh database. There is no migration from HarborGate `main` and no upgrade path. The branch has its own migration history: one `backend/migrations/0001_init.sql` that defines the whole schema, replacing `main`'s `0001` to `0009`. SQLx offline metadata (`.sqlx`) is regenerated. Decided (2026-11-09, spec author, spinoff): at startup, and in `harborgate restore` before it replaces anything, the app refuses a database file that contains a `repo_mappings` table (a `main` database) with the fixed error `this database was created by HarborGate and cannot be used by this version`. Reason: opening a `main` database would silently skip migrations and break on the first query. Importing users, OIDC settings or GitHub credentials from a `main` database is OPEN question 12.

### Tables kept (definition in [database.md](database.md), changes listed)

| Table | Change |
| --- | --- |
| `system_config` | Kept. New keys: `images.max_stored`, `scanners.enabled`. Remove nothing else. |
| `users` | Kept. |
| `user_credentials` | Kept for GitHub only. Drop `service_type`, `base_url`, `username` (they served Harbor). Keep `id`, `user_id`, `label`, `encrypted_token`, `expires_at`, `created_at`. |
| `github_issues` | Kept. `sync_report_id` becomes `publish_report_id` (`ON DELETE SET NULL`). |
| `cve_acceptances` | Kept. `mapping_id` becomes `source_id`. |
| `audit_log`, `alert_channels`, `alert_deliveries` | Kept. |
| `job_runs` | Kept. `job_kind` values: `cleanup`, `retention`, `discover`, `db_update`. |
| `sync_jobs` | Kept. `mapping_id` becomes `source_id`, nullable (a `db_update` job has none). Payload `kind` values: `discover`, `pull`, `scan`, `publish`, `db_update`. Payloads hold ids and the tag only, never a token. |

### Tables removed

`repo_mappings`, `project_webhooks`, `project_webhook_unmatched`, `picker_hidden_items`, `harbor_scanners`, `scanner_reports`, `project_scanner_locks`.

### New and replaced tables

Decided (2026-11-09, spec author, spinoff), each a consequence of decisions 2 to 8:

```sql
-- Registries. Defaults are inserted by this migration. Host is canonical (lowercase, optional :port).
CREATE TABLE IF NOT EXISTS hubs (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('default', 'custom')),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One pull credential per (user, hub). Public images need no row.
CREATE TABLE IF NOT EXISTS hub_credentials (
    id TEXT PRIMARY KEY,
    hub_id TEXT NOT NULL REFERENCES hubs(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    encrypted_token TEXT NOT NULL, -- "v1:" ciphertext, AAD hub_credentials:encrypted_token:<id>
    expires_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (hub_id, user_id)
);

-- Where an image is and where its results go. Replaces repo_mappings.
CREATE TABLE IF NOT EXISTS image_sources (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hub_id TEXT NOT NULL REFERENCES hubs(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,
    tag_value TEXT NOT NULL,           -- exact tag, or a pattern with * or ?
    github_cred_id TEXT NOT NULL REFERENCES user_credentials(id) ON DELETE RESTRICT,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    auto_create_issues BOOLEAN NOT NULL DEFAULT FALSE,
    min_issue_severity TEXT NOT NULL DEFAULT 'CRITICAL' CHECK (min_issue_severity IN ('CRITICAL', 'HIGH')),
    last_discovery_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (user_id, hub_id, repository, tag_value)
);

-- One row per (source, tag), kept after eviction (the once-per-tag memory).
CREATE TABLE IF NOT EXISTS pulled_images (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    manifest_digest TEXT,              -- sha256:<hex> of the manifest pulled; NULL until resolved
    platform TEXT,                     -- os/arch[/variant] when the tag was an index; NULL otherwise
    state TEXT NOT NULL CHECK (state IN ('queued', 'pulling', 'stored', 'evicting', 'evicted', 'failed')),
    size_bytes INTEGER,
    pulled_at INTEGER,                 -- set when state becomes 'stored'; the eviction clock
    evicted_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (source_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_pulled_images_evict ON pulled_images (state, pulled_at, id);

-- One scan of one stored image by one scanner. Replaces scanner_reports.
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    pulled_image_id TEXT NOT NULL REFERENCES pulled_images(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL CHECK (scanner IN ('grype', 'trivy')),
    scanner_version TEXT,
    db_built_at INTEGER,               -- vulnerability database build time at scan time
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
    sync_job_id TEXT REFERENCES sync_jobs(id) ON DELETE SET NULL,
    started_at INTEGER,
    finished_at INTEGER,
    error TEXT,                        -- one fixed string from section 3
    UNIQUE (pulled_image_id, scanner)
);

-- Findings of one run, one row per (CVE id, package). Same columns as today's scanner_findings.
CREATE TABLE IF NOT EXISTS scanner_findings (
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    package TEXT NOT NULL DEFAULT '',
    version TEXT,
    fixed_in_version TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    cvss_v3 REAL,
    description TEXT,                  -- at most 4,000 characters
    PRIMARY KEY (run_id, cve_id, package)
);

-- SARIF upload record per published image. Replaces sync_reports.
CREATE TABLE IF NOT EXISTS publish_reports (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    pulled_image_id TEXT REFERENCES pulled_images(id) ON DELETE SET NULL,
    sync_job_id TEXT REFERENCES sync_jobs(id) ON DELETE SET NULL,
    image_tag TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    commit_sha TEXT,
    vulnerability_summary TEXT NOT NULL,   -- JSON, as sync_reports
    sarif_status TEXT NOT NULL CHECK (sarif_status IN ('pending', 'success', 'failed')),
    github_sarif_id TEXT,
    error_message TEXT,
    synced_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- cve_findings: as today, with mapping_id -> source_id, harbor_repository dropped,
-- UNIQUE (source_id, image_tag, cve_id). It is still the merged view of one tag's image.
```

- Retention: Decided (2026-11-09, spec author, spinoff): `publish_reports` and `scan_runs` follow the existing 90-day rule by `synced_at` and `finished_at`. `pulled_images` is not under retention, because it holds the once-per-tag memory; it goes with its source. `sync_jobs` 90 days, `job_runs` 90 days, `alert_deliveries` 30 days, `audit_log` 365 days, unchanged.
- Audit vocabulary. Removed: all `mapping.*`, `project_webhook.*`, `artifact.remove`. Added (Decided 2026-11-09, spec author, spinoff, no secrets in `details`): `hub.create`, `hub.delete` (`details` the host), `source.create`, `source.update`, `source.delete` (lists the issue numbers left open), `source.scan` (a manual scan, `details` source id), `image.evict` (actor `system`, `details` `{"source_id","tag"}`), and the existing `credential.create`, `credential.rotate`, `credential.delete` for hub credentials (`target` names the hub, never the token). `sync_job.retry`, `sync_job.purge`, `backup.run`, `restore.run`, `key.rotate`, `retention.run`, `log.level_change`, `user.*`, `oidc.config_change`, `alert.config_change`, `cve.accept`, `cve.unaccept` are kept.

### CVE lifecycle rewording

Decided (2026-11-09, spec author, spinoff), the Harbor words in [cve-lifecycle.md](cve-lifecycle.md) become:

| Existing wording | Spinoff wording |
| --- | --- |
| mapping, Harbor repository | image source |
| tracked tag set | tags of the source's `pulled_images` that have at least one `done` scan run |
| newest scanned digest, latest `image_push_time` | PROPOSED: the newest scanned image of the source, by the largest `pulled_at` among its images with at least one `done` run. A registry has no push time; the image config `created` field is not trusted (OPEN question 3). |
| last 10 tags per mapping | Removed. The number of stored images is the `images.max_stored` rule; findings retention is OPEN question 3. |
| every enabled scanner has a report for the newest digest | every enabled scanner has a `done` run for the newest image |
| Harbor deleted the artifact (#249) | Removed. A tag deleted in the registry is not noticed. |
| close and reopen comment scan name `<project>/<repository>:<tag>` | `<hub host>/<repository>:<tag>` |
| issue table column "Harbor repository" | "Image" (`<hub host>/<repository>`) |

The merged view, the issue marker and adoption, the shared issue per GitHub repository and CVE, acceptance, and the dashboard counts keep their rules with those substitutions.

## 7. API and UI

### Rate limits

Every new route that calls an outbound service or starts work is limited, because HarborGate's limiter model is explicit per route. Values are the existing ones, reused, with their source: 60 requests per minute per user for routes that call a registry or GitHub for a list or a test, as the pickers ([api.md](api.md), Pickers, Decided 2026-11-05, delegated, #126), and one start per source per 5 minutes for a manual scan, as the manual pull (Decided 2026-11-05, user, #131); over the limit is `429` with `Retry-After` (RFC 6585, RFC 9110). Held in memory, cleared by a restart.

### Routes

Conventions, auth levels, the error envelope, lists and pagination are unchanged ([api.md](api.md), Conventions). All state-changing routes need the CSRF header.

| Method | Path | Auth | Request | Response | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/hubs` | session | list params | list of `Hub` (`id`, `host`, `display_name`, `kind`, `has_credential` for the caller) | 200, 401 |
| POST | `/api/v1/hubs` | admin | `{"host","display_name"}` | `Hub` | 201, 400, 409 (host exists), 422 (not a valid host, blocked address) |
| DELETE | `/api/v1/hubs/:id` | admin | none | empty | 204, 404, 409 (a source uses it; PROPOSED: also a default hub) |
| PUT | `/api/v1/hubs/:id/credential` | session (own) | `{"username","token","expires_at"?}` (token write-only) | `{"hub_id","username","expires_at"}` | 200, 201, 404, 422 |
| DELETE | `/api/v1/hubs/:id/credential` | session (own) | none | empty | 204, 404, 409 (a source for this hub exists and the repository needs it; not checked, see note) |
| POST | `/api/v1/hubs/:id/credential/test` | session (own) | `{"repository"}` | `{"ok","detail"}` (never the token) | 200, 404, 422, 429, 502 `upstream_unreachable` |
| GET | `/api/v1/image-sources` | session | list params; `hub_id`; admin may add `scope=all` | list of `ImageSource` | 200, 401 |
| POST | `/api/v1/image-sources` | session | `{"hub_id","repository","tag_value","github_cred_id","github_owner","github_repo","default_branch","auto_create_issues","min_issue_severity"}` | `ImageSource` | 201, 400, 404, 409 (same user, hub, repository and tag value exists), 422 (name or tag grammar, code scanning unavailable, Issues permission) |
| GET | `/api/v1/image-sources/:id` | session | none | `ImageSource` | 200, 404 |
| PUT | `/api/v1/image-sources/:id` | session (owner) | any subset of the create fields | `ImageSource` | 200, 404, 409, 422 |
| DELETE | `/api/v1/image-sources/:id` | session (owner) | none | empty | 204, 404 |
| GET | `/api/v1/image-sources/:id/tag-preview` | session (owner) | none | `{"matches": [tag], "truncated": bool}` (names only; lists the registry, records nothing) | 200, 404, 422, 429, 502 |
| POST | `/api/v1/image-sources/:id/scan` | session (owner, or any admin) | none | `{"queued": <n>}` (runs discovery now) | 200, 404, 429 (with `Retry-After`), 502 |
| GET | `/api/v1/image-sources/:id/images` | session (owner, or any admin read) | list params | list of `PulledImage` (`id`, `tag`, `manifest_digest`, `platform`, `state`, `size_bytes`, `pulled_at`, `scans`: per scanner `status`, `version`, `error`) | 200, 404 |
| GET | `/api/v1/images` | session | list params; `state`, `source_id`; admin may add `scope=all` | list of `PulledImage` | 200, 401 |
| GET, PUT | `/api/v1/admin/image-store` | admin | `{"max_stored","scanners_enabled"}` | same | 200, 401, 403, 422 |

Notes: `DELETE .../credential` does not check dependent sources; a source whose pull then fails shows `registry rejected the credentials`. Decided (2026-11-09, spec author, spinoff): simplest rule, no coupling between the credential and a source, since a public repository needs no credential. The GitHub repository picker `GET /api/v1/credentials/:id/github-repositories` is kept.

Kept routes: auth, account, credentials (GitHub only; `service_type` removed from the body), `cves` (with `mapping`/`mapping_id` renamed `source`/`source_id`; Harbor `project` and `harbor_*` parameters removed), `sync-jobs` (including retry, failed-count, purge-failed), dashboard (recent syncs become recent scans), admin (users, oidc, github-url, alert-channels, audit-log, jobs, backup, logs, log-level), `/healthz`. `GET /api/v1/admin/health` drops the Harbor and robot-account fields and adds: per hub reachability, the pinned scanner versions found, the database build time per scanner, and free disk space of the store.

Removed routes: `/api/v1/webhooks/harbor/*`, `/api/v1/project-webhooks*`, `/api/v1/mappings*` (replaced by `image-sources`), `/api/v1/mappings/:id/scanners`, `/api/v1/mappings/:id/tags/:tag/scan*`, `/api/v1/credentials/:id/harbor-*`, `/api/v1/credentials/:id/source-suggestion`, `/api/v1/pickers/hidden*`.

### UI

Every screen below needs the user's design approval before it is built ([frontend.md](frontend.md), process rules; CLAUDE.md). Copy goes into the string catalog, English only. IA goal and scope, per the information-architecture check: the user's goal is "tell the tool where my images are and see what was scanned and what is open"; sources and images are per-user, hubs and the store limit are instance-wide (admin).

- Rail (Decided 2026-11-09, spec author, spinoff, needs approval): Dashboard, Sources (replaces Mappings), Images (new), CVEs, Sync jobs; bottom: Admin (admins), Account. Reason: the new objects are sources and stored images; Sync jobs stays because the durable queue stays.
- Removed pages and parts: the mapping form's Harbor source section, its Scheduled scan card and its project webhook proposal; the mapping-created screen with shown-once webhook URL and auth secret; the Harbor project and repository pickers, "Already mapped", and the hidden items manager; the Scans card with scanner picker, switch notice and restore states; the Admin Health Harbor and robot expiry rows.
- New: Sources list and form (hub select, repository, tag value with live exact-or-pattern hint and a preview from `tag-preview`, GitHub target, issue settings); Source detail with an Images table (tag, state, pulled time, scan state per scanner) and a Scan now button; Images page (stored images, state, size, which will be evicted next); Admin > Settings: Hubs (list, add custom, remove) and Image store (maximum images, enabled scanners); Account > Credentials: a registry credentials list per hub beside the GitHub credentials.
- CVE list control bar ([frontend.md](frontend.md), "CVE list control bar"): kept concepts: the search field, Severity, Status, GitHub issue and Fix available pill groups, the Repository, Tag and Mapping comboboxes (Mapping renamed Source), URL sync, the table columns, the Create issue dialog. Removed with the Harbor fields: the **Project** combobox and its narrowing of Repository, the search match on "Harbor project", the URL parameters `project` and `harbor_project`, and the old-link compatibility for `harbor_*` and `mapping_id`. Changed: the search matches CVE id, package, hub host and repository; the Repository combobox lists `<hub host>/<repository>`. The "Found by" scanner column and the scanner filter are kept and now list Grype and Trivy. PROPOSED: a **Hub** combobox in the place of Project. The "Tags n of m" column counts tags of the source (see section 6, tracked tag set), not Harbor tags.
- Per-CVE view, dashboard cards, acceptance, Sync jobs page with purge, and the Admin tabs Jobs, Failed syncs, Audit log and Settings are kept with the substitutions above.

## 8. Security

### Credentials and secrets

- Decided (2026-11-09, user, dialogue, spinoff decision 4): hub credentials are encrypted per hub with the existing scheme (section 2, `hub_credentials`). Rotation by the existing CLI command must include `hub_credentials.encrypted_token` and `user_credentials.encrypted_token`, `alert_channels.config_encrypted` and `system_config` values; a test enumerates every `is_encrypted` column so a new table cannot be missed.
- Decided (2026-11-09, user, dialogue, spinoff decision 4, extending CLAUDE.md non-negotiable rules): no hub token, registry `Authorization` or `Www-Authenticate` value, bearer token from a token service, GitHub token, or encryption key is logged, printed, traced, returned, or sent over Server-Sent Events. A registry response body is never copied into a log, job row, alert or API response; only the fixed strings in section 3. The debug-level outbound request log records method, URL path without query, and status only ([security.md](security.md), Application log). The `Authorization` header is not forwarded to a different host on a redirect (the OCI spec's MUST NOT, section 2).
- Tokens are held in memory only while a pull runs and zeroized. They are never put in a scanner's argument vector, environment or working directory. Decided (2026-11-09, spec author, spinoff): scanners work on the local directory only and never contact a private registry.
- Tenancy: users see only their own sources, images, hub credentials and findings. Admins view all read-only. Operational exceptions follow the existing pattern ([security.md](security.md), Tenancy): an admin may start discovery for any source (`POST /image-sources/:id/scan`; it uses the owner's hub credential on the server and shows no value), and may retry or purge failed jobs. Decided (2026-11-09, spec author, spinoff): the exceptions replace the manual-pull and tag-scan exceptions, for the same reason. Hubs and the store limit are admin settings.

### Outbound registry requests (SSRF)

- Decided (2026-11-09, spec author, spinoff): the existing rules in [security.md](security.md), "Outbound HTTP (SSRF)" apply to every hub host: HTTPS only; the resolved address must not be loopback, link-local, private or in the other listed ranges; the check repeats when DNS changes; the opt-out is an environment variable, default `false`, named `HARBORGATE_ALLOW_PRIVATE_REGISTRIES` (provisional with the name). Adding a hub is admin only, and the host is checked when the hub is saved and at every request.
- The conflict with `oci-client` and with redirects is `CONFLICT:` in section 2 and OPEN question 2. Until the user resolves it, the implementation does not claim these rules hold for blob downloads.
- Repository names and tags are validated against the grammars above before any request, and percent-encoded in paths. A name outside the grammar is `422` with no request made.
- Size and decompression: a registry or image is untrusted input. Every manifest and config response has a byte cap, and the total blob bytes of a pull have a bound (OPEN question 5), enforced while streaming, not from the declared size alone.

### Scanner process rules

Decided (2026-11-09, spec author, spinoff), because an image is attacker-controlled input to a parser, and the process runs next to the encryption key's process:

- No shell. The backend starts the scanner with `tokio::process::Command` and an argument vector, never `sh -c`, never string interpolation. The program is an absolute path to the pinned binary; `PATH` is not searched. The only variable argument is the store directory, generated from the image id. A registry, repository or tag string never appears in an argument, a file name or an environment variable.
- Clean environment: the child starts with an empty environment plus a fixed allow-list (cache and home directory under `scanner-cache`, locale, and the scanner's own offline settings). It inherits nothing from the parent, so `HARBORGATE_ENCRYPTION_KEY`, `HARBORGATE_OLD_ENCRYPTION_KEY` and any token never reach it. A test starts a child that prints its environment and asserts the key variables are absent.
- Identity and files: same user as the app (65532), no extra capabilities. The scan reads the image directory and writes the output file and the cache only.
- Network: the scan step is offline (flags above). One container cannot isolate one child's network; this is a limitation, stated, not a guarantee. Only the `db_update` job lets a scanner reach the network, to the database location only.
- Timeout: every run has a wall-clock timeout; on expiry the whole process group is killed (`kill_on_drop` plus a group kill), the output file is deleted, and the run fails with `scanner timed out`. The value is OPEN question 5.
- Bounded output: stdout and stderr are drained with a byte cap and discarded or reduced to a fixed string; the JSON output file has a size cap checked before parsing, and the parser rejects deeply nested input. Exceeding the cap fails the run with `scanner output too large`. The value is OPEN question 5.
- One scanner process at a time (the single worker). A scanner's stderr is never stored or logged raw.
- A crash or restart mid-scan re-queues the job by the existing restart rule ([backend.md](backend.md)); the child is not left running (`kill_on_drop`, and a startup sweep of `scanner-cache` temporary files).

### Alerts

Alerts keep their rules. A failed pull, scan or publish job raises the existing sync-failed alert with a fixed `error` string; the webhook body field `mapping.harbor` becomes `source.image` (`<hub host>/<repository>`). The new CRITICAL CVE alert is unchanged.

## 9. Open questions

Each is asked exactly as written. None is decided.

1. The Docker documentation uses `registry-1.docker.io` for pulls, and `hub.docker.com` is Docker's web site. Which host should the default Docker Hub entry store and show: `docker.io`, `registry-1.docker.io` or `hub.docker.com`?
2. Registries redirect blob downloads to another host, `oci-client` cannot take our redirect policy or DNS check, and our security rules say no redirects and a resolved-address check on every request. Which do you want: use `oci-client` and allow redirects for registry blob downloads with the address check only on the registry host, or write a small registry client on `reqwest` that keeps both rules?
3. Should hubs, the maximum number of stored images and eviction be instance-wide (one shared store, so one user's pulls can evict another user's oldest image), or per user? And when an image is evicted, do its findings, scan runs and CVE view stay (the proposal in section 4), or are they deleted? And, with no push time in a registry, is the newest image of a source the one with the latest pull time (the proposal in section 6)?
4. For a tag that is a multi-architecture image index, which platform do you want pulled and scanned: one fixed platform (which one), the platform of this server, or every platform in the index?
5. Which values do you want for these limits: the maximum size of one pull, the minimum free disk space before a pull, the tag list page size and page cap, the cap on new tags one discovery may record, the scanner wall-clock timeout, the scanner output size cap, and the default for the maximum number of stored images?
6. How often should tag discovery and the vulnerability database update run? And when a tag you already scanned later points to a different image, or the vulnerability database gets newer, should the tag be scanned again, or never (the literal reading of "scanned once")?
7. The runtime image is `scratch` and the spec said the app spawns no processes. Do you accept a different runtime base image (for example `alpine`) if the official Grype and Trivy binaries do not run on `scratch`?
8. Do you need registries over plain HTTP or on a private address (for example a registry on your own network)? If yes, is an environment-variable opt-out like the current Harbor one enough?
9. Can the default hubs (`ghcr.io` and Docker Hub) be removed by an admin, or only the custom ones?
10. Is the glob with only `*` and `?` enough for tag patterns, or do you need character classes, regular expressions or exclusions? And should the set of scanners stay fixed to Grype and Trivy, or should an admin be able to add other scanners later?
11. When the product name is decided, may these be renamed together: the `HARBORGATE_*` variables, the `__Host-harborgate_*` cookies, the `harborgate/*` HKDF labels, the SARIF tool name, the Code Scanning category prefix `harborgate` (changing it makes GitHub create new alerts), the issue label `harborgate` and the issue marker `<!-- harborgate:<CVE id> -->`?
12. Should the spinoff be able to import anything from an existing HarborGate database (users, OIDC settings, GitHub credentials), or is it always a fresh install?

## 10. Verification strategy

The spinoff has no GitHub issue yet. When one is created, its body must carry this list as `- [ ]` items, and it stays open until each is ticked with evidence.

- [ ] The branch `spinoff-local-scan` is not merged to `main`, and a CI or review check prevents it.
- [ ] No Harbor code, route, table, setting, string or doc reference remains (search test for `harbor`, case-insensitive, outside this spec and the changelog).
- [ ] The `0001` migration creates every table in section 6 and none of the removed ones; a `main` database and a `main` backup are refused with the fixed error.
- [ ] A default install has the two default hubs; an admin can add and remove a custom hub; a hub in use cannot be removed.
- [ ] A hub credential is stored as a `v1:` ciphertext with AAD `hub_credentials:encrypted_token:<id>`, is never returned, and key rotation re-encrypts it (a test enumerates all encrypted columns).
- [ ] A public image pulls with no credential; a private image pulls with one; a wrong credential gives `registry rejected the credentials`. A fake registry covers the token flow, paging, redirects and digest mismatch.
- [ ] Tag matching: the examples in section 5 pass; `*` and `?` only; a digest reference and a bad grammar are refused; matching is case-sensitive.
- [ ] Once per tag: two concurrent discovery runs queue one pull; a tag whose image was evicted is not pulled again; a failed tag is not re-queued by discovery.
- [ ] Eviction: with the maximum at N, pulling the N+1th removes the oldest by `pulled_at`; an image with a running or queued scan is never removed; the store stays over the maximum when none is eligible and recovers when a run ends; a crash during eviction is repaired at startup; findings are handled as decided in OPEN question 3.
- [ ] Both scanners run on a fixture image (a real captured Grype and Trivy report as fixtures); their findings merge on (CVE id, package) into one finding with scanner count 2; severity mapping covers `Negligible` and unknown values; `SchemaVersion` other than 2 fails with the fixed error.
- [ ] The merged SARIF validates against SARIF 2.1.0 (`sarif-validate`); the upload, issue creation, close, reopen and manual-close honouring behave as in [cve-lifecycle.md](cve-lifecycle.md); a failed scanner never closes an issue.
- [ ] Scanner process rules: no shell, clean environment (the key variables are absent), timeout kills the process group, output cap enforced, nothing downloaded during a scan, a restart mid-scan recovers.
- [ ] No token, registry header or key appears in a log, a job row, an alert, an API response or an SSE stream (log-capture test across a full pull and scan with a canary token).
- [ ] Every new outbound route returns `429` with `Retry-After` over its limit; the SSRF checks reject a private-address hub host.
- [ ] The CVE list has no Project filter, the Source and Repository filters work, and the old Harbor URL parameters are not read.
- [ ] Every new screen has a user-approved design before it is built, and all text is in the string catalog.
- [ ] The image builds with pinned Grype and Trivy at a verified SHA-256, the `docker-smoke` check passes, and the UNVERIFIED items in sections 2 and 3 are each resolved or restated.
