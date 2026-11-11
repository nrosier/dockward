# Spinoff: local image scanner (working name `localscan`, PROVISIONAL)

Purpose: the build specification for a spinoff of HarborGate that drops Harbor entirely. The spinoff pulls container images from OCI registries ("hubs") through the registry API into OCI image layouts on disk, scans them with Trivy and Grype running out of process, and keeps the SARIF upload, the GitHub issues and the CVE rules.

The product name is not decided (decision 22). `localscan` is a provisional working name. Where this spec names a new identifier with it (environment variables, a metric, a directory), the identifier is provisional and is renamed together with the product (section 14, rename set).

Branch: `spinoff-local-scan`. It must never be merged to `main`. Every other spec file on this branch still describes HarborGate with Harbor. This file overrides them on this branch; where they disagree, this file wins, and section 1 names what it replaces. The binding source is [spinoff-decisions.md](spinoff-decisions.md) (decisions 1 to 45). Where an older spec file or an earlier draft of this file conflicts with a decision, the decision wins.
Decision 58 rename (2026-11-11): the table `sync_jobs` is now `jobs`, `/api/v1/sync-jobs` is `/api/v1/jobs`, the column `sync_job_id` is `job_id`, and the sync-failed alert is the job-failed alert (event `job_failed`). Where this file says `sync_jobs` or `sync-jobs` below, read `jobs`. Kinds and behaviour are unchanged; the audit actions `sync_job.retry` and `sync_job.purge` are kept.


Marks follow [README.md](README.md). `Decided (spinoff N)` cites a decision. `Decided (spec author, spinoff)` is a gap-filler inside the decisions with its reason; the user can overturn it. `UNVERIFIED:` can only be checked by a test run or a live system. Section 15 lists the open items. Nothing in section 15 is decided.

## Decisions

Each decision and where it lands.

| N | Decision (short) | Lands in |
| --- | --- | --- |
| 1 | Harbor removed; source = hub, repository, tag or pattern | 1, 5, 9 |
| 2 | Registry API into OCI layouts on disk; no Docker daemon or socket | 3, 4, 6 |
| 3 | Every platform in an index is scanned; results per platform | 6, 9 |
| 4 | Databases refresh daily; a newer database rescans every retained image by digest | 8 |
| 5 | Scanners out of process, pinned; app image stays `FROM scratch` | 7 |
| 6 | SARIF upload and GitHub issues stay | 1, 6 |
| 7 | Default hubs, custom hubs, encrypted credentials (host string superseded by 11; scope superseded by 35) | 2, 9 |
| 8 | Each match scanned once per digest (extended by 17) | 5, 8 |
| 9 | Count-based retention, never evict a running scan (refined by 18) | 4 |
| 10, 22 | Name undecided; `localscan` provisional | header, 14 |
| 11 | Docker Hub stored as `docker.io`; pulls go to `registry-1.docker.io` | 2 |
| 12 | Own registry client on reqwest; redirects followed, address checked on every hop | 3, 12 |
| 13 | Default hubs not removable; custom hubs addable and removable | 2 |
| 14 | Private or plain-HTTP registries: environment opt-out, off by default, named hubs only | 3, 12 |
| 15 | Tags: exact, `*`, `?`; no exclusions, no regex | 5 |
| 16 | Discovery hourly per repository | 5 |
| 17 | Scan triggers: first pull, tag moves to a new digest, vulnerability DB change | 6, 8 |
| 18 | Retention count default 20; eviction deletes the layout only | 4 |
| 19 | Limits and defaults, operator-configurable | 7, 13 |
| 20 | Keep SARIF, issue, close, reopen, accepted-CVE rules; remove Harbor parts only | 1, 9 |
| 21 | Fresh install only; no import | 9 |
| 33 | No project layer; a source is hub, repository and tag value; the first path segment of the repository is the namespace | 5, 9, 10, 11 |
| 34 | Step 1 held; schema and Harbor removal land with the sync and scanner steps (supersedes 31) | 1, 9 |
| 35 | Credentials per source; no namespace-level default | 2, 9, 10 |
| 36 | SARIF location and Code Scanning category use hub host and repository | 9 |
| 46 | Category includes the tag value (`harborgate/<hub host>/<repository>/<tag value>`) | 9 |
| 47 | Issues keyed by GitHub repository and CVE; sources sharing a GitHub repo share one issue | 9 |
| 37 | Source identity is hub, repository and tag value; same repository on two hubs is two sources | 9, 10 |
| 38 | CVE list keeps a namespace filter in place of the Project filter | 10, 11 |
| 39 | Docker Hub authentication is optional; anonymous pulls work | 2 |
| 40 | Anonymous Docker Hub rate limit: fixed catalog message, retry on the backoff | 2, 3, 6 |
| 41 | Docker Hub credential test as for other hubs; works anonymously | 2, 10 |
| 42 | Removing a Docker Hub credential falls back to anonymous pulls with a note | 2, 10 |
| 43 | ghcr.io: classic personal access token with `read:packages` only | 2 |
| 44 | Custom hub pull endpoint, default the stored host | 2, 9, 10 |
| 45 | A hub is identified by its host only; no display label | 2, 9, 10, 11 |

## 1. Scope

### Removed (decision 1)

This removal lands with the sync and scanner steps (decision 34, "Build order" below). From then on there is no Harbor client, no Harbor webhook receiver, no Harbor poll, no project scanner call, no scheduled Harbor scan and no Harbor robot permission. The words Harbor, robot account, project webhook and `SCANNING_COMPLETED` do not appear in code, API, database or UI. Nothing contacts a Harbor instance. Also removed: the Docker daemon, `/var/run/docker.sock`, `bollard` and any pruning of the host's Docker images. The app never touches the host's Docker.

| Spec file | Fate in the spinoff |
| --- | --- |
| [architecture.md](architecture.md) | Overview, components and data flow steps 1 to 3 replaced by sections 5 to 8. Convert, upload, issues and alerts are kept. |
| [integrations.md](integrations.md) | Removed: Harbor webhook, Harbor API, polling, scheduled scan, scanner reports and scan launch (including the project lock and the Grype report reader for the Harbor adapter), mapping pickers except the GitHub repository list. Kept: SARIF conversion and upload, GitHub base URL, GitHub issues, GitHub target, with the wording in section 9. OCI labels kept, read from the pulled image config (section 6). |
| [database.md](database.md) | Replaced by section 9. |
| [backend.md](backend.md) | Removed: `webhooks.rs`, the Harbor poll, resolve jobs, `scanner_scan`, `scanner_restore`, the project scanner lock, Harbor rate-limit deferral. The durable job queue is kept with the job kinds of section 9. |
| [security.md](security.md) | Removed: webhook limits and body cap, the manual-pull limit, the Harbor scanner secrets paragraph, `HARBORGATE_ALLOW_PRIVATE_HARBOR`. The outbound rules are replaced by section 12. Everything else is kept (below). |
| [cve-lifecycle.md](cve-lifecycle.md) | Reworded by the table in section 9. |
| [alerts.md](alerts.md), [api.md](api.md), [frontend.md](frontend.md) | Harbor parts removed; replaced by sections 10 and 11 and the alert note in section 12. |
| [deployment.md](deployment.md) | "The app spawns no processes" is superseded by section 7. `scratch` stays (decision 5). |
| `docs/SETUP.md` | Stale on this branch; not changed by this spec. |

### Kept (decisions 6 and 20)

- GitHub SARIF 2.1.0 conversion and upload, the GitHub base URL setting, the GitHub token scope, GitHub issues (marker `<!-- harborgate:<CVE id> -->`, label, title, adoption, manual route, create lock), the CVE close, reopen and manual-close rules, acceptance, dashboard counts, the alert channels and the audit log.
- Authentication, first-run setup, OIDC, roles, sessions, CSRF, login CSRF, security headers, client IP, login rate limit, `Cache-Control: no-store`, encryption and keys (`v1:` ciphertext, AAD `<table>:<column>:<row id>`, the HKDF labels, key rotation by CLI, `zeroize`), backup and restore, secrets in logs, the application log ([security.md](security.md)).
- The durable job queue: three outcomes (success, failure, deferred), retry 30 s doubling with 8 attempts, restart recovery, manual retry, purge of failed jobs ([backend.md](backend.md)).
- Timestamps as `INTEGER` Unix seconds, `CHECK` constraints on enumerated columns, `PRAGMA foreign_keys = ON`.

### Build order (decision 34)

- Step 1 (the clean schema and the Harbor removal) is held. It does not land alone. The schema of section 9 and the removal of the Harbor code, routes, tables and tests land together with Steps 3 and 4, the sync and scanner steps, so the spinoff branch builds and passes its gates at each merge. Decision 31 (Step 1 removes the Harbor code in its own change) is superseded by decision 34.
- Step 2, the registry client (section 3), does not depend on the schema and is already on the branch.
- The uncommitted Step 1 work is kept, not discarded, in the worktree `agent-a45531f4f50b14b5f` on branch `feat-spinoff-step1`.
- Until Steps 3 and 4 land, the Harbor code on the branch stays as it is, and sections 1 and 9 describe the target state.

Existing names (`HARBORGATE_*` variables, `__Host-harborgate_*` cookies, `harborgate/*` HKDF labels, the issue marker and label, the SARIF tool name and category prefix) are kept unchanged until the name is decided (decision 22, section 14).

## 2. Hubs and credentials

- A hub is an OCI registry host: lowercase DNS name, optional `:port`, no scheme, no userinfo, no path. The host is its only identifier and the name shown everywhere (decision 45). A hub has no display name or label. It has a kind, `default` or `custom`.
- Defaults (decisions 7, 11, 13): `ghcr.io` and `docker.io`, inserted by the fresh migration. Docker Hub is stored and shown as `docker.io`. For Docker Hub the pull endpoint differs from the stored host: pulls and token requests go to `registry-1.docker.io` (token service and realm as the registry's challenge says, section 3). That mapping lives in one function in the registry client and is not user-editable. Default hubs cannot be removed by an admin.
- Custom hubs (decisions 13, 44): an admin can add and remove them. A custom hub can set a pull endpoint that differs from its stored host: a host in the same grammar as a hub host, to which the registry requests go instead. The default is the stored host (no endpoint set). The stored host stays the identity of the hub, the name shown, and the value in source identity, SARIF paths and issue text; the endpoint is only where requests are sent. Default hubs have no settable endpoint. Removing a hub that an image source uses is refused (`409 conflict`). Adding validates the host grammar, the endpoint grammar, and the address rules of section 12 for each.
- Transport: HTTPS only. Plain HTTP and private addresses only through the environment opt-out in section 12 (decision 14).
- Credentials (decisions 7, 35): credentials are per source. A source has at most one credential, stored encrypted in `source_credentials`, and it is the credential used to pull that source's repository from its hub. There is no credential at hub level and no default credential for a namespace (the first path segment of the repository): a source that needs a credential carries its own, and a credential is not shared between sources. Decided (spec author, spinoff): the credential belongs to the source and so to the source's owner, which keeps the tenancy rule (a user sees only their own credentials) without a separate per-user key; deleting the source deletes its credential.
- A credential is a username and a token. The token is a `v1:` ciphertext with AAD `source_credentials:encrypted_token:<id>`. It is write-only through the API, never logged, never sent to a scanner (section 12).
- Anonymous pulls and when a credential is needed:
  - `docker.io` (decision 39): authentication is optional. A Docker Hub source is pulled anonymously and works with no credential. A credential is needed only for a private repository or to raise the anonymous rate limit.
  - Other hubs keep their current rule (decision 14): a credential as the hub requires. A public repository is pulled anonymously where the registry allows it; a private one needs the source's credential.
- Docker Hub rate limit (decision 40): when Docker Hub refuses an anonymous pull for the rate limit, the source shows a fixed catalog message that asks for a Docker Hub credential, which raises the limit (error string in section 6). The job retries on the backoff, so a later attempt can succeed.
- Removing a Docker Hub credential (decision 42): the source falls back to anonymous pulls and shows a note that no credential is in use. It is not blocked and not paused. Decided (spec author, spinoff): the note is derived, not stored: the source shows it while its hub is `docker.io` and it has no credential. If the repository is private, the next pull fails with `registry rejected the credentials`.
- Pull scope: the client asks only for `repository:<name>:pull`. Verified (2026-11-09) in `distribution/distribution`, `docs/content/spec/auth/token.md`: the registry answers `401` with `Www-Authenticate: Bearer realm=...,service=...,scope=...`, and the client fetches a token from the realm with Basic credentials.
- `ghcr.io` credential (decision 43): a personal access token (classic) with the `read:packages` scope. Fine-grained tokens are not accepted for `ghcr.io`. Verified 2026-11-09 in GitHub's Container registry documentation: only a personal access token (classic) authenticates, and `read:packages` reads packages. This is a different token from the GitHub token used for Code Scanning and issues. Decided (spec author, spinoff): saving a credential for a source on `ghcr.io` is refused with `422` when the token starts with `github_pat_`, the prefix of fine-grained tokens. UNVERIFIED: that prefix; check it against GitHub's token format documentation before the check is built. Any other refusal comes from the registry when a pull or the test runs. UNVERIFIED: the scopes Docker Hub access tokens offer.
- Test button (decision 41): `POST /api/v1/image-sources/:id/credential/test` works like the test for any other hub. It fetches `GET /v2/` and a pull token for the repository the caller names, using the source's credential, and returns `ok` or the failure, never the token. It also works anonymously: with no credential on the source, it runs the same check without one (on Docker Hub this shows whether an anonymous pull is possible).

## 3. Registry client

Decided (spinoff 12): our own client on `reqwest`, in `services/registry/`. No `oci-client`, no `bollard`, no Docker daemon. (The earlier draft's library evaluation is withdrawn.)

Endpoints, from the OCI Distribution Specification (`opencontainers/distribution-spec`, `spec.md`): `GET /v2/`, `GET /v2/<name>/tags/list` with `n` and `last` or the `Link` header, `GET /v2/<name>/manifests/<reference>`, `GET /v2/<name>/blobs/<digest>`.

Verified (2026-11-09) in that spec:

- A `Link` header with `rel="next"` MAY be sent when more tags exist, and clients should prefer it over `last` (lines 592 to 614).
- Registries MAY redirect any request; clients SHOULD follow redirects and MUST NOT forward `Authorization` headers across host boundaries (line 829).
- A tag matches `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`; a repository name matches `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*`.
- Clients should expect to handle manifests of at least 4 megabytes (line 544).
- A token response's `expires_in` defaults to 60 seconds when omitted (distribution token spec).

Contract:

- Auth: the standard Bearer challenge flow. On `401` the client reads `Www-Authenticate`, requests a token from the realm for the scope `repository:<name>:pull` (Basic credentials when the source has a credential, none otherwise), caches it in memory until its expiry, and retries once. Docker Hub's flow is UNVERIFIED (section 15, item 2).
- Redirects (decision 12): followed, using a custom redirect policy. On every hop the client checks scheme (HTTPS only, unless the hub is named in the opt-out), validates the host, and requires every address the host resolves to to pass the address rules of section 12. The `Authorization` header is dropped when the host changes. The hop limit is 10, reqwest's default policy limit, which the client keeps as its own explicit constant. A hop that fails any check ends the request with `registry could not be reached`.
- Address check on every request: the check runs on the addresses actually connected to (a custom resolver or connect-time check), not only on a pre-resolution of the hub host, so DNS rebinding between the check and the connect is closed. The mechanism is an implementation choice; the acceptance test in section 16 decides whether it holds.
- Bounds: manifest and config responses have a byte cap; blobs are streamed with a running byte count against the pull cap (section 13), not trusted from `Content-Length`. Every blob's SHA-256 is verified against its descriptor while streaming.
- Timeouts: a connect timeout and a total per-request timeout, as constants in one place.
- Rate limit `429` from a registry: deferral using `Retry-After`, capped at 1 hour, `attempts` unchanged (the existing deferral rule). The one exception is an anonymous pull refused by Docker Hub for its rate limit (decision 40): that is a failure with the fixed message of section 6, retried on the backoff (30 s doubling, 8 attempts), not a deferral.
- Names are validated against the grammars above before any request and percent-encoded in paths.

## 4. OCI layout store and retention

- Location: `HARBORGATE_DATA_DIR/images` (default `/data/images`). One directory per stored image, named by a generated id, never by a registry-supplied string. Pulls are written to `images/.tmp/<id>` and renamed into place.
- Layout: a standard OCI image layout (`oci-layout`, `index.json`, `blobs/sha256/...`).
- Decided (spec author, spinoff): a stored image is one OCI layout per platform manifest. A multi-arch tag is therefore several stored images, one per platform (decision 3). Reasons: a layout with one manifest needs no platform selector at scan time, results are per platform, and eviction and the pull cap stay a directory delete and a single size. Blobs are not shared between layouts in v1.
- Retention (decision 18): count-based, default 20 stored images, operator-configurable (setting `images.max_stored`, a positive integer). Only images in state `stored` count.
- Eviction deletes the OCI layout only. Findings, scan runs, scan history, publish reports, issues and uploaded SARIF are kept; the UI shows the image as removed. The `image_platforms` row stays with state `evicted`, as the memory that the digest was scanned.
- Order: when the count exceeds the maximum, the oldest is removed first: smallest `pulled_at`, ties by smallest id (decision 9).
- Never evict (decision 9): a layout with a running scan. Decided (spec author, spinoff): also never a layout with a queued scan, and never the image just pulled, because a queued scan would fail with its layout gone.
- Procedure: one `BEGIN IMMEDIATE` transaction selects the oldest eligible image and sets it to `evicting`; a scan starts only if it can move its run to `running` while the image is `stored`, in a transaction, so the two cannot interleave. After commit the directory is deleted, then the state becomes `evicted` with `evicted_at`. This repeats until the count is at the maximum or none is eligible. If none is eligible the store stays over the maximum and the check runs again when a scan run ends.
- Startup sweep: a directory with no `stored` or `evicting` row, and everything in `images/.tmp`, is deleted at start. An `evicting` row is completed. Logged as fixed text.
- An evicted image cannot be rescanned (section 8). A tag that points to an evicted digest is not pulled again; the digest is already known.
- Disk guard: before every pull the free space of the store volume must be at least the minimum (section 13). Otherwise the job fails with `not enough disk space`.

## 5. Tags and discovery

- Source (decisions 1, 33): a hub, a repository and one tag value, an exact tag or a pattern. There is no project layer and no project table. The repository keeps its full path, and its first path segment is the namespace (a user or an organisation). The namespace is the only grouping; it is derived from the repository when needed and is not stored. The repository must match the OCI repository grammar and must not contain `:` or `@`. A digest reference is refused.
- Decided (decision 15): the value is a pattern if it contains `*` or `?`, otherwise an exact tag. Only these two forms exist. There are no exclusions, no regular expressions, no character classes and no braces.
- Glob: `*` is zero or more characters, `?` is exactly one, every other character is literal (`.` is a literal dot). Matching is against the whole tag, case-sensitive. A pattern has at most 128 characters and only tag characters plus `*` and `?`. An exact tag must match the tag grammar. Examples for `1.2.*`: `1.2.0` matches, `1.2.3-rc1` matches, `1.2.` matches, `1.2` does not, `1.20.0` does not, `v1.2.0` does not.
- Matching is done by the app on the full tag list, never by sending the pattern to the registry.
- Discovery (decision 16): a `discover` job runs hourly per configured repository (one job per distinct hub and repository, covering every source on it). It lists the tags (paging by `Link`, with a page cap, section 13), matches each source's value, resolves each matching tag to its manifest digest, and records the observation (section 9, `tag_observations`).
- Triggers (decision 17): a digest is queued for pull and scan when it is new to the store (first pull) or when a tag now points to a different digest than before (tag moved). The old digest stays recorded. A digest already known (stored or evicted) is never pulled again for a tag; two sources or tags that reach the same digest share one image and scan (decision 8).
- Insertion is `INSERT ... ON CONFLICT DO NOTHING` inside one `BEGIN IMMEDIATE` transaction, with the pull job queued only when a row was added, so two discovery runs cannot queue the same digest twice.
- A listing that did not finish (error or page cap) records nothing for the missing tail and is retried at the next hourly run. A pull or scan that failed after 8 attempts is not retried by discovery; a manual retry of the failed job re-runs it.
- A manual `POST /api/v1/image-sources/:id/scan` runs discovery for that source now.
- Editing a source's value does not delete anything already recorded. New matches are pulled.
- A tag deleted in the registry is not noticed; its findings stay until the source is deleted.

## 6. Scan flow per platform

1. **Discover** (section 5). Output: a (tag, top-level digest) observation.
2. **Resolve**: fetch the manifest. If it is an image index, list its entries (decision 3). Attestation entries (platform `unknown/unknown`) are skipped. UNVERIFIED: the exact annotation that marks them; the platform value is the rule until checked. If it is a single manifest, the platform comes from the image config (`os`, `architecture`, `variant`). Each platform digest not already stored or evicted becomes one `pull` job.
3. **Pull** (one platform): check the free-disk guard, then the declared size against the pull cap, then download the manifest, config and layer blobs into `images/.tmp/<id>`, verifying each digest and the running byte total. Write the layout, rename it into place, mark `stored` with `pulled_at`, then run eviction (section 4) in the same transaction. A failed pull deletes the temporary directory.
4. **Scan**: one `scan` job per (platform image, enabled scanner), run by the single worker, one at a time. Section 7.
5. **Convert**: parse the scanner JSON into `scanner_findings` for that run and recompute the merged `cve_findings` of each tag whose current digest includes the platform, in one transaction ([cve-lifecycle.md](cve-lifecycle.md), "Merged view"). Each run is kept; the latest `done` run per (platform image, scanner) is the one the merged view reads.
6. **Publish**: when every enabled scanner's run for every platform of the source's newest image has ended, one `publish` job reads the labels from the pulled config (`config.Labels`, the rules in [integrations.md](integrations.md), "OCI labels", unchanged; for a multi-platform image the first scanned platform's config is used, because labels are image-level metadata), builds one merged SARIF, uploads it and runs the issue rules. Decided (spec author, spinoff): findings are merged across platforms and scanners by (CVE id, package) into one result; the platforms that report a result are added to its property bag as `harborgate/platforms`. A failed run does not hold the SARIF back, and it holds issue closing open, as the existing rule says ([cve-lifecycle.md](cve-lifecycle.md), #224 d14). A missing `org.opencontainers.image.revision` fails the publish with the existing clear error.
7. Decided (spec author, spinoff): publish and issue updates run for the source's newest image only (section 9, newest image). Older images' scans update their tag's `cve_findings` but upload nothing.

Fixed error strings. A job's `last_error`, an alert and the Sync jobs API carry only these, never a registry body, URL, header or scanner stderr.

| Cause | `last_error` |
| --- | --- |
| Registry unreachable, TLS or network error, or an address or redirect check refused | `registry could not be reached` |
| Registry answers 401 or 403 | `registry rejected the credentials` |
| Repository or tag not found (404) | `image not found in registry` |
| Registry 429 | deferral (`Retry-After`, cap 1 hour, `attempts` unchanged) |
| `docker.io` refuses an anonymous pull for the rate limit (decision 40) | `docker hub rate limit reached` (a failure retried on the backoff, not a deferral) |
| Any other non-2xx | `registry returned status N` |
| Blob digest mismatch | `image content did not match its digest` |
| Pull over the cap | `image is larger than the allowed size` |
| Free disk below the minimum | `not enough disk space` |
| Layout evicted before a scan could start | `image is no longer stored` |
| Scanner timed out | `scanner timed out` |
| Scanner output over the cap | `scanner output too large` |
| Scanner exited non-zero | `scanner failed` |
| Scanner output unreadable | `scanner output not recognised` |
| Scanner database missing | `scanner database not available` |

The `docker hub rate limit reached` error is shown through a fixed catalog message (key `errors.dockerHubRateLimited`) that asks for a Docker Hub credential. Decided (spec author, spinoff): the English text is "Docker Hub is limiting anonymous pulls. Add a Docker Hub credential to this source to raise the limit." The user can change the wording. UNVERIFIED: that Docker Hub signals an anonymous rate limit with `429` (section 15, item 2); until checked, the mapping from the registry answer to this error is not fixed. After the 8th attempt the job fails and raises the sync-failed alert with the same fixed error.

## 7. Scanner processes

- Decided (spinoff 5): Trivy and Grype run out of process. The app image stays `FROM scratch`. The app calls pinned scanner executables by absolute path; no shell, no `PATH` search.
- Pinning (repo pinning rule): every scanner image or binary is pinned by image digest (`@sha256:...`) or by release version plus the SHA-256 of the release archive. Never a floating tag such as `latest`. Each pin carries a Renovate comment as in [testing-and-ci.md](testing-and-ci.md), "Pinning (d3) and updates". The pins in that file today are Grype `v0.121.2` and Trivy `v0.76.2`; the implementation checks the newest release, pins it and records the digest. The scanner version in use is stored with every run.
- How the executables reach the app without a Docker socket (copied into the image, or supplied on a read-only volume from the pinned scanner images) is not fixed by decision 5. It is open item 3 in section 15.
- Command line (inputs, flags, exit codes, JSON fields) is UNVERIFIED (section 15, item 1). The rules below hold whatever the flags are.
- Offline scan: a scan run downloads nothing. A scan run fails with `scanner database not available` if the database is missing. Only the `db_update` job (section 8) lets a scanner reach the network.
- Output: JSON for both scanners, written to a file. Decided (spec author, spinoff): JSON and not each scanner's own SARIF, because the merged view needs the fields per finding and one SARIF per image must come from the merged list.
- Limits (decision 19, defaults, operator-configurable): timeout 10 minutes per run; output 64 MB. On timeout the whole process group is killed, the output file is deleted and the run fails with `scanner timed out`. Output over the cap fails with `scanner output too large`; the cap is checked on the file before parsing, and the parser rejects deeply nested input. stdout and stderr are drained with a byte cap and are never stored or logged raw.
- Process rules: argument vector only (`tokio::process::Command`); the only variable argument is the layout directory generated from an id; no registry, repository or tag string in an argument, a file name or the environment; an empty environment plus a fixed allow-list (cache and home under `scanner-cache`, locale, offline settings), so `HARBORGATE_ENCRYPTION_KEY` and `HARBORGATE_OLD_ENCRYPTION_KEY` never reach the child; same user as the app (65532) with no extra capabilities; reads the layout and writes the output file and the cache only; one scanner process at a time; the child is killed on drop and a startup sweep removes temporary files in `scanner-cache`. One container cannot isolate one child's network; that is a stated limitation, not a guarantee.
- Readers are strict. Trivy: `SchemaVersion` must be `2` (Verified 2026-11-09, Trivy reporting documentation example), otherwise `scanner output not recognised`. Grype: the report must be a JSON object with a `matches` array. The field names inside are UNVERIFIED (item 1).
- Severity: compared case-insensitively and stored upper-case as `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`; `Negligible` maps to `LOW`, anything else to `UNKNOWN` ([cve-lifecycle.md](cve-lifecycle.md)).
- Scanner identity is the fixed key `grype` or `trivy`, with the stored version. The merge key, merged fields and order are unchanged ([cve-lifecycle.md](cve-lifecycle.md), "Merged view").
- Until the exit codes are verified, any non-zero exit is `scanner failed`.

## 8. Database refresh and rescan

- Decided (spinoff 4): the Trivy and Grype vulnerability databases refresh once a day. A `db_update` job per scanner runs on a 24-hour schedule, recorded in `job_runs` (`job_kind = 'db_update'`). It is the only job that reaches the network for a scanner, and only to the database location. Verified (2026-11-09, earlier draft): Trivy publishes its database at `ghcr.io/aquasecurity/trivy-db` and `--db-repository` can point elsewhere. Verified (2026-11-10, Trivy v0.76.2 and Grype v0.121.2, decisions 28-29): the update commands are `trivy image --download-db-only` and `--download-java-db-only` with `TRIVY_CACHE_DIR`, and `grype db update` with `GRYPE_DB_CACHE_DIR`. The build time is read from Trivy's `db/metadata.json` (`UpdatedAt`) and from `grype db status -o json` (`built`). Grype's database is about 3 GB, so the first update takes minutes.
- After an update the job compares the database's build time (or version) with `scanner_databases.built_at`, the value stored for that scanner. If the database is newer, it stores the new value and, in the same transaction, queues one `scan` job (trigger `db_update`) for every `stored` platform image and that scanner (decision 4, decision 17). Decided (spec author, spinoff): only the scanner whose database changed rescans, because the other scanner's result cannot change. If the database is not newer, nothing is queued.
- Rescans are keyed on the platform digest. Each rescan is a new `scan_runs` row; earlier runs are kept as history. Evicted images are not rescanned (their layout is gone); their last findings stay as they were.
- After the rescans of an image end, its tags' `cve_findings` are recomputed (step 5 of section 6), and a `publish` job is queued for a source's newest image only, so a CVE added or fixed by the new database updates Code Scanning and the issues.
- A database refresh that fails leaves the old database in use, fails the `db_update` job with the existing retry rules, and raises the sync-failed alert after the 8th attempt. A scan never starts on a missing database.
- Concurrency: rescans queue behind pulls and scans in the single worker. Eviction (section 4) still protects every queued or running scan.

## 9. Data model

A fresh schema in one `backend/migrations/0001_init.sql` (decision 21). There is no import from an existing HarborGate database and no upgrade path. Decided (spec author, spinoff): at startup, and in `harborgate restore` before it replaces anything, a database file that contains a `repo_mappings` table (a HarborGate `main` database) is refused with the fixed error `this database was created by HarborGate and cannot be used by this version`. Reason: opening it would silently skip the migration and break on the first query. SQLx offline metadata is regenerated.

### Kept from [database.md](database.md), with the stated changes

| Table | Change |
| --- | --- |
| `system_config` | Kept. New keys: `images.max_stored`, `scanners.enabled`, and the limit keys of section 13. |
| `users` | Kept. |
| `user_credentials` | GitHub only. `service_type`, `base_url`, `username` dropped. |
| `github_issues` | Kept; `sync_report_id` becomes `publish_report_id` (`ON DELETE SET NULL`). |
| `cve_acceptances` | Kept; `mapping_id` becomes `source_id`. |
| `audit_log`, `alert_channels`, `alert_deliveries` | Kept. |
| `job_runs` | Kept; `job_kind` values `cleanup`, `retention`, `discover`, `db_update`. |
| `sync_jobs` | Kept; `mapping_id` becomes nullable `source_id` (a `db_update` job has none). Payload `kind`: `discover`, `pull`, `scan`, `publish`, `db_update`. Payloads hold ids and the tag only, never a token. |

Removed: `repo_mappings`, `project_webhooks`, `project_webhook_unmatched`, `picker_hidden_items`, `harbor_scanners`, `scanner_reports`, `project_scanner_locks`, `sync_reports`.

### New tables

Decided (spec author, spinoff), each following from decisions 1 to 18.

```sql
-- Registries. Defaults inserted by the migration; host is canonical.
CREATE TABLE IF NOT EXISTS hubs (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL UNIQUE,            -- 'ghcr.io', 'docker.io', or custom; the only identifier and name (decision 45)
    pull_endpoint TEXT,                   -- custom hubs only; NULL means the stored host (decision 44)
    kind TEXT NOT NULL CHECK (kind IN ('default', 'custom')),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (pull_endpoint IS NULL OR kind = 'custom')
);

-- Where an image is and where its results go. Replaces repo_mappings. user_id is the owner.
CREATE TABLE IF NOT EXISTS image_sources (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hub_id TEXT NOT NULL REFERENCES hubs(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,             -- full path; the first segment is the namespace (decision 33); no project column
    tag_value TEXT NOT NULL,              -- exact tag, or a pattern with * or ?
    github_cred_id TEXT NOT NULL REFERENCES user_credentials(id) ON DELETE RESTRICT,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    auto_create_issues BOOLEAN NOT NULL DEFAULT FALSE,
    min_issue_severity TEXT NOT NULL DEFAULT 'CRITICAL' CHECK (min_issue_severity IN ('CRITICAL', 'HIGH')),
    last_discovery_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (hub_id, repository, tag_value)  -- source identity (decision 37)
);

-- At most one credential per source (decision 35). No hub-level or namespace-level credential.
CREATE TABLE IF NOT EXISTS source_credentials (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL UNIQUE REFERENCES image_sources(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    encrypted_token TEXT NOT NULL,        -- "v1:", AAD source_credentials:encrypted_token:<id>
    expires_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One image per (hub, repository, top-level digest): an index or a single manifest.
CREATE TABLE IF NOT EXISTS images (
    id TEXT PRIMARY KEY,
    hub_id TEXT NOT NULL REFERENCES hubs(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,
    digest TEXT NOT NULL,                 -- sha256:<hex>
    is_index BOOLEAN NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (hub_id, repository, digest)
);

-- Which digest a source's tag pointed to, and when discovery first saw it.
CREATE TABLE IF NOT EXISTS tag_observations (
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    first_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (source_id, tag, image_id)
);

-- One platform manifest = one OCI layout on disk. Kept after eviction.
CREATE TABLE IF NOT EXISTS image_platforms (
    id TEXT PRIMARY KEY,
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,               -- os/arch[/variant]
    platform_digest TEXT NOT NULL,        -- sha256:<hex> of the platform manifest
    state TEXT NOT NULL CHECK (state IN ('queued', 'pulling', 'stored', 'evicting', 'evicted', 'failed')),
    size_bytes INTEGER,
    pulled_at INTEGER,                    -- set when 'stored'; the eviction clock
    evicted_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (image_id, platform_digest)
);
CREATE INDEX IF NOT EXISTS idx_image_platforms_evict ON image_platforms (state, pulled_at, id);

-- Per scanner: the vulnerability database in use and when it was built.
CREATE TABLE IF NOT EXISTS scanner_databases (
    scanner TEXT PRIMARY KEY CHECK (scanner IN ('grype', 'trivy')),
    scanner_version TEXT,
    built_at INTEGER,
    checked_at INTEGER
);

-- One scan of one platform image by one scanner. Append-only history.
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    image_platform_id TEXT NOT NULL REFERENCES image_platforms(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL CHECK (scanner IN ('grype', 'trivy')),
    scanner_version TEXT,
    db_built_at INTEGER,
    trigger TEXT NOT NULL CHECK (trigger IN ('first_pull', 'tag_moved', 'db_update')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
    sync_job_id TEXT REFERENCES sync_jobs(id) ON DELETE SET NULL,
    started_at INTEGER,
    finished_at INTEGER,
    error TEXT                            -- one fixed string from section 6
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_current ON scan_runs (image_platform_id, scanner, status, finished_at);

CREATE TABLE IF NOT EXISTS scanner_findings (
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    package TEXT NOT NULL DEFAULT '',
    version TEXT,
    fixed_in_version TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    cvss_v3 REAL,
    description TEXT,                     -- at most 4,000 characters
    PRIMARY KEY (run_id, cve_id, package)
);

-- SARIF upload record per published image. Replaces sync_reports.
CREATE TABLE IF NOT EXISTS publish_reports (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    image_id TEXT REFERENCES images(id) ON DELETE SET NULL,
    sync_job_id TEXT REFERENCES sync_jobs(id) ON DELETE SET NULL,
    image_tag TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    commit_sha TEXT,
    vulnerability_summary TEXT NOT NULL,  -- JSON
    sarif_status TEXT NOT NULL CHECK (sarif_status IN ('pending', 'success', 'failed')),
    github_sarif_id TEXT,
    error_message TEXT,
    synced_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- cve_findings: as today, mapping_id -> source_id, harbor_repository dropped,
-- UNIQUE (source_id, image_tag, cve_id). The merged view of the tag's current image,
-- across its platforms and scanners.
```

- Source identity (decisions 33, 37): a source is identified by hub, repository and tag value, and `UNIQUE (hub_id, repository, tag_value)` enforces it. The same repository on two hubs is two sources, each with its own tag observations, findings, acceptances, alerts (its own Code Scanning category, below) and issue rows. A second source with the same three values is `409 conflict`. Decided (spec author, spinoff): the key has no user, as the old `UNIQUE (harbor_base_url, harbor_project, harbor_repository)` had none, so two users cannot register the same source. The user can overturn this. The namespace is the first path segment of `repository`; it is not a column and no table holds it.
- Retention: `publish_reports` and `scan_runs` follow the existing 90-day rule (by `synced_at`, `finished_at`), except that the latest `done` run per (platform image, scanner) is never deleted, because it carries the findings the view and the issue rules read. `sync_jobs` and `job_runs` 90 days, `alert_deliveries` 30 days, `audit_log` 365 days, unchanged. `images`, `tag_observations` and `image_platforms` are not under age retention (they are the "already scanned" memory).
- Deleting a source removes its `tag_observations`, `cve_findings`, `publish_reports`, acceptances and `source_credentials` row. Images, platforms and runs that no remaining source observes are deleted and their layouts removed. GitHub issues stay open and are listed in the `source.delete` audit row, as for a deleted mapping today.
- Audit vocabulary. Removed: `mapping.*`, `project_webhook.*`, `artifact.remove`. Added: `hub.create`, `hub.delete`, `source.create`, `source.update`, `source.delete`, `source.scan`, `image.evict` (actor `system`; `details` has hub, repository, platform digest, never a path with a secret), `settings.change` (scan limits and retention; `details` old and new values), plus the existing `credential.*` for source credentials (target names the source's hub and repository, never the token). All other existing actions are kept.

### CVE lifecycle wording

The rules in [cve-lifecycle.md](cve-lifecycle.md) (merged view, close, reopen, manual-close honouring, marker and adoption, acceptance, dashboard counts) are kept (decision 20). Harbor words become:

| Existing wording | Spinoff wording |
| --- | --- |
| mapping, Harbor repository | image source |
| tracked tag set | tags observed for the source whose current image has at least one `done` scan run |
| newest scanned digest, latest `image_push_time` | Decided (spec author, spinoff): the source's newest image is the one whose `tag_observations.first_seen_at` for that source is the latest. A registry has no push time and the config `created` field is not trusted. |
| every enabled scanner has a report for the newest digest | every enabled scanner has a `done` run for every platform of the newest image (an evicted platform counts through its last `done` run) |
| last 10 tags per mapping, 10-tag pruning | Removed. Findings are kept (decision 18); the image count rule is section 4. |
| Harbor deleted the artifact (#249) | Removed. |
| close and reopen comment scan name `<project>/<repository>:<tag>` | `<hub host>/<repository>:<tag>` (decision 36) |
| SARIF `artifactLocation.uri` and category (`harborgate/<harbor_project>/<harbor_repository>/`) | Decision 36: uri `<hub host>/<repository>`, for example `ghcr.io/nrosier/walley`; run id `harborgate/<hub host>/<repository>/`, so the category is `harborgate/<hub host>/<repository>` (trailing slash rule unchanged; the `harborgate` prefix is kept by decision 27). No project name appears. The spinoff has no Harbor history to keep, so its alerts start fresh. The same repository on two hubs gives two categories. Changing the prefix later creates new alerts (section 14). |
| issue table column "Harbor repository" | "Image" |
| scanner identity by Harbor UUID, `unknown` scanner | fixed keys `grype`, `trivy` |

## 10. API routes

Conventions, auth levels, the error envelope, lists and pagination are unchanged ([api.md](api.md)). State-changing routes need the CSRF header.

Rate limits. HarborGate has no default limit on authenticated routes; each route that calls an outbound service or starts work declares one explicitly. Values are the existing ones, reused: 60 requests per minute per user for routes that call a registry or GitHub for a list or test ([api.md](api.md), Pickers, Decided 2026-11-05, #126); one start per source per 5 minutes for a manual scan (Decided 2026-11-05, user, #131). Over the limit: `429` with `Retry-After` (RFC 6585, RFC 9110). Held in memory, cleared by a restart. The limited routes are marked "limited" below.

| Method | Path | Auth | Request and response | Status |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/hubs` | session | list of `Hub` (`id`, `host`, `pull_endpoint` or null, `kind`); no display name | 200, 401 |
| POST | `/api/v1/hubs` | admin, limited (60/min/user; resolves the host and the endpoint) | `{"host","pull_endpoint"?}` -> `Hub` (`kind` is `custom`; an omitted endpoint means the stored host) | 201, 400, 409, 422 (grammar, blocked address), 429 |
| DELETE | `/api/v1/hubs/:id` | admin | empty | 204, 404, 409 (a source uses it, or it is a default hub) |
| PUT | `/api/v1/image-sources/:id/credential` | session (owner) | `{"username","token","expires_at"?}` (token write-only) -> `{"source_id","username","expires_at"}`; on `ghcr.io` a token starting `github_pat_` is `422` (section 2) | 200, 201, 404, 422 |
| DELETE | `/api/v1/image-sources/:id/credential` | session (owner) | empty. On `docker.io` the source falls back to anonymous pulls and shows the no-credential note (decision 42); it is not blocked. On other hubs a failing pull shows `registry rejected the credentials`. | 204, 404 |
| POST | `/api/v1/image-sources/:id/credential/test` | session (owner), limited (60/min/user) | `{"repository"}` -> `{"ok","detail"}`, never the token; with no credential on the source it tests anonymously (decision 41) | 200, 404, 422, 429, 502 |
| GET, POST | `/api/v1/image-sources` | session | `Source` carries `has_credential` (never the token). List / create (`hub_id`, `repository`, `tag_value`, `github_cred_id`, `github_owner`, `github_repo`, `default_branch`, `auto_create_issues`, `min_issue_severity`) | 200, 201, 400, 404, 409, 422 |
| GET, PUT, DELETE | `/api/v1/image-sources/:id` | session (owner; admin read) | source / update / delete | 200, 204, 404, 409, 422 |
| GET | `/api/v1/image-sources/:id/tag-preview` | session (owner), limited (60/min/user) | `{"matches":[tag],"truncated"}`, names only, records nothing | 200, 404, 422, 429, 502 |
| POST | `/api/v1/image-sources/:id/scan` | owner or any admin, limited (1 per source per 5 min) | `{"queued": n}`, runs discovery now | 200, 404, 429, 502 |
| GET | `/api/v1/image-sources/:id/images`, `/api/v1/images` | session (owner; admin read) | list of images with per-platform `state`, `size_bytes`, `pulled_at`, per-scanner latest run (`status`, `version`, `error`, `db_built_at`); filters `state`, `source_id`, admin `scope=all` | 200, 404 |
| GET, PUT | `/api/v1/admin/scan-settings` | admin | `{"max_stored","scanners_enabled","scanner_timeout_s","scanner_output_max_bytes","pull_cap_bytes","min_free_disk_bytes"}` | 200, 401, 403, 422 |

Kept routes: auth, account, credentials (GitHub only; `service_type` removed from the body; the GitHub repository picker `GET /api/v1/credentials/:id/github-repositories` kept), `cves` (renaming `mapping` to `source`, Harbor parameters removed, `namespace` filter added: see below), `sync-jobs` (retry, failed count, purge-failed), dashboard (recent syncs become recent scans), admin (users, oidc, github-url, alert-channels, audit-log, jobs, backup, logs, log-level), `/healthz`. `GET /api/v1/admin/health` drops the Harbor and robot fields and adds: per-hub reachability, the pinned scanner versions found, the database build time per scanner, and free disk space of the store.

CVE list namespace filter (decision 38): `namespace` replaces the removed `project` filter on `GET /api/v1/cves` and `GET /api/v1/image-sources/:id/cves`. It takes one value, matched exactly and case-sensitively against the first path segment of the source's repository (so `nrosier` matches `nrosier/walley` and `nrosier/other`, on any hub; the Repository filter, which lists `<hub host>/<repository>`, narrows by hub). It is not split on commas, follows the other text filters' limits (at most 256 characters, no control character, otherwise `400 invalid_request`), combines with the other filters by AND, and is bound as a SQL parameter, never part of the SQL text. An empty value means no filter. The `q` search matches the CVE id, the package and the repository. The Harbor parameters `project`, `harbor_project` and `harbor_repository` are not read.

Removed: `/api/v1/webhooks/harbor/*`, `/api/v1/project-webhooks*`, `/api/v1/mappings*`, `/api/v1/credentials/:id/harbor-*`, `/api/v1/credentials/:id/source-suggestion`, `/api/v1/pickers/hidden*`.

## 11. UI

Every screen needs the user's design approval before it is built ([frontend.md](frontend.md); CLAUDE.md). Copy goes into the string catalog, English only. The rail becomes Dashboard, Sources, Images, CVEs, Sync jobs, then Admin and Account (needs approval).

- New: Sources list and form (hub select, repository, tag value with a live exact-or-pattern hint and a preview from `tag-preview`, GitHub target, issue settings); Source detail with an images table (tag, platform, state, pulled time, per-scanner scan state, database date) and a Scan now button; Images page (stored images, size, which is evicted next); Admin > Settings: Hubs and Scan settings (retention count, enabled scanners, the limits of section 13); the Source form and detail hold the source's registry credential (optional on Docker Hub, with the no-credential note when none is set; on `ghcr.io` a hint that only a classic token with `read:packages` works) and the test button; Account > Credentials keeps the GitHub credentials only. Hubs are listed by host alone, with the pull endpoint where one is set.
- Removed: the Harbor project and repository pickers, the project webhook proposal, the scheduled scan card, the scanner switch and restore states, the Admin Health Harbor rows, the CVE list Project filter and the `project` and `harbor_*` URL parameters. In place of the Project filter the CVE list has a Namespace filter (the first path segment of the repository, decision 38). The Repository filter lists `<hub host>/<repository>`. The "Found by" scanner column lists Grype and Trivy.

## 12. Security

### Outbound requests

- The rules of [security.md](security.md), "Outbound HTTP (SSRF)", apply to every hub host and every redirect hop (decision 12): HTTPS only; every resolved address must pass the deny-list (loopback, link-local, private, shared, reserved and multicast ranges listed there, including `169.254.169.254`); the check runs on the addresses actually connected to, not once at save time. The only change is that redirects are followed (section 3) with the check on each hop.
- Opt-out (decision 14): the environment variable `LOCALSCAN_ALLOW_PRIVATE_REGISTRIES` (provisional name), default empty, is a comma-separated list of hub hosts. A named hub may use plain HTTP and private addresses, and so may the pull endpoint of a named custom hub (decision 44). An endpoint of a hub that is not named gets no exemption. It is environment-only, not an admin setting, and applies to named hubs only: a redirect from a named hub to an unnamed private or HTTP host is refused. An empty value means off.
- Adding a hub is admin-only, because an entered host is an outbound destination for the whole instance.
- Names and tags are validated against the grammars before any request. A name outside the grammar is `422` with no request made.
- Manifests, configs and blobs are untrusted input: byte caps and digest verification while streaming (section 3).
- The `Authorization` header is never sent to a host other than the one that issued the challenge.

### Secrets

- Hub tokens, bearer tokens from a token service, `Authorization` and `Www-Authenticate` values, GitHub tokens and encryption keys are never logged, printed, traced, returned, put in a job row, alert, audit `details`, or sent over Server-Sent Events. A registry response body is never copied anywhere; only the fixed strings of section 6 are. The debug log records method, URL path without query, and status only.
- Tokens are held in memory only while a pull runs and are zeroized. They never enter a scanner's arguments, environment, working directory or cache. Scanners read local layouts only and never contact a registry.
- Key rotation must cover `source_credentials.encrypted_token` as well as `user_credentials.encrypted_token`, `alert_channels.config_encrypted` and the encrypted `system_config` values. A test enumerates every column marked encrypted so a new table cannot be missed.

### Tenancy

Users see only their own sources, credentials, images and findings; admins see all, read-only. Operational exceptions follow [security.md](security.md): an admin may start discovery for any source (using the source's own credential on the server, with no value shown), and retry or purge failed jobs. Hubs and scan settings are admin settings.

### Scanner processes

Section 7 holds the rules. A test starts a child that prints its environment and asserts the key variables are absent.

### Alerts

Alert rules are kept. A failed discover, pull, scan, publish or `db_update` job raises the existing sync-failed alert with a fixed `error` string. The webhook body field `mapping.harbor` becomes `source.image` (`<hub host>/<repository>`).

## 13. Configuration and limits

Decision 19 sets the defaults. All are operator-configurable. Decided (spec author, spinoff): they are `system_config` values edited by an admin in Admin > Settings, so they can change without a restart; the environment holds only things that grant reach (the registry opt-out) or locate files.

| Setting | Default | Source |
| --- | --- | --- |
| `images.max_stored` | 20 | decision 18 |
| `scanner.timeout_s` | 600 (10 minutes) | decision 19 |
| `scanner.output_max_bytes` | 64 MB | decision 19 |
| `pull.max_bytes_per_image` | 10 GB | decision 19 |
| `disk.min_free_bytes_before_pull` | 10 GB | decision 19 |
| `discovery.interval` | 1 hour | decision 16 (fixed; not operator-set) |
| `scanner_db.interval` | 24 hours | decision 4 (fixed; not operator-set) |
| tag list page size, page cap, cap on new digests per discovery | not set by the decisions; constants chosen at implementation and recorded as `Decided (spec author)` | none |

Decision 19 does not say whether MB and GB are decimal or binary. Decided (spec author, spinoff): stored in bytes, entered in the UI with an explicit unit, the defaults read as MiB and GiB (the larger reading, so the default is not stricter than the user may have meant).

Environment (new, provisional names): `LOCALSCAN_ALLOW_PRIVATE_REGISTRIES` (section 12); the paths or locations of the scanner executables (open item 3). Existing `HARBORGATE_*` variables are kept; `HARBORGATE_ALLOW_PRIVATE_HARBOR` is removed.

## 14. Name (provisional)

Decision 22: the name is decided later. `localscan` stays provisional. When the name is decided, these are renamed together, and only then: the `HARBORGATE_*` variables, the `LOCALSCAN_*` variables, the `__Host-harborgate_*` cookies, the SARIF tool name, the Code Scanning category prefix (changing it makes GitHub create new alerts), the issue label and the issue marker (changing the marker needs a re-adoption rule), the crate and image names. The `harborgate/*` HKDF labels are not renamed unless the user says so, because renaming changes the derived keys and breaks every stored ciphertext.

## 15. Open items

Each is asked exactly as written. None is decided.

1. Exact Grype and Trivy command-line behaviour for an OCI layout: the input form, the flag that disables database downloads during a scan, the exit codes, and the JSON field names. These are UNVERIFIED and need a test run. Details to settle: the input form (for Trivy, whether `trivy image --input <layout directory>` or another form is the call for a layout directory; for Grype, whether the form is `oci-dir:<path>` or another), the flag or setting that disables database downloads during a scan (Trivy: `--skip-db-update`, `--skip-java-db-update`, `--skip-check-update`, `--offline-scan` exist in the documentation; Grype: the name of its auto-update setting), the exit codes (whether a non-zero exit with a valid report is possible), and the JSON field names (Trivy `Results[].Vulnerabilities[]` with `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`, `Description`, `CVSS`; Grype `matches[]` with `vulnerability`, `artifact`, `fix`, and Grype's severity names). Also: the update commands for both databases, and how to disable Trivy's usage telemetry. Capture real reports as test fixtures.
2. The registry client's handling of Docker Hub's token service (the auth challenge flow) must be verified against the live registry before the client is built: the realm and service values, the scope string, how `docker.io` maps to `registry-1.docker.io`, the access-token scopes Docker Hub offers, and its behaviour with anonymous pulls and rate limits, including whether an anonymous rate limit is signalled as `429` (decision 40).
3. Not asked by the user, a gap in decision 5: the app image is `FROM scratch` and has no Docker socket, so it can only call a scanner that is a file it can execute. Should the pinned Trivy and Grype executables be copied into the app image (still `FROM scratch`, built from the pinned releases), or supplied on a read-only volume populated from the pinned scanner images, or run as separate sidecar containers the app reaches over a defined protocol? Until answered, section 7 fixes only the pinning, the absolute-path call and the process rules.
4. Not asked by the user, a gap in decision 3: attestation entries in an image index. The rule here is to skip entries with platform `unknown/unknown`. UNVERIFIED: whether that platform value is enough, or the annotation must be read.
5. Not asked by the user, a gap in decisions 36 and 37: two sources on the same hub and repository with different tag values (for example `1.*` and `latest`) share one Code Scanning category, `harborgate/<hub host>/<repository>`, because the category has no tag part, so the later SARIF upload for the category replaces the earlier one in Code Scanning. Should the category include the tag value, should such a pair be refused, or is the shared category intended?
6. Not asked by the user, a gap in decision 37 (separate alerts and issues): GitHub issues are keyed by GitHub repository and CVE, with the marker `harborgate:<CVE id>` (decisions 20 and 27). Two sources, for example the same repository on two hubs, that target the same GitHub repository therefore share one issue per CVE, which closes only when no source reports the CVE. Issues are separate only when the sources target different GitHub repositories. Is that the intended meaning of "separate issues", or must the issue key include the source?

## 16. Verification strategy

The spinoff has no GitHub issue yet. When one is created its body carries this list as `- [ ]` items, and it stays open until every box is ticked with evidence.

- [ ] The branch `spinoff-local-scan` is not merged to `main`, and a CI or review check prevents it.
- [ ] Step 1 did not land alone: the clean schema and the Harbor removal arrived together with the sync and scanner steps (decision 34), and the branch built and passed its gates at each merge.
- [ ] No Harbor code, route, table, setting, string or doc reference remains (case-insensitive search, outside this spec and the changelog). No Docker daemon, socket or `bollard` dependency exists. No project table or project column exists.
- [ ] `0001` creates exactly the tables of section 9 and none removed; a `main` database and a `main` backup are refused with the fixed error.
- [ ] A default install has `ghcr.io` and `docker.io`; neither can be removed; a custom hub can be added and removed; a hub in use cannot be removed.
- [ ] A hub is identified and shown by its host alone: the `hubs` table, the API and the UI have no display name or label.
- [ ] A custom hub with a pull endpoint sends its registry requests to the endpoint, and with none set to the stored host; the stored host stays its name; the endpoint passes the address rules; a default hub cannot have one.
- [ ] A source credential is a `v1:` ciphertext with the right AAD, is never returned, and key rotation re-encrypts it (a test enumerates all encrypted columns). A source has at most one credential, and there is no hub-level or namespace-level credential or default.
- [ ] A `ghcr.io` credential is a classic personal access token with `read:packages`; a token starting `github_pat_` is refused with `422`; no text allows a fine-grained token.
- [ ] A Docker Hub source with no credential pulls anonymously and is scanned. A refused anonymous pull for the rate limit shows the fixed catalog message that asks for a Docker Hub credential, sets `last_error` to `docker hub rate limit reached`, and retries on the backoff until a later attempt succeeds or the 8th fails.
- [ ] The credential test works like the test for other hubs, returns `ok` or the failure and never the token, and also runs anonymously when the source has no credential.
- [ ] Removing a Docker Hub credential leaves the source unblocked, pulls anonymously, and shows the no-credential note.
- [ ] A source is identified by hub, repository and tag value: the same repository on two hubs is two sources with separate tag observations, findings, acceptances and Code Scanning categories; a duplicate (hub, repository, tag value) is `409`.
- [ ] Registry client against a fake registry: anonymous and Bearer-token pulls, tag paging by `Link`, a redirect to another host with `Authorization` dropped, a redirect to a private address refused on that hop, a hub host that re-resolves to a private address after the first check, a digest mismatch, a pull over the cap, a free-disk refusal. The Docker Hub flow, anonymous and with a credential, passes against the live registry (item 2).
- [ ] The plain-HTTP and private-address opt-out is off by default, applies only to named hubs, and does not extend to a redirect target that is not named.
- [ ] A source keeps the repository's full path and its namespace is the first path segment.
- [ ] Tag matching: the examples in section 5 pass; only `*` and `?`; a digest reference and a bad grammar are refused; case-sensitive.
- [ ] Discovery runs hourly per repository; a new tag and a moved tag each queue one pull; two concurrent discovery runs queue one; a known digest (stored or evicted) is not pulled again.
- [ ] A multi-arch index yields one stored image and one scan per platform; attestation entries are skipped; findings are stored per platform and merged for the tag.
- [ ] Eviction with the maximum at N removes the oldest by `pulled_at` and deletes the layout only; findings, runs and history remain; an image with a running or queued scan is never removed; a crash during eviction is repaired at startup.
- [ ] A database refresh that finds a newer database rescans every `stored` platform image by digest with the changed scanner and publishes for each source's newest image; an unchanged database queues nothing; an evicted image is not rescanned.
- [ ] Both scanners run on fixture images from real captured reports; findings merge on (CVE id, package); `SchemaVersion` other than 2 fails with the fixed error; the limits (timeout, output cap) kill and fail the run with the fixed strings.
- [ ] Scanner process rules: no shell, absolute path, clean environment (key variables absent), process group killed on timeout, nothing downloaded during a scan, a restart mid-scan recovers.
- [ ] The SARIF `artifactLocation.uri` is `<hub host>/<repository>` and the category is `harborgate/<hub host>/<repository>`, with no project name and no Harbor-era alert carried over.
- [ ] The merged SARIF validates against SARIF 2.1.0 (`sarif-validate`); the upload, issue create, close, reopen and manual-close honouring behave as in [cve-lifecycle.md](cve-lifecycle.md); a failed scanner or platform never closes an issue.
- [ ] No token, registry header or key appears in a log, job row, alert, API response or SSE stream (log-capture test across a full pull and scan with a canary token).
- [ ] Every limited route in section 10 returns `429` with `Retry-After` over its limit; a private-address hub host is refused.
- [ ] Scanner executables and images are pinned by digest or by version plus checksum, with no floating tag; the app image is `FROM scratch`; the `docker-smoke` check passes.
- [ ] The CVE list has no Project filter and has a Namespace filter on the first path segment of the repository; the old Harbor URL parameters are not read.
- [ ] Every new screen has a user-approved design before it is built, and all text is in the string catalog.
- [ ] Open items 1 to 6 are each resolved or restated.
