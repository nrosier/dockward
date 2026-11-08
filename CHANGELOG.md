# Changelog

All notable changes are recorded here. Versions follow semantic versioning.

## 0.15.0 - 2026-11-08

### Added
- CVE page control bar (#257, PR #258, PR #260): one search field; severity, status and GitHub-issue pills; one row of comboboxes with Mapping as the only scope control; the Tags n of m column; a confirmation before Create issue; URL state that keeps the old parameters working; and admins see every tenant's CVEs.

### Changed
- The status=open filter excludes accepted CVEs (#257, PR #260).
- The My Mappings / All Mappings toggle is removed; Mapping is the only scope control (#257, PR #260).
- A spec was added for the CVE page control bar (#257, PR #258).

## 0.14.0 - 2026-11-08

### Added
- Purge of failed sync jobs: a backend endpoint and a Purge failed jobs button on the Sync jobs page (#243, PR #245, PR #246).
- Dashboard card for accepted CVEs (#247, PR #253).
- Favicon from the HarborGate house mark (PR #248).
- Security scanning workflow with Syft, Grype and Trivy (#227, PR #252).

### Changed
- HarborGate removes the data of artifacts Harbor deleted. When Harbor no longer has the artifact for a tag (found on a poll or pull, or by a 404 in a sync or resolve job), the tag's findings, sync reports and sync jobs are deleted, and the scanner reports too when no other tag of the mapping holds the digest. GitHub issues and uploaded SARIF are kept. This supersedes the #197 rule: the done note "artifact no longer in Harbor" is no longer written for those artifacts, and existing rows keep it (#249, PR #254).
- No database migrations were added since 0.13.0; the latest remains 0010.
- Specs were added for purging failed jobs, the accepted-CVE card and the removal of deleted artifacts (#243, #247, #249, PRs #244, #250, #251).

## 0.13.0 - 2026-11-08

### Added
- Scanner reports: HarborGate stores one report per mapping, image digest and Harbor scanner, and merges them into one finding per CVE and package. SARIF results carry `harborgate/scannerCount` and `harborgate/scannerNames`, and issue bodies carry a "Found by N scanner(s)" line (#224, PR #235, PR #236, PR #237, PR #238).
- Scan launch with a chosen scanner: `GET /api/v1/mappings/:id/scanners` and `POST /api/v1/mappings/:id/tags/:tag/scan` run a scan with one Harbor scanner and restore the project's previous scanner afterwards (#224, PR #236, PR #237).
- `GET /api/v1/mappings/:id/tags/:tag/scans` returns the per-scanner scan state of a tag (#224, PR #238).
- `GET /api/v1/mappings/:id/tags` returns the tracked tags of a mapping with last scan time and open CVE count (#224, PR #240).
- Scans card on the mapping edit page: one row per tracked tag, the report state per scanner, and a Scan button with a scanner picker (#224, PR #239, PR #240).
- Scheduled scans run once per enabled scanner, and a webhook from another scanner fetches that scanner's report (#224, PR #238).
- Newest-digest CVE view: the CVE list and the dashboard count only the tags of each mapping's newest scanned digest. The CVE detail page lists older tags as "Older tag, not counted" (#196, PR #241).

### Changed
- Docker images are pushed to GHCR only on `v*` tags. A `v*` tag publishes `X.Y.Z`, `X.Y` and `latest`; `latest` moves to each release. Pushes to `main` push nothing, and the `sha-<7 hex>` tag is dropped (#227, PR #223).
- A CVE issue closes only when every enabled scanner has a report for the newest digest and none reports the CVE (#224, PR #237).
- The `Affected tags:` line of an issue lists every tracked tag that still reports the CVE (#196, PR #241).
- A scanner removed from Harbor has its reports deleted, and the findings, SARIF and issues follow (#224, PR #238).
- Migration 0009 adds `harbor_scanners` and `scanner_reports`; existing reports become the `unknown` scanner until the next normal sync (#224, PR #235).
- Migration 0010 adds the `newest_digest_tags` view (#196, PR #241).
- Specs for scanner reports, the newest-digest view, the security scanning workflow and the Grype reader were added or updated (#224, #196, #227, PRs #225 to #234).

## 0.12.5 - 2026-11-07

### Added
- Scheduled Harbor scan per mapping: off by default, daily or weekly at a UTC time. HarborGate asks Harbor to scan the newest tagged image and the Sync jobs page lists only the CVEs new for that image (#191, PR #221).
- Custom GitHub API and web base URL per instance, set by the admin in Settings > GitHub; the API base may carry a path such as `/api/v3`, and empty means github.com (#184, PR #206, PR #217).
- Mappings can be sorted by Harbor source, GitHub target, open issues and last sync, with sortable column headers (#190, PR #208, PR #209).
- After a mapping save, an inline banner proposes a project webhook when the Harbor project has none (#179, PR #219).
- HarborGate issues carry the `areai:security` label and a severity label (none for Unknown), and are titled "<CVE id> <package>"; adopted issues are renamed and get missing labels (#192, PR #214).

### Changed
- Several Harbor repositories may target one GitHub repository; issues are shared per GitHub repository and CVE. Migration 0007 drops the unique GitHub target rule (#185, PR #216).
- The picker greys out Harbor repositories that are already mapped, without naming the mapping or its owner (#189, PR #220).
- The Harbor robot needs Scan Create for scheduled scans; `docs/SETUP.md` lists it (#191, PR #221).
- Migration 0008 adds the scan schedule to `repo_mappings` and `cve_ids`, `new_cve_ids` to `sync_reports` (#191, PR #221).
- `docs/SETUP.md` documents the custom GitHub base URL setting (#184, PR #217).

### Fixed
- A sync or resolve job for an image deleted from Harbor is marked done with the note "artifact no longer in Harbor", not failed, with no retry or alert (#197, PR #203).
- Saving a duplicate Harbor repository shows one fixed message and no longer names the other mapping (#180, PR #218).

## 0.12.4

### Fixed
- CVE issues close when the newest scanned digest is clean, not when every tracked tag is clean (#196, PR #200).
- A manual close of a HarborGate issue on GitHub is honoured: HarborGate does not reopen it while the CVE stays, and posts no close comment on an issue already closed (#196, PR #200).

### Changed
- Migration 0006 adds `sync_reports.image_push_time` and `github_issues.closed_manually` (#196, PR #200).

## 0.12.3

### Fixed
- A child image of a tagged multi-arch index is marked done, covered by its parent index, instead of failing (#132, PR #194).

## 0.12.2

### Fixed
- Read OCI labels from Harbor's config and from index children, so multi-arch images sync (#132, PR #182).

## 0.12.1

### Changed
- The mapping screen is redesigned as side-by-side cards (#167).

### Fixed
- The mapping popup is no longer clipped, and the Harbor repository is disabled until a project is typed (#167).
- Every mapping save error shows fixed text (#167).

## 0.12.0

### Added
- Untagged scan events are resolved by the worker: an untagged `SCANNING_COMPLETED` vulnerability event with a valid digest stores one resolve job and returns 202, and the worker reads the digest's tags from Harbor (Artifact Read), keeps the newest 10 by push time, and queues one sync per tag (#132).
- A resolve rate limit (429) defers the job by `Retry-After`, or 5 minutes without it, capped at 1 hour, without using an attempt (#132).
- The job API reports each job's kind, `sync` or `resolve` (#132).
- Operators can verify the published image with cosign, documented in `docs/SETUP.md` (#171, #172).

### Changed
- The Harbor poller caps each digest to its newest 10 tags, the same cut as the resolve job (#132).
- A vulnerability event with a missing or invalid digest returns 400 (#132).
- Project webhook routing is scoped to the webhook's own Harbor project; events for other projects return 202 with nothing stored (#145).
- Unmatched repository names must pass Harbor's name rule and be at most 255 characters (#145).
- Project webhook create checks the secret before reading the body and the mapping budget (#145).
- `project_webhooks.rotated_at` no longer has an insert-time default (migration 0005) (#145).
- Every Docker build requires a `REVISION` build argument and sets the `org.opencontainers.image.revision` label, in both CI build steps (#169).
- `.hg-local` is git-ignored (#170).

### Fixed
- `docs/SETUP.md` no longer says untagged pushes are ignored (#132).
- Project webhook transfer, unmatched visibility and rotate-secret guards are covered by tests (#145).

### Security
- The publish job signs the image digest keyless with cosign and verifies the signature on the same digest, failing the job if verification fails (#171).
- `secret_hash` is redacted in the `ProjectWebhook` Debug output (#145).

## 0.11.0

### Added
- Mapping pickers: choose the Harbor project and repository and the GitHub repository from lists instead of typing them (#126).
- The mapping form suggests the GitHub source repository from the image's source label (#126).
- Per-instance hide and restore of picker items, with a Hidden tab to restore them (#126).
- Project webhook setup guide in `docs/SETUP.md` (#132).

### Changed
- The picker backend caps the upstream response body while reading it, and marks a Harbor list as truncated only when a further item exists (#126).
- A Harbor identity 5xx answers 502 instead of 422, and the picker 422 error carries a fixed detail code (#126).
- The setup guide documents the Repository List and Repository Read robot permissions (#126, #159).

### Fixed
- The suggested image tag is validated against the OCI tag grammar, and an artifact digest that is not `sha256:<64 hex>` is refused (#126).
- Picker cache ordering: cache slots are dropped and the generation bumped under one lock, a fill is not cached if its credential was updated meanwhile, and a deleted user's cache entries are dropped (#126).
- Hidden picker items are keyed by Harbor base URL (#126).

### Security
- The picker refuses an oversized upstream body before buffering it whole (#126).

## 0.10.1

### Fixed
- The app reports its real version. 0.10.0 shipped with the version still set to 0.9.1 in the code; this release sets it to 0.10.1 (the 0.10.0 image reports 0.9.1).

## 0.10.0

### Added
- Project webhook owner page and management API, with one Harbor webhook per project, rotation and unmatched repository counts (#132, #145).
- Manual scan pull for a mapping, a Pull scans button on the mapping page, and a 5-minute cooldown (#131).
- Admin application log page and an admin log level control that reverts after 30 minutes. Secrets are never logged (#136).
- All-severity CVE list with filters for severity, status, package, tag, project and repository, and manual GitHub issues for any severity, with a confirmation for LOW and UNKNOWN (#129).
- `PUT /api/v1/mappings/:id` for partial mapping edits (#130).
- Retry state and error shown for failing sync jobs (#135).
- A startup note that the image revision label is set explicitly (commit cd00199, no issue).

### Changed
- A missing image revision label is a permanent failure and is not retried (#141).
- The webhook auth value is shown as the full Authorization header, ready to paste into Harbor.
- The Account page is split into Profile, Appearance and Credentials tabs.
- The admin setup button explains why it is disabled when the passwords differ.

### Fixed
- A sync job no longer retries forever on a missing revision label (#141).
- A mapping update rebuilds from the locked row (#130).

## 0.9.1

### Fixed
- The container serves the web app. In 0.9.0 the release binary embedded no frontend files, so `/` returned a 404. The frontend is now embedded (#122).

### Added
- A startup log line with the version, bind address and non-secret settings. No key, token or secret is logged (#122).

## 0.9.0

First release candidate for HarborGate. Everything below is built on `main`; the live smoke test against real Harbor and GitHub (#43) is still open.

### Added
- Harbor webhook receiver and polling backup every 15 minutes, with digest dedupe (#28).
- Trivy-to-SARIF 2.1.0 converter, validated against the vendored schema (#26).
- GitHub code scanning SARIF upload and processing status (#27).
- Sync job handler that moves a Harbor report to SARIF upload (#53).
- GitHub issue lifecycle: create, adopt, close and reopen per CVE, and a manual issue route (#30, #54).
- Per-tag CVE findings with a 10-tag limit and fixed-detection (#29).
- CVE accept and un-accept with expiry (#31), and the CVE read APIs (#32).
- Jobs, admin jobs and dashboard read APIs (#55).
- Alert channels with encrypted config (#56), webhook and SMTP senders (#57), and alerts for failed syncs and new CRITICAL CVEs with 24 h dedupe (#33).
- Encrypted admin backup (HGBK1), offline restore and `harborgate rotate-key` (#40, #58, #41).
- Retention and cleanup worker with job_runs history (#34).
- Admin health route with per-target checks (#69).
- Frontend: shell, theme, string catalog, API client, login and setup pages, the Dashboard, Mappings, CVEs and Sync jobs pages, and the Account page with admin tabs (#36, #37, #38, #39).
- Docker image published by digest, scanned, then promoted with tags and signed (#3).

### Security
- Outbound HTTP through one checked client with an SSRF deny-list, no environment proxies, and resolved-address checks (#47, #57).
- Rate-limit and throttle state bounded (#46).
- Argon2 on the blocking pool with a concurrency cap (#45).
- OIDC sessions revoked on refused sign-in, with a race-safe first login (#49).
- Job worker supervised with panic isolation and a crash-loop limit (#48).
- Input origins, Harbor paths and names normalised, and API responses no-store (#50).
- Crypto dependencies upgraded (hmac, hkdf, sha2, aes-gcm, argon2, rand) with known-answer tests (#112, #113, #114).

### Fixed
- Shutdown drains within one 8 s budget, and manual sync retry is audited (#52).
- Harbor client probes the Issues permission on save (#21).
- Runtime image installs ca-certificates for outbound TLS (#90).
- Container uses Alpine 3.24 with a HEALTHCHECK (#2).

### Documentation
- Operator setup and restore docs aligned with the specs (#42), and the approved v1 screen designs recorded (#35).
