# Changelog

All notable changes are recorded here. Versions follow semantic versioning.

## Unreleased

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
