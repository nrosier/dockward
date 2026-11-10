# Spinoff decisions (localscan, provisional name)

Recorded 2026-11-09 from dialogue with the user. Binding for the spinoff spec.

1. Harbor is removed entirely. The image source is a hub (registry host), a repository, and a tag or pattern.
2. Images are reached through the registry API into OCI image layouts on disk. No Docker daemon or socket is used.
3. Multi-arch tags: every platform in the image index is scanned, and results are stored per platform.
4. Periodic scans: the Trivy and Grype databases refresh daily. When a database is newer, every retained image is rescanned by digest.
5. Scanners run out of process. The app image stays FROM scratch and calls separate, pinned Trivy and Grype images or binaries.
6. Output stays: SARIF upload to Code Scanning and GitHub issues, as HarborGate does today.
7. Hubs: ghcr.io and hub.docker.com are included by default. Custom hubs can be added. Credentials are encrypted per hub.
8. Tags: an exact tag or a pattern. Each match is pulled and scanned once per digest.
9. Retention: an operator-set maximum number of stored images. The oldest is removed when exceeded. Never remove an image with a running scan.
10. The name is not decided. Use `localscan` only as a provisional working name.

## Answers from the second dialogue round (2026-11-09)

11. Docker Hub is stored as `docker.io`. Pulls go to `registry-1.docker.io` internally.
12. Registry client: our own client on reqwest. Redirects are followed, and the resolved address is checked on every hop.
13. Default hubs (ghcr.io and Docker Hub) are not removable by an admin. Admins can add and remove custom hubs.
14. Private or plain-HTTP registries: allowed through an environment opt-out, off by default, for named hubs only.
15. Tag matching: exact tags, plus `*` and `?` globs only. No exclusions, no regex.
16. Tag discovery: hourly per configured repository, for new tags and new digests.
17. Scan triggers: a digest is scanned when first pulled, when a tag moves to a new digest, and when the vulnerability DB changes.
18. Retention: count-based, default 20 stored images, operator-configurable. Eviction deletes the OCI layout only. Findings and scan history are kept.
19. Scanner limits, defaults: timeout 10 minutes, output 64 MB, pull cap 10 GB per image, minimum 10 GB free disk before a pull. Operator-configurable.
20. Keep the GitHub SARIF, issue, CVE close/reopen, and accepted-CVE rules. Remove only the Harbor parts.
21. Always a fresh install. No import from an existing HarborGate database.
22. Name: decide later. `localscan` stays provisional.

23. Scanner delivery: the pinned Trivy and Grype executables are copied into the app image, which stays FROM scratch and is built from their pinned releases. The app calls them by absolute path. Scanner updates are an app image rebuild (answer to open item 3, 2026-11-09).

## Scanner command verification (2026-11-09, open item 1 spike)

28. The user approved the scanner design: the pinned static Trivy and Grype executables are copied into the scratch app image and called by absolute path (decision 23), with the flags as the user stated them. Open item 1 then required a run against the real pinned binaries; decisions 29 and 30 record that run.

29. Verified against Trivy v0.76.2 (`aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb`) and Grype v0.121.2 (`anchore/grype@sha256:6a36234da13f9faa327306ac0b3dab3405cfa2b4eb20c8f904125a8707863913`), linux/arm64, on a single-platform OCI layout directory built with `docker buildx build --output type=oci` and extracted. Fixtures: `backend/tests/fixtures/scanner/`.
    - Trivy input: `trivy image --input <layout DIRECTORY>` works as approved. The `.tar` file from the same build is rejected ("file manifest.json not found in tar", "not a directory"), so the call must pass the extracted directory. A missing path or a directory without `index.json` exits 1 (FATAL).
    - Trivy offline: `--skip-db-update --skip-java-db-update` work with a cached DB (exit 0, also with the network disabled). With an empty cache `--skip-db-update` exits 1 ("cannot be specified on the first run"), so the DB must be fetched first by `trivy image --download-db-only --cache-dir <dir>` (and `--download-java-db-only`). The cache location is `--cache-dir` or `TRIVY_CACHE_DIR`; both are honoured (DB in `<dir>/db/trivy.db`, `<dir>/java-db/`, `<dir>/fanal/`). Telemetry: `--disable-telemetry` exists (the `TRIVY_DISABLE_TELEMETRY` env form was set in the runs but its effect was not observed). `--skip-version-check` suppresses the update notice. `--output <file>` writes the report (exit 0).
    - Trivy exit codes: 0 with findings, 0 with no findings, 1 on an unreadable input, 1 on a missing DB with `--skip-db-update`. With `--exit-code N` findings exit N; the call does not set it, so a non-zero exit is always an error.
    - Trivy JSON: top-level keys `ArtifactID, ArtifactName, ArtifactType, CreatedAt, Metadata, ReportID, Results, SchemaVersion, Trivy`; `SchemaVersion` is `2`; `Trivy.Version` is `0.76.2`. With no findings the `Results` key is absent (not an empty array); the reader must treat a missing `Results` as no findings. `Results[]` keys: `Class, Packages, Target, Type, Vulnerabilities`. `Vulnerabilities[]` keys: `CVSS, CweIDs, DataSource, Description, Fingerprint, FixedVersion, InstalledVersion, LastModifiedDate, Layer, PkgID, PkgIdentifier, PkgName, PrimaryURL, PublishedDate, References, Severity, Status, Title, VendorSeverity, VulnerabilityID`. `CVSS` is an object keyed by source name. `ArtifactName` and `Target` carry the input path.
    - Grype input: `grype oci-dir:<layout directory> -o json` works as approved (`-o json=<file>` writes a file, exit 0). A missing path or a directory that is not a layout exits 1 ("no source providers were able to resolve the input").
    - CHANGED from the approved text: Grype has NO `--db-auto-update` flag (`unknown flag`, exit 1). The setting is the environment variable `GRYPE_DB_AUTO_UPDATE=false` (the log shows "skipping db update"; with an empty cache and the variable set there is no download and the run exits 1 with "database does not exist"; with it unset an empty cache downloads the DB). The cache is `GRYPE_DB_CACHE_DIR` (honoured; DB at `<dir>/6/vulnerability.db`). The DB is fetched with `grype db update` (exit 0). Also set `GRYPE_CHECK_FOR_APP_UPDATE=false`: otherwise a scan with no network logs an ERROR about the version lookup, though the exit is still 0.
    - Grype exit codes: 0 with findings, 0 with no findings, 1 on an unreadable input, 1 on a missing DB with auto-update off. With `--fail-on <severity>` and findings it exits 2 (report still written); the call does not set it.
    - Grype JSON: top-level keys `descriptor, distro, matches, source`. `matches[]` keys: `artifact, matchDetails, relatedVulnerabilities, vulnerability`. `vulnerability` keys: `advisories, cvss, cwes, dataSource, epss, fix, id, namespace, risk, severity, urls`; `fix` is `{versions[], state, available[]}` and `state` is `fixed` or empty when unfixed. `artifact` keys: `cpes, id, language, licenses, locations, metadata, metadataType, name, purl, type, upstreams, version`. `matchDetails[]` keys: `fix, found, matcher, searchedBy, type`. Severity values seen: `Critical`, `Medium`. `descriptor.version` is `0.121.2`. With no findings `matches` is `[]`. `description` is not on `vulnerability` in the primary record; it is on `relatedVulnerabilities[]` (keys `cvss, cwes, dataSource, description, epss, id, namespace, severity, urls`) and only some matches have one. The same CVE appears once per package (busybox, busybox-binsh, ssl_client).
    - Not verified: layouts whose `index.json` holds several manifests or a nested index (the design stores one platform image per layout, so a single manifest is the case tested); amd64 binaries; the effect of `TRIVY_DISABLE_TELEMETRY`; whether Trivy omits `FixedVersion` when there is no fix; Trivy and Grype memory and run time on large images; timeout and kill behaviour. The sample image yielded one Trivy finding (zlib) and four Grype matches, so the fixture holds fewer than two Trivy entries.

30. Attestation rule: skip an index entry whose platform is `unknown/unknown`, and skip any entry whose annotation `vnd.docker.reference.type` is `attestation-manifest`, or whose manifest `artifactType` contains `attestation` or any layer `mediaType` contains `in-toto`. Verified on a real index built with `docker buildx build --platform linux/amd64,linux/arm64 --provenance=mode=min --sbom=true`: it has two image entries and two attestation entries; each attestation entry has platform `unknown/unknown`, annotation `vnd.docker.reference.type=attestation-manifest` and `vnd.docker.reference.digest` naming the image it describes; the manifest has `artifactType` `application/vnd.docker.attestation.manifest.v1+json` and layers of `application/vnd.in-toto+json`. The public `aquasec/trivy:0.76.2` index shows the same pattern (four platforms, four `unknown/unknown` attestation entries). The platform value alone was sufficient in both cases. The entry-level `artifactType` is not set in the index, so reading the manifest is needed for the `artifactType` and media-type checks. Unverified: attestations from other tools (cosign, GitHub provenance in the OCI referrers form) that may not appear as index entries at all.

## Rename (2026-11-09, user, dialogue)

24. The spinoff is named dockward. The name is no longer provisional; `localscan` is removed from the spec and the code. Main stays HarborGate; the rename does not touch main.
25. Environment variables in the spinoff: `DOCKWARD_*` only. Rename outright. There is no fallback to `HARBORGATE_*`.
26. The encryption HKDF labels (`harborgate/*`) and the cookie names stay unchanged in the spinoff, so the encrypted data and sessions stay readable. Only the visible name changes.
27. The Code Scanning category prefix (`harborgate`) and the issue marker (`harborgate:<CVE id>`) stay unchanged, so existing alerts and issues stay linked.

## Step 1 decisions (2026-11-09, user, dialogue)

31. Step 1 removes the Harbor code in the same change: the Harbor query code, handlers, services and their tests (spec section 1). The build and gates must pass at the end of Step 1.
32. The first migration includes the kept tables (users, system_config, user_credentials, github_issues, cve_acceptances, audit_log, alert_channels, alert_deliveries, job_runs, sync_jobs) and cve_findings, together with the ten new scanner tables.

## Namespaces and Step 1 (2026-11-10, user, dialogue)

33. No project layer. A source is hub, repository, and tag value. The repository keeps its full path, and its first segment is the namespace (user or organisation). The namespace is the only grouping; no project table is created.
34. Step 1 is held. The clean schema and Harbor removal happen together with Steps 3 and 4, so the spinoff branch stays green at each merge. The uncommitted Step 1 work is kept in the worktree agent-a45531f4f50b14b5f on branch feat-spinoff-step1, and is not discarded.

## Namespace and identity answers (2026-11-10, user, dialogue)

35. Credentials are per source, not per namespace. No namespace-level default credential.
36. SARIF location and Code Scanning category use the hub host and repository (for example `ghcr.io/nrosier/walley`). The spinoff has no Harbor history to keep, so its alerts start fresh.
37. A source is identified by hub, repository, and tag value. The same repository on two hubs is two sources, with separate alerts and issues.
38. The CVE list keeps a namespace filter: the first path segment of the repository, in place of the removed Project filter.

39. Authentication is optional for Docker Hub. A Docker Hub source can be pulled anonymously, and a credential is needed only for private repositories or to raise the anonymous rate limit. Other hubs keep their current rule (credential as the hub requires; see decision 14 and the registry client spec).

40. Docker Hub rate limit on an anonymous pull: the source shows a fixed catalog message that asks for a Docker Hub credential, which raises the limit. The job retries on the backoff, so a later attempt can succeed.
41. Docker Hub credential test: the same as other hubs. The test checks a token for the repository the user names, and returns ok or the failure. It works anonymously too.
42. If a user removes a Docker Hub credential, the source falls back to anonymous pulls and shows a note that no credential is in use. It is not blocked.

43. ghcr.io credentials: classic personal access token only, with read:packages. Fine-grained tokens are not accepted for ghcr.io.
44. Custom hubs: the admin can set a pull endpoint that differs from the stored host. The default for a custom hub is the stored host.
45. A hub is identified by its host only. No separate display label; the host is the name shown everywhere.

46. Code Scanning category includes the tag value: `harborgate/<hub host>/<repository>/<tag value>` (the spec's category prefix is kept, per decision 22). Each source has its own alerts; two tags of one repository never overwrite each other.
47. GitHub issues are keyed by GitHub repository and CVE, as today. Sources that target the same GitHub repository share one issue per CVE. The issue closes only when no source for that GitHub repository reports the CVE. This supersedes the per-source-issue reading of decision 37 for issues; decision 37 still gives each source its own alerts and findings.

48. Step 1 part 1 ports the kept code to the new tables in the same part: issue_lifecycle and merged_view read scan_runs and scanner_findings, and the kept tests are ported, not ignored or deleted. Harbor-only tests are removed with their code in part 3. The build stays green at each merge.

49. The newest image of a source is the tag observation with the latest first_seen_at for that tag (tag_observations.first_seen_at). A tag that moves to a new digest becomes newest on the next discovery. Used by findings, mappings, sync_jobs, github_issues and dashboard.
50. The kept callers merged_view and issue_lifecycle are ported to scan_runs and scanner_findings (per decision 48). scanner_reports and artifact_removal are Harbor-only and are deleted once their kept callers no longer reference them.

51. Minimal Sources and Images screens are built now, reusing the existing filter and table patterns with no new visual system. The user reviews them in the browser and approves them before release.
52. A releasable version requires: the full pipeline (discover, pull, scan, publish), the db_update job, the minimal Sources and Images screens, and a passing gate set on the spinoff branch. The live checks against a real registry, GitHub and Code Scanning are the release's verification and are recorded with the release.

53. The first spinoff release is a pre-release, 0.1.0. It is tagged only after CI is green on the spinoff head. The live checks (registry, GitHub, Code Scanning) and the browser approval of the Sources and Images screens are recorded against the release, not used as a gate for the tag.

54. Supersedes 26 and 27. Every name reflects dockward, including the HKDF labels (`dockward/*`), the cookie names, the Code Scanning category prefix, and the issue marker (`dockward:<CVE id>`). Existing data is migrated: stored credentials are re-encrypted under the new labels, sessions are reset, and existing GitHub issues are re-keyed to the new marker. The migration is a required part of the release.
55. The harborgate images on GHCR are deleted, including 0.1.0 and 0.1.1. dockward 0.2 is the first image in the renamed package. The deletion is permanent and is performed after dockward 0.2 is published and verified.

56. Rename migration for stored data. Each encryption label (`harborgate/*`, now `dockward/*`) and each cookie name changes under decision 54. The new build decrypts with the new label and falls back to the old one. On startup it re-encrypts each stored credential under the new label, one transaction per row, and records a count. The old labels are removed only after every row is re-encrypted and the count check passes. Sessions and CSRF tokens are reissued, not migrated. Decided by the user, 2026-11-10, dialogue.

57. Supersedes 25 for release 0.2 only. The environment variables are renamed to `DOCKWARD_*`. The build reads `DOCKWARD_*` first and falls back to `HARBORGATE_*`, logging a deprecation warning for each fallback read. `DOCKWARD_*` wins when both are set. The fallback is removed in the release after 0.2. Decided by the user, 2026-11-11, dialogue.

58. There are no sync jobs. The spinoff's units of work are discover, pull, scan, publish and db_update, and nothing else. The table `sync_jobs` is renamed `jobs`, the API `/api/v1/sync-jobs` becomes `/api/v1/jobs`, and the UI wording "Sync jobs" becomes "Jobs". Kinds and behaviour are unchanged. The sync-failed alert is renamed to a job-failed alert. Decided by the user, 2026-11-11, dialogue.
