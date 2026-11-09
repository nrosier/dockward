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
