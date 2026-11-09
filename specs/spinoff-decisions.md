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

## Rename (2026-11-09, user, dialogue)

24. The spinoff is named dockward. The name is no longer provisional; `localscan` is removed from the spec and the code. Main stays HarborGate; the rename does not touch main.
25. Environment variables in the spinoff: `DOCKWARD_*` only. Rename outright. There is no fallback to `HARBORGATE_*`.
26. The encryption HKDF labels (`harborgate/*`) and the cookie names stay unchanged in the spinoff, so the encrypted data and sessions stay readable. Only the visible name changes.
27. The Code Scanning category prefix (`harborgate`) and the issue marker (`harborgate:<CVE id>`) stay unchanged, so existing alerts and issues stay linked.
