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
