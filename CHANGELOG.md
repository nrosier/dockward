# Changelog

All notable changes are recorded here. Versions follow semantic versioning.

## Unreleased

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
