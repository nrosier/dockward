# Testing and CI

Purpose: test strategy, CI workflows, dependency updates, and repo hygiene checks.

## Test strategy

- CI tests Harbor and GitHub integrations against mocked or recorded API responses. CI uses no real credentials.
- A manual live smoke test runs against real Harbor and GitHub. It is never run in CI. It needs operator-provided credentials.
  - Decided (2026-11-03, delegated): it also records what can only be seen live: the size of a real webhook payload, the GitHub probe response bodies ("no analysis found", code scanning unavailable, missing permission), the client IP chain behind Cloudflare and Traefik, and no `securitypolicyviolation` event on any page.
- Webhook payload handling has a separate test fixture for each format (default JSON and CloudEvents).
- Cargo tests run with `cargo test`. Build commands are in `CLAUDE.md`.

## CI workflows (`.github/workflows/`)

- `ci.yml` (name "CI"): on pull request, push to `main`, and manual dispatch.
  - Rust job: install the toolchain from `backend/rust-toolchain.toml`, then `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo audit --deny warnings`, and `cargo deny check`.
    - Decided (2026-11-03): `cargo-audit` (and `cargo-deny`) are installed as prebuilt, checksum-verified binaries with `taiki-e/install-action`, not compiled with `cargo install` on each run.
    - Decided (2026-11-03): `backend/deny.toml` is required, so `cargo deny check` always runs. Decided (2026-11-03, delegated) contents: a license allow-list (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib), crates.io as the only source, and a warning on duplicate versions.
  - Frontend job: Node from `frontend/.nvmrc`, then `npm ci --ignore-scripts`, `npm audit --audit-level=high`, `npm run lint`, `npm test`, `npm run build`.
    - Decided (2026-11-03, user): frontend unit tests use Vitest with React Testing Library, `@testing-library/user-event`, `@testing-library/jest-dom`, and jsdom (dev dependencies only). `npm test` runs `vitest run`. Test files sit next to their component as `*.test.tsx` or `*.test.ts`. The API is mocked by stubbing `fetch`; tests make no network calls.
    - Decided (2026-11-03): `npm run lint` runs oxlint with `--deny-warnings` (correctness and suspicious categories, React hooks and jsx-a11y rules). typescript-eslint is not used, because it does not support TypeScript 7: version 8.72.1 declares the peer range `typescript >=4.8.4 <6.1.0`.
- `codeql.yml` (name "CodeQL"): static analysis with the CodeQL action for `rust`, `javascript-typescript`, and `actions`. Decided (2026-11-03): Rust was added, with `build-mode: none`.
- `dependency-review.yml` (name "Dependency review"): dependency-review action on pull requests.
- `docker.yml` (name "Docker"): on push to `main`, `v*` tags, and pull requests.
  - Pull requests: build the image locally and scan it with Trivy (fail on CRITICAL or HIGH). Nothing is pushed.
  - Push to `main` and `v*` tags: Decided (2026-11-03): build once and push to GHCR by digest only (untagged), with provenance `mode=max` and an SBOM. Scan that digest with Trivy (fail on CRITICAL or HIGH; upload SARIF to code scanning). Then add the tags from [deployment.md](deployment.md) to the same digest with `docker buildx imagetools create`, sign the digest with cosign (keyless), and attest build provenance. The published image is the scanned image.
  - Image labels (`org.opencontainers.image.*`) come from `docker/metadata-action`, with `flavor: latest=false` so a `v*` tag does not add `latest`.
- `scorecard.yml` (name "OpenSSF Scorecard"): scorecard action.
- `secret-scan.yml` (name "Secret scan"): gitleaks action.
- All workflows set token permissions to empty by default, and each job grants only what it needs. All actions are pinned to commit SHAs.

## Toolchain pins

- Decided (2026-11-03): Rust 1.99.1, pinned in `backend/rust-toolchain.toml`. The same version is in `rust-version` in `backend/Cargo.toml` and in the `rust:1.99.1-alpine` build image.
- Decided (2026-11-03): Node 26, pinned in `frontend/.nvmrc`. The same major is in `engines` in `frontend/package.json` and in the `node:26-alpine` build image. Node 26 has been Active LTS since 2026-10-28, with end of life on 2029-04-30. Source: https://endoflife.date/nodejs.
- CI reads the pin files and does not float on `stable` or `lts/*`.
- Decided (2026-11-03, delegated): Renovate groups each set (Rust, Node) so the versions move together. It uses a regex custom manager for `rust-toolchain.toml` and `rust-version`, which Renovate does not update by default.

## Dependency updates

- Renovate (`renovate.json`):
  - Extends `config:recommended`, `:pinAllExceptPeerDependencies`, `:semanticCommits`.
  - Pins digests.
  - Major updates are labelled `major-update` and not auto-merged.
  - Minor and patch updates (non-0.x) are not auto-merged.
  - Vulnerability alerts are labelled `security`.
  - Lock file maintenance is enabled.
  - Schedule: before 6am on Monday, UTC. Up to 5 concurrent PRs.

## Repo hygiene

- `SECURITY.md`: security reporting policy.
- `.github/CODEOWNERS`: code ownership.
- `.github/ISSUE_TEMPLATE/`: bug report, feature request, and template config.
- `CHANGELOG.md`: release notes, updated before each tag.
- `.gitignore`: see [deployment.md](deployment.md).

## Schema and SARIF checks

- SARIF output is validated against the SARIF 2.1.0 JSON schema after changes to the converter.
- Decided: 2026-11-02. The official SARIF 2.1.0 JSON schema is vendored into the repo under `backend/tests/schemas/`. The schema file itself is added later with the converter.
