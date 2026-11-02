# Testing and CI

Purpose: test strategy, CI workflows, dependency updates, and repo hygiene checks.

## Test strategy

- CI tests Harbor and GitHub integrations against mocked or recorded API responses. CI uses no real credentials.
- A manual live smoke test runs against real Harbor and GitHub. It is never run in CI. It needs operator-provided credentials.
- Webhook payload handling has a separate test fixture for each format (default JSON and CloudEvents).
- Cargo tests run with `cargo test`. Build commands are in `CLAUDE.md`.

## CI workflows (`.github/workflows/`)

- `ci.yml` (name "CI"): on pull request, push to `main`, and manual dispatch.
  - Rust job: `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo audit --deny warnings`.
  - Frontend job: `npm ci --ignore-scripts`, `npm audit --audit-level=high`, `npm run lint` (if present), `npm run build`.
- `codeql.yml` (name "CodeQL"): static analysis with the CodeQL action.
- `dependency-review.yml` (name "Dependency review"): dependency-review action on pull requests.
- `docker.yml` (name "Docker"): on push to `main`, `v*` tags, and pull requests.
  - Builds the image, scans it with Trivy (uploads SARIF to code scanning), then pushes to GHCR on `main` or tags.
  - Signs the image with cosign and attaches build provenance.
- `scorecard.yml` (name "OpenSSF Scorecard"): scorecard action.
- `secret-scan.yml` (name "Secret scan"): gitleaks action.
- All workflows set token permissions to empty by default, and each job grants only what it needs. All actions are pinned to commit SHAs.

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
