# Testing and CI

Purpose: test strategy, CI workflows (including the security scanning workflow), dependency updates, and repo hygiene checks.

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
- `docker.yml` (name "Docker"): on `v*` tags and pull requests.
  - Pull requests: build the image locally and scan it with Trivy (fail on CRITICAL or HIGH). Nothing is pushed. Decided (2026-11-07, user, issue #227, decisions 1 and 9): this gate stays. The image is scanned here and also by `security-scan.yml`.
  - Pushes happen only on `v*` tags (Decided 2026-11-07, user, via dialogue). A push to `main` publishes nothing. On a `v*` tag: Decided (2026-11-03): build once and push to GHCR by digest only (untagged), with provenance `mode=max` and an SBOM. Scan that digest with Trivy (fail on CRITICAL or HIGH; upload SARIF to code scanning). Then add the tags from [deployment.md](deployment.md) to the same digest with `docker buildx imagetools create`, sign the digest with cosign (keyless), and attest build provenance. The published image is the scanned image.
  - Image labels (`org.opencontainers.image.*`) come from `docker/metadata-action`, with `flavor: latest=false`; `latest` comes from an explicit tag rule that is enabled on `v*` tags.
- `scorecard.yml` (name "OpenSSF Scorecard"): scorecard action.
- `secret-scan.yml` (name "Secret scan"): gitleaks action.
- `security-scan.yml` (name "Security scan"): Syft SBOM, Grype and Trivy, with SARIF upload to Code Scanning and a scheduled `security` issue that the scheduled run opens, updates and closes. Decided (2026-11-07, user, #227). The rules are in "Security scanning workflow" below.
- All workflows set token permissions to empty by default, and each job grants only what it needs. All actions are pinned to full commit SHAs, with the release version in a comment on the same line (`uses: owner/repo@<40-hex sha> # vX.Y.Z`). Decided (2026-11-07, user, #227 d3) for `security-scan.yml`. The existing workflows already use this form.

## Security scanning workflow

Source: issue #227. Decisions 1 to 4 are the user's (2026-11-07, via dialogue, recorded as a comment on #227): d1 keep every existing workflow, d2 report only, d3 pin every action to a full commit SHA with the version in a comment, d4 scan the repository source and the image that `docker.yml` builds. Decisions 5 to 12 are the user's answers to the first version of this section (2026-11-07, via dialogue, recorded as comments on #227): d5 categories split by target, d6 uploads never fail a pull request check, d7 the scheduled run closes the issue, d8 manual runs do not touch the issue, d9 the `docker.yml` Trivy gate stays, d10 the new jobs are not required checks, d11 the weekly run also scans the published image, d12 findings with no fix are reported. A rule marked `spec author` is a decision made by the spec author within d1 to d4. Each one gives its reason, and the user can overturn it.

### Goal and file

- Decided (2026-11-07, user, #227): one workflow, `.github/workflows/security-scan.yml`, name "Security scan". Syft writes a CycloneDX SBOM, Grype scans the SBOM, and Trivy gives a second CVE opinion and also runs its secret and misconfiguration (IaC and Dockerfile) scanners. Both SARIF reports go to GitHub Code Scanning. A weekly run opens or updates one `security` issue when High or Critical findings exist, and closes it with a note when none exist (d7).
- Decided (2026-11-07, user, #227 d2): report only. A finding at any severity never fails a job in this workflow. A scanner that cannot run (a tool error, not a finding) still fails its step, so a broken scan is visible.
- Decided (2026-11-07, user, issue #227, decisions 6 and 10): the Code Scanning uploads never fail a pull request check, and the new scan jobs ("Security scan (source)", "Security scan (image)", "Security scan report") are not required status checks. This spec adds nothing to the `Protect main` ruleset.

### Triggers

- Decided (2026-11-07, user, #227): `push` with `branches: [main]`, `pull_request` with `branches: [main]`, `schedule` with `cron: '0 4 * * 1'` (Mondays 04:00 UTC), and `workflow_dispatch`.
- Why the schedule exists: the vulnerability databases that Grype and Trivy download change every day, while the code may not change for weeks. The weekly run rescans the latest `main` against current data, so a CVE published after the last push is still found. It is also the only trigger that writes the `security` issue (see "Scheduled issue"). GitHub runs `schedule` on the latest commit of the default branch.
- Decided (2026-11-07, user, issue #227, decision 8): a `workflow_dispatch` run scans and uploads like any other run, but it does not open, update or close the `security` issue. Only `schedule` runs do. The `report` job is skipped on every other event (its `if:` names `schedule`).
- Verified (2026-11-07), GitHub Docs, "Events that trigger workflows", `schedule`: a scheduled run can be delayed under high load, and high-load times include the start of every hour. In a public repository, scheduled workflows are disabled after 60 days with no repository activity. The cron is the user's choice and is kept. If runs are often late, the fix is a minute other than `:00`, which needs the user's approval.
- Never use `pull_request_target`. A pull request run builds and scans the pull request's own code with the read-only token GitHub gives it.
- Concurrency. Decided (2026-11-07, spec author, #227): `group: security-scan-${{ github.ref }}-${{ github.event_name }}`, with `cancel-in-progress: ${{ github.event_name == 'pull_request' }}`. The event name is in the group so a push to `main` cannot replace a pending scheduled run. GitHub keeps at most one pending run per group and cancels the older pending run (GitHub Docs, "Control the concurrency of workflows and jobs"). Pull request runs cancel each other, as in the other workflows.

### Scan targets (d4)

- Decided (2026-11-07, user, #227 d4): two targets, the repository source and the container image.
- Decided (2026-11-07, spec author, #227): this workflow builds the image itself on every trigger. It does not take the image from `docker.yml`. Reasons:
  - `docker.yml` pushes an image only on `v*` tags. On a pull request it builds `harborgate:ci` and passes it between its own jobs as a one-day artifact. On a push to `main`, a schedule or a manual run it builds nothing. Taking its image would leave the image unscanned on every trigger except pull requests.
  - Reading another workflow's artifact needs a `workflow_run` trigger or a cross-run download with `actions: read` and a run id. That ties the timing of the two workflows together and adds a permission. A rebuild needs neither.
  - The rebuild uses the same inputs as the `build` job in `docker.yml`, so it is the image that ships for that commit: `docker/build-push-action` with `context: .`, `push: false`, `load: true`, `provenance: false`, and `build-args: REVISION=${{ github.sha }}` (the Dockerfile requires `REVISION`). The local tag is `harborgate:security-scan`. Nothing is pushed.
- The release digest is still scanned by `docker.yml` (`scan-digest`) on `v*` tags.
- Decided (2026-11-07, user, issue #227, decision 11): the weekly (`schedule`) run also scans the published image `ghcr.io/nrosier/harborgate:latest`, in addition to the image built from `main`. The build from `main` stays, so the scan still covers the commit under test. Push, pull request and manual runs scan only the local build. Decided (2026-11-07, user, issue #227, decision 13): its Grype and Trivy results are uploaded under the existing image categories, `grype-engine/image` and `trivy-engine/image`. It gets no categories of its own. Two points stay open in question 9: how its counts enter the `security` issue, and what the run does when `latest` cannot be pulled.
- Known limit: the Dockerfile builds the backend with `cargo build`, not `cargo auditable`, so the binary carries no dependency list. Syft's Rust binary cataloguer reads only cargo-auditable data (`NewAuditBinaryCataloger`, Syft v1.57.0), and Trivy has the same limit. The image scan therefore covers the Alpine packages and the image configuration. The Rust and npm dependencies are covered by the source scan of `backend/Cargo.lock` and `frontend/package-lock.json`. That is why both targets are needed.

### Jobs and steps

The workflow sets `permissions: {}` at the top. It has three jobs. `source` and `image` run in parallel with no `needs`, so a failure in one target never stops the other. Job names must differ from the required status check names in the `Protect main` ruleset (`Build image`, `Trivy scan`, and the others), because a required check is matched by name.

Decided (2026-11-07, spec author, #227): scanner outputs are written to `${{ runner.temp }}/security-scan/`, not to the workspace. Otherwise the Trivy filesystem scan and the Syft directory scan would read the SBOM, the SARIF files and the Trivy cache as if they were source. The Trivy `cache-dir` is `${{ runner.temp }}/trivy-cache` for the same reason (the action's default is under `github.workspace`). Below, `$OUT` means `${{ runner.temp }}/security-scan`.

Job `source`, name "Security scan (source)". `runs-on: ubuntu-latest`, `timeout-minutes: 30` (the value `docker.yml` uses for its build and scan jobs). Permissions: `contents: read`, `security-events: write`.

| # | Step (`id`) | Action | Inputs | `if:` |
|---|---|---|---|---|
| 1 | Harden runner | `step-security/harden-runner` | `egress-policy: audit` | default |
| 2 | Checkout (`checkout`) | `actions/checkout` | `persist-credentials: false` | default |
| 3 | Syft SBOM (`syft`) | `anchore/sbom-action` | `path: .`, `format: cyclonedx-json`, `output-file: $OUT/sbom.cyclonedx.json`, `syft-version: ${{ env.SYFT_VERSION }}`, `upload-artifact: "false"`, `upload-release-assets: "false"`, `dependency-snapshot: "false"` | default |
| 4 | Upload SBOM | `actions/upload-artifact` | `name: sbom-source`, `path: $OUT/sbom.cyclonedx.json`, `if-no-files-found: error` | `always() && steps.syft.outcome == 'success'` |
| 5 | Grype (`grype`) | `anchore/scan-action` | `sbom: $OUT/sbom.cyclonedx.json`, `output-format: sarif`, `output-file: $OUT/grype-results.sarif`, `fail-build: "false"`, `severity-cutoff: high`, `grype-version: ${{ env.GRYPE_VERSION }}` | `always() && steps.syft.outcome == 'success'` |
| 6 | Trivy (`trivy`) | `aquasecurity/trivy-action` | `scan-type: fs`, `scan-ref: .`, `scanners: vuln,secret,misconfig`, `format: sarif`, `output: $OUT/trivy-results.sarif`, `exit-code: "0"`, `cache-dir: ${{ runner.temp }}/trivy-cache`, `version: ${{ env.TRIVY_VERSION }}` | `always() && steps.checkout.outcome == 'success'` |
| 7 | Upload Grype SARIF | `github/codeql-action/upload-sarif` | `sarif_file: $OUT/grype-results.sarif`, `category: grype-engine/source` | `always() && steps.grype.outcome == 'success' && <not a fork PR>` |
| 8 | Upload Trivy SARIF | `github/codeql-action/upload-sarif` | `sarif_file: $OUT/trivy-results.sarif`, `category: trivy-engine/source` | `always() && steps.trivy.outcome == 'success' && <not a fork PR>` |
| 9 | Keep SARIF | `actions/upload-artifact` | `name: sarif-source`, `path:` both SARIF files, `if-no-files-found: warn` | `always() && steps.checkout.outcome == 'success'` |

Job `image`, name "Security scan (image)". The same runner, timeout and permissions. The steps are the same as in `source`, with these changes:

- After Checkout: "Set up Docker Buildx" (`docker/setup-buildx-action`, default `if:`), then "Build image" (`id: build`, `docker/build-push-action` with the inputs in "Scan targets", default `if:`).
- Syft: `image: docker:harborgate:security-scan` in place of `path`. The `docker:` scheme makes Syft read the local daemon only (Syft `scan` help, v1.57.0). Without a scheme and with no local match, Syft would fall through to a registry pull. Artifact name `sbom-image`.
- Trivy: `scan-type: image`, `image-ref: harborgate:security-scan`, the same `scanners`, and the step environment `TRIVY_IMAGE_SRC: docker` (Trivy flag `--image-src`, v0.76.2), so Trivy reads only the local daemon and never pulls a look-alike image from a registry.
- Every `steps.checkout.outcome == 'success'` condition becomes `steps.build.outcome == 'success'`.
- Categories `grype-engine/image` and `trivy-engine/image`, and artifact `sarif-image`. On `schedule` runs the published image `ghcr.io/nrosier/harborgate:latest` is scanned too and uploaded under these same two categories (Decided 2026-11-07, user, issue #227, decision 13; see "Scan targets" and "Security scanning workflow", "Categories").

`<not a fork PR>` is `(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)`. Decided (2026-11-07, spec author, #227): on a pull request from a fork, GitHub gives `GITHUB_TOKEN` read-only permissions (GitHub Docs, "Events that trigger workflows", "Workflows in forked repositories"), so a SARIF upload would fail with a permission error. The scanners still run, and the `sarif-*` artifact keeps the results. Renovate branches live in this repository, so they upload as usual.

Job `report`, name "Security scan report". `needs: [source, image]`. `if: ${{ always() && github.event_name == 'schedule' }}`. `timeout-minutes: 10` (the value in `issue-deps.yml`). Permissions: `contents: read` (for the sparse checkout of the script) and `issues: write`. No `security-events` permission: it reads the SARIF artifacts from this run, not the Code Scanning API. Steps:

1. Harden runner (`egress-policy: audit`).
2. Checkout, with `sparse-checkout: .github/scripts` and `persist-credentials: false` (the pattern `issue-deps.yml` uses).
3. `actions/download-artifact`, `pattern: sarif-*`, `path: ${{ runner.temp }}/sarif`. Downloads from the same run use the runner's artifact token and need no `GITHUB_TOKEN` permission (`actions/download-artifact` v8.0.2 `action.yml`: `github-token` is needed only for another repository or run). `if: always()`, so a missing artifact never stops the report.
4. `actions/github-script`, which imports `.github/scripts/security-scan-report.mjs` and calls it with `github`, `context` and `core`. The script's contract is in "Scheduled issue".

### Failure isolation and `always()`

- Decided (2026-11-07, user, #227): each scanner step and each upload step runs with `if: always()`, combined with a condition on the step it needs, as in the table above. A Grype failure never stops Trivy or the Trivy upload, and a Trivy failure never stops Grype or the Grype upload.
- These steps must not use `always()`: Harden runner, Checkout, Set up Docker Buildx, Build image, and Syft. Each one is a setup step that the scan steps need. If one fails, nothing can be scanned. GitHub's own guidance says not to use `always()` on a step "that could suffer from a critical failure, for example: getting sources", because the run can hang until its timeout (GitHub Docs, "Evaluate expressions in workflows and actions", `always`). Grype needs the SBOM, so it is gated on `steps.syft.outcome`, not on `always()` alone.
- `always()` also runs during a cancellation, so a cancelled pull request run can still upload results for its own merge ref. That is harmless: the next run overwrites the same category for that ref (GitHub Docs, "Uploading a SARIF file to GitHub": a second upload with the same tool and category replaces the earlier results).
- Each upload step needs its scanner step to have succeeded. A scanner that crashed leaves no SARIF file, so the upload is skipped instead of failing a second time on a missing file. The job is already red from the scanner step.

### Reporting only (d2)

- Grype: `fail-build: "false"`. In `anchore/scan-action` v7.4.2 (`action.js`), Grype exit code 2 (a severity at or above `severity-cutoff`) becomes `core.warning` when `fail-build` is false. Any other non-zero exit is `core.setFailed`. `severity-cutoff: high` makes the warning name High and Critical. It has no effect on the SARIF `level`, which Grype derives from each match's own severity.
- Trivy: `exit-code: "0"`, so findings never make Trivy exit non-zero. Tool errors still exit non-zero. No `severity` input is set. For `format: sarif`, the action drops any severity filter unless `limit-severities-for-sarif` is true (`trivy-action` v0.36.0 `entrypoint.sh`), so every severity reaches Code Scanning.
- Unfixed findings. Decided (2026-11-07, user, issue #227, decision 12): findings with no fix are reported, not ignored. Neither `only-fixed` (Grype) nor `ignore-unfixed` (Trivy) is set, which matches Grype's default (`only-fixed: false`). The gate in `docker.yml` ignores unfixed findings, but that is a gate and this workflow is a report.
- Enforcement is checked by the checks in "Verification": the literal inputs, plus a pull request run that is green while Code Scanning shows High or Critical alerts.
- Scope. Decided (2026-11-07, user, issue #227, decisions 1 and 9): report only (d2) governs this workflow. The pull request job `Trivy scan` in `docker.yml` (`exit-code: "1"` on fixed CRITICAL or HIGH) is a required status check and stays. A pull request can therefore still fail on a fixed High or Critical image finding through `docker.yml`, and never through `security-scan.yml`.
- Code Scanning checks. Decided (2026-11-07, user, issue #227, decision 6): the Grype and Trivy uploads never fail a pull request check. See "Interaction with existing workflows (d1)", "Code Scanning pull request checks".

### Scheduled issue

- Decided (2026-11-07, user, #227; issue #227 decisions 7 and 8): on `schedule` runs only, the `report` job opens or updates one open issue labelled `security` when High or Critical findings exist, and closes it with a note when a complete scan finds none. It never opens a second open one. A `workflow_dispatch` run never opens, updates or closes it.
- Script: `.github/scripts/security-scan-report.mjs`, an ES module like `issue-deps.mjs`. It exports:
  - `MARKER = '<!-- harborgate-ci:security-scan -->'`
  - `summarise(inputs)`, a pure function. `inputs` is an array with one entry per target and engine: `{ target: 'source' | 'image', engine: 'grype' | 'trivy', sarif: <parsed SARIF object> | null }`. A missing or unparseable file is `null`. It returns `{ rows: [{ target, engine, available, critical, high }], total, complete }`, where `complete` is true only when all four inputs are present.
  - `upsertIssue({ github, context, core, summary })`, which returns `{ action: 'created' | 'updated' | 'closed' | 'none', number }`.
- Counting. Decided (2026-11-07, spec author, #227): a result counts by its rule's `properties["security-severity"]`. The rule is found by `ruleIndex` or `rule.index` into `runs[].tool.driver.rules`, or else by `ruleId`. A score from 9.0 to 10.0 is Critical and a score from 7.0 to 8.9 is High (CVSS v3.1 specification, Table 14, "Qualitative severity rating scale"). GitHub uses the same bands for display: "over 9.0 is critical, from 7.0 to 8.9 is high" (GitHub Docs, "SARIF support for code scanning", `security-severity`). GitHub's wording leaves exactly 9.0 unassigned, so the CVSS table decides it. A missing, non-numeric or 0.0 score is not counted (GitHub treats it as "no security severity"). Reason: this is the severity the Security tab shows. Verified (2026-11-07): both tools set it on every rule. Grype v0.121.2 uses the best CVSS base score, or else 9.0 for Critical and 7.0 for High. Trivy v0.76.2 uses the CVSS v3 score for CVEs, or else 9.5 for Critical and 8.0 for High, with the same fallback for secret and misconfiguration rules.
- Finding the existing issue (not by title). The `security` label is not unique, because Renovate also puts it on vulnerability alert PRs (`renovate.json`, `vulnerabilityAlerts.labels`). The lookup lists open issues with `github.paginate(github.rest.issues.listForRepo, { owner, repo, state: 'open', labels: 'security', per_page: 100 })`. It drops items that have a `pull_request` key (the Issues API also returns pull requests: GitHub REST docs, "REST API endpoints for issues"), and keeps those whose body's first line, trimmed, equals `MARKER`. It does not use the search API, whose index can lag, for the same reason as the HarborGate marker rule in [cve-lifecycle.md](cve-lifecycle.md). If more than one matches, the lowest issue number is used, and `core.warning` lists the others. The `harborgate-ci:` prefix cannot match the app's `<!-- harborgate:<CVE id> -->` marker.
- Actions:
  - `total > 0`, no match: create the issue with title `Security scan: High or Critical findings`, label `security`, and the body below. Returns `created`.
  - `total > 0`, a match: replace the body (`issues.update`). The title and labels are not changed, so a user's edits to them stay. No comment is added. Returns `updated`.
  - `total == 0`, `complete`, a match: replace the body with the marker line and `No High or Critical findings in [run <run id>](<run url>).`, add one comment with the fixed text `Closed by the scheduled security scan: no High or Critical findings in [run <run id>](<run url>).`, then close the issue (`issues.update` with `state: 'closed'`, `state_reason: 'completed'`). Returns `closed`.
  - Anything else (`total == 0` with no match, or `total == 0` and not `complete`): no change. Returns `none`.
- Closing. Decided (2026-11-07, user, issue #227, decision 7): when a scheduled run finds no High or Critical findings, the open `security` issue is closed with a note. This replaces the earlier rule that the workflow never closes the issue.
- Closing needs a `complete` summary (all inputs present). Decided (2026-11-07, spec author, #227 d7): a run that missed a scanner, or a scan that failed, must not close an issue whose findings may still exist, so an incomplete run changes nothing (`none`).
- Findings that come back. Decided (2026-11-07, spec author, #227 d7, which leaves the choice to this spec): the lookup lists open issues only, so when findings return after a close, the next scheduled run opens a new issue. A closed issue is never reopened, which keeps the one-open-issue rule and the lookup unchanged. An issue that the user closes by hand is treated the same way.
- Body: the marker as the first line, then a table with one row per target and engine (`Target`, `Engine`, `Critical`, `High`; a `null` input shows `not available (scan failed)`), a line `Run: [<run id>](<server_url>/<repo>/actions/runs/<run id>)`, and a link to `<server_url>/<repo>/security/code-scanning`. The body holds only counts, fixed text and URLs built from `context`. It never copies finding text, so no package name, secret match or path can reach the issue or `@`-mention anyone, and the body stays far below GitHub's size limit.
- An issue created or edited with `GITHUB_TOKEN` starts no workflow, so `issue-deps.yml` does not run on it (GitHub Docs, "Events that trigger workflows": apart from `workflow_dispatch` and `repository_dispatch`, events triggered by `GITHUB_TOKEN` "do not create workflow runs at all").

### Permissions

- Top level: `permissions: {}`. Every job grants its own.
- `source` and `image`: `contents: read` (checkout) and `security-events: write` (SARIF upload; GitHub Docs, "Uploading a SARIF file to GitHub": "required for all workflows").
- `report`: `contents: read` and `issues: write`. It is the only job with `issues: write`.
- Decided (2026-11-07, spec author, #227): `id-token: write` is not granted, because no step asks for an OIDC token. Checked at the pinned SHAs: `anchore/sbom-action`, `anchore/scan-action`, `aquasecurity/trivy-action`, `github/codeql-action/upload-sarif`, `actions/github-script`, `actions/upload-artifact` and `actions/download-artifact`. In this repository, OIDC is used only by Scorecard's `publish_results` and by cosign keyless signing in `docker.yml`.
- `actions: read` is not granted. GitHub lists it for SARIF upload as "only required for workflows in private repositories", and this repository is public (checked 2026-11-07). If the repository becomes private, add `actions: read` to `source` and `image`.

### Pinning (d3) and updates

- Decided (2026-11-07, user, #227 d3): every `uses:` is `owner/repo[/path]@<40-hex commit SHA> # vX.Y.Z`, on one line. An annotated tag is dereferenced to its commit. The tag object's own SHA is never pinned.
- Decided (2026-11-07, spec author, #227): the Syft, Grype and Trivy binaries are pinned too, because each action's default lags behind the latest release (see the table). They are workflow `env` values, each with a Renovate comment on the line above:

  ```yaml
  env:
    # renovate: datasource=github-releases depName=anchore/syft
    SYFT_VERSION: v1.57.0
    # renovate: datasource=github-releases depName=anchore/grype
    GRYPE_VERSION: v0.121.2
    # renovate: datasource=github-releases depName=aquasecurity/trivy
    TRIVY_VERSION: v0.76.2
  ```

- Renovate today. Verified (2026-11-07): `renovate.json` extends `config:recommended`, which leaves the `github-actions` manager on, and a package rule sets `pinDigests: true` for `github-actions`. Renovate is active on this repository (PRs #101 to #105, 2026-11-04). The `sha # vX.Y.Z` form is the one Renovate's `github-actions` manager updates (Renovate docs, github-actions manager, "Digest pinning and updating"). The action pins are therefore already covered. There is no Dependabot configuration, and none is added.
- Renovate gap. Renovate does not read `with:` version inputs for `anchore/sbom-action` or `anchore/scan-action`. It reads `version:` for `aquasecurity/trivy-action`, but only as a literal value, not an expression. Required: add `"customManagers:githubActionsVersions"` to `extends` in `renovate.json`. That preset updates `*_VERSION:` values that follow a `# renovate:` comment in workflow files (Renovate `lib/config/presets/internal/custom-managers.preset.ts`). The change is made in the implementation task, not in this spec.
- Versions. Verified (2026-11-07) with `gh api repos/<owner>/<repo>/releases/latest` and `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, with annotated tags dereferenced. The implementation must check again and use any newer release (#227: "verified at implementation time").

| Component | Latest release | Commit SHA | Immutable release | In this repo today |
|---|---|---|---|---|
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | no | same |
| `step-security/harden-runner` | v2.22.4 | `1d88384fd173af6ecb012dfd0264a306b711241a` | yes | v2.22.3 |
| `docker/setup-buildx-action` | v4.4.1 | `f87e5991a6d7451dcb8d9637bfbc97413f497069` | yes | same |
| `docker/build-push-action` | v7.4.0 | `c3c9e263c25d99ce0380d002d59b67737d91b0dc` | yes | same |
| `anchore/sbom-action` | v0.24.3 | `66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c` | yes | new |
| `anchore/scan-action` | v7.4.2 | `27805bf3b4e84b4a5c980df22ed233c00390a439` | yes | new |
| `aquasecurity/trivy-action` | v0.36.0 | `ed142fd0673e97e23eac54620cfb913e5ce36c25` | yes | same (`docker.yml`) |
| `github/codeql-action/upload-sarif` | v4.39.3 | `33d7b85da1a04171e211befe2c739303b9a4c066` | yes | v4.39.2 |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | no | same |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | no | same |
| `actions/github-script` | v9.0.0 | `3a2844b7e9c422d3c10d287c895573f7108da1b3` | no | new |
| Syft (binary) | v1.57.0 | `30f4bce762f31136e055f2965185f12eb95fbe47` | yes | sbom-action default v1.54.0 |
| Grype (binary) | v0.121.2 | `82d7a0ea911946b99343c672056867d372f9b319` | yes | scan-action default v0.118.0 |
| Trivy (binary) | v0.76.2 | `3f6334d223b52188324af3b9923b4249cd206652` | yes | trivy-action default v0.70.0 |

- Notes on the table:
  - `github/codeql-action`: `releases/latest` returns `codeql-bundle-v2.27.4`, which is the CodeQL CLI bundle, not an action version. The action version is the newest `v4.*` release, v4.39.3 (2026-11-04, not a prerelease).
  - None of these is a major version change from what the repository uses. The new actions are not used anywhere yet. `actions/github-script` v9.0.0 is a major release with breaking changes: `require('@actions/github')` fails, and `getOctokit` is now injected and must not be declared with `const` or `let`. The script must use the injected `github` and `getOctokit`.
  - `aquasecurity/trivy-action` and the early-2026 tag incident. v0.36.0 was published on 2026-04-22 as an immutable GitHub release. Its annotated tag (tagger date 2026-04-22T09:29:59Z) resolves to commit `ed142fd0…`, the SHA `docker.yml` already pins. Releases v0.31.0 to v0.35.0 all show a publish date of 2026-03-20, and there is a stray `0.35.0` release without the `v`. That fits releases being re-created during the incident, and v0.36.0 comes after that window. It is pinned by SHA, so a moved tag cannot change what runs. Inside, the action pins `aquasecurity/setup-trivy` by SHA (`3fb12ec1…`, which matches the v0.2.6 tag, checked) and `actions/cache` by SHA. The `main` branch has unreleased Trivy bumps (commit `38b337ff…`, "Update trivy to v0.76.2"). They are not used, because a branch commit is not a release.
  - "Immutable release" is GitHub's immutable-release flag. The `actions/*` releases do not set it, so their tags could in principle move. SHA pinning covers that.

### SARIF validation

- Decided (2026-11-07, user, #227): both SARIF files from both targets must validate against SARIF 2.1.0 with the `sarif-validate` check. The schema is the vendored `backend/tests/schemas/sarif-schema-2.1.0.json` (OASIS errata 01, SHA-256 in `backend/tests/schemas/README.md`).
- The check is run by the verification task on the artifacts of a pull request run, each artifact in its own new, empty directory:
  - `gh run download <run id> -n sarif-source -D <new dir>`, and the same for `sarif-image`.
  - `check-jsonschema --schemafile backend/tests/schemas/sarif-schema-2.1.0.json <dir>/grype-results.sarif <dir>/trivy-results.sarif` exits 0 with no errors.
  - `python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' <file>` prints `2.1.0` for each of the four files.
- Decided (2026-11-07, spec author, #227): this check is not a workflow step, so the workflow installs no extra tool. As a backstop, `upload-sarif` validates every non-CodeQL file against SARIF 2.1.0 before upload (`validateSarifFileSchema`, codeql-action v4.39.3). It turns `uri` and `uri-reference` format errors into warnings, so it is weaker than the check above and does not replace it.
- Categories. Decided (2026-11-07, user, issue #227, decision 5): split by target, `grype-engine/source`, `grype-engine/image`, `trivy-engine/source` and `trivy-engine/image`. GitHub fails a job that uploads twice with the same tool and category ("only one run of the codeql/analyze or codeql/upload-sarif actions is allowed per job per tool/category", codeql-action `validateUniqueCategory`), and a second upload with the same category for the same commit replaces the first (GitHub Docs, "Uploading a SARIF file to GitHub"). Two targets per engine therefore need two categories. The issue's names `grype-engine` and `trivy-engine` stay as the prefixes. The `/` form follows CodeQL's `/language:<lang>`. Decided (2026-11-07, user, issue #227, decision 13): the published image `ghcr.io/nrosier/harborgate:latest`, scanned by the weekly run, is uploaded under `grype-engine/image` and `trivy-engine/image`, not under categories of its own. There is no category for it besides these four. Consequence to check, UNVERIFIED: an upload with a category already used for the same commit replaces the earlier result (GitHub Docs, "Uploading a SARIF file to GitHub"), and one job cannot upload twice with the same tool and category (the rule quoted above), so the implementation must not make two uploads with one category in one job, and the first scheduled run must record which result the Security tab keeps for each image category.
- Neither Grype nor Trivy writes `runs[].automationDetails.id`, so the `category` input applies (checked in the v0.121.2 and v0.76.2 SARIF presenters). If a later version adds it, the file's value takes precedence over the input, and the categories must be checked again.

### Interaction with existing workflows (d1)

- Decided (2026-11-07, user, #227 d1): CodeQL, Scorecard, Secret scan, Dependency review, CI, Docker and Issue dependencies all stay unchanged. Overlap is accepted.
- `secret-scan.yml` (gitleaks, full history, fails on any finding) and the Trivy `secret` scanner (current tree and image layers, report only) both look for secrets. That is the expected duplicate. They use different rule sets, and gitleaks stays the gate. Trivy masks secret matches in its output (`censorLocation`, Trivy v0.76.2).
- `dependency-review.yml` (pull requests, manifest diff, `fail-on-severity: high`) overlaps with the Grype and Trivy source CVE results. It stays the gate for new dependencies.
- `codeql.yml` uses tool `CodeQL` and categories `/language:*`, so its Code Scanning results never collide with these. Its weekly run is Mondays at 03:23 UTC.
- `scorecard.yml` runs Mondays at 04:17 UTC and on pushes to `main`. The SHA pins and the top-level `permissions: {}` in this workflow keep Scorecard's Pinned-Dependencies and Token-Permissions results as they are.
- `docker.yml`: on pull requests both workflows build the image. The second build per pull request is accepted, to keep the workflows independent (see "Scan targets"). On `v*` tags, `docker.yml` uploads Trivy SARIF without a `category`. Those results are on the tag ref and under their own default category, so they do not replace `trivy-engine/*`.
- `issue-deps.yml`: not triggered (see "Scheduled issue").
- Monday morning: CodeQL at 03:23, this workflow at 04:00, Scorecard at 04:17, and Renovate "before 6am on monday". They are separate workflows and do not wait for each other.
- Code Scanning pull request checks. Decided (2026-11-07, user, issue #227, decision 6): report only. The Code Scanning uploads never fail a pull request check, and the new jobs are not required checks (decision 10). UNVERIFIED mechanism: when a workflow uploads SARIF on a pull request, GitHub adds a Code Scanning check run per tool (the existing "CodeQL" check on pull requests is one of these, seen on PR #229), and such a check can fail when the pull request adds alerts at or above the repository's check-failure threshold. The first pull request run must record the check names and conclusions. If a Grype or Trivy Code Scanning check concludes `failure`, the implementer stops and asks the user before changing the repository threshold, because that setting also applies to CodeQL.

### Secrets

- The workflow uses only `GITHUB_TOKEN`. It references no other secret and sets no `registry-username`, `registry-password` or `github-pat` input. The actions use the default `github.token` for release downloads.
- No step prints a token, an SBOM or a SARIF file to the log: there is no `cat`, no `table` output for Grype, and no `debug` input. The report script logs only issue numbers and counts. The rules in [security.md](security.md), "Secrets in logs", and the non-negotiable rule in `CLAUDE.md` apply.
- The SBOM and SARIF artifacts can be read by anyone who can read this public repository. They hold dependency names, which the lock files already make public, and Trivy's masked secret matches.

### Catalog and i18n

- Not applicable. The workflow adds no user-visible UI text, so nothing goes into the string catalog. The issue title and body are fixed English text built by the script. GitHub issue text is not UI text, the same rule as for the HarborGate issue body in [integrations.md](integrations.md).

### Verification (#227 acceptance criteria)

The issue's 13 criteria, in order, with the check for each. Ticking them is the job of the end-of-plan review, with evidence from these checks.

1. Spec first, with dated decisions. Check: this section is on `main` before the workflow commit (compare `git log --format='%H %cs %s' -- specs/testing-and-ci.md .github/workflows/security-scan.yml`), and `grep -c 'Decided (2026-11-07, user, #227' specs/testing-and-ci.md` is at least 1.
2. Triggers. Check: in the parsed YAML (for example `yq '.on' .github/workflows/security-scan.yml`), `push.branches == [main]`, `pull_request.branches == [main]`, `schedule[0].cron == '0 4 * * 1'`, and `workflow_dispatch` is present.
3. Syft SBOM as an artifact. Check: the Syft steps set `format: cyclonedx-json` and an `output-file` ending in `sbom.cyclonedx.json`. On a pull request run, `gh api repos/nrosier/harborgate/actions/runs/<id>/artifacts --jq '.artifacts[].name'` lists `sbom-source` and `sbom-image`, and each downloaded file has `"bomFormat": "CycloneDX"`.
4. Grype SARIF under `grype-engine`. Check: `gh api 'repos/nrosier/harborgate/code-scanning/analyses?ref=refs/pull/<n>/merge' --jq '.[] | [.tool.name, .category] | @tsv'` lists `Grype` with `grype-engine/source` and `grype-engine/image` (decision 5).
5. Trivy CVE, secret and IaC under `trivy-engine`. Check: both Trivy steps set `scanners: vuln,secret,misconfig`, and the same analyses call lists `Trivy` with `trivy-engine/source` and `trivy-engine/image` (decision 5).
6. Uploads with `if: always()`. Check: the `if` of every `upload-sarif` step contains `always()`. Behaviour test on a throwaway pull request that is closed unmerged: point the Grype `sbom` input at a file that does not exist. The Grype step fails, the Trivy step and the Trivy upload still succeed, and `trivy-engine/*` appears for that ref.
7. Least-privilege permissions. Check: top-level `permissions: {}`, `grep -n 'id-token' .github/workflows/security-scan.yml` finds nothing, `security-events: write` appears only under `source` and `image`, and `issues: write` only under `report`.
8. One issue, no duplicate. Check: unit tests for `summarise` and `upsertIssue` with SARIF fixtures and a stubbed `github` (`node --test .github/scripts/`). Cases: no findings and no issue (`none`); findings and no issue (`created`); findings and an existing marker issue (`updated`, no create call); two marker issues (the lowest number is updated, with a warning); a `security` PR with the marker in its body (ignored); no findings with one input `null` and a marker issue (`none`, the issue stays open); a score of exactly 9.0 (Critical); a score of 6.9 (not counted); no findings, complete, with a marker issue (`closed`: body replaced, one comment, `state: 'closed'`); no findings, complete, no marker issue (`none`, no close call). The live part is criterion 13.
9. Pins at the latest version, recorded in the PR. Check: `grep -nE '^\s*(-\s*)?uses:' .github/workflows/security-scan.yml | grep -vE '@[0-9a-f]{40} # v[0-9]'` prints nothing. Each SHA equals the dereferenced `gh api repos/<o>/<r>/git/ref/tags/<tag>` for the latest release on the day the workflow is built. The body of the workflow PR has the version table.
10. SARIF 2.1.0. Check: "SARIF validation" above, for all four files.
11. Passes on a pull request and shows in the Security tab. Check: on the workflow's own pull request (from a branch, not a fork), `gh pr checks <n>` shows "Security scan (source)" and "Security scan (image)" passing, and the analyses call in criterion 4 returns all four categories. Also (decisions 6 and 10): `gh pr checks <n>` shows no Grype or Trivy Code Scanning check with a `fail` result, and `gh api repos/nrosier/harborgate/rulesets/<id>` lists neither new job name among the required checks.
12. No existing workflow broken or removed. Check: `git diff --name-status origin/main -- .github/workflows` shows only `A .github/workflows/security-scan.yml`, and every required check in the `Protect main` ruleset passes on that pull request. The `Trivy scan` job in `docker.yml` is unchanged (decision 9).
13. Live check. UNVERIFIED until a scheduled run: after the next Monday 04:00 UTC run, `gh api 'repos/nrosier/harborgate/issues?labels=security&state=open' --jq '[.[] | select(.pull_request == null) | select(.body | startswith("<!-- harborgate-ci:security-scan -->"))] | length'` is 1 when that run's `report` job logged High or Critical counts, and it is still 1 after a second scheduled run. Then, in the first later scheduled run whose `report` job logs zero High and Critical findings with all inputs present, the same call returns 0 and the issue is closed with the comment in "Scheduled issue". A `workflow_dispatch` run leaves the issue as it was (decision 8): the `report` job is skipped, so the same call returns the same value before and after. The issue's own wording for criterion 13, "a scheduled or manual run", is superseded by decision 8. The issue body is not edited by this spec.

Criteria 1 to 7 and 9 to 12 can be fully tested from the repository and one pull request run. Criterion 8 is tested through the script's unit tests, and its live half is criterion 13. Criterion 13 needs a scheduled run.

### Open questions

- Questions 1 to 8 of the first version of this section are answered by decisions 5 to 12 (2026-11-07, user, issue #227) and are recorded in the rules above. Part (a) of question 9, the categories, is answered by decision 13.
- OPEN (2026-11-07, #227) 9, published image details (decision 11 says the weekly run also scans `ghcr.io/nrosier/harborgate:latest`; decision 13 fixed its categories, see "Categories"): (a) whether its counts are a row in the `security` issue table and part of `total` and `complete`; (b) what the run does when `latest` cannot be pulled (for example, before the first `v*` release). Until the user answers, the implementation must not change `total`.

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
  - GitHub Actions: the `github-actions` manager updates every `sha # vX.Y.Z` pin. Decided (2026-11-07, spec author, #227): `renovate.json` must also extend `customManagers:githubActionsVersions`, so the `SYFT_VERSION`, `GRYPE_VERSION` and `TRIVY_VERSION` values in `security-scan.yml` are updated too. See "Security scanning workflow", "Pinning (d3) and updates".

## Repo hygiene

- `SECURITY.md`: security reporting policy.
- `.github/CODEOWNERS`: code ownership.
- `.github/ISSUE_TEMPLATE/`: bug report, feature request, and template config.
- `CHANGELOG.md`: release notes, updated before each tag. Each release also bumps the version in every version file and verifies the built binary before tagging, and published tags are never moved (see [deployment.md](deployment.md) Releases).
- `.gitignore`: see [deployment.md](deployment.md).

## Schema and SARIF checks

- SARIF output is validated against the SARIF 2.1.0 JSON schema after changes to the converter. The SARIF files from `security-scan.yml` are validated the same way (see "Security scanning workflow", "SARIF validation").
- Decided: 2026-11-02. The official SARIF 2.1.0 JSON schema is vendored into the repo under `backend/tests/schemas/`. Verified (2026-11-07): the file is `backend/tests/schemas/sarif-schema-2.1.0.json` (OASIS errata 01), with its SHA-256 in `backend/tests/schemas/README.md`.
