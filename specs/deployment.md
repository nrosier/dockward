# Deployment

Purpose: container build, compose file, Traefik and Cloudflare routing, volumes, health endpoint, repo hygiene, and releases.

## Container

- Single Docker container, no Docker daemon. Multi-stage Dockerfile. Verified (2026-11-11, `Dockerfile`): the stages are `frontend` (`node:26.13.0-alpine`), `backend` (`rust:1.99.1-alpine`, `cargo auditable build --release --locked`), `rootfs` (`alpine:3.24`, CA bundle and the `/data` and `/tmp` directories), `trivy` (`aquasec/trivy` by digest), `grype` (`anchore/grype` by digest), `rootfs-with-scanners`, and a final `scratch` stage.
- Runtime base image: `scratch`. The image holds the static binary, the scanners, the CA bundle, `/data` and `/tmp`. It has no shell and no package manager. The binary is static, and the frontend is embedded.
- Binary: `/usr/local/bin/dockward` (`COPY --from=backend /dockward /usr/local/bin/dockward`). Verified (2026-11-11).
- Scanner binaries: Trivy at `/usr/local/bin/trivy` and Grype at `/usr/local/bin/grype`. Each is copied from its own digest-pinned image, never a floating tag, and runs as a child process ([integrations.md](integrations.md), "Scanners"). Both are static.
- CA bundle: `/etc/ssl/certs/ca-certificates.crt`, copied from the `rootfs` stage on the pinned `alpine:3.24` image that runs `apk add --no-cache ca-certificates`. Outbound TLS (reqwest and lettre, both using rustls-platform-verifier) verifies against that file, or against `SSL_CERT_FILE` when set.
- Filesystem: `/data` exists and is owned by `65532:65532`, so the named volume is created writable for the runtime user. `/tmp` exists, empty, at mode `1777`, for SQLite temporary files. Both are created in the `rootfs` build stage, because scratch has no `RUN`.
- Runtime user: `USER 65532:65532`.
- Environment: `ENV DOCKWARD_DATA_DIR=/data`. The data directory holds `dockward.db` and the scanner cache under `scanner-cache` ([integrations.md](integrations.md)).
- Volume: `VOLUME ["/data"]`.
- Exposes port 8080 (`EXPOSE 8080`).
- Health check: `HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/dockward", "healthcheck"]`. Exec form, no shell. Verified (2026-11-11, `Dockerfile`).
- Entrypoint: `ENTRYPOINT ["/usr/local/bin/dockward"]`. Verified (2026-11-11).
- Build argument: `REVISION` is required (the source commit). The check runs in the builder stage, because scratch has no shell, and the build fails without it. The image sets the label `org.opencontainers.image.revision` from it. Dockward reads that label on the image it scans ([integrations.md](integrations.md), "OCI labels").
- Build argument for cargo: `cargo-auditable` is installed at a pinned version (`0.7.7`) in the builder stage, so the binary carries its dependency list for the image scans ([testing-and-ci.md](testing-and-ci.md), "Security scanning workflow").
- Labels set in the image: `org.opencontainers.image.title` `Dockward`, `source` `https://github.com/nrosier/dockward`, `licenses` `MIT`, `description` `Dockward: local container image scanner and GitHub Code Scanning relay.` (set on this branch, `Dockerfile`, uncommitted at the time of writing), `revision` (from `REVISION`).
  - Verified (2026-11-11): the working tree of this branch carries the new description. The Harbor text is gone from the `Dockerfile`.
- Toolchain pins: [testing-and-ci.md](testing-and-ci.md), "Toolchain pins".

## Configuration

Environment variables. Each rule lives in the linked file. Verified (2026-11-11, `backend/src/config.rs`): every `DOCKWARD_*` name is read first; the `HARBORGATE_*` name is a deprecated fallback that is logged with its name (never its value) and is kept for 0.2 only, then removed.

- `DOCKWARD_ENCRYPTION_KEY`: required. Format and rules in [security.md](security.md).
- `DOCKWARD_OLD_ENCRYPTION_KEY`: only during key rotation ([security.md](security.md), "Key rotation").
- `DOCKWARD_PUBLIC_URL`: required. The external origin users open, for example `https://dockward.example.com`. It must be `https://`. `http://localhost` with any port is also allowed, for development. It is the only source for the OIDC `redirect_uri` (`<public url>/api/v1/auth/oidc/callback`) and the login origin check. The app never derives these from the `Host` or `X-Forwarded-Host` header. The app refuses to start without it, like the encryption key.
- `DOCKWARD_TRUSTED_PROXIES`: a comma-separated list of CIDRs for the reverse proxies whose `X-Forwarded-For` header is trusted. Default empty. The client IP rule is in [security.md](security.md), "Client IP". Every entry must be a CIDR with no host bits set, so a single address is written `/32` (IPv4) or `/128` (IPv6). An invalid entry stops startup with an error. In the reference setup it lists Traefik's address on the `proxy` network and the address cloudflared connects to Traefik from. See "Client IP behind Cloudflare and Traefik". Docker assigns user-defined network subnets from its default address pools, so the CIDR differs per host and is not hard-coded in the example (Verified 2026-11-03, Docker networking docs).
- `DOCKWARD_DATA_DIR`: data directory, default `/data`.
- `DOCKWARD_BACKUP_DIR`: backup directory, default `/data/backups` ([security.md](security.md)).
- `DOCKWARD_ALLOW_PRIVATE_REGISTRIES`: a comma-separated list of hub hosts that may resolve to private addresses. An entry written `http://host[:port]` may also use plain HTTP. Default empty ([integrations.md](integrations.md), "Address and transport rules").
- `DOCKWARD_ALLOW_PRIVATE_OIDC`, `DOCKWARD_ALLOW_PRIVATE_ALERTS`: outbound address opt-outs, default `false` ([security.md](security.md), "Outbound HTTP (SSRF)").
- `DOCKWARD_ALLOW_PRIVATE_HARBOR`: read by `backend/src/config.rs` but used by no service. `OPEN:` remove it or keep it. Harbor is removed in 0.2.0, so the setting does nothing.

Settings set by the admin in the UI (not environment variables): the scanner timeout (`scanner.timeout_s`, default 600 s), the scanner output cap (`scanner.output_max_bytes`, default 64 MiB), the image-store limit (`images.max_stored`, default 20), the pull cap and the minimum free disk space (`services/scan_settings.rs`). Verified (2026-11-11).

## Plain Docker

- The documented run command is `docker run --init --env-file .env -p 8080:8080 -v dockward_data:/data ghcr.io/nrosier/dockward:latest`. The key comes from `.env`, never from the command line or shell history. `CLAUDE.md` and `README.md` must use this form.
  - Verified (2026-11-11): `CLAUDE.md` uses the local build tag `dockward:latest`. No change is needed there.

## Compose

- `docker-compose.yml` is an example. Hostnames are placeholders (`dockward.example.com`).
- Image: `ghcr.io/nrosier/dockward:latest`. The operator pins a version tag for production.
- Runs read-only (`read_only: true`), with a `/tmp` tmpfs (`/tmp:size=64m`), `no-new-privileges`, and all capabilities dropped (`cap_drop: ALL`).
- `init: true`, because PID 1 does not reap children or forward signals.
- Secrets come from `.env` (`env_file`). The compose file holds no key values.
- Volume `data:/data`.
- Healthcheck: `test: ["CMD", "/usr/local/bin/dockward", "healthcheck"]`, `interval: 30s`, `timeout: 3s`, `retries: 3`, `start_period: 10s`. Verified (2026-11-11, `docker-compose.yml`).
- Joins the external network `proxy`.
- Logs: `json-file` with `max-size: 10m` and `max-file: 3`.

### Compose and Dockerfile health check: current state

Verified (2026-11-11) on this branch (`docs-dockward`, based on `origin/main` 8ce30f2):

- `Dockerfile:65`: `HEALTHCHECK ... CMD ["/usr/local/bin/dockward", "healthcheck"]`.
- `docker-compose.yml:26`: `test: ["CMD", "/usr/local/bin/dockward", "healthcheck"]`.

Both name `/usr/local/bin/dockward`, which is the intended path. No `harborgate` path is found in either file. The health check does not reference a harborgate binary on this branch.

## Traefik

- Single container runs behind Traefik on the external Docker network `proxy`.
- Traefik terminates TLS with the `cloudflare` cert resolver.
- Traefik routes by Host rule. The labels in `docker-compose.yml` set the router rule, the `websecure` entry point, the `cloudflare` cert resolver, and the service port `8080`.

## Cloudflare tunnel

- A Cloudflare tunnel, configured with dockflare labels, publishes the hostname and forwards to the origin.
- The origin address is set per host in `docker-compose.yml`.

## Client IP behind Cloudflare and Traefik

Decided (2026-11-03, delegated). Why both settings are needed: [security.md](security.md), "Client IP".

1. Traefik's address: `docker inspect -f '{{(index .NetworkSettings.Networks "proxy").IPAddress}}' <traefik-container>`. To keep it stable across restarts, give Traefik a fixed `ipv4_address` on `proxy` in Traefik's own compose file. `ipv4_address` needs a network with a configured subnet. Read the subnet with `docker network inspect proxy`.
2. cloudflared's source address, as Traefik sees it: send one request through the tunnel and read `ClientHost` in Traefik's access log. It depends on how cloudflared reaches Traefik. A container on a Docker network shows its container address, and a connection to a published host port can show the bridge gateway instead.
3. Traefik static configuration: `--entryPoints.websecure.forwardedHeaders.trustedIPs=<cloudflared source address or CIDR>`.
4. Dockward `.env`: `DOCKWARD_TRUSTED_PROXIES=<traefik address>/32,<cloudflared source address or CIDR>`.
5. Check: Admin > Health shows the client IP Dockward derived for your own request. It must be your public IP, with source `x-forwarded-for`.

Use the narrowest ranges that work. Trusting the whole `proxy` subnet lets any container on that network send its own `X-Forwarded-For` and get around the per-IP login limits.

## Volumes and state

- Persistent state is in the named volume `data`, mounted at `/data`. It holds the database `dockward.db`, the scanner caches under `scanner-cache`, the OCI layouts for stored images, and backups under `backups`.
- Keep `.env` (with `DOCKWARD_ENCRYPTION_KEY`) out of git.
- A database that still has the old `repo_mappings` table is refused at start (Verified 2026-11-11, `db/mod.rs`, test `legacy_repo_mappings_database_is_refused_before_migration`). There is no data migration from HarborGate to Dockward. An operator starts with an empty volume.

## Health

- Health endpoint: `GET /healthz`. A liveness check of the Dockward process only. It returns `200 {"status":"ok"}` when the HTTP server answers. It does not query SQLite, the registries, GitHub or the OIDC provider. Dependency state is on Admin > Health (`/api/v1/admin/health`).
  - Why: Kubernetes' probe guidance says a liveness check must indicate unrecoverable failure only, because checking dependencies "can lead to cascading failures" (https://kubernetes.io/docs/concepts/workloads/pods/probes/). Verified (2026-11-03) in Traefik's Docker provider (`pkg/provider/docker/config.go`): a container whose health is set and is not `healthy`, including `starting`, gets an empty load balancer. A failing `/healthz` therefore takes Dockward off the network. A database check that times out under write load would do that for no reason.
  - Verified (2026-11-03), Dockerfile reference, `HEALTHCHECK` (moby/buildkit `frontend/dockerfile/docs/reference.md`): the status starts as `starting`. Exit 0 means healthy, and `retries` consecutive failures mean unhealthy. During `start_period`, checks run every `start_interval` (default 5s, Docker Engine 25.0 or later) and failures do not count. Docker Engine 25.0 or later is required for the first check to run early.
- `dockward healthcheck` (`backend/src/cli.rs`, verified 2026-11-11): sends `GET /healthz` to `http://127.0.0.1:8080/healthz` with a 3-second timeout. It exits 0 only on a `200` response and non-zero otherwise. It prints nothing on success and a short reason on failure, never a secret. It reads no configuration, opens no database and needs no session. The probe URL is the constant `HEALTHCHECK_URL`.
- Used by the Dockerfile `HEALTHCHECK`, the compose healthcheck and the docker-smoke check.

## Repo hygiene

- `.gitignore` is required before the first commit. It must exclude `target/`, `node_modules/`, `dist/`, `.env`, `data/`, `*.db`, `*.sqlite`, and `*.key`.
- Repo hygiene files: `SECURITY.md`, `CODEOWNERS`, issue templates, `CHANGELOG.md`.

## Releases

- Create a semver tag `vMAJOR.MINOR.PATCH`.
- Pushing the tag triggers the Docker publish job (`.github/workflows/docker.yml`, on `v*` tags only).
- Update `CHANGELOG.md` before tagging. The 0.2.0 entry must say that Harbor is removed, that there is no data migration from HarborGate, and that the `HARBORGATE_*` variables are deprecated.
- Bump the version in every version file before tagging: `backend/Cargo.toml` (`[package]` version, `name = "dockward"`), `backend/Cargo.lock` (the `dockward` package entry only), `frontend/package.json` (`version`), and `frontend/package-lock.json` (root package entries only). The tag must equal the version in these files.
- Build and verify the binary reports the new version before tagging. The backend reads `CARGO_PKG_VERSION`. Verify with `cargo check --locked` plus a test or a documented run that prints the version. Do not tag until this check passes.
- Scanner pins: before tagging, check the latest stable Trivy and Grype releases. Confirm each Dockerfile digest resolves to that release with `docker buildx imagetools inspect aquasec/trivy@<digest>` and `docker buildx imagetools inspect anchore/grype@<digest>` (the version label or the tag list for that digest). If a newer release exists, bump the digest and the `# trivy vX.Y.Z` / `# grype vX.Y.Z` comment, and `GRYPE_VERSION` and `TRIVY_VERSION` in `security-scan.yml`. Run `scripts/check-scanner-pins.sh` (it also runs in CI) and record both versions in `CHANGELOG.md`. Bundled at the time of writing (2026-11-13): Trivy v0.76.2 (`sha256:8f6bb947...`) and Grype v0.121.3 (`sha256:13113eec...`).
- Never move, delete or re-create a published tag. A bad release gets the next patch version. Published tags are immutable.
- Image publish is to `ghcr.io/<owner>/dockward`, so `ghcr.io/nrosier/dockward`. Verified (2026-11-11, `docker.yml`, `images: ghcr.io/${{ github.repository_owner }}/dockward`). Images are pushed to GHCR only on `v*` tags. A push to `main` and a pull request push nothing.
- Tags: a `v*` tag publishes `<major>.<minor>.<patch>`, `<major>.<minor>`, and `latest` (Decided 2026-11-07, user). `latest` moves to each release, so it points at the most recently tagged release, even if an older line is tagged later. There is no `sha-<7 hex>` tag. Verified (2026-11-11, `docker.yml` metadata: `type=semver` and `type=raw,value=latest`).
- Image signing: images are signed keyless with cosign by the publish job, on the digest (`docker.yml`, `cosign sign` and `cosign verify`). The expected signing identity is `^https://github.com/nrosier/dockward/\.github/workflows/docker\.yml@refs/(heads/main|tags/v[0-9].*)$` with the OIDC issuer `https://token.actions.githubusercontent.com`. Verified (2026-11-11, `docker.yml` line 278). After signing, the publish job runs `cosign verify` on the same digest with the same issuer and identity pattern, and a failed verification fails the job. Operators verify with the command in [docs/SETUP.md](../docs/SETUP.md). Kubernetes admission enforcement is out of scope for now.
- Provenance and SBOM: the publish job builds with provenance `mode=max` and an SBOM, and attests build provenance ([testing-and-ci.md](testing-and-ci.md), "CI workflows").
- `OPEN:` the signing identity pattern in this spec and in `docs/SETUP.md` (not in this spec's scope) must match the new repository name before the first `v*` tag of the renamed image. The repository path in the regex is `nrosier/dockward`.

## Backup and restore

- Backup and restore procedures are in [security.md](security.md). Backup is created from the admin UI (Settings > Backup and restore). Restore is the CLI command `dockward restore <file>`, run with the app stopped (verified 2026-11-11, `backend/src/cli.rs`). Restore steps are in `docs/SETUP.md`.
