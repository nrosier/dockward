# Deployment

Purpose: container build, compose file, Traefik and Cloudflare routing, volumes, health endpoint, repo hygiene, and releases.

## Container

- Single Docker container. Multi-stage Dockerfile: Node (frontend build), then Rust (backend build), then a runtime stage.
- Runtime user: `65532:65532`. Data directory: `HARBORGATE_DATA_DIR=/data`.
- Exposes port 8080.
- Frontend assets are embedded in the binary. See [architecture.md](architecture.md).
- Runtime base image: Decided (2026-11-09, user, issue #269, decision 3): `scratch`. The image holds only the static binary, the CA bundle, `/data`, and `/tmp`. It has no shell and no package manager. The binary is static (TLS through the compiled-in aws-lc, pure-Rust flate2, bundled SQLite), the frontend is embedded, and the app spawns no processes, so nothing else is needed.
- CA bundle: Decided (2026-11-09, user, issue #269, decision 3): `/etc/ssl/certs/ca-certificates.crt` is copied from a `certs` stage on the pinned `alpine:3.24` image that runs `apk add --no-cache ca-certificates`. Outbound TLS (reqwest and lettre, both using rustls-platform-verifier) verifies against that file, or against `SSL_CERT_FILE` when set.
- Filesystem: Decided (2026-11-09, user, issue #269, decision 3): `/data` exists and is owned by `65532:65532`, so the named volume is created writable for the runtime user. `/tmp` exists, empty, at mode `1777`, for SQLite temporary files. Both are copied from a build stage that creates them, because scratch has no `RUN`.
- Build argument check: Decided (2026-11-09, user, issue #269): the `REVISION` check runs in the builder stage, because scratch has no shell. The build still fails without `REVISION`.
- Build: Decided (2026-11-09, user, issue #269, decision 2): the backend is built with `cargo auditable build --release --locked`, with `cargo-auditable` installed at a pinned version in the builder stage, so the binary carries its dependency list for the image scans ([testing-and-ci.md](testing-and-ci.md), "Image scan").
- Build stages: `node:26-alpine` and `rust:1.99.1-alpine`, matching the toolchain pins in [testing-and-ci.md](testing-and-ci.md).

## Configuration

Environment variables. Each rule lives in the linked file.

- `HARBORGATE_ENCRYPTION_KEY`: required. Format and rules in [security.md](security.md).
- `HARBORGATE_PUBLIC_URL`: Decided (2026-11-03): required. The external origin users open, for example `https://harborgate.example.com`. It must be `https://`. Decided (2026-11-03, delegated): `http://localhost` with any port is also allowed, for development. It is the only source for the OIDC `redirect_uri` (`<public url>/api/v1/auth/oidc/callback`), the webhook URL shown in the UI, and the login origin check. The app never derives these from the `Host` or `X-Forwarded-Host` header. The app refuses to start without it, like the encryption key.
- `HARBORGATE_TRUSTED_PROXIES`: Decided (2026-11-03): a comma-separated list of CIDRs for the reverse proxies whose `X-Forwarded-For` header is trusted. Default empty. The client IP rule is in [security.md](security.md), "Client IP". In the reference setup it lists Traefik's address on the `proxy` network and the address cloudflared connects to Traefik from. See "Client IP behind Cloudflare and Traefik" below. Verified (2026-11-03): Docker assigns user-defined network subnets from its default address pools: /16 networks from 172.17.0.0/16 through 172.31.0.0/16, then /20 networks from 192.168.0.0/16 (Docker docs, Networking, `default-address-pools`). The CIDR therefore differs per host and is not hard-coded in the example. Decided (2026-11-03), as implemented in `backend/src/config.rs`: every entry must be a CIDR with no host bits set, so a single address is written `/32` (IPv4) or `/128` (IPv6). An invalid entry stops startup with an error.
- `HARBORGATE_DATA_DIR`: data directory, default `/data`.
- `HARBORGATE_BACKUP_DIR`: backup directory, default `/data/backups` ([security.md](security.md)).
- `HARBORGATE_ALLOW_PRIVATE_HARBOR`, `HARBORGATE_ALLOW_PRIVATE_OIDC`, `HARBORGATE_ALLOW_PRIVATE_ALERTS`: outbound address opt-outs, default `false` ([security.md](security.md), "Outbound HTTP (SSRF)").

## Plain Docker

- Decided (2026-11-03): the documented run command is `docker run --init --env-file .env -p 8080:8080 -v harborgate_data:/data harborgate:latest`. The key comes from `.env`, never from the command line or shell history. `CLAUDE.md` and `README.md` must use this form.

## Compose

- `docker-compose.yml` is an example. Hostnames are placeholders (`harborgate.example.com`).
- Runs read-only with a `/tmp` tmpfs, `no-new-privileges`, and all capabilities dropped.
- Secrets come from `.env`. The compose file holds no key values.
- Joins the external network `proxy`.

## Traefik

- Single container runs behind Traefik on the external Docker network `proxy`.
- Traefik terminates TLS with the `cloudflare` cert resolver.
- Traefik routes by Host rule.

## Cloudflare tunnel

- A Cloudflare tunnel, configured with dockflare labels, publishes the hostname and forwards to the origin.
- The origin address is set per host in `docker-compose.yml`.

## Client IP behind Cloudflare and Traefik

Decided (2026-11-03, delegated). Why both settings are needed: [security.md](security.md), "Client IP".

1. Traefik's address: `docker inspect -f '{{(index .NetworkSettings.Networks "proxy").IPAddress}}' <traefik-container>`. To keep it stable across restarts, give Traefik a fixed `ipv4_address` on `proxy` in Traefik's own compose file. `ipv4_address` needs a network with a configured subnet. Read the subnet with `docker network inspect proxy`.
2. cloudflared's source address, as Traefik sees it: send one request through the tunnel and read `ClientHost` in Traefik's access log. It depends on how cloudflared reaches Traefik. A container on a Docker network shows its container address, and a connection to a published host port can show the bridge gateway instead.
3. Traefik static configuration: `--entryPoints.websecure.forwardedHeaders.trustedIPs=<cloudflared source address or CIDR>`.
4. HarborGate `.env`: `HARBORGATE_TRUSTED_PROXIES=<traefik address>/32,<cloudflared source address or CIDR>`.
5. Check: Admin > Health shows the client IP HarborGate derived for your own request. It must be your public IP, with source `x-forwarded-for`.

Use the narrowest ranges that work. Trusting the whole `proxy` subnet lets any container on that network send its own `X-Forwarded-For` and get around the per-IP login limits.

## Volumes and state

- Persistent state is in the named volume `data`, mounted at `/data`.
- Keep `.env` (with `HARBORGATE_ENCRYPTION_KEY`) out of git.

## Health

- Health endpoint: `GET /healthz`. Decided (2026-11-03, delegated): a liveness check of the HarborGate process only. It returns `200 {"status":"ok"}` when the HTTP server answers. It does not query SQLite, Harbor, GitHub, or the OIDC provider. Dependency state is on Admin > Health (`/api/v1/admin/health`). This matches `healthz` in `backend/src/main.rs`.
  - Why: Kubernetes' probe guidance says a liveness check must indicate unrecoverable failure only, because checking dependencies "can lead to cascading failures" (https://kubernetes.io/docs/concepts/workloads/pods/probes/). Verified (2026-11-03) in Traefik's Docker provider (`pkg/provider/docker/config.go`): a container whose health is set and is not `healthy`, including `starting`, gets an empty load balancer. A failing `/healthz` therefore takes HarborGate off the network, webhooks included. A database check that times out under write load would do that for no reason.
  - Verified (2026-11-03), Dockerfile reference, `HEALTHCHECK` (moby/buildkit `frontend/dockerfile/docs/reference.md`): the status starts as `starting`. Exit 0 means healthy, and `retries` consecutive failures mean unhealthy. During `start_period`, checks run every `start_interval` (default 5s, Docker Engine 25.0 or later) and failures do not count. With the compose values (`start_period: 10s`, `interval: 30s`), the first check runs about 5 seconds after start, so Traefik routes to HarborGate within seconds. On Docker Engine older than 25.0, the first check runs only after `interval`, so Docker Engine 25.0 or later is required.
- Used by the docker-smoke check and the compose healthcheck.
- Decided (2026-11-09, user, issue #269, decision 1): the Dockerfile `HEALTHCHECK` and the `docker-compose.yml` healthcheck run `harborgate healthcheck` in exec form (`["/usr/local/bin/harborgate", "healthcheck"]` and `["CMD", "/usr/local/bin/harborgate", "healthcheck"]`), with no shell and no `wget`, with interval 30s, timeout 3s, retries 3, and start_period 10s.
- `harborgate healthcheck`: Decided (2026-11-09, user, issue #269, decision 1): sends `GET /healthz` to `127.0.0.1` on the listen port (8080) with a 3-second timeout. It exits 0 on a `200` response and non-zero otherwise. It reads no configuration secrets, opens no database, and needs no session. It prints nothing on success and a short reason on failure, never a secret.

## Repo hygiene

- `.gitignore` is required before the first commit. It must exclude `target/`, `node_modules/`, `dist/`, `.env`, `data/`, `*.db`, `*.sqlite`, and `*.key`.
- Repo hygiene files: `SECURITY.md`, `CODEOWNERS`, issue templates, `CHANGELOG.md`.

## Releases

- Create a semver tag `vMAJOR.MINOR.PATCH`.
- Pushing the tag triggers the Docker publish job.
- Update `CHANGELOG.md` before tagging.
- Bump the version in every version file before tagging: `backend/Cargo.toml` (`[package]` version), `backend/Cargo.lock` (the `harborgate` package entry only), `frontend/package.json` (`version`), and `frontend/package-lock.json` (root package entries only). The tag must equal the version in these files.
- Build and verify the binary reports the new version before tagging. The backend reads `CARGO_PKG_VERSION` (`backend/src/main.rs`, the startup log and the API). Verify with `cargo check --locked` plus a test or a documented run that prints the version. Do not tag until this check passes.
- Never move, delete or re-create a published tag. A bad release gets the next patch version. Published tags are immutable.
- Update `CHANGELOG.md` with a version heading that matches the tag.
- Image publish is to `ghcr.io/<owner>/harborgate`. Images are pushed to GHCR only on `v*` tags. A push to `main` and a pull request push nothing.
- Tags: Decided (2026-11-07, user, via dialogue): a `v*` tag publishes `<major>.<minor>.<patch>`, `<major>.<minor>`, and `latest`. `latest` moves to each release, so it points at the most recently tagged release, even if an older line is tagged later. There is no `sha-<7 hex>` tag. This replaces the 2026-11-03 rules that applied `latest` only from `main` and said a `v*` tag never moves `latest`. The publish flow is in [testing-and-ci.md](testing-and-ci.md).
- Image signing: Decided (2026-11-06, user, #171). Images are signed keyless with cosign by the publish job, on the digest. The expected signing identity is the OIDC issuer `https://token.actions.githubusercontent.com` and a certificate identity matching `^https://github.com/nrosier/harborgate/\.github/workflows/docker\.yml@refs/(heads/main|tags/v[0-9].*)$` (this repository's `docker.yml` on `main` or a `v*` tag). After signing, the publish job runs `cosign verify` on the same digest with the same issuer and identity pattern, and a failed verification fails the job. Operators verify with the command in [docs/SETUP.md](../docs/SETUP.md). Kubernetes admission enforcement is out of scope for now.

## Backup and restore

- Backup and restore procedures are in [security.md](security.md). Backup is created from the admin UI (Settings > Backup and restore). Restore is the CLI command `harborgate restore <file>`, run with the app stopped (Decided 2026-11-03). Restore steps are in `docs/SETUP.md`.
