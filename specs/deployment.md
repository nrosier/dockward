# Deployment

Purpose: container build, compose file, Traefik and Cloudflare routing, volumes, health endpoint, repo hygiene, and releases.

## Container

- Single Docker container. Multi-stage Dockerfile: Node (frontend build), then Rust (backend build), then a runtime stage.
- Runtime user: `65532:65532`. Data directory: `HARBORGATE_DATA_DIR=/data`.
- Exposes port 8080.
- Frontend assets are embedded in the binary. See [architecture.md](architecture.md).
- Runtime base image: Decided (2026-11-03): `alpine:3.24`, supported until 2028-06-01. `alpine:3.20` reached end of life on 2026-04-01. Source: https://endoflife.date/alpine-linux.
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

- Health endpoint: `GET /healthz`. Provisional.
- Used by the docker-smoke check and the compose healthcheck.
- Decided: `docker-compose.yml` has a healthcheck that runs `wget -qO- http://127.0.0.1:8080/healthz` (busybox wget in the alpine runtime image), with interval 30s, timeout 3s, retries 3, and start_period 10s.

## Repo hygiene

- `.gitignore` is required before the first commit. It must exclude `target/`, `node_modules/`, `dist/`, `.env`, `data/`, `*.db`, `*.sqlite`, and `*.key`.
- Repo hygiene files: `SECURITY.md`, `CODEOWNERS`, issue templates, `CHANGELOG.md`.

## Releases

- Create a semver tag `vMAJOR.MINOR.PATCH`.
- Pushing the tag triggers the Docker publish job.
- Update `CHANGELOG.md` before tagging.
- Image publish is to `ghcr.io/<owner>/harborgate`. The `:latest` tag is applied only from `main`.
- Tags: Decided (2026-11-03): `sha-<7 hex>` on every published build; `<major>.<minor>.<patch>` and `<major>.<minor>` on `v*` tags; `latest` only from `main`. A `v*` tag never moves `latest`. The publish flow is in [testing-and-ci.md](testing-and-ci.md).

## Backup and restore

- Backup and restore procedures are in [security.md](security.md). Backup is created from the admin UI (Settings > Backup and restore). Restore is the CLI command `harborgate restore <file>`, run with the app stopped (Decided 2026-11-03). Restore steps are in `docs/SETUP.md`.
