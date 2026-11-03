# Deployment

Purpose: container build, compose file, Traefik and Cloudflare routing, volumes, health endpoint, repo hygiene, and releases.

## Container

- Single Docker container. Multi-stage Dockerfile: Node (frontend build), then Rust (backend build), then a runtime stage.
- Runtime user: `65532:65532`. Data directory: `HARBORGATE_DATA_DIR=/data`.
- Exposes port 8080.
- Frontend assets are embedded in the binary. See [architecture.md](architecture.md).

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

## Volumes and state

- Persistent state is in the named volume `data`, mounted at `/data`.
- Keep `.env` (with `HARBORGATE_ENCRYPTION_KEY`) out of git.

## Health

- Health endpoint: `GET /healthz`. Provisional.
- Used by the docker-smoke check and the compose healthcheck.
- Decided: `docker-compose.yml` has a healthcheck that runs `wget -qO- http://127.0.0.1:8080/healthz` (busybox wget in alpine:3.20), with interval 30s, timeout 3s, retries 3, and start_period 10s.

## Repo hygiene

- `.gitignore` is required before the first commit. It must exclude `target/`, `node_modules/`, `dist/`, `.env`, `data/`, `*.db`, `*.sqlite`, and `*.key`.
- Repo hygiene files: `SECURITY.md`, `CODEOWNERS`, issue templates, `CHANGELOG.md`.

## Releases

- Create a semver tag `vMAJOR.MINOR.PATCH`.
- Pushing the tag triggers the Docker publish job.
- Update `CHANGELOG.md` before tagging.
- Image publish is to `ghcr.io/<owner>/harborgate`. The `:latest` tag is applied only from `main`.

## Backup and restore

- Backup and restore procedures are in [security.md](security.md). Backup is created from the admin UI (Settings > Backup and restore). Restore is the CLI command `harborgate restore <file>`, run with the app stopped (Decided 2026-11-03). Restore steps are in `docs/SETUP.md`.
