# syntax=docker/dockerfile:1

FROM node:26.13.0-alpine@sha256:c6ad9e9c1d80f6eb607c26b4b0a132ff7a2344fad1c78ea3baa2a7d4c8de6d94 AS frontend
WORKDIR /build
# The lockfile is copied first, so the npm ci layer is reused until dependencies change.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

# The frontend is built before the backend so rust-embed can embed
# /src/frontend/dist (relative to the backend crate: ../frontend/dist).
FROM rust:1.99.1-alpine@sha256:27cd9befd4a05d6f6eb407c3e28365f5092f008bfc5946207cca76ae5179ef23 AS backend
# cargo-auditable embeds the dependency list in the binary, so Trivy and Grype can read
# the Rust crates in the image (specs/testing-and-ci.md). Pinned; Renovate does not track it.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-auditable --version 0.7.7 --locked
WORKDIR /src/backend
COPY backend/ ./
COPY --from=frontend /build/dist /src/frontend/dist
ENV SQLX_OFFLINE=true
# A cache mount is not part of the layer, so the binary is copied out of target/.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/backend/target \
    cargo auditable build --release --locked && cp target/release/harborgate /harborgate
# The source commit. Required: the build fails without it, so every image carries
# org.opencontainers.image.revision. HarborGate reads that label on the image it scans.
# Checked in the builder because the scratch runtime stage has no shell. Declared after the
# build, so a new commit does not invalidate the cargo layer.
ARG REVISION
RUN test -n "$REVISION" || { echo 'REVISION build argument is required (the source commit)' >&2; exit 1; }

# The files the scratch image needs, built where there is a shell: the system roots for
# outbound TLS (rustls-platform-verifier reads /etc/ssl/certs/ca-certificates.crt),
# /data for the runtime user, and /tmp at 1777 for SQLite temporary files.
# The repository index is pinned by the alpine:3.24 tag, so the version follows the release branch.
FROM alpine:3.24 AS rootfs
RUN apk add --no-cache ca-certificates \
    && mkdir -p /rootfs/etc/ssl/certs /rootfs/data /rootfs/tmp \
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chown 65532:65532 /rootfs/data \
    && chmod 1777 /rootfs/tmp

# Pinned scanner binaries (decisions 28-29). Taken from the verified release images by digest,
# never a floating tag. Each binary is static (CGO_ENABLED=0), so it runs on scratch.
FROM aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy
FROM anchore/grype@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887 AS grype

FROM rootfs AS rootfs-with-scanners
COPY --from=trivy /usr/local/bin/trivy /rootfs/usr/local/bin/trivy
COPY --from=grype /grype /rootfs/usr/local/bin/grype

FROM scratch
ARG REVISION
# One COPY of the tree keeps the owner and mode of each entry: /data owned by 65532 and
# /tmp at 1777. Copying a directory on its own copies only its contents, and --chmod
# drops the sticky bit.
COPY --from=rootfs-with-scanners /rootfs/ /
COPY --from=backend /harborgate /usr/local/bin/harborgate
USER 65532:65532
EXPOSE 8080
ENV HARBORGATE_DATA_DIR=/data
VOLUME ["/data"]
# Same values as docker-compose.yml. Exec form: the image has no shell.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/harborgate", "healthcheck"]
LABEL org.opencontainers.image.title="HarborGate" \
      org.opencontainers.image.source="https://github.com/nrosier/harborgate" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Harbor to GitHub Code Scanning relay" \
      org.opencontainers.image.revision="$REVISION"
ENTRYPOINT ["/usr/local/bin/harborgate"]
