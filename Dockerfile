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
WORKDIR /src/backend
COPY backend/ ./
COPY --from=frontend /build/dist /src/frontend/dist
ENV SQLX_OFFLINE=true
# A cache mount is not part of the layer, so the binary is copied out of target/.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/backend/target \
    cargo build --release --locked && cp target/release/harborgate /harborgate

FROM alpine:3.24
# System roots for outbound TLS: rustls-platform-verifier reads the OS trust store.
# The repository index is pinned by the alpine:3.24 tag, so the version follows the release branch.
RUN apk add --no-cache ca-certificates
RUN mkdir -p /data && chown 65532:65532 /data
COPY --from=backend /harborgate /usr/local/bin/harborgate
USER 65532:65532
EXPOSE 8080
ENV HARBORGATE_DATA_DIR=/data
VOLUME ["/data"]
# Same values as docker-compose.yml. Uses busybox wget, which is in the alpine base image.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
LABEL org.opencontainers.image.title="HarborGate" \
      org.opencontainers.image.source="https://github.com/nrosier/harborgate" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Harbor to GitHub Code Scanning relay"
ENTRYPOINT ["/usr/local/bin/harborgate"]
