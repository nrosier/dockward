# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS frontend
WORKDIR /build
# The lockfile is copied first, so the npm ci layer is reused until dependencies change.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

# The frontend is built before the backend so rust-embed can embed
# /src/frontend/dist (relative to the backend crate: ../frontend/dist).
FROM rust:1.100.0-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS backend
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
    cargo auditable build --release --locked && cp target/release/dockward /dockward
# The source commit. Required: the build fails without it, so every image carries
# org.opencontainers.image.revision. Dockward reads that label on the image it scans.
# Checked in the builder because the scratch runtime stage has no shell. Declared after the
# build, so a new commit does not invalidate the cargo layer.
ARG REVISION
RUN test -n "$REVISION" || { echo 'REVISION build argument is required (the source commit)' >&2; exit 1; }

# The files the scratch image needs, built where there is a shell: the system roots for
# outbound TLS (rustls-platform-verifier reads /etc/ssl/certs/ca-certificates.crt),
# /data for the runtime user, and /tmp at 1777 for SQLite temporary files.
# The repository index is pinned by the alpine:3.24 tag, so the version follows the release branch.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS rootfs
RUN apk add --no-cache ca-certificates \
    && mkdir -p /rootfs/etc/ssl/certs /rootfs/data /rootfs/tmp \
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chown 65532:65532 /rootfs/data \
    && chmod 1777 /rootfs/tmp

# Pinned scanner binaries (decisions 28-29, #482, #483). Built here from the source of the latest
# stable upstream tag with the latest stable Go, not taken from the release images, so the Go
# standard library in each binary is the one we choose. Each tag is cloned from the public GitHub
# repository and must resolve to the pinned commit, or the build fails. The tag, the commit and
# the Go release are checked by scripts/check-scanner-pins.sh and
# scripts/check-scanner-versions.sh (CI and the release steps). CGO_ENABLED=0 keeps each binary
# static, so it runs on scratch. GOTOOLCHAIN=local forbids a toolchain download, so the build
# uses the pinned image's Go or fails. The output is linux/amd64, the platform the image ships for.
# Go builder: golang:1.27.4-alpine, pinned by index digest.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS gobuild
ARG GO_VERSION=go1.27.4
RUN apk add --no-cache git \
    && test "$(go env GOVERSION)" = "$GO_VERSION" \
    || { echo "builder Go is $(go env GOVERSION), expected $GO_VERSION" >&2; exit 1; }
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local

# trivy v0.76.2
# Tag v0.76.2 is a lightweight tag on commit 3f6334d223b52188324af3b9923b4249cd206652.
# Build flags from upstream goreleaser.yml at the tag (no build tags). The version is injected
# without the leading v, as goreleaser's {{.Version}} does, so `trivy --version` prints 0.76.2.
# The module github.com/klauspost/compress is forced to v1.20.5 (upstream v0.76.2 pins v1.20.1,
# which carries CVE-2026-116591, issue #387; v1.20.2 is the first fixed version). `go get` edits
# go.mod and go.sum in the cloned source only, and the build fails unless the binary reports it.
FROM gobuild AS trivy
ARG TRIVY_VERSION=v0.76.2
ARG TRIVY_COMMIT=3f6334d223b52188324af3b9923b4249cd206652
ARG KLAUSPOST_COMPRESS_VERSION=v1.20.5
WORKDIR /src/trivy
RUN git clone --quiet --depth 1 --branch "$TRIVY_VERSION" https://github.com/aquasecurity/trivy.git . \
    && test "$(git rev-parse HEAD)" = "$TRIVY_COMMIT" \
    || { echo "trivy $TRIVY_VERSION does not resolve to $TRIVY_COMMIT" >&2; exit 1; }
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go get "github.com/klauspost/compress@${KLAUSPOST_COMPRESS_VERSION}" \
    && go build -ldflags="-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION#v}" -o /out/trivy ./cmd/trivy \
    && test "$(go version /out/trivy)" = "/out/trivy: $(go env GOVERSION)" \
    && go version -m /out/trivy | grep -Eq "github.com/klauspost/compress[[:space:]]+${KLAUSPOST_COMPRESS_VERSION}[[:space:]]" \
    || { echo "trivy binary does not report klauspost/compress ${KLAUSPOST_COMPRESS_VERSION}" >&2; exit 1; }

# grype v0.122.1
# Tag v0.122.1 is an annotated tag (object 7f47ebe808ea6c8162d3bc630efc237c533c545c) on commit
# 8f3ddeddc4a4ed6314248aaf0a7c510f98db8882. Build tags from upstream .goreleaser.yaml at the tag. The
# version is injected without the leading v, as goreleaser's {{.Version}} does.
FROM gobuild AS grype
ARG GRYPE_VERSION=v0.122.1
ARG GRYPE_COMMIT=8f3ddeddc4a4ed6314248aaf0a7c510f98db8882
WORKDIR /src/grype
RUN git clone --quiet --depth 1 --branch "$GRYPE_VERSION" https://github.com/anchore/grype.git . \
    && test "$(git rev-parse HEAD)" = "$GRYPE_COMMIT" \
    || { echo "grype $GRYPE_VERSION does not resolve to $GRYPE_COMMIT" >&2; exit 1; }
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -tags "containers_image_openpgp,exclude_graphdriver_btrfs" -ldflags="-s -w -X main.version=${GRYPE_VERSION#v}" -o /out/grype ./cmd/grype \
    && test "$(go version /out/grype)" = "/out/grype: $(go env GOVERSION)"

FROM rootfs AS rootfs-with-scanners
COPY --from=trivy /out/trivy /rootfs/usr/local/bin/trivy
COPY --from=grype /out/grype /rootfs/usr/local/bin/grype
# The licence and notice texts of dockward, Trivy and Grype (Apache-2.0 for the scanners), taken
# from the files the About dialog shows, so the image and the dialog carry the same text.
COPY --from=frontend /build/src/licenses/ /rootfs/usr/share/licenses/

FROM scratch
ARG REVISION
# One COPY of the tree keeps the owner and mode of each entry: /data owned by 65532 and
# /tmp at 1777. Copying a directory on its own copies only its contents, and --chmod
# drops the sticky bit.
COPY --from=rootfs-with-scanners /rootfs/ /
COPY --from=backend /dockward /usr/local/bin/dockward
USER 65532:65532
EXPOSE 8080
ENV DOCKWARD_DATA_DIR=/data
VOLUME ["/data"]
# Same values as docker-compose.yml. Exec form: the image has no shell.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/dockward", "healthcheck"]
LABEL org.opencontainers.image.title="Dockward" \
      org.opencontainers.image.source="https://github.com/nrosier/dockward" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Dockward: local container image scanner and GitHub Code Scanning relay." \
      org.opencontainers.image.revision="$REVISION"
ENTRYPOINT ["/usr/local/bin/dockward"]
