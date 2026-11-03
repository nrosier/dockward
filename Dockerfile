# syntax=docker/dockerfile:1

FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/ ./
RUN npm ci --ignore-scripts && npm run build

# The frontend is built before the backend so rust-embed can embed
# /src/frontend/dist (relative to the backend crate: ../frontend/dist).
FROM rust:1.99.1-alpine AS backend
WORKDIR /src/backend
COPY backend/ ./
COPY --from=frontend /build/dist /src/frontend/dist
RUN cargo build --release --locked

FROM alpine:3.20
RUN mkdir -p /data && chown 65532:65532 /data
COPY --from=backend /src/backend/target/release/harborgate /usr/local/bin/harborgate
USER 65532:65532
EXPOSE 8080
ENV HARBORGATE_DATA_DIR=/data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/harborgate"]
