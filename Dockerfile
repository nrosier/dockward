# syntax=docker/dockerfile:1

FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/ ./
RUN npm ci --ignore-scripts && npm run build

FROM rust:1.99.1-alpine AS backend
WORKDIR /build
COPY backend/ ./
RUN cargo build --release --locked

FROM alpine:3.20
RUN mkdir -p /data /app/static && chown 65532:65532 /data
COPY --from=backend /build/target/release/harborgate /usr/local/bin/harborgate
COPY --from=frontend /build/dist/ /app/static/
USER 65532:65532
EXPOSE 8080
ENV HARBORGATE_DATA_DIR=/data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/harborgate"]
