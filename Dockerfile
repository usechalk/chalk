# syntax=docker/dockerfile:1.7
# Production image for chalk-hosted (multi-tenant runtime).
#
# Build from the chalk repo root:
#   docker build -t chalk-hosted:prod .

FROM rust:1.88-bookworm AS builder
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build -p chalk-hosted --release --locked && \
    cp target/release/chalk-hosted /usr/local/bin/chalk-hosted

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -u 10001 -s /usr/sbin/nologin chalk
COPY --from=builder /usr/local/bin/chalk-hosted /usr/local/bin/chalk-hosted
USER chalk
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:9000/health || exit 1
ENTRYPOINT ["chalk-hosted"]
CMD ["serve"]
