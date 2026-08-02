# syntax=docker/dockerfile:1.7
#
# Chalk — single binary, SQLite by default, no external services.
#
#   docker build -t chalk .
#   docker run -p 8080:8080 -v chalk-data:/var/lib/chalk chalk
#
# The first run initialises the data directory and prints an admin password.
#
# WHAT THIS BUILDS: the open-source `chalk` binary from this repo. It used to
# build `chalk-hosted`, which lives in a private repository and is not a member
# of this workspace — so `docker build .` failed immediately for anyone who
# cloned the project. The hosted image belongs in the hosted repo.

# The tag matches rust-toolchain.toml. rustup honours the pin regardless, but
# only after downloading a second toolchain on every cold build.
FROM rust:1.97-bookworm AS builder
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build -p chalk-cli --release --locked && \
    cp target/release/chalk /usr/local/bin/chalk

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -u 10001 -s /usr/sbin/nologin chalk && \
    mkdir -p /var/lib/chalk && chown chalk:chalk /var/lib/chalk

COPY --from=builder /usr/local/bin/chalk /usr/local/bin/chalk
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER chalk

# Everything Chalk keeps: the SQLite database, the master encryption key, the
# SAML keypair and chalk.toml. One volume, so a backup is one directory.
VOLUME ["/var/lib/chalk"]
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve", "--port", "8080"]
