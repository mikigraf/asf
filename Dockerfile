# syntax=docker/dockerfile:1.7

FROM rust:1.97.1-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --locked --release --bins

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 asf \
    && useradd --system --uid 10001 --gid asf --home-dir /nonexistent --shell /usr/sbin/nologin asf \
    && install --directory --owner=asf --group=asf /var/lib/asf/artifacts /opt/asf/migrations

COPY --from=builder /build/target/release/asf /usr/local/bin/asf
COPY --from=builder /build/target/release/asf-server /usr/local/bin/asf-server
COPY --from=builder /build/migrations /opt/asf/migrations

ENV ASF_ARTIFACT_ROOT=/var/lib/asf/artifacts \
    ASF_MIGRATIONS_DIR=/opt/asf/migrations

USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/asf-server"]
CMD ["all"]
