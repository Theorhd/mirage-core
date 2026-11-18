# syntax=docker/dockerfile:1.7

FROM rust:1.100.0-alpine3.21 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# Copy manifests first for dependency layer caching.
COPY Cargo.toml Cargo.lock rust-toolchain.toml deny.toml ./
COPY crates/mirage-core/Cargo.toml crates/mirage-core/Cargo.toml
COPY crates/miraged/Cargo.toml crates/miraged/Cargo.toml

# Copy workspace sources.
COPY crates crates

RUN set -eu; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64)  TARGET="x86_64-unknown-linux-musl" ;; \
        aarch64) TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie -C link-arg=-Wl,-z,relro,-z,now --remap-path-prefix=/build=/src" \
    cargo build --release --locked --bin miraged --target "$TARGET"; \
    cp "/build/target/${TARGET}/release/miraged" /miraged; \
    chmod 0555 /miraged

FROM scratch

COPY --from=builder /miraged /miraged

USER 65534:65534

ENTRYPOINT ["/miraged"]
CMD ["--config", "/run/secrets/config.toml"]
