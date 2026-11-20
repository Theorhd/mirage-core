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

ARG TARGETARCH
ARG RUST_TARGET_CPU=""
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,id=mirage-target-${TARGETARCH:-host},sharing=locked \
    set -eu; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64)  TARGET="x86_64-unknown-linux-musl" ;; \
        aarch64) TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    CPU_FLAG=""; \
    if [ -n "${RUST_TARGET_CPU}" ]; then CPU_FLAG="-C target-cpu=${RUST_TARGET_CPU}"; fi; \
    RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie -C link-arg=-Wl,-z,relro,-z,now --remap-path-prefix=/build=/src --remap-path-prefix=/usr/local/cargo=/cargo ${CPU_FLAG}" \
    cargo build --release --locked --bin miraged --target "$TARGET"; \
    cp "/build/target/${TARGET}/release/miraged" /miraged; \
    chmod 0555 /miraged

FROM scratch

LABEL org.opencontainers.image.title="mirage-core" \
      org.opencontainers.image.description="Hardened Reality + VLESS + XTLS-Vision + Mux/XUDP proxy daemon" \
      org.opencontainers.image.source="https://github.com/Theorhd/mirage-core" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=builder /miraged /miraged

USER 65534:65534

ENTRYPOINT ["/miraged"]
CMD ["--config", "/run/secrets/config.toml"]
