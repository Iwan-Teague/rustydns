# syntax=docker/dockerfile:1
#
# rustydnsd container image.
#
# Multi-stage build:
#   1. `builder` — Rust toolchain + workspace source, produces the
#      release binary. Cached separately via Cargo.lock + manifests
#      so source changes don't refetch deps.
#   2. `runtime` — minimal Debian slim with the binary, a non-root
#      `rustydns` user, and CAP_NET_BIND_SERVICE so we can still bind
#      port 53 without running as root.
#
# Usage:
#   docker build -t rustydnsd .
#   docker run --rm \
#     -v $(pwd)/rustydns.toml:/etc/rustydns/rustydns.toml:ro \
#     -p 53:53/udp -p 53:53/tcp -p 853:853 \
#     --read-only --tmpfs /tmp --cap-add NET_BIND_SERVICE \
#     rustydnsd

# -----------------------------------------------------------------------------
# Stage 1: builder
# -----------------------------------------------------------------------------
FROM rust:1.88-bookworm AS builder

WORKDIR /build

# Copy manifests + lockfile first to cache the dep graph independently
# of source churn. Workspace member manifests are listed individually so
# touching a source file doesn't bust the dep cache.
COPY Cargo.toml Cargo.lock ./
COPY crates/rustydns-core/Cargo.toml         crates/rustydns-core/Cargo.toml
COPY crates/rustydns-blocklist/Cargo.toml    crates/rustydns-blocklist/Cargo.toml
COPY crates/rustydns-authority/Cargo.toml    crates/rustydns-authority/Cargo.toml
COPY crates/rustydns-resolver/Cargo.toml     crates/rustydns-resolver/Cargo.toml
COPY crates/rustydnsd/Cargo.toml             crates/rustydnsd/Cargo.toml

# Bring in the real source.
COPY crates  crates
COPY deny.toml ./

# Build the release binary. LTO + strip are configured in the workspace
# root Cargo.toml, so this is a single command.
RUN cargo build --release --bin rustydnsd \
 && strip target/release/rustydnsd

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Minimal runtime: the binary only needs glibc + libcap utilities
# (for the in-process capability dropping). ca-certificates is NOT
# pulled in because rustydns-resolver ships the Mozilla CA bundle
# via `webpki-roots`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system rustydns \
 && useradd  --system --gid rustydns --no-create-home --shell /usr/sbin/nologin rustydns \
 && install -d -m 0750 -o root -g rustydns /etc/rustydns \
 && install -d -m 0750 -o rustydns -g rustydns /var/lib/rustydns

COPY --from=builder /build/target/release/rustydnsd /usr/local/bin/rustydnsd
# Capability bound to the binary so it can bind 53/853 without
# running as root.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/rustydnsd \
 && chown root:rustydns /usr/local/bin/rustydnsd \
 && chmod 0750 /usr/local/bin/rustydnsd

USER rustydns
WORKDIR /var/lib/rustydns

# tini reaps zombies + forwards SIGTERM cleanly to the daemon. Without
# it the `rustydnsd` PID is 1 inside the container, which means
# tokio's signal handlers have to do everything the init system
# normally does.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/rustydnsd"]
CMD ["--config", "/etc/rustydns/rustydns.toml"]

# Standard ports. The metrics endpoint is intentionally not exposed
# here — it's loopback-only by design (the daemon refuses to bind it
# off-loopback). If you need metrics out-of-container, terminate
# scraping at a sidecar that connects to `localhost:9153`.
EXPOSE 53/udp 53/tcp 853 8053

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:9153/health || exit 1
