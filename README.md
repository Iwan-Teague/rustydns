# RustyDNS

[![CI](https://github.com/Iwan-Teague/rustydns/actions/workflows/ci.yml/badge.svg)](https://github.com/Iwan-Teague/rustydns/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A privacy-first, security-hardened DNS resolver for home and small-office networks,
built in Rust. RustyDNS acts as a local DNS proxy that:

- **Blocks ads, trackers, and malware domains** using community blocklists (Pi-hole
  compatible hosts files, AdGuard filter lists, and RPZ zone files)
- **Encrypts all upstream queries** over DNS-over-HTTPS (RFC 8484) or DNS-over-QUIC
  (RFC 9250) — plain DNS over UDP/TCP is not used
- **Strips client subnet information** from upstream queries (RFC 7871) so upstream
  resolvers cannot see your network's IP address
- **Minimises query names** sent to upstream resolvers (RFC 7816) so intermediate
  servers receive only the labels they need
- **Validates DNSSEC** and rejects forged upstream responses with no silent fallback
- **Anonymises client logs** at /16 (IPv4) or /64 (IPv6) prefix granularity — full
  IPs are never logged by default
- **Integrates with the Rusty Suite mesh** for per-node DNS policy (planned)

Security, privacy, and anonymity are first-class design constraints. All other
trade-offs — performance, convenience, feature completeness — are secondary.

---

## Quick Start

### Prerequisites

- Rust **1.88+** (install from [rustup.rs](https://rustup.rs)) — pinned by `hickory 0.26`
- Linux with systemd, **or** Docker, for the production-hardened deployment paths
- A DoH upstream resolver (e.g. `https://dns.quad9.net/dns-query`)

### Run with Docker (fastest path)

```sh
git clone https://github.com/Iwan-Teague/rustydns.git
cd rustydns
cp rustydns.example.toml rustydns.toml
$EDITOR rustydns.toml
docker compose up -d
```

The shipped `docker-compose.yml` enforces the AGENTS.md security posture:
read-only rootfs, `cap_drop: ALL` + `CAP_NET_BIND_SERVICE`,
`no-new-privileges`, json-file log cap. Full image walkthrough lives in
[`docs/deployment-docker.md`](docs/deployment-docker.md).

### Build from source

```sh
git clone https://github.com/Iwan-Teague/rustydns.git
cd rustydns
cargo build --release
```

### Install on systemd

```sh
sudo bash scripts/install.sh
```

The install script:

1. Creates a `rustydns` system user and group
2. Copies the binary to `/usr/local/bin/rustydns` (mode 750, `root:rustydns`)
3. Installs an example config at `/etc/rustydns/rustydns.toml` (mode 640, `rustydns:rustydns`)
4. Installs the systemd unit and enables it

### Configure

Edit `/etc/rustydns/rustydns.toml`. The most important fields:

```toml
[server]
# ⚠ Binding to 0.0.0.0 exposes the resolver to ALL network interfaces.
# Use "127.0.0.1:53" if you only need local resolution, or a specific
# interface IP (e.g. "192.168.1.1:53") to serve your LAN only.
# Never expose port 53 to the public internet.
listen = "127.0.0.1:53"

[[resolvers]]
url      = "https://dns.quad9.net/dns-query"
protocol = "doh"   # or "doq"

[[blocklist.sources]]
url    = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
format = "hosts"
```

Then restart the daemon:

```sh
sudo systemctl restart rustydns
sudo systemctl status rustydns
```

---

## Architecture

```
Client query
     │
     ▼
┌─────────────────┐
│  Authority zone  │  Local mesh records (.rusty. zone) — checked first
└────────┬────────┘
         │ no match
         ▼
┌─────────────────┐
│  Blocklist      │  AHashSet lookup — O(1), lock-free hot-reload via arc-swap
└────────┬────────┘
         │ not blocked
         ▼
┌─────────────────┐
│  Cache          │  Bounded LRU (moka) with TTL enforcement
└────────┬────────┘
         │ cache miss
         ▼
┌─────────────────┐
│  Resolver       │  DoH / DoQ to upstream, DNSSEC validation, ECS stripped,
│                 │  query name minimised, padded to fixed-size blocks
└─────────────────┘
```

For a detailed description of each component, see [`docs/architecture.md`](docs/architecture.md).

---

## Privacy Features

| Feature                                  | Status                                  | RFC       |
|------------------------------------------|-----------------------------------------|-----------|
| DNS-over-HTTPS upstream                  | Implemented                             | RFC 8484  |
| DNS-over-QUIC upstream                   | Implemented (via hickory `quic-ring`)   | RFC 9250  |
| DNS-over-TLS listener                    | Implemented (`server.dot_listen`)       | RFC 7858  |
| DNS-over-HTTPS listener                  | Implemented (`server.doh_listen`)       | RFC 8484  |
| TLS 1.3 floor for upstreams              | Implemented (`upstream.min_tls_version`)| RFC 8446  |
| EDNS0 Client Subnet stripping            | Implemented (never set on upstreams)    | RFC 7871  |
| DNSSEC validation                        | Implemented (`upstream.dnssec_validation`) | RFC 4033 |
| Randomised upstream selection            | Implemented (`upstream.randomize_upstream_selection`) | — |
| Fail-closed on upstream failure          | Implemented (`upstream.fail_closed`)    | —         |
| Client IP anonymisation (/16 IPv4, /64 IPv6) | Implemented                         | —         |
| In-memory query log (hashed qname, anonymised client) | Implemented                | —         |
| Query Name Minimisation                  | Pending (hickory 0.26 doesn't expose)   | RFC 7816  |
| Query/response padding                   | Pending (hickory 0.26 doesn't expose)   | RFC 8467  |

---

## Security Design

- **`#![forbid(unsafe_code)]`** in all first-party crates
- **`rustls`** for all TLS — no OpenSSL dependency
- **TLS 1.3** minimum (TLS 1.2 configurable with startup warning)
- **TLS certificate validation always on** — there is no `verify_tls_certs = false` option
- **Fail-closed** — on validation failure or upstream error, return SERVFAIL; no stale answers
- **HTTPS-only blocklist sources** — `http://` URLs are rejected at startup
- **RPZ passthru injection protection** — untrusted blocklist sources cannot inject allowlist entries
- **`panic = "abort"`** in release builds — no unwinding machinery
- **Systemd hardening** — `MemoryDenyWriteExecute`, `ProtectSystem=strict`, `NoNewPrivileges`, minimal capabilities
- **Config file permission check** at startup — world-readable config is a hard error
- **`deny_unknown_fields`** on config structs — typos that would silently disable security options are caught at startup

Read the full threat model and deployment checklist in [`docs/security.md`](docs/security.md).

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/architecture.md`](docs/architecture.md) | Component overview, data flow, crate boundaries |
| [`docs/security.md`](docs/security.md) | Threat model, countermeasures, deployment checklist |
| [`docs/blocklist-format.md`](docs/blocklist-format.md) | Supported blocklist formats, source security, RPZ passthru |
| [`docs/integration-rustynet.md`](docs/integration-rustynet.md) | Rusty Suite mesh integration, per-node policy |
| [`docs/operator-endpoints.md`](docs/operator-endpoints.md) | `/metrics`, `/health`, `/queries` reference, privacy properties |
| [`docs/deployment-docker.md`](docs/deployment-docker.md) | Image layout, capability model, compose example, troubleshooting |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability (private channels only) |
| [`AGENTS.md`](AGENTS.md) | Invariants and rules for AI coding agents working on this repo |

---

## Project Structure

```
rustydns/
├── Cargo.toml                    # Workspace root
├── rustydns.example.toml         # Annotated example configuration
├── AGENTS.md                     # Coding-agent invariants
├── crates/
│   ├── rustydns-core/            # Shared types: config, errors, DNS records, client identity
│   ├── rustydns-blocklist/       # Blocklist engine, parser, hot-reload
│   ├── rustydns-authority/       # Local zone authority (Rusty Suite mesh records)
│   ├── rustydns-resolver/        # Upstream DoH/DoQ resolver (stub)
│   └── rustydnsd/                # Daemon entry point
├── docs/
├── install/
│   └── rustydns.service          # Systemd unit with kernel hardening
└── scripts/
    └── install.sh                # Installation script
```

---

## Configuration Reference

See [`rustydns.example.toml`](rustydns.example.toml) for a fully annotated example.
The most security-sensitive options:

| Option | Default | Notes |
|--------|---------|-------|
| `server.listen` | `"127.0.0.1:53"` | ⚠ `0.0.0.0` exposes to all interfaces |
| `privacy.log_client_ips` | `false` | Full IPs; enable only for debugging |
| `privacy.log_queries_to_disk` | `false` | Queries are in-memory only by default |
| `privacy.anonymize_prefix_v4` | `16` | Last two octets zeroed; do not reduce |
| `resolver.dnssec` | `true` | Do not disable |
| `resolver.strip_ecs` | `true` | Do not disable |
| `blocklist.trusted_rpz_sources` | `[]` | Only add URLs you control |
| `metrics_listen` | `"127.0.0.1:9153"` | ⚠ Do not change to `0.0.0.0` |

---

## Contributing

Before modifying this repository, read [`AGENTS.md`](AGENTS.md). It lists the
security and privacy invariants that must be upheld. Any change that weakens an
invariant must include a documented threat model justification.

All pull requests must pass `cargo check`, `cargo clippy -- -D warnings`, and
`cargo deny check advisories`.

---

## License

Dual-licensed under either of:

- [MIT License](LICENSE-MIT) (see `LICENSE-MIT`)
- [Apache License, Version 2.0](LICENSE-APACHE) (see `LICENSE-APACHE`)

at your option. Contributions are assumed to be made under the same terms.
