# RustyDNS

[![CI](https://github.com/Iwan-Teague/rustydns/actions/workflows/ci.yml/badge.svg)](https://github.com/Iwan-Teague/rustydns/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A privacy-first, security-hardened DNS resolver for home and small-office networks,
built in Rust. RustyDNS acts as a local DNS proxy that:

- **Blocks ads, trackers, and malware domains** using community blocklists
  (Pi-hole-compatible hosts files, AdGuard filter lists, and RPZ zone files —
  formats are auto-detected per source)
- **Encrypts all upstream queries** over DNS-over-HTTPS (RFC 8484) or
  DNS-over-QUIC (RFC 9250). Plain DNS to upstream is opt-in only and emits a
  startup warning every time
- **Strips EDNS0 Client Subnet** from upstream queries (RFC 7871) so upstream
  resolvers never learn your network's IP range
- **Validates DNSSEC** and rejects forged upstream responses with no silent
  fallback (fail-closed → `SERVFAIL`)
- **Anonymises client logs** at /16 (IPv4) or /64 (IPv6) prefix granularity —
  full IPs are never logged by default
- **Integrates with the Rusty Suite mesh** — signed dns-zone bundle with
  ed25519 verification + atomic hot-reload, IP-keyed per-client policy
- **Listens on UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS** out of the box;
  exposes a loopback-only `/metrics`, `/health`, `/queries` for operators

Security, privacy, and anonymity are first-class design constraints. All other
trade-offs — performance, convenience, feature completeness — are secondary.

> Two privacy knobs in `rustydns.toml` (`query_minimization`,
> `upstream_padding`) are accepted today but not yet applied — the `hickory
> 0.26` stub resolver doesn't expose RFC 7816 (qmin) or RFC 8467 (padding) yet.
> The daemon emits an explicit startup warning when either is enabled, so an
> operator never silently believes they're active. See
> [`docs/roadmap.md`](docs/roadmap.md) §1.

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

The shipped [`rustydns.example.toml`](rustydns.example.toml) is a fully
annotated configuration with every option documented inline. Most operators
only need to change the listener and (optionally) add or remove blocklist
sources. The minimum bits that matter:

```toml
[server]
# ⚠ Binding to 0.0.0.0 exposes the resolver to ALL network interfaces.
# Use "127.0.0.1:53" for local resolution only, or a specific LAN IP
# (e.g. "192.168.1.1:53") to serve your network. Never expose port 53
# to the public internet without a firewall in front.
listen = ["127.0.0.1:53"]              # <-- TOML array; can list several

[upstream]
# All URLs must use https:// (DoH) or quic:// (DoQ).
# The protocol field must match the URL scheme — validate_config
# rejects mismatches at startup.
protocol = "doh"
resolvers = [
    "https://dns.quad9.net/dns-query",
    "https://cloudflare-dns.com/dns-query",
]

[blocklist]
# Remote sources are fetched over HTTPS. Format is auto-detected
# per source (hosts / plain / RPZ / AdGuard) — no `format` key is needed.
sources = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
```

Then validate the config and restart the daemon:

```sh
sudo /usr/local/bin/rustydnsd --config /etc/rustydns/rustydns.toml --validate-config
sudo systemctl restart rustydns
sudo systemctl status rustydns
```

`--validate-config` parses the file and runs every check the daemon would
run at startup, without binding any sockets — use it before every
production change.

### Verify it's working

```sh
# 1. Daemon is up and ready.
curl -s http://127.0.0.1:9153/health | jq
# {"status":"ok","mesh_zone":{...}}

# 2. A normal query resolves.
dig @127.0.0.1 example.com +short
# 93.184.216.34

# 3. A known ad/tracker domain returns NXDOMAIN (or your sinkhole).
dig @127.0.0.1 doubleclick.net +short
# (empty — status: NXDOMAIN if you use `dig +noshort`)

# 4. Metrics confirm blocking is live.
curl -s http://127.0.0.1:9153/metrics | grep blocklist_hits_total
# rustydns_blocklist_hits_total 1
```

If the blocklist hits counter increments after step 3, ads are being
blocked. Point your router's DHCP option 6 (or per-device DNS) at the host
running rustydnsd, and every device on the network gets the same filtering.

### Troubleshooting

| Symptom | Where to look |
|---|---|
| Daemon refuses to start | `journalctl -u rustydns -n 50` — `validate_config` prints the offending field and the fix |
| `Permission denied` on `:53` | The binary needs `CAP_NET_BIND_SERVICE`. The systemd unit grants it; Docker uses file caps + `cap_add`. For bare runs: `sudo setcap cap_net_bind_service=+ep /usr/local/bin/rustydnsd` |
| Every query → `SERVFAIL` | Upstream DoH is unreachable. Probe with `curl -v https://dns.quad9.net/dns-query`. If that fails, the daemon will too |
| `/health` returns 503 | Mesh-zone bundle is stale or missing (only when `[authority.mesh_*]` is configured). Inspect `/var/lib/rustynet/dns-zone.bundle` mtime |
| Config file rejected as world-readable | `chmod 640 /etc/rustydns/rustydns.toml && chown rustydns:rustydns /etc/rustydns/rustydns.toml` |
| `rustydns_blocklist_hits_total` stays at 0 | Source URL likely failed to fetch (check `rustydns_blocklist_reload_failure_total` + `journalctl`) |
| Plain DNS being used somehow | Confirm `upstream.protocol = "doh"` (or `"doq"`); `"plain"` emits a `tracing::warn!` containing "UNENCRYPTED" on every startup |

When in doubt, run

```sh
rustydnsd --config /etc/rustydns/rustydns.toml --print-config
```

to see the resolved configuration with all defaults applied and all
secrets redacted.

---

## Architecture

```
Client query
     │
     ▼
┌─────────────────┐
│  Authority zone  │  Local mesh records (default zone: "mesh.") + static records.
│                 │   Intra-zone CNAME chains are chased automatically.
└────────┬────────┘
         │ no match (name not in any authoritative zone)
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
│  Resolver       │  DoH / DoQ to upstream, TLS 1.3 floor, DNSSEC validation,
│                 │   ECS stripped, randomised upstream selection, fail-closed.
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
| [`docs/roadmap.md`](docs/roadmap.md) | Single source of truth for everything pending (upstream-blocked, sibling-blocked, unstarted, test gaps) |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability (private channels only) |
| [`AGENTS.md`](AGENTS.md) | Invariants and rules for AI coding agents working on this repo |

---

## Project Structure

```
rustydns/
├── Cargo.toml                    # Workspace root (MSRV 1.88)
├── Cargo.lock                    # Reproducible builds
├── rustydns.example.toml         # Annotated example configuration
├── AGENTS.md                     # Coding-agent invariants
├── deny.toml                     # cargo-deny: advisories + bans + licenses + sources
├── Dockerfile                    # Multi-stage production image
├── docker-compose.yml            # Hardened example deployment
├── .dockerignore
├── crates/
│   ├── rustydns-core/            # Shared types: config, errors, DNS records, client identity
│   ├── rustydns-blocklist/       # Blocklist engine, parser, hot-reload, allowlist
│   ├── rustydns-authority/       # Authoritative zones (static + signed Rustynet mesh bundle, CNAME chasing)
│   ├── rustydns-resolver/        # DoH/DoQ upstream resolver (TLS 1.3 floor, fail-closed, DNSSEC, randomised selection)
│   └── rustydnsd/                # Daemon: UDP/TCP/DoT/DoH listeners + /metrics, /health, /queries
├── docs/
│   ├── architecture.md
│   ├── security.md
│   ├── blocklist-format.md
│   ├── integration-rustynet.md
│   ├── operator-endpoints.md
│   └── deployment-docker.md
├── .github/
│   ├── workflows/ci.yml          # fmt + clippy + test + release-build + cargo-deny + docker smoke
│   └── dependabot.yml            # Weekly cargo + actions updates
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
