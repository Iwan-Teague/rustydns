# rustydns

Mesh-native DNS resolver and ad-blocker for the Rusty Suite.

`rustydns` is a single Rust binary that serves as the authoritative DNS server for a Rustynet mesh, a recursive upstream resolver with DoH/DoQ support, and a blocklist engine for ad and tracker blocking — all in one lightweight, policy-aware daemon.

## How it fits the suite

```
rustyfin ──┐
rustytorrent ┤  ← all resolve via  →  rustydns  ← zone authority from rustynet-dns-zone
rustyjack ──┘                               │
                                      upstream DoH/DoQ
                                      (Cloudflare, NextDNS, etc.)
```

- **Rustynet** provides the mesh and already has a `rustynet-dns-zone` crate that manages zone records. `rustydns` is the runtime that serves those zones over UDP/TCP/DoH.
- **rustyfin** and other suite services become resolvable at stable `.mesh` names instead of IP addresses that shift as the mesh topology changes.
- **rustyjack** operators understand DNS offensively; `rustydns` gives the same understanding defensively, and the daemon can run on the same Pi hardware.
- **rustytorrent** benefits from private DNS that doesn't leak query history to upstream resolvers.

## Design goals

- **Single static binary.** No runtime dependencies, no Python, no dnsmasq. Drop it on a Pi Zero 2 W or a Debian 12 server and it runs.
- **Mesh-first.** Authoritative for the local mesh zone by default. Rustynet policy gates which clients can query which records.
- **Fail-closed.** If the upstream resolver is unreachable and no cached answer exists, `rustydns` returns SERVFAIL rather than leaking queries to a fallback it doesn't trust.
- **Privacy-preserving upstream.** Upstream resolution uses DNS-over-HTTPS or DNS-over-QUIC. Plaintext UDP port 53 upstream is explicitly opt-in.
- **Blocklist as a first-class feature.** Hosts-format and RPZ blocklists, hot-reloaded without daemon restart.
- **Observable.** Prometheus-compatible `/metrics` endpoint. Per-client query logs written to a ring buffer, not unbounded disk.

## Crate layout

```
rustydns/
├── crates/
│   ├── rustydns-core        # Shared config, error types, record model
│   ├── rustydns-authority   # Authoritative zone server (mesh + static zones)
│   ├── rustydns-resolver    # Recursive resolver with DoH/DoQ upstream
│   ├── rustydns-blocklist   # Blocklist engine: hosts format, RPZ, hot-reload
│   └── rustydnsd            # Daemon binary — wires everything together
├── docs/
│   ├── architecture.md
│   ├── integration-rustynet.md
│   └── blocklist-format.md
├── scripts/
├── Cargo.toml               # Workspace manifest
├── README.md
├── AGENTS.md
└── CLAUDE.md
```

## Quick start

```bash
# Install
cargo install --path crates/rustydnsd

# Run with default config (serves 127.0.0.53:53, upstream DoH to Cloudflare)
rustydnsd --config rustydns.toml

# Query the local resolver
dig @127.0.0.53 rustyfin.mesh A
```

## Configuration sketch

```toml
[server]
listen = ["0.0.0.0:53", "0.0.0.0:853"]   # UDP/TCP + DoT
mesh_zone = "mesh."

[upstream]
resolvers = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.nextdns.io/YOUR_ID",
]
protocol = "doh"          # doh | doq | plain (opt-in, insecure)
fail_closed = true

[authority]
# Rustynet zone integration (reads from rustynet-dns-zone's SQLite)
rustynet_db = "/var/lib/rustynet/control.db"

[blocklist]
sources = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
reload_interval_secs = 86400

[metrics]
listen = "127.0.0.1:9153"
path   = "/metrics"
```

## Status

Early planning / scaffolding phase. See `docs/architecture.md` for the intended design and `AGENTS.md` for contribution guidance.
