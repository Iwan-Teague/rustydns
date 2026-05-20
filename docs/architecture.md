# rustydns — Architecture

## Overview

`rustydns` is structured as a pipeline of three cooperating subsystems: an **authority** layer for mesh-local and static records, a **blocklist** layer that intercepts queries before they hit the wire, and a **resolver** layer that handles everything that escapes the first two. A single **daemon binary** (`rustydnsd`) wires them together, owns the UDP/TCP/DoT listeners, and exposes an HTTP management API.

```
 client query (UDP/TCP/DoT/DoH)
         │
         ▼
  ┌─────────────┐
  │  Listener   │  — one tokio task per protocol
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Authority  │  — is this a mesh zone or static zone record?
  │   (cache)   │    yes → answer immediately, NOERROR
  └──────┬──────┘
         │ miss
         ▼
  ┌─────────────┐
  │  Blocklist  │  — is this domain on a blocklist?
  │   engine    │    yes → NXDOMAIN or 0.0.0.0, log it
  └──────┬──────┘
         │ pass
         ▼
  ┌─────────────┐
  │  Resolver   │  — recursive resolver, upstream DoH/DoQ
  │  + cache    │    fail_closed=true → SERVFAIL if no upstream
  └─────────────┘
```

## Crate responsibilities

### `rustydns-core`

Shared types, configuration schema, and error model. Everything else depends on this; it depends on nothing in the workspace.

Key items:
- `DnsConfig` — deserialised from `rustydns.toml` via `serde`
- `DnsRecord` — thin wrapper around `hickory-proto` record types with suite-specific metadata (mesh node ID, TTL policy)
- `ClientId` — identifies a querying host; used by the authority and blocklist to apply per-client policy
- `RustyDnsError` — unified error enum (`thiserror`)

### `rustydns-authority`

Serves authoritative answers for:

1. **The mesh zone** — reads live records from the `rustynet-dns-zone` SQLite database (same DB that `rustynetd` writes to). Records are cached in memory with an invalidation signal from a SQLite change-notification hook.
2. **Static zones** — additional zone files in standard RFC 1035 format, useful for local overrides and split-horizon entries that don't belong in the Rustynet control plane.

The authority speaks the `hickory-server` `Authority` trait so it can be composed with the upstream resolver in `rustydnsd`.

Integration point with Rustynet:

```rust
// rustydns-authority reads this via rustynet-dns-zone's public API
pub trait MeshZoneSource: Send + Sync {
    fn records_for_zone(&self, zone: &Name) -> Vec<DnsRecord>;
    fn subscribe_changes(&self) -> broadcast::Receiver<ZoneChange>;
}
```

### `rustydns-resolver`

A recursive resolver that forwards to configured upstream servers using:

- **DoH** (DNS-over-HTTPS, RFC 8484) — default
- **DoQ** (DNS-over-QUIC, RFC 9250) — optional, faster on low-latency paths
- **Plain UDP/TCP** — explicit opt-in only, logged as a security event

Behaviour:
- Maintains a TTL-respecting in-memory cache (bounded by `max_cache_entries` config).
- Tries upstreams in order; on failure, tries the next. If all fail and `fail_closed = true`, returns SERVFAIL. Never falls back to plain UDP unless configured.
- DNSSEC validation is on by default; responses that fail validation return SERVFAIL.

### `rustydns-blocklist`

A fast in-memory blocklist that intercepts queries before they reach the resolver.

Supported formats:
- **Hosts format** (`0.0.0.0 ads.example.com`) — the most common, used by StevenBlack/hosts and many others
- **RPZ zone** (Response Policy Zone) — for more expressive rules including wildcard subtree blocking
- **Plain domain list** — one domain per line, no IP prefix

Behaviour:
- Blocked queries return `NXDOMAIN` by default, or a configurable sinkhole IP.
- Blocklists are fetched from HTTP(S) URLs on startup and reloaded on a configurable interval without daemon restart (atomic pointer swap).
- Per-client allowlist: a Rustynet node can be given a bypass policy so it skips the blocklist (e.g. a server that legitimately needs to resolve ad-network endpoints for testing).
- Metrics: blocked query count, list size, last-reload timestamp — all exposed on `/metrics`.

### `rustydnsd`

The binary. Responsibilities:
- Parse config, validate, and fail fast on bad configuration.
- Bind listeners (UDP 53, TCP 53, DoT 853). DoH listener is a separate axum HTTP server on port 443 or a configured port.
- Spawn the query pipeline as a tower `Service` stack: `Authority → Blocklist → Resolver`.
- Serve the management HTTP API (`/metrics`, `/blocklist/reload`, `/cache/flush`, `/zones`).
- Handle signals: `SIGHUP` reloads config and blocklists; `SIGTERM`/`SIGINT` shuts down cleanly.

## Data flow — detailed

```
1.  UDP packet arrives on 0.0.0.0:53
2.  Listener decodes DNS message (hickory-proto)
3.  ClientId resolved from source IP → Rustynet node identity if known
4.  Authority checked: is qname in mesh_zone or a static zone?
    a. Yes → return cached/live record, increment authority_hits counter
    b. No  → continue
5.  Blocklist checked: does qname or any parent match a blocklist entry?
    a. Yes → return NXDOMAIN (or sinkhole), increment blocked_queries counter
    b. No  → continue
6.  Resolver: look up in cache
    a. Cache hit → return, update access time
    b. Cache miss → forward to upstream DoH/DoQ
       i.  Upstream responds → cache with TTL, return to client
       ii. All upstreams fail → SERVFAIL (fail_closed) or log + return stale (if configured)
7.  Response encoded and sent back to client
8.  Metrics updated (latency histogram, per-step counters)
```

## Rustynet integration

`rustydns` is designed to be deployed as a standard Rustynet service — meaning it appears in the mesh with a stable DNS name (`rustydns.mesh`) and is reachable only by nodes that have the appropriate Rustynet policy.

The tighter integration is through `rustynet-dns-zone`:

```
rustynetd ──writes──► control.db (SQLite)
                            │
                 rustynet-dns-zone crate (read API)
                            │
              rustydns-authority ──serves──► clients
```

When `rustynetd` adds or removes a peer, the zone change propagates to `rustydns-authority` within one TTL cycle (default 30 seconds for mesh records, configurable down to 5 seconds).

A future tighter integration would have `rustynetd` push zone changes over IPC rather than polling SQLite, bringing propagation latency to sub-second.

## Security posture

- Runs as an unprivileged user (`rustydns`) after binding privileged ports via `CAP_NET_BIND_SERVICE`.
- No `unsafe` code in workspace crates. `hickory-dns` and `quinn` (DoQ) contain unsafe internally; both are audited upstream crates.
- All upstream connections use TLS. Certificate validation is always on.
- Query logs written to a fixed-size ring buffer in memory; nothing written to disk by default. Optional structured logging to a file with configurable retention.
- Rustynet policy can restrict which mesh nodes are allowed to query which zones, enforced at the `ClientId` layer before any answer is returned.

## Performance targets

Running on a Raspberry Pi Zero 2 W (the same hardware as rustyjack):

| Metric | Target |
|--------|--------|
| Authority query latency (p99) | < 1 ms |
| Blocked query latency (p99) | < 2 ms |
| Upstream cache-miss latency (p99) | < 100 ms (network-bound) |
| Blocklist entries | 1M+ without OOM |
| Concurrent clients | 500+ |
| Binary size (stripped) | < 15 MB |
| Idle RSS | < 30 MB |

## Dependencies

| Crate | Use |
|-------|-----|
| `hickory-server` | DNS server framework (authority + resolver) |
| `hickory-proto` | DNS wire protocol |
| `hickory-resolver` | Recursive resolver with caching |
| `tokio` (full) | Async runtime |
| `quinn` | QUIC transport for DoQ |
| `axum` | DoH HTTP server + management API |
| `rusqlite` | Read access to rustynet-dns-zone SQLite DB |
| `serde` + `toml` | Configuration |
| `tracing` | Structured logging |
| `prometheus` | Metrics exposition |
| `thiserror` | Error types |
| `zeroize` | Clear sensitive config values on drop |
