# rustydns — Architecture

## Overview

`rustydns` is a single Rust binary structured as a pipeline of three cooperating subsystems: an **authority** layer for mesh-local and static records, a **blocklist** layer that intercepts queries before they hit the network, and a **resolver** layer for everything else. A **daemon binary** (`rustydnsd`) owns the listeners, wires the pipeline together, and exposes the management API.

Security, privacy, and anonymity are first-class design constraints — not features. Every decision in this document has been made with those three properties as the primary criterion.

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
  │  Authority  │  — mesh zone or static zone hit?
  │   (cache)   │    yes → answer immediately (NOERROR or NXDOMAIN)
  └──────┬──────┘    mesh records are NEVER blocked — authority wins
         │ miss
         ▼
  ┌─────────────┐
  │  Blocklist  │  — domain on blocklist?
  │   engine    │    yes → NXDOMAIN / REFUSED / sinkhole; log it
  └──────┬──────┘
         │ pass
         ▼
  ┌─────────────┐
  │  Resolver   │  — DoH/DoQ upstream only (plaintext is explicit opt-in)
  │  + cache    │    fail_closed=true → SERVFAIL if all upstreams fail
  └─────────────┘    (there is no stale-answer fallback mode)
```

**Pipeline order is an invariant.** Authority answers before blocklist; blocklist before resolver. This order must never change.

## Crate responsibilities

### `rustydns-core`

Shared types, configuration schema, error model. No I/O. Everything else depends on this; it depends on nothing in the workspace.

Key items:
- `DnsConfig` — deserialised from `rustydns.toml` via `serde` with `deny_unknown_fields`
- `PrivacyConfig` — query minimisation, ECS stripping, padding, upstream randomisation, log anonymisation
- `DnsRecord` — thin wrapper with suite-specific metadata (mesh node ID, TTL policy)
- `ClientId` — identifies a querying host; no `Display` impl to prevent accidental full-IP logging
- `RustyDnsError` — unified error enum (`thiserror`)

### `rustydns-authority`

Serves authoritative answers for:

1. **The mesh zone** — records from a signed bundle file written by `rustynetd` (verified against an operator-configured ed25519 verifier key). Changes propagate within one poll interval (default 30 s, configurable to 5 s). See `docs/integration-rustynet.md` for the file format and refresh model.
2. **Static zones** — additional records declared in `rustydns.toml`, useful for local overrides.

Authority answers are trusted answers. The authority never forwards to an upstream. It either has the answer (returns it) or it doesn't (returns `None`, continuing the pipeline to blocklist/resolver).

### `rustydns-resolver`

Recursive resolver forwarding to upstream servers using DoH (default) or DoQ. Privacy features applied to every outgoing query:

| Feature | RFC | Default |
|---------|-----|---------|
| DNS-over-HTTPS upstream | RFC 8484 | ✓ (planned) |
| TLS 1.3 minimum | RFC 8446 | ✓ (planned) |
| Certificate validation (always-on, not configurable) | — | ✓ (planned) |
| DNSSEC validation | RFC 4033–4035 | ✓ (planned) |
| Query Name Minimisation | RFC 7816 | ✓ (planned) |
| Strip EDNS0 Client Subnet | RFC 7871 | ✓ (planned) |
| DoH query/response padding | RFC 8467 | ✓ (planned) |
| Randomised upstream selection | — | ✓ (planned) |
| Fail-closed (SERVFAIL, no stale fallback) | — | ✓ (planned) |

**There is no stale-answer mode.** When `fail_closed = true` (the default), a failure of all upstreams returns `SERVFAIL`. Returning a stale answer without indicating staleness is a silent privacy degradation — a client might rely on that answer for a domain that has since changed, or the cached answer may have been for a different client's query.

### `rustydns-blocklist`

Fast in-memory blocklist engine. Key properties:

- **O(1) lookup** via `AHashSet` (randomised hash seed per process).
- **Lock-free hot-reload** via `arc-swap` — readers never block during reload.
- **Wildcard blocking** — RPZ `*.example.com` and AdGuard `||example.com^` rules.
- **Suffix-aware allowlist** — `*.example.com` whitelists all subdomains; exact match does not.
- **Four input formats** — hosts, plain domain list, RPZ, AdGuard/uBlock (auto-detected per source).
- **Domain validation** — label length (63 bytes), total length (253 bytes), control character rejection.
- **RPZ passthru isolation** — allow/passthru entries from untrusted remote sources are discarded with a warning. See `docs/security.md` for the threat this mitigates.

**Startup behaviour on blocklist fetch failure:** if a remote source fails to fetch at startup, the daemon starts with whatever sources loaded successfully (potentially an empty blocklist if all fail). A warning is logged for each failed source. The daemon does NOT fail to start — DNS resolution must continue even if blocklist fetching is temporarily broken.

### `rustydnsd`

The binary. Responsibilities:
- Parse config, validate, fail fast on bad configuration (before binding any ports).
- Attempt in-process capability dropping after binding privileged ports (also enforced by systemd unit).
- Check config file permissions at startup — warn if world-readable.
- Spawn the query pipeline as a `tower` `Service` stack: `Authority → Blocklist → Resolver`.
- Serve the management HTTP API (`/metrics`, `/blocklist/reload`, `/cache/flush`, `/zones`).
- Background task: fetch blocklist sources on schedule; swap `ArcSwap` atomically on success.
- Signal handling: `SIGHUP` reloads config and blocklists; `SIGTERM`/`SIGINT` shuts down cleanly.
- DoH listener: axum HTTP/2 server. **No TLS on the listener itself** — TLS is on upstream connections going out. If DoH is exposed externally, a TLS-terminating reverse proxy must be in front.
- DoT listener (optional): requires `tls_cert_path` and `tls_key_path` in config.

## Data flow — detailed

```
1.  UDP packet arrives on configured listen address
2.  Listener decodes DNS message (hickory-proto)
3.  ClientId resolved from source IP
      → if mesh peer: populate node_id from Rustynet peer table
      → if unknown: ClientId::from_ip only
4.  Check per-node policy (blocklist_bypass, zones_allowed)
5.  Authority checked: is qname in mesh_zone or a static zone?
    a. Yes → return record, increment authority_hits counter
    b. No  → continue
6.  Blocklist checked: does qname match a blocklist entry?
    a. Yes → NXDOMAIN / REFUSED / sinkhole, increment blocked_queries counter
              log: tracing::info!(client = %client.anonymized(), qname = %name, "query blocked")
              (full qname is logged here because the blocklist hit is the event of interest;
               note this is at info level — see AGENTS.md log redaction invariant)
    b. No  → continue
7.  Resolver: check cache
    a. Hit  → return, no upstream query
    b. Miss → forward to upstream DoH/DoQ with privacy features applied:
               - Select upstream at random (if privacy.randomize_upstream_selection)
               - Apply query name minimisation (if privacy.query_minimization)
               - Strip ECS option (if privacy.no_edns_client_subnet)
               - Pad query to 128-byte blocks (if privacy.upstream_padding)
               - Validate DNSSEC on response
               - On failure: SERVFAIL (fail_closed=true — there is no other mode)
8.  Response encoded and returned to client
9.  Metrics updated (latency histogram, per-step counters)
```

## Rustynet integration

```
rustynetd ──writes──► dns-zone.bundle (signed, ed25519)
                            │
                 read + verify against verifier-key.hex
                            │
              rustydns-authority ──serves──► clients
```

Zone changes propagate to clients within one poll interval + record TTL (default: 30 s each = 60 s worst case). A future IPC push mode would reduce this to sub-second.

## Security posture

- Runs as an unprivileged user (`rustydns`) after binding privileged ports via `CAP_NET_BIND_SERVICE`. The systemd unit enforces this; the binary also attempts in-process capability dropping for non-systemd deployments.
- `#![forbid(unsafe_code)]` in all workspace crates.
- All upstream connections use TLS (DoH/DoQ). Certificate validation is always on and is not configurable. TLS 1.3 is the default minimum.
- No upstream plain DNS by default. Plaintext is an explicit opt-in that emits a persistent startup warning.
- Query logs: in-memory ring buffer only by default. Nothing written to disk.
- Client IPs: anonymised by default (IPv4 /16, IPv6 /64). Full IPs require explicit opt-in.
- Blocklist sources: HTTPS only. Plain HTTP sources rejected at startup.
- RPZ passthru entries: honoured only from trusted sources (local files + `trusted_rpz_sources`).

## Performance targets

Running on Raspberry Pi Zero 2 W:

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
| `hickory-server` | DNS server framework |
| `hickory-proto` | DNS wire protocol |
| `hickory-resolver` | Recursive resolver with DoH/DoQ |
| `tokio` | Async runtime |
| `quinn` | QUIC transport for DoQ |
| `axum` | DoH HTTP/2 server + management API |
| `rustls` | TLS (pure Rust, no OpenSSL) |
| `ed25519-dalek` + `sha2` | Verify the signed Rustynet dns-zone bundle |
| `serde` + `toml` | Configuration |
| `tracing` | Structured logging |
| `prometheus` | Metrics exposition |
| `thiserror` | Error types in library crates |
| `anyhow` | Error handling in the binary |
| `arc-swap` | Lock-free hot-reload |
| `ahash` | Fast, DoS-resistant hashing |
| `moka` | Bounded LRU cache for resolver |
| `zeroize` | Clear sensitive config values on drop |
| `rand` | Upstream randomisation |
| `reqwest` (rustls backend) | Blocklist HTTP fetching — no OpenSSL |
