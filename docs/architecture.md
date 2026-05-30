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
  │ Rate-limit  │  — per-source-IP token bucket (loopback exempt)
  │             │    over-budget → REFUSED; counter bumped
  └──────┬──────┘
         │ admit
         ▼
  ┌─────────────┐
  │  Authority  │  — mesh zone or static zone hit?
  │   (cache)   │    yes → answer immediately (NOERROR or NXDOMAIN)
  └──────┬──────┘    mesh records are NEVER blocked — authority wins
         │ miss
         ▼
  ┌─────────────┐
  │   Rewrite   │  — [[rewrite]] local-cloaking override?
  │ (cloaking)  │    yes → pin to IP / CNAME / NXDOMAIN (NODATA on
  └──────┬──────┘          wrong family); authority still wins above
         │ no match
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

**Pipeline order is an invariant.** Rate-limit before authority; authority before rewrite; rewrite before blocklist; blocklist before resolver. This order must never change. The rate limiter runs first so that a flood of malformed queries from one source IP costs only an `AHashMap` lookup + token-bucket update. Rewrites sit after the authority (so the daemon's own zones always win) and before the blocklist/resolver (so an operator pin/blackhole takes precedence over a list and never leaks upstream).

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

**Intra-zone CNAME chasing.** When the queried name has a CNAME and the target is inside an authoritative zone (mesh or static), `Authority::lookup` follows the chain and returns the full `[CNAME, …, terminal]` answer so stub resolvers get the terminal record in one round-trip (RFC 1034 §3.6.2). The chase stops when the target leaves the authority's zones (the resolver pipeline takes over from there), when a loop is detected, or when the 8-hop depth cap is hit.

### `rustydns-resolver`

Recursive resolver forwarding to upstream servers using DoH (default) or DoQ. Privacy features applied to every outgoing query:

| Feature | RFC | Status |
|---------|-----|--------|
| DNS-over-HTTPS upstream | RFC 8484 | ✓ implemented |
| TLS 1.3 minimum | RFC 8446 | ✓ implemented (`upstream.min_tls_version`) |
| Certificate validation (always-on, not configurable) | — | ✓ implemented (Mozilla bundle via `webpki-roots`) |
| DNSSEC validation | RFC 4033–4035 | ✓ implemented (`upstream.dnssec_validation`) |
| Strip EDNS0 Client Subnet | RFC 7871 | ✓ implemented (resolver never sets ECS) |
| Randomised upstream selection | — | ✓ implemented (`upstream.randomize_upstream_selection`) |
| Fail-closed (SERVFAIL, no stale fallback) | — | ✓ implemented (`upstream.fail_closed`) |
| Conditional forwarding (per-zone routes) | — | ✓ implemented (`[[upstream.routes]]`) |
| DNS-rebinding defence (drop private rdata) | — | ✓ implemented (`upstream.block_private_rdata`, default off) |
| Query Name Minimisation | RFC 7816 | ⏳ pending (hickory 0.26 still doesn't expose qmin) |
| DoH query/response padding | RFC 8467 | ⏳ pending (hickory 0.26 still doesn't expose RFC 8467) |

**There is no stale-answer mode.** When `fail_closed = true` (the default), a failure of all upstreams returns `SERVFAIL`. Returning a stale answer without indicating staleness is a silent privacy degradation — a client might rely on that answer for a domain that has since changed, or the cached answer may have been for a different client's query.

**Conditional forwarding.** `[[upstream.routes]]` attaches a list of resolvers (and an upstream protocol) to a DNS zone. A query whose qname falls inside that zone is forwarded to that route's resolvers instead of the global `upstream.resolvers` list. Longest matching zone wins. Each route gets its own hickory resolver instance; all privacy/security settings (`fail_closed`, `min_tls_version`, `dnssec_validation`, `randomize_upstream_selection`, etc.) are inherited from the global config — there are no per-route escape hatches. Authority and blocklist still run **before** route selection — the pipeline order is unchanged.

### `rustydns-blocklist`

Fast in-memory blocklist engine. Key properties:

- **O(1) lookup** via `AHashSet` (randomised hash seed per process).
- **Lock-free hot-reload** via `arc-swap` — readers never block during reload.
- **Wildcard blocking** — RPZ `*.example.com` and AdGuard `||example.com^` rules.
- **Suffix-aware allowlist** — `*.example.com` whitelists all subdomains; exact match does not.
- **Four input formats** — hosts, plain domain list, RPZ, AdGuard/uBlock (auto-detected per source).
- **Domain validation** — label length (63 bytes), total length (253 bytes), control character rejection.
- **RPZ passthru isolation** — allow/passthru entries from untrusted remote sources are discarded with a warning. See `docs/security.md` for the threat this mitigates.
- **CNAME-cloaking defence** — after the resolver answers, the handler walks the answer's CNAME chain and blocks the whole response (per `block_response`) if any CNAME target is on the blocklist, closing the first-party-cloaking evasion. Toggle: `blocklist.block_cname_cloaking` (default on). See `docs/security.md` §"CNAME Cloaking".

**Startup behaviour on blocklist fetch failure:** if a remote source fails to fetch at startup, the daemon starts with whatever sources loaded successfully (potentially an empty blocklist if all fail). A warning is logged for each failed source. The daemon does NOT fail to start — DNS resolution must continue even if blocklist fetching is temporarily broken.

### `rustydnsd`

The binary. Responsibilities:
- Parse config, validate, fail fast on bad configuration (before binding any ports).
- Refuse to start if `rustydns.toml` is world-readable; warn (not refuse) if group-readable.
- Set `umask(0o077)` in-process so any files the daemon writes are owner-only.
- Drop Linux capabilities in-process after binding privileged ports (via the `caps` crate; also enforced by the systemd unit and Docker file caps).
- Wire the request pipeline as a single `RequestHandler` impl (`DnsHandler`) that runs `Authority → Blocklist → Resolver` directly. Not a `tower::Service` stack — the pipeline is short enough that a hand-written async fn beats the layer-builder ceremony.
- Serve the loopback management API on `metrics.listen` (default `127.0.0.1:9153`): `/metrics` (Prometheus), `/health` (JSON liveness), `/queries` (JSON snapshot of the in-memory ring buffer). All three refuse to bind off-loopback; see [`operator-endpoints.md`](operator-endpoints.md).
- Background tasks: periodic blocklist reload on `blocklist.reload_interval_secs`; periodic mesh-zone bundle reload on `authority.poll_interval_secs`; both swap their state via `ArcSwap` atomically on success.
- Signal handling: `SIGHUP` re-reads blocklist content, the mesh-zone bundle, and `rustydns.toml`. Config reload hot-swaps the upstream resolver, per-client policy, rate limiter, and DNS rewrite map atomically via `ArcSwap` (no dropped in-flight queries), and live-rebinds changed listeners on **unprivileged** ports — DNS UDP/TCP, DoT (incl. TLS cert rotation), DoH, and metrics — zero-drop via `SO_REUSEPORT` (a new generation serves before the old drains). Listeners on **privileged** ports (`:53`, `:853`) cannot be rebound after the startup capability drop and are logged as restart-required. Blocklist *sources* and the on-disk query log are also bound at startup. A config that fails to parse/validate leaves the running config untouched. `SIGTERM`/`SIGINT` runs the bounded graceful shutdown (`RUSTYDNS_SHUTDOWN_TIMEOUT_SECS`, default 10s); a second signal collapses the timeout to zero.
- DoH listener: axum HTTP/2 server. **No TLS on the listener itself** — TLS is on upstream connections going out. If DoH is exposed externally, a TLS-terminating reverse proxy must be in front.
- DoT listener (optional): requires `tls_cert_path` and `tls_key_path`; rejected by `validate_config` if either is missing.

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
    a. Yes → NXDOMAIN / REFUSED / sinkhole, increment blocklist_hits_total counter
              log: tracing::debug!(client = %client.anonymized(), qname = %name, "query blocked")
              (raw qname only at debug level per AGENTS.md privacy invariants —
               info-level path uses the hashed qname from QueryLog::hash_qname)
              query log ring buffer records: hashed qname + anonymised client + ServedBy::Blocklist
    b. No  → continue
7.  Resolver: check cache (moka LRU, bounded by upstream.max_cache_entries)
    a. Hit  → return, no upstream query
    b. Miss → forward to upstream DoH/DoQ/plain with privacy features applied:
               - Select upstream via ServerOrderingStrategy::RoundRobin
                 (if privacy.randomize_upstream_selection) else QueryStatistics
               - Strip ECS option (always — we never set EDNS Client Subnet)
               - Enforce TLS 1.3 floor on the encrypted transports
                 (upstream.min_tls_version)
               - Validate DNSSEC on response (upstream.dnssec_validation)
               - On failure: SERVFAIL (fail_closed=true — there is no other mode)
               - On "no records": the upstream's NXDOMAIN (name does not
                 exist) vs NODATA (name exists, no records of this type) is
                 preserved — the handler emits NXDomain or NoError
                 accordingly rather than collapsing both to NODATA.
               - NOT yet applied: RFC 7816 query minimisation and RFC 8467
                 padding — hickory 0.26's stub resolver doesn't expose either,
                 and the daemon warns at startup if the matching privacy.*
                 knob is enabled.
8.  Response encoded and returned to client
9.  Metrics updated (per-arm counters, policy effect counters)
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
- Query logs: in-memory ring buffer by default. Opt-in on-disk NDJSON
  (`query_log_to_disk`) writes only hashed qnames + anonymised clients, mode 0600,
  with size-based rotation.
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
