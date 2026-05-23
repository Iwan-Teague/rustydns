# Changelog

All notable changes to `rustydns` are recorded here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).
This project does not yet follow semantic versioning — every change up to
`0.1.0` is still pre-release.

## Unreleased

### Daemon (`rustydnsd`)

- **Per-source-IP rate limiting** (`[rate_limit]`). Default-on token
  bucket: each non-loopback client gets `burst` tokens (default 200)
  and refills at `qps` per second (default 100). Excess queries
  respond `REFUSED` — not silently dropped — and increment
  `rustydns_policy_rate_limited_total`. Loopback (`127.0.0.0/8`,
  `::1`) is always exempt so local proxies and DoH/DoT terminators
  aren't penalised. The bucket table is bounded by
  `max_tracked_clients` (default 10,000, capped at 1,000,000) with
  LRU eviction + periodic GC of buckets idle for >5 minutes, so a
  forge-IP flood can't OOM the daemon. Runs FIRST in the query
  pipeline, before authority / blocklist / resolver.
- Bring up the daemon binary with UDP, TCP, and DoH (HTTP/2) listeners.
- DNS request pipeline: Authority → Blocklist → Resolver, with
  AGENTS.md-mandated fail-closed → `SERVFAIL` on upstream failure and
  authority answers explicitly bypassing the blocklist.
- `--validate-config`, `--help`, `--version` CLI flags. Wired into
  `install/rustydns.service` as `ExecStartPre` so invalid configs never
  crash-loop into `Restart=on-failure`.
- Bounded graceful shutdown (`RUSTYDNS_SHUTDOWN_TIMEOUT_SECS`, default
  10s; second signal forces immediate exit).
- In-process Linux capability dropping after socket bind, via the
  `caps` crate. No-op on non-Linux targets.
- Per-client policy enforcement: `blocklist_bypass`, `zones_allowed`,
  `log_all_queries`. Keyed by `client_ip` today; `node_id` parsed
  but inert pending Rustynet peer-table integration.
- In-memory query log ring buffer (`privacy.query_log_ring_size`,
  default 1000, max 100,000). Stores anonymised client and
  per-process-salted u64 hash of the qname; no raw qnames, no full
  IPs, no disk persistence.

### Authority

- Signed Rustynet dns-zone bundle reader with ed25519 verification,
  256 KiB size cap, and freshness check (`mesh_zone_max_age_secs`).
- Atomic mesh-zone hot reload via `ArcSwap` — readers never block.
- Background poller on `poll_interval_secs`; SIGHUP also triggers
  reload.
- Static-record store with merge-on-snapshot.
- Intra-zone CNAME chain following per RFC 1034 §3.6.2 — `lookup`
  returns the full `[CNAME, …, terminal]` answer when the chain
  stays inside the authority's zones, falling back to the partial
  chain when it crosses into a zone we don't own. Loop detection
  via a visited-name set; depth capped at 8 hops.

### Resolver

- **DNS-rebinding defence** (`upstream.block_private_rdata`). When
  enabled (default off), strips A/AAAA records from the default
  upstream's responses whose rdata is RFC 1918, loopback, link-local,
  unspecified, broadcast, documentation, multicast, unique-local, or
  unicast link-local (IPv6) — and the IPv4-mapped IPv6 forms of those.
  Blocks attacker-controlled domains that flip from a public IP to a
  LAN/loopback IP after TTL expiry. Conditional-forwarding route
  responses are passed through untouched regardless of the setting,
  since operators route to internal resolvers precisely so they can
  return private addresses. Authority answers (mesh + static) run
  before the resolver and are never filtered. Each dropped record is
  counted in `rustydns_resolver_private_rdata_dropped_total`.
- **Conditional forwarding** (`[[upstream.routes]]`). Route specific
  DNS zones to specific upstreams — e.g. `lan.` → `192.168.1.1:53`,
  `corp.internal.` → an internal DoH endpoint, public traffic →
  default DoH list. Longest matching zone wins; case-insensitive.
  Each route gets its own hickory resolver instance. All
  privacy/security knobs (`fail_closed`, `min_tls_version`,
  `dnssec_validation`, `randomize_upstream_selection`, ECS strip)
  are inherited from the global config — there are no per-route
  escape hatches. Plaintext routes emit the same UNENCRYPTED-leaks
  startup warning the global plain protocol does. Pipeline order
  (Authority → Blocklist → Resolver) is unchanged: routes only
  affect dispatch *within* the resolver step.
- `hickory-resolver`-backed DoH client with bootstrap DNS via the OS
  resolver (consulted only at startup; never for actual queries).
- DNSSEC validation gated by config.
- Fail-closed: `AllUpstreamsFailed` returned from `resolve()` for
  every upstream error, never a stale or silently downgraded answer.
- Randomised upstream selection.
- DoQ (RFC 9250) upstreams wired via hickory `quic-ring` feature;
  `protocol = "doq"` accepts `quic://` URLs.
- Plain-mode upstreams accept bare `host:port` (e.g. `"8.8.8.8:53"`)
  — `parse_upstream_url` synthesises a `"plain"` scheme so the rest
  of the parser handles a single shape.
- `validate_config` now rejects protocol/URL-scheme mismatches at
  parse time (`doh` + `quic://`, `doq` + `https://`, `plain` with a
  scheme), so a misconfiguration fails fast instead of bubbling up
  as an opaque hickory connect error.
- Resolved upstream URLs logged one-per-line at debug level so
  operators can confirm rotation contents without re-reading config.
- Plaintext upstream emits a persistent `warn!` containing
  "UNENCRYPTED" / "leaks" per AGENTS.md.

### Blocklist

- HTTPS-only sources; HTTP rejected at startup.
- Defence in depth on the fetcher itself: `reqwest::Client` is built
  with `https_only(true)` so plaintext is refused at request time
  too (including after a 3xx redirect), and the redirect chain is
  capped at 3 hops (vs reqwest's default of 10) to bound exposure
  to chain-walking endpoints.
- Identifying `User-Agent` ("rustydnsd/<version> (+<repo url>)")
  so blocklist hosts can attribute the traffic and rate-limit
  intelligently.
- Bounded fetch with `fetch_timeout_ms` and `max_fetch_bytes` caps.
- Trusted/untrusted source distinction for RPZ passthru entries.
- Hosts, plain, RPZ, and AdGuard formats auto-detected.

### Operator endpoints (loopback only)

- `/metrics`  — Prometheus exposition. Pipeline counters, blocklist
  state, mesh-zone reload status, policy effect counters.
- `/health`   — 200 OK liveness for orchestrators.
- `/queries`  — JSON snapshot of the in-memory query log. Hashed
  qnames + anonymised clients only.

See `docs/operator-endpoints.md` for the full reference.

### Tests

- 130+ tests across 5 crates: blocklist parser, allowlist, engine,
  authority static + mesh, mesh signature paths, resolver record
  conversion, config validation (every rejection branch), handler
  e2e via UDP/TCP, DoH GET/POST, query log, policy enforcement,
  policy metrics, `/queries` JSON shape, `/health`.
- GitHub Actions CI: `cargo fmt --check`, clippy (correctness +
  suspicious + perf), full test, release build, `cargo deny check`
  (advisories + bans + licenses + sources), and a
  `--validate-config` smoke on the example config.
- `deny.toml` policy: SPDX license allowlist, banned-crate list
  (`openssl-sys`, `openssl`, `native-tls`, the trust-dns-* family),
  HTTPS-only crates.io as the single approved source. Active
  RUSTSEC ignores are individually annotated with rationale + the
  upgrade that resolves them.

### Documentation

- `docs/architecture.md`, `docs/integration-rustynet.md`,
  `docs/security.md`, `docs/blocklist-format.md`,
  `docs/operator-endpoints.md`, and `docs/deployment-docker.md`
  (image layout, capability model, compose template, scrape
  sidecar pattern, troubleshooting).
- `AGENTS.md` invariants reflected in code and tests.
- `rustydns.example.toml` with worked examples for every section.
- Per-crate `lib.rs` modules carry the security/privacy rules in
  their crate-level docs.

### Upgraded

- **MSRV: 1.85 → 1.88.** Required by `hickory-{net,proto,resolver,server}
  0.26.1`, which all declare `rust-version = 1.88` in their manifests.
  Pinned in `Cargo.toml`, the Dockerfile builder image, and the CI
  toolchain.
- `hickory-{proto,resolver,server}` 0.24 → 0.26 across the
  workspace. The 0.26 line uses `rustls 0.23` (matching axum/reqwest)
  and `quinn 0.11`, clearing nine RUSTSEC advisories that had been
  documented in `deny.toml` for the previous chain.
- **TLS 1.3 floor enforcement now active.** `upstream.min_tls_version`
  is honoured by a real `rustls::ClientConfig` built with
  `with_protocol_versions(&[&TLS13])` (or `[TLS13, TLS12]` if 1.2 is
  asked for). The previous workspace had to leave this as a
  warning-only setting because hickory 0.24's internal rustls 0.21
  wouldn't accept the workspace's rustls 0.23 config.

### Packaging

- **Multi-stage `Dockerfile`** — `rust:1.88-bookworm` builder →
  `debian:bookworm-slim` runtime. Non-root `rustydns` user,
  `cap_net_bind_service` file capability on the binary so `:53`
  and `:853` bind without root. `tini` as PID 1 for zombie reaping
  and clean SIGTERM forwarding. `ca-certificates` deliberately
  omitted — `webpki-roots` ships the Mozilla CA bundle in-binary.
- **`.dockerignore`** trims the build context: `target/`, `.git`,
  docs, and any `*.pem`/`rustydns.toml` are excluded so operator
  secrets can't accidentally be baked into an image.
- **`docker-compose.yml`** with read-only rootfs, `cap_drop: ALL` +
  `cap_add: NET_BIND_SERVICE`, `no-new-privileges`, json-file log
  cap, and a healthcheck against the loopback `/health` endpoint.
- **CI `docker` job** builds the image via Buildx with the GHA cache
  backend and runs `rustydnsd --version` inside it, catching
  Dockerfile regressions on PR.

### Added

- **DNS-over-TLS listener** (`server.dot_listen`). Now wired
  end-to-end with hickory-server 0.26's
  `register_tls_listener_with_tls_config`. Requires
  `server.tls_cert_path` and `server.tls_key_path`; validation in
  `validate_config` rejects `dot_listen` without both.

### Known deferrals

The full, structured list of unfinished work lives in
[`docs/roadmap.md`](docs/roadmap.md) — single source of truth for
upstream-blocked items (hickory 0.26: RFC 7816 qmin, RFC 8467 padding),
sibling-blocked items (Rustynet peer-table → NodeId-keyed policy
matching), unstarted features (`query_log_to_disk`, SIGHUP full-config
reload, DNS rebinding defence, per-client rate limiting), test
coverage gaps, and maintenance items.

For each pending item rustydnsd today either emits an explicit
startup `tracing::warn!` (qmin/padding, NodeId-only policy,
`query_log_to_disk`) or surfaces the limitation in the relevant
crate-level doc, so an operator running with that flag set never
silently believes the feature is active.
