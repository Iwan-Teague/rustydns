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

- **Honour explicit ports on every upstream URL.** Previously,
  `127.0.0.1:8053` (plain), `https://dns.example.com:8443/dns-query`
  (DoH), and `quic://dns.example.com:8853` (DoQ) silently went to
  the protocol-default port (53/443/853) — hickory 0.26's
  `NameServerConfig::{https,quic,udp_and_tcp}` constructors don't
  accept a port, so the parsed port was dropped on the floor.
  `build_name_servers` now stamps the parsed port onto every
  `ConnectionConfig` after construction, so non-default-port
  endpoints actually work.
- **End-to-end integration tests** (`tests/upstream_e2e.rs`). Drive
  the resolver against an in-process plain-UDP mock and assert
  happy-path forwarding, fail-closed on upstream silence, hickory
  cache reuse, conditional-forwarding route dispatch, and the
  rebinding defence (filters on the default arm, passes through on
  route arms, no-op when off). Tests use plain DNS so no TLS/cert
  scaffolding is needed — the code paths under test are
  protocol-agnostic. DoH-specific tests are still tracked in
  roadmap §4.1.
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

- 386 tests across 5 crates: blocklist parser, allowlist, engine,
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

### Security

- **TLD guard extended to BLOCK entries.** The allowlist has always refused
  bare-TLD entries; the block side did not. A single `||com^` line from one
  compromised or buggy blocklist source blackholed every .com domain
  fleet-wide via the wildcard-parent matcher. All four block-entry parse
  sites now route through a >= 2-label guard; skipped entries warn naming
  the domain.
- **Listener-role address overlaps rejected.** `server.dot_listen` /
  `doq_listen` sharing an address with `server.listen` made the kernel hand
  each connection to a random role (plain DNS vs TLS/QUIC) on SO_REUSEPORT
  sockets. `validate_config` now rejects the overlap while DoT + DoQ
  sharing :853 stays allowed (different transports).
- **`authority.poll_interval_secs = 0` rejected.** It fed
  `tokio::time::interval`, which panics on a zero period — aborting the
  daemon at startup under release panic=abort.
- **UDP truncation logs one summary line, not one per shed record.** A
  large upstream answer over the datagram cap previously flooded the
  journal per query; shed/kept/original counts and the cap are in a single
  warn now.
- **Gate refusals log at debug, not warn.** Rate-limit, block-window, and
  zones_allowed refusals emitted a warn PER refused query — journal
  flooding exactly under flood or parental-control conditions. Production
  visibility stays on the bounded metric series; RUST_LOG opts back into
  per-event detail.
- **CLI contract pinned by integration tests.** Unknown flags and a
  valueless `--config` fail loudly; `--version` / `--help` exit 0 listing
  the documented options.
- **QDCOUNT=0 joined the question-count pin.** Empty-question datagrams
  must not panic or misattribute an outcome; differential construction
  proves second-question processing stays observable if it ever happens.
- **EDNS version mismatch now answered with BADVERS (RFC 6891 §6.1.3).**
  A query advertising EDNS0 version > 0 previously got a bare SERVFAIL:
  hickory-server's BADVERS handling lives in its zone-handler `Catalog`,
  which rustydns's listener stack does not use. A new pipeline gate answers
  extended rcode 16 (BADVERS) on every transport, and all outgoing response
  OPT records now advertise our version (0) instead of echoing a request
  version we do not implement (payload clamp unchanged). Pinned end-to-end
  per transport front door with liveness assertions.
- **Adversarial self-review pins (Aug 2026).** Mutation-tested hardening
  added across the attack surface:
  - Name decompression: hostile pointer cycles pinned at every decode seam
    (DoH POST/GET, ODoH plaintext, plain-upstream replies, daemon UDP) with
    bounded-work budgets, plus a prior-pointer overlap trap proven to hit
    hickory's `LabelOverlapsWithOther` at decoder level — exercising the
    recursive-follow guards no hop-1 test reaches.
  - DoQ/DoT protocol separation: a foreign-ALPN client fails its handshake
    against the live DoQ port; both TLS config builders' exact ALPN contracts
    pinned (`doq` exactly; DoT unrestricted).
  - Multi-question UDP datagrams (QDCOUNT=2, differential authority-vs-
    blocked questions): FORMERR'd by hickory 0.26, never answered from the
    second question; daemon liveness asserted.
  - SIGHUP metrics rebinding must route through the loopback-forcing choke
    point (public/wildcard/v4-mapped listens land forced); `--validate-config`
    nonzero-exit contract pinned for the systemd ExecStartPre gate.
  - Duplicate `?dns=` parameters reject with 400 before DNS parsing
    (axum 0.8 / serde_urlencoded behaviour, empirically confirmed).
- **`--print-config` no longer prints URL credentials.** The `Secret`
  wrapper existed but was wired to no config field, so the resolved-config
  dump rendered upstream DoH URLs with embedded `user:pass@` userinfo and
  token-gated blocklist source URLs (`?token=…`) in plaintext — straight
  to stdout (terminals, CI logs, shell history). All URL-bearing fields
  (upstream resolvers, ODoH proxies, conditional-forwarding routes,
  blocklist sources, trusted RPZ sources) now pass through
  `redact_url_credentials`: userinfo becomes `<redacted>@host`, credential
  query values become `key=<redacted>`; hosts, ports, paths and other
  parameters stay legible. Pinned by a new integration suite
  (`tests/print_config.rs`) driving the real binary.
- **Upstream URLs are credential-redacted in logs too**: the resolver's
  bootstrap-failure path logged the full configured URL at `warn` level
  (production journald); it and the debug-level "default upstream loaded"
  line now emit redacted forms.
- **Transitive RUSTSEC fixes re-verified against the advisory database
  (2026-08-24).** The lockfile-only bumps in 27a0493/3e47043 were checked
  against each advisory's published patched range on rustsec.org:
  `crossbeam-epoch` 0.9.18 → 0.9.20 (RUSTSEC-2026-0204, patched
  ≥ 0.9.20), `h2` 0.4.14 → 0.4.18 (RUSTSEC-2026-0258, patched
  ≥ 0.4.16), `quinn-proto` 0.11.14 → **0.11.15** (RUSTSEC-2026-0185,
  patched **≥ 0.11.15**), and `anyhow` → 1.0.104 (RUSTSEC-2026-0190).
  Correction: the 27a0493 commit message says quinn-proto was bumped to
  "0.11.17"; the actual — and sufficient — version is 0.11.15, which is
  exactly the patched floor. Recorded here so a future auditor does not
  mistake the message/logfile mismatch for an incomplete fix. Also
  noted for the record: that bump carried unmentioned `windows-sys`
  0.61.2 → 0.60.2 downgrades in several transitive packages
  (`cargo update` collateral); reviewed as inert for this Linux-only
  daemon. Independently re-verified: `cargo deny check` reports
  advisories/bans/licenses/sources all ok.

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

- **Container healthcheck actually works now.** The Dockerfile and
  compose healthchecks called `wget`, which `debian:bookworm-slim`
  deliberately does not ship — every container reported `unhealthy`
  while serving perfectly. The probe now uses bash's built-in
  `/dev/tcp` to GET `/health` (bash + grep are Essential packages in
  even `-slim`), requires a literal `200 OK` so it still gates on
  listener readiness, and gains `start_period=15s` for slow first
  blocklist fetches. Verified against the release binary.
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

### Added (listeners)

- **DNS-over-TLS listener** (`server.dot_listen`). Wired end-to-end
  with hickory-server 0.26's `register_tls_listener_with_tls_config`.
  Requires `server.tls_cert_path` and `server.tls_key_path`;
  `validate_config` rejects `dot_listen` without both.
- **DNS-over-QUIC listener** (`server.doq_listen`, RFC 9250). QUIC over
  UDP; shares the same cert as DoT. The TLS config carries the `doq` ALPN
  (separate from the no-ALPN DoT config). A real `quinn`-based e2e test
  proves the handshake end-to-end.
- **Inbound DoH listener** (`server.doh_listen`). HTTP/2 axum server on
  loopback; TLS termination is the reverse-proxy's job.

### Added (upstream protocols)

- **Oblivious DoH** (`upstream.protocol = "odoh"`, RFC 9230). The flagship
  anonymity feature: queries are HPKE-encrypted to the target and relayed
  through an oblivious proxy, so the proxy sees the client IP but not the
  query, and the target sees the query but not the client IP. Fail-closed
  (never falls back to plain DoH). Key-rotation recovery. Multi-relay with
  per-query random selection. Optional client-side DNSSEC (chain lookups
  also travel obliviously; BOGUS → SERVFAIL). RFC 8467 padding applied
  on the oblivious plaintext (128-byte blocks via odoh-rs).
- **DNS 0x20 case randomisation** (plain UDP only). Auto-enabled for
  `upstream.protocol = "plain"` to defend against off-path spoofing and
  cache poisoning. Off for DoH/DoQ (TLS already authenticates). A
  case-mismatch → SERVFAIL (fail-closed).

### Added (daemon hardening)

- **SIGHUP live reload Phase 1+2**. Phase 1: hot-swaps upstream resolver,
  policy table, rate limiter, rewrite map, blocklist content atomically
  via `ArcSwap`. Phase 2: zero-drop live rebind of changed listeners on
  unprivileged ports (DNS UDP/TCP, DoT, DoQ, DoH, metrics) via
  `SO_REUSEPORT`. Privileged-port changes detected and logged as
  restart-required.
- **Systemd socket activation** (`install/rustydns.socket`). systemd binds
  the privileged `:53`/`:853` sockets and passes them in via `LISTEN_FDS`;
  the daemon adopts them with `InheritedSockets` and needs no
  `CAP_NET_BIND_SERVICE` at all. A `.service` drop-in can set
  `AmbientCapabilities=` to empty. Strictly additive — non-socket-activated
  starts (Docker, bare binary) bind normally.
- **Disk query log** (`privacy.query_log_to_disk`). Opt-in NDJSON writer
  with file rotation (`max_file_bytes`, `max_files`), mode-0600 creation,
  and world-readable rejection at startup. Stores only hashed qname +
  anonymised client — same privacy posture as the ring buffer.
- **DNS rebinding defence** (`upstream.block_private_rdata`). Strips
  private/loopback/link-local A/AAAA rdata from default-arm upstream
  responses. Route and authority responses are never filtered.
- **Per-source-IP rate limiting** (`[rate_limit]`). Token bucket,
  loopback exempt, bounded LRU table, REFUSED on excess.
- **Per-client blocklist groups** (`[[blocklist.groups]]`). Named sets of
  sources; clients assigned via `[[policy]].blocklist_group`.
- **Deep CNAME-chain blocking** (`blocklist.block_cname_cloaking`). Blocks
  the whole response if any CNAME target is on the blocklist.
- **Response-IP denylist** (`blocklist.response_ip_denylist`). CIDR-based.
- **Safe Search enforcement** (`[safesearch]`). Rewrites A/AAAA for Google,
  Bing, DuckDuckGo, YouTube to their safe-search endpoints.
- **Scheduled block windows** (`[[policy]].block_windows`). Time-of-day
  restrictions per client; active windows refuse all queries before the
  pipeline.
- **Regex custom block rules** (`[[blocklist.regex_rules]]`). ReDoS-guarded
  via the `regex` crate (linear-time finite automata, no catastrophic
  backtracking).
- **Per-qtype / per-rcode Prometheus metrics**.
  `rustydns_dns_queries_by_qtype_total` and
  `rustydns_dns_responses_by_rcode_total` with bounded label cardinality.

### Known deferrals

The full, structured list is in [`docs/roadmap.md`](docs/roadmap.md). Only
three items remain genuinely blocked — all on external code:

- **RFC 7816 query name minimisation** — hickory 0.26 doesn't expose a
  qmin knob yet. Scaffolded + startup warning. Adopts automatically when
  hickory ships it.
- **RFC 8467 DoH/DoQ body padding** — hickory 0.26's `DnsRequestOptions`
  has no padding field. Scaffolded + startup warning. (Already applied on
  the ODoH arm via odoh-rs.) Adopts automatically when hickory ships it.
- **NodeId-keyed policy matching** — `node_id` in `[[policy]]` is parsed
  and validated but inert; wiring requires `rustynetd` to expose a
  `SocketAddr → NodeId` peer-table lookup at query time.

All other features previously listed here as "unstarted" are now fully
shipped and tested.
