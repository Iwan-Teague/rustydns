# Changelog

All notable changes to `rustydns` are recorded here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).
This project does not yet follow semantic versioning — every change up to
`0.1.0` is still pre-release.

## Unreleased

### Daemon (`rustydnsd`)

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

### Resolver

- `hickory-resolver`-backed DoH client with bootstrap DNS via the OS
  resolver (consulted only at startup; never for actual queries).
- DNSSEC validation gated by config.
- Fail-closed: `AllUpstreamsFailed` returned from `resolve()` for
  every upstream error, never a stale or silently downgraded answer.
- Randomised upstream selection.
- Plaintext upstream emits a persistent `warn!` containing
  "UNENCRYPTED" / "leaks" per AGENTS.md.

### Blocklist

- HTTPS-only sources; HTTP rejected at startup.
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
  `docs/security.md`, `docs/blocklist-format.md`, and the new
  `docs/operator-endpoints.md`.
- `AGENTS.md` invariants reflected in code and tests.
- `rustydns.example.toml` with worked examples for every section.
- Per-crate `lib.rs` modules carry the security/privacy rules in
  their crate-level docs.

### Known deferrals

- DNS-over-TLS listener — blocked on `hickory-server` upgrading
  from rustls 0.21 to 0.23. Daemon errors with a clear
  reverse-proxy workaround message if `dot_listen` is set.
- RFC 8467 padding and RFC 7816 query name minimisation — not
  currently exposed by hickory 0.24.
- TLS 1.3 floor enforcement on upstreams — same hickory blocker.
- Rustynet peer-table → `NodeId` resolution for the `node_id`
  half of `[[policy]]` — pending Rustynet-side work.
- Disk persistence for the query log — `privacy.query_log_to_disk`
  is opt-in but unimplemented; emits a startup warning.
