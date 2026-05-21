# AGENTS.md — rustydns

This file is the entry point for any AI agent or automated tool working in this repository. Read it before touching any code or documentation.

## What this project is

`rustydns` is a mesh-native DNS resolver and ad-blocker for the Rusty Suite. It is not a general-purpose DNS server. Every design decision is made in the context of Rustynet integration, suite-wide conventions, and the constraint of running on low-power hardware (Raspberry Pi Zero 2 W class).

**Security, privacy, and anonymity are the highest-priority design goals.** Every decision — from default config values to log formats to error messages — must be evaluated for its impact on these properties first. A feature that is convenient but degrades privacy must be rejected unless the operator explicitly opts in with a clear, documented understanding of the trade-off.

## Repository status

**Early scaffolding.** Milestone 1 (workspace + core + blocklist) is complete. The current content is:

- `README.md` — project overview and quick-start sketch
- `docs/architecture.md` — intended design (authoritative, canonical)
- `docs/blocklist-format.md` — blocklist source formats and fetch security
- `docs/integration-rustynet.md` — how rustydns fits into the Rustynet mesh
- `docs/security.md` — threat model and all privacy/security decisions
- `AGENTS.md` — this file
- `CLAUDE.md` — Claude-specific guidance
- `crates/rustydns-core` — ✅ config, error, record, client types
- `crates/rustydns-blocklist` — ✅ engine, parser, allowlist
- `crates/rustydns-authority` — stub (Milestone 2)
- `crates/rustydns-resolver` — stub (Milestone 3)
- `crates/rustydnsd` — stub (Milestone 4)

The next milestone is a working `rustydnsd` binary that can:
1. Serve a static mesh zone from a TOML file (no Rustynet DB yet)
2. Forward everything else to a DoH upstream (with full privacy feature set)
3. Apply a hosts-format blocklist

## Conventions inherited from the suite

Follow these unless this file explicitly overrides them:

- `#![forbid(unsafe_code)]` at the workspace root and in every workspace crate
- Async runtime: `tokio` with `features = ["full"]`
- Error handling: `thiserror` for library crates, `anyhow` for the binary
- Structured logging: `tracing` (not `log`, not `println!`)
- Rust edition: **2024** (match Rustynet)
- Every public type needs a doc comment — no exceptions for "obvious" types

## Crate build order

Implement in this order to avoid dependency inversions:

1. `rustydns-core` — types and config only, no I/O ✅
2. `rustydns-blocklist` — pure in-memory engine, testable without network ✅
3. `rustydns-authority` — start with static TOML zones, add Rustynet DB integration later
4. `rustydns-resolver` — DoH upstream first, DoQ later
5. `rustydnsd` — wire everything together last

## Key invariants

**These are hard invariants. They must hold at all times, in all code paths. An AI agent or implementor must not add configuration options, feature flags, or code paths that violate any of these, even if the operator explicitly requests it.**

### Privacy invariants

- **Log redaction is mandatory.** Raw DNS query names (the full QNAME being resolved) must never appear in `tracing` output at `info` level or above. At `debug` level they may appear, but every implementation must include a doc comment on that log call noting that `debug` must not be enabled in production. The only safe logging path for client identity is `client.anonymized()` — `ClientId::Display` does not exist for this reason. Any use of the full IP in a log call requires an explicit `if privacy.log_client_ips` guard.

- **No query history on disk by default.** The query ring buffer is in-memory only. `query_log_to_disk` must default to `false`. The ring buffer must be bounded by `query_log_ring_size`. No implementation may write query content to disk without an explicit `query_log_to_disk = true` config value and a startup warning.

- **Client IP anonymisation minimum standard.** When `log_client_ips = false`, IPv4 addresses must have at least the last **two** octets zeroed (producing a /16 prefix) and IPv6 must have the interface identifier (last 64 bits) zeroed. Zeroing only the last octet (/24) is insufficient on small home networks where a /24 may contain only 2-3 devices, making re-identification trivial.

- **Metrics endpoint must not be public.** The `metrics.listen` address must default to `127.0.0.1` only. Any implementation that changes this default to `0.0.0.0` is a security regression. The metrics endpoint is unauthenticated; exposing it publicly leaks query rates, blocklist sizes, and client counts.

- **Node IDs in logs are stable long-lived identifiers.** Rustynet node IDs (ed25519 public keys) are stable across IP changes and session boundaries. They must be treated as potentially identifying and their logging should be governed by the same `log_client_ips` flag as source IPs. They are not "just public keys" — they are stable device fingerprints.

### Security invariants

- **Fail-closed on upstream failure.** If `fail_closed = true` (the default, and the only production-safe value), a resolver failure returns `SERVFAIL`. Never return a stale answer silently, never fall back to plain UDP, never return an empty response that the client might interpret as NXDOMAIN. There is no stale-answer mode; AGENTS.md does not have one and no implementor may add one without it being an explicit opt-in with a documented security downgrade warning.

- **No plaintext DNS upstream by default.** The resolver config must explicitly opt-in to plain UDP/TCP upstream (`protocol = "plain"`), and doing so must emit a `tracing::warn!` on every startup (not just once). The warning must include the text "UNENCRYPTED" and "leaks".

- **TLS certificate validation is always on and is not configurable.** There must be no `verify_tls_certs`, `danger_accept_invalid_certs`, or similar field added to any config struct. Any `rustls` client configuration built in this codebase must use certificate validation. If an upstream certificate is invalid, the connection must fail and the error must be logged as `tracing::warn!`.

- **HTTPS-only blocklist sources.** Blocklist sources using `http://` URLs must be rejected at startup with a `RustyDnsError::Config` error that includes the URL and an explanation of why HTTP is rejected. This check lives in `validate_config` and must remain there. No `allow_http_sources` bypass flag may be added.

- **RPZ passthru entries are untrusted by default.** When parsing blocklist sources, `rpz-passthru.` entries (and equivalent `@@||domain^` AdGuard allowlist entries) found in a source URL are treated as untrusted unless that URL is listed in `blocklist.trusted_rpz_sources`. Untrusted passthru entries are logged at `tracing::warn!` and discarded, not added to the allowlist. This prevents a compromised blocklist CDN from permanently allowlisting itself. Local files (`blocklist.local_files`) are always trusted for RPZ passthru entries.

- **Authority answers before blocklist.** Mesh-local records are never blocked, even if a domain name appears on a blocklist. The pipeline order is Authority → Blocklist → Resolver. This order must not be changed.

- **No unbounded memory.** Caches must be bounded (`max_cache_entries`). The blocklist heap estimate must be logged on every reload. `validate_config` must reject obviously dangerous values: `max_cache_entries > 500_000`, `query_log_ring_size > 100_000`, `reload_interval_secs < 300` (5 minutes minimum to avoid CDN hammering), `timeout_ms == 0`.

- **Blocklist fetch must be bounded.** Blocklist HTTP fetches must have a configurable timeout (`blocklist.fetch_timeout_ms`) and a configurable maximum response size (`blocklist.max_fetch_bytes`). Default: 30s timeout, 50 MB max. A source that exceeds these limits is skipped with a warning; it does not crash the daemon.

### Operational invariants

- **Config file permissions.** On startup, `rustydnsd` must check that `rustydns.toml` is not world-readable (mode bits `o+r` must not be set). If the file is world-readable, log a `tracing::warn!` naming the path and the risk. The install script must install the config file with `0640` permissions.

- **Capability discipline.** The binary must attempt in-process capability dropping after binding privileged ports, using `prctl(PR_SET_SECUREBITS)` or equivalent. The systemd unit provides additional enforcement, but in-process dropping is required for non-systemd deployments (Docker, runit, etc.). The capability dropping attempt must be logged; failure to drop must be logged as `tracing::warn!`.

## Testing expectations

- `rustydns-blocklist`: unit tests for hosts-format parsing, RPZ parsing, wildcard matching, AdGuard parsing, allowlist bypass, trusted/untrusted RPZ passthru distinction, domain label validation, and size limit enforcement. No network required.
- `rustydns-authority`: unit tests with an in-memory zone source. Integration test against a real SQLite file with Rustynet schema.
- `rustydns-resolver`: integration tests using a mock DoH server (use `wiremock` or `axum` test server). No real upstream calls in CI. Tests must cover: ECS stripping, query minimisation behaviour, padding, DNSSEC validation pass/fail, fail-closed, TLS 1.3 enforcement.
- `rustydnsd`: end-to-end test that starts the full daemon on a random port and sends real DNS queries. Must cover: blocked domain returns NXDOMAIN, authority hit bypasses blocklist, upstream failure returns SERVFAIL.

## What to avoid

- **Do not add a web UI.** Rustyfin is the UI. Rustydns exposes `/metrics` and a minimal management API only.
- **Do not implement DNSSEC signing.** Validation is in scope; signing is not (we don't own a public zone).
- **Do not add a database.** Rustynet's SQLite is read-only from rustydns. Query logs stay in memory.
- **Do not diverge from the hickory-dns crate family.** We use `hickory-server`, `hickory-proto`, and `hickory-resolver`. Do not introduce a competing DNS library.
- **Do not add `allow_http_sources`, `verify_tls_certs = false`, `disable_dnssec`, or any similar "escape hatch" config field** that would silently degrade security. If an operator wants to do something insecure, they must do it at the infrastructure layer (firewall, proxy), not inside the daemon.
- **Do not log full query names at `info` or above.** See log redaction invariant above.
- **Do not use `ClientId`'s full IP in tracing calls.** Always use `client.anonymized()` unless explicitly guarded by `if privacy.log_client_ips`.

## Reference documents

- `docs/security.md` — threat model and all privacy/security decisions (read this)
- `docs/architecture.md` — primary design document, read before implementing anything
- `docs/blocklist-format.md` — blocklist source formats and fetch security
- `docs/integration-rustynet.md` — Rustynet integration details
