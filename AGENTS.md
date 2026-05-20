# AGENTS.md — rustydns

This file is the entry point for any AI agent or automated tool working in this repository. Read it before touching any code or documentation.

## What this project is

`rustydns` is a mesh-native DNS resolver and ad-blocker for the Rusty Suite. It is not a general-purpose DNS server. Every design decision is made in the context of Rustynet integration, suite-wide conventions, and the constraint of running on low-power hardware (Raspberry Pi Zero 2 W class).

## Repository status

**Early scaffolding.** No Rust code exists yet. The current content is:

- `README.md` — project overview and quick-start sketch
- `docs/architecture.md` — intended design (authoritative, canonical)
- `docs/integration-rustynet.md` — how rustydns fits into the Rustynet mesh
- `AGENTS.md` — this file
- `CLAUDE.md` — Claude-specific guidance

The next milestone is a working `rustydnsd` binary that can:
1. Serve a static mesh zone from a TOML file (no Rustynet DB yet)
2. Forward everything else to a DoH upstream
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

1. `rustydns-core` — types and config only, no I/O
2. `rustydns-blocklist` — pure in-memory engine, testable without network
3. `rustydns-authority` — start with static TOML zones, add Rustynet DB integration later
4. `rustydns-resolver` — DoH upstream first, DoQ later
5. `rustydnsd` — wire everything together last

## Key invariants

These must hold at all times, in all code paths:

- **Fail-closed on upstream failure.** If `fail_closed = true` (default), a resolver failure returns `SERVFAIL`. Never return a stale answer silently or fall back to plain UDP without explicit configuration.
- **No plaintext DNS upstream by default.** The resolver config must explicitly opt-in to plain UDP/TCP upstream (`protocol = "plain"`), and doing so must emit a `tracing::warn!` on startup.
- **Authority answers before blocklist.** Mesh-local records are never blocked, even if a domain name appears on a blocklist. The pipeline order is Authority → Blocklist → Resolver.
- **No unbounded memory.** Caches must be bounded (`max_cache_entries`). Blocklist must measure and log its memory footprint. Reject configs that would obviously OOM a Pi Zero 2 W.

## Testing expectations

- `rustydns-blocklist`: unit tests for hosts-format parsing, RPZ parsing, wildcard matching, and allow-list bypass. No network required.
- `rustydns-authority`: unit tests with an in-memory zone source. Integration test against a real SQLite file with Rustynet schema.
- `rustydns-resolver`: integration tests using a mock DoH server (use `wiremock` or `axum` test server). No real upstream calls in CI.
- `rustydnsd`: end-to-end test that starts the full daemon on a random port and sends real DNS queries.

## What to avoid

- **Do not add a web UI.** Rustyfin is the UI. Rustydns exposes `/metrics` and a minimal management API only.
- **Do not implement DNSSEC signing.** Validation is in scope; signing is not (we don't own a public zone).
- **Do not add a database.** Rustynet's SQLite is read-only from rustydns. Query logs stay in memory.
- **Do not diverge from the hickory-dns crate family.** We use `hickory-server`, `hickory-proto`, and `hickory-resolver`. Do not introduce a competing DNS library.

## Reference documents

- `docs/architecture.md` — primary design document, read before implementing anything
- `docs/integration-rustynet.md` — Rustynet integration details
- Rustynet `AGENTS.md` — suite-wide conventions
- Rustynet `documents/SecurityMinimumBar.md` — security baseline that all suite projects inherit
