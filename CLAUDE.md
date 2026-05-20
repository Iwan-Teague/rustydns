# CLAUDE.md — rustydns

Read `AGENTS.md` first. This file adds Claude-specific context on top of it.

## Project phase

Scaffolding. No Rust code exists. Your most likely tasks right now are:

- Initialising the Cargo workspace and crate skeletons
- Implementing `rustydns-core` types and config parsing
- Writing the `rustydns-blocklist` engine (good starting point — pure logic, no network)

## Starting a coding session

1. Read `AGENTS.md` (invariants, crate order, conventions)
2. Read `docs/architecture.md` (pipeline design and crate responsibilities)
3. Check `docs/integration-rustynet.md` if the task involves Rustynet or SQLite
4. Look at the Rustynet workspace for established patterns — particularly how `rustynetd` wires its crates together and how `rustynet-crypto` handles config types

## Workspace initialisation (first coding task)

When initialising the Cargo workspace:

```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    "crates/rustydns-core",
    "crates/rustydns-blocklist",
    "crates/rustydns-authority",
    "crates/rustydns-resolver",
    "crates/rustydnsd",
]
resolver = "2"

[workspace.package]
edition = "2024"
rust-version = "1.85"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
tokio       = { version = "1", features = ["full"] }
tracing     = "0.1"
thiserror   = "2"
anyhow      = "1"
serde       = { version = "1", features = ["derive"] }
toml        = "0.8"
hickory-server   = "0.24"
hickory-proto    = "0.24"
hickory-resolver = "0.24"
```

Set `#![forbid(unsafe_code)]` in every crate's `lib.rs` or `main.rs`.

## Blocklist implementation notes

The blocklist engine is the best first Rust target because it has no external dependencies and is fully unit-testable:

- Use an `AHashSet<String>` (or `AHashSet<Name>` after hickory-proto Name parsing) for O(1) lookups
- For RPZ wildcard rules (`*.ads.example.com`), store parent domains in a separate set and check suffix matches
- Hot reload: use `arc-swap` crate (`ArcSwap<BlocklistState>`) so reader threads never block during a reload
- Parse hosts-format lines: skip `#` comments, skip `localhost`, split on whitespace, take the second field

## Config parsing notes

- Use `serde` + `toml` for all config
- Validate at startup — don't let bad config cause a panic at query time
- Provide `Default` implementations for all optional config sections
- Log the resolved config at `tracing::debug!` level on startup (but redact any token-like fields)

## hickory-dns version note

Use `hickory-*` crates (the renamed fork of `trust-dns`). Do not use `trust-dns-*` crates — they are the old unmaintained names. The `hickory` crates are the actively maintained continuation.

## Performance-sensitive paths

The query hot path (Authority lookup → Blocklist check → cache lookup) must not allocate on the heap for cache hits. Use `Cow<'_, str>` or pre-intern domain names where possible.

## Logging conventions

```rust
// At query receipt
tracing::debug!(client = %client_id, qname = %name, qtype = %record_type, "query received");

// At authority hit
tracing::trace!(qname = %name, "authority hit");

// At blocklist hit
tracing::info!(client = %client_id, qname = %name, "query blocked");

// At upstream error
tracing::warn!(upstream = %url, error = %e, "upstream resolver failed");

// Never log raw query content at info+ level in production (privacy)
```
