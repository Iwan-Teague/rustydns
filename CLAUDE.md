# CLAUDE.md — rustydns

Read `AGENTS.md` first. This file adds Claude-specific context on top of it
— things that have bitten us before, conventions for working in the repo, and
historical footguns worth remembering even though they no longer fire.

## Project phase

**Production-ready. Milestones 1–4 feature-complete.** All five crates ship,
the daemon runs end-to-end on UDP/TCP/DoT/DoH with the full privacy posture,
~150 tests pass in CI, and three deployment paths (systemd / bare binary /
Docker) are documented and verified. Your tasks now are typically:

- Operator-visible improvements (validation tightening, startup warnings,
  defence-in-depth on existing surfaces)
- Test coverage for under-tested branches
- Doc accuracy passes when behaviour shifts
- New features that fit the AGENTS.md invariants without expanding the
  attack surface

## Starting a coding session

1. Read `AGENTS.md` (invariants — non-negotiable)
2. Read `docs/architecture.md` if the task touches the pipeline shape
3. Check `docs/integration-rustynet.md` for Rustynet integration questions
   (signed dns-zone bundle file — there is **no** SQLite, despite older
   drafts that mentioned one)
4. Check `docs/deployment-docker.md` if the task touches packaging
5. Look at the Rustynet workspace for established patterns

## Workspace shape (for reference)

```toml
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
edition      = "2024"
rust-version = "1.88"            # bumped in lockstep with hickory 0.26 → 1.88 floor
```

Workspace deps live in `Cargo.toml` `[workspace.dependencies]`. Pin everything
there, not per-crate. Current major-version pins:

- `hickory-{server,proto,resolver} = "0.26"` (with `https-ring`, `quic-ring`,
  `dnssec-ring`, `webpki-roots` features on the resolver)
- `rustls = "0.23"` with the `ring` provider
- `tokio = "1"` with `["full"]`
- `axum = "0.7"` with `["http2"]`
- `prometheus = "0.14"`

Set `#![forbid(unsafe_code)]` in every crate's `lib.rs` or `main.rs` —
already done across the workspace; do not regress.

## Blocklist implementation notes (historical, still valid)

- `AHashSet<String>` for O(1) lookups, randomised seed per process.
- RPZ wildcards (`*.ads.example.com`): parent domains in a separate set,
  suffix-matched at lookup time.
- Hot reload via `arc_swap::ArcSwap<BlocklistState>` so readers never block.
- Hosts/plain/RPZ/AdGuard formats auto-detected per source.
- `validate_config` and the parser jointly enforce: HTTPS-only sources,
  trusted/untrusted RPZ passthru, allowlist entries must have ≥2 labels.

## Config parsing notes

- `serde` + `toml`, `#[serde(deny_unknown_fields)]` on every config struct.
- `validate_config` runs at startup AND at `--validate-config`. Every
  rejection branch has a unit test in `rustydns-core::config::tests`.
- `Default` for every optional section so partial configs work.
- Resolved config is logged at `tracing::debug!`; secrets (`Secret<String>`)
  redact themselves via a manual `Serialize` impl emitting `"<redacted>"`.

## hickory-dns notes

Use `hickory-*` crates. Do not use `trust-dns-*` — those are the old
unmaintained names and `deny.toml` bans them.

### DoH upstream root-CA setup (history — already fixed, but useful to know)

Earlier in the project, `hickory-resolver = { features = ["dns-over-https-rustls", ...] }`
did **not** pull in any root certificate source. With `tls_config: None`
(the old default we passed in `build_name_servers`), hickory built a
`rustls::ClientConfig` with an empty `RootCertStore`, and every upstream cert
validated as `UnknownIssuer`.

Symptom: every DoH query → `SERVFAIL` after ~350 ms. At our log level the
error read `proto error: io error: invalid data` — opaque. The real error
only showed with `RUST_LOG=hickory_proto=trace`:

```
hickory_proto::xfer::dns_exchange: stream errored while connecting,
  error: io error: invalid peer certificate: UnknownIssuer
```

The double-wrap (`io error: invalid data`) was hickory's `Display` impl
flattening the source chain. To debug similar wraps in future, walk
`std::error::Error::source()` and log the chain.

**Current state:** the workspace pulls `hickory-resolver` with the
`webpki-roots` feature so the Mozilla CA bundle is compiled in. On top of
that, the resolver explicitly builds a `rustls::ClientConfig` with
`with_protocol_versions(&[&TLS13])` (or `[TLS13, TLS12]`) and passes it via
`HickoryResolver::builder_with_config(...).with_tls_config(...)`, so
`upstream.min_tls_version` actually pins the floor. The legacy
`rustls-native-certs` / `hickory 0.24 + rustls 0.21` mismatch is gone.

### MSRV is 1.88

`hickory-{net,proto,resolver,server} 0.26.1` all carry `rust-version = 1.88`
in their manifests. Bumping the workspace below 1.88 will break CI.
The Dockerfile builder image and the CI toolchain pin match.

## Performance-sensitive paths

The query hot path (Authority lookup → Blocklist check → cache lookup) must
not allocate on the heap for cache hits. Use `Cow<'_, str>` or pre-intern
domain names where possible. The handler canonicalises the QNAME **once**
(`canonical_qname` → `Cow`, borrowing when the client already sent lower
case) and hands that single form to authority / blocklist / allowlist /
query-log, so the pipeline no longer re-lowercases at each stage.
`Authority::normalise_name` returns a borrowing `Cow` when the input is
already canonical, and `Allowlist::is_allowed` mirrors `engine::is_blocked`'s
ASCII fast path (no alloc unless the name has uppercase). The qtype label
comes from `RecordType -> &'static str` (zero-alloc), and per-client
`zones_allowed` is an `Arc<[String]>` so policied queries clone an `Arc`
rather than deep-copying the zone list. Net: a lowercase cache-hit query
allocates only the unavoidable `info.query.name().to_string()`.

## Logging conventions

**Read the AGENTS.md privacy invariants before touching tracing calls.**
Summary:

- **Never log raw `qname` at `info!`, `warn!`, or `error!`.** Use the hashed
  form from `QueryLog::hash_qname` (per-process-salted u64) or a redacted
  marker.
- **Never log a full client IP at `info+`.** Use `client.anonymized()`.
  `ClientId` deliberately has no `Display` impl to make this hard to forget.
- `tracing::trace!` and `debug!` may carry raw qname or full client IP,
  but every such call should be visibly marked as debug-only.

Worked examples that match the invariants:

```rust
// Query receipt (debug-only; never enable in production)
tracing::debug!(client = %client_id, qname = %name, qtype = %qtype, "query received");

// Authority hit (trace-only — info would log every mesh query)
tracing::trace!(qtype = %rtype, count = matching.len(), "authority lookup");

// Blocklist hit (info-safe ONLY because we anonymise both halves)
tracing::info!(
    client    = %client.anonymized(),
    qname_hash = format!("{:016x}", query_log.hash_qname(&name)),
    "query blocked",
);

// Upstream error (info-safe — URL is operator-controlled, error is from rustls/hickory)
tracing::warn!(upstream = %url, error = %e, "upstream resolver failed");
```

The old version of this file had an example logging `qname` at `info!` for
blocklist hits — that violated the privacy invariants. Do not regress.

## Things to avoid

- Don't add a web UI (Rustyfin's job).
- Don't add a database (mesh state comes from a signed bundle file).
- Don't add `verify_tls_certs = false`, `allow_http_sources`, `disable_dnssec`,
  or any other "escape hatch" — operators who want insecure should do it at
  the infrastructure layer, not in the daemon.
- Don't introduce a competing DNS library — hickory only.
- Don't bump RUSTFLAGS to suppress lints; fix the lints. The CI YAML used
  to silently skip jobs because of unquoted colons in step names; we now
  quote them. Don't write `name: foo: bar` in a workflow file.
