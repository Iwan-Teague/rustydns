# Roadmap

Single source of truth for unfinished work in `rustydns`. Everything not in
this list is either shipped or out of scope. Items are grouped by **what is
blocking them**, then by category. Each item names:

- the concrete deliverable,
- what's blocking it (upstream, sibling project, design, or just unstarted),
- the code/config keys that already exist as scaffolding (so a config written
  today keeps working unchanged when the feature lands),
- the doc surfaces that mention it, so this file and they stay in sync.

If you're adding to this doc: **also add the corresponding `(see roadmap.md)`
marker to the code or doc it relates to**, so no item lives only in one place.

---

## 1. Blocked on upstream (`hickory-dns` 0.26)

### 1.1 RFC 7816 query name minimisation

- **What:** send only the minimum labels needed at each recursion step, so no
  single upstream sees the full QNAME.
- **Blocker:** `hickory-resolver 0.26.1`'s stub resolver does not expose a knob
  to enable qmin on outgoing queries. Tracked at hickory's repo; we adopt
  silently when the knob lands.
- **Scaffolding:** `PrivacyConfig::query_minimization` (default `true`) is
  parsed and validated. `rustydnsd` emits a `tracing::warn!` at startup when
  it is set so operators are not misled into believing qmin is active.
- **Doc mentions:** `docs/architecture.md` resolver table; `docs/security.md`
  §"Query Name Minimisation (RFC 7816) — pending"; `crates/rustydns-resolver/
  src/lib.rs` crate-level table; `rustydns.example.toml` `[privacy]` block.

### 1.2 RFC 8467 DoH query padding

- **What:** pad encrypted query payloads to 128-byte blocks so packet size
  doesn't leak the domain.
- **Blocker:** hickory 0.26 does not apply RFC 8467 padding to DoH bodies.
- **Scaffolding:** `PrivacyConfig::upstream_padding` (default `true`) — same
  startup-warn pattern as qmin.
- **Doc mentions:** `docs/architecture.md` resolver table; `docs/security.md`
  §"Query Padding (RFC 8467) — pending"; resolver crate doc; `example.toml`.

---

## 2. Blocked on Rusty Suite siblings

### 2.1 NodeId-keyed `[[policy]]` matching

- **What:** match per-client DNS policy by Rustynet `NodeId` (ed25519 public
  key) rather than only by `client_ip`. Lets policy follow a peer across IP
  rotations.
- **Blocker:** the `SocketAddr → NodeId` resolution requires a peer-table
  lookup against `rustynetd`'s membership state at query time. That hook isn't
  exposed yet on the Rustynet side.
- **Scaffolding:** `NodePolicy::node_id: Option<String>` is parsed and
  validated (must start with `ed25519:`). `validate_config` rejects entries
  with neither `node_id` nor `client_ip`. A policy with only `node_id` set
  emits a startup warning explaining it is currently inert. The handler keeps
  matching on `client_ip` only; the moment Rustynet exposes the peer-table
  hook, we resolve `NodeId` per query and consult both maps.
- **Doc mentions:** `docs/integration-rustynet.md` §"Per-client DNS policy";
  `rustydns.example.toml` `[[policy]]` block.

---

## 3. Unstarted features (design + privacy review needed)

### 3.1 `query_log_to_disk` implementation

- **What:** opt-in, durable on-disk query log. Today the field exists but the
  daemon refuses to write anything; it logs a startup warning and keeps the
  ring buffer in memory only.
- **Why not yet:** writing query history to disk has hard privacy implications
  (see AGENTS.md §Privacy invariants). Any implementation needs explicit
  decisions on file format (line-delimited JSON, fixed-size rotating?), file
  permissions (always 0600), rotation policy, max-size cap, and whether
  hashed-qname mode is mandatory. Until those are settled, the safer default
  is to refuse.
- **Scaffolding:** `PrivacyConfig::query_log_to_disk: bool` (default `false`)
  is parsed. The daemon warns on `true` and ignores it. `query_log_ring_size`
  (default 1000, max 100,000) bounds the in-memory ring buffer that is
  already wired.

### 3.2 SIGHUP full-config reload

- **What:** re-read `rustydns.toml` end-to-end on SIGHUP — including listener
  addresses, TLS material, upstream resolvers, and per-client policy.
- **Why not yet:** today SIGHUP reloads blocklists and the mesh-zone bundle,
  which covers the high-churn surfaces. Full reload requires socket rebinding,
  resolver reconstruction (with bootstrap retry), and atomic
  `Server`/`DnsHandler` swap-out without dropping in-flight queries. Doable
  but substantial — needs its own design pass.
- **Scaffolding:** `spawn_sighup_reload` in `crates/rustydnsd/src/main.rs` is
  the entry point; today it only delegates to `BlocklistLoader::reload` and
  `Authority::reload_mesh`. Operator workaround: restart the process
  (`systemctl restart rustydns`, `docker compose restart`).
- **Doc mentions:** `crates/rustydnsd/src/main.rs` crate-level signal-handling
  doc; `spawn_sighup_reload` inline comment.

---

## 4. Test coverage gaps

### 4.1 Resolver DoH integration tests via `wiremock`

- **What:** spin up a wiremock server returning canned DoH responses and
  exercise `Resolver::resolve` end-to-end (cache behaviour, fail-closed,
  error decoding, ECS strip verification).
- **Why not yet:** wiremock 0.6 ships TLS support but the resolver
  intentionally uses `webpki-roots` and won't trust a self-signed cert. Either
  needs a test-mode CA injection point (resolver code change) or a custom
  reqwest-backed alternative. Tracked as a real gap, not a "no need".
- **Workspace setup:** `wiremock = "0.6"` is already in `[workspace.dependencies]`.

### 4.2 Subprocess test for qmin/padding startup warnings

- **What:** boot `rustydnsd` in a child process with `query_minimization =
  true`, capture stderr, and assert the warn lines appear. Pins the privacy
  contract so a future refactor that quietly drops the warning fails CI.
- **Why not yet:** subprocess capture is fragile in CI. Unit-testing
  individual `tracing::warn!` calls needs a `tracing-test`-style capturing
  subscriber; not wired.

---

## 5. Maintenance items

### 5.1 `rustls-pemfile` → `rustls-pki-types::pem` migration

- **What:** swap the unmaintained `rustls-pemfile 2.x` (RUSTSEC-2025-0134,
  unmaintained-only) for `rustls-pki-types::pem`. Same job (parse the DoT
  listener's PEM cert/key from disk at startup), modern API.
- **Why not yet:** functional but stylistic — the exposure surface is small
  (we read trusted operator-provided PEM files at startup, not network
  input). `deny.toml` carries the ignore with rationale.
- **Doc mentions:** `deny.toml` comment.

---

## What is NOT on this list (intentionally out of scope)

- **Web UI** — Rustyfin owns operator UI for the suite.
- **DNSSEC signing** — we validate but never sign; we don't own a public zone.
- **A local persistent store** — mesh data lives in the signed bundle file
  (`docs/integration-rustynet.md`); the daemon has no other persistent state
  and won't grow one.
- **A competing DNS library** — hickory only; `deny.toml` bans the old
  `trust-dns-*` names.
- **"Escape hatch" config flags** like `verify_tls_certs = false`,
  `allow_http_sources`, `disable_dnssec`. Operators who need insecure
  behaviour do it at the infrastructure layer.

If something here ever becomes relevant, it warrants its own ADR — not a quiet
addition to roadmap.md.

---

## How to use this file

- **When you finish an item:** delete it here AND from every doc surface
  listed under "Doc mentions". CI will re-read `cargo deny` for advisory
  changes; everything else is doc hygiene.
- **When you add an item:** name a concrete deliverable, the blocker, what
  scaffolding (if any) already exists, and where it surfaces in other docs.
- **When in doubt about scope:** check AGENTS.md §Privacy invariants and
  §Security invariants first. Most "should we add X" questions are already
  answered there.
