# Roadmap

Single source of truth for **feature deferrals** in `rustydns` — things that are
deliberately not built yet because they're blocked on upstream/sibling code, are
restart-only by design, or need their own design pass. For the broader, more
opportunistic **improvement backlog** (security/anonymity/efficiency hardening,
test-coverage gaps, tech debt found by scouring the code), see
[`TODO.md`](TODO.md).

Items are grouped by **what is blocking them**, then by category. Each item
names:

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

## 3. Remaining restart-only configuration

SIGHUP reload (roadmap 3.2) is **done** — both phases shipped:

- **Phase 1 (hot-swap):** `[upstream]` resolver, `[[policy]]`, and
  `[rate_limit]` swap atomically via `ArcSwap`.
- **Phase 2 (live listener handover):** changed listeners on **unprivileged**
  ports (DNS UDP/TCP, DoT incl. TLS cert rotation, DoH, metrics) rebind
  zero-drop via `SO_REUSEPORT`. See `ActiveListeners` in
  `crates/rustydnsd/src/main.rs`, `crates/rustydnsd/src/listeners.rs`, and
  `docs/design-sighup-reload.md`.

A few fields remain restart-only **by design**, not for lack of work:

- **Listeners on privileged ports (<1024)** — DNS `:53`, DoT `:853`. The
  daemon drops `CAP_NET_BIND_SERVICE` (and the whole bounding set) right
  after the initial bind, so it physically cannot rebind a privileged port;
  `SO_REUSEPORT` does not bypass the privilege check. This is the
  capability-discipline invariant working as intended (AGENTS.md). A change
  to such a listener is detected on reload and logged as restart-required.
  Deployments that need live DNS/DoT listener changes can bind unprivileged
  ports and port-map at the orchestrator/firewall layer.
- **Blocklist *source list*** — the loader + engine are built once at startup
  (SIGHUP still re-fetches content from the *current* sources).
- **On-disk query log** path/toggle — the writer task + file handle are bound
  at startup.

---


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
