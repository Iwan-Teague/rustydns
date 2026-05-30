# Design: SIGHUP Full-Config Reload (Roadmap 3.2)

## Context
Reload `rustydns.toml` entirely on SIGHUP, updating upstreams, policies, and listeners without dropping queries.

## Challenges
1. Socket re-binding if listeners change.
2. TLS material reload for DoT/DoH.
3. `hickory-server` does not natively support live-swapping `RequestHandler` or listeners without tearing down the server.

## Proposed Phased Architecture

### Phase 1: Inner State Swap (No-socket reload)
- Wrap `DnsHandler` dynamic components (`Resolver`, `policy_by_ip`, `metrics`) in `arc_swap::ArcSwap`.
- On SIGHUP, parse new config.
- If `listen` addresses or `tls` config changed -> Abort reload, log `warn!("socket/TLS changes require process restart")`.
- If only policies/upstreams changed -> Build new `Resolver` / Policy map, swap them. In-flight queries use whatever `Arc` they cloned.

### Phase 2: Graceful Server Handover (Full reload)
- To support socket/TLS changes later:
- Need a custom socket acceptor that yields connections to the current active `ServerFuture`.
- On SIGHUP, start new `ServerFuture`, signal old one to stop accepting but finish in-flight.

**Recommendation**: Execute Phase 1. 95% of SIGHUP use cases are policy/upstream changes. Phase 1 delivers value instantly with low risk.

## Status: Phase 1 IMPLEMENTED

Phase 1 shipped. On SIGHUP the daemon (`reload_config` in
`crates/rustydnsd/src/main.rs`):

1. Reloads blocklist content from the current sources + the mesh bundle
   (pre-existing behaviour).
2. Re-reads `rustydns.toml`. A parse/validate failure aborts the swap and
   leaves the running config untouched (logged at `warn!`).
3. Rebuilds the upstream `Resolver` and stores it into
   `DnsHandler.resolver: Arc<ArcSwap<Resolver>>`. A rebuild failure keeps the
   old resolver.
4. Rebuilds and swaps the rate limiter (`Arc<ArcSwap<RateLimiter>>`) and the
   per-client policy table (`Arc<ArcSwap<HashMap<IpAddr, NodePolicy>>>`).

In-flight queries that already `load()`ed an `Arc` finish against that
snapshot; the next query sees the new one — no dropped queries.

The handler reads `resolver` via `load_full()` (owned `Arc`) so the `ArcSwap`
guard is never held across the `.await` in the resolve path.

## Status: Phase 2 IMPLEMENTED (with a capability-bound caveat)

Phase 2 (live listener handover) shipped, scoped by a hard constraint
discovered during implementation.

### The capability conflict

The daemon drops **all** capabilities — including the bounding set, so
`CAP_NET_BIND_SERVICE` can never be regained — immediately after the initial
port binds (AGENTS.md §Capability discipline; the whole point is that "a future
bug or compromise can't re-bind privileged ports"). Binding any port < 1024
requires that capability, and `SO_REUSEPORT` does **not** bypass the privilege
check. Therefore a running, post-drop daemon **physically cannot rebind a
privileged port** (`:53`, `:853`) — not even the same port it already holds.

Retaining the capability to enable rebinding was rejected: it would directly
re-enable the port-hijack the invariant exists to prevent, and AGENTS.md
forbids adding such a path "even if the operator explicitly requests it."

### What shipped

Live, **zero-drop** handover for listeners on **unprivileged** ports (≥ 1024):

- Each listener group is independently replaceable: the hickory `Server`
  (UDP/TCP/DoT), the DoH axum server, and the metrics axum server.
- New generations bind with `SO_REUSEADDR` + `SO_REUSEPORT`
  (`listeners::bind_udp` / `bind_tcp`) so the new socket binds the same port
  while the old one is still draining — no query is lost.
- `ActiveListeners::reload_listeners` diffs each group against what is actually
  bound and, on change: builds the new generation, swaps it in, then drains the
  old (the hickory generation drains in the background, bounded by the shutdown
  timeout; DoH/metrics tasks are cancelled via their per-generation child
  token). On a bind/TLS failure the old generation is kept and the error logged
  — the daemon never goes dark.
- **DoT TLS cert rotation** works this way when DoT is on an unprivileged port:
  changing `tls_cert_path`/`tls_key_path` rebuilds the DoT listener with the new
  material.

A change to a listener on a privileged port, or to blocklist *sources* / the
on-disk query log, is detected and logged as restart-required
(`restart_required_changes` covers the latter two). See roadmap.md §3.

### Tests

- `listeners.rs`: `is_privileged` / `all_unprivileged` classification, and
  `SO_REUSEPORT` proving two binds on the same live port succeed (TCP + UDP).
- `main.rs`: `restart_required_changes` now only flags blocklist/query-log
  fields (listener/metrics handled by the reconciler).
- Verified end-to-end: a SIGHUP that moves the DNS + metrics ports rebinds the
  new ports, drains the old generation cleanly, and refuses (with a clear warn)
  a change to a privileged port while keeping the old listeners serving.
