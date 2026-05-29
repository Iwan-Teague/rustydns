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

`restart_required_changes` compares the new config against the startup config
and logs (at `warn!`) any changed field that Phase 1 cannot apply — listener
addresses, DoT/DoH/TLS paths, the metrics binding, blocklist sources, and the
on-disk query-log toggle/path. Those are **not** applied; they need Phase 2
(socket/TLS handover) or a restart. See roadmap.md §3.2.

The handler reads `resolver` via `load_full()` (owned `Arc`) so the `ArcSwap`
guard is never held across the `.await` in the resolve path.
