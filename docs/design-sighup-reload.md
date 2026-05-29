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
