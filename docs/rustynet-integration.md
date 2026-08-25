# Rustynet Tandem Integration (Operator Decree, 2026-08-25)

RustyDNS and Rustynet must work in tandem, frictionlessly: each fully capable
standalone, but able to gel together immediately, with the integration
**user-toggleable** (default OFF until live-proven).

The composition: rustydns runs on a Rustynet **exit node**; devices tunneling
through that exit get its benefits (blocklists, encrypted DoH/DoQ upstream,
ECS stripping) everywhere they roam. Forwarded packets do not automatically
reach a local resolver, so delivery is via:

1. **Managed-DNS handoff** — Rustynets managed/Magic-DNS layer hands out the
   exit-hosted rustydns (mesh IP) as the mesh resolver when the toggle is ON.
2. **Transparent port-53 redirect** at the exit for clients that hardcode a
   resolver (plus optional DoT/DoH-bypass blocking, same toggle family).

Requirements binding THIS repo:
- **Standalone-first**: no hard Rustynet dependency; everything here keeps
  working with zero Rustynet present.
- **Mesh-friendly defaults**: binding to a mesh IP, health signaling an exit
  can consume, and clean behavior under resolver-handoff must stay supported
  and tested (the docker-compose rustynet-mesh integration is the seed).
- **Fail-closed contract**: when Rustynet points clients here and this daemon
  is unhealthy, Rustynet fails client DNS closed — so health/readiness
  reporting must be truthful and prompt.

Phased DoD (tracked in Rustynets
`documents/operations/active/RustydnsExitIntegrationDecree_2026-08-25.md`):
compose-based integration e2e here, then the `dns` service-kind toggle in
Rustynet, then a live-lab stage on real nodes.
