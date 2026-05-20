# Rustynet Integration

`rustydns` is built to be a first-class citizen of the Rustynet mesh, not just a service that happens to run on the same machine.

## Zone data from rustynet-dns-zone

Rustynet's control plane already maintains a DNS zone for the mesh via the `rustynet-dns-zone` crate. Every peer that joins the mesh gets an `A`/`AAAA` record in the mesh zone (default `mesh.`). `rustydns-authority` reads this data directly:

```
rustynetd
  └─► rustynet-control (membership reconciliation)
        └─► rustynet-dns-zone (zone writes to SQLite)
              └─► rustydns-authority (live reads via zone API)
                    └─► clients get `mydevice.mesh A 100.64.x.x`
```

### Recommended deployment

Run `rustydnsd` on the same host as `rustynetd` (typically the control-plane node or any always-on device like a home server running rustyfin). Point all Rustynet peers at this host's mesh IP as their DNS server via the Rustynet config:

```toml
# In rustynet config (peer side)
[dns]
resolvers = ["100.64.0.1"]   # IP of the node running rustydnsd
search_domains = ["mesh."]
```

### SQLite path

`rustydns-authority` needs read access to the Rustynet control database:

```toml
# In rustydns.toml
[authority]
rustynet_db = "/var/lib/rustynet/control.db"
```

The file is opened read-only. `rustydns` never writes to it. SQLite WAL mode (which Rustynet uses) allows concurrent readers without blocking writers.

## Rustynet policy integration

Rustynet's policy engine controls which nodes can reach which services. `rustydns` participates in this in two ways:

### 1. rustydns as a Rustynet service

`rustydnsd` can register itself as a Rustynet service, making it reachable at `rustydns.mesh:53` only to nodes that have the `dns` capability in their policy. Nodes without the policy cannot resolve mesh names — which is useful for quarantining compromised or untrusted nodes.

```toml
# rustynet policy snippet
[[service]]
name = "rustydns"
port = 53
allowed_capabilities = ["dns"]
```

### 2. Per-client DNS policy

`rustydns` resolves the source IP of each query to a Rustynet `NodeId` (via the peer table in the control DB). This lets it apply per-node rules:

| Rule | Use case |
|------|----------|
| `blocklist_bypass = true` | A server node that legitimately resolves ad-network endpoints |
| `zones_allowed = ["mesh.", "internal."]` | Restrict a guest node to only resolving internal names |
| `log_all_queries = true` | Audit mode for a specific node |

These rules are defined in `rustydns.toml` and keyed by Rustynet node ID:

```toml
[[policy.node]]
node_id = "ed25519:AbCdEf..."
blocklist_bypass = true

[[policy.node]]
node_id = "ed25519:GhIjKl..."
zones_allowed = ["mesh."]
log_all_queries = true
```

## Propagation latency

| Event | Propagation to DNS |
|-------|--------------------|
| New peer joins mesh | ≤ 30 s (SQLite poll interval, configurable) |
| Peer leaves / is removed | ≤ 30 s + record TTL (default 30 s mesh TTL) |
| IPC push mode (future) | < 1 s |

## Split-horizon DNS

`rustydns` serves different answers for the same name depending on whether the client is on the mesh or not — but since it only listens on the mesh interface (or `127.0.0.1` on the control node), this is handled automatically by network topology rather than requiring any special configuration.

If you want a name like `rustyfin.mesh` to also be resolvable from the public internet (via a different IP), add a static zone override:

```toml
# rustydns.toml static zone override
[[authority.static_record]]
name    = "rustyfin.mesh."
type    = "A"
address = "203.0.113.1"      # public IP
ttl     = 300
client_filter = "external"   # only serve to non-mesh clients
```

## Deployment checklist

- [ ] `rustydnsd` binary deployed and running as `rustydns` user
- [ ] `CAP_NET_BIND_SERVICE` granted (or running on port > 1024 behind redirect)
- [ ] Read access to `/var/lib/rustynet/control.db` confirmed
- [ ] Rustynet peers configured to use this node as their DNS resolver
- [ ] Rustynet policy allows `dns` capability for intended nodes
- [ ] Blocklist sources reachable from the resolver host at startup
- [ ] `/metrics` endpoint scraped by your monitoring stack (optional)
- [ ] `SIGHUP` wired into your service manager for config/blocklist reload
