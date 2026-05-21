# Rustynet Integration

`rustydns` is built to be a first-class citizen of the Rustynet mesh.

## Zone data from rustynet-dns-zone

Rustynet's control plane maintains a DNS zone for the mesh via the `rustynet-dns-zone` crate. Every peer that joins the mesh gets an `A` record under the mesh zone (default `mesh.`). The zone is published as a **signed, line-oriented bundle file** that `rustynetd` writes to disk. `rustydns-authority` reads that file, verifies its ed25519 signature against an operator-configured verifier key, and merges the records into its authority store:

```
rustynetd
  └─► rustynet-control (membership reconciliation)
        └─► rustynet-dns-zone (builds + signs zone bundle)
              └─► /var/lib/rustynet/dns-zone.bundle
                    └─► rustydns-authority (read + ed25519 verify + serve)
                          └─► clients get `mydevice.mesh A 100.64.x.x`
```

Earlier drafts of this document and `AGENTS.md` referred to a SQLite
control database. **That was speculative — the real implementation is the
signed bundle file.** `rustydns` matches the real implementation, not the
old spec.

### Recommended deployment

Run `rustydnsd` on the same host as `rustynetd` (or any always-on device like the rustyfin host). Point all Rustynet peers at this host's mesh IP as their DNS resolver:

```toml
# In rustynet config (peer side)
[dns]
resolvers     = ["100.64.0.1"]   # mesh IP of the node running rustydnsd
search_domains = ["mesh."]
```

### Bundle + verifier-key paths

`rustydns-authority` reads the signed dns-zone bundle file written by
`rustynetd`. Both the bundle path and the path to the ed25519 verifier
public key must be configured:

```toml
# In rustydns.toml
[authority]
mesh_zone_bundle_path       = "/var/lib/rustynet/dns-zone.bundle"
mesh_zone_verifier_key_path = "/var/lib/rustynet/dns-zone-verifier.key"
mesh_zone_max_age_secs      = 600   # reject bundles older than 10 min
poll_interval_secs          = 30
```

The verifier key file must contain a single hex-encoded 32-byte ed25519
public key (64 hex chars on one line). The corresponding signing key
lives inside `rustynetd` and never leaves it — that's what makes the
bundle trustworthy after it's been written to disk.

**Required permissions:** the `rustydns` user must be in the group that
owns the bundle file and the key file. Neither file should be writable
by `rustydns` — only by `rustynetd`. Verify with:

```bash
ls -la /var/lib/rustynet/dns-zone.bundle /var/lib/rustynet/dns-zone-verifier.key
# -rw-r----- 1 rustynet rustynet ...   (bundle)
# -rw-r----- 1 rustynet rustynet ...   (verifier key)
id rustydns        # confirm rustydns is in the rustynet group
```

### Refresh model

The daemon re-reads the bundle every `poll_interval_secs` (default 30s)
and atomically swaps in the new snapshot via `ArcSwap` — readers never
block during reload. `SIGHUP` triggers an immediate reload alongside
the blocklist reload.

A bundle whose `expires_at_unix` is in the past, or whose
`generated_at_unix` is older than `mesh_zone_max_age_secs`, is rejected
at load time. The previous snapshot keeps serving — the daemon never
serves an unsigned, untrusted, or expired bundle.

## Rustynet policy integration

### rustydns as a Rustynet service

`rustydnsd` registers as a Rustynet service, making it reachable at `rustydns.mesh:53` only to nodes that have the `dns` capability in their policy. Nodes without this capability cannot reach port 53 at the network layer:

```toml
# rustynet policy snippet
[[service]]
name = "rustydns"
port = 53
allowed_capabilities = ["dns"]
```

**Behaviour for nodes without the `dns` capability:** The Rustynet network layer drops the connection before it reaches `rustydnsd`. The daemon never sees the query. This is enforced at the transport layer, not the application layer — the daemon's application-level policy (below) is a second layer of defence for mesh-adjacent scenarios, not the primary enforcement mechanism.

### Per-client DNS policy

`rustydns` resolves the source IP of each query to a Rustynet `NodeId` (via the peer table in the control DB). This enables per-node DNS rules. **Policy grants are configured in `rustydns.toml` only — they cannot be requested by a node itself.** An operator must explicitly add a `[[policy]]` entry:

```toml
# rustydns.toml
[[policy]]
node_id = "ed25519:AbCdEf..."
blocklist_bypass = true

[[policy]]
node_id = "ed25519:GhIjKl..."
zones_allowed = ["mesh."]
log_all_queries = true
```

**Note on TOML syntax:** Use `[[policy]]` (double brackets) for each node — this is TOML array-of-tables syntax. The field name in the config struct is `policy` (not `policy.node`).

| Rule | Use case | Risk |
|------|----------|------|
| `blocklist_bypass = true` | Server node that resolves ad endpoints for testing | Bypasses all ad blocking for that node |
| `zones_allowed = ["mesh."]` | Guest / quarantined node | Node cannot resolve external names at all |
| `log_all_queries = true` | Audit mode | Logs all queries from this node (subject to `log_client_ips` flag) |

### Trust model for policy grants

`blocklist_bypass` is an operator-level grant. It should be:
- Reviewed before assignment
- Assigned only to identified, trusted nodes
- Audited periodically (the node can be identified by its public key)

There is no mechanism for a node to request its own policy upgrade. A node cannot escalate its own privileges through any DNS mechanism.

## Propagation latency

| Event | Propagation to DNS |
|-------|--------------------|
| New peer joins mesh | ≤ poll interval + record TTL (default: 30 s + 30 s = 60 s) |
| Peer removed | ≤ poll interval + record TTL |
| IPC push mode (future) | < 1 s |

## Split-horizon DNS

`rustydns` serves the mesh zone only to mesh clients by network topology (it listens on the mesh interface or `127.0.0.1`). No special split-horizon configuration is needed for most deployments.

If you need a name like `rustyfin.mesh` to resolve differently from inside and outside the mesh, use a static zone override with `client_filter`:

```toml
[[authority.static_records]]
name          = "rustyfin.mesh."
type          = "A"
address       = "203.0.113.1"    # public IP for external clients
ttl           = 300
client_filter = "external"       # served only to non-mesh clients
```

## Deployment checklist

- [ ] `rustydnsd` binary installed with `chmod 750` and `CAP_NET_BIND_SERVICE` set
- [ ] Running as `rustydns` user (verify: `ps aux | grep rustydnsd`)
- [ ] Config file `rustydns.toml` has permissions `0640` (owner root, group rustydns)
- [ ] `rustydns` user is in the `rustynet` group (for bundle/key read access)
- [ ] Read access to `mesh_zone_bundle_path` and `mesh_zone_verifier_key_path` confirmed
- [ ] Verifier key file contains the **correct** ed25519 public key (64 hex chars). A mismatched key silently disables the mesh zone.
- [ ] Rustynet peers configured to use this node as their DNS resolver
- [ ] Rustynet policy allows `dns` capability for intended nodes
- [ ] Blocklist sources are all `https://` URLs (verify: `rustydnsd --validate-config`)
- [ ] `/metrics` endpoint bound to `127.0.0.1:9153` (not public-facing)
- [ ] `SIGHUP` wired into your service manager for config/blocklist reload
- [ ] systemd unit with hardening directives deployed (`systemctl status rustydns`)
- [ ] DoT listener: if enabled, `tls_cert_path` and `tls_key_path` are set and key file is `chmod 400 -o rustydns`
