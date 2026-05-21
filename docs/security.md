# rustydns — Security and Privacy Architecture

This document is the authoritative reference for every security and privacy
decision in `rustydns`. It explains **what** is protected, **how**, and
**why** — and what is explicitly out of scope.

Every feature documented here defaults to the most secure and most private
option. Operators must explicitly opt out; they cannot accidentally degrade
security by omission.

---

## Threat model

`rustydns` is a DNS resolver and ad-blocker running on a Rustynet mesh node
(typically a Raspberry Pi or home server). The threats it is designed to
defend against:

| Threat | Mechanism | Defence |
|--------|-----------|---------|
| Network observer watching DNS queries | Plaintext UDP port 53 leaks domain names | DoH/DoQ upstream only (plaintext is opt-in with loud warning) |
| Upstream resolver logging all queries | Single resolver sees complete query history | Randomised upstream selection distributes queries |
| Resolver inferring client location | EDNS0 Client Subnet (ECS) sends IP subnet | ECS stripped from all outgoing queries |
| Traffic analysis from query sizes | Encrypted but variable-length payloads are fingerprintable | RFC 8467 query padding to fixed block sizes |
| DNS cache poisoning | Forged upstream responses | DNSSEC validation on all upstream responses |
| Fake blocklist injection | HTTP blocklist sources tampered in transit | HTTPS-only blocklist sources (HTTP rejected at startup) |
| Unauthorised mesh peers querying DNS | No network-level restriction | Rustynet policy gates which nodes can reach `rustydns.mesh:53` |
| Query history on disk | Log files persist after daemon exit | Query logs in-memory ring buffer only (disk logging opt-in) |
| Client IP in log files | Full IPs identify users | Anonymised logging by default (last octet/64 bits zeroed) |
| Memory exhaustion from huge blocklist | Unbounded `HashMap` growth | Heap estimate logged and warned at > 100 MiB |
| Privilege escalation | Running as root | Unprivileged `rustydns` user + `CAP_NET_BIND_SERVICE` only |
| Unsafe memory operations | Buffer overflows, UAF | `#![forbid(unsafe_code)]` in all workspace crates |

### Out of scope

- **DNSSEC signing**: We validate signatures on upstream responses, but
  `rustydns` does not sign any zone it serves. We do not own a public zone.
- **DDoS amplification mitigation**: The daemon runs on a private mesh; it is
  not exposed to the public internet. If you expose it publicly, add rate
  limiting at the network layer.
- **Client authentication**: DNS has no client authentication mechanism at the
  protocol level. Access control is at the Rustynet policy layer (which nodes
  can reach the DNS port).

---

## Encrypted upstream DNS

### DNS-over-HTTPS (DoH, RFC 8484) — default

All upstream queries are sent over HTTPS (HTTP/2 + TLS). An observer on the
network sees only that the resolver is making HTTPS connections to a known DoH
provider — not which domains are being queried.

**TLS configuration:**
- Minimum version: **TLS 1.3** by default (configurable down to 1.2 — not recommended).
- TLS 1.3 provides mandatory forward secrecy (every connection uses ephemeral
  Diffie-Hellman) and has a smaller fingerprinting surface than TLS 1.2.
- Certificate validation is always on and not configurable to off.
- TLS implementation: `rustls` (pure Rust, no OpenSSL dependency, no C code
  in the TLS path).

**To use DoH:**
```toml
[upstream]
protocol = "doh"
resolvers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
]
```

### DNS-over-QUIC (DoQ, RFC 9250) — opt-in

QUIC provides lower latency than TCP (no TLS handshake round-trip after the
first connection, 0-RTT reconnect). The privacy properties are equivalent to
DoH. Use on low-latency paths where the extra QUIC connection setup overhead
is worthwhile.

```toml
[upstream]
protocol = "doq"
```

### Plaintext DNS — opt-in with persistent warnings

`protocol = "plain"` is available for development and debugging only. When
configured, the daemon emits a `WARN`-level log on every startup:

```
WARN upstream.protocol = "plain" — DNS queries will be sent UNENCRYPTED.
     This leaks all resolved domain names to network observers.
```

**Never use `plain` in production.**

---

## Query Name Minimisation (RFC 7816)

Without minimisation, a query for `www.example.com` sent to an upstream
resolver exposes the full QNAME. With minimisation enabled:

1. To resolve `.com`, the query is `?.com` (only the zone label).
2. To resolve `example.com`, the query is `?.example.com`.
3. Only the final resolver for `example.com` sees `www.example.com`.

No single resolver sees the complete query history. This is enabled by default:

```toml
[privacy]
query_minimization = true   # RFC 7816, default
```

---

## EDNS0 Client Subnet stripping (RFC 7871)

EDNS0 Client Subnet (ECS) is an extension that allows resolvers to include the
client's IP subnet in upstream queries to improve CDN geolocation. This leaks
the client's network identity to upstream resolvers and CDN providers.

`rustydns` strips the ECS option from all outgoing queries unconditionally
when `no_edns_client_subnet = true` (the default). The upstream resolver sees
only the resolver's own IP, not the client's subnet.

```toml
[privacy]
no_edns_client_subnet = true   # default
```

---

## DoH query padding (RFC 8467)

Even with TLS encryption, an observer can infer which domain was queried by
measuring the size of the encrypted payload. Short queries are likely common
short domains; long queries may be specific rare domains.

With padding enabled, all DoH query and response messages are padded to a
multiple of 128 bytes. The padding bytes carry no information; they exist only
to make all queries the same size class.

```toml
[privacy]
upstream_padding = true   # RFC 8467, default
```

---

## Randomised upstream selection

With a fixed resolver order (`resolvers[0]` always first), one resolver sees
the majority of query history. If that resolver is compromised or compelled to
log, the full query history is exposed.

With randomised selection (the default), each query is routed to a uniformly
random upstream from the configured list. Across many queries, each resolver
sees approximately 1/N of the history (where N is the number of configured
resolvers).

```toml
[privacy]
randomize_upstream_selection = true   # default

[upstream]
resolvers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    # Add more for better distribution
]
```

---

## DNSSEC validation

DNSSEC (RFC 4033–4035) allows DNS responses to be cryptographically signed.
When a resolver validates a DNSSEC-signed response, a forged or cache-poisoned
answer is detected and rejected (the response fails signature validation and
the resolver returns `SERVFAIL`).

DNSSEC validation is enabled by default and applies to all upstream responses:

```toml
[upstream]
dnssec_validation = true   # default
```

Disabling DNSSEC validation is possible but emits a startup warning. Do not
disable it in production — it is the primary defence against DNS cache
poisoning.

---

## Fail-closed upstream policy

When all configured upstream resolvers fail (network unreachable, timeout, TLS
error, DNSSEC validation failure), the daemon returns `SERVFAIL` to the client
rather than:

- Silently retrying with a different (potentially untrusted) resolver.
- Returning a stale cached answer without indicating it is stale.
- Falling back to plaintext DNS.

This is the default and is controlled by:

```toml
[upstream]
fail_closed = true   # default
```

The client receives `SERVFAIL` and must retry. This is a deliberate trade-off:
availability is sacrificed to prevent silent privacy or security degradation.

---

## Blocklist source integrity

Blocklist content fetched over plain HTTP could be tampered with in transit
(by a network attacker injecting arbitrary domains into the blocklist, either
to block legitimate traffic or to whitelist known ad domains).

`rustydns` enforces HTTPS for all remote blocklist sources. Any source URL
using `http://` is **rejected at startup** with an error:

```
ERROR configuration error: blocklist source `http://...` uses plain HTTP —
      only HTTPS sources are allowed.
```

Local files (`blocklist.local_files`) are not subject to this restriction
(they are read from the local filesystem, not fetched over the network).

---

## Anonymised query logging

By default, query logs record only an anonymised form of the client IP:

- **IPv4**: last octet zeroed (`192.168.1.100` → `192.168.1.0/anon`)
- **IPv6**: interface identifier zeroed (last 64 bits)

The Rustynet node ID (if known) is included in logs unchanged — node IDs are
public keys, not personally-identifying information.

```toml
[privacy]
log_client_ips = false   # default — anonymised IPs only
```

Setting `log_client_ips = true` records full IP addresses and emits a startup
warning.

### No persistent query logs

Query logs are written to an in-memory ring buffer (default: 1000 entries).
The oldest entries are evicted when the buffer is full. Nothing is written to
disk by default.

```toml
[privacy]
query_log_to_disk = false      # default
query_log_ring_size = 1000     # entries in the ring buffer
```

Enabling disk logging (`query_log_to_disk = true`) creates a persistent record
of every domain resolved by every client. If you enable this, ensure the log
file has appropriate permissions and a retention policy.

---

## Privilege model

### Linux capability model

`rustydnsd` uses `CAP_NET_BIND_SERVICE` to bind privileged ports (53, 853)
and immediately drops all other capabilities. It runs as the `rustydns` user
(UID/GID created by `scripts/install.sh`), which has:

- No home directory.
- No shell (`/usr/sbin/nologin`).
- Read access to `/var/lib/rustynet/control.db` (via group membership).
- Read/write access to its own state directory only.

### systemd hardening

The provided `install/rustydns.service` systemd unit applies additional
kernel-level restrictions:

```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
SystemCallFilter=@system-service
MemoryDenyWriteExecute=true
```

These restrictions prevent the daemon from:
- Gaining new privileges after startup.
- Writing to system directories.
- Opening network sockets outside of DNS protocols.
- Executing new processes.
- Using `mmap(PROT_EXEC)` (common exploit primitive).

---

## Memory safety

All workspace crates enforce `#![forbid(unsafe_code)]`. This means:

- No raw pointer dereferences within `rustydns` code.
- No `unsafe` blocks anywhere in the workspace.
- The Rust borrow checker enforces memory safety at compile time.

Dependencies (`hickory-dns`, `quinn`, `rustls`) contain `unsafe` code
internally. Both are widely-used, audited crates. The `quinn` QUIC
implementation and `rustls` TLS stack are the only `unsafe` surface in the
dependency tree.

---

## Configuration security checklist

Before deploying `rustydns` in production, verify:

- [ ] `upstream.protocol` is `"doh"` or `"doq"` (not `"plain"`)
- [ ] `upstream.fail_closed = true` (default)
- [ ] `upstream.dnssec_validation = true` (default)
- [ ] `upstream.min_tls_version = "1.3"` (default)
- [ ] All `blocklist.sources` use `https://` URLs
- [ ] `privacy.query_minimization = true` (default)
- [ ] `privacy.no_edns_client_subnet = true` (default)
- [ ] `privacy.upstream_padding = true` (default)
- [ ] `privacy.randomize_upstream_selection = true` (default)
- [ ] `privacy.query_log_to_disk = false` (default)
- [ ] `privacy.log_client_ips = false` (default)
- [ ] `metrics.listen` is bound to `127.0.0.1` (not `0.0.0.0`)
- [ ] Daemon runs as `rustydns` user (not `root`)
- [ ] `CAP_NET_BIND_SERVICE` granted; all other capabilities dropped
- [ ] systemd unit with hardening directives deployed
