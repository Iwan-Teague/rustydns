# RustyDNS Security Guide

Security, privacy, and anonymity are the highest-priority design goals of RustyDNS.
Every architectural choice has been made under those constraints. This document explains
the threat model, the countermeasures implemented or planned, and the configuration
checklist operators must follow before exposing the daemon to a network.

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Privacy: Hiding Your Queries from Upstream Resolvers](#privacy-hiding-your-queries-from-upstream-resolvers)
3. [Transport Security](#transport-security)
4. [Blocklist Supply-Chain Security](#blocklist-supply-chain-security)
5. [Logging and Data Minimisation](#logging-and-data-minimisation)
6. [Privilege Model](#privilege-model)
7. [Memory Safety and Unsafe Code Surface](#memory-safety-and-unsafe-code-surface)
8. [Additional Threats and Mitigations](#additional-threats-and-mitigations)
9. [Deployment Security Checklist](#deployment-security-checklist)

---

## Threat Model

RustyDNS sits between clients on a local network and upstream recursive resolvers.
The trust boundaries are:

| Zone                  | Trust level  | Notes                                            |
|-----------------------|--------------|--------------------------------------------------|
| Local clients         | Semi-trusted | They are on the operator's network               |
| Upstream resolvers    | Untrusted    | Treat as adversarial observers                   |
| Blocklist CDNs        | Untrusted    | Assume any CDN may be compromised                |
| `trusted_rpz_sources` | Operator-controlled | Only URLs the operator explicitly lists  |
| Rusty Suite mesh      | Partially trusted | Governed by capability grants in config    |

### Actors and Goals

**Passive observer on the wire** — an ISP, transit provider, or co-located attacker who
can read network traffic. Goal: learn what domains you resolve. Countermeasure:
DNS-over-HTTPS (DoH, RFC 8484) or DNS-over-QUIC (DoQ, RFC 9250) to upstream.

**Upstream resolver** — the DoH/DoQ server receives your queries. Goal: build a profile
by IP address and correlate queries over time. Countermeasures: query name minimisation
(RFC 7816), EDNS0 Client Subnet stripping (RFC 7871), query padding (RFC 8467),
and randomised upstream selection across the resolver pool.

**Compromised upstream resolver** — returns forged DNS answers. Countermeasure:
DNSSEC validation; responses that fail validation are dropped and SERVFAIL is returned.

**Compromised blocklist CDN** — a supply-chain attack in which the CDN is taken over and
the attacker injects entries to allowlist their own infrastructure (RPZ passthru injection).
Countermeasure: `BlocklistSource::Trusted/Untrusted` separation; passthru/allowlist entries
from untrusted sources are silently discarded with a warning metric.

**Attacker on the LAN** — a rogue device on the local network sending crafted DNS
requests. Countermeasure: authority-zone lookup before blocklist lookup (invariant order),
validated query parsing, and bounded memory allocation.

**Log file exfiltration** — an attacker who obtains log files learns which clients
resolved which domains. Countermeasure: query logs are in-memory only by default;
client IPs are anonymised at /16 (IPv4) or /64 (IPv6); the type system prevents
accidental full-IP logging.

---

## Privacy: Hiding Your Queries from Upstream Resolvers

### Query Name Minimisation (RFC 7816) — pending

When resolving `www.example.com`, a naive resolver sends the full QNAME to every
nameserver in the chain. RFC 7816 reduces each hop to the minimum labels needed
at the relevant delegation step — the root sees only `.com`, the TLD sees only
`example.com`, and only the authoritative server sees the full name. RustyDNS
forwards to a DoH/DoQ recursive (it is not a from-scratch recursor itself), so
the upstream is the only party that ever sees the full QNAME, and only it (not
the root or TLD operators) is positioned to build a profile.

`privacy.query_minimization = true` is the default and is honoured at the
moment hickory's stub resolver exposes the knob. As of hickory 0.26 it does
not, and the daemon emits a `tracing::warn!` at startup when the setting is
enabled so operators do not silently believe qmin is active.

### EDNS0 Client Subnet Stripping (RFC 7871)

Upstream resolvers may request the client's IP subnet via the ECS EDNS0 option to
return geographically relevant answers. RustyDNS strips ECS options from all outgoing
queries and never adds them. The upstream resolver sees only the RustyDNS server's IP,
not the originating client's subnet.

### Query Padding (RFC 8467) — pending

Even over an encrypted transport, an observer who can see packet sizes may infer the
queried domain from the packet length. RFC 8467 padding to fixed-size blocks (128 bytes
recommended) defeats this — but hickory 0.26's stub resolver does not yet expose the
knob. `privacy.upstream_padding = true` is honoured the moment hickory ships support;
until then, the daemon emits a `tracing::warn!` at startup so operators do not silently
believe padding is active. Encrypted query sizes still leak the queried domain.

### Randomised Upstream Selection

When multiple upstream resolvers are configured, RustyDNS selects among them randomly
per query. No single resolver builds a complete query history. Operators should configure
resolvers from different jurisdictions and operators.

### DNSSEC Validation

Responses from upstream are DNSSEC-validated. A resolver that returns a forged answer
— whether due to compromise, BGP hijacking, or protocol downgrade — will be rejected and
the client receives SERVFAIL. There is no fallback to unvalidated answers, and there is
no stale-answer mode that could serve a cached response after validation failure.

---

## Transport Security

### Encrypted Transport to Upstream

All upstream communication uses DNS-over-HTTPS (RFC 8484) or DNS-over-QUIC (RFC 9250).
Plain DNS over UDP/TCP to upstream resolvers is not supported. If no encrypted resolver
is configured, the daemon refuses to start.

The `protocol` field in `[[resolvers]]` accepts `"doh"` or `"doq"` only. Setting
`"plain"` logs a startup warning and will become a hard error in a future release.

### TLS Implementation

All TLS is implemented by `rustls` — a pure-Rust TLS library with no dependency on
OpenSSL or any system TLS library. `rustls` supports TLS 1.3 and 1.2 only; older
protocol versions are not implemented. TLS 1.3 is the default minimum; configuring TLS
1.2 as the minimum emits a startup warning.

TLS certificate validation is always enabled and is not configurable. There is no
`verify_tls_certs = false` option and no plan to add one. Operators who need to trust
a private CA should add it to the system trust store.

### DNS-over-TLS Listener

For clients on the local network, RustyDNS supports a DoT listener (port 853),
wired end-to-end against hickory-server 0.26's
`register_tls_listener_with_tls_config`. This requires `tls_cert_path` and
`tls_key_path` to be set in `[server]`. If `dot_listen` is configured without
both paths, `validate_config` refuses to start the daemon.

Certificate and key files must be readable only by the `rustydns` user:

```
chmod 640 /etc/rustydns/tls.crt
chmod 600 /etc/rustydns/tls.key
chown rustydns:rustydns /etc/rustydns/tls.crt /etc/rustydns/tls.key
```

### DoH Listener Security

If you expose a DoH listener to the local network, do not expose it to the public
internet without a reverse proxy (nginx, Caddy) that enforces rate limiting, access
control, and TLS termination with a trusted certificate. A public DoH endpoint can be
used as a DNS amplification vector. The metrics endpoint must remain on `127.0.0.1`
and must not be proxied externally.

---

## Blocklist Supply-Chain Security

### HTTPS Enforcement

All blocklist sources must use `https://` URLs. HTTP sources are rejected at startup.
HTTPS provides transport integrity and authenticity for the blocklist download, protecting
against on-path injection by an ISP or network attacker.

### What HTTPS Does Not Protect Against

HTTPS protects the transport. It does not protect against:

- **Compromised CDN or origin server** — the CDN operator, or an attacker who has
  compromised them, can serve malicious blocklist content over a valid HTTPS connection.
- **Domain takeover** — if the blocklist maintainer's domain expires or is hijacked,
  the attacker controls the content served to your resolver.
- **RPZ passthru injection** — an attacker who controls a blocklist source can inject
  allowlist entries (passthru rules in RPZ format) to permanently exempt their own
  domains from blocking.

### RPZ Passthru Isolation

To mitigate passthru injection, RustyDNS distinguishes between trusted and untrusted
blocklist sources:

- **Untrusted** (the default): remote URLs that are not in `trusted_rpz_sources`. Any
  allowlist / passthru entry from an untrusted source is **discarded** with a warning.
  The source can only add domains to the blocklist, never remove them.
- **Trusted**: local files on disk and any URL listed in `trusted_rpz_sources`. Allowlist
  entries from trusted sources are honoured. Only add URLs to `trusted_rpz_sources` if
  you control the origin server end-to-end.

### Fetch Limits

Blocklist fetches are bounded to prevent memory exhaustion from a slow or malicious
source:

- `fetch_timeout_ms` (default 30,000 ms): the entire fetch must complete within this
  window, or the source is skipped for this reload cycle.
- `max_fetch_bytes` (default 52,428,800 bytes = 50 MiB): if a response body exceeds
  this limit, the download is aborted and the source is skipped.

### Domain Validation

Every domain parsed from a blocklist is validated before insertion:

- Label length ≤ 63 bytes (RFC 1035 §2.3.4)
- Total domain length ≤ 253 bytes
- No control characters (0x00–0x1f, 0x7f)
- ASCII only — non-ASCII bytes (≥ 0x80) are rejected (IDNs must be supplied
  in punycode `xn--` form, which is how real queries arrive)
- No empty labels (consecutive dots)

Entries that fail validation are skipped with a warning. They are never inserted into
the blocklist, preventing a malformed entry from causing unexpected behaviour at query
time.

### Overbroad Allowlist Entries

Single-label wildcard allowlist entries such as `*.com` or `*.net` that would exempt an
entire TLD are rejected at startup by `validate_config()`. This prevents a misconfigured
or malicious trusted source from allowlisting broad swaths of the namespace.

---

## Logging and Data Minimisation

### No Client IP in Logs by Default

The `ClientId` type has no `Display` implementation. Every logging call-site must
explicitly choose between `client.anonymized()` or `client.full()`. The latter must only
appear inside a `if config.privacy.log_client_ips { ... }` guard. This is enforced by
the type system, not by convention. A future lint or audit can mechanically verify
compliance by grepping for `.full()` call-sites.

### IPv4 /16 Anonymisation

When anonymised logging is active, the last **two** octets of IPv4 addresses are zeroed,
producing a /16 prefix (`192.168.0.0/16/anon`). Zeroing only the last octet (/24) is
insufficient for home networks where the entire address space may contain only tens of
devices, making re-identification trivial from auxiliary data.

IPv6 addresses have the last 64 bits zeroed, producing a /64 prefix.

### Node ID Suppression

Node IDs (Rusty Suite mesh identifiers) are stable long-lived device fingerprints. Even
if source IP logging is disabled, logging a node ID uniquely identifies a device. Node
IDs are therefore governed by the same `log_client_ips` flag. The `anonymized()` view
of a `ClientId` omits the node ID entirely.

### In-Memory Query Logs by Default

Query logs are held in a bounded ring buffer in memory (default size 10,000 entries,
configurable up to 100,000). They are not written to disk by default. Disk logging must
be explicitly enabled (`privacy.query_log_to_disk = true` plus a `query_log_disk_path`);
doing so emits a startup warning.

When enabled, the on-disk log preserves the privacy invariants by construction:

- **QNAME is always salted-hashed**, never written in plaintext. The raw query name
  cannot reach the disk writer — there is no code path that carries it there.
- **Client IP is always anonymised** (IPv4 `/16`, IPv6 `/64`). The `log_client_ips`
  flag governs `tracing` output only; it does **not** lift anonymisation for the
  on-disk log.
- The file is created mode **0600**. If an existing target is group- or world-readable,
  the daemon **refuses to write to it** and continues serving DNS with the in-memory
  ring only — refusing is the privacy-safe failure mode.
- Format is **NDJSON** with built-in **size-based rotation** (`query_log_max_file_bytes`
  × `query_log_max_files` bounds the total footprint), so no external `logrotate` is
  needed and the disk can't fill unbounded on a low-power device.
- Writes happen on a dedicated task fed by a bounded channel; if the disk can't keep up
  the disk stream drops entries (counted in `rustydns_query_log_disk_dropped_total`)
  rather than stalling the resolver.

#### Residual risk: the QNAME-hash salt lives in process memory

The on-disk (and in-memory) QNAME hash is keyed with a per-process salt
(`rand::random()` at startup) that lives **only in process memory** — never
written to disk, never exposed by any endpoint. An attacker who only obtains
the log file therefore sees opaque hashes and **cannot** dictionary-attack it
("was `example.com` queried?") without first guessing the 64-bit salt. This is
the intended, sound design.

The residual risk is narrow but worth stating so operators do not over-trust the
on-disk hashes: anyone who can **dump the process's memory** (core dump,
`/proc/<pid>/mem`, or swapped-out pages) recovers the salt and can then
offline-confirm whether any *guessed* domain appears in a captured log. This
requires host-level compromise that already implies worse access; it is not a
break of the hash. Mitigations (mostly already implied by the systemd sandbox):
disable or encrypt swap so the salt never pages to disk, restrict core dumps
(`LimitCORE=0`), and keep the log directory `0700` with non-world-readable
backups. Note the salt being process-lifetime *helps* here — a restart mints a
fresh salt, so a log written before the restart can no longer be
cross-referenced against a guess even with the live salt. See
[`operator-endpoints.md`](operator-endpoints.md) for the operator-facing
write-up.

### Metrics Endpoint Binding

The Prometheus metrics endpoint must be bound to `127.0.0.1` (loopback) only. Binding
to `0.0.0.0` exposes query rate, blocklist hit rate, and upstream latency to anyone on
the local network. A startup warning is emitted if the metrics listen address is not
loopback.

---

## Privilege Model

### Linux Capabilities

RustyDNS requires `CAP_NET_BIND_SERVICE` to bind to port 53 (and 853 for DoT). All
other capabilities are unnecessary.

The systemd unit (see `install/rustydns.service`) uses `AmbientCapabilities=CAP_NET_BIND_SERVICE`
and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` to ensure no other capability is ever
available to the process, and runs the daemon as an unprivileged `rustydns` user.

For deployments without systemd, the binary drops capabilities in-process after
binding its sockets via the `caps` crate (Linux-only; no-op on other targets).
The runtime call clears **every** capability set — Effective, Permitted,
Inheritable, Ambient, and Bounding — so the process holds **no** capabilities
afterward, including `CAP_NET_BIND_SERVICE`. A later bug or compromise therefore
cannot re-bind a privileged port or escalate.

This is also why live SIGHUP listener handover (roadmap 3.2 Phase 2) is offered
only for listeners on **unprivileged** ports (≥ 1024): rebinding a port < 1024
needs `CAP_NET_BIND_SERVICE`, which is gone, and `SO_REUSEPORT` does not bypass
the privilege check. A change to a privileged listener (`:53`, `:853`) is
detected on reload and logged as restart-required rather than applied — the
capability posture is never weakened to enable reload.

The Docker image ships the same posture two ways: a `setcap
cap_net_bind_service=+ep` file capability baked onto the binary, plus
`cap_drop: [ALL]` + `cap_add: [NET_BIND_SERVICE]` in
[`docker-compose.yml`](../docker-compose.yml) so the orchestrator state matches
the file caps. See [`docs/deployment-docker.md`](deployment-docker.md) for the
full image security posture.

### Systemd Hardening

The provided systemd unit applies kernel-level sandboxing:

```ini
[Service]
User=rustydns
Group=rustydns
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/rustydns /var/log/rustydns
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
UMask=0077
TasksMax=64
```

`MemoryDenyWriteExecute` prevents the process from mapping memory as both writable and
executable — a hard barrier against code injection. `ProtectSystem=strict` makes the
entire filesystem read-only except for explicitly listed `ReadWritePaths`. The full unit
file in `install/rustydns.service` is authoritative; the snippet above is illustrative.

### Configuration File Permissions

The daemon checks at startup that the configuration file is not world-readable. If
`/etc/rustydns/rustydns.toml` is readable by users other than `rustydns`, a hard error
is emitted and the daemon exits. This prevents other local users from reading upstream
resolver credentials or other sensitive configuration.

Recommended permissions:

```sh
chown rustydns:rustydns /etc/rustydns/rustydns.toml
chmod 640 /etc/rustydns/rustydns.toml
chmod 750 /etc/rustydns
```

---

## Memory Safety and Unsafe Code Surface

### `#![forbid(unsafe_code)]` in All First-Party Crates

Every crate in the RustyDNS workspace declares `#![forbid(unsafe_code)]`. The compiler
will reject any `unsafe` block, including in generated code from macros. This is verified
on every `cargo build`.

### Unsafe in the Dependency Tree

The `forbid` attribute applies to first-party code only. Third-party dependencies
contain unsafe code. The known unsafe surface is:

| Crate / component    | Unsafe reason                                                    | Risk level |
|----------------------|------------------------------------------------------------------|------------|
| `tokio`              | Async runtime, I/O, threading primitives                         | Medium — well-audited |
| `rustls`             | Pure-Rust TLS; some low-level buffer operations                  | Low — formally verified components |
| `quinn`              | QUIC implementation; unsafe for performance-critical paths       | Medium — active security research |
| `reqwest`            | HTTP client built on tokio/hyper                                 | Low — no C FFI |
| `ed25519-dalek`      | ed25519 signature verification for the Rustynet mesh-zone bundle | Low — pure Rust, widely-audited |
| `sha2`               | SHA-256 used by the Rustynet dns-zone watermark format           | Low — pure Rust |
| `ring` / `aws-lc-rs` | Cryptographic primitive implementations (mixed Rust + assembly)  | Low — FIPS-audited paths |

We do not use `openssl-sys`, `libc` directly, or any crate that shells out to an
external process. `cargo deny` is configured to reject crates with known CVEs.

### Panic Policy

The release profile sets `panic = "abort"`. An unexpected panic terminates the process
cleanly rather than unwinding the stack, which eliminates a class of exploit primitives
that rely on stack unwinding side effects. The systemd unit is configured to restart the
service on exit, so an abort is not a permanent denial of service.

---

## Additional Threats and Mitigations

### DNS Rebinding

An attacker-controlled domain returns a short-TTL record pointing to `127.0.0.1` or
a private IP. After the TTL expires the browser re-resolves and the attacker's JS can
now make requests to the local interface.

**Mitigation:** `upstream.block_private_rdata = true` strips A/AAAA records whose
rdata is RFC 1918, loopback, link-local, unspecified, broadcast, documentation,
multicast, unique-local, or unicast link-local (IPv6) — as well as IPv4-mapped
IPv6 forms of those. Filtering applies only to the **default** upstream:
authoritative answers (mesh zone + static records) and conditional-forwarding
route responses (`[[upstream.routes]]`) are passed through untouched, since
operators wire those precisely to resolve internal names. Each dropped record is
counted in `rustydns_resolver_private_rdata_dropped_total`.

The option defaults to **off** because operators with internal DNS deployments
routinely resolve names to RFC 1918 addresses on purpose. Hosts that only
resolve public Internet names should turn it on; deployments with internal
zones should either declare those as static records, route them via
`[[upstream.routes]]`, or leave the defence off.

### DNS Amplification Between Mesh Nodes

Mesh nodes that are granted the `dns` capability can query RustyDNS. A compromised mesh
node could use RustyDNS as a DNS amplification vector to flood third parties. Mitigations:

- The daemon binds only to local interfaces by default (`listen = "127.0.0.1:53"`).
- **Per-source-IP token-bucket rate limiting.** Default-on with a generous 100 qps
  sustained / 200 burst per non-loopback client. Excess queries respond with
  `REFUSED` and increment `rustydns_policy_rate_limited_total`. Loopback is exempt
  so local proxies aren't penalised. Configurable via the `[rate_limit]` block.
  The bucket table is bounded by `max_tracked_clients` (default 10,000) with LRU
  eviction + periodic GC of idle buckets so a forge-source-IP flood cannot OOM the
  daemon. IPv6 clients are keyed on their `/64` prefix, not the full `/128`, so an
  attacker holding a single `/64` cannot rotate the interface identifier to mint
  unlimited fresh buckets and bypass the limit; IPv4 is keyed on the full `/32`.
- The systemd unit sets `TasksMax=64` to limit concurrency.
- `MemoryDenyWriteExecute` and `SystemCallFilter` limit what a compromised process
  can do even if it achieves code execution inside the daemon.

### Blocklist Source Compromise (Supply Chain)

A maintainer's infrastructure is compromised and begins serving a blocklist that
contains the attacker's C2 domains in the allowlist. Mitigations:

- Untrusted sources cannot inject allowlist entries (see RPZ passthru isolation above).
- `fetch_timeout_ms` and `max_fetch_bytes` limit the damage a malicious source can do
  via a slow/large response.
- Operators should configure multiple independent blocklist sources. The blocklist
  engine takes the union of all block entries; a single compromised source cannot
  remove entries added by other sources.

### DoH Listener Exploitation

If a DoH listener is exposed to untrusted clients, a crafted HTTP request could exploit
a parsing vulnerability in `hickory-server` or `hyper`. Mitigations:

- HTTP parsing is handled by `hyper` and `tower`, both well-fuzzed.
- The daemon runs as an unprivileged user with a strict systemd sandbox.
- `panic = "abort"` ensures a parsing panic kills the process cleanly.
- Request bodies are capped at 65 535 bytes (the maximum DNS message size) by an
  axum `DefaultBodyLimit` layer, so an oversized POST is rejected with `413` before
  the payload is buffered into memory — axum's 2 MiB default would otherwise let a
  client force a 2 MiB allocation per request, which matters on Pi-class hardware.
- The DoH listener uses the TCP peer address as the client identity and does **not**
  trust `X-Forwarded-For`/`Forwarded` headers, so a client cannot spoof its source IP
  to evade per-client policy. (As a consequence, behind a TLS-terminating proxy all
  DoH clients share the proxy's loopback identity — apply rate limiting at the proxy.)
- Operators should place a reverse proxy with request size limits and rate limiting
  in front of any externally reachable DoH endpoint.

### Slow Loris on Blocklist Fetch

A malicious blocklist server opens a response but sends data at 1 byte/second, holding
a connection open indefinitely and consuming a worker thread. Mitigation:
`fetch_timeout_ms` (default 30 s) applies to the entire download, not just the
connection establishment. A source that is slower than `max_fetch_bytes / timeout`
bytes per second will be aborted.

### Mesh Bundle Tampering

The authority crate consumes mesh-zone records from a signed bundle file
written by `rustynetd` (see `docs/integration-rustynet.md`). The bundle
is ed25519-signed; if an attacker tampers with the bundle on disk the
signature check fails and the daemon keeps serving the previous trusted
snapshot. Mitigations:

- ed25519 signature verification with a public verifier key configured
  at startup. Bundles that fail verification are rejected and logged.
- Freshness check: a bundle whose `expires_at_unix` is in the past, or
  whose `generated_at_unix` is older than `mesh_zone_max_age_secs`
  (default 600s), is rejected at load time. This limits the replay
  window for an attacker who captures an old signed bundle.
- Anti-rollback / replay protection: freshness alone does not stop an
  attacker who can write the bundle path from replaying an *older but
  still-fresh* signed bundle (e.g. one generated 4 minutes ago, with
  `mesh_zone_max_age_secs = 600`) to roll a name back to a previous IP or
  drop a record — the signature still verifies because it is a legitimately
  old bundle. The authority therefore tracks the last-applied
  `(generated_at_unix, nonce)` in memory and **refuses any candidate that
  orders strictly before it** (older `generated_at_unix`, or equal
  `generated_at_unix` with a lower `nonce`). An identical bundle re-applies
  idempotently (the periodic poller re-reads the same file every interval).
  The watermark is in-memory only — the "no database" invariant stands — so
  a process restart resets it to the freshly-loaded bundle's value; right
  after boot the `mesh_zone_max_age_secs` freshness window is the backstop.
  A rejected rollback keeps the previous trusted snapshot and is logged at
  `warn!` plus the `rustydns_mesh_zone_reload_failure_total` metric.
- Bundle file size cap of 256 KiB, enforced with a *capped reader* (reads
  at most the limit + 1 byte) rather than a `stat`-then-read — so a file
  swapped for a larger one between the size check and the read still cannot
  make us allocate beyond the cap (no TOCTOU).
- `record_count` is bounded (≤ 100,000) *before* any allocation, so a
  signed-but-malicious or buggy bundle cannot drive a multi-gigabyte
  `Vec::with_capacity` from a tiny file. The signature is verified before
  the payload is parsed, so untrusted bytes never reach the record loop.
- The verifier key must be deployed via the operator's normal config
  channel and never written by `rustydns`. The signing key never leaves
  `rustynetd`.

### Log File Access Control

If disk logging is enabled, query logs may contain domain names that reveal sensitive
browsing behaviour. Mitigations:

- Disk logging is opt-in and emits a startup warning.
- The systemd unit sets `UMask=0077`. For non-systemd deployments
  (Docker, runit, OpenRC, bare CLI) the daemon calls `umask(0o077)` in-process
  at startup, so every file the daemon creates is owner-only regardless of
  service-manager state.
- Operators should configure log rotation (e.g. `logrotate`) with `create 600 rustydns rustydns`.
- Log files should not be placed in world-readable directories.

---

## Deployment Security Checklist

Complete this checklist before putting RustyDNS on a network.

### Binary and Installation

- [ ] Binary installed at `/usr/local/bin/rustydns` with mode `750` (not 755)
- [ ] Binary owned by `root:rustydns`
- [ ] Binary checksum verified against a release signature (when releases are tagged)

### Configuration

- [ ] Config directory: `chmod 750 /etc/rustydns`
- [ ] Config file: `chmod 640 /etc/rustydns/rustydns.toml`, owner `rustydns:rustydns`
- [ ] `listen` is not `0.0.0.0:53` unless you intend to serve the entire network
- [ ] All `[[resolvers]]` entries use `protocol = "doh"` or `protocol = "doq"`
- [ ] All `[[resolvers]]` URLs use `https://`
- [ ] No `http://` blocklist URLs in `[[blocklist.sources]]`
- [ ] `trusted_rpz_sources` contains only URLs you control end-to-end
- [ ] No single-label wildcard allowlist entries (e.g., `*.com`)
- [ ] `privacy.log_client_ips = false` unless there is a specific operational need
- [ ] `privacy.log_queries_to_disk = false` unless there is a specific operational need
- [ ] If disk logging is enabled, `logrotate` is configured with `create 600 rustydns rustydns`
- [ ] `metrics_listen` is `127.0.0.1:9153` (loopback only)
- [ ] `max_cache_entries` ≤ 500,000
- [ ] `reload_interval_secs` ≥ 300 (or 0 to disable auto-reload)

### TLS (if using DoT listener)

- [ ] `tls_cert_path` and `tls_key_path` are both set when `dot_listen` is configured
- [ ] `chmod 640 /etc/rustydns/tls.crt`, owner `rustydns:rustydns`
- [ ] `chmod 600 /etc/rustydns/tls.key`, owner `rustydns:rustydns`
- [ ] Certificate is from a trusted CA (not self-signed) or clients are configured to
      trust the CA explicitly

### Systemd Unit

- [ ] Systemd unit installed: `systemctl enable --now rustydns`
- [ ] Unit runs as `User=rustydns` (not root)
- [ ] `MemoryDenyWriteExecute=yes` is present in the unit
- [ ] `ProtectSystem=strict` is present in the unit
- [ ] `UMask=0077` is present in the unit
- [ ] `TasksMax=64` is present in the unit
- [ ] `AmbientCapabilities=CAP_NET_BIND_SERVICE` is the only capability granted

### Network

- [ ] Port 53 is not exposed to the public internet (firewall rule or `listen` binding)
- [ ] If a DoH listener is public-facing, a reverse proxy enforces rate limiting and TLS
- [ ] Metrics endpoint (port 9153) is not reachable from outside the host

### Ongoing

- [ ] `cargo deny check advisories` runs in CI and blocks on new CVEs
- [ ] Blocklist sources are reviewed periodically; removed if they become unmaintained
- [ ] `trusted_rpz_sources` is reviewed whenever a blocklist source changes CDN
- [ ] Log retention policy is documented and enforced
