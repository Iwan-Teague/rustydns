# Operator Endpoints

`rustydnsd` exposes a small HTTP management surface alongside the DNS
listeners. All three endpoints share the metrics listener — by default
`127.0.0.1:9153` — and are accessible only via that loopback bind.

| Path        | Method | Content-Type             | Purpose                              |
|-------------|--------|--------------------------|--------------------------------------|
| `/metrics`  | GET    | `text/plain; version=…`  | Prometheus exposition                |
| `/health`   | GET    | `application/json`       | Liveness for orchestrators           |
| `/queries`  | GET    | `application/json`       | In-memory query ring buffer snapshot |

Port and path are configurable:

```toml
[metrics]
listen = "127.0.0.1:9153"   # loopback only — daemon coerces if not
path   = "/metrics"
```

`/health` and `/queries` are fixed at those paths. `metrics.path`
only renames the Prometheus route.

## Binding rules

The daemon **refuses** to expose these endpoints on a non-loopback
interface. If `metrics.listen` parses as a non-loopback address,
`metrics_listen_addr()` in `main.rs` coerces it to `127.0.0.1` (or
`::1` for IPv6 configs) and logs a `tracing::warn!`. There is no
escape hatch — the endpoints expose query counts, blocklist sizes,
and (in `/queries`) per-query metadata that a public endpoint would
leak. Put a reverse proxy in front if you genuinely need remote
access; that proxy is responsible for authentication.

## `/health`

```text
GET /health
200 OK
Content-Type: application/json

{"status":"ok"}
```

Returns `200` when the daemon process is up and the listener is
serving — that is the entire claim. It does NOT verify upstream
resolver reachability, blocklist freshness, or mesh-bundle staleness;
those live on `/metrics`.

Use as a k8s `livenessProbe`, a systemd `ExecStartPost` healthcheck,
or runit's `./check` script. Pair with a separate Prometheus alert
on `/metrics` for richer health logic (e.g. `mesh_zone_last_reload_seconds`
falling stale).

## `/metrics`

Standard Prometheus exposition over the `prometheus` crate's
`TextEncoder`. The exposed series, grouped by subsystem:

### Query pipeline

| Series                                  | Type    | Meaning                                          |
|-----------------------------------------|---------|--------------------------------------------------|
| `rustydns_dns_queries_total`            | counter | Every accepted query                             |
| `rustydns_authority_hits_total`         | counter | Authority lookups returning records              |
| `rustydns_rewrite_hits_total`           | counter | Queries answered by a `[[rewrite]]` rule          |
| `rustydns_policy_schedule_blocked_total` | counter | Queries refused because the client was inside an active `[[policy.block_windows]]` window |
| `rustydns_blocklist_hits_total`         | counter | Queries blocked by the blocklist                 |
| `rustydns_blocklist_cname_cloaking_blocked_total` | counter | Queries blocked because an answer CNAME targeted a blocked domain |
| `rustydns_blocklist_response_ip_blocked_total` | counter | Queries blocked because a resolved A/AAAA was on the response-IP denylist |
| `rustydns_resolver_queries_total`       | counter | Queries forwarded to an upstream                 |
| `rustydns_resolver_failures_total`      | counter | Resolver failures returned as SERVFAIL           |

### Blocklist state

| Series                                       | Type    | Meaning                                         |
|----------------------------------------------|---------|-------------------------------------------------|
| `rustydns_blocklist_entries`                 | gauge   | Live blocking-entry count (exact + wildcard)    |
| `rustydns_blocklist_heap_bytes`              | gauge   | Approximate heap of the blocklist state         |
| `rustydns_blocklist_reload_success_total`    | counter | Reloads that loaded ≥1 source successfully      |
| `rustydns_blocklist_reload_failure_total`    | counter | Reloads where every source failed               |
| `rustydns_blocklist_last_reload_seconds`     | gauge   | Unix ts of the most recent reload attempt       |

### Mesh zone

| Series                                       | Type    | Meaning                                         |
|----------------------------------------------|---------|-------------------------------------------------|
| `rustydns_mesh_records`                      | gauge   | Live mesh-zone record count                     |
| `rustydns_mesh_zone_reload_success_total`    | counter | Successful bundle reloads (not initial load)    |
| `rustydns_mesh_zone_reload_failure_total`    | counter | Reloads that failed verification or parsing     |
| `rustydns_mesh_zone_last_reload_seconds`     | gauge   | Unix ts of the most recent reload attempt       |

A failed mesh reload does NOT zero `mesh_records` — the daemon is
still serving from the previous valid `ArcSwap` snapshot.

### Policy effects

| Series                                            | Type    | Meaning                                                                  |
|---------------------------------------------------|---------|--------------------------------------------------------------------------|
| `rustydns_policy_blocklist_bypass_total`          | counter | Queries where `blocklist_bypass=true` actually changed the outcome       |
| `rustydns_policy_zone_denied_total`               | counter | Queries refused because they fell outside `zones_allowed`                |
| `rustydns_policy_rate_limited_total`              | counter | Queries refused because the source IP exceeded the per-client rate limit |
| `rustydns_resolver_private_rdata_dropped_total`   | counter | A/AAAA records stripped by the DNS-rebinding defence (per record, not per query) |

`blocklist_bypass_total` only increments when the bypass *changed
something* — a bypass that fired against a non-blocked name doesn't
count. This makes the metric a faithful "blocklist relaxations
served per second" signal.

### On-disk query log

Present only when `privacy.query_log_to_disk = true`. All four are 0 (or
absent in scrapes filtered by value) when disk logging is disabled.

| Series                                          | Type    | Meaning                                                                  |
|-------------------------------------------------|---------|--------------------------------------------------------------------------|
| `rustydns_query_log_disk_written_total`         | counter | Entries successfully written to the NDJSON log                           |
| `rustydns_query_log_disk_dropped_total`         | counter | Entries dropped from the disk stream because the writer channel was full |
| `rustydns_query_log_disk_io_errors_total`       | counter | Write/flush errors hit by the disk writer                                |
| `rustydns_query_log_disk_rotations_total`       | counter | Size-based file rotations performed                                      |

A rising `dropped_total` means the disk can't keep up with the query
rate (common on slow SD cards) — the in-memory ring and DNS serving are
unaffected; only the on-disk record is lossy. A rising `io_errors_total`
means the volume is full or unwritable.

## `/queries`

Snapshot of the in-memory query log ring buffer, newest entry first.

```bash
$ curl -s http://127.0.0.1:9153/queries | jq
{
  "capacity": 1000,
  "count": 2,
  "entries": [
    {
      "ts": 1779441467,
      "client": "127.0.0.0/16/anon",
      "qname_hash": "9d074ccc89eb0e93",
      "qtype": "A",
      "rcode": 0,
      "served_by": "resolver"
    },
    {
      "ts": 1779441466,
      "client": "127.0.0.0/16/anon",
      "qname_hash": "b252f403cc660d23",
      "qtype": "A",
      "rcode": 0,
      "served_by": "authority"
    }
  ]
}
```

Buffer size is `privacy.query_log_ring_size` (default 1000, max
100,000). Set it to `0` to disable the buffer entirely.

### Field semantics

- `ts` — unix seconds when the query was received.
- `client` — `ClientId::anonymized()` form. IPv4 → `/16/anon`,
  IPv6 → `/64/anon`. The raw client IP is never serialised. Setting
  `privacy.log_client_ips = true` does NOT change this field; the
  flag governs `tracing` output, not the inspection endpoint.
- `qname_hash` — 16-char lowercase hex of a salted u64 hash. The
  salt is a per-process random value (`rand::random()` at startup),
  so hashes do NOT cross deployment or restart boundaries. Reversing
  the hash to a domain is computationally infeasible.
- `qtype` — interned RFC 1035 type label (`A`, `AAAA`, `MX`, …).
  Uncommon types collapse to `OTHER`.
- `rcode` — wire-level DNS response code (`0`=NoError, `2`=ServFail,
  `3`=NXDomain, `5`=Refused).
- `served_by` — which pipeline arm produced the answer:
  `authority`, `rewrite`, `blocklist`, `resolver`, `servfail`, or `rejected`.

### Looking up a specific domain

The hash uses `ahash` keyed with the per-process salt. To check
whether `ads.example.com` hit the resolver in the last N queries,
you need to either:

1. Run a small Rust helper on the same host that imports
   `rustydnsd::query_log::QueryLog::hash_qname` and uses the daemon's
   process-id-stable salt (only works while the daemon is running
   and you can read its memory — usually not what an operator can
   do casually).
2. Cross-reference `rcode` + `served_by` patterns instead. For most
   operational questions ("is the blocklist firing?" / "is anyone
   getting NXDOMAINs for mesh names?") the counts on `/metrics` are
   the right answer.

The hash-based lookup model is intentionally inconvenient — the
buffer is for forensic narrowing, not arbitrary domain surveillance.
A future operator-facing helper binary may be added; it will require
local access to the process and operate on a salt snapshot rather
than the live salt.

### Residual risk: the salt lives in process memory

The hash's confidentiality rests entirely on the salt staying secret.
The salt is `rand::random()` at startup and lives **only in process
memory** — it is never written to disk or exposed by any endpoint. So an
attacker who only sees `/queries` output (or a captured on-disk log) sees
opaque hashes and **cannot** run a dictionary attack ("was `example.com`
queried?") — they would have to guess the 64-bit salt first.

The residual risk is narrow but worth stating: anyone who can **dump the
process's memory** — a core dump, `/proc/<pid>/mem`, or swapped-out pages —
recovers the salt, and can then offline-confirm whether any *guessed*
domain appears in a captured log (hash the guess under the recovered salt
and grep). This is not a break of the hash; it requires host-level
compromise that already implies far worse access. Mitigations, mostly
already in place:

- The systemd unit's sandbox (`PrivateTmp`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`) and running as an unprivileged user raise the
  bar for reading the daemon's memory.
- Disable swap, or encrypt it, so the salt and buffer never reach disk via
  paging.
- Restrict core dumps for the service (`LimitCORE=0` / a `coredump` filter)
  so a crash can't spill the salt.

Note the salt being process-lifetime actually **helps** the on-disk log: a
restart mints a fresh salt, so an old on-disk log written under the
previous salt can no longer be cross-referenced against a guess even with
the live process's salt — the two salts differ. Operators should still
treat the on-disk log as sensitive (see below).

### What never appears

- Raw QNAMEs.
- Full client IPs.
- DNSSEC validation chain detail.
- Upstream resolver IPs.
- Bundle / verifier-key file contents.

Anything not listed in the field semantics above is, by construction,
absent from the endpoint output.

## Disk persistence

By default there is **no disk persistence** of the query log — the ring
buffer is in-memory only and is lost on restart. Disk logging is an opt-in
that emits a startup warning (`AGENTS.md §Privacy invariants`).

When `privacy.query_log_to_disk = true` (plus `query_log_disk_path`), the
daemon appends NDJSON — the *same* line format as `/queries`, so the two
can never drift. The privacy invariants are preserved by construction:

- **QNAME is always salted-hashed**, never plaintext. The raw name cannot
  reach the disk writer — there is no code path that carries it there.
- **Client IP is always anonymised** (IPv4 `/16`, IPv6 `/64`).
  `log_client_ips` governs `tracing` output only; it does **not** lift
  anonymisation for the on-disk log.
- The file is created mode **0600**; if an existing target is group- or
  world-readable the daemon refuses to write to it and keeps serving DNS
  with the in-memory ring only.
- Size-based rotation (`query_log_max_file_bytes` × `query_log_max_files`)
  bounds the footprint — no external `logrotate` needed.

Because the on-disk log outlives the process while the salt does not (a
restart mints a fresh one), an old log cannot be cross-referenced against a
guessed domain after a restart. The salt-in-memory residual risk above
still applies *while the daemon is running*; treat the on-disk log as
sensitive, keep its directory `0700`, and avoid world-readable backups.

## Configuration reload: live vs. restart-required

`SIGHUP` re-reads `rustydns.toml` and applies what it safely can without
dropping in-flight queries. Some settings are fixed at startup and need a full
restart. The daemon logs a `warn!` listing any restart-required field that
changed (see `restart_required_changes`), so a reload never *silently* ignores
a change.

| Config | On `SIGHUP` |
|--------|-------------|
| `[upstream]` (resolvers, protocol, `[[upstream.routes]]`, `min_tls_version`, `dnssec_validation`, `timeout_ms`, `max_cache_entries`, `block_private_rdata`) | **Live** — resolver rebuilt and swapped (`ArcSwap`) |
| `[[policy]]` | **Live** — policy table swapped |
| `[rate_limit]` | **Live** — limiter swapped (token-bucket state resets) |
| `[[rewrite]]`, `[safesearch]` | **Live** — rewrite map swapped |
| Blocklist **content** (re-fetched from the *current* sources + local files) | **Live** — atomic content swap |
| Mesh-zone bundle | **Live** — re-read (also polled every `poll_interval_secs`) |
| Listeners on **unprivileged** ports (DNS UDP/TCP, DoT incl. TLS cert rotation, DoH, metrics) | **Live** — zero-drop rebind via `SO_REUSEPORT` |
| Listeners on **privileged** ports (`:53`, `:853`) | **Restart** — `CAP_NET_BIND_SERVICE` is dropped after the initial bind |
| `blocklist.sources` / `blocklist.local_files` (the source *list*) | **Restart** |
| `blocklist.allowlist` | **Restart** — rebuilt from the startup config on each content reload |
| `blocklist.block_response` / `blocklist.sinkhole_ip` | **Restart** |
| `blocklist.block_cname_cloaking` / `blocklist.response_ip_denylist` / `blocklist.regex_rules` | **Restart** — compiled into the engine at startup |
| `privacy.query_log_to_disk` / `query_log_disk_path` and the in-memory ring size | **Restart** — the writer task and ring are bound at startup |

> Why some listener changes are restart-only: the daemon drops **all** Linux
> capabilities right after the initial bind, so it physically cannot rebind a
> port `< 1024`. `SO_REUSEPORT` does not bypass the kernel privilege check. This
> is the capability-discipline invariant working as intended — see
> [`security.md`](security.md) §"Linux Capabilities".

## Authentication

None of the endpoints require authentication. The privacy posture
relies on the loopback binding: only processes on the same host can
reach them. If you must expose them off-host, terminate at an
authenticating reverse proxy and bind the proxy to the appropriate
interface. The daemon's `metrics.listen` setting should remain
`127.0.0.1`.
