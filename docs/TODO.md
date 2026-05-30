# rustydns — Improvement Backlog

A single, prioritized inventory of **everything worth doing** in this repo:
remaining roadmap work, security/anonymity hardening, efficiency wins, test
gaps, tech debt, and ops/doc polish. This is broader than
[`roadmap.md`](roadmap.md) — `roadmap.md` is the canonical list of *feature*
deferrals; this file additionally captures opportunistic improvements found by
scouring the codebase.

**How to read this:** each item has a **severity/value**, an **effort**
estimate, the **files** involved, and a concrete description. When you finish
one, delete it here and (if it's a feature deferral) update `roadmap.md` and the
doc surfaces it names.

Severity legend: 🔴 high · 🟠 medium · 🟡 low · ⚪ nice-to-have
Effort legend: S (hours) · M (a day) · L (multi-day / needs design)

> Before touching anything, read `AGENTS.md` §Privacy invariants and §Security
> invariants. Several "obvious" improvements below are deliberately scoped to
> avoid violating a hard invariant (e.g. capability discipline).

---

## 1. Blocked on external code (cannot implement here)

These live in `roadmap.md` too; repeated here for completeness. **Do not start**
— they need an upstream/sibling change first.

- **1.1 🟠 RFC 7816 query minimisation** — `hickory-resolver 0.26` exposes no
  knob. Scaffolding (`PrivacyConfig::query_minimization` + startup warning)
  already in place. Adopt when hickory ships it. Files:
  `crates/rustydns-resolver/src/lib.rs`, `crates/rustydnsd/src/main.rs`.
- **1.2 🟠 RFC 8467 DoH/DoQ padding** — same situation; hickory doesn't pad
  bodies. Scaffolding (`upstream_padding` + warning) present.
- **2.1 🟠 NodeId-keyed `[[policy]]` matching** — needs `rustynetd` to expose a
  `SocketAddr → NodeId` peer-table lookup at query time. `NodePolicy::node_id`
  is parsed/validated and a startup warning fires for inert entries. Files:
  `crates/rustydnsd/src/handler.rs` (`resolve_policy`), `docs/integration-rustynet.md`.

---

## 2. Security & anonymity

### 2.5 ⚪ Inbound DoQ (DNS-over-QUIC, RFC 9250) listener — **L**

DoQ is supported **upstream** only; the daemon listens on UDP/TCP/DoT/DoH. An
inbound DoQ server would round out the encrypted-transport story for clients
that prefer QUIC.

**Premise update (verified this session):** this is **no longer
upstream-blocked**. `hickory-server 0.26` exposes
`Server::register_quic_listener` / `register_quic_listener_and_tls_config`
(behind the `quic-ring` feature, which the workspace currently enables only for
`hickory-resolver`, not `hickory-server`). So it is now *implementable*, just
unstarted. Remaining work: add `quic-ring` to the `hickory-server` dep (binary-
size cost on Pi targets), a `server.doq_listen` config field requiring
`tls_cert_path`/`tls_key_path` (mirror `dot_listen` validation), register the
QUIC listener in `main.rs`, and a `quinn`-based DoQ handshake integration test
(more plumbing than the tokio-rustls DoT test). DoQ runs on `:853` (privileged)
so it is **restart-only** — the live-handover caveat (roadmap §3) applies. Left
unstarted deliberately: it is a ⚪ feature whose binary-size cost + QUIC-client
test burden aren't justified yet, not a blocked one.

---

## 4. Test coverage gaps

- **4.1 ✅ DoT TLS cert rotation — DONE.**
  `tests/sighup_reload.rs::sighup_rotates_dot_cert_on_path_change` starts DoT on
  an unprivileged port with a self-signed leaf (cert A), SIGHUPs with
  `tls_cert_path`/`tls_key_path` repointed to a second leaf (cert B), and a
  tokio-rustls client (accept-any verifier) reads the presented leaf back off
  the wire — asserting it flips A→B and the daemon logs a live rebind. (Path
  repoint is the documented rotation trigger; see `design-sighup-reload.md`.)
  The pre-existing real-handshake coverage in
  `handler.rs::dot_listener_serves_authority_hit_over_real_tls_handshake`
  remains.
- **4.2 ✅ ActiveListeners DoH-group reload — DONE.**
  `tests/sighup_reload.rs::sighup_rebinds_doh_listener_to_new_unprivileged_port`
  moves the DoH listener to a fresh unprivileged port on SIGHUP and asserts the
  new port serves (RFC 8484 GET → 200), the old port stops, and a live rebind is
  logged. DoH *add* is the startup default (`doh_listen` defaults to
  `127.0.0.1:8053`); DoH *remove* is not expressible in the TOML config (no
  null literal), so that unreachable branch is intentionally not tested.
- **4.3 ✅ Resolver mock coverage — DONE for the testable cases.** Added a UDP
  mock-upstream harness in `tests/upstream_e2e.rs` plus handler-level mock
  harnesses covering: fail-closed → SERVFAIL, ECS stripping (no EDNS Client
  Subnet on the wire even with EDNS0 on), NXDOMAIN vs NODATA, cache reuse,
  conditional-forwarding dispatch, rebinding-defence default-vs-route, CNAME
  cloaking, response-IP denylist, and rewrites. **Remaining (need a TLS mock,
  not a plain-UDP one):** DNSSEC *pass* with a signed zone, and TLS-1.3-floor
  rejection of a 1.2-only upstream. Padding is upstream-blocked (§1.2).
- **4.5 ✅ Property/fuzz tests for parsers — DONE (blocklist).** Dependency-free
  fuzz over the blocklist parser (5000 LCG-generated adversarial inputs across
  all four formats): no panic, and every emitted entry satisfies the domain
  invariants (ASCII, ≤253 B, ≤63 B labels, no empty labels, lowercased). The
  mesh field parser is signature-gated (untrusted bytes never reach the record
  loop without the signing key), and its malformed-payload rejections are
  already covered by the `mesh::tests` suite.

---

## 5. Code quality / tech debt

- **5.1 🟡 `handler.rs` is ~1000+ lines** — the `RequestHandler::handle_request`
  body is long with many early-return branches. Consider extracting the pipeline
  stages (rate-limit → opcode/class → authority → blocklist → resolver) into
  named helpers for readability and unit-testability of each stage.
- **5.2 🟡 `free_port()` race in integration tests** — `tests/sighup_reload.rs`
  binds `:0`, reads the port, drops, then lets the daemon rebind. Tiny TOCTOU;
  acceptable on loopback but could flake under heavy parallelism. The *bigger*
  flake — the daemon doing real network I/O at startup (default StevenBlack
  fetch + DoH bootstrap) and `dns_responds` resolving a public name with a 1.5s
  timeout — is now **fixed**: the test runs the daemon fully offline (empty
  blocklist, plain bare-IP upstream, a local `probe.mesh` static record), so it
  is deterministic and ~7× faster. The residual `free_port` TOCTOU itself
  remains (could pass the bound fd via socket activation, or retry on bind).

(5.3 done: systematic `unwrap()/expect()` audit across all network/parser paths
— no reachable panic on attacker-controlled input; query-log mutex locks now
recover on poison; audit conclusion recorded in `docs/security.md` §Panic
Policy.)

---

## 6. Ops / CI / docs

(All §6 items done: 6.1 CI gates `-D clippy::all`; 6.2 the pinned-1.88 `test`
job is the MSRV gate plus a new `stable` job for forward coverage; 6.3 Docker
capability wording corrected to "startup bind only"; 6.4 reload-vs-restart
matrix added to `docs/operator-endpoints.md`.)

---

## 7. Future / larger design items

- **7.1 ⚪ Privileged-port live reload via socket activation** — the one gap in
  SIGHUP Phase 2 is that `:53`/`:853` can't be rebound after the capability
  drop. systemd **socket activation** (`LISTEN_FDS`) would let systemd own the
  privileged sockets and pass the fds in, so the daemon never needs
  `CAP_NET_BIND_SERVICE` *and* could receive fresh fds on reload — closing the
  gap without weakening the capability posture. Needs a design pass + a
  non-systemd story. See `docs/design-sighup-reload.md`. **Left flagged (no
  clean drop-in):** this is a from-scratch implementation (parse
  `LISTEN_FDS`/`LISTEN_PID`, adopt pre-bound fds into the listener setup, ship a
  `.socket` unit, and design a non-systemd fallback) — not a library feature
  that can be wired in safely without that design pass. Deferred deliberately.
- **7.2 ✅ Per-qtype / per-rcode metrics — DONE.** Added
  `rustydns_dns_queries_by_qtype_total{qtype}` (incremented at the query-receipt
  choke point) and `rustydns_dns_responses_by_rcode_total{rcode}` (incremented in
  the single `respond()` send path, so every protocol — UDP/TCP/DoT/DoH — and
  every response branch is counted exactly once). The cardinality concern is
  resolved by **bounded `&'static str` label sets**: `qtype` uses hickory's
  structurally-bounded `RecordType -> &'static str` (unknown types collapse to
  `Unknown`), and `rcode` maps any code rustydns does not emit to `other`
  (`handler::rcode_metric_label`). Neither labels by qname/client, so the privacy
  posture holds and attacker-chosen qtypes/rcodes cannot exhaust metrics memory.
  Unit-tested in `metrics.rs` (increment + bounded series count) and `handler.rs`
  (rcode bucketing); documented in `docs/operator-endpoints.md`.

- **7.3 ✅ Oblivious DoH (ODoH, RFC 9230) upstream transport — DONE.** The
  flagship anonymity feature: the query is HPKE-encrypted to the **target**
  resolver and relayed through an **oblivious proxy** (`upstream.odoh_proxy`),
  so the proxy sees the client IP but not the query and the target sees the
  query but not the client IP — no single party can correlate "who asked what."
  - **Where:** new `crates/rustydns-resolver/src/odoh.rs` (the `OdohArm`:
    lazy-fetched + cached `ObliviousDoHConfig`, `odoh-rs` HPKE encrypt → `reqwest`
    POST to the proxy with `?targethost=&targetpath=` and
    `application/oblivious-dns-message` → decrypt → `hickory-proto` parse). Wired
    into `Resolver` via a `DefaultArm::{Hickory,Odoh}` split; ODoH is the global
    default only (rejected on routes).
  - **Invariants re-applied on the parallel arm:** **fail-closed** (every
    failure — config fetch, encrypt, relay, decrypt, DNS parse, target
    SERVFAIL/REFUSED — returns SERVFAIL; **never** falls back to plain DoH or the
    target directly); **no ECS**; **rebinding defence** (private rdata stripped);
    NXDOMAIN vs NODATA from the decrypted rcode. Key rotation is handled by
    clearing the cached config and retrying once on a decrypt failure.
  - **DNSSEC:** the oblivious arm does **not** do *client-side* DNSSEC
    validation (that lives in hickory-resolver, which this arm bypasses). Rather
    than let the flag mean nothing, `validate_config` **and** `Resolver::new`
    reject `protocol = "odoh"` + `dnssec_validation = true`; operators set
    `dnssec_validation = false` and rely on a validating target. A one-time
    startup `warn!` discloses this + the proxy-independence requirement.
  - **Deps:** `odoh-rs` (Cloudflare, BSD-2) + `hpke` 0.13, pinned in workspace
    deps, `cargo deny` clean (advisories/licenses/bans/sources ok). `rand 0.9`
    pinned locally in the resolver (hpke needs a rand_core-0.9 CSPRNG).
  - **Verified offline:** `odoh.rs` tests drive the **real** HPKE round-trip
    against an in-process mock target (genuine `odoh-rs` server side) — success,
    NXDOMAIN, target-SERVFAIL→error, relay-failure→error, garbage→error,
    rebinding filter, and config caching. What is *not* covered (reqwest's HTTPS
    transport + TLS floor) is third-party code configured in
    `odoh::build_http_client`. Docs: `docs/security.md`, `docs/architecture.md`,
    `docs/roadmap.md`, `rustydns.example.toml`. Supersedes §8.8.
  - **Future enhancements (not blocking):** client-side DNSSEC over the
    oblivious arm; multiple independent proxies / proxy rotation; honouring
    `privacy.upstream_padding` by padding the oblivious query; pinning the
    target `ODoHConfig` in config instead of fetching `/.well-known`.

---

## 8. Feature ideas from comparable projects

Survey of Pi-hole, AdGuard Home, blocky, Technitium, and dnscrypt-proxy, scored
against rustydns's hard constraints (no web UI, no database, hickory-only,
privacy/security first, low-power). **rustydns already has** ad/tracker blocking
(hosts / plain / RPZ / AdGuard list formats, allowlist, wildcards,
NXDOMAIN/sinkhole/REFUSED responses, HTTPS-only sources, auto-reload),
conditional forwarding, bounded LRU caching, DNSSEC, DoH/DoQ upstream + DoT/DoH
inbound, randomised upstream selection, ECS stripping, per-client (IP) policy,
rate limiting, rebinding defence, CNAME-cloaking defence (§8.1, done), DNS
rewrites / local cloaking (§8.2, done), response-IP denylists (§8.3, done),
Safe Search (§8.4, done), scheduled block windows (§8.5, done), per-client
blocklist groups (§8.6, done), and regex rules (§8.7, done). The only items
those projects have that we still don't are the deliberately-out-of-scope ones
below.

### Worth adding (fits the constraints)

(All "worth adding" §8 items are now done: 8.1–8.5, 8.7. 8.6 per-client
blocklist groups shipped — `[[blocklist.groups]]` named sets + a
`[[policy]].blocklist_group` assignment, routed via `is_blocked_for_group`.)

### High anonymity value — promoted to its own item

- **8.8 → see §7.3 ✅ Oblivious DoH (ODoH, RFC 9230) — DONE.** The flagship
  anonymity feature: the target resolver never learns the client IP and the
  relay never learns the query. Originally filed here as "likely
  upstream-blocked" — that was **wrong** (Cloudflare's `odoh-rs` implements RFC
  9230 and the DNS wire format stays `hickory-proto`), so it was promoted to
  **§7.3** and is now implemented and tested. See §7.3 for the full write-up.

### Deliberately out of scope (note the reason)

- **DHCP server + auto DNS registration** (Technitium) — rustydns is a resolver,
  not a DHCP server. Scope creep; AGENTS.md "what to avoid".
- **Web UI / admin dashboard / 2FA HTTP API** (Pi-hole, AdGuard, Technitium) —
  Rustyfin owns the UI; rustydns exposes only loopback `/metrics` `/health`
  `/queries`. Hard "do not add a web UI" rule.
- **Full from-scratch recursion / local root server** (Technitium, Unbound) — we
  deliberately forward to a DoH/DoQ recursive; not a recursor.
- **DNSCrypt protocol / Anonymized DNSCrypt relays** (dnscrypt-proxy) — would
  need a non-hickory protocol library; violates "hickory only". (ODoH, 8.8, is
  the in-family path to the same anonymity goal.)
- **Serve-stale / stale-while-revalidate** (many) — conflicts with the
  fail-closed security invariant; never return a stale answer silently.
- **Statistics database / long-term query analytics** (Pi-hole FTL, AGH) — "no
  database" invariant; query history stays in the bounded ring (+ opt-in hashed
  on-disk log).

> All §8 "worth adding" items are done: 8.1 (CNAME blocking), 8.2 (DNS rewrite
> map), 8.3 (response-IP blocklists), 8.4 (safe search), 8.5 (scheduled block
> windows), 8.6 (per-client blocklist groups), 8.7 (regex rules).

---

## Done this session (for context — already shipped)

- On-disk query log (roadmap 3.1); SIGHUP config reload Phase 1 + Phase 2 live
  listener handover (roadmap 3.2); IPv6 `/64` rate-limit fix; DoH body-size cap;
  `--validate-config` privacy warnings; mesh-bundle `record_count` bound +
  read TOCTOU fix. See `git log`.
