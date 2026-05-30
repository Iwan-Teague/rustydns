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
that prefer QUIC. Gated on hickory exposing a server-side DoQ acceptor and a
design pass for the live-handover model. Privileged-port caveat (§4 of
`roadmap.md`) applies.

---

## 4. Test coverage gaps

- **4.1 🟠 DoT TLS cert rotation** — claimed working in docs/commits but has no
  automated test. Add an integration test: start with DoT on an unprivileged
  port + a self-signed cert (use `test_pem`), SIGHUP with a new cert, assert the
  listener rebinds and serves the new cert (TLS client checks the presented
  cert). Files: `crates/rustydnsd/tests/`.
- **4.2 🟠 ActiveListeners DoH-group reload** — the e2e covers DNS+metrics
  rebind and the privileged-port refusal; DoH **add/remove/move** on reload is
  only manually verified. Extend `tests/sighup_reload.rs`.
- **4.3 🟠 Resolver mock coverage** — AGENTS.md asks for `wiremock`/axum mock-DoH
  tests covering ECS stripping, DNSSEC pass/fail, fail-closed, TLS 1.3
  enforcement, padding behaviour. Current resolver tests lean on classifier unit
  tests; add a mock upstream. Files: `crates/rustydns-resolver/`.
- **4.5 🟡 Property/fuzz tests for parsers** — blocklist parser and mesh field
  parser process semi-trusted input; add `proptest`-style "no panic, invariants
  hold" tests (e.g. allowlist entries always ≥ 2 labels, no `http://` sources,
  bounded output). Files: `crates/rustydns-blocklist/`, `crates/rustydns-authority/src/mesh.rs`.

---

## 5. Code quality / tech debt

- **5.1 🟡 `handler.rs` is ~1000+ lines** — the `RequestHandler::handle_request`
  body is long with many early-return branches. Consider extracting the pipeline
  stages (rate-limit → opcode/class → authority → blocklist → resolver) into
  named helpers for readability and unit-testability of each stage.
- **5.2 🟡 `free_port()` race in integration tests** — `tests/sighup_reload.rs`
  binds `:0`, reads the port, drops, then lets the daemon rebind. Tiny TOCTOU;
  acceptable on loopback but could flake under heavy parallelism. Could pass the
  bound listener fd via systemd-style activation, or retry on bind failure.
- **5.3 🟡 Audit runtime `unwrap()/expect()`** — with `panic = "abort"` in
  release, any reachable panic on malformed network input is a remote DoS.
  Builder `.unwrap()`s on constant `Response`s are safe; do a focused pass over
  `handler.rs`, `doh.rs`, `metrics.rs` to confirm none are reachable from
  attacker-controlled input. (Spot-check done this session — looked clean — but
  no systematic audit.)

---

## 6. Ops / CI / docs

- **6.1 🟡 CI doesn't gate full clippy** — `ci.yml` enforces
  `correctness`/`suspicious`/`perf` but not `clippy::all` as `-D`. The tree is
  currently clean under `-D warnings`; consider tightening CI to prevent style
  drift (or keep style as warnings deliberately — document the choice).
- **6.2 🟡 No MSRV job** — CLAUDE.md pins MSRV 1.88 (hickory floor). Add a CI job
  building with `1.88` to catch accidental newer-stdlib usage before it breaks
  the documented floor.
- **6.3 ⚪ Docker capability wording** — `docs/deployment-docker.md` says the cap
  is needed "at runtime"; it's needed only at **startup bind** (dropped
  immediately after). Minor precision fix; ties into the §4 capability story.
- **6.4 ⚪ Reload-vs-restart operator matrix** — now that SIGHUP reload covers a
  lot (Phase 1 + 2), a small table in `docs/operator-endpoints.md` mapping each
  config section → "live reload" vs "restart required" would help operators.

---

## 7. Future / larger design items

- **7.1 ⚪ Privileged-port live reload via socket activation** — the one gap in
  SIGHUP Phase 2 is that `:53`/`:853` can't be rebound after the capability
  drop. systemd **socket activation** (`LISTEN_FDS`) would let systemd own the
  privileged sockets and pass the fds in, so the daemon never needs
  `CAP_NET_BIND_SERVICE` *and* could receive fresh fds on reload — closing the
  gap without weakening the capability posture. Needs a design pass + a
  non-systemd story. See `docs/design-sighup-reload.md`.
- **7.2 ⚪ Per-qtype / per-rcode metrics** — useful for operators, but label
  cardinality + the privacy posture need care (never label by qname/client).
  Bounded label sets only.

- **7.3 🟠 Oblivious DoH (ODoH, RFC 9230) upstream transport — L.**
  **The single highest-leverage *anonymity* feature** for rustydns, and a direct
  fit for the project's #1 design goal ("Security, privacy, and anonymity are the
  highest-priority design goals"). With plain DoH/DoQ, the upstream resolver
  sees *both* the query content **and** the client's IP. ODoH breaks that link:
  the query is HPKE-encrypted to the **target** resolver and relayed through an
  **oblivious proxy**, so the proxy sees the client IP but not the query, and the
  target sees the query but not the client IP. No single party can correlate
  "who asked what." This is dnscrypt-proxy's flagship privacy mode (also called
  𝜇ODNS in the literature).

  **Implementable now — NOT upstream-blocked.** Cloudflare's `odoh-rs`
  (RFC 9230, BSD-2, HPKE via the `hpke` crate; `odoh-client-rs` is a working
  reference) provides the oblivious-message encryption/decryption. The DNS wire
  format stays `hickory-proto` (so "hickory only" still holds — that rule is
  about the DNS library, not the crypto), and the HTTP POST to the proxy uses the
  existing `reqwest`. Flow: fetch the target's ODoH config (public key) →
  `hickory-proto` encodes the query → `odoh-rs` HPKE-encrypts it → `reqwest`
  POSTs `application/oblivious-dns-message` to the proxy (`?targethost=&targetpath=`)
  → decrypt the response → `hickory-proto` parses it.

  **Why it's "L" / needs a design pass — the hard parts:**
  - It's a *parallel* upstream arm that bypasses `hickory-resolver`. The
    invariants currently delivered by hickory-resolver — **DNSSEC validation**,
    **fail-closed → SERVFAIL**, ECS stripping, randomised selection,
    rebinding-defence rdata filtering — must be re-applied to the ODoH arm
    (DNSSEC validation in particular: do it with `hickory-proto`'s validator over
    the decrypted message, and keep fail-closed — never fall back to plain DoH on
    ODoH failure, which would silently de-anonymise).
  - **Config surface:** target resolver URL, one or more proxy URLs, and the
    target's `ODoHConfig` (fetch from `/.well-known/odohconfigs` or pin in
    config), plus key-rotation handling. Choose proxies that are operationally
    independent from the target, or the anonymity guarantee collapses.
  - **Dependency vetting:** adds `odoh-rs` + `hpke` (and transitive crypto) to
    the audit surface. `odoh-rs` is Cloudflare-maintained but low-traffic
    (~hundreds of downloads/mo) — run it through `cargo deny` (advisories +
    license: BSD-2 is fine) and pin it like everything else in
    `[workspace.dependencies]`. The minimal-attack-surface ethos means this
    dependency choice deserves explicit sign-off.
  - **Scaffolding suggestion:** add `upstream.protocol = "odoh"` (alongside
    `doh`/`doq`/`plain`) + `upstream.odoh_proxy` so a config written today is
    forward-compatible, and emit a startup warning until the arm is wired (same
    pattern as the qmin/padding knobs).

  Files: new `crates/rustydns-resolver` ODoH arm, `crates/rustydns-core/src/config.rs`
  (`UpstreamConfig`), `deny.toml`, `Cargo.toml` workspace deps. Docs:
  `docs/security.md` (new threat-model entry), `docs/architecture.md`,
  `rustydns.example.toml`. Supersedes the (inaccurate) "upstream-blocked" framing
  of §8.8.

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
rewrites / local cloaking (§8.2, done), response-IP denylists (§8.3, done), and
Safe Search (§8.4, done). The items below are what those projects have that we
**don't**.

### Worth adding (fits the constraints)

- **8.5 🟡 Scheduled / time-window rules — M.** Per-client or per-domain block
  schedules ("block social media 09:00–17:00", "kids' devices off after 22:00").
  AdGuard has access schedules. Novel for a config-file resolver; extend
  `[[policy]]` with optional `block_windows`. Keep it timezone-explicit. Files:
  `config.rs` (`NodePolicy`), `handler.rs` (`resolve_policy`).
- **8.6 🟡 Per-client blocklist groups — M.** Today `[[policy]]` toggles
  bypass/zones per IP. blocky/AdGuard let you assign clients to named groups,
  each with its own set of blocklists ("iot can only reach vendor domains",
  "guest gets the strict list"). Extends the existing policy model rather than
  adding a subsystem. Files: `config.rs`, `blocklist` engine (multiple named
  sets), `handler.rs`.
### High anonymity value — promoted to its own item

- **8.8 → see §7.3 🟠 Oblivious DoH (ODoH, RFC 9230).** The flagship anonymity
  feature: the target resolver never learns the client IP and the relay never
  learns the query. Originally filed here as "likely upstream-blocked" — that was
  **wrong**: Cloudflare's `odoh-rs` implements RFC 9230 today, and the DNS wire
  format stays `hickory-proto`, so it's implementable now (not blocked on
  hickory). Promoted to **§7.3** with full design notes (DNSSEC/fail-closed
  re-application, config surface, dependency vetting) because it directly serves
  rustydns's #1 goal.

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

> Done: 8.1 (CNAME blocking), 8.2 (DNS rewrite map), 8.3 (response-IP
> blocklists), 8.4 (safe search), 8.7 (regex rules). Remaining: 8.5 (scheduled
> rules), 8.6 (per-client groups).

---

## Done this session (for context — already shipped)

- On-disk query log (roadmap 3.1); SIGHUP config reload Phase 1 + Phase 2 live
  listener handover (roadmap 3.2); IPv6 `/64` rate-limit fix; DoH body-size cap;
  `--validate-config` privacy warnings; mesh-bundle `record_count` bound +
  read TOCTOU fix. See `git log`.
