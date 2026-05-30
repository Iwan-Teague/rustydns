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

### 2.1 🔴 Mesh-bundle anti-rollback / replay protection — **M**

`Authority::reload_mesh` accepts any bundle that passes signature + freshness,
but does **not** check that the new bundle is *newer* than the one currently
loaded. The bundle carries both `generated_at_unix` and a `nonce`
(`LoadedBundle` already parses them) — neither is used for ordering.

**Attack:** an actor who can write the bundle path (or cause a stale file to
reappear) can roll the mesh zone back to an **older but still-fresh** signed
bundle — e.g. one generated 4 minutes ago (with `mesh_zone_max_age_secs = 600`)
that re-points a name to a previous IP or drops a record. The signature still
verifies because it's a legitimately old bundle.

**Fix:** track the last-applied `(generated_at_unix, nonce)` in the `Authority`
and reject a reload whose `generated_at_unix` is `<` current (tie-break on
`nonce`). Keep it in-memory (the "no database" invariant stands); document that a
process restart resets the watermark, so the `max_age` window is still the
backstop right after boot. Add a test: load bundle@T, then attempt bundle@T-60 →
rejected, snapshot unchanged.

Files: `crates/rustydns-authority/src/lib.rs` (`reload_mesh`),
`crates/rustydns-authority/src/mesh.rs` (`LoadedBundle`). Doc:
`docs/security.md` §"Mesh Bundle Tampering", `docs/integration-rustynet.md`.

### 2.2 🟡 Query-log hash relies on the in-memory salt staying secret — **S (doc)**

The ring buffer and on-disk NDJSON store a per-process-salted `u64` hash of each
QNAME. The salt (`rand::random()` at startup) lives only in process memory, so
an actor who reads `/queries` or the log file sees only hashes and **cannot**
run a dictionary attack ("was `example.com` queried?") without the salt — this
is the intended, sound design.

The residual risk is narrow but worth documenting: anyone who can dump the
process's memory (core dump, `/proc/<pid>/mem`, swap) recovers the salt and can
then offline-confirm whether any guessed domain appears in a captured log. The
on-disk log makes this more relevant (the log outlives the process; the salt does
not, which actually *helps* — old logs can't be cross-referenced after a
restart). Action: spell this out in `docs/operator-endpoints.md` and
`docs/security.md` so operators don't over-trust the on-disk hashes, and note
that disabling swap / restricting core dumps (already implied by the systemd
sandbox) is the mitigation. No code change needed.

Files: `docs/operator-endpoints.md`, `docs/security.md`,
`crates/rustydnsd/src/query_log.rs` (rationale already in module docs).

### 2.3 🟡 Resolver conflates NODATA and NXDOMAIN — **M**

`Resolver::resolve` maps both "no records" and "name does not exist" to
`Ok(ResolveOutcome::default())` (empty), and the handler then always emits
`NoError` (NODATA). A genuinely non-existent name is therefore returned as
NODATA, not NXDOMAIN. This is **deliberate and documented**
(`crates/rustydns-resolver/src/lib.rs:298`), but it is technically incorrect DNS
and can weaken downstream negative caching. To fix: capture the upstream
`response_code` from hickory's `NoRecordsFound` and thread an
`nxdomain: bool` (or `ResponseCode`) through `ResolveOutcome` so the handler can
emit the right code. Low security impact; correctness/interop nicety.

Files: `crates/rustydns-resolver/src/lib.rs` (~line 386),
`crates/rustydnsd/src/handler.rs` (resolver `Ok` arm).

### 2.4 🟡 Blocklist parser accepts non-ASCII domain bytes — **S**

`validate_and_normalize` rejects control bytes but allows bytes ≥ 0x80, then
applies Unicode `to_lowercase()`. Such entries are harmless dead weight (real
queries arrive as punycode/`xn--`, ASCII) but they (a) never match anything and
(b) make the `to_lowercase()` comment ("ASCII lowercased") inaccurate. Consider
rejecting non-ASCII labels outright (smaller, faster set; honest comment).

Files: `crates/rustydns-blocklist/src/parser.rs` (`validate_and_normalize`).

### 2.5 ⚪ Inbound DoQ (DNS-over-QUIC, RFC 9250) listener — **L**

DoQ is supported **upstream** only; the daemon listens on UDP/TCP/DoT/DoH. An
inbound DoQ server would round out the encrypted-transport story for clients
that prefer QUIC. Gated on hickory exposing a server-side DoQ acceptor and a
design pass for the live-handover model. Privileged-port caveat (§4 of
`roadmap.md`) applies.

---

## 3. Efficiency (Pi Zero 2 W is the target)

### 3.1 🟠 QNAME is lowercased/allocated 3–4× per query — **M**

The hot path re-derives the canonical name several times:
1. `handler`: `info.query.name().to_string()` (mixed-case, trailing dot).
2. `authority.lookup` → `normalise_name` → `to_ascii_lowercase()` (alloc).
3. `allowlist.is_allowed` → `to_lowercase()` (**always** allocs, see 3.2).
4. `log_query` → `qname.to_ascii_lowercase()` (alloc) for the ring/disk.

CLAUDE.md explicitly calls out "the query hot path must not allocate on the heap
for cache hits." Canonicalise **once** at the top of `handle_request` into a
lowercased, dot-stripped `String` (or `Cow`) and pass that form to authority /
blocklist / allowlist / query-log, dropping the redundant lowercasings. Measure
with a micro-bench before/after.

Files: `crates/rustydnsd/src/handler.rs`, `crates/rustydns-authority/src/lib.rs`
(`normalise_name` / `lookup`), `crates/rustydns-blocklist/src/{engine,allowlist}.rs`.

### 3.2 🟡 `Allowlist::is_allowed` always allocates — **S**

`engine::is_blocked` is carefully allocation-free for ASCII names (lowercases via
a stack buffer / only allocs on non-ASCII), but `Allowlist::is_allowed`
(`allowlist.rs:86`) does `domain.trim_end_matches('.').to_lowercase()`
unconditionally. Mirror the engine's ASCII-fast path so the allowlist check
(run on every non-bypassed query) doesn't allocate.

Files: `crates/rustydns-blocklist/src/allowlist.rs`.

### 3.3 🟡 `qtype.to_string()` per query — **S**

`handle_request` does `qtype.to_string()` (alloc) then later `intern_qtype`
maps it back to a `&'static str`. Map the hickory `RecordType` to the static
label directly (match on the enum) and avoid the `String`.

Files: `crates/rustydnsd/src/handler.rs` (`intern_qtype` + call site).

### 3.4 ⚪ Audit `.clone()` on `zones_allowed` / policy per query — **S**

`resolve_policy` clones `zones_allowed: Vec<String>` for every query that
matches a policy. For policied clients this allocates per query. Consider an
`Arc<[String]>` or returning a borrow tied to the `ArcSwap` guard.

Files: `crates/rustydnsd/src/handler.rs` (`PolicyDecision`, `resolve_policy`).

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
- **4.4 🟡 Mesh anti-rollback** — add once §2.1 lands.
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

---

## Done this session (for context — already shipped)

- On-disk query log (roadmap 3.1); SIGHUP config reload Phase 1 + Phase 2 live
  listener handover (roadmap 3.2); IPv6 `/64` rate-limit fix; DoH body-size cap;
  `--validate-config` privacy warnings; mesh-bundle `record_count` bound +
  read TOCTOU fix. See `git log`.
