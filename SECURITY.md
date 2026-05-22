# Security Policy

`rustydns` is a security-first DNS resolver. We take vulnerability
reports seriously and want to make it easy to send one in.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Use one of these private channels:

- **GitHub Security Advisories** (preferred). Open a draft advisory at
  <https://github.com/Iwan-Teague/rustydns/security/advisories/new>.
  The form lets you describe the issue, propose a fix, and request a
  CVE; only repository maintainers and the people you invite can see
  it until you publish.
- **Email**: `teague.iwan@outlook.com`. Plain English is fine. PGP is
  not required; if you'd like an encrypted channel anyway, ask in the
  initial mail and a key will be supplied for the reply.

When you report, please include:

1. A description of the vulnerability and which crate / module it
   lives in (`rustydns-resolver`, `rustydnsd`, etc.).
2. The shortest reproduction you can produce — a config snippet, a
   `dig` command, a malformed bundle, whatever applies. Avoid live
   exploitation of third-party deployments.
3. The impact you think the issue has (information disclosure, DoS,
   integrity, etc.) and any mitigation you've identified.
4. Whether you'd like to be credited in the resulting advisory.

Expected response times:

- **Acknowledgement**: within 72 hours.
- **Initial assessment** (severity, scope): within 7 days.
- **Patch release**: depends on severity. Critical issues affecting
  the resolver, authority, or blocklist pipeline aim for a patch
  within 14 days of confirmation.

If you don't hear back within 72 hours, please escalate by emailing
again with a subject prefix `[BUMP]` — the original mail may have
been caught in a filter.

## Supported versions

The project is still pre-`0.1.0`. The `main` branch is the only
supported release line; we don't ship LTS branches yet. Once we cut
`0.1.0`, this section will list explicit supported version windows.

## Scope

In scope for security reports:

- **Resolver path**: cache poisoning, DNSSEC validation bypasses,
  fail-closed regressions (a path where an upstream failure returns
  anything other than `SERVFAIL`).
- **Authority**: signature-verification bypasses on the Rustynet
  mesh bundle, freshness-check bypasses, parser memory blow-ups.
- **Blocklist**: HTTPS-only enforcement bypasses, RPZ-passthru
  trust-boundary bypasses, fetch-size bypasses leading to OOM.
- **Pipeline**: anything that lets a client skip the
  `Authority → Blocklist → Resolver` order or extract raw QNAMEs
  from `tracing` output / `/queries` / `/metrics`.
- **Privilege**: capability-dropping bypasses, escalation through a
  malformed config file, etc.
- **Operator endpoints**: `/metrics`, `/health`, `/queries`
  reaching off-loopback when the config doesn't ask for it.

Out of scope (please file these as regular issues):

- Bugs in dependencies that don't reach `rustydns` code paths.
- Reports against the example config rather than the daemon
  itself.
- Theoretical timing attacks where the practical impact is bounded
  by network noise.

## Hardening checklist for operators

Independent of receiving a report, please read:

- [`AGENTS.md`](AGENTS.md) §Privacy invariants and §Security invariants
- [`docs/security.md`](docs/security.md) — threat model + countermeasure rationale
- [`docs/operator-endpoints.md`](docs/operator-endpoints.md) — `/metrics`, `/health`, `/queries` reference and loopback-only contract
- [`docs/deployment-docker.md`](docs/deployment-docker.md) — image capability model, compose hardening, metrics-via-sidecar pattern

These document what the daemon protects against by construction, and
what the operator is responsible for (firewall placement, file
permissions on the verifier key, reverse-proxy authentication on
exposed endpoints, etc.).

## Coordinated disclosure

If your report affects another open-source project as well (for
example, a hickory-resolver issue we also depend on), we are happy to
coordinate with upstream maintainers on a joint disclosure timeline.

## Acknowledgements

Reporters who consent to public credit will be listed in the resulting
GitHub Security Advisory and the project CHANGELOG. Anonymous reports
are equally welcome.
