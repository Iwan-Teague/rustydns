# Blocklist Format Reference

`rustydns-blocklist` accepts four blocklist formats, auto-detected per source.

---

## Source security requirements

**All remote blocklist sources must use `https://`.** Plain `http://` URLs are rejected at startup with an error message. Fetching blocklist content over HTTP allows a network attacker (on the path between rustydns and the CDN) to inject arbitrary allow or block rules — silently allowlisting malware domains or blocking legitimate ones.

### What HTTPS protects

HTTPS (TLS) ensures:
- **Confidentiality** — the list contents are encrypted in transit.
- **Integrity** — a network attacker cannot modify the list.
- **Authenticity** — the server presenting the TLS certificate is the configured host.

### What HTTPS does not protect

HTTPS does not protect against:
- **Source compromise** — if the GitHub repo or CDN hosting the blocklist is taken over, the attacker can serve a modified list. HTTPS validates the transport, not the content.
- **CDN compromise** — a CDN (jsDelivr, CloudFlare, etc.) can serve modified content with a valid certificate.
- **No content integrity verification** — there is no checksum or signature on blocklist content. If you require strong content integrity guarantees, host your own blocklist and verify it out-of-band.

### RPZ passthru injection

Blocklist sources that use RPZ format or AdGuard format can include "passthru" (allowlist) entries:
- RPZ: `example.com CNAME rpz-passthru.`
- AdGuard: `@@||example.com^`

A compromised CDN or source repository could inject these entries to permanently allowlist itself, bypassing the blocklist. To prevent this, `rustydns-blocklist` **discards allow/passthru entries from untrusted sources** and logs a warning. Only add a source to `blocklist.trusted_rpz_sources` if you control it or have strong trust in it.

```toml
[blocklist]
sources = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",  # untrusted: plain domains only
]

# Only add here if you deeply trust the source and need its RPZ passthru entries.
trusted_rpz_sources = [
    # "https://my-internal-rpz.example.com/policy.rpz",
]

# Local files are always trusted for passthru entries.
local_files = [
    "/etc/rustydns/local-allowlist.rpz",
]
```

### Fetch limits

To prevent DoS from large or malicious sources:

```toml
[blocklist]
fetch_timeout_ms = 30000   # 30 s — sources not responding within this are skipped
max_fetch_bytes  = 52428800  # 50 MiB — sources larger than this are truncated
```

Both limits apply per source. A source that exceeds either limit is skipped with a warning; the daemon continues with whatever other sources loaded successfully.

---

## Format 1: Hosts format (recommended for large community lists)

The most widely used format. Lines starting with `#` are comments. The first field is the sinkhole IP; the second (and subsequent) fields are domains to block.

```
# This is a comment
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net
127.0.0.1 malware.example.org   # sinkhole IP is ignored — rustydns uses its own
```

**Parsing rules:**
- Lines starting with `#`: skip
- Empty lines: skip
- `localhost`, `broadcasthost`, and loopback aliases: always skip
- Lines with only one field: skip
- IP field (first): ignored
- Domain field (second+): lowercased, trailing dot stripped, validated

**Domain validation (applied to all formats):**
- Maximum total length: 253 bytes (RFC 1035 wire-format limit)
- Maximum label length: 63 bytes (RFC 1035)
- No control characters (null bytes, etc.)
- No empty labels (consecutive dots)
- Entries failing validation are silently skipped

**Community sources using this format:**
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) — 100k+ entries
- [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) — tiered lists

---

## Format 2: Plain domain list

One domain per line, no IP prefix. Lines starting with `#` or `;` are comments.

```
# Advertising domains
ads.example.com
tracker.example.net
```

Auto-detected when the first non-comment line is a single field with no valid IP prefix.

---

## Format 3: RPZ (Response Policy Zone)

A DNS zone file where blocked domains are represented as resource records. The most expressive format; supports wildcard subtree blocking and passthru (allowlist) entries.

```
; Block exact domain
ads.example.com  CNAME  .

; Block entire subtree (all subdomains of example-ads.com)
*.example-ads.com  CNAME  .

; Allow a specific domain (passthru)
; ⚠ Only honoured if this source is in blocklist.trusted_rpz_sources or is a local file
safe.example-ads.com  CNAME  rpz-passthru.
```

**Note on `rpz-passthru.` entries:** As described in the source security section above, passthru entries from untrusted sources are discarded. They are only honoured from:
1. Local files (`blocklist.local_files`)
2. URLs listed in `blocklist.trusted_rpz_sources`

---

## Format 4: AdGuard / uBlock Origin filter syntax

```
! AdGuard/uBlock format
||ads.example.com^          ← block ads.example.com AND all its subdomains
||tracker.example.net^      ← block tracker.example.net AND all its subdomains
@@||safe.example.com^       ← allowlist entry (only honoured from trusted sources)
```

**AdGuard semantics in rustydns:**
`||domain^` in AdGuard blocks the apex AND all subdomains. rustydns models this as both an `Exact("domain")` and a `WildcardParent("domain")` entry.

**URL path rules are skipped:** `||cdn.example.com/ads^` contains a path component and is skipped — rustydns works at the domain level, not the URL level.

**`@@||domain^` allowlist entries** are subject to the same trusted-source restriction as RPZ passthru entries.

---

## Allowlist

The allowlist is checked before the blocklist. Any matching domain is never blocked, even if it appears in a blocklist source.

```toml
[blocklist]
allowlist = [
    # Exact match: only this domain
    "safe.ads.example.com",

    # Wildcard prefix: matches any subdomain of example.com, but NOT example.com itself
    "*.example.com",
    # Equivalent leading-dot syntax:
    # ".example.com",
]
```

**Wildcard semantics:**
- `"*.example.com"` matches `foo.example.com`, `bar.foo.example.com`, etc.
- `"*.example.com"` does NOT match `example.com` itself.
- To allowlist both the apex and all subdomains, add both: `["example.com", "*.example.com"]`.

**Overbroad entries are rejected:** Single-label or TLD-level wildcard entries (e.g. `"*.com"`) are rejected at startup because they would allowlist entire TLDs.

**Allowlist entries from blocklist sources:** RPZ passthru and AdGuard `@@` entries found in trusted sources augment the allowlist at reload time. These are merged with the static `allowlist` from config.

---

## Memory footprint

Approximate memory usage (AHashSet):

| List size | Approximate RAM |
|-----------|----------------|
| 100k domains | ~8 MiB |
| 250k domains | ~20 MiB |
| 1M domains | ~80 MiB |

The engine logs its heap estimate after every reload and emits a warning if usage exceeds 100 MiB. On a Pi Zero 2 W (512 MiB total), the full StevenBlack unified list plus hagezi Pro comfortably fits within the 30 MiB idle RSS target.
