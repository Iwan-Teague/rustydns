# Blocklist Format Reference

`rustydns-blocklist` accepts three blocklist formats. All formats can be mixed — each source URL is parsed independently.

## Hosts format (recommended)

The most widely used format. Lines beginning with `#` are comments. The first field is the sinkhole IP, the second is the domain to block.

```
# This is a comment
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net
127.0.0.1 malware.example.org   # sinkhole IP is ignored — rustydns always uses NXDOMAIN or its own sinkhole
```

**Parsing rules:**
- Lines starting with `#` (after optional whitespace): skip
- Empty lines: skip
- `localhost` and `broadcasthost`: always skip, even if listed
- Lines with only one field: skip (malformed)
- IP field: ignored — `rustydns` uses its own configured sinkhole (`0.0.0.0` or `NXDOMAIN`)
- Domain field (second): lowercased, trailing dot stripped if present

**Sources that use this format:**
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) — `hosts` file with 100k+ entries
- [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) — tiered lists

## Plain domain list

One domain per line, no IP prefix. Lines starting with `#` are comments.

```
# Advertising domains
ads.example.com
tracker.example.net
```

`rustydns-blocklist` auto-detects this format when the first non-comment line does not start with a valid IP address.

## RPZ (Response Policy Zone)

A DNS zone file where blocked domains are represented as resource records. Supports wildcard subtree blocking.

```
; Block exact domain
ads.example.com  CNAME  .         ; CNAME to "." means NXDOMAIN

; Block entire subtree (all subdomains of example-ads.com)
*.example-ads.com  CNAME  .

; Allow a specific subdomain even within a blocked subtree
safe.example-ads.com  CNAME  rpz-passthru.
```

RPZ is the most expressive format but the least common for community blocklists. Useful for writing your own internal policy rules.

## Configuration

```toml
[blocklist]
# Remote sources — fetched at startup, reloaded on interval or SIGHUP
sources = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt",
]

# Local files — read at startup, reloaded on SIGHUP
local_files = [
    "/etc/rustydns/my-blocklist.txt",
]

# How to respond to blocked queries
# "nxdomain"  → NXDOMAIN (recommended)
# "sinkhole"  → return sinkhole_ip
# "refused"   → REFUSED
block_response = "nxdomain"
sinkhole_ip    = "0.0.0.0"   # only used if block_response = "sinkhole"

# Reload interval in seconds (0 = only reload on SIGHUP)
reload_interval_secs = 86400

# Per-domain allowlist (overrides blocklist)
allowlist = [
    "safe.ads-that-fund-things-i-like.com",
]
```

## Allowlist

The allowlist is checked before the blocklist. Any domain in the allowlist passes through to the resolver unconditionally, even if it appears in a blocklist source.

Allowlist entries support exact matches only — no wildcards. If you need to allow an entire subdomain tree, add each subdomain explicitly or use a local RPZ file with `rpz-passthru.` entries.

## Memory footprint

As a rough guide on the StevenBlack unified hosts list (~230k entries):

| List size | AHashSet memory |
|-----------|----------------|
| 100k domains | ~8 MB |
| 250k domains | ~20 MB |
| 1M domains | ~80 MB |

On a Pi Zero 2 W (512 MB RAM), the full StevenBlack list plus the hagezi Pro list together comfortably fit within the 30 MB idle RSS target for rustydns.
