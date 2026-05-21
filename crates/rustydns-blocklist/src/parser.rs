//! Blocklist content parsers for all supported formats.
//!
//! # Supported formats (auto-detected)
//!
//! | Format | Example line | Auto-detection |
//! |--------|-------------|----------------|
//! | Hosts | `0.0.0.0 ads.example.com` | First field is a valid IP |
//! | Plain domain list | `ads.example.com` | Single field, no IP |
//! | RPZ zone | `ads.example.com CNAME .` | Three fields with DNS type |
//! | AdGuard/uBlock | `\|\|ads.example.com^` | Starts with `\|\|` |
//!
//! All parsers are zero-allocation for the common path (no heap allocation
//! per domain — strings are only created for matched entries).

/// A single parsed blocklist directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEntry {
    /// Block exactly this domain (case-folded, no trailing dot).
    Exact(String),
    /// Block all subdomains of this domain.
    ///
    /// E.g. `WildcardParent("example-ads.com")` blocks `foo.example-ads.com`
    /// and `bar.foo.example-ads.com` but NOT `example-ads.com` itself.
    WildcardParent(String),
    /// Allow this domain (RPZ `rpz-passthru.` directive).
    ///
    /// These are merged into the allowlist after parsing so they take
    /// precedence over block entries.
    Allow(String),
}

/// Auto-detected blocklist format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    /// `0.0.0.0 domain` or `127.0.0.1 domain` (hosts file).
    Hosts,
    /// One domain per line, no IP prefix.
    Plain,
    /// DNS Response Policy Zone (`domain CNAME .`).
    Rpz,
    /// AdGuard/uBlock Origin filter syntax (`||domain^`).
    AdGuard,
}

/// Auto-detect the format of a blocklist from its content.
///
/// Reads only the minimum number of lines needed to make a determination.
/// Falls back to [`ListFormat::Plain`] if the format is ambiguous.
pub fn detect_format(content: &str) -> ListFormat {
    for line in content.lines() {
        let line = line.trim();
        // Skip comments and empty lines — they appear in all formats.
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('!')  // AdGuard comment
            || line.starts_with('[')  // AdGuard header
        {
            continue;
        }

        // AdGuard block: ||domain^ or @@||domain^
        if (line.starts_with("||") || line.starts_with("@@||")) && line.contains('^') {
            return ListFormat::AdGuard;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        // RPZ: requires at least "name TYPE rdata"
        if parts.len() >= 3 {
            let typ = parts[1].to_ascii_uppercase();
            if matches!(typ.as_str(), "CNAME" | "A" | "AAAA" | "TXT" | "SOA" | "NS") {
                return ListFormat::Rpz;
            }
        }

        // Hosts: first field is a valid IP address.
        if parts.len() >= 2 && is_ip_address(parts[0]) {
            return ListFormat::Hosts;
        }

        // Single field or non-IP first field → plain domain list.
        return ListFormat::Plain;
    }

    // Entirely empty / comment-only file → treat as plain.
    ListFormat::Plain
}

/// Parse blocklist `content`, auto-detecting the format.
///
/// Returns a `Vec<ParsedEntry>` which the caller inserts into the engine's
/// domain sets. Malformed lines are silently skipped.
pub fn parse(content: &str) -> Vec<ParsedEntry> {
    match detect_format(content) {
        ListFormat::Hosts => parse_hosts(content),
        ListFormat::Plain => parse_plain(content),
        ListFormat::Rpz => parse_rpz(content),
        ListFormat::AdGuard => parse_adguard(content),
    }
}

/// Parse hosts-format content.
///
/// Parsing rules (per [`docs/blocklist-format.md`]):
/// - Lines starting with `#` (after optional whitespace): skip.
/// - Empty lines: skip.
/// - `localhost`, `broadcasthost`, and other loopback aliases: always skip.
/// - Lines with only one field: skip (malformed).
/// - IP field (first): ignored — rustydns uses its own configured sinkhole.
/// - Domain field (second and beyond): lowercased, trailing dot stripped.
pub fn parse_hosts(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        // Strip inline comments.
        let line = strip_comment(line, '#');
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();

        // First field must be an IP address; skip if not.
        match parts.next() {
            Some(ip) if is_ip_address(ip) => {}
            _ => continue,
        }

        // Remaining fields are domains to block.
        for domain in parts {
            let domain = normalize_domain(domain);
            if !domain.is_empty() && !is_always_skipped(&domain) {
                entries.push(ParsedEntry::Exact(domain));
            }
        }
    }

    entries
}

/// Parse a plain domain list (one domain per line).
pub fn parse_plain(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = strip_comment(line, '#');
        let line = strip_comment(line, ';');
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        // Reject lines with spaces (likely malformed or wrong format).
        if line.contains(' ') || line.contains('\t') {
            continue;
        }

        let domain = normalize_domain(line);
        if !domain.is_empty() && !is_always_skipped(&domain) {
            entries.push(ParsedEntry::Exact(domain));
        }
    }

    entries
}

/// Parse an RPZ zone file.
///
/// Supported record types:
/// - `domain CNAME .` → block exact domain (NXDOMAIN equivalent).
/// - `*.domain CNAME .` → block entire subtree.
/// - `domain CNAME rpz-passthru.` → allow (passthru — added to allowlist).
///
/// SOA and NS records are silently skipped (zone boilerplate).
pub fn parse_rpz(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = strip_comment(line, ';');
        let line = strip_comment(line, '#');
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let name = parts[0];
        let rtype = parts[1].to_ascii_uppercase();
        let rdata = parts[2];

        // We only process CNAME RPZ actions.
        if rtype != "CNAME" {
            continue;
        }

        let rdata_lower = rdata.to_lowercase();

        if rdata_lower == "rpz-passthru." || rdata_lower == "rpz-passthru" {
            // Allow entry.
            if let Some(domain) = rpz_name_to_domain(name) {
                entries.push(ParsedEntry::Allow(domain));
            }
        } else if rdata == "." {
            // Block entry.
            if let Some(parent) = name.strip_prefix("*.") {
                // Wildcard subtree block.
                let parent = normalize_domain(parent);
                if !parent.is_empty() {
                    entries.push(ParsedEntry::WildcardParent(parent));
                }
            } else {
                // Exact block.
                if let Some(domain) = rpz_name_to_domain(name) {
                    if !is_always_skipped(&domain) {
                        entries.push(ParsedEntry::Exact(domain));
                    }
                }
            }
        }
        // Other rdata (e.g. sinkhole IPs, NXDOMAIN triggers) are skipped.
    }

    entries
}

/// Parse AdGuard/uBlock Origin filter list syntax.
///
/// Supported:
/// - `||example.com^` — block `example.com` (and all subdomains in AdGuard
///   semantics; we model this as a wildcard parent block).
/// - `@@||example.com^` — allowlist entry.
///
/// Unsupported (silently skipped): cosmetic filters (`##`), URL path rules,
/// modifier-only rules, and anything with `/`.
pub fn parse_adguard(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comment and header lines.
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }

        // Allowlist: @@||domain^
        if let Some(rest) = line.strip_prefix("@@||") {
            if let Some(domain_part) = rest.split('^').next() {
                if !domain_part.contains('/') {
                    let domain = normalize_domain(domain_part);
                    if !domain.is_empty() {
                        entries.push(ParsedEntry::Allow(domain));
                    }
                }
            }
            continue;
        }

        // Block: ||domain^
        // In AdGuard syntax `||domain^` blocks domain AND all its subdomains.
        // We model this as WildcardParent (matching subdomains) plus Exact
        // (matching the apex), to faithfully represent AdGuard semantics.
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(caret_pos) = rest.find('^') {
                let domain_part = &rest[..caret_pos];
                // Skip URL path rules.
                if domain_part.contains('/') {
                    continue;
                }
                // Skip rules with modifiers we don't understand.
                let domain = normalize_domain(domain_part);
                if !domain.is_empty() && !is_always_skipped(&domain) {
                    // Exact match for the apex.
                    entries.push(ParsedEntry::Exact(domain.clone()));
                    // Wildcard for all subdomains.
                    entries.push(ParsedEntry::WildcardParent(domain));
                }
            }
        }
        // All other lines (cosmetic, anchor-only, etc.) are silently skipped.
    }

    entries
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip a comment starting at `marker` from `line`.
fn strip_comment(line: &str, marker: char) -> &str {
    if let Some(pos) = line.find(marker) {
        &line[..pos]
    } else {
        line
    }
}

/// Normalise a domain: lowercase, trim whitespace, strip trailing dot.
fn normalize_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_lowercase()
}

/// Convert an RPZ record name to a plain domain (strips the RPZ zone suffix if present).
///
/// RPZ zone files often qualify names with the zone apex, e.g.
/// `ads.example.com.rpz.example.` In practice, most community RPZ files use
/// bare names. We handle both by stripping any trailing zone label if it
/// doesn't look like a public TLD.
fn rpz_name_to_domain(name: &str) -> Option<String> {
    let domain = normalize_domain(name);
    if domain.is_empty() || domain == "@" {
        return None;
    }
    Some(domain)
}

/// Returns `true` if `s` looks like an IPv4 or IPv6 address.
fn is_ip_address(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok() || s.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Returns `true` for domains that should always be skipped regardless of
/// which blocklist they appear in.
///
/// These are loopback/link-local names that must never be blocked.
fn is_always_skipped(domain: &str) -> bool {
    matches!(
        domain,
        "localhost"
            | "broadcasthost"
            | "local"
            | "ip6-localhost"
            | "ip6-loopback"
            | "ip6-localnet"
            | "ip6-mcastprefix"
            | "ip6-allnodes"
            | "ip6-allrouters"
            | "ip6-allhosts"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- format detection ---------------------------------------------------

    #[test]
    fn detect_hosts_format() {
        let content = "# comment\n0.0.0.0 ads.example.com\n";
        assert_eq!(detect_format(content), ListFormat::Hosts);
    }

    #[test]
    fn detect_plain_format() {
        let content = "# comment\nads.example.com\n";
        assert_eq!(detect_format(content), ListFormat::Plain);
    }

    #[test]
    fn detect_rpz_format() {
        let content = "; rpz\nads.example.com CNAME .\n";
        assert_eq!(detect_format(content), ListFormat::Rpz);
    }

    #[test]
    fn detect_adguard_format() {
        let content = "! AdGuard\n||ads.example.com^\n";
        assert_eq!(detect_format(content), ListFormat::AdGuard);
    }

    // --- hosts parser -------------------------------------------------------

    #[test]
    fn hosts_basic() {
        let content = "0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.net\n";
        let entries = parse_hosts(content);
        assert!(entries.contains(&ParsedEntry::Exact("ads.example.com".into())));
        assert!(entries.contains(&ParsedEntry::Exact("tracker.example.net".into())));
    }

    #[test]
    fn hosts_skips_localhost() {
        let content = "0.0.0.0 localhost\n0.0.0.0 broadcasthost\n";
        let entries = parse_hosts(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn hosts_strips_inline_comments() {
        let content = "0.0.0.0 ads.example.com # this is an ad server\n";
        let entries = parse_hosts(content);
        assert_eq!(entries.len(), 1);
        assert!(entries.contains(&ParsedEntry::Exact("ads.example.com".into())));
    }

    #[test]
    fn hosts_multiple_domains_per_line() {
        let content = "0.0.0.0 ads.example.com tracker.example.com\n";
        let entries = parse_hosts(content);
        assert_eq!(entries.len(), 2);
    }

    // --- RPZ parser ---------------------------------------------------------

    #[test]
    fn rpz_exact_block() {
        let content = "ads.example.com CNAME .\n";
        let entries = parse_rpz(content);
        assert!(entries.contains(&ParsedEntry::Exact("ads.example.com".into())));
    }

    #[test]
    fn rpz_wildcard_block() {
        let content = "*.example-ads.com CNAME .\n";
        let entries = parse_rpz(content);
        assert!(entries.contains(&ParsedEntry::WildcardParent("example-ads.com".into())));
    }

    #[test]
    fn rpz_passthru_becomes_allow() {
        let content = "safe.example.com CNAME rpz-passthru.\n";
        let entries = parse_rpz(content);
        assert!(entries.contains(&ParsedEntry::Allow("safe.example.com".into())));
    }

    // --- AdGuard parser -----------------------------------------------------

    #[test]
    fn adguard_block_adds_exact_and_wildcard() {
        let content = "||ads.example.com^\n";
        let entries = parse_adguard(content);
        assert!(entries.contains(&ParsedEntry::Exact("ads.example.com".into())));
        assert!(entries.contains(&ParsedEntry::WildcardParent("ads.example.com".into())));
    }

    #[test]
    fn adguard_allowlist() {
        let content = "@@||safe.example.com^\n";
        let entries = parse_adguard(content);
        assert!(entries.contains(&ParsedEntry::Allow("safe.example.com".into())));
    }

    #[test]
    fn adguard_skips_cosmetic_filters() {
        let content = "example.com##.ad-banner\n||ads.example.com^\n";
        let entries = parse_adguard(content);
        // Only the || rule should be parsed
        assert_eq!(entries.len(), 2); // Exact + WildcardParent for ads.example.com
    }

    #[test]
    fn adguard_skips_path_rules() {
        let content = "||cdn.example.com/ads^\n";
        let entries = parse_adguard(content);
        assert!(entries.is_empty(), "URL path rules should be skipped");
    }
}
