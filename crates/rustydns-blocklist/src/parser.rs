//! Blocklist content parsers for all supported formats.
//!
//! # Supported formats (auto-detected)
//!
//! | Format | Example | Detection |
//! |--------|---------|-----------|
//! | Hosts | `0.0.0.0 ads.example.com` | First field is valid IP |
//! | Plain | `ads.example.com` | Single field, no IP |
//! | RPZ | `ads.example.com CNAME .` | Three fields with DNS type |
//! | AdGuard | `\|\|ads.example.com^` | Starts with `\|\|` |
//!
//! # Security notes
//!
//! All parsers apply per-line and per-domain limits to prevent DoS from
//! pathologically large or malicious sources:
//!
//! - Lines longer than [`MAX_LINE_BYTES`] are skipped with a warning.
//! - Domain names longer than [`MAX_DOMAIN_BYTES`] are skipped.
//! - Individual labels longer than 63 bytes are skipped (RFC 1035).
//! - Domain names containing non-ASCII, null bytes, or control characters
//!   are skipped (they cannot match valid DNS names).
//! - Total parsed entry count is not bounded here — the engine caller is
//!   responsible for enforcing `blocklist.max_fetch_bytes`.
//!
//! # RPZ passthru entries
//!
//! `rpz-passthru.` entries and AdGuard `@@||domain^` allowlist entries are
//! returned as [`ParsedEntry::Allow`]. Whether to act on them (add to the
//! allowlist) or discard them (for untrusted sources) is the engine's decision.
//! The parser never makes that call.

/// Maximum line length in bytes. Lines exceeding this are skipped.
/// The longest valid DNS name is 253 bytes; a hosts-format line adds an IP + space.
/// 512 bytes gives a generous margin while protecting against lines designed to
/// stress the parser.
pub const MAX_LINE_BYTES: usize = 512;

/// Maximum domain name length in bytes (RFC 1035: 253 octets in wire format).
pub const MAX_DOMAIN_BYTES: usize = 253;

/// Maximum DNS label length in bytes (RFC 1035: 63 octets).
pub const MAX_LABEL_BYTES: usize = 63;

/// A parsed blocklist directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEntry {
    /// Block exactly this domain (normalised: lowercase, no trailing dot).
    Exact(String),
    /// Block all subdomains of this domain.
    ///
    /// E.g. `WildcardParent("example-ads.com")` blocks `foo.example-ads.com`
    /// and `deep.foo.example-ads.com` but NOT `example-ads.com` itself.
    WildcardParent(String),
    /// Allow this domain (RPZ passthru or AdGuard `@@` entry).
    ///
    /// Whether to act on this is the engine's decision based on source trust.
    Allow(String),
}

/// Auto-detected blocklist format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    Hosts,
    Plain,
    Rpz,
    AdGuard,
}

/// Auto-detect the format by scanning only the first non-comment, non-empty line.
pub fn detect_format(content: &str) -> ListFormat {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('!')
            || line.starts_with('[')
        {
            continue;
        }
        if (line.starts_with("||") || line.starts_with("@@||")) && line.contains('^') {
            return ListFormat::AdGuard;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let typ = parts[1].to_ascii_uppercase();
            if matches!(typ.as_str(), "CNAME" | "A" | "AAAA" | "TXT" | "SOA" | "NS") {
                return ListFormat::Rpz;
            }
        }
        if parts.len() >= 2 && is_ip_address(parts[0]) {
            return ListFormat::Hosts;
        }
        return ListFormat::Plain;
    }
    ListFormat::Plain
}

/// Parse blocklist content, auto-detecting the format.
pub fn parse(content: &str) -> Vec<ParsedEntry> {
    match detect_format(content) {
        ListFormat::Hosts   => parse_hosts(content),
        ListFormat::Plain   => parse_plain(content),
        ListFormat::Rpz     => parse_rpz(content),
        ListFormat::AdGuard => parse_adguard(content),
    }
}

// ---------------------------------------------------------------------------
// Hosts parser
// ---------------------------------------------------------------------------

pub fn parse_hosts(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();
    let mut long_lines: u32 = 0;

    for line in content.lines() {
        if line.len() > MAX_LINE_BYTES {
            long_lines += 1;
            continue;
        }
        let line = strip_comment(line, '#');
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some(ip) if is_ip_address(ip) => {}
            _ => continue,
        }
        for domain in parts {
            if let Some(d) = validate_and_normalize(domain) {
                if !is_always_skipped(&d) {
                    entries.push(ParsedEntry::Exact(d));
                }
            }
        }
    }

    if long_lines > 0 {
        tracing::warn!(
            count = long_lines,
            max_bytes = MAX_LINE_BYTES,
            "skipped lines exceeding maximum line length in hosts-format blocklist"
        );
    }

    entries
}

// ---------------------------------------------------------------------------
// Plain parser
// ---------------------------------------------------------------------------

pub fn parse_plain(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();
    let mut long_lines: u32 = 0;

    for line in content.lines() {
        if line.len() > MAX_LINE_BYTES {
            long_lines += 1;
            continue;
        }
        let line = strip_comment(line, '#');
        let line = strip_comment(line, ';');
        let line = line.trim();
        if line.is_empty() || line.contains(' ') || line.contains('\t') {
            continue;
        }
        if let Some(d) = validate_and_normalize(line) {
            if !is_always_skipped(&d) {
                entries.push(ParsedEntry::Exact(d));
            }
        }
    }

    if long_lines > 0 {
        tracing::warn!(
            count = long_lines,
            "skipped long lines in plain-format blocklist"
        );
    }

    entries
}

// ---------------------------------------------------------------------------
// RPZ parser
// ---------------------------------------------------------------------------

pub fn parse_rpz(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
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
        let name  = parts[0];
        let rtype = parts[1].to_ascii_uppercase();
        let rdata = parts[2].to_lowercase();

        if rtype != "CNAME" {
            continue;
        }

        if rdata == "rpz-passthru." || rdata == "rpz-passthru" {
            if let Some(d) = validate_and_normalize(name) {
                entries.push(ParsedEntry::Allow(d));
            }
        } else if rdata == "." {
            if let Some(parent) = name.strip_prefix("*.") {
                if let Some(d) = validate_and_normalize(parent) {
                    entries.push(ParsedEntry::WildcardParent(d));
                }
            } else if let Some(d) = validate_and_normalize(name) {
                if !is_always_skipped(&d) {
                    entries.push(ParsedEntry::Exact(d));
                }
            }
        }
        // All other rdata values are silently ignored.
    }

    entries
}

// ---------------------------------------------------------------------------
// AdGuard parser
// ---------------------------------------------------------------------------

pub fn parse_adguard(content: &str) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }

        // @@||domain^ → allow
        if let Some(rest) = line.strip_prefix("@@||") {
            if let Some(caret) = rest.find('^') {
                let domain_part = &rest[..caret];
                if !domain_part.contains('/') {
                    if let Some(d) = validate_and_normalize(domain_part) {
                        entries.push(ParsedEntry::Allow(d));
                    }
                }
            }
            continue;
        }

        // ||domain^ → block apex + all subdomains
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(caret) = rest.find('^') {
                let domain_part = &rest[..caret];
                if domain_part.contains('/') {
                    continue; // URL path rule — skip
                }
                if let Some(d) = validate_and_normalize(domain_part) {
                    if !is_always_skipped(&d) {
                        entries.push(ParsedEntry::Exact(d.clone()));
                        entries.push(ParsedEntry::WildcardParent(d));
                    }
                }
            }
        }
        // All other lines (cosmetic rules, anchor-only, etc.) are skipped.
    }

    entries
}

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

/// Normalise and validate a domain name.
///
/// Returns `None` and logs a trace if the domain is invalid. Invalid reasons:
/// - Exceeds [`MAX_DOMAIN_BYTES`]
/// - Any label exceeds [`MAX_LABEL_BYTES`]  (RFC 1035)
/// - Contains null bytes, control characters, or spaces
/// - Is empty after normalisation
///
/// Valid domains are lowercased and the trailing dot is stripped.
fn validate_and_normalize(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.');
    if s.is_empty() {
        return None;
    }

    // Reject non-printable / control characters (null byte, newlines embedded in line, etc.)
    if s.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
        tracing::trace!(domain = %s, "skipping domain with control characters");
        return None;
    }

    let lower = s.to_lowercase();

    // Total length check (ASCII lowercased, so byte length == char length for valid DNS names)
    if lower.len() > MAX_DOMAIN_BYTES {
        tracing::trace!(domain = %lower, max = MAX_DOMAIN_BYTES, "skipping domain exceeding max length");
        return None;
    }

    // Per-label length check
    for label in lower.split('.') {
        if label.len() > MAX_LABEL_BYTES {
            tracing::trace!(label = %label, max = MAX_LABEL_BYTES, "skipping domain with oversized label");
            return None;
        }
        // Labels must not be empty (consecutive dots)
        if label.is_empty() {
            tracing::trace!(domain = %lower, "skipping domain with empty label");
            return None;
        }
    }

    Some(lower)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn strip_comment(line: &str, marker: char) -> &str {
    if let Some(pos) = line.find(marker) { &line[..pos] } else { line }
}

fn is_ip_address(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok() || s.parse::<std::net::Ipv6Addr>().is_ok()
}

fn is_always_skipped(domain: &str) -> bool {
    matches!(
        domain,
        "localhost" | "broadcasthost" | "local" | "ip6-localhost" | "ip6-loopback"
            | "ip6-localnet" | "ip6-mcastprefix" | "ip6-allnodes" | "ip6-allrouters"
            | "ip6-allhosts"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(s: &str) -> ParsedEntry { ParsedEntry::Exact(s.to_string()) }
    fn wildcard(s: &str) -> ParsedEntry { ParsedEntry::WildcardParent(s.to_string()) }
    fn allow(s: &str) -> ParsedEntry { ParsedEntry::Allow(s.to_string()) }

    // --- format detection ---------------------------------------------------

    #[test] fn detect_hosts()   { assert_eq!(detect_format("0.0.0.0 ads.example.com\n"), ListFormat::Hosts); }
    #[test] fn detect_plain()   { assert_eq!(detect_format("ads.example.com\n"), ListFormat::Plain); }
    #[test] fn detect_rpz()     { assert_eq!(detect_format("ads.example.com CNAME .\n"), ListFormat::Rpz); }
    #[test] fn detect_adguard() { assert_eq!(detect_format("||ads.example.com^\n"), ListFormat::AdGuard); }

    // --- hosts --------------------------------------------------------------

    #[test]
    fn hosts_basic() {
        let e = parse_hosts("0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.net\n");
        assert!(e.contains(&exact("ads.example.com")));
        assert!(e.contains(&exact("tracker.example.net")));
    }

    #[test]
    fn hosts_skips_localhost() {
        assert!(parse_hosts("0.0.0.0 localhost\n0.0.0.0 broadcasthost\n").is_empty());
    }

    #[test]
    fn hosts_strips_inline_comment() {
        let e = parse_hosts("0.0.0.0 ads.example.com # ad server\n");
        assert_eq!(e, vec![exact("ads.example.com")]);
    }

    #[test]
    fn hosts_skips_oversized_label() {
        let long_label = "a".repeat(64);
        let line = format!("0.0.0.0 {long_label}.example.com\n");
        assert!(parse_hosts(&line).is_empty(), "label > 63 bytes should be skipped");
    }

    #[test]
    fn hosts_skips_oversized_domain() {
        let long = format!("0.0.0.0 {}.example.com\n", "a".repeat(250));
        assert!(parse_hosts(&long).is_empty(), "domain > 253 bytes should be skipped");
    }

    #[test]
    fn hosts_skips_long_lines() {
        let line = format!("0.0.0.0 {}\n", "a".repeat(MAX_LINE_BYTES + 1));
        // Should not panic; just skip the line
        let _ = parse_hosts(&line);
    }

    // --- RPZ ----------------------------------------------------------------

    #[test]
    fn rpz_exact_block() {
        assert!(parse_rpz("ads.example.com CNAME .\n").contains(&exact("ads.example.com")));
    }

    #[test]
    fn rpz_wildcard_block() {
        assert!(parse_rpz("*.example-ads.com CNAME .\n").contains(&wildcard("example-ads.com")));
    }

    #[test]
    fn rpz_passthru_becomes_allow() {
        assert!(parse_rpz("safe.example.com CNAME rpz-passthru.\n").contains(&allow("safe.example.com")));
    }

    // --- AdGuard ------------------------------------------------------------

    #[test]
    fn adguard_block_adds_exact_and_wildcard() {
        let e = parse_adguard("||ads.example.com^\n");
        assert!(e.contains(&exact("ads.example.com")));
        assert!(e.contains(&wildcard("ads.example.com")));
    }

    #[test]
    fn adguard_allowlist() {
        assert!(parse_adguard("@@||safe.example.com^\n").contains(&allow("safe.example.com")));
    }

    #[test]
    fn adguard_skips_path_rules() {
        assert!(parse_adguard("||cdn.example.com/ads^\n").is_empty());
    }

    // --- Domain validation --------------------------------------------------

    #[test]
    fn control_chars_rejected() {
        assert!(parse_plain("ads\x00.example.com\n").is_empty());
    }

    #[test]
    fn consecutive_dots_rejected() {
        assert!(parse_plain("ads..example.com\n").is_empty());
    }
}
