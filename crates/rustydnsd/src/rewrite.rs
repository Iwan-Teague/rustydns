#![forbid(unsafe_code)]

//! DNS rewrite / local cloaking map (TODO 8.2).
//!
//! A config-driven map (`[[rewrite]]`) that pins a name **outside** the
//! authority zones to a local answer: an IP (synthesised A/AAAA), a CNAME
//! target, or NXDOMAIN. This is AdGuard's "DNS rewrites" and dnscrypt-proxy's
//! "cloaking" — pin an internal service, override a CDN to a LAN address, or
//! blackhole a domain without maintaining a blocklist.
//!
//! # Pipeline position
//!
//! Consulted **after** the authority (authority always wins for names in its
//! own zones) and **before** the blocklist and resolver. Rewrites are
//! operator-defined local overrides, so they apply to every client regardless
//! of `blocklist_bypass`.
//!
//! ```text
//! query → Authority → Rewrite → Blocklist → Resolver
//! ```

use std::collections::HashMap;
use std::net::IpAddr;

use hickory_proto::rr::RecordType;

use rustydns_core::config::RewriteRule;
use rustydns_core::record::{DnsRecord, RecordData, STATIC_RECORD_TTL};

/// Compiled action for a matched rewrite.
#[derive(Debug, Clone)]
enum Action {
    /// Synthesise an A/AAAA answer for the matching query type.
    Address(IpAddr),
    /// Synthesise a CNAME to this (normalised, FQDN) target.
    Cname(String),
    /// Blackhole the name — NXDOMAIN for every type.
    Block,
}

/// The decision a rewrite lookup reached for a `(name, qtype)` pair.
#[derive(Debug, Clone)]
pub enum RewriteDecision {
    /// Answer with these synthesised records (NoError).
    Answer(Vec<DnsRecord>),
    /// The name is owned by a rewrite but has no record of the requested type
    /// (NoError, empty) — e.g. an A-pinned name queried for AAAA. The pinned
    /// name never falls through to the resolver, so it cannot leak upstream.
    NoData,
    /// Blackhole — return NXDOMAIN.
    Nxdomain,
}

/// In-memory rewrite map built from `[[rewrite]]` config. Cheap to build and
/// to query; the rule set is operator-sized (tens, not millions).
#[derive(Debug, Default)]
pub struct RewriteMap {
    /// Exact matches, keyed by lowercased name without trailing dot.
    exact: HashMap<String, Action>,
    /// Wildcard suffixes as `(".example.com", action)`, sorted longest-first
    /// so the most specific wildcard wins.
    suffixes: Vec<(String, Action)>,
}

impl RewriteMap {
    /// Build a [`RewriteMap`] from validated config rules.
    ///
    /// `validate_config` has already rejected malformed rules (no action,
    /// multiple actions, bad address, TLD-level wildcard); any that slip
    /// through are skipped defensively rather than panicking.
    pub fn from_rules(rules: &[RewriteRule]) -> Self {
        let mut exact: HashMap<String, Action> = HashMap::new();
        let mut suffixes: Vec<(String, Action)> = Vec::new();

        for rule in rules {
            let action = if let Some(addr) = &rule.address {
                match addr.parse::<IpAddr>() {
                    Ok(ip) => Action::Address(ip),
                    Err(_) => continue,
                }
            } else if let Some(target) = &rule.target {
                Action::Cname(normalise_fqdn(target))
            } else if rule.block {
                Action::Block
            } else {
                continue;
            };

            let name = rule.name.trim();
            if let Some(rest) = name.strip_prefix("*.") {
                suffixes.push((format!(".{}", lower_no_dot(rest)), action));
            } else if let Some(rest) = name.strip_prefix('.') {
                suffixes.push((format!(".{}", lower_no_dot(rest)), action));
            } else {
                exact.insert(lower_no_dot(name), action);
            }
        }

        suffixes.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        Self { exact, suffixes }
    }

    /// Number of rules (exact + wildcard).
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    /// Returns `true` if there are no rewrite rules.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }

    /// Look up `qname_canon` (lowercased, trailing-dot FQDN) for `qtype`.
    /// Returns `None` if no rule matches (the pipeline then continues to the
    /// blocklist / resolver). Exact matches win over wildcards.
    pub fn lookup(&self, qname_canon: &str, qtype: RecordType) -> Option<RewriteDecision> {
        let key = qname_canon.trim_end_matches('.');
        if key.is_empty() {
            return None;
        }

        if let Some(action) = self.exact.get(key) {
            return Some(decide(action, qname_canon, qtype));
        }
        // Suffixes are sorted longest-first → first match is the most specific.
        // The leading dot in the stored suffix ensures `*.example.com` matches
        // `foo.example.com` but neither the apex `example.com` nor an
        // unrelated `evilexample.com`.
        for (suffix, action) in &self.suffixes {
            if key.ends_with(suffix.as_str()) {
                return Some(decide(action, qname_canon, qtype));
            }
        }
        None
    }
}

/// Resolve a matched [`Action`] into a [`RewriteDecision`] for `qtype`.
fn decide(action: &Action, qname_canon: &str, qtype: RecordType) -> RewriteDecision {
    match action {
        Action::Block => RewriteDecision::Nxdomain,
        Action::Cname(target) => RewriteDecision::Answer(vec![DnsRecord::new(
            qname_canon,
            RecordData::Cname(target.clone()),
            STATIC_RECORD_TTL,
        )]),
        Action::Address(ip) => match (ip, qtype) {
            (IpAddr::V4(v4), RecordType::A | RecordType::ANY) => {
                RewriteDecision::Answer(vec![DnsRecord::new(
                    qname_canon,
                    RecordData::A(*v4),
                    STATIC_RECORD_TTL,
                )])
            }
            (IpAddr::V6(v6), RecordType::AAAA | RecordType::ANY) => {
                RewriteDecision::Answer(vec![DnsRecord::new(
                    qname_canon,
                    RecordData::Aaaa(*v6),
                    STATIC_RECORD_TTL,
                )])
            }
            // Pinned name, wrong address family or unrelated type → NODATA so
            // the name never leaks upstream.
            _ => RewriteDecision::NoData,
        },
    }
}

/// Lowercase, strip the trailing dot.
fn lower_no_dot(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Lowercase and ensure a trailing dot (FQDN form for a CNAME target).
fn normalise_fqdn(s: &str) -> String {
    let mut n = s.trim().to_ascii_lowercase();
    if !n.ends_with('.') {
        n.push('.');
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, address: Option<&str>, target: Option<&str>, block: bool) -> RewriteRule {
        RewriteRule {
            name: name.to_string(),
            address: address.map(str::to_string),
            target: target.map(str::to_string),
            block,
        }
    }

    fn a_addr(records: &[DnsRecord]) -> String {
        match &records[0].data {
            RecordData::A(ip) => ip.to_string(),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn exact_address_rewrite_answers_matching_type() {
        let map = RewriteMap::from_rules(&[rule(
            "grafana.corp.example.com",
            Some("10.0.0.20"),
            None,
            false,
        )]);
        match map
            .lookup("grafana.corp.example.com.", RecordType::A)
            .unwrap()
        {
            RewriteDecision::Answer(recs) => {
                assert_eq!(recs.len(), 1);
                assert_eq!(a_addr(&recs), "10.0.0.20");
                assert_eq!(recs[0].name, "grafana.corp.example.com.");
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn address_rewrite_wrong_family_is_nodata() {
        // A-pinned name queried for AAAA → NODATA (never forwarded upstream).
        let map =
            RewriteMap::from_rules(&[rule("pinned.example.com", Some("10.0.0.20"), None, false)]);
        assert!(matches!(
            map.lookup("pinned.example.com.", RecordType::AAAA),
            Some(RewriteDecision::NoData)
        ));
        // A TXT query for a pinned name is also NODATA.
        assert!(matches!(
            map.lookup("pinned.example.com.", RecordType::TXT),
            Some(RewriteDecision::NoData)
        ));
    }

    #[test]
    fn any_query_returns_address_record() {
        let map =
            RewriteMap::from_rules(&[rule("svc.example.com", Some("2001:db8::1"), None, false)]);
        match map.lookup("svc.example.com.", RecordType::ANY).unwrap() {
            RewriteDecision::Answer(recs) => match &recs[0].data {
                RecordData::Aaaa(ip) => assert_eq!(ip.to_string(), "2001:db8::1"),
                other => panic!("expected AAAA, got {other:?}"),
            },
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn block_rewrite_is_nxdomain_for_all_types() {
        let map = RewriteMap::from_rules(&[rule("telemetry.vendor.example", None, None, true)]);
        assert!(matches!(
            map.lookup("telemetry.vendor.example.", RecordType::A),
            Some(RewriteDecision::Nxdomain)
        ));
        assert!(matches!(
            map.lookup("telemetry.vendor.example.", RecordType::AAAA),
            Some(RewriteDecision::Nxdomain)
        ));
    }

    #[test]
    fn cname_rewrite_answers_with_cname_for_any_type() {
        let map = RewriteMap::from_rules(&[rule(
            "cdn.example.com",
            None,
            Some("internal-cdn.lan"),
            false,
        )]);
        match map.lookup("cdn.example.com.", RecordType::A).unwrap() {
            RewriteDecision::Answer(recs) => match &recs[0].data {
                RecordData::Cname(t) => assert_eq!(t, "internal-cdn.lan."),
                other => panic!("expected CNAME, got {other:?}"),
            },
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_matches_subdomains_not_apex() {
        let map = RewriteMap::from_rules(&[rule("*.ads.example.com", None, None, true)]);
        // subdomain → blocked
        assert!(matches!(
            map.lookup("pixel.ads.example.com.", RecordType::A),
            Some(RewriteDecision::Nxdomain)
        ));
        assert!(matches!(
            map.lookup("a.b.ads.example.com.", RecordType::A),
            Some(RewriteDecision::Nxdomain)
        ));
        // apex → NOT matched (wildcard excludes apex)
        assert!(map.lookup("ads.example.com.", RecordType::A).is_none());
        // unrelated name that merely shares a trailing label → NOT matched
        assert!(map.lookup("notads.example.com.", RecordType::A).is_none());
    }

    #[test]
    fn exact_wins_over_wildcard() {
        let map = RewriteMap::from_rules(&[
            rule("*.example.com", None, None, true),
            rule("safe.example.com", Some("10.0.0.9"), None, false),
        ]);
        // exact rule answers with the address, not the wildcard's block
        match map.lookup("safe.example.com.", RecordType::A).unwrap() {
            RewriteDecision::Answer(recs) => assert_eq!(a_addr(&recs), "10.0.0.9"),
            other => panic!("exact must win over wildcard, got {other:?}"),
        }
        // a different subdomain still hits the wildcard block
        assert!(matches!(
            map.lookup("other.example.com.", RecordType::A),
            Some(RewriteDecision::Nxdomain)
        ));
    }

    #[test]
    fn no_match_returns_none() {
        let map =
            RewriteMap::from_rules(&[rule("pinned.example.com", Some("10.0.0.1"), None, false)]);
        assert!(
            map.lookup("unrelated.example.org.", RecordType::A)
                .is_none()
        );
    }

    #[test]
    fn case_insensitive_match() {
        let map =
            RewriteMap::from_rules(&[rule("Pinned.Example.COM", Some("10.0.0.1"), None, false)]);
        assert!(map.lookup("pinned.example.com.", RecordType::A).is_some());
    }

    #[test]
    fn empty_map_matches_nothing() {
        let map = RewriteMap::from_rules(&[]);
        assert!(map.is_empty());
        assert!(map.lookup("anything.example.com.", RecordType::A).is_none());
    }
}
