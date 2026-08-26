//! Dependency-free IP/CIDR matcher for **response-IP blocking** (TODO 8.3).
//!
//! Blocks a query whose resolved A/AAAA rdata falls inside an operator-supplied
//! IP or CIDR range (known malware C2, ad-network ranges, …). This complements
//! the rebinding defence (`upstream.block_private_rdata`, which strips
//! *private* rdata) by letting operators name *arbitrary* bad ranges.
//!
//! We implement CIDR matching by hand rather than pull in a crate: the logic is
//! a few lines of masking and keeping the dependency surface minimal is a
//! project goal. Entries are validated at config load and matched in O(rules)
//! per resolved address (rule sets are operator-sized).

use std::net::IpAddr;

/// A parsed CIDR (or single host) entry, split by address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cidr {
    /// IPv4 `(network, mask)` — both pre-masked.
    V4 { network: u32, mask: u32 },
    /// IPv6 `(network, mask)` — both pre-masked.
    V6 { network: u128, mask: u128 },
}

/// An operator-supplied denylist of IPs / CIDR ranges, matched against the
/// resolved rdata of upstream answers.
#[derive(Debug, Clone, Default)]
pub struct IpDenylist {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpDenylist {
    /// Parse a list of `"addr"` or `"addr/prefix"` entries. A bare address is
    /// treated as a single host (`/32` or `/128`). Returns the offending entry
    /// in the error so `validate_config` can surface a precise message.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for entry in entries {
            match parse_entry(entry)? {
                Cidr::V4 { network, mask } => v4.push((network, mask)),
                Cidr::V6 { network, mask } => v6.push((network, mask)),
            }
        }
        Ok(Self { v4, v6 })
    }

    /// Returns `true` if `ip` falls inside any configured range.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped before
    /// matching, so an upstream cannot dodge a v4 range by answering with the
    /// mapped form as AAAA rdata — the same pivot `is_private_or_internal_v6`
    /// closes for the rebinding defence. A mapped address is classified by the
    /// IPv4 predicate only; configure v4 ranges to catch it.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        };
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                self.v4.iter().any(|(net, mask)| (bits & mask) == *net)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                self.v6.iter().any(|(net, mask)| (bits & mask) == *net)
            }
        }
    }

    /// Total number of ranges (v4 + v6).
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Returns `true` if there are no ranges configured.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

fn parse_entry(entry: &str) -> Result<Cidr, String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err("empty response-IP denylist entry".to_string());
    }
    let (addr_part, prefix_part) = match entry.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (entry, None),
    };
    let ip: IpAddr = addr_part
        .parse()
        .map_err(|_| format!("`{entry}` is not a valid IP address"))?;

    match ip {
        IpAddr::V4(v4) => {
            let prefix = parse_prefix(prefix_part, 32, entry)?;
            let bits = u32::from(v4);
            // prefix==0 → mask 0 (matches everything); avoid the `<< 32` UB.
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok(Cidr::V4 {
                network: bits & mask,
                mask,
            })
        }
        IpAddr::V6(v6) => {
            let prefix = parse_prefix(prefix_part, 128, entry)?;
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Ok(Cidr::V6 {
                network: bits & mask,
                mask,
            })
        }
    }
}

fn parse_prefix(prefix_part: Option<&str>, max: u8, entry: &str) -> Result<u8, String> {
    match prefix_part {
        None => Ok(max),
        Some(p) => {
            let prefix: u8 = p
                .parse()
                .map_err(|_| format!("`{entry}` has an invalid prefix length"))?;
            if prefix > max {
                return Err(format!(
                    "`{entry}` prefix length {prefix} exceeds the maximum of {max} for its address family"
                ));
            }
            Ok(prefix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> IpDenylist {
        IpDenylist::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn single_host_v4_matches_exactly() {
        let d = list(&["5.6.7.8"]);
        assert!(d.contains("5.6.7.8".parse().unwrap()));
        assert!(!d.contains("5.6.7.9".parse().unwrap()));
    }

    #[test]
    fn cidr_v4_matches_range() {
        let d = list(&["1.2.3.0/24"]);
        assert!(d.contains("1.2.3.1".parse().unwrap()));
        assert!(d.contains("1.2.3.254".parse().unwrap()));
        assert!(!d.contains("1.2.4.1".parse().unwrap()));
    }

    #[test]
    fn cidr_v4_slash_zero_matches_all_v4() {
        let d = list(&["0.0.0.0/0"]);
        assert!(d.contains("8.8.8.8".parse().unwrap()));
        assert!(d.contains("203.0.113.1".parse().unwrap()));
        // does NOT match v6
        assert!(!d.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_matches_range() {
        let d = list(&["2001:db8::/32"]);
        assert!(d.contains("2001:db8::1".parse().unwrap()));
        assert!(d.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!d.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn single_host_v6() {
        let d = list(&["2606:4700::1111"]);
        assert!(d.contains("2606:4700::1111".parse().unwrap()));
        assert!(!d.contains("2606:4700::1112".parse().unwrap()));
    }

    #[test]
    fn mixed_families() {
        let d = list(&["10.0.0.0/8", "fc00::/7"]);
        assert!(d.contains("10.1.2.3".parse().unwrap()));
        assert!(d.contains("fd12::1".parse().unwrap()));
        assert!(!d.contains("11.0.0.1".parse().unwrap()));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn empty_denylist_matches_nothing() {
        let d = IpDenylist::default();
        assert!(d.is_empty());
        assert!(!d.contains("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn bad_ip_rejected() {
        let err = IpDenylist::parse(&["not-an-ip".to_string()]).unwrap_err();
        assert!(err.contains("not a valid IP"), "{err}");
    }

    #[test]
    fn bad_prefix_rejected() {
        let err = IpDenylist::parse(&["1.2.3.0/33".to_string()]).unwrap_err();
        assert!(err.contains("exceeds the maximum"), "{err}");
        let err = IpDenylist::parse(&["2001:db8::/129".to_string()]).unwrap_err();
        assert!(err.contains("exceeds the maximum"), "{err}");
    }

    #[test]
    fn non_numeric_prefix_rejected() {
        let err = IpDenylist::parse(&["1.2.3.0/foo".to_string()]).unwrap_err();
        assert!(err.contains("invalid prefix"), "{err}");
    }

    #[test]
    fn ipv4_mapped_v6_form_matches_v4_ranges() {
        // A hostile upstream can dodge a v4 denylist by answering with the
        // IPv4-mapped form (`::ffff:a.b.c.d`) as AAAA rdata — the address
        // family tag alone must not decide which rule set is consulted.
        let d = list(&["10.0.0.0/8", "5.6.7.8"]);
        assert!(d.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(d.contains("::ffff:5.6.7.8".parse().unwrap()));
        // Distinct v4 outside the range stays out, even in mapped form.
        assert!(!d.contains("::ffff:11.0.0.1".parse().unwrap()));
        // Genuine (non-mapped) v6 is untouched by v4 rules.
        assert!(!d.contains("2001:db8::1".parse().unwrap()));
        // v6 rules still match genuine v6 in the same list.
        let d6 = list(&["fc00::/7"]);
        assert!(d6.contains("fd12::1".parse().unwrap()));
        assert!(!d6.contains("::ffff:10.1.2.3".parse().unwrap()));
    }
}
