//! Allowlist checked before the blocklist.
//!
//! The allowlist always wins: a domain that matches any allowlist entry is
//! **never** blocked, regardless of what blocklist sources say.
//!
//! # Entry formats
//!
//! - Exact: `"safe.ads.example.com"` — matches only that domain.
//! - Suffix wildcard:
//!   - `"*.example.com"` — matches any subdomain of `example.com`
//!     (e.g. `foo.example.com`, `bar.foo.example.com`), but NOT `example.com` itself.
//!   - `".example.com"` — same as `"*.example.com"` (leading-dot syntax).
//!
//! Entries are lowercased and trailing dots are stripped at load time.

use ahash::AHashSet;

/// Allowlist for the blocklist engine.
///
/// Constructed once from [`rustydns_core::config::BlocklistConfig::allowlist`] and
/// optionally augmented with `rpz-passthru.` entries found during blocklist parsing.
#[derive(Debug, Default, Clone)]
pub struct Allowlist {
    /// Exact domain matches (lowercased, no trailing dot).
    exact: AHashSet<String>,

    /// Suffix matches stored with a leading dot (e.g. `".example.com"`).
    ///
    /// To check a domain `"foo.bar.example.com"`, we walk up its label tree
    /// and check `".bar.example.com"`, `".example.com"`, `".com"`.
    suffixes: AHashSet<String>,
}

impl Allowlist {
    /// Build an `Allowlist` from a slice of config entries.
    ///
    /// Entries starting with `*.` or `.` are treated as suffix wildcards.
    /// All others are exact matches. All entries are lowercased.
    pub fn from_entries(entries: &[String]) -> Self {
        let mut exact = AHashSet::with_capacity(entries.len());
        let mut suffixes = AHashSet::new();

        for entry in entries {
            let entry = entry.trim().to_lowercase();
            let entry = entry.trim_end_matches('.');
            if entry.is_empty() {
                continue;
            }
            if let Some(rest) = entry.strip_prefix("*.") {
                // "*.example.com" → suffix ".example.com"
                suffixes.insert(format!(".{rest}"));
            } else if entry.starts_with('.') {
                // ".example.com" → suffix match (already has leading dot)
                suffixes.insert(entry.to_string());
            } else {
                exact.insert(entry.to_string());
            }
        }

        Self { exact, suffixes }
    }

    /// Extend this allowlist with additional exact-match entries.
    ///
    /// Used to incorporate `rpz-passthru.` entries discovered during blocklist
    /// parsing without rebuilding the entire allowlist.
    pub fn extend_exact(&mut self, entries: impl IntoIterator<Item = String>) {
        for entry in entries {
            let entry = entry.trim().trim_end_matches('.').to_lowercase();
            if !entry.is_empty() {
                self.exact.insert(entry);
            }
        }
    }

    /// Check whether `domain` is in the allowlist.
    ///
    /// `domain` may have a trailing dot (FQDN form); it is stripped before
    /// comparison. Comparison is case-insensitive (input is lowercased).
    ///
    /// This is called on every query that passes the authority check — it must
    /// be fast. It is allocation-free for ASCII names (the overwhelming common
    /// case): it lowercases into a stack-local `String` **only** when the input
    /// actually contains an uppercase ASCII byte, mirroring
    /// [`crate::engine`]'s `is_blocked` fast path. Since the engine already
    /// lowercases before calling this, the common path never allocates at all.
    #[inline]
    pub fn is_allowed(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return false;
        }

        // Lowercase without allocating for ASCII-only-or-already-lowercase
        // names. Only mixed-case input pays a single allocation.
        let lower_buf: String;
        let domain = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lower_buf = domain.to_ascii_lowercase();
            lower_buf.as_str()
        } else {
            domain
        };

        // Fast path: exact match (O(1) hash lookup).
        if self.exact.contains(domain) {
            return true;
        }

        // Suffix walk: for "foo.bar.example.com", check:
        //   ".bar.example.com"  → check
        //   ".example.com"      → check
        //   ".com"              → check
        // We never check "" (root), which would allow everything.
        let mut rest = domain;
        while let Some(dot_pos) = rest.find('.') {
            rest = &rest[dot_pos..]; // includes the leading dot
            if self.suffixes.contains(rest) {
                return true;
            }
            rest = &rest[1..]; // advance past the dot for next iteration
        }

        false
    }

    /// Total number of allowlist entries (exact + suffix).
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    /// Returns `true` if the allowlist has no entries.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(entries: &[&str]) -> Allowlist {
        Allowlist::from_entries(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn exact_match() {
        let a = allow(&["safe.ads.example.com"]);
        assert!(a.is_allowed("safe.ads.example.com"));
        assert!(!a.is_allowed("other.ads.example.com"));
        assert!(!a.is_allowed("example.com"));
    }

    #[test]
    fn exact_match_strips_trailing_dot() {
        let a = allow(&["safe.example.com."]);
        assert!(a.is_allowed("safe.example.com"));
        assert!(a.is_allowed("safe.example.com."));
    }

    #[test]
    fn wildcard_prefix_syntax() {
        let a = allow(&["*.example.com"]);
        assert!(a.is_allowed("foo.example.com"));
        assert!(a.is_allowed("bar.foo.example.com"));
        // "*.example.com" does NOT match the apex
        assert!(!a.is_allowed("example.com"));
    }

    #[test]
    fn leading_dot_syntax() {
        let a = allow(&[".example.com"]);
        assert!(a.is_allowed("foo.example.com"));
        assert!(a.is_allowed("deep.nested.foo.example.com"));
        assert!(!a.is_allowed("example.com"));
    }

    #[test]
    fn case_insensitive() {
        let a = allow(&["Safe.Example.COM"]);
        assert!(a.is_allowed("safe.example.com"));
        assert!(a.is_allowed("SAFE.EXAMPLE.COM"));
    }

    #[test]
    fn empty_input_never_allowed() {
        let a = allow(&[]);
        assert!(!a.is_allowed(""));
        assert!(!a.is_allowed("."));
    }

    #[test]
    fn extend_exact_adds_entries() {
        let mut a = allow(&["existing.com"]);
        a.extend_exact(["added.com".to_string()]);
        assert!(a.is_allowed("existing.com"));
        assert!(a.is_allowed("added.com"));
    }
}
