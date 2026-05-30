//! Linear-time regex block rules (TODO 8.7).
//!
//! Power users can supply regex patterns (`blocklist.regex_rules`) that block a
//! QNAME on match. The matcher is the `regex` crate — a finite-automata engine
//! with **linear-time** guarantees, so there is **no catastrophic backtracking
//! / ReDoS** even on adversarial operator patterns. Two extra bounds keep a
//! pathological config from blowing up startup:
//!
//! - each pattern is capped at [`crate::config::MAX_REGEX_PATTERN_LEN`] bytes,
//! - the rule set is capped at [`crate::config::MAX_REGEX_RULES`] patterns, and
//! - the compiled program is capped at 1 MiB (`RegexSetBuilder::size_limit`).
//!
//! Patterns are matched **case-insensitively** against the lowercased QNAME
//! (no trailing dot) in ASCII mode (domains are ASCII here — the `regex`
//! dependency is built without the Unicode tables to keep the binary small).

use regex::RegexSet;

use crate::config::{MAX_REGEX_PATTERN_LEN, MAX_REGEX_RULES};

/// A compiled set of QNAME regex block rules. Empty when no patterns are
/// configured. Cheap to clone (the compiled automaton is shared).
#[derive(Debug, Clone, Default)]
pub struct RegexRules {
    set: Option<RegexSet>,
}

impl RegexRules {
    /// Compile `patterns` into a [`RegexRules`].
    ///
    /// Enforces the count, length, and compiled-size bounds and returns a
    /// human-readable error (naming the offending rule) on any violation, so
    /// `validate_config` can reject a bad config at startup.
    pub fn compile(patterns: &[String]) -> Result<Self, String> {
        if patterns.is_empty() {
            return Ok(Self { set: None });
        }
        if patterns.len() > MAX_REGEX_RULES {
            return Err(format!(
                "{} regex rules exceeds the maximum of {MAX_REGEX_RULES}",
                patterns.len()
            ));
        }
        for (i, p) in patterns.iter().enumerate() {
            if p.len() > MAX_REGEX_PATTERN_LEN {
                return Err(format!(
                    "regex rule {i} is {} bytes, exceeding the maximum of {MAX_REGEX_PATTERN_LEN}",
                    p.len()
                ));
            }
        }
        let set = regex::RegexSetBuilder::new(patterns)
            .case_insensitive(true)
            // ASCII only — domains are ASCII and the dep is built without the
            // Unicode tables. Be explicit so an accidental Unicode class errors
            // at compile time rather than silently changing semantics.
            .unicode(false)
            // Bound the compiled program so a huge pattern set can't exhaust
            // memory at startup.
            .size_limit(1 << 20)
            .build()
            .map_err(|e| format!("invalid regex rule: {e}"))?;
        Ok(Self { set: Some(set) })
    }

    /// Returns `true` if `qname_lc` (lowercased, no trailing dot) matches any
    /// rule. Always `false` when no rules are configured.
    pub fn is_match(&self, qname_lc: &str) -> bool {
        match &self.set {
            Some(set) => set.is_match(qname_lc),
            None => false,
        }
    }

    /// Number of compiled patterns.
    pub fn len(&self) -> usize {
        self.set.as_ref().map_or(0, RegexSet::len)
    }

    /// Returns `true` if no rules are configured.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(patterns: &[&str]) -> RegexRules {
        RegexRules::compile(&patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn empty_matches_nothing() {
        let r = RegexRules::compile(&[]).unwrap();
        assert!(r.is_empty());
        assert!(!r.is_match("anything.example.com"));
    }

    #[test]
    fn simple_substring_match() {
        let r = rules(&["ads?-tracker"]);
        assert!(r.is_match("ad-tracker.example.com"));
        assert!(r.is_match("ads-tracker.example.net"));
        assert!(!r.is_match("safe.example.com"));
    }

    #[test]
    fn anchored_pattern() {
        let r = rules(&[r"^metrics\.[a-z0-9-]+\.example\.com$"]);
        assert!(r.is_match("metrics.app.example.com"));
        assert!(!r.is_match("notmetrics.app.example.com"));
        assert!(!r.is_match("metrics.app.example.com.evil.net"));
    }

    #[test]
    fn case_insensitive() {
        // The engine lowercases before matching, but case-insensitivity lets a
        // pattern written with uppercase still match.
        let r = rules(&["TRACKER"]);
        assert!(r.is_match("tracker.example.com"));
    }

    #[test]
    fn multiple_patterns_via_set() {
        let r = rules(&["doubleclick", "googlesyndication", r"\.ads\."]);
        assert!(r.is_match("doubleclick.net"));
        assert!(r.is_match("pagead2.googlesyndication.com"));
        assert!(r.is_match("foo.ads.example.com"));
        assert!(!r.is_match("example.org"));
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn invalid_pattern_rejected() {
        let err = RegexRules::compile(&["(unclosed".to_string()]).unwrap_err();
        assert!(err.contains("invalid regex rule"), "{err}");
    }

    #[test]
    fn overlong_pattern_rejected() {
        let long = "a".repeat(MAX_REGEX_PATTERN_LEN + 1);
        let err = RegexRules::compile(&[long]).unwrap_err();
        assert!(err.contains("exceeding the maximum"), "{err}");
    }

    #[test]
    fn too_many_patterns_rejected() {
        let many: Vec<String> = (0..=MAX_REGEX_RULES).map(|i| format!("p{i}")).collect();
        let err = RegexRules::compile(&many).unwrap_err();
        assert!(err.contains("exceeds the maximum"), "{err}");
    }
}
