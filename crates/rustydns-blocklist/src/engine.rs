//! Blocklist engine: O(1) lookup, lock-free hot-reload, RPZ passthru isolation.
//!
//! # RPZ passthru injection protection
//!
//! A compromised blocklist CDN could inject `rpz-passthru.` entries or AdGuard
//! `@@||domain^` entries to permanently allowlist itself. The engine prevents
//! this by only acting on [`ParsedEntry::Allow`] entries from *trusted* sources.
//!
//! Sources are classified at load time:
//! - `BlocklistSource::Trusted` — local files and URLs in `trusted_rpz_sources`.
//!   Allow entries are added to the allowlist.
//! - `BlocklistSource::Untrusted` — all other remote URLs.
//!   Allow entries are **logged as warnings and discarded**.
//!
//! # Lock-free hot-reload
//!
//! State is stored behind an [`ArcSwap`]. Reads (the query hot path) are
//! entirely lock-free. Reloads build a new state off the hot path, then
//! atomically swap the pointer. Readers in flight see either the old or new
//! state, never a partial one.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use ahash::AHashSet;
use arc_swap::ArcSwap;
use tracing::{error, info, warn};

use rustydns_core::config::BlocklistConfig;
use rustydns_core::{IpDenylist, RegexRules};

use crate::allowlist::Allowlist;
use crate::parser::{ParsedEntry, parse};

/// Whether a blocklist source is trusted to provide allowlist/passthru entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistSource {
    /// Local file or URL in `trusted_rpz_sources`. Allow entries are honoured.
    Trusted,
    /// Remote URL not in `trusted_rpz_sources`. Allow entries are discarded.
    Untrusted,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct BlocklistState {
    domains: AHashSet<String>,
    wildcard_parents: AHashSet<String>,
    allowlist: Allowlist,
    /// Compiled regex block rules (startup-fixed; cloned in from the engine on
    /// every reload so the allowlist-wins ordering in `is_blocked` holds).
    regex_rules: RegexRules,
    entry_count: usize,
    heap_bytes: usize,
    loaded_at: SystemTime,
    untrusted_allows_discarded: u32,
}

impl BlocklistState {
    fn new_empty(allowlist: Allowlist) -> Self {
        Self {
            domains: AHashSet::new(),
            wildcard_parents: AHashSet::new(),
            allowlist,
            regex_rules: RegexRules::default(),
            entry_count: 0,
            heap_bytes: 0,
            loaded_at: SystemTime::now(),
            untrusted_allows_discarded: 0,
        }
    }

    /// Check whether `domain` is blocked.
    ///
    /// Pipeline (all without allocation for the common path):
    /// 1. Allowlist — if allowed, return false immediately.
    /// 2. Exact match.
    /// 3. Wildcard parent walk.
    fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return false;
        }

        // Lowercase without allocating for ASCII-only names (the vast majority).
        let domain_lc: String;
        let domain = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            domain_lc = domain.to_lowercase();
            &domain_lc
        } else {
            domain
        };

        if self.allowlist.is_allowed(domain) {
            return false;
        }

        if self.domains.contains(domain) {
            return true;
        }

        // Walk up the label tree checking wildcard parents.
        let mut rest = domain;
        while let Some(dot_pos) = rest.find('.') {
            rest = &rest[dot_pos + 1..];
            if self.wildcard_parents.contains(rest) {
                return true;
            }
        }

        // Regex rules last (the exact/wildcard sets are O(1) and far more
        // common; the allowlist above already short-circuited an allowed name,
        // so the allowlist still wins over a regex match).
        self.regex_rules.is_match(domain)
    }
}

// ---------------------------------------------------------------------------
// Public engine
// ---------------------------------------------------------------------------

/// The blocklist engine.
///
/// All public methods are thread-safe. `is_blocked` is lock-free and
/// allocation-free for the common case.
pub struct BlocklistEngine {
    state: ArcSwap<BlocklistState>,
    config: BlocklistConfig,
    /// Parsed response-IP denylist (startup-fixed, like the blocklist sources).
    response_ip_denylist: IpDenylist,
    /// Compiled regex block rules (startup-fixed). Cloned into each new
    /// [`BlocklistState`] on reload (cheap — the automaton is shared).
    regex_rules: RegexRules,
    /// Per-client blocklist groups (TODO 8.6): one swappable state per named
    /// `[[blocklist.groups]]` entry. A client assigned to a group is matched
    /// against its state instead of the global `state`. The global regex rules
    /// still apply (cloned into each group state).
    groups: HashMap<String, ArcSwap<BlocklistState>>,
}

impl BlocklistEngine {
    /// Create a new engine from config with an empty blocklist.
    pub fn new(config: BlocklistConfig) -> Self {
        let allowlist = Allowlist::from_entries(&config.allowlist);
        // `validate_config` already rejected malformed entries; parse/compile
        // defensively and fall back to empty on the can't-happen error path
        // rather than panicking.
        let response_ip_denylist = match IpDenylist::parse(&config.response_ip_denylist) {
            Ok(d) => d,
            Err(e) => {
                error!(
                    error = %e,
                    "invalid blocklist.response_ip_denylist — response-IP blocking disabled"
                );
                IpDenylist::default()
            }
        };
        let regex_rules = match RegexRules::compile(&config.regex_rules) {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "invalid blocklist.regex_rules — regex blocking disabled");
                RegexRules::default()
            }
        };
        let mut initial = BlocklistState::new_empty(allowlist);
        initial.regex_rules = regex_rules.clone();
        // One empty state per configured group; content is filled by the loader.
        let groups: HashMap<String, ArcSwap<BlocklistState>> = config
            .groups
            .iter()
            .map(|g| {
                let mut st = BlocklistState::new_empty(Allowlist::from_entries(&g.allowlist));
                st.regex_rules = regex_rules.clone();
                (g.name.clone(), ArcSwap::from_pointee(st))
            })
            .collect();
        Self {
            state: ArcSwap::from_pointee(initial),
            config,
            response_ip_denylist,
            regex_rules,
            groups,
        }
    }

    /// Build a [`BlocklistState`] from `sources` using `allowlist_entries` as
    /// the base allowlist. `label` names the set in log output (`"default"` or
    /// a group name). Shared by the global loader and the per-group loader.
    fn build_state(
        &self,
        sources: &[(&str, BlocklistSource)],
        allowlist_entries: &[String],
        label: &str,
    ) -> BlocklistState {
        let mut state = BlocklistState::new_empty(Allowlist::from_entries(allowlist_entries));
        let mut trusted_allows: Vec<String> = Vec::new();

        for (content, trust) in sources {
            for entry in parse(content) {
                match entry {
                    ParsedEntry::Exact(d) => {
                        state.domains.insert(d);
                    }
                    ParsedEntry::WildcardParent(p) => {
                        state.wildcard_parents.insert(p);
                    }
                    ParsedEntry::Allow(d) => match trust {
                        BlocklistSource::Trusted => {
                            trusted_allows.push(d);
                        }
                        BlocklistSource::Untrusted => {
                            state.untrusted_allows_discarded += 1;
                            warn!(
                                domain = %d,
                                "discarded allowlist/passthru entry from untrusted blocklist \
                                 source — add the source URL to `blocklist.trusted_rpz_sources` \
                                 if this is intentional"
                            );
                        }
                    },
                }
            }
        }

        if !trusted_allows.is_empty() {
            state.allowlist.extend_exact(trusted_allows);
        }

        // Carry the (startup-fixed) regex rules into the new state so a
        // content reload doesn't drop them.
        state.regex_rules = self.regex_rules.clone();

        state.entry_count = state.domains.len() + state.wildcard_parents.len();
        // ~30 bytes average domain + ~50 bytes AHashSet overhead per entry
        state.heap_bytes = state.entry_count * 80;

        info!(
            group = %label,
            exact = state.domains.len(),
            wildcards = state.wildcard_parents.len(),
            total = state.entry_count,
            heap_kib = state.heap_bytes / 1024,
            allowlist = state.allowlist.len(),
            untrusted_allows_discarded = state.untrusted_allows_discarded,
            "blocklist loaded"
        );

        if state.heap_bytes > 100 * 1024 * 1024 {
            warn!(
                heap_mib = state.heap_bytes / (1024 * 1024),
                "blocklist heap usage exceeds 100 MiB — may OOM Pi Zero 2 W (512 MiB total RAM)"
            );
        }

        if state.untrusted_allows_discarded > 0 {
            warn!(
                count = state.untrusted_allows_discarded,
                "untrusted blocklist sources contained allowlist/passthru entries that were \
                 discarded. If these are legitimate, add the source URL to \
                 `blocklist.trusted_rpz_sources`."
            );
        }

        state
    }

    /// Load and merge multiple blocklist sources into the **global** state.
    ///
    /// Each source is paired with a [`BlocklistSource`] trust level. Allow
    /// entries from untrusted sources are discarded with a warning; allow
    /// entries from trusted sources are added to the allowlist.
    ///
    /// All sources are processed before the atomic state swap — exactly one
    /// swap per reload regardless of source count.
    pub fn load_many_with_trust(&self, sources: &[(&str, BlocklistSource)]) {
        let state = self.build_state(sources, &self.config.allowlist, "default");
        self.state.store(Arc::new(state));
    }

    /// Load sources into a named per-client group's state (TODO 8.6). No-op
    /// (with a warning) if `group` is not a configured group.
    pub fn load_group(
        &self,
        group: &str,
        sources: &[(&str, BlocklistSource)],
        allowlist_entries: &[String],
    ) {
        match self.groups.get(group) {
            Some(slot) => {
                let state = self.build_state(sources, allowlist_entries, group);
                slot.store(Arc::new(state));
            }
            None => warn!(
                group,
                "load_group called for an unknown blocklist group — ignoring"
            ),
        }
    }

    /// Convenience: load a single content string, treated as untrusted.
    pub fn load(&self, content: &str) {
        self.load_many_with_trust(&[(content, BlocklistSource::Untrusted)]);
    }

    /// Convenience: load a single trusted content string.
    pub fn load_trusted(&self, content: &str) {
        self.load_many_with_trust(&[(content, BlocklistSource::Trusted)]);
    }

    /// Returns `true` if `domain` is blocked by the **global** blocklist.
    ///
    /// Lock-free, allocation-free for the common case. Hot path.
    #[inline]
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.is_blocked_for_group(domain, None)
    }

    /// Returns `true` if `domain` is blocked for a client in `group` (TODO
    /// 8.6). `None`, or an unknown group name, falls back to the global
    /// blocklist. Lock-free; the group lookup is a single `HashMap` get.
    #[inline]
    pub fn is_blocked_for_group(&self, domain: &str, group: Option<&str>) -> bool {
        match group.and_then(|g| self.groups.get(g)) {
            Some(slot) => slot.load().is_blocked(domain),
            None => self.state.load().is_blocked(domain),
        }
    }

    /// Names of the configured blocklist groups (for the loader to iterate).
    pub fn group_names(&self) -> Vec<String> {
        self.groups.keys().cloned().collect()
    }

    /// Number of blocking entries currently loaded (exact + wildcard).
    pub fn entry_count(&self) -> usize {
        self.state.load().entry_count
    }
    /// Approximate heap usage of the blocklist state, in bytes.
    pub fn heap_bytes(&self) -> usize {
        self.state.load().heap_bytes
    }
    /// Wall-clock time at which the current state was loaded.
    pub fn loaded_at(&self) -> SystemTime {
        self.state.load().loaded_at
    }

    /// Configured response code for a blocked query.
    pub fn block_response(&self) -> rustydns_core::config::BlockResponse {
        self.config.block_response
    }
    /// Configured sinkhole IP (only used when `block_response = "sinkhole"`).
    pub fn sinkhole_ip(&self) -> &str {
        &self.config.sinkhole_ip
    }

    /// Whether CNAME-cloaking defence is enabled (`blocklist.block_cname_cloaking`).
    pub fn block_cname_cloaking(&self) -> bool {
        self.config.block_cname_cloaking
    }

    /// Whether any response-IP denylist range is configured. Cheap guard so
    /// the handler skips per-record checks when the feature is unused.
    pub fn response_ip_denylist_active(&self) -> bool {
        !self.response_ip_denylist.is_empty()
    }

    /// Returns `true` if `ip` (a resolved A/AAAA rdata) is on the
    /// response-IP denylist.
    pub fn is_response_ip_blocked(&self, ip: IpAddr) -> bool {
        self.response_ip_denylist.contains(ip)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustydns_core::config::BlocklistConfig;

    fn engine() -> BlocklistEngine {
        BlocklistEngine::new(BlocklistConfig::default())
    }

    fn load(content: &str) -> BlocklistEngine {
        let e = engine();
        e.load(content);
        e
    }

    #[test]
    fn blocks_exact() {
        assert!(load("0.0.0.0 ads.example.com\n").is_blocked("ads.example.com"));
    }

    #[test]
    fn does_not_block_unrelated() {
        let e = load("0.0.0.0 ads.example.com\n");
        assert!(!e.is_blocked("safe.example.com"));
    }

    #[test]
    fn wildcard_rpz_blocks_subdomains() {
        let e = load("*.example-ads.com CNAME .\n");
        assert!(e.is_blocked("foo.example-ads.com"));
        assert!(e.is_blocked("deep.foo.example-ads.com"));
        assert!(
            !e.is_blocked("example-ads.com"),
            "apex not blocked by wildcard-only entry"
        );
    }

    #[test]
    fn config_allowlist_overrides_blocklist() {
        let cfg = BlocklistConfig {
            allowlist: vec!["safe.ads.example.com".to_string()],
            ..BlocklistConfig::default()
        };
        let e = BlocklistEngine::new(cfg);
        e.load("0.0.0.0 safe.ads.example.com\n0.0.0.0 other.ads.example.com\n");
        assert!(!e.is_blocked("safe.ads.example.com"));
        assert!(e.is_blocked("other.ads.example.com"));
    }

    #[test]
    fn case_insensitive() {
        let e = load("0.0.0.0 ADS.EXAMPLE.COM\n");
        assert!(e.is_blocked("ads.example.com"));
        assert!(e.is_blocked("ADS.EXAMPLE.COM"));
    }

    #[test]
    fn trailing_dot_ignored() {
        assert!(load("0.0.0.0 ads.example.com\n").is_blocked("ads.example.com."));
    }

    #[test]
    fn never_blocks_localhost() {
        let e = load("0.0.0.0 localhost\n127.0.0.1 broadcasthost\n");
        assert!(!e.is_blocked("localhost"));
    }

    #[test]
    fn untrusted_allow_entry_is_discarded() {
        // An RPZ passthru entry from an untrusted source must NOT allowlist the domain.
        let e = engine();
        // Load the RPZ source as untrusted (default)
        e.load("ads.example.com CNAME .\nsafe.example.com CNAME rpz-passthru.\n");
        // ads.example.com should still be blocked
        assert!(e.is_blocked("ads.example.com"), "block entry should remain");
        // The passthru for safe.example.com should be DISCARDED — safe.example.com is not in the
        // blocklist so it wasn't going to be blocked anyway, but if we also had:
        // "0.0.0.0 safe.example.com" in another source, it should remain blocked
        let e2 = engine();
        e2.load_many_with_trust(&[
            ("0.0.0.0 safe.example.com\n", BlocklistSource::Untrusted),
            (
                "safe.example.com CNAME rpz-passthru.\n",
                BlocklistSource::Untrusted,
            ),
        ]);
        assert!(
            e2.is_blocked("safe.example.com"),
            "untrusted passthru should NOT allowlist"
        );
    }

    #[test]
    fn trusted_allow_entry_is_honoured() {
        let e = engine();
        e.load_many_with_trust(&[
            ("0.0.0.0 safe.example.com\n", BlocklistSource::Untrusted),
            (
                "safe.example.com CNAME rpz-passthru.\n",
                BlocklistSource::Trusted,
            ),
        ]);
        assert!(
            !e.is_blocked("safe.example.com"),
            "trusted passthru SHOULD allowlist"
        );
    }

    #[test]
    fn merge_multiple_sources() {
        let e = engine();
        e.load_many_with_trust(&[
            ("0.0.0.0 ads.example.com\n", BlocklistSource::Untrusted),
            ("tracker.example.net\n", BlocklistSource::Untrusted),
        ]);
        assert!(e.is_blocked("ads.example.com"));
        assert!(e.is_blocked("tracker.example.net"));
    }

    // --- regex block rules (TODO 8.7) ---------------------------------

    #[test]
    fn regex_rule_blocks_matching_qname() {
        let cfg = BlocklistConfig {
            regex_rules: vec![r"^ads?\d*\.".to_string()],
            ..BlocklistConfig::default()
        };
        let e = BlocklistEngine::new(cfg);
        assert!(e.is_blocked("ads3.example.com"));
        assert!(e.is_blocked("ad.example.net"));
        assert!(!e.is_blocked("safe.example.com"));
    }

    #[test]
    fn allowlist_wins_over_regex() {
        let cfg = BlocklistConfig {
            allowlist: vec!["safe.ads.example.com".to_string()],
            regex_rules: vec![r"ads".to_string()],
            ..BlocklistConfig::default()
        };
        let e = BlocklistEngine::new(cfg);
        // regex matches and not allowlisted → blocked
        assert!(e.is_blocked("tracker.ads.example.com"));
        // allowlisted → the allowlist wins over the regex
        assert!(!e.is_blocked("safe.ads.example.com"));
    }

    #[test]
    fn group_uses_its_own_blocklist() {
        let cfg = BlocklistConfig {
            groups: vec![rustydns_core::config::BlocklistGroup {
                name: "strict".to_string(),
                sources: Vec::new(),
                local_files: Vec::new(),
                trusted_rpz_sources: Vec::new(),
                allowlist: Vec::new(),
            }],
            ..BlocklistConfig::default()
        };
        let e = BlocklistEngine::new(cfg);
        // Global blocks ads.example.com; the "strict" group blocks a different
        // name (tracker.example.net) and NOT ads.
        e.load("0.0.0.0 ads.example.com\n");
        e.load_group(
            "strict",
            &[("0.0.0.0 tracker.example.net\n", BlocklistSource::Untrusted)],
            &[],
        );

        // Default (no group) → the global set.
        assert!(e.is_blocked_for_group("ads.example.com", None));
        assert!(!e.is_blocked_for_group("tracker.example.net", None));
        assert!(e.is_blocked("ads.example.com")); // convenience == group None

        // "strict" group → its OWN set, independent of the global one.
        assert!(e.is_blocked_for_group("tracker.example.net", Some("strict")));
        assert!(!e.is_blocked_for_group("ads.example.com", Some("strict")));

        // Unknown group name → falls back to the global set (never a panic).
        assert!(e.is_blocked_for_group("ads.example.com", Some("nope")));
        assert!(!e.is_blocked_for_group("tracker.example.net", Some("nope")));
    }

    #[test]
    fn group_has_its_own_allowlist() {
        let cfg = BlocklistConfig {
            groups: vec![rustydns_core::config::BlocklistGroup {
                name: "g".to_string(),
                sources: Vec::new(),
                local_files: Vec::new(),
                trusted_rpz_sources: Vec::new(),
                allowlist: vec!["safe.example.com".to_string()],
            }],
            ..BlocklistConfig::default()
        };
        let e = BlocklistEngine::new(cfg);
        e.load_group(
            "g",
            &[(
                "0.0.0.0 safe.example.com\n0.0.0.0 bad.example.com\n",
                BlocklistSource::Untrusted,
            )],
            &["safe.example.com".to_string()],
        );
        assert!(!e.is_blocked_for_group("safe.example.com", Some("g")));
        assert!(e.is_blocked_for_group("bad.example.com", Some("g")));
    }

    #[test]
    fn regex_survives_content_reload() {
        let cfg = BlocklistConfig {
            regex_rules: vec!["tracker".to_string()],
            ..BlocklistConfig::default()
        };
        let e = BlocklistEngine::new(cfg);
        assert!(e.is_blocked("x.tracker.net"));
        // A content reload (sources) must not drop the regex rules.
        e.load("0.0.0.0 ads.example.com\n");
        assert!(
            e.is_blocked("x.tracker.net"),
            "regex rules must survive a content reload"
        );
        assert!(e.is_blocked("ads.example.com"));
    }
}
