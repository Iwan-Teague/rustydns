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

use std::sync::Arc;
use std::time::SystemTime;

use ahash::AHashSet;
use arc_swap::ArcSwap;
use tracing::{info, warn};

use rustydns_core::config::BlocklistConfig;

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

        false
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
}

impl BlocklistEngine {
    /// Create a new engine from config with an empty blocklist.
    pub fn new(config: BlocklistConfig) -> Self {
        let allowlist = Allowlist::from_entries(&config.allowlist);
        Self {
            state: ArcSwap::from_pointee(BlocklistState::new_empty(allowlist)),
            config,
        }
    }

    /// Load and merge multiple blocklist sources.
    ///
    /// Each source is paired with a [`BlocklistSource`] trust level. Allow
    /// entries from untrusted sources are discarded with a warning; allow
    /// entries from trusted sources are added to the allowlist.
    ///
    /// All sources are processed before the atomic state swap — exactly one
    /// swap per reload regardless of source count.
    pub fn load_many_with_trust(&self, sources: &[(&str, BlocklistSource)]) {
        let mut state = BlocklistState::new_empty(Allowlist::from_entries(&self.config.allowlist));
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

        state.entry_count = state.domains.len() + state.wildcard_parents.len();
        // ~30 bytes average domain + ~50 bytes AHashSet overhead per entry
        state.heap_bytes = state.entry_count * 80;

        info!(
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

        self.state.store(Arc::new(state));
    }

    /// Convenience: load a single content string, treated as untrusted.
    pub fn load(&self, content: &str) {
        self.load_many_with_trust(&[(content, BlocklistSource::Untrusted)]);
    }

    /// Convenience: load a single trusted content string.
    pub fn load_trusted(&self, content: &str) {
        self.load_many_with_trust(&[(content, BlocklistSource::Trusted)]);
    }

    /// Returns `true` if `domain` is blocked.
    ///
    /// Lock-free, allocation-free for the common case. Hot path.
    #[inline]
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.state.load().is_blocked(domain)
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
        let mut cfg = BlocklistConfig::default();
        cfg.allowlist = vec!["safe.ads.example.com".to_string()];
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
}
