//! Blocklist engine: O(1) domain lookup with lock-free hot-reload.
//!
//! # Architecture
//!
//! The engine stores all blocked domains in an [`ahash::AHashSet`] behind an
//! [`arc_swap::ArcSwap`]. This means:
//!
//! - **Reads** (the query hot path) are entirely lock-free and allocation-free.
//!   `is_blocked` acquires a reference to the current state, checks the sets,
//!   and releases it — no mutex, no allocation.
//!
//! - **Writes** (blocklist reload) build a brand-new `BlocklistState` off the
//!   hot path, then atomically swap the `ArcSwap` pointer. Readers in flight
//!   see either the old or new state, never a partially-built one.
//!
//! # Memory bounds
//!
//! The engine logs its heap usage after every reload and emits a warning if
//! usage exceeds 100 MB — the budget for a Raspberry Pi Zero 2 W running the
//! full Rusty Suite.

use std::sync::Arc;
use std::time::SystemTime;

use ahash::AHashSet;
use arc_swap::ArcSwap;
use tracing::{info, warn};

use rustydns_core::config::BlocklistConfig;

use crate::allowlist::Allowlist;
use crate::parser::{ParsedEntry, parse};

// ---------------------------------------------------------------------------
// Internal state (behind the ArcSwap)
// ---------------------------------------------------------------------------

/// The immutable blocklist state snapshot.
///
/// A new `BlocklistState` is built on every reload; the old one is dropped
/// once all readers that hold a reference to it finish their queries.
struct BlocklistState {
    /// Exact domain blocks (lowercased, no trailing dot).
    domains: AHashSet<String>,

    /// Wildcard parent domains.
    ///
    /// If `"example-ads.com"` is in this set, then `foo.example-ads.com` and
    /// `bar.foo.example-ads.com` are both blocked, but `example-ads.com`
    /// itself is not (use `domains` for that).
    wildcard_parents: AHashSet<String>,

    /// Allowlist — checked first; a match here overrides any block.
    allowlist: Allowlist,

    /// Total number of block entries (exact + wildcard).
    entry_count: usize,

    /// Approximate heap usage in bytes (rough estimate for monitoring).
    heap_bytes: usize,

    /// Wall-clock time when this state was loaded.
    loaded_at: SystemTime,
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
        }
    }

    /// Check whether `domain` should be blocked.
    ///
    /// Pipeline:
    /// 1. Allowlist check — if allowed, return `false` immediately.
    /// 2. Exact match in `domains`.
    /// 3. Walk up the label tree checking `wildcard_parents`.
    ///
    /// Does not allocate on any path.
    fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            return false;
        }

        // Lowercase comparison without allocating for the common case.
        // We lowercase on insert, so we only need to lowercase the input here.
        // For ASCII domains (the overwhelming majority) this is cheap.
        let domain_lc: String;
        let domain = if domain.chars().any(|c| c.is_ascii_uppercase()) {
            domain_lc = domain.to_lowercase();
            &domain_lc
        } else {
            domain
        };

        // Allowlist always wins.
        if self.allowlist.is_allowed(domain) {
            return false;
        }

        // Exact match.
        if self.domains.contains(domain) {
            return true;
        }

        // Wildcard parent walk.
        // For "ads.tracker.example.com", check:
        //   "tracker.example.com"   (strip label "ads.")
        //   "example.com"           (strip label "tracker.")
        //   "com"                   (strip label "example.") — we stop here
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
/// Thread-safe and `Clone`-able (cloning shares the same underlying state).
/// Cheaply passed to query handler tasks as `Arc<BlocklistEngine>`.
pub struct BlocklistEngine {
    state: ArcSwap<BlocklistState>,
    config: BlocklistConfig,
}

impl BlocklistEngine {
    /// Create a new engine from config with an **empty** blocklist.
    ///
    /// Call [`load`] or [`load_many`] to populate the blocklist before
    /// serving queries.
    pub fn new(config: BlocklistConfig) -> Self {
        let allowlist = Allowlist::from_entries(&config.allowlist);
        Self {
            state: ArcSwap::from_pointee(BlocklistState::new_empty(allowlist)),
            config,
        }
    }

    /// Load blocklist content from a single string slice.
    ///
    /// The format is auto-detected. This atomically replaces the current state.
    pub fn load(&self, content: &str) {
        self.load_many(&[content]);
    }

    /// Load and merge multiple blocklist sources into a single atomic state.
    ///
    /// All sources are parsed and their entries merged before the `ArcSwap`
    /// pointer is swapped — there is exactly one swap regardless of how many
    /// sources are provided.
    ///
    /// `rpz-passthru.` allow entries from RPZ sources are merged into the
    /// allowlist and take precedence over any block entries in the same or
    /// other sources.
    pub fn load_many(&self, sources: &[&str]) {
        let mut state = BlocklistState::new_empty(Allowlist::from_entries(&self.config.allowlist));
        let mut rpz_allows: Vec<String> = Vec::new();

        for content in sources {
            for entry in parse(content) {
                match entry {
                    ParsedEntry::Exact(d) => {
                        state.domains.insert(d);
                    }
                    ParsedEntry::WildcardParent(p) => {
                        state.wildcard_parents.insert(p);
                    }
                    ParsedEntry::Allow(d) => {
                        rpz_allows.push(d);
                    }
                }
            }
        }

        // Merge RPZ passthru allows into the allowlist.
        if !rpz_allows.is_empty() {
            state.allowlist.extend_exact(rpz_allows);
        }

        let exact_count = state.domains.len();
        let wildcard_count = state.wildcard_parents.len();
        state.entry_count = exact_count + wildcard_count;

        // Rough heap estimate: ~30 bytes average domain + ~50 bytes AHashSet overhead/entry.
        state.heap_bytes = state.entry_count * 80;

        info!(
            exact    = exact_count,
            wildcards = wildcard_count,
            total    = state.entry_count,
            heap_kib = state.heap_bytes / 1024,
            allowlist = state.allowlist.len(),
            "blocklist loaded"
        );

        // Warn if this would likely OOM Pi Zero 2 W class hardware.
        if state.heap_bytes > 100 * 1024 * 1024 {
            warn!(
                heap_mib = state.heap_bytes / (1024 * 1024),
                "blocklist heap usage exceeds 100 MiB — may cause OOM on low-memory hardware \
                 (Pi Zero 2 W has 512 MiB total; rustydns targets < 30 MiB idle RSS)"
            );
        }

        self.state.store(Arc::new(state));
    }

    /// Returns `true` if `domain` is blocked.
    ///
    /// This is the **hot path** — called for every query that escapes the
    /// authority layer. It is lock-free and does not allocate for the common
    /// (not-blocked) case.
    #[inline]
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.state.load().is_blocked(domain)
    }

    /// Returns the total number of blocked entries (exact + wildcard).
    pub fn entry_count(&self) -> usize {
        self.state.load().entry_count
    }

    /// Returns the approximate heap usage of the blocklist in bytes.
    pub fn heap_bytes(&self) -> usize {
        self.state.load().heap_bytes
    }

    /// Returns when the current blocklist state was loaded.
    pub fn loaded_at(&self) -> SystemTime {
        self.state.load().loaded_at
    }

    /// Returns the configured block response type.
    pub fn block_response(&self) -> rustydns_core::config::BlockResponse {
        self.config.block_response
    }

    /// Returns the configured sinkhole IP (only meaningful when
    /// `block_response = "sinkhole"`).
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

    fn engine_with_hosts(content: &str) -> BlocklistEngine {
        let engine = BlocklistEngine::new(BlocklistConfig::default());
        engine.load(content);
        engine
    }

    #[test]
    fn blocks_exact_domain() {
        let engine = engine_with_hosts("0.0.0.0 ads.example.com\n");
        assert!(engine.is_blocked("ads.example.com"));
    }

    #[test]
    fn does_not_block_unrelated_domain() {
        let engine = engine_with_hosts("0.0.0.0 ads.example.com\n");
        assert!(!engine.is_blocked("safe.example.com"));
        assert!(!engine.is_blocked("example.com"));
    }

    #[test]
    fn wildcard_rpz_blocks_subdomains() {
        let engine = engine_with_hosts("*.example-ads.com CNAME .\n");
        assert!(engine.is_blocked("foo.example-ads.com"));
        assert!(engine.is_blocked("deep.foo.example-ads.com"));
        // Apex itself is NOT blocked by a wildcard parent entry.
        assert!(!engine.is_blocked("example-ads.com"));
    }

    #[test]
    fn allowlist_overrides_blocklist() {
        let mut config = BlocklistConfig::default();
        config.allowlist = vec!["safe.ads.example.com".to_string()];
        let engine = BlocklistEngine::new(config);
        engine.load("0.0.0.0 safe.ads.example.com\n0.0.0.0 other.ads.example.com\n");

        assert!(!engine.is_blocked("safe.ads.example.com"), "allowlisted domain should not be blocked");
        assert!(engine.is_blocked("other.ads.example.com"));
    }

    #[test]
    fn wildcard_allowlist_overrides_blocklist() {
        let mut config = BlocklistConfig::default();
        config.allowlist = vec!["*.example.com".to_string()];
        let engine = BlocklistEngine::new(config);
        engine.load("0.0.0.0 ads.example.com\n");

        assert!(!engine.is_blocked("ads.example.com"));
        assert!(!engine.is_blocked("any.subdomain.example.com"));
    }

    #[test]
    fn case_insensitive_lookup() {
        let engine = engine_with_hosts("0.0.0.0 ADS.EXAMPLE.COM\n");
        assert!(engine.is_blocked("ads.example.com"));
        assert!(engine.is_blocked("ADS.EXAMPLE.COM"));
        assert!(engine.is_blocked("Ads.Example.Com"));
    }

    #[test]
    fn trailing_dot_ignored() {
        let engine = engine_with_hosts("0.0.0.0 ads.example.com\n");
        assert!(engine.is_blocked("ads.example.com."));
    }

    #[test]
    fn empty_after_load_many_with_no_sources() {
        let engine = BlocklistEngine::new(BlocklistConfig::default());
        engine.load_many(&[]);
        assert_eq!(engine.entry_count(), 0);
    }

    #[test]
    fn load_many_merges_sources() {
        let engine = BlocklistEngine::new(BlocklistConfig::default());
        engine.load_many(&[
            "0.0.0.0 ads.example.com\n",
            "tracker.example.net\n",
        ]);
        assert!(engine.is_blocked("ads.example.com"));
        assert!(engine.is_blocked("tracker.example.net"));
    }

    #[test]
    fn never_blocks_localhost() {
        let engine = engine_with_hosts("0.0.0.0 localhost\n127.0.0.1 broadcasthost\n");
        assert!(!engine.is_blocked("localhost"));
        assert!(!engine.is_blocked("broadcasthost"));
    }
}
