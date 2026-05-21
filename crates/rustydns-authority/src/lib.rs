#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Authoritative zone server for `rustydns`.
//!
//! Serves DNS answers for two zone types:
//!
//! 1. **Mesh zone** — live records read from the `rustynet-dns-zone` SQLite
//!    database. Updated on a configurable poll interval (default 30 s) and
//!    cached in memory between polls.
//!
//! 2. **Static zones** — records declared directly in `rustydns.toml` under
//!    `[[authority.static_records]]`. Useful for local overrides and
//!    split-horizon entries that don't belong in the Rustynet control plane.
//!
//! # Pipeline position
//!
//! The authority is checked **first** in the query pipeline, before the
//! blocklist and before the upstream resolver. Mesh-local records are **never**
//! blocked, even if a domain name appears in a blocklist source.
//!
//! ```text
//! query → Authority → (miss) → Blocklist → (pass) → Resolver
//! ```
//!
//! # Key invariant
//!
//! Authority answers are trusted answers. The authority never forwards to an
//! upstream resolver; it either has the answer or it doesn't.
//!
//! # Status
//!
//! Milestone 2 (in progress). Current implementation: static zone from TOML.
//! Rustynet SQLite integration is the next step.

use rustydns_core::config::AuthorityConfig;
use rustydns_core::record::DnsRecord;

/// Result type for authority operations.
pub type AuthorityResult<T> = Result<T, rustydns_core::RustyDnsError>;

/// The authoritative zone server.
///
/// Holds an in-memory view of all zones it is authoritative for. Answers
/// queries for names within those zones; returns `None` for names outside
/// them (which the daemon then forwards to the blocklist + resolver pipeline).
pub struct Authority {
    config: AuthorityConfig,
    // TODO (Milestone 2): add static zone store and SQLite zone reader.
}

impl Authority {
    /// Create a new authority from config.
    ///
    /// At startup, static records from `config.static_records` are loaded
    /// into memory. The Rustynet SQLite database is opened read-only (if it
    /// exists); missing database is non-fatal at startup (gracefully degrades
    /// to static-only mode with a warning).
    pub fn new(config: AuthorityConfig) -> AuthorityResult<Self> {
        tracing::info!(
            static_records = config.static_records.len(),
            db = %config.rustynet_db.display(),
            poll_interval_secs = config.poll_interval_secs,
            "authority initialised (static-only mode — Rustynet DB integration pending)"
        );
        Ok(Self { config })
    }

    /// Look up `name` in the authority's zones.
    ///
    /// Returns `Some(records)` if the name is within an authoritative zone
    /// and records exist. Returns `None` if the name is not within any
    /// authoritative zone (caller should continue to blocklist + resolver).
    ///
    /// The returned slice is empty (but `Some`) for authoritative NXDOMAIN
    /// (name is in the zone but has no records of the requested type).
    ///
    /// # Privacy note
    ///
    /// Authority hits are logged at `tracing::trace!` level only — they must
    /// not appear at `info` or above in production (would log every mesh query).
    pub fn lookup(&self, name: &str, record_type: &str) -> Option<Vec<DnsRecord>> {
        // TODO (Milestone 2): check static zones and SQLite zone.
        let _ = (name, record_type);
        tracing::trace!(qname = name, qtype = record_type, "authority miss (stub)");
        None
    }

    /// Returns `true` if `name` is within one of the authority's zones.
    pub fn is_authoritative_for(&self, name: &str) -> bool {
        // TODO (Milestone 2): check zone apex list.
        let mesh_zone = self.config.mesh_zone.trim_end_matches('.');
        name.ends_with(mesh_zone)
    }
}
