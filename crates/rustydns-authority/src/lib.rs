#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Authoritative zone server for `rustydns`.
//!
//! Serves DNS answers for two zone types:
//!
//! 1. **Mesh zone** — records read from a signed bundle file written by
//!    `rustynetd`. The bundle's ed25519 signature is verified at every
//!    load against an operator-configured verifier key. Updated on a
//!    configurable poll interval (default 30 s) and held behind
//!    `arc_swap::ArcSwap` so reads never block during reload.
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
//! Production. Static zones from TOML, signed mesh-zone bundle read from
//! disk with ed25519 verification, atomic hot reload via `ArcSwap`, and
//! intra-zone CNAME chain following per RFC 1034 §3.6.2 (depth-capped at
//! 8 hops, with loop detection and partial-chain return when the chase
//! crosses out of the authority's zones).

mod mesh;

pub use mesh::{LoadedBundle, MeshBundleError};

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;

use rustydns_core::RustyDnsError;
use rustydns_core::config::{AuthorityConfig, StaticRecord};
use rustydns_core::record::{DnsRecord, RecordData, STATIC_RECORD_TTL};

/// Result type for authority operations.
pub type AuthorityResult<T> = Result<T, RustyDnsError>;

/// Immutable snapshot of the authority's zone state.
///
/// All reader-visible state lives in a snapshot held behind
/// [`arc_swap::ArcSwap`] so the background reloader can swap it
/// atomically without blocking readers.
#[derive(Debug, Clone)]
struct Snapshot {
    /// Lowercased, trailing-dot zone apexes (static + mesh).
    zones: Vec<String>,
    /// Per-name record store. Key is the lowercased FQDN with trailing dot.
    records: HashMap<String, Vec<DnsRecord>>,
}

/// The authoritative zone server.
///
/// Holds an in-memory view of all zones it is authoritative for. Answers
/// queries for names within those zones; returns `None` for names outside
/// them (which the daemon then forwards to the blocklist + resolver pipeline).
///
/// Lock-free hot reload: the mesh-zone bundle can be re-read via
/// [`Authority::reload_mesh`] without blocking lookups.
#[derive(Debug)]
pub struct Authority {
    config: AuthorityConfig,
    /// Lowercased mesh zone with trailing dot (e.g. `"mesh."`).
    mesh_zone: String,
    /// Static records — fixed at startup, used to rebuild snapshots on reload.
    static_records: HashMap<String, Vec<DnsRecord>>,
    /// Static zone apexes — fixed at startup.
    static_zones: Vec<String>,
    /// Atomically swappable snapshot of the merged static + mesh state.
    snapshot: ArcSwap<Snapshot>,
    /// Anti-rollback watermark: the `(generated_at_unix, nonce)` of the most
    /// recently *applied* mesh bundle, or `None` until the first is applied.
    ///
    /// A reload whose `(generated_at_unix, nonce)` orders strictly before
    /// this is rejected as a rollback/replay (see [`Authority::reload_mesh`]).
    /// Kept in-memory only — the "no database" invariant stands. A process
    /// restart resets it to the freshly-loaded bundle's value, so the
    /// `mesh_zone_max_age_secs` freshness window is the backstop right after
    /// boot.
    ///
    /// Wrapped in a `Mutex` (not `ArcSwap`) so the watermark check and the
    /// snapshot store happen atomically together: concurrent reloads (the
    /// periodic poller racing a SIGHUP) cannot interleave such that an older
    /// bundle's snapshot wins after a newer bundle already advanced the
    /// watermark. The expensive signature verification runs *outside* this
    /// lock; only the brief apply is serialised.
    mesh_watermark: Mutex<Option<(u64, u64)>>,
}

impl Authority {
    /// Create a new authority from config.
    ///
    /// At startup, static records from `config.static_records` are loaded
    /// into memory. If `mesh_zone_bundle_path` and
    /// `mesh_zone_verifier_key_path` are both set, the Rustynet
    /// mesh-zone bundle is read and its ed25519 signature verified; on
    /// any failure the daemon falls back to static-only mode with a
    /// warning rather than refusing to start.
    ///
    /// Returns [`RustyDnsError::Zone`] if any static record is malformed
    /// (unknown type, missing required field, unparseable address, etc.).
    pub fn new(config: AuthorityConfig) -> AuthorityResult<Self> {
        let mesh_zone = normalise_name(&config.mesh_zone);

        // Build the static-record half once — it never changes at runtime.
        let mut static_records: HashMap<String, Vec<DnsRecord>> = HashMap::new();
        let mut static_zones: Vec<String> = Vec::new();
        for sr in &config.static_records {
            let rec = static_record_to_dns_record(sr)?;
            let name = rec.name.clone();
            if !static_zones.iter().any(|z| z == &name) {
                static_zones.push(name.clone());
            }
            static_records.entry(name).or_default().push(rec);
        }

        // Initial mesh-zone load. Failure is non-fatal.
        let mesh = load_mesh_if_configured(&config, &mesh_zone);
        let mesh_record_count = mesh.as_ref().map(|m| m.records.len()).unwrap_or(0);
        // Seed the anti-rollback watermark from the bundle we just applied,
        // so the very first `reload_mesh` already rejects an older bundle.
        let mesh_watermark = mesh.as_ref().map(|m| (m.generated_at_unix, m.nonce));

        let snapshot = build_snapshot(&static_records, &static_zones, mesh.as_ref());

        tracing::info!(
            static_records = config.static_records.len(),
            static_zones = static_zones.len(),
            mesh_records = mesh_record_count,
            mesh_zone = %mesh_zone,
            poll_interval_secs = config.poll_interval_secs,
            "authority initialised"
        );

        Ok(Self {
            config,
            mesh_zone,
            static_records,
            static_zones,
            snapshot: ArcSwap::from(Arc::new(snapshot)),
            mesh_watermark: Mutex::new(mesh_watermark),
        })
    }

    /// Re-read the mesh-zone bundle (if configured) and atomically swap
    /// in a new snapshot.
    ///
    /// Returns:
    /// - `Ok(Some(count))` — bundle reloaded successfully, `count` mesh
    ///   records are now live.
    /// - `Ok(None)` — bundle is not configured; nothing to do.
    /// - `Err(MeshBundleError::Rollback { .. })` — the candidate bundle is
    ///   signature- and freshness-valid but orders strictly *before* the
    ///   last-applied bundle, so it is rejected as a rollback/replay. The
    ///   previous snapshot is **kept**.
    /// - `Err(_)` — bundle read or signature verification failed. The
    ///   previous snapshot is **kept** (caller decides whether to keep
    ///   running or shut down).
    ///
    /// # Anti-rollback / replay protection
    ///
    /// Signature + freshness checks alone do not stop an actor who can write
    /// the bundle path (or cause a stale file to reappear) from replaying an
    /// *older but still-fresh* signed bundle — one generated a few minutes
    /// ago, within `mesh_zone_max_age_secs` — to roll a name back to a
    /// previous IP or drop a record. The signature still verifies because it
    /// is a legitimately old bundle. To close this, the authority refuses any
    /// candidate whose `(generated_at_unix, nonce)` orders strictly before the
    /// last-applied bundle's. An identical bundle (equal tuple) is allowed —
    /// the periodic poller re-reads the same file every interval and that must
    /// stay idempotent, not log a spurious rollback.
    ///
    /// Lock-free reads: existing lookups in flight see the old snapshot until
    /// they finish; new lookups after the swap see the new one. The watermark
    /// check + snapshot store are serialised under a `Mutex` so concurrent
    /// reloads cannot apply an older snapshot after a newer one won.
    pub fn reload_mesh(&self) -> Result<Option<usize>, MeshBundleError> {
        let (bundle_path, key_path) = match (
            self.config.mesh_zone_bundle_path.as_ref(),
            self.config.mesh_zone_verifier_key_path.as_ref(),
        ) {
            (Some(b), Some(k)) => (b, k),
            _ => return Ok(None),
        };

        // Signature + freshness verification happens BEFORE taking the
        // watermark lock — the expensive ed25519 check must not serialise
        // with other reloads, and an attacker-supplied bundle never reaches
        // the apply path if it fails to verify.
        let loaded = mesh::load_mesh_bundle(
            bundle_path,
            key_path,
            &self.mesh_zone,
            self.config.mesh_zone_max_age_secs,
        )?;
        let candidate = (loaded.generated_at_unix, loaded.nonce);

        // A poisoned watermark lock can only happen if a previous holder
        // panicked mid-apply (which, with panic=abort in release, terminates
        // the process). Recover the inner value rather than propagating the
        // poison so a debug-build test panic doesn't wedge reloads forever.
        let mut watermark = self
            .mesh_watermark
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some((cur_gen, cur_nonce)) = *watermark
            && candidate < (cur_gen, cur_nonce)
        {
            tracing::warn!(
                candidate_generated_at = loaded.generated_at_unix,
                candidate_nonce = loaded.nonce,
                current_generated_at = cur_gen,
                current_nonce = cur_nonce,
                "mesh bundle rejected as a rollback/replay — it is older than the currently \
                 applied bundle. Keeping the previous snapshot. If this is a legitimate \
                 re-key or clock reset, restart the daemon to reset the watermark."
            );
            return Err(MeshBundleError::Rollback {
                candidate_generated_at: loaded.generated_at_unix,
                candidate_nonce: loaded.nonce,
                current_generated_at: cur_gen,
                current_nonce: cur_nonce,
            });
        }

        let count = loaded.records.len();
        let snapshot = build_snapshot(&self.static_records, &self.static_zones, Some(&loaded));
        self.snapshot.store(Arc::new(snapshot));
        *watermark = Some(candidate);
        drop(watermark);
        tracing::info!(mesh_records = count, "mesh zone bundle reloaded");
        Ok(Some(count))
    }

    /// Look up `name` in the authority's zones.
    ///
    /// Returns:
    /// - `Some(records)` if the name is within an authoritative zone and one
    ///   or more records of `record_type` exist at that exact name.
    /// - `Some(vec![])` for authoritative NXDOMAIN — the name is within an
    ///   authoritative zone but has no records of the requested type.
    /// - `None` if the name is not within any authoritative zone. The caller
    ///   should continue to the blocklist + resolver pipeline.
    ///
    /// `record_type` is matched case-insensitively (`"A"` / `"a"` / `"A "`-trimmed
    /// all behave the same).
    ///
    /// # Privacy note
    ///
    /// Authority hits are logged at `tracing::trace!` only — they must not
    /// appear at `info` or above in production (would log every mesh query
    /// and defeat the privacy posture).
    pub fn lookup(&self, name: &str, record_type: &str) -> Option<Vec<DnsRecord>> {
        let key = normalise_name(name);
        let rtype = record_type.trim().to_ascii_uppercase();
        let snap = self.snapshot.load();

        if !self.is_authoritative_for_normalised(&key, &snap) {
            tracing::trace!(qtype = %rtype, "authority not authoritative for name");
            return None;
        }

        let matching = collect_with_cname_chain(self, &key, &rtype, &snap);
        tracing::trace!(qtype = %rtype, count = matching.len(), "authority lookup");
        Some(matching)
    }

    /// Returns `true` if `name` is within one of the authority's zones.
    ///
    /// A name is "within a zone" if it equals the zone apex or is a
    /// subdomain of it. Both the mesh zone and every zone apex derived
    /// from static records are checked.
    pub fn is_authoritative_for(&self, name: &str) -> bool {
        let normalised = normalise_name(name);
        let snap = self.snapshot.load();
        self.is_authoritative_for_normalised(&normalised, &snap)
    }

    fn is_authoritative_for_normalised(&self, name: &str, snap: &Snapshot) -> bool {
        if name_within_zone(name, &self.mesh_zone) {
            return true;
        }
        snap.zones.iter().any(|zone| name_within_zone(name, zone))
    }

    /// Borrow the authority's config.
    pub fn config(&self) -> &AuthorityConfig {
        &self.config
    }

    /// Count of mesh-zone records currently live in the snapshot
    /// (records contributed by the Rustynet bundle, NOT by static
    /// config). Used by the daemon to seed `rustydns_mesh_records` at
    /// startup.
    pub fn mesh_record_count(&self) -> usize {
        let snap = self.snapshot.load();
        snap.records
            .values()
            .flat_map(|recs| recs.iter())
            .filter(|r| r.mesh_node_id.is_some())
            .count()
    }
}

/// Maximum number of CNAME hops to follow inside the authority's zones
/// before giving up.
///
/// RFC 1034 §3.6.2 expects authoritative servers to chase intra-zone
/// CNAME chains so a stub resolver can answer with one round-trip. We
/// cap the depth to bound work per query and to break alias cycles
/// (which would otherwise loop forever).
///
/// 8 hops is generous — real chains in mesh deployments are 1–2 deep.
const MAX_CNAME_DEPTH: usize = 8;

/// Resolve `name` for `rtype` against `snap`, following intra-zone CNAME
/// chains.
///
/// Behaviour:
/// - If a non-CNAME record of `rtype` exists directly at `name`, return
///   those records and stop (RFC 1034: a name with non-CNAME RRs must
///   not also have a CNAME).
/// - If `rtype == "CNAME"` or `rtype == "ANY"`, return the literal set
///   at `name` without chasing.
/// - Otherwise, if a CNAME exists at `name`, follow its target. Append
///   each CNAME on the path to the answer; if the chain reaches a
///   terminal record of `rtype`, append those too.
/// - Stop and return the partial chain when the target leaves the
///   authority's zones (the daemon's resolver pipeline will then chase
///   the rest), when a loop is detected, or when [`MAX_CNAME_DEPTH`] is
///   exceeded.
///
/// Authoritative NXDOMAIN (name in zone but no records of requested
/// type and no CNAME) returns an empty vector — the caller then emits
/// a NoError / NoData response.
fn collect_with_cname_chain(
    auth: &Authority,
    name: &str,
    rtype: &str,
    snap: &Snapshot,
) -> Vec<DnsRecord> {
    let records_at = |n: &str| snap.records.get(n);

    let initial = records_at(name);
    let direct: Vec<DnsRecord> = initial
        .map(|recs| {
            if rtype == "ANY" {
                recs.clone()
            } else {
                recs.iter()
                    .filter(|r| r.type_name() == rtype)
                    .cloned()
                    .collect()
            }
        })
        .unwrap_or_default();

    // Asked for CNAME / ANY explicitly, or we already have a non-CNAME
    // direct answer of the requested type → no chasing.
    if rtype == "CNAME" || rtype == "ANY" || !direct.is_empty() {
        return direct;
    }

    // Direct answer empty for the requested type. If there's a CNAME at
    // this name, follow it.
    let Some(first_cname) = initial.and_then(|recs| {
        recs.iter()
            .find(|r| matches!(r.data, RecordData::Cname(_)))
            .cloned()
    }) else {
        // No CNAME, no terminal record of `rtype` → authoritative
        // empty (NoData).
        return Vec::new();
    };

    let mut out: Vec<DnsRecord> = vec![first_cname.clone()];
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(name.to_string());

    let mut next = match &first_cname.data {
        RecordData::Cname(t) => t.clone(),
        _ => return out,
    };

    for _ in 0..MAX_CNAME_DEPTH {
        if !visited.insert(next.clone()) {
            // Cycle. The CNAME author shot themselves in the foot. We
            // log at debug — bumping to warn would log a (low-cardinality
            // but still operator-visible) qname-shaped string, which
            // we'd rather not do.
            tracing::debug!(
                qname = %name,
                cycle_at = %next,
                "CNAME loop in authority zone; truncating chain",
            );
            return out;
        }

        // Target outside authoritative scope. Return the partial chain;
        // the daemon's resolver pipeline (or the client's stub) will
        // chase from here.
        if !auth.is_authoritative_for_normalised(&next, snap) {
            return out;
        }

        let recs_at_next = records_at(&next);

        // Terminal records of the requested type at the target?
        if let Some(recs) = recs_at_next {
            let terminal: Vec<DnsRecord> = recs
                .iter()
                .filter(|r| r.type_name() == rtype)
                .cloned()
                .collect();
            if !terminal.is_empty() {
                out.extend(terminal);
                return out;
            }

            // Another CNAME hop?
            if let Some(next_cname) = recs.iter().find(|r| matches!(r.data, RecordData::Cname(_))) {
                out.push(next_cname.clone());
                next = match &next_cname.data {
                    RecordData::Cname(t) => t.clone(),
                    _ => return out,
                };
                continue;
            }
        }

        // Authoritative for the target, but neither a terminal record
        // of `rtype` nor a further CNAME — authoritative NoData for
        // the type at the chain end. Return the chain we have.
        return out;
    }

    tracing::warn!(
        qname = %name,
        max_depth = MAX_CNAME_DEPTH,
        "CNAME chain exceeded max depth in authority zone; truncating",
    );
    out
}

/// Build a [`Snapshot`] from the immutable static state plus the optional
/// loaded mesh bundle. Static records take precedence within a single
/// name (we push them first, so authority lookups that don't care about
/// order still see them).
fn build_snapshot(
    static_records: &HashMap<String, Vec<DnsRecord>>,
    static_zones: &[String],
    mesh: Option<&LoadedBundle>,
) -> Snapshot {
    let mut records: HashMap<String, Vec<DnsRecord>> = static_records.clone();
    let mut zones: Vec<String> = static_zones.to_vec();

    if let Some(loaded) = mesh {
        for rec in &loaded.records {
            records
                .entry(rec.name.clone())
                .or_default()
                .push(rec.clone());
            if !zones.iter().any(|z| z == &rec.name) {
                zones.push(rec.name.clone());
            }
        }
    }

    Snapshot { zones, records }
}

/// Attempt the initial mesh-zone bundle load. Failures are logged and
/// returned as `None` so the daemon can still start in static-only mode.
fn load_mesh_if_configured(config: &AuthorityConfig, mesh_zone: &str) -> Option<LoadedBundle> {
    let (bundle, key) = match (
        config.mesh_zone_bundle_path.as_ref(),
        config.mesh_zone_verifier_key_path.as_ref(),
    ) {
        (Some(b), Some(k)) => (b, k),
        (Some(_), None) | (None, Some(_)) => {
            tracing::warn!(
                "authority.mesh_zone_bundle_path and authority.mesh_zone_verifier_key_path must \
                 both be set to enable mesh integration — running in static-only mode"
            );
            return None;
        }
        (None, None) => return None,
    };

    match mesh::load_mesh_bundle(bundle, key, mesh_zone, config.mesh_zone_max_age_secs) {
        Ok(loaded) => Some(loaded),
        Err(e) => {
            tracing::warn!(
                bundle = %bundle.display(),
                error = %e,
                "mesh zone bundle could not be loaded — running in static-only mode"
            );
            None
        }
    }
}

/// Returns `true` if `name` equals `zone` or is a subdomain of it.
///
/// Both arguments must already be normalised (lowercased, trailing dot).
fn name_within_zone(name: &str, zone: &str) -> bool {
    if name == zone {
        return true;
    }
    // Subdomain: name must be longer and end with ".<zone>"
    name.len() > zone.len()
        && name.ends_with(zone)
        && name.as_bytes()[name.len() - zone.len() - 1] == b'.'
}

/// Normalise a DNS name: lowercase, ensure trailing dot.
fn normalise_name(name: &str) -> String {
    let mut n = name.trim().to_ascii_lowercase();
    if !n.ends_with('.') {
        n.push('.');
    }
    n
}

/// Convert a TOML [`StaticRecord`] into the in-memory [`DnsRecord`] form.
///
/// Returns [`RustyDnsError::Zone`] for unknown record types or missing /
/// unparseable required fields.
fn static_record_to_dns_record(sr: &StaticRecord) -> AuthorityResult<DnsRecord> {
    let ttl = if sr.ttl == 0 {
        STATIC_RECORD_TTL
    } else {
        Duration::from_secs(u64::from(sr.ttl))
    };

    let rtype = sr.record_type.trim().to_ascii_uppercase();
    let data = match rtype.as_str() {
        "A" => {
            let addr = require_address(sr, "A")?;
            let ip: Ipv4Addr = addr.parse().map_err(|e| {
                RustyDnsError::Zone(format!(
                    "static record `{}` has invalid A address `{}`: {}",
                    sr.name, addr, e
                ))
            })?;
            RecordData::A(ip)
        }
        "AAAA" => {
            let addr = require_address(sr, "AAAA")?;
            let ip: Ipv6Addr = addr.parse().map_err(|e| {
                RustyDnsError::Zone(format!(
                    "static record `{}` has invalid AAAA address `{}`: {}",
                    sr.name, addr, e
                ))
            })?;
            RecordData::Aaaa(ip)
        }
        "CNAME" => RecordData::Cname(normalise_name(require_target(sr, "CNAME")?)),
        "PTR" => RecordData::Ptr(normalise_name(require_target(sr, "PTR")?)),
        "TXT" => {
            let target = require_target(sr, "TXT")?;
            RecordData::Txt(vec![target.as_bytes().to_vec()])
        }
        "NS" => RecordData::Ns(normalise_name(require_target(sr, "NS")?)),
        "MX" => {
            let target = require_target(sr, "MX")?;
            let mut parts = target.split_whitespace();
            let pref = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| {
                    RustyDnsError::Zone(format!(
                        "static record `{}` MX target `{}` must be \"<preference> <hostname>\"",
                        sr.name, target
                    ))
                })?;
            let exchange = parts
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    RustyDnsError::Zone(format!(
                        "static record `{}` MX target `{}` missing exchange hostname",
                        sr.name, target
                    ))
                })?;
            if parts.next().is_some() {
                return Err(RustyDnsError::Zone(format!(
                    "static record `{}` MX target `{}` has trailing junk after \"<preference> <hostname>\"",
                    sr.name, target
                )));
            }
            RecordData::Mx {
                preference: pref,
                exchange: normalise_name(exchange),
            }
        }
        "SRV" => {
            let target = require_target(sr, "SRV")?;
            let parts: Vec<&str> = target.split_whitespace().collect();
            if parts.len() != 4 {
                return Err(RustyDnsError::Zone(format!(
                    "static record `{}` SRV target `{}` must be \"<priority> <weight> <port> <hostname>\"",
                    sr.name, target
                )));
            }
            let priority = parse_u16(sr, "SRV priority", parts[0])?;
            let weight = parse_u16(sr, "SRV weight", parts[1])?;
            let port = parse_u16(sr, "SRV port", parts[2])?;
            RecordData::Srv {
                priority,
                weight,
                port,
                target: normalise_name(parts[3]),
            }
        }
        other => {
            return Err(RustyDnsError::Zone(format!(
                "static record `{}` has unsupported type `{}` \
                 (supported: A, AAAA, CNAME, PTR, TXT, MX, NS, SRV)",
                sr.name, other
            )));
        }
    };

    Ok(DnsRecord::new(&sr.name, data, ttl))
}

fn require_address<'a>(sr: &'a StaticRecord, type_label: &str) -> AuthorityResult<&'a str> {
    sr.address
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            RustyDnsError::Zone(format!(
                "static record `{}` of type {} is missing required `address` field",
                sr.name, type_label
            ))
        })
}

fn require_target<'a>(sr: &'a StaticRecord, type_label: &str) -> AuthorityResult<&'a str> {
    sr.target
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            RustyDnsError::Zone(format!(
                "static record `{}` of type {} is missing required `target` field",
                sr.name, type_label
            ))
        })
}

fn parse_u16(sr: &StaticRecord, label: &str, value: &str) -> AuthorityResult<u16> {
    value.parse::<u16>().map_err(|_| {
        RustyDnsError::Zone(format!(
            "static record `{}` {} `{}` is not a valid u16",
            sr.name, label, value
        ))
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(records: Vec<StaticRecord>) -> AuthorityConfig {
        AuthorityConfig {
            mesh_zone_bundle_path: None,
            mesh_zone_verifier_key_path: None,
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records: records,
            poll_interval_secs: 30,
        }
    }

    fn a(name: &str, addr: &str) -> StaticRecord {
        StaticRecord {
            name: name.to_string(),
            record_type: "A".to_string(),
            address: Some(addr.to_string()),
            target: None,
            ttl: 300,
            client_filter: None,
        }
    }

    #[test]
    fn static_a_record_exact_match_returns_record() {
        let auth = Authority::new(cfg(vec![a("host.lab.example.com", "10.0.0.5")])).unwrap();

        let result = auth.lookup("host.lab.example.com", "A").expect("in zone");
        assert_eq!(result.len(), 1);
        match &result[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "10.0.0.5"),
            other => panic!("expected A record, got {other:?}"),
        }
        assert_eq!(result[0].name, "host.lab.example.com.");
    }

    #[test]
    fn wrong_type_returns_authoritative_nxdomain() {
        let auth = Authority::new(cfg(vec![a("host.lab.example.com", "10.0.0.5")])).unwrap();

        let result = auth
            .lookup("host.lab.example.com", "AAAA")
            .expect("in zone");
        assert!(
            result.is_empty(),
            "expected authoritative NXDOMAIN (empty Some)"
        );
    }

    #[test]
    fn name_outside_any_zone_returns_none() {
        let auth = Authority::new(cfg(vec![a("host.lab.example.com", "10.0.0.5")])).unwrap();

        // Not in mesh, not in any static zone — pipeline must continue.
        assert!(auth.lookup("example.org", "A").is_none());
        assert!(auth.lookup("other.example.com", "A").is_none());
    }

    #[test]
    fn name_normalisation_trailing_dot_and_case() {
        let auth = Authority::new(cfg(vec![a("Host.Lab.Example.COM", "10.0.0.5")])).unwrap();

        // Stored normalised; queries via either form must resolve.
        let cases = [
            "host.lab.example.com",
            "host.lab.example.com.",
            "HOST.LAB.EXAMPLE.COM",
            "Host.Lab.Example.Com.",
        ];
        for q in cases {
            let result = auth
                .lookup(q, "a")
                .unwrap_or_else(|| panic!("`{q}` should resolve"));
            assert_eq!(result.len(), 1, "lookup of `{q}` should return one record");
            match &result[0].data {
                RecordData::A(ip) => assert_eq!(ip.to_string(), "10.0.0.5"),
                other => panic!("expected A record for `{q}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_static_record_missing_address_errors() {
        let bad = StaticRecord {
            name: "broken.example.com".to_string(),
            record_type: "A".to_string(),
            address: None, // missing!
            target: None,
            ttl: 300,
            client_filter: None,
        };
        let err = Authority::new(cfg(vec![bad])).expect_err("should reject");
        match err {
            RustyDnsError::Zone(msg) => {
                assert!(msg.contains("broken.example.com"), "msg = {msg}");
                assert!(msg.contains("address"), "msg = {msg}");
            }
            other => panic!("expected Zone error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_static_record_unparseable_address_errors() {
        let err = Authority::new(cfg(vec![a("bad.example.com", "not-an-ip")]))
            .expect_err("should reject");
        match err {
            RustyDnsError::Zone(msg) => {
                assert!(msg.contains("bad.example.com"), "msg = {msg}");
            }
            other => panic!("expected Zone error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_static_record_unknown_type_errors() {
        let bad = StaticRecord {
            name: "weird.example.com".to_string(),
            record_type: "FOO".to_string(),
            address: None,
            target: None,
            ttl: 300,
            client_filter: None,
        };
        let err = Authority::new(cfg(vec![bad])).expect_err("should reject");
        match err {
            RustyDnsError::Zone(msg) => assert!(msg.contains("FOO"), "msg = {msg}"),
            other => panic!("expected Zone error, got {other:?}"),
        }
    }

    #[test]
    fn is_authoritative_covers_mesh_zone_and_static_apexes() {
        let auth = Authority::new(cfg(vec![a("host.lab.example.com", "10.0.0.5")])).unwrap();

        // Mesh zone — apex and subdomains.
        assert!(auth.is_authoritative_for("mesh"));
        assert!(auth.is_authoritative_for("mesh."));
        assert!(auth.is_authoritative_for("router.mesh"));
        assert!(auth.is_authoritative_for("ROUTER.MESH"));
        assert!(auth.is_authoritative_for("a.b.c.mesh."));

        // Static zone apex (the record's own name).
        assert!(auth.is_authoritative_for("host.lab.example.com"));
        assert!(auth.is_authoritative_for("host.lab.example.com."));

        // Outside any zone.
        assert!(!auth.is_authoritative_for("example.com"));
        assert!(!auth.is_authoritative_for("lab.example.com"));
        assert!(!auth.is_authoritative_for("meshx")); // not a subdomain of "mesh."
        assert!(!auth.is_authoritative_for("notmesh"));
    }

    #[test]
    fn cname_target_is_normalised() {
        let r = StaticRecord {
            name: "alias.example.com".to_string(),
            record_type: "CNAME".to_string(),
            address: None,
            target: Some("Target.Example.COM".to_string()),
            ttl: 300,
            client_filter: None,
        };
        let auth = Authority::new(cfg(vec![r])).unwrap();
        let result = auth.lookup("alias.example.com", "CNAME").unwrap();
        assert_eq!(result.len(), 1);
        match &result[0].data {
            RecordData::Cname(t) => assert_eq!(t, "target.example.com."),
            other => panic!("expected CNAME, got {other:?}"),
        }
    }

    #[test]
    fn mx_target_parses_preference_and_exchange() {
        let r = StaticRecord {
            name: "example.com".to_string(),
            record_type: "MX".to_string(),
            address: None,
            target: Some("10 mail.example.com".to_string()),
            ttl: 300,
            client_filter: None,
        };
        let auth = Authority::new(cfg(vec![r])).unwrap();
        let result = auth.lookup("example.com", "MX").unwrap();
        assert_eq!(result.len(), 1);
        match &result[0].data {
            RecordData::Mx {
                preference,
                exchange,
            } => {
                assert_eq!(*preference, 10);
                assert_eq!(exchange, "mail.example.com.");
            }
            other => panic!("expected MX, got {other:?}"),
        }
    }

    #[test]
    fn srv_target_parses_all_four_fields() {
        let r = StaticRecord {
            name: "_sip._tcp.example.com".to_string(),
            record_type: "SRV".to_string(),
            address: None,
            target: Some("10 20 5060 sipserver.example.com".to_string()),
            ttl: 300,
            client_filter: None,
        };
        let auth = Authority::new(cfg(vec![r])).unwrap();
        let result = auth.lookup("_sip._tcp.example.com", "SRV").unwrap();
        assert_eq!(result.len(), 1);
        match &result[0].data {
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!(*priority, 10);
                assert_eq!(*weight, 20);
                assert_eq!(*port, 5060);
                assert_eq!(target, "sipserver.example.com.");
            }
            other => panic!("expected SRV, got {other:?}"),
        }
    }

    #[test]
    fn ttl_zero_uses_static_record_ttl_default() {
        let r = StaticRecord {
            name: "host.example.com".to_string(),
            record_type: "A".to_string(),
            address: Some("10.0.0.1".to_string()),
            target: None,
            ttl: 0,
            client_filter: None,
        };
        let auth = Authority::new(cfg(vec![r])).unwrap();
        let result = auth.lookup("host.example.com", "A").unwrap();
        assert_eq!(result[0].ttl, STATIC_RECORD_TTL);
    }

    #[test]
    fn multiple_records_at_same_name_all_returned() {
        let recs = vec![
            a("multi.example.com", "10.0.0.1"),
            a("multi.example.com", "10.0.0.2"),
        ];
        let auth = Authority::new(cfg(recs)).unwrap();
        let result = auth.lookup("multi.example.com", "A").unwrap();
        assert_eq!(result.len(), 2);
    }

    // -----------------------------------------------------------------
    // Mesh-bundle integration
    // -----------------------------------------------------------------

    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn write_temp(name: &str, contents: &[u8]) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "rustydns-authority-test-{}-{id}-{name}",
            std::process::id()
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents).unwrap();
        p
    }

    /// Build a valid signed bundle and return (bundle_path, key_path).
    /// Fresh `generated_at_unix = now`, `expires_at_unix = now + 600`, nonce 42.
    fn make_bundle(records: &[(&str, &str)], zone: &str) -> (PathBuf, PathBuf) {
        let now = now_secs();
        make_bundle_at(records, zone, now, now + 600, 42)
    }

    /// Build a signed bundle with explicit `generated_at_unix`,
    /// `expires_at_unix`, and `nonce`. Always signs with the same key
    /// (`[7u8; 32]`) so a second bundle written over the first still
    /// verifies under the key the authority loaded at startup — exactly the
    /// shape of a rollback/replay attempt.
    fn make_bundle_at(
        records: &[(&str, &str)],
        zone: &str,
        generated_at_unix: u64,
        expires_at_unix: u64,
        nonce: u64,
    ) -> (PathBuf, PathBuf) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifier_hex: String = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut payload = String::new();
        payload.push_str("version=1\n");
        payload.push_str(&format!("zone_name={zone}\n"));
        payload.push_str("subject_node_id=test\n");
        payload.push_str(&format!("generated_at_unix={generated_at_unix}\n"));
        payload.push_str(&format!("expires_at_unix={expires_at_unix}\n"));
        payload.push_str(&format!("nonce={nonce}\n"));
        payload.push_str(&format!("record_count={}\n", records.len()));
        for (i, (label, ip)) in records.iter().enumerate() {
            payload.push_str(&format!("record.{i}.label={label}\n"));
            payload.push_str(&format!("record.{i}.fqdn={label}.{zone}\n"));
            payload.push_str(&format!("record.{i}.target_node_id=node-{i}\n"));
            payload.push_str(&format!("record.{i}.rr_type=A\n"));
            payload.push_str(&format!("record.{i}.target_addr_kind=mesh_ipv4\n"));
            payload.push_str(&format!("record.{i}.expected_ip={ip}\n"));
            payload.push_str(&format!("record.{i}.ttl_secs=30\n"));
            payload.push_str(&format!("record.{i}.aliases=\n"));
        }
        let sig: String = signing
            .sign(payload.as_bytes())
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let wire = format!("{payload}signature={sig}\n");
        let bundle_path = write_temp("auth-bundle", wire.as_bytes());
        let key_path = write_temp("auth-key", verifier_hex.as_bytes());
        (bundle_path, key_path)
    }

    #[test]
    fn authority_serves_mesh_records_from_bundle() {
        let (bundle_path, key_path) = make_bundle(&[("router", "100.64.0.1")], "mesh");

        let config = AuthorityConfig {
            mesh_zone_bundle_path: Some(bundle_path),
            mesh_zone_verifier_key_path: Some(key_path),
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records: Vec::new(),
            poll_interval_secs: 30,
        };
        let auth = Authority::new(config).unwrap();

        let result = auth.lookup("router.mesh", "A").expect("in zone");
        assert_eq!(result.len(), 1, "router.mesh must resolve");
        match &result[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "100.64.0.1"),
            other => panic!("expected A record, got {other:?}"),
        }
        // Mesh node id is preserved.
        assert!(result[0].mesh_node_id.is_some());
    }

    #[test]
    fn authority_reload_mesh_picks_up_new_bundle() {
        let (bundle_path, key_path) = make_bundle(&[("router", "100.64.0.1")], "mesh");

        let config = AuthorityConfig {
            mesh_zone_bundle_path: Some(bundle_path.clone()),
            mesh_zone_verifier_key_path: Some(key_path),
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records: Vec::new(),
            poll_interval_secs: 30,
        };
        let auth = Authority::new(config).unwrap();

        // Initially 1 record.
        assert_eq!(auth.lookup("router.mesh", "A").unwrap().len(), 1);
        assert!(auth.lookup("nas.mesh", "A").unwrap().is_empty());

        // Rewrite the bundle file with two records, same key.
        let (new_bundle, _) =
            make_bundle(&[("router", "100.64.0.1"), ("nas", "100.64.0.2")], "mesh");
        std::fs::copy(&new_bundle, &bundle_path).unwrap();

        let count = auth.reload_mesh().unwrap().expect("Some");
        assert_eq!(count, 2);

        // New record now visible.
        let nas = auth.lookup("nas.mesh", "A").unwrap();
        assert_eq!(nas.len(), 1);
        match &nas[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "100.64.0.2"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn authority_reload_mesh_preserves_snapshot_on_failure() {
        let (bundle_path, key_path) = make_bundle(&[("router", "100.64.0.1")], "mesh");
        let config = AuthorityConfig {
            mesh_zone_bundle_path: Some(bundle_path.clone()),
            mesh_zone_verifier_key_path: Some(key_path),
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records: Vec::new(),
            poll_interval_secs: 30,
        };
        let auth = Authority::new(config).unwrap();

        // Corrupt the file so reload fails.
        std::fs::write(&bundle_path, b"garbage").unwrap();
        let err = auth.reload_mesh().unwrap_err();
        // Should be MissingSignature (no signature= line found in garbage).
        assert!(matches!(err, MeshBundleError::MissingSignature), "{err:?}");

        // Previous snapshot still serves.
        assert_eq!(auth.lookup("router.mesh", "A").unwrap().len(), 1);
    }

    #[test]
    fn authority_reload_mesh_returns_none_when_unconfigured() {
        let auth = Authority::new(cfg(vec![])).unwrap();
        assert!(matches!(auth.reload_mesh(), Ok(None)));
    }

    // ----- Anti-rollback / replay protection (TODO §2.1 / §4.4) ----------

    /// Helper: build an authority from a bundle path + key path.
    fn auth_from(bundle_path: PathBuf, key_path: PathBuf) -> Authority {
        Authority::new(AuthorityConfig {
            mesh_zone_bundle_path: Some(bundle_path),
            mesh_zone_verifier_key_path: Some(key_path),
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records: Vec::new(),
            poll_interval_secs: 30,
        })
        .unwrap()
    }

    fn router_ip(auth: &Authority) -> String {
        match &auth.lookup("router.mesh", "A").unwrap()[0].data {
            RecordData::A(ip) => ip.to_string(),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn reload_mesh_rejects_rollback_to_older_bundle() {
        // Apply bundle@T (newer), then attempt bundle@T-60 (older but still
        // fresh, same signing key) → must be rejected, snapshot unchanged.
        let now = now_secs();
        let (bundle_path, key_path) =
            make_bundle_at(&[("router", "100.64.0.9")], "mesh", now, now + 600, 5);
        let auth = auth_from(bundle_path.clone(), key_path);
        assert_eq!(router_ip(&auth), "100.64.0.9");

        // Overwrite with an older bundle (generated_at = now-60). Still within
        // the 600s freshness window, so signature + freshness both pass — only
        // the anti-rollback watermark stops it.
        let (older, _) =
            make_bundle_at(&[("router", "100.64.0.1")], "mesh", now - 60, now + 600, 4);
        std::fs::copy(&older, &bundle_path).unwrap();

        let err = auth.reload_mesh().unwrap_err();
        match err {
            MeshBundleError::Rollback {
                candidate_generated_at,
                current_generated_at,
                ..
            } => {
                assert_eq!(candidate_generated_at, now - 60);
                assert_eq!(current_generated_at, now);
            }
            other => panic!("expected Rollback, got {other:?}"),
        }

        // Snapshot unchanged: still the NEWER value.
        assert_eq!(router_ip(&auth), "100.64.0.9");
    }

    #[test]
    fn reload_mesh_allows_identical_bundle_reapply() {
        // The periodic poller re-reads the same file every interval. An
        // identical (generated_at, nonce) must NOT be treated as a rollback —
        // it re-applies idempotently.
        let now = now_secs();
        let (bundle_path, key_path) =
            make_bundle_at(&[("router", "100.64.0.9")], "mesh", now, now + 600, 5);
        let auth = auth_from(bundle_path, key_path);
        // Reload the very same file — equal tuple, must succeed.
        let count = auth.reload_mesh().expect("identical re-apply must succeed");
        assert_eq!(count, Some(1));
        assert_eq!(router_ip(&auth), "100.64.0.9");
    }

    #[test]
    fn reload_mesh_rejects_same_generated_at_lower_nonce() {
        // Same second, lower nonce → orders before → rollback.
        let now = now_secs();
        let (bundle_path, key_path) =
            make_bundle_at(&[("router", "100.64.0.9")], "mesh", now, now + 600, 10);
        let auth = auth_from(bundle_path.clone(), key_path);

        let (lower_nonce, _) =
            make_bundle_at(&[("router", "100.64.0.1")], "mesh", now, now + 600, 9);
        std::fs::copy(&lower_nonce, &bundle_path).unwrap();

        let err = auth.reload_mesh().unwrap_err();
        assert!(matches!(err, MeshBundleError::Rollback { .. }), "{err:?}");
        assert_eq!(router_ip(&auth), "100.64.0.9");
    }

    #[test]
    fn reload_mesh_accepts_same_generated_at_higher_nonce() {
        // Same second, higher nonce → orders after → accepted (a legitimate
        // re-publish within the same wall-clock second).
        let now = now_secs();
        let (bundle_path, key_path) =
            make_bundle_at(&[("router", "100.64.0.1")], "mesh", now, now + 600, 10);
        let auth = auth_from(bundle_path.clone(), key_path);

        let (higher_nonce, _) =
            make_bundle_at(&[("router", "100.64.0.9")], "mesh", now, now + 600, 11);
        std::fs::copy(&higher_nonce, &bundle_path).unwrap();

        let count = auth.reload_mesh().expect("higher nonce must apply");
        assert_eq!(count, Some(1));
        assert_eq!(router_ip(&auth), "100.64.0.9");
    }

    #[test]
    fn reload_mesh_accepts_newer_bundle() {
        // The normal happy path: a genuinely newer bundle advances the zone.
        let now = now_secs();
        let (bundle_path, key_path) =
            make_bundle_at(&[("router", "100.64.0.1")], "mesh", now - 300, now + 600, 1);
        let auth = auth_from(bundle_path.clone(), key_path);
        assert_eq!(router_ip(&auth), "100.64.0.1");

        let (newer, _) = make_bundle_at(&[("router", "100.64.0.9")], "mesh", now, now + 600, 2);
        std::fs::copy(&newer, &bundle_path).unwrap();

        let count = auth.reload_mesh().expect("newer bundle must apply");
        assert_eq!(count, Some(1));
        assert_eq!(router_ip(&auth), "100.64.0.9");
    }

    #[test]
    fn mesh_record_count_excludes_static_records() {
        let (bundle_path, key_path) =
            make_bundle(&[("router", "100.64.0.1"), ("nas", "100.64.0.2")], "mesh");
        let cfg = AuthorityConfig {
            mesh_zone_bundle_path: Some(bundle_path),
            mesh_zone_verifier_key_path: Some(key_path),
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            // Two static records — must NOT be counted in mesh_record_count.
            static_records: vec![
                a("static1.example.com", "10.0.0.1"),
                a("static2.example.com", "10.0.0.2"),
            ],
            poll_interval_secs: 30,
        };
        let auth = Authority::new(cfg).unwrap();
        assert_eq!(auth.mesh_record_count(), 2, "only the 2 mesh records count");
    }

    #[test]
    fn mesh_record_count_zero_when_no_bundle() {
        let auth = Authority::new(cfg(vec![a("static.example.com", "10.0.0.1")])).unwrap();
        assert_eq!(auth.mesh_record_count(), 0);
    }

    // ----- CNAME chain following -----------------------------------------

    fn cname(name: &str, target: &str) -> StaticRecord {
        StaticRecord {
            name: name.to_string(),
            record_type: "CNAME".to_string(),
            address: None,
            target: Some(target.to_string()),
            ttl: 300,
            client_filter: None,
        }
    }

    #[test]
    fn cname_chain_resolves_intra_zone_one_hop() {
        // alias → host (A=10.0.0.5). Query A=alias must return [CNAME, A].
        let auth = Authority::new(cfg(vec![
            cname("alias.lab.example.com", "host.lab.example.com"),
            a("host.lab.example.com", "10.0.0.5"),
        ]))
        .unwrap();

        let result = auth.lookup("alias.lab.example.com", "A").expect("in zone");
        assert_eq!(result.len(), 2, "expected [CNAME, A]; got: {result:?}");
        assert_eq!(result[0].type_name(), "CNAME");
        assert_eq!(result[1].type_name(), "A");
        match &result[1].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "10.0.0.5"),
            other => panic!("expected A record at end of chain, got {other:?}"),
        }
    }

    #[test]
    fn cname_chain_resolves_two_hops() {
        // a → b → c (A=10.0.0.7). Query A=a must return [CNAME(a→b),
        // CNAME(b→c), A(c)].
        let auth = Authority::new(cfg(vec![
            cname("a.lab.example.com", "b.lab.example.com"),
            cname("b.lab.example.com", "c.lab.example.com"),
            a("c.lab.example.com", "10.0.0.7"),
        ]))
        .unwrap();

        let result = auth.lookup("a.lab.example.com", "A").expect("in zone");
        assert_eq!(result.len(), 3, "expected 2 CNAMEs + 1 A: {result:?}");
        assert_eq!(result[0].type_name(), "CNAME");
        assert_eq!(result[1].type_name(), "CNAME");
        assert_eq!(result[2].type_name(), "A");
    }

    #[test]
    fn cname_query_for_cname_type_returns_only_the_cname() {
        // Asking explicitly for CNAME must NOT chase the chain.
        let auth = Authority::new(cfg(vec![
            cname("alias.lab.example.com", "host.lab.example.com"),
            a("host.lab.example.com", "10.0.0.5"),
        ]))
        .unwrap();

        let result = auth
            .lookup("alias.lab.example.com", "CNAME")
            .expect("in zone");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].type_name(), "CNAME");
    }

    #[test]
    fn cname_loop_truncated_at_chain_head() {
        // a → b → a. Query A=a must return the CNAMEs collected up to
        // loop detection without spinning forever.
        let auth = Authority::new(cfg(vec![
            cname("a.lab.example.com", "b.lab.example.com"),
            cname("b.lab.example.com", "a.lab.example.com"),
        ]))
        .unwrap();

        let result = auth.lookup("a.lab.example.com", "A").expect("in zone");
        // Both CNAMEs are recorded before the cycle is hit on the
        // second visit of "a".
        assert_eq!(
            result.len(),
            2,
            "expected the two CNAMEs collected before loop trip: {result:?}",
        );
        assert!(result.iter().all(|r| r.type_name() == "CNAME"));
    }

    #[test]
    fn cname_max_depth_truncates_chain() {
        // 10 hops: 0 → 1 → 2 → ... → 9 (each a CNAME). MAX_CNAME_DEPTH
        // is 8, so the answer must be capped at the first CNAME plus
        // MAX_CNAME_DEPTH further CNAMEs collected during the chase.
        let mut recs = Vec::new();
        for i in 0..9 {
            recs.push(cname(
                &format!("h{i}.lab.example.com"),
                &format!("h{}.lab.example.com", i + 1),
            ));
        }
        // Terminal A so the chain *could* resolve if depth allowed it.
        recs.push(a("h9.lab.example.com", "10.0.0.9"));

        let auth = Authority::new(cfg(recs)).unwrap();
        let result = auth.lookup("h0.lab.example.com", "A").expect("in zone");

        // First CNAME pushed eagerly + up to MAX_CNAME_DEPTH hops chased.
        assert!(
            result.len() <= 1 + MAX_CNAME_DEPTH,
            "chain length {} exceeds 1 + MAX_CNAME_DEPTH = {}: {result:?}",
            result.len(),
            1 + MAX_CNAME_DEPTH,
        );
        assert!(
            result.iter().all(|r| r.type_name() == "CNAME"),
            "expected only CNAMEs since terminal A is past the depth cap",
        );
    }

    #[test]
    fn cname_target_outside_zone_returns_partial_chain() {
        // alias → external.example.org (not in any authoritative zone
        // we own). Should return just the CNAME so the resolver
        // pipeline can chase the rest.
        let auth = Authority::new(cfg(vec![cname(
            "alias.lab.example.com",
            "external.example.org",
        )]))
        .unwrap();

        let result = auth.lookup("alias.lab.example.com", "A").expect("in zone");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].type_name(), "CNAME");
    }

    #[test]
    fn cname_chain_into_mesh_zone_resolves() {
        // alias.example.com → router.mesh — the target is inside our
        // mesh zone (we're authoritative for it even without a bundle
        // loaded, so the chase will land in an authoritative-NoData
        // state and return the CNAME alone).
        let auth = Authority::new(cfg(vec![cname("alias.example.com", "router.mesh")])).unwrap();

        let result = auth.lookup("alias.example.com", "A").expect("in zone");
        // Mesh zone is authoritative; no record at router.mesh in this
        // test → return the single CNAME (authoritative NoData at the
        // chain end).
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].type_name(), "CNAME");
    }

    #[test]
    fn cname_chain_into_mesh_zone_resolves_to_bundle_record() {
        // Static CNAME alias.example.com → router.mesh; bundle loads
        // router.mesh A=100.64.0.7. Chase must cross from the static
        // zone into the mesh zone and return [CNAME, A].
        let (bundle_path, key_path) = make_bundle(&[("router", "100.64.0.7")], "mesh");

        let config = AuthorityConfig {
            mesh_zone_bundle_path: Some(bundle_path),
            mesh_zone_verifier_key_path: Some(key_path),
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records: vec![cname("alias.example.com", "router.mesh")],
            poll_interval_secs: 30,
        };
        let auth = Authority::new(config).unwrap();

        let result = auth.lookup("alias.example.com", "A").expect("in zone");
        assert_eq!(
            result.len(),
            2,
            "expected [CNAME → router.mesh, A=100.64.0.7]: {result:?}",
        );
        assert_eq!(result[0].type_name(), "CNAME");
        match &result[1].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "100.64.0.7"),
            other => panic!("expected terminal A, got {other:?}"),
        }
    }

    #[test]
    fn cname_direct_a_wins_over_chain() {
        // A name with both an A and a CNAME shouldn't normally exist
        // per RFC 1034, but if static config carries one we prefer the
        // direct answer of the requested type and do NOT chase the
        // CNAME. (Defensive.)
        let auth = Authority::new(cfg(vec![
            a("host.lab.example.com", "10.0.0.5"),
            cname("host.lab.example.com", "other.lab.example.com"),
        ]))
        .unwrap();

        let result = auth.lookup("host.lab.example.com", "A").expect("in zone");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].type_name(), "A");
    }
}
