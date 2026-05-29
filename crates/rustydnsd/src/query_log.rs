#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded in-memory query log ring buffer, with an optional on-disk fan-out.
//!
//! Per `AGENTS.md §Privacy invariants`:
//!
//! - The ring buffer is **in-memory** and bounded by
//!   `privacy.query_log_ring_size` (default 1000, max 100,000).
//! - Stores only **anonymised** client identifiers and **hashed** query
//!   names. The full QNAME never enters the buffer — even an operator
//!   with shell access on the daemon host cannot recover the queried
//!   domain from the buffer alone.
//! - Disk persistence (`privacy.query_log_to_disk = true`) is a separate
//!   opt-in that emits a startup warning. When enabled, each recorded
//!   entry is *also* sent over a bounded channel to the on-disk NDJSON
//!   writer in [`crate::query_log_disk`]. The same [`QueryLogEntry`] —
//!   hashed qname, anonymised client — is what reaches disk; there is no
//!   path that writes a raw QNAME or full IP. See `query_log_disk.rs`.
//!
//! # Why hash instead of redact?
//!
//! Hashing lets an operator answer "did this domain hit the resolver in
//! the last N queries?" by hashing the candidate domain and grepping —
//! the same workflow as `/etc/hosts` style debugging — without ever
//! storing a recoverable plaintext list. The hash is keyed with a
//! per-process random salt, so a leaked buffer cannot be cross-referenced
//! to another deployment.
//!
//! # Capacity
//!
//! When the buffer is full, the oldest entry is evicted on insert
//! (`VecDeque::pop_front`). All operations are O(1).

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use prometheus::IntCounter;

use rustydns_core::client::ClientId;

/// Which arm of the pipeline served the query — useful when diagnosing
/// "why did this domain return NXDOMAIN".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServedBy {
    /// Authority returned a record (or authoritative NODATA).
    Authority,
    /// Blocklist returned the configured `block_response`.
    Blocklist,
    /// Resolver forwarded to an upstream and returned its answer.
    Resolver,
    /// Resolver failed and fail-closed → SERVFAIL.
    ServerFailure,
    /// Pre-pipeline rejection (e.g. non-Query opcode → NotImp).
    Rejected,
}

impl ServedBy {
    /// Short stable label for serialisation / metrics.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            ServedBy::Authority => "authority",
            ServedBy::Blocklist => "blocklist",
            ServedBy::Resolver => "resolver",
            ServedBy::ServerFailure => "servfail",
            ServedBy::Rejected => "rejected",
        }
    }
}

/// One entry in the query log ring buffer.
///
/// Crucially, this struct does NOT carry the raw query name. The
/// `qname_hash` field is a u64 hash keyed with a per-process salt;
/// reversing it to a domain is computationally infeasible.
///
/// Some fields are read only by the (planned) inspection endpoint —
/// `#[allow(dead_code)]` keeps the warning lid down until that lands.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct QueryLogEntry {
    /// Unix seconds when the query was received.
    pub timestamp_unix: u64,

    /// Anonymised client representation. Always safe to log/expose.
    /// See [`ClientId::anonymized`].
    pub client_anonymised: AnonymisedClient,

    /// Salted hash of the lowercased FQDN. Use [`QueryLog::hash_qname`] to compute.
    pub qname_hash: u64,

    /// RFC 1035 query type (`A`, `AAAA`, ...). Stored as a small string
    /// label for compactness — never the raw integer code, so we don't
    /// accidentally leak the discriminator of obscure record types.
    pub qtype: &'static str,

    /// Numeric DNS response code (`NoError`=0, `FormErr`=1, `ServFail`=2,
    /// `NXDomain`=3, ...). Stored as raw `u8` because the hickory
    /// `ResponseCode` enum isn't `Copy`-friendly across our boundaries
    /// and the wire-level value is what an operator wants to grep for.
    pub rcode: u8,

    /// Which pipeline arm produced the answer.
    pub served_by: ServedBy,
}

/// 48-byte anonymised string form of the client. Sized to fit IPv4
/// `/16` and IPv6 `/64` prefix representations without heap allocation.
/// We never store the full IP — that would defeat the privacy invariant.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct AnonymisedClient {
    bytes: [u8; 48],
    len: u8,
}

impl AnonymisedClient {
    /// Build from a [`ClientId`].
    pub fn from_client(client: &ClientId) -> Self {
        // ClientId::anonymized returns AnonymizedClientId, which only
        // exposes its identity via fmt::Display — exactly to prevent
        // accidental misuse of the raw IP. Render through Display once,
        // store as bounded bytes.
        let s = client.anonymized().to_string();
        let bytes_in = s.as_bytes();
        let len = bytes_in.len().min(48);
        let mut bytes = [0u8; 48];
        bytes[..len].copy_from_slice(&bytes_in[..len]);
        Self {
            bytes,
            len: len as u8,
        }
    }

    /// View as a string slice. Never panics; falls back to "?" if the
    /// stored bytes aren't valid UTF-8 (should be unreachable in
    /// practice — `ClientId::anonymized` produces ASCII).
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("?")
    }
}

impl QueryLogEntry {
    /// Render this entry as a single-line JSON object (no trailing
    /// newline). Used by both the `/queries` endpoint and the on-disk
    /// NDJSON writer so the two never drift. Every field is a primitive
    /// or a known-ASCII string; the client string is JSON-escaped
    /// defensively even though `ClientId::anonymized` never emits a
    /// JSON-significant character.
    ///
    /// Privacy: by construction this carries only the **hashed** qname
    /// and the **anonymised** client — never a raw QNAME or full IP.
    pub fn to_json(self) -> String {
        format!(
            "{{\"ts\":{},\"client\":\"{}\",\"qname_hash\":\"{:016x}\",\"qtype\":\"{}\",\"rcode\":{},\"served_by\":\"{}\"}}",
            self.timestamp_unix,
            json_escape(self.client_anonymised.as_str()),
            self.qname_hash,
            self.qtype,
            self.rcode,
            self.served_by.as_str()
        )
    }
}

/// Escape the small set of JSON-significant characters that
/// `ClientId::anonymized` could theoretically produce. In practice the
/// output is `<ip>/<prefix>/anon`, which contains none of them — this is
/// belt-and-braces against a future change to the formatter.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Bounded in-memory query log.
///
/// Optionally fans each recorded entry out to an on-disk NDJSON writer
/// via a bounded channel (see [`QueryLog::with_disk_sink`]). The send is
/// non-blocking: if the writer falls behind and the channel fills, the
/// entry is dropped from the disk stream (counted in `disk_dropped`)
/// rather than stalling the DNS hot path. The in-memory ring buffer is
/// unaffected by disk back-pressure.
#[derive(Debug)]
pub struct QueryLog {
    capacity: usize,
    salt: u64,
    inner: Mutex<VecDeque<QueryLogEntry>>,
    /// `Some` only when `privacy.query_log_to_disk = true` and the disk
    /// writer started successfully.
    disk_tx: Option<tokio::sync::mpsc::Sender<QueryLogEntry>>,
    /// Incremented when an entry is dropped from the disk stream because
    /// the channel was full (writer behind). Surfaced as
    /// `rustydns_query_log_disk_dropped_total`.
    disk_dropped: Option<IntCounter>,
}

impl QueryLog {
    /// Create a new in-memory-only buffer with the given capacity. A
    /// `capacity` of 0 produces an "always-empty" log — `record()`
    /// becomes a no-op, useful when an operator wants to disable the
    /// buffer entirely.
    pub fn new(capacity: usize) -> Self {
        let salt: u64 = rand::random();
        Self {
            capacity,
            salt,
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            disk_tx: None,
            disk_dropped: None,
        }
    }

    /// Create a buffer that also fans entries out to the on-disk writer
    /// over `disk_tx`. `disk_dropped` is incremented whenever the channel
    /// is full and an entry is dropped from the disk stream. The
    /// in-memory ring still works exactly as in [`QueryLog::new`].
    pub fn with_disk_sink(
        capacity: usize,
        disk_tx: tokio::sync::mpsc::Sender<QueryLogEntry>,
        disk_dropped: IntCounter,
    ) -> Self {
        let mut log = Self::new(capacity);
        log.disk_tx = Some(disk_tx);
        log.disk_dropped = Some(disk_dropped);
        log
    }

    /// Hash a (lowercased) qname using the per-process salt. Operators
    /// who want to look up a domain in the buffer should call this with
    /// the same lowercased FQDN form.
    pub fn hash_qname(&self, qname_lower: &str) -> u64 {
        let mut hasher = ahash::AHasher::default();
        self.salt.hash(&mut hasher);
        qname_lower.hash(&mut hasher);
        hasher.finish()
    }

    /// Record a query. Fans out to the on-disk writer (if enabled) and
    /// pushes into the in-memory ring (if `capacity > 0`), evicting the
    /// oldest entry when the ring is full. Cheap: one non-blocking
    /// channel send + one Mutex acquire + one VecDeque push.
    pub fn record(
        &self,
        client: &ClientId,
        qname_lower: &str,
        qtype: &'static str,
        rcode: u8,
        served_by: ServedBy,
    ) {
        // Nothing to do when both sinks are off.
        if self.capacity == 0 && self.disk_tx.is_none() {
            return;
        }
        let entry = QueryLogEntry {
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            client_anonymised: AnonymisedClient::from_client(client),
            qname_hash: self.hash_qname(qname_lower),
            qtype,
            rcode,
            served_by,
        };
        // Fan out to the on-disk writer first (cheap, non-blocking). A
        // full channel means the writer is behind; we drop from the disk
        // stream rather than stall the DNS path. The in-memory ring below
        // is never affected by disk back-pressure.
        if let Some(tx) = &self.disk_tx
            && tx.try_send(entry).is_err()
            && let Some(c) = &self.disk_dropped
        {
            c.inc();
        }

        if self.capacity == 0 {
            return;
        }
        let mut buf = self.inner.lock().expect("query log lock poisoned");
        if buf.len() == self.capacity {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Snapshot the current buffer, newest entry first. Allocates a
    /// `Vec<QueryLogEntry>`; intended for the (future) operator
    /// inspection endpoint and for tests.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<QueryLogEntry> {
        let buf = self.inner.lock().expect("query log lock poisoned");
        buf.iter().rev().copied().collect()
    }

    /// Current entry count.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("query log lock poisoned").len()
    }

    /// True if the buffer holds no entries.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum entries the buffer can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn client() -> ClientId {
        ClientId::from_ip(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
    }

    #[test]
    fn records_and_snapshots_in_newest_first_order() {
        let log = QueryLog::new(4);
        for i in 0..3 {
            let qname = format!("host-{i}.example.com");
            log.record(&client(), &qname, "A", 0, ServedBy::Resolver);
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), 3);
        // Newest-first ordering: hashes for host-2 should be at index 0.
        assert_eq!(snap[0].qname_hash, log.hash_qname("host-2.example.com"));
        assert_eq!(snap[2].qname_hash, log.hash_qname("host-0.example.com"));
    }

    #[test]
    fn capacity_evicts_oldest() {
        let log = QueryLog::new(3);
        for i in 0..5 {
            let qname = format!("host-{i}");
            log.record(&client(), &qname, "A", 0, ServedBy::Resolver);
        }
        assert_eq!(log.len(), 3);
        let snap = log.snapshot();
        // Only host-2, host-3, host-4 should remain.
        let h4 = log.hash_qname("host-4");
        let h3 = log.hash_qname("host-3");
        let h2 = log.hash_qname("host-2");
        assert_eq!(snap[0].qname_hash, h4);
        assert_eq!(snap[1].qname_hash, h3);
        assert_eq!(snap[2].qname_hash, h2);
    }

    #[test]
    fn capacity_zero_is_a_noop() {
        let log = QueryLog::new(0);
        log.record(&client(), "x.example.com", "A", 0, ServedBy::Resolver);
        assert!(log.is_empty());
        assert!(log.snapshot().is_empty());
    }

    #[test]
    fn hash_is_stable_across_calls_within_one_log() {
        let log = QueryLog::new(4);
        let a = log.hash_qname("example.com.");
        let b = log.hash_qname("example.com.");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_differs_across_logs_due_to_random_salt() {
        // The two logs were seeded from independent thread_rng draws; with
        // overwhelming probability they produce different hashes for the
        // same input.
        let log1 = QueryLog::new(4);
        let log2 = QueryLog::new(4);
        let a = log1.hash_qname("example.com.");
        let b = log2.hash_qname("example.com.");
        assert_ne!(a, b, "salts collided — improbable, regenerate to confirm");
    }

    #[test]
    fn anonymised_client_round_trips() {
        let c = client();
        let a = AnonymisedClient::from_client(&c);
        // 10.0.x.x with /16 anonymisation → "10.0.0.0/16/anon" (or similar
        // formatted by ClientId::anonymized — we don't care about the
        // exact string, only that it's bounded and printable).
        assert!(!a.as_str().is_empty());
        assert!(a.as_str().contains("10.0"));
    }

    #[test]
    fn served_by_label_is_stable() {
        assert_eq!(ServedBy::Authority.as_str(), "authority");
        assert_eq!(ServedBy::Blocklist.as_str(), "blocklist");
        assert_eq!(ServedBy::Resolver.as_str(), "resolver");
        assert_eq!(ServedBy::ServerFailure.as_str(), "servfail");
        assert_eq!(ServedBy::Rejected.as_str(), "rejected");
    }
}
