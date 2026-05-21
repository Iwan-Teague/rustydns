//! DNS record model for `rustydns`.
//!
//! This module provides a suite-specific record type that wraps the data
//! types used in the authority layer. Wire-format encoding is delegated
//! to `hickory-proto`; this module concerns itself only with the
//! in-memory representation and suite-specific metadata.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Default TTL for mesh zone records.
///
/// Short enough that peer changes propagate within one TTL cycle.
/// Configurable down to 5 seconds via `authority.poll_interval_secs`.
pub const MESH_RECORD_TTL: Duration = Duration::from_secs(30);

/// Default TTL for static zone records.
pub const STATIC_RECORD_TTL: Duration = Duration::from_secs(300);

/// The data payload of a DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// IPv4 address (A record).
    A(Ipv4Addr),
    /// IPv6 address (AAAA record).
    Aaaa(Ipv6Addr),
    /// Canonical name alias (CNAME record).
    /// The value is a fully-qualified domain name.
    Cname(String),
    /// Reverse DNS pointer (PTR record).
    Ptr(String),
    /// Text record (TXT). Each inner `Vec<u8>` is one string element.
    Txt(Vec<Vec<u8>>),
    /// Mail exchange (MX record).
    Mx {
        /// Preference value (lower = higher priority).
        preference: u16,
        /// Mail server hostname (FQDN).
        exchange: String,
    },
    /// Authoritative name server (NS record).
    Ns(String),
    /// Service locator (SRV record).
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        /// Target hostname (FQDN).
        target: String,
    },
}

impl RecordData {
    /// Returns the DNS record type name as a string (e.g. `"A"`, `"AAAA"`).
    pub fn type_name(&self) -> &'static str {
        match self {
            RecordData::A(_) => "A",
            RecordData::Aaaa(_) => "AAAA",
            RecordData::Cname(_) => "CNAME",
            RecordData::Ptr(_) => "PTR",
            RecordData::Txt(_) => "TXT",
            RecordData::Mx { .. } => "MX",
            RecordData::Ns(_) => "NS",
            RecordData::Srv { .. } => "SRV",
        }
    }
}

/// A single DNS resource record as managed within `rustydns`.
///
/// Wraps the record data with suite-specific metadata (TTL, mesh source).
/// Wire-format encoding uses `hickory-proto`; this type is the in-memory
/// representation used by the authority and authority cache.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Fully-qualified domain name. Always ends with `'.'`.
    pub name: String,

    /// Record data and implicit record type.
    pub data: RecordData,

    /// Time-to-live.
    pub ttl: Duration,

    /// Rustynet mesh node ID that this record was sourced from, if applicable.
    ///
    /// `Some` for records read from the `rustynet-dns-zone` SQLite database.
    /// `None` for static config records.
    pub mesh_node_id: Option<String>,
}

impl DnsRecord {
    /// Create a new record.
    ///
    /// The `name` is normalised to be fully qualified (trailing dot added if
    /// missing) and lowercased.
    pub fn new(name: impl Into<String>, data: RecordData, ttl: Duration) -> Self {
        let mut name = name.into().to_lowercase();
        if !name.ends_with('.') {
            name.push('.');
        }
        Self {
            name,
            data,
            ttl,
            mesh_node_id: None,
        }
    }

    /// Attach a Rustynet mesh node ID to this record.
    ///
    /// Called by `rustydns-authority` when loading records from the Rustynet
    /// SQLite database.
    pub fn with_mesh_node(mut self, node_id: impl Into<String>) -> Self {
        self.mesh_node_id = Some(node_id.into());
        self
    }

    /// Returns the DNS record type name (e.g. `"A"`).
    pub fn type_name(&self) -> &'static str {
        self.data.type_name()
    }
}

impl std::fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} (ttl={}s)",
            self.name,
            self.type_name(),
            match &self.data {
                RecordData::A(ip) => ip.to_string(),
                RecordData::Aaaa(ip) => ip.to_string(),
                RecordData::Cname(n) | RecordData::Ptr(n) | RecordData::Ns(n) => n.clone(),
                RecordData::Txt(parts) => format!("{} TXT parts", parts.len()),
                RecordData::Mx { preference, exchange } =>
                    format!("{preference} {exchange}"),
                RecordData::Srv { priority, weight, port, target } =>
                    format!("{priority} {weight} {port} {target}"),
            },
            self.ttl.as_secs()
        )
    }
}
