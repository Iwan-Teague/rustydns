//! Client identity for per-query policy and privacy-safe logging.
//!
//! # Design: forced explicit choice at log sites
//!
//! `ClientId` deliberately does **not** implement `fmt::Display`. This is a
//! type-system enforcement of the log-redaction invariant from `AGENTS.md`:
//!
//! > Any use of the full IP in a log call requires an explicit
//! > `if privacy.log_client_ips` guard.
//!
//! Without `Display`, a developer cannot accidentally write `%client_id` in a
//! `tracing` call and log a full IP. They must choose one of:
//!
//! - `client.anonymized()` — always safe, always appropriate in production.
//! - `client.full()` — must only be used inside an `if config.privacy.log_client_ips` block.
//!
//! The type system enforces the choice; code review enforces the guard.
//!
//! # Anonymisation standard
//!
//! IPv4: last **two** octets zeroed, producing a /16 prefix.
//! `192.168.1.100` → `192.168.0.0/anon`
//!
//! Zeroing only the last octet (/24) is insufficient: on a typical home
//! network a /24 contains 2–10 devices, making re-identification trivial.
//! A /16 prefix retains enough information to identify the network segment
//! while preventing per-device identification in most deployments.
//!
//! IPv6: interface identifier (last 64 bits) zeroed.
//! `2001:db8::dead:beef:1234:5678` → `2001:db8::/anon`
//!
//! # Node IDs
//!
//! Rustynet node IDs (ed25519 public keys) are **stable long-lived device
//! fingerprints**. They correlate queries across IP changes and reboots. Their
//! logging is governed by the same `log_client_ips` flag as source IPs.
//! They must not appear in `anonymized()` output.

use std::fmt;
use std::net::IpAddr;

/// Identifies the source of a DNS query.
///
/// On a Rustynet mesh, clients are identified by their Rustynet node ID
/// (derived from their ed25519 public key). For off-mesh clients, only
/// the source IP is available.
///
/// `ClientId` is used to:
/// - Apply per-node policy (blocklist bypass, zone restrictions).
/// - Produce log representations via [`ClientId::anonymized`] (always safe)
///   or [`ClientId::full`] (requires `privacy.log_client_ips = true` guard).
///
/// # Note on `Display`
///
/// `ClientId` intentionally does **not** implement `fmt::Display`. See the
/// module-level documentation for the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId {
    /// Source IP address of the query packet.
    pub source_ip: IpAddr,

    /// Rustynet node ID (`ed25519:<base64>`) if the client is a known mesh peer.
    /// `None` for clients not found in the Rustynet peer table.
    ///
    /// This is a stable long-lived device identifier and must be treated
    /// with the same sensitivity as `source_ip`.
    pub node_id: Option<String>,
}

impl ClientId {
    /// Create a `ClientId` from a bare IP address (non-mesh or unknown client).
    pub fn from_ip(ip: IpAddr) -> Self {
        Self {
            source_ip: ip,
            node_id: None,
        }
    }

    /// Create a `ClientId` for a known Rustynet mesh peer.
    pub fn from_mesh_peer(ip: IpAddr, node_id: impl Into<String>) -> Self {
        Self {
            source_ip: ip,
            node_id: Some(node_id.into()),
        }
    }

    /// Whether this client is a known Rustynet mesh peer.
    pub fn is_mesh_peer(&self) -> bool {
        self.node_id.is_some()
    }

    /// Returns an anonymised representation for production log output.
    ///
    /// **Always use this in `tracing` calls unless `privacy.log_client_ips = true`
    /// has been explicitly checked.**
    ///
    /// Anonymisation:
    /// - IPv4: last two octets zeroed (→ /16 prefix). E.g. `192.168.1.100` → `192.168.0.0/anon`
    /// - IPv6: interface identifier (last 64 bits) zeroed. E.g. `2001:db8::1` → `2001:db8::/anon`
    /// - Node ID: **omitted entirely** (stable long-lived identifier).
    ///
    /// The /16 threshold is chosen because:
    /// - /24 is too narrow: a home network often has ≤ 10 devices in a /24.
    /// - /16 gives ~65k possible addresses per prefix, sufficient to prevent
    ///   per-device identification in all but extremely small deployments.
    pub fn anonymized(&self) -> AnonymizedClientId {
        let anon_ip = match self.source_ip {
            IpAddr::V4(v4) => {
                let mut octets = v4.octets();
                // Zero the last TWO octets → /16 prefix.
                octets[2] = 0;
                octets[3] = 0;
                IpAddr::V4(octets.into())
            }
            IpAddr::V6(v6) => {
                let mut segs = v6.segments();
                // Zero the interface identifier (last 64 bits = segments 4–7).
                segs[4] = 0;
                segs[5] = 0;
                segs[6] = 0;
                segs[7] = 0;
                IpAddr::V6(segs.into())
            }
        };
        // Node ID is intentionally omitted: it is a stable long-lived device
        // fingerprint that would correlate queries across IP changes.
        AnonymizedClientId { anon_ip }
    }

    /// Returns the full (non-anonymised) client identity.
    ///
    /// # Safety requirement
    ///
    /// This must only be called inside a guard:
    /// ```rust,ignore
    /// if config.privacy.log_client_ips {
    ///     tracing::debug!(client = %client.full(), "query received");
    /// } else {
    ///     tracing::debug!(client = %client.anonymized(), "query received");
    /// }
    /// ```
    ///
    /// Using this in a `tracing` call without the guard is a privacy violation.
    pub fn full(&self) -> FullClientId {
        FullClientId {
            source_ip: self.source_ip,
            node_id: self.node_id.clone(),
        }
    }
}

// ClientId does NOT implement Display. See module doc for why.

/// A privacy-safe anonymised representation of a client for log output.
///
/// Produced by [`ClientId::anonymized`]. Implements `Display` so it can be
/// used directly in `tracing` field values: `client = %client.anonymized()`.
///
/// The IP is truncated to /16 (IPv4) or /64 (IPv6). The node ID is omitted.
#[derive(Debug)]
pub struct AnonymizedClientId {
    anon_ip: IpAddr,
}

impl fmt::Display for AnonymizedClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.anon_ip {
            IpAddr::V4(_) => write!(f, "{}/16/anon", self.anon_ip),
            IpAddr::V6(_) => write!(f, "{}/64/anon", self.anon_ip),
        }
    }
}

/// The full (non-anonymised) client identity for use when `log_client_ips = true`.
///
/// Produced by [`ClientId::full`]. Only use inside an explicit
/// `if config.privacy.log_client_ips` guard.
#[derive(Debug)]
pub struct FullClientId {
    source_ip: IpAddr,
    node_id: Option<String>,
}

impl fmt::Display for FullClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(node) = &self.node_id {
            write!(f, "{} ({})", self.source_ip, node)
        } else {
            write!(f, "{}", self.source_ip)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymized_ipv4_zeroes_last_two_octets() {
        let id = ClientId::from_ip("192.168.1.100".parse().unwrap());
        let anon = id.anonymized().to_string();
        // Last two octets should be 0
        assert!(anon.contains("192.168.0.0"), "expected /16, got: {anon}");
        assert!(!anon.contains(".1.100"), "last two octets must be zeroed, got: {anon}");
        assert!(!anon.contains(".1."), "third octet must be zeroed, got: {anon}");
    }

    #[test]
    fn anonymized_ipv4_preserves_first_two_octets() {
        let id = ClientId::from_ip("10.20.30.40".parse().unwrap());
        let anon = id.anonymized().to_string();
        assert!(anon.contains("10.20.0.0"), "got: {anon}");
    }

    #[test]
    fn anonymized_ipv6_zeroes_interface_id() {
        let id = ClientId::from_ip("2001:db8:0:1:dead:beef:1234:5678".parse().unwrap());
        let anon = id.anonymized().to_string();
        // Segments 4-7 should be zeroed; segments 0-3 preserved
        assert!(anon.contains("2001:db8:0:1::"), "got: {anon}");
        assert!(!anon.contains("dead"), "interface ID should be zeroed, got: {anon}");
    }

    #[test]
    fn anonymized_omits_node_id() {
        let id = ClientId::from_mesh_peer(
            "10.0.0.1".parse().unwrap(),
            "ed25519:AbCdEf",
        );
        let anon = id.anonymized().to_string();
        assert!(!anon.contains("ed25519"), "node ID must be omitted from anonymized output, got: {anon}");
    }

    #[test]
    fn full_includes_node_id() {
        let id = ClientId::from_mesh_peer(
            "10.0.0.1".parse().unwrap(),
            "ed25519:AbCdEf",
        );
        let full = id.full().to_string();
        assert!(full.contains("ed25519:AbCdEf"), "got: {full}");
        assert!(full.contains("10.0.0.1"), "got: {full}");
    }

    #[test]
    fn anonymized_shows_prefix_length() {
        let id = ClientId::from_ip("192.168.1.1".parse().unwrap());
        assert!(id.anonymized().to_string().contains("/16/anon"));

        let id6 = ClientId::from_ip("::1".parse().unwrap());
        assert!(id6.anonymized().to_string().contains("/64/anon"));
    }
}
