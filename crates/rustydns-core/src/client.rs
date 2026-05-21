//! Client identity for per-query policy and anonymised logging.

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
/// - Produce anonymised log representations when `privacy.log_client_ips = false`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId {
    /// Source IP address of the query packet.
    pub source_ip: IpAddr,

    /// Rustynet node ID (`ed25519:<base64>`) if the client is a known mesh peer.
    /// `None` for clients not found in the Rustynet peer table.
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

    /// Returns an anonymised representation of the client IP for log output.
    ///
    /// This is the value that appears in logs when `privacy.log_client_ips = false`:
    /// - IPv4: last octet zeroed (`192.168.1.100` → `192.168.1.0/anon`)
    /// - IPv6: interface identifier (last 64 bits) zeroed
    ///
    /// The node ID (if present) is included unchanged — Rustynet node IDs are
    /// public keys, not personally-identifying information.
    pub fn anonymized(&self) -> AnonymizedClientId {
        let anon_ip = match self.source_ip {
            IpAddr::V4(v4) => {
                let mut octets = v4.octets();
                octets[3] = 0;
                IpAddr::V4(octets.into())
            }
            IpAddr::V6(v6) => {
                let mut segs = v6.segments();
                // Zero the interface identifier (last 64 bits = segments 4-7).
                segs[4] = 0;
                segs[5] = 0;
                segs[6] = 0;
                segs[7] = 0;
                IpAddr::V6(segs.into())
            }
        };
        AnonymizedClientId {
            anon_ip,
            node_id: self.node_id.clone(),
        }
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(node) = &self.node_id {
            write!(f, "{} ({})", self.source_ip, node)
        } else {
            write!(f, "{}", self.source_ip)
        }
    }
}

/// A privacy-safe representation of a [`ClientId`] for log output.
///
/// Produced by [`ClientId::anonymized`]. Use this in all `tracing` calls
/// when `privacy.log_client_ips = false`.
#[derive(Debug)]
pub struct AnonymizedClientId {
    anon_ip: IpAddr,
    node_id: Option<String>,
}

impl fmt::Display for AnonymizedClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(node) = &self.node_id {
            write!(f, "{}/anon ({})", self.anon_ip, node)
        } else {
            write!(f, "{}/anon", self.anon_ip)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn anonymized_ipv4_zeroes_last_octet() {
        let id = ClientId::from_ip("192.168.1.100".parse().unwrap());
        let anon = id.anonymized().to_string();
        assert!(anon.contains("192.168.1.0"), "got: {anon}");
        assert!(!anon.contains("100"), "last octet should be zeroed, got: {anon}");
    }

    #[test]
    fn anonymized_ipv6_zeroes_interface_id() {
        let id = ClientId::from_ip("2001:db8::1".parse().unwrap());
        let anon = id.anonymized().to_string();
        // The interface identifier (last 64 bits) should be zeroed.
        assert!(anon.contains("2001:db8::"), "got: {anon}");
    }

    #[test]
    fn display_includes_node_id_for_mesh_peers() {
        let id = ClientId::from_mesh_peer(
            "10.0.0.1".parse().unwrap(),
            "ed25519:AbCdEf",
        );
        assert!(id.to_string().contains("ed25519:AbCdEf"));
    }
}
