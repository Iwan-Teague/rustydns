#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Recursive resolver with DoH/DoQ upstream for `rustydns`.
//!
//! # Security and privacy features
//!
//! All features default to the most secure/private option. They are controlled
//! by [`rustydns_core::config::PrivacyConfig`] and [`rustydns_core::config::UpstreamConfig`].
//!
//! | Feature | RFC | Default | Config key |
//! |---------|-----|---------|------------|
//! | DNS-over-HTTPS upstream | RFC 8484 | ✓ | `upstream.protocol = "doh"` |
//! | DNS-over-QUIC upstream | RFC 9250 | opt-in | `upstream.protocol = "doq"` |
//! | TLS 1.3 minimum | RFC 8446 | ✓ | `upstream.min_tls_version = "1.3"` |
//! | DNSSEC validation | RFC 4033-4035 | ✓ | `upstream.dnssec_validation = true` |
//! | Fail-closed on upstream failure | — | ✓ | `upstream.fail_closed = true` |
//! | Query Name Minimisation | RFC 7816 | ✓ | `privacy.query_minimization = true` |
//! | Strip EDNS Client Subnet | RFC 7871 | ✓ | `privacy.no_edns_client_subnet = true` |
//! | DoH query padding | RFC 8467 | ✓ | `privacy.upstream_padding = true` |
//! | Randomise upstream selection | — | ✓ | `privacy.randomize_upstream_selection = true` |
//!
//! # Fail-closed guarantee
//!
//! When `upstream.fail_closed = true` (the default), a failure of all configured
//! upstreams results in `SERVFAIL` being returned to the client. The resolver
//! **never** silently falls back to plain DNS or to a stale cached answer.
//!
//! # Status
//!
//! Milestone 3 (pending). The structure and public API are defined here;
//! the hickory-resolver integration is the next implementation step.

use rustydns_core::config::{DnsConfig, UpstreamProtocol};
use rustydns_core::RustyDnsError;

/// Result type for resolver operations.
pub type ResolverResult<T> = Result<T, RustyDnsError>;

/// The upstream recursive resolver.
///
/// Wraps `hickory-resolver` with privacy-preserving configuration:
/// query name minimisation, ECS stripping, DoH padding, and randomised
/// upstream selection.
pub struct Resolver {
    config: DnsConfig,
    // TODO (Milestone 3): hickory AsyncResolver, moka cache, TLS client config.
}

impl Resolver {
    /// Build a resolver from the full daemon config.
    ///
    /// # Startup behaviour
    ///
    /// - If `upstream.protocol = "plain"`, emits a persistent `tracing::warn!`
    ///   and continues (the warning was already emitted by config validation,
    ///   but is repeated here so it appears in the service log at query time).
    /// - Validates that all configured resolver URLs use `https://` or `quic://`.
    /// - Builds a TLS client config with the minimum TLS version from config.
    pub async fn new(config: DnsConfig) -> ResolverResult<Self> {
        if config.upstream.protocol == UpstreamProtocol::Plain {
            tracing::warn!(
                "upstream.protocol = \"plain\" — DNS queries will be sent UNENCRYPTED. \
                 This leaks all resolved domain names to network observers."
            );
        }

        tracing::info!(
            resolvers = config.upstream.resolvers.len(),
            protocol  = ?config.upstream.protocol,
            dnssec    = config.upstream.dnssec_validation,
            fail_closed = config.upstream.fail_closed,
            qmin      = config.privacy.query_minimization,
            no_ecs    = config.privacy.no_edns_client_subnet,
            padding   = config.privacy.upstream_padding,
            randomize = config.privacy.randomize_upstream_selection,
            "resolver initialised (stub — hickory integration pending)"
        );

        Ok(Self { config })
    }

    /// Resolve `name` with record type `qtype`.
    ///
    /// # Privacy
    ///
    /// - If `privacy.query_minimization = true`, only the minimum necessary
    ///   labels are sent to each upstream at each resolution step (RFC 7816).
    /// - If `privacy.no_edns_client_subnet = true`, EDNS0 ECS option is
    ///   stripped from all outgoing queries.
    /// - If `privacy.upstream_padding = true`, queries are padded to 128-byte
    ///   blocks (RFC 8467).
    /// - If `privacy.randomize_upstream_selection = true`, the upstream is
    ///   chosen uniformly at random from the configured list.
    ///
    /// # Errors
    ///
    /// Returns [`RustyDnsError::AllUpstreamsFailed`] if all configured
    /// upstreams fail and `fail_closed = true`. Never falls back to plain DNS.
    pub async fn resolve(&self, name: &str, qtype: &str) -> ResolverResult<Vec<String>> {
        // TODO (Milestone 3): implement hickory-resolver integration.
        tracing::debug!(qname = name, qtype = qtype, "resolver stub called");
        Err(RustyDnsError::AllUpstreamsFailed)
    }
}
