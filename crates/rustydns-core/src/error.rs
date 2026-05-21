//! Unified error type for all `rustydns` crates.

use thiserror::Error;

/// All errors that can occur within the `rustydns` stack.
#[derive(Debug, Error)]
pub enum RustyDnsError {
    // --- Configuration ------------------------------------------------------

    /// A configuration value failed validation.
    #[error("configuration error: {0}")]
    Config(String),

    /// A TOML configuration file could not be parsed.
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    // --- Zone / Authority ---------------------------------------------------

    /// An error in zone data or zone loading.
    #[error("zone error: {0}")]
    Zone(String),

    /// The SQLite database for the Rustynet zone could not be opened or read.
    #[error("rustynet database error: {0}")]
    Database(String),

    // --- Blocklist ----------------------------------------------------------

    /// A blocklist source could not be fetched or parsed.
    #[error("blocklist error: {0}")]
    Blocklist(String),

    // --- Resolver -----------------------------------------------------------

    /// A generic resolver error.
    #[error("resolver error: {0}")]
    Resolver(String),

    /// A specific upstream resolver failed.
    #[error("upstream error for {upstream}: {source}")]
    Upstream {
        /// The URL of the upstream resolver that failed.
        upstream: String,
        /// The underlying error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// All configured upstreams failed and `fail_closed = true`.
    ///
    /// The daemon returns `SERVFAIL` to the client rather than leaking the
    /// query to an untrusted fallback.
    #[error("all upstream resolvers failed — returning SERVFAIL (fail_closed = true)")]
    AllUpstreamsFailed,

    /// A response failed DNSSEC validation.
    #[error("DNSSEC validation failed for `{name}`: {reason}")]
    DnssecValidation {
        /// The queried domain name.
        name: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    // --- Policy -------------------------------------------------------------

    /// A query was rejected by the per-node policy engine.
    #[error("policy denied query from `{client}` for zone `{zone}`")]
    PolicyDenied {
        /// Anonymised client identifier.
        client: String,
        /// The zone the client attempted to query.
        zone: String,
    },

    // --- I/O ----------------------------------------------------------------

    /// A filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // --- TLS ----------------------------------------------------------------

    /// A TLS handshake or certificate error on an upstream connection.
    #[error("TLS error for {upstream}: {reason}")]
    Tls {
        /// The upstream URL.
        upstream: String,
        /// Reason string (certificate validation failure, version mismatch, etc.).
        reason: String,
    },
}
