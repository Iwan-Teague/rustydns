//! Daemon configuration schema for `rustydns`.
//!
//! Deserialised from `rustydns.toml` at startup. Every section has a `Default`
//! implementation that chooses the **most secure and most private** option.
//! Operators must explicitly opt out of privacy protections — the defaults
//! never degrade privacy silently.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Serde helper defaults
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_timeout_ms() -> u64 {
    5_000
}
fn default_max_cache_entries() -> usize {
    10_000
}
fn default_resolvers() -> Vec<String> {
    // Two independent resolvers: Cloudflare (1.1.1.1) and Quad9 (privacy-focused).
    // Having two ensures failover without relying on a single provider.
    vec![
        "https://cloudflare-dns.com/dns-query".to_string(),
        "https://dns.quad9.net/dns-query".to_string(),
    ]
}
fn default_rustynet_db() -> PathBuf {
    PathBuf::from("/var/lib/rustynet/control.db")
}
fn default_poll_interval() -> u64 {
    30
}
fn default_sinkhole_ip() -> String {
    "0.0.0.0".to_string()
}
fn default_reload_interval() -> u64 {
    86_400
}
fn default_ring_size() -> usize {
    1_000
}
fn default_metrics_listen() -> String {
    // Localhost only — metrics are not authenticated and must not be public.
    "127.0.0.1:9153".to_string()
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}
fn default_mesh_zone() -> String {
    "mesh.".to_string()
}
fn default_listen() -> Vec<String> {
    vec!["127.0.0.53:53".to_string()]
}
fn default_doh_listen() -> Option<String> {
    // Non-standard port avoids conflict with other HTTPS services on the host.
    // Port 443 is NOT the default; operators must opt in.
    Some("127.0.0.1:8053".to_string())
}
fn default_sources() -> Vec<String> {
    vec![
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Top-level daemon configuration, read from `rustydns.toml`.
///
/// Every field has a secure default; unknown fields are rejected to catch
/// typos that would silently leave a security option un-set.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// Network listener configuration.
    #[serde(default)]
    pub server: ServerConfig,

    /// Upstream resolver configuration.
    #[serde(default)]
    pub upstream: UpstreamConfig,

    /// Authoritative zone configuration (mesh zone + static records).
    #[serde(default)]
    pub authority: AuthorityConfig,

    /// Ad/tracker blocklist configuration.
    #[serde(default)]
    pub blocklist: BlocklistConfig,

    /// Privacy and anonymity settings.
    /// All options default to maximum privacy — opt out explicitly.
    #[serde(default)]
    pub privacy: PrivacyConfig,

    /// Prometheus metrics endpoint.
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Per-Rustynet-node DNS policy overrides.
    #[serde(default)]
    pub policy: Vec<NodePolicy>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Network listener addresses for the DNS daemon.
#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    /// UDP and TCP listen addresses (plain DNS port 53 / DoT port 853).
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,

    /// Rustynet mesh zone name (must end with '.').
    #[serde(default = "default_mesh_zone")]
    pub mesh_zone: String,

    /// DNS-over-HTTPS listener address (axum HTTP/2 server).
    /// Defaults to `127.0.0.1:8053` — non-standard port to avoid conflict
    /// with other HTTPS services. To expose DoH publicly, bind `0.0.0.0:8053`
    /// and put it behind a TLS-terminating reverse proxy.
    #[serde(default = "default_doh_listen")]
    pub doh_listen: Option<String>,

    /// DNS-over-TLS listener address (port 853 per RFC 7858).
    #[serde(default)]
    pub dot_listen: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            mesh_zone: default_mesh_zone(),
            doh_listen: default_doh_listen(),
            dot_listen: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------

/// Protocol used for upstream DNS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// DNS-over-HTTPS (RFC 8484). Encrypted, widely supported. **Default.**
    #[default]
    Doh,
    /// DNS-over-QUIC (RFC 9250). Lower latency on good network paths.
    Doq,
    /// Plaintext UDP/TCP port 53.
    ///
    /// # Security warning
    /// This option is **insecure** — queries are sent in clear text and can
    /// be observed or tampered with on the network. Enabling it emits a
    /// `tracing::warn!` on every startup and is intended only for development.
    Plain,
}

/// Minimum TLS version for all upstream encrypted connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    /// TLS 1.2 — accepted but not recommended.
    /// TLS 1.2 has a larger fingerprinting surface than 1.3.
    #[serde(rename = "1.2")]
    Tls12,
    /// TLS 1.3 — **default**. Mandatory forward secrecy, no legacy cipher
    /// suites, smaller fingerprinting surface.
    #[default]
    #[serde(rename = "1.3")]
    Tls13,
}

/// Upstream resolver configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct UpstreamConfig {
    /// Ordered list of upstream resolver URLs.
    ///
    /// Selection order is **randomised** by default (see `privacy.randomize_upstream_selection`),
    /// which distributes queries across providers to reduce per-resolver correlation.
    /// All URLs must use `https://` scheme. Plain `http://` URLs are rejected at startup.
    #[serde(default = "default_resolvers")]
    pub resolvers: Vec<String>,

    /// Upstream protocol. Default: `doh`.
    #[serde(default)]
    pub protocol: UpstreamProtocol,

    /// Return `SERVFAIL` when all upstreams fail.
    ///
    /// When `true` (default), a failed upstream never silently falls back to
    /// plain DNS or to a stale cached answer. The client gets `SERVFAIL` and
    /// must retry — nothing leaks to an untrusted resolver.
    #[serde(default = "default_true")]
    pub fail_closed: bool,

    /// Minimum TLS version. Default: `1.3`.
    #[serde(default)]
    pub min_tls_version: TlsVersion,

    /// Validate DNSSEC signatures on all upstream responses.
    ///
    /// When `true` (default), responses that fail DNSSEC validation return
    /// `SERVFAIL`. Disabling this allows spoofed answers — do not disable
    /// in production.
    #[serde(default = "default_true")]
    pub dnssec_validation: bool,

    /// Per-upstream query timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum number of cached upstream responses (LRU eviction).
    /// Keep this bounded to avoid OOM on Pi-class hardware.
    #[serde(default = "default_max_cache_entries")]
    pub max_cache_entries: usize,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            resolvers: default_resolvers(),
            protocol: UpstreamProtocol::Doh,
            fail_closed: true,
            min_tls_version: TlsVersion::Tls13,
            dnssec_validation: true,
            timeout_ms: default_timeout_ms(),
            max_cache_entries: default_max_cache_entries(),
        }
    }
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// Configuration for the authoritative zone layer.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorityConfig {
    /// Path to the Rustynet control-plane SQLite database (opened **read-only**).
    /// `rustydns` never writes to this file.
    #[serde(default = "default_rustynet_db")]
    pub rustynet_db: PathBuf,

    /// Static zone records defined in this config file (used before the
    /// Rustynet DB is available or for local overrides).
    #[serde(default)]
    pub static_records: Vec<StaticRecord>,

    /// How often (in seconds) to poll the SQLite database for zone changes.
    /// Reduce this to speed up mesh peer propagation; minimum useful value is 5.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            rustynet_db: default_rustynet_db(),
            static_records: Vec::new(),
            poll_interval_secs: default_poll_interval(),
        }
    }
}

/// A static DNS record declared directly in `rustydns.toml`.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StaticRecord {
    /// Fully-qualified domain name (trailing dot optional — normalised at load time).
    pub name: String,

    /// DNS record type: `"A"`, `"AAAA"`, `"CNAME"`, `"TXT"`, `"MX"`, etc.
    #[serde(rename = "type")]
    pub record_type: String,

    /// IPv4 or IPv6 address (for A/AAAA records).
    pub address: Option<String>,

    /// Target name (for CNAME/MX/PTR records).
    pub target: Option<String>,

    /// Time-to-live in seconds.
    pub ttl: u32,

    /// If set, only serve this record to clients whose source IP matches this
    /// filter tag (`"mesh"` = on-mesh clients, `"external"` = off-mesh).
    pub client_filter: Option<String>,
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

/// How to respond to a blocked query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    /// Return `NXDOMAIN`. **Default and recommended.**
    /// Does not reveal the sinkhole IP or that blocking is active.
    #[default]
    Nxdomain,
    /// Return a sinkhole IP address (see `sinkhole_ip`).
    /// Useful if clients need an IP to display a block page.
    Sinkhole,
    /// Return `REFUSED`.
    Refused,
}

/// Blocklist engine configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlocklistConfig {
    /// Remote blocklist source URLs.
    ///
    /// **Must use `https://`** — plain HTTP sources are rejected at startup
    /// because blocklist content fetched over HTTP can be tampered with.
    ///
    /// Supported formats (auto-detected): hosts, plain domain list, RPZ, AdGuard.
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,

    /// Local blocklist files on disk (read at startup and on `SIGHUP`).
    #[serde(default)]
    pub local_files: Vec<PathBuf>,

    /// Response type for blocked queries.
    #[serde(default)]
    pub block_response: BlockResponse,

    /// Sinkhole IP returned when `block_response = "sinkhole"`.
    /// Ignored when `block_response != "sinkhole"`.
    #[serde(default = "default_sinkhole_ip")]
    pub sinkhole_ip: String,

    /// Interval in seconds between automatic blocklist reloads.
    /// Set to `0` to disable automatic reloads (reload only on `SIGHUP`).
    #[serde(default = "default_reload_interval")]
    pub reload_interval_secs: u64,

    /// Allowlist — domains that are **never** blocked even if they appear in
    /// a blocklist source.
    ///
    /// Supports:
    /// - Exact match: `"safe.ads.example.com"`
    /// - Wildcard prefix: `"*.example.com"` or `".example.com"` — matches
    ///   any subdomain of `example.com`
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            sources: default_sources(),
            local_files: Vec::new(),
            block_response: BlockResponse::Nxdomain,
            sinkhole_ip: default_sinkhole_ip(),
            reload_interval_secs: default_reload_interval(),
            allowlist: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

/// Privacy and anonymity settings.
///
/// **All options default to the most privacy-preserving value.** Disabling
/// any of these requires an explicit opt-out in `rustydns.toml`.
///
/// # Design philosophy
///
/// rustydns treats privacy as a property of the system, not a feature to be
/// toggled on by the user. Every query that escapes to an upstream resolver
/// is a potential data point. These settings minimise what any single party
/// can observe.
#[derive(Debug, Deserialize, Serialize)]
pub struct PrivacyConfig {
    /// **RFC 7816 — Query Name Minimisation.**
    ///
    /// Instead of sending the full query name (`www.example.com`) to upstream
    /// resolvers, send only the labels needed for the current resolution step.
    /// An upstream resolver for `.com` sees only `example.com`, not the full
    /// QNAME. This significantly reduces the information any resolver receives.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub query_minimization: bool,

    /// **Strip EDNS0 Client Subnet (RFC 7871) from outgoing queries.**
    ///
    /// Some resolvers include the client's IP subnet in upstream queries to
    /// improve CDN geolocation. This leaks client network identity to upstream
    /// resolvers and CDN providers. rustydns strips ECS from all outgoing
    /// queries unconditionally when this is `true`.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub no_edns_client_subnet: bool,

    /// **RFC 8467 — Padding for DNS over CoAP/HTTPS/QUIC.**
    ///
    /// Pads DoH/DoQ query and response messages to fixed block sizes (128
    /// bytes by default). Prevents an observer on the network from fingerprinting
    /// which domain was queried based on the size of the encrypted payload.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub upstream_padding: bool,

    /// **Randomise upstream resolver selection.**
    ///
    /// When `true`, the upstream resolver is chosen uniformly at random from
    /// the configured list rather than always trying `resolvers[0]` first.
    /// This distributes query history across multiple resolvers, so no single
    /// resolver sees a complete picture of the client's DNS activity.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub randomize_upstream_selection: bool,

    /// **Write query logs to disk.**
    ///
    /// When `false` (default), queries are logged only to an in-memory ring
    /// buffer that is lost on daemon restart. No query history is persisted
    /// to disk. Set to `true` only if you need persistent audit logs and
    /// accept the privacy trade-off.
    ///
    /// Default: `false`.
    #[serde(default = "default_false")]
    pub query_log_to_disk: bool,

    /// **In-memory query log ring buffer size (number of entries).**
    ///
    /// The oldest entries are silently evicted when the buffer is full.
    /// This bounds memory usage from query logging.
    ///
    /// Default: `1000`.
    #[serde(default = "default_ring_size")]
    pub query_log_ring_size: usize,

    /// **Log full client IP addresses.**
    ///
    /// When `false` (default), only a truncated/anonymised form of the client
    /// IP is written to logs:
    /// - IPv4: last octet zeroed (`192.168.1.100` → `192.168.1.0`)
    /// - IPv6: interface identifier zeroed (last 64 bits)
    ///
    /// Set to `true` only if you need full IP addresses for debugging and
    /// accept the privacy trade-off.
    ///
    /// Default: `false`.
    #[serde(default = "default_false")]
    pub log_client_ips: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            query_minimization: true,
            no_edns_client_subnet: true,
            upstream_padding: true,
            randomize_upstream_selection: true,
            query_log_to_disk: false,
            query_log_ring_size: default_ring_size(),
            log_client_ips: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Prometheus-compatible metrics endpoint configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Listen address for the `/metrics` HTTP endpoint.
    ///
    /// **Bind to localhost only** (`127.0.0.1`) unless the endpoint is behind
    /// an authenticated reverse proxy. Metrics are unauthenticated and expose
    /// query counts, blocklist sizes, and cache hit rates.
    #[serde(default = "default_metrics_listen")]
    pub listen: String,

    /// URL path for the Prometheus scrape endpoint.
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: default_metrics_listen(),
            path: default_metrics_path(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-node policy
// ---------------------------------------------------------------------------

/// Per-Rustynet-node DNS policy override.
///
/// Keyed by Rustynet node ID (the ed25519 public key in `"ed25519:..."` form).
/// Policy entries are matched against [`ClientId::node_id`] at query time.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodePolicy {
    /// Rustynet node ID (`ed25519:<base64-pubkey>`).
    pub node_id: String,

    /// Allow this node to bypass the blocklist entirely.
    ///
    /// Use for server nodes that legitimately need to resolve ad-network
    /// domains (e.g. for testing or monitoring).
    #[serde(default = "default_false")]
    pub blocklist_bypass: bool,

    /// Restrict this node to resolving only these DNS zones.
    ///
    /// Empty list (default) = unrestricted. Useful for quarantining untrusted
    /// or guest nodes to mesh-local resolution only.
    #[serde(default)]
    pub zones_allowed: Vec<String>,

    /// Log every query from this node, regardless of the global log level.
    ///
    /// Useful for auditing a specific node's DNS activity.
    #[serde(default = "default_false")]
    pub log_all_queries: bool,
}

// ---------------------------------------------------------------------------
// Sensitive config wrapper
// ---------------------------------------------------------------------------

/// Wraps a `String` that holds a sensitive value (API token, shared secret).
///
/// The inner value is zeroed on drop and is never emitted in `Debug` output.
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Borrow the secret value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/// Load and validate a [`DnsConfig`] from a TOML file.
///
/// Validation rules enforced here:
/// - All `sources` URLs must use `https://`.
/// - `plain` upstream protocol emits a startup warning.
/// - `query_log_to_disk = true` emits a startup privacy warning.
/// - `log_client_ips = true` emits a startup privacy warning.
/// - `dnssec_validation = false` emits a startup security warning.
pub fn load_config(path: &std::path::Path) -> Result<DnsConfig, crate::RustyDnsError> {
    let raw = std::fs::read_to_string(path)?;
    let config: DnsConfig = toml::from_str(&raw)?;
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(cfg: &DnsConfig) -> Result<(), crate::RustyDnsError> {
    // Reject plain HTTP blocklist sources — content could be tampered with.
    for source in &cfg.blocklist.sources {
        if source.starts_with("http://") {
            return Err(crate::RustyDnsError::Config(format!(
                "blocklist source `{source}` uses plain HTTP — only HTTPS sources are allowed. \
                 Fetching blocklists over HTTP allows an attacker to inject arbitrary domains."
            )));
        }
    }

    // Warn on plaintext upstream DNS.
    if cfg.upstream.protocol == UpstreamProtocol::Plain {
        tracing::warn!(
            "upstream.protocol = \"plain\" — all DNS queries will be sent unencrypted. \
             This leaks query content to network observers and violates the privacy goals \
             of rustydns. Use \"doh\" or \"doq\" in production."
        );
    }

    // Warn on DNSSEC disabled.
    if !cfg.upstream.dnssec_validation {
        tracing::warn!(
            "upstream.dnssec_validation = false — DNSSEC signatures will not be verified. \
             Cache poisoning and DNS spoofing attacks become possible. \
             Do not disable this in production."
        );
    }

    // Warn on disk query logging.
    if cfg.privacy.query_log_to_disk {
        tracing::warn!(
            "privacy.query_log_to_disk = true — all DNS queries will be written to disk. \
             This creates a persistent record of every domain resolved by every client. \
             Ensure the log file is protected and has a retention policy."
        );
    }

    // Warn on full client IP logging.
    if cfg.privacy.log_client_ips {
        tracing::warn!(
            "privacy.log_client_ips = true — full client IP addresses will appear in logs. \
             Consider using the default anonymised form (last octet zeroed)."
        );
    }

    Ok(())
}
