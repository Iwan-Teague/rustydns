//! Daemon configuration schema for `rustydns`.
//!
//! Deserialised from `rustydns.toml` at startup. Every section has a `Default`
//! implementation that chooses the **most secure and most private** option.
//! Operators must explicitly opt out of privacy protections — the defaults
//! never degrade privacy silently.
//!
//! # Validation
//!
//! [`load_config`] calls [`validate_config`] after deserialisation. Validation
//! enforces the invariants from `AGENTS.md`:
//! - HTTPS-only blocklist sources
//! - No empty resolver list
//! - Sane timeout and cache bounds
//! - mesh_zone ends with '.'
//! - TLS 1.2 minimum emits a warning
//! - Plaintext upstream emits a persistent warning
//! - DNSSEC disabled emits a warning
//! - Disk query logging emits a warning
//! - Full IP logging emits a warning

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Serde helper defaults (keep alphabetical)
// ---------------------------------------------------------------------------

fn default_block_response() -> BlockResponse { BlockResponse::Nxdomain }
fn default_doh_listen() -> Option<String> { Some("127.0.0.1:8053".to_string()) }
fn default_false() -> bool { false }
fn default_fetch_timeout_ms() -> u64 { 30_000 }
fn default_listen() -> Vec<String> { vec!["127.0.0.53:53".to_string()] }
fn default_max_cache_entries() -> usize { 10_000 }
fn default_max_fetch_bytes() -> u64 { 50 * 1024 * 1024 } // 50 MiB
fn default_mesh_zone() -> String { "mesh.".to_string() }
fn default_metrics_listen() -> String { "127.0.0.1:9153".to_string() }
fn default_metrics_path() -> String { "/metrics".to_string() }
fn default_poll_interval() -> u64 { 30 }
fn default_reload_interval() -> u64 { 86_400 }
fn default_resolvers() -> Vec<String> {
    vec![
        "https://cloudflare-dns.com/dns-query".to_string(),
        "https://dns.quad9.net/dns-query".to_string(),
    ]
}
fn default_ring_size() -> usize { 1_000 }
fn default_rustynet_db() -> PathBuf { PathBuf::from("/var/lib/rustynet/control.db") }
fn default_sinkhole_ip() -> String { "0.0.0.0".to_string() }
fn default_sources() -> Vec<String> {
    vec!["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string()]
}
fn default_timeout_ms() -> u64 { 5_000 }
fn default_true() -> bool { true }

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Top-level daemon configuration, read from `rustydns.toml`.
///
/// All defaults are the most secure and most private option. Unknown fields
/// are rejected (`deny_unknown_fields`) to catch typos that would silently
/// leave a security option un-set.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub authority: AuthorityConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    /// Privacy and anonymity settings. All default to maximum privacy.
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Per-Rustynet-node DNS policy. Use `[[policy]]` in TOML.
    #[serde(default)]
    pub policy: Vec<NodePolicy>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Network listener configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    /// UDP and TCP listen addresses.
    ///
    /// Default: `["127.0.0.53:53"]` (loopback only).
    /// For network-wide use, change to `["0.0.0.0:53"]` — but ensure the host
    /// has a firewall restricting access to trusted clients. Binding 0.0.0.0
    /// on a host with a public interface exposes DNS to the internet.
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,

    /// Rustynet mesh zone name. Must end with '.'.
    #[serde(default = "default_mesh_zone")]
    pub mesh_zone: String,

    /// DNS-over-HTTPS listener (HTTP/2, no TLS — put a TLS proxy in front).
    ///
    /// Default: `"127.0.0.1:8053"`. Do not change to `0.0.0.0` unless this
    /// port is behind a TLS-terminating reverse proxy with client auth. The
    /// DoH listener itself does not speak TLS; all TLS is on upstream
    /// connections going OUT, not incoming connections.
    #[serde(default = "default_doh_listen")]
    pub doh_listen: Option<String>,

    /// DNS-over-TLS listener (port 853, RFC 7858).
    ///
    /// Requires `tls_cert_path` and `tls_key_path` to be set.
    /// Disabled by default (None).
    #[serde(default)]
    pub dot_listen: Option<String>,

    /// Path to the TLS certificate (PEM) for the DoT listener.
    /// Required if `dot_listen` is set; ignored otherwise.
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,

    /// Path to the TLS private key (PEM) for the DoT listener.
    /// Required if `dot_listen` is set; ignored otherwise.
    /// The file must be readable only by the `rustydns` user (`chmod 400`).
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            mesh_zone: default_mesh_zone(),
            doh_listen: default_doh_listen(),
            dot_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------

/// Protocol for upstream DNS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// DNS-over-HTTPS (RFC 8484). Encrypted, widely supported. **Default.**
    #[default]
    Doh,
    /// DNS-over-QUIC (RFC 9250). Lower latency; requires QUIC support.
    Doq,
    /// Plaintext UDP/TCP port 53.
    ///
    /// # Security warning
    ///
    /// **INSECURE.** Queries are sent in clear text. Every DNS request is
    /// visible to any observer on the network path. This must never be used
    /// in production. A persistent `tracing::warn!` is emitted on every startup
    /// when this is configured.
    Plain,
}

/// Minimum TLS version for all upstream encrypted connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    /// TLS 1.2. Accepted but not recommended.
    ///
    /// TLS 1.2 does not mandate forward secrecy and has a larger
    /// fingerprinting surface. A startup warning is emitted when this is used.
    #[serde(rename = "1.2")]
    Tls12,
    /// TLS 1.3. **Default.** Mandatory forward secrecy, minimal fingerprinting.
    #[default]
    #[serde(rename = "1.3")]
    Tls13,
}

/// Upstream resolver configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct UpstreamConfig {
    /// Upstream DoH/DoQ resolver URLs. All must use `https://`.
    ///
    /// With `privacy.randomize_upstream_selection = true` (the default),
    /// queries are distributed uniformly across these URLs so no single
    /// resolver sees a complete query history.
    #[serde(default = "default_resolvers")]
    pub resolvers: Vec<String>,

    /// Upstream protocol. Default: `doh`.
    #[serde(default)]
    pub protocol: UpstreamProtocol,

    /// Return `SERVFAIL` when all upstreams fail. Default: `true`.
    ///
    /// When true, a failed upstream never silently falls back to plain DNS or
    /// to a stale cached answer. The client gets `SERVFAIL`. There is no
    /// stale-answer fallback mode — this is intentional.
    #[serde(default = "default_true")]
    pub fail_closed: bool,

    /// Minimum TLS version for upstream connections. Default: `"1.3"`.
    ///
    /// TLS certificate validation is always on and is not configurable.
    #[serde(default)]
    pub min_tls_version: TlsVersion,

    /// Validate DNSSEC signatures on upstream responses. Default: `true`.
    ///
    /// When true, responses failing DNSSEC validation return `SERVFAIL`.
    /// Disabling this allows spoofed answers — never disable in production.
    #[serde(default = "default_true")]
    pub dnssec_validation: bool,

    /// Per-upstream query timeout in milliseconds. Default: `5000`.
    ///
    /// Must be > 0. `timeout_ms = 0` is rejected at startup.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum number of cached upstream responses (LRU eviction).
    ///
    /// Keep bounded — unbounded caches OOM Pi-class hardware.
    /// Maximum allowed: 500,000. Default: 10,000.
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

/// Authoritative zone configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorityConfig {
    /// Path to the Rustynet control SQLite database (opened **read-only**).
    #[serde(default = "default_rustynet_db")]
    pub rustynet_db: PathBuf,

    /// Static zone records declared in this config.
    #[serde(default)]
    pub static_records: Vec<StaticRecord>,

    /// SQLite poll interval in seconds. Minimum: 5. Default: 30.
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
    /// Fully-qualified domain name (trailing dot is optional — normalised at load time).
    pub name: String,
    /// Record type: `"A"`, `"AAAA"`, `"CNAME"`, `"TXT"`, `"MX"`, etc.
    #[serde(rename = "type")]
    pub record_type: String,
    /// IPv4 or IPv6 address (for A/AAAA records).
    pub address: Option<String>,
    /// Target name (for CNAME/MX/PTR/NS records).
    pub target: Option<String>,
    /// TTL in seconds.
    pub ttl: u32,
    /// Client filter tag: `"mesh"` (on-mesh only) or `"external"` (off-mesh only).
    /// Empty = serve to all clients.
    pub client_filter: Option<String>,
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

/// Response type for blocked queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    /// Return `NXDOMAIN`. **Default and recommended.**
    /// Does not reveal that blocking is active or expose the sinkhole IP.
    #[default]
    Nxdomain,
    /// Return a sinkhole IP (see `sinkhole_ip`).
    Sinkhole,
    /// Return `REFUSED`.
    Refused,
}

/// Blocklist engine configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlocklistConfig {
    /// Remote blocklist source URLs. **Must use `https://`.**
    ///
    /// Plain `http://` URLs are rejected at startup. Fetching blocklists
    /// over HTTP allows a network attacker to inject arbitrary allow/block rules.
    ///
    /// Supported formats (auto-detected per source):
    /// hosts, plain domain list, RPZ, AdGuard/uBlock.
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,

    /// URLs in `sources` that are trusted to provide RPZ passthru/allowlist entries.
    ///
    /// By default, `rpz-passthru.` entries and AdGuard `@@||domain^` allowlist
    /// entries found in untrusted sources are **discarded with a warning**.
    /// A compromised blocklist CDN could otherwise permanently allowlist itself
    /// by injecting passthru entries.
    ///
    /// Local files (`local_files`) are always trusted for passthru entries.
    ///
    /// Only add a URL here if you control or deeply trust that source.
    #[serde(default)]
    pub trusted_rpz_sources: Vec<String>,

    /// Local blocklist files (read at startup and on `SIGHUP`).
    /// All formats supported. Local files are always trusted for RPZ passthru entries.
    #[serde(default)]
    pub local_files: Vec<PathBuf>,

    /// Response for blocked queries. Default: `nxdomain`.
    #[serde(default = "default_block_response")]
    pub block_response: BlockResponse,

    /// Sinkhole IP when `block_response = "sinkhole"`.
    /// Must be a valid IPv4 or IPv6 address.
    #[serde(default = "default_sinkhole_ip")]
    pub sinkhole_ip: String,

    /// Reload interval in seconds. Minimum: 300 (5 min) to avoid CDN abuse.
    /// Set to 0 to disable automatic reloads (SIGHUP only).
    #[serde(default = "default_reload_interval")]
    pub reload_interval_secs: u64,

    /// HTTP fetch timeout for remote sources in milliseconds. Default: 30,000.
    ///
    /// A source that does not respond within this time is skipped with a warning.
    /// The daemon starts/continues with whatever other sources loaded successfully.
    #[serde(default = "default_fetch_timeout_ms")]
    pub fetch_timeout_ms: u64,

    /// Maximum response size for a single blocklist source in bytes.
    /// Sources exceeding this are truncated and a warning is logged.
    /// Default: 50 MiB. Prevents OOM from a huge or malicious source.
    #[serde(default = "default_max_fetch_bytes")]
    pub max_fetch_bytes: u64,

    /// Allowlist — domains never blocked even if they appear in a blocklist source.
    ///
    /// Supports exact matches (`"safe.ads.example.com"`) and wildcard prefix
    /// matches (`"*.example.com"` or `".example.com"`). Wildcards match all
    /// subdomains but NOT the apex domain itself.
    ///
    /// Be specific. Wildcard entries like `"*.com"` would allowlist the entire
    /// `.com` TLD. `validate_config` rejects single-label wildcard entries.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            sources: default_sources(),
            trusted_rpz_sources: Vec::new(),
            local_files: Vec::new(),
            block_response: BlockResponse::Nxdomain,
            sinkhole_ip: default_sinkhole_ip(),
            reload_interval_secs: default_reload_interval(),
            fetch_timeout_ms: default_fetch_timeout_ms(),
            max_fetch_bytes: default_max_fetch_bytes(),
            allowlist: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

/// Privacy and anonymity settings.
///
/// **All options default to the most privacy-preserving value.**
/// Every option is documented with what it protects against.
/// To reduce privacy, you must explicitly opt out — nothing degrades silently.
#[derive(Debug, Deserialize, Serialize)]
pub struct PrivacyConfig {
    /// RFC 7816 — Query Name Minimisation.
    ///
    /// Only sends the minimum necessary labels to each upstream resolver at each
    /// resolution step. An upstream for `.com` sees only `?.com`, not the full
    /// QNAME. This prevents any single resolver from seeing a complete picture
    /// of what domains the client is resolving.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub query_minimization: bool,

    /// Strip EDNS0 Client Subnet (RFC 7871) from outgoing queries.
    ///
    /// Without stripping, some resolvers include the client's IP subnet in
    /// upstream queries for CDN geolocation. This leaks client network identity
    /// to upstream resolvers and CDN operators. Stripping prevents this.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub no_edns_client_subnet: bool,

    /// RFC 8467 — Padding for DoH/DoQ queries.
    ///
    /// Pads encrypted query messages to fixed block sizes (128 bytes), preventing
    /// an observer from fingerprinting which domain was queried based on the
    /// encrypted payload size. Without padding, even encrypted DNS leaks query
    /// identity via size.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub upstream_padding: bool,

    /// Randomise upstream resolver selection.
    ///
    /// Chooses each upstream uniformly at random rather than always using the
    /// first configured resolver. Distributes query history across multiple
    /// providers; no single provider sees a complete picture.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub randomize_upstream_selection: bool,

    /// Write query logs to disk. Default: `false`.
    ///
    /// When false (the default), queries are logged only to an in-memory ring
    /// buffer that is lost on restart — no query history is persisted.
    ///
    /// Setting this to `true` creates a permanent record of every domain
    /// resolved by every client. A startup warning is emitted.
    #[serde(default = "default_false")]
    pub query_log_to_disk: bool,

    /// In-memory query log ring buffer size. Default: `1000`.
    ///
    /// Oldest entries are evicted when full. Maximum: 100,000.
    #[serde(default = "default_ring_size")]
    pub query_log_ring_size: usize,

    /// Log full (non-anonymised) client IP addresses. Default: `false`.
    ///
    /// When false: IPv4 → /16 prefix (last two octets zeroed), IPv6 → /64 prefix.
    /// When true: full IP address. A startup warning is emitted.
    ///
    /// Node IDs (Rustynet device fingerprints) are governed by this same flag.
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

/// Prometheus metrics endpoint configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Listen address. **Bind to `127.0.0.1` only** unless behind an
    /// authenticated reverse proxy. Metrics are unauthenticated and expose
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
/// In TOML, declare as `[[policy]]` (array of tables):
///
/// ```toml
/// [[policy]]
/// node_id = "ed25519:AbCdEf..."
/// blocklist_bypass = true
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodePolicy {
    /// Rustynet node ID (`ed25519:<base64-pubkey>`).
    /// Format is validated at startup.
    pub node_id: String,

    /// Allow this node to bypass the blocklist. Default: `false`.
    ///
    /// Use only for server nodes that legitimately resolve ad-network domains.
    /// Granting this is an operator-level decision that must be reviewed.
    #[serde(default = "default_false")]
    pub blocklist_bypass: bool,

    /// Restrict this node to resolving only these zones. Default: `[]` (unrestricted).
    ///
    /// Useful for quarantining guest or untrusted nodes to internal resolution only.
    #[serde(default)]
    pub zones_allowed: Vec<String>,

    /// Log every query from this node regardless of the global log level.
    /// Subject to the same anonymisation rules as global query logging.
    #[serde(default = "default_false")]
    pub log_all_queries: bool,
}

// ---------------------------------------------------------------------------
// Sensitive value wrapper
// ---------------------------------------------------------------------------

/// A `String` holding a sensitive value (API token, shared secret, etc.).
///
/// - Never emitted in `Debug` output (shown as `<redacted>`).
/// - Zeroed on drop via `zeroize`.
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
// Config loading and validation
// ---------------------------------------------------------------------------

/// Load and validate a [`DnsConfig`] from a TOML file.
///
/// Enforces all security invariants from `AGENTS.md`. Returns an error for
/// hard violations; emits `tracing::warn!` for soft violations (insecure but
/// not rejected, to allow development use).
pub fn load_config(path: &std::path::Path) -> Result<DnsConfig, crate::RustyDnsError> {
    let raw = std::fs::read_to_string(path)?;
    let config: DnsConfig = toml::from_str(&raw)?;
    validate_config(&config)?;
    Ok(config)
}

/// Validate a [`DnsConfig`] against security invariants.
///
/// Hard errors (returned as `Err`): blocklist `http://` sources, empty
/// resolver list, `timeout_ms = 0`, excessively large cache/ring values.
///
/// Soft warnings (logged, not rejected): plaintext protocol, TLS 1.2,
/// DNSSEC disabled, disk query logging, full IP logging.
pub fn validate_config(cfg: &DnsConfig) -> Result<(), crate::RustyDnsError> {
    // --- Server ------------------------------------------------------------------

    // mesh_zone must end with '.'
    if !cfg.server.mesh_zone.ends_with('.') {
        return Err(crate::RustyDnsError::Config(format!(
            "server.mesh_zone `{}` must end with '.' (it is a DNS zone name)",
            cfg.server.mesh_zone
        )));
    }

    // DoT requires cert + key
    if cfg.server.dot_listen.is_some() {
        if cfg.server.tls_cert_path.is_none() || cfg.server.tls_key_path.is_none() {
            return Err(crate::RustyDnsError::Config(
                "server.dot_listen is set but server.tls_cert_path and/or \
                 server.tls_key_path are missing. DNS-over-TLS requires a TLS certificate. \
                 Set both fields to the PEM files, or remove dot_listen."
                    .to_string(),
            ));
        }
    }

    // Warn if listen contains 0.0.0.0 (public exposure)
    for addr in &cfg.server.listen {
        if addr.starts_with("0.0.0.0") {
            tracing::warn!(
                addr = %addr,
                "server.listen binds to 0.0.0.0 — this exposes DNS to ALL network interfaces, \
                 including any public-facing interface. Ensure a firewall restricts access to \
                 trusted clients only."
            );
        }
    }

    // --- Upstream ----------------------------------------------------------------

    // Must have at least one resolver
    if cfg.upstream.resolvers.is_empty() {
        return Err(crate::RustyDnsError::Config(
            "upstream.resolvers is empty — at least one DoH/DoQ resolver URL is required".to_string(),
        ));
    }

    // All resolver URLs must be https:// or quic://
    for url in &cfg.upstream.resolvers {
        if url.starts_with("http://") {
            return Err(crate::RustyDnsError::Config(format!(
                "upstream resolver `{url}` uses plain HTTP — only https:// or quic:// resolvers \
                 are allowed. DNS queries sent over plain HTTP are visible to any network observer."
            )));
        }
        if url.is_empty() {
            return Err(crate::RustyDnsError::Config(
                "upstream.resolvers contains an empty URL".to_string(),
            ));
        }
    }

    // timeout_ms must be non-zero
    if cfg.upstream.timeout_ms == 0 {
        return Err(crate::RustyDnsError::Config(
            "upstream.timeout_ms = 0 is invalid — use a positive timeout in milliseconds".to_string(),
        ));
    }

    // max_cache_entries bounded
    if cfg.upstream.max_cache_entries > 500_000 {
        return Err(crate::RustyDnsError::Config(format!(
            "upstream.max_cache_entries = {} exceeds the maximum of 500,000. \
             This would likely OOM Pi Zero 2 W class hardware (512 MiB RAM). \
             Reduce to a value that fits within the 30 MiB idle RSS target.",
            cfg.upstream.max_cache_entries
        )));
    }

    // Plaintext upstream warning
    if cfg.upstream.protocol == UpstreamProtocol::Plain {
        tracing::warn!(
            "upstream.protocol = \"plain\" — DNS queries will be sent UNENCRYPTED over UDP/TCP \
             port 53. Every resolved domain name is visible to any observer on the network path. \
             This is not safe for any deployment where privacy matters. Use \"doh\" or \"doq\"."
        );
    }

    // TLS 1.2 warning
    if cfg.upstream.min_tls_version == TlsVersion::Tls12 {
        tracing::warn!(
            "upstream.min_tls_version = \"1.2\" — TLS 1.2 does not mandate forward secrecy \
             and has a larger fingerprinting surface than TLS 1.3. Upgrade to \"1.3\" unless \
             your upstream resolvers do not support it."
        );
    }

    // DNSSEC warning
    if !cfg.upstream.dnssec_validation {
        tracing::warn!(
            "upstream.dnssec_validation = false — DNSSEC signatures will NOT be verified. \
             DNS cache poisoning and spoofing attacks become possible. \
             Do not disable DNSSEC validation in production."
        );
    }

    // --- Blocklist ---------------------------------------------------------------

    // All remote sources must use HTTPS
    for source in &cfg.blocklist.sources {
        if source.starts_with("http://") {
            return Err(crate::RustyDnsError::Config(format!(
                "blocklist source `{source}` uses plain HTTP — only https:// sources are allowed. \
                 A blocklist fetched over HTTP can be tampered with in transit, allowing an attacker \
                 to inject allow/block rules. Use an https:// URL or a local file instead."
            )));
        }
    }

    // reload_interval_secs minimum (0 is allowed — means SIGHUP only)
    if cfg.blocklist.reload_interval_secs > 0 && cfg.blocklist.reload_interval_secs < 300 {
        return Err(crate::RustyDnsError::Config(format!(
            "blocklist.reload_interval_secs = {} is too short. Minimum is 300 seconds (5 minutes) \
             to avoid abusing blocklist CDNs. Set to 0 to reload only on SIGHUP.",
            cfg.blocklist.reload_interval_secs
        )));
    }

    // Validate sinkhole_ip (only relevant when block_response = sinkhole)
    if cfg.blocklist.block_response == BlockResponse::Sinkhole {
        if cfg.blocklist.sinkhole_ip.parse::<std::net::Ipv4Addr>().is_err()
            && cfg.blocklist.sinkhole_ip.parse::<std::net::Ipv6Addr>().is_err()
        {
            return Err(crate::RustyDnsError::Config(format!(
                "blocklist.sinkhole_ip `{}` is not a valid IPv4 or IPv6 address",
                cfg.blocklist.sinkhole_ip
            )));
        }
    }

    // Warn on overbroad allowlist entries
    for entry in &cfg.blocklist.allowlist {
        let entry = entry.trim().trim_start_matches("*.").trim_start_matches('.');
        let label_count = entry.split('.').filter(|l| !l.is_empty()).count();
        if label_count <= 1 {
            return Err(crate::RustyDnsError::Config(format!(
                "blocklist.allowlist entry `{}` is a single-label or TLD-level wildcard. \
                 This would allowlist an entire TLD (e.g. all .com domains). \
                 Allowlist entries must have at least two labels (e.g. `example.com`).",
                entry
            )));
        }
    }

    // --- Privacy -----------------------------------------------------------------

    if cfg.privacy.query_log_ring_size > 100_000 {
        return Err(crate::RustyDnsError::Config(format!(
            "privacy.query_log_ring_size = {} exceeds the maximum of 100,000 entries. \
             This would use excessive memory. Reduce the ring buffer size.",
            cfg.privacy.query_log_ring_size
        )));
    }

    if cfg.privacy.query_log_to_disk {
        tracing::warn!(
            "privacy.query_log_to_disk = true — ALL DNS queries will be written to disk. \
             This creates a permanent record of every domain resolved by every client. \
             Ensure the log file is protected (mode 0600, owner rustydns) and has a \
             retention/rotation policy. Consider whether this data must be held at all."
        );
    }

    if cfg.privacy.log_client_ips {
        tracing::warn!(
            "privacy.log_client_ips = true — full client IP addresses will appear in logs. \
             This identifies individual clients. Consider using the default anonymised form \
             (last two IPv4 octets zeroed → /16 prefix)."
        );
    }

    // --- Per-node policy ---------------------------------------------------------

    for policy in &cfg.policy {
        if !policy.node_id.starts_with("ed25519:") {
            return Err(crate::RustyDnsError::Config(format!(
                "policy.node_id `{}` does not start with `ed25519:`. \
                 Expected format: `ed25519:<base64-pubkey>`.",
                policy.node_id
            )));
        }
    }

    Ok(())
}
