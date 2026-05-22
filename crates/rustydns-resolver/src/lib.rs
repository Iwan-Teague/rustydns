#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Recursive resolver with DoH/plain upstream for `rustydns`.
//!
//! Wraps `hickory-resolver` with rustydns' privacy/security posture:
//! TLS 1.3 floor, no EDNS Client Subnet, fail-closed on upstream failure,
//! and randomised upstream selection across a configured list.
//!
//! # Security and privacy features
//!
//! | Feature | RFC | Default | Config key | Status |
//! |---------|-----|---------|------------|--------|
//! | DNS-over-HTTPS upstream | RFC 8484 | ✓ | `upstream.protocol = "doh"` | implemented |
//! | DNS-over-QUIC upstream | RFC 9250 | opt-in | `upstream.protocol = "doq"` | implemented (via hickory `quic-ring` feature → `NameServerConfig::quic`) |
//! | TLS 1.3 minimum | RFC 8446 | ✓ | `upstream.min_tls_version = "1.3"` | implemented |
//! | DNSSEC validation | RFC 4033-4035 | ✓ | `upstream.dnssec_validation = true` | implemented (passes through `ResolverOpts.validate`) |
//! | Fail-closed on upstream failure | — | ✓ | `upstream.fail_closed = true` | implemented |
//! | Strip EDNS Client Subnet | RFC 7871 | ✓ | `privacy.no_edns_client_subnet = true` | implemented (we never set ECS) |
//! | DoH query padding | RFC 8467 | ✓ | `privacy.upstream_padding = true` | **planned** (hickory 0.26 still doesn't expose RFC 8467) |
//! | Randomise upstream selection | — | ✓ | `privacy.randomize_upstream_selection = true` | implemented (round-robin server-ordering strategy) |
//! | Query Name Minimisation | RFC 7816 | ✓ | `privacy.query_minimization = true` | **planned** (hickory 0.26's stub resolver still doesn't apply qmin) |
//!
//! # Fail-closed guarantee
//!
//! When `upstream.fail_closed = true` (the default), a failure of all
//! configured upstreams results in [`RustyDnsError::AllUpstreamsFailed`]
//! which the daemon translates to `SERVFAIL`. The resolver **never**
//! silently falls back to plain DNS or to a stale cached answer. There
//! is no stale-answer mode. Do not add one.
//!
//! # Bootstrap DNS
//!
//! Resolving a DoH endpoint's hostname (e.g. `cloudflare-dns.com`) at
//! startup requires DNS itself — a chicken-and-egg problem. We bootstrap
//! via the OS resolver ([`tokio::net::lookup_host`]) **once at startup**
//! and use the resulting IP addresses for every subsequent query over
//! the encrypted transport. This means the OS resolver only ever learns
//! the hostnames of your DoH providers, never the names you actually
//! resolve.
//!
//! # Log redaction
//!
//! Query names (`qname`) are sensitive. See `AGENTS.md §Privacy invariants`
//! and `rustydns_core::client` for the full policy. Summary:
//!
//! - `qname` must **never** appear in `tracing::info!`, `warn!`, or `error!`.
//! - `qname` may appear at `debug` / `trace` (require explicit opt-in via
//!   `RUST_LOG=debug`); prefer hashed or truncated forms.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::Resolver as HickoryResolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    NameServerConfig, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use rustydns_core::RustyDnsError;
use rustydns_core::config::{DnsConfig, TlsVersion, UpstreamProtocol};
use rustydns_core::record::{DnsRecord, RecordData};

/// Result type for resolver operations.
pub type ResolverResult<T> = Result<T, RustyDnsError>;

/// The upstream recursive resolver.
///
/// Wraps `hickory-resolver`'s `TokioAsyncResolver` with privacy-preserving
/// defaults and rustydns-specific failure semantics (fail-closed →
/// `SERVFAIL`).
#[derive(Debug)]
pub struct Resolver {
    config: DnsConfig,
    inner: TokioResolver,
    /// The upstream URLs as configured — kept for logging only.
    upstream_urls: Vec<String>,
}

impl Resolver {
    /// Build a resolver from the full daemon config.
    ///
    /// Performs bootstrap DNS resolution of every DoH/DoQ provider's
    /// hostname via the OS resolver. This is the only time the OS
    /// resolver is consulted; once running, all queries go through the
    /// configured encrypted upstreams.
    ///
    /// # Errors
    ///
    /// - [`RustyDnsError::Config`] if `upstream.resolvers` is empty or
    ///   contains an unparseable URL.
    /// - [`RustyDnsError::Resolver`] if bootstrap resolution of every
    ///   configured upstream hostname fails (no upstream is usable).
    /// - [`RustyDnsError::Tls`] if the rustls client config cannot be
    ///   built (e.g. no native CA roots found).
    ///
    /// # Startup behaviour
    ///
    /// - If `upstream.protocol = "plain"`, emits a persistent `warn!`
    ///   containing "UNENCRYPTED" and "leaks" so it's visible at every
    ///   service start.
    pub async fn new(config: DnsConfig) -> ResolverResult<Self> {
        if config.upstream.resolvers.is_empty() {
            return Err(RustyDnsError::Config(
                "upstream.resolvers is empty — at least one resolver URL is required".to_string(),
            ));
        }

        if config.upstream.protocol == UpstreamProtocol::Plain {
            tracing::warn!(
                "upstream.protocol = \"plain\" — DNS queries will be sent UNENCRYPTED over UDP/TCP \
                 port 53. Every resolved domain name leaks to any observer on the network path. \
                 Switch to \"doh\" or \"doq\" for any deployment where privacy matters."
            );
        }

        // TLS 1.3 floor: hickory-resolver 0.26 takes a rustls 0.23
        // ClientConfig matching our workspace, so the configured
        // `upstream.min_tls_version` actually pins the floor (instead
        // of being a soft warning the way it was on 0.24).
        let tls_client_config = build_tls_client_config(config.upstream.min_tls_version)?;

        let mut name_servers: Vec<NameServerConfig> = Vec::new();
        let mut configured_any = false;
        for url in &config.upstream.resolvers {
            match build_name_servers(url, config.upstream.protocol).await {
                Ok(ns_configs) => {
                    for ns in ns_configs {
                        name_servers.push(ns);
                    }
                    configured_any = true;
                }
                Err(e) => {
                    tracing::warn!(
                        upstream = %url,
                        error = %e,
                        "upstream bootstrap failed; skipping this resolver"
                    );
                }
            }
        }

        if !configured_any {
            return Err(RustyDnsError::Resolver(
                "no upstream resolver could be bootstrapped — check network connectivity and \
                 the URLs in upstream.resolvers"
                    .to_string(),
            ));
        }

        let resolver_config = ResolverConfig::from_parts(None, Vec::new(), name_servers);

        let mut opts = ResolverOpts::default();
        // PRIVACY: never advertise EDNS0 Client Subnet. hickory does not
        // attach ECS automatically, but we also do not enable edns0
        // unless DNSSEC requires it (which we set below).
        opts.edns0 = config.upstream.dnssec_validation;
        opts.validate = config.upstream.dnssec_validation;
        opts.timeout = Duration::from_millis(config.upstream.timeout_ms);
        opts.cache_size = config.upstream.max_cache_entries as u64;
        // Hickory 0.26 took an enum for use_hosts_file. We never want
        // /etc/hosts consulted for upstream queries (it would leak
        // mesh names to the OS resolver path on misconfigurations).
        opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        opts.preserve_intermediates = true;
        // hickory 0.26 dropped `shuffle_dns_servers`; the equivalent is
        // `ServerOrderingStrategy::RoundRobin` which distributes load
        // uniformly over time. When randomisation is off we fall back
        // to QueryStatistics so the healthiest provider gets preference.
        opts.server_ordering_strategy = if config.privacy.randomize_upstream_selection {
            ServerOrderingStrategy::RoundRobin
        } else {
            ServerOrderingStrategy::QueryStatistics
        };

        let inner: TokioResolver =
            HickoryResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                .with_options(opts)
                .with_tls_config((*tls_client_config).clone())
                .build()
                .map_err(|e| {
                    RustyDnsError::Resolver(format!("hickory resolver build failed: {e}"))
                })?;

        tracing::info!(
            resolvers   = config.upstream.resolvers.len(),
            protocol    = ?config.upstream.protocol,
            dnssec      = config.upstream.dnssec_validation,
            fail_closed = config.upstream.fail_closed,
            min_tls     = ?config.upstream.min_tls_version,
            no_ecs      = config.privacy.no_edns_client_subnet,
            randomize   = config.privacy.randomize_upstream_selection,
            cache_size  = config.upstream.max_cache_entries,
            "resolver initialised"
        );
        // Emit the actual upstream URLs at debug level so operators can
        // confirm which providers are loaded without reading the config
        // file back. Upstream URLs are not sensitive — they're well-known
        // public endpoints — but they're noisy enough to warrant `debug`
        // rather than `info`.
        for url in &config.upstream.resolvers {
            tracing::debug!(upstream = %url, "resolver upstream loaded");
        }

        let upstream_urls = config.upstream.resolvers.clone();
        Ok(Self {
            config,
            inner,
            upstream_urls,
        })
    }

    /// Resolve `name` with record type `qtype` (e.g. `"A"`, `"AAAA"`, `"MX"`).
    ///
    /// Returns:
    /// - `Ok(records)` with zero or more records of `qtype`. An empty
    ///   vec indicates the upstream returned NOERROR with no records
    ///   (NODATA / authoritative empty answer) or NXDOMAIN — both
    ///   represent "no positive answer" from the resolver's perspective.
    /// - `Err(RustyDnsError::AllUpstreamsFailed)` if every configured
    ///   upstream failed and `fail_closed = true`. The daemon translates
    ///   this to `SERVFAIL`.
    /// - `Err(RustyDnsError::Resolver(...))` for other resolver errors
    ///   (bad query name, protocol violation, etc.).
    ///
    /// # Log redaction
    ///
    /// `qname` is logged at `debug` only. Never promote — see module doc.
    pub async fn resolve(&self, name: &str, qtype: &str) -> ResolverResult<Vec<DnsRecord>> {
        let record_type = parse_record_type(qtype)?;

        // PRIVACY: qname only at debug level. See module-level doc.
        tracing::debug!(qname = name, qtype = %record_type, "resolving via upstream");

        match self.inner.lookup(name, record_type).await {
            Ok(lookup) => {
                let records = lookup_to_dns_records(lookup.answers());
                tracing::trace!(qtype = %record_type, count = records.len(), "upstream answer");
                Ok(records)
            }
            Err(e) => self.map_resolve_error(e),
        }
    }

    /// Translate a hickory `NetError` into a `RustyDnsError`.
    fn map_resolve_error(&self, e: NetError) -> ResolverResult<Vec<DnsRecord>> {
        // No records is not an upstream failure — return empty vec.
        if e.is_no_records_found() {
            return Ok(Vec::new());
        }
        // qname is inside e.to_string() in some kinds; we log only the
        // error kind at warn level, never the full Display, to avoid
        // leaking the query name. The full error chain is available at
        // debug level for operators who opt in via
        // RUST_LOG=rustydns_resolver=debug.
        tracing::warn!(
            upstreams = self.upstream_urls.len(),
            kind = error_kind_label(&e),
            "upstream resolution failed"
        );
        tracing::debug!(
            upstreams = self.upstream_urls.len(),
            error     = %e,
            "upstream resolution failed (full error)"
        );
        if self.config.upstream.fail_closed {
            Err(RustyDnsError::AllUpstreamsFailed)
        } else {
            Err(RustyDnsError::Resolver(error_kind_label(&e).to_string()))
        }
    }
}

// ---------------------------------------------------------------------------
// URL parsing and bootstrap
// ---------------------------------------------------------------------------

/// Parsed upstream URL.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedUpstream {
    scheme: String,
    host: String,
    port: u16,
}

fn parse_upstream_url(url: &str, protocol: UpstreamProtocol) -> ResolverResult<ParsedUpstream> {
    let url = url.trim();
    // Plain mode accepts bare `host:port` (no scheme) — validate_config
    // already enforced that "plain" + scheme is rejected, and that the
    // other two protocols require their scheme. Here we synthesise a
    // "plain" scheme so the rest of the parser handles a single shape.
    let (scheme, rest) = if let Some(pair) = url.split_once("://") {
        (pair.0.to_ascii_lowercase(), pair.1)
    } else if protocol == UpstreamProtocol::Plain {
        ("plain".to_string(), url)
    } else {
        return Err(RustyDnsError::Config(format!(
            "upstream `{url}` is not a URL (expected `scheme://host[:port][/path]`)"
        )));
    };

    let host_port = rest.split('/').next().unwrap_or("");
    if host_port.is_empty() {
        return Err(RustyDnsError::Config(format!(
            "upstream `{url}` is missing a host"
        )));
    }

    let (host, port) = if let Some(idx) = host_port.rfind(':') {
        // Avoid matching colons inside an IPv6 literal `[::1]:443`.
        let after_bracket = host_port.starts_with('[') && host_port.contains(']');
        if after_bracket {
            let close = host_port.find(']').unwrap();
            let host = host_port[1..close].to_string();
            let port_part = host_port.get(close + 2..).unwrap_or("");
            let port = port_part
                .parse::<u16>()
                .map_err(|_| RustyDnsError::Config(format!("upstream `{url}` has invalid port")))?;
            (host, port)
        } else if host_port[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            let port = host_port[idx + 1..]
                .parse::<u16>()
                .map_err(|_| RustyDnsError::Config(format!("upstream `{url}` has invalid port")))?;
            (host_port[..idx].to_string(), port)
        } else {
            (host_port.to_string(), default_port(&scheme, protocol))
        }
    } else {
        (host_port.to_string(), default_port(&scheme, protocol))
    };

    if host.is_empty() {
        return Err(RustyDnsError::Config(format!(
            "upstream `{url}` is missing a host"
        )));
    }

    Ok(ParsedUpstream { scheme, host, port })
}

fn default_port(scheme: &str, protocol: UpstreamProtocol) -> u16 {
    match scheme {
        "https" => 443,
        "quic" => 853,
        "plain" => 53,
        _ => match protocol {
            UpstreamProtocol::Doh => 443,
            UpstreamProtocol::Doq => 853,
            UpstreamProtocol::Plain => 53,
        },
    }
}

/// Bootstrap-resolve `host:port` via the OS resolver with bounded
/// retries. Each attempt waits 1s, 2s, 4s before retry — total
/// ~7 seconds. Returns the first successful set of IPs, or the
/// final attempt's error.
async fn bootstrap_resolve_with_retry(host: &str, port: u16) -> ResolverResult<Vec<IpAddr>> {
    const ATTEMPTS: usize = 4;
    let host_port = format!("{host}:{port}");
    let mut delay = Duration::from_secs(1);
    let mut last_err: Option<String> = None;

    for attempt in 1..=ATTEMPTS {
        match tokio::net::lookup_host(&host_port).await {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
                if !ips.is_empty() {
                    if attempt > 1 {
                        tracing::info!(
                            host = %host,
                            attempt,
                            "bootstrap DNS recovered after transient failure"
                        );
                    }
                    return Ok(ips);
                }
                last_err = Some("returned no addresses".to_string());
            }
            Err(e) => last_err = Some(e.to_string()),
        }

        if attempt < ATTEMPTS {
            tracing::warn!(
                host = %host,
                attempt,
                next_retry_secs = delay.as_secs(),
                error = last_err.as_deref().unwrap_or("?"),
                "bootstrap DNS failed; retrying"
            );
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2);
        }
    }

    Err(RustyDnsError::Resolver(format!(
        "bootstrap DNS for `{}` failed after {} attempts: {}",
        host,
        ATTEMPTS,
        last_err.unwrap_or_else(|| "unknown".to_string())
    )))
}

/// Build a rustls [`ClientConfig`] honouring the configured minimum
/// TLS version. Uses the embedded Mozilla CA bundle via `webpki-roots`
/// (deterministic; matches `CLAUDE.md` §"DoH upstream needs an
/// explicit root-CA feature"). Returned as `Arc` so we can pass an
/// owned `(*arc).clone()` into the hickory builder.
fn build_tls_client_config(min_tls: TlsVersion) -> ResolverResult<Arc<rustls::ClientConfig>> {
    // Install ring as the default crypto provider (idempotent —
    // multiple installs are a no-op after the first). hickory 0.26
    // with the `https-ring`/`quic-ring`/`dnssec-ring` features
    // expects ring.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions: &[&rustls::SupportedProtocolVersion] = match min_tls {
        TlsVersion::Tls13 => &[&rustls::version::TLS13],
        TlsVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };

    let cfg = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Resolve `host` to one or more IP addresses via the OS resolver, then
/// build one [`NameServerConfig`] per IP using hickory 0.26's typed
/// constructors (`NameServerConfig::https`, `quic`, `udp_and_tcp`).
async fn build_name_servers(
    url: &str,
    protocol: UpstreamProtocol,
) -> ResolverResult<Vec<NameServerConfig>> {
    let parsed = parse_upstream_url(url, protocol)?;

    // Bootstrap-resolve via OS. The retry helper buys us ~7s of
    // tolerance for k8s init-container races / systemd ordering
    // hiccups before giving up. See `bootstrap_resolve_with_retry`.
    let ips: Vec<IpAddr> = if let Ok(ip) = IpAddr::from_str(&parsed.host) {
        vec![ip]
    } else {
        bootstrap_resolve_with_retry(&parsed.host, parsed.port).await?
    };

    if ips.is_empty() {
        return Err(RustyDnsError::Resolver(format!(
            "bootstrap DNS for `{}` returned no addresses",
            parsed.host
        )));
    }

    let server_name: Arc<str> = Arc::from(parsed.host.as_str());
    let mut configs = Vec::with_capacity(ips.len());
    for ip in ips {
        let ns = match protocol {
            UpstreamProtocol::Doh => NameServerConfig::https(
                ip,
                server_name.clone(),
                // RFC 8484 says /dns-query by default. We don't surface
                // the URL path yet; hickory uses the default.
                None,
            ),
            UpstreamProtocol::Doq => NameServerConfig::quic(ip, server_name.clone()),
            UpstreamProtocol::Plain => NameServerConfig::udp_and_tcp(ip),
        };
        configs.push(ns);
    }
    Ok(configs)
}

// ---------------------------------------------------------------------------
// Record conversion
// ---------------------------------------------------------------------------

fn parse_record_type(qtype: &str) -> ResolverResult<RecordType> {
    let upper = qtype.trim().to_ascii_uppercase();
    RecordType::from_str(&upper)
        .map_err(|_| RustyDnsError::Resolver(format!("unsupported record type `{qtype}`")))
}

fn lookup_to_dns_records(records: &[Record]) -> Vec<DnsRecord> {
    records.iter().filter_map(record_to_dns_record).collect()
}

fn record_to_dns_record(rec: &Record) -> Option<DnsRecord> {
    // hickory 0.26 exposes Record fields publicly; accessor methods
    // only live on the borrowed `RecordRef` newtype. For owned/&Record
    // we go through the fields directly.
    let data = rdata_to_record_data(&rec.data)?;
    Some(DnsRecord::new(
        rec.name.to_utf8(),
        data,
        Duration::from_secs(u64::from(rec.ttl)),
    ))
}

fn rdata_to_record_data(rdata: &RData) -> Option<RecordData> {
    match rdata {
        RData::A(a) => Some(RecordData::A(a.0)),
        RData::AAAA(aaaa) => Some(RecordData::Aaaa(aaaa.0)),
        RData::CNAME(c) => Some(RecordData::Cname(c.0.to_utf8())),
        RData::PTR(p) => Some(RecordData::Ptr(p.0.to_utf8())),
        RData::NS(n) => Some(RecordData::Ns(n.0.to_utf8())),
        RData::MX(mx) => Some(RecordData::Mx {
            preference: mx.preference,
            exchange: mx.exchange.to_utf8(),
        }),
        RData::SRV(s) => Some(RecordData::Srv {
            priority: s.priority,
            weight: s.weight,
            port: s.port,
            target: s.target.to_utf8(),
        }),
        RData::TXT(t) => Some(RecordData::Txt(
            t.txt_data.iter().map(|b| b.to_vec()).collect(),
        )),
        _ => None, // record types we don't model are dropped
    }
}

fn error_kind_label(e: &NetError) -> &'static str {
    // hickory 0.26 collapsed the old `ResolveErrorKind` into NetError
    // with semantic accessors. Map the common shapes back to the short
    // labels we already use in metrics + tracing fields.
    if e.is_no_records_found() {
        return "no-records";
    }
    match e {
        NetError::Busy => "busy",
        NetError::Dns(_) => "dns",
        NetError::Message(_) | NetError::Msg(_) => "message",
        NetError::NoConnections => "no-connections",
        NetError::Proto(_) => "proto",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SRV, TXT};

    #[test]
    fn parse_upstream_url_https_default_port() {
        let p = parse_upstream_url(
            "https://cloudflare-dns.com/dns-query",
            UpstreamProtocol::Doh,
        )
        .unwrap();
        assert_eq!(p.scheme, "https");
        assert_eq!(p.host, "cloudflare-dns.com");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_upstream_url_explicit_port() {
        let p = parse_upstream_url("https://example.com:8443/dns-query", UpstreamProtocol::Doh)
            .unwrap();
        assert_eq!(p.port, 8443);
        assert_eq!(p.host, "example.com");
    }

    #[test]
    fn parse_upstream_url_ipv6_literal() {
        let p = parse_upstream_url(
            "https://[2606:4700::1111]:443/dns-query",
            UpstreamProtocol::Doh,
        )
        .unwrap();
        assert_eq!(p.host, "2606:4700::1111");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_upstream_url_no_scheme_fails_for_doh() {
        // DoH demands an https:// URL — a bare host without scheme is
        // rejected so the operator doesn't silently get a different
        // transport.
        let err = parse_upstream_url("cloudflare-dns.com", UpstreamProtocol::Doh).unwrap_err();
        match err {
            RustyDnsError::Config(msg) => assert!(msg.contains("not a URL"), "msg={msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn parse_upstream_url_plain_accepts_bare_host_port() {
        // Plain mode is the one place a bare `host:port` is allowed —
        // there's no transport ambiguity since `protocol = "plain"`
        // already pins UDP/TCP port 53 semantics.
        let p = parse_upstream_url("8.8.8.8:53", UpstreamProtocol::Plain).unwrap();
        assert_eq!(p.host, "8.8.8.8");
        assert_eq!(p.port, 53);
        assert_eq!(p.scheme, "plain");
    }

    #[test]
    fn parse_upstream_url_plain_defaults_port_to_53() {
        let p = parse_upstream_url("1.1.1.1", UpstreamProtocol::Plain).unwrap();
        assert_eq!(p.host, "1.1.1.1");
        assert_eq!(p.port, 53);
    }

    #[test]
    fn parse_upstream_url_no_host_fails() {
        let err = parse_upstream_url("https:///", UpstreamProtocol::Doh).unwrap_err();
        match err {
            RustyDnsError::Config(msg) => assert!(msg.contains("host"), "msg={msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn rdata_a_maps_to_record_data_a() {
        let rd = RData::A(A("10.0.0.1".parse().unwrap()));
        match rdata_to_record_data(&rd).unwrap() {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "10.0.0.1"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn rdata_aaaa_maps() {
        let rd = RData::AAAA(AAAA("2606:4700::1111".parse().unwrap()));
        match rdata_to_record_data(&rd).unwrap() {
            RecordData::Aaaa(ip) => assert_eq!(ip.to_string(), "2606:4700::1111"),
            other => panic!("expected AAAA, got {other:?}"),
        }
    }

    #[test]
    fn rdata_cname_ptr_ns_map() {
        let n = Name::from_ascii("target.example.com.").unwrap();
        match rdata_to_record_data(&RData::CNAME(CNAME(n.clone()))).unwrap() {
            RecordData::Cname(s) => assert!(s.starts_with("target.example.com")),
            o => panic!("{o:?}"),
        }
        match rdata_to_record_data(&RData::PTR(PTR(n.clone()))).unwrap() {
            RecordData::Ptr(s) => assert!(s.starts_with("target.example.com")),
            o => panic!("{o:?}"),
        }
        match rdata_to_record_data(&RData::NS(NS(n))).unwrap() {
            RecordData::Ns(s) => assert!(s.starts_with("target.example.com")),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn rdata_mx_maps() {
        let mx = MX::new(10, Name::from_ascii("mail.example.com.").unwrap());
        match rdata_to_record_data(&RData::MX(mx)).unwrap() {
            RecordData::Mx {
                preference,
                exchange,
            } => {
                assert_eq!(preference, 10);
                assert!(exchange.starts_with("mail.example.com"));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn rdata_srv_maps() {
        let srv = SRV::new(10, 20, 5060, Name::from_ascii("sip.example.com.").unwrap());
        match rdata_to_record_data(&RData::SRV(srv)).unwrap() {
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!(priority, 10);
                assert_eq!(weight, 20);
                assert_eq!(port, 5060);
                assert!(target.starts_with("sip.example.com"));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn rdata_txt_maps_to_bytes() {
        let txt = TXT::new(vec!["v=spf1 -all".to_string()]);
        match rdata_to_record_data(&RData::TXT(txt)).unwrap() {
            RecordData::Txt(parts) => {
                assert_eq!(parts.len(), 1);
                assert_eq!(&parts[0], b"v=spf1 -all");
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn parse_record_type_accepts_common() {
        assert_eq!(parse_record_type("A").unwrap(), RecordType::A);
        assert_eq!(parse_record_type("aaaa").unwrap(), RecordType::AAAA);
        assert_eq!(parse_record_type("MX").unwrap(), RecordType::MX);
        assert_eq!(parse_record_type(" srv ").unwrap(), RecordType::SRV);
    }

    #[test]
    fn parse_record_type_rejects_garbage() {
        let err = parse_record_type("NOTAREALTYPE").unwrap_err();
        match err {
            RustyDnsError::Resolver(msg) => assert!(msg.contains("NOTAREALTYPE")),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_resolve_passes_through_for_ipv4_literal() {
        // IPv4 literals are passed through in `build_name_servers`
        // before this helper is consulted — but to keep the helper
        // testable, exercise it directly with localhost. `localhost`
        // is always resolvable on a developer box or CI runner, so
        // it never trips the retry path.
        let ips = bootstrap_resolve_with_retry("localhost", 53)
            .await
            .expect("localhost must resolve");
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn empty_resolvers_list_rejected_at_new() {
        let mut cfg = DnsConfig {
            server: Default::default(),
            upstream: Default::default(),
            authority: Default::default(),
            blocklist: Default::default(),
            privacy: Default::default(),
            metrics: Default::default(),
            policy: Vec::new(),
        };
        cfg.upstream.resolvers.clear();
        let err = Resolver::new(cfg).await.unwrap_err();
        match err {
            RustyDnsError::Config(msg) => assert!(msg.contains("empty"), "msg={msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }
}
