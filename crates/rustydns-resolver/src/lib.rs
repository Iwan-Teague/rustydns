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
//! | Conditional forwarding (per-zone routes) | — | opt-in | `[[upstream.routes]]` | implemented (longest-suffix match) |
//! | DNS-rebinding defence (drop private rdata) | — | opt-in | `upstream.block_private_rdata` | implemented (default arm only; never filters route or authority responses) |
//! | Strip EDNS Client Subnet | RFC 7871 | ✓ | `privacy.no_edns_client_subnet = true` | implemented (we never set ECS) |
//! | DoH query padding | RFC 8467 | ✓ | `privacy.upstream_padding = true` | **pending** — hickory 0.26 doesn't expose RFC 8467 yet; daemon warns at startup. See `docs/roadmap.md` §1.2. |
//! | Randomise upstream selection | — | ✓ | `privacy.randomize_upstream_selection = true` | implemented (round-robin server-ordering strategy) |
//! | Query Name Minimisation | RFC 7816 | ✓ | `privacy.query_minimization = true` | **pending** — hickory 0.26 doesn't apply qmin yet; daemon warns at startup. See `docs/roadmap.md` §1.1. |
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

/// The outcome of a single [`Resolver::resolve`] call.
///
/// Holds the answer records plus auxiliary stats the daemon promotes to
/// Prometheus counters. Today the only such stat is the DNS-rebinding
/// drop count; new fields can be added without breaking the API because
/// the struct is non-exhaustively constructed.
#[derive(Debug, Default, Clone)]
pub struct ResolveOutcome {
    /// Answer records returned to the caller. May be empty (NODATA / NXDOMAIN
    /// at the upstream, or every record dropped by the rebinding defence).
    pub records: Vec<DnsRecord>,
    /// Number of A/AAAA records that were dropped because their rdata
    /// resolved to a private/loopback/link-local/etc. address while
    /// `upstream.block_private_rdata = true`.
    ///
    /// Always `0` when the matched arm is a conditional-forwarding route
    /// (operators route to internal resolvers precisely so they CAN
    /// return private addresses), or when the rebinding defence is off.
    pub private_rdata_dropped: u32,
}

/// A single resolver instance — one hickory `TokioResolver` plus its bound
/// upstream URLs (kept for logging only).
///
/// Used both for the global default upstream list and for each
/// conditional-forwarding route.
#[derive(Debug)]
struct ResolverArm {
    inner: TokioResolver,
    upstream_urls: Vec<String>,
}

/// A conditional-forwarding route: a normalised DNS zone bound to one
/// [`ResolverArm`].
#[derive(Debug)]
struct RouteArm {
    /// Zone in its fully-normalised form: lowercase, trailing dot, no
    /// leading dot. E.g. `"lan."` or `"corp.internal."`.
    ///
    /// Used to match the zone apex itself (a query for `lan.` should hit
    /// the `lan.` route).
    zone_with_dot: String,
    /// `"." + zone_with_dot`. Used for the suffix check — a query for
    /// `foo.lan.` ends with `.lan.` and therefore matches.
    dotted_suffix: String,
    arm: ResolverArm,
}

/// The upstream recursive resolver.
///
/// Wraps `hickory-resolver`'s `TokioAsyncResolver` with privacy-preserving
/// defaults and rustydns-specific failure semantics (fail-closed →
/// `SERVFAIL`).
///
/// # Conditional forwarding
///
/// When `upstream.routes` is non-empty, the resolver holds one
/// independent hickory resolver per route plus the global default. On
/// every query the qname is matched against the configured zones
/// (longest-suffix wins, case-insensitive); the matching arm forwards
/// the query. Unmatched qnames go to the default arm. See the
/// [`UpstreamConfig::routes`] doc for the model and
/// `Resolver::select_arm` for the dispatch rules.
///
/// [`UpstreamConfig::routes`]: rustydns_core::config::UpstreamConfig::routes
#[derive(Debug)]
pub struct Resolver {
    config: DnsConfig,
    default: ResolverArm,
    /// Routes, sorted longest-zone-first so first-match-wins is also
    /// longest-match-wins (`foo.corp.internal.` prefers a `corp.internal.`
    /// route over a `internal.` route).
    routes: Vec<RouteArm>,
}

impl Resolver {
    /// Build a resolver from the full daemon config.
    ///
    /// Performs bootstrap DNS resolution of every DoH/DoQ provider's
    /// hostname via the OS resolver. This is the only time the OS
    /// resolver is consulted; once running, all queries go through the
    /// configured encrypted upstreams.
    ///
    /// One hickory resolver is built per route plus the default. Each
    /// arm inherits the global privacy/security settings
    /// (`fail_closed`, `min_tls_version`, `dnssec_validation`,
    /// `timeout_ms`, `max_cache_entries`, `randomize_upstream_selection`)
    /// — there are no per-route overrides for any privacy or security
    /// knob, by design.
    ///
    /// # Errors
    ///
    /// - [`RustyDnsError::Config`] if `upstream.resolvers` is empty.
    /// - [`RustyDnsError::Resolver`] if bootstrap resolution fails for
    ///   every upstream in any arm (default or route). A failed route
    ///   is fatal — operators who configured a route for `corp.internal.`
    ///   want corp DNS to work, not to silently fall back to public DoH.
    /// - [`RustyDnsError::Tls`] if the rustls client config cannot be
    ///   built.
    ///
    /// # Startup behaviour
    ///
    /// - If `upstream.protocol = "plain"` for the default OR any route,
    ///   emits a `warn!` containing "UNENCRYPTED" and "leaks" so it's
    ///   visible at every service start.
    pub async fn new(config: DnsConfig) -> ResolverResult<Self> {
        Self::new_internal(config, &[]).await
    }

    /// Construct a new `Resolver` with supplemental root CAs.
    /// Used only during DoH integration testing to inject a mock CA.
    #[cfg(test)]
    pub async fn new_with_test_root_certs(
        config: DnsConfig,
        test_roots: &[rustls_pki_types::CertificateDer<'static>],
    ) -> ResolverResult<Self> {
        Self::new_internal(config, test_roots).await
    }

    async fn new_internal(
        config: DnsConfig,
        test_roots: &[rustls_pki_types::CertificateDer<'static>],
    ) -> ResolverResult<Self> {
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
        for r in &config.upstream.routes {
            if r.protocol == UpstreamProtocol::Plain {
                tracing::warn!(
                    zone = %r.zone,
                    "upstream.routes zone uses protocol = \"plain\" — DNS queries for this zone \
                     will be sent UNENCRYPTED. Domain names in this zone leak to any observer on \
                     the network path between rustydnsd and the routed resolver."
                );
            }
        }

        // TLS 1.3 floor: hickory-resolver 0.26 takes a rustls 0.23
        // ClientConfig matching our workspace, so the configured
        // `upstream.min_tls_version` actually pins the floor (instead
        // of being a soft warning the way it was on 0.24).
        let tls_client_config = build_tls_client_config(config.upstream.min_tls_version, test_roots)?;

        // Default arm — the global upstream list.
        let default = build_resolver_arm(
            "default",
            &config.upstream.resolvers,
            config.upstream.protocol,
            tls_client_config.clone(),
            &config,
        )
        .await?;

        // Per-route arms. A route that fails to bootstrap any upstream
        // aborts startup: silent fallback to the default arm would let
        // a misconfigured corp-DNS route leak internal queries to public
        // DoH, which is exactly what conditional forwarding is meant to
        // prevent.
        let mut routes: Vec<RouteArm> = Vec::with_capacity(config.upstream.routes.len());
        for r in &config.upstream.routes {
            let zone_with_dot = r.zone.trim().to_ascii_lowercase();
            let dotted_suffix = format!(".{zone_with_dot}");
            let arm = build_resolver_arm(
                &zone_with_dot,
                &r.resolvers,
                r.protocol,
                tls_client_config.clone(),
                &config,
            )
            .await?;
            routes.push(RouteArm {
                zone_with_dot,
                dotted_suffix,
                arm,
            });
        }
        // Longest zone first so a more-specific route shadows a more-
        // general one (`corp.internal.` beats `internal.`).
        routes.sort_by_key(|r| std::cmp::Reverse(r.zone_with_dot.len()));

        tracing::info!(
            resolvers   = config.upstream.resolvers.len(),
            routes      = routes.len(),
            protocol    = ?config.upstream.protocol,
            dnssec      = config.upstream.dnssec_validation,
            fail_closed = config.upstream.fail_closed,
            min_tls     = ?config.upstream.min_tls_version,
            no_ecs      = config.privacy.no_edns_client_subnet,
            randomize   = config.privacy.randomize_upstream_selection,
            cache_size  = config.upstream.max_cache_entries,
            "resolver initialised"
        );
        for url in &config.upstream.resolvers {
            tracing::debug!(upstream = %url, "default upstream loaded");
        }
        for r in &routes {
            tracing::debug!(
                zone = %r.zone_with_dot,
                resolvers = r.arm.upstream_urls.len(),
                "conditional-forwarding route loaded"
            );
        }

        Ok(Self {
            config,
            default,
            routes,
        })
    }

    /// Resolve `name` with record type `qtype` (e.g. `"A"`, `"AAAA"`, `"MX"`).
    ///
    /// Returns:
    /// - `Ok(ResolveOutcome)` with the answer records (possibly empty for
    ///   NODATA / NXDOMAIN at the upstream) plus the count of records
    ///   dropped by the rebinding defence.
    /// - `Err(RustyDnsError::AllUpstreamsFailed)` if every configured
    ///   upstream failed and `fail_closed = true`. The daemon translates
    ///   this to `SERVFAIL`.
    /// - `Err(RustyDnsError::Resolver(...))` for other resolver errors
    ///   (bad query name, protocol violation, etc.).
    ///
    /// # Rebinding defence
    ///
    /// When `upstream.block_private_rdata = true` AND the query is
    /// answered by the default arm, A/AAAA records whose rdata points
    /// at a private/loopback/link-local/etc. address are stripped from
    /// the answer set. See [`is_private_or_internal_v4`] /
    /// [`is_private_or_internal_v6`] for the exact predicate, and the
    /// config docstring on `block_private_rdata` for the rationale and
    /// expected operator workflow.
    ///
    /// # Log redaction
    ///
    /// `qname` is logged at `debug` only. Never promote — see module doc.
    pub async fn resolve(&self, name: &str, qtype: &str) -> ResolverResult<ResolveOutcome> {
        let record_type = parse_record_type(qtype)?;

        let (arm, on_default) = self.select_arm(name);

        // PRIVACY: qname only at debug level. See module-level doc.
        // The matched zone is operator-configured (not user-controlled)
        // and therefore safe to log at debug too.
        tracing::debug!(qname = name, qtype = %record_type, "resolving via upstream");

        match arm.inner.lookup(name, record_type).await {
            Ok(lookup) => {
                let mut records = lookup_to_dns_records(lookup.answers());
                let mut dropped: u32 = 0;
                if on_default && self.config.upstream.block_private_rdata {
                    dropped = filter_private_rdata(&mut records);
                }
                tracing::trace!(
                    qtype = %record_type,
                    count = records.len(),
                    dropped,
                    "upstream answer"
                );
                Ok(ResolveOutcome {
                    records,
                    private_rdata_dropped: dropped,
                })
            }
            Err(e) => self.map_resolve_error(arm, e),
        }
    }

    /// Pick the [`ResolverArm`] that should handle `name`.
    ///
    /// Routes are pre-sorted longest-zone-first; the first route whose
    /// normalised zone is a suffix of (or equal to) the normalised qname
    /// wins. If nothing matches the default arm is returned.
    ///
    /// Returns the chosen arm AND a boolean that is `true` iff the default
    /// arm was selected. The default-vs-route distinction matters for the
    /// rebinding defence — only default-arm responses are filtered.
    ///
    /// When no routes are configured this short-circuits without any
    /// allocation — the hot path for the typical operator (global DoH
    /// only) is unchanged from pre-routes.
    fn select_arm(&self, name: &str) -> (&ResolverArm, bool) {
        if self.routes.is_empty() {
            return (&self.default, true);
        }
        // Normalise once per query: lowercase + trailing dot so the
        // suffix match is a single ends_with call.
        let mut lower = name.to_ascii_lowercase();
        if !lower.ends_with('.') {
            lower.push('.');
        }
        for r in &self.routes {
            if lower == r.zone_with_dot || lower.ends_with(&r.dotted_suffix) {
                return (&r.arm, false);
            }
        }
        (&self.default, true)
    }

    /// Translate a hickory `NetError` into a `RustyDnsError`.
    fn map_resolve_error(&self, arm: &ResolverArm, e: NetError) -> ResolverResult<ResolveOutcome> {
        // No records is not an upstream failure — return empty outcome.
        if e.is_no_records_found() {
            return Ok(ResolveOutcome::default());
        }
        // qname is inside e.to_string() in some kinds; we log only the
        // error kind at warn level, never the full Display, to avoid
        // leaking the query name. The full error chain is available at
        // debug level for operators who opt in via
        // RUST_LOG=rustydns_resolver=debug.
        tracing::warn!(
            upstreams = arm.upstream_urls.len(),
            kind = error_kind_label(&e),
            "upstream resolution failed"
        );
        tracing::debug!(
            upstreams = arm.upstream_urls.len(),
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

/// Bootstrap-resolve every URL in `resolvers`, build the hickory
/// resolver options from the shared `config`, and return a ready-to-
/// query [`ResolverArm`].
///
/// `label` is used only in log/error messages so operators can tell
/// which arm failed to bootstrap (e.g. `"default"`, `"lan."`).
async fn build_resolver_arm(
    label: &str,
    resolvers: &[String],
    protocol: UpstreamProtocol,
    tls_client_config: Arc<rustls::ClientConfig>,
    config: &DnsConfig,
) -> ResolverResult<ResolverArm> {
    let mut name_servers: Vec<NameServerConfig> = Vec::new();
    let mut configured_any = false;
    for url in resolvers {
        match build_name_servers(url, protocol).await {
            Ok(ns_configs) => {
                for ns in ns_configs {
                    name_servers.push(ns);
                }
                configured_any = true;
            }
            Err(e) => {
                tracing::warn!(
                    arm = %label,
                    upstream = %url,
                    error = %e,
                    "upstream bootstrap failed; skipping this resolver"
                );
            }
        }
    }

    if !configured_any {
        return Err(RustyDnsError::Resolver(format!(
            "no upstream resolver could be bootstrapped for arm `{label}` — check network \
             connectivity and the configured URLs"
        )));
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
            .map_err(|e| RustyDnsError::Resolver(format!("hickory resolver build failed: {e}")))?;

    Ok(ResolverArm {
        inner,
        upstream_urls: resolvers.to_vec(),
    })
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

/// Build a rustls `ClientConfig` honouring the configured minimum
/// TLS version. Uses the embedded Mozilla CA bundle via `webpki-roots`
/// (deterministic; matches `CLAUDE.md` §"DoH upstream needs an
/// explicit root-CA feature"). Returned as `Arc` so we can pass an
/// owned `(*arc).clone()` into the hickory builder.
fn build_tls_client_config(
    min_tls: TlsVersion,
    test_roots: &[rustls_pki_types::CertificateDer<'static>]
) -> ResolverResult<Arc<rustls::ClientConfig>> {
    // Install ring as the default crypto provider (idempotent —
    // multiple installs are a no-op after the first). hickory 0.26
    // with the `https-ring`/`quic-ring`/`dnssec-ring` features
    // expects ring.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for root in test_roots {
        roots.add(root.clone()).map_err(|e| RustyDnsError::Resolver(format!("failed to add test root: {e}")))?;
    }

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
        let mut ns = match protocol {
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
        // hickory 0.26's `NameServerConfig::{https,quic,udp_and_tcp}`
        // pin every ConnectionConfig to the protocol's default port
        // (53/443/853). That ignores the operator-supplied port — a
        // bare `127.0.0.1:8053` or `https://dns.example.com:8443/...`
        // would otherwise silently hit the wrong port. Stamp the
        // parsed port on every ConnectionConfig so the URL is honoured.
        for conn in &mut ns.connections {
            conn.port = parsed.port;
        }
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

// ---------------------------------------------------------------------------
// DNS-rebinding defence
// ---------------------------------------------------------------------------

/// Strip A/AAAA records from `records` whose rdata is private/loopback/
/// link-local/etc. Returns the count removed.
///
/// Records of other types (CNAME, MX, NS, …) are preserved verbatim — they
/// can't host the rebinding attack. The defence is enforced at the IP level
/// because that is what a browser actually binds to after following any
/// CNAME chain.
fn filter_private_rdata(records: &mut Vec<DnsRecord>) -> u32 {
    let before = records.len();
    records.retain(|r| match &r.data {
        RecordData::A(ip) => !is_private_or_internal_v4(ip),
        RecordData::Aaaa(ip) => !is_private_or_internal_v6(ip),
        _ => true,
    });
    let dropped = (before - records.len()) as u32;
    if dropped > 0 {
        // info-safe: count + log, no qname, no client IP. The matched
        // qname is available at debug via the `upstream answer` trace.
        tracing::warn!(
            dropped,
            "rebinding defence: dropped upstream A/AAAA record(s) with private rdata"
        );
    }
    dropped
}

/// `true` if `ip` is any IPv4 address that should never appear in an
/// upstream public-DNS response: RFC 1918 private, loopback, link-local,
/// unspecified (0.0.0.0/8), broadcast, documentation, or multicast.
///
/// CGNAT shared space (`100.64.0.0/10`) is **not** flagged — Tailscale,
/// some ISPs, and other legitimate deployments use it, and dropping it
/// would silently break those.
pub fn is_private_or_internal_v4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || is_documentation_v4(ip)
        || ip.is_multicast()
}

/// RFC 5737 documentation prefixes: `192.0.2.0/24` (TEST-NET-1),
/// `198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3).
///
/// `Ipv4Addr::is_documentation` is still gated behind the unstable
/// `feature(ip)` flag, so we inline the check here.
fn is_documentation_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    matches!(
        (o[0], o[1], o[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    )
}

/// `true` if `ip` is any IPv6 address that should never appear in an
/// upstream public-DNS response: loopback (`::1`), unspecified (`::`),
/// unique-local (`fc00::/7`), unicast link-local (`fe80::/10`),
/// documentation (`2001:db8::/32`), or multicast.
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped and
/// classified by the IPv4 predicate — otherwise an attacker could
/// pivot to a private IPv4 via the IPv6 record type.
pub fn is_private_or_internal_v6(ip: &Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_or_internal_v4(&v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || is_documentation_v6(ip)
        || ip.is_multicast()
}

/// RFC 3849 documentation prefix: `2001:db8::/32`.
///
/// `Ipv6Addr::is_documentation` is gated behind the unstable
/// `feature(ip)` flag, so we inline the check here.
fn is_documentation_v6(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0x2001 && s[1] == 0x0db8
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

    // --- conditional-forwarding zone matching -----------------------
    //
    // These tests exercise the pure matching helper (`zone_matches`)
    // without standing up real hickory resolvers, so they're fast and
    // don't need network.

    /// Mirror the matching logic from `Resolver::select_arm` for unit
    /// testing. Keep this in sync with that function — if either drifts
    /// the routing behaviour drifts with it.
    fn zone_matches(qname: &str, zone_with_dot: &str) -> bool {
        let mut lower = qname.to_ascii_lowercase();
        if !lower.ends_with('.') {
            lower.push('.');
        }
        let dotted_suffix = format!(".{zone_with_dot}");
        lower == zone_with_dot || lower.ends_with(&dotted_suffix)
    }

    #[test]
    fn zone_matches_exact_apex() {
        assert!(zone_matches("lan.", "lan."));
        assert!(zone_matches("lan", "lan."));
        assert!(zone_matches("LAN.", "lan."));
    }

    #[test]
    fn zone_matches_subdomain() {
        assert!(zone_matches("foo.lan.", "lan."));
        assert!(zone_matches("foo.bar.lan.", "lan."));
        assert!(zone_matches("FOO.LAN", "lan."));
    }

    #[test]
    fn zone_no_match_for_unrelated() {
        assert!(!zone_matches("example.com.", "lan."));
        assert!(!zone_matches("notlan.", "lan."));
        // "lan." must not match a name where "lan" appears mid-label,
        // e.g. `wlan.example.com.` — the leading dot in `dotted_suffix`
        // is what prevents this.
        assert!(!zone_matches("wlan.example.com.", "lan."));
    }

    #[test]
    fn zone_match_compound_zone() {
        // Multi-label zones should match subdomains but not unrelated
        // names that happen to share the trailing label.
        assert!(zone_matches("server.corp.internal.", "corp.internal."));
        assert!(zone_matches("corp.internal.", "corp.internal."));
        assert!(!zone_matches("internal.", "corp.internal."));
        assert!(!zone_matches("example.com.", "corp.internal."));
    }

    #[test]
    fn zone_match_reverse_dns() {
        // RFC 1918 reverse zone — a real conditional-forwarding case.
        let zone = "168.192.in-addr.arpa.";
        assert!(zone_matches("1.1.168.192.in-addr.arpa.", zone));
        assert!(zone_matches("168.192.in-addr.arpa.", zone));
        assert!(!zone_matches("10.in-addr.arpa.", zone));
    }

    // --- DNS rebinding defence (block_private_rdata) ---------------

    fn record_a(name: &str, ip: &str) -> DnsRecord {
        DnsRecord::new(
            name,
            RecordData::A(ip.parse().unwrap()),
            Duration::from_secs(60),
        )
    }
    fn record_aaaa(name: &str, ip: &str) -> DnsRecord {
        DnsRecord::new(
            name,
            RecordData::Aaaa(ip.parse().unwrap()),
            Duration::from_secs(60),
        )
    }

    #[test]
    fn v4_rfc1918_classified_private() {
        assert!(is_private_or_internal_v4(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_or_internal_v4(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_or_internal_v4(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn v4_loopback_link_local_unspecified_broadcast_classified_private() {
        assert!(is_private_or_internal_v4(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_or_internal_v4(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_or_internal_v4(&"0.0.0.0".parse().unwrap()));
        assert!(is_private_or_internal_v4(
            &"255.255.255.255".parse().unwrap()
        ));
    }

    #[test]
    fn v4_documentation_and_multicast_classified_private() {
        // RFC 5737 documentation prefixes.
        assert!(is_private_or_internal_v4(&"192.0.2.1".parse().unwrap()));
        assert!(is_private_or_internal_v4(&"198.51.100.1".parse().unwrap()));
        assert!(is_private_or_internal_v4(&"203.0.113.1".parse().unwrap()));
        // Multicast.
        assert!(is_private_or_internal_v4(&"224.0.0.1".parse().unwrap()));
    }

    #[test]
    fn v4_public_ips_pass() {
        assert!(!is_private_or_internal_v4(&"1.1.1.1".parse().unwrap()));
        assert!(!is_private_or_internal_v4(&"8.8.8.8".parse().unwrap()));
        // CGNAT is intentionally NOT flagged.
        assert!(!is_private_or_internal_v4(&"100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn v6_loopback_unspecified_classified_private() {
        assert!(is_private_or_internal_v6(&"::1".parse().unwrap()));
        assert!(is_private_or_internal_v6(&"::".parse().unwrap()));
    }

    #[test]
    fn v6_unique_local_and_link_local_classified_private() {
        assert!(is_private_or_internal_v6(&"fc00::1".parse().unwrap()));
        assert!(is_private_or_internal_v6(&"fd00::1".parse().unwrap()));
        assert!(is_private_or_internal_v6(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn v6_documentation_and_multicast_classified_private() {
        assert!(is_private_or_internal_v6(&"2001:db8::1".parse().unwrap()));
        assert!(is_private_or_internal_v6(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn v6_ipv4_mapped_unwrapped_for_classification() {
        // ::ffff:192.168.1.1 — IPv6 wire form of a private IPv4. Must
        // be flagged so an attacker can't smuggle private IPv4 via AAAA.
        assert!(is_private_or_internal_v6(
            &"::ffff:192.168.1.1".parse().unwrap()
        ));
        // ::ffff:1.1.1.1 — public via IPv6 — must pass.
        assert!(!is_private_or_internal_v6(
            &"::ffff:1.1.1.1".parse().unwrap()
        ));
    }

    #[test]
    fn v6_public_pass() {
        assert!(!is_private_or_internal_v6(
            &"2606:4700::1111".parse().unwrap()
        ));
    }

    #[test]
    fn filter_strips_private_a_records_only() {
        let mut records = vec![
            record_a("evil.example.", "1.2.3.4"),
            record_a("evil.example.", "192.168.1.1"),
            record_a("evil.example.", "127.0.0.1"),
        ];
        let dropped = filter_private_rdata(&mut records);
        assert_eq!(dropped, 2);
        assert_eq!(records.len(), 1);
        match &records[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "1.2.3.4"),
            other => panic!("expected A 1.2.3.4, got {other:?}"),
        }
    }

    #[test]
    fn filter_strips_private_aaaa_records() {
        let mut records = vec![
            record_aaaa("evil.example.", "2606:4700::1111"),
            record_aaaa("evil.example.", "::1"),
            record_aaaa("evil.example.", "fe80::1"),
        ];
        let dropped = filter_private_rdata(&mut records);
        assert_eq!(dropped, 2);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn filter_preserves_non_address_records() {
        // CNAMEs and other types are passed through verbatim — only
        // bindable A/AAAA matter for rebinding.
        let mut records = vec![
            DnsRecord::new(
                "evil.example.",
                RecordData::Cname("cdn.example.".to_string()),
                Duration::from_secs(60),
            ),
            record_a("evil.example.", "192.168.1.1"),
        ];
        let dropped = filter_private_rdata(&mut records);
        assert_eq!(dropped, 1);
        assert_eq!(records.len(), 1);
        assert!(matches!(&records[0].data, RecordData::Cname(_)));
    }

    #[test]
    fn filter_empty_record_set_is_noop() {
        let mut records: Vec<DnsRecord> = Vec::new();
        let dropped = filter_private_rdata(&mut records);
        assert_eq!(dropped, 0);
        assert!(records.is_empty());
    }

    #[test]
    fn filter_all_public_records_keeps_all() {
        let mut records = vec![
            record_a("good.example.", "1.1.1.1"),
            record_a("good.example.", "8.8.8.8"),
            record_aaaa("good.example.", "2606:4700::1111"),
        ];
        let before = records.len();
        let dropped = filter_private_rdata(&mut records);
        assert_eq!(dropped, 0);
        assert_eq!(records.len(), before);
    }

    /// Independent of any real hickory build, prove that the
    /// longest-zone-first sort order produces the expected dispatch.
    /// We model what `select_arm` does after the sort.
    #[test]
    fn longest_zone_wins() {
        // Two routes — the more specific zone must win.
        let mut zones = vec!["internal.".to_string(), "corp.internal.".to_string()];
        zones.sort_by_key(|z| std::cmp::Reverse(z.len()));
        // First match wins after the sort: `server.corp.internal.`
        // must hit `corp.internal.`, not `internal.`.
        let qname = "server.corp.internal.";
        let mut hit = None;
        for z in &zones {
            if zone_matches(qname, z) {
                hit = Some(z.clone());
                break;
            }
        }
        assert_eq!(hit.as_deref(), Some("corp.internal."));
    }

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
            rate_limit: Default::default(),
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
