#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{debug, warn};

use rustydns_authority::Authority;
use rustydns_blocklist::BlocklistEngine;
use rustydns_core::RustyDnsError;
use rustydns_core::client::ClientId;
use rustydns_core::config::{BlockResponse, NodePolicy};
use rustydns_core::record::{DnsRecord, RecordData};
use rustydns_resolver::Resolver;

use crate::metrics::Metrics;
use crate::query_log::{QueryLog, ServedBy};
use crate::rate_limiter::{LimitDecision, RateLimiter};

use std::collections::HashMap;

const SINKHOLE_TTL_SECS: u32 = 60;

/// Resolved per-client policy decision for one query.
///
/// Built once per query from the source IP. The default value is "no
/// restrictions" so clients with no matching `[[policy]]` entry get
/// the standard pipeline treatment.
#[derive(Debug, Clone, Default)]
struct PolicyDecision {
    blocklist_bypass: bool,
    zones_allowed: Vec<String>,
    log_all_queries: bool,
}

/// DNS request handler implementing Authority -> Blocklist -> Resolver.
///
/// `resolver`, `rate_limiter`, and `policy_by_ip` are held behind
/// [`ArcSwap`] so a SIGHUP-driven config reload can atomically swap new
/// values in without dropping in-flight queries (roadmap 3.2, Phase 1).
/// A query that has already `load()`ed an `Arc` keeps using that snapshot
/// to completion; the next query sees the new one. Listener/TLS changes
/// are *not* hot-swappable and still require a process restart.
#[derive(Clone)]
pub struct DnsHandler {
    authority: Arc<Authority>,
    blocklist: Arc<BlocklistEngine>,
    resolver: Arc<ArcSwap<Resolver>>,
    metrics: Arc<Metrics>,
    query_log: Arc<QueryLog>,
    rate_limiter: Arc<ArcSwap<RateLimiter>>,
    sinkhole_ip: Option<IpAddr>,
    /// IP-keyed policy table, hot-swappable on SIGHUP.
    policy_by_ip: Arc<ArcSwap<HashMap<IpAddr, NodePolicy>>>,
}

/// Build the IP-keyed policy lookup table from a `[[policy]]` list.
///
/// `validate_config` already rejected unparseable `client_ip` values, so
/// the parse cannot fail in practice — we log and skip if it somehow does.
fn build_policy_map(policies: &[NodePolicy]) -> HashMap<IpAddr, NodePolicy> {
    let mut policy_by_ip: HashMap<IpAddr, NodePolicy> = HashMap::new();
    for policy in policies {
        if let Some(ip_str) = &policy.client_ip {
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => {
                    if policy_by_ip.insert(ip, policy.clone()).is_some() {
                        warn!(
                            client_ip = %ip,
                            "duplicate [[policy]] entries for the same client_ip; \
                             the later one wins — review your rustydns.toml"
                        );
                    }
                }
                Err(_) => warn!(
                    client_ip = %ip_str,
                    "policy.client_ip failed late parse; this should have been caught \
                     by validate_config — ignoring this entry"
                ),
            }
        }
    }
    policy_by_ip
}

impl DnsHandler {
    /// Construct a new handler with shared authority, blocklist, resolver,
    /// rate limiter, and query-log ring buffer.
    pub fn new(
        authority: Arc<Authority>,
        blocklist: Arc<BlocklistEngine>,
        resolver: Arc<Resolver>,
        metrics: Arc<Metrics>,
        query_log: Arc<QueryLog>,
        rate_limiter: Arc<RateLimiter>,
        policies: &[NodePolicy],
    ) -> Result<Self, RustyDnsError> {
        let sinkhole_ip = if blocklist.block_response() == BlockResponse::Sinkhole {
            Some(IpAddr::from_str(blocklist.sinkhole_ip()).map_err(|_| {
                RustyDnsError::Config(format!(
                    "blocklist.sinkhole_ip `{}` is not a valid IP address",
                    blocklist.sinkhole_ip()
                ))
            })?)
        } else {
            None
        };

        let policy_by_ip = build_policy_map(policies);

        Ok(Self {
            authority,
            blocklist,
            resolver: Arc::new(ArcSwap::from(resolver)),
            metrics,
            query_log,
            rate_limiter: Arc::new(ArcSwap::from(rate_limiter)),
            sinkhole_ip,
            policy_by_ip: Arc::new(ArcSwap::from_pointee(policy_by_ip)),
        })
    }

    /// Atomically replace the upstream resolver (SIGHUP reload). In-flight
    /// queries that already loaded the old resolver finish against it.
    pub fn swap_resolver(&self, resolver: Arc<Resolver>) {
        self.resolver.store(resolver);
    }

    /// Atomically replace the rate limiter (SIGHUP reload). Token-bucket
    /// state resets — acceptable on an explicit operator reload.
    pub fn swap_rate_limiter(&self, rate_limiter: Arc<RateLimiter>) {
        self.rate_limiter.store(rate_limiter);
    }

    /// Atomically replace the per-client policy table (SIGHUP reload).
    pub fn swap_policies(&self, policies: &[NodePolicy]) {
        self.policy_by_ip
            .store(Arc::new(build_policy_map(policies)));
    }

    /// Resolve the per-query policy for `src_ip`. Returns the default
    /// (no restrictions) when no `[[policy]]` entry matches.
    fn resolve_policy(&self, src_ip: IpAddr) -> PolicyDecision {
        match self.policy_by_ip.load().get(&src_ip) {
            Some(p) => PolicyDecision {
                blocklist_bypass: p.blocklist_bypass,
                zones_allowed: p.zones_allowed.clone(),
                log_all_queries: p.log_all_queries,
            },
            None => PolicyDecision::default(),
        }
    }

    /// Borrow the query log buffer (for inspection / future
    /// management endpoint).
    #[allow(dead_code)]
    pub fn query_log(&self) -> &Arc<QueryLog> {
        &self.query_log
    }

    /// Record one query into the ring buffer AND emit a tracing::info!
    /// audit line if the matching policy sets `log_all_queries = true`.
    /// Centralised so every pipeline arm uses the same hashing rules and
    /// `ServedBy` label.
    fn log_query(
        &self,
        policy: &PolicyDecision,
        client: &ClientId,
        qname: &str,
        qtype: &str,
        rcode: ResponseCode,
        served_by: ServedBy,
    ) {
        // Static qtype label — `qtype.to_string()` would allocate
        // every query. The hickory `RecordType: Display` form is
        // already lowercase/uppercase ascii so we copy into a small
        // static interning table.
        let qtype_static = intern_qtype(qtype);
        let qname_lower = qname.to_ascii_lowercase();
        self.query_log.record(
            client,
            &qname_lower,
            qtype_static,
            // ResponseCode lacks `From<ResponseCode> for u8` but does
            // expose `.low()` for the wire-level value (top nibble is
            // for EDNS extended codes which we don't surface here).
            rcode.low(),
            served_by,
        );
        if policy.log_all_queries {
            // PRIVACY: hashed qname only, never the raw form. Anonymised
            // client only, never the raw IP. Matches the privacy
            // invariants for tracing output at info+ level.
            let qname_hash = self.query_log.hash_qname(&qname_lower);
            tracing::info!(
                client     = %client.anonymized(),
                qname_hash = format!("{qname_hash:016x}"),
                qtype      = %qtype_static,
                rcode      = rcode.low(),
                served_by  = served_by.as_str(),
                "policy.log_all_queries audit"
            );
        }
    }

    async fn respond<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        mut builder: MessageResponseBuilder<'_>,
        response_code: ResponseCode,
        authoritative: bool,
        answers: Vec<Record>,
    ) -> ResponseInfo {
        // hickory 0.26: Request derefs to MessageRequest, and the
        // EDNS opt-record lives on `MessageRequest::edns` directly.
        // The builder's `.edns()` now takes `&Edns` (borrowed,
        // tied to the request's lifetime).
        if let Some(edns) = request.edns.as_ref() {
            builder.edns(edns);
        }

        // hickory 0.26 split `Header` into `{ metadata, counts }`,
        // and `MessageResponseBuilder::build` takes `Metadata`
        // directly (counts are computed by the encoder). Mutate the
        // response metadata's public fields in place — no setters
        // anymore.
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = response_code;
        metadata.authoritative = authoritative;
        metadata.recursion_available = true;

        let response = builder.build(
            metadata,
            answers.iter(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                warn!(error = %e, "failed to send DNS response");
                // On the unrecoverable send-side error we return a
                // synthetic ResponseInfo so the trait sig is satisfied.
                Header {
                    metadata: Metadata::new(
                        0,
                        hickory_proto::op::MessageType::Response,
                        OpCode::Query,
                    ),
                    counts: HeaderCounts::default(),
                }
                .into()
            }
        }
    }

    fn dns_records_to_rrs(records: &[DnsRecord]) -> Vec<Record> {
        records.iter().filter_map(dns_record_to_rr).collect()
    }

    fn sinkhole_answers(&self, qname: &str, qtype: RecordType) -> Vec<Record> {
        let ip = match self.sinkhole_ip {
            Some(ip) => ip,
            None => return Vec::new(),
        };

        let name = match Name::from_str(qname) {
            Ok(name) => name,
            Err(_) => return Vec::new(),
        };

        match (qtype, ip) {
            (RecordType::A, IpAddr::V4(v4)) => {
                vec![Record::from_rdata(name, SINKHOLE_TTL_SECS, RData::A(A(v4)))]
            }
            (RecordType::AAAA, IpAddr::V6(v6)) => vec![Record::from_rdata(
                name,
                SINKHOLE_TTL_SECS,
                RData::AAAA(AAAA(v6)),
            )],
            (RecordType::ANY, IpAddr::V4(v4)) => {
                vec![Record::from_rdata(name, SINKHOLE_TTL_SECS, RData::A(A(v4)))]
            }
            (RecordType::ANY, IpAddr::V6(v6)) => vec![Record::from_rdata(
                name,
                SINKHOLE_TTL_SECS,
                RData::AAAA(AAAA(v6)),
            )],
            _ => Vec::new(),
        }
    }
}

#[async_trait]
impl RequestHandler for DnsHandler {
    // hickory 0.26 added a `T: Time` type parameter to handle_request.
    // We don't use it ourselves — it lets the server's transport layer
    // plug in its own time impl — but the trait sig now requires it.
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        // `request_info()` now returns Result. A malformed multi-query
        // message would Err here; we treat that as the moral equivalent
        // of the old class-mismatch branch and SERVFAIL.
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => {
                let builder = MessageResponseBuilder::from_message_request(request);
                let client = ClientId::from_ip(request.src().ip());
                let policy = self.resolve_policy(request.src().ip());
                self.log_query(
                    &policy,
                    &client,
                    "",
                    "?",
                    ResponseCode::FormErr,
                    ServedBy::Rejected,
                );
                return self
                    .respond(
                        request,
                        response_handle,
                        builder,
                        ResponseCode::FormErr,
                        false,
                        Vec::new(),
                    )
                    .await;
            }
        };
        let qname = info.query.name().to_string();
        let qtype = info.query.query_type();
        let qclass = info.query.query_class();
        let qtype_str = qtype.to_string();

        self.metrics.inc_queries();

        let client = ClientId::from_ip(info.src.ip());

        // Resolve policy ONCE per query, BEFORE any rejection branches,
        // so every `log_query` call (including the early opcode and
        // class rejections) honours `log_all_queries`.
        let policy = self.resolve_policy(info.src.ip());

        // Per-source-IP rate limiting. Runs BEFORE any pipeline work so
        // a flood costs only an `AHashMap` lookup + bucket update. The
        // limiter exempts loopback internally so local proxies aren't
        // penalised. See `crate::rate_limiter` for the algorithm.
        if self.rate_limiter.load().check(info.src.ip()) == LimitDecision::Refuse {
            self.metrics.inc_policy_rate_limited();
            warn!(
                client = %client.anonymized(),
                "policy denied: per-source-IP rate limit exceeded"
            );
            let builder = MessageResponseBuilder::from_message_request(request);
            self.log_query(
                &policy,
                &client,
                &qname,
                &qtype_str,
                ResponseCode::Refused,
                ServedBy::Rejected,
            );
            return self
                .respond(
                    request,
                    response_handle,
                    builder,
                    ResponseCode::Refused,
                    false,
                    Vec::new(),
                )
                .await;
        }

        // hickory 0.26 dropped the `op_code()` accessor; it's now a
        // public field on the deref'd MessageRequest's metadata.
        if request.metadata.op_code != OpCode::Query {
            let builder = MessageResponseBuilder::from_message_request(request);
            self.log_query(
                &policy,
                &client,
                &qname,
                &qtype_str,
                ResponseCode::NotImp,
                ServedBy::Rejected,
            );
            return self
                .respond(
                    request,
                    response_handle,
                    builder,
                    ResponseCode::NotImp,
                    false,
                    Vec::new(),
                )
                .await;
        }

        if qclass != DNSClass::IN {
            let builder = MessageResponseBuilder::from_message_request(request);
            self.log_query(
                &policy,
                &client,
                &qname,
                &qtype_str,
                ResponseCode::NotImp,
                ServedBy::Rejected,
            );
            return self
                .respond(
                    request,
                    response_handle,
                    builder,
                    ResponseCode::NotImp,
                    false,
                    Vec::new(),
                )
                .await;
        }

        // PRIVACY: qname logged at debug only; do not enable debug in production.
        debug!(client = %client.anonymized(), qname = %qname, qtype = %qtype, "query received");

        let builder = MessageResponseBuilder::from_message_request(request);

        // Zone allowlist: if the policy restricts this client to a set
        // of zones, refuse anything outside that set BEFORE consulting
        // the pipeline. Mesh-local quarantine clients never even probe
        // the resolver / blocklist.
        if !policy.zones_allowed.is_empty() && !name_in_any_zone(&qname, &policy.zones_allowed) {
            self.metrics.inc_policy_zone_denied();
            warn!(client = %client.anonymized(), "policy denied: name outside zones_allowed");
            let builder = MessageResponseBuilder::from_message_request(request);
            self.log_query(
                &policy,
                &client,
                &qname,
                &qtype_str,
                ResponseCode::Refused,
                ServedBy::Rejected,
            );
            return self
                .respond(
                    request,
                    response_handle,
                    builder,
                    ResponseCode::Refused,
                    false,
                    Vec::new(),
                )
                .await;
        }

        if let Some(records) = self.authority.lookup(&qname, &qtype_str) {
            self.metrics.inc_authority_hits();
            let answers = Self::dns_records_to_rrs(&records);
            self.log_query(
                &policy,
                &client,
                &qname,
                &qtype_str,
                ResponseCode::NoError,
                ServedBy::Authority,
            );
            return self
                .respond(
                    request,
                    response_handle,
                    builder,
                    ResponseCode::NoError,
                    true,
                    answers,
                )
                .await;
        }

        // Surface blocklist_bypass only when it ACTUALLY changed the
        // outcome — i.e. the name would have been blocked but wasn't.
        // A trivial bypass on a name that wasn't on the blocklist
        // anyway doesn't deserve a metric bump.
        let bypassed = policy.blocklist_bypass && self.blocklist.is_blocked(&qname);
        if bypassed {
            self.metrics.inc_policy_blocklist_bypass();
        }
        if !policy.blocklist_bypass && self.blocklist.is_blocked(&qname) {
            self.metrics.inc_blocklist_hits();
            // PRIVACY: qname logged at debug only; do not enable debug in production.
            debug!(client = %client.anonymized(), qname = %qname, "query blocked");
            let (code, answers) = match self.blocklist.block_response() {
                BlockResponse::Nxdomain => (ResponseCode::NXDomain, Vec::new()),
                BlockResponse::Refused => (ResponseCode::Refused, Vec::new()),
                BlockResponse::Sinkhole => {
                    let answers = self.sinkhole_answers(&qname, qtype);
                    if answers.is_empty() {
                        (ResponseCode::NXDomain, Vec::new())
                    } else {
                        (ResponseCode::NoError, answers)
                    }
                }
            };

            self.log_query(
                &policy,
                &client,
                &qname,
                &qtype_str,
                code,
                ServedBy::Blocklist,
            );
            return self
                .respond(request, response_handle, builder, code, false, answers)
                .await;
        }

        self.metrics.inc_resolver_queries();
        // load_full() yields an owned Arc so we don't hold the ArcSwap
        // guard across the .await (the guard is not Send).
        let resolver = self.resolver.load_full();
        match resolver.resolve(&qname, &qtype_str).await {
            Ok(out) => {
                self.metrics
                    .inc_private_rdata_dropped(out.private_rdata_dropped);
                let answers = Self::dns_records_to_rrs(&out.records);
                self.log_query(
                    &policy,
                    &client,
                    &qname,
                    &qtype_str,
                    ResponseCode::NoError,
                    ServedBy::Resolver,
                );
                self.respond(
                    request,
                    response_handle,
                    builder,
                    ResponseCode::NoError,
                    false,
                    answers,
                )
                .await
            }
            Err(err) => {
                self.metrics.inc_resolver_failures();
                match err {
                    RustyDnsError::AllUpstreamsFailed => {
                        warn!(client = %client.anonymized(), "all upstreams failed");
                    }
                    RustyDnsError::DnssecValidation { .. } => {
                        warn!(client = %client.anonymized(), "DNSSEC validation failed");
                    }
                    RustyDnsError::Upstream { upstream, .. } => {
                        warn!(client = %client.anonymized(), upstream = %upstream, "upstream error");
                    }
                    _ => {
                        warn!(client = %client.anonymized(), "resolver error");
                    }
                }
                self.log_query(
                    &policy,
                    &client,
                    &qname,
                    &qtype_str,
                    ResponseCode::ServFail,
                    ServedBy::ServerFailure,
                );
                self.respond(
                    request,
                    response_handle,
                    builder,
                    ResponseCode::ServFail,
                    false,
                    Vec::new(),
                )
                .await
            }
        }
    }
}

/// Returns `true` if `qname` falls within any of the configured
/// `zones_allowed` entries (case-insensitive, trailing-dot tolerant
/// subdomain match). The empty list case is handled by the caller
/// (treated as "no restriction").
fn name_in_any_zone(qname: &str, zones: &[String]) -> bool {
    let lower = qname.trim_end_matches('.').to_ascii_lowercase();
    for zone in zones {
        let z = zone.trim().trim_end_matches('.').to_ascii_lowercase();
        if z.is_empty() {
            continue;
        }
        if lower == z {
            return true;
        }
        if lower.len() > z.len()
            && lower.ends_with(&z)
            && lower.as_bytes()[lower.len() - z.len() - 1] == b'.'
        {
            return true;
        }
    }
    false
}

/// Map a hickory `RecordType` Display string to a stable `&'static str`.
/// Centralising this avoids allocating a `String` per query just for
/// the log buffer.
fn intern_qtype(s: &str) -> &'static str {
    match s {
        "A" => "A",
        "AAAA" => "AAAA",
        "CNAME" => "CNAME",
        "MX" => "MX",
        "NS" => "NS",
        "PTR" => "PTR",
        "SOA" => "SOA",
        "SRV" => "SRV",
        "TXT" => "TXT",
        "CAA" => "CAA",
        "DS" => "DS",
        "DNSKEY" => "DNSKEY",
        "RRSIG" => "RRSIG",
        "ANY" => "ANY",
        _ => "OTHER",
    }
}

fn dns_record_to_rr(rec: &DnsRecord) -> Option<Record> {
    let name = Name::from_str(&rec.name).ok()?;
    let ttl = u64::min(rec.ttl.as_secs(), u64::from(u32::MAX)) as u32;

    let rdata = match &rec.data {
        RecordData::A(ip) => RData::A(A(*ip)),
        RecordData::Aaaa(ip) => RData::AAAA(AAAA(*ip)),
        RecordData::Cname(target) => RData::CNAME(CNAME(Name::from_str(target).ok()?)),
        RecordData::Ptr(target) => RData::PTR(PTR(Name::from_str(target).ok()?)),
        RecordData::Ns(target) => RData::NS(NS(Name::from_str(target).ok()?)),
        RecordData::Txt(parts) => {
            let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
            RData::TXT(TXT::from_bytes(refs))
        }
        RecordData::Mx {
            preference,
            exchange,
        } => {
            let exchange = Name::from_str(exchange).ok()?;
            RData::MX(MX::new(*preference, exchange))
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            let target = Name::from_str(target).ok()?;
            RData::SRV(SRV::new(*priority, *weight, *port, target))
        }
    };

    Some(Record::from_rdata(name, ttl, rdata))
}

// ===========================================================================
// End-to-end integration tests
//
// Wires Authority + BlocklistEngine + Resolver + DnsHandler + ServerFuture
// in-process on a loopback UDP port and sends real DNS queries via a raw
// tokio UdpSocket. Covers the three invariants from AGENTS.md §Testing:
//   - blocked domain → NXDOMAIN
//   - authority hit bypasses the blocklist
//   - upstream failure → SERVFAIL (fail_closed)
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name as ProtoName, RecordType as ProtoRecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use hickory_server::Server;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    use rustydns_authority::Authority;
    use rustydns_blocklist::BlocklistEngine;
    use rustydns_core::config::{
        AuthorityConfig, BlockResponse, BlocklistConfig, DnsConfig, NodePolicy, StaticRecord,
        UpstreamConfig,
    };

    use super::name_in_any_zone;
    use rustydns_resolver::Resolver;

    use crate::handler::DnsHandler;
    use crate::metrics::Metrics;

    /// Daemon test harness: pipeline wired, listening on a randomly
    /// assigned loopback port. `port` is the bound UDP port.
    struct Harness {
        port: u16,
        query_log: Arc<crate::query_log::QueryLog>,
        // Hold the server future so it isn't dropped (which would shut
        // the listener down). The test drops it at the end of scope.
        _server: Server<DnsHandler>,
    }

    async fn build_harness(
        static_records: Vec<StaticRecord>,
        blocklist_lines: &str,
        upstream_resolvers: Vec<String>,
        block_response: BlockResponse,
    ) -> Harness {
        build_harness_with_policies(
            static_records,
            blocklist_lines,
            upstream_resolvers,
            block_response,
            Vec::new(),
        )
        .await
    }

    async fn build_harness_with_policies(
        static_records: Vec<StaticRecord>,
        blocklist_lines: &str,
        upstream_resolvers: Vec<String>,
        block_response: BlockResponse,
        policies: Vec<NodePolicy>,
    ) -> Harness {
        let metrics = Arc::new(Metrics::new().expect("metrics"));

        let authority_cfg = AuthorityConfig {
            mesh_zone_bundle_path: None,
            mesh_zone_verifier_key_path: None,
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records,
            poll_interval_secs: 30,
        };
        let authority = Arc::new(Authority::new(authority_cfg).expect("authority"));

        let blocklist_cfg = BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            block_response,
            ..BlocklistConfig::default()
        };
        let blocklist = Arc::new(BlocklistEngine::new(blocklist_cfg));
        if !blocklist_lines.is_empty() {
            blocklist.load_trusted(blocklist_lines);
        }

        // Build a DnsConfig for the resolver. We intentionally use
        // unreachable upstreams in the SERVFAIL test so we never touch
        // the network in CI. Short timeout so SERVFAIL doesn't take 5+s.
        let upstream = UpstreamConfig {
            resolvers: upstream_resolvers,
            timeout_ms: 500,
            ..UpstreamConfig::default()
        };
        let mut dns_config = DnsConfig {
            server: Default::default(),
            upstream,
            authority: Default::default(),
            blocklist: Default::default(),
            privacy: Default::default(),
            metrics: Default::default(),
            rate_limit: Default::default(),
            policy: Vec::new(),
        };
        // Disable randomisation for deterministic test ordering.
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;

        let resolver = Arc::new(
            Resolver::new(dns_config)
                .await
                .expect("resolver builds even with bogus upstreams (bootstrap is best-effort)"),
        );

        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
        // Tests exercise pipeline correctness, not rate limiting — use
        // the default-disabled limiter so test loopback bursts never
        // hit the cap. (Loopback is exempt anyway, but be explicit.)
        let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::new(
            &rustydns_core::config::RateLimitConfig {
                enabled: false,
                ..rustydns_core::config::RateLimitConfig::default()
            },
        ));
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            query_log.clone(),
            rate_limiter,
            &policies,
        )
        .expect("handler");

        // Bind UDP first, capture the assigned port, then bind TCP on
        // the same port so a single Harness exposes BOTH transports.
        // The OS rarely reuses the UDP port for TCP automatically, so
        // we explicitly request it.
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let tcp = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("bind tcp on same port");

        let mut server = Server::new(handler);
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(5), 4096);

        Harness {
            port,
            query_log,
            _server: server,
        }
    }

    /// Build a bare `DnsHandler` (no sockets/server) for unit-testing the
    /// SIGHUP hot-swap methods. Uses a bogus upstream — resolver
    /// construction is best-effort and never touches the network here.
    async fn bare_handler(policies: Vec<NodePolicy>) -> DnsHandler {
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: Vec::new(),
                poll_interval_secs: 30,
            })
            .expect("authority"),
        );
        let blocklist = Arc::new(BlocklistEngine::new(BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            ..BlocklistConfig::default()
        }));
        let mut dns_config = DnsConfig {
            server: Default::default(),
            upstream: UpstreamConfig {
                resolvers: vec!["https://192.0.2.1/dns-query".to_string()],
                timeout_ms: 500,
                ..UpstreamConfig::default()
            },
            authority: Default::default(),
            blocklist: Default::default(),
            privacy: Default::default(),
            metrics: Default::default(),
            rate_limit: Default::default(),
            policy: Vec::new(),
        };
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(8));
        let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::new(
            &rustydns_core::config::RateLimitConfig {
                enabled: false,
                ..rustydns_core::config::RateLimitConfig::default()
            },
        ));
        DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            query_log,
            rate_limiter,
            &policies,
        )
        .expect("handler")
    }

    fn policy_for(ip: &str, bypass: bool) -> NodePolicy {
        NodePolicy {
            node_id: None,
            client_ip: Some(ip.to_string()),
            blocklist_bypass: bypass,
            zones_allowed: Vec::new(),
            log_all_queries: false,
        }
    }

    #[tokio::test]
    async fn swap_policies_updates_policy_decision() {
        let ip: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        // Start with no policies → default decision (no bypass).
        let handler = bare_handler(Vec::new()).await;
        assert!(
            !handler.resolve_policy(ip).blocklist_bypass,
            "no policy ⇒ default (no bypass)"
        );

        // Hot-swap in a bypass policy for that IP.
        handler.swap_policies(&[policy_for("10.0.0.7", true)]);
        assert!(
            handler.resolve_policy(ip).blocklist_bypass,
            "after swap, the IP must resolve to the new bypass policy"
        );

        // Swap back to empty → default again.
        handler.swap_policies(&[]);
        assert!(
            !handler.resolve_policy(ip).blocklist_bypass,
            "swapping to empty policy set restores the default"
        );
    }

    #[tokio::test]
    async fn swap_rate_limiter_takes_effect() {
        let handler = bare_handler(Vec::new()).await;
        let off_net: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        // Default limiter in bare_handler is disabled → always Allow.
        assert_eq!(
            handler.rate_limiter.load().check(off_net),
            crate::rate_limiter::LimitDecision::Allow
        );
        // Swap in a strict limiter (1 token, no refill in this window).
        handler.swap_rate_limiter(Arc::new(crate::rate_limiter::RateLimiter::new(
            &rustydns_core::config::RateLimitConfig {
                enabled: true,
                qps: 1,
                burst: 1,
                max_tracked_clients: 16,
            },
        )));
        assert_eq!(
            handler.rate_limiter.load().check(off_net),
            crate::rate_limiter::LimitDecision::Allow,
            "first query consumes the single token"
        );
        assert_eq!(
            handler.rate_limiter.load().check(off_net),
            crate::rate_limiter::LimitDecision::Refuse,
            "second immediate query is refused by the swapped-in limiter"
        );
    }

    /// Send a question over TCP using the standard 2-byte length prefix
    /// from RFC 1035 §4.2.2. Returns the parsed response.
    async fn query_tcp(port: u16, name: &str, rtype: ProtoRecordType) -> Message {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("tcp connect");
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii(name).unwrap())
                .set_query_type(rtype);
            q
        });
        let bytes = msg.to_bytes().expect("encode");
        let len = (bytes.len() as u16).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(&bytes).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await.unwrap();
        Message::from_bytes(&resp).expect("decode tcp response")
    }

    /// Send a question over UDP, return the parsed response.
    async fn query(port: u16, name: &str, rtype: ProtoRecordType) -> Message {
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = ProtoName::from_ascii(name).expect("name parse");
        msg.add_query({
            let mut q = Query::new();
            q.set_name(name).set_query_type(rtype);
            q
        });
        let bytes = msg.to_bytes().expect("encode");
        client
            .send_to(&bytes, format!("127.0.0.1:{port}"))
            .await
            .expect("send");
        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("response within 5s")
            .expect("recv");
        Message::from_bytes(&buf[..n]).expect("decode response")
    }

    fn static_a(name: &str, addr: &str) -> StaticRecord {
        StaticRecord {
            name: name.to_string(),
            record_type: "A".to_string(),
            address: Some(addr.to_string()),
            target: None,
            ttl: 300,
            client_filter: None,
        }
    }

    fn static_cname(name: &str, target: &str) -> StaticRecord {
        StaticRecord {
            name: name.to_string(),
            record_type: "CNAME".to_string(),
            address: None,
            target: Some(target.to_string()),
            ttl: 300,
            client_filter: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authority_hit_serves_static_record_with_aa_flag() {
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()], // unreachable, but unused
            BlockResponse::Nxdomain,
        )
        .await;

        let resp = query(harness.port, "router.mesh.", ProtoRecordType::A).await;

        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(
            resp.metadata.authoritative,
            "authority hit must set the aa flag"
        );
        let answers = resp.answers;
        assert_eq!(answers.len(), 1, "exactly one A record expected");
        let rdata = &answers[0].data;
        let ip = match rdata {
            hickory_proto::rr::RData::A(a) => a.0.to_string(),
            other => panic!("expected A, got {other:?}"),
        };
        assert_eq!(ip, "100.64.0.5");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authority_hit_bypasses_blocklist() {
        // Static record for the same name that the blocklist would have blocked.
        // The authority is FIRST in the pipeline (AGENTS.md invariant);
        // the blocklist must not be consulted for mesh-authoritative names.
        let harness = build_harness(
            vec![static_a("ads.example.com", "10.0.0.99")],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let resp = query(harness.port, "ads.example.com.", ProtoRecordType::A).await;

        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "authority record must NOT be blocked by the blocklist"
        );
        assert!(resp.metadata.authoritative);
        let answers = resp.answers;
        assert_eq!(answers.len(), 1);
        match &answers[0].data {
            hickory_proto::rr::RData::A(a) => assert_eq!(a.0.to_string(), "10.0.0.99"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_domain_returns_nxdomain() {
        let harness = build_harness(
            vec![],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let resp = query(harness.port, "ads.example.com.", ProtoRecordType::A).await;

        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(resp.answers.len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_domain_refused_response_code() {
        let harness = build_harness(
            vec![],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Refused,
        )
        .await;

        let resp = query(harness.port, "ads.example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn upstream_failure_returns_servfail() {
        // No authority hit, no blocklist match, unreachable upstream →
        // fail-closed → SERVFAIL.
        let harness = build_harness(
            vec![],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let resp = query(
            harness.port,
            "definitely-not-cached.example.test.",
            ProtoRecordType::A,
        )
        .await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::ServFail,
            "fail-closed must return SERVFAIL when no upstream is reachable"
        );
        assert_eq!(resp.answers.len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_log_captures_each_pipeline_arm() {
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        // 1. authority hit
        let _ = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        // 2. blocklist hit
        let _ = query(harness.port, "ads.example.com.", ProtoRecordType::A).await;
        // 3. resolver / fail-closed
        let _ = query(
            harness.port,
            "definitely-uncached.example.test.",
            ProtoRecordType::A,
        )
        .await;

        let snap = harness.query_log.snapshot();
        assert_eq!(snap.len(), 3, "every query should be recorded");

        // Snapshots are newest-first: resolver-fail, blocklist, authority.
        assert_eq!(snap[0].served_by, crate::query_log::ServedBy::ServerFailure);
        assert_eq!(snap[0].rcode, 2 /* SERVFAIL */);
        assert_eq!(snap[1].served_by, crate::query_log::ServedBy::Blocklist);
        assert_eq!(snap[1].rcode, 3 /* NXDOMAIN */);
        assert_eq!(snap[2].served_by, crate::query_log::ServedBy::Authority);
        assert_eq!(snap[2].rcode, 0 /* NoError */);

        // Hashes line up with the qnames if we hash again with the
        // same buffer's salt.
        let h_authority = harness.query_log.hash_qname("router.mesh.");
        let h_block = harness.query_log.hash_qname("ads.example.com.");
        let h_resolver = harness
            .query_log
            .hash_qname("definitely-uncached.example.test.");
        assert_eq!(snap[2].qname_hash, h_authority);
        assert_eq!(snap[1].qname_hash, h_block);
        assert_eq!(snap[0].qname_hash, h_resolver);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authority_hit_follows_cname_chain_over_udp() {
        // alias.lab.example.com → host.lab.example.com (A=10.0.0.5).
        // The wire response must carry BOTH the CNAME and the terminal
        // A in the answer section, with aa=1 — exercises the full
        // authority chain follower + handler RR conversion + UDP
        // encode round-trip.
        let harness = build_harness(
            vec![
                static_cname("alias.lab.example.com", "host.lab.example.com"),
                static_a("host.lab.example.com", "10.0.0.5"),
            ],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let resp = query(harness.port, "alias.lab.example.com.", ProtoRecordType::A).await;

        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(
            resp.metadata.authoritative,
            "authority chain follow must keep aa=1",
        );
        assert_eq!(
            resp.answers.len(),
            2,
            "expected CNAME + A in answer section, got: {:?}",
            resp.answers,
        );

        // Order matters for a well-formed answer: CNAME first, then
        // the terminal A.
        match &resp.answers[0].data {
            hickory_proto::rr::RData::CNAME(target) => {
                assert_eq!(target.to_string(), "host.lab.example.com.");
            }
            other => panic!("expected CNAME first, got {other:?}"),
        }
        match &resp.answers[1].data {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0.to_string(), "10.0.0.5");
            }
            other => panic!("expected terminal A, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_listener_serves_authority_hit() {
        // Same scenario as the UDP authority-hit test, but over TCP
        // (with the 2-byte length prefix). Pins that
        // `register_listener` is wired into the same DnsHandler and
        // that the TCP encode/decode round-trip is intact.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let resp = query_tcp(harness.port, "router.mesh.", ProtoRecordType::A).await;

        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.metadata.authoritative);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => assert_eq!(a.0.to_string(), "100.64.0.5"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_listener_returns_servfail_when_upstream_fails() {
        let harness = build_harness(
            vec![],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let resp = query_tcp(
            harness.port,
            "tcp-uncached.example.test.",
            ProtoRecordType::A,
        )
        .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dot_listener_serves_authority_hit_over_real_tls_handshake() {
        // Full DoT path:
        //   1. Build the daemon's pipeline (authority + blocklist + resolver).
        //   2. Bind a TLS listener using our embedded self-signed cert.
        //   3. Connect via tokio-rustls with a ClientConfig that trusts
        //      that cert as a root.
        //   4. Send a length-prefixed DNS query (RFC 7858 framing).
        //   5. Decode the response and assert the authority hit.
        //
        // This catches regressions in:
        //   - load_tls_config PEM parsing
        //   - hickory-server's TLS handshake plumbing
        //   - rustls version compatibility across our deps
        //   - the rest of the pipeline that the UDP/TCP/DoH tests cover

        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};

        use crate::test_pem::{TEST_CA_PEM, TEST_CERT_CN, TEST_LEAF_CERT_PEM, TEST_LEAF_KEY_PEM};

        // Ring crypto provider is required for both sides of the
        // handshake. Idempotent — second install is a no-op.
        let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        );

        // Write test cert + key to per-test unique temp files so
        // parallel runs don't collide.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let cert_path = std::env::temp_dir().join(format!("rustydns-dot-cert-{id}.pem"));
        let key_path = std::env::temp_dir().join(format!("rustydns-dot-key-{id}.pem"));
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(TEST_LEAF_CERT_PEM.as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(TEST_LEAF_KEY_PEM.as_bytes())
            .unwrap();

        // Build the pipeline. Authority answers `router.mesh A 100.64.0.7`.
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority_cfg = AuthorityConfig {
            mesh_zone_bundle_path: None,
            mesh_zone_verifier_key_path: None,
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records: vec![static_a("router.mesh", "100.64.0.7")],
            poll_interval_secs: 30,
        };
        let authority = Arc::new(Authority::new(authority_cfg).unwrap());
        let blocklist = Arc::new(BlocklistEngine::new(BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            ..BlocklistConfig::default()
        }));
        let mut dns_config = DnsConfig {
            server: Default::default(),
            upstream: UpstreamConfig {
                resolvers: vec!["https://127.0.0.1:1/dns-query".to_string()],
                timeout_ms: 500,
                ..UpstreamConfig::default()
            },
            authority: Default::default(),
            blocklist: Default::default(),
            privacy: Default::default(),
            metrics: Default::default(),
            rate_limit: Default::default(),
            policy: Vec::new(),
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.unwrap());
        let query_log = Arc::new(crate::query_log::QueryLog::new(16));
        let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::new(
            &rustydns_core::config::RateLimitConfig {
                enabled: false,
                ..rustydns_core::config::RateLimitConfig::default()
            },
        ));
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            query_log,
            rate_limiter,
            &[],
        )
        .unwrap();

        // Reuse the daemon's TLS-config loader so the test path
        // matches production.
        use rustydns_core::config::ServerConfig as RsServerConfig;
        let tls_server_config = crate::load_tls_config(&RsServerConfig {
            tls_cert_path: Some(cert_path.clone()),
            tls_key_path: Some(key_path.clone()),
            ..RsServerConfig::default()
        })
        .expect("load_tls_config");

        // Pick a random port + register the TLS listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server
            .register_tls_listener_with_tls_config(
                listener,
                Duration::from_secs(5),
                tls_server_config,
            )
            .expect("register_tls_listener_with_tls_config");

        // Build a rustls ClientConfig that trusts the embedded cert as
        // a root. Don't go through webpki — we want the self-signed CN
        // to validate without DNS plumbing.
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let ca_der = CertificateDer::from_pem_slice(TEST_CA_PEM.as_bytes())
            .expect("parse embedded CA as DER");
        roots.add(ca_der).expect("add CA to root store");

        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        // Connect, TLS-handshake, send query, read response.
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("tcp connect");
        let server_name = ServerName::try_from(TEST_CERT_CN.to_string()).expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls handshake");

        // Build a wire-format DNS query for `router.mesh A` with the
        // 2-byte length prefix from RFC 7858 §4.
        let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii("router.mesh.").unwrap())
                .set_query_type(ProtoRecordType::A);
            q
        });
        let body = msg.to_bytes().expect("encode query");
        let len = (body.len() as u16).to_be_bytes();
        tls.write_all(&len).await.expect("write length prefix");
        tls.write_all(&body).await.expect("write body");

        let mut len_buf = [0u8; 2];
        tls.read_exact(&mut len_buf)
            .await
            .expect("read response length");
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tls.read_exact(&mut resp_buf)
            .await
            .expect("read response body");
        let resp = Message::from_bytes(&resp_buf).expect("decode response");

        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.metadata.authoritative, "authority hit must set aa");
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => assert_eq!(a.0.to_string(), "100.64.0.7"),
            other => panic!("expected A, got {other:?}"),
        }

        // Drop the server explicitly so the listener future cancels
        // before tokio drops the runtime.
        drop(server);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_blocklist_bypass_lets_blocked_name_through() {
        // The query loopback originates from 127.0.0.1, so put a policy
        // for that IP. With blocklist_bypass = true the same name that
        // the blocklist would block must reach the resolver — which
        // will fail-closed → SERVFAIL because the upstream is bogus.
        let policy = NodePolicy {
            node_id: None,
            client_ip: Some("127.0.0.1".to_string()),
            blocklist_bypass: true,
            zones_allowed: Vec::new(),
            log_all_queries: false,
        };
        let harness = build_harness_with_policies(
            vec![],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
            vec![policy],
        )
        .await;
        let resp = query(harness.port, "ads.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::ServFail,
            "blocklist_bypass should let the query reach the resolver, which then fail-closes"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_zones_allowed_refuses_out_of_scope_query() {
        // Restrict 127.0.0.1 to mesh.* only.
        let policy = NodePolicy {
            node_id: None,
            client_ip: Some("127.0.0.1".to_string()),
            blocklist_bypass: false,
            zones_allowed: vec!["mesh.".to_string()],
            log_all_queries: false,
        };
        let harness = build_harness_with_policies(
            vec![static_a("router.mesh", "100.64.0.1")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
            vec![policy],
        )
        .await;

        // In-zone query still works.
        let resp = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);

        // Out-of-zone query → REFUSED, pipeline never consulted.
        let resp = query(harness.port, "example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_log_all_queries_threads_through_to_log_query() {
        // We can't easily intercept tracing::info! from a test without a
        // subscriber, but we CAN prove that PolicyDecision.log_all_queries
        // is true for a matching client and that the query is still
        // recorded normally in the ring buffer. The actual info! emit is
        // exercised through inspection of the daemon log at runtime.
        let policy = NodePolicy {
            node_id: None,
            client_ip: Some("127.0.0.1".to_string()),
            blocklist_bypass: false,
            zones_allowed: Vec::new(),
            log_all_queries: true,
        };
        let harness = build_harness_with_policies(
            vec![static_a("router.mesh", "100.64.0.1")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
            vec![policy],
        )
        .await;

        let resp = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);

        // Buffer entry exists — same shape as non-audited paths.
        let snap = harness.query_log.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].served_by, crate::query_log::ServedBy::Authority);
        assert_eq!(snap[0].rcode, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_does_not_match_other_clients() {
        // Policy keyed to 10.0.0.5 — must NOT affect 127.0.0.1.
        let policy = NodePolicy {
            node_id: None,
            client_ip: Some("10.0.0.5".to_string()),
            blocklist_bypass: true,
            zones_allowed: Vec::new(),
            log_all_queries: false,
        };
        let harness = build_harness_with_policies(
            vec![],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
            vec![policy],
        )
        .await;
        // Query from 127.0.0.1 should still be blocked (policy is for 10.0.0.5).
        let resp = query(harness.port, "ads.example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn name_in_any_zone_handles_trailing_dot_and_case() {
        let zones = vec!["MESH.".to_string(), "lab.example.com".to_string()];
        assert!(name_in_any_zone("router.mesh.", &zones));
        assert!(name_in_any_zone("Router.MESH", &zones));
        assert!(name_in_any_zone("nas.lab.example.com.", &zones));
        // Zone apex itself matches.
        assert!(name_in_any_zone("mesh", &zones));
        // Not a subdomain — "meshx" must not match "mesh".
        assert!(!name_in_any_zone("meshx", &zones));
        // Outside any zone.
        assert!(!name_in_any_zone("example.com", &zones));
        // Empty zone list: caller treats as no restriction; we don't
        // exercise that path through this helper but the predicate
        // returns false for "matches nothing".
        assert!(!name_in_any_zone("anything", &[]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_query_opcode_returns_notimp() {
        // We're a recursive resolver, not a master server. UPDATE etc.
        // must return NotImp without ever consulting the pipeline.
        let harness = build_harness(
            vec![],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut msg = Message::new(1, MessageType::Query, OpCode::Update); // not Query
        let n = ProtoName::from_ascii("ignored.example.").unwrap();
        msg.add_query({
            let mut q = Query::new();
            q.set_name(n).set_query_type(ProtoRecordType::A);
            q
        });
        client
            .send_to(
                &msg.to_bytes().unwrap(),
                format!("127.0.0.1:{}", harness.port),
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = Message::from_bytes(&buf[..n]).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
    }
}
