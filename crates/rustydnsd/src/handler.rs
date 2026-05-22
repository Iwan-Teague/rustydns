#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Header, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
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

use std::collections::HashMap;

const SINKHOLE_TTL_SECS: u32 = 60;

/// Resolved per-client policy decision for one query.
///
/// Built once per query from the source IP. `None` for clients with no
/// matching `[[policy]]` entry — the pipeline runs with defaults.
#[derive(Debug, Clone, Default)]
struct PolicyDecision {
    blocklist_bypass: bool,
    zones_allowed: Vec<String>,
}

/// DNS request handler implementing Authority -> Blocklist -> Resolver.
#[derive(Clone)]
pub struct DnsHandler {
    authority: Arc<Authority>,
    blocklist: Arc<BlocklistEngine>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
    query_log: Arc<QueryLog>,
    sinkhole_ip: Option<IpAddr>,
    /// IP-keyed policy table. Rebuilt at startup; constant for the
    /// lifetime of the handler. SIGHUP-driven reload of policy is a
    /// separate TODO (would require config reload, currently only
    /// blocklist + mesh reload on HUP).
    policy_by_ip: Arc<HashMap<IpAddr, NodePolicy>>,
}

impl DnsHandler {
    /// Construct a new handler with shared authority, blocklist, resolver,
    /// and query-log ring buffer.
    pub fn new(
        authority: Arc<Authority>,
        blocklist: Arc<BlocklistEngine>,
        resolver: Arc<Resolver>,
        metrics: Arc<Metrics>,
        query_log: Arc<QueryLog>,
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

        // Build the IP-keyed lookup table once. validate_config already
        // rejected unparseable client_ip values, so the parse can't fail
        // here in practice — log and skip if it somehow does.
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

        Ok(Self {
            authority,
            blocklist,
            resolver,
            metrics,
            query_log,
            sinkhole_ip,
            policy_by_ip: Arc::new(policy_by_ip),
        })
    }

    /// Resolve the per-query policy for `src_ip`. Returns the default
    /// (no restrictions) when no `[[policy]]` entry matches.
    fn resolve_policy(&self, src_ip: IpAddr) -> PolicyDecision {
        match self.policy_by_ip.get(&src_ip) {
            Some(p) => PolicyDecision {
                blocklist_bypass: p.blocklist_bypass,
                zones_allowed: p.zones_allowed.clone(),
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

    /// Record one query into the ring buffer. Centralised so every
    /// pipeline arm uses the same hashing rules and `ServedBy`
    /// label.
    fn log_query(
        &self,
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
        self.query_log.record(
            client,
            &qname.to_ascii_lowercase(),
            qtype_static,
            // ResponseCode lacks `From<ResponseCode> for u8` but does
            // expose `.low()` for the wire-level value (top nibble is
            // for EDNS extended codes which we don't surface here).
            rcode.low(),
            served_by,
        );
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
        if let Some(edns) = request.edns() {
            builder.edns(edns.clone());
        }

        let mut header = Header::response_from_request(request.header());
        header.set_response_code(response_code);
        header.set_authoritative(authoritative);
        header.set_recursion_available(true);

        let response = builder.build(
            header,
            answers.iter(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                warn!(error = %e, "failed to send DNS response");
                Header::new().into()
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
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let info = request.request_info();
        let qname = info.query.name().to_string();
        let qtype = info.query.query_type();
        let qclass = info.query.query_class();
        let qtype_str = qtype.to_string();

        self.metrics.inc_queries();

        let client = ClientId::from_ip(info.src.ip());

        if request.op_code() != OpCode::Query {
            let builder = MessageResponseBuilder::from_message_request(request);
            self.log_query(
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

        let policy = self.resolve_policy(info.src.ip());

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

            self.log_query(&client, &qname, &qtype_str, code, ServedBy::Blocklist);
            return self
                .respond(request, response_handle, builder, code, false, answers)
                .await;
        }

        self.metrics.inc_resolver_queries();
        match self.resolver.resolve(&qname, &qtype_str).await {
            Ok(records) => {
                let answers = Self::dns_records_to_rrs(&records);
                self.log_query(
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
    use hickory_server::server::ServerFuture;
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
        _server: ServerFuture<DnsHandler>,
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

        let mut blocklist_cfg = BlocklistConfig::default();
        blocklist_cfg.sources = Vec::new();
        blocklist_cfg.reload_interval_secs = 0;
        blocklist_cfg.block_response = block_response;
        let blocklist = Arc::new(BlocklistEngine::new(blocklist_cfg));
        if !blocklist_lines.is_empty() {
            blocklist.load_trusted(blocklist_lines);
        }

        // Build a DnsConfig for the resolver. We intentionally use
        // unreachable upstreams in the SERVFAIL test so we never touch
        // the network in CI.
        let mut upstream = UpstreamConfig::default();
        upstream.resolvers = upstream_resolvers;
        // Short timeout so the SERVFAIL test doesn't take 5+ seconds.
        upstream.timeout_ms = 500;
        let mut dns_config = DnsConfig {
            server: Default::default(),
            upstream,
            authority: Default::default(),
            blocklist: Default::default(),
            privacy: Default::default(),
            metrics: Default::default(),
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
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            query_log.clone(),
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

        let mut server = ServerFuture::new(handler);
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(5));

        Harness {
            port,
            query_log,
            _server: server,
        }
    }

    /// Send a question over TCP using the standard 2-byte length prefix
    /// from RFC 1035 §4.2.2. Returns the parsed response.
    async fn query_tcp(port: u16, name: &str, rtype: ProtoRecordType) -> Message {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("tcp connect");
        let mut msg = Message::new();
        msg.set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
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
        let mut msg = Message::new();
        msg.set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
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

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.authoritative(), "authority hit must set the aa flag");
        let answers = resp.answers();
        assert_eq!(answers.len(), 1, "exactly one A record expected");
        let rdata = answers[0].data().expect("rdata");
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
            resp.response_code(),
            ResponseCode::NoError,
            "authority record must NOT be blocked by the blocklist"
        );
        assert!(resp.authoritative());
        let answers = resp.answers();
        assert_eq!(answers.len(), 1);
        match answers[0].data().unwrap() {
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

        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert_eq!(resp.answers().len(), 0);
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
        assert_eq!(resp.response_code(), ResponseCode::Refused);
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
            resp.response_code(),
            ResponseCode::ServFail,
            "fail-closed must return SERVFAIL when no upstream is reachable"
        );
        assert_eq!(resp.answers().len(), 0);
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

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.authoritative());
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data().unwrap() {
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
        assert_eq!(resp.response_code(), ResponseCode::ServFail);
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
            resp.response_code(),
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
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);

        // Out-of-zone query → REFUSED, pipeline never consulted.
        let resp = query(harness.port, "example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.response_code(), ResponseCode::Refused);
        assert!(resp.answers().is_empty());
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
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
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
        let mut msg = Message::new();
        msg.set_id(1)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update); // not Query
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
        assert_eq!(resp.response_code(), ResponseCode::NotImp);
    }
}
