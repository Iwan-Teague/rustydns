#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Header, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SRV, TXT};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tracing::{debug, warn};

use rustydns_authority::Authority;
use rustydns_blocklist::BlocklistEngine;
use rustydns_core::client::ClientId;
use rustydns_core::config::BlockResponse;
use rustydns_core::record::{DnsRecord, RecordData};
use rustydns_core::RustyDnsError;
use rustydns_resolver::Resolver;

use crate::metrics::Metrics;

const SINKHOLE_TTL_SECS: u32 = 60;

/// DNS request handler implementing Authority -> Blocklist -> Resolver.
#[derive(Clone)]
pub struct DnsHandler {
    authority: Arc<Authority>,
    blocklist: Arc<BlocklistEngine>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
    sinkhole_ip: Option<IpAddr>,
}

impl DnsHandler {
    /// Construct a new handler with shared authority, blocklist, and resolver.
    pub fn new(
        authority: Arc<Authority>,
        blocklist: Arc<BlocklistEngine>,
        resolver: Arc<Resolver>,
        metrics: Arc<Metrics>,
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

        Ok(Self {
            authority,
            blocklist,
            resolver,
            metrics,
            sinkhole_ip,
        })
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
            (RecordType::A, IpAddr::V4(v4)) => vec![Record::from_rdata(name, SINKHOLE_TTL_SECS, RData::A(A(v4)))],
            (RecordType::AAAA, IpAddr::V6(v6)) => vec![Record::from_rdata(name, SINKHOLE_TTL_SECS, RData::AAAA(AAAA(v6)))],
            (RecordType::ANY, IpAddr::V4(v4)) => vec![Record::from_rdata(name, SINKHOLE_TTL_SECS, RData::A(A(v4)))],
            (RecordType::ANY, IpAddr::V6(v6)) => vec![Record::from_rdata(name, SINKHOLE_TTL_SECS, RData::AAAA(AAAA(v6)))],
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

        if request.op_code() != OpCode::Query {
            let builder = MessageResponseBuilder::from_message_request(request);
            return self
                .respond(request, response_handle, builder, ResponseCode::NotImp, false, Vec::new())
                .await;
        }

        if qclass != DNSClass::IN {
            let builder = MessageResponseBuilder::from_message_request(request);
            return self
                .respond(request, response_handle, builder, ResponseCode::NotImp, false, Vec::new())
                .await;
        }

        let client = ClientId::from_ip(info.src.ip());

        // PRIVACY: qname logged at debug only; do not enable debug in production.
        debug!(client = %client.anonymized(), qname = %qname, qtype = %qtype, "query received");

        let builder = MessageResponseBuilder::from_message_request(request);

        if let Some(records) = self.authority.lookup(&qname, &qtype_str) {
            self.metrics.inc_authority_hits();
            let answers = Self::dns_records_to_rrs(&records);
            return self
                .respond(request, response_handle, builder, ResponseCode::NoError, true, answers)
                .await;
        }

        if self.blocklist.is_blocked(&qname) {
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

            return self.respond(request, response_handle, builder, code, false, answers).await;
        }

        self.metrics.inc_resolver_queries();
        match self.resolver.resolve(&qname, &qtype_str).await {
            Ok(records) => {
                let answers = Self::dns_records_to_rrs(&records);
                self.respond(request, response_handle, builder, ResponseCode::NoError, false, answers)
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
                self.respond(request, response_handle, builder, ResponseCode::ServFail, false, Vec::new())
                    .await
            }
        }
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
        RecordData::Mx { preference, exchange } => {
            let exchange = Name::from_str(exchange).ok()?;
            RData::MX(MX::new(*preference, exchange))
        }
        RecordData::Srv { priority, weight, port, target } => {
            let target = Name::from_str(target).ok()?;
            RData::SRV(SRV::new(*priority, *weight, *port, target))
        }
    };

    Some(Record::from_rdata(name, ttl, rdata))
}
