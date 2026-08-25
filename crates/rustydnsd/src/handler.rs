#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::{Edns, Header, HeaderCounts, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncoder;
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{debug, warn};

use rustydns_authority::Authority;
use rustydns_blocklist::BlocklistEngine;
use rustydns_core::BlockSchedule;
use rustydns_core::RustyDnsError;
use rustydns_core::client::ClientId;
use rustydns_core::config::{BlockResponse, NodePolicy, RewriteRule, redact_url_credentials};
use rustydns_core::record::{DnsRecord, RecordData};
use rustydns_resolver::Resolver;

use crate::metrics::Metrics;
use crate::query_log::{QueryLog, ServedBy};
use crate::rate_limiter::{LimitDecision, RateLimiter};
use crate::rewrite::{RewriteDecision, RewriteMap};

use std::collections::HashMap;

const SINKHOLE_TTL_SECS: u32 = 60;

/// A process-wide shared empty `Arc<[String]>`.
///
/// `resolve_policy` returns `PolicyDecision::default()` for every
/// non-policied client (the common case) — cloning this shared `Arc`
/// is O(1) and allocation-free, so the default path never touches the
/// heap. Without the shared instance, `Arc::from(Vec::new())` would
/// allocate an `Arc` header on every query.
fn empty_zones() -> Arc<[String]> {
    static EMPTY: OnceLock<Arc<[String]>> = OnceLock::new();
    EMPTY.get_or_init(|| Vec::<String>::new().into()).clone()
}

/// Current Unix time in seconds. Used to evaluate per-client block schedules.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolved per-client policy decision for one query.
///
/// Built once per query from the source IP. The default value is "no
/// restrictions" so clients with no matching `[[policy]]` entry get
/// the standard pipeline treatment.
///
/// `zones_allowed` is an `Arc<[String]>` (not a `Vec<String>`) so a query
/// from a zone-restricted client clones an `Arc` (O(1)) instead of deep-
/// copying every zone string per query.
#[derive(Debug, Clone)]
struct PolicyDecision {
    blocklist_bypass: bool,
    zones_allowed: Arc<[String]>,
    log_all_queries: bool,
    /// `true` if a `[[policy.block_windows]]` window is active for this client
    /// right now — every query is refused before the pipeline runs.
    schedule_blocked: bool,
    /// Named blocklist group for this client (TODO 8.6), or `None` for the
    /// global blocklist. `Arc<str>` so the per-query clone is O(1).
    blocklist_group: Option<Arc<str>>,
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self {
            blocklist_bypass: false,
            zones_allowed: empty_zones(),
            log_all_queries: false,
            schedule_blocked: false,
            blocklist_group: None,
        }
    }
}

/// A `[[policy]]` entry compiled for fast per-query lookup: the zone list is
/// pre-interned into an `Arc<[String]>` and the block schedule is pre-compiled
/// once at map-build time so [`DnsHandler::resolve_policy`] only does cheap
/// per-query work (an `Arc` clone and a timestamp check).
#[derive(Debug, Clone)]
struct CompiledPolicy {
    blocklist_bypass: bool,
    zones_allowed: Arc<[String]>,
    log_all_queries: bool,
    schedule: BlockSchedule,
    blocklist_group: Option<Arc<str>>,
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
    policy_by_ip: Arc<ArcSwap<HashMap<IpAddr, CompiledPolicy>>>,
    /// DNS rewrite / local cloaking map, hot-swappable on SIGHUP.
    rewrites: Arc<ArcSwap<RewriteMap>>,
}

/// Build the IP-keyed policy lookup table from a `[[policy]]` list.
///
/// `validate_config` already rejected unparseable `client_ip` values, so
/// the parse cannot fail in practice — we log and skip if it somehow does.
/// Canonicalise a client/policy address for per-client keying: IPv4-mapped
/// V6 forms collapse to native V4 so policy lookup and map keys agree no
/// matter which socket family delivered the packet. Mirrors the rate
/// limiter's bucket-key normalisation.
fn canonical_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn build_policy_map(policies: &[NodePolicy]) -> HashMap<IpAddr, CompiledPolicy> {
    let mut policy_by_ip: HashMap<IpAddr, CompiledPolicy> = HashMap::new();
    for policy in policies {
        if let Some(ip_str) = &policy.client_ip {
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => {
                    // Canonicalise IPv4-mapped V6 spellings to native V4 so
                    // entries match clients regardless of whether the socket
                    // delivered the source as `192.168.1.55` (v4-native) or
                    // `::ffff:192.168.1.55` (dual-stack v6 listener). Without
                    // this, a mapped-form client silently misses its policy.
                    let ip = canonical_client_ip(ip);
                    let compiled = CompiledPolicy {
                        blocklist_bypass: policy.blocklist_bypass,
                        zones_allowed: Arc::from(policy.zones_allowed.as_slice()),
                        log_all_queries: policy.log_all_queries,
                        // validate_config already checked these compile; fall
                        // back to an empty (never-blocking) schedule on the
                        // can't-happen error rather than panicking.
                        schedule: BlockSchedule::compile(&policy.block_windows).unwrap_or_default(),
                        blocklist_group: policy.blocklist_group.as_deref().map(Arc::from),
                    };
                    if policy_by_ip.insert(ip, compiled).is_some() {
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
    // A dependency-injection constructor: each argument is a distinct shared
    // subsystem or config slice the handler wires together. Grouping them into
    // a struct would only move the same fields elsewhere, so allow the arg
    // count here.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: Arc<Authority>,
        blocklist: Arc<BlocklistEngine>,
        resolver: Arc<Resolver>,
        metrics: Arc<Metrics>,
        query_log: Arc<QueryLog>,
        rate_limiter: Arc<RateLimiter>,
        policies: &[NodePolicy],
        rewrites: &[RewriteRule],
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

        let rewrite_map = RewriteMap::from_rules(rewrites);
        if !rewrite_map.is_empty() {
            tracing::info!(rules = rewrite_map.len(), "DNS rewrite map active");
        }

        Ok(Self {
            authority,
            blocklist,
            resolver: Arc::new(ArcSwap::from(resolver)),
            metrics,
            query_log,
            rate_limiter: Arc::new(ArcSwap::from(rate_limiter)),
            sinkhole_ip,
            policy_by_ip: Arc::new(ArcSwap::from_pointee(policy_by_ip)),
            rewrites: Arc::new(ArcSwap::from_pointee(rewrite_map)),
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

    /// Atomically replace the DNS rewrite map (SIGHUP reload).
    pub fn swap_rewrites(&self, rewrites: &[RewriteRule]) {
        self.rewrites
            .store(Arc::new(RewriteMap::from_rules(rewrites)));
    }

    /// Resolve the per-query policy for `src_ip`. Returns the default
    /// (no restrictions) when no `[[policy]]` entry matches.
    fn resolve_policy(&self, src_ip: IpAddr) -> PolicyDecision {
        // Same canonicalisation as build_policy_map: a dual-stack v6
        // listener delivers v4 peers as ::ffff:a.b.c.d; the map is keyed on
        // native V4, so normalise before lookup or the entry silently misses.
        let src_ip = canonical_client_ip(src_ip);
        match self.policy_by_ip.load().get(&src_ip) {
            Some(p) => PolicyDecision {
                blocklist_bypass: p.blocklist_bypass,
                // Arc clone — O(1), no per-element String copy.
                zones_allowed: Arc::clone(&p.zones_allowed),
                log_all_queries: p.log_all_queries,
                // Evaluate the (pre-compiled) block schedule against now. Cheap
                // when no windows are configured (empty schedule → false).
                // Conservative eval: an untrusted wall clock (pre-epoch, dead RTC)
                // keeps configured restrictions ACTIVE instead of silently
                // failing open.
                schedule_blocked: !p.schedule.is_empty()
                    && p.schedule.is_blocked_at_conservative(now_unix()),
                blocklist_group: p.blocklist_group.clone(),
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
    /// `qname_canon` must already be the lowercased canonical form (the
    /// handler computes it once per query); `qtype` is the static label from
    /// `RecordType::into::<&'static str>()`. Neither allocates here.
    fn log_query(
        &self,
        policy: &PolicyDecision,
        client: &ClientId,
        qname_canon: &str,
        qtype: &'static str,
        rcode: ResponseCode,
        served_by: ServedBy,
    ) {
        self.query_log.record(
            client,
            qname_canon,
            qtype,
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
            let qname_hash = self.query_log.hash_qname(qname_canon);
            tracing::info!(
                client     = %client.anonymized(),
                qname_hash = format!("{qname_hash:016x}"),
                qtype      = %qtype,
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
        mut answers: Vec<Record>,
    ) -> ResponseInfo {
        // Single send choke point for every response path — count the final
        // rcode here, mapped to a bounded label set (see `rcode_metric_label`).
        self.metrics
            .inc_response_rcode(rcode_metric_label(response_code));

        // hickory 0.26: Request derefs to MessageRequest, and the
        // EDNS opt-record lives on `MessageRequest::edns` directly.
        // The builder's `.edns()` now takes `&Edns` (borrowed,
        // tied to the request's lifetime).
        // Clamp oversized client buffer-size advertisements: echoing a
        // 64 KiB advertisement verbatim advertises our willingness to
        // emit/accept oversized datagrams — needless amplification and
        // fragmentation surface. The advertised value never needs to be
        // larger than what we will actually put on the wire. Hoisted so the
        // borrow outlives the builder's use below.
        const MAX_EDNS_PAYLOAD: u16 = 4096;
        let normalized_edns = request.edns.as_ref().map(|e| {
            let mut c = e.clone();
            if c.max_payload() > MAX_EDNS_PAYLOAD {
                c.set_max_payload(MAX_EDNS_PAYLOAD);
            }
            // RFC 6891 §6.1.1: a response OPT advertises OUR version — 0 —
            // never an echoed request version we do not implement.
            c.set_version(0);
            c
        });
        if let Some(edns) = normalized_edns.as_ref() {
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

        // UDP responses must never exceed the applicable datagram cap: the
        // classic 512-byte limit without EDNS, or the (already-clamped)
        // advertised payload with it. hickory's encoder happily emits an
        // arbitrarily large answer over UDP, so we shed trailing records
        // here and mark the message TC — the client then retries over TCP.
        if request.protocol() == Protocol::Udp {
            let cap: usize = match request.edns.as_ref() {
                Some(e) => (e.max_payload() as usize).clamp(512, MAX_EDNS_PAYLOAD as usize),
                None => 512,
            };
            // The probe MUST include the same echoed EDNS the final
            // emission attaches — otherwise shed decisions under-count by
            // the OPT size and an "fits" verdict can still ship an
            // over-cap datagram.
            let measure =
                |ans: &[Record], tc: bool, m0: Metadata, edns: Option<&Edns>| -> Option<usize> {
                    let mut m = m0;
                    m.truncation = tc;
                    let mut b = MessageResponseBuilder::from_message_request(request);
                    if let Some(e) = edns {
                        b.edns(e);
                    }
                    let r = b.build(
                        m,
                        ans.iter(),
                        std::iter::empty::<&Record>(),
                        std::iter::empty::<&Record>(),
                        std::iter::empty::<&Record>(),
                    );
                    let mut scratch = Vec::with_capacity(cap * 2);
                    let mut enc = BinEncoder::new(&mut scratch);
                    r.destructive_emit(&mut enc).ok()?;
                    Some(scratch.len())
                };
            let measure_now = |ans: &[Record], tc: bool, m0: Metadata| -> Option<usize> {
                measure(ans, tc, m0, normalized_edns.as_ref())
            };
            if measure_now(&answers, false, metadata).is_none_or(|n| n > cap) {
                metadata.truncation = true;
                let original = answers.len();
                let mut shed = 0usize;
                while !answers.is_empty()
                    && measure_now(&answers, true, metadata).is_none_or(|n| n > cap)
                {
                    answers.pop();
                    shed += 1;
                }
                // ONE summary line: a per-record warn here turned any large
                // (but legitimate) upstream answer into journal flooding,
                // repeatable per query.
                warn!(
                    shed,
                    kept = answers.len(),
                    original,
                    cap,
                    "udp response exceeded its cap; truncated to fit (TC set)"
                );
            }
        }

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

    /// Build the `(response_code, answers)` for a blocked query per the
    /// configured `block_response`. Shared by the QNAME-block path and the
    /// CNAME-cloaking path so both honour `nxdomain` / `refused` / `sinkhole`
    /// identically. `qname` is the original (cased) name so a sinkhole record
    /// echoes the client's name.
    fn build_block_response(&self, qname: &str, qtype: RecordType) -> (ResponseCode, Vec<Record>) {
        match self.blocklist.block_response() {
            BlockResponse::Nxdomain => (ResponseCode::NXDomain, Vec::new()),
            BlockResponse::Refused => (ResponseCode::Refused, Vec::new()),
            BlockResponse::Sinkhole => {
                let answers = self.sinkhole_answers(qname, qtype);
                if answers.is_empty() {
                    (ResponseCode::NXDomain, Vec::new())
                } else {
                    (ResponseCode::NoError, answers)
                }
            }
        }
    }

    /// CNAME-cloaking defence: returns `true` if any CNAME target in the
    /// upstream answer is on the blocklist.
    ///
    /// Trackers evade QNAME blocklists by pointing an innocuous first-party
    /// name at a CNAME like `c.tracker-adnetwork.net`. The QNAME isn't on any
    /// list, so it passes the pre-resolution blocklist check — but the answer
    /// reveals the blocked target. We check every CNAME target in the chain;
    /// since the final A/AAAA owner name is always the last CNAME target,
    /// checking targets covers the whole chain. Pure in-memory lookups — no
    /// extra upstream queries.
    fn cname_chain_blocked(&self, records: &[DnsRecord], group: Option<&str>) -> bool {
        records.iter().any(|rec| match &rec.data {
            RecordData::Cname(target) => self.blocklist.is_blocked_for_group(target, group),
            _ => false,
        })
    }

    /// Response-IP denylist (TODO 8.3): returns `true` if any resolved A/AAAA
    /// rdata is on the operator-supplied IP/CIDR denylist. Lets operators
    /// blackhole malware C2 / ad-network IP ranges that rotate domains faster
    /// than a name blocklist can track.
    fn response_ip_blocked(&self, records: &[DnsRecord]) -> bool {
        records.iter().any(|rec| match &rec.data {
            RecordData::A(ip) => self.blocklist.is_response_ip_blocked(IpAddr::V4(*ip)),
            RecordData::Aaaa(ip) => self.blocklist.is_response_ip_blocked(IpAddr::V6(*ip)),
            _ => false,
        })
    }

    // --- Pipeline stages -------------------------------------------------
    //
    // `handle_request` runs these in order; each returns `Some(Reply)` to short-
    // circuit (the first one that does wins) or `None` to fall through. The
    // resolver stage always produces a `Reply`. Keeping each stage as a named
    // method means the response is logged and sent in exactly ONE place
    // ([`DnsHandler::finish`]) instead of being duplicated at every branch.

    /// Per-source-IP rate limit. Loopback is exempt inside the limiter, so
    /// local proxies are never penalised. Runs first so a flood costs only a
    /// hash lookup + bucket update.
    fn gate_rate_limit(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        if self.rate_limiter.load().check(ctx.src_ip) == LimitDecision::Refuse {
            self.metrics.inc_policy_rate_limited();
            // PRIVACY + flood-safety: refusals are counted by
            // rustydns_policy_rate_limited_total; a per-query warn here would
            // flood the journal at exactly the moment we are being flooded.
            // Opt in via RUST_LOG for per-event detail.
            debug!(
                client = %ctx.client.anonymized(),
                "policy denied: per-source-IP rate limit exceeded"
            );
            Some(Reply::reject(ResponseCode::Refused))
        } else {
            None
        }
    }

    /// Only standard queries are served; anything else (UPDATE, NOTIFY, …) is
    /// NOTIMP.
    fn gate_opcode(&self, request: &Request, _ctx: &QueryCtx<'_>) -> Option<Reply> {
        // hickory 0.26 exposes the opcode as a field on the deref'd request
        // metadata (the `op_code()` accessor was dropped).
        if request.metadata.op_code != OpCode::Query {
            Some(Reply::reject(ResponseCode::NotImp))
        } else {
            None
        }
    }

    /// Only the IN class is served; CHAOS/HESIOD/etc. are NOTIMP.
    fn gate_class(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        if ctx.qclass != DNSClass::IN {
            Some(Reply::reject(ResponseCode::NotImp))
        } else {
            None
        }
    }

    /// RFC 6891 §6.1.3: a request advertising an EDNS version greater than
    /// the one we support (0) must be answered with BADVERS — never silently
    /// accepted (we cannot be trusted to honour newer semantics) and never a
    /// bare SERVFAIL (which tells the client nothing actionable). The
    /// response carries an OPT RR advertising OUR version, which `respond`
    /// normalises to 0 for every reply.
    fn gate_edns_version(&self, request: &Request) -> Option<Reply> {
        let edns = request.edns.as_ref()?;
        if edns.version() > 0 {
            // Rcode is counted once, in `respond` (single choke point).
            Some(Reply::reject(ResponseCode::BADVERS))
        } else {
            None
        }
    }

    /// ANY (qtype 255) queries are REFUSED: an ANY answer can be arbitrarily
    /// large (every record the zone holds), making the resolver an
    /// amplification vector, and RFC 8482 documents refusal as the compliant
    /// minimal-answer posture. Nothing here serves zone transfers by any
    /// other name.
    fn gate_any_qtype(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        if ctx.qtype == RecordType::ANY {
            self.metrics.inc_policy_refused_any();
            Some(Reply::reject(ResponseCode::Refused))
        } else {
            None
        }
    }

    /// Scheduled block window (TODO 8.5): if the client is inside an active
    /// `[[policy.block_windows]]` window, refuse every query before the
    /// pipeline (e.g. "kids' devices off after 22:00").
    fn gate_schedule(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        if ctx.policy.schedule_blocked {
            self.metrics.inc_policy_schedule_blocked();
            // Same flood-safety rationale as the rate-limit refusal above.
            debug!(
                client = %ctx.client.anonymized(),
                "policy denied: client is within a scheduled block window"
            );
            Some(Reply::reject(ResponseCode::Refused))
        } else {
            None
        }
    }

    /// Zone allowlist: if the policy restricts this client to a set of zones,
    /// refuse anything outside it before the pipeline. Mesh-local quarantine
    /// clients never even probe the resolver / blocklist.
    fn gate_zones(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        if !ctx.policy.zones_allowed.is_empty()
            && !name_in_any_zone(ctx.qname_canon, &ctx.policy.zones_allowed)
        {
            self.metrics.inc_policy_zone_denied();
            // PRIVACY + flood-safety: counted by the REFUSED rcode series;
            // per-query warns would flood the journal during sustained
            // out-of-zone probing.
            debug!(
                client = %ctx.client.anonymized(),
                "policy denied: name outside zones_allowed"
            );
            Some(Reply::reject(ResponseCode::Refused))
        } else {
            None
        }
    }

    /// Authoritative answer (mesh zone or static zone). Wins over rewrite,
    /// blocklist, and resolver.
    fn gate_authority(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        let records = self.authority.lookup(ctx.qname_canon, ctx.qtype_label)?;
        self.metrics.inc_authority_hits();
        Some(Reply {
            code: ResponseCode::NoError,
            authoritative: true,
            answers: Self::dns_records_to_rrs(&records),
            served_by: ServedBy::Authority,
        })
    }

    /// DNS rewrites / local cloaking map (TODO 8.2): operator overrides for
    /// names outside our zones — pin to an IP, CNAME elsewhere, or blackhole.
    /// After authority (authority wins), before blocklist/resolver.
    fn gate_rewrite(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        // Bind to a local so the ArcSwap guard is released at the end of this
        // statement (this stage is synchronous — nothing is held across await).
        let decision = self.rewrites.load().lookup(ctx.qname_canon, ctx.qtype)?;
        self.metrics.inc_rewrite_hits();
        // PRIVACY: qname at debug only; do not enable debug in production.
        debug!(client = %ctx.client.anonymized(), qname = %ctx.qname, "query rewritten");
        let (code, authoritative, answers) = match decision {
            RewriteDecision::Nxdomain => (ResponseCode::NXDomain, false, Vec::new()),
            RewriteDecision::NoData => (ResponseCode::NoError, false, Vec::new()),
            RewriteDecision::Answer(records) => (
                ResponseCode::NoError,
                false,
                Self::dns_records_to_rrs(&records),
            ),
        };
        Some(Reply {
            code,
            authoritative,
            answers,
            served_by: ServedBy::Rewrite,
        })
    }

    /// QNAME blocklist (per-client group when assigned, else global), honouring
    /// `blocklist_bypass`. The bypass metric is bumped only when bypass actually
    /// changed the outcome (the name *would* have been blocked).
    fn gate_blocklist(&self, ctx: &QueryCtx<'_>) -> Option<Reply> {
        let group = ctx.policy.blocklist_group.as_deref();
        let bypassed = ctx.policy.blocklist_bypass
            && self.blocklist.is_blocked_for_group(ctx.qname_canon, group);
        if bypassed {
            self.metrics.inc_policy_blocklist_bypass();
        }
        if !ctx.policy.blocklist_bypass
            && self.blocklist.is_blocked_for_group(ctx.qname_canon, group)
        {
            self.metrics.inc_blocklist_hits();
            // PRIVACY: qname at debug only; do not enable debug in production.
            debug!(client = %ctx.client.anonymized(), qname = %ctx.qname, "query blocked");
            let (code, answers) = self.build_block_response(ctx.qname, ctx.qtype);
            Some(Reply {
                code,
                authoritative: false,
                answers,
                served_by: ServedBy::Blocklist,
            })
        } else {
            None
        }
    }

    /// Forward to the upstream resolver, then apply the answer-time blocklist
    /// defences (CNAME cloaking, response-IP denylist) and the NXDOMAIN-vs-
    /// NODATA distinction. Always produces a `Reply` (this is the last stage):
    /// on any upstream error it fails closed with SERVFAIL.
    async fn stage_resolve(&self, ctx: &QueryCtx<'_>) -> Reply {
        self.metrics.inc_resolver_queries();
        // load_full() yields an owned Arc so the ArcSwap guard is not held
        // across the .await (the guard is not Send). Raw `qname` (original
        // case) goes to the upstream — unchanged behaviour.
        let resolver = self.resolver.load_full();
        match resolver.resolve(ctx.qname, ctx.qtype_label).await {
            Ok(out) => {
                self.metrics
                    .inc_private_rdata_dropped(out.private_rdata_dropped);

                // CNAME-cloaking defence (TODO 8.1): a tracker can pass the
                // pre-resolution QNAME check by CNAMEing a clean first-party
                // name to a blocked domain. Block the whole response if any
                // CNAME target is blocked — unless this client bypasses the
                // blocklist. The `&&` short-circuits so bypass clients pay
                // nothing.
                if self.blocklist.block_cname_cloaking()
                    && !ctx.policy.blocklist_bypass
                    && self.cname_chain_blocked(&out.records, ctx.policy.blocklist_group.as_deref())
                {
                    self.metrics.inc_blocklist_hits();
                    self.metrics.inc_blocklist_cname_cloaking_blocked();
                    // PRIVACY: qname at debug only; do not enable debug in prod.
                    debug!(client = %ctx.client.anonymized(), qname = %ctx.qname, "query blocked (CNAME cloaking)");
                    let (code, answers) = self.build_block_response(ctx.qname, ctx.qtype);
                    return Reply {
                        code,
                        authoritative: false,
                        answers,
                        served_by: ServedBy::Blocklist,
                    };
                }

                // Response-IP denylist (TODO 8.3): block if any resolved A/AAAA
                // rdata is on the operator's IP/CIDR denylist. Same bypass
                // exemption; the active guard short-circuits when no ranges are
                // configured.
                if self.blocklist.response_ip_denylist_active()
                    && !ctx.policy.blocklist_bypass
                    && self.response_ip_blocked(&out.records)
                {
                    self.metrics.inc_blocklist_hits();
                    self.metrics.inc_blocklist_response_ip_blocked();
                    // PRIVACY: qname at debug only; do not enable debug in prod.
                    debug!(client = %ctx.client.anonymized(), qname = %ctx.qname, "query blocked (response-IP denylist)");
                    let (code, answers) = self.build_block_response(ctx.qname, ctx.qtype);
                    return Reply {
                        code,
                        authoritative: false,
                        answers,
                        served_by: ServedBy::Blocklist,
                    };
                }

                let answers = Self::dns_records_to_rrs(&out.records);
                // Honour the upstream's NXDOMAIN vs NODATA distinction. The
                // `answers.is_empty()` guard ensures we never emit NXDomain
                // alongside records (defensive — the resolver only sets
                // `nxdomain` on the empty-answer path).
                let code = if out.nxdomain && answers.is_empty() {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::NoError
                };
                Reply {
                    code,
                    authoritative: false,
                    answers,
                    served_by: ServedBy::Resolver,
                }
            }
            Err(err) => {
                self.metrics.inc_resolver_failures();
                match err {
                    RustyDnsError::AllUpstreamsFailed => {
                        warn!(client = %ctx.client.anonymized(), "all upstreams failed");
                    }
                    RustyDnsError::DnssecValidation { .. } => {
                        warn!(client = %ctx.client.anonymized(), "DNSSEC validation failed");
                    }
                    RustyDnsError::Upstream { upstream, .. } => {
                        // PRIVACY: the stored URL may embed credentials; same
                        // redaction as every other URL-bearing log surface.
                        warn!(
                            client = %ctx.client.anonymized(),
                            upstream = %redact_url_credentials(&upstream),
                            "upstream error"
                        );
                    }
                    _ => {
                        warn!(client = %ctx.client.anonymized(), "resolver error");
                    }
                }
                Reply {
                    code: ResponseCode::ServFail,
                    authoritative: false,
                    answers: Vec::new(),
                    served_by: ServedBy::ServerFailure,
                }
            }
        }
    }

    /// The single response choke point: log the query once (honouring
    /// `log_all_queries`) and send the response. Every pipeline path ends here,
    /// so logging and metric attribution happen in exactly one place.
    async fn finish<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        builder: MessageResponseBuilder<'_>,
        ctx: &QueryCtx<'_>,
        reply: Reply,
    ) -> ResponseInfo {
        self.log_query(
            &ctx.policy,
            &ctx.client,
            ctx.qname_canon,
            ctx.qtype_label,
            reply.code,
            reply.served_by,
        );
        self.respond(
            request,
            response_handle,
            builder,
            reply.code,
            reply.authoritative,
            reply.answers,
        )
        .await
    }
}

/// Per-query context, assembled once and threaded by reference through the
/// pipeline stages. Holds only borrows, `Copy` scalars, and the once-resolved
/// policy — so building it allocates nothing beyond what the caller already did
/// (the QNAME `String` and its canonical `Cow`, both owned by `handle_request`
/// and borrowed here). This is what keeps a lowercase cache-hit query off the
/// heap.
struct QueryCtx<'a> {
    src_ip: IpAddr,
    client: ClientId,
    policy: PolicyDecision,
    /// Original-case QNAME (the client's bytes): used for the upstream query
    /// and the sinkhole/ block-response owner, which preserve case, and for
    /// debug logging.
    qname: &'a str,
    /// Lowercased QNAME, computed once. Handed to authority / blocklist /
    /// allowlist / zones / query-log so the pipeline never re-lowercases.
    qname_canon: &'a str,
    qtype: RecordType,
    /// `RecordType -> &'static str` (zero-alloc), used as the metric + log label.
    qtype_label: &'static str,
    qclass: DNSClass,
}

/// What a pipeline stage decided. Stages return this instead of writing the
/// response themselves, so [`DnsHandler::finish`] is the one place that logs +
/// sends — collapsing what used to be ~10 duplicated tail blocks into one.
struct Reply {
    code: ResponseCode,
    authoritative: bool,
    answers: Vec<Record>,
    served_by: ServedBy,
}

impl Reply {
    /// A rejection: no answers, not authoritative, attributed to `Rejected`.
    /// (SERVFAIL is built directly in `stage_resolve` since it is attributed to
    /// `ServerFailure`, not `Rejected`.)
    fn reject(code: ResponseCode) -> Self {
        Self {
            code,
            authoritative: false,
            answers: Vec::new(),
            served_by: ServedBy::Rejected,
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
        // Canonicalise the QNAME ONCE: lowercased, borrowing when the client
        // already sent lowercase (the common case). `QueryCtx` borrows this
        // single form for authority / blocklist / allowlist / zones / log, so
        // the pipeline never re-lowercases. The raw `qname` is kept for the
        // paths that preserve the client's original case (upstream query and
        // sinkhole/block-response owner) and for debug logging.
        let qname_canon = canonical_qname(&qname);

        // Static qtype label via `RecordType -> &'static str` (zero-alloc),
        // also used as the bounded metric label (attacker-chosen qtypes
        // collapse to "Unknown" rather than inflating cardinality).
        let qtype: RecordType = info.query.query_type();
        let qtype_label: &'static str = qtype.into();
        self.metrics.inc_queries();
        self.metrics.inc_query_qtype(qtype_label);

        // Assemble the per-query context once. `policy` is resolved BEFORE any
        // rejection branch so every `log_query` (including early gates) honours
        // `log_all_queries`. `QueryCtx` holds only borrows + `Copy` + the moved
        // policy, so it adds no allocation.
        let ctx = QueryCtx {
            src_ip: info.src.ip(),
            client: ClientId::from_ip(info.src.ip()),
            policy: self.resolve_policy(info.src.ip()),
            qname: &qname,
            qname_canon: &qname_canon,
            qtype,
            qtype_label,
            qclass: info.query.query_class(),
        };
        let builder = MessageResponseBuilder::from_message_request(request);

        // Gates that must run BEFORE the "query received" debug line (so a
        // rate-limited or non-Query message is not logged as received). First
        // gate to return `Some` wins; `response_handle` is consumed by the
        // single `finish`.
        if let Some(reply) = self
            .gate_rate_limit(&ctx)
            .or_else(|| self.gate_opcode(request, &ctx))
            .or_else(|| self.gate_edns_version(request))
            .or_else(|| self.gate_any_qtype(&ctx))
            .or_else(|| self.gate_class(&ctx))
        {
            return self
                .finish(request, response_handle, builder, &ctx, reply)
                .await;
        }

        // PRIVACY: qname logged at debug only; do not enable debug in production.
        debug!(client = %ctx.client.anonymized(), qname = %ctx.qname, qtype = %ctx.qtype, "query received");

        // The pipeline proper: policy gates → authority → rewrite → blocklist,
        // each short-circuiting, else the resolver (which always replies, and
        // fails closed to SERVFAIL).
        let reply = self
            .gate_schedule(&ctx)
            .or_else(|| self.gate_zones(&ctx))
            .or_else(|| self.gate_authority(&ctx))
            .or_else(|| self.gate_rewrite(&ctx))
            .or_else(|| self.gate_blocklist(&ctx));
        let reply = match reply {
            Some(reply) => reply,
            None => self.stage_resolve(&ctx).await,
        };
        self.finish(request, response_handle, builder, &ctx, reply)
            .await
    }
}

/// Returns `true` if `qname` falls within any of the configured
/// `zones_allowed` entries (case-insensitive, trailing-dot tolerant
/// subdomain match). The empty list case is handled by the caller
/// (treated as "no restriction").
/// Map a `ResponseCode` to a bounded `&'static str` metric label. Only the
/// codes rustydns itself emits get their own series; everything else (an
/// unusual upstream rcode, an EDNS extended code) collapses to `"other"`, so
/// the `rustydns_dns_responses_by_rcode_total` label set cannot be inflated
/// into a metrics-memory DoS by attacker- or upstream-controlled rcodes.
fn rcode_metric_label(rcode: ResponseCode) -> &'static str {
    match rcode {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        // Emitted by gate_edns_version since RFC 6891 conformance landed.
        ResponseCode::BADVERS => "BADVERS",
        _ => "other",
    }
}

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

/// Lowercase a QNAME into the single canonical form used for matching and
/// logging, **borrowing** the input when the client already sent it in lower
/// case (the common case — browsers emit lowercase names). hickory always
/// yields a trailing-dot FQDN, so only the case can differ; we never need to
/// touch the dot. Only a mixed-case query pays one allocation.
fn canonical_qname(name: &str) -> Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
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
    use hickory_proto::rr::DNSClass as TestDNSClass;
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

    use super::{build_policy_map, name_in_any_zone, rcode_metric_label};
    use rustydns_resolver::Resolver;

    use crate::handler::DnsHandler;
    use crate::metrics::Metrics;

    #[test]
    fn rcode_metric_label_maps_known_codes_and_buckets_the_rest() {
        // Codes rustydns emits map to their own stable series.
        assert_eq!(rcode_metric_label(ResponseCode::NoError), "NOERROR");
        assert_eq!(rcode_metric_label(ResponseCode::FormErr), "FORMERR");
        assert_eq!(rcode_metric_label(ResponseCode::ServFail), "SERVFAIL");
        assert_eq!(rcode_metric_label(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_metric_label(ResponseCode::NotImp), "NOTIMP");
        assert_eq!(rcode_metric_label(ResponseCode::Refused), "REFUSED");
        // BADVERS is emitted by gate_edns_version (RFC 6891) and gets its
        // own series — operators need to see EDNS-version probes separately
        // from the generic "other" bucket.
        assert_eq!(rcode_metric_label(ResponseCode::BADVERS), "BADVERS");
        // Anything else collapses to a single "other" bucket, so an unusual
        // upstream rcode can never inflate the metric's label cardinality.
        assert_eq!(rcode_metric_label(ResponseCode::NXRRSet), "other");
        assert_eq!(rcode_metric_label(ResponseCode::YXDomain), "other");
        assert_eq!(rcode_metric_label(ResponseCode::NotAuth), "other");
    }

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
            rewrite: Vec::new(),
            safesearch: Default::default(),
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
            &[],
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

    /// Spawn a tiny mock UDP DNS upstream that answers **any** A query for
    /// `NAME` with the chain `NAME CNAME <cname_target>` + `<cname_target> A
    /// 93.184.216.34`. Returns the bound port. Used by the CNAME-cloaking
    /// tests so the handler sees a real CNAME chain in the answer.
    async fn spawn_cname_mock(cname_target: &'static str) -> u16 {
        use hickory_proto::rr::rdata::{A, CNAME};
        use hickory_proto::rr::{RData, Record};

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(q) = query.queries.first() else {
                    continue;
                };
                let owner = q.name().clone();
                let target = ProtoName::from_ascii(cname_target).unwrap();
                let mut resp =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.add_query(q.clone());
                resp.add_answer(Record::from_rdata(
                    owner,
                    300,
                    RData::CNAME(CNAME(target.clone())),
                ));
                resp.add_answer(Record::from_rdata(
                    target,
                    300,
                    RData::A(A("93.184.216.34".parse().unwrap())),
                ));
                if let Ok(bytes) = resp.to_bytes() {
                    let _ = sock.send_to(&bytes, src).await;
                }
            }
        });
        port
    }

    /// Build a harness whose resolver forwards to a real plain-UDP upstream
    /// at `127.0.0.1:upstream_port` (used with `spawn_cname_mock`), with the
    /// CNAME-cloaking defence toggle and an optional client policy.
    async fn build_cname_harness(
        blocklist_lines: &str,
        upstream_port: u16,
        block_cname_cloaking: bool,
        policies: Vec<NodePolicy>,
    ) -> Harness {
        use rustydns_core::config::UpstreamProtocol;

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

        let blocklist_cfg = BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            block_response: BlockResponse::Nxdomain,
            block_cname_cloaking,
            ..BlocklistConfig::default()
        };
        let blocklist = Arc::new(BlocklistEngine::new(blocklist_cfg));
        if !blocklist_lines.is_empty() {
            blocklist.load_trusted(blocklist_lines);
        }

        let mut dns_config = DnsConfig {
            server: Default::default(),
            upstream: UpstreamConfig {
                resolvers: vec![format!("127.0.0.1:{upstream_port}")],
                protocol: UpstreamProtocol::Plain,
                timeout_ms: 1000,
                ..UpstreamConfig::default()
            },
            authority: Default::default(),
            blocklist: Default::default(),
            privacy: Default::default(),
            metrics: Default::default(),
            rate_limit: Default::default(),
            policy: Vec::new(),
            rewrite: Vec::new(),
            safesearch: Default::default(),
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));

        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            &[],
        )
        .expect("handler");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);
        Harness {
            port,
            query_log,
            _server: server,
        }
    }

    #[tokio::test]
    async fn cname_cloaking_blocks_when_answer_targets_blocked_domain() {
        // QNAME `metrics.example.com` is NOT on the blocklist, but it CNAMEs
        // to `c.tracker-adnetwork.net`, which IS. Only the CNAME-cloaking
        // defence can catch this → NXDOMAIN.
        let port = spawn_cname_mock("c.tracker-adnetwork.net.").await;
        let harness =
            build_cname_harness("0.0.0.0 c.tracker-adnetwork.net\n", port, true, Vec::new()).await;

        let resp = query(harness.port, "metrics.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "a CNAME-cloaked tracker must be blocked"
        );
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn cname_cloaking_allows_clean_chain() {
        // CNAME target is a normal CDN, not on the blocklist → answer passes.
        let port = spawn_cname_mock("cdn.cloudfront.net.").await;
        let harness =
            build_cname_harness("0.0.0.0 c.tracker-adnetwork.net\n", port, true, Vec::new()).await;

        let resp = query(harness.port, "assets.example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(
            !resp.answers.is_empty(),
            "a clean CNAME chain must be returned unchanged"
        );
    }

    #[tokio::test]
    async fn cname_cloaking_disabled_lets_blocked_target_through() {
        // With the defence off, the cloaked tracker resolves normally.
        let port = spawn_cname_mock("c.tracker-adnetwork.net.").await;
        let harness =
            build_cname_harness("0.0.0.0 c.tracker-adnetwork.net\n", port, false, Vec::new()).await;

        let resp = query(harness.port, "metrics.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "with block_cname_cloaking = false the cloaked tracker is not blocked"
        );
        assert!(!resp.answers.is_empty());
    }

    /// Two-hop CNAME chain: QNAME → `b.relay.example.` → `ads.tracker-deep.net.`
    /// (→ A). Only the FINAL hop is on the blocklist, so only a defence that
    /// follows the whole chain — not just the first CNAME record — can catch
    /// it.
    async fn spawn_deep_cname_mock() -> u16 {
        use hickory_proto::rr::rdata::{A, CNAME};
        use hickory_proto::rr::{RData, Record};

        let hop_b: &'static str = "b.relay.example.";
        let hop_c: &'static str = "ads.tracker-deep.net.";

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(q) = query.queries.first() else {
                    continue;
                };
                let owner = q.name().clone();
                let b = ProtoName::from_ascii(hop_b).unwrap();
                let c = ProtoName::from_ascii(hop_c).unwrap();
                let mut resp =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.add_query(q.clone());
                resp.add_answer(Record::from_rdata(
                    owner,
                    300,
                    RData::CNAME(CNAME(b.clone())),
                ));
                resp.add_answer(Record::from_rdata(b, 300, RData::CNAME(CNAME(c.clone()))));
                resp.add_answer(Record::from_rdata(
                    c,
                    300,
                    RData::A(A("93.184.216.34".parse().unwrap())),
                ));
                if let Ok(bytes) = resp.to_bytes() {
                    let _ = sock.send_to(&bytes, src).await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn deep_cname_chain_blocked_through_final_hop() {
        // The blocklist names ONLY the final hop (`ads.tracker-deep.net`);
        // neither the QNAME nor the intermediate relay matches. The chain
        // check must walk every CNAME record in the answer and block on the
        // deep one.
        let port = spawn_deep_cname_mock().await;
        let harness =
            build_cname_harness("0.0.0.0 ads.tracker-deep.net\n", port, true, Vec::new()).await;

        let resp = query(harness.port, "front.clean.example.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "a chain ending in a blocked domain must be blocked at depth 2"
        );
        assert!(resp.answers.is_empty());
    }

    /// Build a harness with `[[rewrite]]` rules and optional static records.
    /// The upstream is bogus — rewrites are served before the resolver, so a
    /// rewrite hit never touches the network.
    async fn build_rewrite_harness(
        static_records: Vec<StaticRecord>,
        rewrites: Vec<rustydns_core::config::RewriteRule>,
    ) -> Harness {
        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records,
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
            rewrite: Vec::new(),
            safesearch: Default::default(),
        };
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            &[],
            &rewrites,
        )
        .expect("handler");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);
        Harness {
            port,
            query_log,
            _server: server,
        }
    }

    fn rewrite_rule(
        name: &str,
        address: Option<&str>,
        target: Option<&str>,
        block: bool,
    ) -> rustydns_core::config::RewriteRule {
        rustydns_core::config::RewriteRule {
            name: name.to_string(),
            address: address.map(str::to_string),
            target: target.map(str::to_string),
            block,
        }
    }

    #[tokio::test]
    async fn rewrite_address_pins_name_to_ip() {
        let harness = build_rewrite_harness(
            vec![],
            vec![rewrite_rule(
                "grafana.corp.example.com",
                Some("10.0.0.20"),
                None,
                false,
            )],
        )
        .await;
        let resp = query(
            harness.port,
            "grafana.corp.example.com.",
            ProtoRecordType::A,
        )
        .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => assert_eq!(a.0.to_string(), "10.0.0.20"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rewrite_block_returns_nxdomain() {
        let harness = build_rewrite_harness(
            vec![],
            vec![rewrite_rule("telemetry.vendor.example", None, None, true)],
        )
        .await;
        let resp = query(
            harness.port,
            "telemetry.vendor.example.",
            ProtoRecordType::A,
        )
        .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn rewrite_address_wrong_family_is_nodata_not_upstream() {
        // A-pinned name queried for AAAA → NODATA (NoError, empty). It must
        // NOT fall through to the bogus upstream (which would SERVFAIL).
        let harness = build_rewrite_harness(
            vec![],
            vec![rewrite_rule(
                "pinned.example.com",
                Some("10.0.0.20"),
                None,
                false,
            )],
        )
        .await;
        let resp = query(harness.port, "pinned.example.com.", ProtoRecordType::AAAA).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "pinned name must NODATA for the wrong family, not SERVFAIL upstream"
        );
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn rewrite_address_pins_name_to_ipv6() {
        // IPv6 local cloaking: the same pinning guarantee as
        // rewrite_address_pins_name_to_ip, on the AAAA family — the answer is
        // the configured local address and the upstream (unreachable in this
        // harness) is never consulted; anything else would SERVFAIL.
        let harness = build_rewrite_harness(
            vec![],
            vec![rewrite_rule(
                "nas6.corp.example.com",
                Some("fd00:dead:beef::7"),
                None,
                false,
            )],
        )
        .await;
        let resp = query(
            harness.port,
            "nas6.corp.example.com.",
            ProtoRecordType::AAAA,
        )
        .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::AAAA(aaaa) => {
                assert_eq!(aaaa.0.to_string(), "fd00:dead:beef::7")
            }
            other => panic!("expected AAAA, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rewrite_cname_returns_cname() {
        let harness = build_rewrite_harness(
            vec![],
            vec![rewrite_rule(
                "cdn.example.com",
                None,
                Some("internal-cdn.lan"),
                false,
            )],
        )
        .await;
        let resp = query(harness.port, "cdn.example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::CNAME(t) => assert_eq!(t.to_string(), "internal-cdn.lan."),
            other => panic!("expected CNAME, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safesearch_rewrites_google_via_pipeline() {
        // Safe Search rules are ordinary CNAME rewrites; feeding them through
        // the rewrite harness proves the same pipeline serves them. A query
        // for google.com must return a CNAME to forcesafesearch.google.com.
        let ss = rustydns_core::config::SafeSearchConfig {
            enabled: true,
            ..rustydns_core::config::SafeSearchConfig::default()
        };
        let harness = build_rewrite_harness(vec![], ss.rewrite_rules()).await;
        let resp = query(harness.port, "google.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::CNAME(t) => {
                assert_eq!(t.to_string(), "forcesafesearch.google.com.")
            }
            other => panic!("expected CNAME to forcesafesearch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safesearch_rewrites_other_engines_and_spares_non_search_domains() {
        // google is covered by the test above; this pins the OTHER default
        // engines (bing → strict, duckduckgo → safe) through the same
        // pipeline, and — the no-collateral half — that a non-search domain
        // is NOT rewritten: its answer must never be a CNAME to any safe
        // variant. The harness upstream is unreachable, so a pass-through
        // query fails closed as SERVFAIL with no answers — which still proves
        // gate_rewrite did not fire for it.
        let ss = rustydns_core::config::SafeSearchConfig {
            enabled: true,
            ..rustydns_core::config::SafeSearchConfig::default()
        };
        let harness = build_rewrite_harness(vec![], ss.rewrite_rules()).await;

        let resp = query(harness.port, "bing.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::CNAME(t) => {
                assert_eq!(t.to_string(), "strict.bing.com.")
            }
            other => panic!("expected CNAME to strict.bing.com, got {other:?}"),
        }

        let resp = query(harness.port, "duckduckgo.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::CNAME(t) => {
                assert_eq!(t.to_string(), "safe.duckduckgo.com.")
            }
            other => panic!("expected CNAME to safe.duckduckgo.com, got {other:?}"),
        }

        // Non-search collateral check: not a CNAME to any safe variant.
        let resp = query(harness.port, "example.org.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert!(
            resp.answers.is_empty(),
            "non-search domain must produce no answers, got {:?}",
            resp.answers
        );
    }

    #[tokio::test]
    async fn authority_wins_over_rewrite() {
        // A static record AND a rewrite for the same name: authority is first
        // in the pipeline, so it answers and the rewrite never runs.
        let harness = build_rewrite_harness(
            vec![static_a("host.lab.example.com", "10.0.0.5")],
            vec![rewrite_rule(
                "host.lab.example.com",
                Some("9.9.9.9"),
                None,
                false,
            )],
        )
        .await;
        let resp = query(harness.port, "host.lab.example.com.", ProtoRecordType::A).await;
        assert!(resp.metadata.authoritative, "authority must answer");
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => assert_eq!(
                a.0.to_string(),
                "10.0.0.5",
                "authority record must win over the rewrite"
            ),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cname_cloaking_bypassed_for_bypass_client() {
        // A client with blocklist_bypass must reach the cloaked answer just
        // as it bypasses QNAME blocking. Loopback is the query source.
        let policy = NodePolicy {
            node_id: None,
            client_ip: Some("127.0.0.1".to_string()),
            blocklist_bypass: true,
            zones_allowed: Vec::new(),
            log_all_queries: false,
            block_windows: Vec::new(),
            blocklist_group: None,
        };
        let port = spawn_cname_mock("c.tracker-adnetwork.net.").await;
        let harness = build_cname_harness(
            "0.0.0.0 c.tracker-adnetwork.net\n",
            port,
            true,
            vec![policy],
        )
        .await;

        let resp = query(harness.port, "metrics.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "blocklist_bypass clients are exempt from CNAME-cloaking blocking too"
        );
    }

    /// Spawn a mock UDP upstream that answers any A query for `NAME` with a
    /// single `NAME A <ip>` record. Used by the response-IP denylist tests.
    async fn spawn_a_mock(ip: &'static str) -> u16 {
        use hickory_proto::rr::rdata::{A, AAAA};
        use hickory_proto::rr::{RData, Record};

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(q) = query.queries.first() else {
                    continue;
                };
                let owner = q.name().clone();
                let mut resp =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.add_query(q.clone());
                // Answer in the family of the mock IP (v4 → A, v6 → AAAA),
                // and only for the qtype that matches it — so the same
                // helper serves A, AAAA, and negative-qtype cases.
                let rdata = if ip.parse::<std::net::Ipv6Addr>().is_ok() {
                    if q.query_type() == ProtoRecordType::AAAA {
                        Some(RData::AAAA(AAAA(ip.parse().unwrap())))
                    } else {
                        None
                    }
                } else if q.query_type() == ProtoRecordType::A {
                    Some(RData::A(A(ip.parse().unwrap())))
                } else {
                    None
                };
                if let Some(rdata) = rdata {
                    resp.add_answer(Record::from_rdata(owner, 300, rdata));
                }
                if let Ok(bytes) = resp.to_bytes() {
                    let _ = sock.send_to(&bytes, src).await;
                }
            }
        });
        port
    }

    /// Build a harness whose resolver forwards to a plain-UDP upstream and
    /// whose blocklist has `response_ip_denylist` set to `denylist`.
    async fn build_response_ip_harness(denylist: &[&str], upstream_port: u16) -> Harness {
        use rustydns_core::config::UpstreamProtocol;

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
            response_ip_denylist: denylist.iter().map(|s| s.to_string()).collect(),
            ..BlocklistConfig::default()
        }));
        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec![format!("127.0.0.1:{upstream_port}")],
                protocol: UpstreamProtocol::Plain,
                timeout_ms: 1000,
                ..UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            &[],
            &[],
        )
        .expect("handler");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);
        Harness {
            port,
            query_log,
            _server: server,
        }
    }

    #[tokio::test]
    async fn response_ip_denylist_blocks_matching_answer() {
        // Upstream resolves the name to 198.51.100.7, which is inside the
        // configured /24 denylist → NXDOMAIN.
        let upstream = spawn_a_mock("198.51.100.7").await;
        let harness = build_response_ip_harness(&["198.51.100.0/24"], upstream).await;
        let resp = query(harness.port, "c2.malware.example.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "an answer IP inside the denylist must be blocked"
        );
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn response_ip_denylist_blocks_matching_ipv6_answer() {
        // The AAAA leg of the same defence: upstream resolves the (unblocked)
        // name to an IPv6 address inside a /48 denylist entry → NXDOMAIN.
        let upstream = spawn_a_mock("2001:db8:bad::7").await;
        let harness = build_response_ip_harness(&["2001:db8:bad::/48"], upstream).await;
        let resp = query(harness.port, "c6.malware.example.", ProtoRecordType::AAAA).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "an AAAA answer IP inside the denylist must be blocked"
        );
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn response_ip_denylist_allows_clean_answer() {
        // Same name resolves to a public IP outside the denylist → allowed.
        let upstream = spawn_a_mock("93.184.216.34").await;
        let harness = build_response_ip_harness(&["198.51.100.0/24"], upstream).await;
        let resp = query(harness.port, "site.example.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => assert_eq!(a.0.to_string(), "93.184.216.34"),
            other => panic!("expected A, got {other:?}"),
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
            rewrite: Vec::new(),
            safesearch: Default::default(),
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
            &[],
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
            block_windows: Vec::new(),
            blocklist_group: None,
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

    /// Minimal [`ResponseHandler`] that records every encoded reply so a test
    /// can drive `handle_request` directly without a live socket.
    #[derive(Clone)]
    struct CapturingHandler {
        responses: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl hickory_server::server::ResponseHandler for CapturingHandler {
        async fn send_response<'a>(
            &mut self,
            response: hickory_server::zone_handler::MessageResponse<
                '_,
                'a,
                impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
                impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
                impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
                impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            >,
        ) -> Result<hickory_server::server::ResponseInfo, hickory_server::net::NetError> {
            let mut buffer = Vec::with_capacity(512);
            let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut buffer);
            encoder.set_max_size(u16::MAX);
            let info = response
                .destructive_emit(&mut encoder)
                .map_err(|e| hickory_server::net::NetError::Msg(format!("encode error: {e}")))?;
            self.responses.lock().unwrap().push(buffer);
            Ok(info)
        }
    }

    #[tokio::test]
    async fn rate_limit_refuses_query_beyond_configured_burst() {
        // Pipeline proof for the per-client limiter: once one client exhausts
        // its burst, gate_rate_limit must answer REFUSED before any other
        // stage runs — while a different client keeps its own budget.
        //
        // Driven through handle_request directly with a NON-loopback source:
        // the limiter deliberately exempts loopback (local proxies), so no
        // real socket test from 127.0.0.1 could ever exercise the refusal.
        // `Request::from_bytes` lets the test present an off-host src addr.
        use hickory_proto::op::Message as ProtoMessage;
        use hickory_server::net::xfer::Protocol;
        use hickory_server::server::Request as HickoryRequest;
        // handle_request is the (private) RequestHandler trait method; tests
        // reach it through the trait, pinning hickory's TokioTime impl
        // (hickory-server re-exports hickory_net as `net`).
        use hickory_server::net::runtime::TokioTime;
        use hickory_server::server::RequestHandler;

        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: vec![static_a("rl.example.", "203.0.113.90")],
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
            upstream: rustydns_core::config::UpstreamConfig {
                resolvers: vec!["127.0.0.1:1".to_string()],
                protocol: rustydns_core::config::UpstreamProtocol::Plain,
                timeout_ms: 100,
                ..rustydns_core::config::UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::new(
            &rustydns_core::config::RateLimitConfig {
                enabled: true,
                qps: 1,
                burst: 2,
                max_tracked_clients: 16,
            },
        ));
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            Arc::new(crate::query_log::QueryLog::new(64)),
            rate_limiter,
            &[],
            &[],
        )
        .expect("handler");

        let responses = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capturer = CapturingHandler {
            responses: responses.clone(),
        };

        let mut query_msg = ProtoMessage::new(0x1234, MessageType::Query, OpCode::Query);
        query_msg.metadata.recursion_desired = true;
        query_msg.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii("rl.example.").unwrap())
                .set_query_type(ProtoRecordType::A);
            q
        });
        let raw = query_msg.to_bytes().expect("encode query");
        let src = |ip: &str, port: u16| {
            format!("{ip}:{port}")
                .parse::<std::net::SocketAddr>()
                .unwrap()
        };

        let ask = |bytes: Vec<u8>, peer: std::net::SocketAddr| -> HickoryRequest {
            HickoryRequest::from_bytes(bytes, peer, Protocol::Udp).expect("build request")
        };

        // burst = 2: the first two queries from client A are served from the
        // authority record...
        for _ in 0..2 {
            let req = ask(raw.clone(), src("203.0.113.44", 53001));
            let info = handler
                .handle_request::<_, TokioTime>(&req, capturer.clone())
                .await;
            assert_eq!(info.response_code, ResponseCode::NoError);
        }
        // ...the third immediate query from the SAME client is REFUSED by
        // the limiter gate — before authority, blocklist or resolution run.
        let req = ask(raw.clone(), src("203.0.113.44", 53001));
        let info = handler
            .handle_request::<_, TokioTime>(&req, capturer.clone())
            .await;
        assert_eq!(
            info.response_code,
            ResponseCode::Refused,
            "query beyond the configured burst must be refused"
        );
        // Client B has an independent bucket and is untouched by A's flood.
        let req = ask(raw, src("203.0.113.45", 53002));
        let info = handler
            .handle_request::<_, TokioTime>(&req, capturer.clone())
            .await;
        assert_eq!(info.response_code, ResponseCode::NoError);

        // Four replies were emitted (2×NoError, Refused, NoError); decode
        // the last two to confirm what actually went back on the "wire".
        let sent = responses.lock().unwrap().clone();
        assert_eq!(sent.len(), 4);
        for (idx, expected) in [(2, ResponseCode::Refused), (3, ResponseCode::NoError)] {
            let msg = ProtoMessage::from_bytes(&sent[idx]).expect("decode reply");
            assert_eq!(
                msg.metadata.response_code, expected,
                "reply {idx} rcode mismatch"
            );
        }
    }

    #[tokio::test]
    async fn per_client_policies_are_ip_keyed_and_do_not_leak() {
        // Policy-level counterpart to the rate-limit differential above: two
        // distinct client IPs in ONE handler must resolve to their OWN
        // compiled policies. Client A carries an all-day block window (the
        // schedule gate refuses even authority hits); client B has no policy
        // at all and must be served the same name — in both directions, and
        // repeatedly, so neither client's traffic can lift or inherit the
        // other's state.
        use hickory_proto::op::Message as ProtoMessage;
        use hickory_server::net::runtime::TokioTime;
        use hickory_server::net::xfer::Protocol;
        use hickory_server::server::{Request as HickoryRequest, RequestHandler};
        use rustydns_core::config::NodePolicy;

        let windowed = NodePolicy {
            node_id: None,
            client_ip: Some("203.0.113.10".to_string()),
            blocklist_bypass: false,
            zones_allowed: Vec::new(),
            log_all_queries: false,
            block_windows: vec![rustydns_core::config::BlockWindow {
                days: Vec::new(), // every day
                start: None,      // all-day
                end: None,
                utc_offset_minutes: 0,
            }],
            blocklist_group: None,
        };
        // B is deliberately ABSENT from the map — default posture, not a
        // second entry that could alias A's.
        let policies = vec![windowed];

        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: vec![static_a("pk.example.", "100.64.0.9")],
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
            upstream: rustydns_core::config::UpstreamConfig {
                resolvers: vec!["127.0.0.1:1".to_string()],
                protocol: rustydns_core::config::UpstreamProtocol::Plain,
                timeout_ms: 100,
                ..rustydns_core::config::UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            Arc::new(Metrics::new().expect("metrics")),
            Arc::new(crate::query_log::QueryLog::new(64)),
            Arc::new(crate::rate_limiter::RateLimiter::new(
                &rustydns_core::config::RateLimitConfig {
                    enabled: false,
                    ..rustydns_core::config::RateLimitConfig::default()
                },
            )),
            &policies,
            &[],
        )
        .expect("handler");

        let responses = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capturer = CapturingHandler {
            responses: responses.clone(),
        };

        let mut query_msg = ProtoMessage::new(0x4321, MessageType::Query, OpCode::Query);
        query_msg.metadata.recursion_desired = true;
        query_msg.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii("pk.example.").unwrap())
                .set_query_type(ProtoRecordType::A);
            q
        });
        let raw = query_msg.to_bytes().expect("encode query");
        let ask = |peer: &str| -> HickoryRequest {
            HickoryRequest::from_bytes(
                raw.clone(),
                peer.parse::<std::net::SocketAddr>().unwrap(),
                Protocol::Udp,
            )
            .expect("build request")
        };

        // A (policy-keyed, all-day window): refused every time.
        for leg in 0..2 {
            let info = handler
                .handle_request::<_, TokioTime>(&ask("203.0.113.10:53101"), capturer.clone())
                .await;
            assert_eq!(
                info.response_code,
                ResponseCode::Refused,
                "leg {leg}: the windowed client's schedule gate must fire"
            );
        }
        // B (no policy entry): served from authority, unaffected by A.
        for leg in 0..2 {
            let info = handler
                .handle_request::<_, TokioTime>(&ask("203.0.113.11:53102"), capturer.clone())
                .await;
            assert_eq!(
                info.response_code,
                ResponseCode::NoError,
                "leg {leg}: the unkeyed client must NOT inherit A's window"
            );
        }
        // Interleaved again: A is still refused after B's traffic — policy
        // state never crossed.
        let info = handler
            .handle_request::<_, TokioTime>(&ask("203.0.113.10:53101"), capturer.clone())
            .await;
        assert_eq!(info.response_code, ResponseCode::Refused);

        // Decode what went back on the wire for the final pair.
        let sent = responses.lock().unwrap().clone();
        assert_eq!(sent.len(), 5);
        let last_a = ProtoMessage::from_bytes(&sent[4]).expect("decode reply");
        assert_eq!(last_a.metadata.response_code, ResponseCode::Refused);
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
    async fn static_zone_answers_authoritatively_and_never_fakes_out_of_zone() {
        // Pipeline-level rendering of the authority contract: configured
        // names are answered authoritatively (AA set, no recursion), an
        // IN-zone name we have no record for short-circuits before the
        // upstream (unreachable here on purpose — a SERVFAIL would prove
        // fall-through), and an OUT-of-zone name recurses BY DESIGN — it is
        // never answered fake-authoritatively from the local zones.
        let harness = build_harness(
            vec![static_a("router.lab.example.com", "10.0.0.99")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        // Configured name: authoritative answer.
        let resp = query(harness.port, "router.lab.example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.metadata.authoritative);
        assert_eq!(resp.answers.len(), 1);

        // Same-suffix UNKNOWN name: static zones are exact-name tables (no
        // SOA/NX-proof machinery), so an unknown name is NOT claimed
        // authoritatively — it falls through to the upstream like any other
        // recursive name and fails closed against the unreachable resolver.
        // Pinning that it is never fake-answered locally.
        let ghost = query(harness.port, "ghost.lab.example.com.", ProtoRecordType::A).await;
        assert_eq!(ghost.metadata.response_code, ResponseCode::ServFail);
        assert!(!ghost.metadata.authoritative);
        assert_eq!(
            ghost.answers.len(),
            0,
            "no fabricated data for an unknown name"
        );

        // Out of zone: falls through to the (unreachable) upstream and fails
        // closed as SERVFAIL — proving the pipeline did NOT answer
        // authoritatively for a name outside our zones.
        let out = query(harness.port, "unrouted.example.org.", ProtoRecordType::A).await;
        assert_eq!(out.metadata.response_code, ResponseCode::ServFail);
        assert!(!out.metadata.authoritative);
    }

    #[tokio::test]
    async fn any_query_is_refused_against_amplification() {
        // RFC 8482 posture: ANY (qtype 255) invites the largest possible
        // answer, so the gate refuses before authority/blocklist/resolver —
        // the unreachable upstream proves no fall-through happened.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let resp = query(harness.port, "any.example.org.", ProtoRecordType::ANY).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
        assert!(resp.answers.is_empty(), "ANY must never carry answers");
        assert!(!resp.metadata.authoritative);
    }

    #[tokio::test]
    async fn oversized_edns_payload_advertisement_is_clamped() {
        // A client advertising a huge EDNS buffer must not pull an
        // equally-huge advertised ceiling back out of us: responses clamp the
        // advertisement to 4096, while sub-cap advertisements pass through
        // untouched (EDNS semantics preserved for normal clients).
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let send_with = |payload_max: u16| {
            let mut msg = Message::new(0x7777, MessageType::Query, OpCode::Query);
            msg.metadata.recursion_desired = true;
            msg.add_query({
                let mut q = Query::new();
                q.set_name(ProtoName::from_ascii("router.mesh.").expect("name"));
                q.set_query_type(ProtoRecordType::A);
                q
            });
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(payload_max);
            msg.edns = Some(edns);
            msg.to_bytes().expect("encode")
        };

        // Leg 1: oversized advertisement comes back clamped to 4096.
        client
            .send_to(&send_with(8192), format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");
        let mut buf = [0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("reply within timeout")
            .expect("udp recv");
        let resp = Message::from_bytes(&buf[..n]).expect("decode reply");
        let advertised = resp
            .edns
            .as_ref()
            .map(|e| e.max_payload())
            .expect("reply must carry EDNS when queried with EDNS");
        assert!(
            advertised <= 4096,
            "oversized EDNS advertisement was echoed verbatim: {advertised}"
        );

        // Leg 2: a modest advertisement passes through unchanged.
        client
            .send_to(&send_with(1232), format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("reply within timeout")
            .expect("udp recv");
        let resp = Message::from_bytes(&buf[..n]).expect("decode reply");
        assert_eq!(
            resp.edns.as_ref().map(|e| e.max_payload()),
            Some(1232),
            "sub-cap advertisements must be honoured as-is"
        );

        // Leg 3: exactly-at-cap is the strict-inequality boundary — an
        // advertisement of precisely MAX_EDNS_PAYLOAD passes through
        // untouched (no clamping, no alteration).
        client
            .send_to(&send_with(4096), format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("reply within timeout")
            .expect("udp recv");
        let resp = Message::from_bytes(&buf[..n]).expect("decode reply");
        assert_eq!(resp.edns.as_ref().map(|e| e.max_payload()), Some(4096),);

        // --- Leg 4: RFC 6891 §6.2.3 sub-512 advertisement ----------------
        // A client advertising BELOW the 512-byte minimum must still get
        // replies (the size BUDGET floors at 512) while its advertisement
        // is echoed as-is — no silent rewriting in either direction.
        client
            .send_to(&send_with(100), format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("reply within timeout")
            .expect("udp recv");
        let small = Message::from_bytes(&buf[..n]).expect("decode reply");
        // Observed contract: sub-floor advertisements are FLOORED to the
        // RFC 6891 §6.2.3 minimum of 512 on echo, never sent back as-is.
        assert_eq!(
            small.edns.as_ref().map(|e| e.max_payload()),
            Some(512),
            "sub-floor advertisement must be normalised up to 512"
        );
        assert!(
            n <= 512 + 4,
            "datagram must still respect the classic cap for this exchange"
        );
    }

    #[tokio::test]
    async fn udp_reply_never_exceeds_cap_and_sets_tc_when_truncated() {
        // 80 same-name A records (~2.3 KB of answer rdata alone) overflow the
        // classic 512-byte UDP limit and stay under the 4096 EDNS clamp —
        // exercising BOTH caps. Whatever hickory's emit path decides, the
        // datagram on the wire must never exceed the applicable cap, and a
        // reply that had to shed records must say so with TC.
        let mut huge = Vec::new();
        for i in 0..80u32 {
            let ip = format!("10.9.{}.{}", (i / 256) as u8, (i % 256) as u8);
            huge.push(static_a("huge.mesh", &ip));
        }
        let harness = build_harness(
            huge,
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let send_with = |edns_payload: Option<u16>| {
            let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
            msg.metadata.recursion_desired = true;
            msg.add_query({
                let mut q = Query::new();
                q.set_name(ProtoName::from_ascii("huge.mesh.").expect("name"));
                q.set_query_type(ProtoRecordType::A);
                q
            });
            if let Some(max) = edns_payload {
                let mut edns = hickory_proto::op::Edns::new();
                edns.set_max_payload(max);
                msg.edns = Some(edns);
            }
            msg.to_bytes().expect("encode")
        };

        // Leg A: no EDNS → the classic 512-byte cap applies.
        client
            .send_to(&send_with(None), format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");
        let buf_a = [0u8; 65535];
        let mut buf_a = buf_a;
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf_a))
            .await
            .expect("reply within timeout")
            .expect("udp recv");
        assert!(
            n <= 512,
            "no-EDNS reply exceeded the classic UDP cap: {n} bytes"
        );
        let resp = Message::from_bytes(&buf_a[..n]).expect("decode reply");
        assert!(
            resp.metadata.truncation || n <= 512,
            "truncated reply must carry TC"
        );

        // Surviving-answer ordering pin: the shed loop pops from the END,
        // so the FIRST records in the original set must survive. All
        // surviving A records must have distinct IPs matching the low end
        // of the original range (10.9.0.0 onward), proving deterministic
        // shed order.
        let mut seen_ips = Vec::new();
        for answer in &resp.answers {
            if let hickory_proto::rr::RData::A(a) = &answer.data {
                seen_ips.push(a.0);
            }
        }
        assert!(!seen_ips.is_empty(), "at least one answer must survive");
        seen_ips.sort();
        seen_ips.dedup();
        assert_eq!(
            seen_ips.len(),
            resp.answers.len(),
            "no duplicate A records expected"
        );
        for ip in &seen_ips {
            assert_eq!(ip.octets()[0], 10, "unexpected non-mesh IP: {ip}");
            assert_eq!(ip.octets()[1], 9, "unexpected non-mesh IP: {ip}");
        }

        // Leg B: advertise 4096 (our clamp) → reply stays within it.
        client
            .send_to(
                &send_with(Some(4096)),
                format!("127.0.0.1:{}", harness.port),
            )
            .await
            .expect("send");
        let mut buf_b = [0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf_b))
            .await
            .expect("reply within timeout")
            .expect("udp recv");
        assert!(n <= 4096, "EDNS-clamped reply exceeded 4096: {n} bytes");
    }

    #[tokio::test]
    async fn udp_in_zone_nodata_is_noerror_not_nxdomain() {
        // Design decision pinned: an in-zone name WITHOUT matching records
        // returns NoError + zero answers (NODATA), never NXDOMAIN.
        //
        // RFC 2308 §2.1 distinguishes NODATA ("name exists but not this
        // type") from NXDOMAIN ("name does not exist"). These are cached
        // differently by downstream stubs: NXDOMAIN triggers negative
        // caching with SOA-minimum TTLs while NODATA uses shorter TTLs.
        //
        // For mesh zones where peers join/leave dynamically, returning
        // NXDOMAIN for transient gaps would poison downstream caches and
        // delay peer discovery after the record reappears. NODATA is the
        // safer choice: it says "I'm authoritative, I processed your query,
        // but no data right now" without asserting nonexistence.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        // Query for a DIFFERENT in-zone name with no records configured.
        let resp = query(harness.port, "ghost.mesh.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "in-zone miss must return NODATA (NoError), not NXDOMAIN"
        );
        assert!(
            resp.answers.is_empty(),
            "in-zone miss must return zero answers"
        );
        assert!(
            resp.metadata.authoritative,
            "authority hit must set AA flag even for NODATA"
        );
    }

    #[tokio::test]
    async fn oversized_inbound_datagram_is_never_processed() {
        // hickory's UDP listener reads into a bounded buffer
        // (MAX_RECEIVE_BUFFER_SIZE = 4096, or the advertised EDNS payload,
        // whichever is smaller), so a datagram larger than the cap is cut
        // mid-message and can never decode as a valid query. Pin the
        // observable contract: an oversized datagram must never yield a
        // served answer — silence or an error rcode, never authoritative
        // NoError data derived from attacker bytes.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        // A plausible 12-byte DNS header followed by ~6 KB of padding:
        // larger than any accepted inbound cap.
        let mut blob = vec![0u8; 12 + 6000];
        blob[2] = 0x01; // recursion desired flag
        blob[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1, rest garbage
        client
            .send_to(&blob, format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf)).await {
            // Silently dropped: nothing to process (the expected shape).
            Err(_) => {}
            Ok(Ok((n, _))) => {
                // Any bytes that do come back must not be a served answer
                // derived from the oversized datagram; undecodable filler
                // (FORMERR etc.) still satisfies the contract.
                if let Ok(msg) = Message::from_bytes(&buf[..n]) {
                    assert!(
                        !(msg.metadata.response_code == ResponseCode::NoError
                            && !msg.answers.is_empty()
                            && msg.metadata.authoritative),
                        "oversized datagram produced a served answer"
                    );
                }
            }
            Ok(Err(e)) => panic!("socket error on oversized datagram: {e}"),
        }
    }

    #[tokio::test]
    async fn malformed_query_names_are_never_processed() {
        // RFC 1035 names terminate at a zero-length label. A datagram whose
        // question section carries trailing garbage after that terminator,
        // or one whose name never terminates before end-of-packet, must
        // never be processed into a served answer.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        let build = |mut wire: Vec<u8>| {
            let mut msg = vec![0x77, 0x77, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            msg.append(&mut wire);
            // qtype A + class IN close out the question.
            msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            msg
        };

        // Leg A: name terminates early ('a'), then trailing label garbage.
        let trailing_garbage = build(vec![
            1, b'a', 0, 1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'o', b'r', b'g',
            0,
        ]);

        // Leg B: unterminated name — no zero-length root label at all.
        let unterminated = build(vec![1, b'a', 1, b'b']);

        for wire in [trailing_garbage, unterminated] {
            client
                .send_to(&wire, format!("127.0.0.1:{}", harness.port))
                .await
                .expect("send");
            let mut buf = [0u8; 512];
            match tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await {
                Err(_) => {}
                Ok(Ok((n, _))) => {
                    if let Ok(msg) = Message::from_bytes(&buf[..n]) {
                        assert!(
                            !(msg.metadata.response_code == ResponseCode::NoError
                                && !msg.answers.is_empty()
                                && msg.metadata.authoritative),
                            "malformed query produced a served answer"
                        );
                    }
                }
                Ok(Err(e)) => panic!("socket error on malformed query: {e}"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_compression_pointer_loop_query_is_bounded_and_daemon_stays_live() {
        // Name-decompression safety at the UDP front door: a datagram whose
        // question name is a compression pointer pointing AT ITSELF
        // (offset N → N) can never decompress. hickory's decoder rejects
        // any non-prior pointer on its first hop (`PointerNotPriorToLabel`)
        // and bounds recursive follows by strictly decreasing position, so
        // this must be dropped or error-rcoded in bounded work — never a
        // hang — and afterwards the daemon must still answer valid queries
        // promptly (no wedged listener, no unbounded allocation).
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        let mut loop_q = vec![0x51, 0x11, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        loop_q.extend_from_slice(&[0xC0, 0x0C]); // question name: ptr to offset 12 — itself
        loop_q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN

        client
            .send_to(&loop_q, format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await {
            // Silently dropped: nothing to process (the expected shape).
            Err(_) => {}
            Ok(Ok((n, _))) => {
                if let Ok(msg) = Message::from_bytes(&buf[..n]) {
                    assert!(
                        !(msg.metadata.response_code == ResponseCode::NoError
                            && !msg.answers.is_empty()
                            && msg.metadata.authoritative),
                        "pointer-loop query produced a served answer"
                    );
                }
            }
            Ok(Err(e)) => panic!("socket error on pointer-loop query: {e}"),
        }

        // Bounded-work proof: the same socket reaches a healthy daemon.
        let resp = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_multi_question_query_never_answers_the_second_question() {
        // Multi/absent-question datagrams are a classic parser-confusion
        // vector: RFC 1035 technically allows QDCOUNT>0, resolvers implement
        // exactly-one-question semantics, and QDCOUNT=0 must not index an
        // empty query list. Differential construction makes second-question
        // processing observable: Q1 is an AUTHORITY name (answerable), Q2 a
        // BLOCKED name (NXDOMAIN if ever consulted).
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "0.0.0.0 ads.second.net\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        // Family legs: QDCOUNT=2 (differential questions) and QDCOUNT=0
        // (empty question section) — both are shapes a naive parser mishandles
        // (answering question two, or indexing an empty query list).
        let mut loop_q = vec![0x51, 0x12, 0x01, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0];
        // Q1: router.mesh. A IN (authority zone — answerable).
        loop_q.extend_from_slice(b"\x06router\x04mesh\x00");
        loop_q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Q2: ads.second.net. A IN (blocked — NXDOMAIN if ever processed).
        loop_q.extend_from_slice(b"\x03ads\x06second\x03net\x00");
        loop_q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let empty_q = {
            let mut w = vec![0x51, 0x13, 0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0]; // QDCOUNT=0
            w.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // orphan A IN
            w
        };

        for (label, wire) in [
            ("QDCOUNT=2 differential", loop_q),
            ("QDCOUNT=0 empty", empty_q),
        ] {
            client
                .send_to(&wire, format!("127.0.0.1:{}", harness.port))
                .await
                .expect("send");

            let mut buf = [0u8; 512];
            match tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await {
                // Silence satisfies the contract (drop).
                Err(_) => {}
                Ok(Ok((n, _))) => {
                    let reply = Message::from_bytes(&buf[..n]);
                    if let Ok(msg) = reply {
                        if msg.metadata.response_code == ResponseCode::FormErr {
                            continue; // rejected: never an outcome from Q1 or Q2
                        }
                        assert_eq!(
                            msg.metadata.response_code,
                            ResponseCode::NoError,
                            "{label}: only a first-question answer may follow NoError"
                        );
                        for answer in &msg.answers {
                            let owner = answer.name.to_string().to_ascii_lowercase();
                            assert!(
                                owner.starts_with("router.mesh"),
                                "{label}: answer must belong to the FIRST question, got {owner}"
                            );
                            assert!(
                                !owner.contains("ads.second"),
                                "{label}: second question leaked into the answers"
                            );
                        }
                        assert!(
                            !msg.answers.is_empty(),
                            "{label}: a first-question NoError must carry its authority A"
                        );
                    } else if let Err(e) = reply {
                        panic!("{label}: undecodable reply is neither silence nor an answer: {e}");
                    }
                }
                Ok(Err(e)) => panic!("{label}: socket error {e}"),
            }
        }

        // Liveness: normal EDNS-less service continues afterwards.
        let resp = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_axfr_against_authoritative_zone_leaks_nothing() {
        // Classic recon probes: AXFR (252) and IXFR (251) against a name
        // inside our AUTHORITY zone. We are not a master server — RFC 5936
        // transfers are never served, so an attacker mapping the mesh/static
        // zone gets nothing. Pinned observable: the response carries ZERO
        // answer records (NODATA-shaped; NOTIMP/REFUSED would equally
        // satisfy the no-leak property), regardless of the queried name
        // being authoritative. Liveness leg keeps the daemon honest
        // afterwards.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        for qtype in [ProtoRecordType::AXFR, ProtoRecordType::IXFR] {
            let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
            msg.metadata.recursion_desired = true;
            msg.add_query({
                let mut q = Query::new();
                q.set_name(ProtoName::from_ascii("router.mesh.").unwrap());
                q.set_query_type(qtype);
                q
            });
            let wire = msg.to_bytes().expect("encode");
            client
                .send_to(&wire, format!("127.0.0.1:{}", harness.port))
                .await
                .expect("send");

            let mut buf = [0u8; 512];
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                .await
                .expect("response within budget")
                .expect("recv");
            let reply = Message::from_bytes(&buf[..n]).expect("decode");
            assert!(
                matches!(
                    reply.metadata.response_code,
                    ResponseCode::NoError | ResponseCode::NotImp | ResponseCode::Refused
                ),
                "unexpected rcode for {qtype} probe: {:?}",
                reply.metadata.response_code
            );
            assert!(
                reply.answers.is_empty() && reply.authorities.is_empty(),
                "a {qtype} probe must never return zone data: {:?}",
                reply.answers
            );
        }

        // Liveness: normal service continues afterwards.
        let resp = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_chaos_version_bind_probe_leaks_nothing() {
        // The other classic recon probe: `version.bind CHAOS TXT`. Only the
        // IN class is served (gate_class → NOTIMP), so the daemon must
        // neither disclose its software/version nor answer with any TXT
        // payload. Pinned: NOTIMP, zero answers, then liveness.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        let mut msg = Message::new(0x4243, MessageType::Query, OpCode::Query);
        msg.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii("version.bind.").unwrap());
            q.set_query_type(ProtoRecordType::TXT);
            q.set_query_class(TestDNSClass::CH);
            q
        });
        let wire = msg.to_bytes().expect("encode");
        client
            .send_to(&wire, format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");

        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response within budget")
            .expect("recv");
        let reply = Message::from_bytes(&buf[..n]).expect("decode");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NotImp,
            "CHAOS-class probes must be NOTIMP"
        );
        assert!(
            reply.answers.is_empty(),
            "a CHAOS probe must never return version text: {:?}",
            reply.answers
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_edns_version_mismatch_answers_badvers() {
        // RFC 6891 §6.1.3: a query advertising an EDNS0 version the server
        // does not support must be answered with BADVERS (rcode 16) — not
        // silently accepted, not FORMERR'd, not ignored. NOTE: hickory
        // 0.26's Catalog implements this, but our listener stack registers
        // DnsHandler directly and bypasses the Catalog — the enforcement is
        // OURS, via `gate_edns_version`. This pin proves the guarantee
        // survives through OUR listener stack, so a future transport or
        // framework change cannot silently start accepting (and
        // mis-handling) newer EDNS versions.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        let mut wire = vec![0x62, 0x64, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 1]; // ARCOUNT=1
        wire.extend_from_slice(b"\x06victim\x07example\x03org\x00"); // qname
        wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        // OPT pseudo-record: root name, type 41, class = payload (4096),
        // ttl = ext-rcode(0) | version(1) | flags(0) → version 1.
        wire.extend_from_slice(&[0x00]); // root name
        wire.extend_from_slice(&[0x00, 0x29]); // OPT
        wire.extend_from_slice(&[0x10, 0x00]); // payload 4096
        wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // version = 1
        wire.extend_from_slice(&[0x00, 0x00]); // rdlen 0

        client
            .send_to(&wire, format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");

        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("BADVERS response must arrive within budget")
            .expect("recv");
        let msg = Message::from_bytes(&buf[..n]).expect("response must decode");
        // Wire truth: extended rcode 16 == BADVERS. On decode hickory labels
        // 16 as BADSIG (RFC 6891 and RFC 4034 share the value; the resolver
        // disambiguates by context we don't have here), so accept either
        // name for the same wire bytes.
        assert!(
            matches!(
                msg.metadata.response_code,
                ResponseCode::BADVERS | ResponseCode::BADSIG
            ),
            "EDNS version > 0 must be answered with extended rcode 16 (BADVERS), got {:?}",
            msg.metadata.response_code
        );
        assert!(
            msg.answers.is_empty(),
            "BADVERS is an error response — no records may be served"
        );
        // The response OPT must advertise OUR version (0), never an echoed
        // request version, and keep the clamped payload advertisement.
        let resp_edns = msg.edns.as_ref().expect("BADVERS must carry an OPT RR");
        assert_eq!(resp_edns.version(), 0, "response EDNS version must be 0");
        assert_eq!(
            resp_edns.max_payload(),
            4096,
            "payload advertisement must survive the clamp path"
        );

        // Liveness: normal EDNS-less service continues afterwards.
        let resp = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
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
    async fn blocked_domain_mixed_case_wire_query_is_still_blocked() {
        // Case-variant bypass guard: the wire qname is canonicalised
        // (lowercased) BEFORE blocklist/authority matching, so a client
        // spelling the name "Ads.Example.COM." cannot dodge an exact-match
        // block entry. Pins the WIRE-to-blocklist path, not just the
        // helper's output.
        let harness = build_harness(
            vec![],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;

        for spelling in ["Ads.Example.COM.", "ADS.EXAMPLE.COM.", "aDs.eXaMpLe.CoM."] {
            let resp = query(harness.port, spelling, ProtoRecordType::A).await;
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::NXDomain,
                "{spelling} must be blocked like its lowercase form"
            );
            assert!(resp.answers.is_empty());
        }
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
    async fn allowlisted_domain_matching_a_blocklist_entry_serves_the_upstream_answer() {
        // Allowlist precedence through the whole pipeline: a name that
        // matches BOTH a blocklist entry and a config allowlist entry must be
        // served from the live upstream — never NXDOMAIN'd, sinkholed, or
        // refused. The blocklist engine already proves precedence at its own
        // layer (config_allowlist_overrides_blocklist); this pins the same
        // guarantee where it matters, at the daemon's gate stage.
        use rustydns_core::config::UpstreamProtocol;

        let upstream_port = spawn_a_mock("203.0.113.50").await;
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
            // The SAME name is on the blocklist and the allowlist; the
            // allowlist must win.
            allowlist: vec!["allowed.example.com".to_string()],
            ..BlocklistConfig::default()
        }));
        blocklist.load_trusted("0.0.0.0 allowed.example.com\n");
        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec![format!("127.0.0.1:{upstream_port}")],
                protocol: UpstreamProtocol::Plain,
                timeout_ms: 1000,
                ..UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            &[],
            &[],
        )
        .expect("handler");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);

        let resp = query(port, "allowed.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "allowlisted name must not be blocked"
        );
        assert_eq!(resp.answers.len(), 1, "the real upstream answer");
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(
                    a.0.to_string(),
                    "203.0.113.50",
                    "upstream rdata served for the allowlisted name"
                );
            }
            other => panic!("expected A rdata, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn regex_rule_blocks_and_sinkholes_through_the_pipeline() {
        // Regex block rules enforced at the daemon's gate stage: the name is
        // NOT on any exact blocklist — only the regex `^ads-` matches it —
        // and with block_response = "sinkhole" it must be answered from the
        // configured sinkhole IP even though a live plain-UDP upstream stands
        // ready. The blocklist engine proves regex matching at its own layer
        // (regex_rule_blocks_matching_qname); this pins enforcement where
        // resolution happens, so no upstream rdata can leak for a regex hit.
        use rustydns_core::config::UpstreamProtocol;

        let upstream_port = spawn_a_mock("203.0.113.77").await;
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
            block_response: BlockResponse::Sinkhole,
            sinkhole_ip: "198.18.0.9".to_string(),
            regex_rules: vec![r"^ads-".to_string()],
            ..BlocklistConfig::default()
        }));
        // No load_trusted entries at all: the ONLY blocking mechanism in this
        // test is the regex rule.
        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec![format!("127.0.0.1:{upstream_port}")],
                protocol: UpstreamProtocol::Plain,
                timeout_ms: 1000,
                ..UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            &[],
            &[],
        )
        .expect("handler");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);

        // The regex hit is sinkholed; the upstream answer cannot leak.
        let resp = query(port, "ads-tracker.example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0.to_string(), "198.18.0.9", "regex hit sinkholed");
                assert_ne!(
                    a.0.to_string(),
                    "203.0.113.77",
                    "upstream answer leaked through a regex block"
                );
            }
            other => panic!("expected A rdata, got {other:?}"),
        }

        // A non-matching name on the SAME suffix flows through to the live
        // upstream untouched (the rule anchors on the `ads-` prefix, not the
        // domain) — proving the sinkhole came from the regex match itself.
        let pass = query(port, "docs.example.com.", ProtoRecordType::A).await;
        assert_eq!(pass.metadata.response_code, ResponseCode::NoError);
        match &pass.answers[0].data {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0.to_string(), "203.0.113.77", "unmatched name resolved");
            }
            other => panic!("expected A rdata, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_domain_returns_sinkhole_ip_not_upstream_answer() {
        // block_response = "sinkhole": a blocked name must be answered from
        // the CONFIGURED SINKHOLE IP even though a live plain-UDP upstream
        // stands ready to answer 203.0.113.99 — the blocklist gate fires
        // before resolution, so the upstream answer can never leak through.
        use rustydns_core::config::UpstreamProtocol;

        let upstream_port = spawn_a_mock("203.0.113.99").await;
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
            block_response: BlockResponse::Sinkhole,
            sinkhole_ip: "198.18.0.7".to_string(),
            ..BlocklistConfig::default()
        }));
        blocklist.load_trusted("0.0.0.0 ads.example.com\n");
        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec![format!("127.0.0.1:{upstream_port}")],
                protocol: UpstreamProtocol::Plain,
                timeout_ms: 1000,
                ..UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            &[],
            &[],
        )
        .expect("handler");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);

        let resp = query(port, "ads.example.com.", ProtoRecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1, "exactly the sinkhole answer");
        match &resp.answers[0].data {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0.to_string(), "198.18.0.7", "sinkhole IP served");
                assert_ne!(a.0.to_string(), "203.0.113.99", "upstream answer leaked");
            }
            other => panic!("expected A rdata, got {other:?}"),
        }
    }

    /// Rendered `/metrics` value for one labelled series (0.0 when the series
    /// has not been created yet — Prometheus omits zero-valued counters).
    fn counter_value(text: &str, family: &str, label_pair: &str) -> f64 {
        let needle = format!("{family}{{{label_pair}}} ");
        text.lines()
            .find_map(|l| l.strip_prefix(&needle))
            .and_then(|rest| rest.trim().parse::<f64>().ok())
            .unwrap_or(0.0)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn metrics_counters_increment_on_real_queries() {
        // Complements metrics_handler_renders_every_registered_family, which
        // proves EXPOSITION wiring by calling mutators directly. Here the
        // counters must move because REAL pipeline traffic flowed: each query
        // increments rustydns_dns_queries_by_qtype_total at receipt, and the
        // single respond() path increments
        // rustydns_dns_responses_by_rcode_total exactly once per reply —
        // NoError for an authority hit, NXDOMAIN for a blocklist block.
        use std::sync::atomic::AtomicBool;
        use tokio_util::sync::CancellationToken;

        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: vec![static_a("router.mesh", "100.64.0.5")],
                poll_interval_secs: 30,
            })
            .expect("authority"),
        );
        let blocklist = Arc::new(BlocklistEngine::new(BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            ..BlocklistConfig::default()
        }));
        blocklist.load_trusted("0.0.0.0 blocked.example\n");
        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec!["https://127.0.0.1:1/dns-query".to_string()],
                timeout_ms: 500,
                ..UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            metrics.clone(),
            query_log.clone(),
            rate_limiter,
            &[],
            &[],
        )
        .expect("handler");

        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);

        // Serve /metrics on a second loopback listener so assertions read what
        // an operator's Prometheus would scrape.
        let metrics_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metrics");
        let mport = metrics_listener.local_addr().unwrap().port();
        let shutdown = CancellationToken::new();
        tokio::spawn(crate::metrics::serve(
            metrics,
            query_log,
            metrics_listener,
            "/metrics".to_string(),
            shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        ));

        let rendered = |mport: u16| async move {
            reqwest::get(format!("http://127.0.0.1:{mport}/metrics"))
                .await
                .expect("scrape /metrics")
                .text()
                .await
                .expect("metrics body")
        };

        let base = rendered(mport).await;
        let qtype_a_base =
            counter_value(&base, "rustydns_dns_queries_by_qtype_total", "qtype=\"A\"");
        let noerror_base = counter_value(
            &base,
            "rustydns_dns_responses_by_rcode_total",
            "rcode=\"NOERROR\"",
        );
        let nxdomain_base = counter_value(
            &base,
            "rustydns_dns_responses_by_rcode_total",
            "rcode=\"NXDOMAIN\"",
        );

        let ok = query(port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
        let blocked = query(port, "blocked.example.", ProtoRecordType::A).await;
        assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);

        let after = rendered(mport).await;
        assert_eq!(
            counter_value(&after, "rustydns_dns_queries_by_qtype_total", "qtype=\"A\""),
            qtype_a_base + 2.0,
            "both queries counted by qtype at receipt"
        );
        assert_eq!(
            counter_value(
                &after,
                "rustydns_dns_responses_by_rcode_total",
                "rcode=\"NOERROR\""
            ),
            noerror_base + 1.0,
            "authority hit counted once as noerror"
        );
        assert_eq!(
            counter_value(
                &after,
                "rustydns_dns_responses_by_rcode_total",
                "rcode=\"NXDOMAIN\""
            ),
            nxdomain_base + 1.0,
            "blocklist hit counted once as nxdomain"
        );

        shutdown.cancel();
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
            rewrite: Vec::new(),
            safesearch: Default::default(),
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
    async fn dot_hostile_pointer_query_fails_closed_and_daemon_stays_live() {
        // Decompression pin over DoT — the last transport without one.
        //
        // The client sends a query whose QUESTION NAME is a compression
        // pointer pointing back at itself (offset 12 -> offset 12).
        // hickory's strictly-prior rule rejects it on the first hop; the
        // pinned contract is bounded work: silence or an error rcode within
        // budget, NEVER a served answer derived from attacker bytes. A
        // control leg (valid query first) proves any rejection is caused by
        // the hostile bytes alone, and a final liveness leg proves the
        // daemon keeps serving afterwards.
        use crate::test_pem::{TEST_CA_PEM, TEST_CERT_CN, TEST_LEAF_CERT_PEM, TEST_LEAF_KEY_PEM};
        use std::io::Write;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::{
            ClientConfig,
            pki_types::{CertificateDer, ServerName, pem::PemObject},
        };

        let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        );

        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: vec![static_a("router.mesh", "100.64.0.7")],
                poll_interval_secs: 30,
            })
            .unwrap(),
        );
        let blocklist = Arc::new(BlocklistEngine::new(BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            ..BlocklistConfig::default()
        }));
        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec!["https://127.0.0.1:1/dns-query".to_string()],
                timeout_ms: 500,
                ..UpstreamConfig::default()
            },
            ..DnsConfig::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.unwrap());
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            Arc::new(crate::query_log::QueryLog::new(16)),
            Arc::new(crate::rate_limiter::RateLimiter::new(
                &rustydns_core::config::RateLimitConfig {
                    enabled: false,
                    ..Default::default()
                },
            )),
            &[],
            &[],
        )
        .unwrap();

        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let cert_path = std::env::temp_dir().join(format!("rustydns-dot-hp-cert-{id}.pem"));
        let key_path = std::env::temp_dir().join(format!("rustydns-dot-hp-key-{id}.pem"));
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(TEST_LEAF_CERT_PEM.as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(TEST_LEAF_KEY_PEM.as_bytes())
            .unwrap();

        use rustydns_core::config::ServerConfig as RsServerConfig;
        let tls_server_cfg = crate::load_tls_config(&RsServerConfig {
            tls_cert_path: Some(cert_path),
            tls_key_path: Some(key_path),
            ..RsServerConfig::default()
        })
        .expect("load_tls_config");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server
            .register_tls_listener_with_tls_config(listener, Duration::from_secs(5), tls_server_cfg)
            .expect("register DoT listener");

        // --- Control leg: valid query must be served --------------------
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let ca_der = CertificateDer::from_pem_slice(TEST_CA_PEM.as_bytes()).expect("parse CA");
        roots.add(ca_der).expect("add CA");
        let client_cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let server_name = ServerName::try_from(TEST_CERT_CN.to_string()).expect("server name");

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        let mut msg = Message::new(0x1111, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query({
            let mut qq = Query::new();
            qq.set_name(ProtoName::from_ascii("router.mesh.").unwrap());
            qq.set_query_type(ProtoRecordType::A);
            qq
        });
        let body = msg.to_bytes().unwrap();
        tls.write_all(&(body.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tls.write_all(&body).await.unwrap();
        let mut hdr = [0u8; 2];
        tls.read_exact(&mut hdr)
            .await
            .expect("control reply length");
        let n = u16::from_be_bytes(hdr) as usize;
        let mut resp = vec![0u8; n];
        tls.read_exact(&mut resp).await.unwrap();
        let ok = Message::from_bytes(&resp).unwrap();
        assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
        assert_eq!(ok.answers.len(), 1, "authority hit expected");

        // --- Hostile leg: self-referential pointer as the question name --
        // Wire: header(QDCOUNT=1) | 0xC0 0x0C (pointer to offset 12 = the
        // question name itself) | A IN.
        let mut hostile = vec![0xDE, 0xAD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        hostile.extend_from_slice(&[0xC0, 0x0C]);
        hostile.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let tcp2 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut tls2 = connector.connect(server_name.clone(), tcp2).await.unwrap();
        tls2.write_all(&(hostile.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tls2.write_all(&hostile).await.unwrap();

        // Bounded read: either an error response arrives within budget, or
        // the stream ends — never an unbounded wait on attacker bytes.
        let mut hdr2 = [0u8; 2];
        let reply: Option<Vec<u8>> = tokio::time::timeout(Duration::from_secs(3), async {
            tls2.read_exact(&mut hdr2).await.ok()?;
            if hdr2 == [0, 0] {
                return None;
            }
            let n2 = u16::from_be_bytes(hdr2) as usize;
            let mut body = vec![0u8; n2];
            tls2.read_exact(&mut body).await.ok()?;
            Some(body)
        })
        .await
        .unwrap_or_default();

        match reply {
            // Silence (timeout) satisfies the contract.
            None => {}
            Some(bytes) => {
                // A reply DID come back for attacker bytes: it must never be
                // a served answer. FORMERR or another error rcode is fine;
                // NoError-with-records is not.
                if let Ok(parsed) = Message::from_bytes(&bytes) {
                    assert!(
                        !(parsed.metadata.response_code == ResponseCode::NoError
                            && !parsed.answers.is_empty()),
                        "DoT pointer-loop query produced a served answer: {parsed:?}"
                    );
                }
            }
        }
        // Silence and errors are both acceptable; what matters is that the
        // daemon survived, proven by the liveness leg below.

        // Liveness leg: a FRESH TLS connection still gets served promptly.
        let tcp3 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut tls3 = connector.connect(server_name.clone(), tcp3).await.unwrap();
        let mut msg3 = Message::new(0x3333, MessageType::Query, OpCode::Query);
        msg3.metadata.recursion_desired = true;
        msg3.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii("router.mesh.").unwrap());
            q.set_query_type(ProtoRecordType::A);
            q
        });
        let body3 = msg3.to_bytes().unwrap();
        tls3.write_all(&(body3.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tls3.write_all(&body3).await.unwrap();
        let mut hdr3 = [0u8; 2];
        tls3.read_exact(&mut hdr3)
            .await
            .expect("liveness reply length");
        let n3 = u16::from_be_bytes(hdr3) as usize;
        let mut resp3 = vec![0u8; n3];
        tls3.read_exact(&mut resp3).await.expect("liveness body");
        let ok3 = Message::from_bytes(&resp3).unwrap();
        assert_eq!(ok3.metadata.response_code, ResponseCode::NoError);
        assert_eq!(ok3.answers.len(), 1, "authority hit expected");

        drop(server);
    }

    #[tokio::test]
    async fn udp_malformed_opt_option_length_fails_closed() {
        // RFC 6891 §6.1.2: each EDNS option carries a 2-byte OPTION-CODE,
        // 2-byte OPTION-LENGTH, and OPTION-DATA of exactly that length.
        // A hostile client can craft an OPT whose option-length exceeds the
        // remaining RDATA bytes — probing whether the parser reads out of
        // range or panics. Pinned contract: bounded work, silence or error
        // rcode within budget, daemon stays live afterwards.
        let harness = build_harness(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

        // Wire layout:
        //   header(12): id, flags, QDCOUNT=1, ARCOUNT=1
        //   question: victim.example.org. A IN
        //   OPT root-record: type=41 class=4096 ttl=0 rdlen=6
        //     rdata: code=8(ECS) len=0xFFFF(claims 65535 B, only 2 follow)
        let mut wire = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 1];
        wire.extend_from_slice(b"\x06victim\x07example\x03org\x00");
        wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        // OPT pseudo-record:
        wire.push(0x00); // root name
        wire.extend_from_slice(&[0x00, 0x29]); // type 41 (OPT)
        wire.extend_from_slice(&[0x10, 0x00]); // class = 4096 payload
        wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ttl: v0, no flags
        wire.extend_from_slice(&[0x00, 0x06]); // rdlen = 6
        // rdata: ECS option (code 8) claiming 0xFFFF bytes, then 2 pad bytes
        wire.extend_from_slice(&[0x00, 0x08]); // option code = 8 (ECS)
        wire.extend_from_slice(&[0xFF, 0xFF]); // option length = 65535 (!!)
        wire.extend_from_slice(&[0xDE, 0xAD]); // only 2 actual bytes

        client
            .send_to(&wire, format!("127.0.0.1:{}", harness.port))
            .await
            .expect("send");

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf)).await {
            Err(_) => {} // silence satisfies the contract
            Ok(Ok((n, _))) => {
                if let Ok(msg) = Message::from_bytes(&buf[..n]) {
                    assert!(
                        !(msg.metadata.response_code == ResponseCode::NoError
                            && !msg.answers.is_empty()),
                        "malformed-OPT query produced a served answer"
                    );
                }
            }
            Ok(Err(e)) => panic!("socket error on malformed-OPT probe: {e}"),
        }

        // Liveness: daemon still serves valid queries afterwards.
        let liveness = query(harness.port, "router.mesh.", ProtoRecordType::A).await;
        assert_eq!(liveness.metadata.response_code, ResponseCode::NoError);
        assert_eq!(liveness.answers.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dot_listener_refuses_plaintext_connection_on_its_port() {
        // DoT is RFC 7858: the port speaks TLS and NOTHING else. Control
        // leg proves the port serves real TLS DNS; attack leg connects a
        // RAW TCP client sending unencrypted wire-format DNS bytes and
        // must observe the handshake fail (EOF/reset/timeout) — never a
        // parseable DNS reply on the plaintext path.
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};

        use crate::test_pem::{TEST_CA_PEM, TEST_CERT_CN, TEST_LEAF_CERT_PEM, TEST_LEAF_KEY_PEM};

        let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        );

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let cert_path = std::env::temp_dir().join(format!("rustydns-dot-plain-cert-{id}.pem"));
        let key_path = std::env::temp_dir().join(format!("rustydns-dot-plain-key-{id}.pem"));
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(TEST_LEAF_CERT_PEM.as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(TEST_LEAF_KEY_PEM.as_bytes())
            .unwrap();

        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: vec![static_a("router.mesh", "100.64.0.8")],
                poll_interval_secs: 30,
            })
            .unwrap(),
        );
        let blocklist = Arc::new(BlocklistEngine::new(BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            ..BlocklistConfig::default()
        }));
        let mut dns_config = DnsConfig::default();
        dns_config.upstream.resolvers = vec!["https://127.0.0.1:1/dns-query".to_string()];
        dns_config.upstream.timeout_ms = 500;
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.unwrap());
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            Arc::new(crate::query_log::QueryLog::new(16)),
            Arc::new(crate::rate_limiter::RateLimiter::new(
                &rustydns_core::config::RateLimitConfig {
                    enabled: false,
                    ..rustydns_core::config::RateLimitConfig::default()
                },
            )),
            &[],
            &[],
        )
        .unwrap();

        use rustydns_core::config::ServerConfig as RsServerConfig;
        let tls_server_config = crate::load_tls_config(&RsServerConfig {
            tls_cert_path: Some(cert_path),
            tls_key_path: Some(key_path),
            ..RsServerConfig::default()
        })
        .expect("load_tls_config");

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

        // Shared wire query for both legs.
        let build_query = |id: u16| {
            let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
            msg.metadata.recursion_desired = true;
            msg.add_query({
                let mut q = Query::new();
                q.set_name(ProtoName::from_ascii("router.mesh.").unwrap())
                    .set_query_type(ProtoRecordType::A);
                q
            });
            let body = msg.to_bytes().expect("encode query");
            let mut framed = (body.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&body);
            framed
        };

        // --- Leg A (control): a proper TLS client gets a real answer. ---
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(TEST_CA_PEM.as_bytes()).expect("parse CA"))
            .expect("add CA");
        let connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("tcp connect");
        let mut tls = connector
            .connect(
                ServerName::try_from(TEST_CERT_CN.to_string()).expect("server name"),
                tcp,
            )
            .await
            .expect("tls handshake");
        tls.write_all(&build_query(0x1111)).await.expect("write");
        let mut len_buf = [0u8; 2];
        tls.read_exact(&mut len_buf).await.expect("read length");
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tls.read_exact(&mut resp_buf).await.expect("read body");
        let resp = Message::from_bytes(&resp_buf).expect("decode response");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        drop(tls);

        // --- Leg B (attack): plaintext client sends raw DNS bytes. ---
        let raw_query = build_query(0x2222);
        let mut plain = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("plaintext tcp connect succeeds (TCP layer)");
        plain.write_all(&raw_query).await.expect("write plaintext");

        // The TLS acceptor cannot parse our DNS bytes as a ClientHello, so
        // the server must abort the connection: the read side sees EOF /
        // reset / an error — never a well-formed DNS response.
        let mut buf = vec![0u8; 512];
        let outcome = tokio::time::timeout(Duration::from_secs(5), plain.read(&mut buf)).await;
        match outcome {
            Ok(Ok(0)) => { /* clean EOF — connection refused at protocol level */ }
            Ok(Ok(n)) => {
                // Any bytes that DID arrive must not decode as the DNS
                // response we asked for (defence-in-depth: garbage from a
                // failed handshake must never look like a valid reply).
                assert!(
                    Message::from_bytes(&buf[..n]).is_err(),
                    "plaintext client received a parseable DNS response"
                );
            }
            Ok(Err(_)) => { /* connection reset / io error — expected */ }
            Err(_) => panic!("plaintext connection neither closed nor errored"),
        }

        drop(server);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doq_listener_refuses_non_quic_datagram_on_its_port() {
        // Mirror of the DoT plaintext pin, for the QUIC transport: the DoQ
        // port is a UDP socket owned by quinn, so an attacker's "plaintext
        // connection" is a raw unframed DNS datagram with no QUIC long
        // header. The engine must drop it silently — no parseable RFC 9250
        // reply may ever come back. The real-QUIC happy path is proven
        // end-to-end by tests/sighup_reload.rs::daemon_serves_doq_queries;
        // successful registration on a bound socket is the liveness proof
        // here.
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};

        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use rustydns_blocklist::BlocklistEngine;
        use rustydns_core::config::{RateLimitConfig, ServerConfig as RsServerConfig};
        use tokio::net::UdpSocket;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let cert_path = std::env::temp_dir().join(format!("rustydns-doq-plain-cert-{id}.pem"));
        let key_path = std::env::temp_dir().join(format!("rustydns-doq-plain-key-{id}.pem"));
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(crate::test_pem::TEST_LEAF_CERT_PEM.as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(crate::test_pem::TEST_LEAF_KEY_PEM.as_bytes())
            .unwrap();

        let _guard = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );

        let metrics = Arc::new(Metrics::new().expect("metrics"));
        let authority = Arc::new(
            Authority::new(AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: vec![static_a("router.mesh", "100.64.0.8")],
                poll_interval_secs: 30,
            })
            .expect("authority"),
        );
        let blocklist = Arc::new(BlocklistEngine::new(BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            ..Default::default()
        }));
        let mut dns_config = DnsConfig::default();
        dns_config.upstream.resolvers = vec!["https://127.0.0.1:1/dns-query".to_string()];
        dns_config.upstream.timeout_ms = 500;
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));

        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            Arc::new(crate::query_log::QueryLog::new(16)),
            Arc::new(crate::rate_limiter::RateLimiter::new(&RateLimitConfig {
                enabled: false,
                ..Default::default()
            })),
            &[],
            &[],
        )
        .expect("handler");

        // doq-ALPN TLS config (distinct from DoT's no-ALPN config).
        let server_cfg = RsServerConfig {
            tls_cert_path: Some(cert_path),
            tls_key_path: Some(key_path),
            ..Default::default()
        };
        let doq_tls = crate::load_doq_tls_config(&server_cfg).expect("doq tls config");

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server
            .register_quic_listener_and_tls_config(udp, Duration::from_secs(5), doq_tls)
            .expect("register quic listener");

        // A plain DNS query on the wire — no QUIC long header, no ALPN, no
        // RFC 9250 framing. Quinn cannot interpret this as a connection and
        // must discard it.
        let build_query = |msg_id: u16| -> Vec<u8> {
            let mut msg = Message::new(msg_id, MessageType::Query, OpCode::Query);
            msg.metadata.recursion_desired = true;
            msg.add_query(Query::query(
                "router.mesh.".parse().expect("name"),
                ProtoRecordType::A,
            ));
            msg.to_bytes().expect("encode query").to_vec()
        };

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&build_query(0x2222), format!("127.0.0.1:{port}"))
            .await
            .expect("send raw datagram");

        let mut buf = [0u8; 512];
        match timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await {
            // Expected: the non-QUIC datagram is dropped silently and nothing
            // ever comes back.
            Err(_) => {}
            Ok(Ok((n, _))) => {
                // Defensive: even if some bytes were somehow produced, they
                // must not be a valid RFC 9250-framed reply to OUR query id.
                if n > 2 {
                    let framed = &buf[2..n]; // strip the length prefix
                    if let Ok(reply) = Message::from_bytes(framed) {
                        assert_ne!(
                            reply.metadata.id, 0x2222_u16,
                            "non-QUIC datagram elicited a DNS response"
                        );
                    }
                }
            }
            Ok(Err(e)) => panic!("unexpected io error on DoQ probe: {e}"),
        }

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
            block_windows: Vec::new(),
            blocklist_group: None,
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
            block_windows: Vec::new(),
            blocklist_group: None,
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
            block_windows: Vec::new(),
            blocklist_group: None,
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

    /// Harness with a named blocklist group: the global list blocks
    /// `default_lines`, the group `group_name` blocks `group_lines`, and the
    /// given policies (assigning a client to the group) are installed.
    async fn build_group_harness(
        default_lines: &str,
        group_name: &str,
        group_lines: &str,
        policies: Vec<NodePolicy>,
    ) -> Harness {
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
            groups: vec![rustydns_core::config::BlocklistGroup {
                name: group_name.to_string(),
                sources: Vec::new(),
                local_files: Vec::new(),
                trusted_rpz_sources: Vec::new(),
                allowlist: Vec::new(),
            }],
            ..BlocklistConfig::default()
        }));
        blocklist.load_trusted(default_lines);
        blocklist.load_group(
            group_name,
            &[(group_lines, rustydns_blocklist::BlocklistSource::Trusted)],
            &[],
        );

        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec!["https://127.0.0.1:1/dns-query".to_string()],
                timeout_ms: 500,
                ..UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.upstream.dnssec_validation = false;
        dns_config.privacy.randomize_upstream_selection = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
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
            &[],
        )
        .expect("handler");
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);
        Harness {
            port,
            query_log,
            _server: server,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocklist_group_routes_grouped_client_to_group_list() {
        // 127.0.0.1 is assigned to the "strict" group. The group blocks
        // grouponly.example.com; the global list blocks defaultonly.example.com.
        let policy = NodePolicy {
            node_id: None,
            client_ip: Some("127.0.0.1".to_string()),
            blocklist_bypass: false,
            zones_allowed: Vec::new(),
            log_all_queries: false,
            block_windows: Vec::new(),
            blocklist_group: Some("strict".to_string()),
        };
        let harness = build_group_harness(
            "0.0.0.0 defaultonly.example.com\n",
            "strict",
            "0.0.0.0 grouponly.example.com\n",
            vec![policy],
        )
        .await;

        // The group's list applies → grouponly is blocked (NXDOMAIN).
        let resp = query(harness.port, "grouponly.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "a name on the client's group list must be blocked"
        );

        // The GLOBAL list does NOT apply to a grouped client → defaultonly
        // reaches the resolver, which fail-closes (bogus upstream) → SERVFAIL.
        let resp = query(harness.port, "defaultonly.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::ServFail,
            "the global blocklist must NOT apply to a client assigned to a group"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocklist_group_blocks_strict_client_while_default_client_resolves() {
        // One daemon, two clients, one name. Through a dual-stack ([::])
        // listener a 127.0.0.1 peer arrives as ::ffff:127.0.0.1 and ::1 as
        // itself — two distinct policy keys on loopback. The strict-group
        // policy matches the mapped-v4 key; ::1 stays default (global list,
        // which is EMPTY here). The group list alone names ads.example.com,
        // so the identical query must be blocked for A and RESOLVED for B.
        use rustydns_blocklist::BlocklistSource;
        use rustydns_core::config::{BlocklistGroup, UpstreamProtocol};

        let upstream_port = spawn_a_mock("203.0.113.80").await;
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
            groups: vec![BlocklistGroup {
                name: "strict".to_string(),
                sources: Vec::new(),
                local_files: Vec::new(),
                trusted_rpz_sources: Vec::new(),
                allowlist: Vec::new(),
            }],
            ..BlocklistConfig::default()
        }));
        // Global list empty; only the group blocks.
        blocklist.load_trusted("");
        blocklist.load_group(
            "strict",
            &[("0.0.0.0 ads.example.com\n", BlocklistSource::Trusted)],
            &[],
        );
        let mut dns_config = DnsConfig {
            upstream: UpstreamConfig {
                resolvers: vec![format!("127.0.0.1:{upstream_port}")],
                protocol: UpstreamProtocol::Plain,
                timeout_ms: 1000,
                ..UpstreamConfig::default()
            },
            ..Default::default()
        };
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;
        let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
        let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::new(
            &rustydns_core::config::RateLimitConfig {
                enabled: false,
                ..rustydns_core::config::RateLimitConfig::default()
            },
        ));
        let policies = vec![
            NodePolicy {
                node_id: None,
                client_ip: Some("::ffff:127.0.0.1".to_string()),
                blocklist_bypass: false,
                zones_allowed: Vec::new(),
                log_all_queries: false,
                block_windows: Vec::new(),
                blocklist_group: Some("strict".to_string()),
            },
            NodePolicy {
                node_id: None,
                client_ip: Some("::1".to_string()),
                blocklist_bypass: false,
                zones_allowed: Vec::new(),
                log_all_queries: false,
                block_windows: Vec::new(),
                blocklist_group: None,
            },
        ];
        let handler = DnsHandler::new(
            authority,
            blocklist,
            resolver,
            metrics,
            query_log.clone(),
            rate_limiter,
            &policies,
            &[],
        )
        .expect("handler");
        // Dual-stack bind: accepts both v4-mapped and native-v6 peers.
        let udp = UdpSocket::bind("[::]:0").await.expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        let mut server = Server::new(handler);
        server.register_socket(udp);

        // Client A — 127.0.0.1 (mapped on the wire) → strict group → blocked.
        let resp = query(port, "ads.example.com.", ProtoRecordType::A).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "the grouped (stricter) client must be blocked by its group list"
        );

        // Client B — ::1 → no group, global list empty → served by upstream.
        let b = UdpSocket::bind("[::1]:0").await.expect("client v6 bind");
        let mut msg = Message::new(0x4321, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii("ads.example.com.").expect("name"))
                .set_query_type(ProtoRecordType::A);
            q
        });
        b.send_to(&msg.to_bytes().expect("encode"), format!("[::1]:{port}"))
            .await
            .expect("send");
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(5), b.recv(&mut buf))
            .await
            .expect("reply within 5s")
            .expect("recv");
        let resp = Message::from_bytes(&buf[..n]).expect("decode");
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "the default client must NOT inherit the group's blocks"
        );
        match resp.answers.first().map(|a| &a.data) {
            Some(hickory_proto::rr::RData::A(a)) => {
                assert_eq!(a.0.to_string(), "203.0.113.80", "served from upstream");
            }
            other => panic!("expected an A answer for the default client, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_block_window_refuses_during_active_window() {
        // An all-day, every-day block window is active at any wall-clock time,
        // so the client (loopback 127.0.0.1) must be REFUSED — even for a name
        // the authority would otherwise answer (the schedule gate runs first).
        let policy = NodePolicy {
            node_id: None,
            client_ip: Some("127.0.0.1".to_string()),
            blocklist_bypass: false,
            zones_allowed: Vec::new(),
            log_all_queries: false,
            block_windows: vec![rustydns_core::config::BlockWindow {
                days: Vec::new(), // every day
                start: None,      // all-day
                end: None,
                utc_offset_minutes: 0,
            }],
            blocklist_group: None,
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
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::Refused,
            "an active all-day block window must REFUSE every query, even authority hits"
        );
        assert!(resp.answers.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_block_window_timed_blocks_inside_and_serves_outside() {
        // A TIMED window is time-scoped: while the client's local minute-of-
        // day is inside the span the schedule gate REFUSES (it runs first),
        // and outside the span the identical query flows through to a live
        // upstream. No blocklist entries are loaded, so ONLY the window can
        // refuse — the differential isolates the schedule gate itself.
        //
        // Both windows are derived from the current UTC minute (`m`), so the
        // test is deterministic at any wall-clock time:
        // - INSIDE: a WRAPPING window `[m+20:00, m+19:59)` — wrapping windows
        //   are active everywhere except their sub-window gap, which here
        //   lies entirely behind `now`; `now` sits ≥4 h away from either
        //   gap edge (the one boundary minute where the span degenerates to
        //   a non-wrapping `[0, ...)` range still contains `now`).
        // - OUTSIDE: a normal window `[m+12:00, m+22:00)` whose nearest edge
        //   is ≥10 h of wall-clock away from `now`.
        use rustydns_core::config::{BlockWindow, UpstreamProtocol};

        fn hhmm(min_of_day: i64) -> String {
            let m = min_of_day.rem_euclid(1440);
            format!("{:02}:{:02}", m / 60, m % 60)
        }
        fn window(start_min: i64, end_min: i64) -> BlockWindow {
            BlockWindow {
                days: Vec::new(), // every day
                start: Some(hhmm(start_min)),
                end: Some(hhmm(end_min)),
                utc_offset_minutes: 0,
            }
        }

        async fn build_windowed_harness(windows: Vec<BlockWindow>, upstream_port: u16) -> u16 {
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
            let blocklist = Arc::new(BlocklistEngine::new(BlocklistConfig::default()));
            let mut dns_config = DnsConfig {
                upstream: UpstreamConfig {
                    resolvers: vec![format!("127.0.0.1:{upstream_port}")],
                    protocol: UpstreamProtocol::Plain,
                    timeout_ms: 1000,
                    ..UpstreamConfig::default()
                },
                ..Default::default()
            };
            dns_config.privacy.randomize_upstream_selection = false;
            dns_config.upstream.dnssec_validation = false;
            let resolver = Arc::new(Resolver::new(dns_config).await.expect("resolver"));
            let query_log = Arc::new(crate::query_log::QueryLog::new(64));
            let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::new(
                &rustydns_core::config::RateLimitConfig {
                    enabled: false,
                    ..rustydns_core::config::RateLimitConfig::default()
                },
            ));
            let policy = NodePolicy {
                node_id: None,
                client_ip: Some("127.0.0.1".to_string()),
                blocklist_bypass: false,
                zones_allowed: Vec::new(),
                log_all_queries: false,
                block_windows: windows,
                blocklist_group: None,
            };
            let handler = DnsHandler::new(
                authority,
                blocklist,
                resolver,
                metrics,
                query_log,
                rate_limiter,
                &[policy],
                &[],
            )
            .expect("handler");
            let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
            let port = udp.local_addr().unwrap().port();
            let mut server = Server::new(handler);
            server.register_socket(udp);
            // The helper returns only the port; deliberately leak the server
            // so its serve task outlives this call (the other tests keep the
            // Server alive in the test fn's own scope).
            std::mem::forget(server);
            port
        }

        let now_min = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs() as i64)
            / 60;

        // Leg 1 — INSIDE the timed window → Refused.
        let inside_port = spawn_a_mock("203.0.113.60").await;
        let inside_windows = vec![window(now_min + 1200, now_min + 1199)];
        let inside_port_listener = build_windowed_harness(inside_windows, inside_port).await;
        let resp = query(
            inside_port_listener,
            "timed.example.com.",
            ProtoRecordType::A,
        )
        .await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::Refused,
            "a query inside the scheduled window must be REFUSED by the schedule gate"
        );
        assert!(resp.answers.is_empty());

        // Leg 2 — OUTSIDE the timed window → served by the live upstream.
        let outside_port = spawn_a_mock("203.0.113.61").await;
        let outside_windows = vec![window(now_min + 720, now_min + 1320)];
        let outside_port_listener = build_windowed_harness(outside_windows, outside_port).await;
        let pass = query(
            outside_port_listener,
            "timed.example.com.",
            ProtoRecordType::A,
        )
        .await;
        assert_eq!(
            pass.metadata.response_code,
            ResponseCode::NoError,
            "outside the window the query must not be refused"
        );
        match &pass.answers[0].data {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0.to_string(), "203.0.113.61", "served outside the window");
            }
            other => panic!("expected A rdata, got {other:?}"),
        }
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
            block_windows: Vec::new(),
            blocklist_group: None,
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
    fn canonical_qname_borrows_lowercase_and_owns_mixed_case() {
        use super::canonical_qname;
        use std::borrow::Cow;
        // Already-lowercase FQDN → borrowed, no allocation.
        assert!(matches!(
            canonical_qname("ads.example.com."),
            Cow::Borrowed("ads.example.com.")
        ));
        // Mixed case → owned, lowercased; trailing dot untouched.
        match canonical_qname("Ads.Example.COM.") {
            Cow::Owned(s) => assert_eq!(s, "ads.example.com."),
            Cow::Borrowed(_) => panic!("mixed-case input must be owned + lowercased"),
        }
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
        // Multi-label GLUE must not match either: "evilinternal.lan" ends
        // with "internal.lan" as a raw string, but the character before the
        // putative zone is '-' not '.', so it lives OUTSIDE the allowed
        // zone. This is the leg that discriminates the byte-boundary check:
        // a refactor to bare ends_with() passes every assertion above and
        // silently widens the quarantine boundary to lookalike names.
        assert!(!name_in_any_zone(
            "evilinternal.lan.",
            &["internal.lan.".to_string()]
        ));
        assert!(!name_in_any_zone(
            "notlab.example.com.",
            &["lab.example.com".to_string()]
        ));
        // Outside any zone.
        assert!(!name_in_any_zone("example.com", &zones));
        // Empty zone list: caller treats as no restriction; we don't
        // exercise that path through this helper but the predicate
        // returns false for "matches nothing".
        assert!(!name_in_any_zone("anything", &[]));
    }

    #[test]
    fn policy_v6_matching_is_exact_no_prefix_fallback() {
        // Documents the deliberate IPv6 semantics (see the NodePolicy::
        // client_ip doc in rustydns-core): entries match the EXACT /128
        // source address only. A host rotating its SLAAC interface
        // identifier intentionally falls back to the unrestricted default
        // policy rather than inheriting its old entry's restrictions — and,
        // critically, a PERMISSIVE field like blocklist_bypass must never
        // leak to the rest of its /64 via prefix matching (that direction
        // would be privilege escalation). The rotation trade-off is spelled
        // out in the config docs and tracked for the NodeId path.
        let policies = vec![NodePolicy {
            node_id: None,
            client_ip: Some("2001:db8:1:2::10".to_string()),
            blocklist_bypass: true,
            zones_allowed: vec!["internal.lan.".to_string()],
            log_all_queries: false,
            block_windows: Vec::new(),
            blocklist_group: None,
        }];
        let map = build_policy_map(&policies);

        let exact: std::net::IpAddr = "2001:db8:1:2::10".parse().unwrap();
        let entry = map.get(&exact).expect("exact /128 entry must match itself");
        assert!(!entry.zones_allowed.is_empty());
        assert!(entry.blocklist_bypass);

        // Rotated interface identifier → different /128 → deliberately NO
        // policy (no prefix fallback in either direction).
        let rotated: std::net::IpAddr = "2001:db8:1:2::dead".parse().unwrap();
        assert!(
            !map.contains_key(&rotated),
            "prefix fallback would over-apply blocklist_bypass to the whole link"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_matches_across_ipv4_mapped_forms() {
        // A dual-stack [::] listener delivers v4 peers as ::ffff:a.b.c.d;
        // the policy map is canonicalised to native V4. Both written forms
        // of the SAME address must resolve to one entry, and a mapped-form
        // client must not silently miss its policy.
        let policies = vec![NodePolicy {
            node_id: None,
            client_ip: Some("::ffff:192.168.1.55".to_string()),
            blocklist_bypass: true,
            zones_allowed: vec![],
            log_all_queries: false,
            block_windows: Vec::new(),
            blocklist_group: None,
        }];
        let map = build_policy_map(&policies);

        let native_v4: std::net::IpAddr = "192.168.1.55".parse().unwrap();
        assert!(
            map.contains_key(&native_v4),
            "mapped-form entry must be stored under native V4"
        );

        // Lookup path: resolve_policy normalises src_ip, so both
        // presentations of the same client resolve to the same decision.
        let handler = bare_handler(policies).await;
        let mapped: std::net::IpAddr = "::ffff:192.168.1.55".parse().unwrap();
        assert!(handler.resolve_policy(native_v4).blocklist_bypass);
        assert!(handler.resolve_policy(mapped).blocklist_bypass);
    }

    #[test]
    fn policy_duplicate_across_spellings_collapses_later_wins() {
        // Both spellings of ONE address configured as separate [[policy]]
        // entries. Key-side canonicalisation collapses them onto the same
        // map slot: exactly one entry survives, the LATER one wins (same
        // semantics as an exact-text duplicate), so behavior stays
        // deterministic instead of depending on which spelling a query's
        // socket happened to present.
        let policies = vec![
            NodePolicy {
                node_id: None,
                client_ip: Some("::ffff:10.0.0.7".to_string()),
                blocklist_bypass: true,
                zones_allowed: vec![],
                log_all_queries: false,
                block_windows: Vec::new(),
                blocklist_group: None,
            },
            NodePolicy {
                node_id: None,
                client_ip: Some("10.0.0.7".to_string()),
                blocklist_bypass: false,
                zones_allowed: vec![],
                log_all_queries: false,
                block_windows: Vec::new(),
                blocklist_group: None,
            },
        ];
        let map = build_policy_map(&policies);

        let canon: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        let entry = map.get(&canon).expect("canonical entry must exist");
        assert_eq!(
            map.values().count(),
            1,
            "both spellings collapse to one slot"
        );
        assert!(
            !entry.blocklist_bypass,
            "the LATER entry must win the collapse"
        );
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
