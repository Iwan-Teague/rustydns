//! End-to-end resolver integration tests against an in-process UDP DNS
//! mock. Exercises the pipeline behaviours that previously had only
//! synthetic unit coverage:
//!
//! - happy-path forwarding
//! - fail-closed behaviour when no upstream responds
//! - cache reuse across repeat queries
//! - conditional-forwarding route dispatch
//! - DNS-rebinding defence on the default arm
//! - rebinding defence is bypassed for route arms
//!
//! Tests use `protocol = "plain"` with `127.0.0.1:<port>` to avoid
//! TLS/cert plumbing. The resolver code paths under test — cache,
//! fail-closed, route dispatch, rdata filtering — are
//! protocol-agnostic: a plain-UDP mock is sufficient. A TLS injection
//! point for DoH-specific tests is still tracked in roadmap §4.1.
//!
//! Privacy invariants are deliberately NOT exercised here — the unit
//! tests in `lib.rs` (zone matching, rdata classification, filter
//! semantics) cover those at a finer grain.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use rustydns_core::RustyDnsError;
use rustydns_core::config::{
    AuthorityConfig, BlocklistConfig, DnsConfig, MetricsConfig, PrivacyConfig, RateLimitConfig,
    ServerConfig, UpstreamConfig, UpstreamProtocol, UpstreamRoute,
};
use rustydns_core::record::RecordData;
use rustydns_resolver::Resolver;

// ---------------------------------------------------------------------
// Mock UDP DNS upstream
// ---------------------------------------------------------------------

/// A tiny in-process UDP DNS server used as a test upstream.
///
/// Bind on `127.0.0.1:0`, parse incoming queries, hand them to a
/// closure `responder` for record-set selection, encode the response,
/// write it back. Tracks the number of queries received so cache
/// tests can verify the upstream was only consulted once.
struct MockUpstream {
    addr: SocketAddr,
    queries_received: Arc<AtomicUsize>,
    shutdown: CancellationToken,
}

impl MockUpstream {
    async fn new<F>(responder: F) -> Self
    where
        F: Fn(&Name, RecordType) -> Vec<Record> + Send + Sync + 'static,
    {
        // Default response code is NoError; delegate to the rcode-aware ctor.
        Self::new_with_rcode(move |name, rtype| (ResponseCode::NoError, responder(name, rtype)))
            .await
    }

    /// Like [`MockUpstream::new`], but the responder also chooses the
    /// response code — used to drive NXDOMAIN vs NODATA classification.
    async fn new_with_rcode<F>(responder: F) -> Self
    where
        F: Fn(&Name, RecordType) -> (ResponseCode, Vec<Record>) + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = socket.local_addr().expect("local_addr");
        let queries_received = Arc::new(AtomicUsize::new(0));
        let shutdown = CancellationToken::new();

        let q = queries_received.clone();
        let sh = shutdown.clone();
        let responder = Arc::new(responder);
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                tokio::select! {
                    _ = sh.cancelled() => break,
                    res = socket.recv_from(&mut buf) => {
                        let (n, src) = match res {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        q.fetch_add(1, Ordering::SeqCst);
                        let Ok(query) = Message::from_bytes(&buf[..n]) else {
                            continue;
                        };
                        let Some(question) = query.queries.first() else {
                            continue;
                        };
                        let (rcode, answers) = responder(question.name(), question.query_type());
                        let mut resp = Message::new(
                            query.metadata.id,
                            MessageType::Response,
                            OpCode::Query,
                        );
                        resp.metadata.recursion_available = true;
                        resp.metadata.response_code = rcode;
                        resp.add_query(question.clone());
                        for rec in answers {
                            resp.add_answer(rec);
                        }
                        if let Ok(bytes) = resp.to_bytes() {
                            let _ = socket.send_to(&bytes, src).await;
                        }
                    }
                }
            }
        });
        Self {
            addr,
            queries_received,
            shutdown,
        }
    }

    fn addr_string(&self) -> String {
        self.addr.to_string()
    }

    fn query_count(&self) -> usize {
        self.queries_received.load(Ordering::SeqCst)
    }

    fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

// ---------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------

/// Build a baseline `DnsConfig` pointing at `upstream_addr` over plain
/// UDP. DNSSEC is off (the mock doesn't sign), randomisation is off so
/// tests are deterministic, and the cache is small but non-zero so
/// cache-hit tests are visible.
fn plain_config(upstream_addr: &str) -> DnsConfig {
    DnsConfig {
        server: ServerConfig::default(),
        upstream: UpstreamConfig {
            resolvers: vec![upstream_addr.to_string()],
            protocol: UpstreamProtocol::Plain,
            fail_closed: true,
            dnssec_validation: false,
            timeout_ms: 1500,
            max_cache_entries: 32,
            block_private_rdata: false,
            routes: Vec::new(),
            ..UpstreamConfig::default()
        },
        authority: AuthorityConfig::default(),
        blocklist: BlocklistConfig::default(),
        privacy: PrivacyConfig {
            randomize_upstream_selection: false,
            ..PrivacyConfig::default()
        },
        metrics: MetricsConfig::default(),
        rate_limit: RateLimitConfig::default(),
        policy: Vec::new(),
        rewrite: Vec::new(),
        safesearch: Default::default(),
    }
}

fn a_record(name: &Name, ip: Ipv4Addr, ttl: u32) -> Record {
    Record::from_rdata(name.clone(), ttl, RData::A(A(ip)))
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[tokio::test]
async fn happy_path_a_query_returns_record() {
    let mock =
        MockUpstream::new(|name, _| vec![a_record(name, Ipv4Addr::new(1, 2, 3, 4), 300)]).await;

    let cfg = plain_config(&mock.addr_string());
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let out = resolver
        .resolve("example.com.", "A")
        .await
        .expect("resolve");

    assert_eq!(out.records.len(), 1, "expected exactly one record");
    match &out.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 2, 3, 4)),
        other => panic!("expected A record, got {other:?}"),
    }
    assert_eq!(out.private_rdata_dropped, 0);
    assert_eq!(mock.query_count(), 1, "mock saw exactly one query");
}

#[tokio::test]
async fn fail_closed_when_no_upstream_responds() {
    // Bind a UDP socket to capture a port, then DROP the socket so the
    // port is free. The chance of another process binding the same
    // ephemeral port before the timeout fires is negligible. Resolver
    // sends the query into the void; hickory times out; we return
    // AllUpstreamsFailed.
    let unused_port = {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.local_addr().unwrap().port()
    };

    let mut cfg = plain_config(&format!("127.0.0.1:{unused_port}"));
    // Keep the timeout short so the test finishes quickly.
    cfg.upstream.timeout_ms = 250;
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let err = resolver.resolve("example.com.", "A").await.unwrap_err();
    assert!(
        matches!(err, RustyDnsError::AllUpstreamsFailed),
        "expected AllUpstreamsFailed under fail_closed, got {err:?}"
    );
}

#[tokio::test]
async fn cache_serves_repeat_query_without_upstream_hit() {
    let mock =
        MockUpstream::new(|name, _| vec![a_record(name, Ipv4Addr::new(8, 8, 8, 8), 300)]).await;

    let cfg = plain_config(&mock.addr_string());
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let _ = resolver
        .resolve("cached.example.com.", "A")
        .await
        .expect("first resolve");

    // Kill the mock — the second resolve must be served entirely from
    // hickory's internal cache.
    mock.shutdown();
    // Brief yield so the mock task observes the cancellation before
    // we send the second query (avoids a race that would surface as
    // the mock incrementing its counter on the second packet).
    tokio::time::sleep(Duration::from_millis(20)).await;

    let out = resolver
        .resolve("cached.example.com.", "A")
        .await
        .expect("second resolve from cache");

    assert_eq!(out.records.len(), 1);
    match &out.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(8, 8, 8, 8)),
        other => panic!("expected A record, got {other:?}"),
    }
    assert_eq!(
        mock.query_count(),
        1,
        "second resolve must be served from cache (mock saw 1 packet, not 2)"
    );
}

#[tokio::test]
async fn route_dispatch_uses_zone_specific_upstream() {
    // Default mock answers everything with 1.1.1.1.
    let default_mock =
        MockUpstream::new(|name, _| vec![a_record(name, Ipv4Addr::new(1, 1, 1, 1), 300)]).await;
    // Route mock answers everything with 192.168.0.42.
    let route_mock =
        MockUpstream::new(|name, _| vec![a_record(name, Ipv4Addr::new(192, 168, 0, 42), 300)])
            .await;

    let mut cfg = plain_config(&default_mock.addr_string());
    cfg.upstream.routes = vec![UpstreamRoute {
        zone: "lan.".to_string(),
        resolvers: vec![route_mock.addr_string()],
        protocol: UpstreamProtocol::Plain,
    }];

    let resolver = Resolver::new(cfg).await.expect("resolver init");

    // Query inside the route → route mock answers, default untouched.
    let lan = resolver.resolve("printer.lan.", "A").await.expect("lan");
    match &lan.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 0, 42)),
        other => panic!("expected route mock's IP, got {other:?}"),
    }
    assert_eq!(route_mock.query_count(), 1);
    assert_eq!(default_mock.query_count(), 0);

    // Query outside the route → default mock answers, route untouched.
    let public = resolver.resolve("example.com.", "A").await.expect("public");
    match &public.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 1, 1, 1)),
        other => panic!("expected default mock's IP, got {other:?}"),
    }
    assert_eq!(
        route_mock.query_count(),
        1,
        "route mock untouched by public"
    );
    assert_eq!(default_mock.query_count(), 1);
}

#[tokio::test]
async fn rebinding_defence_filters_private_a_from_default_arm() {
    // Mock returns ONE public + ONE private A. With block_private_rdata
    // = true, only the public address must survive.
    let mock = MockUpstream::new(|name, _| {
        vec![
            a_record(name, Ipv4Addr::new(93, 184, 216, 34), 300),
            a_record(name, Ipv4Addr::new(192, 168, 1, 1), 300),
        ]
    })
    .await;

    let mut cfg = plain_config(&mock.addr_string());
    cfg.upstream.block_private_rdata = true;
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let out = resolver
        .resolve("rebind.example.", "A")
        .await
        .expect("resolve");

    assert_eq!(
        out.records.len(),
        1,
        "private record must be filtered, leaving the public one"
    );
    match &out.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected public A, got {other:?}"),
    }
    assert_eq!(out.private_rdata_dropped, 1);
}

#[tokio::test]
async fn rebinding_defence_passes_private_from_route_arm() {
    // Route arm — operator routed `lan.` here precisely BECAUSE it
    // serves private IPs. The defence must NOT apply.
    let route_mock =
        MockUpstream::new(|name, _| vec![a_record(name, Ipv4Addr::new(192, 168, 0, 1), 300)]).await;
    // Default mock just answers public IPs (unused in this test, but
    // resolver requires a valid default arm).
    let default_mock =
        MockUpstream::new(|name, _| vec![a_record(name, Ipv4Addr::new(1, 1, 1, 1), 300)]).await;

    let mut cfg = plain_config(&default_mock.addr_string());
    cfg.upstream.block_private_rdata = true;
    cfg.upstream.routes = vec![UpstreamRoute {
        zone: "lan.".to_string(),
        resolvers: vec![route_mock.addr_string()],
        protocol: UpstreamProtocol::Plain,
    }];
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let out = resolver.resolve("router.lan.", "A").await.expect("resolve");

    assert_eq!(out.records.len(), 1, "route response must pass through");
    match &out.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 0, 1)),
        other => panic!("expected route's private A, got {other:?}"),
    }
    assert_eq!(
        out.private_rdata_dropped, 0,
        "route arm must not filter even when block_private_rdata is on"
    );
}

#[tokio::test]
async fn rebinding_defence_disabled_lets_private_through() {
    let mock =
        MockUpstream::new(|name, _| vec![a_record(name, Ipv4Addr::new(10, 0, 0, 1), 300)]).await;

    // block_private_rdata defaults to false (plain_config keeps it off).
    let cfg = plain_config(&mock.addr_string());
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let out = resolver
        .resolve("internal.example.", "A")
        .await
        .expect("resolve");

    assert_eq!(out.records.len(), 1, "defence off: record must survive");
    match &out.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1)),
        other => panic!("expected unfiltered private A, got {other:?}"),
    }
    assert_eq!(out.private_rdata_dropped, 0);
}

#[tokio::test]
async fn resolver_never_sends_edns_client_subnet() {
    // PRIVACY (RFC 7871): the resolver must never advertise EDNS Client Subnet
    // upstream — that would leak the client's network to the upstream/CDN.
    // Enable DNSSEC so EDNS0 IS present on the wire (DO bit), making this the
    // meaningful case: EDNS0 on, but ClientSubnet absent. The response is
    // unsigned so validation fails (we ignore the SERVFAIL); the mock has
    // already inspected the outgoing query.
    use hickory_proto::rr::rdata::opt::EdnsCode;
    use std::sync::atomic::AtomicBool;

    let saw_ecs = Arc::new(AtomicBool::new(false));
    let flag = saw_ecs.clone();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            if query
                .edns
                .as_ref()
                .is_some_and(|e| e.option(EdnsCode::Subnet).is_some())
            {
                flag.store(true, Ordering::SeqCst);
            }
            let Some(q) = query.queries.first() else {
                continue;
            };
            let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_query(q.clone());
            resp.add_answer(a_record(q.name(), Ipv4Addr::new(1, 2, 3, 4), 300));
            if let Ok(bytes) = resp.to_bytes() {
                let _ = socket.send_to(&bytes, src).await;
            }
        }
    });

    let mut cfg = plain_config(&addr.to_string());
    cfg.upstream.dnssec_validation = true; // turns EDNS0 on
    let resolver = Resolver::new(cfg).await.expect("resolver init");
    // The answer is unsigned → validation fails → Err; we only care that the
    // outgoing query carried no ECS.
    let _ = resolver.resolve("example.com.", "A").await;
    assert!(
        !saw_ecs.load(Ordering::SeqCst),
        "resolver must never advertise EDNS Client Subnet"
    );
}

#[tokio::test]
async fn nxdomain_upstream_sets_nxdomain_flag() {
    // Upstream says the name does not exist (NXDOMAIN, no answers). The
    // resolver must surface that as an empty outcome with nxdomain = true so
    // the handler emits NXDomain rather than collapsing it to NODATA.
    let mock = MockUpstream::new_with_rcode(|_, _| (ResponseCode::NXDomain, Vec::new())).await;

    let cfg = plain_config(&mock.addr_string());
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let out = resolver
        .resolve("does-not-exist.example.", "A")
        .await
        .expect("no-records is Ok, not an error");

    assert!(out.records.is_empty(), "NXDOMAIN carries no answers");
    assert!(out.nxdomain, "NXDOMAIN upstream must set the nxdomain flag");
}

#[tokio::test]
async fn nodata_upstream_leaves_nxdomain_clear() {
    // Upstream says the name exists but has no A records (NOERROR, no
    // answers = NODATA). nxdomain must stay false → handler emits NoError.
    let mock = MockUpstream::new_with_rcode(|_, _| (ResponseCode::NoError, Vec::new())).await;

    let cfg = plain_config(&mock.addr_string());
    let resolver = Resolver::new(cfg).await.expect("resolver init");

    let out = resolver
        .resolve("exists-no-a.example.", "A")
        .await
        .expect("NODATA is Ok");

    assert!(out.records.is_empty());
    assert!(
        !out.nxdomain,
        "NODATA (NoError, empty) must NOT set the nxdomain flag"
    );
}

// `_unused_addr_string` is referenced indirectly via SocketAddr usage
// above; keep this dead import suppressor so the test file lints clean
// even if a future test deletes the only IpAddr usage.
#[allow(dead_code)]
fn _unused_addr_string(addr: IpAddr) -> String {
    addr.to_string()
}
