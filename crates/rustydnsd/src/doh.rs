#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! DNS-over-HTTPS listener (HTTP/2, no TLS — terminate TLS at a reverse proxy).
//!
//! Implements the GET (`?dns=<base64url>`) and POST (`application/dns-message`)
//! forms of RFC 8484. The listener is HTTP/2 only — TLS termination is the
//! reverse proxy's job (per `AGENTS.md`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::header;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use hickory_proto::serialize::binary::BinEncoder;
use hickory_server::net::NetError;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use rustydns_core::RustyDnsError;
use rustydns_core::client::ClientId;

use crate::handler::DnsHandler;

const MAX_DOH_MESSAGE_BYTES: usize = 65_535;
/// Floor for the DoH response deadline. The effective deadline is derived
/// from the configured upstream timeout so a slow upstream can never race —
/// and lose — the HTTP layer while UDP/TCP would still have served.
const DOH_TIMEOUT_FLOOR: Duration = Duration::from_secs(5);
/// Slack added on top of `2 x upstream.timeout_ms` (hickory may retry once).
const DOH_TIMEOUT_SLACK: Duration = Duration::from_millis(500);
const DOH_PATH: &str = "/dns-query";

/// Derive the DoH response deadline from the configured upstream timeout:
/// `max(5 s floor, 2 x upstream_timeout + slack)`. hickory may retry once
/// inside its budget, and the HTTP layer must never win a race against a
/// DNS answer UDP/TCP would deliver.
///
/// Saturating arithmetic: an operator-supplied `timeout_ms` near `u64::MAX`
/// must clamp here instead of overflowing a multiply into an abort.
pub(crate) fn doh_deadline(upstream_timeout: Duration) -> Duration {
    (upstream_timeout.saturating_mul(2) + DOH_TIMEOUT_SLACK).max(DOH_TIMEOUT_FLOOR)
}

/// Start the DoH listener (HTTP, no TLS) on a pre-bound listener until
/// shutdown.
///
/// The caller binds the `TcpListener` (with `SO_REUSEPORT`, see
/// [`crate::listeners::bind_tcp`]) so a live SIGHUP handover can stand up a
/// new generation on the same port before draining the old one.
pub async fn serve(
    handler: Arc<DnsHandler>,
    listener: TcpListener,
    shutdown: CancellationToken,
    upstream_timeout: Duration,
) -> Result<(), RustyDnsError> {
    // Deadline formula: floor of 5 s, else 2x the upstream timeout plus
    // slack — hickory may retry once inside its budget, and the HTTP layer
    // must never win a race against a DNS answer UDP/TCP would deliver.
    let doh_timeout = doh_deadline(upstream_timeout);
    let state = DohState {
        handler,
        doh_timeout,
    };
    let app = Router::new()
        .route(DOH_PATH, get(handle_get).post(handle_post))
        // Reject oversized POST bodies at the framework layer, before the
        // whole payload is buffered into memory. A DNS message can't exceed
        // 65 535 bytes, so anything larger is abuse; axum's 2 MiB default
        // would otherwise let a client force us to buffer 2 MiB per request
        // (matters on Pi-class hardware). The handler re-checks the length
        // as defence-in-depth.
        .layer(DefaultBodyLimit::max(MAX_DOH_MESSAGE_BYTES))
        .with_state(state);

    let listen = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    info!(listen = %listen, path = DOH_PATH, "DoH listener started");

    // `with_graceful_shutdown` requires a 'static future. The
    // CancellationToken is cheaply cloneable; clone it into an owned
    // future so it lives long enough.
    let shutdown_signal = async move { shutdown.cancelled().await };

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await
    .map_err(|e| RustyDnsError::Config(format!("DoH server error: {e}")))
}

#[derive(Clone)]
struct DohState {
    handler: Arc<DnsHandler>,
    doh_timeout: Duration,
}

#[derive(Deserialize)]
struct DohQuery {
    dns: String,
}

async fn handle_get(
    State(state): State<DohState>,
    ConnectInfo(src): ConnectInfo<SocketAddr>,
    Query(query): Query<DohQuery>,
) -> Response {
    let decoded = match URL_SAFE_NO_PAD.decode(query.dns.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => return bad_request("invalid base64url in dns parameter"),
    };

    handle_dns_message(state.handler.clone(), state.doh_timeout, src, decoded).await
}

async fn handle_post(
    State(state): State<DohState>,
    ConnectInfo(src): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // RFC 8484 §6.1: a DoH POST carries `application/dns-message`. Anything
    // else is not a DNS message by the client's own declaration — reject it
    // at the HTTP layer instead of feeding arbitrary bytes to the parser.
    if !is_dns_message_content_type(&headers) {
        return Response::builder()
            .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .header(header::ACCEPT, "application/dns-message")
            .body(Body::from("content-type must be application/dns-message"))
            .unwrap();
    }
    handle_dns_message(state.handler.clone(), state.doh_timeout, src, body.to_vec()).await
}

/// True iff the request declares the RFC 8484 DNS media type. Parameters
/// (`;charset=…`) are tolerated per MIME rules; matching on the bare type is
/// case-insensitive.
fn is_dns_message_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/dns-message"))
        })
}

async fn handle_dns_message(
    handler: Arc<DnsHandler>,
    doh_timeout: Duration,
    src: SocketAddr,
    bytes: Vec<u8>,
) -> Response {
    if bytes.is_empty() {
        return bad_request("empty DNS message");
    }
    if bytes.len() > MAX_DOH_MESSAGE_BYTES {
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header("Cache-Control", "no-store")
            .body(Body::from("DNS message too large"))
            .unwrap();
    }

    // hickory 0.26 has Request::from_bytes which does the whole
    // parse (header + queries + edns) in one shot. Cleaner than the
    // old two-step.
    let request = match Request::from_bytes(bytes, src, Protocol::Https) {
        Ok(request) => request,
        Err(e) => {
            // Form errors are a client problem — return HTTP 400 rather
            // than synthesise a DNS-format FormErr response (which
            // would require a parsed Header we don't have).
            // PRIVACY: anonymise the client (never log a full client IP at
            // info+); this path fires before the handler's own anonymisation.
            warn!(client = %ClientId::from_ip(src.ip()).anonymized(), error = %e, "malformed DNS-over-HTTPS request");
            return bad_request("malformed DNS message");
        }
    };

    let (tx, rx) = oneshot::channel();
    let response_handler = DohResponseHandler::new(tx);

    // hickory 0.26 added a `T: Time` type param to handle_request.
    // Use the default Tokio time impl via turbofish; nothing in our
    // handler reads it.
    handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(&request, response_handler)
        .await;

    let response_bytes = match timeout(doh_timeout, rx).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return server_error("failed to build DNS response"),
        Err(_) => return server_error("DNS response timed out"),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/dns-message")
        .header("Cache-Control", "no-store")
        .body(Body::from(response_bytes))
        .unwrap()
}

fn bad_request(message: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("Cache-Control", "no-store")
        .body(Body::from(message))
        .unwrap()
}

fn server_error(message: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("Cache-Control", "no-store")
        .body(Body::from(message))
        .unwrap()
}

#[derive(Clone)]
struct DohResponseHandler {
    sender: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
}

impl DohResponseHandler {
    fn new(sender: oneshot::Sender<Vec<u8>>) -> Self {
        Self {
            sender: Arc::new(Mutex::new(Some(sender))),
        }
    }
}

#[async_trait::async_trait]
impl ResponseHandler for DohResponseHandler {
    // hickory 0.26: MessageResponse moved to `zone_handler`,
    // send_response returns `Result<ResponseInfo, NetError>` instead
    // of `io::Result<ResponseInfo>`.
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
    ) -> Result<ResponseInfo, NetError> {
        let mut buffer = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buffer);
        encoder.set_max_size(u16::MAX);
        let info = response
            .destructive_emit(&mut encoder)
            .map_err(|e| NetError::Msg(format!("encode error: {e}")))?;

        let mut sender = self.sender.lock().await;
        if let Some(sender) = sender.take() {
            let _ = sender.send(buffer);
        }

        Ok(info)
    }
}

// ===========================================================================
// Integration tests
//
// Boot the DoH listener on a random loopback port, send GET (?dns=base64url)
// and POST (application/dns-message) requests through reqwest, assert that
// the responses are well-formed DNS messages with the expected response
// codes.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name as ProtoName, RData, RecordType as ProtoRecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    use rustydns_authority::Authority;
    use rustydns_blocklist::BlocklistEngine;
    use rustydns_core::config::{
        AuthorityConfig, BlockResponse, BlocklistConfig, DnsConfig, StaticRecord, UpstreamConfig,
    };
    use rustydns_resolver::Resolver;

    use crate::handler::DnsHandler;
    use crate::metrics::Metrics;

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

    async fn build_handler(
        static_records: Vec<StaticRecord>,
        blocklist_lines: &str,
        upstream_resolvers: Vec<String>,
        block_response: BlockResponse,
    ) -> Arc<DnsHandler> {
        let metrics = Arc::new(Metrics::new().unwrap());
        let authority_cfg = AuthorityConfig {
            mesh_zone_bundle_path: None,
            mesh_zone_verifier_key_path: None,
            mesh_zone_max_age_secs: 600,
            mesh_zone: "mesh.".to_string(),
            static_records,
            poll_interval_secs: 30,
        };
        let authority = Arc::new(Authority::new(authority_cfg).unwrap());

        let bl_cfg = BlocklistConfig {
            sources: Vec::new(),
            reload_interval_secs: 0,
            block_response,
            ..BlocklistConfig::default()
        };
        let blocklist = Arc::new(BlocklistEngine::new(bl_cfg));
        if !blocklist_lines.is_empty() {
            blocklist.load_trusted(blocklist_lines);
        }

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
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;

        let resolver = Arc::new(Resolver::new(dns_config).await.unwrap());
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
        let rate_limiter = Arc::new(crate::rate_limiter::RateLimiter::new(
            &rustydns_core::config::RateLimitConfig {
                enabled: false,
                ..rustydns_core::config::RateLimitConfig::default()
            },
        ));
        Arc::new(
            DnsHandler::new(
                authority,
                blocklist,
                resolver,
                metrics,
                query_log,
                rate_limiter,
                &[],
                &[],
            )
            .unwrap(),
        )
    }

    #[test]
    fn doh_deadline_floor_applies_to_small_timeouts() {
        assert_eq!(
            doh_deadline(Duration::from_millis(1000)),
            Duration::from_secs(5),
            "small upstream timeouts must clamp to the 5 s floor"
        );
    }

    #[test]
    fn doh_deadline_tracks_large_upstream_timeouts() {
        // 5 s upstream (the example/default) -> 2x + slack, ABOVE the floor:
        // this leg is what discriminates the formula from a fixed constant.
        assert_eq!(
            doh_deadline(Duration::from_millis(5000)),
            Duration::from_millis(10_500)
        );
        assert_eq!(
            doh_deadline(Duration::from_millis(20_000)),
            Duration::from_millis(40_500)
        );
    }

    #[test]
    fn doh_deadline_saturates_instead_of_panicking_on_huge_values() {
        // timeout_ms has no upper validation bound. The pre-fix expression
        // (`upstream_timeout * 2`) PANICS on u64-scale inputs — under
        // release panic=abort that aborts the daemon at startup. Saturating
        // arithmetic must instead yield a finite deadline >= the floor.
        let big = doh_deadline(Duration::from_millis(u64::MAX));
        assert!(big >= DOH_TIMEOUT_FLOOR);
        // Monotonic: a larger upstream timeout never yields a smaller
        // deadline.
        assert!(
            doh_deadline(Duration::from_millis(u64::MAX))
                >= doh_deadline(Duration::from_millis(20_000))
        );
    }

    /// Boot a DoH listener on a random port. Returns `(base_url, shutdown_token)`.    /// Boot a DoH listener on a random port. Returns `(base_url, shutdown_token)`.
    /// Drop the token (or call .cancel()) to stop the listener.
    async fn spawn_doh(handler: Arc<DnsHandler>) -> (String, CancellationToken) {
        let listener = crate::listeners::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = listener.local_addr().unwrap().port();

        let shutdown = CancellationToken::new();
        let shutdown_for_task = shutdown.clone();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        tokio::spawn(async move {
            // Tests use the documented default upstream timeout (5 s), which
            // maps to the 5 s deadline floor.
            let _ = serve(
                handler,
                listener,
                shutdown_for_task,
                Duration::from_millis(5000),
            )
            .await;
        });

        // Wait for the listener to come up. axum binds inside serve()
        // after spawn returns control to us, so poll briefly.
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        (format!("http://127.0.0.1:{port}"), shutdown)
    }

    fn build_query(name: &str, qtype: ProtoRecordType) -> Vec<u8> {
        let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query({
            let mut q = Query::new();
            q.set_name(ProtoName::from_ascii(name).unwrap())
                .set_query_type(qtype);
            q
        });
        msg.to_bytes().unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_post_authority_hit() {
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = build_query("router.mesh.", ProtoRecordType::A);
        let resp = client
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/dns-message"),
        );
        // RFC 8484 §5.1 + supply-chain hygiene: responses must carry
        // Cache-Control: no-store to prevent intermediate proxies from
        // caching DNS data.
        assert_eq!(
            resp.headers()
                .get("Cache-Control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "DoH responses must carry Cache-Control: no-store"
        );
        let body = resp.bytes().await.unwrap();
        let dns = Message::from_bytes(&body).unwrap();
        assert_eq!(dns.metadata.response_code, ResponseCode::NoError);
        assert!(dns.metadata.authoritative);
        let answers = dns.answers;
        assert_eq!(answers.len(), 1);
        match &answers[0].data {
            RData::A(a) => assert_eq!(a.0.to_string(), "100.64.0.5"),
            other => panic!("expected A, got {other:?}"),
        }

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_get_blocked_returns_nxdomain() {
        let handler = build_handler(
            vec![],
            "0.0.0.0 ads.example.com\n",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let wire = build_query("ads.example.com.", ProtoRecordType::A);
        let dns_param = URL_SAFE_NO_PAD.encode(&wire);
        let url = format!("{base}/dns-query?dns={dns_param}");
        let client = reqwest::Client::builder().build().unwrap();
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.bytes().await.unwrap();
        let dns = Message::from_bytes(&body).unwrap();
        assert_eq!(dns.metadata.response_code, ResponseCode::NXDomain);
        assert!(dns.answers.is_empty());

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_compression_pointer_cycles_are_rejected_in_bounded_work() {
        // Name-decompression safety (docs/security.md): a client-supplied
        // DNS message whose question name is built from compression
        // pointers that can never terminate must be rejected by the parser
        // in bounded work — never a hang, never unbounded allocation.
        //
        // hickory-proto's decoder structurally forbids non-prior pointers:
        // every pointer target must precede the start of the name being
        // decoded (`PointerNotPriorToLabel`), so a self-loop at offset N
        // (N → N) and every possible pointer cycle dies on its FIRST hop,
        // and recursive follows strictly decrease position, bounding total
        // decompression work by the message length. This pins that
        // contract at our attacker-facing seam: hostile bytes must come
        // back as HTTP 400 quickly, and the listener must keep serving
        // well-formed traffic afterwards (no wedged parser state).
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;
        let client = reqwest::Client::builder().build().unwrap();

        // Minimal query header: QDCOUNT=1, question name starts at offset 12.
        let header: &[u8] = &[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let tail: &[u8] = &[0x00, 0x01, 0x00, 0x01]; // QTYPE=A QCLASS=IN
        let hostile = |name_bytes: &[u8]| {
            let mut w = header.to_vec();
            w.extend_from_slice(name_bytes);
            w.extend_from_slice(tail);
            w
        };

        // Leg 1: self-pointer — offset N pointing back to N itself.
        let self_loop = hostile(&[0xC0, 0x0C]);
        // Leg 2: two-node cycle attempt (12→14→12): the first hop's target
        // (14) is not prior to the name start (12), so it is rejected
        // before the second pointer is ever read.
        let two_cycle = hostile(&[0xC0, 0x0E, 0xC0, 0x0C]);
        // Leg 3: forward pointer to offset 255, far past the question it
        // appears in (and beyond this short packet entirely).
        let forward = hostile(&[0xC0, 0xFF]);

        for (label, wire) in [
            ("self-loop", self_loop),
            ("two-node cycle", two_cycle),
            ("forward pointer", forward),
        ] {
            let started = std::time::Instant::now();
            let resp = tokio::time::timeout(
                Duration::from_secs(5),
                client
                    .post(format!("{base}/dns-query"))
                    .header("content-type", "application/dns-message")
                    .body(wire)
                    .send(),
            )
            .await
            .expect(label /* must not hang */);
            let resp = resp.expect("POST completes");
            assert_eq!(
                resp.status(),
                reqwest::StatusCode::BAD_REQUEST,
                "{label} must be rejected as a malformed message"
            );
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "{label} rejection exceeded the bounded-work budget"
            );
        }

        // GET parity: the same self-loop via ?dns= is also 400.
        let dns_param = URL_SAFE_NO_PAD.encode(hostile(&[0xC0, 0x0C]));
        let resp = client
            .get(format!("{base}/dns-query?dns={dns_param}"))
            .send()
            .await
            .expect("GET completes");
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

        // Liveness: after hostile input the listener still serves a valid
        // query end-to-end — proof the rejection was bounded, not a wedge.
        let resp = client
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(build_query("router.mesh.", ProtoRecordType::A))
            .send()
            .await
            .expect("valid query after hostile input");
        assert_eq!(resp.status(), 200);
        let dns = Message::from_bytes(&resp.bytes().await.unwrap()).unwrap();
        assert_eq!(dns.metadata.response_code, ResponseCode::NoError);
        assert_eq!(dns.answers.len(), 1);

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_get_duplicate_dns_param_is_handled_deterministically() {
        // RFC 8484 does not define repeated `dns=` parameters, but proxies
        // and middleboxes sometimes append one. Whatever axum's
        // duplicate-key resolution is (reject / first-wins / last-wins),
        // the pinned contract is: the request either fails as a bad request,
        // or behaves EXACTLY like a single well-formed query for the name in
        // the FIRST parameter — never a mixed/garbage-derived answer, and
        // never more than one DNS response.
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;
        let client = reqwest::Client::builder().build().unwrap();

        let valid = build_query("router.mesh.", ProtoRecordType::A);
        let mut garbage = vec![0xFFu8; 16]; // undecodable header+question bytes
        garbage[2] = 0x01;
        let dup_url = format!(
            "{base}/dns-query?dns={}&dns={}",
            URL_SAFE_NO_PAD.encode(&valid),
            URL_SAFE_NO_PAD.encode(&garbage),
        );

        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(Duration::from_secs(5), client.get(&dup_url).send())
            .await
            .expect("duplicate-param GET must not hang")
            .expect("GET completes");
        let status = resp.status();
        let _body = resp.bytes().await.unwrap();

        // Observed axum 0.8 / serde_urlencoded behaviour, pinned: a repeated
        // `dns` key is a struct-deserialisation error → Query extractor
        // rejects with 400 BAD_REQUEST before any DNS parsing happens. The
        // request can never execute a payload chosen by duplicate-key
        // resolution.
        assert_eq!(
            status,
            reqwest::StatusCode::BAD_REQUEST,
            "duplicate dns= params must be rejected as malformed"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "duplicate-param handling exceeded the bounded-work budget"
        );

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_rejects_unsupported_methods() {
        // Input hardening: the router registers ONLY GET and POST on
        // /dns-query. PUT/DELETE are rejected by the framework with 405
        // Method Not Allowed — never routed to a handler, so the request
        // body is never parsed as DNS. HEAD is special-cased: axum's
        // MethodRouter serves HEAD through the GET handler (with an empty
        // body), and with no `?dns=` parameter the Query extractor rejects
        // it with 400 — still a rejection before any DNS processing.
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = build_query("router.mesh.", ProtoRecordType::A);
        for method in ["PUT", "DELETE"] {
            let resp = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("{base}/dns-query"),
                )
                .header("content-type", "application/dns-message")
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                reqwest::StatusCode::METHOD_NOT_ALLOWED,
                "{method} must not reach the DNS pipeline"
            );
            // No handler ran, so no DNS response bytes can come back.
            let headers = resp.headers().clone();
            assert_ne!(
                headers.get("content-type").and_then(|v| v.to_str().ok()),
                Some("application/dns-message"),
                "{method} must not produce a DNS response"
            );
        }

        // HEAD rides the GET route; it is refused with 400 on the missing
        // `dns` parameter — rejected before the body could ever be parsed,
        // and no application/dns-message response is produced.
        let resp = client
            .request(reqwest::Method::HEAD, format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "HEAD must not reach the DNS pipeline"
        );
        assert_ne!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/dns-message"),
            "HEAD must not produce a DNS response"
        );

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_rejects_malformed_dns_message() {
        let handler = build_handler(
            vec![],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let client = reqwest::Client::builder().build().unwrap();
        let resp = client
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(b"not a DNS message".to_vec())
            .send()
            .await
            .unwrap();
        // RFC 8484 says implementations may return either a DNS-format
        // FormErr or HTTP 4xx; we return HTTP 400 per a comment in
        // handle_dns_message about not synthesising a FormErr without
        // a parsed header.
        assert_eq!(resp.status(), 400);

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_rejects_empty_post_body() {
        // Zero-length body gets its OWN attribution ("empty DNS message"),
        // distinct from the malformed-wire path - keeps the two rejection
        // layers distinguishable in client-facing errors.
        let handler = build_handler(
            vec![],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let client = reqwest::Client::builder().build().unwrap();
        let resp = client
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(Vec::new())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
        let body = resp.text().await.expect("body text");
        assert!(
            body.contains("empty DNS message"),
            "empty-body errors must be attributed as such, got: {body}"
        );

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_rejects_oversized_post_body() {
        let handler = build_handler(
            vec![],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        // One byte past the ABSOLUTE DNS message ceiling (u16 max wire
        // size), deliberately NOT derived from MAX_DOH_MESSAGE_BYTES so the
        // pin stays discriminating if the constant ever drifts upward.
        let oversized = vec![0u8; 65_536];
        let client = reqwest::Client::builder().build().unwrap();
        let resp = client
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(oversized)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            413,
            "oversized DoH POST must be rejected with 413 Payload Too Large"
        );

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_rejects_non_dns_message_content_types_on_post() {
        // RFC 8484 §6.1: the POST media type is part of the contract. A
        // client that declares any other type — or none — is not sending a
        // DNS message and must get 415 before the body reaches the parser.
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;
        let client = reqwest::Client::new();
        let query = build_query("router.mesh.", ProtoRecordType::A);

        // Wrong types AND a missing header all land on the same rejection.
        for ct in [
            "text/plain",
            "application/json",
            "application/octet-stream",
            "",
        ] {
            let mut req = client.post(format!("{base}/dns-query")).body(query.clone());
            if !ct.is_empty() {
                req = req.header("content-type", ct);
            }
            let resp = req.send().await.unwrap();
            assert_eq!(
                resp.status(),
                reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "content-type {ct:?} must be rejected with 415"
            );
            // And never a DNS-format reply.
            assert_ne!(
                resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok()),
                Some("application/dns-message"),
                "a rejected POST must not produce a DNS response"
            );
        }

        // Control: parameters after the media type are tolerated (MIME rules).
        let ok = client
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message; charset=utf-8")
            .body(query)
            .send()
            .await
            .unwrap();
        assert_ne!(
            ok.status(),
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "media-type parameters must not cause a rejection"
        );

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_rejects_invalid_base64url_get() {
        let handler = build_handler(
            vec![],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let client = reqwest::Client::builder().build().unwrap();
        let resp = client
            .get(format!("{base}/dns-query?dns=*not-base64*"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_get_invalid_base64_is_rejected_before_dns_processing() {
        // The decode-error arm must 400 with the base64-specific message —
        // NOT fall through to the generic empty/malformed-message paths,
        // which would blur which layer rejected the request.
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let client = reqwest::Client::builder().build().unwrap();
        let resp = client
            .get(format!("{base}/dns-query?dns=not%%20base64!!"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
        let body = resp.text().await.expect("body text");
        assert!(
            body.contains("invalid base64url"),
            "decode errors must be attributed to base64, got: {body}"
        );

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_get_without_dns_param_is_rejected() {
        // axum 0.7→0.8 migration pin (d097ffe): the Query<DohQuery>
        // extractor must still reject a parameter-less GET with 400 before
        // any DNS processing — the HEAD leg of the verb-rejection test trips
        // this path indirectly; here it is pinned directly so a silent
        // extractor behaviour change across the migration cannot slip
        // through.
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        let client = reqwest::Client::builder().build().unwrap();
        let resp = client
            .get(format!("{base}/dns-query"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "a GET without ?dns= must be rejected by the extractor"
        );
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok());
        assert_ne!(
            ct,
            Some("application/dns-message"),
            "missing dns= parameter produced a DNS-shaped response"
        );

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn doh_rejects_oversized_base64url_get() {
        // GET/POST parity for the size cap: the decoded `dns=` parameter goes
        // through the same handle_dns_message gate as a POST body, so a
        // valid-base64url payload beyond MAX_DOH_MESSAGE_BYTES must be
        // rejected 413 rather than parsed.
        let handler = build_handler(
            vec![static_a("router.mesh", "100.64.0.5")],
            "",
            vec!["https://127.0.0.1:1/dns-query".to_string()],
            BlockResponse::Nxdomain,
        )
        .await;
        let (base, shutdown) = spawn_doh(handler).await;

        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let oversized = vec![0u8; MAX_DOH_MESSAGE_BYTES + 1];
        let encoded = URL_SAFE_NO_PAD.encode(&oversized);
        let client = reqwest::Client::builder().build().unwrap();
        // The ~87 KiB URL trips transport-layer URI limits BEFORE our handler:
        // reqwest's own builder rejects it client-side. Either shape satisfies
        // the contract — an oversized GET payload is never processed; our
        // shared handle_dns_message gate (>65_535 → 413) still covers moderate
        // sizes for BOTH verbs.
        match client
            .get(format!("{base}/dns-query?dns={encoded}"))
            .send()
            .await
        {
            Err(e) if e.is_builder() => {}
            Err(e) => panic!("unexpected transport error: {e}"),
            Ok(resp) => {
                let status = resp.status();
                assert!(
                    status.is_client_error() || status.is_server_error(),
                    "oversized GET payload must not be processed: {status}"
                );
            }
        }
        shutdown.cancel();
    }
}
