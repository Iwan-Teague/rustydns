#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! DNS-over-HTTPS listener (HTTP/2, no TLS — terminate TLS at a reverse proxy).
//!
//! Implements the GET (`?dns=<base64url>`) and POST (`application/dns-message`)
//! forms of RFC 8484. The listener is HTTP/2 only — TLS termination is the
//! reverse proxy's job (per `AGENTS.md`).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
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

use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};
use hickory_server::authority::MessageRequest;
use hickory_server::server::{Protocol, Request, RequestHandler, ResponseHandler, ResponseInfo};

use rustydns_core::RustyDnsError;

use crate::handler::DnsHandler;

const MAX_DOH_MESSAGE_BYTES: usize = 65_535;
const DOH_TIMEOUT: Duration = Duration::from_secs(5);
const DOH_PATH: &str = "/dns-query";

/// Start the DoH listener (HTTP, no TLS) until shutdown.
pub async fn serve(
    handler: Arc<DnsHandler>,
    listen: SocketAddr,
    shutdown: CancellationToken,
) -> Result<(), RustyDnsError> {
    let state = DohState { handler };
    let app = Router::new()
        .route(DOH_PATH, get(handle_get).post(handle_post))
        .with_state(state);

    let listener = TcpListener::bind(listen).await.map_err(RustyDnsError::Io)?;

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

    handle_dns_message(state.handler.clone(), src, decoded).await
}

async fn handle_post(
    State(state): State<DohState>,
    ConnectInfo(src): ConnectInfo<SocketAddr>,
    body: axum::body::Bytes,
) -> Response {
    handle_dns_message(state.handler.clone(), src, body.to_vec()).await
}

async fn handle_dns_message(
    handler: Arc<DnsHandler>,
    src: SocketAddr,
    bytes: Vec<u8>,
) -> Response {
    if bytes.is_empty() {
        return bad_request("empty DNS message");
    }
    if bytes.len() > MAX_DOH_MESSAGE_BYTES {
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(Body::from("DNS message too large"))
            .unwrap();
    }

    let mut decoder = BinDecoder::new(&bytes);
    let message = match MessageRequest::read(&mut decoder) {
        Ok(message) => message,
        Err(e) => {
            // Form errors are a client problem — return HTTP 400 rather
            // than try to synthesise a DNS-format FormErr response
            // (which would require a parsed Header we don't have).
            warn!(src = %src, error = %e, "malformed DNS-over-HTTPS request");
            return bad_request("malformed DNS message");
        }
    };

    let request = Request::new(message, src, Protocol::Https);
    let (tx, rx) = oneshot::channel();
    let response_handler = DohResponseHandler::new(tx);

    handler.handle_request(&request, response_handler).await;

    let response_bytes = match timeout(DOH_TIMEOUT, rx).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return server_error("failed to build DNS response"),
        Err(_) => return server_error("DNS response timed out"),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/dns-message")
        .body(Body::from(response_bytes))
        .unwrap()
}

fn bad_request(message: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(message))
        .unwrap()
}

fn server_error(message: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
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
    async fn send_response<'a>(
        &mut self,
        response: hickory_server::authority::MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut buffer = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buffer);
        encoder.set_max_size(u16::MAX);
        let info = response
            .destructive_emit(&mut encoder)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encode error: {e}")))?;

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

        let mut bl_cfg = BlocklistConfig::default();
        bl_cfg.sources = Vec::new();
        bl_cfg.reload_interval_secs = 0;
        bl_cfg.block_response = block_response;
        let blocklist = Arc::new(BlocklistEngine::new(bl_cfg));
        if !blocklist_lines.is_empty() {
            blocklist.load_trusted(blocklist_lines);
        }

        let mut upstream = UpstreamConfig::default();
        upstream.resolvers = upstream_resolvers;
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
        dns_config.privacy.randomize_upstream_selection = false;
        dns_config.upstream.dnssec_validation = false;

        let resolver = Arc::new(Resolver::new(dns_config).await.unwrap());
        let query_log = Arc::new(crate::query_log::QueryLog::new(64));
        Arc::new(
            DnsHandler::new(
                authority,
                blocklist,
                resolver,
                metrics,
                query_log,
                &[],
            )
            .unwrap(),
        )
    }

    /// Boot a DoH listener on a random port. Returns `(base_url, shutdown_token)`.
    /// Drop the token (or call .cancel()) to stop the listener.
    async fn spawn_doh(handler: Arc<DnsHandler>) -> (String, CancellationToken) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // free the port — serve() will rebind it

        let shutdown = CancellationToken::new();
        let shutdown_for_task = shutdown.clone();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        tokio::spawn(async move {
            let _ = serve(handler, addr, shutdown_for_task).await;
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
        let mut msg = Message::new();
        msg.set_id(0x4242)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
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
            resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/dns-message"),
        );
        let body = resp.bytes().await.unwrap();
        let dns = Message::from_bytes(&body).unwrap();
        assert_eq!(dns.response_code(), ResponseCode::NoError);
        assert!(dns.authoritative());
        let answers = dns.answers();
        assert_eq!(answers.len(), 1);
        match answers[0].data().unwrap() {
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
        assert_eq!(dns.response_code(), ResponseCode::NXDomain);
        assert!(dns.answers().is_empty());

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
}
