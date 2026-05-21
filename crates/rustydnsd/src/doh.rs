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
