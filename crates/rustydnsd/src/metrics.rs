#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use rustydns_core::RustyDnsError;

use crate::query_log::QueryLog;

/// Prometheus metrics registry and counters for rustydnsd.
pub struct Metrics {
    registry: Registry,
    dns_queries_total: IntCounter,
    authority_hits_total: IntCounter,
    blocklist_hits_total: IntCounter,
    resolver_queries_total: IntCounter,
    resolver_failures_total: IntCounter,
    blocklist_reload_success_total: IntCounter,
    blocklist_reload_failure_total: IntCounter,
    blocklist_entries: IntGauge,
    blocklist_heap_bytes: IntGauge,
    blocklist_last_reload: IntGauge,
    mesh_records: IntGauge,
    mesh_zone_reload_success_total: IntCounter,
    mesh_zone_reload_failure_total: IntCounter,
    mesh_zone_last_reload: IntGauge,
    policy_blocklist_bypass_total: IntCounter,
    policy_zone_denied_total: IntCounter,
}

impl Metrics {
    /// Build a new metrics registry with rustydns counters and gauges.
    pub fn new() -> Result<Self, RustyDnsError> {
        let registry = Registry::new();

        let dns_queries_total = register_counter(
            &registry,
            "rustydns_dns_queries_total",
            "Total DNS queries received",
        )?;
        let authority_hits_total = register_counter(
            &registry,
            "rustydns_authority_hits_total",
            "Authority lookups that returned a result",
        )?;
        let blocklist_hits_total = register_counter(
            &registry,
            "rustydns_blocklist_hits_total",
            "Queries blocked by the blocklist",
        )?;
        let resolver_queries_total = register_counter(
            &registry,
            "rustydns_resolver_queries_total",
            "Queries forwarded to upstream resolvers",
        )?;
        let resolver_failures_total = register_counter(
            &registry,
            "rustydns_resolver_failures_total",
            "Resolver failures returned as SERVFAIL",
        )?;
        let blocklist_reload_success_total = register_counter(
            &registry,
            "rustydns_blocklist_reload_success_total",
            "Successful blocklist reloads",
        )?;
        let blocklist_reload_failure_total = register_counter(
            &registry,
            "rustydns_blocklist_reload_failure_total",
            "Failed blocklist reloads",
        )?;

        let blocklist_entries = register_gauge(
            &registry,
            "rustydns_blocklist_entries",
            "Current blocklist entry count",
        )?;
        let blocklist_heap_bytes = register_gauge(
            &registry,
            "rustydns_blocklist_heap_bytes",
            "Estimated blocklist heap usage in bytes",
        )?;
        let blocklist_last_reload = register_gauge(
            &registry,
            "rustydns_blocklist_last_reload_seconds",
            "Unix timestamp of the most recent blocklist reload",
        )?;

        let mesh_records = register_gauge(
            &registry,
            "rustydns_mesh_records",
            "Current mesh-zone record count loaded from the Rustynet bundle",
        )?;
        let mesh_zone_reload_success_total = register_counter(
            &registry,
            "rustydns_mesh_zone_reload_success_total",
            "Successful mesh-zone bundle reloads",
        )?;
        let mesh_zone_reload_failure_total = register_counter(
            &registry,
            "rustydns_mesh_zone_reload_failure_total",
            "Mesh-zone bundle reloads that failed verification or parsing",
        )?;
        let mesh_zone_last_reload = register_gauge(
            &registry,
            "rustydns_mesh_zone_last_reload_seconds",
            "Unix timestamp of the most recent mesh-zone reload attempt",
        )?;

        let policy_blocklist_bypass_total = register_counter(
            &registry,
            "rustydns_policy_blocklist_bypass_total",
            "Queries for which a [[policy]] entry's blocklist_bypass=true \
             skipped the blocklist check",
        )?;
        let policy_zone_denied_total = register_counter(
            &registry,
            "rustydns_policy_zone_denied_total",
            "Queries refused with REFUSED because they fell outside a \
             [[policy]] entry's zones_allowed list",
        )?;

        Ok(Self {
            registry,
            dns_queries_total,
            authority_hits_total,
            blocklist_hits_total,
            resolver_queries_total,
            resolver_failures_total,
            blocklist_reload_success_total,
            blocklist_reload_failure_total,
            blocklist_entries,
            blocklist_heap_bytes,
            blocklist_last_reload,
            mesh_records,
            mesh_zone_reload_success_total,
            mesh_zone_reload_failure_total,
            mesh_zone_last_reload,
            policy_blocklist_bypass_total,
            policy_zone_denied_total,
        })
    }

    /// Increment total DNS queries counter.
    pub fn inc_queries(&self) {
        self.dns_queries_total.inc();
    }

    /// Increment authority hit counter.
    pub fn inc_authority_hits(&self) {
        self.authority_hits_total.inc();
    }

    /// Increment blocklist hit counter.
    pub fn inc_blocklist_hits(&self) {
        self.blocklist_hits_total.inc();
    }

    /// Increment resolver query counter.
    pub fn inc_resolver_queries(&self) {
        self.resolver_queries_total.inc();
    }

    /// Increment resolver failure counter.
    pub fn inc_resolver_failures(&self) {
        self.resolver_failures_total.inc();
    }

    /// Record a successful blocklist reload and timestamp it.
    pub fn mark_blocklist_reload_success(&self) {
        self.blocklist_reload_success_total.inc();
        self.set_blocklist_last_reload();
    }

    /// Record a failed blocklist reload and timestamp it.
    pub fn mark_blocklist_reload_failure(&self) {
        self.blocklist_reload_failure_total.inc();
        self.set_blocklist_last_reload();
    }

    /// Update gauges for blocklist state.
    pub fn set_blocklist_state(&self, entries: usize, heap_bytes: usize) {
        self.blocklist_entries.set(entries as i64);
        self.blocklist_heap_bytes.set(heap_bytes as i64);
    }

    fn set_blocklist_last_reload(&self) {
        self.blocklist_last_reload.set(now_unix_secs());
    }

    /// Record a successful mesh-zone bundle reload and update gauges.
    pub fn mark_mesh_zone_reload_success(&self, record_count: usize) {
        self.mesh_zone_reload_success_total.inc();
        self.mesh_records.set(record_count as i64);
        self.mesh_zone_last_reload.set(now_unix_secs());
    }

    /// Record a failed mesh-zone bundle reload (signature mismatch,
    /// stale bundle, I/O error). The previous mesh_records gauge value
    /// is intentionally NOT zeroed — the daemon is still serving from
    /// the previous valid snapshot.
    pub fn mark_mesh_zone_reload_failure(&self) {
        self.mesh_zone_reload_failure_total.inc();
        self.mesh_zone_last_reload.set(now_unix_secs());
    }

    /// Increment when a `[[policy]]` entry's `blocklist_bypass = true`
    /// caused the daemon to skip the blocklist for a query.
    pub fn inc_policy_blocklist_bypass(&self) {
        self.policy_blocklist_bypass_total.inc();
    }

    /// Increment when a query was refused with `REFUSED` because it
    /// fell outside the matching `[[policy]]` entry's `zones_allowed`.
    pub fn inc_policy_zone_denied(&self) {
        self.policy_zone_denied_total.inc();
    }
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Serve the Prometheus metrics, health, and (loopback-only) query
/// inspection endpoints until shutdown.
///
/// # Privacy
///
/// All three routes are bound to the same loopback listener (caller
/// enforces this in `metrics_listen_addr`). The `/queries` endpoint
/// exposes the in-memory query ring buffer but only with
/// **hashed** qnames and **anonymised** client identifiers — no raw
/// QNAMEs or full IPs ever cross this boundary. See `query_log.rs`
/// for the rationale.
pub async fn serve(
    metrics: Arc<Metrics>,
    query_log: Arc<QueryLog>,
    listen: SocketAddr,
    path: String,
    shutdown: CancellationToken,
) -> Result<(), RustyDnsError> {
    let metrics_clone = metrics.clone();
    let query_log_clone = query_log.clone();
    let app = Router::new()
        .route(&path, get(move || metrics_handler(metrics_clone.clone())))
        // Liveness endpoint for orchestrators (k8s, runit, systemd's
        // ExecStartPost healthcheck wrappers). 200 OK means the daemon
        // process is up and its loopback listener is serving — it
        // doesn't claim anything about upstream resolver reachability
        // or blocklist freshness (those are visible on /metrics).
        .route("/health", get(health_handler))
        // Operator inspection of the in-memory query ring buffer.
        // Exposes ONLY hashed qnames + anonymised client identifiers.
        .route("/queries", get(move || queries_handler(query_log_clone.clone())));

    let listener = TcpListener::bind(listen)
        .await
        .map_err(RustyDnsError::Io)?;

    info!(
        listen = %listen,
        metrics_path = %path,
        health_path = "/health",
        queries_path = "/queries",
        "metrics listener started"
    );

    // `with_graceful_shutdown` requires a 'static future. Move the
    // cancellation token into an owned async block so it outlives the
    // borrow.
    let shutdown_signal = async move { shutdown.cancelled().await };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|e| RustyDnsError::Config(format!("metrics server error: {e}")))
}

async fn metrics_handler(metrics: Arc<Metrics>) -> Response {
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        warn!(error = %e, "failed to encode metrics");
        return Response::builder()
            .status(500)
            .body(Body::from("metrics encoding error"))
            .unwrap();
    }

    Response::builder()
        .status(200)
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .unwrap()
}

async fn health_handler() -> Response {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Body::from("{\"status\":\"ok\"}"))
        .unwrap()
}

/// Render the query ring buffer as JSON. Newest entry first. Hand-rolls
/// the JSON so we don't pull `serde_json` in just for this endpoint —
/// every field is a primitive or a known-ASCII string.
async fn queries_handler(query_log: Arc<QueryLog>) -> Response {
    let entries = query_log.snapshot();
    let mut out = String::with_capacity(64 + entries.len() * 128);
    out.push_str(&format!(
        "{{\"capacity\":{},\"count\":{},\"entries\":[",
        query_log.capacity(),
        entries.len()
    ));
    for (idx, e) in entries.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"ts\":{},\"client\":\"{}\",\"qname_hash\":\"{:016x}\",\"qtype\":\"{}\",\"rcode\":{},\"served_by\":\"{}\"}}",
            e.timestamp_unix,
            json_escape(e.client_anonymised.as_str()),
            e.qname_hash,
            e.qtype,
            e.rcode,
            e.served_by.as_str()
        ));
    }
    out.push_str("]}");

    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Body::from(out))
        .unwrap()
}

/// Escape the small set of JSON-significant characters that
/// `ClientId::anonymized` could theoretically produce. In practice
/// the output is `<ip>/<prefix>/anon` which never contains any of
/// these — this is belt-and-braces for the case where the underlying
/// formatter changes.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_log::{QueryLog, ServedBy};
    use rustydns_core::client::ClientId;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test(flavor = "current_thread")]
    async fn queries_handler_emits_well_formed_json() {
        let log = Arc::new(QueryLog::new(4));
        let client = ClientId::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
        log.record(&client, "router.mesh.", "A", 0, ServedBy::Authority);
        log.record(&client, "ads.example.com.", "A", 3, ServedBy::Blocklist);

        let resp = queries_handler(log.clone()).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        // Extract the body. Axum 0.7 wraps Body as a stream; collect()
        // returns Bytes for known-bounded bodies like ours.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body collect");
        let body = std::str::from_utf8(&body).expect("utf-8 body");

        // Capacity + count are present and correct.
        assert!(body.contains("\"capacity\":4"));
        assert!(body.contains("\"count\":2"));
        // Newest-first ordering: blocklist entry comes before authority entry.
        let pos_block = body.find("\"served_by\":\"blocklist\"").expect("blocklist");
        let pos_auth = body.find("\"served_by\":\"authority\"").expect("authority");
        assert!(pos_block < pos_auth, "newest-first ordering violated");
        // Anonymised client is present and NOT the raw IP.
        assert!(body.contains("10.0.0.0/16/anon"));
        assert!(!body.contains("10.0.0.7"), "raw IP leaked into /queries");
        // qname_hash field is a 16-char hex string.
        assert!(body.contains("\"qname_hash\":\""));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn health_handler_returns_200_ok_json() {
        let resp = health_handler().await;
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"{\"status\":\"ok\"}");
    }
}

fn register_counter(
    registry: &Registry,
    name: &str,
    help: &str,
) -> Result<IntCounter, RustyDnsError> {
    let counter = IntCounter::new(name, help)
        .map_err(|e| RustyDnsError::Config(format!("metrics error: {e}")))?;
    registry
        .register(Box::new(counter.clone()))
        .map_err(|e| RustyDnsError::Config(format!("metrics error: {e}")))?;
    Ok(counter)
}

fn register_gauge(
    registry: &Registry,
    name: &str,
    help: &str,
) -> Result<IntGauge, RustyDnsError> {
    let gauge = IntGauge::new(name, help)
        .map_err(|e| RustyDnsError::Config(format!("metrics error: {e}")))?;
    registry
        .register(Box::new(gauge.clone()))
        .map_err(|e| RustyDnsError::Config(format!("metrics error: {e}")))?;
    Ok(gauge)
}
