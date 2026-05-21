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
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Serve the Prometheus metrics endpoint until shutdown.
pub async fn serve(
    metrics: Arc<Metrics>,
    listen: SocketAddr,
    path: String,
    shutdown: CancellationToken,
) -> Result<(), RustyDnsError> {
    let metrics_clone = metrics.clone();
    let app = Router::new()
        .route(&path, get(move || metrics_handler(metrics_clone.clone())))
        // Liveness endpoint for orchestrators (k8s, runit, systemd's
        // ExecStartPost healthcheck wrappers). 200 OK means the daemon
        // process is up and its loopback listener is serving — it
        // doesn't claim anything about upstream resolver reachability
        // or blocklist freshness (those are visible on /metrics).
        .route("/health", get(health_handler));

    let listener = TcpListener::bind(listen)
        .await
        .map_err(RustyDnsError::Io)?;

    info!(listen = %listen, metrics_path = %path, health_path = "/health", "metrics listener started");

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
