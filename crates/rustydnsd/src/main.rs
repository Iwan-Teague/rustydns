#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! `rustydnsd` — the rustydns daemon binary.
//!
//! Wires together:
//! - [`rustydns_authority`] — authoritative zone server (mesh + static zones)
//! - [`rustydns_blocklist`] — ad/tracker blocklist engine
//! - [`rustydns_resolver`] — DoH/DoQ upstream resolver
//!
//! # Query pipeline
//!
//! ```text
//! client (UDP/TCP/DoT/DoH)
//!   → Listener
//!   → Authority  (mesh zone or static zone hit? → answer immediately)
//!   → Blocklist  (domain on blocklist? → NXDOMAIN/sinkhole/REFUSED)
//!   → Resolver   (DoH/DoQ upstream; SERVFAIL if all fail and fail_closed=true)
//! ```
//!
//! # Signal handling
//!
//! - `SIGHUP`  — reload config and blocklist sources (no restart required).
//! - `SIGTERM` / `SIGINT` — graceful shutdown (drain in-flight queries, close listeners).
//!
//! # Privilege model
//!
//! The daemon binds privileged ports (53, 853) and then drops all capabilities
//! except `CAP_NET_BIND_SERVICE` (Linux). On startup it verifies it is running
//! as the `rustydns` user (or a non-root user in development mode).
//!
//! # Status
//!
//! Milestone 4 (pending). This binary will be fleshed out once `rustydns-resolver`
//! is complete. The structure, signal handling, and blocklist fetch loop are
//! the next implementation steps.

use anyhow::{Context, Result};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise structured logging.
    // In production: JSON format, env-filter controlled by RUST_LOG.
    // In development: pretty format for readability.
    init_tracing();

    let config_path = std::path::PathBuf::from(
        std::env::args().nth(2).unwrap_or_else(|| "rustydns.toml".to_string()),
    );

    info!(config = %config_path.display(), "rustydnsd starting");

    // Load and validate configuration.
    let config = rustydns_core::config::load_config(&config_path)
        .context("failed to load configuration")?;

    info!(
        mesh_zone  = %config.server.mesh_zone,
        protocol   = ?config.upstream.protocol,
        fail_closed = config.upstream.fail_closed,
        dnssec     = config.upstream.dnssec_validation,
        blocklist_sources = config.blocklist.sources.len(),
        "configuration loaded"
    );

    // TODO (Milestone 4):
    // 1. Create CancellationToken for graceful shutdown.
    // 2. Spawn authority (load static zones, open rustynet DB read-only).
    // 3. Create blocklist engine; spawn background fetch + reload task.
    // 4. Build resolver with privacy config.
    // 5. Bind UDP/TCP listeners on config.server.listen addresses.
    // 6. Optionally bind DoT listener on config.server.dot_listen.
    // 7. Spawn DoH axum server on config.server.doh_listen.
    // 8. Spawn metrics axum server on config.metrics.listen.
    // 9. Install SIGHUP handler to trigger blocklist reload.
    // 10. Await shutdown signal (SIGTERM/SIGINT).

    info!("rustydnsd stub running — full daemon implementation pending (Milestone 4)");

    // Keep alive until Ctrl-C for development.
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;

    info!("shutting down");
    Ok(())
}

/// Initialise the tracing subscriber.
///
/// Reads `RUST_LOG` for the log filter (default: `info`).
/// Uses JSON format in release builds (machine-readable for log aggregation)
/// and pretty format in debug builds.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(debug_assertions)]
    let fmt_layer = fmt::layer().pretty();

    #[cfg(not(debug_assertions))]
    let fmt_layer = fmt::layer().json();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}
