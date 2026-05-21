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
//! The daemon binds privileged ports (53, 853) then drops capabilities.
//! Under systemd the unit enforces `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
//! For non-systemd deployments, the daemon drops capabilities in-process after
//! binding sockets (see the `drop_capabilities` TODO below).
//!
//! # Status
//!
//! Milestone 4 (pending). This binary will be fleshed out once
//! `rustydns-resolver` is complete. The structure, signal handling, and
//! blocklist fetch loop are the next implementation steps.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Set a restrictive umask so any files the daemon create (e.g. log files
    // created before the config is read) are not world-readable by default.
    //
    // Under systemd, UMask=0077 in the service unit provides this guarantee.
    // For non-systemd deployments, add the `nix` crate and call:
    //   nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    // nix::sys::stat::umask is a safe function (umask never fails).
    //
    // TODO (Milestone 4): add `nix` to workspace dependencies and call it here
    // so non-systemd deployments also benefit from the restricted umask.

    // Initialise structured logging before anything else so that all startup
    // errors are captured in the journal.
    init_tracing();

    let config_path = PathBuf::from(
        std::env::args().nth(2).unwrap_or_else(|| "rustydns.toml".to_string()),
    );

    info!(config = %config_path.display(), "rustydnsd starting");

    // --- Security: verify config file permissions before reading ----------
    // A world-readable config file leaks upstream resolver credentials and
    // other sensitive settings. Fail hard rather than warn.
    check_config_permissions(&config_path)?;

    // Load and validate configuration.
    let config = rustydns_core::config::load_config(&config_path)
        .context("failed to load configuration")?;

    info!(
        mesh_zone         = %config.server.mesh_zone,
        protocol          = ?config.upstream.protocol,
        fail_closed       = config.upstream.fail_closed,
        dnssec            = config.upstream.dnssec_validation,
        blocklist_sources = config.blocklist.sources.len(),
        "configuration loaded"
    );

    // --- TODO (Milestone 4): in-process capability dropping ---------------
    // After binding sockets, drop all Linux capabilities except those
    // explicitly needed. Under systemd this is handled by the unit
    // (CapabilityBoundingSet + AmbientCapabilities), but for non-systemd
    // deployments we must do it ourselves:
    //
    //   1. Bind all sockets (port 53 UDP/TCP, port 853 DoT, DoH port).
    //   2. Call prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED | …)
    //      to prevent privilege re-acquisition.
    //   3. Call capset() to drop all capabilities from the effective,
    //      permitted, and inheritable sets.
    //   4. Log the resulting capability state with capget() for auditability.
    //
    // Reference: `caps` crate (https://crates.io/crates/caps)
    // Tracking: implement before Milestone 4 is marked complete.
    // --------------------------------------------------------------------------

    // TODO (Milestone 4):
    // 1. Create CancellationToken for graceful shutdown.
    // 2. Spawn authority (load static zones, open rustynet DB read-only).
    // 3. Create blocklist engine; spawn background fetch + reload task.
    //    Policy: if ALL sources fail on first fetch, abort startup with an
    //    error. If only SOME sources fail, log a warning and continue with
    //    the partial list — this is preferable to refusing all DNS.
    // 4. Build resolver with privacy config.
    // 5. Bind UDP/TCP listeners on config.server.listen addresses.
    // 6. If config.server.dot_listen is set:
    //    a. Load TLS certificate from config.server.tls_cert_path.
    //    b. Load private key from config.server.tls_key_path.
    //    c. Build rustls ServerConfig (TLS 1.3 minimum, no client auth).
    //    d. Bind DoT listener.
    // 7. Spawn DoH axum server on config.server.doh_listen (if set).
    // 8. Spawn metrics axum server on config.metrics.listen.
    //    Bind to loopback only — validate this even if config says otherwise.
    // 9. Drop capabilities (see above).
    // 10. Install SIGHUP handler to trigger blocklist reload.
    // 11. Await shutdown signal (SIGTERM/SIGINT).

    info!("rustydnsd stub running — full daemon implementation pending (Milestone 4)");

    // Keep alive until Ctrl-C for development.
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;

    info!("shutting down");
    Ok(())
}

/// Verify that the configuration file is not world-readable.
///
/// A world-readable config may expose upstream resolver URLs, shared secrets,
/// or node IDs to other users on the system. This check is performed before
/// parsing the file so the error fires even if parsing would fail for other
/// reasons.
///
/// # Errors
///
/// Returns an error if:
/// - The file's metadata cannot be read.
/// - On Unix: the file's mode has any other-read bit (`o+r`) set.
#[cfg(unix)]
fn check_config_permissions(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot stat config file: {}", path.display()))?;
    let mode = metadata.permissions().mode();
    // 0o004 = other-read bit
    if mode & 0o004 != 0 {
        bail!(
            "config file {} is world-readable (mode {:04o}). \
             Fix with: chmod o-r {}",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    // 0o040 = group-read bit — warn but don't abort (group read is acceptable
    // when the group is the restricted 'rustydns' group).
    if mode & 0o040 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{:04o}", mode & 0o777),
            "config file is group-readable; ensure the group is restricted to the rustydns service account"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_config_permissions(_path: &PathBuf) -> Result<()> {
    // Permission checking is Unix-specific. On other platforms we skip it and
    // rely on OS-level access controls.
    Ok(())
}

/// Initialise the tracing subscriber.
///
/// Reads `RUST_LOG` for the log filter (default: `info`).
/// Uses JSON format in release builds (machine-readable for log aggregation)
/// and pretty format in debug builds.
///
/// # Privacy
///
/// The default filter level `info` does not emit query names or client IPs.
/// Setting `RUST_LOG=debug` or `RUST_LOG=trace` may expose query names in
/// log output — use only in development environments, never in production.
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
