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
//! Milestone 4 (in progress). UDP/TCP query pipeline, DoT/DoH listeners,
//! metrics, and blocklist reload are implemented; capability dropping remains TODO.

mod blocklist_loader;
mod handler;
mod doh;
mod metrics;

use anyhow::{Context, Result, bail, anyhow};
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use hickory_server::server::ServerFuture;

use blocklist_loader::BlocklistLoader;
use handler::DnsHandler;
use doh as doh_server;
use metrics::Metrics;
use rustydns_authority::Authority;
use rustydns_blocklist::BlocklistEngine;
use rustydns_resolver::Resolver;
use rustydns_core::config::{MetricsConfig, ServerConfig};
use rustls::ServerConfig as TlsServerConfig;
use rustls_pemfile as pemfile;

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

    let args = parse_args()?;
    let config_path = PathBuf::from(&args.config_path);

    info!(config = %config_path.display(), "rustydnsd starting");

    // --- Security: verify config file permissions before reading ----------
    // A world-readable config file leaks upstream resolver credentials and
    // other sensitive settings. Fail hard rather than warn.
    check_config_permissions(&config_path)?;

    // Load and validate configuration.
    let config = rustydns_core::config::load_config(&config_path)
        .context("failed to load configuration")?;

    // `--validate-config`: stop here. We've already parsed the file and
    // run `validate_config` (inside `load_config`). Exit 0 to signal
    // success to the install script or CI step that invoked us.
    if args.validate_only {
        info!("configuration validated — exiting (--validate-config)");
        return Ok(());
    }

    let config = Arc::new(config);

    let metrics = Arc::new(Metrics::new()?);

    info!(
        mesh_zone         = %config.server.mesh_zone,
        protocol          = ?config.upstream.protocol,
        fail_closed       = config.upstream.fail_closed,
        dnssec            = config.upstream.dnssec_validation,
        blocklist_sources = config.blocklist.sources.len(),
        "configuration loaded"
    );

    // Build authority (mesh integration is best-effort — failures are
    // logged at warn! inside Authority::new and the daemon continues in
    // static-only mode).
    let authority = Arc::new(Authority::new(config.authority.clone())?);
    // Seed the mesh-records gauge from the initial snapshot. If the
    // initial mesh load failed this will be 0 and the next successful
    // reload will populate it. The `_success_total` counter is left at
    // 0 — we only count *reloads*, not the initial load, so dashboards
    // can distinguish reload errors from a never-loaded daemon.
    let initial_mesh_records = authority.mesh_record_count();
    if initial_mesh_records > 0 {
        metrics.mark_mesh_zone_reload_success(initial_mesh_records);
    }

    // Blocklist engine + initial load.
    let blocklist_engine = Arc::new(BlocklistEngine::new(config.blocklist.clone()));
    let blocklist_config = Arc::new(config.blocklist.clone());
    let blocklist_loader = Arc::new(BlocklistLoader::new(blocklist_config.clone())?);
    match blocklist_loader.reload(&blocklist_engine).await {
        Ok(summary) => {
            if summary.loaded_sources == 0 {
                metrics.mark_blocklist_reload_failure();
            } else {
                metrics.mark_blocklist_reload_success();
            }
            metrics.set_blocklist_state(blocklist_engine.entry_count(), blocklist_engine.heap_bytes());
        }
        Err(e) => {
            metrics.mark_blocklist_reload_failure();
            warn!(error = %e, "initial blocklist load failed; continuing with existing state");
        }
    }

    // Resolver (DoH/DoQ upstream).
    let resolver = Arc::new(Resolver::new((*config).clone()).await?);

    // Build request handler and server.
    let handler = DnsHandler::new(authority.clone(), blocklist_engine.clone(), resolver, metrics.clone())?;
    let doh_handler = Arc::new(handler.clone());
    let mut server = ServerFuture::new(handler);

    for addr in &config.server.listen {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("failed to bind UDP socket on {addr}"))?;
        server.register_socket(udp);

        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind TCP listener on {addr}"))?;
        server.register_listener(tcp, Duration::from_secs(5));

        info!(listen = %addr, "listening for DNS queries");
    }

    // --- Capability discipline -------------------------------------------
    // All privileged ports are bound. We no longer need
    // CAP_NET_BIND_SERVICE or any other capability for the lifetime of
    // the daemon. Drop everything so a future bug or compromise can't
    // re-bind privileged ports or escalate privileges.
    //
    // Under systemd this is belt-and-braces (the unit already pins the
    // capability bounding set). For non-systemd deployments (Docker,
    // runit, OpenRC) this is the only enforcement.
    //
    // Non-fatal: a failure to drop is logged at warn! and the daemon
    // continues. The systemd-level bounding set is the primary defence
    // in supported deployments; we never refuse to serve DNS because
    // capability dropping failed.
    drop_capabilities();

    if let Some(dot_listen) = &config.server.dot_listen {
        // TODO: enable DoT listener once hickory-server upgrades to
        // rustls 0.23. hickory-server 0.24 pins rustls 0.21 internally
        // while the rest of our workspace uses rustls 0.23 (axum,
        // reqwest), and bridging the two ServerConfig types isn't
        // worthwhile for a single listener. For now, run DoT behind a
        // TLS-terminating reverse proxy that forwards to the plain TCP
        // listener.
        let _ = load_tls_config; // silence dead_code if compiled
        bail!(
            "server.dot_listen `{dot_listen}` requested but DoT is not yet supported in-process \
             (blocked on hickory-server rustls 0.21 → 0.23 upgrade). Remove dot_listen from the \
             config, or terminate TLS at a reverse proxy and forward to the plain TCP listener."
        );
    }

    let shutdown = CancellationToken::new();

    if let Some(doh_listen) = &config.server.doh_listen {
        if let Ok(addr) = doh_listen.parse::<SocketAddr>() {
            if !addr.ip().is_loopback() {
                warn!(listen = %doh_listen, "DoH listener is not loopback; ensure a TLS reverse proxy and access controls are in place");
            }
            spawn_doh_server(doh_handler, addr, shutdown.clone());
        } else {
            bail!("server.doh_listen `{}` is not a valid socket address", doh_listen);
        }
    }
    spawn_blocklist_reload_loop(
        blocklist_loader.clone(),
        blocklist_engine.clone(),
        metrics.clone(),
        config.blocklist.reload_interval_secs,
        shutdown.clone(),
    );
    spawn_sighup_reload(
        blocklist_loader,
        blocklist_engine,
        authority.clone(),
        metrics.clone(),
        shutdown.clone(),
    );
    spawn_mesh_reload_loop(
        authority.clone(),
        metrics.clone(),
        config.authority.poll_interval_secs,
        shutdown.clone(),
    );

    let metrics_addr = metrics_listen_addr(&config.metrics)?;
    let metrics_path = normalize_metrics_path(&config.metrics.path);
    spawn_metrics_server(metrics.clone(), metrics_addr, metrics_path, shutdown.clone());

    wait_for_shutdown_signal().await?;
    shutdown.cancel();
    server
        .shutdown_gracefully()
        .await
        .context("server shutdown failed")?;

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

    // PRIVACY: by default the hickory crates can emit qnames at info
    // level. We clamp them to `warn` UNLESS the operator has explicitly
    // set their level via RUST_LOG (in which case they're knowingly
    // opting into more verbose logging for debugging).
    //
    // Filter composition: start with `info` so the daemon's own logs
    // appear, then apply any user RUST_LOG directives on top, then
    // pin the hickory crates to `warn` if the user hasn't overridden them.
    let user_filter = std::env::var("RUST_LOG").unwrap_or_default();
    let mut filter = EnvFilter::new("info");
    for directive in user_filter.split(',').filter(|s| !s.trim().is_empty()) {
        if let Ok(d) = directive.parse() {
            filter = filter.add_directive(d);
        }
    }
    for crate_name in ["hickory_server", "hickory_proto", "hickory_resolver"] {
        if !user_filter.contains(crate_name) {
            if let Ok(d) = format!("{crate_name}=warn").parse() {
                filter = filter.add_directive(d);
            }
        }
    }

    #[cfg(debug_assertions)]
    let fmt_layer = fmt::layer().pretty();

    #[cfg(not(debug_assertions))]
    let fmt_layer = fmt::layer().json();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

/// Parsed command-line arguments.
#[derive(Debug)]
struct CliArgs {
    config_path: String,
    /// `--validate-config`: load config, run validation, exit. Never
    /// binds sockets. Useful in deployment checklists and CI.
    validate_only: bool,
}

fn parse_args() -> Result<CliArgs> {
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut config_path = "rustydns.toml".to_string();
    let mut validate_only = false;

    while i < argv.len() {
        match argv[i].as_str() {
            "--config" => {
                i += 1;
                if i >= argv.len() {
                    bail!("--config requires a path argument");
                }
                config_path = argv[i].clone();
            }
            "--validate-config" => validate_only = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("rustydnsd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => bail!("unknown argument `{other}` (try --help)"),
        }
        i += 1;
    }

    Ok(CliArgs {
        config_path,
        validate_only,
    })
}

fn print_help() {
    let exe = std::env::args()
        .next()
        .unwrap_or_else(|| "rustydnsd".to_string());
    println!(
        "rustydnsd — mesh-native DNS resolver and ad blocker

USAGE:
    {exe} [OPTIONS]

OPTIONS:
    --config <PATH>       Path to rustydns.toml (default: ./rustydns.toml)
    --validate-config     Load and validate the config, then exit 0 if it
                          parses cleanly and passes every invariant in
                          AGENTS.md. Sockets are never bound. Exit 1 on
                          validation failure. Useful in install scripts
                          and CI.
    -V, --version         Print version and exit.
    -h, --help            Show this help and exit.

ENVIRONMENT:
    RUST_LOG              Override log filter. Default is `info` with the
                          hickory crates clamped to `warn` for privacy.
                          Setting this opts in to deeper diagnostics —
                          qnames may appear at `debug` level."
    );
}

fn spawn_blocklist_reload_loop(
    loader: Arc<BlocklistLoader>,
    engine: Arc<BlocklistEngine>,
    metrics: Arc<Metrics>,
    interval_secs: u64,
    shutdown: CancellationToken,
) {
    if interval_secs == 0 {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match loader.reload(&engine).await {
                        Ok(summary) => {
                            if summary.loaded_sources == 0 {
                                metrics.mark_blocklist_reload_failure();
                            } else {
                                metrics.mark_blocklist_reload_success();
                            }
                            metrics.set_blocklist_state(engine.entry_count(), engine.heap_bytes());
                        }
                        Err(e) => {
                            metrics.mark_blocklist_reload_failure();
                            warn!(error = %e, "blocklist reload failed");
                        }
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
    });
}

fn spawn_sighup_reload(
    loader: Arc<BlocklistLoader>,
    engine: Arc<BlocklistEngine>,
    authority: Arc<Authority>,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
) {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};

        let mut hup = match signal(SignalKind::hangup()) {
            Ok(sig) => sig,
            Err(e) => {
                warn!(error = %e, "failed to register SIGHUP handler");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = hup.recv() => {
                    info!("SIGHUP received — reloading blocklists");
                    match loader.reload(&engine).await {
                        Ok(summary) => {
                            if summary.loaded_sources == 0 {
                                metrics.mark_blocklist_reload_failure();
                            } else {
                                metrics.mark_blocklist_reload_success();
                            }
                            metrics.set_blocklist_state(engine.entry_count(), engine.heap_bytes());
                        }
                        Err(e) => {
                            metrics.mark_blocklist_reload_failure();
                            warn!(error = %e, "blocklist reload failed");
                        }
                    }
                    // Also reload the mesh-zone bundle on SIGHUP so
                    // operators get a single reload trigger for both.
                    match authority.reload_mesh() {
                        Ok(Some(n)) => {
                            metrics.mark_mesh_zone_reload_success(n);
                            info!(mesh_records = n, "mesh zone reloaded on SIGHUP");
                        }
                        Ok(None) => {}
                        Err(e) => {
                            metrics.mark_mesh_zone_reload_failure();
                            warn!(error = %e, "mesh zone reload failed");
                        }
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
    });

    #[cfg(not(unix))]
    {
        let _ = (loader, engine, authority, metrics, shutdown);
    }
}

/// Periodically re-read the Rustynet mesh-zone bundle and atomically
/// swap it into the authority. Bundle-load failures are non-fatal —
/// the previous snapshot continues to serve queries.
fn spawn_mesh_reload_loop(
    authority: Arc<Authority>,
    metrics: Arc<Metrics>,
    interval_secs: u64,
    shutdown: CancellationToken,
) {
    if interval_secs == 0 {
        return;
    }
    // Skip the poller entirely if the bundle isn't configured — saves
    // a sleeping task in static-only deployments.
    if authority.config().mesh_zone_bundle_path.is_none() {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // skip the immediate first tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match authority.reload_mesh() {
                        Ok(Some(n)) => {
                            metrics.mark_mesh_zone_reload_success(n);
                            tracing::debug!(mesh_records = n, "mesh zone reloaded");
                        }
                        Ok(None) => {}
                        Err(e) => {
                            metrics.mark_mesh_zone_reload_failure();
                            warn!(error = %e, "mesh zone reload failed; keeping previous snapshot");
                        }
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
    });
}

fn spawn_metrics_server(
    metrics: Arc<Metrics>,
    listen: SocketAddr,
    path: String,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        if let Err(e) = metrics::serve(metrics, listen, path, shutdown).await {
            warn!(error = %e, "metrics server failed");
        }
    });
}

fn spawn_doh_server(
    handler: Arc<DnsHandler>,
    listen: SocketAddr,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        if let Err(e) = doh_server::serve(handler, listen, shutdown).await {
            warn!(error = %e, "DoH server failed");
        }
    });
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate())
            .context("failed to register SIGTERM handler")?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to listen for ctrl-c")?;
    }

    Ok(())
}

fn metrics_listen_addr(metrics: &MetricsConfig) -> Result<SocketAddr> {
    let addr: SocketAddr = metrics.listen.parse().map_err(|_| {
        anyhow!("metrics.listen `{}` is not a valid socket address", metrics.listen)
    })?;

    if addr.ip().is_loopback() {
        return Ok(addr);
    }

    warn!(
        listen = %metrics.listen,
        "metrics.listen is not loopback; forcing loopback to avoid public exposure"
    );

    let loopback_ip = match addr.ip() {
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };

    Ok(SocketAddr::new(loopback_ip, addr.port()))
}

fn normalize_metrics_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/metrics".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Drop every Linux capability from every set after the daemon has
/// finished binding privileged ports.
///
/// Called once at startup, after the UDP/TCP listeners are bound. From
/// that point on the daemon needs no special privileges — it just
/// reads, decodes, and writes DNS messages on already-bound sockets.
/// Dropping caps means a later code-injection bug, dependency CVE, or
/// kernel-side capability check can't be used to re-bind privileged
/// ports or escalate to other privileged operations.
///
/// Per `AGENTS.md §Operational invariants`, failure is logged at
/// `warn!` but never aborts startup — the systemd unit's
/// `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` is the primary defence
/// in supported deployments, and we never refuse to serve DNS because
/// of a defence-in-depth measure failing.
#[cfg(target_os = "linux")]
fn drop_capabilities() {
    use caps::{CapSet, Capability};

    // Snapshot caps we hold before dropping, for the audit log.
    let before = caps::read(None, CapSet::Effective)
        .map(|set| {
            set.iter()
                .map(Capability::to_string)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|e| format!("<read failed: {e}>"));

    let sets = [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Bounding,
    ];

    for set in sets {
        if let Err(e) = caps::clear(None, set) {
            warn!(
                set = ?set,
                error = %e,
                "failed to clear capability set; continuing — systemd CapabilityBoundingSet \
                 is the primary defence and daemon operation is unaffected"
            );
        }
    }

    // Confirm by re-reading.
    let after = caps::read(None, CapSet::Effective)
        .map(|set| {
            if set.is_empty() {
                "<empty>".to_string()
            } else {
                set.iter()
                    .map(Capability::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        })
        .unwrap_or_else(|e| format!("<read failed: {e}>"));

    info!(
        before = %before,
        after  = %after,
        "capability dropping complete"
    );
}

/// No-op on non-Linux platforms. macOS dev builds, FreeBSD ports, etc.
/// rely on OS-level access controls instead of Linux capabilities.
#[cfg(not(target_os = "linux"))]
fn drop_capabilities() {
    info!(
        target_os = std::env::consts::OS,
        "capability dropping not applicable on this platform — relying on OS access controls"
    );
}

fn load_tls_config(server: &ServerConfig) -> Result<Arc<TlsServerConfig>> {
    let cert_path = server.tls_cert_path.as_ref().ok_or_else(|| {
        anyhow!("server.tls_cert_path must be set when server.dot_listen is enabled")
    })?;
    let key_path = server.tls_key_path.as_ref().ok_or_else(|| {
        anyhow!("server.tls_key_path must be set when server.dot_listen is enabled")
    })?;

    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("failed to open TLS certificate {cert_path:?}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read TLS certificate {cert_path:?}"))?;
    if certs.is_empty() {
        bail!("TLS certificate {cert_path:?} contains no certificates");
    }

    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("failed to open TLS private key {key_path:?}"))?;
    let mut key_reader = BufReader::new(key_file);
    let key = pemfile::private_key(&mut key_reader)
        .with_context(|| format!("failed to read TLS private key {key_path:?}"))?;
    let key = key.ok_or_else(|| anyhow!("TLS private key {key_path:?} contains no key"))?;

    let config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("invalid TLS key or certificate: {e}"))?;

    Ok(Arc::new(config))
}
