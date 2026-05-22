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
//! - `SIGHUP`  — re-read blocklist sources AND the signed mesh-zone
//!   bundle. Does NOT re-read `rustydns.toml` itself: listener
//!   addresses, upstream resolvers, TLS material, and per-client
//!   policies are fixed for the lifetime of the process. Restart the
//!   daemon (systemd `restart`, `docker compose restart`, etc.) to
//!   change anything else.
//! - `SIGTERM` / `SIGINT` — graceful shutdown (drain in-flight queries, close listeners).
//!
//! # Privilege model
//!
//! The daemon binds privileged ports (53, 853) then drops capabilities.
//! Under systemd the unit enforces `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
//! For non-systemd deployments, the daemon drops capabilities in-process
//! after binding sockets via [`drop_capabilities`] (Linux-only; no-op on
//! other targets).
//!
//! # Status
//!
//! Milestone 4 feature-complete. UDP/TCP/DoT/DoH query pipeline,
//! metrics, mesh-zone bundle reload, blocklist reload, per-client
//! policy, query log ring buffer, capability dropping, bounded
//! graceful shutdown, and `--print-config` / `--validate-config`
//! CLI flags are all wired up. Remaining gaps are hickory-side
//! (RFC 8467 padding, RFC 7816 query minimisation) and a
//! Rustynet-side peer-table integration for NodeId-keyed policy.

mod blocklist_loader;
mod doh;
mod handler;
mod metrics;
mod query_log;

#[cfg(test)]
mod test_pem;

use anyhow::{Context, Result, anyhow, bail};
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use hickory_server::Server;

use blocklist_loader::BlocklistLoader;
use doh as doh_server;
use handler::DnsHandler;
use metrics::Metrics;
use rustls::ServerConfig as TlsServerConfig;
use rustls_pemfile as pemfile;
use rustydns_authority::Authority;
use rustydns_blocklist::BlocklistEngine;
use rustydns_core::config::{MetricsConfig, ServerConfig};
use rustydns_resolver::Resolver;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise structured logging first so the umask line below
    // (and every subsequent startup event) reaches the subscriber.
    // Tracing writes go to stdout/stderr/journal, not to disk —
    // they're not affected by umask.
    init_tracing();

    // Set a restrictive umask so any files the daemon creates later
    // (e.g. accidental log files written before privileges are
    // dropped) are owner-only. systemd's `UMask=0077` covers this
    // under the service unit; this call covers non-systemd deployments
    // (Docker, runit, OpenRC, bare CLI).
    set_restrictive_umask();

    let args = parse_args()?;
    let config_path = PathBuf::from(&args.config_path);

    info!(config = %config_path.display(), "rustydnsd starting");

    // --- Security: verify config file permissions before reading ----------
    // A world-readable config file leaks upstream resolver credentials and
    // other sensitive settings. Fail hard rather than warn.
    check_config_permissions(&config_path)?;

    // Load and validate configuration.
    let config =
        rustydns_core::config::load_config(&config_path).context("failed to load configuration")?;

    // `--print-config`: emit the resolved config and exit. Implies
    // --validate-config (load_config has already run validate_config).
    // Sensitive fields render as <redacted> via the Secret Debug impl.
    if args.print_config {
        let rendered = toml::to_string_pretty(&config)
            .context("failed to serialise resolved config as TOML")?;
        print!("{rendered}");
        return Ok(());
    }

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
            metrics.set_blocklist_state(
                blocklist_engine.entry_count(),
                blocklist_engine.heap_bytes(),
            );
        }
        Err(e) => {
            metrics.mark_blocklist_reload_failure();
            warn!(error = %e, "initial blocklist load failed; continuing with existing state");
        }
    }

    // Resolver (DoH/DoQ upstream).
    let resolver = Arc::new(Resolver::new((*config).clone()).await?);

    // Build request handler and server.
    // In-memory query log ring buffer (privacy invariant: never on disk).
    let query_log = Arc::new(query_log::QueryLog::new(config.privacy.query_log_ring_size));
    info!(
        capacity = query_log.capacity(),
        "query log ring buffer initialised (in-memory only)"
    );

    let handler = DnsHandler::new(
        authority.clone(),
        blocklist_engine.clone(),
        resolver,
        metrics.clone(),
        query_log.clone(),
        &config.policy,
    )?;
    let doh_handler = Arc::new(handler.clone());
    let mut server = Server::new(handler);

    for addr in &config.server.listen {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("failed to bind UDP socket on {addr}"))?;
        server.register_socket(udp);

        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind TCP listener on {addr}"))?;
        // hickory 0.26 added a response-buffer-size param to
        // register_listener. 4096 is the hickory default elsewhere
        // in the crate.
        server.register_listener(tcp, Duration::from_secs(5), 4096);

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
        let tls_config = load_tls_config(&config.server)?;
        let dot = TcpListener::bind(dot_listen)
            .await
            .with_context(|| format!("failed to bind DoT listener on {dot_listen}"))?;
        server
            .register_tls_listener_with_tls_config(dot, Duration::from_secs(5), tls_config)
            .with_context(|| format!("failed to register DoT listener on {dot_listen}"))?;
        info!(listen = %dot_listen, "listening for DoT");
    }

    let shutdown = CancellationToken::new();

    if let Some(doh_listen) = &config.server.doh_listen {
        if let Ok(addr) = doh_listen.parse::<SocketAddr>() {
            if !addr.ip().is_loopback() {
                warn!(listen = %doh_listen, "DoH listener is not loopback; ensure a TLS reverse proxy and access controls are in place");
            }
            spawn_doh_server(doh_handler, addr, shutdown.clone());
        } else {
            bail!(
                "server.doh_listen `{}` is not a valid socket address",
                doh_listen
            );
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
    spawn_metrics_server(
        metrics.clone(),
        query_log.clone(),
        metrics_addr,
        metrics_path,
        shutdown.clone(),
    );

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received");
    shutdown.cancel();

    // Bounded graceful shutdown. If hickory's `shutdown_gracefully`
    // hasn't drained within SHUTDOWN_TIMEOUT we force-exit by dropping
    // the future — better to abandon a stuck in-flight query than to
    // sit unresponsive while systemd / Docker / k8s wait on us.
    //
    // A second SIGTERM/SIGINT during the drain window collapses the
    // timeout to zero (operator wants out now).
    let shutdown_timeout = shutdown_timeout_from_env();
    tokio::select! {
        result = tokio::time::timeout(shutdown_timeout, server.shutdown_gracefully()) => {
            match result {
                Ok(Ok(())) => info!("server drained cleanly"),
                Ok(Err(e)) => warn!(error = %e, "server reported error during graceful shutdown"),
                Err(_) => warn!(
                    timeout_secs = shutdown_timeout.as_secs(),
                    "graceful shutdown timed out — forcing exit"
                ),
            }
        }
        _ = wait_for_shutdown_signal() => {
            warn!("second shutdown signal received — forcing exit");
        }
    }

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
        if !user_filter.contains(crate_name)
            && let Ok(d) = format!("{crate_name}=warn").parse()
        {
            filter = filter.add_directive(d);
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
    /// `--print-config`: load + validate + emit the resolved config
    /// to stdout (TOML), then exit 0. Useful for debugging
    /// "what does the daemon actually think it has?" without
    /// running it. Implies `--validate-config`.
    print_config: bool,
}

fn parse_args() -> Result<CliArgs> {
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut config_path = "rustydns.toml".to_string();
    let mut validate_only = false;
    let mut print_config = false;

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
            "--print-config" => print_config = true,
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
        print_config,
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
    --print-config        Load + validate + emit the resolved config to
                          stdout (TOML) and exit 0. Sockets are never
                          bound. Useful for debugging deployment issues;
                          sensitive fields print as <redacted>.
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
        use tokio::signal::unix::{SignalKind, signal};

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
                    // Reload scope is intentionally narrow: blocklists
                    // and the mesh-zone bundle. Full-config reload
                    // (listeners, TLS material, per-client policy,
                    // upstreams) requires restarting the process —
                    // socket rebinding and Resolver/Server reconstruction
                    // are not currently driveable from a signal handler.
                    info!("SIGHUP received — reloading blocklists and mesh-zone bundle");
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
    query_log: Arc<query_log::QueryLog>,
    listen: SocketAddr,
    path: String,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        if let Err(e) = metrics::serve(metrics, query_log, listen, path, shutdown).await {
            warn!(error = %e, "metrics server failed");
        }
    });
}

fn spawn_doh_server(handler: Arc<DnsHandler>, listen: SocketAddr, shutdown: CancellationToken) {
    tokio::spawn(async move {
        if let Err(e) = doh_server::serve(handler, listen, shutdown).await {
            warn!(error = %e, "DoH server failed");
        }
    });
}

/// How long to wait for in-flight queries to drain before forcing exit.
///
/// Reads `RUSTYDNS_SHUTDOWN_TIMEOUT_SECS` from the environment (clamped
/// to `[1, 60]` seconds; out-of-range or unparseable values fall back
/// to the 10-second default). 10s is below systemd's default
/// `TimeoutStopSec=90s` and k8s's default `terminationGracePeriodSeconds=30s`,
/// so we always finish before the orchestrator SIGKILLs us.
fn shutdown_timeout_from_env() -> Duration {
    const DEFAULT_SECS: u64 = 10;
    let secs = std::env::var("RUSTYDNS_SHUTDOWN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| (1..=60).contains(&v))
        .unwrap_or(DEFAULT_SECS);
    Duration::from_secs(secs)
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm =
            signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;

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
        anyhow!(
            "metrics.listen `{}` is not a valid socket address",
            metrics.listen
        )
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

/// Set the process umask to `0o077` so files created by the daemon
/// default to mode `0o600` (owner-only). Equivalent to systemd's
/// `UMask=0077` for non-systemd deployments.
#[cfg(unix)]
fn set_restrictive_umask() {
    use nix::sys::stat::{Mode, umask};
    // umask never fails — the system call returns the previous mask.
    let previous = umask(Mode::from_bits_truncate(0o077));
    info!(
        previous_mask = format!("{:#o}", previous.bits()),
        new_mask = format!("{:#o}", 0o077),
        "process umask set"
    );
}

#[cfg(not(unix))]
fn set_restrictive_umask() {
    // umask is a Unix concept. On Windows, file mode is set via ACLs
    // that don't have a per-process default the same way.
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

/// Build a rustls [`TlsServerConfig`] from the cert+key paths in
/// `server`. Called when `dot_listen` is configured.
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Per-test unique temp path so parallel tests don't collide.
    fn tmp_path(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rustydnsd-test-{}-{id}-{name}", std::process::id()))
    }

    fn write_file(path: &PathBuf, contents: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    fn server_with_paths(cert: Option<PathBuf>, key: Option<PathBuf>) -> ServerConfig {
        ServerConfig {
            tls_cert_path: cert,
            tls_key_path: key,
            ..ServerConfig::default()
        }
    }

    #[test]
    fn load_tls_config_requires_cert_path() {
        let key = tmp_path("k.pem");
        write_file(
            &key,
            b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        );
        let err = load_tls_config(&server_with_paths(None, Some(key))).unwrap_err();
        assert!(
            format!("{err:#}").contains("tls_cert_path"),
            "error must name the missing field: {err:#}"
        );
    }

    #[test]
    fn load_tls_config_requires_key_path() {
        let cert = tmp_path("c.pem");
        write_file(
            &cert,
            b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        );
        let err = load_tls_config(&server_with_paths(Some(cert), None)).unwrap_err();
        assert!(
            format!("{err:#}").contains("tls_key_path"),
            "error must name the missing field: {err:#}"
        );
    }

    #[test]
    fn load_tls_config_rejects_missing_cert_file() {
        let cert = tmp_path("does-not-exist.pem");
        let key = tmp_path("k.pem");
        write_file(
            &key,
            b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        );
        let err = load_tls_config(&server_with_paths(Some(cert), Some(key))).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("failed to open TLS certificate"),
            "msg = {msg}"
        );
    }

    use crate::test_pem::{TEST_CERT_PEM, TEST_KEY_PEM};

    #[test]
    fn load_tls_config_accepts_valid_pem_pair() {
        let cert = tmp_path("good-cert.pem");
        let key = tmp_path("good-key.pem");
        write_file(&cert, TEST_CERT_PEM.as_bytes());
        write_file(&key, TEST_KEY_PEM.as_bytes());

        // ring needs to be installed as the default provider for
        // ClientConfig builders elsewhere in the workspace. The DoT
        // ServerConfig builder used here is happy with whatever
        // provider is registered globally; this also runs first in
        // test order on many machines so make the install idempotent
        // and best-effort.
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );

        let cfg = load_tls_config(&server_with_paths(Some(cert), Some(key)))
            .expect("valid PEM pair must load");
        // The returned config is wrapped in Arc; we don't probe its
        // internals further — that's hickory's job during the
        // handshake.
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    #[test]
    fn load_tls_config_rejects_empty_cert_file() {
        let cert = tmp_path("empty-cert.pem");
        let key = tmp_path("k.pem");
        write_file(&cert, b""); // empty file
        write_file(
            &key,
            b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        );
        let err = load_tls_config(&server_with_paths(Some(cert), Some(key))).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("contains no certificates"), "msg = {msg}");
    }

    #[test]
    fn normalize_metrics_path_prepends_slash() {
        assert_eq!(normalize_metrics_path(""), "/metrics");
        assert_eq!(normalize_metrics_path("foo"), "/foo");
        assert_eq!(normalize_metrics_path("/foo"), "/foo");
        assert_eq!(normalize_metrics_path("  /foo  "), "/foo");
    }
}
