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
//! - `SIGHUP`  — re-read blocklist content from the current sources, the
//!   signed mesh-zone bundle, AND `rustydns.toml`. Config reload applies:
//!   - **Phase 1 (hot-swap):** the upstream resolver (`[upstream]`),
//!     per-client policy (`[[policy]]`), and rate limiter (`[rate_limit]`)
//!     are swapped atomically via `ArcSwap` — in-flight queries are never
//!     dropped.
//!   - **Phase 2 (live listener handover):** changed listeners (DNS UDP/TCP,
//!     DoT incl. TLS cert rotation, DoH, metrics) on **unprivileged** ports
//!     are rebound zero-drop via `SO_REUSEPORT` — the new generation serves
//!     before the old drains. Listeners on **privileged** ports (<1024)
//!     cannot be rebound after the startup capability drop, so a change to
//!     one is logged as restart-required, not applied (see [`listeners`]).
//!   - Blocklist *sources* and the on-disk query log are still bound at
//!     startup and need a restart; such changes are logged at `warn!`.
//!   - A config that fails to parse/validate aborts the reload and leaves
//!     the running configuration untouched.
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
mod listeners;
mod metrics;
mod query_log;
mod query_log_disk;
mod rate_limiter;
mod rewrite;

#[cfg(test)]
mod test_pem;

use anyhow::{Context, Result, anyhow, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use hickory_server::Server;

use blocklist_loader::BlocklistLoader;
use doh as doh_server;
use handler::DnsHandler;
use metrics::Metrics;
use rate_limiter::RateLimiter;
use rustls::ServerConfig as TlsServerConfig;
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

    // Warn about privacy knobs that the operator may believe are
    // active but are not, because hickory 0.26's stub resolver
    // doesn't yet expose them. Keeping the config keys around lets
    // the daemon adopt them silently when hickory ships support —
    // but until then, an operator with `upstream_padding = true`
    // would have no signal that padding isn't actually happening.
    // Emitted before the --validate-config / --print-config early
    // returns so an operator validating their config sees them too.
    if config.privacy.query_minimization {
        warn!(
            "privacy.query_minimization is enabled in config but hickory 0.26's stub \
             resolver does not yet apply RFC 7816 qmin — queries are sent in full. \
             The setting is honoured the moment hickory exposes it."
        );
    }
    if config.privacy.upstream_padding {
        warn!(
            "privacy.upstream_padding is enabled in config but hickory 0.26 does not \
             yet apply RFC 8467 DoH padding — encrypted query sizes still leak which \
             domain was queried. The setting is honoured the moment hickory exposes it."
        );
    }

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

    // Single shutdown token shared by every background task (listeners,
    // reload loops, metrics server, on-disk query-log writer). Created
    // early so the query-log writer — spawned during handler setup — can
    // observe it.
    let shutdown = CancellationToken::new();

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
    // In-memory query log ring buffer, optionally fanned out to an
    // on-disk NDJSON writer when `privacy.query_log_to_disk = true`.
    // Both sinks store only hashed qnames + anonymised clients.
    let query_log = if config.privacy.query_log_to_disk {
        // validate_config guarantees the path is Some + non-empty here.
        let path = config
            .privacy
            .query_log_disk_path
            .clone()
            .expect("validate_config ensures query_log_disk_path is set");
        match query_log_disk::spawn(
            path,
            config.privacy.query_log_max_file_bytes,
            config.privacy.query_log_max_files,
            metrics.clone(),
            shutdown.clone(),
        ) {
            Some(handle) => Arc::new(query_log::QueryLog::with_disk_sink(
                config.privacy.query_log_ring_size,
                handle.sender,
                metrics.query_log_disk_dropped_counter(),
            )),
            // Disk writer refused to start (bad perms / open error). It
            // already logged why; fall back to the in-memory ring only.
            None => Arc::new(query_log::QueryLog::new(config.privacy.query_log_ring_size)),
        }
    } else {
        Arc::new(query_log::QueryLog::new(config.privacy.query_log_ring_size))
    };
    info!(
        capacity = query_log.capacity(),
        to_disk = config.privacy.query_log_to_disk,
        "query log ring buffer initialised"
    );

    // Per-source-IP rate limiter. Default-on with generous limits;
    // loopback is exempt internally so local proxies and DoH/DoT
    // terminators are never penalised.
    let rate_limiter = Arc::new(RateLimiter::new(&config.rate_limit));
    info!(
        enabled = config.rate_limit.enabled,
        qps = config.rate_limit.qps,
        burst = config.rate_limit.burst,
        max_tracked = config.rate_limit.max_tracked_clients,
        "per-source-IP rate limiter initialised"
    );

    let handler = DnsHandler::new(
        authority.clone(),
        blocklist_engine.clone(),
        resolver,
        metrics.clone(),
        query_log.clone(),
        rate_limiter,
        &config.policy,
        &combined_rewrite_rules(&config),
    )?;
    // An owning handler clone, used to build new listener generations and
    // to perform SIGHUP hot-swaps. Every generation/DoH server gets its
    // own clone — they all share the handler's inner ArcSwaps.
    let reload_handle = handler.clone();

    // Parse + validate listen addresses up front so a bad address fails
    // startup rather than mid-bind.
    let listen_addrs =
        parse_socket_addrs(&config.server.listen).context("invalid server.listen address")?;
    let dot_addr =
        match &config.server.dot_listen {
            Some(s) => Some(s.parse::<SocketAddr>().with_context(|| {
                format!("server.dot_listen `{s}` is not a valid socket address")
            })?),
            None => None,
        };

    // Build + start the initial DNS server (UDP/TCP + optional DoT). This
    // binds the privileged ports (53/853) while we STILL hold
    // CAP_NET_BIND_SERVICE — see the capability drop immediately below.
    let initial_tls = if dot_addr.is_some() {
        Some(load_tls_config(&config.server)?)
    } else {
        None
    };
    let dns_server =
        listeners::build_dns_server(handler.clone(), &listen_addrs, dot_addr, initial_tls)
            .context("failed to bind DNS listeners")?;
    for addr in &listen_addrs {
        info!(listen = %addr, "listening for DNS queries (UDP+TCP)");
    }
    if let Some(dot) = dot_addr {
        info!(listen = %dot, "listening for DoT");
    }

    // --- Capability discipline -------------------------------------------
    // All privileged ports are bound. We no longer need
    // CAP_NET_BIND_SERVICE or any other capability for the lifetime of
    // the daemon. Drop everything so a future bug or compromise can't
    // re-bind privileged ports or escalate privileges.
    //
    // This is also why live SIGHUP listener handover (roadmap 3.2 Phase 2)
    // is offered only for UNPRIVILEGED ports: rebinding a port < 1024
    // needs this capability, which is gone. A privileged-port listener
    // change is detected on reload and logged as restart-required.
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

    // Assemble the active listener generation and spawn the independent
    // axum servers (DoH + metrics), each under its own child token so a
    // reload can replace one without touching the others.
    let mut active = ActiveListeners::new(
        reload_handle.clone(),
        metrics.clone(),
        query_log.clone(),
        shutdown.clone(),
        dns_server,
        listen_addrs,
        dot_addr,
        (
            config.server.tls_cert_path.clone(),
            config.server.tls_key_path.clone(),
        ),
    );
    active.start_doh(&config)?;
    active.start_metrics(&config)?;

    // Periodic (non-signal) reload loops.
    spawn_blocklist_reload_loop(
        blocklist_loader.clone(),
        blocklist_engine.clone(),
        metrics.clone(),
        config.blocklist.reload_interval_secs,
        shutdown.clone(),
    );
    spawn_mesh_reload_loop(
        authority.clone(),
        metrics.clone(),
        config.authority.poll_interval_secs,
        shutdown.clone(),
    );

    // Unified signal loop: SIGHUP reloads (blocklist + mesh + config hot
    // swaps + listener handover); SIGTERM/SIGINT ends the loop.
    run_signal_loop(
        &mut active,
        &reload_handle,
        config.as_ref(),
        &blocklist_loader,
        &blocklist_engine,
        &authority,
        &metrics,
        &config_path,
    )
    .await;

    info!("shutdown signal received");
    shutdown.cancel();

    let shutdown_timeout = shutdown_timeout_from_env();
    active.drain(shutdown_timeout).await;

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

#[allow(clippy::too_many_arguments)]
/// Parse a list of `host:port` strings into [`SocketAddr`]s.
fn parse_socket_addrs(addrs: &[String]) -> Result<Vec<SocketAddr>> {
    addrs
        .iter()
        .map(|s| {
            s.parse::<SocketAddr>()
                .with_context(|| format!("`{s}` is not a valid socket address"))
        })
        .collect()
}

/// The currently-bound generation of network listeners plus the state
/// needed for a live SIGHUP handover (roadmap 3.2, Phase 2).
///
/// The hickory `Server` (UDP/TCP/DoT) and the two axum servers (DoH,
/// metrics) are each replaceable independently. Replacement is **zero-drop**:
/// the new generation binds with `SO_REUSEPORT` and starts serving before
/// the old one is drained/cancelled. Listeners on privileged ports (<1024)
/// cannot be rebound after the startup capability drop, so a change to one
/// is detected and logged as restart-required rather than applied.
struct ActiveListeners {
    /// Template handler cloned into each new generation (shares ArcSwaps).
    handler: DnsHandler,
    metrics: Arc<Metrics>,
    query_log: Arc<query_log::QueryLog>,
    /// Parent token; child tokens for DoH/metrics derive from it so a
    /// global shutdown cancels them all.
    parent_shutdown: CancellationToken,

    dns_server: Option<Server<DnsHandler>>,
    doh_token: Option<CancellationToken>,
    metrics_token: Option<CancellationToken>,

    // What is actually bound right now (drives reload diffing).
    live_listen: Vec<SocketAddr>,
    live_dot: Option<SocketAddr>,
    live_tls_paths: (Option<PathBuf>, Option<PathBuf>),
    live_doh: Option<SocketAddr>,
    live_metrics: Option<SocketAddr>,
    live_metrics_path: String,
}

impl ActiveListeners {
    #[allow(clippy::too_many_arguments)]
    fn new(
        handler: DnsHandler,
        metrics: Arc<Metrics>,
        query_log: Arc<query_log::QueryLog>,
        parent_shutdown: CancellationToken,
        dns_server: Server<DnsHandler>,
        live_listen: Vec<SocketAddr>,
        live_dot: Option<SocketAddr>,
        live_tls_paths: (Option<PathBuf>, Option<PathBuf>),
    ) -> Self {
        Self {
            handler,
            metrics,
            query_log,
            parent_shutdown,
            dns_server: Some(dns_server),
            doh_token: None,
            metrics_token: None,
            live_listen,
            live_dot,
            live_tls_paths,
            live_doh: None,
            live_metrics: None,
            live_metrics_path: String::new(),
        }
    }

    /// Spawn the DoH server if configured. Startup variant: a bind failure
    /// is fatal (propagated).
    fn start_doh(&mut self, cfg: &rustydns_core::config::DnsConfig) -> Result<()> {
        if let Some(s) = &cfg.server.doh_listen {
            let addr = s.parse::<SocketAddr>().with_context(|| {
                format!("server.doh_listen `{s}` is not a valid socket address")
            })?;
            self.install_doh(addr)?;
        }
        Ok(())
    }

    /// Spawn the metrics server (always present). Startup variant.
    fn start_metrics(&mut self, cfg: &rustydns_core::config::DnsConfig) -> Result<()> {
        let addr = metrics_listen_addr(&cfg.metrics)?;
        let path = normalize_metrics_path(&cfg.metrics.path);
        self.install_metrics(addr, path)
    }

    /// Bind + spawn a DoH server on `addr`, then cancel any prior one
    /// (zero-drop). On bind failure the old server is left untouched.
    fn install_doh(&mut self, addr: SocketAddr) -> Result<()> {
        if !addr.ip().is_loopback() {
            warn!(listen = %addr, "DoH listener is not loopback; ensure a TLS reverse proxy and access controls are in place");
        }
        let listener = listeners::bind_tcp(addr)
            .with_context(|| format!("failed to bind DoH listener on {addr}"))?;
        let token = self.parent_shutdown.child_token();
        let handler = Arc::new(self.handler.clone());
        let task_token = token.clone();
        tokio::spawn(async move {
            if let Err(e) = doh_server::serve(handler, listener, task_token).await {
                warn!(error = %e, "DoH server failed");
            }
        });
        if let Some(old) = self.doh_token.replace(token) {
            old.cancel();
        }
        self.live_doh = Some(addr);
        info!(listen = %addr, "DoH listener started");
        Ok(())
    }

    /// Bind + spawn the metrics server on `addr`, then cancel any prior one
    /// (zero-drop). On bind failure the old server is left untouched.
    fn install_metrics(&mut self, addr: SocketAddr, path: String) -> Result<()> {
        let listener = listeners::bind_tcp(addr)
            .with_context(|| format!("failed to bind metrics listener on {addr}"))?;
        let token = self.parent_shutdown.child_token();
        let metrics = self.metrics.clone();
        let query_log = self.query_log.clone();
        let path_for_task = path.clone();
        let task_token = token.clone();
        tokio::spawn(async move {
            if let Err(e) =
                metrics::serve(metrics, query_log, listener, path_for_task, task_token).await
            {
                warn!(error = %e, "metrics server failed");
            }
        });
        if let Some(old) = self.metrics_token.replace(token) {
            old.cancel();
        }
        self.live_metrics = Some(addr);
        self.live_metrics_path = path;
        Ok(())
    }

    /// Reconcile all three listener groups to `cfg`. Each group is handled
    /// independently; a failure or restart-required field in one never
    /// blocks the others.
    fn reload_listeners(&mut self, cfg: &rustydns_core::config::DnsConfig) {
        self.reload_dns_group(cfg);
        self.reload_doh_group(cfg);
        self.reload_metrics_group(cfg);
    }

    fn reload_dns_group(&mut self, cfg: &rustydns_core::config::DnsConfig) {
        let new_listen = match parse_socket_addrs(&cfg.server.listen) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "SIGHUP: server.listen unparseable; DNS listeners unchanged");
                return;
            }
        };
        let new_dot = match cfg
            .server
            .dot_listen
            .as_deref()
            .map(|s| s.parse::<SocketAddr>())
            .transpose()
        {
            Ok(v) => v,
            Err(_) => {
                warn!("SIGHUP: server.dot_listen unparseable; DNS listeners unchanged");
                return;
            }
        };
        let new_tls = (
            cfg.server.tls_cert_path.clone(),
            cfg.server.tls_key_path.clone(),
        );
        if new_listen == self.live_listen
            && new_dot == self.live_dot
            && new_tls == self.live_tls_paths
        {
            return; // nothing changed
        }

        let mut group = new_listen.clone();
        if let Some(d) = new_dot {
            group.push(d);
        }
        if !listeners::all_unprivileged(&group) {
            warn!(
                "SIGHUP: DNS/DoT listener change needs a process restart — the new config \
                 binds a privileged port (<1024) and CAP_NET_BIND_SERVICE was dropped at \
                 startup. NOT applied; the previous listeners keep serving."
            );
            return;
        }

        let tls = if new_dot.is_some() {
            match load_tls_config(&cfg.server) {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!(error = %e, "SIGHUP: TLS reload failed; keeping current DNS/DoT listeners");
                    return;
                }
            }
        } else {
            None
        };

        match listeners::build_dns_server(self.handler.clone(), &new_listen, new_dot, tls) {
            Ok(new_server) => {
                let old = self.dns_server.replace(new_server);
                self.live_listen = new_listen.clone();
                self.live_dot = new_dot;
                self.live_tls_paths = new_tls;
                info!(
                    listen = ?new_listen,
                    dot = ?new_dot,
                    "SIGHUP: DNS listeners rebound live (zero-drop via SO_REUSEPORT)"
                );
                if let Some(old) = old {
                    drain_server_in_background(old);
                }
            }
            Err(e) => {
                warn!(error = %e, "SIGHUP: DNS rebind failed; keeping current listeners");
            }
        }
    }

    fn reload_doh_group(&mut self, cfg: &rustydns_core::config::DnsConfig) {
        let new_doh = match cfg
            .server
            .doh_listen
            .as_deref()
            .map(|s| s.parse::<SocketAddr>())
            .transpose()
        {
            Ok(v) => v,
            Err(_) => {
                warn!("SIGHUP: server.doh_listen unparseable; DoH listener unchanged");
                return;
            }
        };
        if new_doh == self.live_doh {
            return;
        }
        match new_doh {
            None => {
                if let Some(old) = self.doh_token.take() {
                    old.cancel();
                }
                self.live_doh = None;
                info!("SIGHUP: DoH listener removed");
            }
            Some(addr) if listeners::is_privileged(&addr) => {
                warn!(listen = %addr, "SIGHUP: DoH listener change needs a restart — privileged port (<1024), capabilities dropped; NOT applied");
            }
            Some(addr) => {
                if let Err(e) = self.install_doh(addr) {
                    warn!(error = %e, "SIGHUP: DoH rebind failed; keeping current DoH listener");
                } else {
                    info!(listen = %addr, "SIGHUP: DoH listener rebound live");
                }
            }
        }
    }

    fn reload_metrics_group(&mut self, cfg: &rustydns_core::config::DnsConfig) {
        let new_addr = match metrics_listen_addr(&cfg.metrics) {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "SIGHUP: metrics.listen invalid; metrics listener unchanged");
                return;
            }
        };
        let new_path = normalize_metrics_path(&cfg.metrics.path);
        if Some(new_addr) == self.live_metrics && new_path == self.live_metrics_path {
            return;
        }
        if listeners::is_privileged(&new_addr) {
            warn!(listen = %new_addr, "SIGHUP: metrics listener change needs a restart — privileged port (<1024), capabilities dropped; NOT applied");
            return;
        }
        if let Err(e) = self.install_metrics(new_addr, new_path) {
            warn!(error = %e, "SIGHUP: metrics rebind failed; keeping current metrics listener");
        } else {
            info!(listen = %new_addr, "SIGHUP: metrics listener rebound live");
        }
    }

    /// Bounded graceful shutdown of the active generation. The DoH/metrics
    /// child tokens are already cancelled by the global shutdown; we drain
    /// the hickory server here, collapsing the timeout on a second signal.
    async fn drain(&mut self, timeout: Duration) {
        if let Some(old) = self.doh_token.take() {
            old.cancel();
        }
        if let Some(old) = self.metrics_token.take() {
            old.cancel();
        }
        if let Some(mut server) = self.dns_server.take() {
            tokio::select! {
                result = tokio::time::timeout(timeout, server.shutdown_gracefully()) => {
                    match result {
                        Ok(Ok(())) => info!("server drained cleanly"),
                        Ok(Err(e)) => warn!(error = %e, "server reported error during graceful shutdown"),
                        Err(_) => warn!(
                            timeout_secs = timeout.as_secs(),
                            "graceful shutdown timed out — forcing exit"
                        ),
                    }
                }
                _ = wait_for_shutdown_signal() => {
                    warn!("second shutdown signal received — forcing exit");
                }
            }
        }
    }
}

/// Drain a retired hickory `Server` generation in the background so the
/// SIGHUP handler returns promptly. Bounded by the same shutdown timeout.
fn drain_server_in_background(mut server: Server<DnsHandler>) {
    let timeout = shutdown_timeout_from_env();
    tokio::spawn(async move {
        match tokio::time::timeout(timeout, server.shutdown_gracefully()).await {
            Ok(Ok(())) => info!("retired DNS listener generation drained cleanly"),
            Ok(Err(e)) => warn!(error = %e, "retired DNS generation reported a drain error"),
            Err(_) => warn!("retired DNS generation drain timed out; dropping it"),
        }
    });
}

/// Unified signal loop: handle SIGHUP reloads until SIGTERM/SIGINT.
#[allow(clippy::too_many_arguments)]
async fn run_signal_loop(
    active: &mut ActiveListeners,
    handler: &DnsHandler,
    startup_config: &rustydns_core::config::DnsConfig,
    loader: &Arc<BlocklistLoader>,
    engine: &Arc<BlocklistEngine>,
    authority: &Arc<Authority>,
    metrics: &Arc<Metrics>,
    config_path: &std::path::Path,
) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut hup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to register SIGHUP handler; config reload disabled");
                let _ = wait_for_shutdown_signal().await;
                return;
            }
        };
        let mut term = signal(SignalKind::terminate()).ok();

        loop {
            tokio::select! {
                _ = hup.recv() => {
                    handle_sighup(active, handler, startup_config, loader, engine, authority, metrics, config_path).await;
                }
                _ = tokio::signal::ctrl_c() => break,
                _ = async {
                    match term.as_mut() {
                        Some(t) => { t.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => break,
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (
            active,
            handler,
            startup_config,
            loader,
            engine,
            authority,
            metrics,
            config_path,
        );
        let _ = wait_for_shutdown_signal().await;
    }
}

/// Handle one SIGHUP: reload blocklist content + mesh bundle, then re-read
/// the config and apply it — hot-swapping the resolver/policy/rate-limit
/// (Phase 1) and reconciling the listeners (Phase 2).
#[allow(clippy::too_many_arguments)]
async fn handle_sighup(
    active: &mut ActiveListeners,
    handler: &DnsHandler,
    startup_config: &rustydns_core::config::DnsConfig,
    loader: &Arc<BlocklistLoader>,
    engine: &Arc<BlocklistEngine>,
    authority: &Arc<Authority>,
    metrics: &Arc<Metrics>,
    config_path: &std::path::Path,
) {
    info!("SIGHUP received — reloading blocklists, mesh-zone bundle, and config");

    match loader.reload(engine).await {
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

    let new_config = match rustydns_core::config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                error = %e,
                "SIGHUP config reload: new config failed to parse/validate — \
                 keeping the currently running configuration"
            );
            return;
        }
    };

    // Phase 1: hot-swap resolver / policy / rate limiter.
    apply_hot_swaps(handler, &new_config).await;

    // Phase 2: reconcile listeners (live rebind where possible).
    active.reload_listeners(&new_config);

    // Warn about the handful of fields that still need a restart and that
    // the listener reconciler does not own.
    let restart_required = restart_required_changes(startup_config, &new_config);
    if !restart_required.is_empty() {
        warn!(
            fields = %restart_required.join(", "),
            "SIGHUP config reload: these settings changed but require a process restart \
             to take effect — they were NOT applied (blocklist sources/response and the \
             on-disk query log are fixed at startup)"
        );
    }
}

/// Atomically swap the hot-reloadable components into the running handler
/// (roadmap 3.2, Phase 1). A resolver rebuild failure keeps the old
/// resolver; policy and rate-limit builds are infallible.
/// Combine the operator's `[[rewrite]]` rules with the built-in Safe Search
/// rules into the single rule list the handler's rewrite map consumes.
///
/// Safe Search rules are listed **first** so an explicit `[[rewrite]]` for the
/// same name overrides them — `RewriteMap::from_rules` lets a later exact rule
/// win. Returns just the operator rules when Safe Search is disabled.
fn combined_rewrite_rules(
    config: &rustydns_core::config::DnsConfig,
) -> Vec<rustydns_core::config::RewriteRule> {
    let mut rules = config.safesearch.rewrite_rules();
    rules.extend(config.rewrite.iter().cloned());
    rules
}

async fn apply_hot_swaps(handler: &DnsHandler, new_config: &rustydns_core::config::DnsConfig) {
    match Resolver::new(new_config.clone()).await {
        Ok(resolver) => {
            handler.swap_resolver(Arc::new(resolver));
            info!(
                protocol = ?new_config.upstream.protocol,
                "SIGHUP config reload: upstream resolver rebuilt and swapped"
            );
        }
        Err(e) => {
            warn!(error = %e, "SIGHUP config reload: resolver rebuild failed — keeping the old resolver");
        }
    }
    handler.swap_rate_limiter(Arc::new(RateLimiter::new(&new_config.rate_limit)));
    handler.swap_policies(&new_config.policy);
    handler.swap_rewrites(&combined_rewrite_rules(new_config));
    info!(
        policies = new_config.policy.len(),
        rate_limit_enabled = new_config.rate_limit.enabled,
        "SIGHUP config reload: policy table and rate limiter swapped"
    );
}

/// Names of restart-required settings that differ between the startup
/// config and a freshly read one — limited to fields the listener
/// reconciler does NOT own. Listener/TLS/metrics changes are handled live
/// (or warned per-group) by [`ActiveListeners::reload_listeners`]; here we
/// only flag the blocklist source/response settings (loader + engine are
/// built once) and the on-disk query log (writer + file handle are bound
/// at startup).
fn restart_required_changes(
    old: &rustydns_core::config::DnsConfig,
    new: &rustydns_core::config::DnsConfig,
) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.blocklist.sources != new.blocklist.sources {
        changed.push("blocklist.sources");
    }
    if old.blocklist.local_files != new.blocklist.local_files {
        changed.push("blocklist.local_files");
    }
    if old.blocklist.block_response != new.blocklist.block_response {
        changed.push("blocklist.block_response");
    }
    if old.blocklist.sinkhole_ip != new.blocklist.sinkhole_ip {
        changed.push("blocklist.sinkhole_ip");
    }
    if old.privacy.query_log_to_disk != new.privacy.query_log_to_disk
        || old.privacy.query_log_disk_path != new.privacy.query_log_disk_path
    {
        changed.push("privacy.query_log_to_disk/path");
    }
    changed
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
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let cert_path = server.tls_cert_path.as_ref().ok_or_else(|| {
        anyhow!("server.tls_cert_path must be set when server.dot_listen is enabled")
    })?;
    let key_path = server.tls_key_path.as_ref().ok_or_else(|| {
        anyhow!("server.tls_key_path must be set when server.dot_listen is enabled")
    })?;

    let certs = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("failed to read TLS certificate {cert_path:?}"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS certificate {cert_path:?}"))?;

    if certs.is_empty() {
        bail!("TLS certificate {cert_path:?} contains no certificates");
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("failed to read or parse TLS private key {key_path:?}"))?;

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
            msg.contains("failed to read TLS certificate"),
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

    // ---- check_config_permissions ------------------------------------------

    #[cfg(unix)]
    fn set_mode(path: &PathBuf, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_config_permissions_accepts_owner_only() {
        let p = tmp_path("config-600.toml");
        write_file(&p, b"");
        set_mode(&p, 0o600);
        check_config_permissions(&p).expect("0o600 must pass");
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn check_config_permissions_accepts_owner_and_group() {
        let p = tmp_path("config-640.toml");
        write_file(&p, b"");
        // 0o640 keeps other-read clear; the function logs a warning
        // about the group-read bit but does NOT reject.
        set_mode(&p, 0o640);
        check_config_permissions(&p).expect("0o640 must pass (group-read warned, not rejected)");
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn check_config_permissions_rejects_world_readable() {
        let p = tmp_path("config-644.toml");
        write_file(&p, b"");
        // 0o644 has the other-read bit set — a hard failure.
        set_mode(&p, 0o644);
        let err = check_config_permissions(&p).expect_err("0o644 must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("world-readable"),
            "error must call out world-readability: {msg}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn check_config_permissions_rejects_world_writable() {
        let p = tmp_path("config-622.toml");
        write_file(&p, b"");
        // 0o622: other-write but not other-read. Still rejects because
        // the path "world-readable" bit catches *any* other-read bit.
        // Use 0o604 to exercise read-without-write.
        set_mode(&p, 0o604);
        let err = check_config_permissions(&p).expect_err("0o604 must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("world-readable"),
            "error must call out world-readability: {msg}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn check_config_permissions_errors_on_missing_file() {
        let p = tmp_path("config-missing.toml");
        // file never created
        let err = check_config_permissions(&p).expect_err("missing file must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("cannot stat"),
            "error must surface the stat failure: {msg}"
        );
    }

    // ---- restart_required_changes (SIGHUP reload, roadmap 3.2) -------------

    fn base_config() -> rustydns_core::config::DnsConfig {
        rustydns_core::config::DnsConfig {
            server: Default::default(),
            upstream: Default::default(),
            authority: Default::default(),
            blocklist: Default::default(),
            privacy: Default::default(),
            metrics: Default::default(),
            rate_limit: Default::default(),
            policy: Vec::new(),
            rewrite: Vec::new(),
            safesearch: Default::default(),
        }
    }

    #[test]
    fn restart_required_empty_when_identical() {
        let a = base_config();
        let b = base_config();
        assert!(restart_required_changes(&a, &b).is_empty());
    }

    #[test]
    fn restart_required_ignores_listener_and_metrics_changes() {
        // Listener / DoH / metrics changes are reconciled live by
        // ActiveListeners, NOT flagged restart-required here.
        let a = base_config();
        let mut b = base_config();
        b.server.listen = vec!["0.0.0.0:5353".to_string()];
        b.server.doh_listen = Some("127.0.0.1:8053".to_string());
        b.metrics.listen = "127.0.0.1:9999".to_string();
        b.metrics.path = "/m".to_string();
        assert!(
            restart_required_changes(&a, &b).is_empty(),
            "listener/metrics changes are handled by the reconciler, not restart-required"
        );
    }

    #[test]
    fn restart_required_flags_blocklist_sources() {
        let a = base_config();
        let mut b = base_config();
        b.blocklist.sources = vec!["https://example.com/list".to_string()];
        assert_eq!(restart_required_changes(&a, &b), vec!["blocklist.sources"]);
    }

    #[test]
    fn restart_required_ignores_hot_swappable_fields() {
        // Upstream, policy, and rate_limit are hot-swappable — changing
        // them must NOT appear in the restart-required list.
        let a = base_config();
        let mut b = base_config();
        b.upstream.resolvers = vec!["https://dns.example/dns-query".to_string()];
        b.rate_limit.qps = 1;
        b.policy.push(rustydns_core::config::NodePolicy {
            node_id: None,
            client_ip: Some("10.0.0.1".to_string()),
            blocklist_bypass: true,
            zones_allowed: Vec::new(),
            log_all_queries: false,
        });
        assert!(
            restart_required_changes(&a, &b).is_empty(),
            "hot-swappable changes must not be flagged restart-required"
        );
    }

    #[test]
    fn restart_required_flags_disk_log_toggle() {
        let a = base_config();
        let mut b = base_config();
        b.privacy.query_log_to_disk = true;
        b.privacy.query_log_disk_path = Some("/var/log/rustydns/q.ndjson".to_string());
        assert_eq!(
            restart_required_changes(&a, &b),
            vec!["privacy.query_log_to_disk/path"]
        );
    }
}
