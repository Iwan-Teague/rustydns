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
//! client (UDP/TCP/DoT/DoQ/DoH)
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
//! Milestone 4 feature-complete. UDP/TCP/DoT/DoQ/DoH query pipeline,
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
use std::sync::atomic::AtomicBool;
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
    let config = rustydns_core::config::load_config(&config_path).with_context(|| {
        format!(
            "failed to load configuration file `{}` — pass --config <path> to choose another",
            config_path.display()
        )
    })?;

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
    // ODoH pads the oblivious query itself (odoh-rs pads the plaintext), so the
    // "not applied" caveat is true only for the doh/doq/plain arms, where
    // hickory 0.26 can't yet pad.
    if config.privacy.upstream_padding
        && config.upstream.protocol != rustydns_core::config::UpstreamProtocol::Odoh
    {
        warn!(
            "privacy.upstream_padding is enabled in config but hickory 0.26 does not \
             yet apply RFC 8467 DoH padding — encrypted query sizes still leak which \
             domain was queried. The setting is honoured the moment hickory exposes it \
             (it IS already applied on the \"odoh\" arm)."
        );
    }

    // `--print-config`: emit the resolved config and exit. Implies
    // --validate-config (load_config has already run validate_config).
    // PRIVACY: URL-bearing fields (upstream resolvers, ODoH proxies,
    // routes, blocklist sources) may embed credentials — `user:pass@host`
    // userinfo or `?token=…` query parameters. The dump goes through
    // DnsConfig::redacted_for_display so those components render as
    // `<redacted>` and never reach terminals, CI logs or shell history.
    if args.print_config {
        let rendered = toml::to_string_pretty(&config.redacted_for_display())
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
    let doq_addr =
        match &config.server.doq_listen {
            Some(s) => Some(s.parse::<SocketAddr>().with_context(|| {
                format!("server.doq_listen `{s}` is not a valid socket address")
            })?),
            None => None,
        };

    // Build + start the initial DNS server (UDP/TCP + optional DoT/DoQ). This
    // binds the privileged ports (53/853) while we STILL hold
    // CAP_NET_BIND_SERVICE — see the capability drop immediately below.
    let initial_tls = if dot_addr.is_some() {
        Some(load_tls_config(&config.server)?)
    } else {
        None
    };
    let initial_doq_tls = if doq_addr.is_some() {
        Some(load_doq_tls_config(&config.server)?)
    } else {
        None
    };
    // systemd socket activation: adopt any sockets passed via LISTEN_FDS so the
    // privileged :53/:853 binds can happen in systemd and the daemon never needs
    // CAP_NET_BIND_SERVICE. Empty (→ normal binding below) for every
    // non-socket-activated start.
    let mut inherited =
        listeners::InheritedSockets::from_env().context("failed to adopt LISTEN_FDS sockets")?;
    if !inherited.is_empty() {
        info!("systemd socket activation detected (LISTEN_FDS) — adopting passed sockets");
    }
    let dns_server = listeners::build_dns_server(
        handler.clone(),
        &listen_addrs,
        dot_addr,
        initial_tls,
        doq_addr,
        initial_doq_tls,
        &mut inherited,
    )
    .context("failed to bind DNS listeners")?;
    if inherited.remaining() > 0 {
        warn!(
            unmatched = inherited.remaining(),
            "systemd passed socket(s) whose address matches no configured listener — \
             check that the .socket unit's Listen directives match server.listen / \
             dot_listen / doq_listen. Those sockets will receive no queries."
        );
    }
    for addr in &listen_addrs {
        info!(listen = %addr, "listening for DNS queries (UDP+TCP)");
    }
    if let Some(dot) = dot_addr {
        info!(listen = %dot, "listening for DoT");
    }
    if let Some(doq) = doq_addr {
        info!(listen = %doq, "listening for DoQ");
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
    // Under **socket activation** the privileged sockets were bound by
    // systemd and adopted above (LISTEN_FDS), so the daemon never needed
    // CAP_NET_BIND_SERVICE in the first place — the `.socket` unit lets the
    // `.service` run with an empty capability set (roadmap §7.1).
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
        doq_addr,
        (
            config.server.tls_cert_path.clone(),
            config.server.tls_key_path.clone(),
        ),
    );
    active.start_doh(&config)?;
    active.start_metrics(&config)?;

    // Startup complete: every configured listener is bound. From here /health
    // reports 200 ok instead of 503 starting.
    active
        .health_ready
        .store(true, std::sync::atomic::Ordering::Relaxed);
    info!("DNS listeners bound; /health reports ok");

    // Periodic (non-signal) reload loops.
    spawn_blocklist_reload_loop(
        blocklist_loader.clone(),
        blocklist_engine.clone(),
        metrics.clone(),
        config.blocklist.reload_interval_secs,
        shutdown.clone(),
    );
    // poll_interval_secs == 0 is the documented "SIGHUP-only" mode: no
    // periodic polling, and never a zero-period tokio interval (which would
    // panic).
    if mesh_polling_enabled(config.authority.poll_interval_secs) {
        spawn_mesh_reload_loop(
            authority.clone(),
            metrics.clone(),
            config.authority.poll_interval_secs,
            shutdown.clone(),
        );
    } else {
        info!("authority.poll_interval_secs = 0 — bundle polling disabled; reload via SIGHUP");
    }

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
    let metadata = std::fs::metadata(path).with_context(|| {
        format!(
            "cannot read config file `{}` — does it exist? pass --config <path> to choose one",
            path.display()
        )
    })?;
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
/// True when the operator's RUST_LOG explicitly targeted THIS hickory crate
/// by name (exact target match — never a substring), meaning our privacy
/// clamp must stand down for it alone.
fn hickory_clamp_overridden(targets: &[String], crate_name: &str) -> bool {
    targets.iter().any(|t| t == crate_name)
}

/// Directives clamping every qname-bearing hickory crate to `warn`,
/// minus any the operator overrode by exact name. Pure => unit-testable;
/// the crate LIST is the security surface (see hickory-net audit).
fn hickory_clamp_directives(targets: &[String]) -> Vec<String> {
    const QNAME_BEARING_CRATES: [&str; 4] = [
        "hickory_server",
        "hickory_proto",
        "hickory_resolver",
        "hickory_net",
    ];
    QNAME_BEARING_CRATES
        .iter()
        .filter(|c| !hickory_clamp_overridden(targets, c))
        .map(|c| format!("{c}=warn"))
        .collect()
}

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
    // Extract each directive's TARGET (text before any '=') so the clamp
    // below can check per-crate override by exact name. Substring matching
    // was a privacy bug: `hickory_resolver=off` silenced one crate but its
    // substring skipped the clamp for all three, re-enabling info-level
    // logs that can carry qnames.
    let targets: Vec<String> = user_filter
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|d| d.split('=').next().unwrap_or("").trim().to_string())
        .collect();
    for directive in user_filter.split(',').filter(|s| !s.trim().is_empty()) {
        if let Ok(d) = directive.parse() {
            filter = filter.add_directive(d);
        }
    }
    // Clamp every qname-bearing hickory crate unless the operator named it
    // exactly. Pure helper => the wiring itself is unit-testable.
    for directive in hickory_clamp_directives(&targets) {
        filter = filter.add_directive(directive.parse().unwrap());
    }

    // LOGS GO TO STDERR. stdout is reserved for data (--print-config's
    // TOML), so `rustydnsd --print-config > out.toml` yields pure,
    // re-parseable TOML even when startup warnings fire.
    #[cfg(debug_assertions)]
    let fmt_layer = fmt::layer().pretty().with_writer(std::io::stderr);

    #[cfg(not(debug_assertions))]
    let fmt_layer = fmt::layer().json().with_writer(std::io::stderr);

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

/// Whether the periodic mesh-bundle poll loop should run: `0` disables it
/// (documented SIGHUP-only mode). Any non-zero value is the period in
/// seconds.
fn mesh_polling_enabled(poll_interval_secs: u64) -> bool {
    poll_interval_secs > 0
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
/// The hickory `Server` (UDP/TCP/DoT/DoQ) and the two axum servers (DoH,
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
    live_doq: Option<SocketAddr>,
    live_tls_paths: (Option<PathBuf>, Option<PathBuf>),
    live_doh: Option<SocketAddr>,
    /// Upstream timeout the CURRENT DoH server was built with — a SIGHUP
    /// that changes only `upstream.timeout_ms` must still rebind DoH so its
    /// derived deadline tracks the resolver.
    live_doh_timeout: Option<Duration>,
    live_metrics: Option<SocketAddr>,
    live_metrics_path: String,
    /// Flipped once startup has finished binding the DNS listeners. `/health`
    /// reports 503 "starting" until then — never a static 200.
    health_ready: Arc<AtomicBool>,
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
        live_doq: Option<SocketAddr>,
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
            live_doq,
            live_tls_paths,
            live_doh: None,
            live_doh_timeout: None,
            live_metrics: None,
            live_metrics_path: String::new(),
            health_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Spawn the DoH server if configured. Startup variant: a bind failure
    /// is fatal (propagated).
    fn start_doh(&mut self, cfg: &rustydns_core::config::DnsConfig) -> Result<()> {
        if let Some(s) = &cfg.server.doh_listen {
            let addr = s.parse::<SocketAddr>().with_context(|| {
                format!("server.doh_listen `{s}` is not a valid socket address")
            })?;
            let upstream_timeout = Duration::from_millis(cfg.upstream.timeout_ms);
            let tls_configured =
                cfg.server.tls_cert_path.is_some() && cfg.server.tls_key_path.is_some();
            self.install_doh(addr, upstream_timeout, tls_configured)?;
        }
        Ok(())
    }

    /// Spawn the metrics server (always present). Startup variant.
    fn start_metrics(&mut self, cfg: &rustydns_core::config::DnsConfig) -> Result<()> {
        let addr = metrics_listen_addr(&cfg.metrics)?;
        let path = normalize_metrics_path(&cfg.metrics.path)?;
        self.install_metrics(addr, path)
    }

    /// Bind + spawn a DoH server on `addr`, then cancel any prior one
    /// (zero-drop). On bind failure the old server is left untouched.
    /// A non-loopback bind is refused unless TLS material is configured
    /// (see [`ensure_doh_bind_allowed`]).
    fn install_doh(
        &mut self,
        addr: SocketAddr,
        upstream_timeout: Duration,
        tls_configured: bool,
    ) -> Result<()> {
        ensure_doh_bind_allowed(addr, tls_configured)?;
        let listener = listeners::bind_tcp(addr)
            .with_context(|| format!("failed to bind DoH listener on {addr}"))?;
        let token = self.parent_shutdown.child_token();
        let handler = Arc::new(self.handler.clone());
        let task_token = token.clone();
        tokio::spawn(async move {
            if let Err(e) = doh_server::serve(handler, listener, task_token, upstream_timeout).await
            {
                warn!(error = %e, "DoH server failed");
            }
        });
        if let Some(old) = self.doh_token.replace(token) {
            old.cancel();
        }
        self.live_doh = Some(addr);
        self.live_doh_timeout = Some(upstream_timeout);
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
        let health_ready = self.health_ready.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(
                metrics,
                query_log,
                listener,
                path_for_task,
                task_token,
                health_ready,
            )
            .await
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
        let new_doq = match cfg
            .server
            .doq_listen
            .as_deref()
            .map(|s| s.parse::<SocketAddr>())
            .transpose()
        {
            Ok(v) => v,
            Err(_) => {
                warn!("SIGHUP: server.doq_listen unparseable; DNS listeners unchanged");
                return;
            }
        };
        let new_tls = (
            cfg.server.tls_cert_path.clone(),
            cfg.server.tls_key_path.clone(),
        );
        if new_listen == self.live_listen
            && new_dot == self.live_dot
            && new_doq == self.live_doq
            && new_tls == self.live_tls_paths
        {
            return; // nothing changed
        }

        let mut group = new_listen.clone();
        if let Some(d) = new_dot {
            group.push(d);
        }
        if let Some(d) = new_doq {
            group.push(d);
        }
        if !listeners::all_unprivileged(&group) {
            warn!(
                "SIGHUP: DNS/DoT/DoQ listener change needs a process restart — the new config \
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
        let doq_tls = if new_doq.is_some() {
            match load_doq_tls_config(&cfg.server) {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!(error = %e, "SIGHUP: DoQ TLS reload failed; keeping current DNS listeners");
                    return;
                }
            }
        } else {
            None
        };

        // Reload always binds fresh: inherited (socket-activated) fds are
        // adopted once, at startup. A live rebind here only ever targets
        // unprivileged ports (privileged ones are restart-required), so an
        // empty inherited set is correct.
        match listeners::build_dns_server(
            self.handler.clone(),
            &new_listen,
            new_dot,
            tls,
            new_doq,
            doq_tls,
            &mut listeners::InheritedSockets::empty(),
        ) {
            Ok(new_server) => {
                let old = self.dns_server.replace(new_server);
                self.live_listen = new_listen.clone();
                self.live_dot = new_dot;
                self.live_doq = new_doq;
                self.live_tls_paths = new_tls;
                info!(
                    listen = ?new_listen,
                    dot = ?new_dot,
                    doq = ?new_doq,
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
        let new_timeout = Duration::from_millis(cfg.upstream.timeout_ms);
        if new_doh == self.live_doh && Some(new_timeout) == self.live_doh_timeout {
            return;
        }
        match new_doh {
            None => {
                if let Some(old) = self.doh_token.take() {
                    old.cancel();
                }
                self.live_doh = None;
                self.live_doh_timeout = None;
                info!("SIGHUP: DoH listener removed");
            }
            Some(addr) if listeners::is_privileged(&addr) => {
                warn!(listen = %addr, "SIGHUP: DoH listener change needs a restart — privileged port (<1024), capabilities dropped; NOT applied");
            }
            Some(addr) => {
                let upstream_timeout = Duration::from_millis(cfg.upstream.timeout_ms);
                let tls_configured =
                    cfg.server.tls_cert_path.is_some() && cfg.server.tls_key_path.is_some();
                if let Err(e) = self.install_doh(addr, upstream_timeout, tls_configured) {
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
        let new_path = match normalize_metrics_path(&cfg.metrics.path) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    error = %e,
                    "SIGHUP: metrics.path invalid; metrics listener unchanged"
                );
                return;
            }
        };
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

        // CDN-hammering guard for the SIGHUP path: the periodic blocklist
        // reload enforces >= 300s between fetch rounds; without a floor
        // here, a flapping config-management system or logrotate script
        // re-fetching per signal hammers every source. The first SIGHUP is
        // always allowed.
        let mut last_fetch_round: Option<tokio::time::Instant> = None;

        loop {
            tokio::select! {
                _ = hup.recv() => {
                    handle_sighup(
                        active,
                        handler,
                        startup_config,
                        loader,
                        engine,
                        authority,
                        metrics,
                        config_path,
                        &mut last_fetch_round,
                    )
                    .await;
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
    last_fetch_round: &mut Option<tokio::time::Instant>,
) {
    info!("SIGHUP received — reloading blocklists, mesh-zone bundle, and config");

    // CDN-hammering guard (AGENTS.md applies the same rationale to the
    // periodic path's >= 300s floor): a rapid SIGHUP stream must not turn
    // into one full source re-fetch per signal. Only the FETCH round is
    // spaced; mesh verification, config parsing, and listener reconciliation
    // below still run every time.
    let now = tokio::time::Instant::now();
    // Option, not `now - spacing`: a fresh-boot start would underflow the
    // monotonic clock. None means no round yet and is always allowed.
    if !fetch_spacing_ok(
        last_fetch_round.map(|t| now.duration_since(t)),
        MIN_SIGHUP_FETCH_SPACING,
    ) {
        info!(
            "SIGHUP: skipping blocklist fetch round (minimum spacing not elapsed); sources \
             unchanged since the last fetch"
        );
        metrics.mark_blocklist_reload_skipped();
    } else {
        *last_fetch_round = Some(now);
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

#[cfg(test)]
mod safesearch_combine_tests {
    use super::*;

    #[test]
    fn operator_rewrites_override_injected_safesearch_rules() {
        // Documented contract: Safe Search rules are injected FIRST so an
        // explicit [[rewrite]] for the same name overrides them — an
        // operator who pins google.com to their own mirror must win over
        // the built-in forcesafesearch CNAME. Rewriting the combine order
        // (or switching RewriteMap::from_rules to first-insert-wins) would
        // silently break operator customisation.
        let mut cfg = rustydns_core::config::DnsConfig::default();
        cfg.safesearch.enabled = true;
        cfg.safesearch.google = true;
        cfg.rewrite.push(rustydns_core::config::RewriteRule {
            name: "google.com".to_string(),
            address: Some("10.0.0.9".to_string()),
            target: None,
            block: false,
        });

        let rules = combined_rewrite_rules(&cfg);
        assert!(
            !rules.is_empty(),
            "safesearch rules must be injected when enabled"
        );

        let map = crate::rewrite::RewriteMap::from_rules(&rules);
        match map.lookup("google.com.", hickory_proto::rr::RecordType::A) {
            Some(crate::rewrite::RewriteDecision::Answer(recs)) => {
                assert_eq!(
                    recs.len(),
                    1,
                    "operator override must replace the safesearch CNAME: {recs:?}"
                );
                assert!(
                    matches!(&recs[0].data, rustydns_core::record::RecordData::A(ip) if ip.to_string() == "10.0.0.9"),
                    "operator address must win, got {:?}",
                    recs[0].data
                );
            }
            other => panic!("operator rewrite must win over safesearch, got {other:?}"),
        }

        // Non-overridden engines still enforce.
        match map.lookup("www.bing.com.", hickory_proto::rr::RecordType::A) {
            Some(crate::rewrite::RewriteDecision::Answer(recs)) => {
                assert!(
                    matches!(&recs[0].data, rustydns_core::record::RecordData::Cname(t)
                    if t == "strict.bing.com."),
                    "bing strict must still apply: {:?}",
                    recs[0].data
                );
            }
            other => panic!("expected bing strict CNAME, got {other:?}"),
        }
    }
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
    // These are compiled into the engine at startup (the SIGHUP path re-fetches
    // blocklist *content* but does not rebuild the engine from the new config),
    // so a change to them needs a restart. Flag them rather than silently
    // ignoring. `allowlist` is rebuilt from the engine's startup config on every
    // content reload, so a config-file allowlist change is also restart-only.
    if old.blocklist.allowlist != new.blocklist.allowlist {
        changed.push("blocklist.allowlist");
    }
    if old.blocklist.block_cname_cloaking != new.blocklist.block_cname_cloaking {
        changed.push("blocklist.block_cname_cloaking");
    }
    if old.blocklist.response_ip_denylist != new.blocklist.response_ip_denylist {
        changed.push("blocklist.response_ip_denylist");
    }
    if old.blocklist.regex_rules != new.blocklist.regex_rules {
        changed.push("blocklist.regex_rules");
    }
    // Group *definitions* (names/sources/allowlist) are baked into the engine's
    // group map at startup; the SIGHUP loader re-fetches a group's content but
    // cannot add/remove groups or change their source URLs. Restart-only.
    if old.blocklist.groups != new.blocklist.groups {
        changed.push("blocklist.groups");
    }
    // Authority fields are baked into the Authority instance at startup:
    // SIGHUP re-reads the BUNDLE (content) but cannot rebuild static
    // records, rename the served zone, or move the poll loop. Flag them
    // rather than letting a reload appear to succeed while nothing changed.
    // StaticRecord does not derive PartialEq; a stable Debug dump gives the
    // same change-detection without widening its derived traits.
    if format!("{:?}", old.authority.static_records)
        != format!("{:?}", new.authority.static_records)
    {
        changed.push("authority.static_records");
    }
    if old.authority.mesh_zone != new.authority.mesh_zone {
        changed.push("authority.mesh_zone");
    }
    if old.authority.mesh_zone_max_age_secs != new.authority.mesh_zone_max_age_secs {
        changed.push("authority.mesh_zone_max_age_secs");
    }
    if old.authority.poll_interval_secs != new.authority.poll_interval_secs {
        changed.push("authority.poll_interval_secs");
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
    shutdown_timeout_from(
        std::env::var("RUSTYDNS_SHUTDOWN_TIMEOUT_SECS")
            .ok()
            .as_deref(),
    )
}

/// Pure core of [`shutdown_timeout_from_env`], unit-testable without
/// process-global env mutation (which is `unsafe` under the workspace-wide
/// `forbid(unsafe_code)`).
fn shutdown_timeout_from(raw: Option<&str>) -> Duration {
    const DEFAULT_SECS: u64 = 10;
    let secs = raw
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

    // Canonicalise IPv4-mapped spellings BEFORE the loopback decision —
    // the same rule as MetricsConfig::effective_listen in core. Binding
    // must agree with what validate_config collision-checked: treating
    // `::ffff:x.x.x.x` as V6 here would bind [::1] where validation
    // cleared 127.0.0.1 (or vice versa), reopening a random-role overlap
    // on SO_REUSEPORT sockets.
    let ip = match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };

    if ip.is_loopback() {
        return Ok(SocketAddr::new(ip, addr.port()));
    }

    warn!(
        listen = %metrics.listen,
        "metrics.listen is not loopback; forcing loopback to avoid public exposure"
    );

    let loopback_ip = match ip {
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };

    Ok(SocketAddr::new(loopback_ip, addr.port()))
}

/// Paths owned by fixed endpoints on the metrics listener. A configured
/// `metrics.path` colliding with either would insert a duplicate axum route,
/// which panics at serve time ("Overlapping method route") — fatal under the
/// release profile's `panic = "abort"`.
const RESERVED_METRICS_PATHS: [&str; 2] = ["/health", "/queries"];

/// Minimum spacing between SIGHUP-triggered blocklist fetch rounds. The
/// periodic reload path enforces >= 300s (reload_interval_secs floor) for the
/// same reason; SIGHUP is a force-refresh, but a flapping automation loop
/// must not re-fetch every source per signal.
const MIN_SIGHUP_FETCH_SPACING: tokio::time::Duration = tokio::time::Duration::from_secs(60);

/// Pure core of the SIGHUP spacing guard: `None` elapsed means no round has
/// run yet (always allowed); otherwise the round must be at least `min` old.
fn fetch_spacing_ok(last_elapsed: Option<Duration>, min: Duration) -> bool {
    match last_elapsed {
        None => true,
        Some(d) => d >= min,
    }
}

/// Normalise `metrics.path` (trim, ensure a leading slash, default
/// `/metrics`) and reject paths that collide with the reserved `/health` and
/// `/queries` endpoints. Both call sites — startup (fatal) and SIGHUP reload
/// (warn + keep current) — flow through here, so the collision can never
/// reach the router.
fn normalize_metrics_path(path: &str) -> anyhow::Result<String> {
    let trimmed = path.trim();
    let normalised = if trimmed.is_empty() {
        "/metrics".to_string()
    } else if let Some(rest) = trimmed.strip_prefix('/') {
        format!("/{rest}")
    } else {
        format!("/{trimmed}")
    };
    if RESERVED_METRICS_PATHS.contains(&normalised.as_str()) {
        anyhow::bail!(
            "metrics.path `{path}` collides with the fixed `{normalised}` endpoint; pick \
             another path (the metrics listener always serves /health and /queries)"
        );
    }
    // axum routes through matchit, where `{...}` is a parameter capture
    // and `{*...}` a tail wildcard. A configured path carrying those
    // characters would register a capture-all route — widening the reach
    // of the UNAUTHENTICATED metrics endpoint to arbitrary paths — or be
    // rejected by matchit at insert time, panicking inside the spawned
    // server task and silently killing the listener. Reject up front.
    if normalised.contains('{') || normalised.contains('}') || normalised.contains('*') {
        anyhow::bail!(
            "metrics.path `{path}` contains router metacharacters (`{{`, `}}`, `*`) that axum/matchit would interpret as parameter or wildcard captures; use a plain literal path"
        );
    }
    // RFC 3986 §3.3 dot-segments. Our router matches the RAW configured
    // bytes, but clients and intermediaries (browsers, reverse proxies,
    // gateways) normalise `.` / `..` segments before forwarding — so a
    // path like `/./health` serves metrics at this address while looking
    // like `/health` to every hop in front of the daemon. That mismatch
    // is an easy way to park the unauthenticated metrics endpoint on a
    // path that monitoring and ACLs believe is the health check. Reject
    // rather than silently rewriting operator config. Percent-encoded
    // spellings count too: most clients percent-decode `%2e` BEFORE path
    // normalisation, so `/%2e/health` normalises to `/health` on the way
    // in even though this daemon routes it as a distinct literal.
    if normalised.split('/').any(is_dot_segment) {
        anyhow::bail!(
            "metrics.path `{path}` contains RFC 3986 dot-segments (`.` or `..`, including percent-encoded %2e spellings) that clients and proxies may normalise onto a different route than this daemon serves; use a plain literal path"
        );
    }
    Ok(normalised)
}

/// Is this path segment a dot-segment — literally (`.` / `..`) or via a
/// minimal percent-decoding of the only byte that matters here (`%2e`,
/// case-insensitive)? A conservative decoder: invalid or non-`%2e` escapes
/// are left verbatim, so `/%2etrics` stays a legal literal segment.
fn is_dot_segment(seg: &str) -> bool {
    if seg == "." || seg == ".." {
        return true;
    }
    let bytes = seg.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 3 <= bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0) as u8;
            decoded.push(hi * 16 + lo);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    decoded.as_slice() == b"." || decoded.as_slice() == b".."
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

/// Fail-closed gate for the DoH bind address.
///
/// The DoH listener speaks PLAINTEXT HTTP/2 (`doh.rs`) — TLS is expected
/// to be terminated by a reverse proxy in front of it. Binding it to a
/// non-loopback address without any TLS material configured
/// (`server.tls_cert_path` + `server.tls_key_path`, the only evidence a
/// deployment terminates TLS at all) would publish an open, unencrypted
/// DNS resolver, so the bind is refused. Mirror `MetricsConfig::
/// effective_listen`: canonicalise IPv4-mapped V6 forms first so
/// `[::ffff:203.0.113.7]` is judged by the public address it really is,
/// not by its `::ffff:` spelling. A non-loopback bind WITH TLS material
/// configured is accepted, but still warned about (the DoH port itself
/// stays plaintext; only the proxy terminates TLS).
fn ensure_doh_bind_allowed(addr: SocketAddr, tls_configured: bool) -> Result<()> {
    let ip = match addr.ip() {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        v4 => v4,
    };
    if ip.is_loopback() {
        return Ok(());
    }
    if !tls_configured {
        bail!(
            "server.doh_listen `{addr}` is not a loopback address and no TLS cert/key \
             is configured; refusing to serve plaintext DNS-over-HTTPS on a public \
             interface. Bind DoH to 127.0.0.1 behind a TLS-terminating reverse proxy. \
             server.tls_cert_path and server.tls_key_path only PERMIT a non-loopback \
             bind — they do not make DoH itself TLS: the DoH port serves PLAINTEXT \
             HTTP/2 and TLS must be terminated by an operator-provided reverse proxy."
        );
    }
    warn!(
        listen = %addr,
        "DoH listener is not loopback; tls_cert_path/tls_key_path only permit this bind \
         and do NOT secure DoH itself — the DoH port still serves PLAINTEXT HTTP/2, so \
         an operator-provided TLS reverse proxy and access controls must sit in front"
    );
    Ok(())
}

/// Build a rustls [`TlsServerConfig`] from the cert+key paths in
/// `server`. Called when `dot_listen` is configured.
fn load_tls_config(server: &ServerConfig) -> Result<Arc<TlsServerConfig>> {
    // DoT (TCP): no ALPN restriction — RFC 7858 doesn't require it, and pinning
    // one would break clients that negotiate a different protocol name.
    build_tls_server_config(server, &[])
}

/// Like [`load_tls_config`] but with the `doq` ALPN set, as RFC 9250 / hickory's
/// QUIC server require. A separate config (not the DoT one) because the DoT
/// listener must NOT advertise `doq`.
fn load_doq_tls_config(server: &ServerConfig) -> Result<Arc<TlsServerConfig>> {
    build_tls_server_config(server, &[b"doq"])
}

fn build_tls_server_config(server: &ServerConfig, alpn: &[&[u8]]) -> Result<Arc<TlsServerConfig>> {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let cert_path = server.tls_cert_path.as_ref().ok_or_else(|| {
        anyhow!("server.tls_cert_path must be set when a DoT/DoQ listener is enabled")
    })?;
    let key_path = server.tls_key_path.as_ref().ok_or_else(|| {
        anyhow!("server.tls_key_path must be set when a DoT/DoQ listener is enabled")
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

    // TLS 1.3 ONLY: pin the protocol floor before any suite selection.
    // `with_protocol_versions(&[&rustls::version::TLS13])` restricts
    // the versions the server will negotiate, so a TLS 1.2 ClientHello is
    // answered with a `protocol_version` alert instead of a handshake — there
    // is no way for a client to downgrade the DoT/DoQ listeners. Both RFC
    // 7858 (DoT) and RFC 9250 (DoQ) clients we target speak TLS 1.3, and
    // keeping 1.2 enabled would only serve downgrade-and-strip middleboxes.
    // The `ring` CryptoProvider is passed EXPLICITLY via
    // `builder_with_provider` rather than relying on the process-default
    // provider: production code never calls `install_default` (only tests
    // do), so the default builder's implicit "ambient process state, else
    // crate-feature" selection is exactly the kind of hidden dependency a
    // crypto-critical config must not have. `with_protocol_versions` returns
    // `Result` (suite selection can fail for the pinned versions), hence `?`.
    let builder = TlsServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("invalid TLS key or certificate: {e}"))?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

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
    fn hickory_clamp_override_requires_exact_target_match() {
        use super::hickory_clamp_overridden;
        // Exact per-crate override works.
        assert!(hickory_clamp_overridden(
            &["hickory_resolver".to_string()],
            "hickory_resolver"
        ));
        // Substring containment must NOT count: `my_hickory_server=debug`
        // is an unrelated target, and a bare substring check would silently
        // disable the qname clamp for ALL three crates.
        assert!(!hickory_clamp_overridden(
            &["my_hickory_server".to_string()],
            "hickory_server"
        ));
        // A different crate's override does not stand down the others.
        assert!(!hickory_clamp_overridden(
            &["hickory_proto".to_string()],
            "hickory_server"
        ));
        // A strict-PREFIX target ("hickory") must not stand down the clamp
        // for "hickory_server": only naming a crate exactly counts, else
        // one broad RUST_LOG target would unclamp all three crates at once.
        assert!(!hickory_clamp_overridden(
            &["hickory".to_string()],
            "hickory_server"
        ));
    }

    #[test]
    fn hickory_clamp_directives_cover_all_four_crates() {
        use super::hickory_clamp_directives;
        // Empty targets (default startup): ALL four crates clamped.
        let d = hickory_clamp_directives(&[]);
        assert_eq!(d.len(), 4, "all four crates must be clamped: {d:?}");
        for c in [
            "hickory_server",
            "hickory_proto",
            "hickory_resolver",
            "hickory_net",
        ] {
            assert!(
                d.contains(&format!("{c}=warn")),
                "missing clamp directive for {c}: {d:?}"
            );
        }
        // Exact override of one crate drops only its directive.
        let d = hickory_clamp_directives(&["hickory_net".to_string()]);
        assert_eq!(d.len(), 3, "overridden crate must be dropped: {d:?}");
        assert!(!d.iter().any(|x| x.contains("hickory_net")));
    }

    // BARE-LEVEL directive (RUST_LOG=debug, no `target=` form): the
    // directive text lands in the targets list as the literal "debug",
    // which matches no hickory crate name - so the clamp MUST stay
    // engaged for all four. Pins that a plain level bump cannot
    // silently unclamp hickory's qname-bearing internals.
    #[test]
    fn bare_level_directive_does_not_override_hickory_clamp() {
        let targets: Vec<String> = ["debug".to_string()].to_vec();
        let directives = hickory_clamp_directives(&targets);
        assert_eq!(
            directives.len(),
            4,
            "all four crates clamped: {directives:?}"
        );
        for c in [
            "hickory_server",
            "hickory_proto",
            "hickory_resolver",
            "hickory_net",
        ] {
            assert!(
                directives.contains(&format!("{c}=warn")),
                "missing clamp directive for {c}: {directives:?}"
            );
        }
    }

    #[test]
    fn normalize_metrics_path_prepends_slash() {
        assert_eq!(normalize_metrics_path("").unwrap(), "/metrics");
        assert_eq!(normalize_metrics_path("foo").unwrap(), "/foo");
        assert_eq!(normalize_metrics_path("/foo").unwrap(), "/foo");
        assert_eq!(normalize_metrics_path("  /foo  ").unwrap(), "/foo");
    }

    #[test]
    fn fetch_spacing_ok_none_means_always_allowed() {
        use super::fetch_spacing_ok;
        // None = no round has run yet (fresh boot or first SIGHUP): allowed.
        assert!(fetch_spacing_ok(None, Duration::from_secs(60)));
        // Recent round: refused.
        assert!(!fetch_spacing_ok(
            Some(Duration::from_secs(30)),
            Duration::from_secs(60)
        ));
        // EXACTLY at the minimum: allowed (inclusive >=). Pins the
        // off-by-one boundary — a strict `>` would defer SIGHUPs spaced
        // precisely at the configured interval.
        assert!(fetch_spacing_ok(
            Some(Duration::from_secs(60)),
            Duration::from_secs(60)
        ));
        // Old-enough round: allowed.
        assert!(fetch_spacing_ok(
            Some(Duration::from_secs(61)),
            Duration::from_secs(60)
        ));
    }

    #[test]
    fn normalize_metrics_path_rejects_reserved_endpoints() {
        // A metrics.path colliding with the fixed /health or /queries
        // endpoints would insert a duplicate axum route — a PANIC at serve
        // time ("Overlapping method route"), fatal under release
        // panic=abort and reachable from both startup and SIGHUP. Both
        // reserved paths must be rejected with a name-the-collision error.
        for bad in ["/health", "/queries", "health", "queries"] {
            let err = normalize_metrics_path(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad} must be rejected"));
            let msg = format!("{err:#}");
            assert!(
                msg.contains("collides"),
                "{bad} rejection must explain the collision: {msg}"
            );
        }
        // Sanity: non-reserved paths still pass.
        assert!(normalize_metrics_path("/mymetrics").is_ok());
    }

    #[test]
    fn metrics_path_router_metacharacters_are_rejected() {
        // axum/matchit treat `{...}` as a parameter capture and `{*...}`
        // as a tail wildcard. A configured metrics.path carrying them
        // would either register a capture-all route for the UNAUTHENTICATED
        // metrics endpoint or panic at insert inside the spawned server
        // task. Both spellings must be rejected with a metacharacter error.
        for bad in [
            "/{p}",       // single-segment capture-all
            "/{*rest}",   // tail wildcard
            "/met{rics}", // embedded brace, still matchit syntax
            "/*",         // bare star rejected conservatively
        ] {
            let err = normalize_metrics_path(bad).expect_err("metacharacter path must be rejected");
            let msg = format!("{err:#}");
            assert!(msg.contains("metacharacters"), "msg = {msg}");
        }
    }

    #[test]
    fn metrics_path_dot_segments_are_rejected() {
        // RFC 3986 §3.3 dot-segments split the address space: this daemon's
        // router matches raw configured bytes, while browsers and reverse
        // proxies normalise `.`/`..` before forwarding — so `/./health`
        // would park the UNAUTHENTICATED metrics endpoint on a path every
        // intermediary treats as the health route. Every dot-segment
        // spelling must be rejected with a dot-segment error, including
        // after whitespace trim (the operator may write " ./health ").
        for bad in [
            "./health",     // no leading slash: normalize prepends one
            "/./health",    // the /health shadow
            "/health/.",    // trailing dot-segment
            "/../metrics",  // parent escape
            "/a/./b",       // embedded mid-path
            "/././metrics", // repeated
            // Percent-encoded spellings decode to `.` in browsers/proxies
            // before normalisation — same shadow, sneakier bytes.
            "/%2e/health",     // %2e == "."
            "/%2E%2E/metrics", // uppercase hex == ".."
            "/x/.%2e/queries", // mixed literal + encoded == ".."
        ] {
            let err = normalize_metrics_path(bad).expect_err("dot-segment path must be rejected");
            let msg = format!("{err:#}");
            assert!(msg.contains("dot-segments"), "msg = {msg}");
        }
        // Dot-free paths that merely CONTAIN dots inside labels stay legal —
        // including escapes that are NOT `%2e` (the decoder must not
        // over-reject: `2r` is not a hex pair, so it stays verbatim).
        for good in ["/metrics", "/m.etrics", "/v1.2/metrics", "/%2etrics"] {
            normalize_metrics_path(good).expect("dot-in-label path must be accepted");
        }
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
    fn restrictive_umask_makes_new_files_owner_only() {
        use nix::sys::stat::{Mode, umask};
        use std::os::unix::fs::PermissionsExt;
        // Save and restore the process-wide mask so parallel tests that
        // create files are unaffected outside this window.
        let saved = umask(Mode::empty());
        {
            set_restrictive_umask();
            let p = tmp_path("umask-probe.txt");
            std::fs::File::create(&p).expect("create probe");
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "files created under the daemon umask must be owner-only, got {mode:o}"
            );
            let _ = std::fs::remove_file(&p);
        }
        umask(saved);
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
            msg.contains("cannot read config file"),
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
    fn restart_required_flags_authority_field_changes() {
        // Authority state is baked into the Authority instance at startup;
        // SIGHUP only re-reads the bundle CONTENT. Any change to these
        // fields must be surfaced as restart-required instead of silently
        // doing nothing.
        let old = base_config();
        let mut new = base_config();
        new.authority.static_records = vec![rustydns_core::config::StaticRecord {
            name: "new.mesh".to_string(),
            record_type: "A".to_string(),
            address: Some("10.0.0.9".to_string()),
            target: None,
            ttl: 300,
            client_filter: None,
        }];
        // Keep server/authority zones CONSISTENT (both renamed) — the
        // startup divergence check would otherwise reject this pair before
        // restart-required logic ever runs.
        new.authority.mesh_zone = "mesh2.".to_string();
        new.server.mesh_zone = "mesh2.".to_string();
        new.authority.mesh_zone_max_age_secs = 900;
        new.authority.poll_interval_secs = 60;

        let changed = restart_required_changes(&old, &new);
        for label in [
            "authority.static_records",
            "authority.mesh_zone",
            "authority.mesh_zone_max_age_secs",
            "authority.poll_interval_secs",
        ] {
            assert!(changed.contains(&label), "missing {label}: {changed:?}");
        }
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
            block_windows: Vec::new(),
            blocklist_group: None,
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

    #[test]
    fn restart_required_ignores_rewrite_and_safesearch() {
        // Rewrites and safe search hot-swap on SIGHUP — not restart-required.
        let a = base_config();
        let mut b = base_config();
        b.rewrite.push(rustydns_core::config::RewriteRule {
            name: "x.example.com".to_string(),
            address: Some("10.0.0.1".to_string()),
            target: None,
            block: false,
        });
        b.safesearch.enabled = true;
        assert!(
            restart_required_changes(&a, &b).is_empty(),
            "rewrite/safesearch changes hot-swap and must not be flagged restart-required"
        );
    }

    #[test]
    fn restart_required_flags_startup_fixed_blocklist_fields() {
        // block_cname_cloaking / response_ip_denylist / regex_rules are
        // compiled into the engine at startup → restart-required.
        let a = base_config();
        let mut b = base_config();
        b.blocklist.block_cname_cloaking = !a.blocklist.block_cname_cloaking;
        b.blocklist.response_ip_denylist = vec!["1.2.3.0/24".to_string()];
        b.blocklist.regex_rules = vec!["tracker".to_string()];
        let changed = restart_required_changes(&a, &b);
        assert!(changed.contains(&"blocklist.block_cname_cloaking"));
        assert!(changed.contains(&"blocklist.response_ip_denylist"));
        assert!(changed.contains(&"blocklist.regex_rules"));
    }

    /// Minimal live-generation stand-in for the reload guards: a real
    /// handler (empty authority/blocklist, unreachable upstream) plus
    /// baseline unprivileged listener state, no hickory server attached
    /// (the reload paths under test never touch it).
    async fn reload_test_listeners() -> ActiveListeners {
        let mut cfg = base_config();
        cfg.upstream.resolvers = vec!["https://127.0.0.1:1/dns-query".to_string()];
        cfg.upstream.timeout_ms = 500;
        cfg.privacy.randomize_upstream_selection = false;
        cfg.upstream.dnssec_validation = false;

        let authority = Arc::new(
            Authority::new(rustydns_core::config::AuthorityConfig {
                mesh_zone_bundle_path: None,
                mesh_zone_verifier_key_path: None,
                mesh_zone_max_age_secs: 600,
                mesh_zone: "mesh.".to_string(),
                static_records: Vec::new(),
                poll_interval_secs: 30,
            })
            .expect("authority"),
        );
        let blocklist = Arc::new(BlocklistEngine::new(
            rustydns_core::config::BlocklistConfig {
                sources: Vec::new(),
                reload_interval_secs: 0,
                ..rustydns_core::config::BlocklistConfig::default()
            },
        ));
        let resolver = Arc::new(Resolver::new(cfg).await.expect("resolver"));
        ActiveListeners {
            handler: DnsHandler::new(
                authority,
                blocklist,
                resolver,
                Arc::new(Metrics::new().expect("metrics")),
                Arc::new(crate::query_log::QueryLog::new(64)),
                Arc::new(crate::rate_limiter::RateLimiter::new(
                    &rustydns_core::config::RateLimitConfig {
                        enabled: false,
                        ..Default::default()
                    },
                )),
                &[],
                &[],
            )
            .expect("handler"),
            metrics: Arc::new(Metrics::new().expect("metrics")),
            query_log: Arc::new(crate::query_log::QueryLog::new(64)),
            parent_shutdown: CancellationToken::new(),
            dns_server: None,
            doh_token: Some(CancellationToken::new()),
            metrics_token: Some(CancellationToken::new()),
            live_listen: Vec::new(),
            live_dot: None,
            live_doq: None,
            live_tls_paths: (None, None),
            live_doh: Some("127.0.0.1:8053".parse().unwrap()),
            live_doh_timeout: Some(Duration::from_millis(5000)),
            live_metrics: Some("127.0.0.1:8089".parse().unwrap()),
            live_metrics_path: "/metrics".to_string(),
            health_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    #[tokio::test]
    async fn sighup_refuses_privileged_listener_move_after_capability_drop() {
        // drop_capabilities() clears every capability set after the
        // privileged binds, so a LIVE rebind onto <1024 is impossible by
        // design — SIGHUP must refuse the move and keep serving on the old
        // binding instead of failing to bind (or worse, silently dropping
        // the listener). This pins both refusal guards cross-platform; the
        // kernel cap-clear itself is Linux prctl/caps, enforced additionally
        // by the systemd CapabilityBoundingSet.
        let mut al = reload_test_listeners().await;

        // DoH leg: move onto :853 must be refused, state untouched.
        let mut cfg = base_config();
        cfg.server.doh_listen = Some("127.0.0.1:853".to_string());
        al.reload_doh_group(&cfg);
        assert_eq!(
            al.live_doh,
            Some("127.0.0.1:8053".parse().unwrap()),
            "privileged DoH move must NOT be applied live"
        );
        assert!(
            al.doh_token.is_some(),
            "current DoH listener must stay alive"
        );

        // Metrics leg: same guard before install_metrics.
        let mut cfg = base_config();
        cfg.metrics.listen = "127.0.0.1:853".to_string();
        al.reload_metrics_group(&cfg);
        assert_eq!(
            al.live_metrics,
            Some("127.0.0.1:8089".parse().unwrap()),
            "privileged metrics move must NOT be applied live"
        );
        assert!(
            al.metrics_token.is_some(),
            "current metrics listener must stay alive"
        );
    }

    #[tokio::test]
    async fn sighup_rebinds_doh_when_only_upstream_timeout_changes() {
        // The DoH deadline derives from upstream.timeout_ms. If a SIGHUP
        // changes ONLY that value, reload_doh_group must NOT take the
        // address-unchanged fast path — otherwise the running HTTP server
        // keeps the old deadline while the rebuilt resolver honours the new
        // one, reintroducing the transport race for that timeout.
        let mut al = reload_test_listeners().await;

        let mut cfg = base_config();
        cfg.server.doh_listen = Some("127.0.0.1:8053".to_string()); // same addr as live
        cfg.upstream.timeout_ms = 900; // differs from the 5000 recorded
        al.reload_doh_group(&cfg);

        assert_eq!(
            al.live_doh_timeout,
            Some(Duration::from_millis(900)), // raw upstream ms (derive happens in serve)
            "timeout-only change must force a DoH rebind tracking the new upstream timeout"
        );

        // Idempotent leg: reloading with identical settings must be a no-op
        // (no spurious rebinds).
        let before = al.live_doh_timeout;
        al.reload_doh_group(&cfg);
        assert_eq!(
            al.live_doh_timeout, before,
            "identical reload must not churn"
        );
    }

    #[tokio::test]
    async fn sighup_metrics_rebind_cannot_land_on_non_loopback() {
        // Wiring pin for the bind-safety invariant: reload_metrics_group
        // must derive its address THROUGH metrics_listen_addr (the forcing
        // choke point), never by re-parsing cfg.metrics.listen directly.
        // A hostile or misconfigured SIGHUP config pointing the
        // unauthenticated metrics endpoint at a public, wildcard, or
        // v4-mapped address must be applied FORCED — loopback IP with the
        // operator's port preserved. If a refactor bypasses the choke
        // point, these legs fail because live_metrics records exactly what
        // was bound.
        let mut al = reload_test_listeners().await;

        // Leg 1: explicit public IPv4.
        let mut cfg = base_config();
        cfg.metrics.listen = "203.0.113.9:9207".to_string();
        al.reload_metrics_group(&cfg);
        assert_eq!(
            al.live_metrics,
            Some("127.0.0.1:9207".parse().unwrap()),
            "public IPv4 metrics listen must be forced to loopback on SIGHUP reload"
        );

        // Leg 2: wildcard IPv6 (an attempt to bind all interfaces).
        let mut cfg = base_config();
        cfg.metrics.listen = "[::]:9208".to_string();
        al.reload_metrics_group(&cfg);
        assert_eq!(
            al.live_metrics,
            Some("[::1]:9208".parse().unwrap()),
            "wildcard IPv6 metrics listen must be forced to ::1 on SIGHUP reload"
        );

        // Leg 3: v4-mapped public IPv6 — canonicalised to its embedded v4
        // first (same rule as core's effective_listen), which is not
        // loopback, so it hits the forcing branch: 127.0.0.1, matching what
        // validate_config collision-checked.
        let mut cfg = base_config();
        cfg.metrics.listen = "[::ffff:203.0.113.9]:9209".to_string();
        al.reload_metrics_group(&cfg);
        assert_eq!(
            al.live_metrics,
            Some("127.0.0.1:9209".parse().unwrap()),
            "v4-mapped metrics listen must canonicalise to v4 and force to 127.0.0.1"
        );

        // Leg 4: v4-mapped LOOPBACK spelling passes through as NATIVE V4 —
        // no forcing branch, and the bound socket is the same one the core
        // contract (effective_listen) promised, never a [::1] re-bind.
        let mut cfg = base_config();
        cfg.metrics.listen = "[::ffff:127.0.0.1]:9210".to_string();
        al.reload_metrics_group(&cfg);
        assert_eq!(
            al.live_metrics,
            Some("127.0.0.1:9210".parse().unwrap()),
            "mapped loopback must bind native 127.0.0.1, not [::1]"
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_honours_deadline_and_cancels_children() {
        use std::time::Instant;
        // Bounded shutdown contract, three legs:
        // 1) the configured deadline comes from
        //    RUSTYDNS_SHUTDOWN_TIMEOUT_SECS, clamped to 1..=60 with a 10s
        //    default for unset/invalid values — operators must be able to
        //    reason about how long systemd's TimeoutStopSec needs to be;
        // 2) drain() must return promptly and take BOTH child tokens, so no
        //    DoH/metrics task outlives the deadline;
        // 3) a real (idle) hickory Server generation drains cleanly within
        //    its window — the select! timeout + second-signal escape are the
        //    forcing-exit backstop for generations that hang on in-flight
        //    queries.

        // Leg 1: deadline parsing/clamping (pure core — env::set_var is
        // unsafe under forbid(unsafe_code), so the env wrapper delegates to
        // shutdown_timeout_from and we test that directly).
        assert_eq!(shutdown_timeout_from(None), Duration::from_secs(10));
        assert_eq!(
            shutdown_timeout_from(Some("1")),
            Duration::from_secs(1),
            "in-range values must be honoured"
        );
        assert_eq!(shutdown_timeout_from(Some("60")), Duration::from_secs(60));
        for bad in ["0", "99", "abc", "", " 5", "5 "] {
            assert_eq!(
                shutdown_timeout_from(Some(bad)),
                Duration::from_secs(10),
                "{bad:?} must fall back to the default deadline"
            );
        }

        // Leg 2: token-only drain returns promptly and cancels children.
        let mut al = reload_test_listeners().await;
        let start = Instant::now();
        al.drain(Duration::from_millis(250)).await;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "token-only drain must not block: {:?}",
            start.elapsed()
        );
        assert!(al.doh_token.is_none(), "DoH child task must be cancelled");
        assert!(
            al.metrics_token.is_none(),
            "metrics child task must be cancelled"
        );

        // Leg 3: a REAL idle server generation drains cleanly in-window.
        let mut al2 = reload_test_listeners().await;
        let handler = al2.handler.clone();
        let mut inherited = crate::listeners::InheritedSockets::empty();
        let server = crate::listeners::build_dns_server(
            handler,
            &["127.0.0.1:0".parse().unwrap()],
            None,
            None,
            None,
            None,
            &mut inherited,
        )
        .expect("idle test server");
        al2.dns_server = Some(server);
        let start = Instant::now();
        al2.drain(Duration::from_millis(500)).await;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "idle server drain hung past its window: {:?}",
            start.elapsed()
        );
        assert!(al2.doh_token.is_none());
        assert!(al2.metrics_token.is_none());
    }

    #[test]
    fn metrics_listen_bind_safety_forces_non_loopback_to_loopback() {
        // An unparseable listen must be a hard ERROR, never a silent
        // fallback to some default socket — a silent default could bind
        // the unauthenticated endpoint somewhere unexpected.
        let bad = rustydns_core::config::MetricsConfig {
            listen: "not-a-socket".to_string(),
            ..Default::default()
        };
        let err = metrics_listen_addr(&bad).expect_err("unparseable metrics.listen must fail");
        assert!(
            err.to_string().contains("not a valid socket address"),
            "{err}"
        );

        // The unauthenticated metrics endpoint is the bind-safety invariant
        // this daemon enforces: config warns on non-loopback, and the runtime
        // FORCES the address to loopback while preserving the operator's
        // port. (DNS listeners are intentionally operator-bindable — see the
        // ServerConfig docs; no expose flag exists by design.)
        let v4 = rustydns_core::config::MetricsConfig {
            listen: "0.0.0.0:9153".to_string(),
            ..Default::default()
        };
        let forced = metrics_listen_addr(&v4).expect("v4 parse");
        assert!(
            forced.ip().is_loopback(),
            "non-loopback IPv4 must be forced"
        );
        assert_eq!(forced.port(), 9153, "port must be preserved when forcing");

        let v6 = rustydns_core::config::MetricsConfig {
            listen: "[::]:9153".to_string(),
            ..Default::default()
        };
        let forced6 = metrics_listen_addr(&v6).expect("v6 parse");
        assert_eq!(
            forced6.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
        assert_eq!(forced6.port(), 9153);

        let looped = rustydns_core::config::MetricsConfig {
            listen: "127.0.0.1:9153".to_string(),
            ..Default::default()
        };
        let passthrough = metrics_listen_addr(&looped).expect("loopback parse");
        assert_eq!(passthrough.ip().to_string(), "127.0.0.1");

        // Any 127.0.0.0/8 address is genuinely loopback and must pass
        // through UNFORCED — over-forcing (e.g. tightening the check to an
        // exact == 127.0.0.1 match) would silently rewrite valid operator
        // configs onto a different loopback address.
        let looped_other_octet = rustydns_core::config::MetricsConfig {
            listen: "127.250.250.1:9153".to_string(),
            ..Default::default()
        };
        let passthrough8 = metrics_listen_addr(&looped_other_octet).expect("/8 parse");
        assert_eq!(
            passthrough8.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 250, 250, 1)),
            "the rest of 127.0.0.0/8 must pass through unforced"
        );

        // The default posture is already safe.
        let default_addr = metrics_listen_addr(&rustydns_core::config::MetricsConfig::default())
            .expect("default parse");
        assert!(default_addr.ip().is_loopback());
    }

    #[test]
    fn metrics_listen_bind_safety_rejects_ipv4_mapped_v6_endruns() {
        // IPv4-mapped IPv6 literals are the classic bind-safety confusion
        // vector. They are canonicalised to their embedded v4 first (same
        // rule as core's effective_listen), then loopback-checked and
        // forced — so NO mapped form can yield a non-loopback metrics bind,
        // and mapped LOOPBACK binds natively as v4 instead of being re-bound
        // to [::1] (which would diverge from what validate_config
        // collision-checked).
        let mapped_loopback = rustydns_core::config::MetricsConfig {
            listen: "[::ffff:127.0.0.1]:9153".to_string(),
            ..Default::default()
        };
        let forced = metrics_listen_addr(&mapped_loopback).expect("mapped loopback parse");
        assert_eq!(
            forced.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "mapped loopback must bind NATIVE 127.0.0.1, not [::1]"
        );
        assert_eq!(forced.port(), 9153, "port preserved");
        assert!(forced.ip().is_loopback());

        let mapped_public = rustydns_core::config::MetricsConfig {
            listen: "[::ffff:203.0.113.7]:9153".to_string(),
            ..Default::default()
        };
        let forced_pub = metrics_listen_addr(&mapped_public).expect("mapped public parse");
        assert_eq!(
            forced_pub,
            "127.0.0.1:9153".parse().unwrap(),
            "a v4-mapped public address must be canonicalised and FORCED to loopback"
        );
        assert!(forced_pub.ip().is_loopback());
    }

    #[test]
    fn dot_and_doq_tls_configs_advertise_distinct_alpn() {
        // The DoT and DoQ listeners share ONE certificate pair; the ALPN
        // advertisement is what keeps their protocol identities distinct.
        // RFC 9250 §4.3 requires DoQ to offer exactly "doq"; RFC 7858
        // requires nothing for DoT, and pinning a name there would break
        // compliant clients — so the DoT config must stay ALPN-unrestricted
        // (empty list). A copy-paste of the doq config into the DoT path
        // (or a dedup into one shared TlsServerConfig) would silently
        // change which clients can handshake on each port, so pin BOTH
        // builders' exact contracts here. The wire-level enforcement —
        // that a foreign-ALPN client fails the handshake against the live
        // DoQ listener — is pinned e2e in
        // tests/sighup_reload.rs::doq_listener_rejects_foreign_alpn_clients.
        use crate::test_pem::{TEST_LEAF_CERT_PEM, TEST_LEAF_KEY_PEM};
        let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("leaf.pem");
        let key_path = dir.path().join("leaf-key.pem");
        std::fs::write(&cert_path, TEST_LEAF_CERT_PEM).expect("write cert pem");
        std::fs::write(&key_path, TEST_LEAF_KEY_PEM).expect("write key pem");

        let cfg = ServerConfig {
            tls_cert_path: Some(cert_path),
            tls_key_path: Some(key_path),
            ..Default::default()
        };

        let dot = load_tls_config(&cfg).expect("DoT TLS config builds");
        assert!(
            dot.alpn_protocols.is_empty(),
            "DoT must stay ALPN-unrestricted (RFC 7858), got {:?}",
            dot.alpn_protocols
        );

        let doq = load_doq_tls_config(&cfg).expect("DoQ TLS config builds");
        assert_eq!(
            doq.alpn_protocols,
            vec![b"doq".to_vec()],
            "DoQ must advertise exactly RFC 9250's doq"
        );
    }

    #[test]
    fn doh_bind_gate_refuses_public_bind_without_tls() {
        // The DoH listener serves PLAINTEXT HTTP/2; a public bind without any
        // TLS material configured must fail startup, not warn.
        let err = ensure_doh_bind_allowed("192.0.2.10:8053".parse().unwrap(), false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("doh_listen"), "must name the knob: {msg}");
        assert!(msg.contains("loopback"), "must state the rule: {msg}");
        assert!(
            msg.contains("tls_cert_path"),
            "must name the fix (tls_cert_path/tls_key_path): {msg}"
        );

        // IPv4-mapped V6 spellings of a public address are refused too —
        // same canonicalisation rule as MetricsConfig::effective_listen.
        let err = ensure_doh_bind_allowed("[::ffff:192.0.2.10]:8053".parse().unwrap(), false)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("not a loopback"),
            "mapped-V6 public bind must be judged by its real address: {err:#}"
        );
    }

    #[test]
    fn doh_bind_gate_accepts_loopback_and_tls_backed_public_bind() {
        // Loopback binds (native v4, native v6, mapped form) never need TLS.
        for addr in ["127.0.0.1:8053", "[::1]:8053", "[::ffff:127.0.0.1]:8053"] {
            ensure_doh_bind_allowed(addr.parse().unwrap(), false)
                .unwrap_or_else(|e| panic!("{addr} is loopback and must be accepted: {e:#}"));
        }
        // A non-loopback bind WITH TLS cert/key configured is accepted.
        ensure_doh_bind_allowed("192.0.2.10:8053".parse().unwrap(), true)
            .expect("non-loopback DoH with TLS configured must be accepted");
    }

    #[tokio::test]
    async fn dot_tls_config_refuses_tls12_clienthello_but_accepts_tls13() {
        // Wire-level pin of the TLS 1.3 floor (AQ-14): the DoT/DoQ server
        // config is built with `builder_with_protocol_versions(&[TLS13])`, so
        // a client offering a TLS 1.2 ClientHello must fail the handshake
        // (protocol_version alert), while a TLS 1.3 client still completes it.
        use crate::test_pem::{TEST_CA_PEM, TEST_CERT_CN, TEST_LEAF_CERT_PEM, TEST_LEAF_KEY_PEM};
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, ServerName};

        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );

        let cert = tmp_path("dot13-cert.pem");
        let key = tmp_path("dot13-key.pem");
        write_file(&cert, TEST_LEAF_CERT_PEM.as_bytes());
        write_file(&key, TEST_LEAF_KEY_PEM.as_bytes());
        let acceptor = tokio_rustls::TlsAcceptor::from(
            load_tls_config(&server_with_paths(Some(cert), Some(key)))
                .expect("DoT TLS config builds"),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback TLS listener");
        let port = listener.local_addr().unwrap().port();

        // Server side: accept both legs, record the acceptor verdicts.
        let server = tokio::spawn(async move {
            let mut verdicts = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                verdicts.push(acceptor.accept(stream).await.is_ok());
            }
            verdicts
        });

        let mut roots = rustls::RootCertStore::empty();
        for ca in CertificateDer::pem_slice_iter(TEST_CA_PEM.as_bytes()) {
            roots.add(ca.expect("parse CA pem")).expect("add CA root");
        }
        let server_name = ServerName::try_from(TEST_CERT_CN).expect("test CN is a valid name");

        // Control leg: a TLS 1.3 client completes the handshake.
        let tls13 = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots.clone())
                .with_no_client_auth(),
        ));
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect control leg");
        tls13
            .connect(server_name.clone(), stream)
            .await
            .expect("TLS 1.3 client must complete the handshake");

        // Adversarial leg: a TLS 1.2-only client offers a TLS 1.2 ClientHello.
        // The server is pinned to TLS 1.3, so the handshake must fail.
        let tls12 = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect TLS 1.2 leg");
        let err = tls12
            .connect(server_name, stream)
            .await
            .expect_err("a TLS 1.2 ClientHello must be refused by the TLS-1.3-only server");
        // Downcast to the PRECISE rustls reason, not just is_err(): the
        // TLS-1.3-pinned server answers a 1.2 ClientHello with a
        // `protocol_version` alert, so the client must observe
        // `AlertReceived(ProtocolVersion)`. A generic failure (timeout,
        // unexpected EOF, different alert) would pass is_err() but prove
        // nothing about the downgrade refusal.
        let inner = err
            .into_inner()
            .and_then(|e| e.downcast::<rustls::Error>().ok())
            .expect("tokio-rustls io error must wrap a rustls::Error");
        assert!(
            matches!(
                &*inner,
                rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion)
            ),
            "expected AlertReceived(ProtocolVersion), got: {inner:?}"
        );

        let verdicts = server.await.expect("server task");
        assert_eq!(
            verdicts,
            vec![true, false],
            "server must accept the TLS 1.3 leg and reject the TLS 1.2 leg"
        );
    }
}
