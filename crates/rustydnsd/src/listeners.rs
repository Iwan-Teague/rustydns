#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Socket binding helpers and the hickory DNS-server builder used for
//! both initial startup and live SIGHUP listener handover (roadmap 3.2,
//! Phase 2).
//!
//! # Zero-drop handover
//!
//! Every socket is bound with `SO_REUSEADDR` + `SO_REUSEPORT` (unix) so a
//! reload can bind the *new* generation on the same address while the old
//! one is still draining — no query is lost in the gap. After the old
//! generation finishes draining, the kernel routes everything to the new
//! socket.
//!
//! # Capability discipline vs. live rebind
//!
//! Binding a port below 1024 requires `CAP_NET_BIND_SERVICE`, and
//! `SO_REUSEPORT` does **not** bypass that check. The daemon drops *all*
//! capabilities (including the bounding set) right after the initial
//! privileged binds, so it can never rebind a privileged port again — by
//! design (see `AGENTS.md` §Capability discipline). Therefore live
//! handover is only offered for listeners on **unprivileged** ports
//! (≥ 1024); a privileged listener change is detected on reload and logged
//! as restart-required. [`is_privileged`] is the gate.
//!
//! # Socket activation
//!
//! With systemd socket activation the privileged binds happen *in systemd*,
//! which passes the already-bound sockets to the daemon ([`InheritedSockets`]).
//! The daemon then needs no `CAP_NET_BIND_SERVICE` at all. Adoption is
//! startup-only and matches passed sockets to configured listeners by bound
//! address + type; reload still binds fresh.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use listenfd::ListenFd;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use hickory_server::Server;
use rustls::ServerConfig as TlsServerConfig;

use crate::handler::DnsHandler;

/// TCP/UDP idle timeout for hickory listeners. Matches the value used at
/// the original call sites.
const LISTENER_TIMEOUT: Duration = Duration::from_secs(5);
/// hickory's default response-buffer size for TCP listeners.
const TCP_RESPONSE_BUFFER: usize = 4096;
/// TCP accept backlog.
const TCP_BACKLOG: i32 = 1024;

/// `true` if binding `addr` requires `CAP_NET_BIND_SERVICE` (port < 1024).
///
/// Port 0 ("any") is treated as unprivileged — the kernel assigns a high
/// ephemeral port. We deliberately use the fixed 1024 boundary rather than
/// reading `net.ipv4.ip_unprivileged_port_start`: being over-conservative
/// (refusing a live rebind on a port that *might* be bindable) is safe; the
/// operator can always restart.
pub fn is_privileged(addr: &SocketAddr) -> bool {
    let p = addr.port();
    p != 0 && p < 1024
}

/// `true` if every address in `addrs` is unprivileged — i.e. the group can
/// be rebound live after capabilities have been dropped.
pub fn all_unprivileged(addrs: &[SocketAddr]) -> bool {
    addrs.iter().all(|a| !is_privileged(a))
}

/// Bind a UDP socket with `SO_REUSEADDR` + `SO_REUSEPORT`, ready to hand to
/// `hickory`'s `register_socket`.
pub fn bind_udp(addr: SocketAddr) -> Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("failed to create UDP socket for {addr}"))?;
    set_reuse(&socket)?;
    socket
        .set_nonblocking(true)
        .context("failed to set UDP socket non-blocking")?;
    socket
        .bind(&SockAddr::from(addr))
        .with_context(|| format!("failed to bind UDP socket on {addr}"))?;
    let std_sock: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_sock)
        .with_context(|| format!("failed to convert UDP socket on {addr} to tokio"))
}

/// Bind a listening TCP socket with `SO_REUSEADDR` + `SO_REUSEPORT`, ready
/// to hand to `hickory`'s `register_listener` / an axum server.
pub fn bind_tcp(addr: SocketAddr) -> Result<tokio::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
        .with_context(|| format!("failed to create TCP socket for {addr}"))?;
    set_reuse(&socket)?;
    socket
        .set_nonblocking(true)
        .context("failed to set TCP socket non-blocking")?;
    socket
        .bind(&SockAddr::from(addr))
        .with_context(|| format!("failed to bind TCP socket on {addr}"))?;
    socket
        .listen(TCP_BACKLOG)
        .with_context(|| format!("failed to listen on TCP socket {addr}"))?;
    let std_sock: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_sock)
        .with_context(|| format!("failed to convert TCP listener on {addr} to tokio"))
}

fn set_reuse(socket: &Socket) -> Result<()> {
    socket
        .set_reuse_address(true)
        .context("failed to set SO_REUSEADDR")?;
    // SO_REUSEPORT is unix-only; the `all` feature exposes it. On targets
    // without it we fall back to REUSEADDR alone (live same-port handover
    // is then best-effort, but those targets aren't the deployment target).
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket
        .set_reuse_port(true)
        .context("failed to set SO_REUSEPORT")?;
    Ok(())
}

/// Sockets handed to the daemon by **systemd socket activation** (`LISTEN_FDS`).
///
/// When `rustydnsd` is started by a `.socket` unit, systemd binds the listening
/// sockets itself and passes them in as already-bound file descriptors. Because
/// the privileged `:53` / `:853` binds then happen *in systemd*, the daemon
/// needs **no `CAP_NET_BIND_SERVICE`** at all — the one residual gap in the
/// capability posture (roadmap §7.1) is closed without ever holding the
/// capability.
///
/// This is strictly additive: for every non-socket-activated start (`LISTEN_FDS`
/// unset — Docker, bare binary, `cargo run`, tests) [`InheritedSockets::from_env`]
/// yields an empty set and [`build_dns_server`] binds normally. The single
/// `unsafe` `FromRawFd` adoption lives inside the `listenfd` crate, so this crate
/// stays `#![forbid(unsafe_code)]`.
pub struct InheritedSockets {
    udp: Vec<(SocketAddr, tokio::net::UdpSocket)>,
    tcp: Vec<(SocketAddr, tokio::net::TcpListener)>,
}

impl InheritedSockets {
    /// An empty set — used both for the non-socket-activated path and for
    /// SIGHUP reload (passed fds are adopted exactly once, at startup; a live
    /// rebind always binds fresh).
    pub fn empty() -> Self {
        Self {
            udp: Vec::new(),
            tcp: Vec::new(),
        }
    }

    /// Adopt every socket passed via `LISTEN_FDS`.
    ///
    /// Each fd is probed as a TCP listener first, then as a UDP socket
    /// (`listenfd` leaves the fd in place when the type does not match), made
    /// non-blocking, converted to its tokio type, and tagged with its bound
    /// address so [`build_dns_server`] can match it to a configured listener.
    /// Returns an empty set when the process was not socket-activated.
    ///
    /// Must be called from within the tokio runtime (the `from_std`
    /// conversions register with the reactor).
    pub fn from_env() -> Result<Self> {
        let mut lf = ListenFd::from_env();
        let mut udp = Vec::new();
        let mut tcp = Vec::new();
        for idx in 0..lf.len() {
            if let Some(listener) = lf.take_tcp_listener(idx).ok().flatten() {
                let addr = listener
                    .local_addr()
                    .context("LISTEN_FDS TCP socket has no local address")?;
                listener
                    .set_nonblocking(true)
                    .context("failed to set inherited TCP listener non-blocking")?;
                let listener = tokio::net::TcpListener::from_std(listener)
                    .context("failed to adopt inherited TCP listener into tokio")?;
                tcp.push((addr, listener));
            } else if let Some(socket) = lf.take_udp_socket(idx).ok().flatten() {
                let addr = socket
                    .local_addr()
                    .context("LISTEN_FDS UDP socket has no local address")?;
                socket
                    .set_nonblocking(true)
                    .context("failed to set inherited UDP socket non-blocking")?;
                let socket = tokio::net::UdpSocket::from_std(socket)
                    .context("failed to adopt inherited UDP socket into tokio")?;
                udp.push((addr, socket));
            } else {
                tracing::warn!(
                    fd_index = idx,
                    "LISTEN_FDS entry is neither a TCP listener nor a UDP socket — ignoring"
                );
            }
        }
        Ok(Self { udp, tcp })
    }

    /// `true` if no sockets were inherited (the common, non-socket-activated
    /// case).
    pub fn is_empty(&self) -> bool {
        self.udp.is_empty() && self.tcp.is_empty()
    }

    /// Number of inherited sockets not yet matched to a configured listener.
    /// A non-zero value after [`build_dns_server`] means the `.socket` unit
    /// passed a socket whose address does not match any configured listener.
    pub fn remaining(&self) -> usize {
        self.udp.len() + self.tcp.len()
    }

    /// Take the inherited UDP socket bound to `addr`, if any.
    fn take_udp(&mut self, addr: SocketAddr) -> Option<tokio::net::UdpSocket> {
        let i = self.udp.iter().position(|(a, _)| *a == addr)?;
        Some(self.udp.remove(i).1)
    }

    /// Take the inherited TCP listener bound to `addr`, if any.
    fn take_tcp(&mut self, addr: SocketAddr) -> Option<tokio::net::TcpListener> {
        let i = self.tcp.iter().position(|(a, _)| *a == addr)?;
        Some(self.tcp.remove(i).1)
    }
}

/// Use an inherited (socket-activated) UDP socket bound to `addr` if one was
/// passed, else bind a fresh one with `SO_REUSEPORT`.
fn udp_listener(
    addr: SocketAddr,
    inherited: &mut InheritedSockets,
) -> Result<tokio::net::UdpSocket> {
    match inherited.take_udp(addr) {
        Some(sock) => {
            tracing::info!(listen = %addr, "adopted UDP socket from systemd (LISTEN_FDS)");
            Ok(sock)
        }
        None => bind_udp(addr),
    }
}

/// Use an inherited (socket-activated) TCP listener bound to `addr` if one was
/// passed, else bind a fresh one with `SO_REUSEPORT`.
fn tcp_listener(
    addr: SocketAddr,
    inherited: &mut InheritedSockets,
) -> Result<tokio::net::TcpListener> {
    match inherited.take_tcp(addr) {
        Some(listener) => {
            tracing::info!(listen = %addr, "adopted TCP listener from systemd (LISTEN_FDS)");
            Ok(listener)
        }
        None => bind_tcp(addr),
    }
}

/// Build (and implicitly start) a hickory DNS server for one generation of
/// listeners: UDP + TCP on each `listen` address, plus optional DoT (TCP) and
/// DoQ (UDP/QUIC) listeners. All sockets use `SO_REUSEPORT` so this can be
/// called for a new generation while the previous one is still draining.
///
/// The returned [`Server`] is already serving — `register_*` spawns the
/// accept loops. Drain it with `shutdown_gracefully`.
///
/// `inherited` carries any sockets passed by systemd socket activation
/// ([`InheritedSockets`]). For each address, a matching inherited socket is
/// adopted instead of binding fresh — so under socket activation the privileged
/// binds happen in systemd and the daemon needs no `CAP_NET_BIND_SERVICE`. Pass
/// [`InheritedSockets::empty`] for the non-socket-activated path and for SIGHUP
/// reload (inherited fds are adopted once, at startup).
pub fn build_dns_server(
    handler: DnsHandler,
    listen: &[SocketAddr],
    dot: Option<SocketAddr>,
    tls: Option<Arc<TlsServerConfig>>,
    doq: Option<SocketAddr>,
    doq_tls: Option<Arc<TlsServerConfig>>,
    inherited: &mut InheritedSockets,
) -> Result<Server<DnsHandler>> {
    let mut server = Server::new(handler);

    for addr in listen {
        let udp = udp_listener(*addr, inherited)?;
        server.register_socket(udp);

        let tcp = tcp_listener(*addr, inherited)?;
        server.register_listener(tcp, LISTENER_TIMEOUT, TCP_RESPONSE_BUFFER);
    }

    if let Some(dot_addr) = dot {
        let tls = tls.context("DoT listener configured but no TLS config was provided")?;
        let tcp = tcp_listener(dot_addr, inherited)?;
        server
            .register_tls_listener_with_tls_config(tcp, LISTENER_TIMEOUT, tls)
            .with_context(|| format!("failed to register DoT listener on {dot_addr}"))?;
    }

    if let Some(doq_addr) = doq {
        // DoQ is QUIC → a UDP socket (bound with SO_REUSEPORT for zero-drop
        // SIGHUP handover, like the others). The TLS config carries the `doq`
        // ALPN.
        let doq_tls = doq_tls.context("DoQ listener configured but no DoQ TLS config provided")?;
        let udp = udp_listener(doq_addr, inherited)?;
        server
            .register_quic_listener_and_tls_config(udp, LISTENER_TIMEOUT, doq_tls)
            .with_context(|| format!("failed to register DoQ listener on {doq_addr}"))?;
    }

    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn privileged_port_classification() {
        assert!(is_privileged(&sa("0.0.0.0:53")));
        assert!(is_privileged(&sa("127.0.0.1:853")));
        assert!(is_privileged(&sa("[::1]:443")));
        assert!(!is_privileged(&sa("0.0.0.0:5353")));
        assert!(!is_privileged(&sa("127.0.0.1:9153")));
        // Port 0 = kernel-assigned ephemeral → unprivileged.
        assert!(!is_privileged(&sa("0.0.0.0:0")));
    }

    #[test]
    fn all_unprivileged_requires_every_addr() {
        assert!(all_unprivileged(&[sa("0.0.0.0:5353"), sa("0.0.0.0:8853")]));
        assert!(!all_unprivileged(&[sa("0.0.0.0:5353"), sa("0.0.0.0:53")]));
        assert!(all_unprivileged(&[]));
    }

    #[tokio::test]
    async fn reuseport_allows_two_binds_on_same_port() {
        // The whole point of SO_REUSEPORT: a second bind on a live port
        // succeeds, which is what makes zero-drop handover possible.
        let a = bind_tcp(sa("127.0.0.1:0")).unwrap();
        let port = a.local_addr().unwrap().port();
        let same = SocketAddr::from(([127, 0, 0, 1], port));
        let b = bind_tcp(same).expect("second REUSEPORT bind on the live port must succeed");
        assert_eq!(b.local_addr().unwrap().port(), port);
        drop((a, b));
    }

    #[tokio::test]
    async fn udp_reuseport_allows_two_binds_on_same_port() {
        let a = bind_udp(sa("127.0.0.1:0")).unwrap();
        let port = a.local_addr().unwrap().port();
        let same = SocketAddr::from(([127, 0, 0, 1], port));
        let b = bind_udp(same).expect("second REUSEPORT UDP bind on the live port must succeed");
        assert_eq!(b.local_addr().unwrap().port(), port);
        drop((a, b));
    }

    // --- socket activation (LISTEN_FDS) ----------------------------------

    #[test]
    fn from_env_without_socket_activation_is_empty() {
        // The cargo test harness sets no LISTEN_FDS/LISTEN_PID, so the daemon
        // is not socket-activated and falls through to normal binding. (No fds
        // to convert means `from_env` needs no runtime.)
        let inherited = InheritedSockets::from_env().unwrap();
        assert!(inherited.is_empty());
        assert_eq!(inherited.remaining(), 0);
    }

    #[tokio::test]
    async fn inherited_udp_socket_is_adopted_by_matching_address() {
        // Stand in for a systemd-passed socket: bind one ourselves and seed the
        // inherited set with it, exactly as `from_env` would.
        let seeded = bind_udp(sa("127.0.0.1:0")).unwrap();
        let addr = seeded.local_addr().unwrap();
        let mut inherited = InheritedSockets {
            udp: vec![(addr, seeded)],
            tcp: Vec::new(),
        };
        assert!(!inherited.is_empty());
        assert_eq!(inherited.remaining(), 1);

        // A request for the matching address adopts the seeded socket — same
        // bound address, and the inherited set is now drained.
        let adopted = udp_listener(addr, &mut inherited).unwrap();
        assert_eq!(adopted.local_addr().unwrap(), addr);
        assert_eq!(inherited.remaining(), 0, "matched socket must be consumed");

        // A request for any other address falls through to a fresh bind.
        let fresh = udp_listener(sa("127.0.0.1:0"), &mut inherited).unwrap();
        assert_ne!(fresh.local_addr().unwrap(), addr);
        assert_eq!(inherited.remaining(), 0);
    }

    #[tokio::test]
    async fn inherited_tcp_listener_is_adopted_by_matching_address() {
        let seeded = bind_tcp(sa("127.0.0.1:0")).unwrap();
        let addr = seeded.local_addr().unwrap();
        let mut inherited = InheritedSockets {
            udp: Vec::new(),
            tcp: vec![(addr, seeded)],
        };

        let adopted = tcp_listener(addr, &mut inherited).unwrap();
        assert_eq!(adopted.local_addr().unwrap(), addr);
        assert_eq!(
            inherited.remaining(),
            0,
            "matched listener must be consumed"
        );

        // Non-matching address → fresh bind, inherited set untouched.
        let other = sa("127.0.0.1:0");
        let fresh = tcp_listener(other, &mut inherited).unwrap();
        assert_ne!(fresh.local_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn unmatched_inherited_socket_is_reported_as_remaining() {
        // A socket on an address that no listener asks for stays in the set —
        // this is what main.rs warns about (a .socket unit whose Listen
        // directives drifted from the config).
        let seeded = bind_udp(sa("127.0.0.1:0")).unwrap();
        let addr = seeded.local_addr().unwrap();
        let mut inherited = InheritedSockets {
            udp: vec![(addr, seeded)],
            tcp: Vec::new(),
        };

        // Build a server that listens on a *different* unprivileged port: the
        // seeded socket matches nothing and must remain.
        let _ = udp_listener(sa("127.0.0.1:0"), &mut inherited).unwrap();
        assert_eq!(inherited.remaining(), 1);
    }
}
