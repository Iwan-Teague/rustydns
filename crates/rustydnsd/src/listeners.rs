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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
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

/// Build (and implicitly start) a hickory DNS server for one generation of
/// listeners: UDP + TCP on each `listen` address, plus an optional DoT
/// listener. All sockets use `SO_REUSEPORT` so this can be called for a new
/// generation while the previous one is still draining.
///
/// The returned [`Server`] is already serving — `register_*` spawns the
/// accept loops. Drain it with `shutdown_gracefully`.
pub fn build_dns_server(
    handler: DnsHandler,
    listen: &[SocketAddr],
    dot: Option<SocketAddr>,
    tls: Option<Arc<TlsServerConfig>>,
) -> Result<Server<DnsHandler>> {
    let mut server = Server::new(handler);

    for addr in listen {
        let udp = bind_udp(*addr)?;
        server.register_socket(udp);

        let tcp = bind_tcp(*addr)?;
        server.register_listener(tcp, LISTENER_TIMEOUT, TCP_RESPONSE_BUFFER);
    }

    if let Some(dot_addr) = dot {
        let tls = tls.context("DoT listener configured but no TLS config was provided")?;
        let tcp = bind_tcp(dot_addr)?;
        server
            .register_tls_listener_with_tls_config(tcp, LISTENER_TIMEOUT, tls)
            .with_context(|| format!("failed to register DoT listener on {dot_addr}"))?;
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
}
