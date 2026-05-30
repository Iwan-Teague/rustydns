//! End-to-end tests for SIGHUP live listener handover (roadmap 3.2, Phase 2).
//!
//! These spawn the real `rustydnsd` binary, drive it with SIGHUP, and assert
//! on observable behaviour (ports serving / refused, log lines). Unix-only —
//! they send signals and rely on the in-process capability/umask path.
#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

/// Kill the child daemon when the guard drops, so a failed assertion never
/// leaks a process holding a port.
struct DaemonGuard(Child);
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Grab a currently-free TCP port. There's an inherent race between drop and
/// the daemon re-binding, but on loopback in a test it's reliable enough.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn write_config(path: &Path, dns: u16, metrics: u16, doh: u16) {
    let body = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns}\"]\n\
         mesh_zone = \"mesh.\"\n\
         doh_listen = \"127.0.0.1:{doh}\"\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics}\"\n"
    );
    std::fs::write(path, body).unwrap();
    set_mode_600(path);
}

fn set_mode_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn spawn_daemon(config: &Path, log: &Path) -> DaemonGuard {
    let f = File::create(log).unwrap();
    let f2 = f.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(config)
        .stdout(Stdio::from(f))
        .stderr(Stdio::from(f2))
        .spawn()
        .expect("failed to spawn rustydnsd");
    DaemonGuard(child)
}

fn send_sighup(guard: &DaemonGuard) {
    let pid = guard.0.id();
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status()
        .expect("failed to run kill");
    assert!(status.success(), "kill -HUP failed for pid {pid}");
}

/// True if an HTTP `GET /health` to `port` returns a 200.
fn metrics_health_ok(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    s.set_read_timeout(Some(Duration::from_millis(800))).ok();
    if s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.contains("200")
}

/// True if the DNS listener on `port` answers a UDP query with a parseable
/// DNS response (any rcode — we only care that the listener is serving).
fn dns_responds(port: u16) -> bool {
    let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query({
        let mut q = Query::new();
        q.set_name(Name::from_ascii("example.com.").unwrap())
            .set_query_type(RecordType::A);
        q
    });
    let Ok(bytes) = msg.to_bytes() else {
        return false;
    };
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    sock.set_read_timeout(Some(Duration::from_millis(1500)))
        .ok();
    if sock.send_to(&bytes, ("127.0.0.1", port)).is_err() {
        return false;
    }
    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => Message::from_bytes(&buf[..n]).is_ok(),
        Err(_) => false,
    }
}

/// Poll `cond` until it returns true or `timeout` elapses.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn sighup_rebinds_dns_and_metrics_to_new_unprivileged_ports() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let log = dir.path().join("daemon.log");

    let (dns_old, metrics_old, doh) = (free_port(), free_port(), free_port());
    write_config(&config, dns_old, metrics_old, doh);

    let guard = spawn_daemon(&config, &log);

    // Wait for both listeners to come up.
    assert!(
        wait_until(Duration::from_secs(10), || metrics_health_ok(metrics_old)),
        "metrics listener never came up on {metrics_old}\nlog:\n{}",
        read_log(&log)
    );
    assert!(
        wait_until(Duration::from_secs(5), || dns_responds(dns_old)),
        "DNS listener never answered on {dns_old}\nlog:\n{}",
        read_log(&log)
    );

    // Rewrite the config with fresh ports and reload.
    let (dns_new, metrics_new) = (free_port(), free_port());
    write_config(&config, dns_new, metrics_new, doh);
    send_sighup(&guard);

    // New ports must come up...
    assert!(
        wait_until(Duration::from_secs(10), || metrics_health_ok(metrics_new)),
        "metrics did not rebind to new port {metrics_new}\nlog:\n{}",
        read_log(&log)
    );
    assert!(
        wait_until(Duration::from_secs(5), || dns_responds(dns_new)),
        "DNS did not rebind to new port {dns_new}\nlog:\n{}",
        read_log(&log)
    );

    // ...and the old metrics port must stop serving (the old generation was
    // drained/cancelled).
    assert!(
        wait_until(Duration::from_secs(5), || !metrics_health_ok(metrics_old)),
        "old metrics port {metrics_old} still serving after handover\nlog:\n{}",
        read_log(&log)
    );

    let log_text = read_log(&log);
    assert!(
        log_text.contains("rebound live"),
        "expected a 'rebound live' log line; log:\n{log_text}"
    );
    drop(guard);
}

#[test]
fn sighup_refuses_privileged_port_change_and_keeps_serving() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let log = dir.path().join("daemon.log");

    let (dns, metrics, doh) = (free_port(), free_port(), free_port());
    write_config(&config, dns, metrics, doh);

    let guard = spawn_daemon(&config, &log);
    assert!(
        wait_until(Duration::from_secs(10), || dns_responds(dns)),
        "DNS listener never came up on {dns}\nlog:\n{}",
        read_log(&log)
    );

    // Change the DNS listener to a privileged port (:53). The daemon dropped
    // CAP_NET_BIND_SERVICE at startup, so it must refuse the rebind, warn,
    // and keep the existing listener serving.
    let body = format!(
        "[server]\n\
         listen = [\"127.0.0.1:53\"]\n\
         mesh_zone = \"mesh.\"\n\
         doh_listen = \"127.0.0.1:{doh}\"\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics}\"\n"
    );
    std::fs::write(&config, body).unwrap();
    set_mode_600(&config);
    send_sighup(&guard);

    // Give the reload a moment to process.
    assert!(
        wait_until(Duration::from_secs(5), || read_log(&log)
            .contains("needs a process restart")),
        "expected a restart-required warning for the privileged-port change\nlog:\n{}",
        read_log(&log)
    );

    // The original listener must still be serving — we never tore it down.
    assert!(
        dns_responds(dns),
        "original DNS listener on {dns} stopped serving after a refused reload\nlog:\n{}",
        read_log(&log)
    );
    drop(guard);
}
