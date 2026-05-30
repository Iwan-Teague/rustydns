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

// DoT cert-rotation test (roadmap 4.1) drives a tokio-rustls client that
// accepts any server cert, then reads back the presented leaf to prove the
// cert actually rotated on SIGHUP.
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

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
    // Keep the daemon fully OFFLINE so this listener-reload test is
    // deterministic: no remote blocklist fetch, and a plain bare-IP upstream
    // (an IP literal needs no bootstrap DNS). A `probe.mesh` static record is
    // answered locally by the authority, so `dns_responds` never depends on a
    // reachable public resolver.
    std::fs::write(path, local_config_body(dns, metrics, doh)).unwrap();
    set_mode_600(path);
}

/// The shared offline config body — also used for the in-place SIGHUP rewrite
/// so the resolver hot-swap never bootstraps over the network either.
fn local_config_body(dns: u16, metrics: u16, doh: u16) -> String {
    config_body(dns, metrics, doh)
}

fn config_body(dns: u16, metrics: u16, doh: u16) -> String {
    format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns}\"]\n\
         mesh_zone = \"mesh.\"\n\
         doh_listen = \"127.0.0.1:{doh}\"\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics}\"\n\
         [blocklist]\n\
         sources = []\n\
         reload_interval_secs = 0\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:5353\"]\n\
         [[authority.static_records]]\n\
         name = \"probe.mesh\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n"
    )
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
        // `probe.mesh` is a local static record (see `local_config_body`), so a
        // response proves the listener is up WITHOUT needing an upstream.
        q.set_name(Name::from_ascii("probe.mesh.").unwrap())
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

/// True if the DoH listener on `port` answers a `probe.mesh` query with HTTP
/// 200. Uses an RFC 8484 GET (`?dns=<base64url>`) over raw HTTP/1.1 (axum's
/// `serve` negotiates 1.1 or 2). A 200 proves the listener is up AND the
/// pipeline answered (probe.mesh is a local static record — no upstream).
fn doh_responds(port: u16) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query({
        let mut q = Query::new();
        q.set_name(Name::from_ascii("probe.mesh.").unwrap())
            .set_query_type(RecordType::A);
        q
    });
    let Ok(wire) = msg.to_bytes() else {
        return false;
    };
    let dns = URL_SAFE_NO_PAD.encode(&wire);

    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    s.set_read_timeout(Some(Duration::from_millis(800))).ok();
    let req = format!("GET /dns-query?dns={dns} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    // Status line is ASCII; the DNS body that follows may be binary.
    let head = String::from_utf8_lossy(&buf[..buf.len().min(64)]);
    head.contains("200")
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

// ---------------------------------------------------------------------------
// DoT TLS cert-rotation support (roadmap 4.1)
// ---------------------------------------------------------------------------

/// CN + SAN shared by both rotation test certs, so the client can name the
/// server. The accept-any verifier ignores the name; rustls still requires a
/// syntactically valid `ServerName` to start a handshake.
const DOT_SNI: &str = "rustydns-dot-test";

// Two distinct self-signed P-256 leaves. Rotation is proven by the presented
// leaf changing from A to B. Generated with:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
//     -nodes -days 3650 -subj /CN=rustydns-dot-<n> \
//     -addext subjectAltName=DNS:rustydns-dot-test -keyout key.pem -out cert.pem
const DOT_CERT_A: &str = "-----BEGIN CERTIFICATE-----
MIIBpDCCAUugAwIBAgIUL+JUi+KM4KkWB/ZkOEQ3JxWcjcIwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOcnVzdHlkbnMtZG90LWEwHhcNMjYwNTMwMTcxNTIxWhcNMzYw
NTI3MTcxNTIxWjAZMRcwFQYDVQQDDA5ydXN0eWRucy1kb3QtYTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABHn9735tJu8BgjMKKB4+kxdTvq4sicWvhJFx3D6C8m9a
N4A/NuXEFVAdnYlmTbG/3jHdrRGX9S0Z4FyZIXFkaZqjcTBvMB0GA1UdDgQWBBRf
EQQZyKr5YK5CXwrKfmhI3SAnJDAfBgNVHSMEGDAWgBRfEQQZyKr5YK5CXwrKfmhI
3SAnJDAPBgNVHRMBAf8EBTADAQH/MBwGA1UdEQQVMBOCEXJ1c3R5ZG5zLWRvdC10
ZXN0MAoGCCqGSM49BAMCA0cAMEQCIALNVijjS5J7wSHfiKPW7OyrF3ojOTxzTrQf
FajfN5WRAiB4ATgc1JqXSy0T5kyEoW0PPoB3yNW1eirWWP2LYRVEyw==
-----END CERTIFICATE-----
";
const DOT_KEY_A: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtOxkJnPtzyJIXkT1
sl+IdRo1ZwaTkj7z1XbSlybOrfKhRANCAAR5/e9+bSbvAYIzCigePpMXU76uLInF
r4SRcdw+gvJvWjeAPzblxBVQHZ2JZk2xv94x3a0Rl/UtGeBcmSFxZGma
-----END PRIVATE KEY-----
";
const DOT_CERT_B: &str = "-----BEGIN CERTIFICATE-----
MIIBpjCCAUugAwIBAgIUchON16eCgzvRtzW5UOsI5tvvfiwwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOcnVzdHlkbnMtZG90LWIwHhcNMjYwNTMwMTcxNTIxWhcNMzYw
NTI3MTcxNTIxWjAZMRcwFQYDVQQDDA5ydXN0eWRucy1kb3QtYjBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABN+Xd6+vdx2wIIqM41v6sSxW34Som+cnfvirNJXJSmb4
LMlhLzRIaGgO/G/XRyOo8JnwsP+XfHnFf76KP2gKWJCjcTBvMB0GA1UdDgQWBBQa
aAjFNIfMTfuNHEk6V4Y6oUjD9jAfBgNVHSMEGDAWgBQaaAjFNIfMTfuNHEk6V4Y6
oUjD9jAPBgNVHRMBAf8EBTADAQH/MBwGA1UdEQQVMBOCEXJ1c3R5ZG5zLWRvdC10
ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQCKflvW5XHIB0hllM2Jhci31EIIO24f8ack
T8FuUccIrQIhANOPi4HzesOMkNkBANJWXWPaobv1y4B80L5md/uHqNW/
-----END CERTIFICATE-----
";
const DOT_KEY_B: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwoaiENMD4Cv50X7R
bEh8RJTWgFXg31Pux08kJhQNoW2hRANCAATfl3evr3cdsCCKjONb+rEsVt+EqJvn
J374qzSVyUpm+CzJYS80SGhoDvxv10cjqPCZ8LD/l3x5xX++ij9oCliQ
-----END PRIVATE KEY-----
";

/// A rustls server-cert verifier that accepts ANY certificate. Test-only: it
/// lets the client finish a handshake against an untrusted self-signed leaf so
/// we can read back which cert the server presented. NEVER use this shape in
/// production — it disables server authentication entirely.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Decode an embedded PEM cert to its DER bytes, for comparison against the
/// leaf the server presents on the wire.
fn cert_pem_to_der(pem: &str) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem.as_bytes())
        .expect("parse embedded DoT cert PEM")
        .as_ref()
        .to_vec()
}

/// TLS-connect to the DoT listener on `port`, complete the handshake with an
/// accept-any verifier, and return the DER of the leaf cert the server
/// presented (`None` if the listener isn't up or the handshake failed).
fn dot_presented_leaf(port: u16) -> Option<Vec<u8>> {
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::ClientConfig;

    // The ring provider drives both ends of the handshake; idempotent.
    let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    rt.block_on(async move {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = tokio::time::timeout(
            Duration::from_millis(800),
            tokio::net::TcpStream::connect(("127.0.0.1", port)),
        )
        .await
        .ok()?
        .ok()?;

        let server_name = ServerName::try_from(DOT_SNI.to_string()).ok()?;
        let tls = tokio::time::timeout(
            Duration::from_millis(1500),
            connector.connect(server_name, tcp),
        )
        .await
        .ok()?
        .ok()?;

        let (_io, conn) = tls.get_ref();
        Some(conn.peer_certificates()?.first()?.as_ref().to_vec())
    })
}

/// Offline DoT config body: empty blocklist, plain bare-IP upstream, a local
/// `probe.mesh` static record, plus a DoT listener with the given cert/key.
fn dot_config_body(dns: u16, metrics: u16, doh: u16, dot: u16, cert: &Path, key: &Path) -> String {
    // tempdir paths on the test host carry no quotes/backslashes, so plain
    // interpolation into a double-quoted TOML string is safe.
    let cert = cert.display();
    let key = key.display();
    format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns}\"]\n\
         mesh_zone = \"mesh.\"\n\
         doh_listen = \"127.0.0.1:{doh}\"\n\
         dot_listen = \"127.0.0.1:{dot}\"\n\
         tls_cert_path = \"{cert}\"\n\
         tls_key_path = \"{key}\"\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics}\"\n\
         [blocklist]\n\
         sources = []\n\
         reload_interval_secs = 0\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:5353\"]\n\
         [[authority.static_records]]\n\
         name = \"probe.mesh\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n"
    )
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
    // and keep the existing listener serving. Reuse the offline body (just
    // swapping the DNS port to :53) so the SIGHUP resolver hot-swap stays
    // network-free.
    let body = local_config_body(53, metrics, doh);
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

#[test]
fn sighup_rebinds_doh_listener_to_new_unprivileged_port() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let log = dir.path().join("daemon.log");

    let (dns, metrics, doh_old) = (free_port(), free_port(), free_port());
    write_config(&config, dns, metrics, doh_old);

    let guard = spawn_daemon(&config, &log);

    // DoH must come up on the original port (a `probe.mesh` GET returns 200).
    assert!(
        wait_until(Duration::from_secs(10), || doh_responds(doh_old)),
        "DoH listener never came up on {doh_old}\nlog:\n{}",
        read_log(&log)
    );

    // Move ONLY the DoH listener to a fresh port; DNS + metrics unchanged.
    let doh_new = free_port();
    write_config(&config, dns, metrics, doh_new);
    send_sighup(&guard);

    // New DoH port must come up...
    assert!(
        wait_until(Duration::from_secs(10), || doh_responds(doh_new)),
        "DoH did not rebind to new port {doh_new}\nlog:\n{}",
        read_log(&log)
    );
    // ...and the old DoH port must stop serving (old generation cancelled).
    assert!(
        wait_until(Duration::from_secs(5), || !doh_responds(doh_old)),
        "old DoH port {doh_old} still serving after handover\nlog:\n{}",
        read_log(&log)
    );

    let log_text = read_log(&log);
    assert!(
        log_text.contains("DoH listener rebound live"),
        "expected a 'DoH listener rebound live' log line; log:\n{log_text}"
    );
    drop(guard);
}

#[test]
fn sighup_rotates_dot_cert_on_path_change() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let log = dir.path().join("daemon.log");

    // Cert A and cert B live at DISTINCT paths. Rotation = repoint
    // tls_cert_path/tls_key_path, which is exactly what
    // docs/design-sighup-reload.md documents as the DoT rotation trigger.
    let cert_a = dir.path().join("cert_a.pem");
    let key_a = dir.path().join("key_a.pem");
    let cert_b = dir.path().join("cert_b.pem");
    let key_b = dir.path().join("key_b.pem");
    std::fs::write(&cert_a, DOT_CERT_A).unwrap();
    std::fs::write(&key_a, DOT_KEY_A).unwrap();
    std::fs::write(&cert_b, DOT_CERT_B).unwrap();
    std::fs::write(&key_b, DOT_KEY_B).unwrap();

    let der_a = cert_pem_to_der(DOT_CERT_A);
    let der_b = cert_pem_to_der(DOT_CERT_B);
    assert_ne!(der_a, der_b, "the two rotation test certs must differ");

    let (dns, metrics, doh, dot) = (free_port(), free_port(), free_port(), free_port());
    std::fs::write(
        &config,
        dot_config_body(dns, metrics, doh, dot, &cert_a, &key_a),
    )
    .unwrap();
    set_mode_600(&config);

    let guard = spawn_daemon(&config, &log);

    // DoT must come up presenting cert A.
    assert!(
        wait_until(Duration::from_secs(10), || dot_presented_leaf(dot)
            .as_deref()
            == Some(der_a.as_slice())),
        "DoT listener never presented cert A on {dot}\nlog:\n{}",
        read_log(&log)
    );

    // Rotate: repoint cert/key paths to B and reload. Only the TLS material
    // changes — the DNS and DoT ports stay put, so this is a live rebind.
    std::fs::write(
        &config,
        dot_config_body(dns, metrics, doh, dot, &cert_b, &key_b),
    )
    .unwrap();
    set_mode_600(&config);
    send_sighup(&guard);

    // The listener must rebind and present cert B once the old generation
    // (still serving cert A under SO_REUSEPORT) drains.
    assert!(
        wait_until(Duration::from_secs(10), || dot_presented_leaf(dot)
            .as_deref()
            == Some(der_b.as_slice())),
        "DoT did not rotate to cert B on {dot}\nlog:\n{}",
        read_log(&log)
    );

    let log_text = read_log(&log);
    assert!(
        log_text.contains("rebound live"),
        "expected a 'rebound live' log line after cert rotation; log:\n{log_text}"
    );
    drop(guard);
}
