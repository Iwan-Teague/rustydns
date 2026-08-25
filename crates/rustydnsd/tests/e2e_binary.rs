//! Binary-level end-to-end: spawn the REAL `rustydnsd` binary on ephemeral
//! loopback ports with a minimal config, drive it over actual UDP, and
//! assert a normal A query resolves end-to-end through a stub plain-DNS
//! upstream spawned inside this test process. Fully offline.
//!
//! Teardown kills the daemon child and aborts the stub task.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

/// Reserve an ephemeral TCP port by bind-then-drop. Small TOCTOU window,
/// acceptable for a loopback CI test.
fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("port")
        .port()
}

/// Minimal DNS-over-UDP stub upstream: for every datagram it flips the QR
/// bit, sets RA, appends a single A answer (192.0.2.1) whose NAME is a
/// compression pointer at offset 12 (the question), and echoes it back.
/// Works for any single-question A query without touching hickory APIs.
async fn spawn_stub_udp_dns(port: u16) -> tokio::task::JoinHandle<()> {
    let std_sock = std::net::UdpSocket::bind(("127.0.0.1", port)).expect("stub bind");
    std_sock.set_nonblocking(true).expect("nonblocking");
    let sock = tokio::net::UdpSocket::from_std(std_sock).expect("stub into tokio");

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            if n < 12 {
                continue;
            }
            let mut out = buf[..n].to_vec();
            out[2] |= 0x80; // QR = response
            out[3] |= 0x80; // RA available
            // ANCOUNT (bytes 6..8) = 1
            out[6] = 0;
            out[7] = 1;
            // Answer: ptr to QNAME @12, TYPE=A, CLASS=IN, TTL=60, RDLEN=4
            out.extend_from_slice(&[
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 0, 2,
                1,
            ]);
            let _ = sock.send_to(&out, peer).await;
        }
    })
}

/// Build a well-formed A query for `name` with the given id.
fn build_query(id: u16, name: &str) -> Vec<u8> {
    use hickory_proto::op::OpCode;
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = hickory_proto::op::Query::new();
    q.set_name(Name::from_ascii(name).expect("query name"));
    q.set_query_type(RecordType::A);
    msg.add_query(q);
    msg.to_vec().expect("encode query")
}

#[tokio::test(flavor = "current_thread")]
async fn binary_end_to_end_resolves_a_query_over_real_udp() {
    let dns_port = reserve_port();
    let upstream_port = reserve_port();
    let metrics_port = reserve_port();

    let stub = spawn_stub_udp_dns(upstream_port).await;

    // --- minimal config -----------------------------------------------------
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, config).expect("write config");
    // The daemon refuses world-readable configs — tighten before spawn.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    // --- spawn the real daemon ----------------------------------------------
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn rustydnsd");

    // --- readiness: TCP listener appears once bound -------------------------
    let mut ready = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", dns_port))
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        let _ = child.kill().await;
        panic!("rustydnsd did not become ready on port {dns_port}");
    }

    // --- real UDP query round-trip ------------------------------------------
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    let mut resolved = false;
    'outer: for id in 1u16..=4 {
        let query = build_query(id, "example.test.");
        sock.send(&query).await.expect("send query");
        for _ in 0..10 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await {
                Err(_) => break 'outer, // 1s with no reply: re-send a fresh query
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                        continue;
                    };
                    if reply.metadata.id != id {
                        continue; // stale/stray packet
                    }
                    assert_eq!(reply.metadata.message_type, MessageType::Response);
                    assert_eq!(
                        reply.metadata.response_code,
                        ResponseCode::NoError,
                        "expected NOERROR from stub-backed resolution"
                    );
                    let got_a = reply.answers.iter().any(|r| {
                        r.record_type() == RecordType::A
                            && match &r.data {
                                hickory_proto::rr::RData::A(a) => a.0.to_string() == "192.0.2.1",
                                _ => false,
                            }
                    });
                    assert!(
                        got_a,
                        "expected A 192.0.2.1 answer, got {:?}",
                        reply.answers
                    );
                    resolved = true;
                    break 'outer;
                }
            }
        }
    }
    assert!(resolved, "A query never resolved end-to-end");

    // --- teardown -------------------------------------------------------------
    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}
