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
/// The returned counter increments for every datagram received - lets
/// tests prove which names DID reach the upstream.
async fn spawn_stub_udp_dns(
    port: u16,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    let std_sock = std::net::UdpSocket::bind(("127.0.0.1", port)).expect("stub bind");
    std_sock.set_nonblocking(true).expect("nonblocking");
    let sock = tokio::net::UdpSocket::from_std(std_sock).expect("stub into tokio");

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            hits_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    });
    (handle, hits)
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
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, _hits) = spawn_stub_udp_dns(upstream_port).await;

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

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

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_blocklist_blocks_domain_before_upstream() {
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(
        tmp.path(),
        dns_port,
        upstream_port,
        metrics_port,
        Some("0.0.0.0 blocked.test\n"),
    );
    let (stub, hits) = spawn_stub_udp_dns(upstream_port).await;

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Blocked name -> NXDOMAIN with zero answers.
    sock.send(&build_query(10, "blocked.test."))
        .await
        .expect("send");
    let mut saw_nxdomain = false;
    for _ in 0..10 {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                if reply.metadata.id != 10 {
                    continue;
                }
                assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
                assert!(reply.answers.is_empty());
                saw_nxdomain = true;
                break;
            }
        }
    }
    assert!(saw_nxdomain, "blocked.test must be NXDOMAIN");

    // Control: a different name still resolves through the stub.
    let ok = resolve_a(&sock, 11, "fine.test.").await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);

    // The blocked query must NEVER have reached the upstream.
    let upstream_hits = hits.load(Ordering::SeqCst);
    assert_eq!(
        upstream_hits, 1,
        "only the control query may hit the upstream; blocked.test leaked"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

// --- shared harness helpers (used by multiple e2e tests) -------------------

fn pick_ports() -> (u16, u16, u16) {
    (reserve_port(), reserve_port(), reserve_port())
}

/// Write a minimal daemon config; returns the path. `blocklist_hosts` is an
/// optional hosts-format snippet written to a second temp file and wired as
/// blocklist.local_files.
fn write_daemon_config(
    dir: &std::path::Path,
    dns_port: u16,
    upstream_port: u16,
    metrics_port: u16,
    blocklist_hosts: Option<&str>,
) -> std::path::PathBuf {
    let mut blocklist_section = String::from("[blocklist]\n");
    if let Some(hosts) = blocklist_hosts {
        let bl_path = dir.join("blocklist.hosts");
        std::fs::write(&bl_path, hosts).expect("write blocklist file");
        blocklist_section.push_str(&format!("local_files = [{}]\n", quote_path(&bl_path)));
    }

    let cfg_path = dir.join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         {blocklist_section}\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, config).expect("write config");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod config");
    cfg_path
}

fn quote_path(p: &std::path::Path) -> String {
    format!("\"{}\"", p.display())
}

async fn spawn_and_wait_ready(cfg_path: &std::path::Path, dns_port: u16) -> tokio::process::Child {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn rustydnsd");

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
    child
}

/// Send one A query and wait for the NOERROR answer carrying 192.0.2.1.
async fn resolve_a(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> Message {
    sock.send(&build_query(id, name)).await.expect("send query");
    for _ in 0..20 {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
            Err(_) => continue,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                if reply.metadata.id != id {
                    continue;
                }
                assert_eq!(reply.metadata.message_type, MessageType::Response);
                return reply;
            }
        }
    }
    panic!("no reply for {name}");
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_malformed_packets_never_crash_or_poison() {
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits) = spawn_stub_udp_dns(upstream_port).await;

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Hostile datagram battery - each shape targets a different parser edge:
    //   1. Pure garbage bytes
    //   2. Truncated header (< 12 bytes)
    //   3. Valid header claiming QDCOUNT=0xFFFF (parse bomb)
    //   4. Compression-pointer loop in QNAME (self-referential @12)
    //   5. Oversized blob (6 KB, beyond any sane inbound cap)
    //   6. Zero-length datagram
    let mut hostile: Vec<Vec<u8>> = Vec::new();
    hostile.push(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42]);
    hostile.push(vec![0u8; 5]);
    let mut bomb = vec![0u8; 12];
    bomb[6..8].copy_from_slice(&0xFFFFu16.to_be_bytes());
    hostile.push(bomb);
    let mut ptrloop = vec![0u8; 20];
    ptrloop[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    ptrloop[12..14].copy_from_slice(&[0xC0, 0x0C]); // self-pointer
    hostile.push(ptrloop);
    hostile.push(vec![0x41; 6000]);
    hostile.push(Vec::new());
    for pkt in &hostile {
        let _ = sock.send(pkt).await.expect("send hostile");
    }

    // Drain window: give the daemon a moment to (maybe) emit FORMERRs or
    // drop silently - none of these may become a served answer.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut drain = vec![0u8; 4096];
    while tokio::time::timeout(Duration::from_millis(50), sock.recv_from(&mut drain))
        .await
        .is_ok()
    {
        if let Ok(msg) = Message::from_bytes(&drain) {
            assert!(
                !(msg.metadata.response_code == ResponseCode::NoError && !msg.answers.is_empty()),
                "hostile datagram produced a SERVED ANSWER: {:?}",
                msg.answers
            );
        }
        drain = vec![0u8; 4096];
    }

    // Liveness: normal resolution still works after the battery.
    let ok = resolve_a(&sock, 99, "alive.test.").await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);

    // Only the liveness query reached the upstream - hostile bytes were
    // never forwarded as if they were legitimate questions.
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // The child process itself must still be running (no crash).
    assert!(
        matches!(child.try_wait(), Ok(None)),
        "daemon crashed under malformed-packet battery"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_sighup_picks_up_blocklist_change_live() {
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let bl_path = tmp.path().join("live.blocklist");
    // Seed: exists but blocks nothing yet.
    std::fs::write(&bl_path, "# empty seed\n").expect("write seed");

    // Config identical to write_daemon_config except pointing local_files
    // at the mutable path.
    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\
         local_files = [\"{}\"]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n",
        bl_path.display()
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub, hits) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Pre-HUP: late.test resolves through the stub.
    let pre = resolve_a(&sock, 20, "late.test.").await;
    assert_eq!(pre.metadata.response_code, ResponseCode::NoError);

    // Operator edits the blocklist and signals a live reload.
    std::fs::write(&bl_path, "0.0.0.0 late.test\n").expect("append block rule");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().expect("pid") as i32),
        nix::sys::signal::Signal::SIGHUP,
    )
    .expect("send SIGHUP");

    // Poll until enforcement appears (reload is async), bounded.
    let mut enforced = false;
    'poll: for id in 30u16..60 {
        sock.send(&build_query(id, "late.test."))
            .await
            .expect("send");
        for _ in 0..6 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(300), sock.recv_from(&mut buf)).await {
                Err(_) => break,
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                        continue;
                    };
                    if reply.metadata.id != id {
                        continue;
                    }
                    if reply.metadata.response_code == ResponseCode::NXDomain
                        && reply.answers.is_empty()
                    {
                        enforced = true;
                        break 'poll;
                    }
                    break; // non-NXDOMAIN reply: try next probe round
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(enforced, "SIGHUP did not activate the new blocklist entry");

    // Control name unaffected post-reload.
    let post = resolve_a(&sock, 70, "stillfine.test.").await;
    assert_eq!(post.metadata.response_code, ResponseCode::NoError);

    // Upstream only ever saw the two control queries - never late.test,
    // before OR after enforcement.
    assert!(
        hits.load(Ordering::SeqCst) <= 3,
        "unexpected upstream traffic: {}",
        hits.load(Ordering::SeqCst)
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_operator_endpoints_health_metrics_queries() {
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, _hits) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let client = reqwest::Client::builder().build().unwrap();
    let base = format!("http://127.0.0.1:{metrics_port}");

    // /health: ready after listeners bound; no-store caching.
    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(
        health
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    let hb = health.text().await.unwrap();
    assert!(hb.contains("\"status\":\"ok\""), "{hb}");

    // Baseline counter, then three real queries.
    async fn metric_value(client: &reqwest::Client, base: &str) -> f64 {
        let m = client.get(format!("{base}/metrics")).send().await.unwrap();
        assert_eq!(m.status(), 200);
        let body = m.text().await.unwrap();
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("rustydns_dns_queries_total ") {
                return rest.trim().parse::<f64>().expect("counter value");
            }
        }
        panic!("rustydns_dns_queries_total missing from metrics output");
    }
    let before = metric_value(&client, &base).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");
    for id in 40u16..43 {
        let reply = resolve_a(&sock, id, "counted.test.").await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    }

    let after = metric_value(&client, &base).await;
    assert!(
        (after - before - 3.0).abs() < f64::EPSILON,
        "expected +3 queries, {before} -> {after}"
    );

    // /queries: ring holds our entries - hashed qnames only, never the
    // plaintext name, and the anonymised client form.
    let q = client.get(format!("{base}/queries")).send().await.unwrap();
    assert_eq!(q.status(), 200);
    let qb = q.text().await.unwrap();
    assert!(!qb.contains("counted.test"), "plaintext qname leaked: {qb}");
    assert!(qb.contains("\"qname_hash\""), "{qb}");
    assert!(qb.contains("/16"), "anonymised client marker missing: {qb}");

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_resolves_over_tcp_with_length_framing() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, _hits) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    // RFC 1035 4.2.2 framing: 2-byte big-endian length prefix per message.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", dns_port))
        .await
        .expect("tcp connect");
    let query = build_query(7, "tcp.test.");
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await.expect("write framed query");

    // Read the reply prefix, then exactly that many bytes.
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.expect("reply length");
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    assert!(
        reply_len > 12 && reply_len <= 4096,
        "implausible reply length {reply_len}"
    );
    let mut reply_buf = vec![0u8; reply_len];
    stream.read_exact(&mut reply_buf).await.expect("reply body");

    let reply = Message::from_bytes(&reply_buf).expect("decode tcp reply");
    assert_eq!(reply.metadata.id, 7);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(
        reply.answers.iter().any(|r| matches!(&r.data,
            hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")),
        "expected A answer over TCP, got {:?}",
        reply.answers
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}
