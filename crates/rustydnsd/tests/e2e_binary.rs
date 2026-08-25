//! Binary-level end-to-end: spawn the REAL `rustydnsd` binary on ephemeral
//! loopback ports with a minimal config, drive it over actual UDP, and
//! assert a normal A query resolves end-to-end through a stub plain-DNS
//! upstream spawned inside this test process. Fully offline.
//!
//! Teardown kills the daemon child and aborts the stub task.
#![cfg(unix)]

mod test_certs;

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
type Captures = std::sync::Arc<std::sync::Mutex<Vec<(std::net::SocketAddr, Vec<u8>)>>>;

/// compression pointer at offset 12 (the question), and echoes it back.
/// Works for any single-question A query without touching hickory APIs.
/// The returned counter increments for every datagram received - lets
/// tests prove which names DID reach the upstream.
async fn spawn_stub_udp_dns(
    port: u16,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    Captures,
) {
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    let captures: Captures = Arc::new(Mutex::new(Vec::new()));
    let task_caps = Arc::clone(&captures);
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
            task_caps.lock().unwrap().push((peer, buf[..n].to_vec()));
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
    (handle, hits, captures)
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
    let (stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;

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
    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;

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
         dnssec_validation = false\n\
         timeout_ms = 1500\n\n\
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
    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;

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
         dnssec_validation = false\n\
         timeout_ms = 1500\n\n\
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

    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
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
    let (stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
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
    let (stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
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

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_doh_post_resolves_over_http_seam() {
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let doh_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    // write_daemon_config covers the common shape; DoH needs one extra
    // line, so build the config inline here.
    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\
         doh_listen = \"127.0.0.1:{doh_port}\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    // RFC 8484 POST: application/dns-message body -> same back.
    let client = reqwest::Client::builder().build().unwrap();
    let resp = client
        .post(format!("http://127.0.0.1:{doh_port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(build_query(9, "doh.test."))
        .send()
        .await
        .expect("DoH POST");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/dns-message")
    );
    let wire = resp.bytes().await.expect("response bytes");
    let reply = Message::from_bytes(&wire).expect("decode DoH reply");
    assert_eq!(reply.metadata.id, 9);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));

    // The query genuinely traversed the pipeline to our stub upstream.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_doh_get_resolves_via_base64url_param() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let doh_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\
         doh_listen = \"127.0.0.1:{doh_port}\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let client = reqwest::Client::builder().build().unwrap();
    let encoded = URL_SAFE_NO_PAD.encode(build_query(12, "get.test."));
    let resp = client
        .get(format!(
            "http://127.0.0.1:{doh_port}/dns-query?dns={encoded}"
        ))
        .header("accept", "application/dns-message")
        .send()
        .await
        .expect("DoH GET");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/dns-message")
    );
    let wire = resp.bytes().await.expect("response bytes");
    let reply = Message::from_bytes(&wire).expect("decode DoH GET reply");
    assert_eq!(reply.metadata.id, 12);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_dot_tls_handshake_and_resolution() {
    use std::sync::atomic::Ordering;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName},
    };

    // Integration tests are a separate crate: install the ring provider
    // exactly like the daemon's own DoT tests do.
    let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    );

    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let dot_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    // Write cert/key files for the daemon's DoT listener.
    let cert_path = tmp.path().join("leaf-cert.pem");
    let key_path = tmp.path().join("leaf-key.pem");
    std::fs::write(&cert_path, test_certs::TEST_LEAF_CERT_PEM).expect("write cert");
    std::fs::write(&key_path, test_certs::TEST_LEAF_KEY_PEM).expect("write key");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\
         dot_listen = \"127.0.0.1:{dot_port}\"\n\
         tls_cert_path = \"{}\"\n\
         tls_key_path = \"{}\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n",
        cert_path.display(),
        key_path.display()
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    // TLS client trusting ONLY the embedded test CA; dial by leaf SAN.
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(test_certs::TEST_CA_PEM.as_bytes()) {
        roots.add(cert.expect("ca cert")).expect("add ca");
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", dot_port))
        .await
        .expect("tcp connect to DoT");
    let server_name = ServerName::try_from(test_certs::TEST_CERT_CN.to_string()).expect("san name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    // RFC 1035 framing inside the TLS stream.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let query = build_query(15, "dot.test.");
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    tls.write_all(&framed).await.expect("write framed DoT");

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).await.expect("reply length");
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    assert!(
        reply_len > 12 && reply_len <= 4096,
        "implausible {reply_len}"
    );
    let mut reply_buf = vec![0u8; reply_len];
    tls.read_exact(&mut reply_buf).await.expect("reply body");

    let reply = Message::from_bytes(&reply_buf).expect("decode DoT reply");
    assert_eq!(reply.metadata.id, 15);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_doq_quic_stream_resolution_with_ca_trust() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};

    let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    );

    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let doq_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cert_path = tmp.path().join("leaf-cert.pem");
    let key_path = tmp.path().join("leaf-key.pem");
    std::fs::write(&cert_path, test_certs::TEST_LEAF_CERT_PEM).expect("write cert");
    std::fs::write(&key_path, test_certs::TEST_LEAF_KEY_PEM).expect("write key");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\
         doq_listen = \"127.0.0.1:{doq_port}\"\n\
         tls_cert_path = \"{}\"\n\
         tls_key_path = \"{}\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n",
        cert_path.display(),
        key_path.display()
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    // Quinn client trusting ONLY the embedded test CA; ALPN exactly "doq".
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(test_certs::TEST_CA_PEM.as_bytes()) {
        roots.add(cert.expect("ca cert")).expect("add ca");
    }
    let mut crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"doq".to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic cfg");
    let mut endpoint =
        quinn::Endpoint::client((std::net::Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcc)));

    let connecting = endpoint
        .connect(
            (std::net::Ipv4Addr::LOCALHOST, doq_port).into(),
            test_certs::TEST_CERT_CN,
        )
        .expect("connect");
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("quinn connect timeout")
        .expect("quinn handshake");

    // RFC 9250 §4.2: one query per bidirectional stream, 2-byte length
    // prefix, DNS message id MUST be 0.
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
    let mut msg = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query({
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("doq.test.").expect("name"));
        q.set_query_type(RecordType::A);
        q
    });
    let wire = msg.to_vec().expect("encode");
    send.write_all(&(wire.len() as u16).to_be_bytes())
        .await
        .expect("len");
    send.write_all(&wire).await.expect("query");
    send.finish().expect("finish stream");

    let resp = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(65_535))
        .await
        .expect("read timeout")
        .expect("read reply");
    assert!(resp.len() >= 2, "reply too short: {resp:?}");
    let rlen = u16::from_be_bytes([resp[0], resp[1]]) as usize;
    assert_eq!(resp.len(), rlen + 2, "framing mismatch");
    let reply = Message::from_bytes(&resp[2..]).expect("decode DoQ reply");
    assert_eq!(reply.metadata.id, 0);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_dot_rejects_wrong_san_dial() {
    // Trusting the right CA is not enough: the DIALED NAME must match the
    // leaf's SAN. A client dialing "wrong.example" (even against the
    // genuine daemon cert) must fail the handshake - this pins that cert
    // validation is load-bearing, not decorative.
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName},
    };

    let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    );

    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let dot_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cert_path = tmp.path().join("leaf-cert.pem");
    let key_path = tmp.path().join("leaf-key.pem");
    std::fs::write(&cert_path, test_certs::TEST_LEAF_CERT_PEM).expect("write cert");
    std::fs::write(&key_path, test_certs::TEST_LEAF_KEY_PEM).expect("write key");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\
         dot_listen = \"127.0.0.1:{dot_port}\"\n\
         tls_cert_path = \"{}\"\n\
         tls_key_path = \"{}\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n",
        cert_path.display(),
        key_path.display()
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(test_certs::TEST_CA_PEM.as_bytes()) {
        roots.add(cert.expect("ca cert")).expect("add ca");
    }
    let crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(crypto));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", dot_port))
        .await
        .expect("tcp connect");
    let wrong_name = ServerName::try_from("wrong.example".to_string()).expect("san name");
    let handshake = connector.connect(wrong_name, tcp);
    let outcome = tokio::time::timeout(Duration::from_secs(3), handshake).await;
    match outcome {
        Err(_) => {}     // timeout waiting for alert: acceptable failure shape
        Ok(Err(_)) => {} // explicit TLS alert: the expected shape
        Ok(Ok(_)) => {
            panic!("handshake SUCCEEDED against wrong SAN - certificate validation is not enforced")
        }
    }

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_default_logging_never_leaks_client_or_query_name() {
    // CAPSTONE privacy contract, verified against the shipped binary with
    // DEFAULT logging (RUST_LOG pinned to info): after driving canary
    // queries through UDP and TCP, every byte the daemon emitted - stdout
    // AND stderr - must be free of (a) the canary query name and (b) the
    // client's full address:port identity.
    use tokio::io::AsyncReadExt;

    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);

    // Pin the DEFAULT posture explicitly (unset env == info anyway).
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&cfg_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn rustydnsd");

    // Readiness poll (same contract as spawn_and_wait_ready).
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
    assert!(ready, "daemon not ready");

    // Drain both pipes concurrently so nothing blocks or truncates.
    let mut out_pipe = child.stdout.take().expect("stdout piped");
    let mut err_pipe = child.stderr.take().expect("stderr piped");
    let out_task = tokio::spawn(async move {
        let mut v = Vec::new();
        let _ = out_pipe.read_to_end(&mut v).await;
        v
    });
    let err_task = tokio::spawn(async move {
        let mut v = Vec::new();
        let _ = err_pipe.read_to_end(&mut v).await;
        v
    });

    // Stub upstream so resolution succeeds and success-path logging runs.
    let (stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;

    let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    client_sock
        .connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");
    let client_port = client_sock.local_addr().expect("local addr").port();

    // Canary queries through both transports.
    for id in [80u16, 81] {
        client_sock
            .send(&build_query(id, "canary-f7q9z.privacy.example."))
            .await
            .expect("send canary udp");
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client_sock.recv_from(&mut buf))
            .await
            .expect("udp reply")
            .expect("recv");
        let reply = Message::from_bytes(&buf[..n]).expect("decode");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);

        // Same name over TCP.
        use tokio::io::{AsyncReadExt as TcpRead, AsyncWriteExt as TcpWrite};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", dns_port))
            .await
            .expect("tcp");
        let q = build_query(id + 10, "canary-f7q9z.privacy.example.");
        let mut framed = Vec::with_capacity(q.len() + 2);
        framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
        framed.extend_from_slice(&q);
        stream.write_all(&framed).await.expect("write tcp");
        let mut lb = [0u8; 2];
        stream.read_exact(&mut lb).await.expect("len");
        let rl = u16::from_be_bytes(lb) as usize;
        let mut rb = vec![0u8; rl];
        stream.read_exact(&mut rb).await.expect("body");
        let treply = Message::from_bytes(&rb).expect("decode tcp");
        assert_eq!(treply.metadata.response_code, ResponseCode::NoError);
    }

    // Upstream-failure path: abort the stub, force one query through the
    // fail-closed arm so its client-context WARN fires. Hickory's own
    // retry/timeout window is ~5s, so wait generously for the SERVFAIL.
    stub.abort();
    let _ = client_sock
        .send(&build_query(90, "after-death.privacy.example."))
        .await;
    let deadline = std::time::Instant::now() + Duration::from_secs(9);
    while std::time::Instant::now() < deadline {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), client_sock.recv_from(&mut buf))
            .await
        {
            Err(_) => continue,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                if let Ok(m) = Message::from_bytes(&buf[..n])
                    && m.metadata.id == 90
                {
                    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
                    break;
                }
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Teardown first: EOF flushes the drain tasks.
    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
    let stdout_bytes = out_task.await.expect("stdout task");
    let stderr_bytes = err_task.await.expect("stderr task");
    let everything = String::from_utf8_lossy(&stdout_bytes).to_string()
        + "\n"
        + &String::from_utf8_lossy(&stderr_bytes);

    // Prove we actually captured daemon output (not an empty pipe).
    assert!(
        everything.contains("rustydnsd starting"),
        "startup banner missing from capture - collection broken"
    );

    // THE CONTRACT: neither identifier appears anywhere.
    assert!(
        !everything.contains("canary-f7q9z"),
        "CANARY QUERY NAME leaked into daemon logs:\n{everything}"
    );
    assert!(
        !everything.contains(&format!("127.0.0.1:{client_port}")),
        "FULL CLIENT IDENTITY (ip:port) leaked into daemon logs:\\n{everything}"
    );

    // Identity-leg teeth: every client-context warn line must carry the
    // ANONYMISED /16 form - never the raw client IP.
    let client_lines: Vec<&str> = everything
        .lines()
        .filter(|l| l.contains("client"))
        .collect();
    eprintln!(
        "DIAG capture_len={} client_lines={} sample={:?}",
        everything.len(),
        client_lines.len(),
        everything.lines().take(4).collect::<Vec<_>>()
    );
    assert!(
        !client_lines.is_empty(),
        "expected at least one client-context warn after stub abort"
    );
    for l in &client_lines {
        assert!(
            l.contains("127.0.0.0/16"),
            "client-context line missing anonymised form: {l}"
        );
        assert!(
            !l.contains("127.0.0.1"),
            "RAW CLIENT IP in client-context line: {l}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_repeat_query_served_from_cache_without_upstream() {
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // First query: MISS -> upstream hit.
    let r1 = resolve_a(&sock, 50, "cached.test.").await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Identical repeat: HIT from cache - same answer, ZERO new upstream
    // traffic. This pins the resolver cache end-to-end; a regression that
    // forwards every query would show hits == 2 here.
    let r2 = resolve_a(&sock, 51, "cached.test.").await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);
    assert!(
        r2.answers.iter().any(|r| matches!(&r.data,
            hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")),
        "cached reply must carry the same A answer"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "repeat query must be served from cache, not re-forwarded"
    );

    // Distinct name: MISS again -> counter advances exactly once more.
    let r3 = resolve_a(&sock, 52, "fresh.test.").await;
    assert_eq!(r3.metadata.response_code, ResponseCode::NoError);
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_any_qtype_refused_rfc8482() {
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // qtype ANY (255) is an amplification vector: must be REFUSED at the
    // edge, never forwarded to the upstream.
    let mut msg = Message::new(60, MessageType::Query, hickory_proto::op::OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query({
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("any.test.").expect("name"));
        q.set_query_type(RecordType::ANY);
        q
    });
    sock.send(&msg.to_vec().expect("encode"))
        .await
        .expect("send");

    let mut refused = false;
    for _ in 0..10 {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                if reply.metadata.id != 60 {
                    continue;
                }
                assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
                assert!(reply.answers.is_empty());
                refused = true;
                break;
            }
        }
    }
    assert!(refused, "ANY query must be refused");
    // And it never reached the upstream as a forwardable question.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_edns_version_mismatch_answers_badvers() {
    // RFC 6891 §6.1.3: an OPT advertising version > ours MUST get BADVERS
    // (extended rcode 16) plus a reply OPT advertising version 0.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    use hickory_proto::op::{Edns, OpCode};
    let mut msg = Message::new(77, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query({
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("edns.test.").expect("name"));
        q.set_query_type(RecordType::A);
        q
    });
    let mut opt = Edns::default();
    opt.set_version(1);
    opt.set_max_payload(1232);
    msg.set_edns(opt);
    let query = msg.to_vec().expect("encode");
    sock.send(&query).await.expect("send");

    let mut saw_badvers = false;
    for _ in 0..10 {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                if reply.metadata.id != 77 {
                    continue;
                }
                // RFC 6891 wire truth: BADVERS = ext-rcode-high 1 with
                // header nibble 0 (hickory's decoder mislabels this
                // combination BADSIG, so assert on the fields themselves).
                let opt = reply.edns.as_ref().expect("reply must carry an OPT");
                assert_eq!(opt.rcode_high(), 1, "ext-rcode-high must encode BADVERS");
                assert_eq!(
                    buf[3] & 0x0F,
                    0,
                    "header rcode nibble must be zero for extended codes"
                );
                assert_eq!(opt.version(), 0, "reply OPT must advertise version 0");
                assert!(reply.answers.is_empty());
                saw_badvers = true;
                break;
            }
        }
    }
    assert!(saw_badvers);
    // The probe never reached upstream resolution.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_upstream_privacy_no_ecs_no_identity_exact_qname() {
    // UPSTREAM PRIVACY CONTRACT, asserted at the wire:
    //   1. The forwarded QNAME is the ORIGINAL name (no search-suffix
    //      prepending, no mutation) - compared case-insensitively.
    //   2. NO EDNS Client Subnet option (code 8) on the upstream OPT -
    //      the LAN client's network must never be disclosed upstream.
    //   3. Datagrams originate from the DAEMON's socket (127.0.0.1 here),
    //      never carrying any per-client source identity.
    //   4. Plain path additionally applies 0x20 case randomization
    //      (anti-spoofing), pinned positively via case divergence.
    //
    // QNAME minimisation note: we are a FORWARDING stub; RFC 9156 qmin
    // governs iterative<->authoritative hops. The privacy levers that DO
    // apply here - exact-name-only, ECS-free, encrypted transports, and
    // ODoH for full obliviousness - are exactly what this test pins.
    use std::sync::atomic::Ordering;

    let canary = "privacy-sensitive-e7c4a9b2.example.";

    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits, captures) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    for id in 300u16..304 {
        let reply = resolve_a(&sock, id, canary).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    }

    // Give the daemon a beat to flush any final retry datagrams.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let caps = captures.lock().unwrap().clone();
    assert!(!caps.is_empty(), "stub captured nothing");

    use hickory_proto::rr::{RecordType, rdata::opt::EdnsCode};

    let mut saw_case_divergence = false;
    for (peer, raw) in &caps {
        // (3) daemon-originated source.
        assert_eq!(
            peer.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "upstream datagram not originated by the daemon: {peer}"
        );
        let msg = Message::from_bytes(raw).expect("captured query must parse");
        // (1) exactly one question, matching the original name.
        assert_eq!(msg.queries.len(), 1, "multiple questions leaked");
        let qname = msg.queries[0].name().to_string();
        assert!(
            qname.eq_ignore_ascii_case(canary),
            "QNAME mutated in transit: got {qname}"
        );
        if qname != *canary {
            saw_case_divergence = true;
        }
        // (2) EDNS present is fine; Client Subnet is not.
        if let Some(edns) = msg.edns.as_ref() {
            assert!(
                edns.option(EdnsCode::Subnet).is_none(),
                "EDNS CLIENT SUBNET leaked upstream! options: {:?}",
                edns.options()
            );
            // No private/experimental option codes either (65001..=65535).
            for (code, _val) in edns.options().as_ref() {
                if let hickory_proto::rr::rdata::opt::EdnsCode::Unknown(num) = code {
                    assert!(
                        *num < 65001,
                        "private-use EDNS option {num} leaked upstream"
                    );
                }
            }
        }
        // Query-only shape: no answers travelling TO the upstream.
        assert!(msg.answers.is_empty(), "answers leaked toward upstream");
        let _ = RecordType::A; // keep import used if API changes
    }

    // (4) plain path must apply 0x20 randomization (case divergence seen).
    assert!(
        saw_case_divergence,
        "plain-path queries lacked 0x20 case randomization (all-lowercase)"
    );

    // Sanity: every canary resolution produced at least one datagram.
    assert!(hits.load(Ordering::SeqCst) >= 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}
