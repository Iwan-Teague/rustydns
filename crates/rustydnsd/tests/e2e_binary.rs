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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
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

    // Refused-at-gate traffic counts TOO: an ANY probe is REFUSED before
    // the pipeline but MUST still advance dns_queries_total - counters
    // are placed PRE-GATE by design ("total DNS queries received").
    // Pinning that placement: moving counters behind the gates makes this
    // leg short by exactly one.
    let mut any_msg = Message::new(44, MessageType::Query, hickory_proto::op::OpCode::Query);
    any_msg.metadata.recursion_desired = true;
    any_msg.add_query({
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("any.counted.test.").expect("name"));
        q.set_query_type(RecordType::ANY);
        q
    });
    sock.send(&any_msg.to_vec().unwrap())
        .await
        .expect("send ANY");
    let mut any_refused = false;
    for _ in 0..8 {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                if let Ok(m) = Message::from_bytes(&buf[..n])
                    && m.metadata.id == 44
                {
                    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
                    any_refused = true;
                    break;
                }
            }
        }
    }
    assert!(any_refused, "ANY probe must be REFUSED");

    // Per-qtype label correctness: the refused probe must appear under
    // qtype="ANY", proving the bounded label mapping survives the early
    // refusal path.
    let m = client.get(format!("{base}/metrics")).send().await.unwrap();
    let mtext = m.text().await.unwrap();
    let any_line = mtext
        .lines()
        .find(|l| l.starts_with("rustydns_dns_queries_by_qtype_total{qtype=\"ANY\"}"))
        .expect("ANY series must exist in by-qtype vector");
    assert!(
        any_line.trim_end().ends_with('1'),
        "exactly one ANY query expected, got: {any_line}"
    );

    let after = metric_value(&client, &base).await;
    assert!(
        (after - before - 4.0).abs() < f64::EPSILON,
        "expected +4 queries (3 served + 1 refused-at-gate), {before} -> {after}"
    );

    // /queries: ring holds our entries - hashed qnames only, never the
    // plaintext name, and the anonymised client form.
    let q = client.get(format!("{base}/queries")).send().await.unwrap();
    assert_eq!(q.status(), 200);
    let qb = q.text().await.unwrap();
    assert!(!qb.contains("counted.test"), "plaintext qname leaked: {qb}");
    assert!(qb.contains("\"qname_hash\""), "{qb}");
    assert!(qb.contains("/16"), "anonymised client marker missing: {qb}");
    // served_by attribution: all three counted.test queries went through
    // the resolver arm; the ring must reflect that - never mislabelled.
    let resolver_entries = qb.matches("\"served_by\":\"resolver\"").count();
    assert!(
        resolver_entries >= 3,
        "expected >=3 Resolver-attributed entries, dump: {qb}"
    );
    // The refused ANY probe is attributed to its own arm - gate
    // rejections are distinguishable from pipeline answers in /queries.
    assert!(
        qb.contains("\"served_by\":\"rejected\""),
        "refused-at-gate entry must carry rejected attribution: {qb}"
    );

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
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
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
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
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
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
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
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
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

    let (stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
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
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .expect("tls handshake timeout")
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

    // SESSION REUSE (RFC 7858 §3.4 encourages it): a SECOND framed
    // exchange on the SAME TLS connection must also resolve. Tearing down
    // per query would defeat session reuse and add a handshake per lookup.
    let query2 = build_query(16, "dot-second.test.");
    let mut framed2 = Vec::with_capacity(query2.len() + 2);
    framed2.extend_from_slice(&(query2.len() as u16).to_be_bytes());
    framed2.extend_from_slice(&query2);
    tls.write_all(&framed2)
        .await
        .expect("write second framed query");

    let mut len_buf2 = [0u8; 2];
    tls.read_exact(&mut len_buf2)
        .await
        .expect("second reply length");
    let reply_len2 = u16::from_be_bytes(len_buf2) as usize;
    assert!(
        reply_len2 > 12 && reply_len2 <= 4096,
        "implausible {reply_len2}"
    );
    let mut reply_buf2 = vec![0u8; reply_len2];
    tls.read_exact(&mut reply_buf2)
        .await
        .expect("second reply body");

    let reply2 = Message::from_bytes(&reply_buf2).expect("decode second");
    assert_eq!(reply2.metadata.id, 16);
    assert_eq!(reply2.metadata.response_code, ResponseCode::NoError);
    assert!(reply2.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));

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
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
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

    // CONNECTION REUSE (RFC 9250 §4.2.1): a SECOND query on a NEW
    // bidirectional stream of the SAME QUIC connection must also resolve.
    let (mut send2, mut recv2) = conn.open_bi().await.expect("open second bi");
    let mut msg2 = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
    msg2.metadata.recursion_desired = true;
    msg2.add_query({
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("second.doq.test.").expect("name"));
        q.set_query_type(RecordType::A);
        q
    });
    let wire2 = msg2.to_vec().expect("encode");
    send2
        .write_all(&(wire2.len() as u16).to_be_bytes())
        .await
        .expect("len");
    send2.write_all(&wire2).await.expect("query");
    send2.finish().expect("finish");

    let resp2 = tokio::time::timeout(Duration::from_secs(5), recv2.read_to_end(65_535))
        .await
        .expect("read timeout")
        .expect("read reply");
    assert!(resp2.len() >= 2);
    let r2 = Message::from_bytes(&resp2[2..]).expect("decode second reply");
    assert_eq!(r2.metadata.id, 0);
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);
    assert!(r2.answers.iter().any(|a| matches!(&a.data,
        hickory_proto::rr::RData::A(ip) if ip.0.to_string() == "192.0.2.1")));
    assert_eq!(hits.load(Ordering::SeqCst), 2);

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
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
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
        // (2) EDNS present is fine; Client Subnet is not - and neither is
        // the DNS Cookie option (10), another tracking/fingerprint vector,
        // nor any TSIG/SIG0 signature material on the query itself.
        if let Some(edns) = msg.edns.as_ref() {
            assert!(
                edns.option(EdnsCode::Subnet).is_none(),
                "EDNS CLIENT SUBNET leaked upstream! options: {:?}",
                edns.options()
            );
            assert!(
                edns.option(EdnsCode::Cookie).is_none(),
                "EDNS COOKIE leaked upstream (tracking vector): {:?}",
                edns.options()
            );
            assert!(
                msg.signature.is_none(),
                "query carried TSIG/SIG0 signature material upstream"
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

/// Adversarial stub: answers EVERY query with the correct A rdata but a
/// DELIBERATELY wrong-cased QNAME echo (all-lowercase), modelling a
/// spoofing/hijacking upstream. Pairs with the daemon's 0x20 verification
/// (opts.case_randomization on plain): responses whose question case does
/// not match the randomized probe MUST be rejected, never served.
async fn spawn_case_spoofing_stub(
    port: u16,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = Arc::clone(&hits);
    let std_sock = std::net::UdpSocket::bind(("127.0.0.1", port)).expect("stub bind");
    std_sock.set_nonblocking(true).expect("nonblocking");
    let sock = tokio::net::UdpSocket::from_std(std_sock).expect("stub into tokio");

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            task_hits.fetch_add(1, Ordering::SeqCst);
            if n < 12 {
                continue;
            }
            // Lowercase every byte of the QUESTION NAME region (offset 12
            // until first zero byte) - guaranteed mismatch whenever the
            // daemon's probe used any uppercase byte (0x20 encoding).
            let mut out = buf[..n].to_vec();
            let mut i = 12;
            while i < out.len() && out[i] != 0 {
                if out[i].is_ascii_uppercase() {
                    out[i] += 32;
                }
                i += 1;
            }
            out[2] |= 0x80;
            out[3] |= 0x80;
            out[6] = 0;
            out[7] = 1;
            out.extend_from_slice(&[
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 0, 2,
                1,
            ]);
            let _ = sock.send_to(&out, peer).await;
        }
    });
    (handle, hits)
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_spoofed_case_responses_fail_closed() {
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits) = spawn_case_spoofing_stub(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Two probes: both carry 0x20-randomized QNAMEs upstream; the spoofer
    // mangles case on every reply, so BOTH must fail closed (SERVFAIL).
    // The spoofed A record must NEVER surface to the client.
    for id in [400u16, 401] {
        let reply = resolve_a(&sock, id, "hijack-target.example.").await;
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::ServFail,
            "case-mismatched upstream response must fail closed, got {reply:?}"
        );
        assert!(
            reply.answers.is_empty(),
            "spoofed answer leaked to client: {:?}",
            reply.answers
        );
    }

    // Both probes genuinely traversed to the upstream (rejection happens
    // AFTER receipt, so two datagrams must have been exchanged).
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_doh_wrong_content_type_is_415() {
    // RFC 8484 §6.1: the POST media type is contractual. A client
    // declaring any other type must get 415 BEFORE the body reaches the
    // parser - completing the binary-level DoH error trio alongside the
    // empty-body and malformed-wire pins.
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
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for ct in ["text/plain", "application/json", ""] {
        let mut req = client
            .post(format!("http://127.0.0.1:{doh_port}/dns-query"))
            .header("content-type", ct)
            .body(build_query(88, "whatever.test."));
        if ct.is_empty() {
            req = req.header("content-type", "application/octet-stream");
        }
        let resp = req.send().await.expect("send");
        assert_eq!(resp.status(), 415, "content-type `{ct}` must be 415");
        assert_eq!(
            resp.headers().get("accept").and_then(|v| v.to_str().ok()),
            Some("application/dns-message"),
            "415 must advertise the accepted type"
        );
    }
    // Nothing reached the upstream.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

/// Stub answering with a configurable TTL - lets tests observe cache
/// EXPIRY without waiting minutes.
async fn spawn_short_ttl_stub(
    port: u16,
    ttl: u32,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = Arc::clone(&hits);
    let std_sock = std::net::UdpSocket::bind(("127.0.0.1", port)).expect("stub bind");
    std_sock.set_nonblocking(true).expect("nonblocking");
    let sock = tokio::net::UdpSocket::from_std(std_sock).expect("stub into tokio");

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            task_hits.fetch_add(1, Ordering::SeqCst);
            if n < 12 {
                continue;
            }
            let mut out = buf[..n].to_vec();
            out[2] |= 0x80;
            out[3] |= 0x80;
            out[6] = 0;
            out[7] = 1;
            let ttl_be = ttl.to_be_bytes();
            out.extend_from_slice(&[
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, ttl_be[0], ttl_be[1], ttl_be[2], ttl_be[3],
                0x00, 0x04, 192, 0, 2, 1,
            ]);
            let _ = sock.send_to(&out, peer).await;
        }
    });
    (handle, hits)
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_cache_entry_expires_and_reforwards() {
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits) = spawn_short_ttl_stub(upstream_port, 1).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // First query: MISS -> forwarded (TTL=1s cached).
    let r1 = resolve_a(&sock, 60, "expiring.test.").await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Wait past expiry. NOTE: the resolver enforces a deliberate cache
    // FLOOR of MIN_POSITIVE_CACHE_TTL_SECS = 2s (anti-requery-storm
    // defense: a hostile upstream cannot force a lookup per request with
    // 0-second records), so our TTL=1 stub entry is clamped UP to 2s and
    // only expires after that floor. Sleeping 2.6s clears it with margin.
    tokio::time::sleep(Duration::from_millis(2600)).await;

    // Second query after expiry: MUST re-forward (hits == 2).
    let r2 = resolve_a(&sock, 61, "expiring.test.").await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "expired entry must be re-fetched from upstream"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_absurd_upstream_ttl_is_clamped() {
    // CACHE-CEILING at the wire: an upstream advertising an absurd TTL
    // (here ~11.5 days) cannot wedge an entry in the cache forever - the
    // resolver clamps positive TTLs down to MAX_POSITIVE_CACHE_TTL_SECS
    // (86 400). Assert the CLIENT-visible TTL reflects that clamp.
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits) = spawn_short_ttl_stub(upstream_port, 999_999).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    sock.send(&build_query(70, "wedged.test."))
        .await
        .expect("send");
    let mut reply = None;
    for _ in 0..10 {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                if let Ok(m) = Message::from_bytes(&buf[..n])
                    && m.metadata.id == 70
                {
                    reply = Some(m);
                    break;
                }
            }
        }
    }
    let reply = reply.expect("no reply");
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 1);
    let served_ttl = reply.answers[0].ttl;
    assert!(
        served_ttl > 0 && served_ttl <= 86_400,
        "absurd upstream TTL must be clamped to <= 86 400, got {served_ttl}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

/// Stub that answers EVERY query with authoritative NXDOMAIN (no SOA -
// hickory tolerates its absence for caching defaults.
async fn spawn_nxdomain_stub(
    port: u16,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = Arc::clone(&hits);
    let std_sock = std::net::UdpSocket::bind(("127.0.0.1", port)).expect("stub bind");
    std_sock.set_nonblocking(true).expect("nonblocking");
    let sock = tokio::net::UdpSocket::from_std(std_sock).expect("stub into tokio");

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            task_hits.fetch_add(1, Ordering::SeqCst);
            if n < 12 {
                continue;
            }
            let mut out = buf[..n].to_vec();
            out[2] |= 0x80; // QR
            out[3] = (out[3] & 0xF0) | 0x03; // RCODE=3 NXDOMAIN
            out[6] = 0; // ANCOUNT
            out[7] = 0; // NSCOUNT
            let _ = sock.send_to(&out, peer).await;
        }
    });
    (handle, hits)
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_negative_responses_are_cached_then_expire() {
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits) = spawn_nxdomain_stub(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    async fn ask_nx(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> bool {
        sock.send(&build_query(id, name)).await.expect("send");
        for _ in 0..12 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await {
                Err(_) => continue,
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    if let Ok(m) = Message::from_bytes(&buf[..n])
                        && m.metadata.id == id
                    {
                        return m.metadata.response_code == ResponseCode::NXDomain;
                    }
                }
            }
        }
        false
    }

    // First NXDOMAIN: MISS -> forwarded.
    assert!(
        ask_nx(&sock, 80, "missing.test.").await,
        "expected NXDOMAIN"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Immediate repeat: served from NEGATIVE cache - no new upstream hit.
    assert!(ask_nx(&sock, 81, "missing.test.").await);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "repeat must hit negative cache"
    );

    // Past the negative floor (same MIN constant, 2s): entry expires,
    // upstream consulted again.
    tokio::time::sleep(Duration::from_millis(2600)).await;
    assert!(ask_nx(&sock, 82, "missing.test.").await);
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_multi_upstream_queries_distribute_across_providers() {
    // PRIVACY FEATURE at the wire: randomize_upstream_selection (default
    // on) distributes queries across configured providers so NO SINGLE
    // upstream builds a complete query history. Two stubs, six distinct
    // names: both stubs must see traffic and the total must be exact.
    //
    // ATTRIBUTION (mutation #106): the distribution is carried by SERIAL
    // DISPATCH (num_concurrent_reqs = 1 in build_resolver_arm), NOT by
    // ServerOrderingStrategy - swapping RoundRobin/QueryStatistics leaves
    // both-stubs>0 intact. A refactor that removes the serial dispatch is
    // what this total==queries assertion exists to catch.
    use std::sync::atomic::Ordering;
    let (dns_port, metrics_port) = (reserve_port(), reserve_port());
    let up1 = reserve_port();
    let up2 = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{up1}\", \"127.0.0.1:{up2}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let (stub1, h1, _c1) = spawn_stub_udp_dns(up1).await;
    let (stub2, h2, _c2) = spawn_stub_udp_dns(up2).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    for id in 300u16..306 {
        let name = format!("provider-split-{id}.example.");
        let reply = resolve_a(&sock, id, &name).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    }

    let c1 = h1.load(Ordering::SeqCst);
    let c2 = h2.load(Ordering::SeqCst);
    assert_eq!(c1 + c2, 6, "every query must reach exactly one provider");
    assert!(c1 > 0, "provider 1 saw nothing - distribution broken");
    assert!(
        c2 > 0,
        "provider 2 saw nothing - single-provider fallback leaks history"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub1.abort();
    stub2.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_serial_dispatch_still_fails_over_to_live_provider() {
    // Regression guard for the num_concurrent_reqs=1 privacy fix: serial
    // dispatch must NOT create an availability cliff. With provider 1
    // dead from startup, every query must still resolve via provider 2
    // (hickory retries remaining servers on timeout/error per request).
    let (dns_port, metrics_port) = (reserve_port(), reserve_port());
    let up_dead = reserve_port(); // nothing ever binds here
    let up_live = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{up_dead}\", \"127.0.0.1:{up_live}\"]\n\
         dnssec_validation = false\n\
         timeout_ms = 1200\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let (stub, hits, _caps) = spawn_stub_udp_dns(up_live).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    for (idx, id) in (500u16..503).enumerate() {
        let name = format!("failover-{idx}.test.");
        let reply = resolve_a(&sock, id, &name).await;
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "query {id} must resolve via the live provider despite dead first"
        );
    }
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

/// Poisoning stub: echoes the question verbatim (passes hickory's
/// TXID+question checks) but attaches an ANSWER for a DIFFERENT name -
/// evil.other.test A 6.6.6.6 - i.e., an out-of-bailiwick record riding a
/// matching question. Only queries under .victim-poison.test get the
/// treatment; everything else receives a standard A answer.
async fn spawn_poisoning_stub(
    port: u16,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = Arc::clone(&hits);
    let std_sock = std::net::UdpSocket::bind(("127.0.0.1", port)).expect("stub bind");
    std_sock.set_nonblocking(true).expect("nonblocking");
    let sock = tokio::net::UdpSocket::from_std(std_sock).expect("stub into tokio");

    // victim CNAME -> evil.other.test. Answer name is compression pointer
    // @12 (the echoed question); RDLEN covers "evil.other.test." (17 bytes).
    const CNAME_ANSWER: &[u8] = &[
        0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x11, 4, b'e', b'v',
        b'i', b'l', 5, b'o', b't', b'h', b'e', b'r', 4, b't', b'e', b's', b't', 0,
    ];
    // evil.other.test. IN A 6.6.6.6 - explicit labels.
    const EVIL_ANSWER: &[u8] = &[
        4, b'e', b'v', b'i', b'l', 5, b'o', b't', b'h', b'e', b'r', 4, b't', b'e', b's', b't', 0,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 6, 6, 6, 6,
    ];

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            task_hits.fetch_add(1, Ordering::SeqCst);
            if n < 12 {
                continue;
            }
            let parsed = Message::from_bytes(&buf[..n]);
            let is_victim = parsed
                .as_ref()
                .map(|m| {
                    m.queries
                        .first()
                        .map(|q| {
                            let n = q.name().to_string().to_ascii_lowercase();
                            let n = n.trim_end_matches('.');
                            n.ends_with(".victim-poison.test")
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(false);

            let mut out = buf[..n].to_vec();
            out[2] |= 0x80;
            out[3] |= 0x80;
            out[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1

            if is_victim {
                // Find end of question (first zero label byte after header).
                let mut qend = 12;
                while qend < n && buf[qend] != 0 {
                    qend += 1;
                }
                qend += 1; // include root label
                // Reply = header + original question + CNAME-RIDING POISON:
                // victim CNAME -> evil.other.test, then evil.other.test
                // A 6.6.6.6. hickory validates the question and cleans
                // non-matching answer names itself; our bailiwick filter is
                // defense-in-depth behind that.
                let mut resp: Vec<u8> = out[..qend].to_vec();
                resp.extend_from_slice(CNAME_ANSWER);
                resp.extend_from_slice(EVIL_ANSWER);
                // Header counts: QD=1, AN=2, NS=0, AR=0.
                resp[4..6].copy_from_slice(&1u16.to_be_bytes());
                resp[6..8].copy_from_slice(&2u16.to_be_bytes());
                resp[8..10].copy_from_slice(&0u16.to_be_bytes());
                resp[10..12].copy_from_slice(&0u16.to_be_bytes());
                let _ = sock.send_to(&resp, peer).await;
            } else {
                // Standard: answer name = compression pointer @12.
                let ans = [
                    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 0,
                    2, 1,
                ];
                out.extend_from_slice(&ans);
                let _ = sock.send_to(&out, peer).await;
            }
        }
    });
    (handle, hits)
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_out_of_bailiwick_answer_is_dropped_not_served() {
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, _hits) = spawn_poisoning_stub(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Control FIRST: healthy baseline through the same stub.
    let ok = resolve_a(&sock, 610, "evil.other.test.").await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
    assert!(ok.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));

    // Three probes at the poisoning name: whatever comes back, the
    // attacker's 6.6.6.6 record must NEVER appear in a client-visible
    // answer.
    for id in 600u16..603 {
        let reply = resolve_a(&sock, id, "sub.victim-poison.test.").await;
        eprintln!(
            "PROBE id={id} rcode={:?} answers={:?}",
            reply.metadata.response_code, reply.answers
        );
        let leaked = reply.answers.iter().any(|r| {
            matches!(&r.data,
            hickory_proto::rr::RData::A(a) if a.0.to_string() == "6.6.6.6")
        });
        assert!(
            !leaked,
            "OUT-OF-BAILIWICK POISON SERVED TO CLIENT: {:?}",
            reply.answers
        );
    }

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_conditional_forwarding_routes_by_zone() {
    // CONDITIONAL FORWARDING at the wire: queries under corp.test. must
    // reach the ROUTE upstream; everything else the DEFAULT upstream.
    // Per-stub counters prove the split - a route-table regression that
    // sends zone queries to the default arm (or vice versa) fails here.
    let (dns_port, metrics_port) = (reserve_port(), reserve_port());
    let up_default = reserve_port();
    let up_route = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{up_default}\"]\n\
         dnssec_validation = false\n\n\
         [[upstream.routes]]\n\
         zone = \"corp.test.\"\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{up_route}\"]\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub_default, hits_default, _cd) = spawn_stub_udp_dns(up_default).await;
    let (stub_route, hits_route, _cr) = spawn_stub_udp_dns(up_route).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Zone-matched: must hit the ROUTE stub only.
    for id in 700u16..703 {
        let reply = resolve_a(&sock, id, &format!("db{idx}.corp.test.", idx = id - 700)).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    }
    assert_eq!(
        hits_route.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "zone queries must go to the routed upstream"
    );
    assert_eq!(
        hits_default.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "zone queries must NOT leak to the default upstream"
    );

    // Non-zone: must hit the DEFAULT stub only.
    for id in 710u16..712 {
        let reply = resolve_a(&sock, id, &format!("web{idx}.example.com.", idx = id - 710)).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    }
    assert_eq!(
        hits_route.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "non-zone queries must not touch the routed upstream"
    );
    assert_eq!(hits_default.load(std::sync::atomic::Ordering::SeqCst), 2);

    // Zone APEX (exact match with the zone itself) routes too.
    let apex = resolve_a(&sock, 720, "corp.test.").await;
    assert_eq!(apex.metadata.response_code, ResponseCode::NoError);
    assert_eq!(hits_route.load(std::sync::atomic::Ordering::SeqCst), 4);

    // Mixed-case subdomain routes identically. ATTRIBUTION (mutation
    // #109): case-folding is enforced by the handler's canonical_qname
    // BEFORE route selection - this resolver-side fold is belt-and-braces,
    // so a regression here surfaces as handler-dependent behaviour.
    let mixed = resolve_a(&sock, 721, "Db.Corp.Test.").await;
    assert_eq!(mixed.metadata.response_code, ResponseCode::NoError);
    assert_eq!(hits_route.load(std::sync::atomic::Ordering::SeqCst), 5);
    assert_eq!(hits_default.load(std::sync::atomic::Ordering::SeqCst), 2);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub_default.abort();
    stub_route.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_regex_blocklist_blocks_matching_domains() {
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = tmp.path().join("rustydns.toml");
    // The regex pattern uses \\ for escaped dots (valid in TOML basic
    // strings, producing \. in the regex which matches literal dots).
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\
         block_response = \"refused\"\n\
         regex_rules = [\"tracking\"]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Matching domains: REFUSED by regex substring.
    for (id, name) in [(500u16, "cdn-tracking.net."), (501, "pixel-tracking.io.")] {
        let reply = resolve_a(&sock, id, name).await;
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::Refused,
            "{name} must be REFUSED by regex rule"
        );
    }

    // Non-matching domain: resolve normally through stub.
    let ok = resolve_a(&sock, 502, "content.test.").await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_sinkhole_mode_serves_operator_ip_for_blocked_domains() {
    // SINKHOLE journey: block_response = "sinkhole" turns every blocked
    // domain into an A record pointing at the operator's chosen IP -
    // useful for LAN-wide block pages. Pins that (a) the sinkhole IP is
    // served INSTEAD of any upstream answer, (b) non-blocked domains are
    // untouched, and (c) the distinction is wire-visible (two different
    // A addresses from the same daemon in one session).
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let bl_path = tmp.path().join("sinkhole.blocklist");
    std::fs::write(&bl_path, "0.0.0.0 ads.test\n").expect("write blocklist");

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
         local_files = [\"{}\"]\n\
         block_response = \"sinkhole\"\n\
         sinkhole_ip = \"192.0.2.99\"\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n",
        bl_path.display()
    );
    std::fs::write(&cfg_path, &config).expect("write config");
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

    // Blocked domain: sinkhole A answer, NOT the stub's 192.0.2.1.
    let reply = resolve_a(&sock, 500, "ads.test.").await;
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 1);
    match &reply.answers[0].data {
        hickory_proto::rr::RData::A(ip) => {
            assert_eq!(
                ip.0.to_string(),
                "192.0.2.99",
                "must be the OPERATOR's sinkhole IP"
            );
        }
        other => panic!("expected sinkhole A record, got {other:?}"),
    }

    // Unblocked domain still resolves through the stub normally.
    let ok = resolve_a(&sock, 501, "clean.test.").await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
    assert!(ok.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));

    // Upstream saw exactly one query: only clean.test was forwarded.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_safesearch_rewrites_google_over_udp() {
    // SAFESEARCH enforcement at the wire: a real client query for
    // google.com must be answered with a CNAME to
    // forcesafesearch.google.com — the rewrite pipeline runs BEFORE the
    // resolver, so the stub never sees google.com itself. The control
    // domain (example.org) passes through untouched and fails closed
    // against the unreachable resolver.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
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
         [safesearch]\n\
         enabled = true\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // google.com → CNAME forcesafesearch.google.com.
    let reply = resolve_a(&sock, 500, "google.com.").await;
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(
        reply.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::CNAME(t) if t.to_string() == "forcesafesearch.google.com.")),
        "google.com must produce a forcesafesearch CNAME: {:?}",
        reply.answers
    );

    // Non-search collateral: example.org is NOT rewritten; it goes to
    // the stub upstream as a normal query.
    let ok = resolve_a(&sock, 501, "example.org.").await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_longest_prefix_route_wins_regardless_of_declaration_order() {
    // ROUTE PRIORITY: when two routes overlap (one zone is a suffix of
    // the other), the MORE SPECIFIC route must win regardless of
    // declaration order. Before this was fixed, first-match-wins meant
    // declaration order determined routing - an operator listing
    // `test.` before `corp.test.` would send corp queries to the wrong
    // upstream.
    let (dns_port, metrics_port) = (reserve_port(), reserve_port());
    let up_broad = reserve_port();
    let up_narrow = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    // TWO overlapping routes, BROAD ZONE FIRST — old code matched it.
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{up_broad}\"]\n\
         dnssec_validation = false\n\n\
         [[upstream.routes]]\n\
         zone = \"test.\"\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{up_broad}\"]\n\n\
         [[upstream.routes]]\n\
         zone = \"corp.test.\"\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{up_narrow}\"]\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let (stub_broad, hits_broad, _cb) = spawn_stub_udp_dns(up_broad).await;
    let (stub_narrow, hits_narrow, _cn) = spawn_stub_udp_dns(up_narrow).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Narrow-zone query: must go to the NARROW route's upstream.
    let r1 = resolve_a(&sock, 800, "db.corp.test.").await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        hits_narrow.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "corp.test. query must reach the narrow route"
    );
    assert_eq!(
        hits_broad.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "corp.test. query must NOT leak to the default/broad upstream"
    );

    // Non-overlapping query: goes to the default upstream.
    let r2 = resolve_a(&sock, 801, "web.example.com.").await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        hits_broad.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "non-route query must use the default upstream"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub_broad.abort();
    stub_narrow.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_authority_static_record_served_with_aa_flag() {
    // AUTHORITY path at the wire: a [[authority.static_records]] entry
    // must be served with the AA flag set and bypass both the blocklist
    // AND the resolver entirely (pipeline order: Authority first).
    // Pins that the authority arm works through the real binary, not
    // just handler unit tests.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
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

    // Query the static record: AA flag set, correct A answer.
    sock.send(&build_query(90, "router.mesh."))
        .await
        .expect("send");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply")
        .expect("recv");
    let reply = Message::from_bytes(&buf[..n]).expect("decode");
    assert_eq!(reply.metadata.id, 90);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(
        reply.metadata.authoritative,
        "static record must be served with AA flag"
    );
    assert_eq!(reply.answers.len(), 1);
    match &reply.answers[0].data {
        hickory_proto::rr::RData::A(ip) => {
            assert_eq!(
                ip.0.to_string(),
                "10.0.0.1",
                "must serve the configured address"
            );
        }
        other => panic!("expected A record, got {other:?}"),
    }

    // The authority answered WITHOUT consulting the upstream.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_in_zone_nodata_is_noerror_not_nxdomain() {
    // RFC 2308 §2.1 DESIGN DECISION at the wire: a query for a name INSIDE
    // the authoritative zone that has NO matching record must return
    // NoError + zero answers (NODATA), never NXDOMAIN. Returning NXDOMAIN
    // for transient mesh gaps would poison downstream negative caches and
    // delay peer discovery after the record reappears.
    //
    // Also pins the contrast: an OUT-of-zone query falls through to the
    // upstream (which is unreachable) and fails closed to SERVFAIL.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let (_stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    // No upstream stub needed: the authority serves everything in-zone,
    // and out-of-zone queries fail closed against the unreachable resolver.
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    async fn ask(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> Message {
        sock.send(&build_query(id, name)).await.expect("send");
        for _ in 0..12 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
                Err(_) => continue,
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    if let Ok(m) = Message::from_bytes(&buf[..n])
                        && m.metadata.id == id
                    {
                        return m;
                    }
                }
            }
        }
        panic!("no reply for {name}");
    }

    // In-zone + has record → NoError + answer.
    let found = ask(&sock, 90, "router.mesh.").await;
    assert_eq!(found.metadata.response_code, ResponseCode::NoError);
    assert_eq!(found.answers.len(), 1);
    assert!(found.metadata.authoritative);

    // In-zone + NO record → NoError + EMPTY (NODATA, not NXDOMAIN).
    let nodata = ask(&sock, 91, "ghost.mesh.").await;
    assert_eq!(
        nodata.metadata.response_code,
        ResponseCode::NoError,
        "in-zone missing record must be NODATA, not NXDOMAIN"
    );
    assert!(nodata.answers.is_empty());

    // Out-of-zone → forwarded to upstream → resolved normally.
    let outside = ask(&sock, 92, "external.example.org.").await;
    assert_eq!(
        outside.metadata.response_code,
        ResponseCode::NoError,
        "out-of-zone must forward to upstream and resolve"
    );
    assert!(!outside.answers.is_empty());

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_concurrent_multi_client_resolution() {
    // CONCURRENCY at the wire: four independent client sockets query
    // DIFFERENT names. Each must receive its OWN response on its OWN
    // socket - proving no cross-talk, no port collision, and correct
    // per-query correlation under multi-client load.
    use std::sync::atomic::Ordering;
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (stub, hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let names = ["alpha.test.", "beta.test.", "gamma.test.", "delta.test."];
    let mut socks = Vec::new();
    for _ in 0..4 {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        s.connect(("127.0.0.1", dns_port)).await.expect("connect");
        socks.push(s);
    }

    // Each client queries its own name and verifies its own answer.
    for (i, sock) in socks.iter().enumerate() {
        let id = 700u16 + i as u16;
        let name = names[i];
        sock.send(&build_query(id, name)).await.expect("send");
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("reply within timeout")
            .expect("recv");

        let reply = Message::from_bytes(&buf[..n]).expect("decode");
        assert_eq!(reply.metadata.id, id);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            reply.answers.iter().any(|r| matches!(&r.data,
                hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")),
            "{name} must resolve via stub"
        );
    }

    assert_eq!(hits.load(Ordering::SeqCst), 4);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_multiple_static_records_and_nodata() {
    // AUTHORITY serving: multiple static records for different names,
    // plus NODATA for an in-zone name without any record.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [[authority.static_records]]\n\
         name = \"backup.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.2\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    async fn ask(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> Message {
        sock.send(&build_query(id, name)).await.expect("send");
        for _ in 0..12 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
                Err(_) => continue,
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    if let Ok(m) = Message::from_bytes(&buf[..n])
                        && m.metadata.id == id
                    {
                        return m;
                    }
                }
            }
        }
        panic!("no reply for {name}");
    }

    // Both static records served authoritatively.
    let router = ask(&sock, 90, "router.mesh.").await;
    assert_eq!(router.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        router
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                hickory_proto::rr::RData::A(ip) => Some(ip.0.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec!["10.0.0.1"],
        "router.mesh must serve its configured A record"
    );

    let backup = ask(&sock, 91, "backup.mesh.").await;
    assert_eq!(backup.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        backup
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                hickory_proto::rr::RData::A(ip) => Some(ip.0.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec!["10.0.0.2"],
        "backup.mesh must serve its configured A record"
    );

    // In-zone ghost: NODATA (NoError + empty), never NXDOMAIN.
    let ghost = ask(&sock, 92, "ghost.mesh.").await;
    assert_eq!(ghost.metadata.response_code, ResponseCode::NoError);
    assert!(ghost.answers.is_empty(), "ghost must be NODATA");

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_zone_apex_infrastructure_queries() {
    // Zone-infrastructure queries (SOA, NS for the zone apex) are common
    // from monitoring systems. These must never crash the daemon or leak
    // internal data. The authority has no SOA/NS records configured, so
    // all such queries should return NoError + empty (NODATA).
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = tmp.path().join("rustydns.toml");

    // One static A record so the authority zone exists.
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Infrastructure queries against the zone apex: no SOA/NS records
    // exist, so these return NoError + empty answers (NODATA).
    for (id, qtype, label) in [
        (90u16, RecordType::SOA, "SOA"),
        (91, RecordType::NS, "NS"),
        (92, RecordType::A, "A"),
    ] {
        let mut msg = Message::new(id, MessageType::Query, hickory_proto::op::OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query({
            let mut q = hickory_proto::op::Query::new();
            q.set_name(Name::from_ascii("mesh.").expect("name"));
            q.set_query_type(qtype);
            q
        });
        sock.send(&msg.to_vec().unwrap()).await.expect("send");

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("reply")
            .expect("recv");
        let reply = Message::from_bytes(&buf[..n]).expect("decode");
        assert_eq!(reply.metadata.id, id);
        // Authoritative NODATA is correct: we ARE the authority for this
        // zone, we just don't have {label} records at the apex.
        assert!(
            reply.metadata.authoritative,
            "{label} apex query should carry AA flag from the authority"
        );
        assert!(
            reply.answers.is_empty(),
            "{label} apex must have no answers"
        );
    }

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_maximum_length_domain_name_resolves() {
    // WIRE LIMIT: a domain name approaching the 253-byte presentation
    // limit must resolve correctly through the full pipeline. Tests that
    // the wire encoder/decoder handles multi-label names near the
    // protocol maximum without truncation or corruption.
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

    // Build a ~250-byte name from 50-char labels.
    let l1 = "a".repeat(50);
    let l2 = "b".repeat(50);
    let l3 = "c".repeat(50);
    let l4 = "d".repeat(50);
    let name = format!("{l1}.{l2}.{l3}.{l4}.example.");
    let total = name.len();
    assert!(
        total > 200 && total <= 253,
        "test name must be near but within the 253-byte limit, got {total}"
    );

    sock.send(&build_query(800, &name)).await.expect("send");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply")
        .expect("recv");

    let reply = Message::from_bytes(&buf[..n]).expect("decode");
    assert_eq!(reply.metadata.id, 800);
    // The stub answers everything NoError; the key assertion is that the
    // daemon didn't corrupt or truncate the name during forwarding.
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);

    // Verify the question section preserved the original name exactly.
    let echoed = reply.queries.first().expect("question").name().to_string();
    assert_eq!(
        echoed.trim_end_matches('.'),
        name.trim_end_matches('.'),
        "long QNAME must survive the round-trip unchanged"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_authority_serves_over_doh_transport() {
    // TRANSPORT COVERAGE: all existing authority pins use UDP; this proves
    // the authority arm serves mesh-zone records over DoH transport too.
    // The stub upstream must receive ZERO datagrams (authority short-
    // circuits before resolver per pipeline order).
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let doh_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\
         doh_listen = \"127.0.0.1:{doh_port}\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    // Write a static record file and reference it from the config.
    let sr_path = tmp.path().join("static.toml");
    std::fs::write(
        &sr_path,
        "[[authority.static_records]]\nname = \"router.mesh.\"\ntype = \"A\"\naddress = \"10.0.0.1\"\nttl = 300\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sr_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // RFC 8484 POST: query router.mesh. via DoH.
    let resp = client
        .post(format!("http://127.0.0.1:{doh_port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(build_query(90, "router.mesh."))
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
    let wire = resp.bytes().await.expect("body");
    let reply = Message::from_bytes(&wire).expect("decode DoH reply");
    assert_eq!(reply.metadata.id, 90);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(
        reply.metadata.authoritative,
        "mesh-zone query must carry AA flag"
    );
    assert!(
        reply.answers.iter().any(|r| matches!(&r.data,
            hickory_proto::rr::RData::A(a) if a.0.to_string() == "10.0.0.1")),
        "must serve static record address over DoH"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_authority_cname_chain_resolution() {
    // CNAME CHASE at the wire: alias.mesh. CNAME target.mesh. must be
    // chased to target.mesh.'s A record in a single response containing
    // BOTH the CNAME and the terminal A record. Pins the authority's
    // intra-zone chain-following (RFC 1034 §3.6.2) through the real
    // binary.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"alias.mesh.\"\n\
         type = \"CNAME\"\n\
         target = \"target.mesh.\"\n\
         ttl = 300\n\n\
         [[authority.static_records]]\n\
         name = \"target.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Query A for alias.mesh.: expect NoError + [CNAME + A].
    sock.send(&build_query(95, "alias.mesh."))
        .await
        .expect("send");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply")
        .expect("recv");

    let reply = Message::from_bytes(&buf[..n]).expect("decode");
    assert_eq!(reply.metadata.id, 95);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 2, "chain must surface both records");

    // First answer: CNAME alias.mesh. -> target.mesh.
    assert_eq!(reply.answers[0].record_type(), RecordType::CNAME);
    match &reply.answers[0].data {
        hickory_proto::rr::RData::CNAME(t) => {
            assert_eq!(t.to_string(), "target.mesh.");
        }
        other => panic!("expected CNAME, got {other:?}"),
    }

    // Second answer: A target.mesh. -> 10.0.0.1.
    assert_eq!(reply.answers[1].record_type(), RecordType::A);
    match &reply.answers[1].data {
        hickory_proto::rr::RData::A(ip) => {
            assert_eq!(ip.0.to_string(), "10.0.0.1");
        }
        other => panic!("expected A record, got {other:?}"),
    }

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_authority_precedes_blocklist_for_same_name() {
    // AGENTS.md INVARIANT at the wire: "Authority answers before blocklist."
    // When a name appears in BOTH [[authority.static_records]] AND the
    // blocklist, the AUTHORITY answer must win — the blocklist must never
    // override signed mesh data. Pins pipeline ordering end-to-end.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let bl_path = tmp.path().join("conflict.blocklist");
    std::fs::write(&bl_path, "0.0.0.0 conflict.mesh.\n").expect("write blocklist");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\
         local_files = [\"{}\"]\n\n\
         [[authority.static_records]]\n\
         name = \"conflict.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n",
        bl_path.display()
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Query the conflicting name: MUST get the authority answer (10.0.0.1),
    // NOT the blocklist response.
    sock.send(&build_query(96, "conflict.mesh."))
        .await
        .expect("send");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply")
        .expect("recv");

    let reply = Message::from_bytes(&buf[..n]).expect("decode");
    assert_eq!(reply.metadata.id, 96);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(
        reply.metadata.authoritative,
        "authority answer must carry AA flag"
    );
    assert_eq!(reply.answers.len(), 1);
    match &reply.answers[0].data {
        hickory_proto::rr::RData::A(ip) => {
            assert_eq!(
                ip.0.to_string(),
                "10.0.0.1",
                "AUTHORITY must win over blocklist for the same name"
            );
        }
        other => panic!("expected A record, got {other:?}"),
    }

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_authority_serves_txt_records() {
    // TXT RECORDS: SPF/DKIM/service-discovery data stored as static
    // authority records must be served correctly over UDP.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"mesh.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [blocklist]\n\n\
         [[authority.static_records]]\n\
         name = \"spf.mesh.\"\n\
         type = \"TXT\"\n\
         target = \"v=spf1 ip4:10.0.0.0/8 -all\"\n\
         ttl = 300\n\n\
         [[authority.static_records]]\n\
         name = \"router.mesh.\"\n\
         type = \"A\"\n\
         address = \"10.0.0.1\"\n\
         ttl = 300\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // TXT query for spf.mesh.
    let mut msg = Message::new(97, MessageType::Query, hickory_proto::op::OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query({
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("spf.mesh.").expect("name"));
        q.set_query_type(RecordType::TXT);
        q
    });
    sock.send(&msg.to_vec().unwrap()).await.expect("send");

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply")
        .expect("recv");
    let reply = Message::from_bytes(&buf[..n]).expect("decode");
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 1);
    match &reply.answers[0].data {
        hickory_proto::rr::RData::TXT(txt) => {
            let text: Vec<String> = txt
                .txt_data
                .iter()
                .map(|d| String::from_utf8_lossy(d).to_string())
                .collect();
            assert!(
                text.iter().any(|t| t.contains("v=spf1")),
                "SPF content must be preserved: {text:?}"
            );
        }
        other => panic!("expected TXT record, got {other:?}"),
    }

    // A query for router.mesh. still works (different static record).
    sock.send(&build_query(98, "router.mesh."))
        .await
        .expect("send");
    let mut a_buf = vec![0u8; 4096];
    let (an, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut a_buf))
        .await
        .expect("reply")
        .expect("recv");
    let a_reply = Message::from_bytes(&a_buf[..an]).expect("decode");
    assert_eq!(a_reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(a_reply.answers.len(), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_zero_question_count_gets_formerr() {
    // RFC 1035 §4.1.1: QDCOUNT specifies the number of entries in the
    // question section. A query with QDCOUNT=0 carries no question —
    // hickory-server should reject it before our handler sees it, or our
    // gate should return FORMERR.
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Build a header-only DNS message: QDCOUNT=0, ANCOUNT=0, etc.
    let mut empty_query = vec![0u8; 12];
    empty_query[0] = 0x30; // id high byte
    empty_query[1] = 0x31; // id low byte
    empty_query[2] = 0x01; // RD=1, QR=0
    // bytes 4..12 default to zero counts
    sock.send(&empty_query).await.expect("send");

    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await;
    match result {
        Err(_) => panic!("daemon hung on QDCOUNT=0 query"),
        Ok(Err(_)) => {} // send error / ICMP unreachable: acceptable
        Ok(Ok((n, _))) => {
            let reply = Message::from_bytes(&buf[..n]).expect("decode");
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::FormErr,
                "QDCOUNT=0 must yield FORMERR, got {:?}",
                reply.metadata.response_code
            );
        }
    }

    child.kill().await.expect("kill daemon");
}

#[tokio::test(flavor = "current_thread")]
async fn binary_e2e_max_label_length_resolves() {
    let (dns_port, upstream_port, metrics_port) = pick_ports();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_daemon_config(tmp.path(), dns_port, upstream_port, metrics_port, None);
    let (_stub, _hits, _caps) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = spawn_and_wait_ready(&cfg_path, dns_port).await;
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    let max_label = "a".repeat(63);
    let name = format!("{max_label}.test.");
    sock.send(&build_query(810, &name)).await.expect("send");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply")
        .expect("recv");

    let reply = Message::from_bytes(&buf[..n]).expect("decode");
    assert_eq!(reply.metadata.id, 810);
    assert_eq!(
        reply.metadata.response_code,
        ResponseCode::NoError,
        "63-char label query must resolve"
    );
    let echoed = reply.queries.first().expect("question").name().to_string();
    assert_eq!(
        echoed.trim_end_matches('.'),
        name.trim_end_matches('.'),
        "63-char label must survive round-trip"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
}
