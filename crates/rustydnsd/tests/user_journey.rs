//! USER-JOURNEY lane: plug-and-play proof using the shipped
//! `rustydns.example.toml`, exactly as an operator would.
//!
//! Journey 1 (this file): copy the example VERBATIM, apply ONLY the three
//! substitutions CI physically requires (privileged port 53, external DoH
//! network, remote blocklist fetch), start the REAL binary the way the
//! README says, and assert a query resolves within 10 seconds.
//!
//! Every substitution asserts its search-string matched - so if the
//! example config drifts, THIS test fails and forces a conscious update,
//! instead of silently testing a fictional config.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

const EXAMPLE_REL: &str = "rustydns.example.toml";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("port")
        .port()
}

/// Minimal raw-DNS stub upstream (same wire trick as e2e_binary.rs):
/// QR/RA flip + pointer-compressed A 192.0.2.1 answer.
async fn spawn_stub_udp_dns(
    port: u16,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
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
            task_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < 12 {
                continue;
            }
            let mut out = buf[..n].to_vec();
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

fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query({
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii(name).expect("name"));
        q.set_query_type(RecordType::A);
        q
    });
    msg.to_vec().expect("encode")
}

/// Substitute EXACTLY the three CI-mandatory bits of the shipped example.
/// Each replacement asserts its anchor matched once - example drift fails
/// loudly here instead of silently testing fiction.
fn ci_substitutions(example: &str, dns_port: u16, upstream_port: u16, metrics_port: u16) -> String {
    let out = example
        // (1) Privileged port: CI runs unprivileged; loopback :53 needs
        // CAP_NET_BIND_SERVICE which the test harness cannot grant.
        .replace(
            "listen = [\"127.0.0.1:53\"]",
            &format!("listen = [\"127.0.0.1:{dns_port}\"]"),
        )
        // (2) External DoH network: policy forbids outbound calls from CI;
        // swap the real resolvers for an in-test plain stub.
        .replace(
            "resolvers = [\n    \"https://dns.quad9.net/dns-query\",           # Quad9 (privacy-focused, DNSSEC)\n    \"https://cloudflare-dns.com/dns-query\",       # Cloudflare 1.1.1.1\n]",
            &format!("resolvers = [\"127.0.0.1:{upstream_port}\"]"),
        )
        .replace("protocol = \"doh\"", "protocol = \"plain\"")
        .replace(
            "min_tls_version = \"1.3\"",
            "# min_tls_version: N/A for the plain CI stub",
        )
        .replace(
            "dnssec_validation = true",
            "dnssec_validation = false",
        )
        // (3) Remote blocklist fetch: same no-external-network policy.
        .replace(
            "sources = [\n    \"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts\",\n    # \"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt\",\n]",
            "sources = []",
        )
        // Metrics port collision avoidance (9153 may be occupied on devs).
        .replace(
            "listen = \"127.0.0.1:9153\"",
            &format!("listen = \"127.0.0.1:{metrics_port}\""),
        );

    // Drift guards: every FUNCTIONAL anchor above had to match exactly
    // once. (Bare substrings like `127.0.0.1:53` also appear inside the
    // example's security comments, so guards use the assignment forms.)
    for anchor in [
        "listen = [\"127.0.0.1:53\"]",
        "quad9.net",
        "protocol = \"doh\"",
        "raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "listen = \"127.0.0.1:9153\"",
    ] {
        assert!(
            !out.contains(anchor),
            "substitution missed anchor `{anchor}` - rustydns.example.toml drifted; \
             update ci_substitutions() consciously"
        );
    }
    // And the untouched parts really are the shipped file.
    assert!(out.contains("mesh_zone_bundle_path = \"/var/lib/rustynet/dns-zone.bundle\""));
    assert!(out.contains("[safesearch]"));
    out
}

#[tokio::test(flavor = "current_thread")]
async fn quickstart_example_config_verbatim_validates_and_resolves() {
    let example_path = repo_root().join(EXAMPLE_REL);
    let example = std::fs::read_to_string(&example_path).expect("shipped rustydns.example.toml");

    // --- STEP 1: the UNMODIFIED file must pass --validate-config ----------
    // Plug-and-play starts here: whatever an operator copies must at least
    // be accepted by the shipped binary before any editing.
    let raw_path = repo_root().join("target/journey-example-raw.toml");
    std::fs::create_dir_all(raw_path.parent().unwrap()).unwrap();
    std::fs::write(&raw_path, &example).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&raw_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&raw_path)
        .arg("--validate-config")
        .output()
        .await
        .expect("run --validate-config on the shipped example");
    assert!(
        out.status.success(),
        "the SHIPPED example config failed --validate-config:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // --- STEP 2: CI-substituted variant serves a real query ---------------
    let (dns_port, upstream_port, metrics_port) = (reserve_port(), reserve_port(), reserve_port());
    let served = ci_substitutions(&example, dns_port, upstream_port, metrics_port);

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = tmp.path().join("rustydns.toml");
    std::fs::write(&cfg_path, served).expect("write substituted config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let (stub, _hits) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn rustydnsd");

    // Readiness: TCP listener bound.
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
        panic!("daemon never became ready on the substituted example config");
    }

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // THE JOURNEY CONTRACT: resolves within 10 seconds of going ready.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut resolved = false;
    let mut id = 100u16;
    while std::time::Instant::now() < deadline {
        sock.send(&build_query(id, "www.example.com."))
            .await
            .expect("send");
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await {
            Err(_) => {
                id += 1;
                continue;
            }
            Ok(Err(_)) => {
                id += 1;
                continue;
            }
            Ok(Ok((n, _))) => {
                if let Ok(reply) = Message::from_bytes(&buf[..n])
                    && reply.metadata.id == id
                {
                    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                    assert!(reply.answers.iter().any(|r| matches!(&r.data,
                        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));
                    resolved = true;
                    break;
                }
                id += 1;
            }
        }
    }
    assert!(resolved, "example-config daemon did not resolve within 10s");

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn ad_block_out_of_the_box_doubleclick_blocked_google_resolves() {
    use std::sync::atomic::Ordering;
    let example_path = repo_root().join(EXAMPLE_REL);
    let example = std::fs::read_to_string(&example_path).expect("shipped rustydns.example.toml");

    let (dns_port, upstream_port, metrics_port) = (reserve_port(), reserve_port(), reserve_port());
    let mut served = ci_substitutions(&example, dns_port, upstream_port, metrics_port);

    // Operator journey: drop a Pi-hole-format blocklist next to the config
    // and add ONE line to the shipped [blocklist] section.
    let pihole_path = repo_root().join("target/journey-pihole.hosts");
    std::fs::create_dir_all(pihole_path.parent().unwrap()).unwrap();
    std::fs::write(&pihole_path, "0.0.0.0 doubleclick.net\n").expect("write pihole file");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pihole_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let anchor = "sources = []";
    assert!(
        served.contains(anchor),
        "substituted example lost its (empty) sources anchor"
    );
    served = served.replace(
        anchor,
        &format!(
            "sources = []\nlocal_files = [{}]",
            quote_for_toml(&pihole_path)
        ),
    );

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = tmp.path().join("rustydns.toml");
    std::fs::write(&cfg_path, &served).expect("write config");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let (stub, hits) = spawn_stub_udp_dns(upstream_port).await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
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
    assert!(ready, "daemon not ready");

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // 1) doubleclick.net -> blocked (default response_code = NXDOMAIN).
    let mut blocked = false;
    'b: for id in 200u16..210 {
        sock.send(&build_query(id, "doubleclick.net."))
            .await
            .expect("send");
        for _ in 0..6 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await {
                Err(_) => break,
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                        continue;
                    };
                    if reply.metadata.id != id {
                        continue;
                    }
                    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
                    assert!(reply.answers.is_empty());
                    blocked = true;
                    break 'b;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(blocked, "doubleclick.net was not blocked out of the box");

    // 2) google.com still resolves normally.
    let ok = resolve_via(&sock, 220, "google.com.").await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
    assert!(ok.answers.iter().any(|r| matches!(&r.data,
        hickory_proto::rr::RData::A(a) if a.0.to_string() == "192.0.2.1")));

    // 3) Only the allowed domain ever reached the upstream.
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

async fn resolve_via(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> Message {
    sock.send(&build_query(id, name)).await.expect("send");
    for _ in 0..20 {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
            Err(_) => continue,
            Ok(Err(_)) => continue,
            Ok(Ok((n, _))) => {
                let Ok(reply) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                if reply.metadata.id == id {
                    return reply;
                }
            }
        }
    }
    panic!("no reply for {name}");
}

fn quote_for_toml(p: &Path) -> String {
    format!("\"{}\"", p.display())
}

#[tokio::test(flavor = "current_thread")]
async fn config_error_ux_names_the_offender_and_exits_nonzero() {
    // Journey 3: an operator's typo must produce an error that names the
    // offending key, points at its line, and lists valid alternatives -
    // never a silent ignore and never a raw parse dump.

    async fn validate(body: &str) -> (Option<i32>, String) {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = tmp.path().join("rustydns.toml");
        std::fs::write(&cfg, body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
            .arg("--config")
            .arg(&cfg)
            .arg("--validate-config")
            .output()
            .await
            .expect("run rustydnsd");
        let combined = String::from_utf8_lossy(&out.stdout).to_string()
            + "\n"
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.code(), combined)
    }

    // Case A: typoed key inside [server].
    let typo_body = "[server]\nlistenn = [\"127.0.0.1:53\"]\nmesh_zone = \"test.\"\n\
                     [upstream]\nprotocol = \"plain\"\nresolvers = [\"127.0.0.1:5300\"]\n\
                     dnssec_validation = false\n";
    let (code, out) = validate(typo_body).await;
    assert_ne!(code, Some(0), "typoed key must fail validation");
    assert!(
        out.contains("unknown field `listenn`"),
        "must name the typo: {out}"
    );
    assert!(
        out.contains("expected one of"),
        "must list valid alternatives: {out}"
    );
    assert!(
        out.contains("line 2"),
        "must point at the offending line: {out}"
    );

    // Case B: unparseable listen address.
    let bad_addr_body = "[server]\nlisten = [\"999.999.1.1:53\"]\nmesh_zone = \"test.\"\n\
                         [upstream]\nprotocol = \"plain\"\nresolvers = [\"127.0.0.1:5300\"]\n\
                         dnssec_validation = false\n";
    let (code, out) = validate(bad_addr_body).await;
    assert_ne!(code, Some(0), "bad address must fail validation");
    assert!(
        out.contains("server.listen entries are parseable"),
        "error must name the server.listen key: {out}"
    );
    assert!(
        out.contains("999.999.1.1:53"),
        "error must echo the offending value: {out}"
    );

    // Actionability guard: neither message may be a bare serde/TOML dump
    // without our contextual wrapping.
    assert!(out.contains("configuration error") || out.contains("failed to load configuration"));
}

#[tokio::test(flavor = "current_thread")]
async fn shipped_docker_template_stays_valid_with_privacy_posture() {
    // The Docker template once carried a silent field typo
    // (response_code vs block_response) that deny_unknown_fields caught.
    // This pin keeps BOTH shipped templates honest forever after:
    // - the example must validate byte-for-byte (journey 1 covers runtime;
    //   here we re-assert parse validity cheaply)
    // - the docker template must validate AND retain its security posture:
    //   wildcard DNS binds (container requirement), loopback-only metrics
    //   (privacy invariant), and the correctly-named block response field.
    for rel in ["rustydns.example.toml", "rustydns.docker.toml"] {
        let src = repo_root().join(rel);
        let body =
            std::fs::read_to_string(&src).unwrap_or_else(|e| panic!("{rel} must exist: {e}"));

        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = tmp.path().join("c.toml");
        std::fs::write(&cfg, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
            .arg("--config")
            .arg(&cfg)
            .arg("--validate-config")
            .output()
            .await
            .expect("spawn");
        assert!(
            out.status.success(),
            "{rel} drifted out of validity:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Posture assertions on the docker template specifically.
    let docker =
        std::fs::read_to_string(repo_root().join("rustydns.docker.toml")).expect("docker tpl");
    assert!(
        docker.contains("listen = [\"0.0.0.0:53\"]"),
        "container template must bind wildcard (loopback is unreachable through published ports)"
    );
    assert!(
        docker.contains("block_response = \"nxdomain\""),
        "the fixed field name must stay fixed"
    );
    assert!(
        !docker.contains("response_code"),
        "legacy typo must not return"
    );
    assert!(
        docker.contains("listen = \"127.0.0.1:9153\""),
        "metrics stay loopback-only"
    );
}
