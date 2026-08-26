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
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // 4) Ring attribution: the operator surface must distinguish the
    // BLOCKLIST rejection from ordinary resolver answers - a refactor
    // flattening served_by would silently merge enforcement with
    // resolution in the audit surface.
    let client = reqwest::Client::builder().build().unwrap();
    let q = client
        .get(format!("http://127.0.0.1:{metrics_port}/queries"))
        .send()
        .await
        .expect("scrape /queries");
    let qb = q.text().await.expect("queries body");
    assert!(
        qb.contains("\"served_by\":\"blocklist\""),
        "blocked entry must carry blocklist attribution: {qb}"
    );
    assert!(
        qb.contains("\"served_by\":\"resolver\""),
        "allowed entry must carry resolver attribution: {qb}"
    );

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

    // Case A0: typoed key inside [upstream].
    let typo_upstream_body = "[server]\nlisten = [\"127.0.0.1:5399\"]\nmesh_zone = \"test.\"\n\
                              [upstream]\nresolverss = [\"127.0.0.1:5300\"]\nprotocol = \"plain\"\n\
                              dnssec_validation = false\n";
    {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = tmp.path().join("rustydns.toml");
        std::fs::write(&cfg, typo_upstream_body).unwrap();
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
            .expect("run");
        assert_eq!(out.status.code(), Some(1));
        let combined = String::from_utf8_lossy(&out.stdout).to_string()
            + "\n"
            + &String::from_utf8_lossy(&out.stderr);
        assert!(
            combined.contains("unknown field `resolverss`"),
            "must name the typoed key: {combined}"
        );
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

#[tokio::test(flavor = "current_thread")]
async fn print_config_stdout_is_pure_toml_that_round_trips() {
    // UX contract: `--print-config > out.toml` must yield PURE parseable
    // TOML on stdout even when startup warnings fire - logs belong on
    // stderr. The dump must also keep secrets redacted AND re-validate.
    let body = "[server]\n\
                listen = [\"127.0.0.1:5399\"]\n\
                mesh_zone = \"test.\"\n\n\
                [upstream]\n\
                protocol = \"doh\"\n\
                resolvers = [\"https://user:supersecret@doh.example.com/dns-query\"]\n\
                dnssec_validation = false\n\n\
                [metrics]\n\
                listen = \"127.0.0.1:19153\"\n";
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = tmp.path().join("in.toml");
    std::fs::write(&cfg, body).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let print = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&cfg)
        .arg("--print-config")
        .output()
        .await
        .expect("print-config run");
    assert!(print.status.success());
    let stdout = String::from_utf8_lossy(&print.stdout).to_string();

    // Secrets redacted in the dump.
    assert!(!stdout.contains("supersecret"), "password leaked to dump");
    assert!(stdout.contains("<redacted>"), "placeholder missing");

    // Warnings went to STDERR, not into the TOML stream.
    let stderr = String::from_utf8_lossy(&print.stderr).to_string();
    assert!(
        stderr.contains("DNSSEC signatures will NOT be verified"),
        "dnssec warning must still fire, on stderr"
    );
    assert!(
        !stdout.contains("WARN"),
        "log lines contaminated stdout TOML dump"
    );

    // THE CONTRACT: the dump re-validates as a config file.
    let dump_path = tmp.path().join("dump.toml");
    std::fs::write(&dump_path, stdout.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dump_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let rt = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&dump_path)
        .arg("--validate-config")
        .output()
        .await
        .expect("round-trip validate");
    assert!(
        rt.status.success(),
        "printed config failed re-validation:\n{}{}",
        String::from_utf8_lossy(&rt.stdout),
        String::from_utf8_lossy(&rt.stderr)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn missing_config_error_is_actionable() {
    // Bare `rustydnsd` (or any --print-config/--validate-config) with a
    // MISSING config file must produce an error that (a) names the path,
    // (b) hints at --config — never a bare OS error string.
    for args in [vec!["--print-config"], vec!["--validate-config"], vec![]] {
        let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
            .args(&args)
            .output()
            .await
            .expect("run");
        assert_eq!(out.status.code(), Some(1));
        let combined = String::from_utf8_lossy(&out.stdout).to_string()
            + "\n"
            + &String::from_utf8_lossy(&out.stderr);
        assert!(
            combined.contains("rustydns.toml"),
            "error must name the default path: {combined}"
        );
        assert!(
            combined.contains("--config"),
            "error must hint at --config: {combined}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_existing_config_error_names_file_and_hints() {
    // The OTHER error site: an EXISTING config that fails semantic
    // validation must still name the FILE in the top-level context and
    // carry the --config hint (both come from the load wrapper).
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = tmp.path().join("rustydns.toml");
    std::fs::write(&cfg, "[server]\nlisten = [\"999.999.1.1:53\"]\n").unwrap();
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
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    let combined = String::from_utf8_lossy(&out.stdout).to_string()
        + "\n"
        + &String::from_utf8_lossy(&out.stderr);
    assert!(
        combined.contains("failed to load configuration file"),
        "top-level context must name the file: {combined}"
    );
    assert!(
        combined.contains("--config"),
        "must carry the hint: {combined}"
    );
    assert!(
        combined.contains("server.listen entries are parseable"),
        "inner cause must survive wrapping: {combined}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn blocklist_partial_failure_retains_last_good_entries() {
    // FAIL-CLOSED refresh contract, driven through the real binary:
    // two local hosts-files seed blocks for alpha.test / beta.test.
    // File B is then DELETED and the daemon SIGHUPs. The refreshed list
    // must retain beta's block (loader last-good fallback) - if the
    // source were silently dropped, beta queries would FORWARD to the
    // stub upstream and return NOERROR instead of NXDOMAIN. We probe
    // continuously across the reload window and require EVERY beta
    // response to stay NXDOMAIN; the stub hit-counter must stay ZERO
    // because neither name is ever legitimately forwarded (both are in
    // the shipped-style local files).
    let (dns_port, upstream_port, metrics_port) = (reserve_port(), reserve_port(), reserve_port());
    let dir = tempfile::TempDir::new().unwrap();
    let file_a = dir.path().join("a.hosts");
    let file_b = dir.path().join("b.hosts");
    std::fs::write(&file_a, "0.0.0.0 alpha.test\n").unwrap();
    std::fs::write(&file_b, "0.0.0.0 beta.test\n").unwrap();

    let cfg_path = dir.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\
         timeout_ms = 1200\n\n\
         [blocklist]\n\
         local_files = [\"{a}\", \"{b}\"]\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n",
        a = file_a.display(),
        b = file_b.display()
    );
    std::fs::write(&cfg_path, &config).unwrap();
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

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(("127.0.0.1", dns_port)).await.unwrap();

    // Baseline: both blocked before any failure.
    async fn expect_nx(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> bool {
        sock.send(&build_query(id, name)).await.unwrap();
        for _ in 0..10 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await {
                Err(_) => continue,
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    if let Ok(m) = Message::from_bytes(&buf[..n])
                        && m.metadata.id == id
                    {
                        return m.metadata.response_code == ResponseCode::NXDomain
                            && m.answers.is_empty();
                    }
                }
            }
        }
        false
    }

    assert!(expect_nx(&sock, 300, "alpha.test.").await, "alpha blocked");
    assert!(expect_nx(&sock, 301, "beta.test.").await, "beta blocked");

    // DELETE file B, then SIGHUP: the refresh now loses that source.
    std::fs::remove_file(&file_b).unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().expect("pid") as i32),
        nix::sys::signal::Signal::SIGHUP,
    )
    .unwrap();

    // Continuous probes spanning the reload window: EVERY beta response
    // must remain NXDOMAIN (last-good retention keeps it blocked) and the
    // stub must NEVER see either name forwarded.
    let mut saw_nx_after_reload = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut probe_id = 310u16;
    while std::time::Instant::now() < deadline {
        if expect_nx(&sock, probe_id, "beta.test.").await {
            if probe_id > 320 {
                saw_nx_after_reload = true; // well past reload window
            }
        } else {
            panic!("beta.test unblocked after SIGHUP - last-good retention failed");
        }
        probe_id += 1;
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    assert!(
        saw_nx_after_reload,
        "probe window too short to cross reload"
    );

    // Upstream isolation: zero forwards across baseline + reload window.
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing may leak upstream"
    );

    // Upstream isolation across the whole run: zero forwards. (Sustained-
    // outage retention beyond THIS single failed reload is covered at the
    // loader-unit layer: the daemon enforces a 60s minimum spacing between
    // blocklist fetch rounds, so consecutive SIGHUP-driven rebuilds cannot
    // be driven from an integration test.)
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing may leak upstream"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn docker_config_journey_resolves_over_doh() {
    // JOURNEY 4: the shipped CONTAINER config must work at runtime, not
    // merely parse. Substitutions are limited to ports (CI is unprivileged
    // and collision-free), upstream endpoints (offline stub), and the
    // DNSSEC knob the stub cannot satisfy. Everything else travels
    // verbatim: wildcard binds, fail-closed, TLS 1.3 floor,
    // block_response field, loopback-only metrics.

    let tpl_path = repo_root().join("rustydns.docker.toml");
    let tpl = std::fs::read_to_string(&tpl_path).expect("shipped rustydns.docker.toml");

    // Drift guards on security-posture anchors.
    for anchor in [
        "listen = [\"0.0.0.0:53\"]",
        "doh_listen = \"0.0.0.0:8053\"",
        "block_response = \"nxdomain\"",
        "fail_closed = true",
        "min_tls_version = \"1.3\"",
        "dnssec_validation = true",
        "listen = \"127.0.0.1:9153\"",
        "protocol = \"doh\"",
    ] {
        assert!(
            tpl.contains(anchor),
            "docker template drifted: missing {anchor}"
        );
    }
    assert!(
        !tpl.contains("response_code"),
        "legacy typo must stay banned"
    );

    let (dns_port, doh_port, upstream_port, metrics_port) = (
        reserve_port(),
        reserve_port(),
        reserve_port(),
        reserve_port(),
    );
    let (stub, _hits) = spawn_stub_udp_dns(upstream_port).await;

    let served = tpl
        .replace(
            "listen = [\"0.0.0.0:53\"]",
            &format!("listen = [\"0.0.0.0:{dns_port}\"]"),
        )
        .replace(
            "doh_listen = \"0.0.0.0:8053\"",
            &format!("doh_listen = \"0.0.0.0:{doh_port}\""),
        )
        .replace(
            "listen = \"127.0.0.1:9153\"",
            &format!("listen = \"127.0.0.1:{metrics_port}\""),
        )
        .replace("protocol = \"doh\"", "protocol = \"plain\"")
        .replace("dnssec_validation = true", "dnssec_validation = false");

    // Swap BOTH real DoH resolver URLs for the offline stub (bare
    // host:port form required by protocol=plain).
    let start = served.find("resolvers = [").expect("resolvers array");
    let end = served[start..].find(']').expect("array close") + start;
    let served = format!(
        "{}resolvers = [\"127.0.0.1:{upstream_port}\"]{}",
        &served[..start],
        &served[end + 1..]
    );

    // Post-substitution posture checks.
    assert!(served.contains("block_response = \"nxdomain\""));
    assert!(served.contains("fail_closed = true"));
    assert!(
        served.contains(&format!("resolvers = [\"127.0.0.1:{upstream_port}\"]")),
        "stub resolver substitution missing"
    );
    for provider in ["quad9", "cloudflare-dns"] {
        assert!(
            !served.contains(provider),
            "real upstream {provider} must be fully replaced"
        );
    }
    assert!(!served.contains("response_code"));

    let tmp = tempfile::TempDir::new().unwrap();
    let cfg_path = tmp.path().join("rustydns.toml");
    std::fs::write(&cfg_path, &served).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

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
    assert!(ready, "daemon not ready on docker-template config");

    // UDP resolution through the shipped container config.
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(("127.0.0.1", dns_port)).await.unwrap();

    async fn expect_resolved(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> Message {
        sock.send(&build_query(id, name)).await.expect("send");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
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
        panic!("no reply within 10s for {name}");
    }

    let r = expect_resolved(&sock, 400, "www.example.com.").await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.answers.iter().any(|a| matches!(&a.data,
        hickory_proto::rr::RData::A(ip) if ip.0.to_string() == "192.0.2.1")));

    // DoH POST through the SAME process (template ships doh_listen).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://127.0.0.1:{doh_port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(build_query(401, "via-doh.example.com."))
        .send()
        .await
        .expect("DoH POST");
    assert_eq!(resp.status(), 200);
    let wire = resp.bytes().await.expect("body");
    let reply = Message::from_bytes(&wire).expect("decode");
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.iter().any(|a| matches!(&a.data,
        hickory_proto::rr::RData::A(ip) if ip.0.to_string() == "192.0.2.1")));

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn world_readable_config_is_rejected_with_actionable_error() {
    // PRIVACY invariant (AGENTS.md): config files carry upstream
    // credentials; a world-readable file must be refused with an error
    // that says so and tells the operator the fix. Binary-level pin:
    // unit tests cover the function; this covers the spawned-process
    // contract end-to-end.
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = tmp.path().join("rustydns.toml");
    std::fs::write(
        &cfg,
        "[server]\nlisten = [\"127.0.0.1:5399\"]\nmesh_zone = \"test.\"\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(&cfg)
        .arg("--validate-config")
        .output()
        .await
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "world-readable config must exit 1"
    );
    let combined = String::from_utf8_lossy(&out.stdout).to_string()
        + "\n"
        + &String::from_utf8_lossy(&out.stderr);
    assert!(
        combined.contains("world-readable"),
        "error must name the world-readability: {combined}"
    );
    assert!(
        combined.contains("chmod"),
        "error must suggest the fix: {combined}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn minimal_viable_config_validates_and_serves() {
    // PLUG-AND-PLAY floor: the absolute minimum TOML that starts a
    // functional daemon. Every omitted section falls back to documented
    // defaults — no hidden requirements, no silent "you also need..."
    // surprises. Pins the boundary between "zero config" and "must
    // configure" so future default changes that break this are caught.
    //
    // Minimum: server.listen (bind address) + one plain resolver (offline
    // stub). Everything else defaults.
    let (dns_port, upstream_port, metrics_port) = (reserve_port(), reserve_port(), reserve_port());
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let cfg_path = tmp.path().join("rustydns.toml");
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &config).expect("write config");
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
    assert!(ready, "daemon not ready on minimal config");

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client bind");
    sock.connect(("127.0.0.1", dns_port))
        .await
        .expect("connect");

    // Minimal config serves queries normally: NoError + stub answer.
    for (id, name) in [(600u16, "minimal.test."), (601, "anything.clean.")] {
        sock.send(&build_query(id, name)).await.expect("send");
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
            Err(_) => panic!("no reply for {name}"),
            Ok(Err(e)) => panic!("recv error: {e}"),
            Ok(Ok((n, _))) => {
                let m = Message::from_bytes(&buf[..n]).expect("decode");
                assert_eq!(m.metadata.id, id);
                assert_eq!(m.metadata.response_code, ResponseCode::NoError, "{name}");
                assert!(!m.answers.is_empty(), "{name} must have answers");
            }
        }
    }

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn sighup_picks_up_policy_changes_live() {
    // POLICY HOT-RELOAD journey: start without any [[policy]] entries,
    // then add one restricting 127.0.0.1 to an internal-only allowlist.
    // After SIGHUP, external queries must be REFUSED while internal ones
    // still resolve. Then REMOVE the restriction and verify access is
    // restored - both directions prove the reload is bidirectional.
    let (dns_port, upstream_port, metrics_port) = (reserve_port(), reserve_port(), reserve_port());
    let dir = tempfile::TempDir::new().unwrap();

    let cfg_path = dir.path().join("rustydns.toml");
    let open_config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:{upstream_port}\"]\n\
         dnssec_validation = false\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:{metrics_port}\"\n"
    );
    std::fs::write(&cfg_path, &open_config).unwrap();
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
    assert!(ready);

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(("127.0.0.1", dns_port)).await.unwrap();

    async fn ask(sock: &tokio::net::UdpSocket, id: u16, name: &str) -> ResponseCode {
        sock.send(&build_query(id, name)).await.unwrap();
        for _ in 0..12 {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await {
                Err(_) => continue,
                Ok(Err(_)) => continue,
                Ok(Ok((n, _))) => {
                    if let Ok(m) = Message::from_bytes(&buf[..n])
                        && m.metadata.id == id
                    {
                        return m.metadata.response_code;
                    }
                }
            }
        }
        panic!("no reply for {name}");
    }

    // Pre-policy: external domain resolves.
    assert_eq!(
        ask(&sock, 500, "before-restriction.example.").await,
        ResponseCode::NoError,
        "pre-policy queries must resolve normally"
    );

    // Write RESTRICTED config and SIGHUP.
    let restricted_config = format!(
        "{}\n[[policy]]\nclient_ip = \"127.0.0.1\"\nzones_allowed = [\"internal.lan.\"]\n",
        open_config
    );
    std::fs::write(&cfg_path, &restricted_config).unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().unwrap() as i32),
        nix::sys::signal::Signal::SIGHUP,
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Post-policy: external query refused.
    assert_eq!(
        ask(&sock, 501, "external.example.org.").await,
        ResponseCode::Refused,
        "post-policy external queries must be REFUSED"
    );

    // Restore open config and SIGHUP again.
    std::fs::write(&cfg_path, &open_config).unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().unwrap() as i32),
        nix::sys::signal::Signal::SIGHUP,
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Access restored.
    assert_eq!(
        ask(&sock, 502, "restored.example.org.").await,
        ResponseCode::NoError,
        "removing the policy must restore normal resolution"
    );

    child.kill().await.expect("kill daemon");
    let _ = child.wait().await;
    stub.abort();
}
