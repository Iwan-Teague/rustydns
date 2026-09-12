//! Binary-level pin of the DoH bind gate (D2/F1): a non-loopback
//! `doh_listen` without TLS material must be refused by BOTH
//! `--validate-config` (exit != 0, so systemd `ExecStartPre` / compose
//! pre-upgrade checks stop the upgrade) AND a real daemon start (exit != 0,
//! nothing ever bound) — a startup-only refusal would crash-loop under
//! `restart: unless-stopped` with zero validation feedback. Fully offline.
#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

/// Reserve an ephemeral TCP port by bind-then-drop. Small TOCTOU window,
/// acceptable for a loopback CI test.
fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("port")
        .port()
}

/// Write a config that binds DoH on `doh_listen` with no TLS material.
/// Everything else is the minimal valid shape the e2e suite uses (plain
/// upstream is warn-only, never a validation error).
fn write_config(dir: &std::path::Path, dns_port: u16, doh_listen: &str) -> std::path::PathBuf {
    let config = format!(
        "[server]\n\
         listen = [\"127.0.0.1:{dns_port}\"]\n\
         mesh_zone = \"test.\"\n\
         doh_listen = \"{doh_listen}\"\n\n\
         [upstream]\n\
         protocol = \"plain\"\n\
         resolvers = [\"127.0.0.1:5399\"]\n\
         dnssec_validation = false\n\
         timeout_ms = 1500\n\n\
         [metrics]\n\
         listen = \"127.0.0.1:0\"\n"
    );
    let cfg_path = dir.join("rustydns.toml");
    std::fs::write(&cfg_path, config).expect("write config");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod config");
    cfg_path
}

/// Run the real binary with `extra_args` on `cfg_path`; return (exit code,
/// stderr). Assumes the daemon exits on its own (config refusal) and bounds
/// the wait so a regression that DOES start still fails the test loudly.
async fn run_daemon(cfg_path: &std::path::Path, extra_args: &[&str]) -> (Option<i32>, String) {
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustydnsd"))
        .arg("--config")
        .arg(cfg_path)
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn rustydnsd");

    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("daemon must exit on its own (config refusal), not run")
        .expect("wait rustydnsd");

    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Prove nothing is listening on `port`: connects to 127.0.0.1 must be
/// refused. The refusal exits BEFORE any bind, so a bound socket here would
/// mean the gate never ran.
async fn assert_nothing_bound(port: u16) {
    for attempt in 0..5 {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(_) => panic!(
                "port {port} must have nothing bound after the DoH refusal (attempt {attempt})"
            ),
            Err(e) => {
                // ConnectionRefused is the expected "no listener" verdict;
                // any other error is retried briefly (port racing garbage).
                assert!(
                    e.kind() == std::io::ErrorKind::ConnectionRefused,
                    "unexpected probe error on {port}: {e}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn validate_config_refuses_public_doh_without_tls() {
    let dns_port = reserve_port();
    let doh_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_config(tmp.path(), dns_port, &format!("0.0.0.0:{doh_port}"));

    let (code, stderr) = run_daemon(&cfg_path, &["--validate-config"]).await;

    assert_ne!(
        code,
        Some(0),
        "--validate-config must fail for a non-loopback doh_listen without TLS \
         (ExecStartPre / compose upgrade gate); stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("refusing"),
        "stderr must carry the refusal wording: {stderr}"
    );
    assert!(
        stderr.contains("not a loopback"),
        "stderr must state the rule: {stderr}"
    );
    assert!(
        stderr.contains("plaintext"),
        "stderr must make the plaintext-DoH reality explicit: {stderr}"
    );

    assert_nothing_bound(doh_port).await;
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_refuses_public_doh_without_tls_and_binds_nothing() {
    let dns_port = reserve_port();
    let doh_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // The wildcard form is the upgrade-crash-loop shape: it parses, it is a
    // real address, and without this gate the daemon would die at bind time
    // with only restart-looping as feedback.
    let cfg_path = write_config(tmp.path(), dns_port, &format!("0.0.0.0:{doh_port}"));

    let (code, stderr) = run_daemon(&cfg_path, &[]).await;

    assert_ne!(
        code,
        Some(0),
        "daemon must exit non-zero; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("refusing"),
        "stderr must carry the refusal wording: {stderr}"
    );
    assert!(
        stderr.contains("plaintext"),
        "stderr must say the DoH port is plaintext: {stderr}"
    );

    assert_nothing_bound(doh_port).await;
}

#[tokio::test(flavor = "current_thread")]
async fn validate_config_still_accepts_loopback_doh() {
    // Control leg: the default loopback shape keeps validating cleanly, so
    // the refusal is scoped to non-loopback binds only.
    let dns_port = reserve_port();
    let doh_port = reserve_port();
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg_path = write_config(tmp.path(), dns_port, &format!("127.0.0.1:{doh_port}"));

    let (code, stderr) = run_daemon(&cfg_path, &["--validate-config"]).await;

    assert_eq!(
        code,
        Some(0),
        "--validate-config must accept loopback doh_listen; stderr:\n{stderr}"
    );
}
