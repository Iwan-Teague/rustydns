//! `--print-config` redaction contract.
//!
//! Upstream resolver URLs and blocklist sources may embed credentials
//! (`https://user:pass@host/…` userinfo, `?token=…` query parameters — common
//! with commercial DoH providers and token-gated blocklist CDNs). The dump
//! goes to stdout, where it lands in terminals, CI logs and shell history.
//! `DnsConfig::redacted_for_display` must scrub those components while
//! keeping the rest of the config legible.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn print_config_stdout(config_content: &str) -> String {
    let cargo_bin = env!("CARGO_BIN_EXE_rustydnsd");

    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    fs::write(&config_path, config_content).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(cargo_bin)
        .arg("--config")
        .arg(&config_path)
        .arg("--print-config")
        .output()
        .expect("Failed to execute rustydnsd");
    assert!(
        output.status.success(),
        "--print-config must succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn print_config_redacts_group_source_tokens() {
    // Per-client blocklist groups are the most likely home for token-gated
    // feeds; their sources must be redacted in dumps exactly like the
    // global ones.
    let out = print_config_stdout(
        r#"
[[blocklist.groups]]
name = "kids"
sources = ["https://kids.example/feed?token=k1dsfeed"]
"#,
    );
    assert!(
        !out.contains("k1dsfeed"),
        "group source token leaked via --print-config:\n{out}"
    );
    assert!(
        out.contains("token=<redacted>"),
        "redaction placeholder missing:\n{out}"
    );
}

#[test]
fn print_config_never_leaks_url_credentials() {
    let out = print_config_stdout(
        r#"
[upstream]
protocol = "plain"
resolvers = ["127.0.0.1:5353"]
"#,
    );
    // Sanity: the dump is a full TOML render.
    assert!(out.contains("[upstream]"), "dump was: {out}");
}

#[test]
fn print_config_redacts_embedded_userinfo_and_tokens() {
    let out = print_config_stdout(
        r#"
[upstream]
resolvers = ["https://alice:hunter2@dns.example/dns-query"]

[blocklist]
sources = ["https://lists.example/list?token=t0ps3cret&format=hosts"]
"#,
    );

    assert!(
        !out.contains("hunter2"),
        "userinfo password leaked via --print-config:\n{out}"
    );
    assert!(
        !out.contains("alice@"),
        "userinfo username leaked via --print-config:\n{out}"
    );
    assert!(
        !out.contains("t0ps3cret"),
        "blocklist token leaked via --print-config:\n{out}"
    );
    assert!(
        out.contains("<redacted>"),
        "redaction placeholder must be visible so the operator knows what was hidden:\n{out}"
    );

    // Non-credential parts stay legible for debugging.
    assert!(out.contains("dns.example"), "host must survive:\n{out}");
    assert!(
        out.contains("format=hosts"),
        "non-credential query parameters must survive:\n{out}"
    );
}
