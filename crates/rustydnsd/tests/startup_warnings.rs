use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn test_qmin_padding_startup_warnings() {
    let cargo_bin = env!("CARGO_BIN_EXE_rustydnsd");

    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let config_content = r#"
[privacy]
query_minimization = true
upstream_padding = true
"#;
    fs::write(&config_path, config_content).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(cargo_bin)
        .arg("--config")
        .arg(&config_path)
        .arg("--validate-config")
        .output()
        .expect("Failed to execute rustydnsd");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all_logs = format!("{}\n{}", stdout, stderr);

    assert!(
        all_logs
            .contains("privacy.query_minimization is enabled in config but hickory 0.26's stub"),
        "qmin warning missing. Output was:\n{}",
        all_logs
    );

    assert!(
        all_logs
            .contains("privacy.upstream_padding is enabled in config but hickory 0.26 does not"),
        "padding warning missing. Output was:\n{}",
        all_logs
    );
}

/// Run `rustydnsd --validate-config` against the given TOML body and return
/// everything it logged (stdout + stderr).
fn validate_config_logs(config_content: &str) -> String {
    let cargo_bin = env!("CARGO_BIN_EXE_rustydnsd");

    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    fs::write(&config_path, config_content).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(cargo_bin)
        .arg("--config")
        .arg(&config_path)
        .arg("--validate-config")
        .output()
        .expect("Failed to execute rustydnsd");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{}\n{}", stdout, stderr)
}

#[test]
fn plain_upstream_warning_names_the_leak() {
    // AGENTS.md security invariant: opting into a plaintext upstream must
    // emit a warning containing BOTH "UNENCRYPTED" and "leaks" — and it
    // fires on every startup because validate_config runs inside
    // load_config (startup, SIGHUP reload, and --validate-config alike).
    // Pin both mandated words so the wording cannot silently regress into
    // something vaguer.
    let all_logs = validate_config_logs(
        r#"
[upstream]
protocol = "plain"
resolvers = ["127.0.0.1:5353"]
"#,
    );

    assert!(
        all_logs.contains("UNENCRYPTED"),
        "plain-upstream warning must contain 'UNENCRYPTED'. Output was:\n{all_logs}"
    );
    assert!(
        all_logs.contains("leaks"),
        "plain-upstream warning must contain 'leaks' (AGENTS.md invariant). Output was:\n{all_logs}"
    );
}

#[test]
fn query_log_to_disk_opt_in_warns_at_startup() {
    // AGENTS.md privacy invariant: query history may only be written to disk
    // with an explicit opt-in AND a startup warning naming the risk. The
    // opt-in gate is structural (the ring buffer stays in memory unless
    // privacy.query_log_to_disk = true); this pins the warning side of the
    // contract — including its honesty about durability (hashed QNAMEs,
    // anonymised clients, but still a permanent record).
    let all_logs = validate_config_logs(
        r#"
[privacy]
query_log_to_disk = true
query_log_disk_path = "/tmp/rustydns-test-queries.ndjson"
"#,
    );

    assert!(
        all_logs.contains("query_log_to_disk = true") && all_logs.contains("written to disk"),
        "disk-log opt-in must produce the durable-record startup warning. Output was:\n{all_logs}"
    );
}
