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
    let all_logs = format!("{stdout}\n{stderr}");

    assert!(
        all_logs
            .contains("privacy.query_minimization is enabled in config but hickory 0.26's stub"),
        "qmin warning missing. Output was:\n{all_logs}"
    );

    assert!(
        all_logs
            .contains("privacy.upstream_padding is enabled in config but hickory 0.26 does not"),
        "padding warning missing. Output was:\n{all_logs}"
    );
}

/// Run `rustydnsd --validate-config` against the given TOML body and return
/// everything it logged (stdout + stderr).
fn validate_config_logs(config_content: &str) -> String {
    validate_config_full(config_content).0
}

/// Same, but also returns the process exit status.
fn validate_config_full(config_content: &str) -> (String, Option<i32>) {
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
    (format!("{stdout}\n{stderr}"), output.status.code())
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

#[test]
fn invalid_config_fails_validation_with_nonzero_exit() {
    // Operational contract: install/rustydns.service runs `--validate-config`
    // as ExecStartPre so an invalid config can never crash-loop the daemon —
    // that only works if validation FAILS LOUDLY: nonzero exit plus an error
    // naming the offending field. Pins both halves on a hard-violation
    // config (plain-HTTP blocklist source, an AGENTS.md-mandated rejection).
    let (all_logs, code) = validate_config_full(
        r#"
[blocklist]
sources = ["http://insecure.example/list"]
"#,
    );

    assert_ne!(
        code,
        Some(0),
        "an invalid config must exit NONZERO via --validate-config; logs:\n{all_logs}"
    );
    assert!(
        all_logs.contains("insecure.example"),
        "rejection must name the offending source. Output was:\n{all_logs}"
    );
}

#[test]
fn valid_config_succeeds_validation_with_zero_exit() {
    // The positive half of the ExecStartPre contract: a clean config exits 0
    // (the install script and CI treat any nonzero as "config broken").
    let (_logs, code) = validate_config_full(
        r#"
[upstream]
resolvers = ["https://dns.example/dns-query"]
"#,
    );
    assert_eq!(code, Some(0), "a valid config must exit 0");
}

#[test]
fn bare_tld_static_record_fails_validation_with_nonzero_exit() {
    // AQ-178 (r23 F4): the AQ-171 apex bound makes the daemon ABORT at
    // `Authority::new` for a static record whose derived apex is a bare TLD
    // (a 2-label name like `example.com` implies authority over `com.`),
    // but `--validate-config` — the systemd ExecStartPre / install-script /
    // CI gate — used to exit 0 for exactly that config, reintroducing the
    // crash-loop the pre-start check exists to prevent, one layer up.
    // Pins BOTH halves of the contract: nonzero exit AND the same refusal
    // reason the daemon gives at startup ("bare TLD", authority lib.rs
    // `static_zone_apex`).
    let (all_logs, code) = validate_config_full(
        r#"
[authority]
[[authority.static_records]]
name = "example.com"
type = "A"
ttl = 300
address = "192.0.2.1"
"#,
    );

    assert_ne!(
        code,
        Some(0),
        "a config the daemon aborts on at Authority::new must exit NONZERO via \
         --validate-config; logs:\n{all_logs}"
    );
    assert!(
        all_logs.contains("bare TLD"),
        "rejection must carry the same bare-TLD refusal the daemon gives at \
         startup. Output was:\n{all_logs}"
    );
}

#[test]
fn compliant_static_records_still_validate_with_zero_exit() {
    // The over-refusal guard for the gate above: 3-label names are legal
    // under any mesh_zone, and the AQ-171 carve-out (a 2-label name whose
    // derived apex EQUALS the declared mesh_zone) must keep validating too.
    // If the shared authority construction ever over-tightens, this pins it.
    let (all_logs, code) = validate_config_full(
        r#"
[authority]
mesh_zone = "mesh."
[[authority.static_records]]
name = "router.mesh"
type = "A"
ttl = 300
address = "192.0.2.10"
[[authority.static_records]]
name = "host.zone.tld"
type = "A"
ttl = 300
address = "192.0.2.11"
"#,
    );

    assert_eq!(
        code,
        Some(0),
        "legal static records (3-label + mesh_zone carve-out) must still exit 0; \
         logs:\n{all_logs}"
    );
}
