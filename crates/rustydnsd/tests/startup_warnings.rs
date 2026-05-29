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
