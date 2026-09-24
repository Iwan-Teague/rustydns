//! CLI contract tests.
//!
//! The daemon's argument surface is hand-rolled (no clap), and automation —
//! systemd units, install scripts, CI — depends on its observable behaviour:
//! unknown flags must FAIL LOUDLY rather than be silently ignored (a typo'd
//! flag silently starting against the default config path would be a
//! support nightmare), and the informational flags must exit zero.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_rustydnsd");

fn run(args: &[&str]) -> (std::process::Output, String) {
    let output = Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to execute rustydnsd");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output, format!("{stdout}{stderr}"))
}

#[test]
fn unknown_argument_fails_loudly() {
    let (out, logs) = run(&["--definitely-not-a-flag"]);
    assert!(
        !out.status.success(),
        "an unknown flag must not exit 0 — silent ignore would start the \
         daemon against an unintended configuration"
    );
    assert!(
        logs.contains("unknown argument"),
        "rejection must name the problem: {logs}"
    );
}

#[test]
fn config_without_value_fails_loudly() {
    // `--config` as the last token: the alternative is silently falling back
    // to the default path while the operator believes they passed one.
    let (out, _logs) = run(&["--config"]);
    assert!(
        !out.status.success(),
        "a valueless --config must fail, not fall back to defaults"
    );
}

fn run_combined(args: &[&str]) -> (bool, String) {
    let output = Command::new(BIN).args(args).output().expect("execute");
    let ok = output.status.success();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (ok, combined)
}

#[test]
fn version_flag_exits_zero_and_names_the_binary() {
    let (ok, combined) = run_combined(&["--version"]);
    assert!(ok, "--version must exit 0");
    assert!(
        combined.contains("rustydnsd"),
        "--version must identify the binary: {combined}"
    );
}

#[test]
fn help_flag_exits_zero_and_lists_options() {
    let (ok, combined) = run_combined(&["--help"]);
    assert!(ok, "--help must exit 0");
    for needle in ["--config", "--validate-config", "--print-config"] {
        assert!(
            combined.contains(needle),
            "help must list {needle}: {combined}"
        );
    }
}
