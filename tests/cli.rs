//! Integration tests for the osint-recon CLI.
//!
//! These tests are network-free: they verify argument handling, the
//! authorization banner, and graceful failure on invalid targets.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_osint-recon"))
}

#[test]
fn help_lists_all_subcommands() {
    let out = bin().arg("--help").output().expect("run --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["subdomain", "dns", "tech", "email", "metadata", "full"] {
        assert!(stdout.contains(sub), "missing subcommand {sub} in --help");
    }
}

#[test]
fn banner_states_authorized_use() {
    let out = bin()
        .args(["dns", "invalid domain with spaces"])
        .output()
        .expect("run dns");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("For authorized security assessments only."));
}

#[test]
fn rejects_invalid_domain_gracefully() {
    let out = bin()
        .args(["--quiet", "dns", "https://evil.example/path:8080"])
        .output()
        .expect("run dns");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid target"));
}

#[test]
fn stdout_mode_sends_banner_to_stderr() {
    let out = bin()
        .args(["--stdout", "dns", "invalid domain"])
        .output()
        .expect("run dns --stdout");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("For authorized security assessments only."),
        "banner must not pollute stdout in --stdout mode"
    );
    assert!(
        stderr.contains("For authorized security assessments only."),
        "banner should move to stderr in --stdout mode"
    );
}

#[test]
fn stdin_dash_with_empty_input_errors_cleanly() {
    let out = bin()
        .args(["--quiet", "dns", "-"])
        .output() // stdin is null → immediate EOF
        .expect("run dns -");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no targets on stdin"));
}

#[test]
fn subcommand_help_works() {
    let out = bin()
        .args(["full", "--help"])
        .output()
        .expect("run full --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("domain"));
}
