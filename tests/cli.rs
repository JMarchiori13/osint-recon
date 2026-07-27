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
fn subcommand_help_works() {
    let out = bin()
        .args(["full", "--help"])
        .output()
        .expect("run full --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("domain"));
}
