//! Composes the service's version, `vX.Y.Z(B)-commit`: the package version, the
//! build number (`RUNNER_BUILD_NUMBER`, which Actions sets to its run number;
//! 0 for a local build) and the first six characters of the commit it was
//! built from (`RUNNER_COMMIT`, else the checkout's HEAD).

use std::{path::Path, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=RUNNER_BUILD_NUMBER");
    println!("cargo:rerun-if-env-changed=RUNNER_COMMIT");
    for path in [".git/HEAD", ".git/refs/heads"] {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let build = std::env::var("RUNNER_BUILD_NUMBER")
        .ok()
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or_else(|| "0".into());
    let commit = std::env::var("RUNNER_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(head)
        .map(|c| c.chars().take(6).collect::<String>())
        .filter(|c| c.len() == 6 && c.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| "000000".into());
    let version = env!("CARGO_PKG_VERSION");
    println!("cargo:rustc-env=RUNNER_SERVER_VERSION=v{version}({build})-{commit}");
}

fn head() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}
