//! Passive subdomain enumeration from keyless public sources.
//!
//! Sources:
//! - **crt.sh** — certificate transparency log search (JSON API).
//! - **hackertarget** — free hostsearch endpoint (DNS history, no key).
//!
//! Both sources aggregate previously observed data; nothing is probed
//! directly on the target infrastructure.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::json;

use crate::http::HttpClient;
use crate::modules::crtsh;
use crate::output::ModuleOutput;

/// Query crt.sh for certificate transparency entries covering `*.<domain>`.
fn from_crtsh(client: &HttpClient, domain: &str) -> Result<Vec<String>> {
    let entries = crtsh::fetch(client, domain)?;

    let mut names = Vec::new();
    for entry in entries {
        // name_value may hold several newline-separated names.
        for name in entry.name_value.lines() {
            let clean = name.trim().trim_start_matches("*.").to_lowercase();
            if clean.ends_with(domain) && !clean.is_empty() {
                names.push(clean);
            }
        }
    }
    Ok(names)
}

/// Query hackertarget's keyless hostsearch endpoint.
fn from_hackertarget(client: &HttpClient, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
    let body = client
        .get_text(&url)
        .with_context(|| format!("hackertarget query failed for {domain}"))?;

    if body.contains("error") && body.lines().count() <= 2 {
        anyhow::bail!("hackertarget returned: {}", body.trim());
    }

    Ok(body
        .lines()
        .filter_map(|line| line.split(',').next())
        .map(|h| h.trim().to_lowercase())
        .filter(|h| h.ends_with(domain) && !h.is_empty())
        .collect())
}

/// Enumerate subdomains for `domain` from all passive sources.
///
/// Source failures are logged as warnings and do not abort the run.
pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut sources_used: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (source, fetch) in [
        (
            "crt.sh",
            from_crtsh as fn(&HttpClient, &str) -> Result<Vec<String>>,
        ),
        ("hackertarget", from_hackertarget),
    ] {
        match fetch(client, domain) {
            Ok(names) => {
                found.extend(names);
                sources_used.push(source.to_string());
            }
            Err(e) => {
                eprintln!("{} source {source} failed: {e:#}", "[warn]".yellow());
                errors.push(format!("{source}: {e:#}"));
            }
        }
    }

    let rows: Vec<Vec<String>> = found.iter().map(|s| vec![s.clone()]).collect();
    let count = found.len();

    ModuleOutput {
        name: "Passive subdomain enumeration",
        json: json!({
            "module": "subdomains",
            "domain": domain,
            "sources": sources_used,
            "count": count,
            "subdomains": found,
            "errors": errors,
        }),
        headers: vec!["Subdomain"],
        rows,
    }
}
