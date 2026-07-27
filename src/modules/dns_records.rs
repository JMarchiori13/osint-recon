//! DNS record lookup via DNS-over-HTTPS (dns.google JSON API).
//!
//! Resolves A, AAAA, MX, NS and TXT records using Google's public DoH
//! resolver — a passive query against a third-party resolver, with no
//! direct contact with the target's authoritative nameservers.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;
use serde_json::json;

use crate::http::HttpClient;
use crate::output::ModuleOutput;

#[derive(Debug, Deserialize)]
struct DohAnswer {
    name: String,
    #[serde(rename = "type")]
    _rtype: u32,
    data: String,
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

const RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "NS", "TXT"];

/// Look up a single record type via dns.google.
fn lookup(client: &HttpClient, domain: &str, rtype: &str) -> Result<Vec<String>> {
    let url = format!("https://dns.google/resolve?name={domain}&type={rtype}");
    let resp: DohResponse = client
        .get_json(&url)
        .with_context(|| format!("DoH lookup failed for {domain} {rtype}"))?;
    Ok(resp
        .answer
        .into_iter()
        .map(|a| format!("{} -> {}", a.name.trim_end_matches('.'), a.data))
        .collect())
}

/// Resolve all supported record types for `domain`.
pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut records = serde_json::Map::new();
    let mut errors: Vec<String> = Vec::new();

    for rtype in RECORD_TYPES {
        match lookup(client, domain, rtype) {
            Ok(values) => {
                for v in &values {
                    rows.push(vec![(*rtype).to_string(), v.clone()]);
                }
                records.insert((*rtype).to_string(), json!(values));
            }
            Err(e) => {
                eprintln!("{} DoH lookup for {rtype} failed: {e:#}", "[warn]".yellow());
                errors.push(format!("{rtype}: {e:#}"));
            }
        }
    }

    ModuleOutput {
        name: "DNS records (DNS-over-HTTPS)",
        json: json!({
            "module": "dns",
            "domain": domain,
            "resolver": "dns.google",
            "records": records,
            "errors": errors,
        }),
        headers: vec!["Type", "Record"],
        rows,
    }
}
