//! Shared helper for querying the crt.sh certificate transparency JSON API.
//!
//! crt.sh aggregates publicly logged certificates; querying it is a passive
//! technique (MITRE ATT&CK T1596.003 — Search Open Technical Databases:
//! Digital Certificates). crt.sh rate-limits aggressively, so all callers
//! share the throttled [`HttpClient`] with retries and graceful failure.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::http::HttpClient;

/// A single crt.sh log entry (only the fields we consume).
#[derive(Debug, Deserialize)]
pub struct CrtShEntry {
    /// Newline-separated subject alternative names.
    pub name_value: String,
    /// Issuer distinguished name, e.g. `C=US, O=Let's Encrypt, CN=R11`.
    #[serde(default)]
    pub issuer_name: String,
    /// Certificate validity start, ISO-like (`2025-01-31T00:00:00`).
    #[serde(default)]
    pub not_before: String,
    /// Certificate validity end.
    #[serde(default)]
    pub not_after: String,
}

/// Fetch all CT log entries covering `*.<domain>` from crt.sh.
pub fn fetch(client: &HttpClient, domain: &str) -> Result<Vec<CrtShEntry>> {
    let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    client
        .get_json(&url)
        .with_context(|| format!("crt.sh query failed for {domain}"))
}
