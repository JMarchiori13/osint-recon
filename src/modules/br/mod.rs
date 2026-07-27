//! Brazilian context module (`br`) — public business/infrastructure data.
//!
//! **Scope & LGPD (Lei 13.709/2018):** this module handles *company* and
//! *address* data only. CNPJ records are public business data published by
//! Receita Federal; CEP data is public addressing information. It
//! deliberately does **not** handle personal data (CPF) — personal-data
//! harvesting is out of scope for the whole framework.
//!
//! Not wired into `full`: `br` targets are documents/CEPs, not domains, so
//! it stays a standalone context module (see docs/modules.md).

pub mod cep;
pub mod cnpj;
pub mod dorks;

use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

use crate::http::HttpClient;

/// Fetch JSON with explicit status handling (404/429 → clear errors).
fn fetch_json<T: DeserializeOwned>(client: &HttpClient, url: &str) -> Result<T> {
    let resp = client.get(url)?;
    let status = resp.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        anyhow::bail!("rate limited by source ({status})");
    }
    if status == StatusCode::NOT_FOUND {
        anyhow::bail!("not found at source ({status})");
    }
    if !status.is_success() {
        anyhow::bail!("source returned {status}");
    }
    resp.json::<T>()
        .with_context(|| format!("parsing JSON from {url}"))
}
