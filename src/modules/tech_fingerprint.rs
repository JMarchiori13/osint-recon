//! Passive technology fingerprinting.
//!
//! Fetches the target's public homepage (a single plain GET, like any
//! browser) and fingerprints the stack from:
//! - HTTP response headers (`Server`, `X-Powered-By`, `Via`, ...).
//! - HTML `<meta name="generator">` tags.
//! - CMS / framework signatures in the markup (WordPress, Drupal, React, ...).
//!
//! No scanning, no probing of non-standard paths.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use colored::Colorize;
use regex::Regex;
use serde_json::json;

use crate::http::HttpClient;
use crate::output::ModuleOutput;

/// Interesting response headers for fingerprinting.
const INTERESTING_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-generator",
    "x-aspnet-version",
    "x-drupal-cache",
    "x-wordpress-cache",
    "via",
    "cf-ray",
    "x-vercel-id",
    "x-amz-cf-id",
];

/// HTML/body signatures: (label, pattern).
const BODY_SIGNATURES: &[(&str, &str)] = &[
    ("WordPress", r"(?i)wp-content|wp-includes"),
    ("Joomla", r#"(?i)/media/jui/|content=["']Joomla!"#),
    ("Drupal", r"(?i)Drupal\.settings|/sites/default/files"),
    ("Shopify", r"(?i)cdn\.shopify\.com|Shopify\.theme"),
    ("Wix", r"(?i)wixstatic\.com|X-Wix-"),
    ("Squarespace", r"(?i)squarespace\.com|static1\.squarespace"),
    ("React", r"(?i)data-reactroot|__REACT_DEVTOOLS|react-dom"),
    ("Next.js", r"(?i)__NEXT_DATA__|/_next/static"),
    ("Vue.js", r"(?i)vue(?:\.min)?\.js|data-v-[0-9a-f]{8}"),
    ("Angular", r"(?i)ng-app|ng-version|angular(?:\.min)?\.js"),
    ("jQuery", r"(?i)jquery[-.][0-9]"),
    ("Bootstrap", r"(?i)bootstrap(?:\.min)?\.(?:css|js)"),
    ("Cloudflare", r"(?i)cloudflare"),
];

/// Extract the `<meta name="generator" content="...">` tag, if present.
fn meta_generator(html: &str) -> Option<String> {
    let re = Regex::new(r#"(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']"#)
        .expect("valid regex");
    re.captures(html).map(|c| c[1].to_string())
}

/// Try HTTPS first, fall back to HTTP.
fn fetch_homepage(
    client: &HttpClient,
    domain: &str,
) -> Result<(String, reqwest::header::HeaderMap, String)> {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{domain}/");
        match client.get(&url) {
            Ok(resp) => {
                let final_url = resp.url().to_string();
                let headers = resp.headers().clone();
                let body = resp
                    .text()
                    .with_context(|| format!("reading body of {url}"))?;
                return Ok((final_url, headers, body));
            }
            Err(e) => {
                eprintln!(
                    "{} {scheme}://{domain} unreachable: {e:#}",
                    "[warn]".yellow()
                );
            }
        }
    }
    anyhow::bail!("could not fetch homepage for {domain} over HTTPS or HTTP")
}

/// Fingerprint the technology stack of `domain`.
pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput {
    let (final_url, headers, body) = match fetch_homepage(client, domain) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {e:#}", "[warn]".yellow());
            return ModuleOutput {
                name: "Technology fingerprinting",
                json: json!({
                    "module": "tech",
                    "domain": domain,
                    "error": format!("{e:#}"),
                }),
                headers: vec!["Source", "Evidence", "Technology"],
                rows: vec![],
            };
        }
    };

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut technologies: Vec<String> = Vec::new();
    let mut interesting: BTreeMap<String, String> = BTreeMap::new();

    // 1. Response headers.
    for name in INTERESTING_HEADERS {
        if let Some(value) = headers.get(*name) {
            let v = value.to_str().unwrap_or("<binary>").to_string();
            interesting.insert((*name).to_string(), v.clone());
            rows.push(vec!["header".to_string(), (*name).to_string(), v]);
        }
    }

    // 2. Meta generator.
    if let Some(gen) = meta_generator(&body) {
        technologies.push(gen.clone());
        rows.push(vec![
            "meta generator".to_string(),
            "generator".to_string(),
            gen,
        ]);
    }

    // 3. Body signatures.
    for (label, pattern) in BODY_SIGNATURES {
        let re = Regex::new(pattern).expect("valid regex");
        let evidence = if *label == "Cloudflare" {
            // Server/cf-ray header is stronger evidence than body mentions.
            headers
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        };
        let matched = if *label == "Cloudflare" {
            headers
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_lowercase().contains("cloudflare"))
                .unwrap_or(false)
                || headers.contains_key("cf-ray")
        } else {
            re.is_match(&body)
        };
        if matched {
            technologies.push((*label).to_string());
            rows.push(vec![
                "signature".to_string(),
                evidence.unwrap_or_else(|| "html body".to_string()),
                (*label).to_string(),
            ]);
        }
    }

    technologies.sort();
    technologies.dedup();

    ModuleOutput {
        name: "Technology fingerprinting",
        json: json!({
            "module": "tech",
            "domain": domain,
            "url": final_url,
            "headers": interesting,
            "technologies": technologies,
        }),
        headers: vec!["Source", "Evidence", "Technology"],
        rows,
    }
}
