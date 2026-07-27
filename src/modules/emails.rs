//! Passive email address harvesting from a domain's **public** pages.
//!
//! Fetches the homepage and follows a small, bounded set of same-host links
//! (preferring pages such as `contact`/`about`/`team` that typically publish
//! contact details), extracting addresses with a regular expression and from
//! `mailto:` links.
//!
//! Intended for **authorized engagements only**: collected addresses map the
//! organization's public attack surface for phishing simulation planning
//! (MITRE ATT&CK T1593/T1589). Handle results under the engagement's rules
//! of engagement and applicable privacy law (e.g. Brazil's LGPD).

use std::collections::BTreeSet;

use colored::Colorize;
use regex::Regex;
use reqwest::Url;
use serde_json::json;

use crate::http::{extract_links, HttpClient};
use crate::output::ModuleOutput;

/// Maximum number of pages fetched per run (politeness bound).
const MAX_PAGES: usize = 6;

/// Page path fragments most likely to publish contact addresses.
const PRIORITY_HINTS: &[&str] = &[
    "contact", "about", "team", "staff", "contato", "sobre", "equipe",
];

/// Build the email-matching regex (shared with tests).
pub fn email_regex() -> Regex {
    Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").expect("valid regex")
}

/// Extract addresses from HTML text and `mailto:` links.
fn harvest(html: &str) -> BTreeSet<String> {
    let re = email_regex();
    let mut out = BTreeSet::new();
    for m in re.find_iter(html) {
        let addr = m.as_str().to_lowercase();
        // Filter obvious false positives (image/asset filenames).
        if addr.ends_with(".png")
            || addr.ends_with(".jpg")
            || addr.ends_with(".jpeg")
            || addr.ends_with(".gif")
            || addr.ends_with(".webp")
        {
            continue;
        }
        out.insert(addr);
    }
    out
}

/// Harvest email addresses from the public pages of `domain`.
pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput {
    let mut pages_scanned: Vec<String> = Vec::new();
    let mut all_emails: BTreeSet<String> = BTreeSet::new();
    let mut errors: Vec<String> = Vec::new();

    let base = match Url::parse(&format!("https://{domain}/")) {
        Ok(u) => u,
        Err(e) => {
            return ModuleOutput {
                name: "Email harvesting (public pages)",
                json: json!({"module": "emails", "domain": domain, "error": e.to_string()}),
                headers: vec!["Email", "Found on"],
                rows: vec![],
            };
        }
    };

    // 1. Homepage.
    let homepage = match client.get_text(base.as_str()) {
        Ok(body) => {
            pages_scanned.push(base.to_string());
            all_emails.extend(harvest(&body));
            Some(body)
        }
        Err(e) => {
            eprintln!("{} fetching homepage failed: {e:#}", "[warn]".yellow());
            errors.push(format!("homepage: {e:#}"));
            // Try plain HTTP before giving up.
            match client.get_text(&format!("http://{domain}/")) {
                Ok(body) => {
                    pages_scanned.push(format!("http://{domain}/"));
                    all_emails.extend(harvest(&body));
                    Some(body)
                }
                Err(e2) => {
                    eprintln!(
                        "{} fetching http homepage failed: {e2:#}",
                        "[warn]".yellow()
                    );
                    errors.push(format!("http homepage: {e2:#}"));
                    None
                }
            }
        }
    };

    // 2. Follow a bounded set of same-host links, prioritizing contact pages.
    if let Some(html) = homepage {
        let mut links = extract_links(&html, &base);
        links.sort_by_key(|l| {
            let lower = l.to_lowercase();
            if PRIORITY_HINTS.iter().any(|h| lower.contains(h)) {
                0
            } else {
                1
            }
        });

        for link in links.into_iter().take(MAX_PAGES.saturating_sub(1)) {
            match client.get_text(&link) {
                Ok(body) => {
                    pages_scanned.push(link.clone());
                    all_emails.extend(harvest(&body));
                }
                Err(e) => {
                    eprintln!("{} fetching {link} failed: {e:#}", "[warn]".yellow());
                    errors.push(format!("{link}: {e:#}"));
                }
            }
        }
    }

    let rows: Vec<Vec<String>> = all_emails
        .iter()
        .map(|e| vec![e.clone(), domain.to_string()])
        .collect();
    let count = all_emails.len();

    ModuleOutput {
        name: "Email harvesting (public pages)",
        json: json!({
            "module": "emails",
            "domain": domain,
            "note": "Addresses collected from public pages only. For authorized engagements; handle under LGPD/GDPR and the engagement ROE.",
            "pages_scanned": pages_scanned,
            "count": count,
            "emails": all_emails,
            "errors": errors,
        }),
        headers: vec!["Email", "Domain"],
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harvests_emails_and_filters_assets() {
        let html = r#"
            <a href="mailto:contact@example.com">mail</a>
            Reach us at security@example.com or logo@2x.png
        "#;
        let found = harvest(html);
        assert!(found.contains("contact@example.com"));
        assert!(found.contains("security@example.com"));
        assert!(!found.iter().any(|e| e.ends_with(".png")));
    }
}
