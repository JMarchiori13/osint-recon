//! Document metadata extraction from publicly linked PDFs.
//!
//! Finds PDF links on the target's public pages (homepage + a bounded set of
//! same-host links), downloads a small number of documents and extracts the
//! embedded metadata (Author, Creator, Producer, creation/modification
//! dates) from the PDF Info dictionary.
//!
//! Metadata frequently leaks usernames, internal naming conventions and the
//! exact software versions used to produce documents — classic material for
//! MITRE ATT&CK T1593 (Search Open Websites/Domains). Only documents the
//! site itself links publicly are retrieved.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use colored::Colorize;
use lopdf::{Document, Object};
use reqwest::Url;
use serde_json::json;

use crate::http::{extract_links, HttpClient};
use crate::output::ModuleOutput;

/// Maximum number of PDFs downloaded per run (politeness bound).
const MAX_PDFS: usize = 3;
/// Maximum accepted PDF size (10 MiB) — skip larger files gracefully.
const MAX_PDF_BYTES: usize = 10 * 1024 * 1024;
/// Maximum pages crawled while looking for PDF links.
const MAX_PAGES: usize = 4;

/// Extract printable strings from a PDF Info-dictionary value.
fn object_to_string(obj: &Object) -> Option<String> {
    match obj {
        Object::String(bytes, _) => {
            let s = String::from_utf8_lossy(bytes).to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        Object::Name(name) => Some(String::from_utf8_lossy(name).to_string()),
        _ => None,
    }
}

/// Parse a PDF from memory and return its Info-dictionary entries.
fn pdf_metadata(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let doc = Document::load_mem(bytes).context("parsing PDF")?;
    let mut meta = BTreeMap::new();

    if let Ok(info_ref) = doc.trailer.get(b"Info") {
        if let Ok((_, info_obj)) = doc.dereference(info_ref) {
            if let Ok(dict) = info_obj.as_dict() {
                for (key, value) in dict.iter() {
                    let name = String::from_utf8_lossy(key).to_string();
                    let resolved = match value {
                        Object::Reference(_) => {
                            doc.dereference(value).map(|(_, o)| o).unwrap_or(value)
                        }
                        other => other,
                    };
                    if let Some(text) = object_to_string(resolved) {
                        meta.insert(name, text);
                    }
                }
            }
        }
    }
    Ok(meta)
}

/// Find PDF links on the target's public pages and extract their metadata.
pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput {
    let mut pdf_links: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut documents: Vec<serde_json::Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    let base = match Url::parse(&format!("https://{domain}/")) {
        Ok(u) => u,
        Err(e) => {
            return ModuleOutput {
                name: "Document metadata (public PDFs)",
                json: json!({"module": "metadata", "domain": domain, "error": e.to_string()}),
                headers: vec!["Document", "Field", "Value"],
                rows: vec![],
            };
        }
    };

    // 1. Collect PDF links from the homepage and a bounded link set.
    let mut pages = vec![base.to_string()];
    if let Ok(home_html) = client.get_text(base.as_str()) {
        pdf_links.extend(find_pdf_links(&home_html, &base));
        for link in extract_links(&home_html, &base)
            .into_iter()
            .take(MAX_PAGES.saturating_sub(1))
        {
            pages.push(link);
        }
    } else {
        errors.push("homepage unreachable".to_string());
    }

    for page in pages.into_iter().skip(1) {
        if pdf_links.len() >= MAX_PDFS {
            break;
        }
        match client.get_text(&page) {
            Ok(html) => {
                if let Ok(page_url) = Url::parse(&page) {
                    pdf_links.extend(find_pdf_links(&html, &page_url));
                }
            }
            Err(e) => {
                eprintln!("{} fetching {page} failed: {e:#}", "[warn]".yellow());
                errors.push(format!("{page}: {e:#}"));
            }
        }
    }
    pdf_links.sort();
    pdf_links.dedup();

    if pdf_links.is_empty() {
        eprintln!(
            "{} no public PDF links found on {domain} (this is a normal outcome)",
            "[info]".blue()
        );
    }

    // 2. Download and parse a bounded number of documents.
    for link in pdf_links.iter().take(MAX_PDFS) {
        match client.get_bytes(link) {
            Ok(bytes) if bytes.len() > MAX_PDF_BYTES => {
                eprintln!(
                    "{} skipping {link}: {} bytes exceeds {} byte cap",
                    "[warn]".yellow(),
                    bytes.len(),
                    MAX_PDF_BYTES
                );
                errors.push(format!("{link}: skipped (size cap)"));
            }
            Ok(bytes) => match pdf_metadata(&bytes) {
                Ok(meta) => {
                    if meta.is_empty() {
                        rows.push(vec![
                            link.clone(),
                            "(info)".to_string(),
                            "no metadata".to_string(),
                        ]);
                    }
                    for (field, value) in &meta {
                        rows.push(vec![link.clone(), field.clone(), value.clone()]);
                    }
                    documents.push(json!({
                        "url": link,
                        "size_bytes": bytes.len(),
                        "metadata": meta,
                    }));
                }
                Err(e) => {
                    eprintln!("{} parsing {link} failed: {e:#}", "[warn]".yellow());
                    errors.push(format!("{link}: {e:#}"));
                }
            },
            Err(e) => {
                eprintln!("{} downloading {link} failed: {e:#}", "[warn]".yellow());
                errors.push(format!("{link}: {e:#}"));
            }
        }
    }

    ModuleOutput {
        name: "Document metadata (public PDFs)",
        json: json!({
            "module": "metadata",
            "domain": domain,
            "pdf_links_found": pdf_links,
            "documents": documents,
            "errors": errors,
        }),
        headers: vec!["Document", "Field", "Value"],
        rows,
    }
}

/// Extract links ending in `.pdf` (query strings tolerated) from HTML.
fn find_pdf_links(html: &str, base: &Url) -> Vec<String> {
    extract_links(html, base)
        .into_iter()
        .filter(|l| {
            Url::parse(l)
                .map(|u| u.path().to_lowercase().ends_with(".pdf"))
                .unwrap_or(false)
        })
        .collect()
}
