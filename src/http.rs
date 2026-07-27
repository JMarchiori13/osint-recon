//! Shared HTTP client for passive reconnaissance.
//!
//! Provides user-agent rotation, configurable timeouts, bounded retries and
//! polite rate limiting (default 1 request/second) so that queries against
//! public data sources remain low-impact and respectful.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use colored::Colorize;
use regex::Regex;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::Url;
use serde::de::DeserializeOwned;

/// Rotating pool of common, unremarkable browser user-agents.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/126.0.0.0 Safari/537.36",
];

/// Polite, rate-limited blocking HTTP client.
pub struct HttpClient {
    client: Client,
    /// Minimum interval between outbound requests.
    min_interval: Duration,
    /// Timestamp of the last request (for throttling).
    last_request: Mutex<Option<Instant>>,
    /// Rotating index into [`USER_AGENTS`].
    ua_index: Mutex<usize>,
    /// Number of retries after the initial attempt.
    retries: usize,
}

impl HttpClient {
    /// Build a client with the given timeout (seconds), politeness rate
    /// (requests per second) and retry count.
    pub fn new(timeout_secs: u64, requests_per_second: f64, retries: usize) -> Result<Self> {
        let min_interval = if requests_per_second > 0.0 {
            Duration::from_secs_f64(1.0 / requests_per_second)
        } else {
            Duration::ZERO
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(timeout_secs.min(10)))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            client,
            min_interval,
            last_request: Mutex::new(None),
            ua_index: Mutex::new(0),
            retries,
        })
    }

    /// Pick the next user-agent in rotation.
    fn next_user_agent(&self) -> &'static str {
        let mut idx = self.ua_index.lock().expect("ua_index mutex poisoned");
        let ua = USER_AGENTS[*idx % USER_AGENTS.len()];
        *idx += 1;
        ua
    }

    /// Sleep as needed to honor the politeness interval between requests.
    fn throttle(&self) {
        let mut last = self
            .last_request
            .lock()
            .expect("last_request mutex poisoned");
        if let Some(prev) = *last {
            let elapsed = prev.elapsed();
            if elapsed < self.min_interval {
                std::thread::sleep(self.min_interval - elapsed);
            }
        }
        *last = Some(Instant::now());
    }

    /// Perform a GET request with throttling, UA rotation and bounded retries.
    pub fn get(&self, url: &str) -> Result<Response> {
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 0..=self.retries {
            self.throttle();

            let mut headers = HeaderMap::new();
            headers.insert(USER_AGENT, HeaderValue::from_static(self.next_user_agent()));
            headers.insert(
                ACCEPT,
                HeaderValue::from_static("text/html,application/json,*/*;q=0.8"),
            );

            match self.client.get(url).headers(headers).send() {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    if attempt < self.retries {
                        eprintln!(
                            "{} request to {} failed (attempt {}/{}): {e}",
                            "[warn]".yellow(),
                            url,
                            attempt + 1,
                            self.retries + 1
                        );
                        std::thread::sleep(Duration::from_secs(2_u64.pow(attempt as u32)));
                    }
                    last_err = Some(anyhow::Error::new(e));
                }
            }
        }

        Err(last_err
            .expect("retry loop always records an error")
            .context(format!("GET {url} failed after retries")))
    }

    /// GET a URL and return the body as text.
    pub fn get_text(&self, url: &str) -> Result<String> {
        let resp = self.get(url)?;
        resp.text()
            .with_context(|| format!("reading body of {url}"))
    }

    /// GET a URL and return the body as raw bytes.
    pub fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.get(url)?;
        Ok(resp
            .bytes()
            .with_context(|| format!("reading body of {url}"))?
            .to_vec())
    }

    /// GET a URL and deserialize the body as JSON.
    pub fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let resp = self.get(url)?;
        resp.json::<T>()
            .with_context(|| format!("parsing JSON from {url}"))
    }
}

/// Extract same-host `href` links from an HTML document, resolved against the
/// base URL. Used for passive link following on already-public pages.
pub fn extract_links(html: &str, base: &Url) -> Vec<String> {
    let re = Regex::new(r#"(?i)href\s*=\s*["']([^"'#]+)["']"#).expect("valid regex");
    let host = base.host_str().unwrap_or_default().to_lowercase();
    let mut out = Vec::new();

    for cap in re.captures_iter(html) {
        let raw = &cap[1];
        if raw.starts_with("mailto:") || raw.starts_with("javascript:") || raw.starts_with("tel:") {
            continue;
        }
        if let Ok(abs) = base.join(raw) {
            if matches!(abs.scheme(), "http" | "https")
                && abs.host_str().unwrap_or_default().to_lowercase() == host
            {
                let mut clean = abs.clone();
                clean.set_fragment(None);
                let s = clean.to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_same_host_links_only() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"
            <a href="/about">About</a>
            <a href="https://example.com/contact">Contact</a>
            <a href="https://other.org/x">External</a>
            <a href="mailto:a@example.com">Mail</a>
        "#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://example.com/about".to_string()));
        assert!(links.contains(&"https://example.com/contact".to_string()));
        assert_eq!(links.len(), 2);
    }
}
