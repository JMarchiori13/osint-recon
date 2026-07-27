//! GitHub dorking — passive exposure search via the official GitHub REST API.
//!
//! Two tiers:
//! - **Keyless tier** (works out of the box, ~10 requests/min unauthenticated):
//!   `search/repositories` and `search/users` for the target domain.
//! - **Token tier** (optional): when `OSINT_RECON_GITHUB_TOKEN` (or
//!   `GITHUB_TOKEN`) is set, code-search dorks run via `search/code`
//!   (`.env` files, config files, `password`/`api_key` keyword hits).
//!   A read-only classic token from <https://github.com/settings/tokens> is
//!   sufficient — code search is unavailable without authentication.
//!
//! All traffic goes to `api.github.com`; nothing touches the target.
//! Findings map an organization's *public* exposure for the engagement
//! report — never exploit exposed secrets. MITRE ATT&CK T1593.003 (Search
//! Open Websites/Domains: Code Repositories).

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use colored::Colorize;
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::json;

use crate::http::HttpClient;
use crate::output::ModuleOutput;

/// Code-search dorks (token tier): (label, query template; `{domain}` substituted).
///
/// Extend this table to add dorks — keep them read-only and targeted.
const CODE_DORKS: &[(&str, &str)] = &[
    ("exposed .env", "\"{domain}\" filename:.env"),
    ("config.json", "\"{domain}\" filename:config.json"),
    ("password keyword", "\"{domain}\" password"),
    ("api_key keyword", "\"{domain}\" api_key"),
    ("yaml config", "\"{domain}\" filename:config.yml"),
];

/// Max results kept per search endpoint (politeness + report size bound).
const PER_PAGE: &str = "10";
/// Max results kept per code dork.
const CODE_PER_PAGE: &str = "5";

/// Build the code-search queries for a domain from [`CODE_DORKS`].
fn build_dork_queries(domain: &str) -> Vec<(&'static str, String)> {
    CODE_DORKS
        .iter()
        .map(|(label, template)| (*label, template.replace("{domain}", domain)))
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct SearchResponse<T> {
    #[serde(default)]
    total_count: u64,
    #[serde(default)]
    items: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct RepoItem {
    full_name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    stargazers_count: u64,
    #[serde(default)]
    pushed_at: String,
    html_url: String,
    owner: RepoOwner,
}

#[derive(Debug, Deserialize)]
struct RepoOwner {
    login: String,
}

#[derive(Debug, Deserialize)]
struct UserItem {
    login: String,
    #[serde(rename = "type", default)]
    account_type: String,
    html_url: String,
}

#[derive(Debug, Deserialize)]
struct CodeItem {
    name: String,
    path: String,
    html_url: String,
    repository: CodeRepo,
}

#[derive(Debug, Deserialize)]
struct CodeRepo {
    full_name: String,
}

/// Human-readable rate-limit reset note from response headers.
fn rate_limit_note(resp: &reqwest::blocking::Response) -> String {
    resp.headers()
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .map(|reset| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("limit resets in {}s", reset.saturating_sub(now))
        })
        .unwrap_or_else(|| "reset time unknown".to_string())
}

/// GET a GitHub API endpoint with the required headers and error mapping.
fn github_get<T: for<'de> Deserialize<'de>>(
    client: &HttpClient,
    endpoint: &str,
    params: &[(&str, &str)],
    token: Option<&str>,
) -> Result<T> {
    let url = Url::parse_with_params(&format!("https://api.github.com/{endpoint}"), params)
        .with_context(|| format!("building URL for {endpoint}"))?;

    let auth;
    let mut headers: Vec<(&str, &str)> = vec![
        ("Accept", "application/vnd.github+json"),
        ("X-GitHub-Api-Version", "2022-11-28"),
    ];
    if let Some(t) = token {
        auth = format!("Bearer {t}");
        headers.push(("Authorization", &auth));
    }

    let resp = client.get_with_headers(url.as_str(), &headers)?;
    let status = resp.status();
    if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
        anyhow::bail!(
            "GitHub API rate limit ({status}): {}",
            rate_limit_note(&resp)
        );
    }
    if !status.is_success() {
        anyhow::bail!("GitHub API returned {status} for {endpoint}");
    }
    resp.json::<T>()
        .with_context(|| format!("parsing GitHub response from {endpoint}"))
}

/// Resolve the API token from the environment (never logged or exported).
fn resolve_token() -> Option<String> {
    env::var("OSINT_RECON_GITHUB_TOKEN")
        .ok()
        .or_else(|| env::var("GITHUB_TOKEN").ok())
        .filter(|t| !t.trim().is_empty())
}

/// Search GitHub for public exposure related to `domain`.
pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput {
    let token = resolve_token();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut repos_json: Vec<serde_json::Value> = Vec::new();
    let mut users_json: Vec<serde_json::Value> = Vec::new();
    let mut code_json: Vec<serde_json::Value> = Vec::new();
    let mut dorks_run: Vec<String> = Vec::new();
    let mut total_hits = serde_json::Map::new();

    // ---- Keyless tier: repositories mentioning the domain. ----
    match github_get::<SearchResponse<RepoItem>>(
        client,
        "search/repositories",
        &[("q", domain), ("per_page", PER_PAGE)],
        token.as_deref(),
    ) {
        Ok(resp) => {
            total_hits.insert("repositories".to_string(), json!(resp.total_count));
            for item in resp.items {
                rows.push(vec![
                    "repo".to_string(),
                    item.full_name.clone(),
                    format!("{} stars", item.stargazers_count),
                    format!(
                        "pushed {} — {}",
                        item.pushed_at.get(..10).unwrap_or(&item.pushed_at),
                        item.description.clone().unwrap_or_default()
                    ),
                    item.html_url.clone(),
                ]);
                repos_json.push(json!({
                    "full_name": item.full_name,
                    "owner": item.owner.login,
                    "stars": item.stargazers_count,
                    "pushed_at": item.pushed_at,
                    "description": item.description,
                    "url": item.html_url,
                }));
            }
        }
        Err(e) => {
            eprintln!("{} repository search failed: {e:#}", "[warn]".yellow());
            errors.push(format!("repositories: {e:#}"));
        }
    }

    // ---- Keyless tier: users/orgs associated with the domain. ----
    match github_get::<SearchResponse<UserItem>>(
        client,
        "search/users",
        &[("q", domain), ("per_page", PER_PAGE)],
        token.as_deref(),
    ) {
        Ok(resp) => {
            total_hits.insert("users".to_string(), json!(resp.total_count));
            for item in resp.items {
                rows.push(vec![
                    "user".to_string(),
                    item.login.clone(),
                    item.account_type.clone(),
                    String::new(),
                    item.html_url.clone(),
                ]);
                users_json.push(json!({
                    "login": item.login,
                    "type": item.account_type,
                    "url": item.html_url,
                }));
            }
        }
        Err(e) => {
            eprintln!("{} user search failed: {e:#}", "[warn]".yellow());
            errors.push(format!("users: {e:#}"));
        }
    }

    // ---- Token tier: code-search dorks. ----
    if token.is_some() {
        for (label, query) in build_dork_queries(domain) {
            dorks_run.push(query.clone());
            match github_get::<SearchResponse<CodeItem>>(
                client,
                "search/code",
                &[("q", &query), ("per_page", CODE_PER_PAGE)],
                token.as_deref(),
            ) {
                Ok(resp) => {
                    total_hits.insert(format!("code:{label}"), json!(resp.total_count));
                    for item in resp.items {
                        rows.push(vec![
                            "code".to_string(),
                            item.path.clone(),
                            item.repository.full_name.clone(),
                            format!("dork: {label}"),
                            item.html_url.clone(),
                        ]);
                        code_json.push(json!({
                            "dork": label,
                            "file": item.name,
                            "path": item.path,
                            "repository": item.repository.full_name,
                            "url": item.html_url,
                        }));
                    }
                }
                Err(e) => {
                    eprintln!("{} code dork \"{label}\" failed: {e:#}", "[warn]".yellow());
                    errors.push(format!("code/{label}: {e:#}"));
                }
            }
        }
    } else {
        eprintln!(
            "{} no OSINT_RECON_GITHUB_TOKEN/GITHUB_TOKEN set — keyless tier only (repos + users); code-search dorks skipped",
            "[info]".blue()
        );
    }

    ModuleOutput {
        name: "GitHub dorking (public exposure)",
        json: json!({
            "module": "ghdork",
            "domain": domain,
            "note": "Public GitHub exposure for the engagement report — never exploit exposed secrets.",
            "token_tier": token.is_some(),
            "total_hits": total_hits,
            "repositories": repos_json,
            "users": users_json,
            "code_findings": code_json,
            "code_dorks_run": dorks_run,
            "errors": errors,
        }),
        headers: vec![
            "Type",
            "Name / Path",
            "Owner / Repo / Stars",
            "Notes",
            "URL",
        ],
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dork_queries_substitute_domain() {
        let dorks = build_dork_queries("example.com");
        assert_eq!(dorks.len(), CODE_DORKS.len());
        for (label, query) in &dorks {
            assert!(!label.is_empty());
            assert!(
                query.contains("example.com"),
                "dork missing domain: {query}"
            );
            assert!(
                !query.contains("{domain}"),
                "unsubstituted template: {query}"
            );
        }
        assert!(dorks.iter().any(|(_, q)| q.contains("filename:.env")));
        assert!(dorks.iter().any(|(_, q)| q.contains("api_key")));
    }

    #[test]
    fn parses_repo_search_response() {
        let body = r#"{
            "total_count": 1,
            "items": [{
                "full_name": "org/example-api",
                "description": "API for example.com",
                "stargazers_count": 42,
                "pushed_at": "2026-01-15T10:00:00Z",
                "html_url": "https://github.com/org/example-api",
                "owner": {"login": "org"}
            }]
        }"#;
        let resp: SearchResponse<RepoItem> = serde_json::from_str(body).unwrap();
        assert_eq!(resp.total_count, 1);
        assert_eq!(resp.items[0].full_name, "org/example-api");
        assert_eq!(resp.items[0].stargazers_count, 42);
        assert_eq!(resp.items[0].owner.login, "org");
    }

    #[test]
    fn parses_user_search_response() {
        let body = r#"{
            "total_count": 1,
            "items": [{"login": "example-org", "type": "Organization",
                       "html_url": "https://github.com/example-org"}]
        }"#;
        let resp: SearchResponse<UserItem> = serde_json::from_str(body).unwrap();
        assert_eq!(resp.items[0].login, "example-org");
        assert_eq!(resp.items[0].account_type, "Organization");
    }

    #[test]
    fn parses_code_search_response() {
        let body = r#"{
            "total_count": 1,
            "items": [{
                "name": ".env", "path": "deploy/.env",
                "html_url": "https://github.com/org/repo/blob/main/deploy/.env",
                "repository": {"full_name": "org/repo"}
            }]
        }"#;
        let resp: SearchResponse<CodeItem> = serde_json::from_str(body).unwrap();
        assert_eq!(resp.items[0].path, "deploy/.env");
        assert_eq!(resp.items[0].repository.full_name, "org/repo");
    }

    #[test]
    fn empty_search_response_parses() {
        let body = r#"{"total_count": 0, "items": []}"#;
        let resp: SearchResponse<RepoItem> = serde_json::from_str(body).unwrap();
        assert!(resp.items.is_empty());
    }
}
