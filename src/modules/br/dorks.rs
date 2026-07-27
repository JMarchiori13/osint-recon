//! Brazilian OSINT dork pack (ATT&CK T1593 — Search Open Websites/Domains).
//!
//! **No scraping**: this subcommand generates ready-to-open search URLs
//! (Google, Shodan) for *manual* use in a browser. Executing the searches
//! is a human decision; osint-recon only formats the queries.
//!
//! Extend [`BR_DORKS`] to contribute new dorks — keep them passive.

use serde_json::json;

use crate::output::ModuleOutput;

/// Search engine the dork targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    Google,
    Shodan,
}

/// A dork template: `supports_target` entries get the target string
/// prepended to the query when one is provided.
pub struct BrDork {
    pub name: &'static str,
    pub engine: Engine,
    pub query: &'static str,
    pub supports_target: bool,
}

/// The Brazilian dork pack (from the OSINT Brazuca ecosystem study).
pub const BR_DORKS: &[BrDork] = &[
    BrDork {
        name: "SQL dumps on .br",
        engine: Engine::Google,
        query: "site:br ext:sql \"CREATE TABLE\"",
        supports_target: true,
    },
    BrDork {
        name: "SQL/DB files with passwords (.br)",
        engine: Engine::Google,
        query: "site:br ext:sql|ext:db \"senha\"|\"password\"",
        supports_target: true,
    },
    BrDork {
        name: "Exposed backups (.com.br)",
        engine: Engine::Google,
        query: "site:com.br inurl:\"backup\" ext:sql|ext:bak",
        supports_target: true,
    },
    BrDork {
        name: "Spreadsheets on gov.br",
        engine: Engine::Google,
        query: "site:gov.br ext:xls",
        supports_target: true,
    },
    BrDork {
        name: "PDFs on mil.br",
        engine: Engine::Google,
        query: "site:mil.br ext:pdf",
        supports_target: true,
    },
    BrDork {
        name: "Exposed PowerBI dashboards (Brasil)",
        engine: Engine::Google,
        query: "site:app.powerbi.com/view?r intext:\"brasil\"",
        supports_target: false,
    },
    BrDork {
        name: "WhatsApp group invites (.br)",
        engine: Engine::Google,
        query: "\"chat.whatsapp.com\" site:br",
        supports_target: true,
    },
    BrDork {
        name: "Telegram group invites",
        engine: Engine::Google,
        query: "site:t.me \"joinchat\"",
        supports_target: true,
    },
    BrDork {
        name: "Shodan: hosts in Brazil",
        engine: Engine::Shodan,
        query: "country:\"BR\"",
        supports_target: true,
    },
];

/// Percent-encode a query for use in a URL (unreserved chars kept verbatim).
fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Render the final query: prepend the target where the dork supports it.
pub fn render_query(dork: &BrDork, target: &str) -> String {
    let target = target.trim();
    if dork.supports_target && !target.is_empty() {
        format!("{target} {}", dork.query)
    } else {
        dork.query.to_string()
    }
}

/// Build the ready-to-open search URL for a rendered query.
pub fn build_url(engine: Engine, query: &str) -> String {
    let enc = urlencode(query);
    match engine {
        Engine::Google => format!("https://www.google.com/search?q={enc}"),
        Engine::Shodan => format!("https://www.shodan.io/search?query={enc}"),
    }
}

/// Generate the dork pack table for `target` (no network access).
pub fn run(target: &str) -> ModuleOutput {
    let rows: Vec<Vec<String>> = BR_DORKS
        .iter()
        .map(|d| {
            let query = render_query(d, target);
            vec![
                d.name.to_string(),
                format!("{:?}", d.engine).to_lowercase(),
                query.clone(),
                build_url(d.engine, &query),
            ]
        })
        .collect();

    ModuleOutput {
        name: "Brazilian OSINT dork pack",
        json: json!({
            "module": "br_dorks",
            "note": "Ready-to-open search URLs for MANUAL use — osint-recon does not execute or scrape these searches.",
            "target": target,
            "dorks": BR_DORKS.iter().map(|d| {
                let query = render_query(d, target);
                json!({
                    "name": d.name,
                    "engine": d.engine,
                    "query": query,
                    "url": build_url(d.engine, &query),
                })
            }).collect::<Vec<_>>(),
        }),
        headers: vec!["Dork", "Engine", "Query", "URL"],
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencodes_special_characters() {
        assert_eq!(urlencode("country:\"BR\""), "country%3A%22BR%22");
        assert_eq!(urlencode("site:br ext:sql"), "site%3Abr%20ext%3Asql");
        assert_eq!(urlencode("abc-DEF_123.~"), "abc-DEF_123.~");
    }

    #[test]
    fn renders_target_interpolation() {
        let shodan = BR_DORKS
            .iter()
            .find(|d| d.engine == Engine::Shodan)
            .unwrap();
        assert_eq!(
            render_query(shodan, "exemplo.com.br"),
            "exemplo.com.br country:\"BR\""
        );
        // No target → bare query.
        assert_eq!(render_query(shodan, "  "), "country:\"BR\"");
        // Non-target dorks never interpolate.
        let powerbi = BR_DORKS
            .iter()
            .find(|d| d.name.contains("PowerBI"))
            .unwrap();
        assert_eq!(
            render_query(powerbi, "exemplo.com.br"),
            "site:app.powerbi.com/view?r intext:\"brasil\""
        );
    }

    #[test]
    fn builds_engine_urls() {
        assert_eq!(
            build_url(Engine::Google, "site:gov.br ext:xls"),
            "https://www.google.com/search?q=site%3Agov.br%20ext%3Axls"
        );
        assert_eq!(
            build_url(Engine::Shodan, "country:\"BR\""),
            "https://www.shodan.io/search?query=country%3A%22BR%22"
        );
    }

    #[test]
    fn pack_matches_study_coverage() {
        // All study patterns present: leaks, gov/mil docs, PowerBI,
        // WhatsApp/Telegram indexation, Shodan BR.
        let queries: Vec<&str> = BR_DORKS.iter().map(|d| d.query).collect();
        assert!(queries.iter().any(|q| q.contains("ext:sql")));
        assert!(queries.iter().any(|q| q.contains("gov.br")));
        assert!(queries.iter().any(|q| q.contains("mil.br")));
        assert!(queries.iter().any(|q| q.contains("powerbi")));
        assert!(queries.iter().any(|q| q.contains("chat.whatsapp.com")));
        assert!(queries.iter().any(|q| q.contains("t.me")));
        assert!(queries.iter().any(|q| q.contains("country:\"BR\"")));
    }
}
