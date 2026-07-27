//! Certificate transparency history via crt.sh.
//!
//! Aggregates the CT log entries for `*.<domain>` into a historical view:
//! total certificates, unique issuing CAs, validity windows, SAN coverage
//! and certificates expiring within 30 days (an operational signal for
//! infrastructure churn).
//!
//! crt.sh rate-limits aggressively; the shared [`HttpClient`] retries with
//! backoff and failures degrade gracefully. MITRE ATT&CK T1596.003 (Search
//! Open Technical Databases: Digital Certificates) / T1590.001.

use std::collections::BTreeSet;

use chrono::{DateTime, NaiveDateTime, Utc};
use colored::Colorize;
use serde_json::json;

use crate::http::HttpClient;
use crate::modules::crtsh::{fetch, CrtShEntry};
use crate::output::ModuleOutput;

/// Certificates expiring within this many days are flagged.
const EXPIRING_SOON_DAYS: i64 = 30;

/// Extract a short issuer label from an LDAP-style DN (`C=US, O=..., CN=X`).
fn issuer_short(dn: &str) -> String {
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.trim().to_string();
        }
    }
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(o) = part.strip_prefix("O=") {
            return o.trim().to_string();
        }
    }
    dn.trim().to_string()
}

/// Parse a crt.sh timestamp (`2025-01-31T23:59:59`, optional fractional secs).
fn parse_ts(ts: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(ts.trim(), "%Y-%m-%dT%H:%M:%S%.f").ok()
}

/// Whole days from `now` until `ts` (negative when already expired).
fn days_until(now: DateTime<Utc>, ts: NaiveDateTime) -> i64 {
    (ts.and_utc() - now).num_days()
}

/// Build the aggregated CT history summary for `domain`.
pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput {
    let entries: Vec<CrtShEntry> = match fetch(client, domain) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} crt.sh history query failed: {e:#}", "[warn]".yellow());
            return ModuleOutput {
                name: "Certificate transparency history",
                json: json!({
                    "module": "ct",
                    "domain": domain,
                    "error": format!("{e:#}"),
                }),
                headers: vec!["Metric", "Value"],
                rows: vec![vec![
                    "error".to_string(),
                    "crt.sh unreachable (rate limit?) — try again later".to_string(),
                ]],
            };
        }
    };

    let now = Utc::now();
    let mut issuers: BTreeSet<String> = BTreeSet::new();
    let mut san_names: BTreeSet<String> = BTreeSet::new();
    let mut earliest_not_before: Option<NaiveDateTime> = None;
    let mut latest_not_after: Option<NaiveDateTime> = None;
    let mut expiring_soon: Vec<(String, String, i64)> = Vec::new(); // (name, not_after, days)

    for entry in &entries {
        if !entry.issuer_name.is_empty() {
            issuers.insert(issuer_short(&entry.issuer_name));
        }
        let mut entry_names: Vec<String> = Vec::new();
        for name in entry.name_value.lines() {
            let clean = name.trim().trim_start_matches("*.").to_lowercase();
            if !clean.is_empty() {
                san_names.insert(clean.clone());
                entry_names.push(clean);
            }
        }
        if let Some(nb) = parse_ts(&entry.not_before) {
            earliest_not_before = Some(match earliest_not_before {
                Some(prev) if prev < nb => prev,
                _ => nb,
            });
        }
        if let Some(na) = parse_ts(&entry.not_after) {
            latest_not_after = Some(match latest_not_after {
                Some(prev) if prev > na => prev,
                _ => na,
            });
            let days = days_until(now, na);
            if (0..EXPIRING_SOON_DAYS).contains(&days) {
                if let Some(first) = entry_names.first() {
                    expiring_soon.push((first.clone(), entry.not_after.clone(), days));
                }
            }
        }
    }
    expiring_soon.sort_by_key(|(_, _, days)| *days);
    expiring_soon.dedup_by(|a, b| a.0 == b.0);

    let fmt_ts = |ts: Option<NaiveDateTime>| {
        ts.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "(unknown)".to_string())
    };

    let mut rows: Vec<Vec<String>> = vec![
        vec!["Total certificates".to_string(), entries.len().to_string()],
        vec![
            "Unique issuers (CAs)".to_string(),
            issuers.len().to_string(),
        ],
        vec!["Unique SAN names".to_string(), san_names.len().to_string()],
        vec![
            "Earliest not_before".to_string(),
            fmt_ts(earliest_not_before),
        ],
        vec!["Latest not_after".to_string(), fmt_ts(latest_not_after)],
        vec![
            format!("Expiring in <{EXPIRING_SOON_DAYS} days"),
            expiring_soon.len().to_string(),
        ],
    ];
    for (name, not_after, days) in expiring_soon.iter().take(10) {
        rows.push(vec![
            format!("  expiring: {name}"),
            format!("{not_after} ({days}d left)"),
        ]);
    }

    ModuleOutput {
        name: "Certificate transparency history",
        json: json!({
            "module": "ct",
            "domain": domain,
            "source": "crt.sh",
            "total_certificates": entries.len(),
            "unique_issuers": issuers,
            "unique_san_names": san_names.len(),
            "earliest_not_before": fmt_ts(earliest_not_before),
            "latest_not_after": fmt_ts(latest_not_after),
            "expiring_within_days": EXPIRING_SOON_DAYS,
            "expiring_soon": expiring_soon.iter().map(|(name, not_after, days)| json!({
                "name": name,
                "not_after": not_after,
                "days_left": days,
            })).collect::<Vec<_>>(),
        }),
        headers: vec!["Metric", "Value"],
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_issuer_common_name() {
        assert_eq!(issuer_short("C=US, O=Let's Encrypt, CN=R11"), "R11");
        assert_eq!(issuer_short("C=US, O=DigiCert Inc"), "DigiCert Inc");
        assert_eq!(issuer_short("Some CA"), "Some CA");
    }

    #[test]
    fn parses_crtsh_timestamps() {
        assert!(parse_ts("2025-01-31T23:59:59").is_some());
        assert!(parse_ts("2025-01-31T23:59:59.123").is_some());
        assert!(parse_ts("not a date").is_none());
        assert!(parse_ts("").is_none());
    }

    #[test]
    fn computes_days_until_expiry() {
        let now = Utc::now();
        let in_10_days = (now + chrono::Duration::days(10)).naive_utc();
        assert_eq!(days_until(now, in_10_days), 10);
        let yesterday = (now - chrono::Duration::days(1)).naive_utc();
        assert!(days_until(now, yesterday) < 0);
    }
}
