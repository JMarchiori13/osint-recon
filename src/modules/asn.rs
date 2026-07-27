//! Passive ASN & netblock enumeration.
//!
//! **Source choice: Team Cymru DNS whois over DNS-over-HTTPS.** Team Cymru
//! publishes IP→ASN and ASN→name mappings as DNS TXT records
//! (`<reversed-ip>.origin.asn.cymru.com` and `AS<n>.asn.cymru.com`). Because
//! the mapping is plain DNS, we can query it through the same dns.google DoH
//! resolver already used by the `dns` module — no new HTTP dependency, no
//! API key, and highly reliable. RIPEstat's REST API was the alternative; it
//! is equally passive but returns heavier payloads and occasional coverage
//! gaps for some prefixes, so the DNS path is preferred.
//!
//! All queries hit the public resolver / Team Cymru's DNS service — never
//! the target. MITRE ATT&CK T1590.001 (Domain Properties) / T1590.005
//! (IP Addresses).

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use colored::Colorize;
use serde_json::json;

use crate::http::HttpClient;
use crate::modules::dns_records::resolve;
use crate::output::ModuleOutput;

/// Parsed Team Cymru `origin.asn.cymru.com` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginInfo {
    asn: u64,
    prefix: String,
    country: String,
    registry: String,
}

/// Reverse the octets of an IPv4 address for a Cymru origin query.
fn reverse_ipv4(ip: &str) -> Option<String> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    let o = addr.octets();
    Some(format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0]))
}

/// Parse a Cymru origin TXT answer: `ASN | Prefix | CC | Registry | Date`.
fn parse_origin_txt(txt: &str) -> Option<OriginInfo> {
    let fields: Vec<&str> = txt.split('|').map(str::trim).collect();
    if fields.len() < 4 {
        return None;
    }
    Some(OriginInfo {
        asn: fields[0].parse().ok()?,
        prefix: fields[1].to_string(),
        country: fields[2].to_string(),
        registry: fields[3].to_string(),
    })
}

/// Parse a Cymru AS-name TXT answer: `ASN | CC | Registry | Date | AS Name`.
fn parse_asname_txt(txt: &str) -> Option<String> {
    let fields: Vec<&str> = txt.split('|').map(str::trim).collect();
    if fields.len() < 5 {
        return None;
    }
    Some(fields[4].to_string())
}

/// Strip the quotes dns.google places around TXT character-strings.
fn clean_txt(data: &str) -> String {
    data.replace("\" \"", "").trim_matches('"').to_string()
}

/// Query the IP→ASN mapping for one address.
fn query_origin(client: &HttpClient, ip: &str) -> Result<Option<OriginInfo>, anyhow::Error> {
    let reversed = reverse_ipv4(ip).ok_or_else(|| anyhow::anyhow!("not an IPv4 address: {ip}"))?;
    let name = format!("{reversed}.origin.asn.cymru.com");
    let answers = resolve(client, &name, "TXT")?;
    Ok(answers
        .first()
        .and_then(|a| parse_origin_txt(&clean_txt(a))))
}

/// Query the ASN→name mapping.
fn query_asname(client: &HttpClient, asn: u64) -> Result<Option<String>, anyhow::Error> {
    let name = format!("AS{asn}.asn.cymru.com");
    let answers = resolve(client, &name, "TXT")?;
    Ok(answers
        .first()
        .and_then(|a| parse_asname_txt(&clean_txt(a))))
}

/// Map a domain or IPv4 address to its ASN(s), AS names and announced prefixes.
pub fn run(client: &HttpClient, target: &str) -> ModuleOutput {
    let mut errors: Vec<String> = Vec::new();

    // 1. Determine the IP set: either the target itself or its A records.
    let ips: BTreeSet<String> = if target.parse::<Ipv4Addr>().is_ok() {
        BTreeSet::from([target.to_string()])
    } else {
        match resolve(client, target, "A") {
            Ok(addrs) => addrs
                .into_iter()
                .filter(|a| a.parse::<Ipv4Addr>().is_ok())
                .collect(),
            Err(e) => {
                eprintln!(
                    "{} resolving A records for {target} failed: {e:#}",
                    "[warn]".yellow()
                );
                errors.push(format!("A records: {e:#}"));
                BTreeSet::new()
            }
        }
    };

    // 2. Map each IP to its origin ASN/prefix.
    let mut mappings: Vec<(String, OriginInfo)> = Vec::new();
    for ip in &ips {
        match query_origin(client, ip) {
            Ok(Some(info)) => mappings.push((ip.clone(), info)),
            Ok(None) => {
                eprintln!("{} no Cymru origin data for {ip}", "[warn]".yellow());
                errors.push(format!("{ip}: no origin data"));
            }
            Err(e) => {
                eprintln!("{} origin query for {ip} failed: {e:#}", "[warn]".yellow());
                errors.push(format!("{ip}: {e:#}"));
            }
        }
    }

    // 3. Resolve AS names once per unique ASN.
    let unique_asns: BTreeSet<u64> = mappings.iter().map(|(_, i)| i.asn).collect();
    let mut as_names: BTreeMap<u64, String> = BTreeMap::new();
    for asn in &unique_asns {
        match query_asname(client, *asn) {
            Ok(Some(name)) => {
                as_names.insert(*asn, name);
            }
            Ok(None) => {
                errors.push(format!("AS{asn}: no name data"));
            }
            Err(e) => {
                eprintln!(
                    "{} AS-name query for AS{asn} failed: {e:#}",
                    "[warn]".yellow()
                );
                errors.push(format!("AS{asn}: {e:#}"));
            }
        }
    }

    let rows: Vec<Vec<String>> = mappings
        .iter()
        .map(|(ip, info)| {
            vec![
                ip.clone(),
                format!("AS{}", info.asn),
                as_names
                    .get(&info.asn)
                    .cloned()
                    .unwrap_or_else(|| "(unknown)".to_string()),
                info.prefix.clone(),
                info.country.clone(),
            ]
        })
        .collect();

    ModuleOutput {
        name: "ASN & netblock enumeration",
        json: json!({
            "module": "asn",
            "target": target,
            "source": "Team Cymru DNS whois via dns.google DoH",
            "ips": ips,
            "mappings": mappings.iter().map(|(ip, info)| json!({
                "ip": ip,
                "asn": info.asn,
                "as_name": as_names.get(&info.asn),
                "prefix": info.prefix,
                "country": info.country,
                "registry": info.registry,
            })).collect::<Vec<_>>(),
            "unique_asns": unique_asns,
            "errors": errors,
        }),
        headers: vec!["IP", "ASN", "AS Name", "Prefix", "CC"],
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses_ipv4_octets() {
        assert_eq!(reverse_ipv4("104.20.23.154").unwrap(), "154.23.20.104");
        assert!(reverse_ipv4("not-an-ip").is_none());
    }

    #[test]
    fn parses_origin_txt() {
        let info = parse_origin_txt("13335 | 104.20.16.0/20 | US | arin | 2014-03-28").unwrap();
        assert_eq!(info.asn, 13335);
        assert_eq!(info.prefix, "104.20.16.0/20");
        assert_eq!(info.country, "US");
        assert_eq!(info.registry, "arin");
        assert!(parse_origin_txt("garbage").is_none());
    }

    #[test]
    fn parses_asname_txt() {
        let name = parse_asname_txt("13335 | US | arin | 2011-01-25 | CLOUDFLARENET, US").unwrap();
        assert_eq!(name, "CLOUDFLARENET, US");
        assert!(parse_asname_txt("13335 | US").is_none());
    }

    #[test]
    fn cleans_doh_txt_quotes() {
        assert_eq!(
            clean_txt("\"13335 | x | US | arin\""),
            "13335 | x | US | arin"
        );
    }
}
