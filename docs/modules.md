# Module Reference

Every module implements `run(client: &HttpClient, domain: &str) -> ModuleOutput`,
shares the global HTTP client (rate limit, timeout, retries, UA rotation),
and returns both a structured JSON payload and flat table rows used for the
console and CSV export.

## `subdomain` — passive subdomain enumeration

| | |
|---|---|
| Sources | crt.sh JSON API (`?q=%25.<domain>&output=json`), hackertarget `hostsearch` |
| API keys | none |
| ATT&CK | T1590.001 (Domain Properties) |
| Output fields | `subdomains[]` (deduplicated, lowercased, wildcard prefixes stripped), `sources[]`, `errors[]` |
| Limitations | crt.sh rate-limits aggressively and occasionally times out (handled with retries + warning). Results reflect historical certificates — some hosts may no longer resolve. Email-like names in certs (e.g. `user@example.com`) may appear as artifacts of the source data. |

## `dns` — DNS records via DNS-over-HTTPS

| | |
|---|---|
| Source | `https://dns.google/resolve` JSON API |
| API keys | none |
| ATT&CK | T1590.002 (DNS) |
| Record types | A, AAAA, MX, NS, TXT |
| Output fields | `records.<TYPE>[]` as `"name -> data"` strings, `errors[]` |
| Limitations | Answers reflect Google's resolver view (CDN anycast means IPs vary by vantage point). No AXFR, no reverse sweeps, no queries against the target's authoritative servers. |

## `asn` — ASN & netblock enumeration

| | |
|---|---|
| Source | Team Cymru DNS whois (`origin.asn.cymru.com` / `asn.cymru.com` TXT records) queried via dns.google DoH |
| API keys | none |
| ATT&CK | T1590.001 (Domain Properties), T1590.005 (IP Addresses) |
| Input | domain (A records resolved via DoH first) or bare IPv4 address |
| Output fields | `mappings[]` (ip, asn, as_name, prefix, country, registry), `unique_asns[]`, `errors[]` |
| Source rationale | Team Cymru's mapping is plain DNS, so it reuses the existing DoH resolver path — no new HTTP dependency and high reliability. RIPEstat's REST API (`stat.ripe.net/data/prefix-overview`) was the alternative; it is equally passive but returns heavier payloads and has occasional coverage gaps, so the DNS path is preferred. |
| Limitations | IPv4 only (no IPv6 origin lookups yet). Team Cymru has no data for a small number of legacy blocks — those IPs are reported as "no origin data" rather than failing the run. AS names depend on Cymru's registry data and may lag renames. |

## `ct` — certificate transparency history

| | |
|---|---|
| Source | crt.sh JSON API (shared fetch helper with the `subdomain` module) |
| API keys | none |
| ATT&CK | T1596.003 (Search Open Technical Databases: Digital Certificates), T1590.001 |
| Output fields | `total_certificates`, `unique_issuers[]` (CA short names from the issuer DN), `unique_san_names`, `earliest_not_before`, `latest_not_after`, `expiring_soon[]` (name, not_after, days_left; <30 days) |
| Limitations | crt.sh rate-limits aggressively — transient failures retry with backoff and degrade gracefully. Historical entries include expired/revoked certs by design (it is a *history* view). Issuer labels are the CN of the issuer DN, so CA rebrands appear as distinct issuers. |

## `tech` — technology fingerprinting

| | |
|---|---|
| Source | single GET of the target homepage (HTTPS with HTTP fallback) |
| ATT&CK | T1592.002 (Software) |
| Signals | response headers (`Server`, `X-Powered-By`, `cf-ray`, ...), `<meta name="generator">`, HTML signatures (WordPress, Joomla, Drupal, Shopify, Wix, Squarespace, React, Next.js, Vue, Angular, jQuery, Bootstrap, Cloudflare) |
| Output fields | `headers{}`, `technologies[]`, final `url` after redirects |
| Limitations | Homepage-only view; SPAs and WAFs can mask the origin stack. Signature list is intentionally conservative — absence of a hit is not absence of a technology. |

## `email` — email harvesting from public pages

| | |
|---|---|
| Source | homepage + up to 5 same-host links (prioritizing `contact`/`about`/`team` paths), plain GETs |
| ATT&CK | T1593.002, T1589.002 (Email Addresses) |
| Method | regex extraction from HTML text and `mailto:` links; asset false-positives (`x@2x.png`) filtered |
| Output fields | `emails[]` (deduplicated), `pages_scanned[]`, `errors[]` |
| Limitations | Only addresses the organization itself publishes. Obfuscated addresses (`name [at] domain`) are not decoded by design. Handle results under LGPD/GDPR and the engagement ROE. |

## `metadata` — document metadata from public PDFs

| | |
|---|---|
| Source | PDF links found on the homepage + up to 3 same-host pages; at most 3 PDFs downloaded (≤ 10 MiB each) |
| ATT&CK | T1593.002 (Search Open Websites/Domains) |
| Method | PDF Info dictionary parsed with `lopdf`: Author, Creator, Producer, Title, CreationDate, ModDate, ... |
| Output fields | `pdf_links_found[]`, `documents[].metadata{}`, `errors[]` |
| Limitations | Many sites (e.g. `example.com`) link no PDFs at all — empty output is normal. Some PDFs carry a stripped Info dictionary; XMP-only metadata is not yet parsed (see roadmap). |
