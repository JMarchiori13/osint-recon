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
