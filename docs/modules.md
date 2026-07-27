# Module Reference

Every module implements `run(client: &HttpClient, domain: &str) -> ModuleOutput`,
shares the global HTTP client (rate limit, timeout, retries, UA rotation),
and returns both a structured JSON payload and flat table rows used for the
console and CSV export.

## Composability (all modules)

- **`--stdout`** — results stream as JSONL (one JSON object per result row)
  on stdout, so the tool pipes cleanly into `jq` and friends; the banner and
  all logs move to stderr. Object shape: `{"module": <name>, <column>: <value>, ...}`
  with keys derived from the table headers (`"Name / Path"` → `name_path`).
- **stdin targets** — pass `-` as the target to read one domain per line
  from stdin (`cat domains.txt | osint-recon dns -`); blank lines and `#`
  comments are skipped, invalid lines are warned about and skipped, and each
  target is processed sequentially under the shared rate limiter.

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

## `ghdork` — GitHub dorking (public exposure search)

| | |
|---|---|
| Source | GitHub REST search API (`api.github.com/search/repositories`, `/search/users`, `/search/code`) |
| API keys | keyless tier works out of the box (~10 req/min); optional token tier via `OSINT_RECON_GITHUB_TOKEN` (fallback `GITHUB_TOKEN`) unlocks `search/code`. A read-only classic token from <https://github.com/settings/tokens> is sufficient. |
| ATT&CK | T1593.003 (Search Open Websites/Domains: Code Repositories) |
| Keyless tier | repos mentioning the domain (name, owner, stars, last push, description) + users/orgs associated |
| Token tier | code-search dorks from the `CODE_DORKS` table in `src/modules/github_dorks.rs`: `"<domain>" filename:.env`, `filename:config.json`, `filename:config.yml`, `password`, `api_key` — file path, repo, URL (extend the const to add dorks) |
| Output fields | `repositories[]`, `users[]`, `code_findings[]`, `total_hits{}` (per-endpoint GitHub `total_count`), `code_dorks_run[]`, `token_tier`, `errors[]` |
| Limitations | Unauthenticated search rate limit is strict (~10 req/min) — 403/429 responses are caught and warned with the reset time from `X-RateLimit-Reset`. Common documentation domains (e.g. `example.com`) produce heavy noise in code search; triage findings against the engagement scope. Results are leads for the report — never validate exposed secrets. The token is read from the environment only, never logged or written to exports. |

## `br` — Brazilian context (CNPJ, CEP, dork pack)

> **LGPD (Lei 13.709/2018) scope note:** `br` handles **company and address
> data only**. CNPJ records are public business data published by Receita
> Federal; CEP data is public addressing information. The module does **not**
> query or handle personal data (CPF) — personal-data harvesting is out of
> scope for the whole framework. Partner names appear in the public company
> record; handle them under the engagement's data-handling rules.
>
> **Why `br` is not in `full`:** its targets are Brazilian documents and
> postal codes, not domains — mixing it into the domain-driven `full` run
> would be meaningless. It stays a standalone context module.

### `br cnpj <CNPJ>` — company lookup (T1591)

| | |
|---|---|
| Sources | BrasilAPI `/api/cnpj/v1/<cnpj>` (keyless, generous), ReceitaWS `/v1/cnpj/<cnpj>` fallback (keyless, **3 req/min** — enforced with a per-source 20 s throttle) |
| Validation | Accepts with/without punctuation. Classic numeric format: full mod-11 check-digit validation (rejects typos, repeated digits). **New alphanumeric format (valid since July 2026)**: 12 alphanumeric base chars + 2 numeric check digits — format-validated. Invalid input is rejected with a clear error before any network call. |
| Output fields | razão social, nome fantasia, CNAE (code + description), situação cadastral, abertura, capital social, full address, partners (sócios) with qualification, source used |
| Limitations | ReceitaWS's 3 req/min makes it unsuitable for batch; BrasilAPI occasionally 404s on very new registrations. Sócios lists can be long (public record). |

### `br cep <CEP>` — address resolution (T1591)

| | |
|---|---|
| Sources | BrasilAPI `/api/cep/v2/<cep>` (coordinates when available), ViaCEP `/ws/<cep>/json/` fallback |
| Output fields | street, district, city, state, latitude/longitude (when the v2 source provides them), source used |
| Limitations | Coordinates are present for only part of the CEP base; rows without data are hidden. |

### `br dorks <target>` — Brazilian dork pack (T1593)

| | |
|---|---|
| Sources | **None — no scraping.** Generates ready-to-open Google/Shodan search URLs for manual use; executing the search is a human decision. |
| Pack | Lives in the `BR_DORKS` const in `src/modules/br/dorks.rs`: SQL dumps on .br, DB files with passwords, exposed backups on .com.br, gov.br spreadsheets, mil.br PDFs, exposed PowerBI (`intext:"brasil"`), WhatsApp/Telegram group indexation, Shodan `country:"BR"`. |
| Target interpolation | Dorks marked `supports_target` get the target string prepended (e.g. `exemplo.com.br site:br ext:sql ...`). |
| Limitations | Google may rate-limit/captcha heavy manual dorking; results always require human triage. |

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
