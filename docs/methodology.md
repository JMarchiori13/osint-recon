# Reconnaissance Methodology

osint-recon implements the **passive** portion of the reconnaissance phase
for authorized red team engagements. This document describes the methodology,
the MITRE ATT&CK mapping, and OPSEC considerations.

## For authorized security assessments only

Run this tool only against infrastructure you own or are explicitly
authorized, in writing, to assess. Unauthorized reconnaissance may violate
Brazil's **Lei nº 12.737/2012**, the U.S. **Computer Fraud and Abuse Act
(CFAA)**, and equivalent computer-misuse statutes elsewhere. Collected
personal data (e.g. email addresses) is additionally subject to privacy law
such as Brazil's **LGPD** and the EU **GDPR**.

## What "passive" means here

Passive reconnaissance collects information **without interacting with the
target beyond what an ordinary visitor would do**. osint-recon uses exactly
three categories of passive technique:

1. **Third-party public data aggregators** — crt.sh (certificate
   transparency) and hackertarget (DNS history). The query goes to the
   aggregator, never to the target.
2. **Public DNS resolvers** — DNS-over-HTTPS queries to `dns.google`, a
   recursive resolver. The target's authoritative nameservers are not
   contacted by us; the resolver does that as part of normal DNS operation.
3. **Plain GET requests to already-public pages** — fetching a homepage or a
   linked page is indistinguishable from an ordinary browser visit. Link
   following is bounded (a handful of pages, 1 request/second by default).

Explicitly **out of scope** (active techniques this tool will never perform):

- Port scanning or service probing (T1046)
- Directory, file or subdomain brute forcing (wordlist-driven guessing)
- Vulnerability scanning or exploit delivery
- Credential testing, password spraying, or authentication probing
- Zone transfers or any non-standard DNS query against the target

## MITRE ATT&CK mapping (TA0043 — Reconnaissance)

| Technique | Name | osint-recon module |
|-----------|------|--------------------|
| T1590.002 | Gather Victim Network Information: DNS | `dns` |
| T1590.001 | Gather Victim Network Information: Domain Properties | `subdomain` |
| T1592.002 | Gather Victim Host Information: Software | `tech` |
| T1593.002 | Search Open Websites/Domains: Search Engines / public pages | `email`, `metadata` |
| T1589.002 | Gather Victim Identity Information: Email Addresses | `email` |

Only the **passive** variants of these techniques are implemented.

## Workflow in an engagement

1. **Scope confirmation** — verify the target domain is in the written scope
   of the engagement.
2. **Domain properties** (`subdomain`) — map the public DNS footprint from
   certificate transparency and DNS-history aggregators.
3. **Network information** (`dns`) — enumerate record types via a public
   resolver to understand hosting, mail, and verification records.
4. **Host information** (`tech`) — fingerprint the publicly served stack
   (headers, meta generator, CMS signatures).
5. **Identity information** (`email`) — collect addresses the organization
   itself publishes, to plan authorized phishing simulations.
6. **Document analysis** (`metadata`) — extract author/tool metadata from
   publicly linked PDFs to learn internal naming and software versions.
7. **Export** — JSON/CSV outputs feed the engagement's knowledge base and
   the recon section of the final report.

## OPSEC notes

- **Rate limiting.** Default 1 request/second with a shared throttle across
  all modules. Do not raise it against targets where blending in matters;
  do not lower the timeout below source expectations either.
- **User-agent rotation.** Requests rotate across common browser agents.
  Against aggregators this is ordinary traffic; against the target it looks
  like normal browsing.
- **Bounded crawling.** Email/metadata modules fetch at most a handful of
  same-host pages, prioritizing `contact`/`about`-style pages — never a
  crawl, never a wordlist.
- **Source failures are normal.** crt.sh rate-limits aggressively; a failed
  source degrades gracefully (warn & continue) rather than retrying
  aggressively.
- **Data handling.** Treat exported JSON/CSV as engagement-sensitive
  material: store it under the engagement's data-handling rules and purge
  it at engagement closeout.
