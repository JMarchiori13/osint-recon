//! Passive reconnaissance modules.
//!
//! Every module uses **passive techniques only**: public keyless APIs,
//! DNS-over-HTTPS lookups and plain GET requests to already-public pages.
//! No port scanning, no brute forcing, no credential testing.

pub mod asn;
pub mod crtsh;
pub mod ct_history;
pub mod dns_records;
pub mod doc_metadata;
pub mod emails;
pub mod github_dorks;
pub mod subdomains;
pub mod tech_fingerprint;
