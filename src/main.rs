//! osint-recon — a passive OSINT reconnaissance framework in Rust for
//! authorized red team engagements.
//!
//! **For authorized security assessments only.** All techniques are passive:
//! keyless public data sources, DNS-over-HTTPS and plain GET requests to
//! already-public pages. No port scanning, no brute forcing, no credential
//! testing.

mod http;
mod modules;
mod output;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use output::ModuleOutput;
use serde_json::json;

/// Passive OSINT reconnaissance framework — authorized use only.
#[derive(Parser)]
#[command(
    name = "osint-recon",
    version,
    about = "Passive OSINT reconnaissance framework for authorized red team engagements",
    long_about = "osint-recon performs PASSIVE reconnaissance only: certificate transparency, \
                  DNS-over-HTTPS, keyless public APIs and plain GET requests to public pages. \
                  For authorized security assessments only."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Politeness rate limit in requests per second.
    #[arg(long, global = true, default_value_t = 1.0)]
    rate: f64,

    /// Per-request timeout in seconds.
    #[arg(long, global = true, default_value_t = 15)]
    timeout: u64,

    /// Number of retries per request after the initial attempt.
    #[arg(long, global = true, default_value_t = 2)]
    retries: usize,

    /// Export results as JSON to this path.
    #[arg(long, global = true, value_name = "FILE")]
    json: Option<PathBuf>,

    /// Export results as CSV to this path.
    #[arg(long, global = true, value_name = "FILE")]
    csv: Option<PathBuf>,

    /// Suppress the authorization banner.
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Passive subdomain enumeration (crt.sh, hackertarget).
    Subdomain {
        /// Target domain (e.g. example.com).
        domain: String,
    },
    /// DNS records via DNS-over-HTTPS (A, AAAA, MX, NS, TXT).
    Dns {
        /// Target domain (e.g. example.com).
        domain: String,
    },
    /// Technology fingerprinting from headers and public HTML.
    Tech {
        /// Target domain (e.g. example.com).
        domain: String,
    },
    /// Email harvesting from the domain's public pages (authorized use only).
    Email {
        /// Target domain (e.g. example.com).
        domain: String,
    },
    /// Metadata extraction from publicly linked PDF documents.
    Metadata {
        /// Target domain (e.g. example.com).
        domain: String,
    },
    /// ASN & netblock enumeration (Team Cymru DNS whois over DoH).
    Asn {
        /// Target domain or IPv4 address (e.g. example.com or 93.184.215.14).
        target: String,
    },
    /// Certificate transparency history summary (crt.sh).
    Ct {
        /// Target domain (e.g. example.com).
        domain: String,
    },
    /// Run all modules against the target.
    Full {
        /// Target domain (e.g. example.com).
        domain: String,
    },
}

/// Print the mandatory authorization banner.
fn banner() {
    println!(
        "{}",
        "osint-recon — passive OSINT reconnaissance framework"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "For authorized security assessments only.".bold().yellow()
    );
    println!(
        "{}",
        "Passive techniques only: no scanning, no brute force, no credential testing.".dimmed()
    );
}

/// Validate that a target looks like a bare domain (not a URL or IP+port).
fn normalize_domain(raw: &str) -> Result<String> {
    let d = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_lowercase();
    if d.is_empty()
        || d.contains('/')
        || d.contains(':')
        || d.contains('@')
        || d.chars().any(char::is_whitespace)
    {
        anyhow::bail!("invalid target {raw:?}: provide a bare domain such as example.com");
    }
    Ok(d)
}

/// Render results to the console and export files.
fn report(cli: &Cli, outputs: &[ModuleOutput]) -> Result<()> {
    for out in outputs {
        output::print_table(out.name, &out.headers, &out.rows);
    }

    if let Some(path) = &cli.json {
        let bundle = if outputs.len() == 1 {
            outputs[0].json.clone()
        } else {
            json!({
                "tool": "osint-recon",
                "version": env!("CARGO_PKG_VERSION"),
                "modules": outputs.iter().map(|o| &o.json).collect::<Vec<_>>(),
            })
        };
        output::write_json(path, &bundle)?;
        println!(
            "{} JSON results written to {}",
            "[ok]".green(),
            path.display()
        );
    }

    if let Some(path) = &cli.csv {
        if outputs.len() > 1 {
            eprintln!(
                "{} CSV export supports one module at a time; skipping for `full` (use per-module runs or --json)",
                "[warn]".yellow()
            );
        } else {
            let out = &outputs[0];
            output::write_csv(path, &out.headers, &out.rows)?;
            println!(
                "{} CSV results written to {}",
                "[ok]".green(),
                path.display()
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.quiet {
        banner();
    }

    let client = http::HttpClient::new(cli.timeout, cli.rate, cli.retries)
        .context("initializing HTTP client")?;

    let outputs: Vec<ModuleOutput> = match &cli.command {
        Commands::Subdomain { domain } => {
            let d = normalize_domain(domain)?;
            vec![modules::subdomains::run(&client, &d)]
        }
        Commands::Dns { domain } => {
            let d = normalize_domain(domain)?;
            vec![modules::dns_records::run(&client, &d)]
        }
        Commands::Tech { domain } => {
            let d = normalize_domain(domain)?;
            vec![modules::tech_fingerprint::run(&client, &d)]
        }
        Commands::Email { domain } => {
            let d = normalize_domain(domain)?;
            vec![modules::emails::run(&client, &d)]
        }
        Commands::Metadata { domain } => {
            let d = normalize_domain(domain)?;
            vec![modules::doc_metadata::run(&client, &d)]
        }
        Commands::Asn { target } => {
            let t = target.trim().trim_end_matches('/').to_lowercase();
            // Accept a bare IPv4 address directly; otherwise validate as domain.
            let t = if t.parse::<std::net::Ipv4Addr>().is_ok() {
                t
            } else {
                normalize_domain(&t)?
            };
            vec![modules::asn::run(&client, &t)]
        }
        Commands::Ct { domain } => {
            let d = normalize_domain(domain)?;
            vec![modules::ct_history::run(&client, &d)]
        }
        Commands::Full { domain } => {
            let d = normalize_domain(domain)?;
            vec![
                modules::subdomains::run(&client, &d),
                modules::dns_records::run(&client, &d),
                modules::asn::run(&client, &d),
                modules::ct_history::run(&client, &d),
                modules::tech_fingerprint::run(&client, &d),
                modules::emails::run(&client, &d),
                modules::doc_metadata::run(&client, &d),
            ]
        }
    };

    report(&cli, &outputs)
}
