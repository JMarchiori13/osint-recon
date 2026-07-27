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

    /// Emit results as JSONL on stdout (one JSON object per result) for
    /// composability with jq and other tools. Banner and logs go to stderr.
    #[arg(long, global = true)]
    stdout: bool,

    /// Suppress the authorization banner.
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Passive subdomain enumeration (crt.sh, hackertarget).
    Subdomain {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
    /// DNS records via DNS-over-HTTPS (A, AAAA, MX, NS, TXT).
    Dns {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
    /// Technology fingerprinting from headers and public HTML.
    Tech {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
    /// Email harvesting from the domain's public pages (authorized use only).
    Email {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
    /// Metadata extraction from publicly linked PDF documents.
    Metadata {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
    /// ASN & netblock enumeration (Team Cymru DNS whois over DoH).
    Asn {
        /// Target domain or IPv4 (e.g. example.com, or '-' to read targets from stdin).
        target: String,
    },
    /// Certificate transparency history summary (crt.sh).
    Ct {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
    /// GitHub dorking: public exposure search via the GitHub REST API.
    Ghdork {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
    /// Brazilian context: CNPJ company lookup, CEP resolution, BR dork pack.
    Br {
        #[command(subcommand)]
        command: BrCommands,
    },
    /// Run all modules against the target.
    Full {
        /// Target domain (e.g. example.com, or '-' to read domains from stdin).
        domain: String,
    },
}

/// Subcommands of the Brazilian context module (`br`).
#[derive(Subcommand)]
enum BrCommands {
    /// Brazilian company lookup by CNPJ (BrasilAPI, ReceitaWS fallback).
    Cnpj {
        /// CNPJ with or without punctuation (e.g. 00.000.000/0001-91).
        cnpj: String,
    },
    /// Brazilian postal code (CEP) address resolution (BrasilAPI, ViaCEP fallback).
    Cep {
        /// CEP with or without punctuation (e.g. 01310-100).
        cep: String,
    },
    /// Brazilian OSINT dork pack: ready-to-open Google/Shodan URLs (manual use).
    Dorks {
        /// Target string interpolated into dorks that support it (e.g. exemplo.com.br).
        target: String,
    },
}

/// Print the mandatory authorization banner (stdout normally, stderr when
/// `--stdout` mode must keep stdout clean for JSONL).
fn banner(to_stderr: bool) {
    let lines = [
        "osint-recon — passive OSINT reconnaissance framework"
            .bold()
            .cyan()
            .to_string(),
        "For authorized security assessments only."
            .bold()
            .yellow()
            .to_string(),
        "Passive techniques only: no scanning, no brute force, no credential testing."
            .dimmed()
            .to_string(),
    ];
    for line in lines {
        if to_stderr {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
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

/// Resolve the target argument: a literal value, or `-` to read one target
/// per line from stdin (blank lines and `#` comments are skipped).
fn resolve_targets(arg: &str) -> Result<Vec<String>> {
    if arg != "-" {
        return Ok(vec![arg.to_string()]);
    }
    use std::io::Read as _;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading targets from stdin")?;
    let targets: Vec<String> = buf
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    if targets.is_empty() {
        anyhow::bail!("no targets on stdin (expected one domain per line)");
    }
    Ok(targets)
}

/// Resolve and normalize domain targets. In batch mode (stdin), invalid
/// lines are skipped with a warning instead of aborting the whole run.
fn domains(arg: &str) -> Result<Vec<String>> {
    let raw = resolve_targets(arg)?;
    let single = raw.len() == 1;
    let mut out = Vec::new();
    for r in raw {
        match normalize_domain(&r) {
            Ok(d) => out.push(d),
            Err(e) if single => return Err(e),
            Err(e) => {
                eprintln!("{} skipping invalid target {r:?}: {e:#}", "[warn]".yellow());
            }
        }
    }
    if out.is_empty() {
        anyhow::bail!("no valid targets");
    }
    Ok(out)
}

/// Resolve ASN targets (bare IPv4 allowed in addition to domains).
fn asn_targets(arg: &str) -> Result<Vec<String>> {
    let raw = resolve_targets(arg)?;
    let single = raw.len() == 1;
    let mut out = Vec::new();
    for r in raw {
        let t = r.trim().trim_end_matches('/').to_lowercase();
        let normalized = if t.parse::<std::net::Ipv4Addr>().is_ok() {
            Ok(t)
        } else {
            normalize_domain(&t)
        };
        match normalized {
            Ok(t) => out.push(t),
            Err(e) if single => return Err(e),
            Err(e) => {
                eprintln!("{} skipping invalid target {r:?}: {e:#}", "[warn]".yellow());
            }
        }
    }
    if out.is_empty() {
        anyhow::bail!("no valid targets");
    }
    Ok(out)
}

/// Render results (table or JSONL) and export files.
fn report(cli: &Cli, outputs: &[ModuleOutput]) -> Result<()> {
    if cli.stdout {
        // JSONL mode: machine-readable stdout, humans/logs on stderr.
        for out in outputs {
            output::print_jsonl(out);
        }
    } else {
        let multi = outputs.len() > 1;
        for out in outputs {
            if multi {
                // Label each block when several targets were processed.
                let target = out
                    .json
                    .get("domain")
                    .or_else(|| out.json.get("target"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                println!("{} {}", "==>".bold().magenta(), target.bold());
            }
            output::print_table(out.name, &out.headers, &out.rows);
        }
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
        eprintln!(
            "{} JSON results written to {}",
            "[ok]".green(),
            path.display()
        );
    }

    if let Some(path) = &cli.csv {
        let same_headers = outputs.windows(2).all(|w| w[0].headers == w[1].headers);
        if outputs.len() > 1 && !same_headers {
            eprintln!(
                "{} CSV export needs matching table shapes; skipping for `full` (use per-module runs or --json)",
                "[warn]".yellow()
            );
        } else {
            // Batch runs (stdin) concatenate rows with a leading domain column.
            let (headers, rows) = if outputs.len() > 1 {
                let mut headers = vec!["domain"];
                headers.extend_from_slice(&outputs[0].headers);
                let mut rows = Vec::new();
                for out in outputs {
                    let target = out
                        .json
                        .get("domain")
                        .or_else(|| out.json.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    for row in &out.rows {
                        let mut r = vec![target.clone()];
                        r.extend(row.iter().cloned());
                        rows.push(r);
                    }
                }
                (headers, rows)
            } else {
                (outputs[0].headers.clone(), outputs[0].rows.clone())
            };
            output::write_csv(path, &headers, &rows)?;
            eprintln!(
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
        banner(cli.stdout);
    }

    let client = http::HttpClient::new(cli.timeout, cli.rate, cli.retries)
        .context("initializing HTTP client")?;

    let outputs: Vec<ModuleOutput> = match &cli.command {
        Commands::Subdomain { domain } => domains(domain)?
            .iter()
            .map(|d| modules::subdomains::run(&client, d))
            .collect(),
        Commands::Dns { domain } => domains(domain)?
            .iter()
            .map(|d| modules::dns_records::run(&client, d))
            .collect(),
        Commands::Tech { domain } => domains(domain)?
            .iter()
            .map(|d| modules::tech_fingerprint::run(&client, d))
            .collect(),
        Commands::Email { domain } => domains(domain)?
            .iter()
            .map(|d| modules::emails::run(&client, d))
            .collect(),
        Commands::Metadata { domain } => domains(domain)?
            .iter()
            .map(|d| modules::doc_metadata::run(&client, d))
            .collect(),
        Commands::Asn { target } => asn_targets(target)?
            .iter()
            .map(|t| modules::asn::run(&client, t))
            .collect(),
        Commands::Ct { domain } => domains(domain)?
            .iter()
            .map(|d| modules::ct_history::run(&client, d))
            .collect(),
        Commands::Ghdork { domain } => domains(domain)?
            .iter()
            .map(|d| modules::github_dorks::run(&client, d))
            .collect(),
        // `br` is intentionally NOT part of `full`: it targets Brazilian
        // documents/CEPs, not domains (see docs/modules.md).
        Commands::Br { command } => match command {
            BrCommands::Cnpj { cnpj } => {
                let c = modules::br::cnpj::normalize_cnpj(cnpj)?;
                vec![modules::br::cnpj::run(&client, &c)]
            }
            BrCommands::Cep { cep } => {
                let c = modules::br::cep::normalize_cep(cep)?;
                vec![modules::br::cep::run(&client, &c)]
            }
            BrCommands::Dorks { target } => vec![modules::br::dorks::run(target)],
        },
        Commands::Full { domain } => {
            let mut all = Vec::new();
            for d in domains(domain)? {
                all.extend([
                    modules::subdomains::run(&client, &d),
                    modules::dns_records::run(&client, &d),
                    modules::asn::run(&client, &d),
                    modules::ct_history::run(&client, &d),
                    modules::github_dorks::run(&client, &d),
                    modules::tech_fingerprint::run(&client, &d),
                    modules::emails::run(&client, &d),
                    modules::doc_metadata::run(&client, &d),
                ]);
            }
            all
        }
    };

    report(&cli, &outputs)
}
