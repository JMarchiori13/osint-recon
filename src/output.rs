//! Result export (JSON / CSV) and formatted console tables.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

/// Ensure the parent directory of `path` exists before writing.
fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }
    Ok(())
}

/// Uniform result container produced by every recon module.
///
/// `json` carries the full structured result; `headers`/`rows` drive both the
/// console table and CSV export.
pub struct ModuleOutput {
    /// Human-readable module name.
    pub name: &'static str,
    /// Full structured result for JSON export.
    pub json: serde_json::Value,
    /// Column headers for table/CSV rendering.
    pub headers: Vec<&'static str>,
    /// Data rows aligned with `headers`.
    pub rows: Vec<Vec<String>>,
}

/// Serialize a value as pretty JSON to `path`.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    ensure_parent(path)?;
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .with_context(|| format!("writing JSON to {}", path.display()))?;
    Ok(())
}

/// Write rows as CSV with the given headers.
pub fn write_csv(path: &Path, headers: &[&str], rows: &[Vec<String>]) -> Result<()> {
    ensure_parent(path)?;
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut wtr = csv::Writer::from_writer(file);
    wtr.write_record(headers).context("writing CSV header")?;
    for row in rows {
        wtr.write_record(row).context("writing CSV row")?;
    }
    wtr.flush().context("flushing CSV writer")?;
    Ok(())
}

/// Render a simple aligned console table with a colored header.
pub fn print_table(title: &str, headers: &[&str], rows: &[Vec<String>]) {
    println!("\n{}", title.bold().cyan());
    println!("{}", "-".repeat(title.len()).dimmed());

    if rows.is_empty() {
        println!("{}", "(no results)".dimmed());
        return;
    }

    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count().min(80));
            }
        }
    }

    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<w$}", h, w = widths[i]))
        .collect();
    println!("{}", header_line.join("  ").bold());
    println!(
        "{}",
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  ")
            .dimmed()
    );

    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let truncated = if cell.chars().count() > 80 {
                    let t: String = cell.chars().take(77).collect();
                    format!("{t}...")
                } else {
                    cell.clone()
                };
                format!(
                    "{:<w$}",
                    truncated,
                    w = widths.get(i).copied().unwrap_or(10)
                )
            })
            .collect();
        println!("{}", line.join("  "));
    }
    println!("{} {} row(s)", "->".dimmed(), rows.len());
}
