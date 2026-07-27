//! Brazilian company lookup by CNPJ (ATT&CK T1591 — Gather Victim Org
//! Information).
//!
//! Sources:
//! 1. **BrasilAPI** `brasilapi.com.br/api/cnpj/v1/<cnpj>` — keyless, generous.
//! 2. **ReceitaWS** `receitaws.com.br/v1/cnpj/<cnpj>` — keyless fallback,
//!    limited to 3 req/min (enforced with a per-source throttle).
//!
//! **LGPD note (Lei 13.709/2018):** CNPJ records are public *business* data.
//! This module never queries personal data (CPF). Partner names appear in
//! the public company record — handle them under the engagement's
//! data-handling rules.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use colored::Colorize;
use serde::Deserialize;
use serde_json::json;

use super::fetch_json;
use crate::http::HttpClient;
use crate::output::ModuleOutput;

/// Minimum interval between ReceitaWS calls (3 req/min → 20 s).
const RECEITAWS_INTERVAL: Duration = Duration::from_secs(20);
static RECEITAWS_LAST: Mutex<Option<Instant>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Strip punctuation (`.`, `/`, `-`) and uppercase a CNPJ, validating the
/// result. Accepts both the classic numeric format and the new alphanumeric
/// format valid since July 2026.
pub fn normalize_cnpj(raw: &str) -> Result<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    validate_cnpj(&cleaned)?;
    Ok(cleaned)
}

/// Validate a normalized (14-char, uppercase) CNPJ.
///
/// - Classic numeric: full mod-11 check-digit validation (rejects typos and
///   repeated-digit sequences).
/// - Alphanumeric (new format, July 2026): format validation — 12
///   alphanumeric base chars + 2 numeric check digits.
pub fn validate_cnpj(c: &str) -> Result<()> {
    if c.len() != 14 {
        bail!(
            "invalid CNPJ {c:?}: expected 14 characters, got {}",
            c.len()
        );
    }
    if !c.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        bail!("invalid CNPJ {c:?}: only letters and digits are allowed");
    }
    let (base, dv) = c.split_at(12);
    if !dv.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid CNPJ {c:?}: the two check digits must be numeric");
    }
    if base.bytes().all(|b| b.is_ascii_digit()) {
        // Classic numeric format → full check-digit validation.
        if c.bytes().all(|b| b == c.as_bytes()[0]) {
            bail!("invalid CNPJ {c:?}: repeated-digit sequences are not valid");
        }
        if !check_digits_ok(c) {
            bail!("invalid CNPJ {c:?}: check digits do not match (mod-11)");
        }
    }
    Ok(())
}

/// Receita's character value for mod-11: ASCII - '0'
/// (works for digits and, per the 2026 alphanumeric spec, letters too).
fn char_value(b: u8) -> u64 {
    (b - b'0') as u64
}

fn mod11(bytes: &[u8], weights: &[u64]) -> u64 {
    let sum: u64 = bytes
        .iter()
        .zip(weights.iter())
        .map(|(b, w)| char_value(*b) * w)
        .sum();
    let rem = sum % 11;
    if rem < 2 {
        0
    } else {
        11 - rem
    }
}

/// Verify both mod-11 check digits of a numeric CNPJ.
fn check_digits_ok(c: &str) -> bool {
    const W1: [u64; 12] = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const W2: [u64; 13] = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let b = c.as_bytes();
    mod11(&b[0..12], &W1) == char_value(b[12]) && mod11(&b[0..13], &W2) == char_value(b[13])
}

// ---------------------------------------------------------------------------
// Shared output shape
// ---------------------------------------------------------------------------

/// Normalized company record (either source maps into this).
#[derive(Default, serde::Serialize)]
struct Company {
    source: String,
    razao_social: String,
    nome_fantasia: String,
    cnae: String,
    situacao: String,
    abertura: String,
    capital_social: String,
    endereco: String,
    socios: Vec<Socio>,
}

#[derive(serde::Serialize)]
struct Socio {
    nome: String,
    qualificacao: String,
}

// ---------------------------------------------------------------------------
// BrasilAPI
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BrasilApiCnpj {
    razao_social: Option<String>,
    nome_fantasia: Option<String>,
    cnae_fiscal: Option<u64>,
    cnae_fiscal_descricao: Option<String>,
    descricao_situacao_cadastral: Option<String>,
    data_inicio_atividade: Option<String>,
    capital_social: Option<f64>,
    descricao_tipo_de_logradouro: Option<String>,
    logradouro: Option<String>,
    numero: Option<String>,
    complemento: Option<String>,
    bairro: Option<String>,
    municipio: Option<String>,
    uf: Option<String>,
    cep: Option<String>,
    #[serde(default)]
    qsa: Vec<BrasilApiSocio>,
}

#[derive(Debug, Deserialize)]
struct BrasilApiSocio {
    nome_socio: Option<String>,
    qualificacao_socio: Option<String>,
}

fn from_brasilapi(c: &BrasilApiCnpj) -> Company {
    let addr = [
        c.descricao_tipo_de_logradouro.as_deref().unwrap_or(""),
        c.logradouro.as_deref().unwrap_or(""),
        c.numero.as_deref().unwrap_or(""),
        c.complemento.as_deref().unwrap_or(""),
        c.bairro.as_deref().unwrap_or(""),
        c.municipio.as_deref().unwrap_or(""),
        c.uf.as_deref().unwrap_or(""),
        c.cep.as_deref().unwrap_or(""),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(", ");
    Company {
        source: "BrasilAPI".to_string(),
        razao_social: c.razao_social.clone().unwrap_or_default(),
        nome_fantasia: c.nome_fantasia.clone().unwrap_or_default(),
        cnae: match (&c.cnae_fiscal, &c.cnae_fiscal_descricao) {
            (Some(code), Some(desc)) => format!("{code} — {desc}"),
            (Some(code), None) => code.to_string(),
            _ => String::new(),
        },
        situacao: c.descricao_situacao_cadastral.clone().unwrap_or_default(),
        abertura: c.data_inicio_atividade.clone().unwrap_or_default(),
        capital_social: c
            .capital_social
            .map(|v| format!("R$ {v:.2}"))
            .unwrap_or_default(),
        endereco: addr,
        socios: c
            .qsa
            .iter()
            .map(|s| Socio {
                nome: s.nome_socio.clone().unwrap_or_default(),
                qualificacao: s.qualificacao_socio.clone().unwrap_or_default(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// ReceitaWS (fallback, 3 req/min)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ReceitaWsCnpj {
    status: Option<String>,
    message: Option<String>,
    nome: Option<String>,
    fantasia: Option<String>,
    #[serde(default)]
    atividade_principal: Vec<ReceitaWsCnae>,
    situacao: Option<String>,
    abertura: Option<String>,
    capital_social: Option<String>,
    logradouro: Option<String>,
    numero: Option<String>,
    complemento: Option<String>,
    bairro: Option<String>,
    municipio: Option<String>,
    uf: Option<String>,
    cep: Option<String>,
    #[serde(default)]
    qsa: Vec<ReceitaWsSocio>,
}

#[derive(Debug, Deserialize)]
struct ReceitaWsCnae {
    code: Option<String>,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReceitaWsSocio {
    nome: Option<String>,
    qual: Option<String>,
}

/// ReceitaWS allows 3 requests/minute — enforce a 20 s per-source interval.
fn throttle_receitaws() {
    let mut last = RECEITAWS_LAST.lock().expect("receitaws mutex poisoned");
    if let Some(prev) = *last {
        let elapsed = prev.elapsed();
        if elapsed < RECEITAWS_INTERVAL {
            let wait = RECEITAWS_INTERVAL - elapsed;
            eprintln!(
                "{} ReceitaWS rate limit (3 req/min) — waiting {:.0}s",
                "[info]".blue(),
                wait.as_secs_f64()
            );
            std::thread::sleep(wait);
        }
    }
    *last = Some(Instant::now());
}

fn from_receitaws(c: &ReceitaWsCnpj) -> Result<Company> {
    if c.status.as_deref() == Some("ERROR") {
        bail!(
            "ReceitaWS: {}",
            c.message
                .clone()
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }
    let addr = [
        c.logradouro.as_deref().unwrap_or(""),
        c.numero.as_deref().unwrap_or(""),
        c.complemento.as_deref().unwrap_or(""),
        c.bairro.as_deref().unwrap_or(""),
        c.municipio.as_deref().unwrap_or(""),
        c.uf.as_deref().unwrap_or(""),
        c.cep.as_deref().unwrap_or(""),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(", ");
    Ok(Company {
        source: "ReceitaWS".to_string(),
        razao_social: c.nome.clone().unwrap_or_default(),
        nome_fantasia: c.fantasia.clone().unwrap_or_default(),
        cnae: c
            .atividade_principal
            .first()
            .map(|a| {
                format!(
                    "{} — {}",
                    a.code.clone().unwrap_or_default(),
                    a.text.clone().unwrap_or_default()
                )
            })
            .unwrap_or_default(),
        situacao: c.situacao.clone().unwrap_or_default(),
        abertura: c.abertura.clone().unwrap_or_default(),
        capital_social: c
            .capital_social
            .as_ref()
            .map(|v| format!("R$ {v}"))
            .unwrap_or_default(),
        endereco: addr,
        socios: c
            .qsa
            .iter()
            .map(|s| Socio {
                nome: s.nome.clone().unwrap_or_default(),
                qualificacao: s.qual.clone().unwrap_or_default(),
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// Module entry
// ---------------------------------------------------------------------------

/// Look up a validated, normalized CNPJ (BrasilAPI, ReceitaWS fallback).
pub fn run(client: &HttpClient, cnpj: &str) -> ModuleOutput {
    let company = match fetch_json::<BrasilApiCnpj>(
        client,
        &format!("https://brasilapi.com.br/api/cnpj/v1/{cnpj}"),
    ) {
        Ok(resp) => from_brasilapi(&resp),
        Err(e) => {
            eprintln!(
                "{} BrasilAPI failed: {e:#} — trying ReceitaWS",
                "[warn]".yellow()
            );
            throttle_receitaws();
            match fetch_json::<ReceitaWsCnpj>(
                client,
                &format!("https://receitaws.com.br/v1/cnpj/{cnpj}"),
            )
            .and_then(|r| from_receitaws(&r))
            {
                Ok(company) => company,
                Err(e2) => {
                    return ModuleOutput {
                        name: "Brazilian company lookup (CNPJ)",
                        json: json!({
                            "module": "br_cnpj",
                            "cnpj": cnpj,
                            "error": format!("BrasilAPI: {e:#}; ReceitaWS: {e2:#}"),
                        }),
                        headers: vec!["Field", "Value"],
                        rows: vec![vec![
                            "error".to_string(),
                            "both sources failed — try again later".to_string(),
                        ]],
                    };
                }
            }
        }
    };

    let mut rows: Vec<Vec<String>> = vec![
        vec!["Razão social".to_string(), company.razao_social.clone()],
        vec!["Nome fantasia".to_string(), company.nome_fantasia.clone()],
        vec!["CNAE".to_string(), company.cnae.clone()],
        vec!["Situação cadastral".to_string(), company.situacao.clone()],
        vec!["Abertura".to_string(), company.abertura.clone()],
        vec!["Capital social".to_string(), company.capital_social.clone()],
        vec!["Endereço".to_string(), company.endereco.clone()],
        vec!["Source".to_string(), company.source.clone()],
    ];
    for (i, s) in company.socios.iter().enumerate() {
        rows.push(vec![
            format!("Sócio {}", i + 1),
            format!("{} — {}", s.nome, s.qualificacao),
        ]);
    }

    ModuleOutput {
        name: "Brazilian company lookup (CNPJ)",
        json: json!({
            "module": "br_cnpj",
            "note": "Public business data (Receita Federal). No personal data (CPF) is handled — LGPD Lei 13.709/2018.",
            "cnpj": cnpj,
            "company": company,
        }),
        headers: vec!["Field", "Value"],
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_numeric_cnpj_with_punctuation() {
        // Banco do Brasil S.A. — classic public test CNPJ.
        assert_eq!(
            normalize_cnpj("00.000.000/0001-91").unwrap(),
            "00000000000191"
        );
        assert!(validate_cnpj("00000000000191").is_ok());
    }

    #[test]
    fn rejects_wrong_check_digits() {
        assert!(validate_cnpj("00000000000192").is_err());
        assert!(validate_cnpj("00000000000111").is_err());
    }

    #[test]
    fn rejects_repeated_digits() {
        assert!(validate_cnpj("11111111111111").is_err());
        assert!(validate_cnpj("00000000000000").is_err());
    }

    #[test]
    fn rejects_bad_lengths_and_characters() {
        assert!(validate_cnpj("0000000000191").is_err()); // 13 chars
        assert!(validate_cnpj("000000000001911").is_err()); // 15 chars
        assert!(validate_cnpj("0000000000019A").is_err()); // letter in check digits
        assert!(validate_cnpj("").is_err());
    }

    #[test]
    fn accepts_new_alphanumeric_format() {
        // New CNPJ format valid since July 2026: 12 alnum + 2 numeric DV.
        assert!(validate_cnpj("A1B2C3D4E5F607").is_ok());
        assert_eq!(
            normalize_cnpj("a1.b2c.3d4/e5f6-07").unwrap(),
            "A1B2C3D4E5F607"
        );
    }

    #[test]
    fn parses_brasilapi_response() {
        let body = r#"{
            "cnpj": "00000000000191",
            "razao_social": "BANCO DO BRASIL SA",
            "nome_fantasia": "DIRECAO GERAL",
            "cnae_fiscal": 6422100,
            "cnae_fiscal_descricao": "Bancos múltiplos, com carteira comercial",
            "descricao_situacao_cadastral": "ATIVA",
            "data_inicio_atividade": "1966-08-01",
            "capital_social": 90000000000.0,
            "descricao_tipo_de_logradouro": "QUADRA",
            "logradouro": "SAUN Q 5 L B",
            "numero": "SN",
            "bairro": "ASA NORTE",
            "municipio": "BRASILIA",
            "uf": "DF",
            "cep": "70040912",
            "qsa": [{"nome_socio": "FAUSTO DE ANDRADE RIBEIRO",
                     "qualificacao_socio": "Presidente"}]
        }"#;
        let parsed: BrasilApiCnpj = serde_json::from_str(body).unwrap();
        let company = from_brasilapi(&parsed);
        assert_eq!(company.razao_social, "BANCO DO BRASIL SA");
        assert!(company.cnae.contains("Bancos múltiplos"));
        assert_eq!(company.socios.len(), 1);
        assert!(company.endereco.contains("BRASILIA"));
        assert_eq!(company.source, "BrasilAPI");
    }

    #[test]
    fn parses_receitaws_response_and_error() {
        let body = r#"{
            "status": "OK",
            "nome": "BANCO DO BRASIL SA",
            "fantasia": "DIRECAO GERAL",
            "atividade_principal": [{"code": "64.22-1-00", "text": "Bancos múltiplos"}],
            "situacao": "ATIVA",
            "abertura": "01/08/1966",
            "capital_social": "90000000000.00",
            "logradouro": "QUADRA SAUN Q 5 L B",
            "municipio": "BRASILIA",
            "uf": "DF",
            "qsa": [{"nome": "FAUSTO DE ANDRADE RIBEIRO", "qual": "Presidente"}]
        }"#;
        let parsed: ReceitaWsCnpj = serde_json::from_str(body).unwrap();
        let company = from_receitaws(&parsed).unwrap();
        assert_eq!(company.razao_social, "BANCO DO BRASIL SA");
        assert_eq!(company.source, "ReceitaWS");

        let err: ReceitaWsCnpj =
            serde_json::from_str(r#"{"status":"ERROR","message":"CNPJ inválido"}"#).unwrap();
        assert!(from_receitaws(&err).is_err());
    }
}
