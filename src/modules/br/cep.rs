//! Brazilian postal code (CEP) address resolution (ATT&CK T1591).
//!
//! Sources: BrasilAPI `cep/v2` (includes coordinates when available),
//! ViaCEP fallback (keyless, no official limit). Public addressing data only.

use anyhow::{bail, Result};
use colored::Colorize;
use serde::Deserialize;
use serde_json::json;

use super::fetch_json;
use crate::http::HttpClient;
use crate::output::ModuleOutput;

/// Strip punctuation and validate a CEP (exactly 8 digits).
pub fn normalize_cep(raw: &str) -> Result<String> {
    let cleaned: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() != 8 {
        bail!(
            "invalid CEP {raw:?}: expected 8 digits, got {}",
            cleaned.len()
        );
    }
    Ok(cleaned)
}

#[derive(Debug, Deserialize)]
struct BrasilApiCep {
    state: Option<String>,
    city: Option<String>,
    neighborhood: Option<String>,
    street: Option<String>,
    location: Option<BrasilApiLocation>,
}

#[derive(Debug, Deserialize)]
struct BrasilApiLocation {
    coordinates: Option<BrasilApiCoords>,
}

#[derive(Debug, Deserialize)]
struct BrasilApiCoords {
    longitude: Option<String>,
    latitude: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ViaCep {
    logradouro: Option<String>,
    bairro: Option<String>,
    localidade: Option<String>,
    uf: Option<String>,
    erro: Option<bool>,
}

/// Normalized address record.
#[derive(Default, serde::Serialize)]
struct Address {
    source: String,
    street: String,
    district: String,
    city: String,
    state: String,
    latitude: String,
    longitude: String,
}

/// Resolve a validated, normalized CEP (BrasilAPI v2, ViaCEP fallback).
pub fn run(client: &HttpClient, cep: &str) -> ModuleOutput {
    let address = match fetch_json::<BrasilApiCep>(
        client,
        &format!("https://brasilapi.com.br/api/cep/v2/{cep}"),
    ) {
        Ok(resp) => {
            let coords = resp.location.and_then(|l| l.coordinates);
            Address {
                source: "BrasilAPI".to_string(),
                street: resp.street.unwrap_or_default(),
                district: resp.neighborhood.unwrap_or_default(),
                city: resp.city.unwrap_or_default(),
                state: resp.state.unwrap_or_default(),
                latitude: coords
                    .as_ref()
                    .and_then(|c| c.latitude.clone())
                    .unwrap_or_default(),
                longitude: coords
                    .as_ref()
                    .and_then(|c| c.longitude.clone())
                    .unwrap_or_default(),
            }
        }
        Err(e) => {
            eprintln!(
                "{} BrasilAPI failed: {e:#} — trying ViaCEP",
                "[warn]".yellow()
            );
            match fetch_json::<ViaCep>(client, &format!("https://viacep.com.br/ws/{cep}/json/")) {
                Ok(resp) if resp.erro != Some(true) => Address {
                    source: "ViaCEP".to_string(),
                    street: resp.logradouro.unwrap_or_default(),
                    district: resp.bairro.unwrap_or_default(),
                    city: resp.localidade.unwrap_or_default(),
                    state: resp.uf.unwrap_or_default(),
                    ..Default::default()
                },
                Ok(_) | Err(_) => {
                    return ModuleOutput {
                        name: "Brazilian address resolution (CEP)",
                        json: json!({
                            "module": "br_cep",
                            "cep": cep,
                            "error": "CEP not found at either source",
                        }),
                        headers: vec!["Field", "Value"],
                        rows: vec![vec![
                            "error".to_string(),
                            "CEP not found at either source".to_string(),
                        ]],
                    };
                }
            }
        }
    };

    let rows: Vec<Vec<String>> = [
        ("Street", address.street.clone()),
        ("District", address.district.clone()),
        ("City", address.city.clone()),
        ("State", address.state.clone()),
        ("Latitude", address.latitude.clone()),
        ("Longitude", address.longitude.clone()),
        ("Source", address.source.clone()),
    ]
    .into_iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| vec![k.to_string(), v])
    .collect();

    ModuleOutput {
        name: "Brazilian address resolution (CEP)",
        json: json!({
            "module": "br_cep",
            "cep": cep,
            "address": address,
        }),
        headers: vec!["Field", "Value"],
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_cep_formats() {
        assert_eq!(normalize_cep("01310-100").unwrap(), "01310100");
        assert_eq!(normalize_cep("01310100").unwrap(), "01310100");
        assert!(normalize_cep("0131010").is_err()); // 7 digits
        assert!(normalize_cep("013101000").is_err()); // 9 digits
        assert!(normalize_cep("").is_err());
    }

    #[test]
    fn parses_brasilapi_cep_with_coordinates() {
        let body = r#"{
            "cep": "01310100",
            "state": "SP",
            "city": "São Paulo",
            "neighborhood": "Bela Vista",
            "street": "Avenida Paulista",
            "location": {"coordinates": {"longitude": "-46.65639", "latitude": "-23.56309"}}
        }"#;
        let parsed: BrasilApiCep = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.street.as_deref(), Some("Avenida Paulista"));
        let coords = parsed.location.and_then(|l| l.coordinates).unwrap();
        assert_eq!(coords.latitude.as_deref(), Some("-23.56309"));
    }

    #[test]
    fn parses_viacep_response_and_not_found() {
        let body = r#"{
            "cep": "01310-100",
            "logradouro": "Avenida Paulista",
            "complemento": "",
            "bairro": "Bela Vista",
            "localidade": "São Paulo",
            "uf": "SP"
        }"#;
        let parsed: ViaCep = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.logradouro.as_deref(), Some("Avenida Paulista"));
        assert_ne!(parsed.erro, Some(true));

        let not_found: ViaCep = serde_json::from_str(r#"{"erro": true}"#).unwrap();
        assert_eq!(not_found.erro, Some(true));
    }
}
