//! JSON parser converting CLI `--facts` arguments into `handfest_core::gate::VerifiedFacts`.

use std::fs;
use std::path::Path;

use handfest_core::ast::{
    is_valid_field_path, is_valid_quoted_str, parse_rfc3339_utc, Decimal, Scalar,
};
use handfest_core::gate::VerifiedFacts;
use serde_json::{Map, Value};

pub(crate) fn parse_facts_arg(raw: &str) -> Result<VerifiedFacts, String> {
    let trimmed = raw.trim();
    let json_text = if trimmed.starts_with('{') {
        trimmed.to_string()
    } else if let Some(path) = trimmed.strip_prefix('@') {
        fs::read_to_string(path)
            .map_err(|err| format!("failed to read facts file '{path}': {err}"))?
    } else if Path::new(trimmed).is_file() {
        fs::read_to_string(trimmed)
            .map_err(|err| format!("failed to read facts file '{trimmed}': {err}"))?
    } else {
        trimmed.to_string()
    };

    let parsed: Value =
        serde_json::from_str(&json_text).map_err(|err| format!("invalid facts JSON: {err}"))?;
    let Some(obj) = parsed.as_object() else {
        return Err("facts JSON must be a top-level object".to_string());
    };

    let mut facts = VerifiedFacts::new();
    for (key, value) in obj {
        if !is_valid_field_path(key) {
            return Err(format!("invalid fact field path '{key}'"));
        }
        let scalar = json_value_to_scalar(key, value)?;
        scalar
            .validate()
            .map_err(|err| format!("invalid fact value for '{key}': {err}"))?;
        facts.insert(key.clone(), scalar);
    }
    Ok(facts)
}

fn json_value_to_scalar(field: &str, value: &Value) -> Result<Scalar, String> {
    match value {
        Value::Bool(b) => Ok(Scalar::Bool(*b)),
        Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                Ok(Scalar::Int(i))
            } else {
                let raw = num.to_string();
                let dec = Decimal::parse(&raw).map_err(|err| {
                    format!("fact '{field}': unsupported numeric literal '{raw}': {err}")
                })?;
                Ok(Scalar::Decimal(dec))
            }
        }
        Value::String(s) => {
            if let Ok(ts) = parse_rfc3339_utc(s) {
                Ok(Scalar::Timestamp(ts))
            } else {
                if !is_valid_quoted_str(s) {
                    return Err(format!(
                        "fact '{field}': string must not contain control characters"
                    ));
                }
                Ok(Scalar::Str(s.clone()))
            }
        }
        Value::Object(map) => parse_typed_scalar_object(field, map),
        Value::Null | Value::Array(_) => Err(format!(
            "fact '{field}': unsupported JSON type (expected string, number, bool, or typed scalar object)"
        )),
    }
}

fn parse_typed_scalar_object(field: &str, map: &Map<String, Value>) -> Result<Scalar, String> {
    if map.len() != 1 {
        return Err(format!(
            "fact '{field}': typed scalar object must contain exactly one type key"
        ));
    }
    let (tag, inner) = map.iter().next().expect("checked len == 1");
    match (tag.as_str(), inner) {
        ("str", Value::String(s)) => {
            if !is_valid_quoted_str(s) {
                return Err(format!(
                    "fact '{field}': string must not contain control characters"
                ));
            }
            Ok(Scalar::Str(s.clone()))
        }
        ("timestamp", Value::String(s)) => {
            let ts = parse_rfc3339_utc(s)
                .map_err(|err| format!("fact '{field}': invalid RFC 3339 timestamp: {err}"))?;
            Ok(Scalar::Timestamp(ts))
        }
        ("decimal", Value::String(s)) => {
            let dec = Decimal::parse(s)
                .map_err(|err| format!("fact '{field}': invalid decimal: {err}"))?;
            Ok(Scalar::Decimal(dec))
        }
        ("int", Value::Number(n)) => n
            .as_i64()
            .map(Scalar::Int)
            .ok_or_else(|| format!("fact '{field}': expected 64-bit signed integer")),
        ("bool", Value::Bool(b)) => Ok(Scalar::Bool(*b)),
        _ => Err(format!(
            "fact '{field}': unsupported typed scalar wrapper '{tag}'"
        )),
    }
}
