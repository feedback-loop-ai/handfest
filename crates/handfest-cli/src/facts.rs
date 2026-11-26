//! Exact JSON parser converting CLI `--facts` arguments into `handfest_core::gate::VerifiedFacts`.
//!
//! Numeric literals are lexed directly from raw JSON tokens without routing through IEEE-754 `f64`,
//! preserving exact base-10 fixed-point precision up to `handfest_core::ast::MAX_DECIMAL_SCALE`.

use std::collections::BTreeMap;
use std::fs;

use handfest_core::ast::{is_valid_field_path, is_valid_quoted_str, parse_rfc3339_utc, Scalar};
use handfest_core::exact_json::{parse_exact_json_with_max_depth, ExactJson};
use handfest_core::gate::VerifiedFacts;
use handfest_core::json_num::{parse_canonical_json_int, parse_decimal_str, parse_json_decimal};

const MAX_JSON_DEPTH: usize = 16;

pub(crate) fn parse_facts_arg(raw: &str) -> Result<VerifiedFacts, String> {
    let trimmed = raw.trim();
    let json_text = if trimmed.starts_with('{') {
        trimmed.to_string()
    } else if let Some(path) = trimmed.strip_prefix('@') {
        fs::read_to_string(path)
            .map_err(|err| format!("failed to read facts file '{path}': {err}"))?
    } else if fs::metadata(trimmed).is_ok() {
        fs::read_to_string(trimmed)
            .map_err(|err| format!("failed to read facts file '{trimmed}': {err}"))?
    } else {
        trimmed.to_string()
    };

    let parsed = parse_exact_json_with_max_depth(&json_text, MAX_JSON_DEPTH)
        .map_err(|err| format!("invalid facts JSON: {err}"))?;
    let ExactJson::Object(entries) = parsed else {
        return Err("facts JSON must be a top-level object".to_string());
    };

    let mut facts = VerifiedFacts::new();
    for (key, value) in entries {
        if !is_valid_field_path(&key) {
            return Err(format!("invalid fact field path '{key}'"));
        }
        let scalar = json_value_to_scalar(&key, &value)?;
        scalar
            .validate()
            .map_err(|err| format!("invalid fact value for '{key}': {err}"))?;
        facts.insert(key, scalar);
    }
    Ok(facts)
}

fn json_value_to_scalar(field: &str, value: &ExactJson) -> Result<Scalar, String> {
    match value {
        ExactJson::Bool(b) => Ok(Scalar::Bool(*b)),
        ExactJson::Number(raw) => parse_exact_json_number(field, raw),
        ExactJson::Str(s) => {
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
        ExactJson::Object(entries) => parse_typed_scalar_object(field, entries),
        ExactJson::Null | ExactJson::Array(_) => Err(format!(
            "fact '{field}': unsupported JSON type (expected string, number, bool, or typed scalar object)"
        )),
    }
}

fn parse_typed_scalar_object(
    field: &str,
    entries: &BTreeMap<String, ExactJson>,
) -> Result<Scalar, String> {
    if entries.len() != 1 {
        return Err(format!(
            "fact '{field}': typed scalar object must contain exactly one type key"
        ));
    }
    let Some((tag, inner)) = entries.iter().next() else {
        return Err(format!(
            "fact '{field}': typed scalar object must contain exactly one type key"
        ));
    };
    match (tag.as_str(), inner) {
        ("str", ExactJson::Str(s)) => {
            if !is_valid_quoted_str(s) {
                return Err(format!(
                    "fact '{field}': string must not contain control characters"
                ));
            }
            Ok(Scalar::Str(s.clone()))
        }
        ("timestamp", ExactJson::Str(s)) => {
            let ts = parse_rfc3339_utc(s)
                .map_err(|err| format!("fact '{field}': invalid RFC 3339 timestamp: {err}"))?;
            Ok(Scalar::Timestamp(ts))
        }
        ("decimal", ExactJson::Str(s)) => {
            let dec = parse_decimal_str(s)
                .map_err(|err| format!("fact '{field}': invalid decimal: {err}"))?;
            Ok(Scalar::Decimal(dec))
        }
        ("int", ExactJson::Number(raw)) => parse_canonical_json_int(raw)
            .map(Scalar::Int)
            .ok_or_else(|| format!("fact '{field}': expected 64-bit signed integer")),
        ("bool", ExactJson::Bool(b)) => Ok(Scalar::Bool(*b)),
        _ => Err(format!(
            "fact '{field}': unsupported typed scalar wrapper '{tag}'"
        )),
    }
}

fn parse_exact_json_number(field: &str, raw: &str) -> Result<Scalar, String> {
    if !raw.contains(['.', 'e', 'E']) {
        return parse_canonical_json_int(raw)
            .map(Scalar::Int)
            .ok_or_else(|| {
                format!("fact '{field}': invalid or out-of-range 64-bit signed integer '{raw}'")
            });
    }
    let dec = parse_json_decimal(raw)
        .map_err(|err| format!("fact '{field}': unsupported numeric literal '{raw}': {err}"))?;
    Ok(Scalar::Decimal(dec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use handfest_core::ast::Decimal;

    #[test]
    fn plain_decimals_with_redundant_trailing_zeros_match_scientific_spelling() {
        let plain =
            parse_facts_arg(r#"{"resource.amount": 1.500000000000000000000000000000}"#).unwrap();
        let sci =
            parse_facts_arg(r#"{"resource.amount": 1.500000000000000000000000000000e0}"#).unwrap();
        let expected = Scalar::Decimal(Decimal::parse("1.5").unwrap());
        assert_eq!(plain.get("resource.amount"), Some(&expected));
        assert_eq!(sci.get("resource.amount"), Some(&expected));

        let zero =
            parse_facts_arg(r#"{"resource.amount": 0.000000000000000000000000000000}"#).unwrap();
        assert_eq!(
            zero.get("resource.amount"),
            Some(&Scalar::Decimal(Decimal::ZERO))
        );

        let hundred =
            parse_facts_arg(r#"{"resource.amount": 100.000000000000000000000000000000}"#).unwrap();
        assert_eq!(
            hundred.get("resource.amount"),
            Some(&Scalar::Decimal(Decimal::parse("100.0").unwrap()))
        );

        let tiny_plain = parse_facts_arg(r#"{"resource.amount": 0.00000001}"#).unwrap();
        let tiny_sci = parse_facts_arg(r#"{"resource.amount": 1e-8}"#).unwrap();
        let expected_tiny = Scalar::Decimal(Decimal::parse("0.00000001").unwrap());
        assert_eq!(tiny_plain.get("resource.amount"), Some(&expected_tiny));
        assert_eq!(tiny_sci.get("resource.amount"), Some(&expected_tiny));

        let err =
            parse_facts_arg(r#"{"resource.amount": 0.00000000000000000000000000001}"#).unwrap_err();
        assert!(err.contains("exceeds maximum"), "unexpected error: {err}");
    }

    #[test]
    fn zero_significand_with_huge_exponent_parses_as_exact_zero() {
        for raw in [
            r#"{"resource.amount": 0e2147483648}"#,
            r#"{"resource.amount": 0.0e-2147483649}"#,
            r#"{"resource.amount": 0.000e+999999999999999999999999}"#,
        ] {
            let parsed = parse_facts_arg(raw).unwrap();
            assert_eq!(
                parsed.get("resource.amount"),
                Some(&Scalar::Decimal(Decimal::ZERO)),
                "expected exact Decimal::ZERO for {raw}"
            );
        }

        let err = parse_facts_arg(r#"{"resource.amount": 1e2147483648}"#).unwrap_err();
        assert!(
            err.contains("overflow") || err.contains("out of range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_negative_zero_and_leading_zero_integers_and_decimals_consistently() {
        for raw in [
            r#"{"mode":{"int":-0}}"#,
            r#"{"mode":-0}"#,
            r#"{"amount":-0.0}"#,
            r#"{"amount":-0e5}"#,
            r#"{"amount":-0.000e+999999999999999999999999}"#,
            r#"{"amount":{"decimal":"-0"}}"#,
            r#"{"amount":{"decimal":"-0.00"}}"#,
            r#"{"amount":{"decimal":"010"}}"#,
            r#"{"amount":{"decimal":"0100"}}"#,
            r#"{"amount":{"decimal":"-010"}}"#,
        ] {
            assert!(
                parse_facts_arg(raw).is_err(),
                "CLI facts parser must reject non-canonical literal in {raw}"
            );
        }

        let ok = parse_facts_arg(r#"{"mode":0,"wrapped":{"int":0},"dec":{"decimal":"0.00"}}"#)
            .expect("canonical zeros must be accepted");
        assert_eq!(ok.get("mode"), Some(&Scalar::Int(0)));
        assert_eq!(ok.get("wrapped"), Some(&Scalar::Int(0)));
        assert_eq!(ok.get("dec"), Some(&Scalar::Decimal(Decimal::ZERO)));
    }

    #[test]
    fn rejects_duplicate_keys_everywhere_including_objects_inside_arrays() {
        for raw in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":{"str":"x","str":"y"}}"#,
            r#"{"a":[{"k":1,"k":2}]}"#,
        ] {
            let err = parse_facts_arg(raw).unwrap_err();
            assert!(
                err.contains("duplicate JSON object key"),
                "expected duplicate JSON object key error for {raw}, got {err}"
            );
        }
    }
}
