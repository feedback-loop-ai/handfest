//! Exact JSON parser converting CLI `--facts` arguments into `handfest_core::gate::VerifiedFacts`.
//!
//! Numeric literals are lexed directly from raw JSON tokens without routing through IEEE-754 `f64`,
//! preserving exact base-10 fixed-point precision up to `handfest_core::ast::MAX_DECIMAL_SCALE`.

use std::collections::BTreeSet;
use std::fs;

use handfest_core::ast::{
    is_valid_field_path, is_valid_quoted_str, parse_rfc3339_utc, Decimal, Scalar, MAX_DECIMAL_SCALE,
};
use handfest_core::gate::VerifiedFacts;

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

    let parsed =
        parse_exact_json(&json_text).map_err(|err| format!("invalid facts JSON: {err}"))?;
    let ExactJson::Object(entries) = parsed else {
        return Err("facts JSON must be a top-level object".to_string());
    };

    let mut seen_keys = BTreeSet::new();
    let mut facts = VerifiedFacts::new();
    for (key, value) in entries {
        if !seen_keys.insert(key.clone()) {
            return Err(format!("duplicate fact key '{key}' in facts JSON"));
        }
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
        ExactJson::Null | ExactJson::Array => Err(format!(
            "fact '{field}': unsupported JSON type (expected string, number, bool, or typed scalar object)"
        )),
    }
}

fn parse_typed_scalar_object(
    field: &str,
    entries: &[(String, ExactJson)],
) -> Result<Scalar, String> {
    if entries.len() != 1 {
        return Err(format!(
            "fact '{field}': typed scalar object must contain exactly one type key"
        ));
    }
    let (tag, inner) = &entries[0];
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
            let dec = Decimal::parse(s)
                .map_err(|err| format!("fact '{field}': invalid decimal: {err}"))?;
            Ok(Scalar::Decimal(dec))
        }
        ("int", ExactJson::Number(raw)) => {
            if raw.contains(['.', 'e', 'E']) {
                return Err(format!("fact '{field}': expected 64-bit signed integer"));
            }
            raw.parse::<i64>()
                .map(Scalar::Int)
                .map_err(|_| format!("fact '{field}': expected 64-bit signed integer"))
        }
        ("bool", ExactJson::Bool(b)) => Ok(Scalar::Bool(*b)),
        _ => Err(format!(
            "fact '{field}': unsupported typed scalar wrapper '{tag}'"
        )),
    }
}

fn parse_exact_json_number(field: &str, raw: &str) -> Result<Scalar, String> {
    if !raw.contains(['.', 'e', 'E']) {
        return raw
            .parse::<i64>()
            .map(Scalar::Int)
            .map_err(|_| format!("fact '{field}': integer '{raw}' outside 64-bit signed range"));
    }
    let dec = parse_json_decimal(raw)
        .map_err(|err| format!("fact '{field}': unsupported numeric literal '{raw}': {err}"))?;
    Ok(Scalar::Decimal(dec))
}

fn parse_json_decimal(raw: &str) -> Result<Decimal, String> {
    let (mant_part, exp_str) = match raw.find(['e', 'E']) {
        Some(exp_pos) => {
            let (m, exp_part) = raw.split_at(exp_pos);
            let exp_str = &exp_part[1..];
            let exp_digits = exp_str.strip_prefix(['+', '-']).unwrap_or(exp_str);
            if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("invalid exponent '{exp_str}'"));
            }
            (m, Some(exp_str))
        }
        None => (raw, None),
    };

    let (neg, unsigned_mant) = match mant_part.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mant_part),
    };
    let (int_digits, frac_digits) = match unsigned_mant.split_once('.') {
        Some((i, f)) => (i, f),
        None => (unsigned_mant, ""),
    };

    let mut digits = String::with_capacity(int_digits.len() + frac_digits.len());
    digits.push_str(int_digits);
    digits.push_str(frac_digits);
    let trimmed_leading = digits.trim_start_matches('0');
    if trimmed_leading.is_empty() {
        return Ok(Decimal::ZERO);
    }

    let exp: i64 = match exp_str {
        Some(s) => s
            .parse()
            .map_err(|_| format!("exponent '{s}' out of range"))?,
        None => 0i64,
    };

    let frac_len =
        i64::try_from(frac_digits.len()).map_err(|_| "fractional length overflow".to_string())?;
    let trimmed = trimmed_leading.trim_end_matches('0');
    let trailing_zeros = i64::try_from(trimmed_leading.len() - trimmed.len())
        .map_err(|_| "trailing zero count overflow".to_string())?;
    let net_exp = exp
        .checked_sub(frac_len)
        .and_then(|v| v.checked_add(trailing_zeros))
        .ok_or_else(|| "decimal exponent overflow".to_string())?;

    let mut acc: u128 = 0;
    for b in trimmed.bytes() {
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add(u128::from(b - b'0')))
            .ok_or_else(|| "decimal overflow".to_string())?;
    }

    let scale = if net_exp >= 0 {
        if net_exp > 39 {
            return Err("decimal overflow".to_string());
        }
        for _ in 0..net_exp {
            acc = acc
                .checked_mul(10)
                .ok_or_else(|| "decimal overflow".to_string())?;
        }
        0u8
    } else {
        let neg_exp = net_exp
            .checked_neg()
            .ok_or_else(|| "decimal scale overflow".to_string())?;
        if neg_exp > i64::from(MAX_DECIMAL_SCALE) {
            return Err(format!(
                "scale {neg_exp} exceeds maximum {MAX_DECIMAL_SCALE}"
            ));
        }
        u8::try_from(neg_exp).map_err(|_| "decimal scale overflow".to_string())?
    };

    let mantissa = signed_from_u128(neg, acc).ok_or_else(|| "decimal overflow".to_string())?;
    Decimal::new(mantissa, scale)
        .map(|d| d.canonical())
        .map_err(|err| err.to_string())
}

fn signed_from_u128(neg: bool, abs: u128) -> Option<i128> {
    if !neg {
        i128::try_from(abs).ok()
    } else if abs == (i128::MAX as u128) + 1 {
        Some(i128::MIN)
    } else {
        i128::try_from(abs).ok().map(|v| -v)
    }
}

enum ExactJson {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array,
    Object(Vec<(String, ExactJson)>),
}

fn parse_exact_json(src: &str) -> Result<ExactJson, String> {
    let mut parser = JsonParser {
        src,
        bytes: src.as_bytes(),
        pos: 0,
    };
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing characters at byte {}", parser.pos));
    }
    Ok(val)
}

struct JsonParser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<ExactJson, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting depth exceeded".to_string());
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(ExactJson::Str),
            Some(b't') => self.expect_literal(b"true", ExactJson::Bool(true)),
            Some(b'f') => self.expect_literal(b"false", ExactJson::Bool(false)),
            Some(b'n') => self.expect_literal(b"null", ExactJson::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(ExactJson::Number),
            Some(other) => Err(format!(
                "unexpected byte 0x{other:02x} at offset {}",
                self.pos
            )),
            None => Err("unexpected end of JSON input".to_string()),
        }
    }

    fn expect_literal(&mut self, lit: &[u8], value: ExactJson) -> Result<ExactJson, String> {
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(format!("invalid JSON literal at offset {}", self.pos))
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<ExactJson, String> {
        self.pos += 1;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(ExactJson::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected string key at offset {}", self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at offset {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(ExactJson::Object(entries));
                }
                _ => return Err(format!("expected ',' or '}}' at offset {}", self.pos)),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<ExactJson, String> {
        self.pos += 1;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(ExactJson::Array);
        }
        loop {
            let _ = self.parse_value(depth)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(ExactJson::Array);
                }
                _ => return Err(format!("expected ',' or ']' at offset {}", self.pos)),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        let start = self.pos;
        self.pos += 1;
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'\\' => {
                    self.pos += 2;
                    if self.pos > self.bytes.len() {
                        return Err("unterminated escape sequence in JSON string".to_string());
                    }
                }
                b'"' => {
                    self.pos += 1;
                    let slice = &self.src[start..self.pos];
                    return serde_json::from_str::<String>(slice)
                        .map_err(|err| format!("invalid JSON string: {err}"));
                }
                _ => self.pos += 1,
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_number(&mut self) -> Result<String, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(format!("leading zero in JSON number at offset {start}"));
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                self.consume_digits();
            }
            _ => return Err(format!("invalid JSON number at offset {start}")),
        }

        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !self.consume_digits() {
                return Err(format!("expected fractional digit at offset {}", self.pos));
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !self.consume_digits() {
                return Err(format!("expected exponent digit at offset {}", self.pos));
            }
        }

        Ok(self.src[start..self.pos].to_string())
    }

    fn consume_digits(&mut self) -> bool {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos > start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_decimals_with_redundant_trailing_zeros_match_scientific_spelling() {
        // 30 fractional digits (> MAX_DECIMAL_SCALE = 28), but only 1 significant fractional digit.
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

        // 29 non-zero fractional digits still exceed MAX_DECIMAL_SCALE (28).
        let err =
            parse_facts_arg(r#"{"resource.amount": 0.00000000000000000000000000001}"#).unwrap_err();
        assert!(err.contains("exceeds maximum"), "unexpected error: {err}");
    }

    #[test]
    fn zero_significand_with_huge_exponent_parses_as_exact_zero() {
        for raw in [
            r#"{"resource.amount": 0e2147483648}"#,
            r#"{"resource.amount": 0.0e-2147483649}"#,
            r#"{"resource.amount": -0.000e+999999999999999999999999}"#,
        ] {
            let parsed = parse_facts_arg(raw).unwrap();
            assert_eq!(
                parsed.get("resource.amount"),
                Some(&Scalar::Decimal(Decimal::ZERO)),
                "expected exact Decimal::ZERO for {raw}"
            );
        }

        // Non-zero significand with huge exponent must still be rejected.
        let err = parse_facts_arg(r#"{"resource.amount": 1e2147483648}"#).unwrap_err();
        assert!(
            err.contains("overflow") || err.contains("out of range"),
            "unexpected error: {err}"
        );
    }
}
