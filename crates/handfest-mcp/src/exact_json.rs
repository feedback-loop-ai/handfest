//! Lossless JSON parser, serializer, and exact base-10 decimal helpers.
//!
//! Numeric tokens are preserved verbatim without routing through IEEE-754 `f64`, and duplicate
//! object keys are rejected to prevent parser-differential smuggling between proxy and upstream.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use handfest_core::ast::{Decimal, MAX_DECIMAL_SCALE};

const MAX_JSON_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExactJson {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<ExactJson>),
    Object(BTreeMap<String, ExactJson>),
}

impl ExactJson {
    pub(crate) fn as_object(&self) -> Option<&BTreeMap<String, ExactJson>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    pub(crate) fn as_object_mut(&mut self) -> Option<&mut BTreeMap<String, ExactJson>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    pub(crate) fn as_array_mut(&mut self) -> Option<&mut Vec<ExactJson>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Serializes this AST into compact single-line JSON without routing numbers through `f64`.
    pub(crate) fn to_json_string(&self) -> String {
        let mut out = String::new();
        write_exact_json(self, &mut out);
        out
    }
}

/// Structured errors returned by exact JSON numeric canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NumberError {
    InvalidSyntax(String),
    ExponentOutOfRange(String),
    ExponentOverflow,
}

impl std::fmt::Display for NumberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSyntax(msg) => f.write_str(msg),
            Self::ExponentOutOfRange(exp) => write!(f, "JSON number exponent '{exp}' out of range"),
            Self::ExponentOverflow => f.write_str("JSON number exponent overflow"),
        }
    }
}

impl std::error::Error for NumberError {}

/// Exact canonical base-10 value of an RFC 8259 JSON numeric literal (`(-1)^neg * sig * 10^exp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CanonicalJsonNumber {
    Zero,
    NonZero {
        neg: bool,
        sig_digits: String,
        exp: i128,
    },
}

/// Normalizes a valid RFC 8259 JSON number token for exact numeric equivalence (no `f64`).
///
/// Both JSON-RPC numeric ID comparison and exact `Decimal` fact parsing share this single
/// normalization path so exponent/significand semantics can never drift.
pub(crate) fn canonicalize_json_number(raw: &str) -> Result<CanonicalJsonNumber, NumberError> {
    let (mant_part, exp_str) = split_exponent(raw)?;
    let (neg, unsigned_mant) = match mant_part.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mant_part),
    };
    let (int_digits, frac_digits) = match unsigned_mant.split_once('.') {
        Some((i, f)) => {
            if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(NumberError::InvalidSyntax(format!(
                    "invalid fractional digits in '{raw}'"
                )));
            }
            (i, f)
        }
        None => (unsigned_mant, ""),
    };
    if int_digits.is_empty() || !int_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NumberError::InvalidSyntax(format!(
            "invalid integer digits in '{raw}'"
        )));
    }

    let mut digits = String::with_capacity(int_digits.len() + frac_digits.len());
    digits.push_str(int_digits);
    digits.push_str(frac_digits);

    let trimmed_leading = digits.trim_start_matches('0');
    if trimmed_leading.is_empty() {
        return Ok(CanonicalJsonNumber::Zero);
    }

    let exp: i128 = match exp_str {
        Some(s) => s
            .parse()
            .map_err(|_| NumberError::ExponentOutOfRange(s.to_string()))?,
        None => 0,
    };
    let frac_len = i128::try_from(frac_digits.len()).map_err(|_| NumberError::ExponentOverflow)?;
    let sig_digits = trimmed_leading.trim_end_matches('0');
    let trailing_zeros = i128::try_from(trimmed_leading.len() - sig_digits.len())
        .map_err(|_| NumberError::ExponentOverflow)?;
    // Combine `trailing_zeros - frac_len` before adding to `exp` so equivalent spellings such as
    // `1.0e<i128::MIN>` and `1e<i128::MIN>` never suffer spurious intermediate underflow/overflow.
    let exp_delta = trailing_zeros - frac_len;
    let net_exp = exp
        .checked_add(exp_delta)
        .ok_or(NumberError::ExponentOverflow)?;

    Ok(CanonicalJsonNumber::NonZero {
        neg,
        sig_digits: sig_digits.to_string(),
        exp: net_exp,
    })
}

/// Returns `true` when `raw` is a JSON integer literal representable as a signed 64-bit integer.
pub(crate) fn is_valid_json_int(raw: &str) -> bool {
    !raw.contains(['.', 'e', 'E']) && raw.parse::<i64>().is_ok()
}

/// Appends `s` as a valid RFC 8259 single-line JSON string literal (escaping all control chars).
pub(crate) fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_exact_json(val: &ExactJson, out: &mut String) {
    match val {
        ExactJson::Null => out.push_str("null"),
        ExactJson::Bool(true) => out.push_str("true"),
        ExactJson::Bool(false) => out.push_str("false"),
        ExactJson::Number(raw) => out.push_str(raw),
        ExactJson::Str(s) => write_json_string(s, out),
        ExactJson::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_exact_json(item, out);
            }
            out.push(']');
        }
        ExactJson::Object(map) => {
            out.push('{');
            for (idx, (key, item)) in map.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_exact_json(item, out);
            }
            out.push('}');
        }
    }
}

pub(crate) fn parse_exact_json(src: &str) -> Result<ExactJson, String> {
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

/// Parses a strict base-10 decimal string (`-?[0-9]+(\.[0-9]+)?`) without `f64` rounding.
pub(crate) fn parse_decimal_str(raw: &str) -> Result<Decimal, String> {
    if raw.is_empty() {
        return Err("empty decimal string".to_string());
    }
    let unsigned = raw.strip_prefix('-').unwrap_or(raw);
    let (int_part, frac_part) = match unsigned.split_once('.') {
        Some((i, f)) => {
            if f.is_empty() {
                return Err(format!("missing fractional digits in '{raw}'"));
            }
            (i, Some(f))
        }
        None => (unsigned, None),
    };
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid integer digits in '{raw}'"));
    }
    if let Some(f) = frac_part {
        if !f.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("invalid fractional digits in '{raw}'"));
        }
    }
    parse_json_decimal(raw)
}

/// Parses a JSON numeric literal (plain or scientific notation) into an exact `Decimal`.
pub(crate) fn parse_json_decimal(raw: &str) -> Result<Decimal, String> {
    match canonicalize_json_number(raw).map_err(|err| err.to_string())? {
        CanonicalJsonNumber::Zero => Ok(Decimal::ZERO),
        CanonicalJsonNumber::NonZero {
            neg,
            sig_digits,
            exp,
        } => build_decimal(neg, &sig_digits, exp),
    }
}

fn split_exponent(raw: &str) -> Result<(&str, Option<&str>), NumberError> {
    let Some(exp_pos) = raw.find(['e', 'E']) else {
        return Ok((raw, None));
    };
    let (mant, exp_part) = raw.split_at(exp_pos);
    let exp_str = &exp_part[1..];
    let exp_digits = exp_str.strip_prefix(['+', '-']).unwrap_or(exp_str);
    if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NumberError::InvalidSyntax(format!(
            "invalid exponent '{exp_str}'"
        )));
    }
    Ok((mant, Some(exp_str)))
}

fn build_decimal(neg: bool, trimmed_digits: &str, net_exp: i128) -> Result<Decimal, String> {
    let mut acc: u128 = 0;
    for b in trimmed_digits.bytes() {
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
        let abs_exp = net_exp.unsigned_abs();
        if abs_exp > u128::from(MAX_DECIMAL_SCALE) {
            return Err(format!(
                "scale {abs_exp} exceeds maximum {MAX_DECIMAL_SCALE}"
            ));
        }
        u8::try_from(abs_exp).map_err(|_| "decimal scale overflow".to_string())?
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
        let mut map = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(ExactJson::Object(map));
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
            if map.insert(key.clone(), val).is_some() {
                return Err(format!("duplicate JSON object key '{key}'"));
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(ExactJson::Object(map));
                }
                _ => return Err(format!("expected ',' or '}}' at offset {}", self.pos)),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<ExactJson, String> {
        self.pos += 1;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(ExactJson::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(ExactJson::Array(items));
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
    fn canonical_json_number_compares_losslessly() {
        assert_eq!(
            canonicalize_json_number("1.50").unwrap(),
            canonicalize_json_number("1.5").unwrap()
        );
        assert_eq!(
            canonicalize_json_number("1.50").unwrap(),
            canonicalize_json_number("15e-1").unwrap()
        );
        assert_eq!(
            canonicalize_json_number("0").unwrap(),
            canonicalize_json_number("-0.0e99").unwrap()
        );
        assert_eq!(
            canonicalize_json_number("18446744073709551617").unwrap(),
            canonicalize_json_number("1.8446744073709551617e19").unwrap()
        );
        assert_ne!(
            canonicalize_json_number("18446744073709551616").unwrap(),
            canonicalize_json_number("18446744073709551617").unwrap()
        );
        assert_ne!(
            canonicalize_json_number("9007199254740992").unwrap(),
            canonicalize_json_number("9007199254740993").unwrap()
        );
        assert_eq!(
            canonicalize_json_number("1e9999999999999999999999999999999999999999"),
            Err(NumberError::ExponentOutOfRange(
                "9999999999999999999999999999999999999999".to_string()
            ))
        );

        let min_exp_one = format!("1e{}", i128::MIN);
        let min_exp_one_dot_zero = format!("1.0e{}", i128::MIN);
        assert_eq!(
            canonicalize_json_number(&min_exp_one_dot_zero),
            canonicalize_json_number(&min_exp_one)
        );
        assert_eq!(
            canonicalize_json_number(&min_exp_one_dot_zero),
            Ok(CanonicalJsonNumber::NonZero {
                neg: false,
                sig_digits: "1".to_string(),
                exp: i128::MIN,
            })
        );

        let max_exp_tenth = format!("0.1e{}", i128::MAX);
        let max_exp_minus_one = format!("1e{}", i128::MAX - 1);
        assert_eq!(
            canonicalize_json_number(&max_exp_tenth),
            canonicalize_json_number(&max_exp_minus_one)
        );

        assert_eq!(
            canonicalize_json_number(&format!("10e{}", i128::MAX)),
            Err(NumberError::ExponentOverflow)
        );
        assert_eq!(
            canonicalize_json_number(&format!("0.1e{}", i128::MIN)),
            Err(NumberError::ExponentOverflow)
        );
        assert_eq!(
            parse_json_decimal("1.500e+2"),
            Ok(Decimal::parse("150.0").unwrap())
        );
        assert_eq!(
            parse_json_decimal(&min_exp_one_dot_zero),
            Err(format!(
                "scale {} exceeds maximum {MAX_DECIMAL_SCALE}",
                i128::MIN.unsigned_abs()
            ))
        );
    }

    #[test]
    fn serializer_preserves_numbers_escapes_control_chars_and_supports_deep_nesting() {
        let raw = r#"{"a":100.000000000000001,"b":18446744073709551617,"c":"line\r\n\t\b\f\u0001\"\\","d":[true,false,null]}"#;
        let parsed = parse_exact_json(raw).unwrap();
        let encoded = parsed.to_json_string();
        assert_eq!(encoded, raw);
        assert!(!encoded.contains('\r'));
        assert!(!encoded.contains('\n'));

        let depth_64 = format!("{}1{}", "[".repeat(64), "]".repeat(64));
        assert!(parse_exact_json(&depth_64).is_ok());

        let depth_129 = format!("{}1{}", "[".repeat(129), "]".repeat(129));
        assert_eq!(
            parse_exact_json(&depth_129).unwrap_err(),
            "JSON nesting depth exceeded"
        );
    }
}
