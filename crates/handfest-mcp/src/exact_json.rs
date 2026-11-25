//! Lossless JSON parser and exact base-10 decimal parser.
//!
//! Numeric tokens are preserved verbatim without routing through IEEE-754 `f64`, and duplicate
//! object keys are rejected to prevent parser-differential smuggling between proxy and upstream.

use std::collections::BTreeMap;

use handfest_core::ast::{Decimal, MAX_DECIMAL_SCALE};

const MAX_JSON_DEPTH: usize = 32;

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

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
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
    let (mant_part, exp_str) = split_exponent(raw)?;
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

    build_decimal(neg, trimmed, net_exp)
}

fn split_exponent(raw: &str) -> Result<(&str, Option<&str>), String> {
    let Some(exp_pos) = raw.find(['e', 'E']) else {
        return Ok((raw, None));
    };
    let (mant, exp_part) = raw.split_at(exp_pos);
    let exp_str = &exp_part[1..];
    let exp_digits = exp_str.strip_prefix(['+', '-']).unwrap_or(exp_str);
    if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid exponent '{exp_str}'"));
    }
    Ok((mant, Some(exp_str)))
}

fn build_decimal(neg: bool, trimmed_digits: &str, net_exp: i64) -> Result<Decimal, String> {
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
