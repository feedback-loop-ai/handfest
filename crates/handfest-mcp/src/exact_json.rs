//! Lossless JSON parser, serializer, and exact base-10 decimal helpers.
//!
//! Numeric tokens are preserved verbatim without routing through IEEE-754 `f64`, and duplicate
//! object keys are rejected to prevent parser-differential smuggling between proxy and upstream.

use std::collections::BTreeMap;
use std::fmt::Write as _;

pub(crate) use handfest_core::json_num::{
    canonicalize_json_number, is_canonical_json_int_syntax, parse_canonical_json_int,
    parse_decimal_str, parse_json_decimal, scan_json_number_token, CanonicalJsonNumber,
    NumberError,
};

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

/// Returns `true` when `raw` is a canonical JSON integer literal representable as a signed 64-bit integer.
pub(crate) fn is_valid_json_int(raw: &str) -> bool {
    parse_canonical_json_int(raw).is_some()
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
        let end = scan_json_number_token(self.bytes, start).map_err(|err| err.to_string())?;
        self.pos = end;
        Ok(self.src[start..end].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use handfest_core::ast::Decimal;

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
            canonicalize_json_number("0.0e99").unwrap()
        );
        for neg_zero in ["-0", "-0.0", "-0.00", "-0e5", "-0.0e99"] {
            assert_eq!(
                canonicalize_json_number(neg_zero),
                Err(NumberError::NegativeZero)
            );
            assert_eq!(parse_json_decimal(neg_zero), Err(NumberError::NegativeZero));
        }
        for bad_str in ["-0", "-0.0", "-0.00"] {
            assert_eq!(parse_decimal_str(bad_str), Err(NumberError::NegativeZero));
        }
        for leading in ["010", "0100", "-010", "00", "00.5"] {
            assert_eq!(parse_decimal_str(leading), Err(NumberError::LeadingZero));
            assert_eq!(parse_json_decimal(leading), Err(NumberError::LeadingZero));
        }
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
            Err(NumberError::ScaleOverflow {
                scale: i128::MIN.unsigned_abs(),
                max: handfest_core::ast::MAX_DECIMAL_SCALE,
            })
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

    #[test]
    fn parse_canonical_json_int_enforces_strict_grammar_and_rejects_negative_zero() {
        assert_eq!(parse_canonical_json_int("0"), Some(0));
        assert_eq!(parse_canonical_json_int("1"), Some(1));
        assert_eq!(parse_canonical_json_int("-1"), Some(-1));
        assert_eq!(
            parse_canonical_json_int("9223372036854775807"),
            Some(i64::MAX)
        );
        assert_eq!(
            parse_canonical_json_int("-9223372036854775808"),
            Some(i64::MIN)
        );
        assert!(is_valid_json_int("0"));
        assert!(is_valid_json_int("-32601"));

        for invalid in [
            "-0",
            "+0",
            "+1",
            "00",
            "01",
            "-00",
            "-01",
            "1.0",
            "-0.0",
            "1e0",
            "1E0",
            "",
            "-",
            " 1",
            "1 ",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert_eq!(
                parse_canonical_json_int(invalid),
                None,
                "invalid canonical integer '{invalid}' must be rejected"
            );
            assert!(
                !is_valid_json_int(invalid),
                "is_valid_json_int must reject '{invalid}'"
            );
        }
    }
}
