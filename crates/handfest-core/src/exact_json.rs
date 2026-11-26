//! Pure `#![no_std]` lossless RFC 8259 JSON parser and compact single-line serializer.
//!
//! Numeric tokens are preserved verbatim without routing through IEEE-754 `f64`, and duplicate
//! object keys are rejected at every nesting level (including inside arrays) to prevent
//! parser-differential smuggling across crates and wire boundaries.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{self, Write as _};

use crate::json_num::{scan_json_number_token, NumberError};

/// Default maximum JSON container nesting depth enforced by [`parse_exact_json`].
pub const DEFAULT_MAX_JSON_DEPTH: usize = 128;

/// Lossless JSON AST preserving exact numeric token spellings and rejecting duplicate keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactJson {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<ExactJson>),
    Object(BTreeMap<String, ExactJson>),
}

impl ExactJson {
    /// Borrows the inner object map when this value is [`ExactJson::Object`].
    #[must_use]
    pub fn as_object(&self) -> Option<&BTreeMap<String, ExactJson>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// Mutably borrows the inner object map when this value is [`ExactJson::Object`].
    #[must_use]
    pub fn as_object_mut(&mut self) -> Option<&mut BTreeMap<String, ExactJson>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// Mutably borrows the inner array when this value is [`ExactJson::Array`].
    #[must_use]
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<ExactJson>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Borrows the inner string when this value is [`ExactJson::Str`].
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Serializes this AST into compact single-line JSON without routing numbers through `f64`.
    #[must_use]
    pub fn to_json_string(&self) -> String {
        let mut out = String::new();
        write_exact_json(self, &mut out);
        out
    }
}

/// Structured error returned by lossless RFC 8259 JSON parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    MaxDepthExceeded,
    TrailingCharacters {
        offset: usize,
    },
    UnexpectedByte {
        byte: u8,
        offset: usize,
    },
    UnexpectedEof,
    InvalidLiteral {
        offset: usize,
    },
    Expected {
        expected: &'static str,
        offset: usize,
    },
    DuplicateKey(String),
    UnterminatedEscape,
    UnterminatedString,
    InvalidString(String),
    InvalidNumber(NumberError),
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxDepthExceeded => f.write_str("JSON nesting depth exceeded"),
            Self::TrailingCharacters { offset } => {
                write!(f, "trailing characters at byte {offset}")
            }
            Self::UnexpectedByte { byte, offset } => {
                write!(f, "unexpected byte 0x{byte:02x} at offset {offset}")
            }
            Self::UnexpectedEof => f.write_str("unexpected end of JSON input"),
            Self::InvalidLiteral { offset } => write!(f, "invalid JSON literal at offset {offset}"),
            Self::Expected { expected, offset } => {
                write!(f, "expected {expected} at offset {offset}")
            }
            Self::DuplicateKey(key) => write!(f, "duplicate JSON object key '{key}'"),
            Self::UnterminatedEscape => f.write_str("unterminated escape sequence in JSON string"),
            Self::UnterminatedString => f.write_str("unterminated JSON string"),
            Self::InvalidString(msg) => write!(f, "invalid JSON string: {msg}"),
            Self::InvalidNumber(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for JsonError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidNumber(err) => Some(err),
            _ => None,
        }
    }
}

/// Appends `s` as a valid RFC 8259 single-line JSON string literal (escaping all control chars).
pub fn write_json_string(s: &str, out: &mut String) {
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

/// Parses `src` using [`DEFAULT_MAX_JSON_DEPTH`], preserving exact numeric literals and rejecting
/// duplicate object keys anywhere in the JSON tree.
pub fn parse_exact_json(src: &str) -> Result<ExactJson, JsonError> {
    parse_exact_json_with_max_depth(src, DEFAULT_MAX_JSON_DEPTH)
}

/// Parses `src` with a caller-specified `max_depth`, preserving exact numeric literals and
/// rejecting duplicate object keys anywhere in the JSON tree.
pub fn parse_exact_json_with_max_depth(
    src: &str,
    max_depth: usize,
) -> Result<ExactJson, JsonError> {
    let mut parser = JsonParser {
        src,
        bytes: src.as_bytes(),
        pos: 0,
        max_depth,
    };
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(JsonError::TrailingCharacters { offset: parser.pos });
    }
    Ok(val)
}

struct JsonParser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
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

    fn parse_value(&mut self, depth: usize) -> Result<ExactJson, JsonError> {
        if depth > self.max_depth {
            return Err(JsonError::MaxDepthExceeded);
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
            Some(byte) => Err(JsonError::UnexpectedByte {
                byte,
                offset: self.pos,
            }),
            None => Err(JsonError::UnexpectedEof),
        }
    }

    fn expect_literal(&mut self, lit: &[u8], value: ExactJson) -> Result<ExactJson, JsonError> {
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(JsonError::InvalidLiteral { offset: self.pos })
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<ExactJson, JsonError> {
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
                return Err(JsonError::Expected {
                    expected: "string key",
                    offset: self.pos,
                });
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(JsonError::Expected {
                    expected: "':'",
                    offset: self.pos,
                });
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            if map.insert(key.clone(), val).is_some() {
                return Err(JsonError::DuplicateKey(key));
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(ExactJson::Object(map));
                }
                _ => {
                    return Err(JsonError::Expected {
                        expected: "',' or '}'",
                        offset: self.pos,
                    });
                }
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<ExactJson, JsonError> {
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
                _ => {
                    return Err(JsonError::Expected {
                        expected: "',' or ']'",
                        offset: self.pos,
                    });
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.pos += 1;
        let mut out = String::new();
        let mut run_start = self.pos;
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'"' => {
                    out.push_str(&self.src[run_start..self.pos]);
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.src[run_start..self.pos]);
                    self.pos += 1;
                    self.parse_escape(&mut out)?;
                    run_start = self.pos;
                }
                0x00..=0x1F => {
                    return Err(JsonError::InvalidString(format!(
                        "unescaped control character 0x{:02x} at offset {}",
                        self.bytes[self.pos], self.pos
                    )));
                }
                _ => self.pos += 1,
            }
        }
        Err(JsonError::UnterminatedString)
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        let Some(&esc) = self.bytes.get(self.pos) else {
            return Err(JsonError::UnterminatedEscape);
        };
        self.pos += 1;
        match esc {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{08}'),
            b'f' => out.push('\u{0C}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let ch = self.parse_unicode_escape()?;
                out.push(ch);
            }
            other => {
                return Err(JsonError::InvalidString(format!(
                    "invalid escape '\\{}' at offset {}",
                    other as char,
                    self.pos - 1
                )));
            }
        }
        Ok(())
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let code = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if !self.bytes[self.pos..].starts_with(b"\\u") {
                return Err(JsonError::InvalidString(
                    "lone high surrogate in JSON string".to_string(),
                ));
            }
            self.pos += 2;
            let low = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(JsonError::InvalidString(
                    "invalid low surrogate in JSON string".to_string(),
                ));
            }
            let combined = 0x10000 + ((u32::from(code) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
            char::from_u32(combined).ok_or_else(|| {
                JsonError::InvalidString("invalid Unicode scalar from surrogate pair".to_string())
            })
        } else if (0xDC00..=0xDFFF).contains(&code) {
            Err(JsonError::InvalidString(
                "lone low surrogate in JSON string".to_string(),
            ))
        } else {
            char::from_u32(u32::from(code)).ok_or_else(|| {
                JsonError::InvalidString("invalid Unicode escape in JSON string".to_string())
            })
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, JsonError> {
        let Some(slice) = self.bytes.get(self.pos..self.pos + 4) else {
            return Err(JsonError::UnterminatedEscape);
        };
        let mut acc = 0_u16;
        for &b in slice {
            let nibble = match b {
                b'0'..=b'9' => u16::from(b - b'0'),
                b'a'..=b'f' => u16::from(b - b'a') + 10,
                b'A'..=b'F' => u16::from(b - b'A') + 10,
                _ => {
                    return Err(JsonError::InvalidString(
                        "non-hex digit in \\u escape".to_string(),
                    ));
                }
            };
            acc = (acc << 4) | nibble;
        }
        self.pos += 4;
        Ok(acc)
    }

    fn parse_number(&mut self) -> Result<String, JsonError> {
        let start = self.pos;
        let end = scan_json_number_token(self.bytes, start).map_err(JsonError::InvalidNumber)?;
        self.pos = end;
        Ok(self.src[start..end].to_string())
    }
}

#[cfg(test)]
#[path = "exact_json_tests.rs"]
mod tests;
