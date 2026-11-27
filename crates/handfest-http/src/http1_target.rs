//! Strict HTTP request-target path normalization and query-string parsing.

use std::collections::BTreeMap;

use handfest_core::ast::is_valid_quoted_str;

use crate::http1::{Http1Error, ParsedTarget};

/// Strictly validates and normalizes an HTTP origin-form request target (`path[?query]`).
///
/// Rejects path traversal (`..`, `.`), encoded traversal/delimiters (`%2e`/`%2E`, `%2f`/`%2F`,
/// `%5c`/`%5C`), double slashes (`//`), backslashes, NUL/control characters, fragments (`#`),
/// duplicate query keys, and ASCII case-colliding query keys.
pub fn parse_request_target(target: &str) -> Result<ParsedTarget, Http1Error> {
    if target.is_empty() {
        return Err(Http1Error::InvalidTarget(
            "empty request target".to_string(),
        ));
    }
    if target.bytes().any(|b| b <= 0x20 || b >= 0x7F) {
        return Err(Http1Error::InvalidTarget(
            "request target must contain printable ASCII without whitespace or control chars"
                .to_string(),
        ));
    }
    if target.contains('#') {
        return Err(Http1Error::InvalidTarget(
            "request target must not contain fragment '#'".to_string(),
        ));
    }
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    let segments = parse_and_validate_path(raw_path)?;
    let query = match raw_query {
        Some(q) => parse_query_string(q)?,
        None => BTreeMap::new(),
    };
    Ok(ParsedTarget {
        path: raw_path.to_string(),
        segments,
        query,
    })
}

fn parse_and_validate_path(raw_path: &str) -> Result<Vec<String>, Http1Error> {
    if !raw_path.starts_with('/') {
        return Err(Http1Error::InvalidTarget(
            "request path must start with '/'".to_string(),
        ));
    }
    if raw_path.contains('\\') {
        return Err(Http1Error::PathTraversal(
            "backslash '\\' is forbidden in path".to_string(),
        ));
    }
    if raw_path.contains("//") {
        return Err(Http1Error::PathTraversal(
            "empty path segment '//' is forbidden".to_string(),
        ));
    }
    if raw_path == "/" {
        return Ok(Vec::new());
    }
    if raw_path.ends_with('/') {
        return Err(Http1Error::PathTraversal(
            "trailing '/' produces empty segment and is forbidden".to_string(),
        ));
    }

    let mut segments = Vec::new();
    for raw_seg in raw_path[1..].split('/') {
        if raw_seg == "." || raw_seg == ".." {
            return Err(Http1Error::PathTraversal(format!(
                "dot segment '{raw_seg}' is forbidden"
            )));
        }
        segments.push(percent_decode_path_segment(raw_seg)?);
    }
    Ok(segments)
}

fn percent_decode_path_segment(raw: &str) -> Result<String, Http1Error> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let decoded = decode_percent_byte(bytes, i)?;
            if matches!(decoded, b'.' | b'/' | b'\\') {
                return Err(Http1Error::PathTraversal(format!(
                    "percent-encoded delimiter/dot '%{decoded:02X}' is forbidden in path"
                )));
            }
            if decoded < 0x20 || decoded == 0x7F {
                return Err(Http1Error::InvalidTarget(format!(
                    "percent-encoded control byte '%{decoded:02X}' is forbidden in path"
                )));
            }
            out.push(decoded);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let decoded = String::from_utf8(out).map_err(|_| {
        Http1Error::InvalidPercentEncoding("decoded path segment is not valid UTF-8".to_string())
    })?;
    if !is_valid_quoted_str(&decoded) {
        return Err(Http1Error::InvalidTarget(
            "decoded path segment contains control characters".to_string(),
        ));
    }
    Ok(decoded)
}

/// Strictly parses a URL query string (without leading `?`), rejecting empty pairs, missing `=`,
/// non-ASCII keys, control characters, duplicate keys, and ASCII case-colliding keys.
pub fn parse_query_string(raw_query: &str) -> Result<BTreeMap<String, String>, Http1Error> {
    if raw_query.is_empty() {
        return Err(Http1Error::InvalidQuery(
            "empty query string after '?'".to_string(),
        ));
    }
    let mut out = BTreeMap::new();
    let mut folded_keys: BTreeMap<String, String> = BTreeMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            return Err(Http1Error::InvalidQuery(
                "empty query parameter pair".to_string(),
            ));
        }
        let Some((raw_key, raw_val)) = pair.split_once('=') else {
            return Err(Http1Error::InvalidQuery(format!(
                "query parameter '{pair}' missing '='"
            )));
        };
        let key = percent_decode_query_component(raw_key)?;
        if key.is_empty() || !key.is_ascii() {
            return Err(Http1Error::InvalidQuery(format!(
                "query key '{key}' must be non-empty ASCII"
            )));
        }
        let val = percent_decode_query_component(raw_val)?;
        if out.contains_key(&key) {
            return Err(Http1Error::DuplicateQueryKey(key));
        }
        let folded = key.to_ascii_lowercase();
        if let Some(existing) = folded_keys.get(&folded) {
            return Err(Http1Error::CaseCollidingQueryKey {
                existing: existing.clone(),
                colliding: key,
            });
        }
        folded_keys.insert(folded, key.clone());
        out.insert(key, val);
    }
    Ok(out)
}

fn percent_decode_query_component(raw: &str) -> Result<String, Http1Error> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let decoded = decode_percent_byte(bytes, i)?;
            if decoded < 0x20 || decoded == 0x7F {
                return Err(Http1Error::InvalidQuery(format!(
                    "percent-encoded control byte '%{decoded:02X}' is forbidden in query"
                )));
            }
            out.push(decoded);
            i += 3;
        } else {
            if bytes[i] < 0x20 || bytes[i] >= 0x7F {
                return Err(Http1Error::InvalidQuery(
                    "invalid byte in query string".to_string(),
                ));
            }
            if bytes[i] == b'+' || bytes[i] == b';' {
                return Err(Http1Error::InvalidQuery(format!(
                    "ambiguous character '{}' in query string must be percent-encoded",
                    bytes[i] as char
                )));
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    let decoded = String::from_utf8(out).map_err(|_| {
        Http1Error::InvalidPercentEncoding("decoded query component is not valid UTF-8".to_string())
    })?;
    if !is_valid_quoted_str(&decoded) {
        return Err(Http1Error::InvalidQuery(
            "decoded query value contains control characters".to_string(),
        ));
    }
    Ok(decoded)
}

fn decode_percent_byte(bytes: &[u8], pos: usize) -> Result<u8, Http1Error> {
    let (Some(&hi), Some(&lo)) = (bytes.get(pos + 1), bytes.get(pos + 2)) else {
        return Err(Http1Error::InvalidPercentEncoding(
            "truncated percent-escape".to_string(),
        ));
    };
    let hi_val = hex_nibble(hi).ok_or_else(|| {
        Http1Error::InvalidPercentEncoding("non-hex digit in percent-escape".to_string())
    })?;
    let lo_val = hex_nibble(lo).ok_or_else(|| {
        Http1Error::InvalidPercentEncoding("non-hex digit in percent-escape".to_string())
    })?;
    Ok((hi_val << 4) | lo_val)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
