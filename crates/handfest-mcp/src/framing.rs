//! Bounded newline-delimited JSON-RPC 2.0 stdio framing and envelope validation helpers.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use crate::exact_json::{
    canonicalize_json_number, is_canonical_json_int_syntax, is_valid_json_int,
    parse_canonical_json_int, write_json_string, CanonicalJsonNumber, ExactJson,
};
use crate::proxy::{ProxyError, HANDFEST_DENIED_ERROR_CODE};

pub(crate) const JSONRPC_PARSE_ERROR: i32 = -32700;
pub(crate) const JSONRPC_INVALID_REQUEST: i32 = -32600;
pub(crate) const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
pub(crate) const JSONRPC_INTERNAL_ERROR: i32 = -32603;

const MAX_SAFE_JSONRPC_ID: i64 = (1_i64 << 53) - 1;

#[derive(Debug, Clone)]
pub(crate) enum JsonRpcId {
    Str(String),
    Number { raw: String, value: i64 },
}

impl PartialEq for JsonRpcId {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Str(a), Self::Str(b)) => a == b,
            (Self::Number { value: a, .. }, Self::Number { value: b, .. }) => a == b,
            (Self::Str(_), Self::Number { .. }) | (Self::Number { .. }, Self::Str(_)) => false,
        }
    }
}

impl Eq for JsonRpcId {}

impl JsonRpcId {
    pub(crate) fn to_json_literal(&self) -> String {
        match self {
            Self::Str(s) => {
                let mut out = String::with_capacity(s.len() + 2);
                write_json_string(s, &mut out);
                out
            }
            Self::Number { raw, .. } => raw.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum LineReadError {
    TooLong,
    BareCr,
    InvalidUtf8,
    Io(std::io::Error),
}

#[derive(Debug)]
pub(crate) struct ClientEnvelope<'a> {
    pub(crate) id: Option<JsonRpcId>,
    pub(crate) method: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientEnvelopeError {
    pub(crate) id: Option<JsonRpcId>,
    pub(crate) message: String,
}

pub(crate) enum UpstreamFrame<'a> {
    Notification,
    ServerRequest { id: JsonRpcId, method: &'a str },
    Response { id: JsonRpcId },
}

pub(crate) fn extract_id_value(val: &ExactJson) -> Result<JsonRpcId, String> {
    match val {
        ExactJson::Str(s) => Ok(JsonRpcId::Str(s.clone())),
        ExactJson::Number(raw) => {
            let value = parse_safe_jsonrpc_id_int(raw)?;
            Ok(JsonRpcId::Number {
                raw: raw.clone(),
                value,
            })
        }
        _ => Err("JSON-RPC id must be a string or number".to_string()),
    }
}

fn parse_safe_jsonrpc_id_int(raw: &str) -> Result<i64, String> {
    let Some(value) = parse_canonical_json_int(raw) else {
        if is_canonical_json_int_syntax(raw) {
            return Err("JSON-RPC numeric id outside IEEE-754 safe integer range".to_string());
        }
        return Err(
            "JSON-RPC numeric id must be a plain integer without decimal point or exponent"
                .to_string(),
        );
    };
    if !(-MAX_SAFE_JSONRPC_ID..=MAX_SAFE_JSONRPC_ID).contains(&value) {
        return Err("JSON-RPC numeric id outside IEEE-754 safe integer range".to_string());
    }
    Ok(value)
}

fn extract_upstream_response_id(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<Option<JsonRpcId>, String> {
    match obj.get("id") {
        None => Ok(None),
        Some(val) => extract_upstream_response_id_value(val).map(Some),
    }
}

pub(crate) fn extract_upstream_response_id_value(val: &ExactJson) -> Result<JsonRpcId, String> {
    match val {
        ExactJson::Str(s) => Ok(JsonRpcId::Str(s.clone())),
        ExactJson::Number(raw) => {
            let value = parse_upstream_response_id_int(raw)?;
            Ok(JsonRpcId::Number {
                raw: raw.clone(),
                value,
            })
        }
        _ => Err("JSON-RPC id must be a string or number".to_string()),
    }
}

fn parse_upstream_response_id_int(raw: &str) -> Result<i64, String> {
    if let Some(value) = parse_canonical_json_int(raw) {
        if !(-MAX_SAFE_JSONRPC_ID..=MAX_SAFE_JSONRPC_ID).contains(&value) {
            return Err("JSON-RPC numeric id outside IEEE-754 safe integer range".to_string());
        }
        return Ok(value);
    }
    match canonicalize_json_number(raw).map_err(|err| err.to_string())? {
        CanonicalJsonNumber::Zero => {
            if raw.starts_with('-') {
                return Err("JSON-RPC numeric id must not be negative zero".to_string());
            }
            Ok(0)
        }
        CanonicalJsonNumber::NonZero {
            neg,
            sig_digits,
            exp,
        } => canonical_nonzero_to_safe_i64(neg, &sig_digits, exp),
    }
}

fn canonical_nonzero_to_safe_i64(neg: bool, sig_digits: &str, exp: i128) -> Result<i64, String> {
    if exp < 0 {
        return Err(
            "JSON-RPC numeric id must be an exact integer without fractional part".to_string(),
        );
    }
    // MAX_SAFE_JSONRPC_ID = 9_007_199_254_740_991 has 16 decimal digits.
    // Because `sig_digits` is non-empty, `exp >= 16` or `sig_digits.len() + exp > 16`
    // is strictly >= 10^16 > MAX_SAFE_JSONRPC_ID.
    const MAX_SAFE_DIGITS: usize = 16;
    let Ok(exp_usize) = usize::try_from(exp) else {
        return Err("JSON-RPC numeric id outside IEEE-754 safe integer range".to_string());
    };
    if exp_usize >= MAX_SAFE_DIGITS || sig_digits.len() > MAX_SAFE_DIGITS - exp_usize {
        return Err("JSON-RPC numeric id outside IEEE-754 safe integer range".to_string());
    }
    let mut value: i64 = 0;
    for b in sig_digits.bytes() {
        value = value * 10 + i64::from(b - b'0');
    }
    for _ in 0..exp_usize {
        value *= 10;
    }
    if value > MAX_SAFE_JSONRPC_ID {
        return Err("JSON-RPC numeric id outside IEEE-754 safe integer range".to_string());
    }
    Ok(if neg { -value } else { value })
}

pub(crate) fn reject_unknown_keys(
    obj: &BTreeMap<String, ExactJson>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    if let Some(key) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("unexpected {context} key '{key}'"));
    }
    Ok(())
}

pub(crate) fn find_non_ascii_key(obj: &BTreeMap<String, ExactJson>) -> Option<&str> {
    obj.keys().find(|k| !k.is_ascii()).map(String::as_str)
}

pub(crate) fn find_case_colliding_keys(obj: &BTreeMap<String, ExactJson>) -> Option<(&str, &str)> {
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for key in obj.keys() {
        let folded = key.to_ascii_lowercase();
        if let Some(&prev) = seen.get(&folded) {
            return Some((prev, key.as_str()));
        }
        seen.insert(folded, key.as_str());
    }
    None
}

pub(crate) fn extract_request_id(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<Option<JsonRpcId>, String> {
    match obj.get("id") {
        None => Ok(None),
        Some(val) => extract_id_value(val).map(Some),
    }
}

/// Validates a client JSON-RPC 2.0 request or notification envelope strictly.
pub(crate) fn validate_client_envelope(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<ClientEnvelope<'_>, ClientEnvelopeError> {
    let id =
        extract_request_id(obj).map_err(|message| ClientEnvelopeError { id: None, message })?;

    if obj.get("jsonrpc").and_then(ExactJson::as_str) != Some("2.0") {
        return Err(ClientEnvelopeError {
            id,
            message: "jsonrpc version must be \"2.0\"".to_string(),
        });
    }

    if obj.contains_key("result") || obj.contains_key("error") {
        return Err(ClientEnvelopeError {
            id,
            message: "client request/notification must not contain result or error".to_string(),
        });
    }

    if let Err(message) = reject_unknown_keys(
        obj,
        &["jsonrpc", "id", "method", "params"],
        "JSON-RPC client envelope",
    ) {
        return Err(ClientEnvelopeError { id, message });
    }

    let Some(method) = obj.get("method").and_then(ExactJson::as_str) else {
        return Err(ClientEnvelopeError {
            id,
            message: "missing or non-string JSON-RPC method".to_string(),
        });
    };
    if method.is_empty() {
        return Err(ClientEnvelopeError {
            id,
            message: "JSON-RPC method must not be empty".to_string(),
        });
    }

    if let Some(params) = obj.get("params") {
        if !matches!(params, ExactJson::Object(_) | ExactJson::Array(_)) {
            return Err(ClientEnvelopeError {
                id,
                message: "JSON-RPC params must be a JSON object or array".to_string(),
            });
        }
    }

    Ok(ClientEnvelope { id, method })
}

pub(crate) fn classify_upstream_frame(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<UpstreamFrame<'_>, String> {
    if obj.get("jsonrpc").and_then(ExactJson::as_str) != Some("2.0") {
        return Err("upstream frame jsonrpc version must be \"2.0\"".to_string());
    }

    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");

    if let Some(method_val) = obj.get("method") {
        let Some(method) = method_val.as_str() else {
            return Err("upstream frame method must be a string".to_string());
        };
        if method.is_empty() {
            return Err("upstream frame method must not be empty".to_string());
        }
        if has_result || has_error {
            return Err(
                "upstream request/notification must not contain result or error".to_string(),
            );
        }
        reject_unknown_keys(
            obj,
            &["jsonrpc", "id", "method", "params"],
            "upstream JSON-RPC request/notification",
        )?;
        if let Some(params) = obj.get("params") {
            if !matches!(params, ExactJson::Object(_) | ExactJson::Array(_)) {
                return Err(
                    "upstream request/notification params must be a JSON object or array"
                        .to_string(),
                );
            }
        }
        return match extract_request_id(obj)? {
            None => Ok(UpstreamFrame::Notification),
            Some(id) => Ok(UpstreamFrame::ServerRequest { id, method }),
        };
    }

    let Some(id) = extract_upstream_response_id(obj)? else {
        return Err("upstream response missing required id".to_string());
    };
    validate_response_body(obj, has_result, has_error)?;
    Ok(UpstreamFrame::Response { id })
}

fn validate_response_body(
    obj: &BTreeMap<String, ExactJson>,
    has_result: bool,
    has_error: bool,
) -> Result<(), String> {
    match (has_result, has_error) {
        (true, true) => {
            Err("upstream JSON-RPC response must not contain both result and error".to_string())
        }
        (false, false) => {
            Err("upstream JSON-RPC response must contain either result or error".to_string())
        }
        (true, false) => reject_unknown_keys(
            obj,
            &["jsonrpc", "id", "result"],
            "upstream JSON-RPC response",
        ),
        (false, true) => {
            reject_unknown_keys(
                obj,
                &["jsonrpc", "id", "error"],
                "upstream JSON-RPC response",
            )?;
            match obj.get("error") {
                Some(err_val) if is_valid_jsonrpc_error_object(err_val) => Ok(()),
                _ => Err("malformed JSON-RPC error object in upstream response".to_string()),
            }
        }
    }
}

fn is_valid_jsonrpc_error_object(val: &ExactJson) -> bool {
    let Some(err_obj) = val.as_object() else {
        return false;
    };
    if reject_unknown_keys(
        err_obj,
        &["code", "message", "data"],
        "JSON-RPC error object",
    )
    .is_err()
    {
        return false;
    }
    let valid_code = matches!(
        err_obj.get("code"),
        Some(ExactJson::Number(raw)) if is_valid_json_int(raw)
    );
    let valid_message = err_obj.get("message").and_then(ExactJson::as_str).is_some();
    valid_code && valid_message
}

pub(crate) fn fail_upstream_error<T, CW: Write>(
    client_out: &mut CW,
    expected_id: Option<&JsonRpcId>,
    code: i32,
    detail: String,
) -> Result<T, ProxyError> {
    let _ = write_jsonrpc_error(client_out, expected_id, code, &detail, None);
    Err(ProxyError::UpstreamProtocol(detail))
}

pub(crate) fn fail_upstream_protocol<T, CW: Write>(
    client_out: &mut CW,
    expected_id: Option<&JsonRpcId>,
    detail: String,
) -> Result<T, ProxyError> {
    fail_upstream_error(client_out, expected_id, JSONRPC_INTERNAL_ERROR, detail)
}

pub(crate) fn write_denied_response<W: Write>(
    out: &mut W,
    req_id: &JsonRpcId,
    reason: &str,
    receipt_hash: &str,
) -> Result<(), ProxyError> {
    let mut data = BTreeMap::new();
    data.insert(
        "receipt_hash".to_string(),
        ExactJson::Str(receipt_hash.to_string()),
    );
    data.insert("reason".to_string(), ExactJson::Str(reason.to_string()));
    write_jsonrpc_error(
        out,
        Some(req_id),
        HANDFEST_DENIED_ERROR_CODE,
        &format!("handfest denied: {reason}"),
        Some(&ExactJson::Object(data)),
    )
}

pub(crate) fn format_jsonrpc_error_line(
    id: Option<&JsonRpcId>,
    code: i32,
    message: &str,
    data: Option<&ExactJson>,
) -> String {
    let id_json = id.map_or_else(|| "null".to_string(), JsonRpcId::to_json_literal);
    let mut err_fields = BTreeMap::new();
    err_fields.insert("code".to_string(), ExactJson::Number(code.to_string()));
    err_fields.insert("message".to_string(), ExactJson::Str(message.to_string()));
    if let Some(d) = data {
        err_fields.insert("data".to_string(), d.clone());
    }
    let error_json = ExactJson::Object(err_fields).to_json_string();
    format!(r#"{{"jsonrpc":"2.0","id":{id_json},"error":{error_json}}}"#)
}

pub(crate) fn write_jsonrpc_error<W: Write>(
    out: &mut W,
    id: Option<&JsonRpcId>,
    code: i32,
    message: &str,
    data: Option<&ExactJson>,
) -> Result<(), ProxyError> {
    let line = format_jsonrpc_error_line(id, code, message, data);
    write_raw_line(out, &line)
}

pub(crate) fn write_raw_line<W: Write>(out: &mut W, line: &str) -> Result<(), ProxyError> {
    if line.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n') {
        return Err(ProxyError::UpstreamProtocol(
            "refusing to emit JSON-RPC frame containing raw CR or LF".to_string(),
        ));
    }
    let mut framed = Vec::with_capacity(line.len() + 1);
    framed.extend_from_slice(line.as_bytes());
    framed.push(b'\n');
    write_all_retry_eintr(out, &framed)?;
    flush_retry_eintr(out)?;
    Ok(())
}

fn write_all_retry_eintr<W: Write>(out: &mut W, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match out.write(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole JSON-RPC frame",
                ));
            }
            Ok(n) => buf = &buf[n..],
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn flush_retry_eintr<W: Write>(out: &mut W) -> std::io::Result<()> {
    loop {
        match out.flush() {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

pub(crate) fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, LineReadError> {
    let mut buf = Vec::new();
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(LineReadError::Io(err)),
        };
        if chunk.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            if buf.len() > max_bytes {
                return Err(LineReadError::TooLong);
            }
            if buf.contains(&b'\r') {
                return Err(LineReadError::BareCr);
            }
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|_| LineReadError::InvalidUtf8);
        }

        if let Some(nl_pos) = chunk.iter().position(|&b| b == b'\n') {
            let has_trailing_cr = if nl_pos > 0 {
                chunk[nl_pos - 1] == b'\r'
            } else {
                buf.last() == Some(&b'\r')
            };
            let payload_len = buf
                .len()
                .saturating_add(nl_pos)
                .saturating_sub(usize::from(has_trailing_cr));
            if payload_len > max_bytes {
                reader.consume(nl_pos + 1);
                return Err(LineReadError::TooLong);
            }
            buf.extend_from_slice(&chunk[..nl_pos]);
            reader.consume(nl_pos + 1);
            if has_trailing_cr {
                buf.pop();
            }
            if buf.contains(&b'\r') {
                return Err(LineReadError::BareCr);
            }
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|_| LineReadError::InvalidUtf8);
        }

        let chunk_len = chunk.len();
        let total = buf.len().saturating_add(chunk_len);
        // Allow one extra byte beyond `max_bytes` ONLY when it is a trailing CR that may pair
        // with an LF at the start of the next chunk.
        let pending_crlf =
            max_bytes < usize::MAX && total == max_bytes + 1 && chunk.last() == Some(&b'\r');
        if total > max_bytes && !pending_crlf {
            reader.consume(chunk_len);
            return Err(LineReadError::TooLong);
        }
        buf.extend_from_slice(chunk);
        reader.consume(chunk_len);
    }
}

#[cfg(test)]
#[path = "framing_tests.rs"]
mod tests;
