//! Bounded newline-delimited JSON-RPC 2.0 stdio framing and response helpers.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::exact_json::{parse_exact_json, ExactJson};
use crate::proxy::{ProxyError, HANDFEST_DENIED_ERROR_CODE};

pub(crate) const JSONRPC_PARSE_ERROR: i32 = -32700;
pub(crate) const JSONRPC_INVALID_REQUEST: i32 = -32600;
pub(crate) const JSONRPC_INTERNAL_ERROR: i32 = -32603;

const MAX_UPSTREAM_NOTIFICATIONS_PER_REQUEST: usize = 1024;

pub(crate) struct ProxyIo<'a, CW, UR, UW> {
    pub(crate) client_out: &'a mut CW,
    pub(crate) upstream_in: &'a mut UW,
    pub(crate) upstream_out: &'a mut UR,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonRpcId {
    Str(String),
    Number(String),
}

impl JsonRpcId {
    pub(crate) fn to_json_literal(&self) -> String {
        match self {
            Self::Str(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()),
            Self::Number(raw) => raw.clone(),
        }
    }
}

pub(crate) enum LineReadError {
    TooLong,
    InvalidUtf8,
    Io(std::io::Error),
}

pub(crate) fn extract_request_id(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<Option<JsonRpcId>, String> {
    match obj.get("id") {
        None => Ok(None),
        Some(ExactJson::Str(s)) => Ok(Some(JsonRpcId::Str(s.clone()))),
        Some(ExactJson::Number(raw)) => Ok(Some(JsonRpcId::Number(raw.clone()))),
        Some(_) => Err("JSON-RPC id must be a string or number".to_string()),
    }
}

pub(crate) fn forward_and_read_response<CW, UR, UW>(
    expected_id: &JsonRpcId,
    raw_frame: &str,
    max_line_bytes: usize,
    io: &mut ProxyIo<'_, CW, UR, UW>,
) -> Result<String, ProxyError>
where
    CW: Write,
    UR: BufRead,
    UW: Write,
{
    write_raw_line(io.upstream_in, raw_frame)?;

    for _ in 0..=MAX_UPSTREAM_NOTIFICATIONS_PER_REQUEST {
        let line = read_upstream_line(expected_id, max_line_bytes, io.client_out, io.upstream_out)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed = match parse_exact_json(trimmed) {
            Ok(val) => val,
            Err(err) => {
                return fail_upstream_protocol(
                    io.client_out,
                    expected_id,
                    format!("invalid upstream JSON: {err}"),
                );
            }
        };
        let Some(obj) = parsed.as_object() else {
            return fail_upstream_protocol(
                io.client_out,
                expected_id,
                "upstream frame must be a JSON object".to_string(),
            );
        };
        if obj.get("jsonrpc").and_then(ExactJson::as_str) != Some("2.0") {
            return fail_upstream_protocol(
                io.client_out,
                expected_id,
                "upstream frame jsonrpc version must be \"2.0\"".to_string(),
            );
        }

        match extract_request_id(obj) {
            Ok(None) if obj.get("method").and_then(ExactJson::as_str).is_some() => {
                write_raw_line(io.client_out, trimmed)?;
            }
            Ok(Some(resp_id)) if &resp_id == expected_id => {
                return Ok(trimmed.to_string());
            }
            Ok(Some(other_id)) => {
                return fail_upstream_protocol(
                    io.client_out,
                    expected_id,
                    format!(
                        "response id mismatch: expected {}, got {}",
                        expected_id.to_json_literal(),
                        other_id.to_json_literal()
                    ),
                );
            }
            _ => {
                return fail_upstream_protocol(
                    io.client_out,
                    expected_id,
                    "upstream frame missing valid id or notification method".to_string(),
                );
            }
        }
    }

    fail_upstream_protocol(
        io.client_out,
        expected_id,
        "upstream exceeded maximum notifications before responding".to_string(),
    )
}

fn fail_upstream_protocol<CW: Write>(
    client_out: &mut CW,
    expected_id: &JsonRpcId,
    detail: String,
) -> Result<String, ProxyError> {
    let _ = write_jsonrpc_error(
        client_out,
        Some(expected_id),
        JSONRPC_INTERNAL_ERROR,
        &detail,
        None,
    );
    Err(ProxyError::UpstreamProtocol(detail))
}

fn read_upstream_line<CW: Write, UR: BufRead>(
    expected_id: &JsonRpcId,
    max_line_bytes: usize,
    client_out: &mut CW,
    upstream_out: &mut UR,
) -> Result<String, ProxyError> {
    match read_bounded_line(upstream_out, max_line_bytes) {
        Ok(Some(raw)) => Ok(raw),
        Ok(None) => {
            let _ = write_jsonrpc_error(
                client_out,
                Some(expected_id),
                JSONRPC_INTERNAL_ERROR,
                "upstream MCP server closed stdout before responding",
                None,
            );
            Err(ProxyError::UpstreamEof)
        }
        Err(LineReadError::TooLong) => {
            let _ = write_jsonrpc_error(
                client_out,
                Some(expected_id),
                JSONRPC_INTERNAL_ERROR,
                &format!("upstream response exceeded {max_line_bytes} bytes"),
                None,
            );
            Err(ProxyError::UpstreamFrameTooLarge {
                max_bytes: max_line_bytes,
            })
        }
        Err(LineReadError::InvalidUtf8) => {
            let _ = write_jsonrpc_error(
                client_out,
                Some(expected_id),
                JSONRPC_INTERNAL_ERROR,
                "upstream emitted non-UTF-8 JSON-RPC frame",
                None,
            );
            Err(ProxyError::UpstreamProtocol(
                "non-UTF-8 upstream frame".to_string(),
            ))
        }
        Err(LineReadError::Io(err)) => Err(ProxyError::Io(err)),
    }
}

pub(crate) fn write_denied_response<W: Write>(
    out: &mut W,
    req_id: &JsonRpcId,
    reason: &str,
    receipt_hash: &str,
) -> Result<(), ProxyError> {
    write_jsonrpc_error(
        out,
        Some(req_id),
        HANDFEST_DENIED_ERROR_CODE,
        &format!("handfest denied: {reason}"),
        Some(json!({
            "receipt_hash": receipt_hash,
            "reason": reason,
        })),
    )
}

pub(crate) fn write_jsonrpc_error<W: Write>(
    out: &mut W,
    id: Option<&JsonRpcId>,
    code: i32,
    message: &str,
    data: Option<Value>,
) -> Result<(), ProxyError> {
    let id_json = id.map_or_else(|| "null".to_string(), JsonRpcId::to_json_literal);
    let error_obj = match data {
        Some(d) => json!({ "code": code, "message": message, "data": d }),
        None => json!({ "code": code, "message": message }),
    };
    let error_json = serde_json::to_string(&error_obj)
        .map_err(|err| ProxyError::UpstreamProtocol(err.to_string()))?;
    let line = format!(r#"{{"jsonrpc":"2.0","id":{id_json},"error":{error_json}}}"#);
    write_raw_line(out, &line)
}

pub(crate) fn write_raw_line<W: Write>(out: &mut W, line: &str) -> Result<(), ProxyError> {
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

pub(crate) fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, LineReadError> {
    let mut buf = Vec::new();
    loop {
        let chunk = reader.fill_buf().map_err(LineReadError::Io)?;
        if chunk.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|_| LineReadError::InvalidUtf8);
        }

        if let Some(nl_pos) = chunk.iter().position(|&b| b == b'\n') {
            if buf.len().saturating_add(nl_pos) > max_bytes {
                reader.consume(nl_pos + 1);
                return Err(LineReadError::TooLong);
            }
            buf.extend_from_slice(&chunk[..nl_pos]);
            reader.consume(nl_pos + 1);
            if buf.ends_with(b"\r") {
                buf.pop();
            }
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|_| LineReadError::InvalidUtf8);
        }

        let chunk_len = chunk.len();
        if buf.len().saturating_add(chunk_len) > max_bytes {
            reader.consume(chunk_len);
            return Err(LineReadError::TooLong);
        }
        buf.extend_from_slice(chunk);
        reader.consume(chunk_len);
    }
}
