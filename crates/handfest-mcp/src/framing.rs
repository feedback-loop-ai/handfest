//! Bounded newline-delimited JSON-RPC 2.0 stdio framing and response correlation helpers.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use crate::exact_json::{
    canonicalize_json_number, is_valid_json_int, parse_exact_json, write_json_string,
    CanonicalJsonNumber, ExactJson,
};
use crate::proxy::{ProxyError, HANDFEST_DENIED_ERROR_CODE};

pub(crate) const JSONRPC_PARSE_ERROR: i32 = -32700;
pub(crate) const JSONRPC_INVALID_REQUEST: i32 = -32600;
pub(crate) const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
pub(crate) const JSONRPC_INTERNAL_ERROR: i32 = -32603;

const MAX_UPSTREAM_INTERLEAVED_MESSAGES: usize = 1024;

pub(crate) struct ProxyIo<'a, CW, UR, UW> {
    pub(crate) client_out: &'a mut CW,
    pub(crate) upstream_in: &'a mut UW,
    pub(crate) upstream_out: &'a mut UR,
}

#[derive(Debug, Clone)]
pub(crate) enum JsonRpcId {
    Str(String),
    Number {
        raw: String,
        canonical: CanonicalJsonNumber,
    },
}

impl PartialEq for JsonRpcId {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Str(a), Self::Str(b)) => a == b,
            (Self::Number { canonical: a, .. }, Self::Number { canonical: b, .. }) => a == b,
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

enum UpstreamFrame<'a> {
    Notification,
    ServerRequest { id: JsonRpcId, method: &'a str },
    Response { id: JsonRpcId },
}

pub(crate) fn extract_request_id(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<Option<JsonRpcId>, String> {
    match obj.get("id") {
        None => Ok(None),
        Some(ExactJson::Str(s)) => Ok(Some(JsonRpcId::Str(s.clone()))),
        Some(ExactJson::Number(raw)) => {
            let canonical = canonicalize_json_number(raw)?;
            Ok(Some(JsonRpcId::Number {
                raw: raw.clone(),
                canonical,
            }))
        }
        Some(_) => Err("JSON-RPC id must be a string or number".to_string()),
    }
}

pub(crate) fn forward_and_read_response<CW, UR, UW>(
    expected_id: &JsonRpcId,
    normalized_frame: &str,
    max_line_bytes: usize,
    io: &mut ProxyIo<'_, CW, UR, UW>,
) -> Result<BTreeMap<String, ExactJson>, ProxyError>
where
    CW: Write,
    UR: BufRead,
    UW: Write,
{
    write_raw_line(io.upstream_in, normalized_frame)?;

    for _ in 0..=MAX_UPSTREAM_INTERLEAVED_MESSAGES {
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
        let ExactJson::Object(obj) = parsed else {
            return fail_upstream_protocol(
                io.client_out,
                expected_id,
                "upstream frame must be a JSON object".to_string(),
            );
        };

        let frame = match classify_upstream_frame(&obj) {
            Ok(frame) => frame,
            Err(detail) => return fail_upstream_protocol(io.client_out, expected_id, detail),
        };

        match frame {
            UpstreamFrame::Notification => {
                write_raw_line(io.client_out, &ExactJson::Object(obj).to_json_string())?;
            }
            UpstreamFrame::ServerRequest { id, method } => {
                let msg =
                    format!("handfest-mcp does not support server-to-client request '{method}'");
                write_jsonrpc_error(
                    io.upstream_in,
                    Some(&id),
                    JSONRPC_METHOD_NOT_FOUND,
                    &msg,
                    None,
                )?;
            }
            UpstreamFrame::Response { id: resp_id } if &resp_id == expected_id => {
                return Ok(obj);
            }
            UpstreamFrame::Response { id: other_id } => {
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
        }
    }

    fail_upstream_protocol(
        io.client_out,
        expected_id,
        "upstream exceeded maximum interleaved messages before responding".to_string(),
    )
}

fn classify_upstream_frame(obj: &BTreeMap<String, ExactJson>) -> Result<UpstreamFrame<'_>, String> {
    if obj.get("jsonrpc").and_then(ExactJson::as_str) != Some("2.0") {
        return Err("upstream frame jsonrpc version must be \"2.0\"".to_string());
    }

    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");

    if let Some(method_val) = obj.get("method") {
        let Some(method) = method_val.as_str() else {
            return Err("upstream frame method must be a string".to_string());
        };
        if has_result || has_error {
            return Err(
                "upstream request/notification must not contain result or error".to_string(),
            );
        }
        return match extract_request_id(obj)? {
            None => Ok(UpstreamFrame::Notification),
            Some(id) => Ok(UpstreamFrame::ServerRequest { id, method }),
        };
    }

    let Some(id) = extract_request_id(obj)? else {
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
        (true, false) => Ok(()),
        (false, true) => match obj.get("error") {
            Some(err_val) if is_valid_jsonrpc_error_object(err_val) => Ok(()),
            _ => Err("malformed JSON-RPC error object in upstream response".to_string()),
        },
    }
}

fn is_valid_jsonrpc_error_object(val: &ExactJson) -> bool {
    let Some(err_obj) = val.as_object() else {
        return false;
    };
    let valid_code = matches!(
        err_obj.get("code"),
        Some(ExactJson::Number(raw)) if is_valid_json_int(raw)
    );
    let valid_message = err_obj.get("message").and_then(ExactJson::as_str).is_some();
    valid_code && valid_message
}

pub(crate) fn fail_upstream_protocol<T, CW: Write>(
    client_out: &mut CW,
    expected_id: &JsonRpcId,
    detail: String,
) -> Result<T, ProxyError> {
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
        Err(LineReadError::BareCr) => fail_upstream_protocol(
            client_out,
            expected_id,
            "upstream emitted bare carriage return (0x0D) in JSON-RPC frame".to_string(),
        ),
        Err(LineReadError::InvalidUtf8) => fail_upstream_protocol(
            client_out,
            expected_id,
            "upstream emitted non-UTF-8 JSON-RPC frame".to_string(),
        ),
        Err(LineReadError::Io(err)) => Err(ProxyError::Io(err)),
    }
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

pub(crate) fn write_jsonrpc_error<W: Write>(
    out: &mut W,
    id: Option<&JsonRpcId>,
    code: i32,
    message: &str,
    data: Option<&ExactJson>,
) -> Result<(), ProxyError> {
    let id_json = id.map_or_else(|| "null".to_string(), JsonRpcId::to_json_literal);
    let mut err_fields = BTreeMap::new();
    err_fields.insert("code".to_string(), ExactJson::Number(code.to_string()));
    err_fields.insert("message".to_string(), ExactJson::Str(message.to_string()));
    if let Some(d) = data {
        err_fields.insert("data".to_string(), d.clone());
    }
    let error_json = ExactJson::Object(err_fields).to_json_string();
    let line = format!(r#"{{"jsonrpc":"2.0","id":{id_json},"error":{error_json}}}"#);
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
    out.write_all(&framed)?;
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
            if buf.contains(&b'\r') {
                return Err(LineReadError::BareCr);
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
            if buf.contains(&b'\r') {
                return Err(LineReadError::BareCr);
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn read_bounded_line_rejects_bare_cr_and_accepts_clean_crlf() {
        let mut crlf = Cursor::new(b"{\"a\":1}\r\n".as_slice());
        assert_eq!(
            read_bounded_line(&mut crlf, 64).unwrap(),
            Some("{\"a\":1}".to_string())
        );

        let mut mid_cr = Cursor::new(b"{\"a\":1}\r{\"b\":2}\r\n".as_slice());
        assert!(matches!(
            read_bounded_line(&mut mid_cr, 64),
            Err(LineReadError::BareCr)
        ));

        let mut double_cr = Cursor::new(b"{\"a\":1}\r\r\n".as_slice());
        assert!(matches!(
            read_bounded_line(&mut double_cr, 64),
            Err(LineReadError::BareCr)
        ));

        let mut eof_cr = Cursor::new(b"{\"a\":1}\r".as_slice());
        assert!(matches!(
            read_bounded_line(&mut eof_cr, 64),
            Err(LineReadError::BareCr)
        ));
    }

    #[test]
    fn write_raw_line_refuses_embedded_cr_or_lf() {
        let mut out = Vec::new();
        assert!(matches!(
            write_raw_line(&mut out, "{\"a\":1}\r{\"b\":2}"),
            Err(ProxyError::UpstreamProtocol(_))
        ));
        assert!(out.is_empty());

        assert!(matches!(
            write_raw_line(&mut out, "{\"a\":1}\n{\"b\":2}"),
            Err(ProxyError::UpstreamProtocol(_))
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn jsonrpc_id_compares_numbers_losslessly_and_distinguishes_strings() {
        let id_15 = JsonRpcId::Number {
            raw: "1.5".to_string(),
            canonical: canonicalize_json_number("1.5").unwrap(),
        };
        let id_150 = JsonRpcId::Number {
            raw: "1.50".to_string(),
            canonical: canonicalize_json_number("1.50").unwrap(),
        };
        let id_str = JsonRpcId::Str("1.5".to_string());
        assert_eq!(id_15, id_150);
        assert_ne!(id_15, id_str);

        let big_a = JsonRpcId::Number {
            raw: "18446744073709551616".to_string(),
            canonical: canonicalize_json_number("18446744073709551616").unwrap(),
        };
        let big_b = JsonRpcId::Number {
            raw: "18446744073709551617".to_string(),
            canonical: canonicalize_json_number("18446744073709551617").unwrap(),
        };
        assert_ne!(big_a, big_b);
    }
}
