//! Bounded newline-delimited JSON-RPC 2.0 stdio framing and envelope validation helpers.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use crate::exact_json::{
    canonicalize_json_number, is_valid_json_int, write_json_string, CanonicalJsonNumber, ExactJson,
};
use crate::proxy::{ProxyError, HANDFEST_DENIED_ERROR_CODE};

pub(crate) const JSONRPC_PARSE_ERROR: i32 = -32700;
pub(crate) const JSONRPC_INVALID_REQUEST: i32 = -32600;
pub(crate) const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
pub(crate) const JSONRPC_INTERNAL_ERROR: i32 = -32603;

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
            let canonical = canonicalize_json_number(raw).map_err(|err| err.to_string())?;
            Ok(JsonRpcId::Number {
                raw: raw.clone(),
                canonical,
            })
        }
        _ => Err("JSON-RPC id must be a string or number".to_string()),
    }
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
mod tests {
    use std::io::Cursor;

    use crate::exact_json::parse_exact_json;

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
    fn read_bounded_line_accepts_exact_limit_payload_with_lf_and_crlf_across_chunk_splits() {
        use std::io::BufReader;

        let payload = br#"{"a":1}"#;
        let limit = payload.len();

        let mut lf = Cursor::new(b"{\"a\":1}\n".as_slice());
        assert_eq!(
            read_bounded_line(&mut lf, limit).unwrap(),
            Some("{\"a\":1}".to_string())
        );

        let mut crlf = Cursor::new(b"{\"a\":1}\r\n".as_slice());
        assert_eq!(
            read_bounded_line(&mut crlf, limit).unwrap(),
            Some("{\"a\":1}".to_string())
        );

        let mut crlf_split = BufReader::with_capacity(1, Cursor::new(b"{\"a\":1}\r\n".as_slice()));
        assert_eq!(
            read_bounded_line(&mut crlf_split, limit).unwrap(),
            Some("{\"a\":1}".to_string())
        );

        let mut crlf_over = Cursor::new(b"{\"a\":12}\r\n".as_slice());
        assert!(matches!(
            read_bounded_line(&mut crlf_over, limit),
            Err(LineReadError::TooLong)
        ));

        let mut crlf_over_split =
            BufReader::with_capacity(1, Cursor::new(b"{\"a\":12}\r\n".as_slice()));
        assert!(matches!(
            read_bounded_line(&mut crlf_over_split, limit),
            Err(LineReadError::TooLong)
        ));

        let mut eof_trailing_cr =
            BufReader::with_capacity(1, Cursor::new(b"{\"a\":1}\r".as_slice()));
        assert!(matches!(
            read_bounded_line(&mut eof_trailing_cr, limit),
            Err(LineReadError::TooLong)
        ));

        let mut double_cr_at_limit = Cursor::new(b"{\"a\":1}\r\r\n".as_slice());
        assert!(matches!(
            read_bounded_line(&mut double_cr_at_limit, limit),
            Err(LineReadError::TooLong)
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

    #[test]
    fn error_object_guard_requires_integer_code_and_string_message() {
        let valid = parse_exact_json(r#"{"code":-32601,"message":"not found"}"#).unwrap();
        assert!(is_valid_jsonrpc_error_object(&valid));

        let missing_msg = parse_exact_json(r#"{"code":-32601}"#).unwrap();
        assert!(!is_valid_jsonrpc_error_object(&missing_msg));

        let non_string_msg = parse_exact_json(r#"{"code":-32601,"message":42}"#).unwrap();
        assert!(!is_valid_jsonrpc_error_object(&non_string_msg));

        let null_msg = parse_exact_json(r#"{"code":-32601,"message":null}"#).unwrap();
        assert!(!is_valid_jsonrpc_error_object(&null_msg));

        let float_code = parse_exact_json(r#"{"code":1.5,"message":"bad"}"#).unwrap();
        assert!(!is_valid_jsonrpc_error_object(&float_code));
    }

    #[test]
    fn client_envelope_rejects_response_fields_and_primitive_params() {
        let bad_cases = [
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}"#,
                "client request/notification must not contain result or error",
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"ping","error":{"code":-1,"message":"x"}}"#,
                "client request/notification must not contain result or error",
            ),
            (
                r#"{"jsonrpc":"2.0","method":"notifications/initialized","result":null}"#,
                "client request/notification must not contain result or error",
            ),
            (
                r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":123}"#,
                "JSON-RPC params must be a JSON object or array",
            ),
            (
                r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":"bad"}"#,
                "JSON-RPC params must be a JSON object or array",
            ),
            (
                r#"{"jsonrpc":"2.0","id":3,"method":"ping","params":null}"#,
                "JSON-RPC params must be a JSON object or array",
            ),
        ];

        for (raw, expected_msg) in bad_cases {
            let parsed = parse_exact_json(raw).unwrap();
            let err = validate_client_envelope(parsed.as_object().unwrap()).unwrap_err();
            assert_eq!(err.message, expected_msg, "input: {raw}");
        }

        let valid_obj =
            parse_exact_json(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#).unwrap();
        assert!(validate_client_envelope(valid_obj.as_object().unwrap()).is_ok());

        let valid_arr =
            parse_exact_json(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}"#).unwrap();
        assert!(validate_client_envelope(valid_arr.as_object().unwrap()).is_ok());
    }
}
