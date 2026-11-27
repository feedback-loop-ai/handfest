//! Strict HTTP/1.1 wire-frame reader and serializer with smuggling prevention.

use std::io::BufRead;

use crate::http1::{
    canonical_reason_phrase, is_forbidden_outbound_header, is_valid_header_name,
    is_valid_header_value, sanitize_response_headers, Http1Error, HttpMethod, HttpRequest,
    HttpResponse, DEFAULT_MAX_HEADER_COUNT,
};

const MAX_CHUNK_LINE_BYTES: usize = 64;
pub(crate) const MAX_INTERIM_RESPONSES: usize = 4;

/// Returns `true` for HTTP statuses that MUST NOT carry a message body (`1xx`, `204`, `304`).
#[must_use]
const fn is_bodyless_status(status: u16) -> bool {
    matches!(status, 100..=199 | 204 | 304)
}

/// Validates an outbound HTTP/1.1 origin-form request target (`/`-prefixed printable ASCII without
/// whitespace, control characters, or fragment `#`).
pub(crate) fn validate_wire_target(target: &str) -> Result<(), Http1Error> {
    if !target.starts_with('/')
        || target.contains('#')
        || target.bytes().any(|b| b <= 0x20 || b >= 0x7F)
    {
        return Err(Http1Error::InvalidTarget(
            "wire target must be valid ASCII origin-form starting with '/' without fragment '#'"
                .to_string(),
        ));
    }
    Ok(())
}

/// Rejects framing headers forbidden on bodyless HTTP responses (RFC 9110 §8.6 / RFC 9112 §6.1):
/// - `1xx` and `204`: MUST NOT contain `Content-Length` or `Transfer-Encoding`.
/// - `304`: MUST NOT contain `Transfer-Encoding`.
pub(crate) fn validate_bodyless_response_headers(
    status: u16,
    headers: &[(String, String)],
) -> Result<(), Http1Error> {
    let forbid_cl = matches!(status, 100..=199 | 204);
    let forbid_te = is_bodyless_status(status);
    if !forbid_te {
        return Ok(());
    }
    for (name, _) in headers {
        if forbid_cl && name.eq_ignore_ascii_case("content-length") {
            return Err(Http1Error::InvalidContentLength(format!(
                "Content-Length is forbidden on HTTP {status} response"
            )));
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Http1Error::UnsupportedTransferEncoding(format!(
                "Transfer-Encoding is forbidden on HTTP {status} response"
            )));
        }
    }
    Ok(())
}

/// Reads and strictly validates one HTTP/1.1 request from `reader`.
pub fn read_http_request<R: BufRead>(
    reader: &mut R,
    max_header_bytes: usize,
    max_body_bytes: usize,
) -> Result<HttpRequest, Http1Error> {
    let (lines, _) = read_header_lines(reader, max_header_bytes, max_header_bytes, true)?;
    let (request_line, header_lines) = lines.split_first().ok_or(Http1Error::EmptyStream)?;
    let (method, target) = parse_request_line(request_line)?;
    let headers = parse_headers(header_lines, DEFAULT_MAX_HEADER_COUNT)?;
    validate_single_host_header(&headers)?;
    let framing = resolve_body_framing(&headers, false, 0)?;
    let body = read_body(reader, framing, max_body_bytes)?;
    Ok(HttpRequest {
        method,
        target,
        headers,
        body,
    })
}

/// Reads and strictly validates one HTTP/1.1 (or HTTP/1.0) response from `reader`,
/// skipping up to 4 interim `1xx` responses (e.g. `100 Continue`, `103 Early Hints`).
pub fn read_http_response<R: BufRead>(
    reader: &mut R,
    max_header_bytes: usize,
    max_body_bytes: usize,
) -> Result<HttpResponse, Http1Error> {
    let mut total_header_bytes = 0usize;
    for _ in 0..=MAX_INTERIM_RESPONSES {
        let remaining_budget = max_header_bytes.saturating_sub(total_header_bytes);
        let (lines, block_bytes) =
            read_header_lines(reader, remaining_budget, max_header_bytes, false)?;
        total_header_bytes = total_header_bytes.saturating_add(block_bytes);
        let (status_line, header_lines) = lines.split_first().ok_or(Http1Error::UnexpectedEof)?;
        let (status, reason, _) = parse_status_line(status_line, false)?;
        let headers = parse_headers(header_lines, DEFAULT_MAX_HEADER_COUNT)?;
        if (100..200).contains(&status) {
            validate_bodyless_response_headers(status, &headers)?;
            continue;
        }
        let framing = resolve_body_framing(&headers, true, status)?;
        let body = read_body(reader, framing, max_body_bytes)?;
        return Ok(HttpResponse {
            status,
            reason,
            headers,
            body,
        });
    }
    Err(Http1Error::InvalidStatusLine(
        "too many interim 1xx responses from upstream".to_string(),
    ))
}

/// Serializes an HTTP/1.1 request to wire bytes with explicit `Host`, `Connection: close`, and
/// `Content-Length`.
pub fn write_http_request_wire(
    method: HttpMethod,
    target: &str,
    host_header: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<u8>, Http1Error> {
    validate_wire_target(target)?;
    if host_header.is_empty() || !is_valid_header_value(host_header) {
        return Err(Http1Error::InvalidHeaderValue {
            name: "Host".to_string(),
        });
    }
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host_header.as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\n");
    for (name, value) in headers {
        if !is_valid_header_name(name) || is_forbidden_outbound_header(name) {
            return Err(Http1Error::InvalidHeaderName(name.clone()));
        }
        if !is_valid_header_value(value) {
            return Err(Http1Error::InvalidHeaderValue { name: name.clone() });
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let needs_cl = !body.is_empty()
        || matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
        );
    if needs_cl {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}

/// Serializes an [`HttpResponse`] to HTTP/1.1 wire bytes, stripping hop-by-hop headers and
/// emitting an authoritative `Content-Length` and `Connection: close`.
#[must_use]
pub fn write_http_response_wire(resp: &HttpResponse) -> Vec<u8> {
    let reason = if resp.reason.is_empty() || !is_valid_header_value(&resp.reason) {
        canonical_reason_phrase(resp.status)
    } else {
        resp.reason.as_str()
    };
    let clean_headers = sanitize_response_headers(&resp.headers);
    let mut out = Vec::with_capacity(256 + resp.body.len());
    out.extend_from_slice(format!("HTTP/1.1 {} {reason}\r\n", resp.status).as_bytes());
    for (name, value) in &clean_headers {
        if is_valid_header_name(name) && is_valid_header_value(value) {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    let bodyless = is_bodyless_status(resp.status);
    if !bodyless {
        out.extend_from_slice(format!("Content-Length: {}\r\n", resp.body.len()).as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    if !bodyless {
        out.extend_from_slice(&resp.body);
    }
    out
}

pub(crate) fn read_header_lines<R: BufRead>(
    reader: &mut R,
    remaining_budget: usize,
    reported_max_bytes: usize,
    empty_eof_is_empty_stream: bool,
) -> Result<(Vec<String>, usize), Http1Error> {
    let mut lines = Vec::new();
    let mut total_bytes = 0usize;
    loop {
        let budget = remaining_budget.saturating_sub(total_bytes);
        let line_bytes = read_crlf_line(reader, budget, reported_max_bytes)?;
        match line_bytes {
            None => {
                if lines.is_empty() && empty_eof_is_empty_stream {
                    return Err(Http1Error::EmptyStream);
                }
                return Err(Http1Error::UnexpectedEof);
            }
            Some((buf, raw_len)) => {
                total_bytes =
                    total_bytes
                        .checked_add(raw_len)
                        .ok_or(Http1Error::HeadersTooLarge {
                            max_bytes: reported_max_bytes,
                        })?;
                if total_bytes > remaining_budget {
                    return Err(Http1Error::HeadersTooLarge {
                        max_bytes: reported_max_bytes,
                    });
                }
                if buf.is_empty() {
                    if lines.is_empty() {
                        return Err(Http1Error::InvalidRequestLine(
                            "unexpected leading blank line".to_string(),
                        ));
                    }
                    return Ok((lines, total_bytes));
                }
                let line = String::from_utf8(buf).map_err(|_| {
                    Http1Error::InvalidHeaderLine("non-UTF-8 bytes in HTTP header".to_string())
                })?;
                lines.push(line);
            }
        }
    }
}

fn read_crlf_line<R: BufRead>(
    reader: &mut R,
    remaining_budget: usize,
    max_header_bytes: usize,
) -> Result<Option<(Vec<u8>, usize)>, Http1Error> {
    let mut line = Vec::new();
    let mut read_count = 0usize;
    loop {
        let mut byte = [0u8; 1];
        let n = reader
            .read(&mut byte)
            .map_err(|err| Http1Error::Io(err.to_string()))?;
        if n == 0 {
            if read_count == 0 {
                return Ok(None);
            }
            return Err(Http1Error::UnexpectedEof);
        }
        read_count += 1;
        if read_count > remaining_budget {
            return Err(Http1Error::HeadersTooLarge {
                max_bytes: max_header_bytes,
            });
        }
        match byte[0] {
            b'\n' => return Err(Http1Error::BareLf),
            b'\r' => {
                let mut next = [0u8; 1];
                let n2 = reader
                    .read(&mut next)
                    .map_err(|err| Http1Error::Io(err.to_string()))?;
                if n2 == 0 || next[0] != b'\n' {
                    return Err(Http1Error::BareCr);
                }
                read_count += 1;
                if read_count > remaining_budget {
                    return Err(Http1Error::HeadersTooLarge {
                        max_bytes: max_header_bytes,
                    });
                }
                return Ok(Some((line, read_count)));
            }
            b => line.push(b),
        }
    }
}

fn parse_request_line(line: &str) -> Result<(HttpMethod, String), Http1Error> {
    let mut parts = line.split(' ');
    let (Some(raw_method), Some(raw_target), Some(raw_version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Http1Error::InvalidRequestLine(
            "expected 'METHOD SP target SP HTTP/1.1'".to_string(),
        ));
    };
    if raw_version != "HTTP/1.1" {
        return Err(Http1Error::UnsupportedVersion(raw_version.to_string()));
    }
    let method = HttpMethod::parse(raw_method)?;
    if !raw_target.starts_with('/') || raw_target.bytes().any(|b| b <= 0x20 || b >= 0x7F) {
        return Err(Http1Error::InvalidTarget(format!(
            "request target '{raw_target}' must be ASCII origin-form starting with '/'"
        )));
    }
    Ok((method, raw_target.to_string()))
}

pub(crate) fn parse_status_line(
    line: &str,
    allow_http2: bool,
) -> Result<(u16, String, bool), Http1Error> {
    let Some((version, rest)) = line.split_once(' ') else {
        return Err(Http1Error::InvalidStatusLine(
            "missing space after HTTP version".to_string(),
        ));
    };
    let is_http2 = allow_http2 && (version == "HTTP/2" || version == "HTTP/2.0");
    let valid_version = version == "HTTP/1.1" || version == "HTTP/1.0" || is_http2;
    if !valid_version {
        return Err(Http1Error::UnsupportedVersion(version.to_string()));
    }
    let (status_str, reason_raw) = match rest.split_once(' ') {
        Some((code, reason)) => (code, reason.trim()),
        None => (rest, ""),
    };
    if status_str.len() != 3 || !status_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Http1Error::InvalidStatusLine(format!(
            "invalid status code '{status_str}'"
        )));
    }
    let status: u16 = status_str
        .parse()
        .map_err(|_| Http1Error::InvalidStatusLine(format!("invalid status '{status_str}'")))?;
    if !(100..=599).contains(&status) {
        return Err(Http1Error::InvalidStatusLine(format!(
            "status code {status} out of range 100..=599"
        )));
    }
    if status == 101 {
        return Err(Http1Error::InvalidStatusLine(
            "unsolicited 101 Switching Protocols response is forbidden".to_string(),
        ));
    }
    if !is_valid_header_value(reason_raw) {
        return Err(Http1Error::InvalidStatusLine(
            "invalid characters in reason phrase".to_string(),
        ));
    }
    let reason = if reason_raw.is_empty() {
        canonical_reason_phrase(status).to_string()
    } else {
        reason_raw.to_string()
    };
    Ok((status, reason, is_http2))
}

pub(crate) fn parse_headers(
    lines: &[String],
    max_header_count: usize,
) -> Result<Vec<(String, String)>, Http1Error> {
    if lines.len() > max_header_count {
        return Err(Http1Error::TooManyHeaders {
            max_count: max_header_count,
        });
    }
    let mut headers = Vec::with_capacity(lines.len());
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(Http1Error::ObsoleteLineFolding);
        }
        let Some((name, raw_value)) = line.split_once(':') else {
            return Err(Http1Error::InvalidHeaderLine(
                "missing ':' separator".to_string(),
            ));
        };
        if !is_valid_header_name(name) {
            return Err(Http1Error::InvalidHeaderName(name.to_string()));
        }
        let value = raw_value.trim_matches(|c| c == ' ' || c == '\t');
        if !is_valid_header_value(value) {
            return Err(Http1Error::InvalidHeaderValue {
                name: name.to_string(),
            });
        }
        headers.push((name.to_string(), value.to_string()));
    }
    Ok(headers)
}

fn validate_single_host_header(headers: &[(String, String)]) -> Result<(), Http1Error> {
    let mut host_count = 0usize;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") {
            if value.is_empty() {
                return Err(Http1Error::InvalidHeaderValue { name: name.clone() });
            }
            host_count += 1;
        }
    }
    match host_count {
        0 => Err(Http1Error::MissingHostHeader),
        1 => Ok(()),
        _ => Err(Http1Error::DuplicateHostHeader),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFraming {
    Empty,
    ContentLength(usize),
    Chunked,
    ReadToEof,
}

pub(crate) fn resolve_body_framing(
    headers: &[(String, String)],
    is_response: bool,
    status: u16,
) -> Result<BodyFraming, Http1Error> {
    if is_response {
        validate_bodyless_response_headers(status, headers)?;
    }
    let mut content_length: Option<usize> = None;
    let mut transfer_encoding: Option<&str> = None;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Http1Error::DuplicateContentLength);
            }
            content_length = Some(parse_content_length(value)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(Http1Error::UnsupportedTransferEncoding(
                    "duplicate Transfer-Encoding header".to_string(),
                ));
            }
            transfer_encoding = Some(value.as_str());
        }
    }

    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(Http1Error::TransferEncodingWithContentLength);
    }

    if is_response && is_bodyless_status(status) {
        return Ok(BodyFraming::Empty);
    }

    if let Some(te) = transfer_encoding {
        if te.eq_ignore_ascii_case("chunked") {
            return Ok(BodyFraming::Chunked);
        }
        return Err(Http1Error::UnsupportedTransferEncoding(te.to_string()));
    }

    match content_length {
        Some(0) => Ok(BodyFraming::Empty),
        Some(len) => Ok(BodyFraming::ContentLength(len)),
        None if is_response => Ok(BodyFraming::ReadToEof),
        None => Ok(BodyFraming::Empty),
    }
}

/// Validates that a decoded upstream response body length matches the resolved HTTP framing
/// (bodyless `1xx`/`204`/`304`, `Content-Length: 0`, or explicit `Content-Length: N`).
pub(crate) fn validate_decoded_response_body_len(
    status: u16,
    framing: BodyFraming,
    body_len: usize,
) -> Result<(), String> {
    match framing {
        BodyFraming::Empty if body_len > 0 => {
            if is_bodyless_status(status) {
                Err(format!(
                    "bodyless HTTP {status} response must not contain body bytes"
                ))
            } else {
                Err(format!(
                    "response body length {body_len} does not match Content-Length 0"
                ))
            }
        }
        BodyFraming::ContentLength(expected) if body_len != expected => Err(format!(
            "response body length {body_len} does not match Content-Length {expected}"
        )),
        BodyFraming::Empty
        | BodyFraming::ContentLength(_)
        | BodyFraming::Chunked
        | BodyFraming::ReadToEof => Ok(()),
    }
}

fn parse_content_length(raw: &str) -> Result<usize, Http1Error> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Http1Error::InvalidContentLength(raw.to_string()));
    }
    raw.parse::<usize>()
        .map_err(|_| Http1Error::InvalidContentLength(raw.to_string()))
}

fn read_body<R: BufRead>(
    reader: &mut R,
    framing: BodyFraming,
    max_body_bytes: usize,
) -> Result<Vec<u8>, Http1Error> {
    match framing {
        BodyFraming::Empty => Ok(Vec::new()),
        BodyFraming::ContentLength(len) => {
            if len > max_body_bytes {
                return Err(Http1Error::BodyTooLarge {
                    max_bytes: max_body_bytes,
                });
            }
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|err| map_body_read_err(&err))?;
            Ok(buf)
        }
        BodyFraming::Chunked => read_chunked_body(reader, max_body_bytes),
        BodyFraming::ReadToEof => read_bounded_to_eof(reader, max_body_bytes),
    }
}

fn read_chunked_body<R: BufRead>(
    reader: &mut R,
    max_body_bytes: usize,
) -> Result<Vec<u8>, Http1Error> {
    let mut body = Vec::new();
    loop {
        let size_line = read_crlf_line(reader, MAX_CHUNK_LINE_BYTES, MAX_CHUNK_LINE_BYTES)
            .map_err(|err| match err {
                Http1Error::HeadersTooLarge { .. } => {
                    Http1Error::InvalidChunkedEncoding("chunk size line too long".to_string())
                }
                other => other,
            })?;
        let Some((size_bytes, _)) = size_line else {
            return Err(Http1Error::UnexpectedEof);
        };
        let size_str = std::str::from_utf8(&size_bytes)
            .map_err(|_| Http1Error::InvalidChunkedEncoding("non-UTF-8 chunk size".to_string()))?;
        if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Http1Error::InvalidChunkedEncoding(format!(
                "invalid chunk size '{size_str}'"
            )));
        }
        let chunk_len = usize::from_str_radix(size_str, 16).map_err(|_| {
            Http1Error::InvalidChunkedEncoding(format!("chunk size overflow '{size_str}'"))
        })?;
        if chunk_len == 0 {
            let mut end_crlf = [0u8; 2];
            reader
                .read_exact(&mut end_crlf)
                .map_err(|err| map_body_read_err(&err))?;
            if end_crlf != *b"\r\n" {
                return Err(Http1Error::InvalidChunkedEncoding(
                    "HTTP chunked trailers or missing final CRLF are forbidden".to_string(),
                ));
            }
            return Ok(body);
        }
        let new_len = body
            .len()
            .checked_add(chunk_len)
            .ok_or(Http1Error::BodyTooLarge {
                max_bytes: max_body_bytes,
            })?;
        if new_len > max_body_bytes {
            return Err(Http1Error::BodyTooLarge {
                max_bytes: max_body_bytes,
            });
        }
        let start = body.len();
        body.resize(new_len, 0);
        reader
            .read_exact(&mut body[start..])
            .map_err(|err| map_body_read_err(&err))?;
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|err| map_body_read_err(&err))?;
        if crlf != *b"\r\n" {
            return Err(Http1Error::InvalidChunkedEncoding(
                "missing CRLF after chunk payload".to_string(),
            ));
        }
    }
}

fn read_bounded_to_eof<R: BufRead>(
    reader: &mut R,
    max_body_bytes: usize,
) -> Result<Vec<u8>, Http1Error> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|err| Http1Error::Io(err.to_string()))?;
        if n == 0 {
            return Ok(body);
        }
        let new_len = body.len().checked_add(n).ok_or(Http1Error::BodyTooLarge {
            max_bytes: max_body_bytes,
        })?;
        if new_len > max_body_bytes {
            return Err(Http1Error::BodyTooLarge {
                max_bytes: max_body_bytes,
            });
        }
        body.extend_from_slice(&chunk[..n]);
    }
}

fn map_body_read_err(err: &std::io::Error) -> Http1Error {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        Http1Error::UnexpectedEof
    } else {
        Http1Error::Io(err.to_string())
    }
}
