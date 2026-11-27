//! Strict zero-dependency HTTP/1.1 wire parser, serializer, path normalizer, query parser, and
//! hop-by-hop header sanitizer.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Default maximum total HTTP header block size in bytes (64 KiB).
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;

/// Default maximum number of HTTP headers accepted per message.
pub const DEFAULT_MAX_HEADER_COUNT: usize = 128;

/// Default maximum HTTP request body size in bytes (1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default maximum HTTP upstream response body size in bytes (16 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Supported HTTP methods for `HANDFEST v1` REST route policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    /// Parses an exact uppercase HTTP method token (`GET | POST | PUT | PATCH | DELETE`).
    pub fn parse(raw: &str) -> Result<Self, Http1Error> {
        match raw {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            other => Err(Http1Error::UnsupportedMethod(other.to_string())),
        }
    }

    /// Returns the canonical uppercase HTTP method string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsed HTTP/1.1 request passed into [`crate::HttpProxy::handle_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP/1.1 response returned by [`crate::HttpProxy::handle_request`] or upstream transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Constructs a JSON HTTP response with `Content-Type: application/json`.
    #[must_use]
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason: canonical_reason_phrase(status).to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: body.into(),
        }
    }
}

/// Strictly validated and normalized HTTP request target (path segments + query parameters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarget {
    /// Validated path component (starts with `/`, no traversal or empty segments).
    pub path: String,
    /// Decoded path segments (empty for root `"/"`).
    pub segments: Vec<String>,
    /// Strictly parsed query key-value map (unique, ASCII, no case collisions).
    pub query: BTreeMap<String, String>,
}

/// Structured errors returned by strict HTTP/1.1 parsing, validation, and serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1Error {
    EmptyStream,
    Io(String),
    UnexpectedEof,
    BareCr,
    BareLf,
    HeadersTooLarge { max_bytes: usize },
    TooManyHeaders { max_count: usize },
    InvalidRequestLine(String),
    InvalidStatusLine(String),
    UnsupportedMethod(String),
    UnsupportedVersion(String),
    InvalidHeaderLine(String),
    ObsoleteLineFolding,
    InvalidHeaderName(String),
    InvalidHeaderValue { name: String },
    MissingHostHeader,
    DuplicateHostHeader,
    DuplicateContentLength,
    InvalidContentLength(String),
    TransferEncodingWithContentLength,
    UnsupportedTransferEncoding(String),
    BodyTooLarge { max_bytes: usize },
    InvalidChunkedEncoding(String),
    InvalidTarget(String),
    PathTraversal(String),
    InvalidPercentEncoding(String),
    InvalidQuery(String),
    DuplicateQueryKey(String),
    CaseCollidingQueryKey { existing: String, colliding: String },
}

impl Http1Error {
    /// Maps a wire-level HTTP/1.1 framing error to its appropriate HTTP status code.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::UnsupportedMethod(_) => 405,
            Self::BodyTooLarge { .. } => 413,
            Self::HeadersTooLarge { .. } | Self::TooManyHeaders { .. } => 431,
            Self::UnsupportedVersion(_) => 505,
            _ => 400,
        }
    }
}

impl fmt::Display for Http1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStream => f.write_str("empty HTTP stream (EOF before request)"),
            Self::Io(msg) => write!(f, "HTTP I/O error: {msg}"),
            Self::UnexpectedEof => f.write_str("unexpected EOF while reading HTTP message"),
            Self::BareCr => f.write_str("bare CR without LF in HTTP framing"),
            Self::BareLf => f.write_str("bare LF without CR in HTTP framing"),
            Self::HeadersTooLarge { max_bytes } => {
                write!(f, "HTTP headers exceed maximum size of {max_bytes} bytes")
            }
            Self::TooManyHeaders { max_count } => {
                write!(f, "HTTP header count exceeds maximum of {max_count}")
            }
            Self::InvalidRequestLine(msg) => write!(f, "invalid HTTP request line: {msg}"),
            Self::InvalidStatusLine(msg) => write!(f, "invalid HTTP status line: {msg}"),
            Self::UnsupportedMethod(m) => write!(f, "unsupported HTTP method '{m}'"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported HTTP version '{v}'"),
            Self::InvalidHeaderLine(msg) => write!(f, "invalid HTTP header line: {msg}"),
            Self::ObsoleteLineFolding => {
                f.write_str("obsolete HTTP header line folding (obs-fold) is forbidden")
            }
            Self::InvalidHeaderName(name) => write!(f, "invalid HTTP header name '{name}'"),
            Self::InvalidHeaderValue { name } => {
                write!(f, "invalid HTTP header value for '{name}'")
            }
            Self::MissingHostHeader => f.write_str("HTTP/1.1 request missing required Host header"),
            Self::DuplicateHostHeader => f.write_str("HTTP/1.1 request has duplicate Host header"),
            Self::DuplicateContentLength => {
                f.write_str("duplicate Content-Length header is forbidden")
            }
            Self::InvalidContentLength(raw) => {
                write!(f, "invalid Content-Length value '{raw}'")
            }
            Self::TransferEncodingWithContentLength => f.write_str(
                "request/response smuggling rejected: Transfer-Encoding with Content-Length",
            ),
            Self::UnsupportedTransferEncoding(val) => {
                write!(f, "unsupported Transfer-Encoding '{val}'")
            }
            Self::BodyTooLarge { max_bytes } => {
                write!(f, "HTTP body exceeds maximum size of {max_bytes} bytes")
            }
            Self::InvalidChunkedEncoding(msg) => {
                write!(f, "invalid chunked transfer encoding: {msg}")
            }
            Self::InvalidTarget(msg) => write!(f, "invalid HTTP request target: {msg}"),
            Self::PathTraversal(msg) => write!(f, "HTTP path traversal rejected: {msg}"),
            Self::InvalidPercentEncoding(msg) => {
                write!(f, "invalid percent-encoding in URL: {msg}")
            }
            Self::InvalidQuery(msg) => write!(f, "invalid HTTP query string: {msg}"),
            Self::DuplicateQueryKey(key) => write!(f, "duplicate query parameter '{key}'"),
            Self::CaseCollidingQueryKey {
                existing,
                colliding,
            } => write!(
                f,
                "query parameter '{colliding}' collides case-insensitively with '{existing}'"
            ),
        }
    }
}

impl std::error::Error for Http1Error {}

/// Validates an RFC 9110 HTTP header field-name token (`1*tchar`).
#[must_use]
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_http_tchar)
}

const fn is_http_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

/// Validates an HTTP header field value (printable ASCII `0x20..=0x7E`; no HTAB/CR/LF/NUL/DEL).
#[must_use]
pub fn is_valid_header_value(value: &str) -> bool {
    value.bytes().all(|b| matches!(b, 0x20..=0x7E))
}

/// Returns `true` if `name` is a framing or authority header managed exclusively by the wire
/// serializer / upstream transport (`Host`, `Transfer-Encoding`, `Content-Length`, `Connection`).
#[must_use]
pub(crate) fn is_forbidden_outbound_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
}

/// Returns `true` if `name` is an RFC 9110 hop-by-hop header (case-insensitive).
#[must_use]
pub fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Returns `true` if `name` cannot be used as an operator-configured `upstream_auth` header.
#[must_use]
pub(crate) fn is_forbidden_auth_header_name(name: &str) -> bool {
    is_hop_by_hop_header(name)
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-encoding")
}

/// Strips hop-by-hop headers, `Connection`-nominated headers, framing headers (`Host`,
/// `Content-Length`), any client-supplied `Authorization`, and an optional configured auth header.
#[must_use]
pub fn sanitize_request_headers(
    headers: &[(String, String)],
    strip_auth_header: Option<&str>,
) -> Vec<(String, String)> {
    let connection_nominated = collect_connection_nominated_headers(headers);
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !is_hop_by_hop_header(&lower)
                && !connection_nominated.contains(&lower)
                && lower != "host"
                && lower != "content-length"
                && lower != "authorization"
                && lower != "expect"
                && lower != "x-http-method-override"
                && lower != "x-method-override"
                && lower != "x-http-method"
                && !strip_auth_header.is_some_and(|auth| auth.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

/// Strips hop-by-hop headers, `Connection`-nominated headers, and `Content-Length` from an
/// upstream response before relaying to the client.
#[must_use]
pub fn sanitize_response_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let connection_nominated = collect_connection_nominated_headers(headers);
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !is_hop_by_hop_header(&lower)
                && !connection_nominated.contains(&lower)
                && lower != "content-length"
        })
        .cloned()
        .collect()
}

fn collect_connection_nominated_headers(headers: &[(String, String)]) -> BTreeSet<String> {
    let mut nominated = BTreeSet::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',') {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    nominated.insert(trimmed.to_ascii_lowercase());
                }
            }
        }
    }
    nominated
}

/// Returns the canonical HTTP reason phrase for common status codes.
#[must_use]
pub const fn canonical_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

pub use crate::http1_target::{parse_query_string, parse_request_target};
pub(crate) use crate::http1_wire::{
    parse_headers, parse_status_line, read_header_lines, resolve_body_framing,
    validate_bodyless_response_headers, validate_decoded_response_body_len, validate_wire_target,
    MAX_INTERIM_RESPONSES,
};
pub use crate::http1_wire::{
    read_http_request, read_http_response, write_http_request_wire, write_http_response_wire,
};
