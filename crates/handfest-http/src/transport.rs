//! Pluggable upstream HTTP/HTTPS transports:
//! - [`Http1TcpTransport`]: pure-Rust zero-dependency HTTP/1.1 TCP client (`http://`)
//! - [`CurlTlsTransport`]: zero-dependency HTTPS/TLS client (`https://`) backed by `curl` over
//!   [`CommandRunner`] with stdin `--config -` (zero secrets in `argv`) and `0600` temp body files

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use handfest_anchors::{AnchorError, CommandRunner, SystemCommandRunner};

use crate::http1::{
    is_forbidden_outbound_header, is_valid_header_name, is_valid_header_value, parse_headers,
    parse_status_line, read_header_lines, read_http_response, resolve_body_framing,
    sanitize_response_headers, validate_bodyless_response_headers,
    validate_decoded_response_body_len, validate_wire_target, write_http_request_wire, Http1Error,
    HttpMethod, DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_HEADER_COUNT, DEFAULT_MAX_RESPONSE_BYTES,
    MAX_INTERIM_RESPONSES,
};
use crate::policy::{ParsedBaseUrl, UpstreamScheme};

/// Default upstream connect/request timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

static TEMP_BODY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Outbound upstream HTTP/HTTPS request passed to [`UpstreamTransport::send`].
///
/// Redacts header values and body bytes in [`fmt::Debug`] so injected credentials cannot leak
/// into diagnostic logs.
#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamRequest {
    pub method: HttpMethod,
    pub url: String,
    pub target: String,
    pub host_header: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for UpstreamRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("UpstreamRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("target", &self.target)
            .field("host_header", &self.host_header)
            .field("header_names", &header_names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Raw upstream HTTP/HTTPS response returned by [`UpstreamTransport::send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Structured errors returned by [`UpstreamTransport`] implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    InvalidUrl(String),
    UnsupportedScheme {
        expected: &'static str,
        actual: String,
    },
    InvalidRequest(String),
    ConnectFailed(String),
    Io(String),
    InvalidResponse(String),
    ResponseTooLarge {
        max_bytes: usize,
    },
    CommandFailed(AnchorError),
    TempFileIo(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "invalid upstream URL: {msg}"),
            Self::UnsupportedScheme { expected, actual } => write!(
                f,
                "unsupported upstream URL scheme '{actual}'; expected '{expected}'"
            ),
            Self::InvalidRequest(msg) => write!(f, "invalid upstream request: {msg}"),
            Self::ConnectFailed(msg) => write!(f, "failed to connect to upstream: {msg}"),
            Self::Io(msg) => write!(f, "upstream I/O error: {msg}"),
            Self::InvalidResponse(msg) => write!(f, "invalid upstream HTTP response: {msg}"),
            Self::ResponseTooLarge { max_bytes } => {
                write!(
                    f,
                    "upstream response exceeds maximum size of {max_bytes} bytes"
                )
            }
            Self::CommandFailed(err) => write!(f, "upstream curl transport failed: {err}"),
            Self::TempFileIo(msg) => write!(f, "upstream temp body file error: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CommandFailed(err) => Some(err),
            _ => None,
        }
    }
}

/// Pluggable upstream transport seam (open for extension: HTTP/1.1 TCP, curl TLS, mocks).
pub trait UpstreamTransport {
    fn send(&self, req: &UpstreamRequest) -> Result<UpstreamResponse, TransportError>;
}

/// Pure-Rust zero-dependency HTTP/1.1 TCP client for `http://` upstreams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1TcpTransport {
    connect_timeout: Duration,
    io_timeout: Duration,
    max_header_bytes: usize,
    max_response_bytes: usize,
}

impl Default for Http1TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Http1TcpTransport {
    /// Creates an [`Http1TcpTransport`] with 30s timeouts, 64 KiB header cap, and 16 MiB response cap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            io_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Configures connect and read/write timeouts (must be non-zero).
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, TransportError> {
        if timeout.is_zero() {
            return Err(TransportError::InvalidRequest(
                "transport timeout must be greater than zero".to_string(),
            ));
        }
        self.connect_timeout = timeout;
        self.io_timeout = timeout;
        Ok(self)
    }

    /// Configures maximum response body size in bytes.
    #[must_use]
    pub const fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Configures maximum response header size in bytes.
    #[must_use]
    pub const fn with_max_header_bytes(mut self, max_header_bytes: usize) -> Self {
        self.max_header_bytes = max_header_bytes;
        self
    }
}

impl UpstreamTransport for Http1TcpTransport {
    fn send(&self, req: &UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        let base_url = validate_upstream_request(req, UpstreamScheme::Http)?;

        let wire = write_http_request_wire(
            req.method,
            &req.target,
            &req.host_header,
            &req.headers,
            &req.body,
        )
        .map_err(|err| TransportError::InvalidRequest(err.to_string()))?;

        let addr_str = base_url.socket_addr_string();
        let addrs: Vec<_> = addr_str
            .to_socket_addrs()
            .map_err(|err| TransportError::ConnectFailed(format!("resolve '{addr_str}': {err}")))?
            .collect();
        if addrs.is_empty() {
            return Err(TransportError::ConnectFailed(format!(
                "no addresses resolved for '{addr_str}'"
            )));
        }

        let mut stream = connect_first_addr(&addrs, self.connect_timeout, &addr_str)?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|err| TransportError::Io(err.to_string()))?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|err| TransportError::Io(err.to_string()))?;
        stream
            .write_all(&wire)
            .and_then(|()| stream.flush())
            .map_err(|err| TransportError::Io(err.to_string()))?;

        let mut reader = BufReader::new(&stream);
        let resp = read_http_response(&mut reader, self.max_header_bytes, self.max_response_bytes)
            .map_err(map_http1_response_err)?;

        Ok(UpstreamResponse {
            status: resp.status,
            reason: resp.reason,
            headers: sanitize_response_headers(&resp.headers),
            body: resp.body,
        })
    }
}

fn connect_first_addr(
    addrs: &[std::net::SocketAddr],
    timeout: Duration,
    label: &str,
) -> Result<TcpStream, TransportError> {
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    let detail = last_err.map_or_else(|| "no addresses".to_string(), |e| e.to_string());
    Err(TransportError::ConnectFailed(format!("{label}: {detail}")))
}

fn map_http1_response_err(err: Http1Error) -> TransportError {
    match err {
        Http1Error::BodyTooLarge { max_bytes } => TransportError::ResponseTooLarge { max_bytes },
        Http1Error::Io(msg) => TransportError::Io(msg),
        other => TransportError::InvalidResponse(other.to_string()),
    }
}

/// Zero-dependency HTTPS/TLS client delegating to system `curl` over [`CommandRunner`].
///
/// Enforces `--proto =https --tlsv1.2` and delivers method, URL, and injected auth headers
/// exclusively via stdin (`--config -`) so credentials never appear in `argv`/`ps`. Non-empty
/// request bodies are passed through an atomically created `0600` temp file that is deleted on
/// completion.
pub struct CurlTlsTransport<R: CommandRunner = SystemCommandRunner> {
    runner: R,
    timeout_secs: u64,
    max_header_bytes: usize,
    max_response_bytes: usize,
}

impl<R: CommandRunner> fmt::Debug for CurlTlsTransport<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurlTlsTransport")
            .field("timeout_secs", &self.timeout_secs)
            .field("max_header_bytes", &self.max_header_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl Default for CurlTlsTransport<SystemCommandRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl CurlTlsTransport<SystemCommandRunner> {
    /// Creates a production [`CurlTlsTransport`] backed by [`SystemCommandRunner`].
    #[must_use]
    pub const fn new() -> Self {
        Self::with_runner(SystemCommandRunner)
    }
}

impl<R: CommandRunner> CurlTlsTransport<R> {
    /// Creates a [`CurlTlsTransport`] with an injectable [`CommandRunner`] (for deterministic tests).
    #[must_use]
    pub const fn with_runner(runner: R) -> Self {
        Self {
            runner,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Configures `--max-time` timeout in seconds (must be >= 1).
    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Result<Self, TransportError> {
        if timeout_secs == 0 {
            return Err(TransportError::InvalidRequest(
                "curl timeout_secs must be >= 1".to_string(),
            ));
        }
        self.timeout_secs = timeout_secs;
        Ok(self)
    }

    /// Configures maximum response body size in bytes.
    #[must_use]
    pub const fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Configures maximum response header size in bytes.
    #[must_use]
    pub const fn with_max_header_bytes(mut self, max_header_bytes: usize) -> Self {
        self.max_header_bytes = max_header_bytes;
        self
    }
}

impl<R: CommandRunner> UpstreamTransport for CurlTlsTransport<R> {
    fn send(&self, req: &UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        let _base_url = validate_upstream_request(req, UpstreamScheme::Https)?;

        let temp_headers = TempFile::create_0600("handfest-http-headers", &[])?;
        let temp_body = if req.body.is_empty() {
            None
        } else {
            Some(TempFile::create_0600("handfest-http-body", &req.body)?)
        };

        let config_stdin = build_curl_config(
            req,
            temp_headers.path(),
            temp_body.as_ref().map(TempFile::path),
        )?;

        let max_time = self.timeout_secs.to_string();
        let args = [
            "--disable",
            "--globoff",
            "--suppress-connect-headers",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--silent",
            "--show-error",
            "--max-time",
            max_time.as_str(),
            "--config",
            "-",
        ];

        let output = self
            .runner
            .run("curl", &args, config_stdin.as_bytes())
            .map_err(TransportError::CommandFailed)?;

        drop(temp_body);
        let header_bytes = read_bounded_file(temp_headers.path(), self.max_header_bytes)?;
        drop(temp_headers);

        parse_curl_response(
            &header_bytes,
            &output.stdout,
            self.max_header_bytes,
            self.max_response_bytes,
        )
    }
}

/// Dispatches `http://` requests to [`Http1TcpTransport`] and `https://` requests to
/// [`CurlTlsTransport`].
#[derive(Debug)]
pub struct AutoUpstreamTransport<R: CommandRunner = SystemCommandRunner> {
    http1: Http1TcpTransport,
    curl_tls: CurlTlsTransport<R>,
}

impl Default for AutoUpstreamTransport<SystemCommandRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoUpstreamTransport<SystemCommandRunner> {
    /// Creates an [`AutoUpstreamTransport`] with default timeouts and size limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            http1: Http1TcpTransport::new(),
            curl_tls: CurlTlsTransport::new(),
        }
    }

    /// Creates an [`AutoUpstreamTransport`] with a uniform timeout in seconds.
    pub fn with_timeout_secs(timeout_secs: u64) -> Result<Self, TransportError> {
        let http1 = Http1TcpTransport::new().with_timeout(Duration::from_secs(timeout_secs))?;
        let curl_tls = CurlTlsTransport::new().with_timeout_secs(timeout_secs)?;
        Ok(Self { http1, curl_tls })
    }
}

impl<R: CommandRunner> AutoUpstreamTransport<R> {
    /// Creates an [`AutoUpstreamTransport`] from explicit `http1` and `curl_tls` transports.
    #[must_use]
    pub const fn from_parts(http1: Http1TcpTransport, curl_tls: CurlTlsTransport<R>) -> Self {
        Self { http1, curl_tls }
    }
}

impl<R: CommandRunner> UpstreamTransport for AutoUpstreamTransport<R> {
    fn send(&self, req: &UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
        let base_url = parse_url_origin(&req.url)?;
        match base_url.scheme {
            UpstreamScheme::Http => self.http1.send(req),
            UpstreamScheme::Https => self.curl_tls.send(req),
        }
    }
}

fn validate_upstream_request(
    req: &UpstreamRequest,
    expected_scheme: UpstreamScheme,
) -> Result<ParsedBaseUrl, TransportError> {
    let base_url = parse_url_origin(&req.url)?;
    if base_url.scheme != expected_scheme {
        return Err(TransportError::UnsupportedScheme {
            expected: expected_scheme.as_str(),
            actual: base_url.scheme.as_str().to_string(),
        });
    }
    validate_wire_target(&req.target)
        .map_err(|err| TransportError::InvalidRequest(err.to_string()))?;
    if req.host_header != base_url.host_header {
        return Err(TransportError::InvalidRequest(format!(
            "upstream host_header '{}' does not match URL origin host '{}'",
            req.host_header, base_url.host_header
        )));
    }
    let expected_url = format!("{}{}", base_url.origin, req.target);
    if req.url != expected_url {
        return Err(TransportError::InvalidRequest(format!(
            "upstream url '{}' does not match origin + target '{expected_url}'",
            req.url
        )));
    }
    for (name, value) in &req.headers {
        if !is_valid_header_name(name) {
            return Err(TransportError::InvalidRequest(format!(
                "invalid header name '{name}'"
            )));
        }
        if is_forbidden_outbound_header(name) {
            return Err(TransportError::InvalidRequest(format!(
                "forbidden framing/authority header '{name}'"
            )));
        }
        if !is_valid_header_value(value) {
            return Err(TransportError::InvalidRequest(format!(
                "invalid header value for '{name}'"
            )));
        }
    }
    Ok(base_url)
}

fn parse_url_origin(url: &str) -> Result<ParsedBaseUrl, TransportError> {
    if url.is_empty() || url.contains('#') || url.bytes().any(|b| b <= 0x20 || b >= 0x7F) {
        return Err(TransportError::InvalidUrl(
            "upstream URL must be non-empty printable ASCII without whitespace or fragment '#'"
                .to_string(),
        ));
    }
    let scheme_end = url
        .find("://")
        .ok_or_else(|| TransportError::InvalidUrl(format!("missing scheme in '{url}'")))?;
    let after_scheme = &url[scheme_end + 3..];
    let origin_end = after_scheme
        .find(['/', '?', '#'])
        .map_or(url.len(), |idx| scheme_end + 3 + idx);
    ParsedBaseUrl::parse(&url[..origin_end])
        .map_err(|err| TransportError::InvalidUrl(err.to_string()))
}

fn build_curl_config(
    req: &UpstreamRequest,
    header_file: &Path,
    body_file: Option<&Path>,
) -> Result<String, TransportError> {
    let mut cfg = String::with_capacity(256);
    push_curl_directive(&mut cfg, "request", req.method.as_str())?;
    push_curl_directive(&mut cfg, "url", &req.url)?;
    let header_path_str = header_file.to_str().ok_or_else(|| {
        TransportError::TempFileIo("temp header path is not valid UTF-8".to_string())
    })?;
    push_curl_directive(&mut cfg, "dump-header", header_path_str)?;
    for (name, value) in &req.headers {
        let header_line = if value.is_empty() {
            format!("{name};")
        } else {
            format!("{name}: {value}")
        };
        push_curl_directive(&mut cfg, "header", &header_line)?;
    }
    if let Some(path) = body_file {
        let path_str = path.to_str().ok_or_else(|| {
            TransportError::TempFileIo("temp body path is not valid UTF-8".to_string())
        })?;
        push_curl_directive(&mut cfg, "data-binary", &format!("@{path_str}"))?;
    } else if matches!(
        req.method,
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
    ) {
        push_curl_directive(&mut cfg, "header", "Content-Length: 0")?;
    }
    Ok(cfg)
}

fn push_curl_directive(out: &mut String, key: &str, value: &str) -> Result<(), TransportError> {
    if value.chars().any(char::is_control) {
        return Err(TransportError::InvalidRequest(format!(
            "curl config directive '{key}' must not contain control characters"
        )));
    }
    out.push_str(key);
    out.push_str(" = \"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push_str("\"\n");
    Ok(())
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, TransportError> {
    let file = File::open(path)
        .map_err(|err| TransportError::TempFileIo(format!("open '{}': {err}", path.display())))?;
    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut buf = Vec::new();
    file.take(cap)
        .read_to_end(&mut buf)
        .map_err(|err| TransportError::TempFileIo(format!("read '{}': {err}", path.display())))?;
    Ok(buf)
}

/// Parses separated `curl` `dump-header` file bytes and `stdout` body bytes.
///
/// Rejects any trailing bytes / HTTP trailers after the final response header block and rejects
/// `Transfer-Encoding` on `HTTP/2` responses (RFC 9113 §8.2.2).
pub(crate) fn parse_curl_response(
    header_bytes: &[u8],
    body_bytes: &[u8],
    max_header_bytes: usize,
    max_response_bytes: usize,
) -> Result<UpstreamResponse, TransportError> {
    let mut cursor = std::io::Cursor::new(header_bytes);
    let mut total_header_bytes = 0usize;
    for _ in 0..=MAX_INTERIM_RESPONSES {
        let remaining_budget = max_header_bytes.saturating_sub(total_header_bytes);
        let (lines, block_bytes) =
            read_header_lines(&mut cursor, remaining_budget, max_header_bytes, false)
                .map_err(|err| TransportError::InvalidResponse(err.to_string()))?;
        total_header_bytes = total_header_bytes.saturating_add(block_bytes);

        let (status_line, header_lines) = lines
            .split_first()
            .ok_or_else(|| TransportError::InvalidResponse("missing status line".to_string()))?;
        let (status, reason, is_http2) = parse_status_line(status_line, true)
            .map_err(|err| TransportError::InvalidResponse(err.to_string()))?;
        let headers = parse_headers(header_lines, DEFAULT_MAX_HEADER_COUNT)
            .map_err(|err| TransportError::InvalidResponse(err.to_string()))?;

        if (100..200).contains(&status) {
            validate_bodyless_response_headers(status, &headers)
                .map_err(|err| TransportError::InvalidResponse(err.to_string()))?;
            continue;
        }

        let end_pos = usize::try_from(cursor.position()).unwrap_or(header_bytes.len());
        if end_pos != header_bytes.len() {
            return Err(TransportError::InvalidResponse(
                "unexpected trailing bytes or HTTP trailers in curl dump-header file".to_string(),
            ));
        }

        if is_http2
            && headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        {
            return Err(TransportError::InvalidResponse(
                "Transfer-Encoding header is forbidden on HTTP/2 responses".to_string(),
            ));
        }

        let framing = resolve_body_framing(&headers, true, status)
            .map_err(|err| TransportError::InvalidResponse(err.to_string()))?;
        validate_decoded_response_body_len(status, framing, body_bytes.len())
            .map_err(TransportError::InvalidResponse)?;
        if body_bytes.len() > max_response_bytes {
            return Err(TransportError::ResponseTooLarge {
                max_bytes: max_response_bytes,
            });
        }

        return Ok(UpstreamResponse {
            status,
            reason,
            headers: sanitize_response_headers(&headers),
            body: body_bytes.to_vec(),
        });
    }
    Err(TransportError::InvalidResponse(
        "too many interim 1xx responses from upstream".to_string(),
    ))
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn create_0600(prefix: &str, contents: &[u8]) -> Result<Self, TransportError> {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());

        for attempt in 0..64u32 {
            let seq = TEMP_BODY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("{prefix}-{pid}-{nanos}-{seq}-{attempt}.tmp"));
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&path) {
                Ok(mut file) => {
                    if let Err(err) = write_temp_contents(&mut file, contents) {
                        let _ = fs::remove_file(&path);
                        return Err(TransportError::TempFileIo(format!(
                            "write '{}': {err}",
                            path.display()
                        )));
                    }
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(TransportError::TempFileIo(format!(
                        "create '{}': {err}",
                        path.display()
                    )));
                }
            }
        }
        Err(TransportError::TempFileIo(format!(
            "failed to allocate unique temp file '{prefix}' after 64 attempts"
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_temp_contents(file: &mut File, contents: &[u8]) -> std::io::Result<()> {
    if !contents.is_empty() {
        file.write_all(contents)?;
        file.flush()?;
    }
    Ok(())
}
