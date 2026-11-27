//! Fail-closed HTTP/REST Policy Enforcement Point wrapping [`GateEngine`],
//! [`CompiledHttpPolicyMap`], and a pluggable [`UpstreamTransport`].

use std::fmt;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use handfest_core::ast::KeyId;
use handfest_core::exact_json::write_json_string;
use handfest_core::gate::{ActionRequest, RevocationSnapshot, VerifiedMandate};
use handfest_ledger::{ReceiptLedger, SqliteLedger};
use handfest_pep::{Clock, GateDecision, GateEngine, PepError, SecretError};

use crate::http1::{
    is_valid_header_name, is_valid_header_value, parse_request_target, read_http_request,
    resolve_body_framing, sanitize_request_headers, sanitize_response_headers,
    validate_decoded_response_body_len, write_http_response_wire, Http1Error, HttpRequest,
    HttpResponse, DEFAULT_MAX_HEADER_BYTES,
};
use crate::policy::{CompiledHttpPolicyMap, HttpPolicyError, HttpPolicyMap};
use crate::transport::{AutoUpstreamTransport, TransportError, UpstreamRequest, UpstreamTransport};

const DEFAULT_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Typed errors returned by [`HttpProxy`].
#[derive(Debug)]
pub enum HttpProxyError {
    Pep(PepError),
    Policy(HttpPolicyError),
    Credential(SecretError),
    Transport(TransportError),
    NonLoopbackBind(std::net::SocketAddr),
    InvalidConfig(String),
    Io(std::io::Error),
}

impl fmt::Display for HttpProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pep(err) => write!(f, "PEP engine error: {err}"),
            Self::Policy(err) => write!(f, "HTTP policy error: {err}"),
            Self::Credential(err) => write!(f, "upstream credential error: {err}"),
            Self::Transport(err) => write!(f, "upstream transport error: {err}"),
            Self::NonLoopbackBind(addr) => {
                write!(f, "refusing to serve non-loopback listener address {addr}")
            }
            Self::InvalidConfig(msg) => write!(f, "invalid HTTP proxy configuration: {msg}"),
            Self::Io(err) => write!(f, "HTTP listener I/O error: {err}"),
        }
    }
}

impl std::error::Error for HttpProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pep(err) => Some(err),
            Self::Policy(err) => Some(err),
            Self::Credential(err) => Some(err),
            Self::Transport(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::NonLoopbackBind(_) | Self::InvalidConfig(_) => None,
        }
    }
}

impl From<PepError> for HttpProxyError {
    fn from(err: PepError) -> Self {
        Self::Pep(err)
    }
}

impl From<HttpPolicyError> for HttpProxyError {
    fn from(err: HttpPolicyError) -> Self {
        Self::Policy(err)
    }
}

impl From<SecretError> for HttpProxyError {
    fn from(err: SecretError) -> Self {
        Self::Credential(err)
    }
}

impl From<TransportError> for HttpProxyError {
    fn from(err: TransportError) -> Self {
        Self::Transport(err)
    }
}

impl From<std::io::Error> for HttpProxyError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Fail-closed HTTP/REST Policy Enforcement Point enforcing a verified `HANDFEST v1` mandate
/// chain over [`GateEngine`], [`CompiledHttpPolicyMap`], and [`UpstreamTransport`].
pub struct HttpProxy<
    C: Clock,
    L: ReceiptLedger = SqliteLedger,
    T: UpstreamTransport = AutoUpstreamTransport,
> {
    engine: GateEngine<C, L>,
    policy_map: CompiledHttpPolicyMap,
    transport: T,
    max_header_bytes: usize,
    client_io_timeout: Duration,
}

impl<C: Clock, L: ReceiptLedger, T: UpstreamTransport> fmt::Debug for HttpProxy<C, L, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxy")
            .field("chain_len", &self.engine.verified_chain().len())
            .field("actor_key", self.engine.actor_key())
            .field("upstream_origin", &self.policy_map.base_url().origin)
            .field("route_count", &self.policy_map.routes().len())
            .field("max_header_bytes", &self.max_header_bytes)
            .finish_non_exhaustive()
    }
}

impl<C: Clock, L: ReceiptLedger, T: UpstreamTransport> HttpProxy<C, L, T> {
    /// Constructs a validated [`HttpProxy`] from a verified mandate chain, actor key, policy map,
    /// receipt ledger, clock, and upstream transport.
    pub fn new(
        verified_chain: Vec<VerifiedMandate>,
        actor_key: KeyId,
        policy_map: HttpPolicyMap,
        ledger: L,
        clock: C,
        transport: T,
    ) -> Result<Self, HttpProxyError> {
        let engine = GateEngine::new(verified_chain, actor_key, ledger, clock)?;
        let compiled = policy_map.compile()?;
        Ok(Self {
            engine,
            policy_map: compiled,
            transport,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            client_io_timeout: DEFAULT_CLIENT_IO_TIMEOUT,
        })
    }

    /// Attaches static verified revocations enforced alongside revocations persisted in `ledger`.
    #[must_use]
    pub fn with_revocations(mut self, revocations: RevocationSnapshot) -> Self {
        self.engine = self.engine.with_revocations(revocations);
        self
    }

    /// Overrides the maximum accepted incoming HTTP header block size in bytes.
    pub fn with_max_header_bytes(
        mut self,
        max_header_bytes: usize,
    ) -> Result<Self, HttpProxyError> {
        if max_header_bytes == 0 {
            return Err(HttpProxyError::InvalidConfig(
                "max_header_bytes must be greater than zero".to_string(),
            ));
        }
        self.max_header_bytes = max_header_bytes;
        Ok(self)
    }

    /// Overrides the per-client TCP read/write timeout used by [`Self::serve_listener`].
    pub fn with_client_io_timeout(mut self, timeout: Duration) -> Result<Self, HttpProxyError> {
        if timeout.is_zero() {
            return Err(HttpProxyError::InvalidConfig(
                "client_io_timeout must be greater than zero".to_string(),
            ));
        }
        self.client_io_timeout = timeout;
        Ok(self)
    }

    /// Borrows the underlying [`ReceiptLedger`].
    #[must_use]
    pub const fn ledger(&self) -> &L {
        self.engine.ledger()
    }

    /// Borrows the compiled [`CompiledHttpPolicyMap`].
    #[must_use]
    pub const fn policy_map(&self) -> &CompiledHttpPolicyMap {
        &self.policy_map
    }

    /// Consumes the proxy and returns its underlying [`ReceiptLedger`].
    #[must_use]
    pub fn into_ledger(self) -> L {
        self.engine.into_ledger()
    }

    /// Evaluates one HTTP request against the compiled route policy and `HANDFEST v1` mandate
    /// chain, recording a tamper-evident receipt and forwarding to `T` only on `Permit`.
    pub fn handle_request(
        &mut self,
        raw_req: &HttpRequest,
    ) -> Result<HttpResponse, HttpProxyError> {
        let now = self.engine.now_unix();

        let parsed = match parse_request_target(&raw_req.target) {
            Ok(parsed) => parsed,
            Err(err) => {
                let denial_req = ActionRequest {
                    actor_key: self.engine.actor_key().clone(),
                    action: format!("http.invalid_target:{}", raw_req.method),
                    resource_kind: "http_route".to_string(),
                    resource_id: raw_req.target.clone(),
                };
                return self.record_pre_gate_denial_response(&denial_req, err.to_string(), now);
            }
        };

        if let Err(err) = validate_request_headers(&raw_req.headers) {
            let denial_req = ActionRequest {
                actor_key: self.engine.actor_key().clone(),
                action: format!("http.invalid_header:{}", raw_req.method),
                resource_kind: "http_route".to_string(),
                resource_id: parsed.path,
            };
            return self.record_pre_gate_denial_response(&denial_req, err.to_string(), now);
        }

        let Some((route, path_params)) = self
            .policy_map
            .match_route(raw_req.method, &parsed.segments)
        else {
            let err = HttpPolicyError::UnmappedRoute {
                method: raw_req.method,
                path: parsed.path.clone(),
            };
            let denial_req = ActionRequest {
                actor_key: self.engine.actor_key().clone(),
                action: format!("http.unmapped:{}:{}", raw_req.method, parsed.path),
                resource_kind: "http_route".to_string(),
                resource_id: parsed.path,
            };
            return self.record_pre_gate_denial_response(&denial_req, err.to_string(), now);
        };

        let strip_auth_header = self.policy_map.upstream_auth().map(|a| a.header_name());
        let outbound_headers = sanitize_request_headers(&raw_req.headers, strip_auth_header);
        if route.policy().requires_json_body() {
            if let Err(reason) = validate_json_body_headers(&raw_req.headers, &outbound_headers) {
                let denial_req =
                    self.build_route_denial_request(route, &path_params, &parsed.query, &[]);
                return self.record_pre_gate_denial_response(&denial_req, reason, now);
            }
        }

        let (request, facts) = match self.policy_map.extract_request(
            self.engine.actor_key(),
            route,
            &path_params,
            &parsed.query,
            &raw_req.body,
        ) {
            Ok(extracted) => extracted,
            Err(err) => {
                let denial_req = self.build_route_denial_request(
                    route,
                    &path_params,
                    &parsed.query,
                    &raw_req.body,
                );
                return self.record_pre_gate_denial_response(&denial_req, err.to_string(), now);
            }
        };

        match self.engine.authorize_at(&request, &facts, now)? {
            GateDecision::Deny { reason, receipt } => Ok(build_denied_response(
                &reason,
                &receipt.receipt_hash.to_string(),
            )),
            GateDecision::Permit { .. } => {
                self.forward_permitted_request(raw_req, outbound_headers)
            }
        }
    }

    /// Serves incoming HTTP/1.1 connections on a loopback [`TcpListener`] (`127.0.0.1` / `::1`).
    ///
    /// Refuses non-loopback listeners fail-closed. Wire-framing/smuggling errors return structured
    /// JSON `4xx`/`5xx` responses without invoking the upstream transport.
    pub fn serve_listener(&mut self, listener: TcpListener) -> Result<(), HttpProxyError> {
        let local_addr = listener.local_addr()?;
        if !local_addr.ip().is_loopback() {
            return Err(HttpProxyError::NonLoopbackBind(local_addr));
        }

        for incoming in listener.incoming() {
            let stream = match incoming {
                Ok(s) => s,
                Err(err) => return Err(HttpProxyError::Io(err)),
            };
            self.serve_connection(stream)?;
        }
        Ok(())
    }

    /// Handles a single incoming HTTP/1.1 connection on `stream`.
    ///
    /// Returns `Err` only on fatal ledger integrity failures; client framing errors, credential
    /// errors, and upstream transport errors are converted into structured JSON HTTP responses.
    pub fn serve_connection(&mut self, mut stream: TcpStream) -> Result<(), HttpProxyError> {
        let _ = stream.set_read_timeout(Some(self.client_io_timeout));
        let _ = stream.set_write_timeout(Some(self.client_io_timeout));

        let max_body = self.policy_map.max_route_body_bytes();
        let req = {
            let mut reader = BufReader::new(&stream);
            match read_http_request(&mut reader, self.max_header_bytes, max_body) {
                Ok(req) => req,
                Err(Http1Error::EmptyStream) => return Ok(()),
                Err(err) => {
                    let resp = build_error_response(
                        err.http_status(),
                        "http_framing_error",
                        &err.to_string(),
                    );
                    let _ = write_and_flush(&mut stream, &resp);
                    return Ok(());
                }
            }
        };

        match self.handle_request(&req) {
            Ok(resp) => {
                let _ = write_and_flush(&mut stream, &resp);
                Ok(())
            }
            Err(HttpProxyError::Transport(err)) => {
                let resp = build_error_response(502, "upstream_transport_error", &err.to_string());
                let _ = write_and_flush(&mut stream, &resp);
                Ok(())
            }
            Err(HttpProxyError::Credential(err)) => {
                let resp = build_error_response(500, "credential_error", &err.to_string());
                let _ = write_and_flush(&mut stream, &resp);
                Ok(())
            }
            Err(HttpProxyError::Pep(PepError::Ledger(err))) => {
                let resp = build_error_response(500, "ledger_error", &err.to_string());
                let _ = write_and_flush(&mut stream, &resp);
                Err(HttpProxyError::Pep(PepError::Ledger(err)))
            }
            Err(other) => {
                let resp = build_error_response(500, "proxy_error", &other.to_string());
                let _ = write_and_flush(&mut stream, &resp);
                Err(other)
            }
        }
    }

    fn record_pre_gate_denial_response(
        &mut self,
        denial_req: &ActionRequest,
        mapping_reason: String,
        now: i64,
    ) -> Result<HttpResponse, HttpProxyError> {
        let denial = self
            .engine
            .record_pre_gate_denial(denial_req, mapping_reason, now)?;
        Ok(build_denied_response(
            &denial.reason,
            &denial.receipt.receipt_hash.to_string(),
        ))
    }

    fn build_route_denial_request(
        &self,
        route: &crate::policy::CompiledRoute,
        path_params: &std::collections::BTreeMap<String, String>,
        query: &std::collections::BTreeMap<String, String>,
        body: &[u8],
    ) -> ActionRequest {
        ActionRequest {
            actor_key: self.engine.actor_key().clone(),
            action: route.policy().action.clone(),
            resource_kind: route.policy().resource_kind.clone(),
            resource_id: self
                .policy_map
                .denial_resource_id(route, path_params, query, body),
        }
    }

    fn forward_permitted_request(
        &self,
        raw_req: &HttpRequest,
        mut headers: Vec<(String, String)>,
    ) -> Result<HttpResponse, HttpProxyError> {
        if let Some(auth) = self.policy_map.upstream_auth() {
            let (name, secret) = auth.load_header()?;
            let value = auth.format_header_value(&secret);
            if !is_valid_header_value(&value) {
                return Err(HttpProxyError::Credential(SecretError::InvalidSecretValue(
                    format!("header '{name}'"),
                )));
            }
            headers.push((name, value));
        }

        let base_url = self.policy_map.base_url();
        let upstream_req = UpstreamRequest {
            method: raw_req.method,
            url: format!("{}{}", base_url.origin, raw_req.target),
            target: raw_req.target.clone(),
            host_header: base_url.host_header.clone(),
            headers,
            body: raw_req.body.clone(),
        };

        let upstream_resp = self.transport.send(&upstream_req)?;
        validate_upstream_response(&upstream_resp)?;
        Ok(HttpResponse {
            status: upstream_resp.status,
            reason: upstream_resp.reason,
            headers: sanitize_response_headers(&upstream_resp.headers),
            body: upstream_resp.body,
        })
    }
}

fn validate_upstream_response(
    resp: &crate::transport::UpstreamResponse,
) -> Result<(), HttpProxyError> {
    if !(200..=599).contains(&resp.status) {
        return Err(HttpProxyError::Transport(TransportError::InvalidResponse(
            format!(
                "upstream returned invalid final HTTP status {}",
                resp.status
            ),
        )));
    }
    if !is_valid_header_value(&resp.reason) {
        return Err(HttpProxyError::Transport(TransportError::InvalidResponse(
            "upstream returned invalid HTTP reason phrase".to_string(),
        )));
    }
    for (name, value) in &resp.headers {
        if !is_valid_header_name(name) {
            return Err(HttpProxyError::Transport(TransportError::InvalidResponse(
                format!("upstream returned invalid header name '{name}'"),
            )));
        }
        if !is_valid_header_value(value) {
            return Err(HttpProxyError::Transport(TransportError::InvalidResponse(
                format!("upstream returned invalid header value for '{name}'"),
            )));
        }
    }
    let framing = resolve_body_framing(&resp.headers, true, resp.status).map_err(|err| {
        HttpProxyError::Transport(TransportError::InvalidResponse(err.to_string()))
    })?;
    validate_decoded_response_body_len(resp.status, framing, resp.body.len())
        .map_err(|msg| HttpProxyError::Transport(TransportError::InvalidResponse(msg)))?;
    Ok(())
}

fn write_and_flush(stream: &mut TcpStream, resp: &HttpResponse) -> std::io::Result<()> {
    let wire = write_http_response_wire(resp);
    stream.write_all(&wire)?;
    stream.flush()
}

fn validate_request_headers(headers: &[(String, String)]) -> Result<(), Http1Error> {
    for (name, value) in headers {
        if !is_valid_header_name(name) {
            return Err(Http1Error::InvalidHeaderName(name.clone()));
        }
        if !is_valid_header_value(value) {
            return Err(Http1Error::InvalidHeaderValue { name: name.clone() });
        }
    }
    Ok(())
}

fn validate_json_body_headers(
    raw_headers: &[(String, String)],
    outbound_headers: &[(String, String)],
) -> Result<(), String> {
    if raw_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
    {
        return Err("JSON body route forbids Content-Encoding header".to_string());
    }
    let mut content_types = outbound_headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str());
    let Some(ct) = content_types.next() else {
        return Err("JSON body route requires Content-Type: application/json".to_string());
    };
    if content_types.next().is_some() {
        return Err("duplicate Content-Type headers are forbidden".to_string());
    }
    let mut parts = ct.split(';');
    let media_type = parts.next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(format!(
            "JSON body route requires Content-Type: application/json, got '{media_type}'"
        ));
    }
    let mut seen_charset = false;
    for raw_param in parts {
        let param = raw_param.trim();
        if param.is_empty() {
            return Err("malformed empty Content-Type parameter".to_string());
        }
        let Some((key, val)) = param.split_once('=') else {
            return Err(format!("malformed Content-Type parameter '{param}'"));
        };
        if !key.eq_ignore_ascii_case("charset") {
            return Err(format!(
                "unsupported Content-Type parameter '{key}'; only charset=utf-8 is allowed"
            ));
        }
        if seen_charset {
            return Err("duplicate Content-Type charset parameter is forbidden".to_string());
        }
        seen_charset = true;
        let unquoted = val
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(val);
        if !unquoted.eq_ignore_ascii_case("utf-8") {
            return Err(format!(
                "unsupported Content-Type charset '{val}'; only utf-8 is allowed"
            ));
        }
    }
    Ok(())
}

fn build_denied_response(reason: &str, receipt_hash: &str) -> HttpResponse {
    let mut json = String::from(r#"{"error":"handfest_denied","reason":"#);
    write_json_string(reason, &mut json);
    json.push_str(r#","receipt_hash":"#);
    write_json_string(receipt_hash, &mut json);
    json.push('}');
    HttpResponse::json(403, json.into_bytes())
}

fn build_error_response(status: u16, code: &str, message: &str) -> HttpResponse {
    let mut json = String::from(r#"{"error":"#);
    write_json_string(code, &mut json);
    json.push_str(r#","message":"#);
    write_json_string(message, &mut json);
    json.push('}');
    HttpResponse::json(status, json.into_bytes())
}
