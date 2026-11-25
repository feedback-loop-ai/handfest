//! Transport-agnostic MCP stdio JSON-RPC 2.0 proxy enforcing `HANDFEST v1` mandate chains.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use handfest_anchors::{verify_chain, AnchorError, SignedMandate};
use handfest_core::ast::KeyId;
use handfest_core::gate::{ActionRequest, VerifiedFacts, VerifiedMandate};
use handfest_core::lattice::subsumes;
use handfest_core::Verdict;
use handfest_ledger::{LedgerError, SqliteLedger};
use serde_json::{json, Value};

use crate::exact_json::{parse_exact_json, ExactJson};
use crate::framing::{
    extract_request_id, forward_and_read_response, read_bounded_line, write_denied_response,
    write_jsonrpc_error, write_raw_line, JsonRpcId, LineReadError, ProxyIo, JSONRPC_INTERNAL_ERROR,
    JSONRPC_INVALID_REQUEST, JSONRPC_PARSE_ERROR,
};
use crate::mapping::{MappingError, ToolPolicyMap};

/// Default maximum JSON-RPC line length in bytes (1 MiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;

/// JSON-RPC 2.0 application error code returned when a `HANDFEST v1` policy denies a call.
pub const HANDFEST_DENIED_ERROR_CODE: i32 = -32001;

const ALLOWED_NOTIFICATION_METHODS: &[&str] = &[
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/roots/list_changed",
];

/// Wall-clock abstraction supplying UTC Unix seconds for authorization evaluation.
pub trait Clock {
    /// Returns the current UTC timestamp in Unix seconds.
    fn now_unix(&self) -> i64;
}

/// Production wall-clock backed by [`SystemTime::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        i64::try_from(dur.as_secs()).unwrap_or(i64::MAX)
    }
}

/// Deterministic fixed-timestamp clock for tests and replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    now_unix: i64,
}

impl FixedClock {
    /// Creates a clock that always returns `now_unix` (UTC Unix seconds).
    #[must_use]
    pub const fn new(now_unix: i64) -> Self {
        Self { now_unix }
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.now_unix
    }
}

/// Errors returned while validating chains, constructing [`McpProxy`], or running the proxy loop.
#[derive(Debug)]
pub enum ProxyError {
    Anchor(AnchorError),
    InvalidChain(String),
    Mapping(MappingError),
    Ledger(LedgerError),
    Io(std::io::Error),
    FrameTooLarge { max_bytes: usize },
    UpstreamFrameTooLarge { max_bytes: usize },
    UpstreamEof,
    UpstreamProtocol(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor(err) => write!(f, "mandate signature verification failed: {err}"),
            Self::InvalidChain(msg) => write!(f, "invalid mandate chain: {msg}"),
            Self::Mapping(err) => write!(f, "policy mapping error: {err}"),
            Self::Ledger(err) => write!(f, "ledger error: {err}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::FrameTooLarge { max_bytes } => {
                write!(
                    f,
                    "client JSON-RPC frame exceeded limit of {max_bytes} bytes"
                )
            }
            Self::UpstreamFrameTooLarge { max_bytes } => {
                write!(
                    f,
                    "upstream JSON-RPC frame exceeded limit of {max_bytes} bytes"
                )
            }
            Self::UpstreamEof => f.write_str("upstream MCP server closed stdout unexpectedly"),
            Self::UpstreamProtocol(msg) => write!(f, "upstream MCP protocol error: {msg}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Anchor(err) => Some(err),
            Self::Mapping(err) => Some(err),
            Self::Ledger(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::InvalidChain(_)
            | Self::FrameTooLarge { .. }
            | Self::UpstreamFrameTooLarge { .. }
            | Self::UpstreamEof
            | Self::UpstreamProtocol(_) => None,
        }
    }
}

impl From<AnchorError> for ProxyError {
    fn from(err: AnchorError) -> Self {
        Self::Anchor(err)
    }
}

impl From<MappingError> for ProxyError {
    fn from(err: MappingError) -> Self {
        Self::Mapping(err)
    }
}

impl From<LedgerError> for ProxyError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err)
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Verifies every Ed25519 signature in `signed` via `handfest_anchors::verify_chain` AND
/// verifies root parent absence plus monotonic lattice narrowing (`subsumes`) across every hop.
pub fn verify_mandate_chain(signed: &[SignedMandate]) -> Result<Vec<VerifiedMandate>, ProxyError> {
    let verified = verify_chain(signed)?;
    validate_verified_chain(&verified)?;
    Ok(verified)
}

fn validate_verified_chain(verified: &[VerifiedMandate]) -> Result<(), ProxyError> {
    if verified.is_empty() {
        return Err(ProxyError::InvalidChain(
            "mandate chain must contain at least one mandate".to_string(),
        ));
    }
    if verified[0].ast.parent().is_some() {
        return Err(ProxyError::InvalidChain(
            "root mandate must not declare a PARENT digest".to_string(),
        ));
    }
    for (hop, vm) in verified.iter().enumerate() {
        vm.ast.try_mandate_id().map_err(|err| {
            ProxyError::InvalidChain(format!("hop {hop}: invalid mandate AST: {err}"))
        })?;
    }
    for (hop, pair) in verified.windows(2).enumerate() {
        subsumes(&pair[0].ast, &pair[1].ast).map_err(|err| {
            ProxyError::InvalidChain(format!(
                "attenuation check failed at hop {hop} -> {}: {err}",
                hop + 1
            ))
        })?;
    }
    Ok(())
}

/// Fail-closed MCP stdio JSON-RPC 2.0 proxy enforcing a verified `HANDFEST v1` mandate chain.
pub struct McpProxy<C: Clock> {
    verified_chain: Vec<VerifiedMandate>,
    actor_key: KeyId,
    policy_map: ToolPolicyMap,
    ledger: SqliteLedger,
    clock: C,
    max_line_bytes: usize,
}

impl<C: Clock> fmt::Debug for McpProxy<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpProxy")
            .field("chain_len", &self.verified_chain.len())
            .field("actor_key", &self.actor_key)
            .field("mapped_tools", &self.policy_map.tools.len())
            .field("max_line_bytes", &self.max_line_bytes)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> McpProxy<C> {
    /// Constructs a validated [`McpProxy`] over a verified mandate chain and [`SqliteLedger`].
    pub fn new(
        verified_chain: Vec<VerifiedMandate>,
        actor_key: KeyId,
        policy_map: ToolPolicyMap,
        ledger: SqliteLedger,
        clock: C,
    ) -> Result<Self, ProxyError> {
        validate_verified_chain(&verified_chain)?;
        actor_key
            .validate()
            .map_err(|err| ProxyError::InvalidChain(format!("invalid actor_key: {err}")))?;
        policy_map.validate()?;
        Ok(Self {
            verified_chain,
            actor_key,
            policy_map,
            ledger,
            clock,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        })
    }

    /// Overrides the maximum accepted JSON-RPC frame line length in bytes.
    pub fn with_max_line_bytes(mut self, max_line_bytes: usize) -> Result<Self, ProxyError> {
        if max_line_bytes == 0 {
            return Err(ProxyError::InvalidChain(
                "max_line_bytes must be greater than zero".to_string(),
            ));
        }
        self.max_line_bytes = max_line_bytes;
        Ok(self)
    }

    /// Borrows the underlying [`SqliteLedger`].
    #[must_use]
    pub const fn ledger(&self) -> &SqliteLedger {
        &self.ledger
    }

    /// Mutably borrows the underlying [`SqliteLedger`].
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut SqliteLedger {
        &mut self.ledger
    }

    /// Consumes the proxy and returns its underlying [`SqliteLedger`].
    #[must_use]
    pub fn into_ledger(self) -> SqliteLedger {
        self.ledger
    }

    /// Runs the newline-delimited JSON-RPC 2.0 proxy loop until client EOF or fatal framing error.
    pub fn run<CR, CW, UR, UW>(
        &mut self,
        client_in: &mut CR,
        client_out: &mut CW,
        upstream_in: &mut UW,
        upstream_out: &mut UR,
    ) -> Result<(), ProxyError>
    where
        CR: BufRead,
        CW: Write,
        UR: BufRead,
        UW: Write,
    {
        let mut io = ProxyIo {
            client_out,
            upstream_in,
            upstream_out,
        };
        loop {
            let line = match read_bounded_line(client_in, self.max_line_bytes) {
                Ok(Some(raw)) => raw,
                Ok(None) => return Ok(()),
                Err(LineReadError::TooLong) => {
                    let _ = write_jsonrpc_error(
                        io.client_out,
                        None,
                        JSONRPC_INVALID_REQUEST,
                        &format!(
                            "handfest rejected JSON-RPC frame exceeding {} bytes",
                            self.max_line_bytes
                        ),
                        None,
                    );
                    return Err(ProxyError::FrameTooLarge {
                        max_bytes: self.max_line_bytes,
                    });
                }
                Err(LineReadError::InvalidUtf8) => {
                    write_jsonrpc_error(
                        io.client_out,
                        None,
                        JSONRPC_PARSE_ERROR,
                        "invalid UTF-8 in JSON-RPC frame",
                        None,
                    )?;
                    continue;
                }
                Err(LineReadError::Io(err)) => return Err(ProxyError::Io(err)),
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            self.handle_client_frame(trimmed, &mut io)?;
        }
    }

    fn handle_client_frame<CW, UR, UW>(
        &mut self,
        raw_frame: &str,
        io: &mut ProxyIo<'_, CW, UR, UW>,
    ) -> Result<(), ProxyError>
    where
        CW: Write,
        UR: BufRead,
        UW: Write,
    {
        let parsed = match parse_exact_json(raw_frame) {
            Ok(val) => val,
            Err(err) => {
                return write_jsonrpc_error(
                    io.client_out,
                    None,
                    JSONRPC_PARSE_ERROR,
                    &format!("invalid JSON-RPC frame: {err}"),
                    None,
                );
            }
        };

        let Some(obj) = parsed.as_object() else {
            return write_jsonrpc_error(
                io.client_out,
                None,
                JSONRPC_INVALID_REQUEST,
                "JSON-RPC frame must be a JSON object",
                None,
            );
        };

        let id = match extract_request_id(obj) {
            Ok(id) => id,
            Err(msg) => {
                return write_jsonrpc_error(
                    io.client_out,
                    None,
                    JSONRPC_INVALID_REQUEST,
                    &msg,
                    None,
                );
            }
        };

        if obj.get("jsonrpc").and_then(ExactJson::as_str) != Some("2.0") {
            if let Some(req_id) = id.as_ref() {
                write_jsonrpc_error(
                    io.client_out,
                    Some(req_id),
                    JSONRPC_INVALID_REQUEST,
                    "jsonrpc version must be \"2.0\"",
                    None,
                )?;
            }
            return Ok(());
        }

        let Some(method) = obj.get("method").and_then(ExactJson::as_str) else {
            if let Some(req_id) = id.as_ref() {
                write_jsonrpc_error(
                    io.client_out,
                    Some(req_id),
                    JSONRPC_INVALID_REQUEST,
                    "missing or non-string JSON-RPC method",
                    None,
                )?;
            }
            return Ok(());
        };

        match id {
            None => handle_notification(method, raw_frame, io.upstream_in),
            Some(req_id) => self.handle_request(&req_id, method, obj, raw_frame, io),
        }
    }

    fn handle_request<CW, UR, UW>(
        &mut self,
        req_id: &JsonRpcId,
        method: &str,
        obj: &BTreeMap<String, ExactJson>,
        raw_frame: &str,
        io: &mut ProxyIo<'_, CW, UR, UW>,
    ) -> Result<(), ProxyError>
    where
        CW: Write,
        UR: BufRead,
        UW: Write,
    {
        match method {
            "initialize" | "ping" => {
                let response =
                    forward_and_read_response(req_id, raw_frame, self.max_line_bytes, io)?;
                write_raw_line(io.client_out, &response)
            }
            "tools/list" => self.handle_tools_list(req_id, raw_frame, io),
            "tools/call" => self.handle_tools_call(req_id, obj, raw_frame, io),
            other => write_jsonrpc_error(
                io.client_out,
                Some(req_id),
                HANDFEST_DENIED_ERROR_CODE,
                &format!("handfest denied: method '{other}' is not permitted"),
                Some(json!({ "reason": format!("method '{other}' is not in proxy allowlist") })),
            ),
        }
    }

    fn handle_tools_list<CW, UR, UW>(
        &self,
        req_id: &JsonRpcId,
        raw_frame: &str,
        io: &mut ProxyIo<'_, CW, UR, UW>,
    ) -> Result<(), ProxyError>
    where
        CW: Write,
        UR: BufRead,
        UW: Write,
    {
        let response_line = forward_and_read_response(req_id, raw_frame, self.max_line_bytes, io)?;
        let mut resp: Value = match serde_json::from_str(&response_line) {
            Ok(val) => val,
            Err(err) => {
                return write_jsonrpc_error(
                    io.client_out,
                    Some(req_id),
                    JSONRPC_INTERNAL_ERROR,
                    &format!("invalid JSON in upstream tools/list response: {err}"),
                    None,
                );
            }
        };

        if resp.get("error").is_some() {
            return write_raw_line(io.client_out, &response_line);
        }

        let Some(tools) = resp
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .and_then(|res| res.get_mut("tools"))
            .and_then(Value::as_array_mut)
        else {
            return write_jsonrpc_error(
                io.client_out,
                Some(req_id),
                JSONRPC_INTERNAL_ERROR,
                "malformed upstream tools/list response: missing result.tools array",
                None,
            );
        };

        tools.retain(|entry| {
            entry
                .as_object()
                .and_then(|obj| obj.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| self.is_tool_permitted(name))
        });

        let filtered = serde_json::to_string(&resp)
            .map_err(|err| ProxyError::UpstreamProtocol(err.to_string()))?;
        write_raw_line(io.client_out, &filtered)
    }

    fn handle_tools_call<CW, UR, UW>(
        &mut self,
        req_id: &JsonRpcId,
        obj: &BTreeMap<String, ExactJson>,
        raw_frame: &str,
        io: &mut ProxyIo<'_, CW, UR, UW>,
    ) -> Result<(), ProxyError>
    where
        CW: Write,
        UR: BufRead,
        UW: Write,
    {
        let now = self.clock.now_unix();
        let (tool_name, arguments) = match extract_tool_call_params(obj) {
            Ok(parts) => parts,
            Err(reason) => {
                return self.deny_with_synthetic_receipt(
                    req_id,
                    "invalid_params",
                    &reason,
                    now,
                    io.client_out,
                );
            }
        };

        let (request, facts) =
            match self
                .policy_map
                .map_call_exact(&self.actor_key, tool_name, arguments)
            {
                Ok(mapped) => mapped,
                Err(err) => {
                    return self.deny_with_synthetic_receipt(
                        req_id,
                        tool_name,
                        &err.to_string(),
                        now,
                        io.client_out,
                    );
                }
            };

        let (verdict, receipt) =
            match self
                .ledger
                .evaluate_and_record(&self.verified_chain, &request, &facts, now)
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    write_jsonrpc_error(
                        io.client_out,
                        Some(req_id),
                        JSONRPC_INTERNAL_ERROR,
                        &format!("handfest ledger evaluation failed: {err}"),
                        None,
                    )?;
                    return Err(ProxyError::Ledger(err));
                }
            };

        match verdict {
            Verdict::Permit => {
                let response =
                    forward_and_read_response(req_id, raw_frame, self.max_line_bytes, io)?;
                write_raw_line(io.client_out, &response)
            }
            Verdict::Deny { reason } => write_denied_response(
                io.client_out,
                req_id,
                &reason,
                &receipt.receipt_hash.to_string(),
            ),
        }
    }

    fn deny_with_synthetic_receipt<CW: Write>(
        &mut self,
        req_id: &JsonRpcId,
        tool_name: &str,
        reason: &str,
        now: i64,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        // Colon is forbidden in concrete HANDFEST actions, so `gate::authorize` is
        // guaranteed to return `Verdict::Deny` while still recording a hash-chained receipt.
        let synthetic_request = ActionRequest {
            actor_key: self.actor_key.clone(),
            action: format!("mcp.unmapped:{tool_name}"),
            resource_kind: "mcp_tool".to_string(),
            resource_id: tool_name.to_string(),
        };
        let (verdict, receipt) = self.ledger.evaluate_and_record(
            &self.verified_chain,
            &synthetic_request,
            &VerifiedFacts::new(),
            now,
        )?;
        debug_assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "synthetic unmapped action must always evaluate to Deny"
        );
        write_denied_response(
            client_out,
            req_id,
            reason,
            &receipt.receipt_hash.to_string(),
        )
    }

    fn is_tool_permitted(&self, tool_name: &str) -> bool {
        let Some(policy) = self.policy_map.get(tool_name) else {
            return false;
        };
        let Some(leaf) = self.verified_chain.last() else {
            return false;
        };
        if leaf.ast.to().key() != &self.actor_key {
            return false;
        }
        self.verified_chain
            .iter()
            .all(|vm| vm.ast.allow().iter().any(|pat| pat.matches(&policy.action)))
    }
}

fn extract_tool_call_params(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<(&str, Option<&ExactJson>), String> {
    let Some(params) = obj.get("params").and_then(ExactJson::as_object) else {
        return Err("tools/call params must be a JSON object".to_string());
    };
    let Some(name) = params.get("name").and_then(ExactJson::as_str) else {
        return Err("tools/call params.name must be a string".to_string());
    };
    if name.is_empty() {
        return Err("tools/call params.name must not be empty".to_string());
    }
    Ok((name, params.get("arguments")))
}

fn handle_notification<UW: Write>(
    method: &str,
    raw_frame: &str,
    upstream_in: &mut UW,
) -> Result<(), ProxyError> {
    if ALLOWED_NOTIFICATION_METHODS.contains(&method) {
        write_raw_line(upstream_in, raw_frame)?;
    }
    // Disallowed notifications (including notification `tools/call`) are dropped without forwarding.
    Ok(())
}
