//! Full-duplex MCP JSON-RPC 2.0 session loop, request/response correlation, and cancellation.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, Write};
use std::time::Instant;

use crate::exact_json::{parse_exact_json, ExactJson};
use crate::framing::{
    classify_upstream_frame, extract_id_value, fail_upstream_error, fail_upstream_protocol,
    format_jsonrpc_error_line, validate_client_envelope, write_jsonrpc_error, write_raw_line,
    JsonRpcId, LineReadError, UpstreamFrame, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR,
};
use crate::proxy::{Clock, McpProxy, ProxyError, ReceiptLedger, HANDFEST_DENIED_ERROR_CODE};
use crate::transport::{DuplexTransport, IoEvent, RecvOutcome};

const MAX_UPSTREAM_INTERLEAVED_MESSAGES: usize = 1024;
const MAX_QUEUED_CLIENT_FRAMES: usize = 1024;
const MAX_CANCELLED_IN_FLIGHT: usize = 1024;

const ALLOWED_NOTIFICATION_METHODS: &[&str] = &[
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/roots/list_changed",
];

pub(crate) enum PendingKind {
    Normal,
    ToolsList { evaluated_at: i64 },
}

pub(crate) struct PendingRequest {
    pub(crate) id: JsonRpcId,
    pub(crate) kind: PendingKind,
}

pub(crate) struct DispatchCtx<'a, CW> {
    pub(crate) state: &'a mut SessionState,
    pub(crate) transport: &'a DuplexTransport,
    pub(crate) client_out: &'a mut CW,
}

enum QueuedClientItem {
    Line(String),
    BareCr,
    InvalidUtf8,
}

#[derive(Default)]
pub(crate) struct SessionState {
    pub(crate) active_request: Option<PendingRequest>,
    cancelled_requests: Vec<PendingRequest>,
    queued_client: VecDeque<QueuedClientItem>,
    client_eof: bool,
    pub(crate) upstream_eof: bool,
    shutdown_deadline: Option<Instant>,
    pub(crate) interleaved_count: usize,
}

impl SessionState {
    fn active_id(&self) -> Option<&JsonRpcId> {
        self.active_request.as_ref().map(|req| &req.id)
    }

    fn cancel_active_if_matches(&mut self, cancel_id: &JsonRpcId) {
        if self
            .active_request
            .as_ref()
            .is_some_and(|req| &req.id == cancel_id)
        {
            if let Some(cancelled) = self.active_request.take() {
                if self.cancelled_requests.len() >= MAX_CANCELLED_IN_FLIGHT {
                    self.cancelled_requests.remove(0);
                }
                self.cancelled_requests.push(cancelled);
                self.interleaved_count = 0;
            }
        }
    }

    fn take_cancelled(&mut self, resp_id: &JsonRpcId) -> Option<PendingRequest> {
        let pos = self
            .cancelled_requests
            .iter()
            .position(|req| &req.id == resp_id)?;
        Some(self.cancelled_requests.remove(pos))
    }

    fn is_in_flight(&self, id: &JsonRpcId) -> bool {
        self.active_request.as_ref().is_some_and(|r| &r.id == id)
            || self.cancelled_requests.iter().any(|r| &r.id == id)
    }
}

impl<C: Clock, L: ReceiptLedger> McpProxy<C, L> {
    /// Runs the full-duplex newline-delimited JSON-RPC 2.0 proxy loop until client EOF or fatal
    /// framing error.
    pub fn run<CR, CW, UR, UW>(
        &mut self,
        client_in: CR,
        client_out: &mut CW,
        upstream_in: UW,
        upstream_out: UR,
    ) -> Result<(), ProxyError>
    where
        CR: BufRead + Send + 'static,
        CW: Write,
        UR: BufRead + Send + 'static,
        UW: Write + Send + 'static,
    {
        let mut transport =
            DuplexTransport::start(client_in, upstream_in, upstream_out, self.max_line_bytes);
        let mut state = SessionState::default();

        loop {
            self.drain_queued_client(&mut state, &transport, client_out)?;
            if state.client_eof && state.queued_client.is_empty() {
                if state.active_request.is_none() {
                    return transport.finish_writer(self.shutdown_timeout);
                }
                if state.upstream_eof {
                    return emit_upstream_eof(client_out, state.active_id());
                }
                if state.shutdown_deadline.is_none() {
                    state.shutdown_deadline = Some(Instant::now() + self.shutdown_timeout);
                }
            }

            match transport.recv_event(state.shutdown_deadline) {
                RecvOutcome::Event(IoEvent::ClientLine(res)) => {
                    self.on_client_read(res, &mut state, &transport, client_out)?;
                }
                RecvOutcome::Event(IoEvent::UpstreamLine(res)) => {
                    self.on_upstream_read(res, &mut state, &transport, client_out)?;
                }
                RecvOutcome::Event(IoEvent::UpstreamWriteError(err)) => {
                    return Err(err);
                }
                RecvOutcome::Timeout => {
                    return Ok(());
                }
                RecvOutcome::Disconnected => {
                    if state.active_request.is_some() {
                        return emit_upstream_eof(client_out, state.active_id());
                    }
                    return transport.finish_writer(self.shutdown_timeout);
                }
            }
        }
    }

    fn on_client_read<CW: Write>(
        &mut self,
        res: Result<Option<String>, LineReadError>,
        state: &mut SessionState,
        transport: &DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        match res {
            Ok(None) => {
                state.client_eof = true;
                Ok(())
            }
            Err(LineReadError::TooLong) => {
                let _ = write_jsonrpc_error(
                    client_out,
                    None,
                    JSONRPC_INVALID_REQUEST,
                    &format!(
                        "handfest rejected JSON-RPC frame exceeding {} bytes",
                        self.max_line_bytes
                    ),
                    None,
                );
                Err(ProxyError::FrameTooLarge {
                    max_bytes: self.max_line_bytes,
                })
            }
            Err(LineReadError::Io(err)) => Err(ProxyError::Io(err)),
            Err(LineReadError::BareCr) => self.enqueue_or_process_client(
                QueuedClientItem::BareCr,
                state,
                transport,
                client_out,
            ),
            Err(LineReadError::InvalidUtf8) => self.enqueue_or_process_client(
                QueuedClientItem::InvalidUtf8,
                state,
                transport,
                client_out,
            ),
            Ok(Some(raw_line)) => {
                if state.active_request.is_some()
                    && try_handle_active_cancellation(&raw_line, state, transport)?
                {
                    return Ok(());
                }
                self.enqueue_or_process_client(
                    QueuedClientItem::Line(raw_line),
                    state,
                    transport,
                    client_out,
                )
            }
        }
    }

    fn enqueue_or_process_client<CW: Write>(
        &mut self,
        item: QueuedClientItem,
        state: &mut SessionState,
        transport: &DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        if state.active_request.is_none() && state.queued_client.is_empty() {
            return self.process_client_item(item, state, transport, client_out);
        }
        if state.queued_client.len() >= MAX_QUEUED_CLIENT_FRAMES {
            let _ = write_jsonrpc_error(
                client_out,
                None,
                JSONRPC_INVALID_REQUEST,
                "client exceeded maximum queued JSON-RPC frames",
                None,
            );
            return Err(ProxyError::UpstreamProtocol(
                "client exceeded maximum queued JSON-RPC frames".to_string(),
            ));
        }
        state.queued_client.push_back(item);
        Ok(())
    }

    fn drain_queued_client<CW: Write>(
        &mut self,
        state: &mut SessionState,
        transport: &DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        while state.active_request.is_none() {
            let Some(item) = state.queued_client.pop_front() else {
                break;
            };
            self.process_client_item(item, state, transport, client_out)?;
        }
        Ok(())
    }

    fn process_client_item<CW: Write>(
        &mut self,
        item: QueuedClientItem,
        state: &mut SessionState,
        transport: &DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        match item {
            QueuedClientItem::BareCr => write_jsonrpc_error(
                client_out,
                None,
                JSONRPC_PARSE_ERROR,
                "bare carriage return (0x0D) is not permitted in JSON-RPC stdio frame",
                None,
            ),
            QueuedClientItem::InvalidUtf8 => write_jsonrpc_error(
                client_out,
                None,
                JSONRPC_PARSE_ERROR,
                "invalid UTF-8 in JSON-RPC frame",
                None,
            ),
            QueuedClientItem::Line(raw_line) => {
                self.handle_client_frame(&raw_line, state, transport, client_out)
            }
        }
    }

    fn handle_client_frame<CW: Write>(
        &mut self,
        raw_frame: &str,
        state: &mut SessionState,
        transport: &DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        let parsed = match parse_exact_json(raw_frame) {
            Ok(val) => val,
            Err(err) => {
                return write_jsonrpc_error(
                    client_out,
                    None,
                    JSONRPC_PARSE_ERROR,
                    &format!("invalid JSON-RPC frame: {err}"),
                    None,
                );
            }
        };

        let Some(obj) = parsed.as_object() else {
            return write_jsonrpc_error(
                client_out,
                None,
                JSONRPC_INVALID_REQUEST,
                "JSON-RPC frame must be a JSON object",
                None,
            );
        };

        let env = match validate_client_envelope(obj) {
            Ok(env) => env,
            Err(err) => {
                return write_jsonrpc_error(
                    client_out,
                    err.id.as_ref(),
                    JSONRPC_INVALID_REQUEST,
                    &err.message,
                    None,
                );
            }
        };

        match env.id {
            None => handle_notification(env.method, raw_frame, transport),
            Some(req_id) => {
                if state.is_in_flight(&req_id) {
                    return write_jsonrpc_error(
                        client_out,
                        Some(&req_id),
                        JSONRPC_INVALID_REQUEST,
                        "duplicate in-flight JSON-RPC request id",
                        None,
                    );
                }
                let mut ctx = DispatchCtx {
                    state,
                    transport,
                    client_out,
                };
                self.handle_request(req_id, env.method, obj, raw_frame, &mut ctx)
            }
        }
    }

    fn handle_request<CW: Write>(
        &mut self,
        req_id: JsonRpcId,
        method: &str,
        obj: &BTreeMap<String, ExactJson>,
        raw_frame: &str,
        ctx: &mut DispatchCtx<'_, CW>,
    ) -> Result<(), ProxyError> {
        match method {
            "initialize" | "ping" => {
                dispatch_to_upstream(req_id, PendingKind::Normal, raw_frame, ctx)
            }
            "tools/list" => {
                let evaluated_at = self.clock.now_unix();
                dispatch_to_upstream(
                    req_id,
                    PendingKind::ToolsList { evaluated_at },
                    raw_frame,
                    ctx,
                )
            }
            "tools/call" => self.handle_tools_call(req_id, obj, raw_frame, ctx),
            other => {
                let mut data = BTreeMap::new();
                data.insert(
                    "reason".to_string(),
                    ExactJson::Str(format!("method '{other}' is not in proxy allowlist")),
                );
                write_jsonrpc_error(
                    ctx.client_out,
                    Some(&req_id),
                    HANDFEST_DENIED_ERROR_CODE,
                    &format!("handfest denied: method '{other}' is not permitted"),
                    Some(&ExactJson::Object(data)),
                )
            }
        }
    }

    fn on_upstream_read<CW: Write>(
        &mut self,
        res: Result<Option<String>, LineReadError>,
        state: &mut SessionState,
        transport: &DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        let raw_line = match res {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                state.upstream_eof = true;
                if state.active_request.is_some() {
                    return emit_upstream_eof(client_out, state.active_id());
                }
                return Ok(());
            }
            Err(LineReadError::TooLong) => {
                let _ = write_jsonrpc_error(
                    client_out,
                    state.active_id(),
                    JSONRPC_INTERNAL_ERROR,
                    &format!("upstream response exceeded {} bytes", self.max_line_bytes),
                    None,
                );
                return Err(ProxyError::UpstreamFrameTooLarge {
                    max_bytes: self.max_line_bytes,
                });
            }
            Err(LineReadError::BareCr) => {
                return fail_upstream_error(
                    client_out,
                    state.active_id(),
                    JSONRPC_PARSE_ERROR,
                    "upstream emitted bare carriage return (0x0D) in JSON-RPC frame".to_string(),
                );
            }
            Err(LineReadError::InvalidUtf8) => {
                return fail_upstream_protocol(
                    client_out,
                    state.active_id(),
                    "upstream emitted non-UTF-8 JSON-RPC frame".to_string(),
                );
            }
            Err(LineReadError::Io(err)) => return Err(ProxyError::Io(err)),
        };

        let parsed = match parse_exact_json(&raw_line) {
            Ok(val) => val,
            Err(err) => {
                return fail_upstream_protocol(
                    client_out,
                    state.active_id(),
                    format!("invalid upstream JSON: {err}"),
                );
            }
        };
        let ExactJson::Object(obj) = parsed else {
            return fail_upstream_protocol(
                client_out,
                state.active_id(),
                "upstream frame must be a JSON object".to_string(),
            );
        };

        let frame = match classify_upstream_frame(&obj) {
            Ok(frame) => frame,
            Err(detail) => return fail_upstream_protocol(client_out, state.active_id(), detail),
        };

        match frame {
            UpstreamFrame::Notification => {
                check_interleaved_budget(state, client_out)?;
                write_raw_line(client_out, &raw_line)
            }
            UpstreamFrame::ServerRequest { id, method } => {
                check_interleaved_budget(state, client_out)?;
                let msg =
                    format!("handfest-mcp does not support server-to-client request '{method}'");
                let err_line =
                    format_jsonrpc_error_line(Some(&id), JSONRPC_METHOD_NOT_FOUND, &msg, None);
                transport.send_upstream(err_line)
            }
            UpstreamFrame::Response { id: resp_id } => {
                self.handle_upstream_response(resp_id, obj, &raw_line, state, client_out)
            }
        }
    }

    fn handle_upstream_response<CW: Write>(
        &self,
        resp_id: JsonRpcId,
        obj: BTreeMap<String, ExactJson>,
        raw_line: &str,
        state: &mut SessionState,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        let pending = if state
            .active_request
            .as_ref()
            .is_some_and(|req| req.id == resp_id)
        {
            state.interleaved_count = 0;
            state.active_request.take()
        } else if let Some(cancelled) = state.take_cancelled(&resp_id) {
            Some(cancelled)
        } else {
            let detail = match state.active_id() {
                Some(expected) => format!(
                    "response id mismatch: expected {}, got {}",
                    expected.to_json_literal(),
                    resp_id.to_json_literal()
                ),
                None => format!(
                    "unexpected upstream response for id {} with no pending request",
                    resp_id.to_json_literal()
                ),
            };
            return fail_upstream_protocol(client_out, state.active_id(), detail);
        };

        let Some(pending) = pending else {
            return Ok(());
        };
        match pending.kind {
            PendingKind::Normal => write_raw_line(client_out, raw_line),
            PendingKind::ToolsList { evaluated_at } => {
                self.relay_filtered_tools_list(&pending.id, evaluated_at, obj, raw_line, client_out)
            }
        }
    }
}

pub(crate) fn dispatch_to_upstream<CW: Write>(
    req_id: JsonRpcId,
    kind: PendingKind,
    raw_frame: &str,
    ctx: &mut DispatchCtx<'_, CW>,
) -> Result<(), ProxyError> {
    if ctx.state.upstream_eof {
        return emit_upstream_eof(ctx.client_out, Some(&req_id));
    }
    ctx.transport.send_upstream(raw_frame.to_string())?;
    ctx.state.active_request = Some(PendingRequest { id: req_id, kind });
    ctx.state.interleaved_count = 0;
    Ok(())
}

fn try_handle_active_cancellation(
    raw_line: &str,
    state: &mut SessionState,
    transport: &DuplexTransport,
) -> Result<bool, ProxyError> {
    let Ok(ExactJson::Object(obj)) = parse_exact_json(raw_line) else {
        return Ok(false);
    };
    let Ok(env) = validate_client_envelope(&obj) else {
        return Ok(false);
    };
    if env.id.is_some() || env.method != "notifications/cancelled" {
        return Ok(false);
    }
    transport.send_upstream(raw_line.to_string())?;
    if let Some(cancel_id) = obj
        .get("params")
        .and_then(ExactJson::as_object)
        .and_then(|params| params.get("requestId"))
        .and_then(|val| extract_id_value(val).ok())
    {
        state.cancel_active_if_matches(&cancel_id);
    }
    Ok(true)
}

fn check_interleaved_budget<CW: Write>(
    state: &mut SessionState,
    client_out: &mut CW,
) -> Result<(), ProxyError> {
    if state.active_request.is_some() {
        state.interleaved_count += 1;
        if state.interleaved_count > MAX_UPSTREAM_INTERLEAVED_MESSAGES {
            return fail_upstream_protocol(
                client_out,
                state.active_id(),
                "upstream exceeded maximum interleaved messages before responding".to_string(),
            );
        }
    }
    Ok(())
}

fn emit_upstream_eof<CW: Write>(
    client_out: &mut CW,
    expected_id: Option<&JsonRpcId>,
) -> Result<(), ProxyError> {
    let _ = write_jsonrpc_error(
        client_out,
        expected_id,
        JSONRPC_INTERNAL_ERROR,
        "upstream MCP server closed stdout before responding",
        None,
    );
    Err(ProxyError::UpstreamEof)
}

fn handle_notification(
    method: &str,
    raw_frame: &str,
    transport: &DuplexTransport,
) -> Result<(), ProxyError> {
    if ALLOWED_NOTIFICATION_METHODS.contains(&method) {
        transport.send_upstream(raw_frame.to_string())?;
    }
    // Disallowed notifications (including notification `tools/call`) are dropped without forwarding.
    Ok(())
}
