//! Full-duplex MCP JSON-RPC 2.0 session loop, request/response correlation, and cancellation.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use crate::exact_json::{parse_exact_json, ExactJson};
use crate::framing::{
    classify_upstream_frame, extract_id_value, fail_upstream_line_read, fail_upstream_protocol,
    format_jsonrpc_error_line, reject_unknown_keys, validate_client_envelope,
    validate_optional_meta, write_jsonrpc_error, write_raw_line, JsonRpcId, LineReadError,
    UpstreamFrame, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_REQUEST, JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
};
use crate::proxy::{Clock, McpProxy, ProxyError, ReceiptLedger, HANDFEST_DENIED_ERROR_CODE};
use crate::transport::{DuplexTransport, IoEvent, RecvOutcome};

const MAX_UPSTREAM_INTERLEAVED_MESSAGES: usize = 1024;
pub(crate) const MAX_QUEUED_CLIENT_FRAMES: usize = 1024;
const MAX_CANCELLED_IN_FLIGHT: usize = 1024;

const ALLOWED_NOTIFICATION_METHODS: &[&str] = &[
    "notifications/initialized",
    "notifications/roots/list_changed",
];

enum LoopStep {
    Continue,
    Finish(Result<(), ProxyError>),
    FinishWriter,
}

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
    pub(crate) transport: &'a mut DuplexTransport,
    pub(crate) client_out: &'a mut CW,
}

enum QueuedClientItem {
    BareCr,
    InvalidUtf8,
    ParseError(String),
    InvalidFrame {
        id: Option<JsonRpcId>,
        message: String,
    },
    Notification {
        method: String,
        raw_frame: String,
        cancel_request_id: Option<JsonRpcId>,
    },
    Request {
        id: JsonRpcId,
        method: String,
        obj: BTreeMap<String, ExactJson>,
        raw_frame: String,
    },
}

#[derive(Default)]
pub(crate) struct SessionState {
    pub(crate) active_request: Option<PendingRequest>,
    cancelled_requests: Vec<PendingRequest>,
    queued_client: VecDeque<QueuedClientItem>,
    queued_cancellations: usize,
    client_eof: bool,
    pub(crate) upstream_eof: bool,
    shutdown_deadline: Option<Instant>,
    pub(crate) interleaved_count: usize,
}

impl SessionState {
    fn active_id(&self) -> Option<&JsonRpcId> {
        self.active_request.as_ref().map(|req| &req.id)
    }

    fn set_shutdown_timeout(&mut self, timeout: Duration) {
        if self.shutdown_deadline.is_none() {
            self.shutdown_deadline = Instant::now().checked_add(timeout);
        }
    }

    fn take_cancelled(&mut self, resp_id: &JsonRpcId) -> Option<PendingRequest> {
        let pos = self
            .cancelled_requests
            .iter()
            .position(|req| &req.id == resp_id)?;
        Some(self.cancelled_requests.remove(pos))
    }

    fn has_outstanding_id(&self, id: &JsonRpcId) -> bool {
        self.active_request.as_ref().is_some_and(|r| &r.id == id)
            || self.cancelled_requests.iter().any(|r| &r.id == id)
            || self.queued_client.iter().any(|item| {
                matches!(item, QueuedClientItem::Request { id: queued_id, .. } if queued_id == id)
            })
    }

    fn push_queued_client(&mut self, item: QueuedClientItem) {
        if is_cancellation_item(&item) {
            self.queued_cancellations += 1;
        }
        self.queued_client.push_back(item);
    }

    fn pop_queued_client(&mut self) -> Option<QueuedClientItem> {
        let item = self.queued_client.pop_front()?;
        if is_cancellation_item(&item) {
            self.queued_cancellations -= 1;
        }
        Some(item)
    }

    fn first_queued_client_id(&self) -> Option<&JsonRpcId> {
        self.queued_client.iter().find_map(|item| match item {
            QueuedClientItem::Request { id, .. } => Some(id),
            QueuedClientItem::InvalidFrame { id: Some(id), .. } => Some(id),
            QueuedClientItem::BareCr
            | QueuedClientItem::InvalidUtf8
            | QueuedClientItem::ParseError(_)
            | QueuedClientItem::InvalidFrame { id: None, .. }
            | QueuedClientItem::Notification { .. } => None,
        })
    }

    fn take_queued_active_cancellation(&mut self) -> Option<String> {
        if self.queued_cancellations == 0 {
            return None;
        }
        let pos = self
            .queued_client
            .iter()
            .position(|item| is_active_cancellation(item, self))?;
        let item = self.queued_client.remove(pos)?;
        self.queued_cancellations -= 1;
        match item {
            QueuedClientItem::Notification { raw_frame, .. } => Some(raw_frame),
            _ => None,
        }
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
        let transport =
            DuplexTransport::start(client_in, upstream_in, upstream_out, self.max_line_bytes);
        self.drive_session_loop(transport, client_out, |_| {})
    }

    fn drive_session_loop<CW: Write>(
        &mut self,
        mut transport: DuplexTransport,
        client_out: &mut CW,
        mut before_recv: impl FnMut(&SessionState),
    ) -> Result<(), ProxyError> {
        let mut state = SessionState::default();
        loop {
            if let Some(err) = transport.poll_writer_error() {
                return Err(err);
            }
            if state.upstream_eof
                && (transport.has_pending_upstream() || !state.queued_client.is_empty())
            {
                return emit_upstream_eof(
                    client_out,
                    state.active_id().or_else(|| state.first_queued_client_id()),
                );
            }
            transport.flush_upstream()?;
            if let Some(err) = transport.poll_writer_error() {
                return Err(err);
            }
            self.drain_queued_client(&mut state, &mut transport, client_out)?;
            if self.check_client_eof(&mut state, &transport) {
                return transport.finish_writer(self.shutdown_timeout);
            }

            before_recv(&state);
            let outcome = transport.recv_event(state.shutdown_deadline);
            match self.handle_recv_outcome(outcome, &mut state, &mut transport, client_out) {
                LoopStep::Continue => {}
                LoopStep::Finish(res) => return res,
                LoopStep::FinishWriter => return transport.finish_writer(self.shutdown_timeout),
            }
        }
    }

    fn check_client_eof(&self, state: &mut SessionState, transport: &DuplexTransport) -> bool {
        if !state.client_eof {
            return false;
        }
        if state.queued_client.is_empty()
            && !transport.has_pending_upstream()
            && state.active_request.is_none()
        {
            return true;
        }
        state.set_shutdown_timeout(self.shutdown_timeout);
        false
    }

    fn handle_recv_outcome<CW: Write>(
        &mut self,
        outcome: RecvOutcome,
        state: &mut SessionState,
        transport: &mut DuplexTransport,
        client_out: &mut CW,
    ) -> LoopStep {
        match outcome {
            RecvOutcome::Event(IoEvent::ClientLine(res)) => {
                match self.on_client_read(res, state, transport, client_out) {
                    Ok(()) => LoopStep::Continue,
                    Err(err) => LoopStep::Finish(Err(err)),
                }
            }
            RecvOutcome::Event(IoEvent::UpstreamLine(line)) => {
                match self.on_upstream_read(line, state, transport, client_out) {
                    Ok(()) => LoopStep::Continue,
                    Err(err) => LoopStep::Finish(Err(err)),
                }
            }
            RecvOutcome::Event(IoEvent::UpstreamReadFailed) => {
                LoopStep::Finish(if let Some(err) = transport.take_upstream_read_error() {
                    fail_upstream_line_read(err, self.max_line_bytes, state.active_id(), client_out)
                } else {
                    emit_upstream_eof(client_out, state.active_id())
                })
            }
            RecvOutcome::Event(IoEvent::UpstreamWriteReady) => LoopStep::Continue,
            RecvOutcome::Event(IoEvent::UpstreamWriteFailed) => {
                LoopStep::Finish(Err(transport.take_writer_error()))
            }
            RecvOutcome::Timeout => {
                LoopStep::Finish(transport.poll_writer_error().map_or(Ok(()), Err))
            }
            RecvOutcome::Disconnected => {
                if let Some(err) = transport.poll_writer_error() {
                    return LoopStep::Finish(Err(err));
                }
                if state.active_request.is_some() {
                    return LoopStep::Finish(emit_upstream_eof(client_out, state.active_id()));
                }
                LoopStep::FinishWriter
            }
        }
    }

    fn on_client_read<CW: Write>(
        &mut self,
        res: Result<Option<String>, LineReadError>,
        state: &mut SessionState,
        transport: &mut DuplexTransport,
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
                let item = classify_client_line(raw_line);
                if !transport.has_pending_upstream() && is_active_cancellation(&item, state) {
                    if let QueuedClientItem::Notification { raw_frame, .. } = item {
                        return cancel_active_request(&raw_frame, state, transport, client_out);
                    }
                }
                self.enqueue_or_process_client(item, state, transport, client_out)
            }
        }
    }

    fn enqueue_or_process_client<CW: Write>(
        &mut self,
        item: QueuedClientItem,
        state: &mut SessionState,
        transport: &mut DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        if let QueuedClientItem::Request { ref id, .. } = item {
            if state.has_outstanding_id(id) {
                return write_jsonrpc_error(
                    client_out,
                    Some(id),
                    JSONRPC_INVALID_REQUEST,
                    "duplicate in-flight JSON-RPC request id",
                    None,
                );
            }
        }
        if !transport.has_pending_upstream()
            && state.queued_client.is_empty()
            && (state.active_request.is_none()
                || matches!(item, QueuedClientItem::Notification { .. }))
        {
            return self.process_client_item(item, state, transport, client_out);
        }
        if state.queued_client.len() >= MAX_QUEUED_CLIENT_FRAMES {
            return fail_client_limit(client_out, "client exceeded maximum queued JSON-RPC frames");
        }
        state.push_queued_client(item);
        Ok(())
    }

    fn drain_queued_client<CW: Write>(
        &mut self,
        state: &mut SessionState,
        transport: &mut DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        loop {
            if transport.has_pending_upstream() {
                break;
            }
            if state.active_request.is_some()
                && !matches!(
                    state.queued_client.front(),
                    Some(QueuedClientItem::Notification { .. })
                )
            {
                if let Some(raw_frame) = state.take_queued_active_cancellation() {
                    cancel_active_request(&raw_frame, state, transport, client_out)?;
                    continue;
                }
                break;
            }
            let Some(item) = state.pop_queued_client() else {
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
        transport: &mut DuplexTransport,
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
            QueuedClientItem::ParseError(message) => {
                write_jsonrpc_error(client_out, None, JSONRPC_PARSE_ERROR, &message, None)
            }
            QueuedClientItem::InvalidFrame { id, message } => write_jsonrpc_error(
                client_out,
                id.as_ref(),
                JSONRPC_INVALID_REQUEST,
                &message,
                None,
            ),
            QueuedClientItem::Notification {
                method,
                raw_frame,
                cancel_request_id,
            } => handle_notification(
                &method,
                &raw_frame,
                cancel_request_id.as_ref(),
                state,
                transport,
                client_out,
            ),
            QueuedClientItem::Request {
                id,
                method,
                obj,
                raw_frame,
            } => {
                let mut ctx = DispatchCtx {
                    state,
                    transport,
                    client_out,
                };
                self.handle_request(id, &method, &obj, &raw_frame, &mut ctx)
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
                self.dispatch_to_upstream(req_id, PendingKind::Normal, raw_frame, ctx)
            }
            "tools/list" => {
                let evaluated_at = self.engine.now_unix();
                self.dispatch_to_upstream(
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
        line: Option<String>,
        state: &mut SessionState,
        transport: &mut DuplexTransport,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        let Some(raw_line) = line else {
            state.upstream_eof = true;
            if state.active_request.is_some() {
                return emit_upstream_eof(client_out, state.active_id());
            }
            return Ok(());
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
        mut obj: BTreeMap<String, ExactJson>,
        raw_line: &str,
        state: &mut SessionState,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        let pending = match state.active_request.take() {
            Some(req) if req.id == resp_id => {
                state.interleaved_count = 0;
                req
            }
            active => {
                state.active_request = active;
                if let Some(cancelled) = state.take_cancelled(&resp_id) {
                    cancelled
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
                }
            }
        };
        let id_spelling_matches = pending.id.has_same_spelling(&resp_id);
        if !id_spelling_matches {
            obj.insert("id".to_string(), pending.id.to_exact_json());
        }
        match pending.kind {
            PendingKind::Normal => {
                if id_spelling_matches {
                    write_raw_line(client_out, raw_line)
                } else {
                    write_raw_line(client_out, &ExactJson::Object(obj).to_json_string())
                }
            }
            PendingKind::ToolsList { evaluated_at } => self.relay_filtered_tools_list(
                &pending.id,
                evaluated_at,
                obj,
                id_spelling_matches.then_some(raw_line),
                client_out,
            ),
        }
    }
    pub(crate) fn ensure_upstream_alive<CW: Write>(
        &self,
        req_id: &JsonRpcId,
        ctx: &mut DispatchCtx<'_, CW>,
    ) -> Result<(), ProxyError> {
        let terminal = ctx.state.upstream_eof || ctx.transport.poll_upstream_eof();
        if let Some(err) = ctx.transport.poll_writer_error() {
            return Err(err);
        }
        if terminal {
            if let Some(read_err) = ctx.transport.take_upstream_read_error() {
                return fail_upstream_line_read(
                    read_err,
                    self.max_line_bytes,
                    Some(req_id),
                    ctx.client_out,
                );
            }
            ctx.state.upstream_eof = true;
            return emit_upstream_eof(ctx.client_out, Some(req_id));
        }
        Ok(())
    }

    pub(crate) fn dispatch_to_upstream<CW: Write>(
        &self,
        req_id: JsonRpcId,
        kind: PendingKind,
        raw_frame: &str,
        ctx: &mut DispatchCtx<'_, CW>,
    ) -> Result<(), ProxyError> {
        self.ensure_upstream_alive(&req_id, ctx)?;
        ctx.transport.send_upstream(raw_frame.to_string())?;
        ctx.state.active_request = Some(PendingRequest { id: req_id, kind });
        ctx.state.interleaved_count = 0;
        Ok(())
    }
}

fn classify_client_line(raw_line: String) -> QueuedClientItem {
    let parsed = match parse_exact_json(&raw_line) {
        Ok(val) => val,
        Err(err) => return QueuedClientItem::ParseError(format!("invalid JSON-RPC frame: {err}")),
    };
    let ExactJson::Object(obj) = parsed else {
        return QueuedClientItem::InvalidFrame {
            id: None,
            message: "JSON-RPC frame must be a JSON object".to_string(),
        };
    };
    let (id, method) = match validate_client_envelope(&obj) {
        Ok(env) => (env.id, env.method.to_string()),
        Err(err) => {
            return QueuedClientItem::InvalidFrame {
                id: err.id,
                message: err.message,
            };
        }
    };
    match id {
        None => {
            let cancel_request_id = if method == "notifications/cancelled" {
                extract_cancel_request_id(&obj)
            } else {
                None
            };
            QueuedClientItem::Notification {
                method,
                raw_frame: raw_line,
                cancel_request_id,
            }
        }
        Some(req_id) => QueuedClientItem::Request {
            id: req_id,
            method,
            obj,
            raw_frame: raw_line,
        },
    }
}

fn extract_cancel_request_id(obj: &BTreeMap<String, ExactJson>) -> Option<JsonRpcId> {
    let params = obj.get("params").and_then(ExactJson::as_object)?;
    reject_unknown_keys(
        params,
        &["requestId", "reason", "_meta"],
        "notifications/cancelled params",
    )
    .ok()?;
    if params.get("reason").is_some_and(|v| v.as_str().is_none()) {
        return None;
    }
    validate_optional_meta(params, "notifications/cancelled params._meta").ok()?;
    extract_id_value(params.get("requestId")?).ok()
}

fn is_cancellation_item(item: &QueuedClientItem) -> bool {
    matches!(
        item,
        QueuedClientItem::Notification {
            method,
            cancel_request_id: Some(_),
            ..
        } if method == "notifications/cancelled"
    )
}

fn is_active_cancellation(item: &QueuedClientItem, state: &SessionState) -> bool {
    let Some(active_id) = state.active_id() else {
        return false;
    };
    matches!(
        item,
        QueuedClientItem::Notification {
            method,
            cancel_request_id: Some(cancel_id),
            ..
        } if method == "notifications/cancelled" && cancel_id == active_id
    )
}

fn cancel_active_request<CW: Write>(
    raw_line: &str,
    state: &mut SessionState,
    transport: &mut DuplexTransport,
    client_out: &mut CW,
) -> Result<(), ProxyError> {
    if state.cancelled_requests.len() >= MAX_CANCELLED_IN_FLIGHT {
        return fail_client_limit(
            client_out,
            "client exceeded maximum in-flight cancelled JSON-RPC requests",
        );
    }
    transport.send_upstream(raw_line.to_string())?;
    if let Some(cancelled) = state.active_request.take() {
        state.cancelled_requests.push(cancelled);
        state.interleaved_count = 0;
    }
    Ok(())
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

pub(crate) fn emit_upstream_eof<CW: Write>(
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

fn handle_notification<CW: Write>(
    method: &str,
    raw_frame: &str,
    cancel_request_id: Option<&JsonRpcId>,
    state: &mut SessionState,
    transport: &mut DuplexTransport,
    client_out: &mut CW,
) -> Result<(), ProxyError> {
    if method == "notifications/cancelled" {
        if cancel_request_id.is_some_and(|id| state.active_id().is_some_and(|active| active == id))
        {
            return cancel_active_request(raw_frame, state, transport, client_out);
        }
        // Drop cancellations missing a valid requestId or targeting idle, unknown, completed, or
        // locally-denied requests instead of leaking them upstream.
        return Ok(());
    }
    if ALLOWED_NOTIFICATION_METHODS.contains(&method) {
        transport.send_upstream(raw_frame.to_string())?;
    }
    // Disallowed notifications (including notification `tools/call`) are dropped without forwarding.
    Ok(())
}

fn fail_client_limit<CW: Write>(client_out: &mut CW, message: &str) -> Result<(), ProxyError> {
    let _ = write_jsonrpc_error(client_out, None, JSONRPC_INVALID_REQUEST, message, None);
    Err(ProxyError::UpstreamProtocol(message.to_string()))
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
