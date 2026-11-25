//! Transport-agnostic MCP stdio JSON-RPC 2.0 proxy enforcing `HANDFEST v1` mandate chains.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::time::Duration;

use handfest_core::ast::{is_valid_quoted_str, is_valid_timestamp, KeyId};
use handfest_core::gate::{ActionRequest, VerifiedFacts, VerifiedMandate};
use handfest_core::Verdict;
use handfest_ledger::SqliteLedger;

use crate::adapters::validate_verified_chain;
pub use crate::adapters::{
    verify_mandate_chain, verify_mandate_chain_with, Clock, FixedClock, ProxyError, ReceiptLedger,
    SystemClock,
};
use crate::exact_json::ExactJson;
use crate::framing::{
    fail_upstream_protocol, write_denied_response, write_jsonrpc_error, write_raw_line, JsonRpcId,
    JSONRPC_INTERNAL_ERROR,
};
use crate::mapping::{MappingError, ToolPolicy, ToolPolicyMap};
use crate::session::{dispatch_to_upstream, DispatchCtx, PendingKind};

/// Default maximum JSON-RPC line length in bytes (1 MiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;

/// Default grace period for draining a pending upstream response after client EOF.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// JSON-RPC 2.0 application error code returned when a `HANDFEST v1` policy denies a call.
pub const HANDFEST_DENIED_ERROR_CODE: i32 = -32001;

/// Fail-closed MCP stdio JSON-RPC 2.0 proxy enforcing a verified `HANDFEST v1` mandate chain.
pub struct McpProxy<C: Clock, L: ReceiptLedger = SqliteLedger> {
    pub(crate) verified_chain: Vec<VerifiedMandate>,
    pub(crate) actor_key: KeyId,
    pub(crate) policy_map: ToolPolicyMap,
    pub(crate) ledger: L,
    pub(crate) clock: C,
    pub(crate) max_line_bytes: usize,
    pub(crate) shutdown_timeout: Duration,
}

impl<C: Clock, L: ReceiptLedger> fmt::Debug for McpProxy<C, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpProxy")
            .field("chain_len", &self.verified_chain.len())
            .field("actor_key", &self.actor_key)
            .field("mapped_tools", &self.policy_map.tools.len())
            .field("max_line_bytes", &self.max_line_bytes)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish_non_exhaustive()
    }
}

impl<C: Clock, L: ReceiptLedger> McpProxy<C, L> {
    /// Constructs a validated [`McpProxy`] over a verified mandate chain and [`ReceiptLedger`].
    pub fn new(
        verified_chain: Vec<VerifiedMandate>,
        actor_key: KeyId,
        policy_map: ToolPolicyMap,
        ledger: L,
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
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
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

    /// Overrides the grace period for draining a pending upstream response after client EOF.
    #[must_use]
    pub const fn with_shutdown_timeout(mut self, shutdown_timeout: Duration) -> Self {
        self.shutdown_timeout = shutdown_timeout;
        self
    }

    /// Borrows the underlying [`ReceiptLedger`].
    #[must_use]
    pub const fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Mutably borrows the underlying [`ReceiptLedger`].
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut L {
        &mut self.ledger
    }

    /// Consumes the proxy and returns its underlying [`ReceiptLedger`].
    #[must_use]
    pub fn into_ledger(self) -> L {
        self.ledger
    }

    pub(crate) fn handle_tools_call<CW: Write>(
        &mut self,
        req_id: JsonRpcId,
        obj: &BTreeMap<String, ExactJson>,
        raw_frame: &str,
        ctx: &mut DispatchCtx<'_, CW>,
    ) -> Result<(), ProxyError> {
        let now = self.clock.now_unix();
        let (tool_name, arguments) = match extract_tool_call_params(obj) {
            Ok(parts) => parts,
            Err(reason) => {
                let denial_req = ActionRequest {
                    actor_key: self.actor_key.clone(),
                    action: "mcp.invalid_params".to_string(),
                    resource_kind: format!("mcp_tool:{reason}"),
                    resource_id: "invalid_params".to_string(),
                };
                return self.record_denial_and_respond(&req_id, &denial_req, now, ctx.client_out);
            }
        };

        let (request, facts) =
            match self
                .policy_map
                .map_call_exact(&self.actor_key, tool_name, arguments)
            {
                Ok(mapped) => mapped,
                Err(err) => {
                    let denial_req = build_mapping_denial_request(
                        &self.actor_key,
                        &self.policy_map,
                        tool_name,
                        arguments,
                        &err,
                    );
                    return self.record_denial_and_respond(
                        &req_id,
                        &denial_req,
                        now,
                        ctx.client_out,
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
                        ctx.client_out,
                        Some(&req_id),
                        JSONRPC_INTERNAL_ERROR,
                        &format!("handfest ledger evaluation failed: {err}"),
                        None,
                    )?;
                    return Err(ProxyError::Ledger(Box::new(err)));
                }
            };

        match verdict {
            Verdict::Permit => dispatch_to_upstream(req_id, PendingKind::Normal, raw_frame, ctx),
            Verdict::Deny { reason } => write_denied_response(
                ctx.client_out,
                &req_id,
                &reason,
                &receipt.receipt_hash.to_string(),
            ),
        }
    }

    pub(crate) fn relay_filtered_tools_list<CW: Write>(
        &self,
        req_id: &JsonRpcId,
        evaluated_at: i64,
        mut resp_obj: BTreeMap<String, ExactJson>,
        raw_line: &str,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        // `classify_upstream_frame` already proved `result` XOR valid `error` object.
        if resp_obj.contains_key("error") {
            return write_raw_line(client_out, raw_line);
        }

        let Some(tools) = resp_obj
            .get_mut("result")
            .and_then(ExactJson::as_object_mut)
            .and_then(|res| res.get_mut("tools"))
            .and_then(ExactJson::as_array_mut)
        else {
            return fail_upstream_protocol(
                client_out,
                Some(req_id),
                "malformed upstream tools/list response: missing result.tools array".to_string(),
            );
        };

        tools.retain(|entry| {
            entry
                .as_object()
                .and_then(|obj| obj.get("name"))
                .and_then(ExactJson::as_str)
                .is_some_and(|name| self.is_tool_permitted(name, evaluated_at))
        });

        write_raw_line(client_out, &ExactJson::Object(resp_obj).to_json_string())
    }

    fn record_denial_and_respond<CW: Write>(
        &mut self,
        req_id: &JsonRpcId,
        denial_request: &ActionRequest,
        now: i64,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        let (verdict, receipt) = self
            .ledger
            .evaluate_and_record(
                &self.verified_chain,
                denial_request,
                &VerifiedFacts::new(),
                now,
            )
            .map_err(|err| ProxyError::Ledger(Box::new(err)))?;
        match verdict {
            Verdict::Deny { reason } => write_denied_response(
                client_out,
                req_id,
                &reason,
                &receipt.receipt_hash.to_string(),
            ),
            Verdict::Permit => Err(ProxyError::UpstreamProtocol(
                "internal invariant violation: denial request evaluated to Permit".to_string(),
            )),
        }
    }

    fn chain_proofs_valid_at(&self, now: i64) -> bool {
        if !is_valid_timestamp(now) {
            return false;
        }
        self.verified_chain.iter().all(|vm| {
            &vm.proof.signer_key == vm.ast.from().key()
                && vm.proof.actor_kind == vm.ast.from().kind()
                && vm.proof.valid_from < vm.proof.valid_until
                && now >= vm.proof.valid_from
                && now < vm.proof.valid_until
        })
    }

    fn is_tool_permitted(&self, tool_name: &str, now: i64) -> bool {
        if !self.chain_proofs_valid_at(now) {
            return false;
        }
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

/// Builds a guaranteed-denial [`ActionRequest`] that preserves the actual mapped action when the
/// tool is configured in `policy_map` and records the exact mapping failure in `resource_kind`.
fn build_mapping_denial_request(
    actor_key: &KeyId,
    policy_map: &ToolPolicyMap,
    tool_name: &str,
    arguments: Option<&ExactJson>,
    err: &MappingError,
) -> ActionRequest {
    match policy_map.get(tool_name) {
        Some(policy) => ActionRequest {
            actor_key: actor_key.clone(),
            action: policy.action.clone(),
            // Colon is forbidden in `is_valid_ident`, guaranteeing `Verdict::Deny` even under
            // wildcard mandates while preserving the real mapped action and exact error detail.
            resource_kind: format!("{}:{err}", policy.resource_kind),
            resource_id: best_effort_resource_id(tool_name, policy, arguments),
        },
        None => ActionRequest {
            actor_key: actor_key.clone(),
            action: format!("mcp.unmapped:{tool_name}"),
            resource_kind: "mcp_tool".to_string(),
            resource_id: tool_name.to_string(),
        },
    }
}

fn best_effort_resource_id(
    tool_name: &str,
    policy: &ToolPolicy,
    arguments: Option<&ExactJson>,
) -> String {
    if let Some(static_id) = &policy.static_resource_id {
        return static_id.clone();
    }
    if let Some(arg_key) = &policy.resource_id_arg {
        if let Some(val) = arguments
            .and_then(ExactJson::as_object)
            .and_then(|map| map.get(arg_key))
            .and_then(ExactJson::as_str)
        {
            if is_valid_quoted_str(val) {
                return val.to_string();
            }
        }
    }
    tool_name.to_string()
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
