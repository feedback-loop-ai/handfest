//! Transport-agnostic MCP stdio JSON-RPC 2.0 proxy enforcing `HANDFEST v1` mandate chains.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::time::Duration;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    check_chain_revocations, evaluate_predicate_if_known, verify_chain_runtime, ActionRequest,
    RevocationSnapshot, VerifiedMandate,
};
use handfest_core::Verdict;
pub use handfest_ledger::ReceiptLedger;
use handfest_ledger::SqliteLedger;

use crate::adapters::validate_verified_chain;
pub use crate::adapters::{
    verify_mandate_chain, verify_mandate_chain_with, verify_revocations, verify_revocations_with,
    Clock, FixedClock, ProxyError, SystemClock,
};
use crate::exact_json::ExactJson;
use crate::framing::{
    fail_upstream_protocol, reject_unknown_keys, validate_json_keys_recursive,
    validate_optional_meta, write_denied_response, write_jsonrpc_error, write_raw_line, JsonRpcId,
    JSONRPC_INTERNAL_ERROR,
};
use crate::mapping::{denial_resource_id, CompiledPolicyMap, ToolPolicyMap};
use crate::session::{DispatchCtx, PendingKind};

/// Default maximum JSON-RPC line length in bytes (1 MiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;

/// Default grace period for draining a pending upstream response after client EOF.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// JSON-RPC 2.0 application error code returned when a `HANDFEST v1` policy denies a call.
pub const HANDFEST_DENIED_ERROR_CODE: i32 = -32001;

/// Fail-closed MCP stdio JSON-RPC 2.0 proxy enforcing a verified `HANDFEST v1` mandate chain.
pub struct McpProxy<C: Clock, L: ReceiptLedger = SqliteLedger> {
    pub(crate) verified_chain: Vec<VerifiedMandate>,
    pub(crate) chain_ids: Vec<MandateId>,
    pub(crate) actor_key: KeyId,
    pub(crate) policy_map: CompiledPolicyMap,
    pub(crate) ledger: L,
    pub(crate) clock: C,
    pub(crate) extra_revocations: RevocationSnapshot,
    pub(crate) max_line_bytes: usize,
    pub(crate) shutdown_timeout: Duration,
}

impl<C: Clock, L: ReceiptLedger> fmt::Debug for McpProxy<C, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpProxy")
            .field("chain_len", &self.verified_chain.len())
            .field("actor_key", &self.actor_key)
            .field("mapped_tools", &self.policy_map.policy_map().tools.len())
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
        let chain_ids = validate_verified_chain(&verified_chain)?;
        actor_key
            .validate()
            .map_err(|err| ProxyError::InvalidChain(format!("invalid actor_key: {err}")))?;
        let policy_map = policy_map.compile()?;
        Ok(Self {
            verified_chain,
            chain_ids,
            actor_key,
            policy_map,
            ledger,
            clock,
            extra_revocations: RevocationSnapshot::new(),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        })
    }

    /// Attaches static verified revocations enforced alongside revocations persisted in `ledger`.
    #[must_use]
    pub fn with_revocations(mut self, revocations: RevocationSnapshot) -> Self {
        self.extra_revocations = revocations;
        self
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
                    resource_kind: "mcp_tool".to_string(),
                    resource_id: "invalid_params".to_string(),
                };
                return self.record_denial_and_respond(
                    &req_id,
                    &denial_req,
                    now,
                    reason,
                    ctx.client_out,
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
                    let denial_req = build_mapping_denial_request(
                        &self.actor_key,
                        self.policy_map.policy_map(),
                        tool_name,
                        arguments,
                    );
                    return self.record_denial_and_respond(
                        &req_id,
                        &denial_req,
                        now,
                        err.to_string(),
                        ctx.client_out,
                    );
                }
            };

        self.ensure_upstream_alive(&req_id, ctx)?;

        let (verdict, receipt) = match self.ledger.evaluate_and_record_with_revocations(
            &self.verified_chain,
            &request,
            &facts,
            &self.extra_revocations,
            now,
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                write_jsonrpc_error(
                    ctx.client_out,
                    Some(&req_id),
                    JSONRPC_INTERNAL_ERROR,
                    &format!("handfest ledger evaluation failed: {err}"),
                    None,
                )?;
                return Err(ProxyError::Ledger(err));
            }
        };

        match verdict {
            Verdict::Permit => {
                self.dispatch_to_upstream(req_id, PendingKind::Normal, raw_frame, ctx)
            }
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
        raw_line: Option<&str>,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        // `classify_upstream_frame` already proved `result` XOR valid `error` object.
        if resp_obj.contains_key("error") {
            return match raw_line {
                Some(raw) => write_raw_line(client_out, raw),
                None => write_raw_line(client_out, &ExactJson::Object(resp_obj).to_json_string()),
            };
        }

        let Some(result_obj) = resp_obj
            .get_mut("result")
            .and_then(ExactJson::as_object_mut)
        else {
            return fail_upstream_protocol(
                client_out,
                Some(req_id),
                "malformed upstream tools/list response: missing result object".to_string(),
            );
        };

        if let Err(detail) = validate_tools_list_result_fields(result_obj) {
            return fail_upstream_protocol(client_out, Some(req_id), detail);
        }

        let Some(tools) = result_obj
            .get_mut("tools")
            .and_then(ExactJson::as_array_mut)
        else {
            return fail_upstream_protocol(
                client_out,
                Some(req_id),
                "malformed upstream tools/list response: missing result.tools array".to_string(),
            );
        };

        if let Err(detail) = validate_tools_list_entries(tools) {
            return fail_upstream_protocol(client_out, Some(req_id), detail);
        }

        let chain_revoked = match self.check_revocation_status(evaluated_at) {
            Ok(Ok(())) => false,
            Ok(Err(_)) => true,
            Err(ProxyError::Ledger(err)) => {
                write_jsonrpc_error(
                    client_out,
                    Some(req_id),
                    JSONRPC_INTERNAL_ERROR,
                    &format!("handfest ledger revocation verification failed: {err}"),
                    None,
                )?;
                return Err(ProxyError::Ledger(err));
            }
            Err(err) => return Err(err),
        };

        if verify_chain_runtime(&self.verified_chain, &self.actor_key, evaluated_at).is_err()
            || chain_revoked
        {
            tools.clear();
        } else {
            tools.retain(|entry| {
                entry
                    .as_object()
                    .and_then(|obj| obj.get("name"))
                    .and_then(ExactJson::as_str)
                    .is_some_and(|name| self.is_tool_permitted(name, evaluated_at))
            });
        }

        write_raw_line(client_out, &ExactJson::Object(resp_obj).to_json_string())
    }

    fn record_denial_and_respond<CW: Write>(
        &mut self,
        req_id: &JsonRpcId,
        denial_request: &ActionRequest,
        now: i64,
        mapping_reason: String,
        client_out: &mut CW,
    ) -> Result<(), ProxyError> {
        let reason = match verify_chain_runtime(&self.verified_chain, &self.actor_key, now) {
            Ok(()) => match self.check_revocation_status(now) {
                Ok(Ok(())) => mapping_reason,
                Ok(Err(rev_reason)) => rev_reason,
                Err(ProxyError::Ledger(err)) => {
                    write_jsonrpc_error(
                        client_out,
                        Some(req_id),
                        JSONRPC_INTERNAL_ERROR,
                        &format!("handfest ledger revocation verification failed: {err}"),
                        None,
                    )?;
                    return Err(ProxyError::Ledger(err));
                }
                Err(err) => return Err(err),
            },
            Err(chain_err) => chain_err.to_string(),
        };
        let receipt = match self.ledger.record_denial(
            self.chain_ids.clone(),
            denial_request,
            now,
            reason.clone(),
        ) {
            Ok(receipt) => receipt,
            Err(err) => {
                write_jsonrpc_error(
                    client_out,
                    Some(req_id),
                    JSONRPC_INTERNAL_ERROR,
                    &format!("handfest ledger denial recording failed: {err}"),
                    None,
                )?;
                return Err(ProxyError::Ledger(err));
            }
        };
        write_denied_response(
            client_out,
            req_id,
            &reason,
            &receipt.receipt_hash.to_string(),
        )
    }

    fn check_revocation_status(&self, evaluated_at: i64) -> Result<Result<(), String>, ProxyError> {
        let mut combined = self.ledger.load_revocations().map_err(ProxyError::Ledger)?;
        combined.extend_from(&self.extra_revocations);
        Ok(
            check_chain_revocations(&self.verified_chain, &combined, evaluated_at)
                .map_err(|deny| deny.to_string()),
        )
    }

    fn is_tool_permitted(&self, tool_name: &str, evaluated_at: i64) -> bool {
        let Some(policy) = self.policy_map.policy_map().get(tool_name) else {
            return false;
        };
        let Some(static_facts) = self.policy_map.static_facts_for(tool_name) else {
            return false;
        };
        self.verified_chain.iter().all(|vm| {
            let action_allowed = vm.ast.allow().iter().any(|pat| pat.matches(&policy.action));
            let resource_allowed = match policy.static_resource_id.as_deref() {
                Some(static_id) => vm
                    .ast
                    .on()
                    .iter()
                    .any(|sel| sel.kind() == policy.resource_kind && sel.matches(static_id)),
                None => vm
                    .ast
                    .on()
                    .iter()
                    .any(|sel| sel.kind() == policy.resource_kind),
            };
            let predicates_allowed = vm.ast.where_clauses().iter().all(|pred| {
                evaluate_predicate_if_known(pred, static_facts, evaluated_at).unwrap_or(true)
            });
            action_allowed && resource_allowed && predicates_allowed
        })
    }
}

/// Builds an [`ActionRequest`] for pre-gate mapping denials, preserving the configured mapped
/// action and resource metadata when the tool is present in `policy_map`.
fn build_mapping_denial_request(
    actor_key: &KeyId,
    policy_map: &ToolPolicyMap,
    tool_name: &str,
    arguments: Option<&ExactJson>,
) -> ActionRequest {
    match policy_map.get(tool_name) {
        Some(policy) => ActionRequest {
            actor_key: actor_key.clone(),
            action: policy.action.clone(),
            resource_kind: policy.resource_kind.clone(),
            resource_id: denial_resource_id(policy, arguments),
        },
        None => ActionRequest {
            actor_key: actor_key.clone(),
            action: format!("mcp.unmapped:{tool_name}"),
            resource_kind: "mcp_tool".to_string(),
            resource_id: tool_name.to_string(),
        },
    }
}

fn validate_tools_list_result_fields(
    result_obj: &BTreeMap<String, ExactJson>,
) -> Result<(), String> {
    reject_unknown_keys(
        result_obj,
        &["tools", "nextCursor", "_meta"],
        "upstream tools/list result",
    )
    .map_err(|err| err.to_string())?;
    if let Some(cursor) = result_obj.get("nextCursor") {
        if cursor.as_str().is_none() {
            return Err(
                "malformed upstream tools/list response: result.nextCursor must be a string"
                    .to_string(),
            );
        }
    }
    validate_optional_meta(
        result_obj,
        "malformed upstream tools/list response: result._meta",
    )?;
    Ok(())
}

fn validate_tools_list_entries(tools: &[ExactJson]) -> Result<(), String> {
    for entry in tools {
        let Some(obj) = entry.as_object() else {
            return Err("malformed upstream tools/list entry: expected JSON object".to_string());
        };
        if let Some(key) = obj
            .keys()
            .find(|k| k.as_str() != "name" && k.eq_ignore_ascii_case("name"))
        {
            return Err(format!(
                "malformed upstream tools/list entry: key '{key}' collides case-insensitively with 'name'"
            ));
        }
        validate_json_keys_recursive(entry)
            .map_err(|err| err.format_with_context("malformed upstream tools/list entry"))?;
        let Some(name) = obj.get("name").and_then(ExactJson::as_str) else {
            return Err(
                "malformed upstream tools/list entry: missing or non-string 'name'".to_string(),
            );
        };
        if name.is_empty() {
            return Err(
                "malformed upstream tools/list entry: 'name' must not be empty".to_string(),
            );
        }
    }
    Ok(())
}

fn extract_tool_call_params(
    obj: &BTreeMap<String, ExactJson>,
) -> Result<(&str, Option<&ExactJson>), String> {
    let Some(params) = obj.get("params").and_then(ExactJson::as_object) else {
        return Err("tools/call params must be a JSON object".to_string());
    };
    reject_unknown_keys(params, &["name", "arguments", "_meta"], "tools/call params")
        .map_err(|err| err.to_string())?;
    validate_optional_meta(params, "tools/call params._meta")?;
    let Some(name) = params.get("name").and_then(ExactJson::as_str) else {
        return Err("tools/call params.name must be a string".to_string());
    };
    if name.is_empty() {
        return Err("tools/call params.name must not be empty".to_string());
    }
    Ok((name, params.get("arguments")))
}
