//! Regression tests for shared `handfest_ledger::ReceiptLedger::record_denial` wiring and
//! pre-gate mapping-denial receipt fidelity.

use std::collections::BTreeSet;
use std::io::{self, BufReader, Cursor, Write};
use std::sync::{Arc, Mutex};

use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::{
    authorize, build_denial_receipt, ActionRequest, DecisionReceipt, QuotaSnapshot, VerifiedFacts,
    VerifiedMandate,
};
use handfest_core::{ActorKind, Verdict};
use handfest_ledger::{LedgerError, ReceiptLedger, SqliteLedger, TrackRecord};
use handfest_mcp::{
    verify_mandate_chain, FixedClock, McpProxy, ProxyError, ToolPolicyMap,
    HANDFEST_DENIED_ERROR_CODE,
};
use serde_json::{json, Value};

#[derive(Default)]
struct RecordingLedger {
    receipts: Vec<DecisionReceipt>,
    fail_record_denial: Option<String>,
}

impl ReceiptLedger for RecordingLedger {
    fn evaluate_and_record(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
        let prev = self.receipts.last().map(|r| r.receipt_hash);
        let (verdict, receipt) = authorize(chain, request, facts, &QuotaSnapshot::new(), now, prev);
        self.receipts.push(receipt.clone());
        Ok((verdict, receipt))
    }

    fn record_denial(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
    ) -> Result<DecisionReceipt, LedgerError> {
        if let Some(msg) = &self.fail_record_denial {
            return Err(LedgerError::Storage(msg.clone()));
        }
        let prev = self.receipts.last().map(|r| r.receipt_hash);
        let receipt = build_denial_receipt(
            chain_ids,
            request.actor_key.clone(),
            request.action.clone(),
            request.resource_kind.clone(),
            request.resource_id.clone(),
            now,
            reason,
            prev,
        )
        .map_err(|err| LedgerError::Integrity(err.to_string()))?;
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError> {
        let (_, rec) = self.audit_snapshot(Some(actor_key))?;
        Ok(rec.expect("actor_key was provided"))
    }

    fn audit_snapshot(
        &self,
        actor_key: Option<&KeyId>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
        let mut expected_prev = None;
        for receipt in &self.receipts {
            if receipt.prev_receipt_hash != expected_prev || !receipt.verify_hash() {
                return Err(LedgerError::Integrity("corrupt receipt chain".to_string()));
            }
            expected_prev = Some(receipt.receipt_hash);
        }
        let rec = actor_key.map(|key| {
            let mut permits = 0u64;
            let mut denies = 0u64;
            let mut leaves = BTreeSet::new();
            let mut first = None::<i64>;
            let mut last = None::<i64>;
            for r in self.receipts.iter().filter(|r| &r.actor_key == key) {
                match r.verdict {
                    Verdict::Permit => permits += 1,
                    Verdict::Deny { .. } => denies += 1,
                }
                if let Some(leaf) = r.chain_ids.last() {
                    leaves.insert(*leaf);
                }
                first = Some(first.map_or(r.timestamp, |c| c.min(r.timestamp)));
                last = Some(last.map_or(r.timestamp, |c| c.max(r.timestamp)));
            }
            TrackRecord {
                actor_key: key.clone(),
                total_decisions: permits + denies,
                permits,
                denies,
                distinct_mandates: u64::try_from(leaves.len()).unwrap_or(u64::MAX),
                first_timestamp: first,
                last_timestamp: last,
            }
        });
        Ok((self.receipts.len(), rec))
    }
}

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sign_mandate(
    signer: &Ed25519Keypair,
    text: &str,
    valid_from: i64,
    valid_until: i64,
) -> SignedMandate {
    let ast = parse_mandate(text).expect("valid HANDFEST v1 mandate");
    let canonical = try_render_canonical(&ast).expect("canonical render");
    signer
        .sign_mandate(&canonical, "test-anchor", valid_from, valid_until)
        .expect("sign mandate")
}

fn merge_pr_policy_map() -> ToolPolicyMap {
    ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "merge_pr": {
                    "action": "git.pr.merge",
                    "resource_kind": "repo",
                    "resource_id_arg": "repo"
                }
            }
        }"#,
    )
    .unwrap()
}

fn single_hop_chain(
    allow_action: &str,
    resource_kind: &str,
    resource_pat: &str,
    extra_clauses: &str,
) -> (Vec<VerifiedMandate>, Ed25519Keypair) {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();

    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Admin\" (key: {root})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW {allow_action}\n\
         ON {resource_kind} \"{resource_pat}\"\n\
         {extra_clauses}",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let signed = sign_mandate(&root_kp, &text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();
    (verified, agent_kp)
}

fn run_raw<L: ReceiptLedger>(
    proxy: &mut McpProxy<FixedClock, L>,
    client_bytes: &[u8],
    upstream_bytes: &[u8],
) -> (Result<(), ProxyError>, Vec<Value>, Vec<u8>) {
    let mut client_out = Vec::new();
    let upstream_buf = SharedBuffer::default();
    let res = proxy.run(
        BufReader::new(Cursor::new(client_bytes.to_vec())),
        &mut client_out,
        upstream_buf.clone(),
        BufReader::new(Cursor::new(upstream_bytes.to_vec())),
    );
    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let captured = upstream_buf.0.lock().unwrap().clone();
    (res, responses, captured)
}

#[test]
fn merge_pr_missing_repo_records_exact_receipt_in_sqlite_and_custom_ledger_without_upstream() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("git.*", "repo", "*", "");
    let chain_ids = vec![verified[0].ast.try_mandate_id().unwrap()];
    let call = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{}}}\n";
    let expected_reason = "tool 'merge_pr': missing required resource_id argument 'repo'";

    let mut sqlite_proxy = McpProxy::new(
        verified.clone(),
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let (res, responses, upstream_in) = run_raw(&mut sqlite_proxy, call, b"");
    res.expect("sqlite mapping denial handled cleanly");
    assert!(upstream_in.is_empty(), "upstream must never be called");
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );
    assert_eq!(
        responses[0]["error"]["data"]["reason"],
        json!(expected_reason)
    );
    assert_eq!(
        responses[0]["error"]["message"],
        json!(format!("handfest denied: {expected_reason}"))
    );

    let expected_receipt = build_denial_receipt(
        chain_ids.clone(),
        agent_kp.key_id(),
        "git.pr.merge".to_string(),
        "repo".to_string(),
        "merge_pr".to_string(),
        now,
        expected_reason.to_string(),
        None,
    )
    .unwrap();
    assert_eq!(
        responses[0]["error"]["data"]["receipt_hash"],
        json!(expected_receipt.receipt_hash.to_string())
    );
    assert_eq!(sqlite_proxy.ledger().verify_integrity().unwrap(), 1);
    let tr = sqlite_proxy
        .ledger()
        .track_record(&agent_kp.key_id())
        .unwrap();
    assert_eq!(tr.total_decisions, 1);
    assert_eq!(tr.permits, 0);
    assert_eq!(tr.denies, 1);

    let mut custom_proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        RecordingLedger::default(),
        FixedClock::new(now),
    )
    .unwrap();
    let (res2, responses2, upstream_in2) = run_raw(&mut custom_proxy, call, b"");
    res2.expect("custom ledger mapping denial handled cleanly");
    assert!(upstream_in2.is_empty(), "upstream must never be called");
    assert_eq!(custom_proxy.ledger().verify_integrity().unwrap(), 1);

    let stored = &custom_proxy.ledger().receipts[0];
    assert_eq!(stored.chain_ids, chain_ids);
    assert_eq!(stored.actor_key, agent_kp.key_id());
    assert_eq!(stored.action, "git.pr.merge");
    assert_eq!(stored.resource, "repo \"merge_pr\"");
    assert_eq!(
        stored.verdict,
        Verdict::Deny {
            reason: expected_reason.to_string()
        }
    );
    assert_eq!(
        responses2[0]["error"]["data"]["receipt_hash"],
        json!(stored.receipt_hash.to_string())
    );
    assert_eq!(
        responses2[0]["error"]["data"]["reason"],
        json!(expected_reason)
    );
}

struct ExpectedDenial<'a> {
    chain_ids: &'a [MandateId],
    actor_key: &'a KeyId,
    action: &'a str,
    resource_kind: &'a str,
    resource_id: &'a str,
    now: i64,
    reason: &'a str,
    prev: Option<MandateId>,
}

fn assert_chained_denial(resp: &Value, expected: &ExpectedDenial<'_>) -> MandateId {
    assert_eq!(resp["error"]["code"], json!(HANDFEST_DENIED_ERROR_CODE));
    assert_eq!(resp["error"]["data"]["reason"], json!(expected.reason));
    let receipt = build_denial_receipt(
        expected.chain_ids.to_vec(),
        expected.actor_key.clone(),
        expected.action.to_string(),
        expected.resource_kind.to_string(),
        expected.resource_id.to_string(),
        expected.now,
        expected.reason.to_string(),
        expected.prev,
    )
    .unwrap();
    assert_eq!(
        resp["error"]["data"]["receipt_hash"],
        json!(receipt.receipt_hash.to_string())
    );
    receipt.receipt_hash
}

fn transfer_policy_map() -> ToolPolicyMap {
    ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "transfer": {
                    "action": "finance.transfer",
                    "resource_kind": "account",
                    "resource_id_arg": "account",
                    "arg_facts": {
                        "amount": { "field": "resource.amount", "type": "decimal" }
                    }
                }
            }
        }"#,
    )
    .unwrap()
}

#[test]
fn mapping_denials_chain_with_permits_preserve_quotas_and_exact_reasons() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain(
        "finance.transfer",
        "account",
        "acct-*",
        "LIMIT 2 calls\n  AND 100.00 USD sum(resource.amount)\n",
    );
    let chain_ids = vec![verified[0].ast.try_mandate_id().unwrap()];
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        transfer_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let client_frames = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"transfer\",\"arguments\":{\"account\":\"acct-1\",\"amount\":10.00}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"unmapped_tool\",\"arguments\":{}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"transfer\",\"arguments\":{\"account\":\"acct-1\",\"amount\":true}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"transfer\",\"arguments\":{\"account\":\"acct-1\",\"amount\":90.00}}}\n"
    );
    let upstream_frames = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":1}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"ok\":5}}\n"
    );

    let (res, responses, upstream_in) = run_raw(
        &mut proxy,
        client_frames.as_bytes(),
        upstream_frames.as_bytes(),
    );
    res.expect("mixed permit and mapping denial session succeeded");
    assert_eq!(responses.len(), 5);
    assert_eq!(
        std::str::from_utf8(&upstream_in).unwrap().lines().count(),
        2
    );
    assert_eq!(responses[0]["result"]["ok"], json!(1));
    assert_eq!(responses[4]["result"]["ok"], json!(5));

    let actor_key = agent_kp.key_id();
    let r1 = DecisionReceipt {
        chain_ids: chain_ids.clone(),
        actor_key: actor_key.clone(),
        action: "finance.transfer".to_string(),
        resource: "account \"acct-1\"".to_string(),
        timestamp: now,
        verdict: Verdict::Permit,
        receipt_hash: MandateId([0u8; 32]),
        prev_receipt_hash: None,
    }
    .compute_hash();

    let r2 = assert_chained_denial(
        &responses[1],
        &ExpectedDenial {
            chain_ids: &chain_ids,
            actor_key: &actor_key,
            action: "mcp.unmapped:unmapped_tool",
            resource_kind: "mcp_tool",
            resource_id: "unmapped_tool",
            now,
            reason: "unmapped MCP tool 'unmapped_tool'",
            prev: Some(r1),
        },
    );
    let wrong_type_reason = responses[2]["error"]["data"]["reason"].as_str().unwrap();
    assert!(wrong_type_reason.starts_with("tool 'transfer': invalid argument fact 'amount':"));
    let r3 = assert_chained_denial(
        &responses[2],
        &ExpectedDenial {
            chain_ids: &chain_ids,
            actor_key: &actor_key,
            action: "finance.transfer",
            resource_kind: "account",
            resource_id: "acct-1",
            now,
            reason: wrong_type_reason,
            prev: Some(r2),
        },
    );
    let _r4 = assert_chained_denial(
        &responses[3],
        &ExpectedDenial {
            chain_ids: &chain_ids,
            actor_key: &actor_key,
            action: "mcp.invalid_params",
            resource_kind: "mcp_tool",
            resource_id: "invalid_params",
            now,
            reason: "tools/call params.name must be a string",
            prev: Some(r3),
        },
    );

    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 5);
    let tr = proxy.ledger().track_record(&actor_key).unwrap();
    assert_eq!(tr.total_decisions, 5);
    assert_eq!(tr.permits, 2);
    assert_eq!(tr.denies, 3);
}

fn assert_chain_denial_reason(
    chain: Vec<VerifiedMandate>,
    actor_key: KeyId,
    now: i64,
    expected_substring: &str,
) {
    let call = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{}}}\n";
    let chain_ids: Vec<MandateId> = chain
        .iter()
        .map(|vm| vm.ast.try_mandate_id().unwrap())
        .collect();
    let mut proxy = McpProxy::new(
        chain,
        actor_key.clone(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let (res, responses, upstream_in) = run_raw(&mut proxy, call, b"");
    res.expect("chain denial handled cleanly");
    assert!(upstream_in.is_empty(), "upstream must never be called");
    let reason = responses[0]["error"]["data"]["reason"].as_str().unwrap();
    assert!(
        reason.contains(expected_substring),
        "expected reason containing '{expected_substring}', got: {reason}"
    );
    assert!(
        !reason.contains("missing required resource_id"),
        "chain failure must not be masked by mapping error; got: {reason}"
    );
    let _ = assert_chained_denial(
        &responses[0],
        &ExpectedDenial {
            chain_ids: &chain_ids,
            actor_key: &actor_key,
            action: "git.pr.merge",
            resource_kind: "repo",
            resource_id: "merge_pr",
            now,
            reason,
            prev: None,
        },
    );
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 1);
}

#[test]
fn mapping_failure_never_masks_expired_not_yet_valid_or_unbound_chain() {
    let (verified, agent_kp) = single_hop_chain("git.*", "repo", "*", "");
    let expired_now = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let early_now = parse_rfc3339_utc("2025-12-31T23:59:59Z").unwrap();
    let valid_now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let rogue_actor = Ed25519Keypair::generate();

    assert_chain_denial_reason(
        verified.clone(),
        agent_kp.key_id(),
        expired_now,
        "outside anchor proof validity window",
    );
    assert_chain_denial_reason(
        verified.clone(),
        agent_kp.key_id(),
        early_now,
        "outside anchor proof validity window",
    );
    assert_chain_denial_reason(
        verified.clone(),
        rogue_actor.key_id(),
        valid_now,
        "does not match leaf mandate TO key",
    );

    let mut bad_signer = verified.clone();
    bad_signer[0].proof.signer_key = rogue_actor.key_id();
    assert_chain_denial_reason(bad_signer, agent_kp.key_id(), valid_now, "proof signer key");

    let mut bad_kind = verified.clone();
    bad_kind[0].proof.actor_kind = ActorKind::Service;
    assert_chain_denial_reason(bad_kind, agent_kp.key_id(), valid_now, "proof actor kind");

    let mut bad_window = verified;
    bad_window[0].proof.valid_until = bad_window[0].proof.valid_from;
    assert_chain_denial_reason(
        bad_window,
        agent_kp.key_id(),
        valid_now,
        "invalid anchor proof validity window",
    );
}

#[test]
fn record_denial_ledger_failure_returns_32603_and_typed_ledger_error_without_upstream() {
    let call = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{}}}\n";
    let (verified, agent_kp) = single_hop_chain("git.*", "repo", "*", "");

    let mut ts_proxy = McpProxy::new(
        verified.clone(),
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(i64::MAX),
    )
    .unwrap();
    let (res, responses, upstream_in) = run_raw(&mut ts_proxy, call, b"");
    assert!(
        matches!(res, Err(ProxyError::Ledger(LedgerError::Integrity(_)))),
        "expected ProxyError::Ledger(LedgerError::Integrity(_)), got {res:?}"
    );
    assert!(upstream_in.is_empty());
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], json!(-32603));

    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let failing_ledger = RecordingLedger {
        receipts: Vec::new(),
        fail_record_denial: Some("disk full".to_string()),
    };
    let mut storage_proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        failing_ledger,
        FixedClock::new(now),
    )
    .unwrap();
    let (res, responses, upstream_in) = run_raw(&mut storage_proxy, call, b"");
    assert!(
        matches!(res, Err(ProxyError::Ledger(LedgerError::Storage(ref msg))) if msg == "disk full"),
        "expected ProxyError::Ledger(LedgerError::Storage(\"disk full\")), got {res:?}"
    );
    assert!(upstream_in.is_empty());
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], json!(-32603));
}
