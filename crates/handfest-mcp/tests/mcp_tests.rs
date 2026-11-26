//! Integration tests for `handfest-mcp`: policy mapping, stdio JSON-RPC proxy, and CLI binary.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use handfest_anchors::{AnchorError, AnchorVerifier, Ed25519Keypair, SignedMandate};
use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::{
    authorize, build_denial_receipt, ActionRequest, DecisionReceipt, QuotaSnapshot, VerifiedFacts,
    VerifiedMandate,
};
use handfest_core::{ActorKind, Verdict};
use handfest_ledger::{LedgerError, ReceiptLedger, SqliteLedger, TrackRecord};
use handfest_mcp::{
    verify_mandate_chain, verify_mandate_chain_with, FactSpec, FactType, FixedClock, McpProxy,
    ProxyError, ToolPolicy, ToolPolicyMap, TypedScalar, HANDFEST_DENIED_ERROR_CODE,
};
use serde_json::{json, Value};
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// In-memory byte pipe and fake upstream MCP server
// ---------------------------------------------------------------------------

struct PipeWriter {
    tx: mpsc::Sender<Vec<u8>>,
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pipe reader dropped"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PipeReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.buf.len() {
            let n = (self.buf.len() - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        match self.rx.recv() {
            Ok(chunk) => {
                self.buf = chunk;
                self.pos = 0;
                self.read(out)
            }
            Err(_) => Ok(0),
        }
    }
}

fn mem_pipe() -> (PipeWriter, BufReader<PipeReader>) {
    let (tx, rx) = mpsc::channel();
    (
        PipeWriter { tx },
        BufReader::new(PipeReader {
            rx,
            buf: Vec::new(),
            pos: 0,
        }),
    )
}

#[derive(Default)]
struct FakeUpstreamState {
    tool_calls: Mutex<Vec<Value>>,
    raw_frames: Mutex<Vec<String>>,
    notifications: Mutex<Vec<String>>,
    call_count: AtomicUsize,
}

impl FakeUpstreamState {
    fn calls(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    fn recorded_calls(&self) -> Vec<Value> {
        self.tool_calls.lock().unwrap().clone()
    }

    fn recorded_raw_frames(&self) -> Vec<String> {
        self.raw_frames.lock().unwrap().clone()
    }

    fn recorded_notifications(&self) -> Vec<String> {
        self.notifications.lock().unwrap().clone()
    }
}

fn spawn_fake_upstream(
    advertised_tools: Vec<Value>,
) -> (
    PipeWriter,
    BufReader<PipeReader>,
    Arc<FakeUpstreamState>,
    thread::JoinHandle<()>,
) {
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let state = Arc::new(FakeUpstreamState::default());
    let state_bg = Arc::clone(&state);

    let handle = thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            let read_n = up_in_r.read_line(&mut line).unwrap_or(0);
            if read_n == 0 {
                break;
            }
            let raw = line.trim_end_matches('\n');
            if raw.is_empty() {
                continue;
            }
            state_bg.raw_frames.lock().unwrap().push(raw.to_string());
            let req: Value = serde_json::from_str(raw).expect("upstream received valid JSON");
            let method = req["method"].as_str().unwrap_or("");
            let id = req.get("id");

            if id.is_none() {
                state_bg
                    .notifications
                    .lock()
                    .unwrap()
                    .push(method.to_string());
                continue;
            }
            let id_val = id.unwrap().clone();
            let resp = match method {
                "initialize" => json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": { "protocolVersion": "2024-11-05", "capabilities": { "tools": {} } }
                }),
                "ping" => json!({ "jsonrpc": "2.0", "id": id_val, "result": {} }),
                "tools/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": { "tools": advertised_tools }
                }),
                "tools/call" => {
                    state_bg.call_count.fetch_add(1, Ordering::SeqCst);
                    state_bg.tool_calls.lock().unwrap().push(req.clone());
                    let name = req["params"]["name"].as_str().unwrap_or("unknown");
                    json!({
                        "jsonrpc": "2.0",
                        "id": id_val,
                        "result": {
                            "content": [{ "type": "text", "text": format!("executed:{name}") }]
                        }
                    })
                }
                other => json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "error": { "code": -32601, "message": format!("unexpected method {other}") }
                }),
            };
            let encoded = serde_json::to_string(&resp).unwrap();
            writeln!(up_out_w, "{encoded}").unwrap();
            up_out_w.flush().unwrap();
        }
    });

    (up_in_w, up_out_r, state, handle)
}

// ---------------------------------------------------------------------------
// Mandate signing helpers
// ---------------------------------------------------------------------------

fn sign_text(
    keypair: &Ed25519Keypair,
    mandate_text: &str,
    valid_from: i64,
    valid_until: i64,
) -> (SignedMandate, String) {
    let ast = parse_mandate(mandate_text).expect("mandate parses");
    let canonical = try_render_canonical(&ast).expect("mandate renders canonically");
    let mandate_id = ast.try_mandate_id().expect("mandate id").to_string();
    let signed = keypair
        .sign_mandate(&canonical, "test-ed25519", valid_from, valid_until)
        .expect("mandate signs");
    (signed, mandate_id)
}

fn build_pr_chain(
    root_kp: &Ed25519Keypair,
    mid_kp: &Ed25519Keypair,
    agent_kp: &Ed25519Keypair,
    valid_from: i64,
    valid_until: i64,
) -> (Vec<SignedMandate>, Vec<VerifiedMandate>) {
    let root_text = format!(
        "HANDFEST v1\n\
         FROM human \"Alice\" (key: {root})\n\
         TO agent \"Orchestrator\" (key: {mid})\n\
         DELEGATION max 2 hops\n\
         ALLOW git.pr.*\n\
         ON repo \"org/*\"\n\
         LIMIT 5 calls\n",
        root = root_kp.key_id(),
        mid = mid_kp.key_id(),
    );
    let (root_signed, root_id) = sign_text(root_kp, &root_text, valid_from, valid_until);

    let child_text = format!(
        "HANDFEST v1\n\
         PARENT {root_id}\n\
         FROM agent \"Orchestrator\" (key: {mid})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/app\"\n\
         LIMIT 2 calls\n",
        mid = mid_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let (child_signed, _) = sign_text(mid_kp, &child_text, valid_from, valid_until);
    let signed = vec![root_signed, child_signed];
    let verified = verify_mandate_chain(&signed).expect("chain verifies");
    (signed, verified)
}

fn pr_policy_map() -> ToolPolicyMap {
    let mut tools = BTreeMap::new();
    tools.insert(
        "merge_pr".to_string(),
        ToolPolicy {
            action: "git.pr.merge".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_arg: Some("repo".to_string()),
            static_resource_id: None,
            arg_facts: BTreeMap::new(),
            static_facts: BTreeMap::new(),
        },
    );
    tools.insert(
        "close_pr".to_string(),
        ToolPolicy {
            action: "git.pr.close".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_arg: Some("repo".to_string()),
            static_resource_id: None,
            arg_facts: BTreeMap::new(),
            static_facts: BTreeMap::new(),
        },
    );
    tools.insert(
        "delete_repo".to_string(),
        ToolPolicy {
            action: "git.repo.delete".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_arg: Some("repo".to_string()),
            static_resource_id: None,
            arg_facts: BTreeMap::new(),
            static_facts: BTreeMap::new(),
        },
    );
    ToolPolicyMap { tools }
}

fn run_proxy_session(
    proxy: &mut McpProxy<FixedClock>,
    advertised_tools: Vec<Value>,
    client_lines: &[&str],
) -> (Result<(), ProxyError>, Vec<Value>, Arc<FakeUpstreamState>) {
    let (up_in, up_out, state, handle) = spawn_fake_upstream(advertised_tools);
    let input_blob = client_lines.join("\n") + "\n";
    let client_in = BufReader::new(Cursor::new(input_blob.into_bytes()));
    let mut client_out = Vec::new();

    let run_res = proxy.run(client_in, &mut client_out, up_in, up_out);
    handle.join().expect("fake upstream thread exited cleanly");

    let responses = String::from_utf8(client_out)
        .expect("proxy stdout is valid UTF-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("proxy emitted valid JSON-RPC"))
        .collect();
    (run_res, responses, state)
}

// ---------------------------------------------------------------------------
// 1. tools/list filtering
// ---------------------------------------------------------------------------

#[test]
fn tools_list_filters_to_conjunctive_chain_intersection_and_mapped_tools_only() {
    let root_kp = Ed25519Keypair::generate();
    let mid_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();

    let (_, verified) = build_pr_chain(&root_kp, &mid_kp, &agent_kp, valid_from, valid_until);
    let ledger = SqliteLedger::open_in_memory().unwrap();
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        pr_policy_map(),
        ledger,
        FixedClock::new(now),
    )
    .unwrap();

    let advertised = vec![
        json!({"name": "merge_pr", "description": "Merge a PR"}),
        json!({"name": "close_pr", "description": "Close a PR (root only, not child)"}),
        json!({"name": "delete_repo", "description": "Delete a repo"}),
        json!({"name": "unmapped_tool", "description": "Unmapped"}),
    ];

    let (res, responses, state) = run_proxy_session(
        &mut proxy,
        advertised,
        &[r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#],
    );
    res.expect("proxy session succeeded");
    assert_eq!(state.calls(), 0);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], json!(1));

    let names: Vec<&str> = responses[0]["result"]["tools"]
        .as_array()
        .expect("result.tools is array")
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["merge_pr"]);
}

// ---------------------------------------------------------------------------
// 2. tools/call Permit & forward + lifecycle notifications
// ---------------------------------------------------------------------------

#[test]
fn tools_call_permit_forwards_verbatim_relays_response_and_persists_receipt() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("ledger.sqlite");

    let root_kp = Ed25519Keypair::generate();
    let mid_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();

    let (_, verified) = build_pr_chain(&root_kp, &mid_kp, &agent_kp, valid_from, valid_until);
    let ledger = SqliteLedger::open(&db_path).unwrap();
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        pr_policy_map(),
        ledger,
        FixedClock::new(now),
    )
    .unwrap();

    let (res, responses, state) = run_proxy_session(
        &mut proxy,
        vec![json!({"name": "merge_pr"})],
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
            r#"{ "method" : "tools/call", "params" : { "arguments" : { "pr" : 42, "repo" : "org/app" }, "name" : "merge_pr" }, "id" : "call-1", "jsonrpc" : "2.0" }"#,
        ],
    );
    res.expect("proxy session succeeded");
    assert_eq!(
        state.recorded_notifications(),
        vec!["notifications/initialized"]
    );
    assert_eq!(state.calls(), 1);
    assert_eq!(
        state.recorded_calls()[0]["params"]["arguments"]["pr"],
        json!(42)
    );
    assert_eq!(
        state.recorded_raw_frames().last().map(String::as_str),
        Some(
            r#"{ "method" : "tools/call", "params" : { "arguments" : { "pr" : 42, "repo" : "org/app" }, "name" : "merge_pr" }, "id" : "call-1", "jsonrpc" : "2.0" }"#
        ),
        "allowed tools/call frame must reach upstream byte-for-byte verbatim"
    );

    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["id"], json!(1));
    assert_eq!(responses[1]["id"], json!(2));
    assert_eq!(responses[2]["id"], json!("call-1"));
    assert_eq!(
        responses[2]["result"]["content"][0]["text"],
        json!("executed:merge_pr")
    );

    let ledger = proxy.into_ledger();
    assert_eq!(ledger.verify_integrity().unwrap(), 1);
    let record = ledger.track_record(&agent_kp.key_id()).unwrap();
    assert_eq!(record.permits, 1);
    assert_eq!(record.denies, 0);
}

// ---------------------------------------------------------------------------
// 3. tools/call Deny without forwarding (out-of-scope, unmapped, lossless decimal, call quota)
// ---------------------------------------------------------------------------

#[test]
fn tools_call_deny_without_forwarding_lossless_decimal_and_quotas() {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();

    let mandate_text = format!(
        "HANDFEST v1\n\
         FROM human \"CFO\" (key: {root})\n\
         TO agent \"PayBot\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW finance.transfer\n\
         ON account \"acct-*\"\n\
         LIMIT 2 calls\n  AND 100.00 USD sum(resource.amount)\n",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let (signed, _) = sign_text(&root_kp, &mandate_text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();

    let policy_json = r#"{
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
    }"#;
    let policy_map = ToolPolicyMap::from_json_str(policy_json).unwrap();
    let ledger = SqliteLedger::open_in_memory().unwrap();
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        policy_map,
        ledger,
        FixedClock::new(now),
    )
    .unwrap();

    let frames = [
        // 1. Out-of-scope resource -> Deny
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer","arguments":{"account":"other-99","amount":10.00}}}"#,
        // 2. Unmapped tool -> Deny with receipt_hash
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unmapped_tool","arguments":{"account":"acct-1"}}}"#,
        // 3. Lossless decimal quota exceeded (100.000000000000001 rounds to 100.0 in f64!) -> Deny
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"transfer","arguments":{"account":"acct-1","amount":100.000000000000001}}}"#,
        // 4. Valid call 1 (40.00) -> Permit
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"transfer","arguments":{"account":"acct-1","amount":40.00}}}"#,
        // 5. Valid call 2 (60.00, total 100.00, calls 2/2) -> Permit
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"transfer","arguments":{"account":"acct-1","amount":60.00}}}"#,
        // 6. Call-quota exhaustion (3rd call even with 0.00) -> Deny
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"transfer","arguments":{"account":"acct-1","amount":0.00}}}"#,
    ];

    let (res, responses, state) = run_proxy_session(&mut proxy, vec![], &frames);
    res.expect("proxy session succeeded");
    assert_eq!(
        state.calls(),
        2,
        "only the 2 permitted calls may reach upstream"
    );
    assert_eq!(responses.len(), 6);

    for denied_idx in [0usize, 1, 2, 5] {
        assert_denied_with_receipt(&responses[denied_idx]);
    }
    assert_eq!(
        responses[1]["error"]["data"]["reason"],
        json!("unmapped MCP tool 'unmapped_tool'")
    );

    assert_eq!(
        responses[3]["result"]["content"][0]["text"],
        json!("executed:transfer")
    );
    assert_eq!(
        responses[4]["result"]["content"][0]["text"],
        json!("executed:transfer")
    );

    let ledger = proxy.into_ledger();
    assert_eq!(ledger.verify_integrity().unwrap(), 6);
    let record = ledger.track_record(&agent_kp.key_id()).unwrap();
    assert_eq!(record.permits, 2);
    assert_eq!(record.denies, 4);
}

// ---------------------------------------------------------------------------
// 4. Fact-spoofing defense: static broker facts & Clock always win
// ---------------------------------------------------------------------------

fn build_spoof_policy(broker_author: &str) -> ToolPolicyMap {
    let mut arg_facts = BTreeMap::new();
    arg_facts.insert(
        "author".to_string(),
        FactSpec {
            field: "resource.author".to_string(),
            fact_type: FactType::Str,
        },
    );
    arg_facts.insert(
        "time".to_string(),
        FactSpec {
            field: "context.time".to_string(),
            fact_type: FactType::Timestamp,
        },
    );

    let mut static_facts = BTreeMap::new();
    static_facts.insert(
        "resource.author".to_string(),
        TypedScalar::Str(broker_author.to_string()),
    );

    let mut tools = BTreeMap::new();
    tools.insert(
        "merge_pr".to_string(),
        ToolPolicy {
            action: "git.pr.merge".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_arg: Some("repo".to_string()),
            static_resource_id: None,
            arg_facts,
            static_facts,
        },
    );
    ToolPolicyMap { tools }
}

#[test]
fn fact_spoofing_defense_static_facts_and_clock_always_win() {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();

    let mandate_text = format!(
        "HANDFEST v1\n\
         FROM human \"Maintainer\" (key: {root})\n\
         TO agent \"MergeBot\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/app\"\n\
         WHERE context.time < 2026-06-01T00:00:00Z\n  AND resource.author == \"trusted-alice\"\n",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let (signed, _) = sign_text(&root_kp, &mandate_text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();

    let spoof_frame = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app","author":"trusted-alice","resource.author":"trusted-alice","time":"2026-02-01T00:00:00Z","context.time":"2026-02-01T00:00:00Z"}}}"#;

    // Case A: Model spoofs author="trusted-alice", but broker static fact says "mallory" -> Deny.
    let valid_time = parse_rfc3339_utc("2026-05-01T00:00:00Z").unwrap();
    let mut proxy_a = McpProxy::new(
        verified.clone(),
        agent_kp.key_id(),
        build_spoof_policy("mallory"),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(valid_time),
    )
    .unwrap();
    let (res_a, resp_a, state_a) = run_proxy_session(&mut proxy_a, vec![], &[spoof_frame]);
    res_a.unwrap();
    assert_eq!(state_a.calls(), 0);
    assert_eq!(
        resp_a[0]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );

    // Case B: Broker author is trusted, but Clock is past deadline while model spoofs earlier time -> Deny.
    let expired_time = parse_rfc3339_utc("2026-07-01T00:00:00Z").unwrap();
    let mut proxy_b = McpProxy::new(
        verified.clone(),
        agent_kp.key_id(),
        build_spoof_policy("trusted-alice"),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(expired_time),
    )
    .unwrap();
    let (res_b, resp_b, state_b) = run_proxy_session(&mut proxy_b, vec![], &[spoof_frame]);
    res_b.unwrap();
    assert_eq!(state_b.calls(), 0);
    assert_eq!(
        resp_b[0]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );

    // Case C: Broker author is trusted and Clock is valid; model passes author="mallory" -> static fact wins -> Permit.
    let benign_frame = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app","author":"mallory","time":"2099-01-01T00:00:00Z"}}}"#;
    let mut proxy_c = McpProxy::new(
        verified,
        agent_kp.key_id(),
        build_spoof_policy("trusted-alice"),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(valid_time),
    )
    .unwrap();
    let (res_c, resp_c, state_c) = run_proxy_session(&mut proxy_c, vec![], &[benign_frame]);
    res_c.unwrap();
    assert_eq!(state_c.calls(), 1);
    assert_eq!(
        resp_c[0]["result"]["content"][0]["text"],
        json!("executed:merge_pr")
    );
}

// ---------------------------------------------------------------------------
// 5. Notification tools/call dropped, unknown methods denied, malformed args & oversized frames
// ---------------------------------------------------------------------------

#[test]
fn notification_tools_call_dropped_unknown_methods_denied_and_oversized_frame_fails_closed() {
    let root_kp = Ed25519Keypair::generate();
    let mid_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();

    let (_, verified) = build_pr_chain(&root_kp, &mid_kp, &agent_kp, valid_from, valid_until);
    let mut proxy = McpProxy::new(
        verified.clone(),
        agent_kp.key_id(),
        pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (res, responses, state) = run_proxy_session(
        &mut proxy,
        vec![],
        &[
            // Notification tools/call (missing id): MUST be dropped, never forwarded!
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app"}}}"#,
            // Unknown mutating method: MUST fail closed without forwarding.
            r#"{"jsonrpc":"2.0","id":10,"method":"resources/write","params":{}}"#,
            // Non-object arguments: MUST fail closed without forwarding.
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"merge_pr","arguments":["org/app"]}}"#,
            // Missing resource_id argument: MUST fail closed without forwarding.
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"merge_pr","arguments":{}}}"#,
            // Duplicate JSON keys smuggling attempt: MUST be rejected with parse error.
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app","repo":"other/evil"}}}"#,
        ],
    );
    res.expect("session handled invalid requests cleanly");
    assert_eq!(state.calls(), 0);
    assert!(state.recorded_notifications().is_empty());
    assert_eq!(responses.len(), 4);
    assert_eq!(
        responses[0]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );
    assert_eq!(
        responses[1]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );
    assert_eq!(
        responses[2]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );
    assert_eq!(responses[3]["error"]["code"], json!(-32700));
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 2);

    // Oversized frame fails closed without OOMing or forwarding.
    let mut bounded_proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap()
    .with_max_line_bytes(64)
    .unwrap();
    let oversized = format!(
        r#"{{"jsonrpc":"2.0","id":99,"method":"ping","params":{{"pad":"{}"}}}}"#,
        "x".repeat(128)
    );
    let (err_res, err_responses, err_state) =
        run_proxy_session(&mut bounded_proxy, vec![], &[&oversized]);
    assert!(matches!(
        err_res,
        Err(ProxyError::FrameTooLarge { max_bytes: 64 })
    ));
    assert_eq!(err_state.calls(), 0);
    assert_eq!(err_responses.len(), 1);
    assert_eq!(err_responses[0]["error"]["code"], json!(-32600));
}

// ---------------------------------------------------------------------------
// 6. Subprocess smoke test of compiled `handfest-mcp` binary & startup fail-fast
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn write_pr_chain_fixtures(
    dir: &std::path::Path,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    Ed25519Keypair,
    Ed25519Keypair,
    Vec<SignedMandate>,
) {
    let root_path = dir.join("root.signed.json");
    let child_path = dir.join("child.signed.json");
    let policy_path = dir.join("policy.json");
    let ledger_path = dir.join("ledger.sqlite");

    let root_kp = Ed25519Keypair::generate();
    let mid_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();

    let (signed_chain, _) = build_pr_chain(&root_kp, &mid_kp, &agent_kp, valid_from, valid_until);
    fs::write(
        &root_path,
        serde_json::to_string_pretty(&signed_chain[0]).unwrap(),
    )
    .unwrap();
    fs::write(
        &child_path,
        serde_json::to_string_pretty(&signed_chain[1]).unwrap(),
    )
    .unwrap();
    fs::write(
        &policy_path,
        serde_json::to_string_pretty(&pr_policy_map()).unwrap(),
    )
    .unwrap();

    (
        root_path,
        child_path,
        policy_path,
        ledger_path,
        mid_kp,
        agent_kp,
        signed_chain,
    )
}

#[cfg(unix)]
#[test]
fn subprocess_binary_smoke_test() {
    let dir = tempdir().unwrap();
    let (root_path, child_path, policy_path, ledger_path, _mid_kp, agent_kp, _chain) =
        write_pr_chain_fixtures(dir.path());
    let calls_log = dir.path().join("upstream_calls.log");

    let upstream_script = format!(
        "echo 'upstream diagnostic on stderr' >&2\n\
         while IFS= read -r line; do\n\
           case \"$line\" in\n\
             *'\"method\":\"initialize\"'*) printf '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"capabilities\":{{}}}}}}\\n' ;;\n\
             *'\"method\":\"notifications/initialized\"'*) : ;;\n\
             *'\"method\":\"tools/list\"'*) printf '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"tools\":[{{\"name\":\"merge_pr\"}},{{\"name\":\"delete_repo\"}},{{\"name\":\"unmapped_tool\"}}]}}}}\\n' ;;\n\
             *'\"method\":\"tools/call\"'*) echo \"$line\" >> '{}'; printf '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"ok\":true}}}}\\n' ;;\n\
           esac\n\
         done",
        calls_log.display()
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .args([
            "--chain",
            root_path.to_str().unwrap(),
            child_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--actor-key",
            &agent_kp.key_id().to_string(),
            "--policy-map",
            policy_path.to_str().unwrap(),
            "--now",
            "2026-06-01T00:00:00Z",
            "--",
            "sh",
            "-c",
            &upstream_script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn handfest-mcp binary");

    write_smoke_session_frames(child.stdin.take().unwrap());

    let output = child.wait_with_output().expect("wait handfest-mcp");
    assert!(
        output.status.success(),
        "handfest-mcp failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("upstream diagnostic on stderr"));

    let stdout_lines: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).expect("stdout line is pure JSON-RPC"))
        .collect();
    assert_eq!(stdout_lines.len(), 4);
    assert_eq!(
        stdout_lines[1]["result"]["tools"],
        json!([{"name": "merge_pr"}])
    );
    assert_eq!(stdout_lines[2]["result"]["ok"], json!(true));
    assert_eq!(
        stdout_lines[3]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );
    assert!(stdout_lines[3]["error"]["data"]["receipt_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let logged = fs::read_to_string(&calls_log).unwrap();
    assert_eq!(logged.lines().count(), 1);
    assert!(logged.contains("merge_pr"));

    let ledger = SqliteLedger::open_read_only(&ledger_path).unwrap();
    let (count, record) = ledger.audit_snapshot(Some(&agent_kp.key_id())).unwrap();
    assert_eq!(count, 2);
    let record = record.unwrap();
    assert_eq!(record.permits, 1);
    assert_eq!(record.denies, 1);
}

#[cfg(unix)]
#[test]
fn subprocess_startup_fail_fast_rejects_widened_chain_before_spawning_upstream() {
    let dir = tempdir().unwrap();
    let (root_path, _child_path, policy_path, ledger_path, mid_kp, agent_kp, signed_chain) =
        write_pr_chain_fixtures(dir.path());
    let widened_path = dir.path().join("widened.signed.json");
    let sentinel_path = dir.path().join("must_not_exist");

    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let root_ast = parse_mandate(&signed_chain[0].canonical_words).unwrap();
    let root_id = root_ast.try_mandate_id().unwrap();
    let widened_text = format!(
        "HANDFEST v1\n\
         PARENT {root_id}\n\
         FROM agent \"Orchestrator\" (key: {mid})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.repo.delete\n\
         ON repo \"org/app\"\n\
         LIMIT 2 calls\n",
        mid = mid_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let (widened_signed, _) = sign_text(&mid_kp, &widened_text, valid_from, valid_until);
    fs::write(
        &widened_path,
        serde_json::to_string_pretty(&widened_signed).unwrap(),
    )
    .unwrap();

    let fail_output = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .args([
            "--chain",
            root_path.to_str().unwrap(),
            widened_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--actor-key",
            &agent_kp.key_id().to_string(),
            "--policy-map",
            policy_path.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &format!("touch '{}'", sentinel_path.display()),
        ])
        .output()
        .expect("run handfest-mcp fail-fast");

    assert!(!fail_output.status.success());
    assert!(
        !sentinel_path.exists(),
        "upstream must NEVER be spawned when startup chain verification fails"
    );
    assert!(String::from_utf8_lossy(&fail_output.stderr).contains("attenuation"));
}

// ---------------------------------------------------------------------------
// 7. Round 2 remediation tests (Findings 1–5)
// ---------------------------------------------------------------------------

fn build_pr_proxy(
    now_rfc3339: &str,
) -> (McpProxy<FixedClock>, Vec<VerifiedMandate>, Ed25519Keypair) {
    let root_kp = Ed25519Keypair::generate();
    let mid_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc(now_rfc3339).unwrap();

    let (_, verified) = build_pr_chain(&root_kp, &mid_kp, &agent_kp, valid_from, valid_until);
    let proxy = McpProxy::new(
        verified.clone(),
        agent_kp.key_id(),
        pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    (proxy, verified, agent_kp)
}

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn run_raw_proxy_io(
    proxy: &mut McpProxy<FixedClock>,
    client_bytes: &[u8],
    upstream_bytes: &[u8],
) -> (Result<(), ProxyError>, Vec<u8>, Vec<u8>) {
    let scripted: Vec<Vec<u8>> = if upstream_bytes.is_empty() {
        Vec::new()
    } else {
        vec![upstream_bytes.to_vec()]
    };
    run_scripted_proxy_io(proxy, client_bytes, scripted)
}

fn run_scripted_proxy_io(
    proxy: &mut McpProxy<FixedClock>,
    client_bytes: &[u8],
    scripted_replies: Vec<Vec<u8>>,
) -> (Result<(), ProxyError>, Vec<u8>, Vec<u8>) {
    let client_in = BufReader::new(Cursor::new(client_bytes.to_vec()));
    let mut client_out = Vec::new();

    if scripted_replies.is_empty() {
        let up_buf = Arc::new(Mutex::new(Vec::new()));
        let up_in = SharedWriter(Arc::clone(&up_buf));
        let up_out = BufReader::new(Cursor::new(Vec::new()));
        let res = proxy.run(client_in, &mut client_out, up_in, up_out);
        let captured = up_buf.lock().unwrap().clone();
        return (res, client_out, captured);
    }

    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_bg = Arc::clone(&captured);

    let bg = thread::spawn(move || {
        let mut replies = scripted_replies.into_iter();
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = up_in_r.read_until(b'\n', &mut line).unwrap_or(0);
            if n == 0 {
                break;
            }
            captured_bg.lock().unwrap().extend_from_slice(&line);
            let is_request = serde_json::from_slice::<Value>(&line)
                .ok()
                .is_some_and(|v| v.get("method").is_some() && v.get("id").is_some());
            if is_request {
                if let Some(reply_bytes) = replies.next() {
                    let _ = up_out_w.write_all(&reply_bytes);
                    let _ = up_out_w.flush();
                }
            }
        }
    });

    let res = proxy.run(client_in, &mut client_out, up_in_w, up_out_r);
    let _ = bg.join();
    let up_bytes = captured.lock().unwrap().clone();
    (res, client_out, up_bytes)
}

#[test]
fn bare_cr_smuggling_rejected_on_client_and_upstream_and_crlf_normalized() {
    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");

    let smuggling_input = concat!(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":\r",
        "{\"method\":\"tools/call\",\"params\":{\"name\":\"delete_repo\",\"arguments\":{\"repo\":\"org/app\"}}}\r}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\r",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_repo\",\"arguments\":{\"repo\":\"org/app\"}}}\r\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\r\r\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\r"
    );

    let (res, client_out, upstream_in) =
        run_raw_proxy_io(&mut proxy, smuggling_input.as_bytes(), b"");
    res.expect("client bare CR frames are rejected cleanly without fatal error");
    assert!(
        upstream_in.is_empty(),
        "upstream MUST receive 0 bytes from bare CR smuggling payloads, got: {:?}",
        String::from_utf8_lossy(&upstream_in)
    );

    let errors: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect();
    assert_eq!(errors.len(), 4);
    for err in &errors {
        assert_eq!(err["id"], Value::Null);
        assert_eq!(err["error"]["code"], json!(-32700));
    }

    let valid_crlf = concat!(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\r\n",
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\r\n"
    );
    let upstream_reply = b"{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\r\n";
    let (crlf_res, crlf_out, crlf_up) =
        run_raw_proxy_io(&mut proxy, valid_crlf.as_bytes(), upstream_reply);
    crlf_res.expect("valid CRLF frames succeed");
    assert!(
        !crlf_up.contains(&b'\r'),
        "forwarded bytes must contain zero CR"
    );
    assert!(
        !crlf_out.contains(&b'\r'),
        "relayed bytes must contain zero CR"
    );
    assert_eq!(crlf_up.iter().filter(|&&b| b == b'\n').count(), 2);

    let (up_err, up_client_out, _) = run_raw_proxy_io(
        &mut proxy,
        b"{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"ping\"}\n",
        b"{\"jsonrpc\":\"2.0\",\"id\":10,\"result\":{}\r}\n",
    );
    assert!(matches!(up_err, Err(ProxyError::UpstreamProtocol(_))));
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&up_client_out).unwrap()).unwrap();
    assert_eq!(parsed["id"], json!(10));
    assert_eq!(parsed["error"]["code"], json!(-32700));
}

#[test]
fn tools_list_rejects_error_null_and_dual_result_error_and_relays_valid_error() {
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
    let malicious_responses = [
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"delete_repo\"},{\"name\":\"merge_pr\"}]},\"error\":null}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"delete_repo\"}]},\"error\":{\"code\":-1,\"message\":\"x\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":null}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1.5,\"message\":\"bad\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":123}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":null}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1}\n",
    ];

    for raw_resp in malicious_responses {
        let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
        let (res, client_out, _) = run_raw_proxy_io(&mut proxy, req, raw_resp.as_bytes());
        assert!(
            matches!(res, Err(ProxyError::UpstreamProtocol(_))),
            "expected UpstreamProtocol for {raw_resp}, got {res:?}"
        );
        let out_str = String::from_utf8(client_out).unwrap();
        assert!(
            !out_str.contains("delete_repo") && !out_str.contains("merge_pr"),
            "malformed tools/list response leaked tools: {out_str}"
        );
        let parsed: Value = serde_json::from_str(out_str.trim()).unwrap();
        assert_eq!(parsed["id"], json!(1));
        assert_eq!(parsed["error"]["code"], json!(-32603));
    }

    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
    let valid_err =
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"tools disabled\"}}\n";
    let (ok_res, ok_out, _) = run_raw_proxy_io(&mut proxy, req, valid_err);
    ok_res.expect("valid error-only tools/list response relays cleanly");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&ok_out).unwrap().trim()).unwrap();
    assert_eq!(parsed["id"], json!(1));
    assert_eq!(parsed["error"]["code"], json!(-32601));
    assert_eq!(parsed["error"]["message"], json!("tools disabled"));
}

#[test]
fn upstream_server_requests_and_numeric_id_equivalence_correlate_strictly() {
    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");

    let client_req = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",",
        "\"params\":{\"name\":\"merge_pr\",\"arguments\":{\"repo\":\"org/app\"}}}\n"
    );
    let upstream_stream = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"roots/list\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"step\":1}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"executed:merge_pr\"}]}}\n"
    );

    let (res, client_out, upstream_in) = run_raw_proxy_io(
        &mut proxy,
        client_req.as_bytes(),
        upstream_stream.as_bytes(),
    );
    res.expect("interleaved upstream server requests must not confuse response correlation");

    let client_frames: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(client_frames.len(), 2);
    assert_eq!(client_frames[0]["method"], json!("notifications/progress"));
    assert_eq!(client_frames[1]["id"], json!(1));
    assert_eq!(
        client_frames[1]["result"]["content"][0]["text"],
        json!("executed:merge_pr")
    );

    let upstream_frames: Vec<Value> = String::from_utf8(upstream_in)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(upstream_frames.len(), 3);
    assert_eq!(upstream_frames[0]["method"], json!("tools/call"));
    assert_eq!(upstream_frames[1]["id"], json!(1));
    assert_eq!(upstream_frames[1]["error"]["code"], json!(-32601));
    assert_eq!(upstream_frames[2]["id"], json!(1));
    assert_eq!(upstream_frames[2]["error"]["code"], json!(-32601));

    let equiv_req = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":9007199254740991,\"method\":\"ping\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":-9007199254740991,\"method\":\"ping\"}\n"
    );
    let (eq_res, eq_out, _) = run_scripted_proxy_io(
        &mut proxy,
        equiv_req.as_bytes(),
        vec![
            b"{\"jsonrpc\":\"2.0\",\"id\":1.0,\"result\":{}}\n".to_vec(),
            b"{\"jsonrpc\":\"2.0\",\"id\":9007199254740991.0,\"result\":{}}\n".to_vec(),
            b"{\"jsonrpc\":\"2.0\",\"id\":-9.007199254740991e15,\"result\":{}}\n".to_vec(),
        ],
    );
    eq_res.expect("numerically equivalent safe-integer upstream response ids must match");
    assert_eq!(String::from_utf8(eq_out).unwrap().lines().count(), 3);

    for bad_upstream_id in [
        "-0",
        "-0.0",
        "1.5",
        "1.0000000000000001",
        "9007199254740992",
        "1e16",
    ] {
        let up_resp = format!("{{\"jsonrpc\":\"2.0\",\"id\":{bad_upstream_id},\"result\":{{}}}}\n");
        let (bad_res, _, _) = run_raw_proxy_io(
            &mut proxy,
            b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"ping\"}\n",
            up_resp.as_bytes(),
        );
        assert!(
            matches!(bad_res, Err(ProxyError::UpstreamProtocol(_))),
            "invalid upstream response id {bad_upstream_id} must fail protocol check: {bad_res:?}"
        );
    }

    let (mismatch_res, mismatch_out, _) = run_raw_proxy_io(
        &mut proxy,
        b"{\"jsonrpc\":\"2.0\",\"id\":9007199254740991,\"method\":\"ping\"}\n",
        b"{\"jsonrpc\":\"2.0\",\"id\":9007199254740990,\"result\":{}}\n",
    );
    assert!(matches!(mismatch_res, Err(ProxyError::UpstreamProtocol(_))));
    let mismatch_str = String::from_utf8(mismatch_out).unwrap();
    assert!(mismatch_str.contains("\"id\":9007199254740991"));
    assert!(mismatch_str.contains("-32603"));
}

#[test]
fn tools_list_lossless_serialization_and_deep_nesting() {
    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");

    let mut nested_schema =
        String::from("{\"const\":100.000000000000001,\"bigId\":18446744073709551617}");
    for _ in 0..48 {
        nested_schema = format!("{{\"nested\":{nested_schema}}}");
    }

    let req =
        "{\"jsonrpc\":\"2.0\",\"id\":9007199254740991,\"method\":\"tools/list\",\"params\":{}}\n";
    let upstream_resp = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":9007199254740991,\"result\":{{\"tools\":[{{\"name\":\"merge_pr\",\"inputSchema\":{nested_schema}}},{{\"name\":\"delete_repo\",\"inputSchema\":{{}}}}]}}}}\n"
    );

    let (res, client_out, _) =
        run_raw_proxy_io(&mut proxy, req.as_bytes(), upstream_resp.as_bytes());
    res.expect("deeply nested lossless tools/list must succeed");

    let raw_out = String::from_utf8(client_out).unwrap();
    assert!(
        raw_out.contains("100.000000000000001"),
        "decimal constant must not round through f64: {raw_out}"
    );
    assert!(
        raw_out.contains("\"bigId\":18446744073709551617"),
        "large integer payload must not round through f64: {raw_out}"
    );
    assert!(
        raw_out.contains("\"id\":9007199254740991"),
        "max safe integer id must be preserved verbatim: {raw_out}"
    );
    assert!(
        raw_out.contains("\"bigId\":18446744073709551617"),
        "large integer schema constant must not round through f64: {raw_out}"
    );
    assert!(
        raw_out.contains("\"merge_pr\"") && !raw_out.contains("delete_repo"),
        "unauthorized tool must be filtered out: {raw_out}"
    );
}

#[test]
fn mapping_failure_receipt_records_mapped_action_and_invalid_empty_object_returns_32600() {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();

    let wildcard_mandate = format!(
        "HANDFEST v1\n\
         FROM human \"Admin\" (key: {root})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.*\n\
         ON repo \"*\"\n",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let (signed, _) = sign_text(&root_kp, &wildcard_mandate, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();
    let chain_ids = vec![verified[0].ast.try_mandate_id().unwrap()];

    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let frames = concat!(
        "{}\n",
        "{\"jsonrpc\":\"2.0\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{}}}\n"
    );
    let (res, client_out, upstream_in) = run_raw_proxy_io(&mut proxy, frames.as_bytes(), b"");
    res.expect("invalid request objects and mapping denials handled cleanly");
    assert!(upstream_in.is_empty(), "no frame may reach upstream");

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 3);

    for idx in [0usize, 1] {
        assert_eq!(responses[idx]["id"], Value::Null);
        assert_eq!(responses[idx]["error"]["code"], json!(-32600));
    }

    let deny = &responses[2];
    assert_eq!(deny["id"], json!(1));
    assert_eq!(deny["error"]["code"], json!(HANDFEST_DENIED_ERROR_CODE));
    let reason = deny["error"]["data"]["reason"].as_str().unwrap();
    assert_eq!(
        reason,
        "tool 'merge_pr': missing required resource_id argument 'repo'"
    );

    let expected_receipt = DecisionReceipt {
        chain_ids,
        actor_key: agent_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource: "repo \"\"".to_string(),
        timestamp: now,
        verdict: Verdict::Deny {
            reason: reason.to_string(),
        },
        receipt_hash: MandateId([0u8; 32]),
        prev_receipt_hash: None,
    };
    assert_eq!(
        deny["error"]["data"]["receipt_hash"].as_str().unwrap(),
        expected_receipt.compute_hash().to_string(),
        "recorded SQLite receipt must commit to mapped action 'git.pr.merge', resource, and exact reason"
    );
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 1);
    let tr = proxy.ledger().track_record(&agent_kp.key_id()).unwrap();
    assert_eq!(tr.total_decisions, 1);
    assert_eq!(tr.permits, 0);
    assert_eq!(tr.denies, 1);
}

#[cfg(unix)]
#[test]
fn subprocess_kills_blocked_upstream_without_hanging_on_client_eof_and_error() {
    let dir = tempdir().unwrap();
    let (root_path, child_path, policy_path, ledger_path, _mid_kp, agent_kp, _chain) =
        write_pr_chain_fixtures(dir.path());

    for send_oversized_error in [false, true] {
        let started = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
            .args([
                "--chain",
                root_path.to_str().unwrap(),
                child_path.to_str().unwrap(),
                "--ledger",
                ledger_path.to_str().unwrap(),
                "--actor-key",
                &agent_kp.key_id().to_string(),
                "--policy-map",
                policy_path.to_str().unwrap(),
                "--now",
                "2026-06-01T00:00:00Z",
                "--",
                "sh",
                "-c",
                "exec sleep 30",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn handfest-mcp with blocked upstream");

        {
            let mut stdin = child.stdin.take().unwrap();
            if send_oversized_error {
                let huge = "a".repeat(1024 * 1024 + 32);
                let _ = writeln!(stdin, "{huge}");
            }
        }
        let output = child.wait_with_output().expect("wait handfest-mcp");
        let elapsed = started.elapsed();

        if send_oversized_error {
            assert!(!output.status.success());
        } else {
            assert!(
                output.status.success(),
                "handfest-mcp should exit cleanly on EOF: stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            elapsed < Duration::from_secs(5),
            "handfest-mcp hung waiting on blocked upstream (error={send_oversized_error}): {elapsed:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Round 2 review-reforge regression tests
// ---------------------------------------------------------------------------

struct BoundedPipeWriter {
    tx: mpsc::SyncSender<Vec<u8>>,
    chunk_limit: usize,
}

impl Write for BoundedPipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.chunk_limit);
        self.tx
            .send(buf[..n].to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "bounded pipe closed"))?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_mem_pipe(
    slots: usize,
    chunk_limit: usize,
) -> (BoundedPipeWriter, BufReader<PipeReader>) {
    let (tx, rx) = mpsc::sync_channel(slots);
    (
        BoundedPipeWriter { tx, chunk_limit },
        BufReader::new(PipeReader {
            rx,
            buf: Vec::new(),
            pos: 0,
        }),
    )
}

#[test]
fn idle_upstream_notifications_and_bidirectional_backpressure_never_deadlock() {
    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread =
        thread::spawn(move || proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r));

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}}"#
    )
    .unwrap();
    up_out_w.flush().unwrap();

    let mut first_line = String::new();
    client_out_r.read_line(&mut first_line).unwrap();
    let notif: Value = serde_json::from_str(first_line.trim_end()).unwrap();
    assert_eq!(notif["method"], json!("notifications/tools/list_changed"));

    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let mut up_line = String::new();
    up_in_r.read_line(&mut up_line).unwrap();
    assert!(up_line.contains("\"method\":\"ping\""));
    writeln!(up_out_w, r#"{{"jsonrpc":"2.0","id":1,"result":{{}}}}"#).unwrap();
    let mut reply = String::new();
    client_out_r.read_line(&mut reply).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(reply.trim_end()).unwrap()["id"],
        json!(1)
    );
    drop(client_in_w);
    proxy_thread
        .join()
        .unwrap()
        .expect("idle notification session exited cleanly");

    let (mut bp_proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
    let (up_in_w, mut up_in_r) = bounded_mem_pipe(2, 2048);
    let (mut up_out_w, up_out_r) = bounded_mem_pipe(2, 2048);
    let big_blob = "x".repeat(128 * 1024);
    let big_req = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\",\"params\":{{\"pad\":\"{big_blob}\"}}}}\n"
    );

    let upstream_bg = thread::spawn(move || {
        let notif_pad = "n".repeat(4096);
        for seq in 0..32 {
            writeln!(
                up_out_w,
                "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"seq\":{seq},\"pad\":\"{notif_pad}\"}}}}"
            )
            .unwrap();
        }
        up_out_w.flush().unwrap();

        let mut req_line = String::new();
        up_in_r.read_line(&mut req_line).unwrap();
        assert!(req_line.contains("\"id\":7"));
        writeln!(
            up_out_w,
            r#"{{"jsonrpc":"2.0","id":7,"result":{{"ok":true}}}}"#
        )
        .unwrap();
        up_out_w.flush().unwrap();
    });

    let mut client_out = Vec::new();
    let res = bp_proxy.run(
        BufReader::new(Cursor::new(big_req.into_bytes())),
        &mut client_out,
        up_in_w,
        up_out_r,
    );
    upstream_bg.join().unwrap();
    res.expect("simultaneous bidirectional writes must complete without pipe deadlock");

    let out_lines: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(out_lines.len(), 33);
    assert_eq!(out_lines[32]["id"], json!(7));
    assert_eq!(out_lines[32]["result"]["ok"], json!(true));
}

#[test]
fn pending_request_observes_cancellation_and_client_eof_on_silent_upstream() {
    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread =
        thread::spawn(move || proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r));

    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let mut got_req1 = String::new();
    up_in_r.read_line(&mut got_req1).unwrap();
    assert!(got_req1.contains("\"id\":1"));

    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":1}}}}"#
    )
    .unwrap();
    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":2,"method":"ping"}}"#).unwrap();

    let mut got_cancel = String::new();
    up_in_r.read_line(&mut got_cancel).unwrap();
    assert!(got_cancel.contains("notifications/cancelled"));

    let mut got_req2 = String::new();
    up_in_r.read_line(&mut got_req2).unwrap();
    assert!(got_req2.contains("\"id\":2"));

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":2,"result":{{"pong":2}}}}"#
    )
    .unwrap();
    let mut resp2 = String::new();
    client_out_r.read_line(&mut resp2).unwrap();
    let parsed2: Value = serde_json::from_str(resp2.trim_end()).unwrap();
    assert_eq!(parsed2["id"], json!(2));
    assert_eq!(parsed2["result"]["pong"], json!(2));

    drop(client_in_w);
    proxy_thread
        .join()
        .unwrap()
        .expect("cancelled pending request must not hang shutdown");

    #[cfg(unix)]
    {
        let dir = tempdir().unwrap();
        let (root_path, child_path, policy_path, ledger_path, _mid_kp, agent_kp, _chain) =
            write_pr_chain_fixtures(dir.path());
        let started = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
            .args([
                "--chain",
                root_path.to_str().unwrap(),
                child_path.to_str().unwrap(),
                "--ledger",
                ledger_path.to_str().unwrap(),
                "--actor-key",
                &agent_kp.key_id().to_string(),
                "--policy-map",
                policy_path.to_str().unwrap(),
                "--now",
                "2026-06-01T00:00:00Z",
                "--",
                "sh",
                "-c",
                "IFS= read -r _; exec sleep 30",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn handfest-mcp with silent pending child");

        {
            let mut stdin = child.stdin.take().unwrap();
            writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        }
        let output = child.wait_with_output().expect("wait handfest-mcp");
        let elapsed = started.elapsed();
        assert!(
            output.status.success(),
            "expected clean EOF shutdown during silent pending request: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "pending request hung shutdown on silent child: {elapsed:?}"
        );
    }
}

#[test]
fn client_envelope_rejects_response_fields_and_primitive_params_without_forwarding() {
    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
    let bad_frames = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"result\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\",\"error\":{\"code\":-1,\"message\":\"x\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"result\":null}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\",\"params\":123}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":\"bad\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\",\"params\":null}\n"
    );

    let (res, client_out, upstream_in) = run_raw_proxy_io(&mut proxy, bad_frames.as_bytes(), b"");
    res.expect("invalid client envelopes rejected without fatal error");
    assert!(
        upstream_in.is_empty(),
        "invalid client envelopes must never reach upstream: {:?}",
        String::from_utf8_lossy(&upstream_in)
    );

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 6);
    assert_eq!(responses[0]["id"], json!(1));
    assert_eq!(responses[1]["id"], json!(2));
    assert_eq!(responses[2]["id"], Value::Null);
    assert_eq!(responses[3]["id"], json!(3));
    assert_eq!(responses[4]["id"], Value::Null);
    assert_eq!(responses[5]["id"], json!(4));
    for resp in &responses {
        assert_eq!(resp["error"]["code"], json!(-32600));
    }
}

#[test]
fn unicode_whitespace_and_blank_frames_rejected_on_client_and_upstream() {
    let (mut proxy, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
    let bad_client = concat!(
        "\u{00A0}{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\u{00A0}\n",
        "\u{FEFF}{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n",
        "\u{00A0}\n",
        "   \n"
    );
    let (res, client_out, upstream_in) = run_raw_proxy_io(&mut proxy, bad_client.as_bytes(), b"");
    res.expect("unicode whitespace client frames rejected cleanly");
    assert!(
        upstream_in.is_empty(),
        "invalid whitespace frames must not forward"
    );

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        responses.len(),
        5,
        "no invalid whitespace frame may be silently skipped"
    );
    for resp in &responses {
        assert_eq!(resp["id"], Value::Null);
        assert_eq!(resp["error"]["code"], json!(-32700));
    }

    let bad_upstreams = [
        "\u{00A0}{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
        "\u{00A0}\n",
        "   \n",
    ];
    for raw_up in bad_upstreams {
        let (mut p, _, _) = build_pr_proxy("2026-06-01T00:00:00Z");
        let (up_res, up_out, _) = run_raw_proxy_io(
            &mut p,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
            raw_up.as_bytes(),
        );
        assert!(
            matches!(up_res, Err(ProxyError::UpstreamProtocol(_))),
            "expected UpstreamProtocol for upstream {raw_up:?}, got {up_res:?}"
        );
        let parsed: Value =
            serde_json::from_str(std::str::from_utf8(&up_out).unwrap().trim()).unwrap();
        assert_eq!(parsed["id"], json!(1));
        assert_eq!(parsed["error"]["code"], json!(-32603));
    }
}

#[test]
fn tools_list_hides_tools_for_expired_not_yet_valid_and_unbound_proof_chains() {
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
    let upstream =
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"merge_pr\"}]}}\n";

    let (mut expired_proxy, _, _) = build_pr_proxy("2027-01-01T00:00:00Z");
    let (res, out, _) = run_raw_proxy_io(&mut expired_proxy, req, upstream);
    res.expect("expired tools/list succeeds with empty list");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
    assert_eq!(parsed["result"]["tools"], json!([]));

    let (mut early_proxy, _, _) = build_pr_proxy("2025-12-31T23:59:59Z");
    let (res, out, _) = run_raw_proxy_io(&mut early_proxy, req, upstream);
    res.expect("early tools/list succeeds with empty list");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
    assert_eq!(parsed["result"]["tools"], json!([]));

    let (_, mut bad_signer_chain, agent_kp) = build_pr_proxy("2026-06-01T00:00:00Z");
    let rogue_kp = Ed25519Keypair::generate();
    bad_signer_chain[0].proof.signer_key = rogue_kp.key_id();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let mut bad_signer_proxy = McpProxy::new(
        bad_signer_chain,
        agent_kp.key_id(),
        pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let (res, out, _) = run_raw_proxy_io(&mut bad_signer_proxy, req, upstream);
    res.expect("mismatched signer tools/list succeeds with empty list");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
    assert_eq!(parsed["result"]["tools"], json!([]));

    let (_, mut bad_kind_chain, agent_kp2) = build_pr_proxy("2026-06-01T00:00:00Z");
    bad_kind_chain[0].proof.actor_kind = ActorKind::Service;
    let mut bad_kind_proxy = McpProxy::new(
        bad_kind_chain,
        agent_kp2.key_id(),
        pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let (res, out, _) = run_raw_proxy_io(&mut bad_kind_proxy, req, upstream);
    res.expect("mismatched actor_kind tools/list succeeds with empty list");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
    assert_eq!(parsed["result"]["tools"], json!([]));
}

#[derive(Default)]
struct InMemoryLedger {
    receipts: Vec<DecisionReceipt>,
}

impl ReceiptLedger for InMemoryLedger {
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
                return Err(LedgerError::Integrity("broken in-memory chain".to_string()));
            }
            expected_prev = Some(receipt.receipt_hash);
        }
        let rec = actor_key.map(|key| {
            let mut permits = 0u64;
            let mut denies = 0u64;
            let mut leaves = std::collections::BTreeSet::new();
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

struct StubVerifier {
    verified_hops: Vec<VerifiedMandate>,
}

impl AnchorVerifier for StubVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        self.verified_hops
            .iter()
            .find(|vm| {
                try_render_canonical(&vm.ast)
                    .map(|c| c == signed.canonical_words)
                    .unwrap_or(false)
            })
            .cloned()
            .ok_or_else(|| AnchorError::InvalidSignature("stub verifier rejected".to_string()))
    }
}

#[test]
fn custom_receipt_ledger_and_anchor_verifier_work_without_sqlite_or_ed25519() {
    let root_kp = Ed25519Keypair::generate();
    let mid_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();

    let (mut signed, expected_verified) =
        build_pr_chain(&root_kp, &mid_kp, &agent_kp, valid_from, valid_until);
    signed[0].signature_hex = "00".repeat(64);
    let stub = StubVerifier {
        verified_hops: expected_verified,
    };
    let verified = verify_mandate_chain_with(&stub, &signed).expect("custom verifier succeeds");

    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        pr_policy_map(),
        InMemoryLedger::default(),
        FixedClock::new(now),
    )
    .unwrap();

    let (up_in, up_out, state, handle) = spawn_fake_upstream(vec![
        json!({"name": "merge_pr"}),
        json!({"name": "delete_repo"}),
    ]);
    let client_frames = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{\"repo\":\"org/app\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_repo\",\"arguments\":{\"repo\":\"org/app\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{}}}\n"
    );
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(client_frames.as_bytes().to_vec())),
            &mut client_out,
            up_in,
            up_out,
        )
        .expect("custom ledger proxy session succeeded");
    handle.join().unwrap();

    assert_eq!(state.calls(), 1);
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 3);
    assert_eq!(proxy.ledger().receipts[0].verdict, Verdict::Permit);
    assert!(matches!(
        proxy.ledger().receipts[1].verdict,
        Verdict::Deny { .. }
    ));
    let mapping_receipt = &proxy.ledger().receipts[2];
    assert_eq!(mapping_receipt.action, "git.pr.merge");
    assert_eq!(mapping_receipt.resource, "repo \"\"");
    assert_eq!(
        mapping_receipt.verdict,
        Verdict::Deny {
            reason: "tool 'merge_pr': missing required resource_id argument 'repo'".to_string()
        }
    );
    assert_eq!(
        mapping_receipt.prev_receipt_hash,
        Some(proxy.ledger().receipts[1].receipt_hash)
    );
}

fn assert_denied_with_receipt(resp: &Value) {
    assert_eq!(resp["error"]["code"], json!(HANDFEST_DENIED_ERROR_CODE));
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("handfest denied: "));
    let receipt_hash = resp["error"]["data"]["receipt_hash"]
        .as_str()
        .expect("denied response includes receipt_hash");
    assert!(receipt_hash.starts_with("sha256:"));
    assert!(resp["error"]["data"]["reason"].as_str().is_some());
}

fn write_smoke_session_frames(mut stdin: std::process::ChildStdin) {
    for line in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_repo","arguments":{"repo":"org/app"}}}"#,
    ] {
        writeln!(stdin, "{line}").unwrap();
    }
}
