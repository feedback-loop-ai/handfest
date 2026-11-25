//! Integration tests for `handfest-mcp`: policy mapping, stdio JSON-RPC proxy, and CLI binary.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::VerifiedMandate;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{
    verify_mandate_chain, FactSpec, FactType, FixedClock, McpProxy, ProxyError, ToolPolicy,
    ToolPolicyMap, TypedScalar, HANDFEST_DENIED_ERROR_CODE,
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
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let req: Value = serde_json::from_str(trimmed).expect("upstream received valid JSON");
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
    let (mut up_in, mut up_out, state, handle) = spawn_fake_upstream(advertised_tools);
    let input_blob = client_lines.join("\n") + "\n";
    let mut client_in = BufReader::new(input_blob.as_bytes());
    let mut client_out = Vec::new();

    let run_res = proxy.run(&mut client_in, &mut client_out, &mut up_in, &mut up_out);
    drop(up_in);
    drop(up_out);
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
            r#"{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app","pr":42}}}"#,
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
        let resp = &responses[denied_idx];
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

    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
        )
        .unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"merge_pr","arguments":{{"repo":"org/app"}}}}}}"#).unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"delete_repo","arguments":{{"repo":"org/app"}}}}}}"#).unwrap();
    }

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
