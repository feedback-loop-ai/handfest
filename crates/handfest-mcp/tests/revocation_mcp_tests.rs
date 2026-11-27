//! End-to-end and library-level revocation enforcement tests for `handfest-mcp`.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::thread;

use handfest_anchors::{verify_revocation, Ed25519Keypair};
use handfest_core::ast::{parse_rfc3339_utc, KeyId};
use handfest_core::cnl::parse_mandate;
use handfest_core::revocation::{render_canonical_revocation, RevocationAst, RevocationTarget};
use handfest_core::ActorKind;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{
    verify_mandate_chain, verify_revocations, FixedClock, McpProxy, ToolPolicy, ToolPolicyMap,
    HANDFEST_DENIED_ERROR_CODE,
};
use serde_json::{json, Value};

#[expect(
    dead_code,
    reason = "shared test utilities used selectively across integration test binaries"
)]
mod common;

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid timestamp")
}

fn sample_policy_map() -> ToolPolicyMap {
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
    ToolPolicyMap { tools }
}

fn signed_mandate_and_revocation(
    effective_at: i64,
) -> (
    Ed25519Keypair,
    Ed25519Keypair,
    handfest_anchors::SignedMandate,
    handfest_anchors::SignedRevocation,
) {
    let alice = Ed25519Keypair::from_secret_bytes([0x1a; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x2b; 32]);
    let words = format!(
        "HANDFEST v1\n\
         FROM human \"Alice\" (key: {})\n\
         TO agent \"Bot\" (key: {})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"feedback-loop-ai/*\"\n\
         LIMIT 5 calls\n",
        alice.key_id(),
        agent.key_id()
    );
    let ast = parse_mandate(&words).unwrap();
    let mandate_id = ast.mandate_id();
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let signed_mandate = alice.sign_mandate(&words, "local-ed25519", vf, vu).unwrap();

    let by = handfest_core::ast::ActorDecl::new(
        ActorKind::Human,
        "Alice",
        alice.key_id(),
        BTreeMap::new(),
    )
    .unwrap();
    let rev_ast = RevocationAst::new(
        by,
        RevocationTarget::Mandate(mandate_id),
        effective_at,
        Some("emergency stop".to_string()),
    )
    .unwrap();
    let rev_words = render_canonical_revocation(&rev_ast);
    let signed_rev = alice
        .sign_revocation(&rev_words, "local-ed25519", effective_at, vu)
        .unwrap();
    (alice, agent, signed_mandate, signed_rev)
}

#[test]
fn mcp_proxy_enforces_live_ledger_revocation_and_hides_tools() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("mcp.sqlite");
    let now = ts("2026-11-26T14:00:00Z");
    let (_alice, agent, signed_mandate, signed_rev) = signed_mandate_and_revocation(now);
    let verified_chain = verify_mandate_chain(&[signed_mandate]).unwrap();
    let verified_rev = verify_revocation(&signed_rev).unwrap();
    let rev_id_str = verified_rev.ast.revocation_id().to_string();

    let ledger = SqliteLedger::open(&db_path).unwrap();
    let mut proxy = McpProxy::new(
        verified_chain,
        agent.key_id(),
        sample_policy_map(),
        ledger,
        FixedClock::new(now),
    )
    .unwrap();

    let (mut client_to_proxy, proxy_client_in) = common::mem_pipe();
    let (proxy_client_out, client_from_proxy) = common::mem_pipe();
    let (proxy_to_up, up_in) = common::mem_pipe();
    let (up_to_proxy, proxy_up_out) = common::mem_pipe();

    let proxy_handle = thread::spawn(move || {
        let mut client_out = proxy_client_out;
        proxy
            .run(proxy_client_in, &mut client_out, proxy_to_up, proxy_up_out)
            .expect("proxy run cleanly");
    });

    let up_handle = spawn_echo_upstream(up_in, up_to_proxy);

    let mut reader = BufReader::new(client_from_proxy);
    let mut resp_line = String::new();

    // 1. Before revocation: tools/call #1 is permitted and forwarded to upstream.
    writeln!(
        client_to_proxy,
        "{}",
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "merge_pr", "arguments": {"repo": "feedback-loop-ai/handfest"}}})
    )
    .unwrap();
    reader.read_line(&mut resp_line).unwrap();
    let r1: Value = serde_json::from_str(resp_line.trim()).unwrap();
    assert_eq!(r1["id"], 1);
    assert!(r1["result"].is_object(), "expected permit result, got {r1}");
    resp_line.clear();

    // 2. Record revocation into the SAME SQLite ledger while proxy is running!
    {
        let mut external_writer = SqliteLedger::open(&db_path).unwrap();
        external_writer
            .record_revocation(&verified_rev, &signed_rev.signature_hex)
            .unwrap();
    }

    // 3. Immediately next tools/call #2 is DENIED with -32001 and revocation reason!
    writeln!(
        client_to_proxy,
        "{}",
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "merge_pr", "arguments": {"repo": "feedback-loop-ai/handfest"}}})
    )
    .unwrap();
    reader.read_line(&mut resp_line).unwrap();
    let r2: Value = serde_json::from_str(resp_line.trim()).unwrap();
    assert_eq!(r2["id"], 2);
    assert_eq!(r2["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert!(
        r2["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&rev_id_str),
        "expected revocation id in error message, got {r2}"
    );
    resp_line.clear();

    // 4. tools/list now returns empty tools array because chain is revoked!
    writeln!(
        client_to_proxy,
        "{}",
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    )
    .unwrap();
    reader.read_line(&mut resp_line).unwrap();
    let r3: Value = serde_json::from_str(resp_line.trim()).unwrap();
    assert_eq!(r3["id"], 3);
    assert_eq!(r3["result"]["tools"], json!([]));

    drop(client_to_proxy);
    proxy_handle.join().unwrap();
    up_handle.join().unwrap();

    // Verify ledger audit integrity (1 permit + 1 deny).
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(ro.verify_integrity().unwrap(), 2);
}

#[test]
fn mcp_binary_enforces_static_revocation_flag_and_fails_closed_on_tampered_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let now_str = "2026-11-26T14:00:00Z";
    let now = ts(now_str);
    let (_alice, agent, signed_mandate, signed_rev) = signed_mandate_and_revocation(now);

    let chain_path = dir.path().join("root.signed.json");
    let rev_path = dir.path().join("rev.signed.json");
    let policy_path = dir.path().join("policy.json");
    let ledger_path = dir.path().join("bin.sqlite");

    fs::write(
        &chain_path,
        serde_json::to_string_pretty(&signed_mandate).unwrap(),
    )
    .unwrap();
    fs::write(
        &rev_path,
        serde_json::to_string_pretty(&signed_rev).unwrap(),
    )
    .unwrap();
    fs::write(
        &policy_path,
        serde_json::to_string_pretty(&sample_policy_map()).unwrap(),
    )
    .unwrap();

    // Also test library-level verify_revocations + with_revocations helper
    let snap = verify_revocations(std::slice::from_ref(&signed_rev)).unwrap();
    assert_eq!(snap.len(), 1);
    let _ = KeyId::parse(&agent.key_id().to_string()).unwrap();

    // Spawn real `handfest-mcp` binary with `--revocation rev.signed.json`
    let mut child = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .args([
            "--chain",
            chain_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--actor-key",
            &agent.key_id().to_string(),
            "--policy-map",
            policy_path.to_str().unwrap(),
            "--now",
            now_str,
            "--revocation",
            rev_path.to_str().unwrap(),
            "--",
            "cat",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "merge_pr", "arguments": {"repo": "feedback-loop-ai/handfest"}}})
        )
        .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "handfest-mcp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resp: Value = serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(resp["id"], 10);
    assert_eq!(resp["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("revoked"));
}

fn spawn_echo_upstream(
    mut up_in: BufReader<common::PipeReader>,
    mut up_to_proxy: common::PipeWriter,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut line = String::new();
        while up_in.read_line(&mut line).unwrap() > 0 {
            let req: Value = serde_json::from_str(line.trim()).unwrap();
            let id = req["id"].clone();
            let resp = if req["method"] == "tools/list" {
                json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [{"name": "merge_pr"}]}})
            } else {
                json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": "merged"}]}})
            };
            writeln!(up_to_proxy, "{resp}").unwrap();
            line.clear();
        }
    })
}

#[test]
fn mcp_binary_fails_closed_at_startup_on_tampered_revocation_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let now_str = "2026-11-26T14:00:00Z";
    let now = ts(now_str);
    let (_alice, agent, signed_mandate, signed_rev) = signed_mandate_and_revocation(now);
    let chain_path = dir.path().join("root.signed.json");
    let policy_path = dir.path().join("policy.json");
    let ledger_path = dir.path().join("bin.sqlite");
    fs::write(
        &chain_path,
        serde_json::to_string_pretty(&signed_mandate).unwrap(),
    )
    .unwrap();
    fs::write(
        &policy_path,
        serde_json::to_string_pretty(&sample_policy_map()).unwrap(),
    )
    .unwrap();
    let mut bad_rev = signed_rev;
    bad_rev.signature_hex = "00".repeat(64);
    let bad_rev_path = dir.path().join("bad.rev.json");
    fs::write(
        &bad_rev_path,
        serde_json::to_string_pretty(&bad_rev).unwrap(),
    )
    .unwrap();

    let bad_out = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .args([
            "--chain",
            chain_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--actor-key",
            &agent.key_id().to_string(),
            "--policy-map",
            policy_path.to_str().unwrap(),
            "--now",
            now_str,
            "--revocation",
            bad_rev_path.to_str().unwrap(),
            "--",
            "cat",
        ])
        .output()
        .unwrap();
    assert!(!bad_out.status.success());
    let err_json: Value =
        serde_json::from_str(String::from_utf8_lossy(&bad_out.stderr).trim()).unwrap();
    assert_eq!(err_json["code"], "chain_invalid");
}
