//! Integration tests for fail-closed on-disk mandate chain hot-reload in `handfest-mcp`.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use handfest_anchors::{
    AnchorError, AnchorRegistry, AnchorVerifier, Ed25519Keypair, SignedMandate,
};
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::gate::VerifiedMandate;
use handfest_core::Verdict;
use handfest_ledger::{SqliteLedger, TrackRecord};
use handfest_mcp::{
    ChainReloader, Clock, FixedClock, McpProxy, ProxyError, ToolPolicy, ToolPolicyMap,
    HANDFEST_DENIED_ERROR_CODE,
};
use serde_json::{json, Value};

#[expect(
    dead_code,
    reason = "shared test utilities used selectively across integration test binaries"
)]
mod common;

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 timestamp")
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

fn sign_root(
    alice: &Ed25519Keypair,
    agent: &Ed25519Keypair,
    limit: u64,
    valid_from: i64,
    valid_until: i64,
) -> SignedMandate {
    let unit = if limit == 1 { "call" } else { "calls" };
    let words = format!(
        "HANDFEST v1\n\
         FROM human \"Alice\" (key: {})\n\
         TO agent \"Bot\" (key: {})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"feedback-loop-ai/*\"\n\
         LIMIT {limit} {unit}\n",
        alice.key_id(),
        agent.key_id()
    );
    alice
        .sign_mandate(&words, "local-ed25519", valid_from, valid_until)
        .unwrap()
}

fn atomic_write_json(path: &Path, content: &str) {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, content).unwrap();
    fs::rename(&tmp, path).unwrap();
}

fn tamper_signature(valid: &SignedMandate) -> SignedMandate {
    let mut tampered = valid.clone();
    let flip = if tampered.signature_hex.starts_with('a') {
        "b"
    } else {
        "a"
    };
    tampered.signature_hex = format!("{flip}{}", &tampered.signature_hex[1..]);
    tampered
}

fn spawn_counting_echo_upstream(
    up_in: BufReader<common::PipeReader>,
    mut up_out: common::PipeWriter,
    forwarded_calls: Arc<AtomicUsize>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for line in up_in.lines() {
            let line = line.unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            if method == "tools/call" {
                forwarded_calls.fetch_add(1, Ordering::SeqCst);
                writeln!(
                    up_out,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true}})
                )
                .unwrap();
            } else if method == "tools/list" {
                writeln!(
                    up_out,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [{"name": "merge_pr"}]}})
                )
                .unwrap();
            }
            up_out.flush().unwrap();
        }
    })
}

struct LiveProxyHarness {
    _dir: tempfile::TempDir,
    chain_path: PathBuf,
    db_path: PathBuf,
    client_to_proxy: Option<common::PipeWriter>,
    reader: BufReader<BufReader<common::PipeReader>>,
    forwarded: Arc<AtomicUsize>,
    proxy_handle: Option<thread::JoinHandle<()>>,
    up_handle: Option<thread::JoinHandle<()>>,
}

impl LiveProxyHarness {
    fn start(
        initial: &SignedMandate,
        agent: &Ed25519Keypair,
        now: i64,
        custom_verifier: Option<CountingVerifier>,
    ) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("mcp.sqlite");
        let chain_path = dir.path().join("root.signed.json");
        atomic_write_json(&chain_path, &serde_json::to_string_pretty(initial).unwrap());
        let ledger = SqliteLedger::open(&db_path).unwrap();
        let mut proxy = match custom_verifier {
            Some(v) => McpProxy::from_chain_files_with_verifier(
                vec![chain_path.clone()],
                v,
                agent.key_id(),
                sample_policy_map(),
                ledger,
                FixedClock::new(now),
            )
            .unwrap(),
            None => McpProxy::from_chain_files(
                vec![chain_path.clone()],
                agent.key_id(),
                sample_policy_map(),
                ledger,
                FixedClock::new(now),
            )
            .unwrap(),
        };

        let (client_to_proxy, proxy_client_in) = common::mem_pipe();
        let (proxy_client_out, client_from_proxy) = common::mem_pipe();
        let (proxy_to_up, up_in) = common::mem_pipe();
        let (up_to_proxy, proxy_up_out) = common::mem_pipe();
        let forwarded = Arc::new(AtomicUsize::new(0));

        let proxy_handle = thread::spawn(move || {
            let mut client_out = proxy_client_out;
            proxy
                .run(proxy_client_in, &mut client_out, proxy_to_up, proxy_up_out)
                .expect("proxy exits cleanly");
        });
        let up_handle = spawn_counting_echo_upstream(up_in, up_to_proxy, Arc::clone(&forwarded));

        Self {
            _dir: dir,
            chain_path,
            db_path,
            client_to_proxy: Some(client_to_proxy),
            reader: BufReader::new(client_from_proxy),
            forwarded,
            proxy_handle: Some(proxy_handle),
            up_handle: Some(up_handle),
        }
    }

    fn send_json(&mut self, payload: Value) -> Value {
        let tx = self.client_to_proxy.as_mut().unwrap();
        writeln!(tx, "{payload}").unwrap();
        tx.flush().unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).unwrap()
    }

    fn call_merge(&mut self, id: u64) -> Value {
        self.send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": "merge_pr", "arguments": {"repo": "feedback-loop-ai/handfest"}}
        }))
    }

    fn list_tools(&mut self, id: u64) -> Value {
        self.send_json(json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"}))
    }

    fn assert_reload_denied(&mut self, id: u64, substr: &str, expected_forwarded: usize) -> String {
        let r = self.call_merge(id);
        assert_eq!(r["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
        assert!(
            r["error"]["message"].as_str().unwrap().contains(substr),
            "expected '{substr}' in error message, got {r}"
        );
        let receipt_hash = r["error"]["data"]["receipt_hash"]
            .as_str()
            .expect("reload denial must include receipt_hash in error.data")
            .to_string();
        assert!(
            receipt_hash.starts_with("sha256:") && receipt_hash.len() == 71,
            "receipt_hash must be sha256:<64-hex>, got {receipt_hash}"
        );
        assert_eq!(self.forwarded.load(Ordering::SeqCst), expected_forwarded);
        receipt_hash
    }

    fn shutdown(mut self) -> PathBuf {
        self.client_to_proxy.take();
        self.proxy_handle.take().unwrap().join().unwrap();
        self.up_handle.take().unwrap().join().unwrap();
        let db = self.db_path.clone();
        // Keep TempDir alive? Return db_path only after reading ledger before dropping _dir.
        db
    }
}

#[test]
fn hot_reload_honours_replaced_mandate_with_bumped_quota_and_extended_window() {
    let alice = Ed25519Keypair::from_secret_bytes([0x51; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x52; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    let m1 = sign_root(&alice, &agent, 1, vf, vu);
    let mut h = LiveProxyHarness::start(&m1, &agent, now, None);

    assert_eq!(h.call_merge(1)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 1);

    let r2 = h.call_merge(2);
    assert_eq!(r2["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 1);

    let m2 = sign_root(&alice, &agent, 5, vf, vu);
    atomic_write_json(&h.chain_path, &serde_json::to_string_pretty(&m2).unwrap());

    assert_eq!(h.call_merge(3)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 2);

    let expired = sign_root(&alice, &agent, 5, vf, ts("2026-11-26T12:00:00Z"));
    atomic_write_json(
        &h.chain_path,
        &serde_json::to_string_pretty(&expired).unwrap(),
    );
    assert_eq!(h.call_merge(4)["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 2);

    let extended = sign_root(&alice, &agent, 5, vf, ts("2026-11-26T23:00:00Z"));
    atomic_write_json(
        &h.chain_path,
        &serde_json::to_string_pretty(&extended).unwrap(),
    );
    assert_eq!(h.call_merge(5)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 3);

    h.shutdown();
}

#[test]
fn hot_reload_fails_closed_records_audited_denials_and_recovers() {
    let alice = Ed25519Keypair::from_secret_bytes([0x54; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x55; 32]);
    let other_agent = Ed25519Keypair::from_secret_bytes([0x56; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    let valid = sign_root(&alice, &agent, 5, vf, vu);
    let mut h = LiveProxyHarness::start(&valid, &agent, now, None);

    assert_eq!(h.call_merge(1)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 1);

    let mut expected_denial_hashes = Vec::new();

    // 1. Tampered signature: consecutive calls BOTH fail closed AND record audited Deny receipts!
    let tampered = tamper_signature(&valid);
    atomic_write_json(
        &h.chain_path,
        &serde_json::to_string_pretty(&tampered).unwrap(),
    );
    expected_denial_hashes.push(h.assert_reload_denied(
        2,
        "mandate signature verification failed: chain hop 0: invalid anchor signature: signature error",
        1,
    ));
    expected_denial_hashes.push(h.assert_reload_denied(
        3,
        "mandate signature verification failed: chain hop 0: invalid anchor signature: signature error",
        1,
    ));
    assert_eq!(h.list_tools(4)["error"]["code"], HANDFEST_DENIED_ERROR_CODE);

    // Unmapped tool call and malformed params during reload failure also emit audited receipt_hash.
    let unmapped_resp = h.send_json(json!({
        "jsonrpc": "2.0",
        "id": 40,
        "method": "tools/call",
        "params": {"name": "unknown_tool", "arguments": {}}
    }));
    assert_eq!(unmapped_resp["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    expected_denial_hashes.push(
        unmapped_resp["error"]["data"]["receipt_hash"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    let bad_params_resp = h.send_json(json!({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {"name": ""}
    }));
    assert_eq!(bad_params_resp["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    expected_denial_hashes.push(
        bad_params_resp["error"]["data"]["receipt_hash"]
            .as_str()
            .unwrap()
            .to_string(),
    );

    // 2. Malformed JSON -> fails closed + audited receipt.
    atomic_write_json(&h.chain_path, "{not valid json");
    expected_denial_hashes.push(h.assert_reload_denied(5, "mandate chain reload failed", 1));

    // 3. Valid signature with mismatched leaf TO key -> fails closed + audited receipt.
    let wrong_to = sign_root(&alice, &other_agent, 5, vf, vu);
    atomic_write_json(
        &h.chain_path,
        &serde_json::to_string_pretty(&wrong_to).unwrap(),
    );
    expected_denial_hashes.push(h.assert_reload_denied(
        6,
        "does not match configured actor_key",
        1,
    ));

    // 4. Missing (deleted) chain file -> fails closed + audited receipt.
    fs::remove_file(&h.chain_path).unwrap();
    expected_denial_hashes.push(h.assert_reload_denied(7, "mandate chain reload failed", 1));

    // 5. Restore valid signed mandate -> recovers cleanly!
    atomic_write_json(
        &h.chain_path,
        &serde_json::to_string_pretty(&valid).unwrap(),
    );
    assert_eq!(h.call_merge(8)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 2);
    assert_eq!(h.list_tools(9)["result"]["tools"][0]["name"], "merge_pr");

    // Inspect SQLite ledger before TempDir drops: every reload denial is audited & hash-chained.
    let ledger = SqliteLedger::open(&h.db_path).unwrap();
    ledger
        .verify_integrity()
        .expect("ledger hash chain must verify cleanly");
    let receipts = ledger.list_receipts().unwrap();
    for hash in &expected_denial_hashes {
        let receipt = receipts
            .iter()
            .find(|r| r.receipt_hash.to_string() == *hash)
            .unwrap_or_else(|| panic!("denial receipt_hash {hash} missing from SqliteLedger"));
        assert!(matches!(receipt.verdict, Verdict::Deny { .. }));
        assert!(
            receipt.chain_ids.is_empty(),
            "reload denial receipt {hash} must have empty chain_ids, got {:?}",
            receipt.chain_ids
        );
    }
    assert!(receipts
        .iter()
        .any(|r| r.action == "mcp.tools.call" && r.resource == "mcp_tool \"unknown_tool\""));
    assert!(receipts
        .iter()
        .any(|r| r.action == "mcp.tools.call" && r.resource == "mcp_tool \"invalid_params\""));

    h.shutdown();
}

struct CountingVerifier {
    inner: AnchorRegistry,
    verify_calls: Arc<AtomicUsize>,
}

impl AnchorVerifier for CountingVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(signed)
    }
}

#[test]
fn hot_reload_fast_path_skips_reverification_when_file_metadata_is_unchanged() {
    let alice = Ed25519Keypair::from_secret_bytes([0x61; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x62; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    let m1 = sign_root(&alice, &agent, 10, vf, vu);
    let verify_calls = Arc::new(AtomicUsize::new(0));
    let verifier = CountingVerifier {
        inner: AnchorRegistry::default_registry(),
        verify_calls: Arc::clone(&verify_calls),
    };
    let mut h = LiveProxyHarness::start(&m1, &agent, now, Some(verifier));
    assert_eq!(verify_calls.load(Ordering::SeqCst), 1);

    for id in 1..=3 {
        assert_eq!(h.call_merge(id)["result"]["ok"], true);
    }
    assert_eq!(verify_calls.load(Ordering::SeqCst), 1);

    let m2 = sign_root(&alice, &agent, 20, vf, vu);
    atomic_write_json(&h.chain_path, &serde_json::to_string_pretty(&m2).unwrap());

    assert_eq!(h.call_merge(4)["result"]["ok"], true);
    assert_eq!(verify_calls.load(Ordering::SeqCst), 2);

    assert_eq!(h.call_merge(5)["result"]["ok"], true);
    assert_eq!(verify_calls.load(Ordering::SeqCst), 2);

    h.shutdown();
}

#[test]
fn from_chain_files_fails_immediately_on_tampered_empty_directory_or_mismatched_actor() {
    let alice = Ed25519Keypair::from_secret_bytes([0x63; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x64; 32]);
    let other_agent = Ed25519Keypair::from_secret_bytes([0x65; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("mcp.sqlite");

    let err = ChainReloader::load_initial(
        Vec::new(),
        AnchorRegistry::default_registry(),
        &agent.key_id(),
    )
    .unwrap_err();
    assert!(matches!(err, ProxyError::InvalidChain(_)));

    let dir_err = ChainReloader::load_initial(
        vec![dir.path().to_path_buf()],
        AnchorRegistry::default_registry(),
        &agent.key_id(),
    )
    .unwrap_err();
    assert!(matches!(dir_err, ProxyError::Io(_)));

    let valid = sign_root(&alice, &agent, 5, vf, vu);
    let tampered = tamper_signature(&valid);
    let tampered_path = dir.path().join("tampered.signed.json");
    atomic_write_json(
        &tampered_path,
        &serde_json::to_string_pretty(&tampered).unwrap(),
    );
    let ledger = SqliteLedger::open(&db_path).unwrap();
    let tampered_err = McpProxy::from_chain_files(
        vec![tampered_path],
        agent.key_id(),
        sample_policy_map(),
        ledger,
        FixedClock::new(now),
    )
    .unwrap_err();
    assert!(matches!(tampered_err, ProxyError::Anchor(_)));

    let wrong_to_path = dir.path().join("wrong_to.signed.json");
    let wrong_to = sign_root(&alice, &other_agent, 5, vf, vu);
    atomic_write_json(
        &wrong_to_path,
        &serde_json::to_string_pretty(&wrong_to).unwrap(),
    );
    let ledger2 = SqliteLedger::open(&db_path).unwrap();
    let mismatch_err = McpProxy::from_chain_files(
        vec![wrong_to_path],
        agent.key_id(),
        sample_policy_map(),
        ledger2,
        FixedClock::new(now),
    )
    .unwrap_err();
    assert!(matches!(
        mismatch_err,
        ProxyError::InvalidChain(ref msg) if msg.contains("does not match configured actor_key")
    ));
}

#[cfg(unix)]
struct SymlinkSwapVerifier {
    inner: AnchorRegistry,
    armed: Arc<AtomicBool>,
    link_path: PathBuf,
    swap_target: PathBuf,
}

#[cfg(unix)]
impl AnchorVerifier for SymlinkSwapVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let tmp_link = self.link_path.with_extension("link.tmp");
            let _ = fs::remove_file(&tmp_link);
            std::os::unix::fs::symlink(&self.swap_target, &tmp_link).unwrap();
            fs::rename(&tmp_link, &self.link_path).unwrap();
        }
        self.inner.verify(signed)
    }
}

#[cfg(unix)]
#[test]
fn hot_reload_rejects_mid_verify_symlink_swap_without_poisoning_fingerprint() {
    let alice = Ed25519Keypair::from_secret_bytes([0x66; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x67; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("mcp.sqlite");
    let narrow_path = dir.path().join("narrow.signed.json");
    let broad_path = dir.path().join("broad.signed.json");
    let tampered_path = dir.path().join("tampered.signed.json");
    let link_path = dir.path().join("active.signed.json");

    let narrow = sign_root(&alice, &agent, 1, vf, vu);
    let broad = sign_root(&alice, &agent, 50, vf, vu);
    let tampered = tamper_signature(&broad);

    atomic_write_json(
        &narrow_path,
        &serde_json::to_string_pretty(&narrow).unwrap(),
    );
    atomic_write_json(&broad_path, &serde_json::to_string_pretty(&broad).unwrap());
    atomic_write_json(
        &tampered_path,
        &serde_json::to_string_pretty(&tampered).unwrap(),
    );
    std::os::unix::fs::symlink(&narrow_path, &link_path).unwrap();

    let armed = Arc::new(AtomicBool::new(false));
    let verifier = SymlinkSwapVerifier {
        inner: AnchorRegistry::default_registry(),
        armed: Arc::clone(&armed),
        link_path: link_path.clone(),
        swap_target: tampered_path.clone(),
    };

    let ledger = SqliteLedger::open(&db_path).unwrap();
    let mut proxy = McpProxy::from_chain_files_with_verifier(
        vec![link_path.clone()],
        verifier,
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
    let forwarded = Arc::new(AtomicUsize::new(0));

    let proxy_handle = thread::spawn(move || {
        let mut client_out = proxy_client_out;
        proxy
            .run(proxy_client_in, &mut client_out, proxy_to_up, proxy_up_out)
            .expect("proxy exits cleanly");
    });
    let up_handle = spawn_counting_echo_upstream(up_in, up_to_proxy, Arc::clone(&forwarded));
    let mut reader = BufReader::new(client_from_proxy);

    let mut call = |id: u64| -> Value {
        writeln!(
            client_to_proxy,
            "{}",
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": "merge_pr", "arguments": {"repo": "feedback-loop-ai/handfest"}}
            })
        )
        .unwrap();
        client_to_proxy.flush().unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).unwrap()
    };

    assert_eq!(call(1)["result"]["ok"], true);
    assert_eq!(forwarded.load(Ordering::SeqCst), 1);

    let tmp_link = link_path.with_extension("link.tmp");
    std::os::unix::fs::symlink(&broad_path, &tmp_link).unwrap();
    fs::rename(&tmp_link, &link_path).unwrap();
    armed.store(true, Ordering::SeqCst);

    let r2 = call(2);
    assert_eq!(r2["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert!(
        r2["error"]["message"]
            .as_str()
            .unwrap()
            .contains("changed during verification"),
        "expected symlink swap detection error, got {r2}"
    );
    assert!(r2["error"]["data"]["receipt_hash"].as_str().is_some());
    assert_eq!(forwarded.load(Ordering::SeqCst), 1);

    let r3 = call(3);
    assert_eq!(r3["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert_eq!(forwarded.load(Ordering::SeqCst), 1);

    std::os::unix::fs::symlink(&broad_path, &tmp_link).unwrap();
    fs::rename(&tmp_link, &link_path).unwrap();
    assert_eq!(call(4)["result"]["ok"], true);
    assert_eq!(forwarded.load(Ordering::SeqCst), 2);

    drop(client_to_proxy);
    proxy_handle.join().unwrap();
    up_handle.join().unwrap();
}

fn spawn_gated_tools_list_upstream(
    up_in: BufReader<common::PipeReader>,
    mut up_to_proxy: common::PipeWriter,
    seen_list_tx: mpsc::Sender<Value>,
    release_list_rx: mpsc::Receiver<()>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for line in up_in.lines() {
            let line = line.unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            if req.get("method").and_then(Value::as_str) == Some("tools/list") {
                let id = req["id"].clone();
                seen_list_tx.send(id.clone()).unwrap();
                release_list_rx.recv().unwrap();
                writeln!(
                    up_to_proxy,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [{"name": "merge_pr"}]}})
                )
                .unwrap();
                up_to_proxy.flush().unwrap();
            }
        }
    })
}

#[test]
fn hot_reload_cancelled_and_in_flight_tools_list_return_empty_after_tamper() {
    let alice = Ed25519Keypair::from_secret_bytes([0x68; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x69; 32]);
    let valid = sign_root(
        &alice,
        &agent,
        5,
        ts("2026-11-26T10:00:00Z"),
        ts("2026-11-26T20:00:00Z"),
    );

    let dir = tempfile::TempDir::new().unwrap();
    let chain_path = dir.path().join("root.signed.json");
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&valid).unwrap());
    let ledger = SqliteLedger::open(dir.path().join("mcp.sqlite")).unwrap();
    let mut proxy = McpProxy::from_chain_files(
        vec![chain_path.clone()],
        agent.key_id(),
        sample_policy_map(),
        ledger,
        FixedClock::new(ts("2026-11-26T14:00:00Z")),
    )
    .unwrap();

    let (mut client_to_proxy, proxy_client_in) = common::mem_pipe();
    let (proxy_client_out, client_from_proxy) = common::mem_pipe();
    let (proxy_to_up, up_in) = common::mem_pipe();
    let (up_to_proxy, proxy_up_out) = common::mem_pipe();
    let (seen_list_tx, seen_list_rx) = mpsc::channel::<Value>();
    let (release_list_tx, release_list_rx) = mpsc::channel::<()>();

    let proxy_handle = thread::spawn(move || {
        let mut client_out = proxy_client_out;
        proxy
            .run(proxy_client_in, &mut client_out, proxy_to_up, proxy_up_out)
            .expect("proxy exits cleanly");
    });
    let up_handle =
        spawn_gated_tools_list_upstream(up_in, up_to_proxy, seen_list_tx, release_list_rx);
    let mut reader = BufReader::new(client_from_proxy);
    let mut read_resp = || -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).unwrap()
    };
    let send = |tx: &mut common::PipeWriter, msg: Value| {
        writeln!(tx, "{msg}").unwrap();
        tx.flush().unwrap();
    };

    // 1. Send tools/list (id=1), cancel it, tamper chain, trigger tools/call (id=2).
    send(
        &mut client_to_proxy,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    assert_eq!(seen_list_rx.recv().unwrap(), json!(1));
    send(
        &mut client_to_proxy,
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}),
    );

    let tampered = tamper_signature(&valid);
    atomic_write_json(
        &chain_path,
        &serde_json::to_string_pretty(&tampered).unwrap(),
    );
    send(
        &mut client_to_proxy,
        json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "merge_pr", "arguments": {"repo": "feedback-loop-ai/handfest"}}
        }),
    );
    let call_resp = read_resp();
    assert_eq!(call_resp["id"], 2);
    assert_eq!(call_resp["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert!(call_resp["error"]["data"]["receipt_hash"]
        .as_str()
        .is_some());

    release_list_tx.send(()).unwrap();
    let cancelled_list_resp = read_resp();
    assert_eq!(cancelled_list_resp["id"], 1);
    assert_eq!(cancelled_list_resp["result"]["tools"], json!([]));

    // 2. Restore valid chain, send in-flight tools/list (id=3), tamper BEFORE response (no tools/call).
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&valid).unwrap());
    send(
        &mut client_to_proxy,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
    );
    assert_eq!(seen_list_rx.recv().unwrap(), json!(3));
    atomic_write_json(
        &chain_path,
        &serde_json::to_string_pretty(&tampered).unwrap(),
    );
    release_list_tx.send(()).unwrap();
    let inflight_list_resp = read_resp();
    assert_eq!(inflight_list_resp["id"], 3);
    assert_eq!(inflight_list_resp["result"]["tools"], json!([]));

    drop(client_to_proxy);
    proxy_handle.join().unwrap();
    up_handle.join().unwrap();
}

#[cfg(unix)]
#[test]
fn hot_reload_denies_0000_mode_regular_file_and_recovers_on_0600() {
    let alice = Ed25519Keypair::from_secret_bytes([0x6a; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x6b; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    let valid = sign_root(&alice, &agent, 5, vf, vu);
    let mut h = LiveProxyHarness::start(&valid, &agent, now, None);

    assert_eq!(h.call_merge(1)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 1);

    // Replace with a 0000-mode regular file that can still be stat'd but cannot be opened.
    fs::set_permissions(&h.chain_path, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(
        fs::metadata(&h.chain_path).unwrap().is_file(),
        "0000-mode file must still be stat-able"
    );
    if fs::File::open(&h.chain_path).is_ok() {
        // Running with CAP_DAC_OVERRIDE (e.g. root): 0000 permissions do not block open(2).
        fs::set_permissions(&h.chain_path, fs::Permissions::from_mode(0o600)).unwrap();
        h.shutdown();
        return;
    }
    let h2 = h.assert_reload_denied(2, "failed to open chain file", 1);
    let h3 = h.assert_reload_denied(3, "failed to open chain file", 1);
    assert_ne!(h2, h3);

    // Restore 0600 permissions -> recovers cleanly!
    fs::set_permissions(&h.chain_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(h.call_merge(4)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 2);

    h.shutdown();
}

#[test]
fn handfest_mcp_binary_wires_hot_reload_end_to_end() {
    use std::process::{Command, Stdio};

    let dir = tempfile::TempDir::new().unwrap();
    let chain_path = dir.path().join("root.signed.json");
    let ledger_path = dir.path().join("ledger.sqlite");
    let map_path = dir.path().join("policy-map.json");

    let alice = Ed25519Keypair::from_secret_bytes([0x71; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x72; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");

    let m1 = sign_root(&alice, &agent, 1, vf, vu);
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&m1).unwrap());
    fs::write(
        &map_path,
        serde_json::to_string_pretty(&sample_policy_map()).unwrap(),
    )
    .unwrap();

    let upstream_script = r#"while IFS= read -r line; do id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "${id:-1}"; done"#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .args([
            "--chain",
            chain_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--actor-key",
            &agent.key_id().to_string(),
            "--policy-map",
            map_path.to_str().unwrap(),
            "--now",
            "2026-11-26T14:00:00Z",
            "--",
            "/bin/sh",
            "-c",
            upstream_script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn handfest-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();

    let call = |stdin: &mut std::process::ChildStdin,
                stdout: &mut BufReader<std::process::ChildStdout>,
                line: &mut String,
                id: u64|
     -> Value {
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"feedback-loop-ai/handfest"}}})
        )
        .unwrap();
        stdin.flush().unwrap();
        line.clear();
        stdout.read_line(line).unwrap();
        serde_json::from_str(line.trim()).unwrap()
    };

    assert_eq!(
        call(&mut stdin, &mut stdout, &mut line, 1)["result"]["ok"],
        true
    );
    assert_eq!(
        call(&mut stdin, &mut stdout, &mut line, 2)["error"]["code"],
        HANDFEST_DENIED_ERROR_CODE
    );

    let m2 = sign_root(&alice, &agent, 5, vf, vu);
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&m2).unwrap());
    assert_eq!(
        call(&mut stdin, &mut stdout, &mut line, 3)["result"]["ok"],
        true
    );

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success(), "handfest-mcp exited with {status}");
}

struct AtomicClock {
    now: Arc<AtomicI64>,
}

impl Clock for AtomicClock {
    fn now_unix(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

struct ClockAdvancingVerifier {
    inner: AnchorRegistry,
    armed: Arc<AtomicBool>,
    clock: Arc<AtomicI64>,
    advance_to: i64,
}

impl AnchorVerifier for ClockAdvancingVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.clock.store(self.advance_to, Ordering::SeqCst);
        }
        self.inner.verify(signed)
    }
}

#[test]
fn hot_reload_expired_initial_chain_overwritten_with_tampered_records_empty_chain_ids_and_reload_reason(
) {
    let alice = Ed25519Keypair::from_secret_bytes([0x81; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x82; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let expired_vu = ts("2026-11-26T12:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    // Start with an already-expired initial chain `m1`, then overwrite it with a tampered `m2`.
    let m1 = sign_root(&alice, &agent, 5, vf, expired_vu);
    let m2_tampered = tamper_signature(&sign_root(
        &alice,
        &agent,
        10,
        vf,
        ts("2026-11-26T20:00:00Z"),
    ));

    let mut h = LiveProxyHarness::start(&m1, &agent, now, None);
    atomic_write_json(
        &h.chain_path,
        &serde_json::to_string_pretty(&m2_tampered).unwrap(),
    );

    let resp = h.call_merge(1);
    assert_eq!(resp["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    let data_reason = resp["error"]["data"]["reason"]
        .as_str()
        .expect("error.data.reason must be present");
    assert_eq!(
        data_reason,
        "mandate chain reload failed: mandate signature verification failed: chain hop 0: invalid anchor signature: signature error",
        "expected exact signature verification reload failure reason, got {data_reason}"
    );
    assert!(
        !data_reason.contains("outside anchor proof validity window"),
        "stale expired mandate must never overwrite reload failure reason: {data_reason}"
    );
    let receipt_hash = resp["error"]["data"]["receipt_hash"]
        .as_str()
        .expect("receipt_hash must be present")
        .to_string();
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 0);

    // Inspect persisted SqliteLedger read-only (matching `handfest audit`) before TempDir drops.
    let ledger = SqliteLedger::open_read_only(&h.db_path).unwrap();
    let receipts = ledger.list_receipts().unwrap();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_hash.to_string(), receipt_hash);
    assert_eq!(receipt.actor_key, agent.key_id());
    assert_eq!(receipt.timestamp, now);
    assert_eq!(receipt.action, "git.pr.merge");
    assert!(
        receipt.chain_ids.is_empty(),
        "reload failure denial must persist empty chain_ids [], got {:?}",
        receipt.chain_ids
    );
    assert_eq!(
        receipt.verdict,
        Verdict::Deny {
            reason: data_reason.to_string(),
        }
    );
    let audit = ledger
        .audit_full_snapshot(Some(&agent.key_id()), true)
        .expect("audit_full_snapshot must verify tampered-renewal denial ledger cleanly");
    assert_eq!(audit.verified_receipts, 1);
    assert!(audit.stored_revocations.is_empty());
    let track = audit.track_record.expect("track_record must be present");
    assert_eq!(
        track,
        TrackRecord {
            actor_key: agent.key_id(),
            total_decisions: 1,
            permits: 0,
            denies: 1,
            distinct_mandates: 0,
            first_timestamp: Some(now),
            last_timestamp: Some(now),
        }
    );
    let track_json = serde_json::to_value(&track).unwrap();
    assert_eq!(track_json["distinct_mandates"], 0);
    assert_eq!(track_json["denies"], 1);
    assert_eq!(track_json["permits"], 0);
    let chain_hashes = audit.chain_hashes.expect("chain_hashes must be present");
    assert_eq!(
        chain_hashes.receipt_hashes,
        vec![*receipt.receipt_hash.as_bytes()]
    );
    assert_eq!(chain_hashes.last_permit_seq, None);

    h.shutdown();
}

#[test]
fn hot_reload_tools_call_samples_clock_after_reload_completes() {
    let alice = Ed25519Keypair::from_secret_bytes([0x83; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x84; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T15:00:00Z");
    let before_expiry = ts("2026-11-26T14:59:59Z");
    let after_expiry = ts("2026-11-26T15:00:01Z");

    let m1 = sign_root(&alice, &agent, 1, vf, vu);
    let m2 = sign_root(&alice, &agent, 5, vf, vu);

    let dir = tempfile::TempDir::new().unwrap();
    let chain_path = dir.path().join("root.signed.json");
    let db_path = dir.path().join("mcp.sqlite");
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&m1).unwrap());

    let clock_val = Arc::new(AtomicI64::new(before_expiry));
    let armed = Arc::new(AtomicBool::new(false));
    let verifier = ClockAdvancingVerifier {
        inner: AnchorRegistry::default_registry(),
        armed: Arc::clone(&armed),
        clock: Arc::clone(&clock_val),
        advance_to: after_expiry,
    };

    let ledger = SqliteLedger::open(&db_path).unwrap();
    let mut proxy = McpProxy::from_chain_files_with_verifier(
        vec![chain_path.clone()],
        verifier,
        agent.key_id(),
        sample_policy_map(),
        ledger,
        AtomicClock {
            now: Arc::clone(&clock_val),
        },
    )
    .unwrap();

    let (mut client_to_proxy, proxy_client_in) = common::mem_pipe();
    let (proxy_client_out, client_from_proxy) = common::mem_pipe();
    let (proxy_to_up, up_in) = common::mem_pipe();
    let (up_to_proxy, proxy_up_out) = common::mem_pipe();
    let forwarded = Arc::new(AtomicUsize::new(0));

    let proxy_handle = thread::spawn(move || {
        let mut client_out = proxy_client_out;
        proxy
            .run(proxy_client_in, &mut client_out, proxy_to_up, proxy_up_out)
            .expect("proxy exits cleanly");
    });
    let up_handle = spawn_counting_echo_upstream(up_in, up_to_proxy, Arc::clone(&forwarded));
    let mut reader = BufReader::new(client_from_proxy);
    let mut call = |id: u64| -> Value {
        writeln!(
            client_to_proxy,
            "{}",
            json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": "merge_pr", "arguments": {"repo": "feedback-loop-ai/handfest"}}
            })
        )
        .unwrap();
        client_to_proxy.flush().unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).unwrap()
    };

    // Call 1 succeeds before expiry.
    assert_eq!(call(1)["result"]["ok"], true);
    assert_eq!(forwarded.load(Ordering::SeqCst), 1);

    // Replace chain with m2 and arm clock to cross `vu` DURING reload verification.
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&m2).unwrap());
    armed.store(true, Ordering::SeqCst);

    // Call 2 MUST observe post-reload timestamp `after_expiry` and deny as expired.
    let r2 = call(2);
    assert_eq!(r2["error"]["code"], HANDFEST_DENIED_ERROR_CODE);
    assert_eq!(
        r2["error"]["data"]["reason"].as_str(),
        Some(
            format!(
                "hop 0: timestamp {after_expiry} outside anchor proof validity window [{vf}..{vu})"
            )
            .as_str()
        ),
        "expected post-reload validity-window denial after clock crossed valid_until, got {r2}"
    );
    assert_eq!(forwarded.load(Ordering::SeqCst), 1);

    drop(client_to_proxy);
    proxy_handle.join().unwrap();
    up_handle.join().unwrap();
}

#[test]
fn hot_reload_tools_list_evaluates_newly_active_reloaded_chain_at_response_time() {
    let alice = Ed25519Keypair::from_secret_bytes([0x85; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x86; 32]);
    let t1 = ts("2026-11-26T14:00:00Z");
    let t2 = ts("2026-11-26T16:00:00Z");

    // m1 is active at t1; m2 is ONLY active starting at 15:30 (NOT active at t1, active at t2).
    let m1 = sign_root(
        &alice,
        &agent,
        5,
        ts("2026-11-26T10:00:00Z"),
        ts("2026-11-26T15:00:00Z"),
    );
    let m2 = sign_root(
        &alice,
        &agent,
        5,
        ts("2026-11-26T15:30:00Z"),
        ts("2026-11-26T18:00:00Z"),
    );

    let dir = tempfile::TempDir::new().unwrap();
    let chain_path = dir.path().join("root.signed.json");
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&m1).unwrap());
    let ledger = SqliteLedger::open(dir.path().join("mcp.sqlite")).unwrap();
    let clock_val = Arc::new(AtomicI64::new(t1));
    let armed = Arc::new(AtomicBool::new(false));
    let verifier = ClockAdvancingVerifier {
        inner: AnchorRegistry::default_registry(),
        armed: Arc::clone(&armed),
        clock: Arc::clone(&clock_val),
        advance_to: t2,
    };
    let mut proxy = McpProxy::from_chain_files_with_verifier(
        vec![chain_path.clone()],
        verifier,
        agent.key_id(),
        sample_policy_map(),
        ledger,
        AtomicClock {
            now: Arc::clone(&clock_val),
        },
    )
    .unwrap();

    let (mut client_to_proxy, proxy_client_in) = common::mem_pipe();
    let (proxy_client_out, client_from_proxy) = common::mem_pipe();
    let (proxy_to_up, up_in) = common::mem_pipe();
    let (up_to_proxy, proxy_up_out) = common::mem_pipe();
    let (seen_list_tx, seen_list_rx) = mpsc::channel::<Value>();
    let (release_list_tx, release_list_rx) = mpsc::channel::<()>();

    let proxy_handle = thread::spawn(move || {
        let mut client_out = proxy_client_out;
        proxy
            .run(proxy_client_in, &mut client_out, proxy_to_up, proxy_up_out)
            .expect("proxy exits cleanly");
    });
    let up_handle =
        spawn_gated_tools_list_upstream(up_in, up_to_proxy, seen_list_tx, release_list_rx);
    let mut reader = BufReader::new(client_from_proxy);

    // Send tools/list at t1; upstream holds the response.
    writeln!(
        client_to_proxy,
        "{}",
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    )
    .unwrap();
    client_to_proxy.flush().unwrap();
    assert_eq!(seen_list_rx.recv().unwrap(), json!(1));

    // Hot-reload m2 (valid_from = 15:30 > t1 = 14:00) and arm the reload verifier to advance
    // the clock from t1 -> t2 (16:00) DURING verification. If `handle_tools_list_response`
    // sampled the clock BEFORE `refresh_chain_if_changed()`, it would observe t1 < valid_from
    // and clear `tools` to `[]`.
    atomic_write_json(&chain_path, &serde_json::to_string_pretty(&m2).unwrap());
    armed.store(true, Ordering::SeqCst);
    assert_eq!(clock_val.load(Ordering::SeqCst), t1);

    // Release upstream response; proxy must sample clock AFTER reload -> observes t2 -> permitted.
    release_list_tx.send(()).unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(clock_val.load(Ordering::SeqCst), t2);
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["tools"], json!([{"name": "merge_pr"}]));

    drop(client_to_proxy);
    proxy_handle.join().unwrap();
    up_handle.join().unwrap();
}

#[cfg(unix)]
#[test]
fn hot_reload_fifo_at_startup_and_live_replacement_fail_promptly_without_hanging() {
    use std::process::Command;

    let alice = Ed25519Keypair::from_secret_bytes([0x87; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0x88; 32]);
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let now = ts("2026-11-26T14:00:00Z");

    // 1. Writerless FIFO at startup must fail promptly without blocking in open(2).
    let startup_dir = tempfile::TempDir::new().unwrap();
    let startup_fifo = startup_dir.path().join("startup.fifo");
    assert!(Command::new("mkfifo")
        .arg(&startup_fifo)
        .status()
        .expect("mkfifo")
        .success());
    let agent_key = agent.key_id();
    let startup_db = startup_dir.path().join("startup.sqlite");
    let fifo_for_thread = startup_fifo.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let ledger = SqliteLedger::open(&startup_db).unwrap();
        let res = McpProxy::from_chain_files(
            vec![fifo_for_thread],
            agent_key,
            sample_policy_map(),
            ledger,
            FixedClock::new(now),
        );
        let _ = tx.send(res.map(|_| ()));
    });
    let startup_err = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("from_chain_files on FIFO must never hang")
        .unwrap_err();
    assert!(
        matches!(startup_err, ProxyError::Io(ref err) if err.to_string().contains("not a regular file")),
        "expected regular-file error on startup FIFO, got {startup_err:?}"
    );

    // 2. Replace live watched regular chain file with a writerless FIFO across 2 sequential calls.
    let valid = sign_root(&alice, &agent, 5, vf, vu);
    let mut h = LiveProxyHarness::start(&valid, &agent, now, None);
    assert_eq!(h.call_merge(1)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 1);

    let tmp_fifo = h.chain_path.with_extension("fifo.tmp");
    assert!(Command::new("mkfifo")
        .arg(&tmp_fifo)
        .status()
        .expect("mkfifo")
        .success());
    fs::rename(&tmp_fifo, &h.chain_path).unwrap();

    // Run 2 sequential tools/call requests under a strict 2-second watchdog so any hang fails fast.
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let h2 = h.assert_reload_denied(2, "not a regular file", 1);
        let h3 = h.assert_reload_denied(3, "not a regular file", 1);
        assert_ne!(h2, h3);
        let _ = done_tx.send(h);
    });
    let mut h = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("2 sequential tools/call requests against a FIFO must not hang");
    worker.join().unwrap();

    // Restore regular file -> recovers cleanly.
    atomic_write_json(
        &h.chain_path,
        &serde_json::to_string_pretty(&valid).unwrap(),
    );
    assert_eq!(h.call_merge(4)["result"]["ok"], true);
    assert_eq!(h.forwarded.load(Ordering::SeqCst), 2);
    h.shutdown();
}
