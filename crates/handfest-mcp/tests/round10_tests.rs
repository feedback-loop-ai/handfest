//! Round 10 zero-residual regression tests for `handfest-mcp`.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use handfest_anchors::Ed25519Keypair;
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::VerifiedMandate;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{
    verify_mandate_chain, FixedClock, McpProxy, ProxyError, ToolPolicyMap,
    HANDFEST_DENIED_ERROR_CODE,
};
use serde_json::{json, Value};

#[derive(Default)]
struct PipeInner {
    buf: VecDeque<u8>,
    closed: bool,
}

#[derive(Clone)]
struct PipeWriter(Arc<(Mutex<PipeInner>, Condvar)>);

struct PipeReader {
    state: Arc<(Mutex<PipeInner>, Condvar)>,
}

fn mem_pipe() -> (PipeWriter, BufReader<PipeReader>) {
    let state = Arc::new((Mutex::new(PipeInner::default()), Condvar::new()));
    (
        PipeWriter(Arc::clone(&state)),
        BufReader::new(PipeReader { state }),
    )
}

impl Write for PipeWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let (lock, cv) = &*self.0;
        let mut inner = lock.lock().unwrap();
        inner.buf.extend(data);
        cv.notify_all();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        let (lock, cv) = &*self.0;
        let mut inner = lock.lock().unwrap();
        inner.closed = true;
        cv.notify_all();
    }
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let (lock, cv) = &*self.state;
        let mut inner = lock.lock().unwrap();
        while inner.buf.is_empty() && !inner.closed {
            inner = cv.wait(inner).unwrap();
        }
        let n = inner.buf.len().min(out.len());
        for slot in &mut out[..n] {
            *slot = inner.buf.pop_front().unwrap();
        }
        Ok(n)
    }
}

fn read_line_timeout(reader: &mut BufReader<PipeReader>, timeout: Duration, label: &str) -> String {
    let deadline = Instant::now() + timeout;
    let mut line = Vec::new();
    let (lock, cv) = &*reader.get_ref().state;
    loop {
        let mut inner = lock.lock().unwrap();
        while inner.buf.is_empty() && !inner.closed {
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(!rem.is_zero(), "timed out waiting for {label}");
            let (guard, _) = cv.wait_timeout(inner, rem).unwrap();
            inner = guard;
        }
        while let Some(b) = inner.buf.pop_front() {
            line.push(b);
            if b == b'\n' {
                return String::from_utf8(line).unwrap();
            }
        }
        if inner.closed {
            return String::from_utf8(line).unwrap();
        }
    }
}

fn sign_mandate(
    signer: &Ed25519Keypair,
    text: &str,
    valid_from: i64,
    valid_until: i64,
) -> handfest_anchors::SignedMandate {
    let ast = parse_mandate(text).expect("valid mandate");
    let canonical = try_render_canonical(&ast).expect("canonical");
    signer
        .sign_mandate(&canonical, "anchor-r10", valid_from, valid_until)
        .expect("sign")
}

fn build_single_hop(
    allow: &str,
    on_clause: &str,
    where_clause: &str,
) -> (Vec<VerifiedMandate>, Ed25519Keypair, i64) {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let mandate_text = format!(
        "HANDFEST v1\n\
         FROM human \"Admin\" (key: {root})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW {allow}\n\
         ON {on_clause}\n\
         {where_clause}",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let signed = sign_mandate(&root_kp, &mandate_text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();
    (verified, agent_kp, now)
}

#[test]
fn round10_denies_negative_zero_and_leading_zero_decimal_facts_and_never_forwards_upstream() {
    let (verified, agent_kp, now) = build_single_hop(
        "finance.pay",
        "account \"acct-*\"",
        "WHERE resource.amount >= 0.0\n",
    );
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{"tools":{"pay":{"action":"finance.pay","resource_kind":"account","resource_id_arg":"acct","arg_facts":{"amount":{"field":"resource.amount","type":"decimal"}}}}}"#,
    )
    .unwrap();
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        policy_map,
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let res = proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r);
        let _ = done_tx.send((proxy, res));
    });

    let bad_amounts = [
        "-0",
        "-0.0",
        "-0e5",
        r#""-0""#,
        r#""-0.00""#,
        r#""010""#,
        r#""0100""#,
        r#""-010""#,
    ];
    for (idx, amount_literal) in bad_amounts.iter().enumerate() {
        let id = idx + 1;
        writeln!(
            client_in_w,
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"pay","arguments":{{"acct":"acct-1","amount":{amount_literal}}}}}}}"#
        )
        .unwrap();
        let line = read_line_timeout(&mut client_out_r, Duration::from_secs(2), "decimal denial");
        let resp: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(resp["id"], json!(id));
        assert_eq!(
            resp["error"]["code"],
            json!(HANDFEST_DENIED_ERROR_CODE),
            "bad decimal {amount_literal} must be denied with -32001, got {resp}"
        );
        assert!(resp["error"]["data"]["receipt_hash"].is_string());
    }

    let valid_id = bad_amounts.len() + 1;
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","id":{valid_id},"method":"tools/call","params":{{"name":"pay","arguments":{{"acct":"acct-1","amount":"10.50"}}}}}}"#
    )
    .unwrap();
    let fwd_line = read_line_timeout(&mut up_in_r, Duration::from_secs(2), "valid decimal fwd");
    let fwd: Value = serde_json::from_str(fwd_line.trim_end()).unwrap();
    assert_eq!(fwd["id"], json!(valid_id));

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":{valid_id},"result":{{"paid":true}}}}"#
    )
    .unwrap();
    let ok_line = read_line_timeout(&mut client_out_r, Duration::from_secs(2), "valid reply");
    assert_eq!(
        serde_json::from_str::<Value>(ok_line.trim_end()).unwrap()["result"]["paid"],
        json!(true)
    );

    drop(client_in_w);
    drop(up_out_w);
    let (proxy, res) = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    handle.join().unwrap();
    res.expect("session exited cleanly");
    assert_eq!(
        proxy.ledger().verify_integrity().unwrap(),
        bad_amounts.len() + 1
    );
}

#[test]
fn round10_tools_list_rejects_malformed_names_and_nested_key_collisions_with_32603() {
    let (verified, agent_kp, now) = build_single_hop("ops.deploy", "target \"staging\"", "");
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{"tools":{"deploy_staging":{"action":"ops.deploy","resource_kind":"target","static_resource_id":"staging"}}}"#,
    )
    .unwrap();

    let malformed_responses = [
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":123}]}}"#,
            "missing or non-string 'name'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":""}]}}"#,
            "'name' must not be empty",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"description":"missing name"}]}}"#,
            "missing or non-string 'name'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"deploy_staging","inputSchema":{"type":"object","properties":{"env":{"type":"string"},"ENV":{"type":"string"}}}}]}}"#,
            "collides case-insensitively",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"deploy_staging","inputSchema":{"anyOf":[{"type":"string","TYPE":"number"}]}}]}}"#,
            "collides case-insensitively",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"deploy_staging","inputSchema":{"properties":{"re\u017fpo":{"type":"string"}}}}]}}"#,
            "non-ASCII key",
        ),
    ];

    for (raw_resp, expected_substr) in malformed_responses {
        let mut proxy = McpProxy::new(
            verified.clone(),
            agent_kp.key_id(),
            policy_map.clone(),
            SqliteLedger::open_in_memory().unwrap(),
            FixedClock::new(now),
        )
        .unwrap();
        let client_in = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        let (up_in_w, mut up_in_r) = mem_pipe();
        let (mut up_out_w, up_out_r) = mem_pipe();
        let resp_owned = raw_resp.to_string();
        let upstream = thread::spawn(move || {
            let mut req = String::new();
            up_in_r.read_line(&mut req).unwrap();
            writeln!(up_out_w, "{resp_owned}").unwrap();
        });

        let mut client_out = Vec::new();
        let res = proxy.run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            up_in_w,
            up_out_r,
        );
        upstream.join().unwrap();
        assert!(
            matches!(res, Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains(expected_substr)),
            "expected UpstreamProtocol containing {expected_substr:?} for {raw_resp}, got {res:?}"
        );
        let parsed: Value =
            serde_json::from_str(String::from_utf8(client_out).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["id"], json!(1));
        assert_eq!(parsed["error"]["code"], json!(-32603));
    }
}

#[test]
fn round10_tools_list_filters_static_resource_id_mismatch_and_expired_chain_once() {
    let (verified, agent_kp, now) = build_single_hop("ops.deploy", "target \"staging\"", "");
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "deploy_staging": {
                    "action": "ops.deploy",
                    "resource_kind": "target",
                    "static_resource_id": "staging"
                },
                "deploy_prod": {
                    "action": "ops.deploy",
                    "resource_kind": "target",
                    "static_resource_id": "prod"
                },
                "deploy_wrong_kind": {
                    "action": "ops.deploy",
                    "resource_kind": "cluster",
                    "static_resource_id": "staging"
                }
            }
        }"#,
    )
    .unwrap();

    let run_list = |eval_time: i64| -> Vec<Value> {
        let mut proxy = McpProxy::new(
            verified.clone(),
            agent_kp.key_id(),
            policy_map.clone(),
            SqliteLedger::open_in_memory().unwrap(),
            FixedClock::new(eval_time),
        )
        .unwrap();
        let client_in = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
        let (up_in_w, mut up_in_r) = mem_pipe();
        let (mut up_out_w, up_out_r) = mem_pipe();
        let upstream = thread::spawn(move || {
            let mut req = String::new();
            up_in_r.read_line(&mut req).unwrap();
            writeln!(
                up_out_w,
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{{"name":"deploy_staging","inputSchema":{{"type":"object"}}}},{{"name":"deploy_prod","inputSchema":{{"type":"object"}}}},{{"name":"deploy_wrong_kind","inputSchema":{{"type":"object"}}}}]}}}}"#
            )
            .unwrap();
        });
        let mut client_out = Vec::new();
        proxy
            .run(
                BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
                &mut client_out,
                up_in_w,
                up_out_r,
            )
            .expect("filtered tools/list must succeed");
        upstream.join().unwrap();
        let parsed: Value =
            serde_json::from_str(String::from_utf8(client_out).unwrap().trim_end()).unwrap();
        parsed["result"]["tools"].as_array().unwrap().clone()
    };

    // Valid timestamp: deploy_prod ("prod") hidden under ON target "staging"; deploy_staging shown.
    let active_tools = run_list(now);
    assert_eq!(active_tools.len(), 1);
    assert_eq!(active_tools[0]["name"], json!("deploy_staging"));

    // Expired timestamp: entire tools list cleared cleanly via single chain validation.
    let expired_time = parse_rfc3339_utc("2028-01-01T00:00:00Z").unwrap();
    let expired_tools = run_list(expired_time);
    assert!(expired_tools.is_empty());
}

#[test]
fn round10_post_eof_drain_surfaces_broken_pipe_from_upstream_writer() {
    struct DelayedBrokenPipeWriter {
        entered_tx: Option<mpsc::SyncSender<()>>,
        release_rx: Option<mpsc::Receiver<()>>,
    }
    impl Write for DelayedBrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            if let Some(tx) = self.entered_tx.take() {
                let _ = tx.send(());
            }
            if let Some(rx) = self.release_rx.take() {
                let _ = rx.recv();
            }
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "post-eof upstream broken pipe",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct SilentReader(mpsc::Receiver<()>);
    impl Read for SilentReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    let (verified, agent_kp, now) = build_single_hop("ops.run", "target \"staging\"", "");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        ToolPolicyMap::from_json_str(r#"{"tools":{}}"#).unwrap(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap()
    .with_shutdown_timeout(Duration::from_millis(80));

    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let client_in = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";

    let handle = thread::spawn(move || {
        let mut client_out = Vec::new();
        let res = proxy.run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            DelayedBrokenPipeWriter {
                entered_tx: Some(entered_tx),
                release_rx: Some(release_rx),
            },
            BufReader::new(SilentReader(up_hold_rx)),
        );
        let _ = done_tx.send(res);
    });

    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer thread entered write");
    release_tx.send(()).unwrap();
    let res = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exited");
    handle.join().unwrap();
    assert!(
        matches!(res, Err(ProxyError::Io(ref err)) if err.kind() == io::ErrorKind::BrokenPipe),
        "expected ProxyError::Io(BrokenPipe), got {res:?}"
    );
}
