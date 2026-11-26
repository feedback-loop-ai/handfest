use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;

use handfest_anchors::{
    AnchorError, AnchorVerifier, AssuranceLevel, Ed25519Keypair, SignedMandate,
};
use handfest_core::ast::{parse_rfc3339_utc, KeyId};
use handfest_core::cnl::{parse_canonical, parse_mandate, try_render_canonical};
use handfest_core::gate::{VerifiedAnchorProof, VerifiedMandate};
use handfest_core::ActorKind;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{
    verify_mandate_chain, verify_mandate_chain_with, FixedClock, McpProxy, ProxyError,
    ToolPolicyMap,
};
use serde_json::{json, Value};

#[derive(Default)]
struct PipeBuf {
    data: VecDeque<u8>,
    closed: bool,
}

#[derive(Clone, Default)]
struct SharedPipe {
    inner: Arc<(Mutex<PipeBuf>, Condvar)>,
}

struct PipeWriter(SharedPipe);
struct PipeReader(SharedPipe);

fn mem_pipe() -> (PipeWriter, BufReader<PipeReader>) {
    let pipe = SharedPipe::default();
    (PipeWriter(pipe.clone()), BufReader::new(PipeReader(pipe)))
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (lock, cv) = &*self.0.inner;
        let mut guard = lock.lock().unwrap();
        guard.data.extend(buf);
        cv.notify_all();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        let (lock, cv) = &*self.0.inner;
        let mut guard = lock.lock().unwrap();
        guard.closed = true;
        cv.notify_all();
    }
}

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (lock, cv) = &*self.0.inner;
        let mut guard = lock.lock().unwrap();
        while guard.data.is_empty() && !guard.closed {
            guard = cv.wait(guard).unwrap();
        }
        let mut n = 0;
        while n < buf.len() {
            if let Some(b) = guard.data.pop_front() {
                buf[n] = b;
                n += 1;
            } else {
                break;
            }
        }
        Ok(n)
    }
}

fn build_single_hop(
    allow: &str,
    on_clause: &str,
    where_block: &str,
) -> (Vec<VerifiedMandate>, Ed25519Keypair, i64) {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Root\" (key: {})\n\
         TO agent \"Agent\" (key: {})\n\
         DELEGATION max 0 hops\n\
         ALLOW {allow}\n\
         ON {on_clause}\n\
         {where_block}",
        root_kp.key_id(),
        agent_kp.key_id(),
    );
    let signed = root_kp
        .sign_mandate(&text, "r11-test", valid_from, valid_until)
        .unwrap();
    let verified = verify_mandate_chain(&[signed]).unwrap();
    (verified, agent_kp, now)
}

const MALFORMED_CANCELS: &[&str] = &[
    r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":123}}"#,
    r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":null}}"#,
    r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"_meta":123}}"#,
    r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"_meta":{"a":1,"A":2}}}"#,
    r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"_meta":{"re\u017fpo":1}}}"#,
];

struct LineCountingWriter {
    buf: Vec<u8>,
    lines: usize,
    threshold: usize,
    reached_tx: Option<mpsc::SyncSender<()>>,
}

impl Write for LineCountingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        self.lines += data.iter().filter(|&&b| b == b'\n').count();
        if self.lines >= self.threshold {
            if let Some(tx) = self.reached_tx.take() {
                let _ = tx.send(());
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const FENCE_NOTIF: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

#[test]
fn round11_malformed_cancel_reason_and_meta_preserve_active_request_and_do_not_forward() {
    for &bad_cancel in MALFORMED_CANCELS {
        let (verified, agent_kp, now) = build_single_hop("ops.run", "target \"staging\"", "");
        let mut proxy = McpProxy::new(
            verified,
            agent_kp.key_id(),
            ToolPolicyMap::from_json_str(r#"{"tools":{}}"#).unwrap(),
            SqliteLedger::open_in_memory().unwrap(),
            FixedClock::new(now),
        )
        .unwrap();

        let (mut client_w, client_r) = mem_pipe();
        let (up_in_w, mut up_in_r) = mem_pipe();
        let (mut up_out_w, up_out_r) = mem_pipe();
        let (ping_seen_tx, ping_seen_rx) = mpsc::sync_channel(1);
        let (fence_seen_tx, fence_seen_rx) = mpsc::sync_channel(1);

        let upstream = thread::spawn(move || {
            let mut forwarded = Vec::new();
            let mut line = String::new();
            assert!(up_in_r.read_line(&mut line).unwrap() > 0);
            forwarded.push(line.trim_end().to_string());
            ping_seen_tx.send(()).unwrap();

            // Wait until the FIFO fence arrives AFTER the proxy processed `bad_cancel` while id=1 is active.
            loop {
                line.clear();
                assert!(up_in_r.read_line(&mut line).unwrap() > 0);
                let trimmed = line.trim_end().to_string();
                let is_fence = trimmed == FENCE_NOTIF;
                forwarded.push(trimmed);
                if is_fence {
                    break;
                }
            }
            fence_seen_tx.send(()).unwrap();

            writeln!(
                up_out_w,
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"ok":true}}}}"#
            )
            .unwrap();
            loop {
                line.clear();
                if up_in_r.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                forwarded.push(line.trim_end().to_string());
            }
            forwarded
        });

        let bad_cancel_owned = bad_cancel.to_string();
        let client = thread::spawn(move || {
            writeln!(client_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
            ping_seen_rx.recv().unwrap();
            writeln!(client_w, "{bad_cancel_owned}").unwrap();
            writeln!(client_w, "{FENCE_NOTIF}").unwrap();
            fence_seen_rx.recv().unwrap();
        });

        let mut client_out = Vec::new();
        proxy
            .run(client_r, &mut client_out, up_in_w, up_out_r)
            .expect("session with malformed cancel must stay healthy");
        client.join().unwrap();
        let forwarded = upstream.join().unwrap();

        assert_eq!(
            forwarded,
            vec![r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#, FENCE_NOTIF],
            "malformed cancel {bad_cancel} must NOT be forwarded upstream"
        );
        let resp: Value =
            serde_json::from_str(String::from_utf8(client_out).unwrap().trim()).unwrap();
        assert_eq!(resp, json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}}));
    }
}

#[test]
fn round11_malformed_cancel_preserves_interleaved_budget() {
    for &bad_cancel in MALFORMED_CANCELS {
        let (verified, agent_kp, now) = build_single_hop("ops.run", "target \"staging\"", "");
        let mut proxy = McpProxy::new(
            verified,
            agent_kp.key_id(),
            ToolPolicyMap::from_json_str(r#"{"tools":{}}"#).unwrap(),
            SqliteLedger::open_in_memory().unwrap(),
            FixedClock::new(now),
        )
        .unwrap();

        let (mut client_w, client_r) = mem_pipe();
        let (up_in_w, mut up_in_r) = mem_pipe();
        let (mut up_out_w, up_out_r) = mem_pipe();
        let (six_hundred_tx, six_hundred_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);

        let upstream = thread::spawn(move || {
            let mut line = String::new();
            assert!(up_in_r.read_line(&mut line).unwrap() > 0);
            for i in 0..600 {
                writeln!(
                    up_out_w,
                    r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"n":{i}}}}}"#
                )
                .unwrap();
            }
            // Wait until the FIFO fence arrives, proving `bad_cancel` was processed strictly
            // AFTER the proxy forwarded all 600 progress frames.
            loop {
                line.clear();
                if up_in_r.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.trim_end() == FENCE_NOTIF {
                    break;
                }
            }
            // Send ONLY 425 more frames (600 + 425 = 1025 > 1024, while 425 < 1024).
            for i in 600..1025 {
                if writeln!(
                    up_out_w,
                    r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"n":{i}}}}}"#
                )
                .is_err()
                {
                    break;
                }
            }
            let _ = writeln!(
                up_out_w,
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"ok":true}}}}"#
            );
            let _ = done_tx.send(());
        });

        let bad_cancel_owned = bad_cancel.to_string();
        let client = thread::spawn(move || {
            writeln!(client_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
            six_hundred_rx.recv().unwrap();
            writeln!(client_w, "{bad_cancel_owned}").unwrap();
            writeln!(client_w, "{FENCE_NOTIF}").unwrap();
            let _ = done_rx.recv();
        });

        let mut client_out = LineCountingWriter {
            buf: Vec::new(),
            lines: 0,
            threshold: 600,
            reached_tx: Some(six_hundred_tx),
        };
        let res = proxy.run(client_r, &mut client_out, up_in_w, up_out_r);
        client.join().unwrap();
        upstream.join().unwrap();
        assert!(
            matches!(
                res,
                Err(ProxyError::UpstreamProtocol(ref msg))
                    if msg.contains("exceeded maximum interleaved messages")
            ),
            "interleaved budget must remain enforced after {bad_cancel}, got {res:?}"
        );
    }
}

#[test]
fn round11_valid_cancel_reason_and_meta_cancels_and_forwards() {
    // Positive control: valid reason string + valid _meta object cancels and forwards.
    let (verified, agent_kp, now) = build_single_hop("ops.run", "target \"staging\"", "");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        ToolPolicyMap::from_json_str(r#"{"tools":{}}"#).unwrap(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let (mut client_w, client_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (ping_tx, ping_rx) = mpsc::sync_channel(1);
    let valid_cancel = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"user abort","_meta":{"traceId":"abc"}}}"#;
    let upstream = thread::spawn(move || {
        let mut lines = Vec::new();
        for _ in 0..3 {
            let mut buf = String::new();
            up_in_r.read_line(&mut buf).unwrap();
            lines.push(buf.trim_end().to_string());
            if lines.len() == 1 {
                ping_tx.send(()).unwrap();
            }
        }
        writeln!(
            up_out_w,
            r#"{{"jsonrpc":"2.0","id":2,"result":{{"ok":true}}}}"#
        )
        .unwrap();
        lines
    });
    let client = thread::spawn(move || {
        writeln!(client_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        ping_rx.recv().unwrap();
        writeln!(client_w, "{valid_cancel}").unwrap();
        writeln!(client_w, r#"{{"jsonrpc":"2.0","id":2,"method":"ping"}}"#).unwrap();
    });
    let mut client_out = Vec::new();
    proxy
        .run(client_r, &mut client_out, up_in_w, up_out_r)
        .expect("valid cancel must succeed");
    client.join().unwrap();
    let lines = upstream.join().unwrap();
    assert_eq!(lines[1], valid_cancel);
    let resp: Value = serde_json::from_str(String::from_utf8(client_out).unwrap().trim()).unwrap();
    assert_eq!(resp["id"], json!(2));
}

struct CustomMutatingVerifier {
    override_assurance: Option<AssuranceLevel>,
    override_anchor_id: Option<String>,
    override_window: Option<(i64, i64)>,
    override_ast: Option<handfest_core::ast::HandfestAst>,
}

impl AnchorVerifier for CustomMutatingVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        let ast = match &self.override_ast {
            Some(a) => a.clone(),
            None => parse_canonical(&signed.canonical_words)
                .map_err(AnchorError::NonCanonicalMandate)?,
        };
        let (valid_from, valid_until) = self
            .override_window
            .unwrap_or((signed.valid_from, signed.valid_until));
        Ok(VerifiedMandate {
            ast,
            proof: VerifiedAnchorProof {
                anchor_id: self
                    .override_anchor_id
                    .clone()
                    .unwrap_or_else(|| signed.anchor_id.clone()),
                assurance: self.override_assurance.unwrap_or(AssuranceLevel::Passkey),
                signer_key: KeyId::parse(&signed.signer_key).unwrap(),
                actor_kind: ActorKind::Human,
                valid_from,
                valid_until,
            },
        })
    }
}

#[test]
fn round11_verify_mandate_chain_with_enforces_postconditions_on_custom_verifier() {
    let from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let ast = parse_mandate(
        "HANDFEST v1\n\
         FROM human \"Root\" (key: passkey:cred1)\n\
         TO agent \"Leaf\" (key: passkey:agent1)\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/*\"\n",
    )
    .unwrap();
    let signed = SignedMandate {
        canonical_words: try_render_canonical(&ast).unwrap(),
        anchor_id: "passkey-1".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: "passkey:cred1".to_string(),
        valid_from: from,
        valid_until: until,
        signature_hex: "00".repeat(64),
    };

    let v_assurance = CustomMutatingVerifier {
        override_assurance: Some(AssuranceLevel::QualifiedQes),
        override_anchor_id: None,
        override_window: None,
        override_ast: None,
    };
    assert!(matches!(
        verify_mandate_chain_with(&v_assurance, std::slice::from_ref(&signed)),
        Err(ProxyError::Anchor(AnchorError::ChainHop { hop: 0, ref source }))
            if matches!(source.as_ref(), AnchorError::UnsupportedAssurance { .. })
    ));

    let v_anchor = CustomMutatingVerifier {
        override_assurance: None,
        override_anchor_id: Some("bad\nid".to_string()),
        override_window: None,
        override_ast: None,
    };
    assert!(matches!(
        verify_mandate_chain_with(&v_anchor, std::slice::from_ref(&signed)),
        Err(ProxyError::Anchor(AnchorError::ChainHop { hop: 0, ref source }))
            if matches!(source.as_ref(), AnchorError::InvalidAnchorId(_))
    ));

    let v_window = CustomMutatingVerifier {
        override_assurance: None,
        override_anchor_id: None,
        override_window: Some((from, until + 1)),
        override_ast: None,
    };
    assert!(matches!(
        verify_mandate_chain_with(&v_window, std::slice::from_ref(&signed)),
        Err(ProxyError::Anchor(AnchorError::ChainHop { hop: 0, ref source }))
            if matches!(
                source.as_ref(),
                AnchorError::ValidityWindowMismatch {
                    expected_from,
                    expected_until,
                    actual_from,
                    actual_until,
                } if *expected_from == from
                    && *expected_until == until
                    && *actual_from == from
                    && *actual_until == until + 1
            )
    ));

    let widened_ast = parse_mandate(
        "HANDFEST v1\n\
         FROM human \"Root\" (key: passkey:cred1)\n\
         TO agent \"Leaf\" (key: passkey:agent1)\n\
         DELEGATION max 0 hops\n\
         ALLOW git.*\n\
         ON repo \"org/*\"\n",
    )
    .unwrap();
    let v_ast = CustomMutatingVerifier {
        override_assurance: None,
        override_anchor_id: None,
        override_window: None,
        override_ast: Some(widened_ast),
    };
    assert!(matches!(
        verify_mandate_chain_with(&v_ast, &[signed]),
        Err(ProxyError::Anchor(AnchorError::ChainHop { hop: 0, ref source }))
            if matches!(source.as_ref(), AnchorError::NonCanonicalMandate(_))
    ));
}

fn run_tools_list_once(
    verified: &[VerifiedMandate],
    agent_kp: &Ed25519Keypair,
    policy_map: &ToolPolicyMap,
    eval_time: i64,
    raw_resp: &str,
) -> (Result<(), ProxyError>, String) {
    let mut proxy = McpProxy::new(
        verified.to_vec(),
        agent_kp.key_id(),
        policy_map.clone(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(eval_time),
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
    (res, String::from_utf8(client_out).unwrap())
}

#[test]
fn round11_tools_list_filters_dynamic_resource_kind_and_decidable_where_clauses() {
    let (verified, agent_kp, now) = build_single_hop(
        "ops.exec",
        "sandbox \"*\"",
        "WHERE cmd.safe == true\n  AND context.time < 2026-07-01T00:00:00Z\n  AND env == \"staging\"\n",
    );
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "run_sandbox": {
                    "action": "ops.exec",
                    "resource_kind": "sandbox",
                    "resource_id_arg": "id",
                    "arg_facts": { "safe": { "field": "cmd.safe", "type": "bool" } },
                    "static_facts": { "env": { "str": "staging" } }
                },
                "run_database": {
                    "action": "ops.exec",
                    "resource_kind": "database",
                    "resource_id_arg": "id",
                    "static_facts": { "env": { "str": "staging" } }
                },
                "run_sandbox_prod": {
                    "action": "ops.exec",
                    "resource_kind": "sandbox",
                    "resource_id_arg": "id",
                    "static_facts": { "env": { "str": "prod" } }
                }
            }
        }"#,
    )
    .unwrap();
    let valid_resp = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"run_sandbox"},{"name":"run_database"},{"name":"run_sandbox_prod"}],"nextCursor":"page-2","_meta":{"cursorVersion":1}}}"#;

    let (res_ok, out_ok) = run_tools_list_once(&verified, &agent_kp, &policy_map, now, valid_resp);
    res_ok.expect("valid tools/list with nextCursor and _meta must succeed");
    let parsed_ok: Value = serde_json::from_str(out_ok.trim()).unwrap();
    let tools = parsed_ok["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], json!("run_sandbox"));
    assert_eq!(parsed_ok["result"]["nextCursor"], json!("page-2"));
    assert_eq!(parsed_ok["result"]["_meta"]["cursorVersion"], json!(1));

    let past_where_deadline = parse_rfc3339_utc("2026-08-01T00:00:00Z").unwrap();
    let (res_past, out_past) = run_tools_list_once(
        &verified,
        &agent_kp,
        &policy_map,
        past_where_deadline,
        valid_resp,
    );
    res_past.expect("expired WHERE tools/list must succeed with empty list");
    let parsed_past: Value = serde_json::from_str(out_past.trim()).unwrap();
    assert!(parsed_past["result"]["tools"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn round11_tools_list_validates_next_cursor_and_meta() {
    let (verified, agent_kp, now) = build_single_hop("ops.exec", "sandbox \"*\"", "");
    let policy_map = ToolPolicyMap::from_json_str(r#"{"tools":{}}"#).unwrap();

    for (bad_resp, expected_substr) in [
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[],"nextCursor":123}}"#,
            "result.nextCursor must be a string",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":123}}"#,
            "result._meta must be a JSON object",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":{"a":1,"A":2}}}"#,
            "collides case-insensitively",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":{"re\u017fpo":1}}}"#,
            "non-ASCII key",
        ),
    ] {
        let (res, out) = run_tools_list_once(&verified, &agent_kp, &policy_map, now, bad_resp);
        assert!(
            matches!(res, Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains(expected_substr)),
            "expected UpstreamProtocol containing {expected_substr:?} for {bad_resp}, got {res:?}"
        );
        let parsed: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(parsed["id"], json!(1));
        assert_eq!(parsed["error"]["code"], json!(-32603));
    }
}

#[test]
fn round11_tools_call_rejects_malformed_meta_without_consuming_quota_or_forwarding() {
    let (verified, agent_kp, now) =
        build_single_hop("ops.exec", "sandbox \"main\"", "LIMIT 1 call\n");
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{"tools":{"run_sandbox":{"action":"ops.exec","resource_kind":"sandbox","static_resource_id":"main"}}}"#,
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

    let malformed_calls = [
        (
            1,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_sandbox","arguments":{},"_meta":123}}"#,
            "tools/call params._meta must be a JSON object",
        ),
        (
            2,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_sandbox","arguments":{},"_meta":null}}"#,
            "tools/call params._meta must be a JSON object",
        ),
        (
            3,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_sandbox","arguments":{},"_meta":{"a":1,"A":2}}}"#,
            "collides case-insensitively",
        ),
        (
            4,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_sandbox","arguments":{},"_meta":{"nested":[{"x":1,"X":2}]}}}"#,
            "collides case-insensitively",
        ),
        (
            5,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_sandbox","arguments":{},"_meta":{"re\u017fpo":1}}}"#,
            "non-ASCII key",
        ),
    ];

    let valid_call = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run_sandbox","arguments":{},"_meta":{"traceId":"ok"}}}"#;
    let over_quota = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_sandbox","arguments":{},"_meta":{"traceId":"second"}}}"#;
    let mut client_script: String = malformed_calls
        .iter()
        .map(|(_, f, _)| format!("{f}\n"))
        .collect();
    client_script.push_str(&format!("{valid_call}\n{over_quota}\n"));

    let (client_out, forwarded) = run_echo_ok_upstream(&mut proxy, client_script, 6);
    assert_eq!(forwarded, vec![valid_call]);

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 7);
    for (idx, (id, _, expected)) in malformed_calls.iter().enumerate() {
        assert_eq!(responses[idx]["id"], json!(id));
        assert_eq!(responses[idx]["error"]["code"], json!(-32001));
        assert!(responses[idx]["error"]["data"]["reason"]
            .as_str()
            .unwrap()
            .contains(expected));
    }
    assert_eq!(
        responses[5],
        json!({"jsonrpc":"2.0","id":6,"result":{"ok":true}})
    );
    assert_eq!(responses[6]["id"], json!(7));
    assert_eq!(responses[6]["error"]["code"], json!(-32001));
    assert!(responses[6]["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("quota"));
}

#[test]
fn round11_wire_refusal_oversized_upstream_and_invalid_utf8_frames() {
    let (verified, agent_kp, now) = build_single_hop("ops.exec", "sandbox \"*\"", "");
    let policy_map = ToolPolicyMap::from_json_str(r#"{"tools":{}}"#).unwrap();

    // Oversized upstream frame emits -32603 and returns ProxyError::UpstreamFrameTooLarge.
    let mut proxy = McpProxy::new(
        verified.clone(),
        agent_kp.key_id(),
        policy_map.clone(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap()
    .with_max_line_bytes(64)
    .unwrap();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut req = String::new();
        up_in_r.read_line(&mut req).unwrap();
        let big = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"pad":"{}"}}}}"#,
            "x".repeat(80)
        );
        writeln!(up_out_w, "{big}").unwrap();
    });
    let mut client_out = Vec::new();
    let res = proxy.run(
        BufReader::new(Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".to_vec(),
        )),
        &mut client_out,
        up_in_w,
        up_out_r,
    );
    upstream.join().unwrap();
    assert!(matches!(
        res,
        Err(ProxyError::UpstreamFrameTooLarge { max_bytes: 64 })
    ));
    let err_resp: Value =
        serde_json::from_str(String::from_utf8(client_out).unwrap().trim()).unwrap();
    assert_eq!(err_resp["id"], json!(1));
    assert_eq!(err_resp["error"]["code"], json!(-32603));

    // Invalid UTF-8 from client yields -32700; invalid UTF-8 from upstream yields -32603 + error.
    let mut proxy2 = McpProxy::new(
        verified,
        agent_kp.key_id(),
        policy_map,
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let (up_in_w2, mut up_in_r2) = mem_pipe();
    let (mut up_out_w2, up_out_r2) = mem_pipe();
    let upstream2 = thread::spawn(move || {
        let mut req = String::new();
        up_in_r2.read_line(&mut req).unwrap();
        up_out_w2.write_all(b"\xff\xfe\n").unwrap();
    });
    let mut client_bytes = b"\xff\xfe\n".to_vec();
    client_bytes.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n");
    let mut client_out2 = Vec::new();
    let res2 = proxy2.run(
        BufReader::new(Cursor::new(client_bytes)),
        &mut client_out2,
        up_in_w2,
        up_out_r2,
    );
    upstream2.join().unwrap();
    assert!(matches!(
        res2,
        Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains("non-UTF-8")
    ));
    let lines: Vec<Value> = String::from_utf8(client_out2)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["id"], Value::Null);
    assert_eq!(lines[0]["error"]["code"], json!(-32700));
    assert!(lines[0]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("invalid UTF-8"));
    assert_eq!(lines[1]["id"], json!(2));
    assert_eq!(lines[1]["error"]["code"], json!(-32603));
}

#[test]
fn round11_wire_refusal_malformed_tools_list_payloads() {
    let (verified, agent_kp, now) = build_single_hop("ops.exec", "sandbox \"*\"", "");
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{"tools":{"run_sandbox":{"action":"ops.exec","resource_kind":"sandbox","static_resource_id":"main"}}}"#,
    )
    .unwrap();

    for (bad_resp, expected_substr) in [
        (
            r#"{"jsonrpc":"2.0","id":1,"result":123}"#,
            "missing result object",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            "missing result.tools array",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":{}}}"#,
            "missing result.tools array",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[123]}}"#,
            "expected JSON object",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{}]}}"#,
            "missing or non-string 'name'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":42}]}}"#,
            "missing or non-string 'name'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":""}]}}"#,
            "'name' must not be empty",
        ),
    ] {
        let (res, out) = run_tools_list_once(&verified, &agent_kp, &policy_map, now, bad_resp);
        assert!(
            matches!(res, Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains(expected_substr)),
            "expected UpstreamProtocol containing {expected_substr:?} for {bad_resp}, got {res:?}"
        );
        let parsed: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(parsed["id"], json!(1));
        assert_eq!(parsed["error"]["code"], json!(-32603));
    }
}

#[test]
fn round11_wire_refusal_malformed_tools_call_params() {
    let (verified, agent_kp, now) = build_single_hop("ops.exec", "sandbox \"*\"", "");
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{"tools":{"run_sandbox":{"action":"ops.exec","resource_kind":"sandbox","static_resource_id":"main"}}}"#,
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
    let bad_tool_calls = [
        (
            10,
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call"}"#,
            "tools/call params must be a JSON object",
        ),
        (
            11,
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":[]}"#,
            "tools/call params must be a JSON object",
        ),
        (
            12,
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"run_sandbox","extra":1}}"#,
            "unexpected tools/call params key 'extra'",
        ),
        (
            13,
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{}}"#,
            "tools/call params.name must be a string",
        ),
        (
            14,
            r#"{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":123}}"#,
            "tools/call params.name must be a string",
        ),
        (
            15,
            r#"{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":""}}"#,
            "tools/call params.name must not be empty",
        ),
    ];
    let script: String = bad_tool_calls
        .iter()
        .map(|(_, line, _)| format!("{line}\n"))
        .collect();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (_up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut buf = String::new();
        up_in_r.read_line(&mut buf).unwrap()
    });
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(script.into_bytes())),
            &mut client_out,
            up_in_w,
            up_out_r,
        )
        .expect("bad tools/call params must be denied cleanly");
    assert_eq!(upstream.join().unwrap(), 0);
    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), bad_tool_calls.len());
    for (idx, (id, _, expected)) in bad_tool_calls.iter().enumerate() {
        assert_eq!(responses[idx]["id"], json!(id));
        assert_eq!(responses[idx]["error"]["code"], json!(-32001));
        assert!(responses[idx]["error"]["data"]["reason"]
            .as_str()
            .unwrap()
            .contains(expected));
    }
}

#[test]
fn round11_tools_list_and_call_use_precompiled_static_decimal_and_timestamp_facts() {
    let (verified, agent_kp, now) = build_single_hop(
        "finance.quote",
        "ledger \"main\"",
        "WHERE policy.approved_at < 2026-06-02T00:00:00Z\n  AND pricing.fee <= 10.5\n",
    );
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "cheap_quote": {
                    "action": "finance.quote",
                    "resource_kind": "ledger",
                    "static_resource_id": "main",
                    "static_facts": {
                        "pricing.fee": { "decimal": "9.99" },
                        "policy.approved_at": { "timestamp": "2026-06-01T00:00:00Z" }
                    }
                },
                "expensive_quote": {
                    "action": "finance.quote",
                    "resource_kind": "ledger",
                    "static_resource_id": "main",
                    "static_facts": {
                        "pricing.fee": { "decimal": "20.00" },
                        "policy.approved_at": { "timestamp": "2026-06-01T00:00:00Z" }
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let raw_list = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"cheap_quote"},{"name":"expensive_quote"}]}}"#;
    let (res, out) = run_tools_list_once(&verified, &agent_kp, &policy_map, now, raw_list);
    res.expect("tools/list with static decimal & timestamp facts must succeed");
    let parsed: Value = serde_json::from_str(out.trim()).unwrap();
    let tools = parsed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], json!("cheap_quote"));

    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        policy_map,
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let call = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"cheap_quote\",\"arguments\":{}}}\n";
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut req = String::new();
        up_in_r.read_line(&mut req).unwrap();
        writeln!(
            up_out_w,
            r#"{{"jsonrpc":"2.0","id":2,"result":{{"quoted":true}}}}"#
        )
        .unwrap();
    });
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(call.as_bytes().to_vec())),
            &mut client_out,
            up_in_w,
            up_out_r,
        )
        .expect("cheap_quote call must succeed");
    upstream.join().unwrap();
    let resp: Value = serde_json::from_str(String::from_utf8(client_out).unwrap().trim()).unwrap();
    assert_eq!(
        resp,
        json!({"jsonrpc":"2.0","id":2,"result":{"quoted":true}})
    );
}

fn run_echo_ok_upstream(
    proxy: &mut McpProxy<FixedClock, SqliteLedger>,
    client_script: String,
    ok_id: u64,
) -> (Vec<u8>, Vec<String>) {
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut forwarded = Vec::new();
        let mut line = String::new();
        while up_in_r.read_line(&mut line).unwrap() > 0 {
            forwarded.push(line.trim_end().to_string());
            writeln!(
                up_out_w,
                r#"{{"jsonrpc":"2.0","id":{ok_id},"result":{{"ok":true}}}}"#
            )
            .unwrap();
            line.clear();
        }
        forwarded
    });
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(client_script.into_bytes())),
            &mut client_out,
            up_in_w,
            up_out_r,
        )
        .expect("session must stay healthy across malformed _meta denials");
    (client_out, upstream.join().unwrap())
}
