//! Round 4 regression tests for bounded cancellation tracking, strict `notifications/cancelled`
//! ordering, `upstream_eof` pre-check before ledger evaluation, and `Duration::MAX` shutdown
//! timeouts.

use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::VerifiedMandate;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{
    verify_mandate_chain, FixedClock, McpProxy, ProxyError, ToolPolicyMap,
    HANDFEST_DENIED_ERROR_CODE,
};
use serde_json::{json, Value};

struct PipeWriter {
    tx: mpsc::Sender<Vec<u8>>,
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pipe reader closed"))?;
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
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) if chunk.is_empty() => continue,
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
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

/// Reader wrapper whose `Drop` fires strictly AFTER the transport reader thread has enqueued
/// EOF (`Ok(None)`) into the FIFO event channel and exited.
struct NotifyOnDropReader<R> {
    inner: R,
    dropped_tx: Option<mpsc::SyncSender<()>>,
}

impl<R: Read> Read for NotifyOnDropReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R> Drop for NotifyOnDropReader<R> {
    fn drop(&mut self) {
        if let Some(tx) = self.dropped_tx.take() {
            let _ = tx.send(());
        }
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

fn single_hop_chain(extra_clauses: &str) -> (Vec<VerifiedMandate>, Ed25519Keypair) {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();

    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Admin\" (key: {root})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/*\"\n\
         {extra_clauses}",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let signed = sign_mandate(&root_kp, &text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();
    (verified, agent_kp)
}

#[test]
fn at_max_cancelled_in_flight_1024_tools_list_is_not_evicted() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");

    // Part 1: At exactly 1,024 cancelled in-flight requests (id 1 is `tools/list`, ids 2..=1024
    // are `ping`), `tools/list (id: 1)` MUST NOT be evicted.
    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();

    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    let proxy_thread =
        thread::spawn(move || proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r));
    let drain_up = thread::spawn(move || {
        let mut line = String::new();
        while up_in_r.read_line(&mut line).unwrap_or(0) > 0 {
            line.clear();
        }
    });

    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":1}}}}"#
    )
    .unwrap();
    for id in 2..=1024u32 {
        writeln!(
            client_in_w,
            r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#
        )
        .unwrap();
        writeln!(
            client_in_w,
            r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{id}}}}}"#
        )
        .unwrap();
    }

    // Reusing id: 1 while 1,024 cancelled requests are in flight must be rejected.
    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let mut dup_line = String::new();
    client_out_r.read_line(&mut dup_line).unwrap();
    let dup_resp: Value = serde_json::from_str(dup_line.trim_end()).unwrap();
    assert_eq!(dup_resp["id"], json!(1));
    assert_eq!(dup_resp["error"]["code"], json!(-32600));
    assert_eq!(
        dup_resp["error"]["message"],
        json!("duplicate in-flight JSON-RPC request id")
    );

    // Late upstream response for id: 1 MUST still be filtered via `PendingKind::ToolsList`.
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{{"name":"merge_pr"}},{{"name":"delete_prod"}}]}}}}"#
    )
    .unwrap();
    let mut tools_line = String::new();
    client_out_r.read_line(&mut tools_line).unwrap();
    let tools_resp: Value = serde_json::from_str(tools_line.trim_end()).unwrap();
    assert_eq!(tools_resp["id"], json!(1));
    assert_eq!(tools_resp["result"]["tools"], json!([{"name": "merge_pr"}]));

    drop(client_in_w);
    drop(up_out_w);
    proxy_thread.join().unwrap().unwrap();
    drain_up.join().unwrap();
}

#[test]
fn exceeding_max_cancelled_in_flight_at_1025_fails_closed_without_leaking_tools() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut overflow_proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let mut attack_frames = String::new();
    attack_frames
        .push_str("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n");
    attack_frames.push_str(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n",
    );
    for id in 2..=1025u32 {
        attack_frames.push_str(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\"}}\n"
        ));
        attack_frames.push_str(&format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":{id}}}}}\n"
        ));
    }
    attack_frames.push_str("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");

    let mut client_out = Vec::new();
    let (up_in_w2, mut up_in_r2) = mem_pipe();
    let (_up_out_w2, up_out_r2) = mem_pipe();
    let drain_up2 = thread::spawn(move || {
        let mut line = String::new();
        while up_in_r2.read_line(&mut line).unwrap_or(0) > 0 {
            line.clear();
        }
    });

    let res = overflow_proxy.run(
        BufReader::new(Cursor::new(attack_frames.into_bytes())),
        &mut client_out,
        up_in_w2,
        up_out_r2,
    );
    drain_up2.join().unwrap();

    assert!(
        matches!(
            res,
            Err(ProxyError::UpstreamProtocol(ref msg))
                if msg == "client exceeded maximum in-flight cancelled JSON-RPC requests"
        ),
        "expected fail-closed UpstreamProtocol on 1025th cancellation, got {res:?}"
    );
    let out_str = String::from_utf8(client_out).unwrap();
    assert!(!out_str.contains("delete_prod"));
    let responses: Vec<Value> = out_str
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], json!(-32600));
    assert_eq!(
        responses[0]["error"]["message"],
        json!("client exceeded maximum in-flight cancelled JSON-RPC requests")
    );
}

#[test]
fn pipelined_cancellation_for_queued_request_never_reorders_ahead_of_request() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let up_in_w = PipeWriter { tx: up_in_tx };
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread =
        thread::spawn(move || proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r));

    // Step 1: Send id: 1 and observe it arrive upstream.
    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let frame1 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let parsed1: Value = serde_json::from_str(frame1.trim_end()).unwrap();
    assert_eq!(parsed1["id"], json!(1));
    assert_eq!(parsed1["method"], json!("ping"));

    // Step 2: While id: 1 is active, pipeline tools/call (id: 2) + notifications/cancelled (2).
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"merge_pr","arguments":{{"repo":"org/app"}}}}}}"#
    )
    .unwrap();
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":2}}}}"#
    )
    .unwrap();

    // Neither id: 2 nor notifications/cancelled (2) may be forwarded while id: 1 is still active.
    assert!(
        matches!(
            up_in_rx.recv_timeout(Duration::from_millis(80)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "notifications/cancelled for queued id: 2 must not leapfrog ahead of id: 2"
    );

    // Step 3: Upstream replies to id: 1 -> proxy MUST forward tools/call (2) strictly BEFORE
    // notifications/cancelled (2).
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"pong":1}}}}"#
    )
    .unwrap();

    let mut resp1 = String::new();
    client_out_r.read_line(&mut resp1).unwrap();
    let resp1_json: Value = serde_json::from_str(resp1.trim_end()).unwrap();
    assert_eq!(resp1_json["id"], json!(1));
    assert_eq!(resp1_json["result"]["pong"], json!(1));

    let frame2 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let parsed2: Value = serde_json::from_str(frame2.trim_end()).unwrap();
    assert_eq!(parsed2["id"], json!(2));
    assert_eq!(parsed2["method"], json!("tools/call"));

    let frame3 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let parsed3: Value = serde_json::from_str(frame3.trim_end()).unwrap();
    assert_eq!(parsed3["method"], json!("notifications/cancelled"));
    assert_eq!(parsed3["params"]["requestId"], json!(2));

    drop(client_in_w);
    drop(up_out_w);
    proxy_thread
        .join()
        .unwrap()
        .expect("pipelined cancellation session exited cleanly");
}

#[test]
fn upstream_eof_before_tools_call_returns_32603_without_consuming_quota() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("LIMIT 1 calls\n");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_w, _up_in_r) = mem_pipe();
    let (eof_tx, eof_rx) = mpsc::sync_channel(1);
    let up_out_r = BufReader::new(NotifyOnDropReader {
        inner: Cursor::new(Vec::<u8>::new()),
        dropped_tx: Some(eof_tx),
    });

    let proxy_thread = thread::spawn(move || {
        let res = proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r);
        (proxy, res)
    });

    // Wait until the upstream reader thread has enqueued `UpstreamLine(Ok(None))` in the FIFO
    // event channel before the client writes `merge_pr`.
    eof_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream EOF enqueued");

    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"merge_pr","arguments":{{"repo":"org/app"}}}}}}"#
    )
    .unwrap();
    drop(client_in_w);

    let mut err_line = String::new();
    client_out_r.read_line(&mut err_line).unwrap();
    let err_resp: Value = serde_json::from_str(err_line.trim_end()).unwrap();
    assert_eq!(err_resp["id"], json!(1));
    assert_eq!(err_resp["error"]["code"], json!(-32603));

    let (mut proxy, res) = proxy_thread.join().unwrap();
    assert!(
        matches!(res, Err(ProxyError::UpstreamEof)),
        "expected ProxyError::UpstreamEof, got {res:?}"
    );
    assert_eq!(
        proxy.ledger().verify_integrity().unwrap(),
        0,
        "no receipt or quota may be recorded when upstream is already at EOF"
    );
    let tr = proxy.ledger().track_record(&agent_kp.key_id()).unwrap();
    assert_eq!(tr.total_decisions, 0);

    // Prove the same SQLite ledger still has 0/1 calls used: the next permitted call succeeds
    // (1/1), and a second call is denied by the 1-call quota.
    let second_session_in = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{\"repo\":\"org/app\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{\"repo\":\"org/app\"}}}\n"
    );
    let (up_in_w2, mut up_in_r2) = mem_pipe();
    let (mut up_out_w2, up_out_r2) = mem_pipe();
    let upstream_responder = thread::spawn(move || {
        let mut req = String::new();
        up_in_r2.read_line(&mut req).unwrap();
        assert!(req.contains("\"id\":2"));
        writeln!(
            up_out_w2,
            r#"{{"jsonrpc":"2.0","id":2,"result":{{"merged":true}}}}"#
        )
        .unwrap();
        // Hold upstream stdout open until the proxy closes upstream stdin at session end so
        // request id: 3 is deterministically evaluated against the 1-call quota without racing EOF.
        let mut extra = String::new();
        assert_eq!(
            up_in_r2.read_line(&mut extra).unwrap(),
            0,
            "quota-denied request id: 3 must never be forwarded upstream"
        );
        drop(up_out_w2);
    });
    let mut second_client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(second_session_in.as_bytes().to_vec())),
            &mut second_client_out,
            up_in_w2,
            up_out_r2,
        )
        .expect("second session with live upstream succeeded");
    upstream_responder.join().unwrap();

    let responses: Vec<Value> = String::from_utf8(second_client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], json!(2));
    assert_eq!(responses[0]["result"]["merged"], json!(true));
    assert_eq!(responses[1]["id"], json!(3));
    assert_eq!(
        responses[1]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );

    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 2);
    let tr_after = proxy.ledger().track_record(&agent_kp.key_id()).unwrap();
    assert_eq!(tr_after.permits, 1);
    assert_eq!(tr_after.denies, 1);
}

#[test]
fn shutdown_timeout_duration_max_does_not_panic_on_client_eof() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap()
    .with_shutdown_timeout(Duration::MAX);

    // Path 1: Client EOF while request id: 1 is still active (exercises `set_shutdown_timeout`).
    let (eof_tx, eof_rx) = mpsc::sync_channel(1);
    let client_in_r = BufReader::new(NotifyOnDropReader {
        inner: Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".to_vec()),
        dropped_tx: Some(eof_tx),
    });
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread = thread::spawn(move || {
        let res = proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r);
        (proxy, res)
    });

    let mut req_line = String::new();
    up_in_r.read_line(&mut req_line).unwrap();
    assert!(req_line.contains("\"id\":1"));

    // Wait until client reader thread has enqueued client EOF into `event_rx` before replying.
    eof_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("client EOF enqueued");

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"pong":true}}}}"#
    )
    .unwrap();
    drop(up_out_w);

    let mut resp_line = String::new();
    client_out_r.read_line(&mut resp_line).unwrap();
    let resp: Value = serde_json::from_str(resp_line.trim_end()).unwrap();
    assert_eq!(resp["id"], json!(1));
    assert_eq!(resp["result"]["pong"], json!(true));

    let (mut proxy, res) = proxy_thread.join().unwrap();
    res.expect("Duration::MAX shutdown timeout must not panic when draining active request");

    // Path 2: Immediate client EOF with no active request (exercises `finish_writer(Duration::MAX)`).
    let mut out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(Vec::<u8>::new())),
            &mut out,
            Vec::<u8>::new(),
            BufReader::new(Cursor::new(Vec::<u8>::new())),
        )
        .expect("Duration::MAX shutdown timeout must not panic on immediate EOF");
    assert!(out.is_empty());
}

struct GateWriter {
    gate_rx: Option<mpsc::Receiver<()>>,
    entered_tx: Option<mpsc::SyncSender<()>>,
}

impl Write for GateWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(tx) = self.entered_tx.take() {
            let _ = tx.send(());
        }
        if let Some(rx) = self.gate_rx.take() {
            let _ = rx.recv();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reader that yields `prefix` bytes, signals `drained_tx` once the reader thread has consumed all
/// of `prefix` (guaranteeing by pigeonhole against `EVENT_CHANNEL_BOUND = 64` that the event loop
/// has processed at least `frames - 64` frames), and then blocks until `close_rx` is released.
struct SignalAfterPrefixReader {
    prefix: Vec<u8>,
    pos: usize,
    drained_tx: Option<mpsc::SyncSender<()>>,
    close_rx: mpsc::Receiver<()>,
}

impl Read for SignalAfterPrefixReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        if let Some(tx) = self.drained_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.close_rx.recv();
        Ok(0)
    }
}

fn flooded_client_prefix() -> Vec<u8> {
    // 1 active ping + 1,100 notifications: after the client reader thread finishes reading all
    // 1,101 lines into `event_tx` (bound 64), the event loop is guaranteed to have processed at
    // least 1,037 lines (filling GateWriter (1) + `upstream_tx` (1,024) + spilling into
    // `pending_upstream` / `queued_client`).
    let mut bytes = String::from("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    for _ in 0..1100 {
        bytes.push_str("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
    }
    bytes.into_bytes()
}

#[test]
fn full_writer_queue_does_not_block_upstream_response_or_shutdown_timeout() {
    use std::time::Instant;

    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap()
    .with_shutdown_timeout(Duration::from_millis(120));

    let (drained_tx, drained_rx) = mpsc::sync_channel(1);
    let (close_tx, close_rx) = mpsc::sync_channel(1);
    let client_in_r = BufReader::new(SignalAfterPrefixReader {
        prefix: flooded_client_prefix(),
        pos: 0,
        drained_tx: Some(drained_tx),
        close_rx,
    });
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (_gate_tx, gate_rx) = mpsc::sync_channel(1);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread = thread::spawn(move || {
        proxy.run(
            client_in_r,
            &mut client_out_w,
            GateWriter {
                gate_rx: Some(gate_rx),
                entered_tx: Some(entered_tx),
            },
            up_out_r,
        )
    });

    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer blocked on first frame");
    drained_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("client reader thread drained flooded prefix into event loop");

    // Even while the writer queue is completely full and stalled, the event loop MUST still
    // process upstream responses immediately.
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"pong":true}}}}"#
    )
    .unwrap();
    let mut resp_line = String::new();
    client_out_r.read_line(&mut resp_line).unwrap();
    let resp: Value = serde_json::from_str(resp_line.trim_end()).unwrap();
    assert_eq!(resp["id"], json!(1));
    assert_eq!(resp["result"]["pong"], json!(true));

    // Close client stdin while writer is still stalled -> shutdown_timeout MUST fire cleanly
    // rather than deadlocking forever.
    let started = Instant::now();
    drop(close_tx);
    let res = proxy_thread.join().unwrap();
    res.expect("shutdown timeout must terminate stalled-writer session cleanly");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "session hung instead of honoring shutdown_timeout under full writer queue"
    );
    drop(up_out_w);
}

#[test]
fn full_writer_queue_does_not_block_upstream_eof() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut eof_proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (drained_tx, drained_rx) = mpsc::sync_channel(1);
    let (_close_tx, close_rx) = mpsc::sync_channel(1);
    let cin_r2 = BufReader::new(SignalAfterPrefixReader {
        prefix: flooded_client_prefix(),
        pos: 0,
        drained_tx: Some(drained_tx),
        close_rx,
    });
    let (mut cout_w2, mut cout_r2) = mem_pipe();
    let (_gate_tx2, gate_rx2) = mpsc::sync_channel(1);
    let (entered_tx2, entered_rx2) = mpsc::sync_channel(1);
    let (up_out_w2, up_out_r2) = mem_pipe();
    let eof_thread = thread::spawn(move || {
        eof_proxy.run(
            cin_r2,
            &mut cout_w2,
            GateWriter {
                gate_rx: Some(gate_rx2),
                entered_tx: Some(entered_tx2),
            },
            up_out_r2,
        )
    });

    entered_rx2
        .recv_timeout(Duration::from_secs(2))
        .expect("second writer blocked");
    drained_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer queue guaranteed full before upstream EOF");
    drop(up_out_w2);

    let mut eof_line = String::new();
    cout_r2.read_line(&mut eof_line).unwrap();
    let eof_json: Value = serde_json::from_str(eof_line.trim_end()).unwrap();
    assert_eq!(eof_json["id"], json!(1));
    assert_eq!(eof_json["error"]["code"], json!(-32603));
    assert!(matches!(
        eof_thread.join().unwrap(),
        Err(ProxyError::UpstreamEof)
    ));
}

#[test]
fn queued_cancellation_never_overtakes_earlier_queued_notification() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let up_in_w = PipeWriter { tx: up_in_tx };
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread =
        thread::spawn(move || proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r));

    // Send id: 1 and observe it upstream.
    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let f1 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f1.trim_end()).unwrap()["id"],
        json!(1)
    );

    // While id: 1 is active, pipeline:
    //   1. tools/call (id: 2)
    //   2. notifications/roots/list_changed
    //   3. notifications/cancelled (requestId: 2)
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"merge_pr","arguments":{{"repo":"org/app"}}}}}}"#
    )
    .unwrap();
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}}"#
    )
    .unwrap();
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":2}}}}"#
    )
    .unwrap();

    // Complete id: 1 -> upstream MUST receive strict FIFO order:
    //   tools/call (id: 2) -> notifications/roots/list_changed -> notifications/cancelled (2)
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"pong":1}}}}"#
    )
    .unwrap();
    let mut resp1 = String::new();
    client_out_r.read_line(&mut resp1).unwrap();

    let f2 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let p2: Value = serde_json::from_str(f2.trim_end()).unwrap();
    assert_eq!(p2["id"], json!(2));
    assert_eq!(p2["method"], json!("tools/call"));

    let f3 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let p3: Value = serde_json::from_str(f3.trim_end()).unwrap();
    assert_eq!(p3["method"], json!("notifications/roots/list_changed"));

    let f4 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let p4: Value = serde_json::from_str(f4.trim_end()).unwrap();
    assert_eq!(p4["method"], json!("notifications/cancelled"));
    assert_eq!(p4["params"]["requestId"], json!(2));

    drop(client_in_w);
    drop(up_out_w);
    proxy_thread.join().unwrap().unwrap();
}

#[test]
fn cancellations_for_locally_denied_unknown_or_missing_request_id_are_not_forwarded() {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let client_in = concat!(
        // Locally denied tool call (outside org/*) followed by cancellation for its id.
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{\"repo\":\"other/repo\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n",
        // Unknown id while idle.
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":999}}\n",
        // Missing params / missing requestId / invalid requestId types.
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":null}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":true}}\n",
        // Final valid ping proves the session stays healthy and only this frame reaches upstream.
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n"
    );

    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut seen = Vec::new();
        let mut line = String::new();
        while up_in_r.read_line(&mut line).unwrap() > 0 {
            let trimmed = line.trim_end().to_string();
            let parsed: Value = serde_json::from_str(&trimmed).unwrap();
            seen.push(parsed.clone());
            if parsed.get("id") == Some(&json!(2)) {
                writeln!(
                    up_out_w,
                    r#"{{"jsonrpc":"2.0","id":2,"result":{{"pong":2}}}}"#
                )
                .unwrap();
            }
            line.clear();
        }
        seen
    });

    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            up_in_w,
            up_out_r,
        )
        .expect("idle and invalid cancellations must be dropped cleanly");

    let forwarded = upstream.join().unwrap();
    assert_eq!(
        forwarded.len(),
        1,
        "only ping id: 2 should reach upstream, got: {forwarded:?}"
    );
    assert_eq!(forwarded[0]["id"], json!(2));
    assert_eq!(forwarded[0]["method"], json!("ping"));

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], json!(1));
    assert_eq!(
        responses[0]["error"]["code"],
        json!(HANDFEST_DENIED_ERROR_CODE)
    );
    assert_eq!(responses[1]["id"], json!(2));
    assert_eq!(responses[1]["result"]["pong"], json!(2));
}

#[test]
fn full_waiting_queue_with_interleaved_upstream_notifications_does_not_reparse_quadratically() {
    use std::time::Instant;

    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain("");
    let mut proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread =
        thread::spawn(move || proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r));

    // Send active request id: 1.
    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let mut first = String::new();
    up_in_r.read_line(&mut first).unwrap();
    assert!(first.contains("\"id\":1"));

    // Queue 1,024 substantial requests (each ~4 KiB) while id: 1 is active.
    let pad = "a".repeat(4000);
    for id in 2..=1025u32 {
        writeln!(
            client_in_w,
            r#"{{"jsonrpc":"2.0","id":{id},"method":"ping","params":{{"pad":"{pad}"}}}}"#
        )
        .unwrap();
    }

    // Emit 1,024 interleaved upstream notifications while all 1,024 frames sit in `queued_client`.
    // Without pre-parsing, this would trigger >1,000,000 JSON parses of 4 KiB frames (~4 GiB).
    let started = Instant::now();
    for seq in 0..1024u32 {
        writeln!(
            up_out_w,
            r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"seq":{seq}}}}}"#
        )
        .unwrap();
    }
    for _ in 0..1024 {
        let mut line = String::new();
        client_out_r.read_line(&mut line).unwrap();
        assert!(line.contains("notifications/progress"));
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "interleaved events with a full waiting queue took {:?} (expected linear, non-quadratic)",
        started.elapsed()
    );

    // Reply to id: 1 and cancel/drain cleanly.
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"pong":1}}}}"#
    )
    .unwrap();
    let mut resp1 = String::new();
    client_out_r.read_line(&mut resp1).unwrap();
    assert!(resp1.contains("\"pong\":1"));

    // Reply to queued requests in background so session exits cleanly.
    drop(client_in_w);
    let responder = thread::spawn(move || {
        let mut line = String::new();
        while up_in_r.read_line(&mut line).unwrap() > 0 {
            let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
            let id = &parsed["id"];
            writeln!(
                up_out_w,
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"ok":true}}}}"#
            )
            .unwrap();
            line.clear();
        }
    });
    let mut sink = String::new();
    while client_out_r.read_line(&mut sink).unwrap() > 0 {
        sink.clear();
    }
    proxy_thread.join().unwrap().unwrap();
    responder.join().unwrap();
}
