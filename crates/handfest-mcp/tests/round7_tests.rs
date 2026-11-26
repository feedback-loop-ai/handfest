//! Round 7 regression tests covering:
//! 1. IEEE-754 safe-integer restriction on numeric JSON-RPC `id`s and `notifications/cancelled`.
//! 2. Fatal upstream read errors (`UpstreamLine(Err(_))`) and post-lookahead `poll_writer_error()`
//!    stopping `tools/call` from burning SQLite quota.
//! 3. Closed JSON-RPC 2.0 Error Object keys `{"code", "message", "data"}`.

mod common;

use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::{mem_pipe, mem_pipe_timeout, step_pipe, PipeWriter, WaitOnNthWrite};
use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::VerifiedMandate;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{verify_mandate_chain, FixedClock, McpProxy, ProxyError, ToolPolicyMap};
use serde_json::{json, Value};

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

fn make_proxy(extra_clauses: &str) -> McpProxy<FixedClock, SqliteLedger> {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
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
    let verified: Vec<VerifiedMandate> =
        verify_mandate_chain(&[signed]).expect("mandate chain verifies");
    let policy_map = ToolPolicyMap::from_json_str(
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
    .unwrap();
    McpProxy::new(
        verified,
        agent_kp.key_id(),
        policy_map,
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap()
}

#[test]
fn round7_rejects_fractional_and_unsafe_integer_client_ids_before_upstream() {
    let mut proxy = make_proxy("");
    let client_in = concat!(
        r#"{"jsonrpc":"2.0","id":1.0000000000000001,"method":"tools/list","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":1e-400,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":-9007199254740992,"method":"ping"}"#,
        "\n",
    );

    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let up_in_w = PipeWriter { tx: up_in_tx };
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            up_in_w,
            BufReader::new(Cursor::new(Vec::<u8>::new())),
        )
        .expect("invalid client ids must emit -32600 without crashing session");

    assert!(
        up_in_rx.try_recv().is_err(),
        "fractional/out-of-safe-range client ids must NEVER reach upstream"
    );

    let out_str = String::from_utf8(client_out).unwrap();
    let lines: Vec<Value> = out_str
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 4);
    for (idx, resp) in lines.iter().enumerate() {
        assert_eq!(resp["id"], json!(null), "line {idx}: {resp}");
        assert_eq!(resp["error"]["code"], json!(-32600), "line {idx}: {resp}");
    }
    assert!(lines[0]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("plain integer without decimal point or exponent"));
    assert!(lines[1]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("plain integer without decimal point or exponent"));
    assert!(lines[2]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("IEEE-754 safe integer range"));
    assert!(lines[3]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("IEEE-754 safe integer range"));
}

#[test]
fn round7_notifications_cancelled_drops_fractional_and_unsafe_request_ids() {
    let mut proxy = make_proxy("");
    let (client_in_w, client_in_r) = step_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe_timeout();
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let up_in_w = PipeWriter { tx: up_in_tx };
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    let proxy_thread = thread::spawn(move || {
        let res = proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r);
        let _ = done_tx.send(res);
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    let f1 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f1.trim_end()).unwrap()["id"],
        json!(1)
    );

    client_in_w.send_and_sync_queued(
        concat!(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1.0000000000000001}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9007199254740993}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
            "\n",
        )
        .as_bytes(),
    );
    assert!(
        up_in_rx.try_recv().is_err(),
        "unsafe cancellations must not cancel id: 1 or reach upstream"
    );

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"pong":1}}}}"#
    )
    .unwrap();
    let line1 = client_out_r.read_line_timeout(Duration::from_secs(2), "resp 1");
    assert_eq!(
        serde_json::from_str::<Value>(line1.trim_end()).unwrap()["id"],
        json!(1)
    );

    let f2 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f2.trim_end()).unwrap()["id"],
        json!(2)
    );
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":2,"result":{{"pong":2}}}}"#
    )
    .unwrap();
    let line2 = client_out_r.read_line_timeout(Duration::from_secs(2), "resp 2");
    assert_eq!(
        serde_json::from_str::<Value>(line2.trim_end()).unwrap()["id"],
        json!(2)
    );

    drop(client_in_w);
    drop(up_out_w);
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit timed out")
        .unwrap();
    proxy_thread.join().unwrap();
}

#[test]
fn round7_upstream_bare_cr_before_queued_tools_call_aborts_without_burning_quota() {
    struct GatedPayloadReader {
        release_rx: Option<mpsc::Receiver<()>>,
        payload: Cursor<Vec<u8>>,
        dropped_tx: Option<mpsc::SyncSender<()>>,
    }

    impl Read for GatedPayloadReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(rx) = self.release_rx.take() {
                let _ = rx.recv();
            }
            self.payload.read(buf)
        }
    }

    impl Drop for GatedPayloadReader {
        fn drop(&mut self) {
            if let Some(tx) = self.dropped_tx.take() {
                let _ = tx.send(());
            }
        }
    }

    let mut proxy = make_proxy("LIMIT 1 calls\n");
    let (client_in_w, client_in_r) = step_pipe();
    let (client_out_w, mut client_out_r) = mem_pipe_timeout();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (done_read_tx, done_read_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    let payload = concat!(
        r#"{"jsonrpc":"2.0","id":1,"result":{"pong":1}}"#,
        "\n",
        "bad\rline\n",
    );
    let up_out_r = BufReader::new(GatedPayloadReader {
        release_rx: Some(release_rx),
        payload: Cursor::new(payload.as_bytes().to_vec()),
        dropped_tx: Some(done_read_tx),
    });

    let proxy_thread = thread::spawn(move || {
        let mut gated_out = WaitOnNthWrite {
            inner: client_out_w,
            writes: 0,
            wait_on: 1,
            wait_rx: Some(done_read_rx),
        };
        let res = proxy.run(client_in_r, &mut gated_out, up_in_w, up_out_r);
        let _ = done_tx.send((proxy, res));
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    let mut seen_ping = String::new();
    up_in_r.read_line(&mut seen_ping).unwrap();
    assert!(seen_ping.contains("\"id\":1"));

    client_in_w.send_and_sync_queued(
        b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{\"repo\":\"org/app\"}}}\n",
    );
    release_tx.send(()).unwrap();

    let line1 = client_out_r.read_line_timeout(Duration::from_secs(2), "ping resp 1");
    let resp1: Value = serde_json::from_str(line1.trim_end()).unwrap();
    assert_eq!(resp1["id"], json!(1));
    assert_eq!(resp1["result"]["pong"], json!(1));

    let line2 = client_out_r.read_line_timeout(Duration::from_secs(2), "bare CR error for id 2");
    let resp2: Value = serde_json::from_str(line2.trim_end()).unwrap();
    assert_eq!(resp2["id"], json!(2));
    assert_eq!(resp2["error"]["code"], json!(-32700));

    drop(client_in_w);
    let (proxy, res) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit after upstream BareCr timed out");
    proxy_thread.join().unwrap();
    assert!(
        matches!(res, Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains("bare carriage return")),
        "expected ProxyError::UpstreamProtocol(bare CR), got {res:?}"
    );
    assert_eq!(
        proxy.ledger().verify_integrity().unwrap(),
        0,
        "tools/call must not consume SQLite quota when UpstreamLine(Err(BareCr)) is already queued"
    );
}

struct FailSecondWrite {
    writes: usize,
    raw_os_code: i32,
    first_tx: Option<mpsc::SyncSender<()>>,
    dropped_tx: Option<mpsc::SyncSender<()>>,
}

impl Write for FailSecondWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes == 1 {
            let _ = self.first_tx.take().map(|tx| tx.send(()));
            return Ok(buf.len());
        }
        Err(io::Error::from_raw_os_error(self.raw_os_code))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for FailSecondWrite {
    fn drop(&mut self) {
        if let Some(tx) = self.dropped_tx.take() {
            let _ = tx.send(());
        }
    }
}

struct RespThenNotificationFloodReader {
    release_rx: Option<mpsc::Receiver<()>>,
    flood_ready_tx: Option<mpsc::SyncSender<()>>,
    hold_rx: Option<mpsc::Receiver<()>>,
    emitted: usize,
    buf: Vec<u8>,
    pos: usize,
}

impl RespThenNotificationFloodReader {
    fn next_line(&mut self) -> Option<Vec<u8>> {
        if let Some(rx) = self.release_rx.take() {
            let _ = rx.recv();
        }
        let idx = self.emitted;
        self.emitted += 1;
        if idx == 0 {
            return Some(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"pong\":1}}\n".to_vec());
        }
        if idx <= 80 {
            if idx == 65 {
                let _ = self.flood_ready_tx.take().map(|tx| tx.send(()));
            }
            return Some(
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"n\":{idx}}}}}\n"
                )
                .into_bytes(),
            );
        }
        let _ = self.hold_rx.take().map(|rx| rx.recv());
        None
    }
}

impl Read for RespThenNotificationFloodReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            let Some(line) = self.next_line() else {
                return Ok(0);
            };
            self.buf = line;
            self.pos = 0;
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

struct TwoStageWaitWriter {
    writes: usize,
    w1_rx: Option<mpsc::Receiver<()>>,
    w3_rx: Option<mpsc::Receiver<()>>,
}

impl Write for TwoStageWaitWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes == 1 {
            if let Some(rx) = self.w1_rx.take() {
                rx.recv_timeout(Duration::from_secs(2))
                    .expect("flood saturated event_rx");
            }
        } else if self.writes == 3 {
            if let Some(rx) = self.w3_rx.take() {
                rx.recv_timeout(Duration::from_secs(2))
                    .expect("writer failure published while event_rx saturated");
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn round7_writer_error_while_event_channel_saturated_aborts_tools_call_without_burning_quota() {
    const RAW_OS_CODE: i32 = 32;
    let mut proxy = make_proxy("LIMIT 1 calls\n");
    let (client_in_w, client_in_r) = step_pipe();
    let (first_tx, first_rx) = mpsc::sync_channel(1);
    let (failed_tx, failed_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (flood_tx, flood_rx) = mpsc::sync_channel(1);
    let (_hold_tx, hold_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    let up_out_r = BufReader::new(RespThenNotificationFloodReader {
        release_rx: Some(release_rx),
        flood_ready_tx: Some(flood_tx),
        hold_rx: Some(hold_rx),
        emitted: 0,
        buf: Vec::new(),
        pos: 0,
    });

    let proxy_thread = thread::spawn(move || {
        let mut client_out = TwoStageWaitWriter {
            writes: 0,
            w1_rx: Some(flood_rx),
            w3_rx: Some(failed_rx),
        };
        let res = proxy.run(
            client_in_r,
            &mut client_out,
            FailSecondWrite {
                writes: 0,
                raw_os_code: RAW_OS_CODE,
                first_tx: Some(first_tx),
                dropped_tx: Some(failed_tx),
            },
            up_out_r,
        );
        let _ = done_tx.send((proxy, res));
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    first_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first write succeeded");

    client_in_w.send_and_sync_queued(
        concat!(
            "bad\r1\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            "bad\r2\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app"}}}"#,
            "\n",
        )
        .as_bytes(),
    );
    release_tx.send(()).unwrap();

    let (proxy, res) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit after saturated-channel writer error timed out");
    drop(client_in_w);
    proxy_thread.join().unwrap();
    assert!(
        matches!(res, Err(ProxyError::Io(ref err)) if err.raw_os_error() == Some(RAW_OS_CODE)),
        "expected ProxyError::Io(raw_os_error={RAW_OS_CODE}), got {res:?}"
    );
    assert_eq!(
        proxy.ledger().verify_integrity().unwrap(),
        0,
        "tools/call must not burn quota when writer error arrives with saturated event_rx"
    );
}
#[test]
fn round7_upstream_error_object_rejects_unknown_and_case_colliding_keys() {
    let mut proxy = make_proxy("");
    let (mut client_in_w, client_in_r) = mem_pipe();
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    let proxy_thread = thread::spawn(move || {
        let mut client_out = Vec::new();
        let res = proxy.run(client_in_r, &mut client_out, up_in_w, up_out_r);
        let _ = done_tx.send((res, client_out));
    });

    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let mut seen = String::new();
    up_in_r.read_line(&mut seen).unwrap();
    assert!(seen.contains("\"id\":1"));

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32601,"CODE":"not_an_int","message":"fail","extra":true}}}}"#
    )
    .unwrap();

    let (res, client_out) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit on malformed error object timed out");
    drop(client_in_w);
    drop(up_out_w);
    proxy_thread.join().unwrap();

    assert!(
        matches!(res, Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains("malformed JSON-RPC error object")),
        "expected malformed JSON-RPC error object protocol error, got {res:?}"
    );
    let parsed: Value =
        serde_json::from_str(String::from_utf8(client_out).unwrap().trim_end()).unwrap();
    assert_eq!(parsed["id"], json!(1));
    assert_eq!(parsed["error"]["code"], json!(-32603));
}

#[test]
fn round8_rejects_exponent_and_decimal_integer_spellings_before_upstream() {
    let mut proxy = make_proxy("");
    let client_in = concat!(
        r#"{"jsonrpc":"2.0","id":90071992547409910e-1,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":9007199254740990e0,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":1.0,"method":"tools/list","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":1e0,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":1E0,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":-0.0,"method":"ping"}"#,
        "\n",
    );

    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let up_in_w = PipeWriter { tx: up_in_tx };
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            up_in_w,
            BufReader::new(Cursor::new(Vec::<u8>::new())),
        )
        .expect("non-plain integer ids must emit -32600 without crashing session");

    assert!(
        up_in_rx.try_recv().is_err(),
        "exponent/decimal numeric client ids must NEVER reach upstream"
    );

    let out_str = String::from_utf8(client_out).unwrap();
    let lines: Vec<Value> = out_str
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 6);
    for (idx, resp) in lines.iter().enumerate() {
        assert_eq!(resp["id"], json!(null), "line {idx}: {resp}");
        assert_eq!(resp["error"]["code"], json!(-32600), "line {idx}: {resp}");
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("plain integer without decimal point or exponent"),
            "line {idx}: unexpected error message: {resp}"
        );
    }
}

#[test]
fn round8_notifications_cancelled_drops_exponent_and_decimal_request_ids() {
    let mut proxy = make_proxy("");
    let (client_in_w, client_in_r) = step_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe_timeout();
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let up_in_w = PipeWriter { tx: up_in_tx };
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    let proxy_thread = thread::spawn(move || {
        let res = proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r);
        let _ = done_tx.send(res);
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":9007199254740991,\"method\":\"ping\"}\n");
    let f1 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f1.trim_end()).unwrap()["id"],
        json!(9007199254740991_i64)
    );

    client_in_w.send_and_sync_queued(
        concat!(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":90071992547409910e-1}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9007199254740990e0}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1.0}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
            "\n",
        )
        .as_bytes(),
    );
    assert!(
        up_in_rx.try_recv().is_err(),
        "exponent/decimal cancellations must not cancel active request or reach upstream"
    );

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":9007199254740991,"result":{{"pong":1}}}}"#
    )
    .unwrap();
    let line1 = client_out_r.read_line_timeout(Duration::from_secs(2), "resp max safe");
    assert_eq!(
        serde_json::from_str::<Value>(line1.trim_end()).unwrap()["id"],
        json!(9007199254740991_i64)
    );

    let f2 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f2.trim_end()).unwrap()["id"],
        json!(2)
    );
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":2,"result":{{"pong":2}}}}"#
    )
    .unwrap();
    let line2 = client_out_r.read_line_timeout(Duration::from_secs(2), "resp 2");
    assert_eq!(
        serde_json::from_str::<Value>(line2.trim_end()).unwrap()["id"],
        json!(2)
    );

    drop(client_in_w);
    drop(up_out_w);
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit timed out")
        .unwrap();
    proxy_thread.join().unwrap();
}

#[test]
fn round8_writer_error_with_unsaturated_channel_preserves_io_error_over_upstream_eof() {
    const RAW_OS_CODE: i32 = 32;
    let mut proxy = make_proxy("LIMIT 1 calls\n");
    let (client_in_w, client_in_r) = step_pipe();
    let (first_tx, first_rx) = mpsc::sync_channel(1);
    let (failed_tx, failed_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (_hold_tx, hold_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    struct OneNotifReader {
        release_rx: Option<mpsc::Receiver<()>>,
        hold_rx: Option<mpsc::Receiver<()>>,
        emitted: usize,
        buf: Vec<u8>,
        pos: usize,
    }

    impl Read for OneNotifReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.buf.len() {
                if let Some(rx) = self.release_rx.take() {
                    let _ = rx.recv();
                }
                self.emitted += 1;
                if self.emitted == 1 {
                    self.buf = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"pong\":1}}\n".to_vec();
                } else if self.emitted == 2 {
                    self.buf = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"n\":1}}\n".to_vec();
                } else {
                    let _ = self.hold_rx.take().map(|rx| rx.recv());
                    return Ok(0);
                }
                self.pos = 0;
            }
            let n = (self.buf.len() - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    let up_out_r = BufReader::new(OneNotifReader {
        release_rx: Some(release_rx),
        hold_rx: Some(hold_rx),
        emitted: 0,
        buf: Vec::new(),
        pos: 0,
    });

    let proxy_thread = thread::spawn(move || {
        let mut client_out = TwoStageWaitWriter {
            writes: 0,
            w1_rx: None,
            w3_rx: Some(failed_rx),
        };
        let res = proxy.run(
            client_in_r,
            &mut client_out,
            FailSecondWrite {
                writes: 0,
                raw_os_code: RAW_OS_CODE,
                first_tx: Some(first_tx),
                dropped_tx: Some(failed_tx),
            },
            up_out_r,
        );
        let _ = done_tx.send((proxy, res));
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    first_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first write succeeded");

    client_in_w.send_and_sync_queued(
        concat!(
            "bad\r1\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            "bad\r2\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app"}}}"#,
            "\n",
        )
        .as_bytes(),
    );
    release_tx.send(()).unwrap();

    let (proxy, res) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit after unsaturated-channel writer error timed out");
    drop(client_in_w);
    proxy_thread.join().unwrap();
    assert!(
        matches!(res, Err(ProxyError::Io(ref err)) if err.raw_os_error() == Some(RAW_OS_CODE)),
        "post-lookahead poll_writer_error must preserve ProxyError::Io(raw_os_error={RAW_OS_CODE}) instead of UpstreamEof, got {res:?}"
    );
    assert_eq!(
        proxy.ledger().verify_integrity().unwrap(),
        0,
        "tools/call must not burn quota when UpstreamWriteFailed is queued"
    );
}

#[test]
fn round8_eof_behind_64_notifications_aborts_tools_call_in_o1_without_burning_quota() {
    struct FloodThenEofReader {
        release_rx: Option<mpsc::Receiver<()>>,
        eof_reached_tx: Option<mpsc::SyncSender<()>>,
        emitted: usize,
        buf: Vec<u8>,
        pos: usize,
    }

    impl Read for FloodThenEofReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.buf.len() {
                if let Some(rx) = self.release_rx.take() {
                    let _ = rx.recv();
                }
                let idx = self.emitted;
                self.emitted += 1;
                if idx == 0 {
                    self.buf = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"pong\":1}}\n".to_vec();
                } else if idx <= 64 {
                    self.buf = format!(
                        "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"n\":{idx}}}}}\n"
                    )
                    .into_bytes();
                } else {
                    let _ = self.eof_reached_tx.take().map(|tx| tx.send(()));
                    return Ok(0);
                }
                self.pos = 0;
            }
            let n = (self.buf.len() - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    let mut proxy = make_proxy("LIMIT 1 calls\n");
    let (client_in_w, client_in_r) = step_pipe();
    let (client_out_w, mut client_out_r) = mem_pipe_timeout();
    let (up_in_w, mut up_in_r) = mem_pipe_timeout();
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (eof_tx, eof_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    let up_out_r = BufReader::new(FloodThenEofReader {
        release_rx: Some(release_rx),
        eof_reached_tx: Some(eof_tx),
        emitted: 0,
        buf: Vec::new(),
        pos: 0,
    });

    let proxy_thread = thread::spawn(move || {
        let mut gated_out = WaitOnNthWrite {
            inner: client_out_w,
            writes: 0,
            wait_on: 1,
            wait_rx: Some(eof_rx),
        };
        let res = proxy.run(client_in_r, &mut gated_out, up_in_w, up_out_r);
        let _ = done_tx.send((proxy, res));
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    let seen_ping = up_in_r.read_line_timeout(Duration::from_secs(2), "initial outbound ping");
    assert!(seen_ping.contains("\"id\":1"));

    client_in_w.send_and_sync_queued(
        b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"merge_pr\",\"arguments\":{\"repo\":\"org/app\"}}}\n",
    );
    release_tx.send(()).unwrap();

    let line1 = client_out_r.read_line_timeout(Duration::from_secs(2), "ping resp 1");
    let resp1: Value = serde_json::from_str(line1.trim_end()).unwrap();
    assert_eq!(resp1["id"], json!(1));

    let line2 = client_out_r.read_line_timeout(Duration::from_secs(2), "eof error for id 2");
    let resp2: Value = serde_json::from_str(line2.trim_end()).unwrap();
    assert_eq!(resp2["id"], json!(2));
    assert_eq!(resp2["error"]["code"], json!(-32603));

    drop(client_in_w);
    let (proxy, res) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit after 64 notifications + EOF timed out");
    proxy_thread.join().unwrap();
    assert!(
        matches!(res, Err(ProxyError::UpstreamEof)),
        "expected ProxyError::UpstreamEof, got {res:?}"
    );
    assert_eq!(
        proxy.ledger().verify_integrity().unwrap(),
        0,
        "tools/call must not burn SQLite quota when EOF sits behind 64+ notifications"
    );
}

#[test]
fn round9_rejects_negative_zero_ids_and_matches_upstream_float_int() {
    // 1. Client id: -0 rejected with -32600 before upstream.
    let mut proxy = make_proxy("");
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(
                b"{\"jsonrpc\":\"2.0\",\"id\":-0,\"method\":\"ping\"}\n".to_vec(),
            )),
            &mut client_out,
            PipeWriter { tx: up_in_tx },
            BufReader::new(Cursor::new(Vec::<u8>::new())),
        )
        .expect("id: -0 must emit -32600 without crashing session");
    assert!(
        up_in_rx.try_recv().is_err(),
        "id: -0 must never reach upstream"
    );
    let resp: Value =
        serde_json::from_str(String::from_utf8(client_out).unwrap().trim_end()).unwrap();
    assert_eq!(resp["id"], json!(null));
    assert_eq!(resp["error"]["code"], json!(-32600));

    // 2. notifications/cancelled with requestId: -0 must NOT cancel active id: 0 or reach upstream.
    let mut cancel_proxy = make_proxy("");
    let (client_in_w, client_in_r) = step_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe_timeout();
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let proxy_thread = thread::spawn(move || {
        let res = cancel_proxy.run(
            client_in_r,
            &mut client_out_w,
            PipeWriter { tx: up_in_tx },
            up_out_r,
        );
        let _ = done_tx.send(res);
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"ping\"}\n");
    let f0 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f0.trim_end()).unwrap()["id"],
        json!(0)
    );

    client_in_w.send_and_sync_queued(
        concat!(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":-0}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            "\n",
        )
        .as_bytes(),
    );
    assert!(
        up_in_rx.try_recv().is_err(),
        "requestId: -0 must not cancel active id: 0 or reach upstream"
    );

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":0,"result":{{"pong":0}}}}"#
    )
    .unwrap();
    let r0 = client_out_r.read_line_timeout(Duration::from_secs(2), "resp 0");
    assert_eq!(
        serde_json::from_str::<Value>(r0.trim_end()).unwrap()["id"],
        json!(0)
    );

    // 3. Upstream reply with 1.0 matches client plain safe-integer id: 1 cleanly.
    let f1 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f1.trim_end()).unwrap()["id"],
        json!(1)
    );
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1.0,"result":{{"pong":1}}}}"#
    )
    .unwrap();
    let r1 = client_out_r.read_line_timeout(Duration::from_secs(2), "resp 1 via 1.0");
    let r1_val = assert_wire_int_id(&r1, 1);
    assert_eq!(r1_val["result"]["pong"], json!(1));

    drop(client_in_w);
    drop(up_out_w);
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit timed out")
        .unwrap();
    proxy_thread.join().unwrap();
}

fn assert_wire_int_id(raw_line: &str, expected: i64) -> Value {
    let val: Value = serde_json::from_str(raw_line.trim_end()).unwrap();
    assert_eq!(val["id"].as_i64(), Some(expected), "wire line: {raw_line}");
    assert!(
        !val["id"].is_f64(),
        "reply must emit plain integer id {expected}, got {raw_line}"
    );
    assert_eq!(
        serde_json::from_value::<i64>(val["id"].clone()).unwrap(),
        expected
    );
    val
}

#[test]
fn round9_emits_client_integer_id_for_tools_list_result_and_error() {
    let mut proxy = make_proxy("");
    let (client_in_w, client_in_r) = step_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe_timeout();
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let proxy_thread = thread::spawn(move || {
        let res = proxy.run(
            client_in_r,
            &mut client_out_w,
            PipeWriter { tx: up_in_tx },
            up_out_r,
        );
        let _ = done_tx.send(res);
    });

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n");
    let f3 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let _ = assert_wire_int_id(&f3, 3);
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":3.0,"result":{{"tools":[{{"name":"merge_pr"}},{{"name":"blocked_tool"}}]}}}}"#
    )
    .unwrap();
    let r3 = client_out_r.read_line_timeout(Duration::from_secs(2), "tools/list result via 3.0");
    let r3_val = assert_wire_int_id(&r3, 3);
    assert_eq!(r3_val["result"]["tools"], json!([{"name": "merge_pr"}]));

    client_in_w.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/list\"}\n");
    let f4 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let _ = assert_wire_int_id(&f4, 4);
    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":4.0,"error":{{"code":-32000,"message":"upstream list error"}}}}"#
    )
    .unwrap();
    let r4 = client_out_r.read_line_timeout(Duration::from_secs(2), "tools/list error via 4.0");
    let r4_val = assert_wire_int_id(&r4, 4);
    assert_eq!(r4_val["error"]["code"], json!(-32000));

    drop(client_in_w);
    drop(up_out_w);
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("proxy exit timed out")
        .unwrap();
    proxy_thread.join().unwrap();
}

#[test]
fn round9_denies_negative_zero_int_argument_fact_with_receipt() {
    // tools/call argument `mode: -0` mapped to FactType::Int is denied with receipt & never forwarded.
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
             ALLOW ops.run\n\
             ON target \"prod\"\n\
             WHERE resource.mode == 0\n",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let signed = sign_mandate(&root_kp, &mandate_text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();
    let policy_map = ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "run_op": {
                    "action": "ops.run",
                    "resource_kind": "target",
                    "static_resource_id": "prod",
                    "arg_facts": {
                        "mode": { "field": "resource.mode", "type": "int" }
                    }
                }
            }
        }"#,
    )
    .unwrap();
    let mut mode_proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        policy_map,
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();

    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe_timeout();
    let (up_in_w, mut up_in_r) = mem_pipe_timeout();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let res = mode_proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r);
        let _ = done_tx.send((mode_proxy, res));
    });

    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"run_op","arguments":{{"mode":-0}}}}}}"#
    )
    .unwrap();
    let denied_line = client_out_r.read_line_timeout(Duration::from_secs(2), "mode -0 denial");
    let denied: Value = serde_json::from_str(denied_line.trim_end()).unwrap();
    assert_eq!(denied["id"], json!(1));
    assert_eq!(denied["error"]["code"], json!(-32001));
    assert!(denied["error"]["data"]["receipt_hash"].is_string());

    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"run_op","arguments":{{"mode":0}}}}}}"#
    )
    .unwrap();
    let fwd_line = up_in_r.read_line_timeout(Duration::from_secs(2), "mode 0 forwarded");
    let fwd: Value = serde_json::from_str(fwd_line.trim_end()).unwrap();
    assert_eq!(fwd["id"], json!(2));

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":2.0,"result":{{"ok":true}}}}"#
    )
    .unwrap();
    let ok_line = client_out_r.read_line_timeout(Duration::from_secs(2), "mode 0 reply");
    let ok_val = assert_wire_int_id(&ok_line, 2);
    assert_eq!(ok_val["result"]["ok"], json!(true));

    drop(client_in_w);
    drop(up_out_w);
    let (mode_proxy, res) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("mode proxy exit timed out");
    handle.join().unwrap();
    res.expect("mode: -0 denied cleanly and mode: 0 permitted with 2.0 reply");
    assert_eq!(mode_proxy.ledger().verify_integrity().unwrap(), 2);
}
