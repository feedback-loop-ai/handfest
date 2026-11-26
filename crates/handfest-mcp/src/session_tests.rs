use std::io::{self, BufReader, Cursor, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use handfest_anchors::Ed25519Keypair;
use handfest_core::ast::parse_rfc3339_utc;
use handfest_ledger::SqliteLedger;

use crate::mapping::ToolPolicyMap;
use crate::proxy::{verify_mandate_chain, FixedClock, McpProxy};
use crate::transport::{DuplexTransport, RecvOutcome};

use super::*;

struct BlockingReader(mpsc::Receiver<()>);

impl Read for BlockingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
}

struct BrokenPipeSignalingWriter {
    dropped_tx: Option<mpsc::SyncSender<()>>,
}

impl Write for BrokenPipeSignalingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "simulated upstream broken pipe",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BrokenPipeSignalingWriter {
    fn drop(&mut self) {
        // `DuplexTransport`'s writer thread drops `upstream_in` strictly AFTER sending
        // `Err(ProxyError::Io(BrokenPipe))` into `writer_done_tx`.
        if let Some(tx) = self.dropped_tx.take() {
            let _ = tx.send(());
        }
    }
}

struct GatedBrokenPipeWriter {
    seen_tx: Option<mpsc::SyncSender<()>>,
    fail_rx: Option<mpsc::Receiver<()>>,
    dropped_tx: Option<mpsc::SyncSender<()>>,
}

impl Write for GatedBrokenPipeWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        if let Some(tx) = self.seen_tx.take() {
            let _ = tx.send(());
        }
        if let Some(rx) = self.fail_rx.take() {
            let _ = rx.recv();
        }
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "simulated post-eof upstream broken pipe",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for GatedBrokenPipeWriter {
    fn drop(&mut self) {
        if let Some(tx) = self.dropped_tx.take() {
            let _ = tx.send(());
        }
    }
}

struct AcceptingSignalingWriter {
    seen_tx: Option<mpsc::SyncSender<()>>,
}

impl Write for AcceptingSignalingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(tx) = self.seen_tx.take() {
            let _ = tx.send(());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn build_test_proxy() -> McpProxy<FixedClock, SqliteLedger> {
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
         ALLOW ops.run\n\
         ON target \"staging\"\n",
        root_kp.key_id(),
        agent_kp.key_id(),
    );
    let signed = root_kp
        .sign_mandate(&text, "session-test", valid_from, valid_until)
        .unwrap();
    let verified = verify_mandate_chain(&[signed]).unwrap();
    McpProxy::new(
        verified,
        agent_kp.key_id(),
        ToolPolicyMap::from_json_str(r#"{"tools":{}}"#).unwrap(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap()
}

#[test]
fn post_eof_drain_timeout_in_run_loop_surfaces_broken_pipe() {
    let mut proxy = build_test_proxy().with_shutdown_timeout(Duration::from_millis(20));
    let (seen_tx, seen_rx) = mpsc::sync_channel(1);
    let (fail_tx, fail_rx) = mpsc::sync_channel(1);
    let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
    let (up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let client_in = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";

    // Drive `McpProxy::run`'s exact event loop with upstream stdout held open (cannot exit via
    // `Disconnected`). Once client EOF arms `state.shutdown_deadline` (strictly after top-of-loop
    // `poll_writer_error()` checks), trigger `BrokenPipe` and wait past the deadline so
    // `recv_event` deterministically returns `RecvOutcome::Timeout` and only
    // `handle_post_eof_timeout`'s `poll_writer_error()` can surface `BrokenPipe`.
    let handle = thread::spawn(move || {
        let transport = DuplexTransport::start(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            GatedBrokenPipeWriter {
                seen_tx: Some(seen_tx),
                fail_rx: Some(fail_rx),
                dropped_tx: Some(dropped_tx),
            },
            BufReader::new(BlockingReader(up_hold_rx)),
            proxy.max_line_bytes,
        );
        let mut client_out = Vec::new();
        let mut armed_deadline = false;
        let mut fail_tx = Some(fail_tx);
        let res = proxy.drive_session_loop(transport, &mut client_out, |state| {
            let Some(deadline) = state.shutdown_deadline else {
                return;
            };
            let Some(tx) = fail_tx.take() else {
                return;
            };
            armed_deadline = true;
            seen_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("writer thread received ping before post-EOF fail");
            let _ = tx.send(());
            dropped_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("writer thread populated writer_done_rx with BrokenPipe");
            if let Some(rem) = deadline.checked_duration_since(Instant::now()) {
                thread::sleep(rem + Duration::from_millis(5));
            }
        });
        let _ = done_tx.send((armed_deadline, res));
    });

    let (armed_deadline, res) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("run loop hung instead of exiting via RecvOutcome::Timeout");
    let _ = up_hold_tx.send(());
    handle.join().unwrap();
    assert!(
        armed_deadline,
        "client EOF with active request must arm shutdown_deadline before recv_event"
    );
    assert!(
        matches!(res, Err(ProxyError::Io(ref io_err)) if io_err.kind() == io::ErrorKind::BrokenPipe),
        "expected Err(ProxyError::Io(BrokenPipe)) via RecvOutcome::Timeout, got {res:?}"
    );
}

#[test]
fn client_eof_arms_shutdown_deadline_and_exits_on_timeout_in_run() {
    let mut proxy = build_test_proxy().with_shutdown_timeout(Duration::from_millis(50));
    let (seen_tx, seen_rx) = mpsc::sync_channel(1);
    let (up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let client_in = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";

    // Upstream accepts `ping` cleanly (no BrokenPipe) and holds stdout silently open (no reply,
    // no EOF). The ONLY way `McpProxy::run` can terminate is if client EOF arms
    // `state.shutdown_deadline` and `recv_event` hits `RecvOutcome::Timeout`.
    let handle = thread::spawn(move || {
        let mut client_out = Vec::new();
        let res = proxy.run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            AcceptingSignalingWriter {
                seen_tx: Some(seen_tx),
            },
            BufReader::new(BlockingReader(up_hold_rx)),
        );
        let _ = done_tx.send(res);
    });

    seen_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream received ping before EOF drain");
    let res = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("McpProxy::run hung instead of arming shutdown_deadline on client EOF");
    let _ = up_hold_tx.send(());
    handle.join().unwrap();
    assert!(
        res.is_ok(),
        "expected clean Ok(()) on post-EOF timeout, got {res:?}"
    );
}

#[test]
fn post_eof_armed_deadline_timeout_surfaces_broken_pipe() {
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);

    let mut proxy = build_test_proxy().with_shutdown_timeout(Duration::from_millis(20));
    let mut state = SessionState::default();
    let mut client_out = Vec::new();
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingReader(client_hold_rx)),
        BrokenPipeSignalingWriter {
            dropped_tx: Some(dropped_tx),
        },
        BufReader::new(BlockingReader(up_hold_rx)),
        1024,
    );

    proxy
        .on_client_read(
            Ok(Some(
                r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string(),
            )),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("active request dispatched");
    assert!(!proxy.check_client_eof(&mut state, &transport));
    assert!(state.shutdown_deadline.is_none());

    proxy
        .on_client_read(Ok(None), &mut state, &mut transport, &mut client_out)
        .expect("client EOF recorded");
    assert!(!proxy.check_client_eof(&mut state, &transport));
    let deadline = state
        .shutdown_deadline
        .expect("client EOF with active request must arm shutdown_deadline");

    dropped_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer thread failed with BrokenPipe and populated writer_done_rx");
    if let Some(rem) = deadline.checked_duration_since(Instant::now()) {
        thread::sleep(rem + Duration::from_millis(5));
    }

    let outcome = transport.recv_event(state.shutdown_deadline);
    assert!(
        matches!(outcome, RecvOutcome::Timeout),
        "expected RecvOutcome::Timeout from EOF-armed deadline, got {outcome:?}"
    );
    let step = proxy.handle_recv_outcome(outcome, &mut state, &mut transport, &mut client_out);
    assert!(
        matches!(
            step,
            LoopStep::Finish(Err(ProxyError::Io(ref io_err)))
                if io_err.kind() == io::ErrorKind::BrokenPipe
        ),
        "expected LoopStep::Finish(Err(BrokenPipe)) on EOF-armed RecvOutcome::Timeout dispatch"
    );
}

#[test]
fn post_eof_armed_deadline_timeout_returns_ok_when_writer_has_no_error() {
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);

    let mut proxy = build_test_proxy().with_shutdown_timeout(Duration::from_millis(20));
    let mut state = SessionState::default();
    let mut client_out = Vec::new();
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingReader(client_hold_rx)),
        io::sink(),
        BufReader::new(BlockingReader(up_hold_rx)),
        1024,
    );

    proxy
        .on_client_read(
            Ok(Some(
                r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string(),
            )),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("active request dispatched");
    proxy
        .on_client_read(Ok(None), &mut state, &mut transport, &mut client_out)
        .expect("client EOF recorded");
    assert!(!proxy.check_client_eof(&mut state, &transport));
    assert!(state.shutdown_deadline.is_some());

    let outcome = transport.recv_event(state.shutdown_deadline);
    assert!(matches!(outcome, RecvOutcome::Timeout));
    let step = proxy.handle_recv_outcome(outcome, &mut state, &mut transport, &mut client_out);
    assert!(matches!(step, LoopStep::Finish(Ok(()))));

    // When idle at client EOF, `check_client_eof` finishes immediately without arming a deadline.
    let mut idle_state = SessionState {
        client_eof: true,
        ..SessionState::default()
    };
    assert!(proxy.check_client_eof(&mut idle_state, &transport));
    assert!(idle_state.shutdown_deadline.is_none());
}

fn make_idle_transport() -> (DuplexTransport, mpsc::SyncSender<()>, mpsc::SyncSender<()>) {
    let (client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let transport = DuplexTransport::start(
        BufReader::new(BlockingReader(client_hold_rx)),
        io::sink(),
        BufReader::new(BlockingReader(up_hold_rx)),
        1024,
    );
    (transport, client_hold_tx, up_hold_tx)
}

#[test]
fn with_max_line_bytes_rejects_zero_and_accepts_positive() {
    let Err(err) = build_test_proxy().with_max_line_bytes(0) else {
        panic!("zero frame limit must be rejected");
    };
    assert!(
        matches!(err, ProxyError::InvalidChain(ref msg) if msg == "max_line_bytes must be greater than zero"),
        "unexpected error: {err:?}"
    );
    let ok = build_test_proxy()
        .with_max_line_bytes(1)
        .expect("positive frame limit must be accepted");
    assert_eq!(ok.max_line_bytes, 1);
}

#[test]
fn duplicate_active_and_queued_request_ids_rejected_at_admission() {
    let (mut transport, _c_hold, _u_hold) = make_idle_transport();
    let mut proxy = build_test_proxy();
    let mut state = SessionState::default();
    let mut client_out = Vec::new();
    let ping = |id: u64| format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);

    proxy
        .on_client_read(
            Ok(Some(ping(1))),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("initial active request succeeds");
    assert_eq!(
        state.active_id().map(JsonRpcId::to_json_literal).as_deref(),
        Some("1")
    );

    // Duplicate of ACTIVE id: 1 must be refused immediately at admission and NOT queued.
    proxy
        .on_client_read(
            Ok(Some(ping(1))),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("duplicate active id emits -32600 cleanly");
    assert!(state.queued_client.is_empty());

    // Queue distinct id: 2, then reject duplicate of QUEUED id: 2 at admission.
    proxy
        .on_client_read(
            Ok(Some(ping(2))),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("distinct id: 2 enqueues");
    assert_eq!(state.queued_client.len(), 1);
    proxy
        .on_client_read(
            Ok(Some(ping(2))),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("duplicate queued id emits -32600 cleanly");
    assert_eq!(state.queued_client.len(), 1);

    // Completing id: 1 drains id: 2 (and NEVER dispatches a second id: 1).
    proxy
        .on_upstream_read(
            Some(r#"{"jsonrpc":"2.0","id":1,"result":{"pong":1}}"#.to_string()),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("upstream response for id: 1 handled");
    proxy
        .drain_queued_client(&mut state, &mut transport, &mut client_out)
        .expect("drain dispatches id: 2");
    assert_eq!(
        state.active_id().map(JsonRpcId::to_json_literal).as_deref(),
        Some("2")
    );
    assert!(state.queued_client.is_empty());

    let lines: Vec<String> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 3);
    for (line, expected_id) in [(&lines[0], r#""id":1"#), (&lines[1], r#""id":2"#)] {
        assert!(line.contains(expected_id));
        assert!(line.contains(r#""code":-32600"#));
        assert!(line.contains("duplicate in-flight JSON-RPC request id"));
    }
    assert!(lines[2].contains(r#""id":1"#) && lines[2].contains(r#""pong":1"#));
}

#[test]
fn queued_client_frame_cap_returns_invalid_request_and_protocol_error() {
    let (mut transport, _c_hold, _u_hold) = make_idle_transport();
    let mut proxy = build_test_proxy();
    let mut state = SessionState::default();
    let mut client_out = Vec::new();

    // Activate id: 1 so subsequent requests queue.
    proxy
        .on_client_read(
            Ok(Some(
                r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string(),
            )),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .unwrap();

    for i in 2..=(MAX_QUEUED_CLIENT_FRAMES + 1) {
        proxy
            .on_client_read(
                Ok(Some(format!(
                    r#"{{"jsonrpc":"2.0","id":{i},"method":"ping"}}"#
                ))),
                &mut state,
                &mut transport,
                &mut client_out,
            )
            .expect("within queue cap must enqueue");
    }
    assert_eq!(state.queued_client.len(), MAX_QUEUED_CLIENT_FRAMES);

    let overflow_id = MAX_QUEUED_CLIENT_FRAMES + 2;
    let err = proxy
        .on_client_read(
            Ok(Some(format!(
                r#"{{"jsonrpc":"2.0","id":{overflow_id},"method":"ping"}}"#
            ))),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .unwrap_err();
    assert!(
        matches!(err, ProxyError::UpstreamProtocol(ref msg) if msg == "client exceeded maximum queued JSON-RPC frames"),
        "unexpected overflow error: {err:?}"
    );
    let out = String::from_utf8(client_out).unwrap();
    assert!(out.contains(r#""id":null"#));
    assert!(out.contains(r#""code":-32600"#));
    assert!(out.contains("client exceeded maximum queued JSON-RPC frames"));
}

#[test]
fn non_object_frames_on_both_sides_and_unsolicited_idle_response_refuse_cleanly() {
    // 1. Non-object client frame (JSON-RPC batch array) -> -32600 Invalid Request
    let (mut transport, _c1, _u1) = make_idle_transport();
    let mut proxy = build_test_proxy();
    let mut state = SessionState::default();
    let mut client_out = Vec::new();
    proxy
        .on_client_read(
            Ok(Some(
                r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#.to_string(),
            )),
            &mut state,
            &mut transport,
            &mut client_out,
        )
        .expect("non-object client frame emits JSON-RPC error without killing session");
    let c_out = String::from_utf8(client_out).unwrap();
    assert!(c_out.contains(r#""id":null"#));
    assert!(c_out.contains(r#""code":-32600"#));
    assert!(c_out.contains("JSON-RPC frame must be a JSON object"));

    // 2. Non-object upstream frame -> -32603 + ProxyError::UpstreamProtocol
    let mut u_out = Vec::new();
    let err_non_obj = proxy
        .on_upstream_read(
            Some(r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#.to_string()),
            &mut state,
            &mut transport,
            &mut u_out,
        )
        .unwrap_err();
    assert!(matches!(
        err_non_obj,
        ProxyError::UpstreamProtocol(ref msg) if msg == "upstream frame must be a JSON object"
    ));
    let u_out_str = String::from_utf8(u_out).unwrap();
    assert!(u_out_str.contains(r#""id":null"#));
    assert!(u_out_str.contains(r#""code":-32603"#));
    assert!(u_out_str.contains("upstream frame must be a JSON object"));

    // 3. Unsolicited upstream response while idle (no pending request) -> -32603 + UpstreamProtocol
    let mut idle_out = Vec::new();
    let err_idle = proxy
        .on_upstream_read(
            Some(r#"{"jsonrpc":"2.0","id":99,"result":{}}"#.to_string()),
            &mut state,
            &mut transport,
            &mut idle_out,
        )
        .unwrap_err();
    let expected = "unexpected upstream response for id 99 with no pending request";
    assert!(matches!(
        err_idle,
        ProxyError::UpstreamProtocol(ref msg) if msg == expected
    ));
    let idle_str = String::from_utf8(idle_out).unwrap();
    assert!(idle_str.contains(r#""id":null"#));
    assert!(idle_str.contains(r#""code":-32603"#));
    assert!(idle_str.contains(expected));
}
