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
