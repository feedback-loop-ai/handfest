use std::io::{self, BufReader, Read, Write};
use std::sync::mpsc;
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
fn post_eof_drain_timeout_dispatch_surfaces_broken_pipe_without_prior_polling() {
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);

    let mut proxy = build_test_proxy();
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

    transport
        .send_upstream("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}".to_string())
        .expect("initial enqueue into writer channel succeeds");
    dropped_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer thread failed with BrokenPipe and populated writer_done_rx");

    // Deterministically produce `RecvOutcome::Timeout` and drive `McpProxy::run`'s exact outcome
    // dispatcher (`handle_recv_outcome`), proving the timeout arm itself surfaces `BrokenPipe`
    // rather than relying on an earlier non-timeout `poll_writer_error` or `UpstreamWriteFailed`.
    let outcome = transport.recv_event(Some(Instant::now()));
    assert!(
        matches!(outcome, RecvOutcome::Timeout),
        "expected RecvOutcome::Timeout, got {outcome:?}"
    );
    let step = proxy.handle_recv_outcome(outcome, &mut state, &mut transport, &mut client_out);
    assert!(
        matches!(
            step,
            LoopStep::Finish(Err(ProxyError::Io(ref io_err)))
                if io_err.kind() == io::ErrorKind::BrokenPipe
        ),
        "expected LoopStep::Finish(Err(BrokenPipe)) on RecvOutcome::Timeout dispatch"
    );
}

#[test]
fn post_eof_drain_timeout_dispatch_returns_ok_when_writer_has_no_error() {
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);

    let mut proxy = build_test_proxy();
    let mut state = SessionState::default();
    let mut client_out = Vec::new();
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingReader(client_hold_rx)),
        io::sink(),
        BufReader::new(BlockingReader(up_hold_rx)),
        1024,
    );

    let outcome = transport.recv_event(Some(Instant::now()));
    assert!(matches!(outcome, RecvOutcome::Timeout));
    let step = proxy.handle_recv_outcome(outcome, &mut state, &mut transport, &mut client_out);
    assert!(matches!(step, LoopStep::Finish(Ok(()))));
}
