use std::io::{self, BufReader, Read, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

#[test]
fn post_eof_drain_timeout_surfaces_broken_pipe_from_poll_writer_error() {
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);

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

    // Simulate post-EOF drain deadline expiring (`RecvOutcome::Timeout`) before `UpstreamWriteFailed`
    // is dequeued from `event_rx`: `handle_post_eof_timeout` MUST surface `BrokenPipe`.
    let expired_deadline = Some(Instant::now());
    let outcome = transport.recv_event(expired_deadline);
    assert!(
        matches!(outcome, RecvOutcome::Timeout),
        "expected RecvOutcome::Timeout, got {outcome:?}"
    );
    let err = handle_post_eof_timeout(&transport).unwrap_err();
    assert!(
        matches!(err, ProxyError::Io(ref io_err) if io_err.kind() == io::ErrorKind::BrokenPipe),
        "expected ProxyError::Io(BrokenPipe) on post-EOF drain timeout, got {err:?}"
    );
}

#[test]
fn post_eof_drain_timeout_returns_ok_when_writer_has_no_error() {
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);

    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingReader(client_hold_rx)),
        io::sink(),
        BufReader::new(BlockingReader(up_hold_rx)),
        1024,
    );

    let outcome = transport.recv_event(Some(Instant::now()));
    assert!(matches!(outcome, RecvOutcome::Timeout));
    assert!(handle_post_eof_timeout(&transport).is_ok());
}
