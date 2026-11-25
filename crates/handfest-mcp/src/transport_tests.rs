use std::io::{self, BufReader, Cursor, Read};
use std::sync::mpsc;

use super::*;

struct BurstLineReader {
    remaining: usize,
    emitted: usize,
    milestones: Vec<(usize, mpsc::SyncSender<()>)>,
    ready_tx: Option<mpsc::SyncSender<()>>,
    eof_gate_rx: Option<mpsc::Receiver<()>>,
    buf: Vec<u8>,
    pos: usize,
}

impl BurstLineReader {
    fn new(lines: usize, ready_tx: mpsc::SyncSender<()>) -> Self {
        Self {
            remaining: lines,
            emitted: 0,
            milestones: Vec::new(),
            ready_tx: Some(ready_tx),
            eof_gate_rx: None,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn gated(
        lines: usize,
        ready_tx: mpsc::SyncSender<()>,
        eof_gate_rx: mpsc::Receiver<()>,
    ) -> Self {
        let mut r = Self::new(lines, ready_tx);
        r.eof_gate_rx = Some(eof_gate_rx);
        r
    }

    fn with_milestone(mut self, after_lines: usize, tx: mpsc::SyncSender<()>) -> Self {
        self.milestones.push((after_lines, tx));
        self
    }

    fn notify_milestones(&mut self) {
        let emitted = self.emitted;
        self.milestones.retain(|(at, tx)| {
            let pending = emitted < *at;
            if !pending {
                let _ = tx.send(());
            }
            pending
        });
    }
}

impl Read for BurstLineReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            if self.remaining == 0 {
                let _ = self.eof_gate_rx.take().map(|rx| rx.recv());
                return Ok(0);
            }
            self.remaining -= 1;
            self.emitted += 1;
            if self.remaining == 0 {
                let _ = self.ready_tx.take().map(|tx| tx.send(()));
            }
            self.notify_milestones();
            self.buf = format!(
                "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"id\":\"n{}\"}}}}\n",
                self.emitted
            )
            .into_bytes();
            self.pos = 0;
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

struct RawOsFailingWriter {
    raw_os_code: i32,
    attempted_tx: Option<mpsc::SyncSender<()>>,
}

impl Write for RawOsFailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        if let Some(tx) = self.attempted_tx.take() {
            let _ = tx.send(());
        }
        Err(io::Error::from_raw_os_error(self.raw_os_code))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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

struct BlockingEofReader(mpsc::Receiver<()>);

impl Read for BlockingEofReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
}

#[test]
fn finish_writer_drops_full_event_channel_without_deadlock_and_preserves_raw_os_error() {
    const RAW_OS_CODE: i32 = 32;
    let expected_kind = io::Error::from_raw_os_error(RAW_OS_CODE).kind();
    let (full_tx, full_rx) = mpsc::sync_channel(1);
    let (fail_tx, fail_rx) = mpsc::sync_channel(1);
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        RawOsFailingWriter {
            raw_os_code: RAW_OS_CODE,
            attempted_tx: Some(fail_tx),
        },
        BufReader::new(BurstLineReader::new(EVENT_CHANNEL_BOUND + 1, full_tx)),
        1024,
    );

    // Wait until all `EVENT_CHANNEL_BOUND` slots of `event_rx` are filled.
    full_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream reader fills event_rx");

    transport
        .send_upstream(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string())
        .expect("queued frame to failing writer");
    fail_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer observed raw OS error");

    let started = Instant::now();
    let res = transport.finish_writer(Duration::from_secs(5));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "finish_writer deadlocked while event_rx was full"
    );
    assert!(
        matches!(
            res,
            Err(ProxyError::Io(ref io_err))
                if io_err.kind() == expected_kind && io_err.raw_os_error() == Some(RAW_OS_CODE)
        ),
        "expected preserved ProxyError::Io with raw_os_error={RAW_OS_CODE}, got {res:?}"
    );
}

#[test]
fn live_writer_failure_preserves_raw_os_error_via_event_and_take_writer_error() {
    const RAW_OS_CODE: i32 = 9;
    let expected_kind = io::Error::from_raw_os_error(RAW_OS_CODE).kind();
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        RawOsFailingWriter {
            raw_os_code: RAW_OS_CODE,
            attempted_tx: None,
        },
        BufReader::new(BlockingEofReader(up_hold_rx)),
        1024,
    );

    transport
        .send_upstream(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string())
        .expect("queued frame to failing writer");

    let ev = transport.recv_event(Some(Instant::now() + Duration::from_secs(2)));
    assert!(matches!(
        ev,
        RecvOutcome::Event(IoEvent::UpstreamWriteFailed)
    ));
    let err = transport.take_writer_error();
    assert!(
        matches!(
            err,
            ProxyError::Io(ref io_err)
                if io_err.kind() == expected_kind && io_err.raw_os_error() == Some(RAW_OS_CODE)
        ),
        "expected live writer error to preserve raw_os_error={RAW_OS_CODE}, got {err:?}"
    );
}

#[test]
fn send_upstream_never_blocks_when_writer_queue_is_full_and_wakes_on_drain() {
    let (gate_tx, gate_rx) = mpsc::sync_channel(1);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let (_up_hold_tx, up_hold_rx) = mpsc::sync_channel(1);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        GateWriter {
            gate_rx: Some(gate_rx),
            entered_tx: Some(entered_tx),
        },
        BufReader::new(BlockingEofReader(up_hold_rx)),
        1024,
    );

    // First frame blocks inside `GateWriter::write`.
    transport
        .send_upstream(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string())
        .unwrap();
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer entered GateWriter::write");

    // Fill all `MAX_QUEUED_CLIENT_FRAMES` channel slots without blocking.
    for _ in 0..MAX_QUEUED_CLIENT_FRAMES {
        transport
            .send_upstream(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string())
            .unwrap();
    }
    assert!(!transport.has_pending_upstream());

    // Next `send_upstream` must NOT block; it spills into `pending_upstream` instead.
    let started = Instant::now();
    transport
        .send_upstream(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string())
        .expect("spilled frame must not block");
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "send_upstream blocked when writer queue was full"
    );
    assert!(transport.has_pending_upstream());

    // Release writer -> `UpstreamWriteReady` wakes the consumer, `flush_upstream` drains it,
    // and `finish_writer(Duration::MAX)` does not panic on overflow.
    let _ = gate_tx.send(());
    let woke = transport.recv_event(Some(Instant::now() + Duration::from_secs(2)));
    assert!(matches!(
        woke,
        RecvOutcome::Event(IoEvent::UpstreamWriteReady)
    ));
    transport.flush_upstream().unwrap();
    assert!(!transport.has_pending_upstream());

    transport
        .finish_writer(Duration::MAX)
        .expect("finish_writer(Duration::MAX) must succeed without panicking");
}

#[test]
fn send_upstream_fails_closed_when_pending_overflow_reaches_cap() {
    let (_gate_tx, gate_rx) = mpsc::sync_channel(1);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let mut transport = DuplexTransport::start(
        BufReader::new(Cursor::new(Vec::<u8>::new())),
        GateWriter {
            gate_rx: Some(gate_rx),
            entered_tx: Some(entered_tx),
        },
        BufReader::new(Cursor::new(Vec::<u8>::new())),
        1024,
    );

    transport
        .send_upstream(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string())
        .unwrap();
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer blocked");

    for _ in 0..(MAX_QUEUED_CLIENT_FRAMES * 2) {
        transport
            .send_upstream(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string())
            .unwrap();
    }
    let overflow = transport
        .send_upstream(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string());
    assert!(matches!(
        overflow,
        Err(ProxyError::UpstreamProtocol(ref msg))
            if msg == "upstream writer queue exceeded maximum pending frames"
    ));
}

#[test]
fn recv_event_enforces_expired_deadline_before_popping_buffered_or_queued_events() {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (eof_gate_tx, eof_gate_rx) = mpsc::sync_channel(1);
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        Vec::<u8>::new(),
        BufReader::new(BurstLineReader::gated(4, ready_tx, eof_gate_rx)),
        1024,
    );
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream notifications queued in event_rx");

    // Even with events ready in `event_rx` (and also when buffered via `poll_upstream_eof`),
    // an already-expired deadline MUST return `Timeout` immediately.
    let expired = Instant::now();
    assert!(matches!(
        transport.recv_event(Some(expired)),
        RecvOutcome::Timeout
    ));
    // While upstream is still open, `poll_upstream_eof` buffers notifications and returns false.
    assert!(!transport.poll_upstream_eof());
    assert!(matches!(
        transport.recv_event(Some(expired)),
        RecvOutcome::Timeout
    ));

    // Release EOF behind the buffered notifications: full lookahead MUST detect EOF before
    // draining the notifications, while preserving all 4 notifications + EOF in FIFO order.
    drop(eof_gate_tx);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !transport.poll_upstream_eof() {
        assert!(
            Instant::now() < deadline,
            "poll_upstream_eof failed to detect EOF behind buffered notifications"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        transport.recv_event(Some(expired)),
        RecvOutcome::Timeout
    ));
    for expected in ["n1", "n2", "n3", "n4"] {
        match transport.recv_event(Some(Instant::now() + Duration::from_secs(2))) {
            RecvOutcome::Event(IoEvent::UpstreamLine(Some(line))) => {
                assert!(
                    line.contains(&format!("\"id\":\"{expected}\"")),
                    "expected FIFO notification {expected}, got {line}"
                );
            }
            other => panic!("expected notification {expected}, got {other:?}"),
        }
    }
    assert!(matches!(
        transport.recv_event(Some(Instant::now() + Duration::from_secs(2))),
        RecvOutcome::Event(IoEvent::UpstreamLine(None))
    ));
}

#[test]
fn poll_upstream_eof_detects_write_failure_behind_buffered_notification_in_fifo_order() {
    const RAW_OS_CODE: i32 = 32;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (_eof_gate_tx, eof_gate_rx) = mpsc::sync_channel(1);
    let (fail_tx, fail_rx) = mpsc::sync_channel(1);
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        RawOsFailingWriter {
            raw_os_code: RAW_OS_CODE,
            attempted_tx: Some(fail_tx),
        },
        BufReader::new(BurstLineReader::gated(1, ready_tx, eof_gate_rx)),
        1024,
    );
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream notification queued first");
    assert!(!transport.poll_upstream_eof());

    transport
        .send_upstream(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string())
        .expect("queued frame to failing writer");
    fail_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("writer observed raw OS error");

    let deadline = Instant::now() + Duration::from_secs(2);
    while !transport.poll_upstream_eof() {
        assert!(
            Instant::now() < deadline,
            "poll_upstream_eof failed to detect UpstreamWriteFailed behind notification"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        transport.recv_event(Some(Instant::now() + Duration::from_secs(2))),
        RecvOutcome::Event(IoEvent::UpstreamLine(Some(_)))
    ));
    assert!(matches!(
        transport.recv_event(Some(Instant::now() + Duration::from_secs(2))),
        RecvOutcome::Event(IoEvent::UpstreamWriteFailed)
    ));
    assert!(matches!(
        transport.take_writer_error(),
        ProxyError::Io(ref err) if err.raw_os_error() == Some(RAW_OS_CODE)
    ));
}

#[test]
fn poll_upstream_eof_bounds_buffered_events_to_event_channel_bound() {
    let (phase1_tx, phase1_rx) = mpsc::sync_channel(1);
    let (phase2_tx, phase2_rx) = mpsc::sync_channel(1);
    let (all_tx, _all_rx) = mpsc::sync_channel(1);
    let (_eof_gate_tx, eof_gate_rx) = mpsc::sync_channel(1);
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let reader = BurstLineReader::gated(EVENT_CHANNEL_BOUND * 4, all_tx, eof_gate_rx)
        .with_milestone(EVENT_CHANNEL_BOUND, phase1_tx)
        .with_milestone(EVENT_CHANNEL_BOUND * 2, phase2_tx);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        Vec::<u8>::new(),
        BufReader::new(reader),
        1024,
    );
    phase1_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("burst 1");
    assert!(!transport.poll_upstream_eof());
    assert!(transport.buffered_events.len() <= EVENT_CHANNEL_BOUND);

    phase2_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("burst 2");
    for _ in 0..8 {
        assert!(!transport.poll_upstream_eof());
        assert!(transport.buffered_events.len() <= EVENT_CHANNEL_BOUND);
    }
    assert_eq!(transport.buffered_events.len(), EVENT_CHANNEL_BOUND);

    let first = transport.recv_event(Some(Instant::now() + Duration::from_secs(2)));
    assert!(
        matches!(first, RecvOutcome::Event(IoEvent::UpstreamLine(Some(ref l))) if l.contains("\"id\":\"n1\""))
    );
    assert!(!transport.poll_upstream_eof());
    assert_eq!(transport.buffered_events.len(), EVENT_CHANNEL_BOUND);
}

#[test]
fn poll_upstream_eof_detects_upstream_read_error_as_terminal_and_extracts_it() {
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let payload = concat!(
        r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"id":"n1"}}"#,
        "\n",
        "bad\rline\n"
    );
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        Vec::<u8>::new(),
        BufReader::new(Cursor::new(payload.as_bytes().to_vec())),
        1024,
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    while !transport.poll_upstream_eof() {
        assert!(
            Instant::now() < deadline,
            "poll_upstream_eof failed to detect UpstreamLine(Err(BareCr))"
        );
        thread::yield_now();
    }
    assert!(matches!(
        transport.take_upstream_read_error(),
        Some(LineReadError::BareCr)
    ));
    assert!(transport.take_upstream_read_error().is_none());
}

struct BurstThenBareCrReader {
    remaining: usize,
    emitted: usize,
    milestones: Vec<(usize, mpsc::SyncSender<()>)>,
    err_gate_rx: Option<mpsc::Receiver<()>>,
    sent_err: bool,
    buf: Vec<u8>,
    pos: usize,
}

impl BurstThenBareCrReader {
    fn new(lines: usize, err_gate_rx: mpsc::Receiver<()>) -> Self {
        Self {
            remaining: lines,
            emitted: 0,
            milestones: Vec::new(),
            err_gate_rx: Some(err_gate_rx),
            sent_err: false,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn with_milestone(mut self, after_lines: usize, tx: mpsc::SyncSender<()>) -> Self {
        self.milestones.push((after_lines, tx));
        self
    }

    fn notify_milestones(&mut self) {
        let emitted = self.emitted;
        self.milestones.retain(|(at, tx)| {
            let pending = emitted < *at;
            if !pending {
                let _ = tx.send(());
            }
            pending
        });
    }
}

impl Read for BurstThenBareCrReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            if self.remaining > 0 {
                self.remaining -= 1;
                self.emitted += 1;
                self.notify_milestones();
                self.buf = format!(
                    "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"id\":\"n{}\"}}}}\n",
                    self.emitted
                )
                .into_bytes();
                self.pos = 0;
            } else if !self.sent_err {
                let _ = self.err_gate_rx.take().map(|rx| rx.recv());
                self.sent_err = true;
                self.buf = b"bad\rline\n".to_vec();
                self.pos = 0;
            } else {
                return Ok(0);
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn poll_upstream_eof_detects_eof_in_o1_even_when_buffered_events_and_event_rx_are_full() {
    let (phase1_tx, phase1_rx) = mpsc::sync_channel(1);
    let (phase2_tx, phase2_rx) = mpsc::sync_channel(1);
    let (all_tx, _all_rx) = mpsc::sync_channel(1);
    let (eof_gate_tx, eof_gate_rx) = mpsc::sync_channel(1);
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let reader = BurstLineReader::gated(EVENT_CHANNEL_BOUND * 2, all_tx, eof_gate_rx)
        .with_milestone(EVENT_CHANNEL_BOUND, phase1_tx)
        .with_milestone(EVENT_CHANNEL_BOUND * 2, phase2_tx);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        Vec::<u8>::new(),
        BufReader::new(reader),
        1024,
    );

    phase1_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first 64 notifications queued");
    let fill_deadline = Instant::now() + Duration::from_secs(2);
    while transport.buffered_events.len() < EVENT_CHANNEL_BOUND {
        assert!(!transport.poll_upstream_eof());
        assert!(
            Instant::now() < fill_deadline,
            "buffered_events failed to reach EVENT_CHANNEL_BOUND"
        );
        thread::yield_now();
    }
    phase2_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second 64 notifications saturated event_rx");
    assert_eq!(transport.buffered_events.len(), EVENT_CHANNEL_BOUND);
    assert!(!transport.poll_upstream_eof());

    drop(eof_gate_tx);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !transport.poll_upstream_eof() {
        assert!(
            Instant::now() < deadline,
            "O(1) upstream_reader_terminated failed to detect EOF behind 128 notifications"
        );
        thread::yield_now();
    }
    assert_eq!(
        transport.buffered_events.len(),
        EVENT_CHANNEL_BOUND,
        "buffered_events must never exceed EVENT_CHANNEL_BOUND"
    );
    assert!(transport.take_upstream_read_error().is_none());
}

#[test]
fn poll_upstream_eof_detects_bare_cr_in_o1_even_when_buffered_events_and_event_rx_are_full() {
    let (phase1_tx, phase1_rx) = mpsc::sync_channel(1);
    let (phase2_tx, phase2_rx) = mpsc::sync_channel(1);
    let (err_gate_tx, err_gate_rx) = mpsc::sync_channel(1);
    let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
    let reader = BurstThenBareCrReader::new(EVENT_CHANNEL_BOUND * 2, err_gate_rx)
        .with_milestone(EVENT_CHANNEL_BOUND, phase1_tx)
        .with_milestone(EVENT_CHANNEL_BOUND * 2, phase2_tx);
    let mut transport = DuplexTransport::start(
        BufReader::new(BlockingEofReader(client_hold_rx)),
        Vec::<u8>::new(),
        BufReader::new(reader),
        1024,
    );

    phase1_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first 64 notifications queued");
    let fill_deadline = Instant::now() + Duration::from_secs(2);
    while transport.buffered_events.len() < EVENT_CHANNEL_BOUND {
        assert!(!transport.poll_upstream_eof());
        assert!(
            Instant::now() < fill_deadline,
            "buffered_events failed to reach EVENT_CHANNEL_BOUND"
        );
        thread::yield_now();
    }
    phase2_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second 64 notifications saturated event_rx");
    assert!(!transport.poll_upstream_eof());

    drop(err_gate_tx);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !transport.poll_upstream_eof() {
        assert!(
            Instant::now() < deadline,
            "O(1) upstream_reader_terminated failed to detect BareCr behind 128 notifications"
        );
        thread::yield_now();
    }
    assert_eq!(transport.buffered_events.len(), EVENT_CHANNEL_BOUND);
    assert!(matches!(
        transport.take_upstream_read_error(),
        Some(LineReadError::BareCr)
    ));
}
