//! Full-duplex concurrent stdio transport isolating client reads, upstream reads, and upstream
//! writes so idle notifications flow immediately, bidirectional pipe traffic cannot deadlock, and
//! client EOF or cancellation is always observable while waiting on upstream replies.

use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::framing::{read_bounded_line, write_raw_line, LineReadError};
use crate::proxy::ProxyError;
use crate::session::MAX_QUEUED_CLIENT_FRAMES;

const EVENT_CHANNEL_BOUND: usize = 64;

pub(crate) enum IoEvent {
    ClientLine(Result<Option<String>, LineReadError>),
    UpstreamLine(Result<Option<String>, LineReadError>),
    UpstreamWriteReady,
    UpstreamWriteFailed,
}

pub(crate) enum RecvOutcome {
    Event(IoEvent),
    Timeout,
    Disconnected,
}

pub(crate) struct DuplexTransport {
    event_rx: Receiver<IoEvent>,
    buffered_events: VecDeque<IoEvent>,
    upstream_tx: Option<SyncSender<String>>,
    pending_upstream: VecDeque<String>,
    writer_wakeup_armed: Arc<AtomicBool>,
    writer_done_rx: Receiver<Result<(), ProxyError>>,
}

impl DuplexTransport {
    pub(crate) fn start<CR, UR, UW>(
        mut client_in: CR,
        mut upstream_in: UW,
        mut upstream_out: UR,
        max_line_bytes: usize,
    ) -> Self
    where
        CR: BufRead + Send + 'static,
        UR: BufRead + Send + 'static,
        UW: Write + Send + 'static,
    {
        let (event_tx, event_rx) = mpsc::sync_channel::<IoEvent>(EVENT_CHANNEL_BOUND);
        let (upstream_tx, upstream_rx) = mpsc::sync_channel::<String>(MAX_QUEUED_CLIENT_FRAMES);
        let (writer_done_tx, writer_done_rx) = mpsc::sync_channel::<Result<(), ProxyError>>(1);
        let writer_wakeup_armed = Arc::new(AtomicBool::new(false));

        let client_tx = event_tx.clone();
        thread::spawn(move || loop {
            let res = read_bounded_line(&mut client_in, max_line_bytes);
            let done = matches!(
                &res,
                Ok(None) | Err(LineReadError::TooLong | LineReadError::Io(_))
            );
            if client_tx.send(IoEvent::ClientLine(res)).is_err() || done {
                break;
            }
        });

        let up_read_tx = event_tx.clone();
        thread::spawn(move || loop {
            let res = read_bounded_line(&mut upstream_out, max_line_bytes);
            let done = matches!(
                &res,
                Ok(None)
                    | Err(LineReadError::TooLong
                        | LineReadError::BareCr
                        | LineReadError::InvalidUtf8
                        | LineReadError::Io(_))
            );
            if up_read_tx.send(IoEvent::UpstreamLine(res)).is_err() || done {
                break;
            }
        });

        let up_write_tx = event_tx;
        let writer_wakeup = Arc::clone(&writer_wakeup_armed);
        thread::spawn(move || {
            let mut final_res = Ok(());
            while let Ok(frame) = upstream_rx.recv() {
                if writer_wakeup.swap(false, Ordering::SeqCst) {
                    let _ = up_write_tx.try_send(IoEvent::UpstreamWriteReady);
                }
                if let Err(err) = write_raw_line(&mut upstream_in, &frame) {
                    final_res = Err(err);
                    break;
                }
            }
            drop(upstream_in);
            let failed = final_res.is_err();
            let _ = writer_done_tx.send(final_res);
            drop(upstream_rx);
            if failed {
                let _ = up_write_tx.try_send(IoEvent::UpstreamWriteFailed);
            }
        });

        Self {
            event_rx,
            buffered_events: VecDeque::new(),
            upstream_tx: Some(upstream_tx),
            pending_upstream: VecDeque::new(),
            writer_wakeup_armed,
            writer_done_rx,
        }
    }

    pub(crate) fn recv_event(&mut self, deadline: Option<Instant>) -> RecvOutcome {
        let remaining = match deadline {
            None => None,
            Some(limit) => {
                let rem = limit.saturating_duration_since(Instant::now());
                if rem.is_zero() {
                    return RecvOutcome::Timeout;
                }
                Some(rem)
            }
        };
        if let Some(ev) = self.buffered_events.pop_front() {
            return RecvOutcome::Event(ev);
        }
        match remaining {
            None => match self.event_rx.recv() {
                Ok(ev) => RecvOutcome::Event(ev),
                Err(_) => RecvOutcome::Disconnected,
            },
            Some(rem) => match self.event_rx.recv_timeout(rem) {
                Ok(ev) => RecvOutcome::Event(ev),
                Err(RecvTimeoutError::Timeout) => RecvOutcome::Timeout,
                Err(RecvTimeoutError::Disconnected) => RecvOutcome::Disconnected,
            },
        }
    }

    /// Non-blockingly drains all currently queued transport events from `event_rx` into the FIFO
    /// `buffered_events` buffer (preserving order for `recv_event`) and reports whether an
    /// upstream EOF (`UpstreamLine(Ok(None))`) or writer failure (`UpstreamWriteFailed`) is
    /// already queued, even behind buffered upstream notifications.
    pub(crate) fn poll_upstream_eof(&mut self) -> bool {
        const MAX_POLL_DRAIN: usize = EVENT_CHANNEL_BOUND + 3;
        if self.buffered_events.iter().any(is_upstream_terminal_event) {
            return true;
        }
        for _ in 0..MAX_POLL_DRAIN {
            match self.event_rx.try_recv() {
                Ok(ev) => {
                    let terminal = is_upstream_terminal_event(&ev);
                    self.buffered_events.push_back(ev);
                    if terminal {
                        return true;
                    }
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        false
    }

    pub(crate) fn has_pending_upstream(&self) -> bool {
        !self.pending_upstream.is_empty()
    }

    pub(crate) fn poll_writer_error(&self) -> Option<ProxyError> {
        match self.writer_done_rx.try_recv() {
            Ok(Err(err)) => Some(err),
            Ok(Ok(())) | Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    pub(crate) fn take_writer_error(&self) -> ProxyError {
        match self.writer_done_rx.recv() {
            Ok(Err(err)) => err,
            Ok(Ok(())) | Err(_) => ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "upstream writer thread terminated",
            )),
        }
    }

    pub(crate) fn flush_upstream(&mut self) -> Result<(), ProxyError> {
        let Some(tx) = &self.upstream_tx else {
            return Ok(());
        };
        while let Some(frame) = self.pending_upstream.pop_front() {
            match try_send_with_wakeup(tx, frame, &self.writer_wakeup_armed) {
                Ok(()) => {}
                Err(TrySendError::Full(frame)) => {
                    self.pending_upstream.push_front(frame);
                    return Ok(());
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(self.take_writer_error());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn send_upstream(&mut self, frame: String) -> Result<(), ProxyError> {
        self.flush_upstream()?;
        let Some(tx) = &self.upstream_tx else {
            return Err(ProxyError::UpstreamProtocol(
                "upstream stdin pipe is already closed".to_string(),
            ));
        };
        if self.pending_upstream.is_empty() {
            match try_send_with_wakeup(tx, frame, &self.writer_wakeup_armed) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(frame)) => {
                    self.pending_upstream.push_back(frame);
                    return Ok(());
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(self.take_writer_error());
                }
            }
        }
        if self.pending_upstream.len() >= MAX_QUEUED_CLIENT_FRAMES {
            return Err(ProxyError::UpstreamProtocol(
                "upstream writer queue exceeded maximum pending frames".to_string(),
            ));
        }
        self.pending_upstream.push_back(frame);
        self.flush_upstream()
    }

    pub(crate) fn close_upstream_stdin(&mut self) {
        self.upstream_tx.take();
    }

    pub(crate) fn finish_writer(mut self, timeout: Duration) -> Result<(), ProxyError> {
        self.close_upstream_stdin();
        // Drop `event_rx` before awaiting `writer_done_rx` so reader threads blocked on a full
        // `event_tx` channel unblock immediately, then return the writer's exact `Result`.
        drop(self.event_rx);
        let wait_res = if Instant::now().checked_add(timeout).is_some() {
            self.writer_done_rx.recv_timeout(timeout)
        } else {
            self.writer_done_rx
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected)
        };
        match wait_res {
            Ok(res) => res,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Ok(()),
        }
    }
}

const fn is_upstream_terminal_event(ev: &IoEvent) -> bool {
    matches!(
        ev,
        IoEvent::UpstreamLine(Ok(None)) | IoEvent::UpstreamWriteFailed
    )
}

fn try_send_with_wakeup(
    tx: &SyncSender<String>,
    frame: String,
    wakeup_armed: &AtomicBool,
) -> Result<(), TrySendError<String>> {
    match tx.try_send(frame) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(frame)) => {
            wakeup_armed.store(true, Ordering::SeqCst);
            tx.try_send(frame)
        }
        Err(TrySendError::Disconnected(frame)) => Err(TrySendError::Disconnected(frame)),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufReader, Cursor, Read};
    use std::sync::mpsc;

    use super::*;

    struct BurstLineReader {
        remaining: usize,
        ready_tx: Option<mpsc::SyncSender<()>>,
        eof_gate_rx: Option<mpsc::Receiver<()>>,
        buf: Vec<u8>,
        pos: usize,
    }

    impl BurstLineReader {
        fn new(lines: usize, ready_tx: mpsc::SyncSender<()>) -> Self {
            Self {
                remaining: lines,
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
            Self {
                remaining: lines,
                ready_tx: Some(ready_tx),
                eof_gate_rx: Some(eof_gate_rx),
                buf: Vec::new(),
                pos: 0,
            }
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
                if self.remaining == 0 {
                    let _ = self.ready_tx.take().map(|tx| tx.send(()));
                }
                self.buf =
                    b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n".to_vec();
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
                .send_upstream(
                    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
                )
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
                .send_upstream(
                    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
                )
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
        for _ in 0..4 {
            assert!(matches!(
                transport.recv_event(Some(Instant::now() + Duration::from_secs(2))),
                RecvOutcome::Event(IoEvent::UpstreamLine(Ok(Some(_))))
            ));
        }
        assert!(matches!(
            transport.recv_event(Some(Instant::now() + Duration::from_secs(2))),
            RecvOutcome::Event(IoEvent::UpstreamLine(Ok(None)))
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
            RecvOutcome::Event(IoEvent::UpstreamLine(Ok(Some(_))))
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
}
