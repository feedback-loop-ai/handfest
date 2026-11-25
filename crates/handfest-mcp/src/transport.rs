//! Full-duplex concurrent stdio transport isolating client reads, upstream reads, and upstream
//! writes so idle notifications flow immediately, bidirectional pipe traffic cannot deadlock, and
//! client EOF or cancellation is always observable while waiting on upstream replies.

use std::io::{BufRead, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use crate::framing::{read_bounded_line, write_raw_line, LineReadError};
use crate::proxy::ProxyError;
use crate::session::MAX_QUEUED_CLIENT_FRAMES;

const EVENT_CHANNEL_BOUND: usize = 64;

pub(crate) enum IoEvent {
    ClientLine(Result<Option<String>, LineReadError>),
    UpstreamLine(Result<Option<String>, LineReadError>),
    UpstreamWriteError(ProxyError),
}

pub(crate) enum RecvOutcome {
    Event(IoEvent),
    Timeout,
    Disconnected,
}

pub(crate) struct DuplexTransport {
    event_rx: Receiver<IoEvent>,
    upstream_tx: Option<SyncSender<String>>,
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
        thread::spawn(move || {
            let mut final_res = Ok(());
            while let Ok(frame) = upstream_rx.recv() {
                if let Err(err) = write_raw_line(&mut upstream_in, &frame) {
                    let preserved = duplicate_write_error(&err);
                    let _ = up_write_tx.send(IoEvent::UpstreamWriteError(err));
                    final_res = Err(preserved);
                    break;
                }
            }
            drop(upstream_in);
            let _ = writer_done_tx.send(final_res);
        });

        Self {
            event_rx,
            upstream_tx: Some(upstream_tx),
            writer_done_rx,
        }
    }

    pub(crate) fn recv_event(&self, deadline: Option<Instant>) -> RecvOutcome {
        let Some(limit) = deadline else {
            return match self.event_rx.recv() {
                Ok(ev) => RecvOutcome::Event(ev),
                Err(_) => RecvOutcome::Disconnected,
            };
        };
        let remaining = limit.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return match self.event_rx.try_recv() {
                Ok(ev) => RecvOutcome::Event(ev),
                Err(mpsc::TryRecvError::Empty) => RecvOutcome::Timeout,
                Err(mpsc::TryRecvError::Disconnected) => RecvOutcome::Disconnected,
            };
        }
        match self.event_rx.recv_timeout(remaining) {
            Ok(ev) => RecvOutcome::Event(ev),
            Err(RecvTimeoutError::Timeout) => RecvOutcome::Timeout,
            Err(RecvTimeoutError::Disconnected) => RecvOutcome::Disconnected,
        }
    }

    pub(crate) fn send_upstream(&self, frame: String) -> Result<(), ProxyError> {
        let Some(tx) = &self.upstream_tx else {
            return Err(ProxyError::UpstreamProtocol(
                "upstream stdin pipe is already closed".to_string(),
            ));
        };
        tx.send(frame).map_err(|_| {
            ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "upstream writer thread terminated",
            ))
        })
    }

    pub(crate) fn close_upstream_stdin(&mut self) {
        self.upstream_tx.take();
    }

    pub(crate) fn finish_writer(mut self, timeout: Duration) -> Result<(), ProxyError> {
        self.close_upstream_stdin();
        // Drop `event_rx` before awaiting `writer_done_rx` so a writer thread blocked on a full
        // `event_tx` channel immediately unblocks with `SendError` instead of deadlocking.
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

fn duplicate_write_error(err: &ProxyError) -> ProxyError {
    match err {
        ProxyError::Io(io_err) => {
            ProxyError::Io(std::io::Error::new(io_err.kind(), io_err.to_string()))
        }
        other => ProxyError::UpstreamProtocol(other.to_string()),
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
        buf: Vec<u8>,
        pos: usize,
    }

    impl BurstLineReader {
        fn new(lines: usize, ready_tx: mpsc::SyncSender<()>) -> Self {
            Self {
                remaining: lines,
                ready_tx: Some(ready_tx),
                buf: Vec::new(),
                pos: 0,
            }
        }
    }

    impl Read for BurstLineReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.buf.len() {
                if self.remaining == 0 {
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

    struct FailingWriter {
        attempted_tx: Option<mpsc::SyncSender<()>>,
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            if let Some(tx) = self.attempted_tx.take() {
                let _ = tx.send(());
            }
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated broken upstream pipe",
            ))
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
    fn finish_writer_drops_full_event_channel_without_deadlock_and_preserves_io_error() {
        let (full_tx, full_rx) = mpsc::sync_channel(1);
        let (fail_tx, fail_rx) = mpsc::sync_channel(1);
        let (_client_hold_tx, client_hold_rx) = mpsc::sync_channel(1);
        let transport = DuplexTransport::start(
            BufReader::new(BlockingEofReader(client_hold_rx)),
            FailingWriter {
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
            .expect("writer observed broken pipe");

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
                    if io_err.kind() == io::ErrorKind::BrokenPipe
                        && io_err.to_string().contains("simulated broken upstream pipe")
            ),
            "expected preserved ProxyError::Io(BrokenPipe), got {res:?}"
        );
    }

    #[test]
    fn upstream_tx_is_bounded_and_finish_writer_handles_duration_max() {
        let (gate_tx, gate_rx) = mpsc::sync_channel(1);
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let transport = DuplexTransport::start(
            BufReader::new(Cursor::new(Vec::<u8>::new())),
            GateWriter {
                gate_rx: Some(gate_rx),
                entered_tx: Some(entered_tx),
            },
            BufReader::new(Cursor::new(Vec::<u8>::new())),
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

        // Next `try_send` must report `Full`, proving `upstream_tx` is bounded.
        let overflow = transport
            .upstream_tx
            .as_ref()
            .unwrap()
            .try_send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string());
        assert!(matches!(overflow, Err(mpsc::TrySendError::Full(_))));

        // Release writer and verify `finish_writer(Duration::MAX)` does not panic on overflow.
        let _ = gate_tx.send(());
        transport
            .finish_writer(Duration::MAX)
            .expect("finish_writer(Duration::MAX) must succeed without panicking");
    }

    #[test]
    fn duplicate_write_error_preserves_protocol_variant() {
        let err = ProxyError::UpstreamProtocol("embedded LF".to_string());
        assert!(matches!(
            duplicate_write_error(&err),
            ProxyError::UpstreamProtocol(msg) if msg.contains("embedded LF")
        ));
    }
}
