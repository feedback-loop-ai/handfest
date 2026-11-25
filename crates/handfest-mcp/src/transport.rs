//! Full-duplex concurrent stdio transport isolating client reads, upstream reads, and upstream
//! writes so idle notifications flow immediately, bidirectional pipe traffic cannot deadlock, and
//! client EOF or cancellation is always observable while waiting on upstream replies.

use std::io::{BufRead, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::framing::{read_bounded_line, write_raw_line, LineReadError};
use crate::proxy::ProxyError;

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
    upstream_tx: Option<Sender<String>>,
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
        let (upstream_tx, upstream_rx) = mpsc::channel::<String>();
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
                    let msg = err.to_string();
                    let _ = up_write_tx.send(IoEvent::UpstreamWriteError(err));
                    final_res = Err(ProxyError::UpstreamProtocol(msg));
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

    pub(crate) fn finish_writer(&mut self, timeout: Duration) -> Result<(), ProxyError> {
        self.close_upstream_stdin();
        match self.writer_done_rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Ok(()),
        }
    }
}
