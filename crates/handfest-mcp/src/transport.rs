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

#[derive(Debug)]
pub(crate) enum IoEvent {
    ClientLine(Result<Option<String>, LineReadError>),
    UpstreamLine(Option<String>),
    UpstreamReadFailed,
    UpstreamWriteReady,
    UpstreamWriteFailed,
}

#[derive(Debug)]
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
    upstream_reader_terminated: Arc<AtomicBool>,
    upstream_read_err_rx: Receiver<LineReadError>,
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
        let (upstream_read_err_tx, upstream_read_err_rx) = mpsc::sync_channel::<LineReadError>(1);
        let writer_wakeup_armed = Arc::new(AtomicBool::new(false));
        let upstream_reader_terminated = Arc::new(AtomicBool::new(false));

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
        let up_terminated = Arc::clone(&upstream_reader_terminated);
        thread::spawn(move || loop {
            match read_bounded_line(&mut upstream_out, max_line_bytes) {
                Ok(Some(line)) => {
                    if up_read_tx.send(IoEvent::UpstreamLine(Some(line))).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    up_terminated.store(true, Ordering::Release);
                    let _ = up_read_tx.send(IoEvent::UpstreamLine(None));
                    break;
                }
                Err(err) => {
                    let _ = upstream_read_err_tx.send(err);
                    up_terminated.store(true, Ordering::Release);
                    let _ = up_read_tx.send(IoEvent::UpstreamReadFailed);
                    break;
                }
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
            let failed = final_res.is_err();
            if failed {
                let _ = writer_done_tx.send(final_res);
                drop(upstream_rx);
                let _ = up_write_tx.try_send(IoEvent::UpstreamWriteFailed);
                drop(upstream_in);
            } else {
                drop(upstream_in);
                let _ = writer_done_tx.send(final_res);
                drop(upstream_rx);
            }
        });

        Self {
            event_rx,
            buffered_events: VecDeque::new(),
            upstream_tx: Some(upstream_tx),
            pending_upstream: VecDeque::new(),
            writer_wakeup_armed,
            writer_done_rx,
            upstream_reader_terminated,
            upstream_read_err_rx,
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

    /// Checks the O(1) atomic upstream reader termination flag first, then non-blockingly drains
    /// queued transport events from `event_rx` into the FIFO `buffered_events` buffer (capped at
    /// `EVENT_CHANNEL_BOUND` to preserve channel backpressure and FIFO order for `recv_event`) to
    /// detect whether an upstream terminal event (`UpstreamLine(None)`, `UpstreamReadFailed`, or
    /// `UpstreamWriteFailed`) has occurred, even behind 64+ buffered notifications.
    pub(crate) fn poll_upstream_eof(&mut self) -> bool {
        if self.upstream_reader_terminated.load(Ordering::Acquire) {
            return true;
        }
        if self.buffered_events.iter().any(is_upstream_terminal_event) {
            return true;
        }
        while self.buffered_events.len() < EVENT_CHANNEL_BOUND {
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
        self.upstream_reader_terminated.load(Ordering::Acquire)
    }

    pub(crate) fn take_upstream_read_error(&self) -> Option<LineReadError> {
        self.upstream_read_err_rx.try_recv().ok()
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
        IoEvent::UpstreamLine(None) | IoEvent::UpstreamReadFailed | IoEvent::UpstreamWriteFailed
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
#[path = "transport_tests.rs"]
mod tests;
