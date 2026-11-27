//! Shared deterministic stdio test pipes and synchronization barriers for integration tests.

use std::io::{self, BufReader, Read, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(crate) struct PipeWriter {
    pub(crate) tx: mpsc::Sender<Vec<u8>>,
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pipe reader closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct PipeReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) if chunk.is_empty() => continue,
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl PipeReader {
    pub(crate) fn from_receiver(rx: mpsc::Receiver<Vec<u8>>) -> BufReader<Self> {
        BufReader::new(Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        })
    }
}

pub(crate) fn mem_pipe() -> (PipeWriter, BufReader<PipeReader>) {
    let (tx, rx) = mpsc::channel();
    (PipeWriter { tx }, PipeReader::from_receiver(rx))
}

pub(crate) struct TimeoutLineReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
}

impl TimeoutLineReader {
    pub(crate) fn read_line_timeout(&mut self, timeout: Duration, context: &str) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return String::from_utf8(line).expect("valid UTF-8 JSON-RPC line");
            }
            let rem = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("timed out waiting for line: {context}"));
            let chunk = self
                .rx
                .recv_timeout(rem)
                .unwrap_or_else(|_| panic!("timed out waiting for line: {context}"));
            self.buf.extend_from_slice(&chunk);
        }
    }
}

pub(crate) fn mem_pipe_timeout() -> (PipeWriter, TimeoutLineReader) {
    let (tx, rx) = mpsc::channel();
    (
        PipeWriter { tx },
        TimeoutLineReader {
            rx,
            buf: Vec::new(),
        },
    )
}

pub(crate) struct StepWriter {
    tx: mpsc::Sender<(Vec<u8>, Option<mpsc::SyncSender<()>>)>,
}

impl StepWriter {
    pub(crate) fn send_bytes(&self, data: &[u8]) {
        self.tx.send((data.to_vec(), None)).unwrap();
    }

    pub(crate) fn send_and_sync_queued(&self, data: &[u8]) {
        let mut payload = data.to_vec();
        // Append > EVENT_CHANNEL_BOUND (64) silently-dropped notifications so the client reader
        // cannot finish sending them until the proxy loop has moved `data` into `queued_client`.
        for _ in 0..70 {
            payload.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/noop\"}\n");
        }
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.tx.send((payload, Some(ack_tx))).unwrap();
        ack_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("client reader thread drained queued frames into proxy state");
    }
}

pub(crate) struct StepReader {
    rx: mpsc::Receiver<(Vec<u8>, Option<mpsc::SyncSender<()>>)>,
    pending_ack: Option<mpsc::SyncSender<()>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for StepReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            if let Some(ack) = self.pending_ack.take() {
                let _ = ack.send(());
            }
            match self.rx.recv() {
                Ok((chunk, ack)) => {
                    self.pending_ack = ack;
                    if chunk.is_empty() {
                        continue;
                    }
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

pub(crate) fn step_pipe() -> (StepWriter, BufReader<StepReader>) {
    let (tx, rx) = mpsc::channel();
    (
        StepWriter { tx },
        BufReader::new(StepReader {
            rx,
            pending_ack: None,
            buf: Vec::new(),
            pos: 0,
        }),
    )
}

pub(crate) struct WaitOnNthWrite<W> {
    pub(crate) inner: W,
    pub(crate) writes: usize,
    pub(crate) wait_on: usize,
    pub(crate) wait_rx: Option<mpsc::Receiver<()>>,
}

impl<W: Write> Write for WaitOnNthWrite<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes == self.wait_on {
            if let Some(rx) = self.wait_rx.take() {
                rx.recv_timeout(Duration::from_secs(2))
                    .expect("synchronization barrier before write did not fire");
            }
        }
        self.inner.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
