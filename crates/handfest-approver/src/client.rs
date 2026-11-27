//! Unix domain socket client for requesting and independently verifying signed mandates.

use std::fmt;
use std::io::{self, BufReader};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use handfest_anchors::{verify_verifier_postconditions, AnchorVerifier, SignedMandate};
use handfest_core::ast::MandateId;
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::VerifiedMandate;

use crate::protocol::{
    decode_sign_response, write_frame, FrameReader, ProtocolError, SignRequest, SignResponse,
    MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES,
};
use crate::socket::{
    remaining_until, ClientIoStream, DeadlineClock, DeadlineStreamReader, DeadlineStreamWriter,
    SystemDeadlineClock,
};
use crate::{validate_finite_timeout, TimeoutValidationError};

pub use crate::MAX_TIMEOUT;

/// Default client wait timeout in seconds while awaiting human approval.
pub const DEFAULT_CLIENT_TIMEOUT_SECS: u64 = 120;

/// Verified approval bundle returned by [`request_and_verify_signature`].
#[derive(Debug, Clone)]
pub struct VerifiedApproval {
    pub signed_mandate: SignedMandate,
    pub verified_mandate: VerifiedMandate,
    pub mandate_id: MandateId,
}

/// Structured errors returned by the approver Unix socket client.
#[derive(Debug)]
pub enum ClientError {
    Protocol(ProtocolError),
    Connect { path: String, source: io::Error },
    EmptyResponse,
    Denied { reason: String },
    DaemonError { code: String, message: String },
    VerificationFailed(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(err) => write!(f, "protocol error: {err}"),
            Self::Connect { path, source } => {
                write!(f, "failed to connect to approver socket '{path}': {source}")
            }
            Self::EmptyResponse => {
                f.write_str("approver daemon closed connection without sending a response")
            }
            Self::Denied { reason } => write!(f, "signing request denied: {reason}"),
            Self::DaemonError { code, message } => {
                write!(f, "approver daemon error ({code}): {message}")
            }
            Self::VerificationFailed(detail) => {
                write!(f, "returned signed mandate failed verification: {detail}")
            }
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(err) => Some(err),
            Self::Connect { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn compute_request_deadline_at(
    now: Instant,
    timeout: Option<Duration>,
) -> Result<Option<Instant>, ClientError> {
    let Some(duration) = timeout else {
        return Ok(None);
    };
    let duration = validate_finite_timeout(duration).map_err(|err| match err {
        TimeoutValidationError::Zero => ClientError::Protocol(ProtocolError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "request timeout must be greater than zero",
        ))),
        TimeoutValidationError::ExceedsMax => {
            ClientError::Protocol(ProtocolError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "request timeout must not exceed {} seconds",
                    MAX_TIMEOUT.as_secs()
                ),
            )))
        }
    })?;
    // Defense in depth: even though `duration <= MAX_TIMEOUT`, Unix monotonic clocks
    // have a finite upper bound, so fail closed if `now + duration` overflows.
    now.checked_add(duration).map(Some).ok_or_else(|| {
        ClientError::Protocol(ProtocolError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request timeout overflows monotonic clock",
        )))
    })
}

fn request_signature_on_stream_with_deadline<S: ClientIoStream, C: DeadlineClock>(
    mut stream: S,
    request: &SignRequest,
    deadline: Option<Instant>,
    clock: &C,
) -> Result<SignResponse, ClientError> {
    {
        let mut writer = DeadlineStreamWriter::with_clock(&mut stream, deadline, clock);
        write_frame(&mut writer, request, MAX_REQUEST_FRAME_BYTES)
            .map_err(ClientError::Protocol)?;
    }

    let deadline_reader = DeadlineStreamReader::with_clock(&mut stream, deadline, clock);
    let mut reader = FrameReader::new(BufReader::new(deadline_reader));
    let line = reader
        .read_frame_line(MAX_RESPONSE_FRAME_BYTES)
        .map_err(ClientError::Protocol)?
        .ok_or(ClientError::EmptyResponse)?;
    decode_sign_response(&line).map_err(ClientError::Protocol)
}

const MAX_IN_FLIGHT_CONNECT_WORKERS: usize = 16;

static IN_FLIGHT_CONNECT_WORKERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

struct ConnectWorkerSlot;

impl ConnectWorkerSlot {
    fn try_acquire() -> io::Result<Self> {
        use std::sync::atomic::Ordering;
        let mut current = IN_FLIGHT_CONNECT_WORKERS.load(Ordering::Acquire);
        loop {
            if current >= MAX_IN_FLIGHT_CONNECT_WORKERS {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "too many timed-out socket connect attempts still in flight",
                ));
            }
            match IN_FLIGHT_CONNECT_WORKERS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for ConnectWorkerSlot {
    fn drop(&mut self) {
        IN_FLIGHT_CONNECT_WORKERS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn connect_with_deadline<S, C, F>(
    deadline: Option<Instant>,
    clock: &C,
    connect_op: F,
) -> io::Result<S>
where
    S: Send + 'static,
    C: DeadlineClock,
    F: FnOnce() -> io::Result<S> + Send + 'static,
{
    let Some(deadline) = deadline else {
        return connect_op();
    };
    let _ = remaining_until(deadline, clock.now(), "connect")?;
    let slot = ConnectWorkerSlot::try_acquire()?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("handfest-unix-connect".to_string())
        .spawn(move || {
            let _slot = slot;
            let _ = tx.send(connect_op());
        })
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to spawn connect worker thread: {err}"),
            )
        })?;

    // Recompute remaining budget after thread creation so spawn/scheduling delay
    // cannot extend the wait past `deadline`.
    let remaining = remaining_until(deadline, clock.now(), "connect")?;
    match rx.recv_timeout(remaining) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out connecting to approver socket",
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
            "connect worker terminated before returning a result",
        )),
    }
}

pub(crate) fn connect_unix_with_deadline_for_probe(
    socket_path: &Path,
    deadline: Option<Instant>,
) -> io::Result<UnixStream> {
    connect_unix_with_deadline(socket_path, deadline, &SystemDeadlineClock)
}

fn connect_unix_with_deadline<C: DeadlineClock>(
    socket_path: &Path,
    deadline: Option<Instant>,
    clock: &C,
) -> io::Result<UnixStream> {
    let owned_path = socket_path.to_path_buf();
    connect_with_deadline(deadline, clock, move || UnixStream::connect(&owned_path))
}

fn request_signature_with_clock<S, C, F>(
    socket_path: &Path,
    request: &SignRequest,
    timeout: Option<Duration>,
    clock: &C,
    connect: F,
) -> Result<SignResponse, ClientError>
where
    S: ClientIoStream,
    C: DeadlineClock,
    F: FnOnce(&Path, Option<Instant>) -> io::Result<S>,
{
    request.validate().map_err(ClientError::Protocol)?;
    let deadline = compute_request_deadline_at(clock.now(), timeout)?;

    let stream = connect(socket_path, deadline).map_err(|source| ClientError::Connect {
        path: socket_path.display().to_string(),
        source,
    })?;

    request_signature_on_stream_with_deadline(stream, request, deadline, clock)
}

/// Sends a [`SignRequest`] to `socket_path` and returns the decoded [`SignResponse`].
pub fn request_signature(
    socket_path: &Path,
    request: &SignRequest,
    timeout: Option<Duration>,
) -> Result<SignResponse, ClientError> {
    request_signature_with_clock(
        socket_path,
        request,
        timeout,
        &SystemDeadlineClock,
        |path, deadline| connect_unix_with_deadline(path, deadline, &SystemDeadlineClock),
    )
}

/// Sends a [`SignRequest`] to `socket_path` and independently verifies any approved
/// [`SignedMandate`] against `verifier` and the requested canonical mandate/metadata.
pub fn request_and_verify_signature<V: AnchorVerifier + ?Sized>(
    socket_path: &Path,
    request: &SignRequest,
    verifier: &V,
    timeout: Option<Duration>,
) -> Result<VerifiedApproval, ClientError> {
    let expected_ast = parse_mandate(&request.mandate_text)
        .map_err(|err| ClientError::VerificationFailed(format!("invalid draft mandate: {err}")))?;
    let expected_canonical = try_render_canonical(&expected_ast)
        .map_err(|err| ClientError::VerificationFailed(format!("render error: {err}")))?;
    let expected_mandate_id = expected_ast
        .try_mandate_id()
        .map_err(|err| ClientError::VerificationFailed(format!("hash error: {err}")))?;

    match request_signature(socket_path, request, timeout)? {
        SignResponse::Approved { signed_mandate } => verify_returned_mandate(
            &signed_mandate,
            &expected_canonical,
            request,
            verifier,
            expected_mandate_id,
        ),
        SignResponse::Denied { reason } => Err(ClientError::Denied { reason }),
        SignResponse::Error { code, message } => Err(ClientError::DaemonError { code, message }),
    }
}

fn verify_returned_mandate<V: AnchorVerifier + ?Sized>(
    signed_mandate: &SignedMandate,
    expected_canonical: &str,
    request: &SignRequest,
    verifier: &V,
    expected_mandate_id: MandateId,
) -> Result<VerifiedApproval, ClientError> {
    if signed_mandate.canonical_words != expected_canonical {
        return Err(ClientError::VerificationFailed(
            "returned canonical mandate text does not match requested mandate".to_string(),
        ));
    }
    if signed_mandate.valid_from != request.valid_from
        || signed_mandate.valid_until != request.valid_until
    {
        return Err(ClientError::VerificationFailed(
            "returned validity window does not match requested window".to_string(),
        ));
    }
    if let Some(expected_anchor) = request.anchor_id.as_deref() {
        if signed_mandate.anchor_id != expected_anchor {
            return Err(ClientError::VerificationFailed(format!(
                "returned anchor_id '{}' does not match requested '{}'",
                signed_mandate.anchor_id, expected_anchor
            )));
        }
    }
    let verified_mandate = verifier
        .verify(signed_mandate)
        .map_err(|err| ClientError::VerificationFailed(err.to_string()))?;
    verify_verifier_postconditions(signed_mandate, &verified_mandate)
        .map_err(|err| ClientError::VerificationFailed(err.to_string()))?;
    Ok(VerifiedApproval {
        signed_mandate: signed_mandate.clone(),
        verified_mandate,
        mandate_id: expected_mandate_id,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    use handfest_core::ast::KeyId;

    use super::*;
    use crate::protocol::ERR_TIMEOUT;

    #[derive(Clone)]
    struct VirtualClock {
        now: Arc<Mutex<Instant>>,
    }

    impl VirtualClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn advance(&self, delta: Duration) {
            let mut guard = self.now.lock().unwrap();
            *guard = guard
                .checked_add(delta)
                .expect("virtual clock advance must not overflow");
        }
    }

    impl DeadlineClock for VirtualClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

    struct DeterministicMockStream {
        clock: VirtualClock,
        write_advance: Duration,
        advanced_write: bool,
        recorded_write_timeouts: Arc<Mutex<Vec<Option<Duration>>>>,
        recorded_read_timeouts: Arc<Mutex<Vec<Option<Duration>>>>,
        response: Option<Vec<u8>>,
        read_offset: usize,
    }

    impl DeterministicMockStream {
        fn new(
            clock: VirtualClock,
            write_advance: Duration,
            recorded_write_timeouts: Arc<Mutex<Vec<Option<Duration>>>>,
            recorded_read_timeouts: Arc<Mutex<Vec<Option<Duration>>>>,
            response: Option<Vec<u8>>,
        ) -> Self {
            Self {
                clock,
                write_advance,
                advanced_write: false,
                recorded_write_timeouts,
                recorded_read_timeouts,
                response,
                read_offset: 0,
            }
        }
    }

    impl Read for DeterministicMockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(resp) = &self.response {
                if self.read_offset >= resp.len() {
                    return Ok(0);
                }
                let n = (resp.len() - self.read_offset).min(buf.len());
                buf[..n].copy_from_slice(&resp[self.read_offset..self.read_offset + n]);
                self.read_offset += n;
                return Ok(n);
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mock read timed out",
            ))
        }
    }

    impl Write for DeterministicMockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.advanced_write && !self.write_advance.is_zero() {
                self.advanced_write = true;
                self.clock.advance(self.write_advance);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ClientIoStream for DeterministicMockStream {
        fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
            self.recorded_read_timeouts.lock().unwrap().push(dur);
            Ok(())
        }

        fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
            self.recorded_write_timeouts.lock().unwrap().push(dur);
            Ok(())
        }
    }

    fn sample_request() -> SignRequest {
        let signer = KeyId::new("ed25519", "1".repeat(64)).unwrap();
        let agent = KeyId::new("ed25519", "2".repeat(64)).unwrap();
        SignRequest {
            mandate_text: format!(
                "HANDFEST v1\nFROM human \"Valentin\" (key: {signer})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n"
            ),
            valid_from: 100,
            valid_until: 200,
            anchor_id: None,
        }
    }

    #[test]
    fn request_signature_carries_pre_connect_deadline_into_write_and_read() {
        let req = sample_request();
        let clock = VirtualClock::new();
        let write_timeouts = Arc::new(Mutex::new(Vec::new()));
        let read_timeouts = Arc::new(Mutex::new(Vec::new()));
        let denied_line = b"{\"status\":\"denied\",\"reason\":\"no\"}\n".to_vec();

        let connect_clock = clock.clone();
        let w_rec = Arc::clone(&write_timeouts);
        let r_rec = Arc::clone(&read_timeouts);
        let resp = request_signature_with_clock(
            Path::new("/tmp/virtual.sock"),
            &req,
            Some(Duration::from_millis(80)),
            &clock,
            move |_, _| {
                connect_clock.advance(Duration::from_millis(60));
                Ok(DeterministicMockStream::new(
                    connect_clock,
                    Duration::ZERO,
                    w_rec,
                    r_rec,
                    Some(denied_line),
                ))
            },
        )
        .expect("response within remaining 20ms budget must succeed");

        assert_eq!(
            resp,
            SignResponse::Denied {
                reason: "no".to_string(),
            }
        );
        let w_vals = write_timeouts.lock().unwrap();
        let r_vals = read_timeouts.lock().unwrap();
        assert!(!w_vals.is_empty(), "set_write_timeout must be called");
        assert!(!r_vals.is_empty(), "set_read_timeout must be called");
        for dur in w_vals.iter().chain(r_vals.iter()) {
            assert_eq!(
                *dur,
                Some(Duration::from_millis(20)),
                "write/read must receive exact 20ms remaining after 60ms connect"
            );
        }
    }

    #[test]
    fn request_signature_shares_single_deadline_across_slow_write_and_read_deterministically() {
        let req = sample_request();
        let clock = VirtualClock::new();
        let write_timeouts = Arc::new(Mutex::new(Vec::new()));
        let read_timeouts = Arc::new(Mutex::new(Vec::new()));

        let stream_clock = clock.clone();
        let w_rec = Arc::clone(&write_timeouts);
        let r_rec = Arc::clone(&read_timeouts);
        let err = request_signature_with_clock(
            Path::new("/tmp/virtual.sock"),
            &req,
            Some(Duration::from_millis(80)),
            &clock,
            move |_, _| {
                Ok(DeterministicMockStream::new(
                    stream_clock,
                    Duration::from_millis(60),
                    w_rec,
                    r_rec,
                    None,
                ))
            },
        )
        .unwrap_err();

        match err {
            ClientError::Protocol(ref perr) => {
                assert_eq!(perr.error_code(), ERR_TIMEOUT);
                assert!(matches!(
                    perr,
                    ProtocolError::Io(io_err) if io_err.kind() == io::ErrorKind::TimedOut
                ));
            }
            other => panic!("expected TimedOut protocol error, got {other:?}"),
        }

        let w_vals = write_timeouts.lock().unwrap();
        let r_vals = read_timeouts.lock().unwrap();
        assert_eq!(
            w_vals.as_slice(),
            &[
                Some(Duration::from_millis(80)),
                Some(Duration::from_millis(20)),
            ]
        );
        assert_eq!(r_vals.as_slice(), &[Some(Duration::from_millis(20))]);
    }

    #[test]
    fn request_signature_rejects_timeouts_exceeding_max_timeout() {
        let req = sample_request();
        let clock = VirtualClock::new();

        for bad_timeout in [
            Duration::MAX,
            Duration::from_secs(1 << 54),
            MAX_TIMEOUT.checked_add(Duration::from_secs(1)).unwrap(),
        ] {
            let err = request_signature_with_clock(
                Path::new("/tmp/unused.sock"),
                &req,
                Some(bad_timeout),
                &clock,
                |_, _| -> io::Result<DeterministicMockStream> {
                    panic!("connect must not run on invalid timeout {bad_timeout:?}")
                },
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    ClientError::Protocol(ProtocolError::Io(ref io_err))
                        if io_err.kind() == io::ErrorKind::InvalidInput
                ),
                "expected InvalidInput for timeout {bad_timeout:?}, got {err:?}"
            );
        }

        // Exact MAX_TIMEOUT (86,400s) is accepted by deadline calculation.
        let exact = compute_request_deadline_at(clock.now(), Some(MAX_TIMEOUT))
            .expect("MAX_TIMEOUT must be accepted");
        assert!(exact.is_some());
    }

    #[test]
    fn request_signature_rejects_accepted_timeout_when_monotonic_clock_overflows() {
        let req = sample_request();
        let near_max = crate::socket::near_max_instant();
        let accepted_timeout = Duration::from_secs(5);
        assert!(accepted_timeout <= MAX_TIMEOUT);

        let direct_err = compute_request_deadline_at(near_max, Some(accepted_timeout)).unwrap_err();
        assert!(
            matches!(
                direct_err,
                ClientError::Protocol(ProtocolError::Io(ref io_err))
                    if io_err.kind() == io::ErrorKind::InvalidInput
                        && io_err.to_string().contains("overflows monotonic clock")
            ),
            "expected InvalidInput clock-overflow error, got {direct_err:?}"
        );

        let clock = VirtualClock {
            now: Arc::new(Mutex::new(near_max)),
        };
        let err = request_signature_with_clock(
            Path::new("/tmp/unused.sock"),
            &req,
            Some(accepted_timeout),
            &clock,
            |_, _| -> io::Result<DeterministicMockStream> {
                panic!("connect must not run when monotonic clock overflows")
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Protocol(ProtocolError::Io(ref io_err))
                    if io_err.kind() == io::ErrorKind::InvalidInput
                        && io_err.to_string().contains("overflows monotonic clock")
            ),
            "expected InvalidInput clock-overflow error, got {err:?}"
        );
    }

    #[test]
    fn connect_with_deadline_bounds_blocking_connect_and_handles_edge_cases() {
        let clock = VirtualClock::new();

        // 1. Unbounded deadline runs connect_op directly and returns its result.
        let ok_val = connect_with_deadline(None, &clock, || Ok(42u32)).unwrap();
        assert_eq!(ok_val, 42);
        let refused = connect_with_deadline::<u32, _, _>(None, &clock, || {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
        })
        .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);

        // 2. Already-expired deadline fails closed immediately without invoking connect_op.
        let expired = clock.now().checked_sub(Duration::from_millis(1)).unwrap();
        let expired_err = connect_with_deadline::<u32, _, _>(Some(expired), &clock, || {
            panic!("connect_op must not run when deadline already expired")
        })
        .unwrap_err();
        assert_eq!(expired_err.kind(), io::ErrorKind::TimedOut);

        // 3. Blocking connect_op times out within remaining budget.
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let deadline = clock.now().checked_add(Duration::from_millis(50)).unwrap();
        let started = Instant::now();
        let timeout_err = connect_with_deadline::<u32, _, _>(Some(deadline), &clock, move || {
            let _ = release_rx.recv();
            Ok(99)
        })
        .unwrap_err();
        let elapsed = started.elapsed();
        let _ = release_tx.send(());
        assert_eq!(timeout_err.kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_millis(250),
            "blocking connect must time out within 50ms budget, elapsed {elapsed:?}"
        );

        // 4. Connect completing before deadline returns its Ok/Err result.
        let future = clock.now().checked_add(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connect_with_deadline(Some(future), &clock, || Ok(7u32)).unwrap(),
            7
        );
        let err = connect_with_deadline::<u32, _, _>(Some(future), &clock, || {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // 5. Connect worker panic drops sender -> ErrorKind::Other (does not unwind caller).
        let disconnected = connect_with_deadline::<u32, _, _>(Some(future), &clock, || {
            panic!("simulated connect worker panic")
        })
        .unwrap_err();
        assert_eq!(disconnected.kind(), io::ErrorKind::Other);
    }
}
