//! Out-of-band WYSIWYS signing daemon (`ApproverDaemon`).

use std::fmt;
use std::io::{self, BufReader};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use handfest_anchors::{
    format_actor_kind, format_assurance, sign_mandate_with, MandateSigner, SignedMandate,
};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::validate_proof_shape;
use handfest_core::ActorKind;

use crate::prompt::{ApprovalOutcome, ApprovalPrompt, WysiwysPromptView};
use crate::protocol::{
    decode_sign_request, is_forbidden_wysiwys_char, validate_single_line_text, write_frame,
    FrameReader, ProtocolError, SignRequest, SignResponse, ERR_INTERNAL, ERR_INVALID_MANDATE,
    ERR_INVALID_REQUEST, ERR_PROMPT_FAILED, ERR_SIGNER_MISMATCH, ERR_SIGNING_FAILED, ERR_TIMEOUT,
    MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES,
};
use crate::socket::{DeadlineClock, DeadlineStreamReader, SystemDeadlineClock};
use crate::{validate_finite_timeout, TimeoutValidationError};

pub use crate::socket::{BoundSocket, SocketMode};
pub use crate::MAX_TIMEOUT;

/// Default per-request socket and approval deadline in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Conservative signature hex headroom reserved when pre-checking serialized [`SignResponse::Approved`]
/// size before prompting or signing.
const APPROVED_SIGNATURE_HEADROOM_BYTES: usize = 2048;

/// Maximum UTF-8 byte length of any sanitized `Denied` reason or `Error` code/message on the wire.
const MAX_WIRE_MESSAGE_BYTES: usize = 2048;

/// Structured errors returned while binding or serving the approver Unix socket.
#[derive(Debug)]
pub enum DaemonError {
    InvalidConfig(String),
    SymlinkRejected(PathBuf),
    NotADirectory(PathBuf),
    InsecureParentPermissions {
        path: PathBuf,
        mode: u32,
    },
    UntrustedParentOwner {
        path: PathBuf,
        parent_uid: u32,
        expected_uid: u32,
    },
    UntrustedAncestorOwner {
        path: PathBuf,
        ancestor_uid: u32,
        expected_uid: u32,
    },
    PathExistsNotSocket(PathBuf),
    SocketAlreadyActive(PathBuf),
    Io {
        path: Option<PathBuf>,
        source: io::Error,
    },
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(detail) => write!(f, "invalid daemon configuration: {detail}"),
            Self::SymlinkRejected(path) => write!(f, "refusing symlink path '{}'", path.display()),
            Self::NotADirectory(path) => {
                write!(f, "socket parent '{}' is not a directory", path.display())
            }
            Self::InsecureParentPermissions { path, mode } => write!(
                f,
                "socket parent directory '{}' has insecure permissions {mode:04o}",
                path.display()
            ),
            Self::UntrustedParentOwner {
                path,
                parent_uid,
                expected_uid,
            } => write!(
                f,
                "socket parent directory '{}' is owned by uid {parent_uid} (expected root or daemon euid {expected_uid})",
                path.display()
            ),
            Self::UntrustedAncestorOwner {
                path,
                ancestor_uid,
                expected_uid,
            } => write!(
                f,
                "socket ancestor directory '{}' is owned by uid {ancestor_uid} (expected root or daemon euid {expected_uid})",
                path.display()
            ),
            Self::PathExistsNotSocket(path) => write!(
                f,
                "refusing to overwrite existing non-socket path '{}'",
                path.display()
            ),
            Self::SocketAlreadyActive(path) => write!(
                f,
                "Unix socket '{}' is already active with a live listener",
                path.display()
            ),
            Self::Io {
                path: Some(path),
                source,
            } => write!(f, "socket I/O error on '{}': {source}", path.display()),
            Self::Io { path: None, source } => write!(f, "socket I/O error: {source}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Out-of-band WYSIWYS signing daemon holding a [`MandateSigner`] and [`ApprovalPrompt`].
///
/// Requests are processed strictly sequentially (one at a time) to prevent concurrent prompt
/// flooding or clickjacking.
#[derive(Debug)]
pub struct ApproverDaemon<S: MandateSigner, P: ApprovalPrompt> {
    signer: S,
    prompt: P,
    default_anchor_id: String,
    timeout: Duration,
}

impl<S: MandateSigner, P: ApprovalPrompt> ApproverDaemon<S, P> {
    /// Constructs a new [`ApproverDaemon`], validating `default_anchor_id` and non-zero `timeout`.
    pub fn new(
        signer: S,
        prompt: P,
        default_anchor_id: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, DaemonError> {
        let default_anchor_id = default_anchor_id.into();
        validate_finite_timeout(timeout).map_err(|err| match err {
            TimeoutValidationError::Zero => {
                DaemonError::InvalidConfig("timeout must be greater than zero".to_string())
            }
            TimeoutValidationError::ExceedsMax => DaemonError::InvalidConfig(format!(
                "timeout must not exceed {} seconds",
                MAX_TIMEOUT.as_secs()
            )),
        })?;
        validate_single_line_text(&default_anchor_id, "default anchor_id").map_err(|err| {
            DaemonError::InvalidConfig(format!("invalid default anchor_id: {err}"))
        })?;
        validate_proof_shape(&default_anchor_id, 0, 0).map_err(|err| {
            DaemonError::InvalidConfig(format!("invalid default anchor_id: {err}"))
        })?;
        Ok(Self {
            signer,
            prompt,
            default_anchor_id,
            timeout,
        })
    }

    /// Returns a reference to the configured [`MandateSigner`].
    #[must_use]
    pub const fn signer(&self) -> &S {
        &self.signer
    }

    /// Returns a reference to the configured [`ApprovalPrompt`].
    #[must_use]
    pub const fn prompt(&self) -> &P {
        &self.prompt
    }

    /// Processes a single [`SignRequest`] deterministically and fail-closed.
    pub fn handle_request(&mut self, req: &SignRequest) -> SignResponse {
        self.handle_request_with_start(req, Instant::now(), &SystemDeadlineClock)
    }

    fn handle_request_with_start<C: DeadlineClock>(
        &mut self,
        req: &SignRequest,
        started: Instant,
        clock: &C,
    ) -> SignResponse {
        let view = match self.prepare_prompt_view(req) {
            Ok(view) => view,
            Err((code, msg)) => return error_response(code, &msg),
        };
        let elapsed = clock.now().saturating_duration_since(started);
        let Some(remaining) = self.timeout.checked_sub(elapsed).filter(|d| !d.is_zero()) else {
            return error_response(
                ERR_TIMEOUT,
                "request exceeded configured approval timeout before prompting",
            );
        };
        match self.prompt.prompt_with_timeout(&view, remaining) {
            Ok(ApprovalOutcome::Approved) => {
                if clock.now().saturating_duration_since(started) > self.timeout {
                    return error_response(
                        ERR_TIMEOUT,
                        "request exceeded configured approval timeout before signing",
                    );
                }
                match sign_mandate_with(
                    &self.signer,
                    view.canonical_mandate(),
                    view.anchor_id(),
                    req.valid_from,
                    req.valid_until,
                ) {
                    Ok(signed_mandate) => SignResponse::Approved { signed_mandate },
                    Err(err) => error_response(ERR_SIGNING_FAILED, &err.to_string()),
                }
            }
            Ok(ApprovalOutcome::Denied { reason }) => SignResponse::Denied {
                reason: sanitize_wire_message(&reason, "request denied by operator"),
            },
            Err(err) => error_response(ERR_PROMPT_FAILED, &err.to_string()),
        }
    }

    fn prepare_prompt_view(
        &self,
        req: &SignRequest,
    ) -> Result<WysiwysPromptView, (&'static str, String)> {
        if let Err(err) = req.validate() {
            return Err((err.error_code(), err.to_string()));
        }
        let anchor_id = req.anchor_id.as_deref().unwrap_or(&self.default_anchor_id);
        validate_proof_shape(anchor_id, req.valid_from, req.valid_until)
            .map_err(|err| (ERR_INVALID_REQUEST, err.to_string()))?;

        let ast = parse_mandate(&req.mandate_text)
            .map_err(|err| (ERR_INVALID_MANDATE, err.to_string()))?;
        let canonical =
            try_render_canonical(&ast).map_err(|err| (ERR_INVALID_MANDATE, err.to_string()))?;
        let mandate_id = ast
            .try_mandate_id()
            .map_err(|err| (ERR_INVALID_MANDATE, err.to_string()))?;

        let signer_key_id = self.signer.key_id();
        if ast.from().key() != &signer_key_id {
            return Err((
                ERR_SIGNER_MISMATCH,
                format!(
                    "mandate FROM key {} does not match daemon signer {}",
                    ast.from().key(),
                    signer_key_id
                ),
            ));
        }

        let estimated_response_bytes = self.estimate_approved_response_bytes(
            &canonical,
            anchor_id,
            ast.from().kind(),
            req.valid_from,
            req.valid_until,
        )?;
        if estimated_response_bytes > MAX_RESPONSE_FRAME_BYTES {
            return Err((
                ERR_INVALID_REQUEST,
                "canonical mandate exceeds maximum response frame size".to_string(),
            ));
        }

        WysiwysPromptView::new(
            canonical,
            mandate_id,
            req.valid_from,
            req.valid_until,
            signer_key_id,
            anchor_id.to_string(),
        )
        .map_err(|err| (ERR_INVALID_REQUEST, err.to_string()))
    }

    fn estimate_approved_response_bytes(
        &self,
        canonical_words: &str,
        anchor_id: &str,
        actor_kind: ActorKind,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<usize, (&'static str, String)> {
        let probe = SignResponse::Approved {
            signed_mandate: SignedMandate {
                canonical_words: canonical_words.to_string(),
                anchor_id: anchor_id.to_string(),
                assurance: format_assurance(self.signer.assurance()).to_string(),
                actor_kind: format_actor_kind(actor_kind).to_string(),
                signer_key: self.signer.key_id().to_string(),
                valid_from,
                valid_until,
                signature_hex: String::new(),
            },
        };
        let base_len = serde_json::to_string(&probe)
            .map_err(|err| (ERR_INVALID_REQUEST, err.to_string()))?
            .len();
        Ok(base_len.saturating_add(APPROVED_SIGNATURE_HEADROOM_BYTES))
    }

    /// Handles a single accepted [`UnixStream`] connection sequentially under an overall deadline.
    pub fn handle_stream(&mut self, stream: &UnixStream) -> Result<(), DaemonError> {
        self.handle_stream_with_clock(stream, &SystemDeadlineClock)
    }

    fn handle_stream_with_clock<C: DeadlineClock>(
        &mut self,
        stream: &UnixStream,
        clock: &C,
    ) -> Result<(), DaemonError> {
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|source| DaemonError::Io { path: None, source })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|source| DaemonError::Io { path: None, source })?;

        let started = clock.now();
        // Defense in depth: even though `self.timeout <= MAX_TIMEOUT`, Unix monotonic clocks
        // have a finite upper bound, so fail closed if `started + self.timeout` overflows.
        let Some(deadline) = started.checked_add(self.timeout) else {
            return Err(DaemonError::Io {
                path: None,
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "request timeout overflows monotonic clock",
                ),
            });
        };
        let deadline_reader = DeadlineStreamReader::with_clock(stream, Some(deadline), clock);
        let mut reader = FrameReader::new(BufReader::new(deadline_reader));
        let response = match reader.read_frame_line(MAX_REQUEST_FRAME_BYTES) {
            Ok(None) => return Ok(()),
            Ok(Some(line)) => match decode_sign_request(&line) {
                Ok(req) => self.handle_request_with_start(&req, started, clock),
                Err(err) => error_response(err.error_code(), &err.to_string()),
            },
            Err(err) => error_response(err.error_code(), &err.to_string()),
        };

        let mut writer = stream;
        if let Err(ProtocolError::FrameTooLarge { .. }) =
            write_frame(&mut writer, &response, MAX_RESPONSE_FRAME_BYTES)
        {
            let fallback =
                error_response(ERR_INTERNAL, "signed response exceeded maximum frame size");
            let _ = write_frame(&mut writer, &fallback, MAX_RESPONSE_FRAME_BYTES);
        }
        Ok(())
    }

    /// Accepts and handles exactly one incoming connection on `listener`.
    pub fn serve_one(&mut self, listener: &UnixListener) -> Result<(), DaemonError> {
        let (stream, _) = listener
            .accept()
            .map_err(|source| DaemonError::Io { path: None, source })?;
        self.handle_stream(&stream)
    }

    /// Serves sequential requests until `stop` becomes `true`.
    pub fn serve_until(
        &mut self,
        listener: &UnixListener,
        stop: &AtomicBool,
    ) -> Result<(), DaemonError> {
        self.serve_until_with_clock(listener, stop, &SystemDeadlineClock)
    }

    fn serve_until_with_clock<C: DeadlineClock>(
        &mut self,
        listener: &UnixListener,
        stop: &AtomicBool,
        clock: &C,
    ) -> Result<(), DaemonError> {
        listener
            .set_nonblocking(true)
            .map_err(|source| DaemonError::Io { path: None, source })?;
        let _restore_blocking = RestoreBlockingGuard(listener);
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    self.handle_stream_with_clock(&stream, clock)?;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(DaemonError::Io { path: None, source }),
            }
        }
        Ok(())
    }

    /// Serves incoming connections sequentially forever until an unrecoverable listener error occurs.
    pub fn serve_forever(&mut self, listener: &UnixListener) -> Result<(), DaemonError> {
        loop {
            match listener.accept() {
                Ok((stream, _)) => self.handle_stream(&stream)?,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(DaemonError::Io { path: None, source }),
            }
        }
    }
}

struct RestoreBlockingGuard<'a>(&'a UnixListener);

impl Drop for RestoreBlockingGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.set_nonblocking(false);
    }
}

fn error_response(code: &str, message: &str) -> SignResponse {
    SignResponse::Error {
        code: sanitize_wire_message(code, ERR_INVALID_REQUEST),
        message: sanitize_wire_message(message, "request failed"),
    }
}

fn sanitize_wire_message(raw: &str, fallback: &str) -> String {
    let mut cleaned = String::new();
    for c in raw.chars() {
        let mapped = if c.is_control() || is_forbidden_wysiwys_char(c) {
            ' '
        } else {
            c
        };
        if cleaned.is_empty() && mapped.is_whitespace() {
            continue;
        }
        if cleaned.len() + mapped.len_utf8() > MAX_WIRE_MESSAGE_BYTES {
            break;
        }
        cleaned.push(mapped);
    }
    let trimmed = cleaned.trim_end();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use handfest_anchors::Ed25519Keypair;

    use super::*;
    use crate::prompt::PromptError;
    use crate::socket::near_max_instant;

    struct FixedClock(Instant);

    impl DeadlineClock for FixedClock {
        fn now(&self) -> Instant {
            self.0
        }
    }

    struct RejectingPrompt;

    impl ApprovalPrompt for RejectingPrompt {
        fn prompt(&mut self, _view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError> {
            Ok(ApprovalOutcome::Denied {
                reason: "test".to_string(),
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn listener_is_nonblocking(listener: &UnixListener) -> bool {
        use std::os::fd::AsRawFd;

        let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", listener.as_raw_fd()))
            .expect("must read /proc/self/fdinfo for listener");
        let flags_line = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .expect("fdinfo must contain flags line")
            .trim();
        let flags = u32::from_str_radix(flags_line, 8).expect("fdinfo flags must be octal");
        // Linux O_NONBLOCK = 0o4000.
        (flags & 0o4000) != 0
    }

    #[test]
    fn handle_stream_fails_closed_when_accepted_timeout_overflows_monotonic_clock() {
        let kp = Ed25519Keypair::from_secret_bytes([0x61; 32]);
        let mut daemon =
            ApproverDaemon::new(kp, RejectingPrompt, "local-ed25519", Duration::from_secs(5))
                .expect("5s timeout must be accepted");

        let (server_stream, _client_stream) = UnixStream::pair().unwrap();
        let overflow_clock = FixedClock(near_max_instant());
        let err = daemon
            .handle_stream_with_clock(&server_stream, &overflow_clock)
            .unwrap_err();
        assert!(
            matches!(
                err,
                DaemonError::Io {
                    path: None,
                    ref source,
                } if source.kind() == io::ErrorKind::InvalidInput
                    && source.to_string().contains("overflows monotonic clock")
            ),
            "expected InvalidInput clock-overflow error, got {err:?}"
        );
    }

    #[test]
    fn serve_until_restores_listener_blocking_mode_after_normal_stop_and_serve_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let canonical = fs::canonicalize(dir.path()).unwrap();
        fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
        let sock = canonical.join("restore_both_paths.sock");
        let bound = BoundSocket::bind(&sock, SocketMode::OwnerOnly).unwrap();

        #[cfg(target_os = "linux")]
        {
            assert!(!listener_is_nonblocking(bound.listener()));
            bound.listener().set_nonblocking(true).unwrap();
            assert!(
                listener_is_nonblocking(bound.listener()),
                "fdinfo helper must detect O_NONBLOCK"
            );
            bound.listener().set_nonblocking(false).unwrap();
            assert!(!listener_is_nonblocking(bound.listener()));
        }

        let kp = Ed25519Keypair::from_secret_bytes([0x62; 32]);
        let mut daemon =
            ApproverDaemon::new(kp, RejectingPrompt, "local-ed25519", Duration::from_secs(5))
                .unwrap();

        // 1. Normal stop path restores blocking mode.
        daemon
            .serve_until(bound.listener(), &AtomicBool::new(true))
            .unwrap();
        #[cfg(target_os = "linux")]
        assert!(
            !listener_is_nonblocking(bound.listener()),
            "listener must be restored to blocking mode after normal stop"
        );

        // 2. Serve error path (handle_stream_with_clock returns Err on accepted stream)
        // also restores blocking mode via RAII guard.
        let _client = UnixStream::connect(&sock).unwrap();
        let stop = AtomicBool::new(false);
        let overflow_clock = FixedClock(near_max_instant());
        let err = daemon
            .serve_until_with_clock(bound.listener(), &stop, &overflow_clock)
            .unwrap_err();
        assert!(matches!(
            err,
            DaemonError::Io {
                path: None,
                ref source,
            } if source.kind() == io::ErrorKind::InvalidInput
                && source.to_string().contains("overflows monotonic clock")
        ));

        #[cfg(target_os = "linux")]
        assert!(
            !listener_is_nonblocking(bound.listener()),
            "listener must be restored to blocking mode after serve_until error"
        );

        // Portable behavioral check with zero queued clients: accept() must block, not return WouldBlock.
        let listener_clone = bound.listener().try_clone().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let res = listener_clone.accept();
            let _ = done_tx.send(res.map(|_| ()));
        });
        ready_rx.recv().unwrap();
        assert!(
            matches!(
                done_rx.recv_timeout(Duration::from_millis(60)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "listener must block in accept() with no queued client after serve_until error"
        );
        let _unblock = UnixStream::connect(&sock).unwrap();
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("accept must complete once client connects")
            .expect("accept must succeed");
        waiter.join().unwrap();
    }
}
