//! Internal `tmux display-popup` WYSIWYS helper and kill-and-reap bounded subprocess runner.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use handfest_anchors::{AnchorError, CommandOutput, CommandRunner, SystemCommandRunner};

use crate::prompt::{read_tty_approval_reply, ApprovalOutcome, PromptError};

/// Maximum bytes accepted when reading the private popup display file.
pub(super) const MAX_DISPLAY_FILE_BYTES: u64 = 1024 * 1024;

/// Maximum bytes captured from a bounded subprocess stdout/stderr pipe.
const MAX_SUBPROCESS_OUTPUT_BYTES: u64 = 1024 * 1024;

/// Polling interval while waiting for a bounded subprocess to exit before its deadline.
const SUBPROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Brief post-line window for detecting canonical-PTY multi-line pastes (e.g. `yes\nno\n`).
const POPUP_TRAILING_INPUT_WINDOW: Duration = Duration::from_millis(25);

/// Exit classification returned by [`run_internal_popup_prompt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalPopupOutcome {
    /// Operator confirmed exact `"yes"` after the mandate display file was rendered.
    Approved,
    /// Operator declined, closed stdin, or supplied any non-`"yes"` input.
    Denied,
    /// Operator did not answer before the popup timeout elapsed.
    TimedOut,
}

pub(super) fn write_private_file(
    path: &Path,
    label: &str,
    content: &str,
) -> Result<(), PromptError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(path)
        .map_err(|err| PromptError::Io(format!("failed to create tmux {label} file: {err}")))?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|err| {
            PromptError::Io(format!(
                "failed to set 0600 permissions on tmux {label} file: {err}"
            ))
        })?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|err| PromptError::Io(format!("failed to write tmux {label} file: {err}")))
}

pub(super) fn read_display_bounded<R: Read>(reader: R) -> Result<String, PromptError> {
    let mut buf = Vec::new();
    reader
        .take(MAX_DISPLAY_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|err| PromptError::Io(format!("failed to read tmux display file: {err}")))?;
    if buf.len() as u64 > MAX_DISPLAY_FILE_BYTES {
        return Err(PromptError::Io(format!(
            "tmux display file exceeded maximum size of {MAX_DISPLAY_FILE_BYTES} bytes"
        )));
    }
    let content = String::from_utf8(buf)
        .map_err(|err| PromptError::Io(format!("tmux display file is not valid UTF-8: {err}")))?;
    if content.trim().is_empty() {
        return Err(PromptError::Io("tmux display file is empty".to_string()));
    }
    Ok(content)
}

pub(super) fn read_display_file(path: &Path) -> Result<String, PromptError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| PromptError::Io(format!("failed to stat tmux display file: {err}")))?;
    if !meta.file_type().is_file() {
        return Err(PromptError::Io(
            "tmux display file must be a regular file".to_string(),
        ));
    }
    let file = fs::File::open(path)
        .map_err(|err| PromptError::Io(format!("failed to open tmux display file: {err}")))?;
    let fd_meta = file
        .metadata()
        .map_err(|err| PromptError::Io(format!("failed to stat open tmux display file: {err}")))?;
    if !fd_meta.file_type().is_file() {
        return Err(PromptError::Io(
            "tmux display file must be a regular file".to_string(),
        ));
    }
    read_display_bounded(file)
}

pub(super) enum PopupStdinEvent {
    FirstReply(Result<ApprovalOutcome, PromptError>),
    TrailingInput,
    CleanEof,
    TrailingInterrupted,
    TrailingIo(String),
}

pub(super) fn wait_for_trailing_popup_input(
    rx: &mpsc::Receiver<PopupStdinEvent>,
    window: Duration,
    deadline: Option<Instant>,
) -> Result<Option<ApprovalOutcome>, PromptError> {
    match rx.recv_timeout(window) {
        Ok(PopupStdinEvent::TrailingInput | PopupStdinEvent::FirstReply(_)) => {
            Ok(Some(ApprovalOutcome::Denied {
                reason: "ambiguous multi-line TTY input rejected".to_string(),
            }))
        }
        Ok(PopupStdinEvent::TrailingInterrupted) => Ok(Some(ApprovalOutcome::Denied {
            reason: "operator interrupted prompt".to_string(),
        })),
        Ok(PopupStdinEvent::TrailingIo(detail)) => Err(PromptError::Io(detail)),
        Ok(PopupStdinEvent::CleanEof) | Err(mpsc::RecvTimeoutError::Timeout) => {
            if deadline.is_some_and(|d| Instant::now() > d) {
                Ok(None)
            } else {
                Ok(Some(ApprovalOutcome::Approved))
            }
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(PromptError::Io(
            "popup stdin reader terminated unexpectedly".to_string(),
        )),
    }
}

pub(super) fn read_popup_approval_reply<R: BufRead + Send + 'static>(
    reader: R,
    timeout: Duration,
) -> Result<Option<ApprovalOutcome>, PromptError> {
    let deadline = Instant::now().checked_add(timeout);
    let (tx, rx) = mpsc::channel();
    let _reader_thread = thread::spawn(move || {
        let mut reader = reader;
        let first = read_tty_approval_reply(&mut reader);
        let check_trailing = matches!(first, Ok(ApprovalOutcome::Approved));
        if tx.send(PopupStdinEvent::FirstReply(first)).is_err() || !check_trailing {
            return;
        }
        let trailing_event = match reader.fill_buf() {
            Ok([]) => PopupStdinEvent::CleanEof,
            Ok(_) => PopupStdinEvent::TrailingInput,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                PopupStdinEvent::TrailingInterrupted
            }
            Err(err) => PopupStdinEvent::TrailingIo(err.to_string()),
        };
        let _ = tx.send(trailing_event);
    });

    match rx.recv_timeout(timeout) {
        Ok(PopupStdinEvent::FirstReply(Ok(ApprovalOutcome::Approved))) => {
            let remaining =
                deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
            // Fail closed rather than truncating the paste-disambiguation window.
            if remaining < POPUP_TRAILING_INPUT_WINDOW {
                return Ok(None);
            }
            wait_for_trailing_popup_input(&rx, POPUP_TRAILING_INPUT_WINDOW, deadline)
        }
        Ok(PopupStdinEvent::FirstReply(Ok(denied))) => Ok(Some(denied)),
        Ok(PopupStdinEvent::FirstReply(Err(err))) => Err(err),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(PromptError::Io(
            "popup stdin reader terminated unexpectedly".to_string(),
        )),
        Ok(_) => Err(PromptError::Io(
            "unexpected popup stdin reader event".to_string(),
        )),
    }
}

pub(super) fn run_popup_prompt_with_io<R, W>(
    display_file: &Path,
    result_file: &Path,
    timeout: Duration,
    reader: R,
    mut writer: W,
) -> Result<InternalPopupOutcome, PromptError>
where
    R: BufRead + Send + 'static,
    W: Write,
{
    let display = read_display_file(display_file)?;

    writeln!(writer, "{display}")
        .map_err(|err| PromptError::Io(format!("failed to display mandate in popup: {err}")))?;
    write!(writer, "\nApprove and sign this mandate? [yes/N]: ")
        .map_err(|err| PromptError::Io(format!("failed to write approval prompt: {err}")))?;
    writer
        .flush()
        .map_err(|err| PromptError::Io(format!("failed to flush approval prompt: {err}")))?;
    drop(writer);

    match read_popup_approval_reply(reader, timeout)? {
        None => Ok(InternalPopupOutcome::TimedOut),
        Some(ApprovalOutcome::Approved) => {
            write_private_file(result_file, "result", "approved\n")?;
            Ok(InternalPopupOutcome::Approved)
        }
        Some(ApprovalOutcome::Denied { .. }) => {
            write_private_file(result_file, "result", "denied\n")?;
            Ok(InternalPopupOutcome::Denied)
        }
    }
}

/// RAII guard that disables `ICANON` on a real TTY stdin so canonical line buffering cannot
/// hide trailing bytes of a newline-free multi-line paste (`yes\nno`, `yes\rno`, or bracketed
/// paste) inside the kernel `n_tty` edit buffer across the trailing-input check.
struct NonCanonicalTtyGuard {
    saved_mode: Option<String>,
}

impl NonCanonicalTtyGuard {
    fn enter_if_tty() -> Self {
        use std::io::IsTerminal;
        if !io::stdin().is_terminal() {
            return Self { saved_mode: None };
        }
        let saved_mode = Command::new("stty")
            .arg("-g")
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if saved_mode.is_some() {
            let _ = Command::new("stty")
                .args(["-icanon", "min", "1", "time", "0"])
                .stdin(Stdio::inherit())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        Self { saved_mode }
    }
}

impl Drop for NonCanonicalTtyGuard {
    fn drop(&mut self) {
        if let Some(ref mode) = self.saved_mode {
            let _ = Command::new("stty")
                .arg(mode)
                .stdin(Stdio::inherit())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Executes the pure-Rust internal `tmux display-popup` approval prompt.
///
/// Security invariants:
/// - Reads `display_file` strictly as a regular file using a bounded `.take()` read before
///   prompting; fails closed with an error if the file is missing, unreadable, non-regular,
///   oversized, or empty (NEVER prompts without rendering the canonical mandate view).
/// - Disables `ICANON` when attached to a TTY and waits a brief trailing-input window after
///   `"yes\n"` / `"yes\r\n"` so embedded NUL bytes (`y\0es\n`), EOF without newline, oversized
///   lines, and multi-line pastes (`yes\nno`, `yes\rno`, `yes\nno\n`) all fail closed.
/// - Writes `"approved\n"` (`0600`, `create_new`) to `result_file` ONLY on unambiguous `"yes\n"`
///   or `"yes\r\n"`.
pub fn run_internal_popup_prompt(
    display_file: &Path,
    result_file: &Path,
    timeout: Duration,
) -> Result<InternalPopupOutcome, PromptError> {
    let _tty_guard = NonCanonicalTtyGuard::enter_if_tty();
    run_popup_prompt_with_io(
        display_file,
        result_file,
        timeout,
        BufReader::new(io::stdin()),
        io::stdout().lock(),
    )
}

/// Outcome of executing a command under an enforced wall-clock timeout.
#[derive(Debug)]
pub enum BoundedCommandOutcome {
    /// Command completed before the deadline with captured output or an execution error.
    Completed(Result<CommandOutput, AnchorError>),
    /// Command exceeded its deadline (OS subprocesses are terminated and reaped before returning).
    TimedOut,
}

/// Pluggable seam for executing commands with an enforced wall-clock deadline.
///
/// [`SystemCommandRunner`] implements this by spawning `std::process::Command` directly,
/// polling [`std::process::Child::try_wait`], and invoking `kill()` + `wait()` on timeout so
/// timed-out `tmux` subprocesses are terminated and reaped cleanly with zero leaked popups.
pub trait BoundedCommandRunner: CommandRunner {
    fn run_bounded(&self, program: &str, args: &[&str], timeout: Duration)
        -> BoundedCommandOutcome;
}

impl BoundedCommandRunner for SystemCommandRunner {
    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> BoundedCommandOutcome {
        run_subprocess_bounded(program, args, timeout)
    }
}

fn spawn_bounded_pipe_reader<R: Read + Send + 'static>(
    pipe: R,
) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (tx, rx) = mpsc::sync_channel(1);
    let _reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let res = pipe
            .take(MAX_SUBPROCESS_OUTPUT_BYTES.saturating_add(1))
            .read_to_end(&mut buf)
            .and_then(|_| {
                if buf.len() as u64 > MAX_SUBPROCESS_OUTPUT_BYTES {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "subprocess output exceeded maximum size of {MAX_SUBPROCESS_OUTPUT_BYTES} bytes"
                        ),
                    ))
                } else {
                    Ok(buf)
                }
            });
        let _ = tx.send(res);
    });
    rx
}

fn recv_pipe_bounded(
    program: &str,
    stream_name: &str,
    rx: &mpsc::Receiver<io::Result<Vec<u8>>>,
    deadline: Option<Instant>,
) -> Result<Option<Vec<u8>>, AnchorError> {
    let outcome = match deadline {
        Some(d) => {
            let Some(remaining) = d.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            if remaining.is_zero() {
                return Ok(None);
            }
            rx.recv_timeout(remaining)
        }
        None => rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
    };
    match outcome {
        Ok(Ok(bytes)) => Ok(Some(bytes)),
        Ok(Err(err)) => Err(AnchorError::CommandIo {
            program: program.to_string(),
            detail: err.to_string(),
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(AnchorError::CommandIo {
            program: program.to_string(),
            detail: format!("subprocess {stream_name} reader panicked"),
        }),
    }
}

fn collect_subprocess_output(
    program: &str,
    status: ExitStatus,
    stdout_rx: &mpsc::Receiver<io::Result<Vec<u8>>>,
    stderr_rx: &mpsc::Receiver<io::Result<Vec<u8>>>,
    deadline: Option<Instant>,
) -> BoundedCommandOutcome {
    let stdout = match recv_pipe_bounded(program, "stdout", stdout_rx, deadline) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return BoundedCommandOutcome::TimedOut,
        Err(err) => return BoundedCommandOutcome::Completed(Err(err)),
    };
    let stderr = match recv_pipe_bounded(program, "stderr", stderr_rx, deadline) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return BoundedCommandOutcome::TimedOut,
        Err(err) => return BoundedCommandOutcome::Completed(Err(err)),
    };
    if !status.success() {
        return BoundedCommandOutcome::Completed(Err(AnchorError::CommandFailed {
            program: program.to_string(),
            status: status.code(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
        }));
    }
    BoundedCommandOutcome::Completed(Ok(CommandOutput { stdout, stderr }))
}

fn run_subprocess_bounded(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> BoundedCommandOutcome {
    if timeout.is_zero() {
        return BoundedCommandOutcome::TimedOut;
    }
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return BoundedCommandOutcome::Completed(Err(AnchorError::CommandIo {
                program: program.to_string(),
                detail: err.to_string(),
            }));
        }
    };

    let stdout_rx = spawn_bounded_pipe_reader(
        child
            .stdout
            .take()
            .expect("child stdout was configured with Stdio::piped()"),
    );
    let stderr_rx = spawn_bounded_pipe_reader(
        child
            .stderr
            .take()
            .expect("child stderr was configured with Stdio::piped()"),
    );

    let deadline = Instant::now().checked_add(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return collect_subprocess_output(
                    program, status, &stdout_rx, &stderr_rx, deadline,
                );
            }
            Ok(None) => {
                let now = Instant::now();
                if deadline.is_some_and(|d| now >= d) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return BoundedCommandOutcome::TimedOut;
                }
                let sleep_for = deadline.map_or(SUBPROCESS_POLL_INTERVAL, |d| {
                    d.saturating_duration_since(now)
                        .min(SUBPROCESS_POLL_INTERVAL)
                });
                thread::sleep(sleep_for);
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return BoundedCommandOutcome::Completed(Err(AnchorError::CommandIo {
                    program: program.to_string(),
                    detail: err.to_string(),
                }));
            }
        }
    }
}

pub(super) fn timeout_ms_floor(remaining: Duration) -> Option<u64> {
    let clamped_ms = remaining.as_millis().min(crate::MAX_TIMEOUT.as_millis());
    if clamped_ms == 0 {
        return None;
    }
    Some(u64::try_from(clamped_ms).unwrap_or(u64::MAX))
}
