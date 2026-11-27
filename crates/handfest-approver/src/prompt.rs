//! Pluggable human WYSIWYS approval prompts (`TtyPrompt` and `DesktopPrompt`).

use std::fmt;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::BufReader;
use std::io::{self, BufRead, Write};
use std::time::Duration;

use handfest_anchors::{AnchorError, CommandRunner, SystemCommandRunner};
use handfest_core::ast::{try_format_rfc3339_utc, KeyId, MandateId};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::validate_proof_shape;

use crate::protocol::{find_forbidden_mandate_char, validate_single_line_text};

/// Maximum bytes read from an interactive TTY response line before failing closed.
const MAX_TTY_REPLY_BYTES: usize = 1024;

/// Default desktop approval dialog timeout in seconds when no per-request timeout is supplied.
pub const DEFAULT_DESKTOP_TIMEOUT_SECS: u64 = 60;

/// Canonical WYSIWYS review bundle computed exclusively by the approver daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WysiwysPromptView {
    canonical_mandate: String,
    mandate_id: MandateId,
    valid_from: i64,
    valid_until: i64,
    valid_from_rfc3339: String,
    valid_until_rfc3339: String,
    signer_key_id: KeyId,
    anchor_id: String,
}

impl WysiwysPromptView {
    /// Constructs a validated [`WysiwysPromptView`] from canonical mandate text and metadata.
    ///
    /// Enforces fail-closed WYSIWYS invariants:
    /// - `anchor_id` is non-empty and free of control, newline, quote, line/paragraph separator,
    ///   and Unicode Bidi override characters;
    /// - `valid_from` and `valid_until` are valid RFC 3339 timestamps with `valid_from <= valid_until`;
    /// - `signer_key_id` passes `KeyId::validate()` and matches the mandate's `FROM` key;
    /// - `canonical_mandate` is free of forbidden control/Bidi characters (other than `\n`),
    ///   parses cleanly as `HANDFEST v1`, equals its canonical rendering, and hashes to `mandate_id`.
    pub fn new(
        canonical_mandate: String,
        mandate_id: MandateId,
        valid_from: i64,
        valid_until: i64,
        signer_key_id: KeyId,
        anchor_id: String,
    ) -> Result<Self, PromptError> {
        validate_single_line_text(&anchor_id, "anchor_id")
            .map_err(|err| PromptError::InvalidView(err.to_string()))?;
        validate_proof_shape(&anchor_id, valid_from, valid_until)
            .map_err(|err| PromptError::InvalidView(err.to_string()))?;
        let valid_from_rfc3339 = try_format_rfc3339_utc(valid_from)
            .map_err(|err| PromptError::InvalidView(err.to_string()))?;
        let valid_until_rfc3339 = try_format_rfc3339_utc(valid_until)
            .map_err(|err| PromptError::InvalidView(err.to_string()))?;
        signer_key_id
            .validate()
            .map_err(|err| PromptError::InvalidView(format!("invalid signer_key_id: {err}")))?;

        validate_canonical_mandate_view(&canonical_mandate, mandate_id, &signer_key_id)?;

        Ok(Self {
            canonical_mandate,
            mandate_id,
            valid_from,
            valid_until,
            valid_from_rfc3339,
            valid_until_rfc3339,
            signer_key_id,
            anchor_id,
        })
    }

    /// Returns the verified canonical `HANDFEST v1` mandate text.
    #[must_use]
    pub fn canonical_mandate(&self) -> &str {
        &self.canonical_mandate
    }

    /// Returns the content-addressed [`MandateId`] matching [`Self::canonical_mandate`].
    #[must_use]
    pub const fn mandate_id(&self) -> MandateId {
        self.mandate_id
    }

    /// Returns the mandate validity start timestamp (Unix seconds).
    #[must_use]
    pub const fn valid_from(&self) -> i64 {
        self.valid_from
    }

    /// Returns the mandate validity end timestamp (Unix seconds).
    #[must_use]
    pub const fn valid_until(&self) -> i64 {
        self.valid_until
    }

    /// Returns the UTC RFC 3339 rendering of [`Self::valid_from`].
    #[must_use]
    pub fn valid_from_rfc3339(&self) -> &str {
        &self.valid_from_rfc3339
    }

    /// Returns the UTC RFC 3339 rendering of [`Self::valid_until`].
    #[must_use]
    pub fn valid_until_rfc3339(&self) -> &str {
        &self.valid_until_rfc3339
    }

    /// Returns the daemon signer's [`KeyId`].
    #[must_use]
    pub const fn signer_key_id(&self) -> &KeyId {
        &self.signer_key_id
    }

    /// Returns the validated trust anchor identifier.
    #[must_use]
    pub fn anchor_id(&self) -> &str {
        &self.anchor_id
    }

    /// Formats the deterministic, human-legible WYSIWYS approval summary.
    #[must_use]
    pub fn format_display(&self) -> String {
        format!(
            "=== HANDFEST MANDATE APPROVAL REQUEST ===\n\
             Mandate ID:  {}\n\
             Signer Key:  {}\n\
             Anchor ID:   {}\n\
             Valid From:  {}\n\
             Valid Until: {}\n\
             -----------------------------------------\n\
             {}\
             -----------------------------------------",
            self.mandate_id,
            self.signer_key_id,
            self.anchor_id,
            self.valid_from_rfc3339,
            self.valid_until_rfc3339,
            self.canonical_mandate,
        )
    }
}

fn validate_canonical_mandate_view(
    canonical_mandate: &str,
    expected_id: MandateId,
    signer_key_id: &KeyId,
) -> Result<(), PromptError> {
    if canonical_mandate.trim().is_empty() {
        return Err(PromptError::InvalidView(
            "canonical_mandate must not be empty".to_string(),
        ));
    }
    if let Some(ch) = find_forbidden_mandate_char(canonical_mandate) {
        return Err(PromptError::InvalidView(format!(
            "canonical_mandate contains forbidden character U+{:04X}",
            u32::from(ch)
        )));
    }
    let ast = parse_mandate(canonical_mandate)
        .map_err(|err| PromptError::InvalidView(format!("invalid canonical mandate: {err}")))?;
    if ast.from().key() != signer_key_id {
        return Err(PromptError::InvalidView(format!(
            "signer_key_id mismatch: mandate FROM key {} does not match signer {}",
            ast.from().key(),
            signer_key_id
        )));
    }
    let rendered = try_render_canonical(&ast)
        .map_err(|err| PromptError::InvalidView(format!("failed to render mandate: {err}")))?;
    if rendered != canonical_mandate {
        return Err(PromptError::InvalidView(
            "canonical_mandate is not in canonical HANDFEST v1 form".to_string(),
        ));
    }
    let computed_id = MandateId::sha256(rendered.as_bytes());
    if computed_id != expected_id {
        return Err(PromptError::InvalidView(format!(
            "mandate_id mismatch: expected {computed_id}, got {expected_id}"
        )));
    }
    Ok(())
}

/// Explicit outcome of a human WYSIWYS approval prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Denied { reason: String },
}

/// Structured error returned when a prompt backend cannot interact with the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    InvalidView(String),
    Io(String),
    CommandFailed { program: String, detail: String },
}

impl fmt::Display for PromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidView(detail) => write!(f, "invalid prompt view: {detail}"),
            Self::Io(detail) => write!(f, "approval prompt I/O error: {detail}"),
            Self::CommandFailed { program, detail } => {
                write!(f, "desktop approval prompt '{program}' failed: {detail}")
            }
        }
    }
}

impl std::error::Error for PromptError {}

/// Pluggable out-of-band human approval seam.
///
/// Every implementation must fail closed: only explicit human confirmation may return
/// [`ApprovalOutcome::Approved`].
pub trait ApprovalPrompt {
    fn prompt(&mut self, view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError>;

    /// Prompts the operator with an explicit remaining approval timeout.
    ///
    /// Backends that support native dialog timeouts (such as [`DesktopPrompt`]) enforce
    /// `timeout`; others delegate to [`Self::prompt`].
    fn prompt_with_timeout(
        &mut self,
        view: &WysiwysPromptView,
        _timeout: Duration,
    ) -> Result<ApprovalOutcome, PromptError> {
        self.prompt(view)
    }
}

/// Interactive terminal prompt reading from a dedicated reader/writer (e.g. `/dev/tty`).
///
/// Fails closed: binds approval to a full 256-bit (64-lowercase-hex) domain-separated SHA-256
/// confirmation digest covering the canonical mandate text, validity window (`valid_from`,
/// `valid_until`), `signer_key_id`, and `anchor_id`. Accepts ONLY exact `"yes <64-hex-code>"`
/// (with an optional single trailing `\r` before `\n` and no trailing buffered bytes). Empty
/// input, EOF, `ErrorKind::Interrupted` (Ctrl-C), oversized replies, or any other text returns
/// `Denied`.
#[derive(Debug)]
pub struct TtyPrompt<R, W> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> TtyPrompt<R, W> {
    /// Constructs a `TtyPrompt` bound to explicit interactive reader and writer streams.
    #[must_use]
    pub const fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

#[cfg(unix)]
impl TtyPrompt<BufReader<File>, File> {
    /// Opens the operator's controlling terminal (`/dev/tty`) for out-of-band approval.
    pub fn open_dev_tty() -> Result<Self, PromptError> {
        let read_file = OpenOptions::new()
            .read(true)
            .open("/dev/tty")
            .map_err(|err| {
                PromptError::Io(format!("failed to open /dev/tty for reading: {err}"))
            })?;
        let write_file = OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .map_err(|err| {
                PromptError::Io(format!("failed to open /dev/tty for writing: {err}"))
            })?;
        Ok(Self::new(BufReader::new(read_file), write_file))
    }
}

impl<R: BufRead, W: Write> ApprovalPrompt for TtyPrompt<R, W> {
    fn prompt(&mut self, view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError> {
        writeln!(self.writer, "\n{}", view.format_display())
            .map_err(|err| PromptError::Io(err.to_string()))?;
        write!(self.writer, "Approve and sign this mandate? [yes/N]: ")
            .map_err(|err| PromptError::Io(err.to_string()))?;
        self.writer
            .flush()
            .map_err(|err| PromptError::Io(err.to_string()))?;

        match read_bounded_tty_reply(&mut self.reader, MAX_TTY_REPLY_BYTES) {
            Ok(TtyReadResult::Eof) => Ok(ApprovalOutcome::Denied {
                reason: "operator closed prompt (EOF)".to_string(),
            }),
            Ok(TtyReadResult::Truncated) => Ok(ApprovalOutcome::Denied {
                reason: "operator closed prompt before newline (EOF)".to_string(),
            }),
            Ok(TtyReadResult::AmbiguousMultiLine) => Ok(ApprovalOutcome::Denied {
                reason: "ambiguous multi-line TTY input rejected".to_string(),
            }),
            Ok(TtyReadResult::Interrupted) => Ok(ApprovalOutcome::Denied {
                reason: "operator interrupted prompt".to_string(),
            }),
            Ok(TtyReadResult::TooLong) => Ok(ApprovalOutcome::Denied {
                reason: "operator input exceeded maximum reply length".to_string(),
            }),
            Ok(TtyReadResult::Line(reply)) => Ok(classify_tty_reply(&reply)),
            Err(err) => Err(PromptError::Io(err.to_string())),
        }
    }
}

enum TtyReadResult {
    Eof,
    Truncated,
    AmbiguousMultiLine,
    Interrupted,
    TooLong,
    Line(String),
}

fn read_bounded_tty_reply<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<TtyReadResult> {
    let mut buf = Vec::new();
    let mut overflowed = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                return Ok(TtyReadResult::Interrupted);
            }
            Err(err) => return Err(err),
        };
        if chunk.is_empty() {
            return if overflowed {
                Ok(TtyReadResult::TooLong)
            } else if buf.is_empty() {
                Ok(TtyReadResult::Eof)
            } else {
                // Fail closed: require an explicit terminating `\n` (or `\r\n`).
                Ok(TtyReadResult::Truncated)
            };
        }
        if let Some(nl_pos) = chunk.iter().position(|&b| b == b'\n') {
            let chunk_len = chunk.len();
            let has_trailing = nl_pos + 1 < chunk_len;
            if !overflowed && buf.len().saturating_add(nl_pos) <= max_bytes {
                buf.extend_from_slice(&chunk[..nl_pos]);
            } else {
                overflowed = true;
            }
            // Inspect already-buffered trailing bytes and drain any unfinished trailing line
            // through its terminating `\n` (or EOF) so a truncated tail can never be read by a
            // subsequent prompt call.
            if has_trailing {
                let ended_with_nl = chunk[chunk_len - 1] == b'\n';
                reader.consume(chunk_len);
                if !ended_with_nl && drain_tty_until_newline(reader)? {
                    return Ok(TtyReadResult::Interrupted);
                }
                return Ok(TtyReadResult::AmbiguousMultiLine);
            }
            reader.consume(nl_pos + 1);
            return if overflowed {
                Ok(TtyReadResult::TooLong)
            } else {
                Ok(TtyReadResult::Line(
                    String::from_utf8_lossy(&buf).into_owned(),
                ))
            };
        }
        let chunk_len = chunk.len();
        if !overflowed && buf.len().saturating_add(chunk_len) <= max_bytes {
            buf.extend_from_slice(chunk);
        } else {
            overflowed = true;
        }
        reader.consume(chunk_len);
    }
}

fn drain_tty_until_newline<R: BufRead>(reader: &mut R) -> io::Result<bool> {
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => return Ok(true),
            Err(err) => return Err(err),
        };
        if chunk.is_empty() {
            return Ok(false);
        }
        let chunk_len = chunk.len();
        let ended_with_nl = chunk[chunk_len - 1] == b'\n';
        reader.consume(chunk_len);
        if ended_with_nl {
            return Ok(false);
        }
    }
}

fn classify_tty_reply(raw: &str) -> ApprovalOutcome {
    let line = raw.strip_suffix('\r').unwrap_or(raw);
    if line == "yes" {
        return ApprovalOutcome::Approved;
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        ApprovalOutcome::Denied {
            reason: "operator declined (default No)".to_string(),
        }
    } else if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
        ApprovalOutcome::Denied {
            reason: "operator denied request".to_string(),
        }
    } else {
        ApprovalOutcome::Denied {
            reason: "operator did not confirm approval".to_string(),
        }
    }
}

/// Supported native desktop modal backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopBackend {
    /// Linux GTK modal dialog via `zenity --question --no-markup`.
    Zenity,
    /// macOS AppleScript modal dialog via `osascript` with argv-passed text.
    Osascript,
}

impl DesktopBackend {
    /// Selects the native desktop modal backend for the current OS target.
    #[must_use]
    pub const fn platform_default() -> Self {
        if cfg!(target_os = "macos") {
            Self::Osascript
        } else {
            Self::Zenity
        }
    }
}

/// Desktop modal WYSIWYS approval prompt backed by a pluggable [`CommandRunner`].
#[derive(Debug, Clone)]
pub struct DesktopPrompt<R: CommandRunner = SystemCommandRunner> {
    runner: R,
    backend: DesktopBackend,
    timeout: Duration,
}

impl DesktopPrompt<SystemCommandRunner> {
    /// Constructs a desktop prompt using the host OS backend and [`SystemCommandRunner`].
    #[must_use]
    pub const fn system() -> Self {
        Self::with_backend(SystemCommandRunner, DesktopBackend::platform_default())
    }
}

impl<R: CommandRunner> DesktopPrompt<R> {
    /// Constructs a desktop prompt using the platform default backend and a custom runner.
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self::with_backend(runner, DesktopBackend::platform_default())
    }

    /// Constructs a desktop prompt with an explicit [`DesktopBackend`] and [`CommandRunner`].
    #[must_use]
    pub const fn with_backend(runner: R, backend: DesktopBackend) -> Self {
        Self {
            runner,
            backend,
            timeout: Duration::from_secs(DEFAULT_DESKTOP_TIMEOUT_SECS),
        }
    }

    /// Overrides the default dialog timeout used by [`ApprovalPrompt::prompt`].
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn run_with_timeout(
        &self,
        view: &WysiwysPromptView,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, PromptError> {
        let display = view.format_display();
        let timeout_secs = timeout_secs_ceil(timeout);
        match self.backend {
            DesktopBackend::Zenity => run_zenity_prompt(&self.runner, &display, timeout_secs),
            DesktopBackend::Osascript => run_osascript_prompt(&self.runner, &display, timeout_secs),
        }
    }
}

impl<R: CommandRunner> ApprovalPrompt for DesktopPrompt<R> {
    fn prompt(&mut self, view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError> {
        self.run_with_timeout(view, self.timeout)
    }

    fn prompt_with_timeout(
        &mut self,
        view: &WysiwysPromptView,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, PromptError> {
        self.run_with_timeout(view, timeout)
    }
}

const fn timeout_secs_ceil(timeout: Duration) -> u64 {
    let secs = timeout.as_secs();
    if timeout.subsec_nanos() > 0 {
        secs.saturating_add(1)
    } else if secs == 0 {
        1
    } else {
        secs
    }
}

fn run_zenity_prompt<R: CommandRunner>(
    runner: &R,
    display: &str,
    timeout_secs: u64,
) -> Result<ApprovalOutcome, PromptError> {
    let timeout_arg = format!("--timeout={timeout_secs}");
    let args = [
        "--question",
        "--no-markup",
        "--no-wrap",
        "--default-cancel",
        timeout_arg.as_str(),
        "--title",
        "Handfest Mandate Approval",
        "--ok-label",
        "Approve & Sign",
        "--cancel-label",
        "Deny",
        "--text",
        display,
    ];
    match runner.run("zenity", &args, &[]) {
        Ok(_) => Ok(ApprovalOutcome::Approved),
        Err(AnchorError::CommandFailed {
            status: Some(1), ..
        }) => Ok(ApprovalOutcome::Denied {
            reason: "operator denied desktop prompt".to_string(),
        }),
        Err(AnchorError::CommandFailed {
            status: Some(5), ..
        }) => Ok(ApprovalOutcome::Denied {
            reason: "desktop prompt timed out".to_string(),
        }),
        Err(err) => Err(PromptError::CommandFailed {
            program: "zenity".to_string(),
            detail: err.to_string(),
        }),
    }
}

fn build_osascript_dialog(timeout_secs: u64) -> String {
    // Only the integer `timeout_secs` is formatted into the script; display text enters strictly
    // via `argv` (`--`, display) and is never interpolated into AppleScript source.
    format!(
        "on run argv\n\
         \x20   set promptText to item 1 of argv\n\
         \x20   set dlg to display dialog promptText with title \"Handfest Mandate Approval\" buttons {{\"Deny\", \"Approve & Sign\"}} default button \"Deny\" cancel button \"Deny\" giving up after {timeout_secs}\n\
         \x20   if gave up of dlg then\n\
         \x20       return \"gave up:true\"\n\
         \x20   end if\n\
         \x20   return \"button returned:\" & (button returned of dlg)\n\
         end run"
    )
}

fn run_osascript_prompt<R: CommandRunner>(
    runner: &R,
    display: &str,
    timeout_secs: u64,
) -> Result<ApprovalOutcome, PromptError> {
    let script = build_osascript_dialog(timeout_secs);
    let args = ["-e", script.as_str(), "--", display];
    match runner.run("osascript", &args, &[]) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let trimmed = stdout.trim();
            if trimmed == "button returned:Approve & Sign" {
                Ok(ApprovalOutcome::Approved)
            } else if trimmed == "gave up:true" {
                Ok(ApprovalOutcome::Denied {
                    reason: "desktop prompt timed out".to_string(),
                })
            } else {
                Ok(ApprovalOutcome::Denied {
                    reason: "operator did not confirm approval in desktop dialog".to_string(),
                })
            }
        }
        Err(AnchorError::CommandFailed {
            status: Some(1),
            stderr,
            ..
        }) if stderr.contains("-128") || stderr.contains("User canceled") => {
            Ok(ApprovalOutcome::Denied {
                reason: "operator denied desktop prompt".to_string(),
            })
        }
        Err(err) => Err(PromptError::CommandFailed {
            program: "osascript".to_string(),
            detail: err.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn build_view(
        signer_hex_char: &str,
        valid_from: i64,
        valid_until: i64,
        anchor_id: &str,
    ) -> WysiwysPromptView {
        let signer = KeyId::new("ed25519", signer_hex_char.repeat(64)).unwrap();
        let agent = KeyId::new("ed25519", "2".repeat(64)).unwrap();
        let draft = format!(
            "HANDFEST v1\nFROM human \"Valentin\" (key: {signer})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n"
        );
        let ast = parse_mandate(&draft).unwrap();
        let canonical = try_render_canonical(&ast).unwrap();
        let id = ast.try_mandate_id().unwrap();
        WysiwysPromptView::new(
            canonical,
            id,
            valid_from,
            valid_until,
            signer,
            anchor_id.to_string(),
        )
        .unwrap()
    }

    #[test]
    fn tty_prompt_accepts_exact_yes_and_rejects_other_replies() {
        let view = build_view("1", 1_760_000_000, 1_760_003_600, "local-ed25519");

        let mut out_ok = Vec::new();
        let mut p_ok = TtyPrompt::new(Cursor::new(b"yes\n".as_slice()), &mut out_ok);
        assert_eq!(p_ok.prompt(&view), Ok(ApprovalOutcome::Approved));

        for bad in [b"y\n".as_slice(), b"YES\n", b"yes \n", b"no\n", b"\n"] {
            let mut out = Vec::new();
            let mut prompt = TtyPrompt::new(Cursor::new(bad), &mut out);
            assert!(matches!(
                prompt.prompt(&view),
                Ok(ApprovalOutcome::Denied { .. })
            ));
        }
    }
}
