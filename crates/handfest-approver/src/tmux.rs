//! `tmux` popup approval backend (`TmuxPrompt`), internal pure-Rust popup helper, and
//! per-request auto-selector (`AutoPrompt`).

use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use handfest_anchors::{AnchorError, SystemCommandRunner};

#[path = "tmux_popup.rs"]
mod popup;

pub use self::popup::{
    run_internal_popup_prompt, BoundedCommandOutcome, BoundedCommandRunner, InternalPopupOutcome,
};
use self::popup::{timeout_ms_floor, write_private_file};
use crate::prompt::{
    run_desktop_prompt, ApprovalOutcome, ApprovalPrompt, DesktopBackend, PromptError,
    WysiwysPromptView, DEFAULT_DESKTOP_TIMEOUT_SECS,
};
use crate::protocol::is_forbidden_wysiwys_char;

/// Default `tmux` popup timeout in seconds when no per-request timeout is supplied.
pub const DEFAULT_TMUX_TIMEOUT_SECS: u64 = DEFAULT_DESKTOP_TIMEOUT_SECS;

/// Maximum bytes accepted when reading the private popup result file.
const MAX_RESULT_FILE_BYTES: u64 = 64;

/// Maximum retry attempts when creating a unique private temporary directory.
const MAX_TEMP_DIR_ATTEMPTS: usize = 64;

/// Bounded timeout for best-effort `tmux display-popup -C -c <client>` cleanup after a timeout.
const TMUX_POPUP_DISMISS_TIMEOUT: Duration = Duration::from_millis(250);

/// `tmux list-clients -F` format string capturing control-mode, read-only, activity timestamp,
/// and client name separated by literal tabs.
const TMUX_LIST_CLIENTS_FORMAT: &str =
    "#{client_control_mode}\t#{client_readonly}\t#{client_activity}\t#{client_name}";

/// Monotonic counter used to disambiguate private temp directories created within the same tick.
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII private `0700` temporary directory cleaned up automatically on drop.
struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    fn create() -> Result<Self, PromptError> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for _ in 0..MAX_TEMP_DIR_ATTEMPTS {
            let seq = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let candidate = base.join(format!("handfest-tmux-{pid}-{seq}-{nanos}"));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&candidate) {
                Ok(()) => {
                    #[cfg(unix)]
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).map_err(
                        |err| {
                            let _ = fs::remove_dir_all(&candidate);
                            PromptError::Io(format!(
                                "failed to set 0700 permissions on tmux temp dir: {err}"
                            ))
                        },
                    )?;
                    return Ok(Self { path: candidate });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(PromptError::Io(format!(
                        "failed to create private tmux temp dir: {err}"
                    )));
                }
            }
        }
        Err(PromptError::Io(
            "failed to allocate unique private tmux temp dir after retries".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn validate_tmux_client_name(raw: &str) -> Result<String, PromptError> {
    if raw.is_empty() || raw.trim().is_empty() {
        return Err(PromptError::CommandFailed {
            program: "tmux".to_string(),
            detail: "no attached tmux client found".to_string(),
        });
    }
    if raw.starts_with('-') {
        return Err(PromptError::CommandFailed {
            program: "tmux".to_string(),
            detail: format!("invalid tmux client name starting with '-': '{raw}'"),
        });
    }
    if let Some(ch) = raw
        .chars()
        .find(|&c| c.is_control() || is_forbidden_wysiwys_char(c))
    {
        return Err(PromptError::CommandFailed {
            program: "tmux".to_string(),
            detail: format!(
                "invalid tmux client name containing forbidden char U+{:04X}",
                u32::from(ch)
            ),
        });
    }
    Ok(raw.to_string())
}

fn parse_tmux_client_list(stdout: &str) -> Result<String, PromptError> {
    if !stdout.is_empty() && !stdout.ends_with('\n') {
        return Err(PromptError::CommandFailed {
            program: "tmux".to_string(),
            detail: "unterminated tmux list-clients output".to_string(),
        });
    }
    let mut best: Option<(u64, String)> = None;
    // Split strictly on `\n` (NOT `.lines()`) so a trailing `\r` in `client_name` is preserved
    // and rejected by `validate_tmux_client_name`.
    for line in stdout.split('\n') {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(4, '\t');
        let (Some(control_mode), Some(readonly), Some(activity_str), Some(client_name)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PromptError::CommandFailed {
                program: "tmux".to_string(),
                detail: "malformed tmux list-clients output".to_string(),
            });
        };
        if control_mode != "0" || readonly != "0" {
            continue;
        }
        let activity = activity_str
            .parse::<u64>()
            .map_err(|_| PromptError::CommandFailed {
                program: "tmux".to_string(),
                detail: format!("invalid tmux client_activity '{activity_str}'"),
            })?;
        let validated_name = validate_tmux_client_name(client_name)?;
        if best
            .as_ref()
            .is_none_or(|(best_activity, _)| activity > *best_activity)
        {
            best = Some((activity, validated_name));
        }
    }
    best.map(|(_, name)| name)
        .ok_or_else(|| PromptError::CommandFailed {
            program: "tmux".to_string(),
            detail: "no attached tmux client found".to_string(),
        })
}

fn find_attached_tmux_client<R: BoundedCommandRunner>(
    runner: &R,
    timeout: Duration,
) -> Result<String, PromptError> {
    let output = match runner.run_bounded(
        "tmux",
        &["list-clients", "-F", TMUX_LIST_CLIENTS_FORMAT],
        timeout,
    ) {
        BoundedCommandOutcome::TimedOut => {
            return Err(PromptError::CommandFailed {
                program: "tmux".to_string(),
                detail: "tmux list-clients timed out".to_string(),
            });
        }
        BoundedCommandOutcome::Completed(Err(err)) => {
            return Err(PromptError::CommandFailed {
                program: "tmux".to_string(),
                detail: err.to_string(),
            });
        }
        BoundedCommandOutcome::Completed(Ok(output)) => output,
    };
    let stdout = String::from_utf8(output.stdout).map_err(|err| PromptError::CommandFailed {
        program: "tmux".to_string(),
        detail: format!("tmux list-clients returned non-UTF-8 output: {err}"),
    })?;
    parse_tmux_client_list(&stdout)
}

fn read_tmux_result(result_path: &Path) -> ApprovalOutcome {
    let Ok(meta) = fs::symlink_metadata(result_path) else {
        return ApprovalOutcome::Denied {
            reason: "tmux approval prompt completed without confirmation".to_string(),
        };
    };
    if !meta.file_type().is_file() || meta.len() > MAX_RESULT_FILE_BYTES {
        return ApprovalOutcome::Denied {
            reason: "tmux approval prompt produced invalid confirmation file".to_string(),
        };
    }
    let Ok(file) = fs::File::open(result_path) else {
        return ApprovalOutcome::Denied {
            reason: "tmux approval prompt confirmation file unreadable".to_string(),
        };
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_RESULT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return ApprovalOutcome::Denied {
            reason: "tmux approval prompt confirmation file read failed".to_string(),
        };
    }
    if bytes == b"approved\n" {
        ApprovalOutcome::Approved
    } else if bytes == b"denied\n" {
        ApprovalOutcome::Denied {
            reason: "operator denied tmux prompt".to_string(),
        }
    } else {
        ApprovalOutcome::Denied {
            reason: "operator did not confirm approval in tmux popup".to_string(),
        }
    }
}

fn resolve_popup_bin(configured: Option<&Path>) -> Result<PathBuf, PromptError> {
    match configured {
        Some(path) => Ok(path.to_path_buf()),
        None => std::env::current_exe().map_err(|err| {
            PromptError::Io(format!(
                "failed to resolve handfest-approver binary path for tmux popup: {err}"
            ))
        }),
    }
}

fn run_tmux_popup_for_client<R: BoundedCommandRunner>(
    runner: &R,
    popup_bin: Option<&Path>,
    client: &str,
    view: &WysiwysPromptView,
    timeout: Duration,
) -> Result<ApprovalOutcome, PromptError> {
    let Some(timeout_ms) = timeout_ms_floor(timeout) else {
        return Ok(ApprovalOutcome::Denied {
            reason: "tmux approval prompt timed out".to_string(),
        });
    };
    let resolved_bin = resolve_popup_bin(popup_bin)?;
    let popup_bin_str = resolved_bin
        .to_str()
        .ok_or_else(|| PromptError::Io("tmux popup binary path is not valid UTF-8".to_string()))?;

    let temp_dir = PrivateTempDir::create()?;
    let display_path = temp_dir.path().join("display.txt");
    let result_path = temp_dir.path().join("result.txt");
    write_private_file(&display_path, "display", &view.format_display())?;

    let display_path_str = display_path
        .to_str()
        .ok_or_else(|| PromptError::Io("tmux display path is not valid UTF-8".to_string()))?;
    let result_path_str = result_path
        .to_str()
        .ok_or_else(|| PromptError::Io("tmux result path is not valid UTF-8".to_string()))?;
    let timeout_ms_str = timeout_ms.to_string();

    let args = [
        "display-popup",
        "-c",
        client,
        "-E",
        "-w",
        "85%",
        "-h",
        "70%",
        "-T",
        "Handfest Mandate Approval",
        "--",
        popup_bin_str,
        "--internal-popup-prompt",
        "--display-file",
        display_path_str,
        "--result-file",
        result_path_str,
        "--timeout-ms",
        timeout_ms_str.as_str(),
    ];

    match runner.run_bounded("tmux", &args, timeout) {
        BoundedCommandOutcome::TimedOut => {
            // Dismiss any lingering server-side popup left open when the CLI client was killed.
            let _ = runner.run_bounded(
                "tmux",
                &["display-popup", "-C", "-c", client],
                TMUX_POPUP_DISMISS_TIMEOUT,
            );
            Ok(ApprovalOutcome::Denied {
                reason: "tmux approval prompt timed out".to_string(),
            })
        }
        BoundedCommandOutcome::Completed(Ok(_)) => Ok(read_tmux_result(&result_path)),
        BoundedCommandOutcome::Completed(Err(AnchorError::CommandFailed {
            status: Some(143),
            stderr,
            ..
        })) if stderr.is_empty() => Ok(ApprovalOutcome::Denied {
            reason: "tmux approval prompt timed out".to_string(),
        }),
        BoundedCommandOutcome::Completed(Err(AnchorError::CommandFailed {
            status: Some(_),
            stderr,
            ..
        })) if stderr.is_empty() => Ok(ApprovalOutcome::Denied {
            reason: "tmux approval prompt cancelled or exited without approval".to_string(),
        }),
        BoundedCommandOutcome::Completed(Err(err)) => Err(PromptError::CommandFailed {
            program: "tmux".to_string(),
            detail: err.to_string(),
        }),
    }
}

/// `tmux display-popup` WYSIWYS approval prompt backed by a pluggable [`CommandRunner`].
///
/// Discovers the most recently active interactive attached `tmux` client per request, writes the
/// canonical WYSIWYS view to a private `0600` file inside a `0700` temporary directory, and floats
/// a bounded-timeout popup running `handfest-approver --internal-popup-prompt` without ever
/// invoking a shell or interpolating mandate text into argv.
#[derive(Debug, Clone)]
pub struct TmuxPrompt<R: BoundedCommandRunner = SystemCommandRunner> {
    runner: R,
    timeout: Duration,
    popup_bin: Option<PathBuf>,
}

impl TmuxPrompt<SystemCommandRunner> {
    /// Constructs a `tmux` prompt using [`SystemCommandRunner`].
    #[must_use]
    pub const fn system() -> Self {
        Self::new(SystemCommandRunner)
    }
}

impl<R: BoundedCommandRunner> TmuxPrompt<R> {
    /// Constructs a `tmux` prompt backed by a custom [`CommandRunner`].
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self {
            runner,
            timeout: Duration::from_secs(DEFAULT_TMUX_TIMEOUT_SECS),
            popup_bin: None,
        }
    }

    /// Overrides the default popup timeout used by [`ApprovalPrompt::prompt`].
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the binary path invoked inside `tmux display-popup` (defaults to
    /// `std::env::current_exe()`).
    #[must_use]
    pub fn with_popup_bin(mut self, popup_bin: PathBuf) -> Self {
        self.popup_bin = Some(popup_bin);
        self
    }

    fn run_with_timeout(
        &self,
        view: &WysiwysPromptView,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, PromptError> {
        let deadline = Instant::now().checked_add(timeout);
        let client = find_attached_tmux_client(&self.runner, timeout)?;
        let remaining = deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
        run_tmux_popup_for_client(
            &self.runner,
            self.popup_bin.as_deref(),
            &client,
            view,
            remaining,
        )
    }
}

impl<R: BoundedCommandRunner> ApprovalPrompt for TmuxPrompt<R> {
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

/// Pluggable seam for detecting whether a local desktop GUI display is available.
pub trait DisplayDetector {
    fn has_desktop_display(&self) -> bool;
}

/// Production [`DisplayDetector`] checking macOS or non-empty `DISPLAY` / `WAYLAND_DISPLAY`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDisplayDetector;

impl DisplayDetector for SystemDisplayDetector {
    fn has_desktop_display(&self) -> bool {
        has_desktop_display_with(cfg!(target_os = "macos"), |name| std::env::var_os(name))
    }
}

pub(crate) fn has_desktop_display_with<F>(is_macos: bool, mut lookup_env: F) -> bool
where
    F: FnMut(&str) -> Option<OsString>,
{
    if is_macos {
        return true;
    }
    env_var_non_empty(&mut lookup_env, "DISPLAY")
        || env_var_non_empty(&mut lookup_env, "WAYLAND_DISPLAY")
}

fn env_var_non_empty<F>(lookup_env: &mut F, name: &str) -> bool
where
    F: FnMut(&str) -> Option<OsString>,
{
    lookup_env(name).is_some_and(|val| !val.is_empty())
}

/// Per-request automatic approval prompt selecting native desktop dialogs or `tmux` popups.
///
/// Detection runs on every approval request so a long-lived background daemon (e.g. under
/// `systemd --user`) automatically discovers a `tmux` session attached later over SSH:
/// 1. Desktop GUI present (`DisplayDetector::has_desktop_display`) -> native desktop modal.
/// 2. Headless / SSH with an active attached interactive `tmux` client -> `tmux display-popup`.
/// 3. Neither available -> fail closed with an actionable [`PromptError::CommandFailed`].
#[derive(Debug, Clone)]
pub struct AutoPrompt<
    R: BoundedCommandRunner = SystemCommandRunner,
    D: DisplayDetector = SystemDisplayDetector,
> {
    runner: R,
    detector: D,
    desktop_backend: DesktopBackend,
    timeout: Duration,
    popup_bin: Option<PathBuf>,
}

impl AutoPrompt<SystemCommandRunner, SystemDisplayDetector> {
    /// Constructs an [`AutoPrompt`] using the host OS runner, display detector, and desktop backend.
    #[must_use]
    pub const fn system() -> Self {
        Self::with_backend(
            SystemCommandRunner,
            SystemDisplayDetector,
            DesktopBackend::platform_default(),
        )
    }
}

impl<R: BoundedCommandRunner, D: DisplayDetector> AutoPrompt<R, D> {
    /// Constructs an [`AutoPrompt`] with an explicit [`DesktopBackend`].
    #[must_use]
    pub const fn with_backend(runner: R, detector: D, desktop_backend: DesktopBackend) -> Self {
        Self {
            runner,
            detector,
            desktop_backend,
            timeout: Duration::from_secs(DEFAULT_DESKTOP_TIMEOUT_SECS),
            popup_bin: None,
        }
    }

    /// Overrides the default approval timeout used by [`ApprovalPrompt::prompt`].
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the binary path invoked inside `tmux display-popup`.
    #[must_use]
    pub fn with_popup_bin(mut self, popup_bin: PathBuf) -> Self {
        self.popup_bin = Some(popup_bin);
        self
    }

    fn run_with_timeout(
        &self,
        view: &WysiwysPromptView,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, PromptError> {
        if self.detector.has_desktop_display() {
            return run_desktop_prompt(&self.runner, self.desktop_backend, view, timeout);
        }
        let deadline = Instant::now().checked_add(timeout);
        if let Ok(client) = find_attached_tmux_client(&self.runner, timeout) {
            let remaining =
                deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
            return run_tmux_popup_for_client(
                &self.runner,
                self.popup_bin.as_deref(),
                &client,
                view,
                remaining,
            );
        }
        Err(PromptError::CommandFailed {
            program: "auto".to_string(),
            detail: "no GUI display or attached tmux session detected; re-run with --prompt tty or start inside tmux".to_string(),
        })
    }
}

impl<R: BoundedCommandRunner, D: DisplayDetector> ApprovalPrompt for AutoPrompt<R, D> {
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

#[cfg(test)]
#[path = "tmux_tests.rs"]
mod tests;
