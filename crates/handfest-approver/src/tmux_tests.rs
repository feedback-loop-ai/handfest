//! Unit tests for `tmux.rs` helpers, bounded subprocess termination/reaping,
//! bounded display file reads, and canonical-PTY multi-line paste rejection.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Cursor};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use handfest_anchors::{CommandOutput, CommandRunner};
use handfest_core::ast::KeyId;
use handfest_core::cnl::{parse_mandate, try_render_canonical};

use super::popup::{
    read_display_bounded, read_display_file, read_popup_approval_reply, run_popup_prompt_with_io,
    timeout_ms_floor, wait_for_trailing_popup_input, write_private_file, PopupStdinEvent,
    MAX_DISPLAY_FILE_BYTES,
};
use super::*;

struct ChunkedReader {
    chunks: VecDeque<Vec<u8>>,
    block_on_empty: Option<mpsc::Receiver<()>>,
}

impl ChunkedReader {
    fn from_chunks(chunks: &[&[u8]]) -> Self {
        Self {
            chunks: chunks.iter().map(|c| c.to_vec()).collect(),
            block_on_empty: None,
        }
    }

    fn blocking_after(chunks: &[&[u8]], release: mpsc::Receiver<()>) -> Self {
        Self {
            chunks: chunks.iter().map(|c| c.to_vec()).collect(),
            block_on_empty: Some(release),
        }
    }
}

impl Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(chunk) = self.chunks.pop_front() {
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n < chunk.len() {
                self.chunks.push_front(chunk[n..].to_vec());
            }
            return Ok(n);
        }
        if let Some(ref rx) = self.block_on_empty {
            let _ = rx.recv_timeout(Duration::from_secs(5));
        }
        Ok(0)
    }
}

#[test]
fn has_desktop_display_with_covers_display_wayland_empty_unset_and_macos() {
    let lookup = |display: Option<&str>, wayland: Option<&str>| {
        let display = display.map(OsString::from);
        let wayland = wayland.map(OsString::from);
        move |name: &str| match name {
            "DISPLAY" => display.clone(),
            "WAYLAND_DISPLAY" => wayland.clone(),
            _ => None,
        }
    };

    assert!(!has_desktop_display_with(false, lookup(None, None)));
    assert!(!has_desktop_display_with(false, lookup(Some(""), None)));
    assert!(!has_desktop_display_with(false, lookup(Some(""), Some(""))));
    assert!(has_desktop_display_with(false, lookup(Some(":0"), None)));
    assert!(has_desktop_display_with(
        false,
        lookup(None, Some("wayland-0"))
    ));
    assert!(has_desktop_display_with(
        false,
        lookup(Some(""), Some("wayland-0"))
    ));
    assert!(has_desktop_display_with(true, lookup(None, None)));

    let expected_host =
        has_desktop_display_with(cfg!(target_os = "macos"), |name| std::env::var_os(name));
    assert_eq!(SystemDisplayDetector.has_desktop_display(), expected_host);
}

#[test]
fn parse_tmux_client_list_filters_control_readonly_rejects_cr_and_picks_most_recent() {
    let sample = "\
        1\t0\t9999\t/dev/pts/1\n\
        0\t1\t8888\t/dev/pts/2\n\
        0\t0\t1000\t/dev/pts/3\n\
        0\t0\t2500\t/dev/pts/4\n\
        0\t0\t1500\t/dev/pts/5\n";
    assert_eq!(
        parse_tmux_client_list(sample).unwrap(),
        "/dev/pts/4".to_string()
    );

    let cr_err = parse_tmux_client_list("0\t0\t100\t/dev/pts/9\r\n").unwrap_err();
    assert!(matches!(
        cr_err,
        PromptError::CommandFailed { ref program, ref detail }
            if program == "tmux" && detail.contains("U+000D")
    ));

    let non_interactive = "1\t0\t100\t/dev/pts/1\n0\t1\t200\t/dev/pts/2\n";
    let none_err = parse_tmux_client_list(non_interactive).unwrap_err();
    assert!(matches!(
        none_err,
        PromptError::CommandFailed { ref program, ref detail }
            if program == "tmux" && detail.contains("no attached tmux client")
    ));

    assert!(matches!(
        parse_tmux_client_list("0\t0\tnotanumber\t/dev/pts/1\n"),
        Err(PromptError::CommandFailed { ref program, ref detail })
            if program == "tmux" && detail.contains("client_activity")
    ));
    assert!(matches!(
        parse_tmux_client_list("malformed-line-without-tabs\n"),
        Err(PromptError::CommandFailed { ref program, ref detail })
            if program == "tmux" && detail.contains("malformed")
    ));
}

#[test]
fn read_display_file_fails_closed_on_missing_directory_empty_oversized_and_invalid_utf8() {
    let temp = PrivateTempDir::create().unwrap();
    let missing = temp.path().join("missing.txt");
    assert!(matches!(
        read_display_file(&missing),
        Err(PromptError::Io(msg)) if msg.contains("stat")
    ));

    assert!(matches!(
        read_display_file(temp.path()),
        Err(PromptError::Io(msg)) if msg.contains("regular file")
    ));

    let empty = temp.path().join("empty.txt");
    write_private_file(&empty, "display", "   \n").unwrap();
    assert!(matches!(
        read_display_file(&empty),
        Err(PromptError::Io(msg)) if msg.contains("empty")
    ));

    // Bounded read rejects any display file exceeding MAX_DISPLAY_FILE_BYTES (1 MiB).
    let oversized = temp.path().join("oversized.txt");
    let over_bytes = vec![b'A'; usize::try_from(MAX_DISPLAY_FILE_BYTES + 1).unwrap()];
    fs::write(&oversized, &over_bytes).unwrap();
    assert!(matches!(
        read_display_file(&oversized),
        Err(PromptError::Io(msg)) if msg.contains("exceeded maximum size")
    ));

    // Exact MAX_DISPLAY_FILE_BYTES succeeds.
    let exact_max = temp.path().join("exact_max.txt");
    let exact_bytes = vec![b'B'; usize::try_from(MAX_DISPLAY_FILE_BYTES).unwrap()];
    fs::write(&exact_max, &exact_bytes).unwrap();
    assert_eq!(
        read_display_file(&exact_max).unwrap().len(),
        usize::try_from(MAX_DISPLAY_FILE_BYTES).unwrap()
    );

    // Invalid UTF-8 fails closed cleanly.
    let bad_utf8 = temp.path().join("bad_utf8.txt");
    fs::write(&bad_utf8, [0xFF, 0xFE, 0xFD]).unwrap();
    assert!(matches!(
        read_display_file(&bad_utf8),
        Err(PromptError::Io(msg)) if msg.contains("UTF-8")
    ));

    #[cfg(unix)]
    {
        let link = temp.path().join("display.link");
        std::os::unix::fs::symlink(&exact_max, &link).unwrap();
        assert!(matches!(
            read_display_file(&link),
            Err(PromptError::Io(msg)) if msg.contains("regular file")
        ));
    }
}

#[test]
fn popup_prompt_rejects_split_read_multiline_paste_and_never_writes_approved() {
    for chunks in [
        &[b"yes\n".as_slice(), b"no\n".as_slice()][..],
        &[b"yes\r\n".as_slice(), b"no\r\n".as_slice()][..],
        &[b"yes\n".as_slice(), b"yes\n".as_slice()][..],
        &[b"yes\n".as_slice(), b"trailing".as_slice()][..],
    ] {
        // Direct reply helper asserts the exact refusal reason.
        let outcome = read_popup_approval_reply(
            BufReader::new(ChunkedReader::from_chunks(chunks)),
            Duration::from_secs(2),
        )
        .expect("read reply");
        assert_eq!(
            outcome,
            Some(ApprovalOutcome::Denied {
                reason: "ambiguous multi-line TTY input rejected".to_string(),
            }),
            "split read {chunks:?} must fail closed"
        );

        // Full popup helper writes "denied\n" and NEVER "approved\n".
        let temp = PrivateTempDir::create().unwrap();
        let display = temp.path().join("display.txt");
        let result = temp.path().join("result.txt");
        write_private_file(&display, "display", "HANDFEST v1\n...").unwrap();
        let mut out = Vec::new();
        let popup_outcome = run_popup_prompt_with_io(
            &display,
            &result,
            Duration::from_secs(2),
            BufReader::new(ChunkedReader::from_chunks(chunks)),
            &mut out,
        )
        .expect("run popup prompt");
        assert_eq!(popup_outcome, InternalPopupOutcome::Denied);
        assert_eq!(fs::read_to_string(&result).unwrap(), "denied\n");
    }
}

#[test]
fn popup_prompt_approves_unambiguous_single_yes_on_eof_or_quiet_tty() {
    let temp = PrivateTempDir::create().unwrap();

    // Case 1: single "yes\n" followed by immediate EOF approves promptly.
    let display1 = temp.path().join("d1.txt");
    let result1 = temp.path().join("r1.txt");
    write_private_file(&display1, "display", "HANDFEST v1\n...").unwrap();
    let mut out1 = Vec::new();
    let outcome1 = run_popup_prompt_with_io(
        &display1,
        &result1,
        Duration::from_secs(2),
        Cursor::new(b"yes\n".to_vec()),
        &mut out1,
    )
    .expect("approve on EOF");
    assert_eq!(outcome1, InternalPopupOutcome::Approved);
    assert_eq!(fs::read_to_string(&result1).unwrap(), "approved\n");

    // Case 2: single "yes\n" on an open blocking TTY with no trailing bytes in 25ms approves.
    let display2 = temp.path().join("d2.txt");
    let result2 = temp.path().join("r2.txt");
    write_private_file(&display2, "display", "HANDFEST v1\n...").unwrap();
    let (release_tx, release_rx) = mpsc::channel();
    let mut out2 = Vec::new();
    let outcome2 = run_popup_prompt_with_io(
        &display2,
        &result2,
        Duration::from_secs(2),
        BufReader::new(ChunkedReader::blocking_after(&[b"yes\n"], release_rx)),
        &mut out2,
    )
    .expect("approve on quiet TTY");
    let _ = release_tx.send(());
    assert_eq!(outcome2, InternalPopupOutcome::Approved);
    assert_eq!(fs::read_to_string(&result2).unwrap(), "approved\n");
}

#[test]
fn timeout_ms_floor_clamps_strictly_within_remaining_and_max_timeout() {
    assert_eq!(timeout_ms_floor(Duration::ZERO), None);
    assert_eq!(timeout_ms_floor(Duration::from_micros(999)), None);
    assert_eq!(timeout_ms_floor(Duration::from_millis(1)), Some(1));
    assert_eq!(
        timeout_ms_floor(Duration::from_millis(1234) + Duration::from_micros(999)),
        Some(1234)
    );
    assert_eq!(
        timeout_ms_floor(crate::MAX_TIMEOUT + Duration::from_secs(500)),
        Some(u64::try_from(crate::MAX_TIMEOUT.as_millis()).unwrap())
    );
}

#[cfg(unix)]
#[test]
fn system_bounded_runner_kills_and_reaps_timed_out_subprocess() {
    let temp = PrivateTempDir::create().unwrap();
    let pid_file = temp.path().join("child.pid");
    let script = format!(
        "printf '%s' \"$$\" > '{}'; exec sleep 30",
        pid_file.display()
    );

    let started = Instant::now();
    let outcome =
        SystemCommandRunner.run_bounded("/bin/sh", &["-c", &script], Duration::from_millis(150));
    let elapsed = started.elapsed();

    assert!(
        matches!(outcome, BoundedCommandOutcome::TimedOut),
        "expected TimedOut, got {outcome:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1000),
        "bounded subprocess exceeded deadline: {elapsed:?}"
    );

    // Wait briefly if needed only to confirm pid file was written, then verify the PID is dead
    // and reaped (NOT running and NOT a zombie).
    if let Ok(pid_str) = fs::read_to_string(&pid_file) {
        let pid = pid_str.trim();
        if !pid.is_empty() {
            let alive = Command::new("kill")
                .args(["-0", pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run kill -0")
                .success();
            assert!(
                !alive,
                "timed-out child process {pid} must be killed and reaped before returning"
            );
        }
    }
}

struct DelayedChunkReader {
    chunks: VecDeque<(Duration, Vec<u8>)>,
    block_on_empty: Option<mpsc::Receiver<()>>,
}

impl DelayedChunkReader {
    fn new(chunks: Vec<(Duration, &[u8])>, release: Option<mpsc::Receiver<()>>) -> Self {
        Self {
            chunks: chunks
                .into_iter()
                .map(|(delay, bytes)| (delay, bytes.to_vec()))
                .collect(),
            block_on_empty: release,
        }
    }
}

impl Read for DelayedChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some((delay, chunk)) = self.chunks.pop_front() {
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n < chunk.len() {
                self.chunks
                    .push_front((Duration::ZERO, chunk[n..].to_vec()));
            }
            return Ok(n);
        }
        if let Some(ref rx) = self.block_on_empty {
            let _ = rx.recv_timeout(Duration::from_secs(5));
        }
        Ok(0)
    }
}

struct PanicOnSecondFillBuf {
    calls: usize,
    first_chunk: &'static [u8],
    pos: usize,
}

impl PanicOnSecondFillBuf {
    fn new(first_chunk: &'static [u8]) -> Self {
        Self {
            calls: 0,
            first_chunk,
            pos: 0,
        }
    }
}

impl Read for PanicOnSecondFillBuf {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl BufRead for PanicOnSecondFillBuf {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.calls += 1;
        if self.calls == 1 {
            Ok(&self.first_chunk[self.pos..])
        } else {
            panic!("simulated stdin reader panic on trailing fill_buf");
        }
    }

    fn consume(&mut self, amt: usize) {
        self.pos = (self.pos + amt).min(self.first_chunk.len());
    }
}

struct CountingReader {
    remaining: u64,
    bytes_read: u64,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let chunk_len = usize::try_from(self.remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        buf[..chunk_len].fill(b'X');
        self.remaining -= chunk_len as u64;
        self.bytes_read += chunk_len as u64;
        Ok(chunk_len)
    }
}

type RecordedBoundedCall = (String, Vec<String>, Duration);

#[derive(Clone)]
struct RecordingTimeoutRunner {
    calls: Arc<Mutex<Vec<RecordedBoundedCall>>>,
    dismiss_outcome: fn() -> BoundedCommandOutcome,
}

impl CommandRunner for RecordingTimeoutRunner {
    fn run(
        &self,
        program: &str,
        _args: &[&str],
        _stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        Err(AnchorError::CommandIo {
            program: program.to_string(),
            detail: "unexpected unbounded run".to_string(),
        })
    }
}

impl BoundedCommandRunner for RecordingTimeoutRunner {
    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> BoundedCommandOutcome {
        self.calls.lock().unwrap().push((
            program.to_string(),
            args.iter().map(|s| (*s).to_string()).collect(),
            timeout,
        ));
        if args.first() == Some(&"list-clients") {
            BoundedCommandOutcome::Completed(Ok(CommandOutput {
                stdout: b"0\t0\t500\t/dev/pts/7\n".to_vec(),
                stderr: Vec::new(),
            }))
        } else if args.contains(&"-C") {
            (self.dismiss_outcome)()
        } else {
            BoundedCommandOutcome::TimedOut
        }
    }
}

fn sample_unit_view() -> WysiwysPromptView {
    let signer = KeyId::new("ed25519", "1".repeat(64)).unwrap();
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
        1_760_000_000,
        1_760_003_600,
        signer,
        "local-ed25519".to_string(),
    )
    .expect("valid prompt view")
}

#[test]
fn popup_prompt_times_out_when_remaining_below_trailing_input_window() {
    // Deterministic case: timeout (15ms) < 25ms trailing-input window, "yes\n" arrives
    // immediately and "no\n" arrives at 17ms. Must NEVER truncate the 25ms window to approve.
    let reader = BufReader::new(DelayedChunkReader::new(
        vec![
            (Duration::ZERO, b"yes\n".as_slice()),
            (Duration::from_millis(17), b"no\n".as_slice()),
        ],
        None,
    ));
    let outcome =
        read_popup_approval_reply(reader, Duration::from_millis(15)).expect("timed out cleanly");
    assert_eq!(
        outcome, None,
        "approval arriving with remaining < 25ms must time out rather than approve"
    );

    // Delayed case: --timeout-ms 15, "yes\n" at 12ms, "no\n" at 17ms via full popup helper.
    let temp = PrivateTempDir::create().unwrap();
    let display = temp.path().join("display.txt");
    let result = temp.path().join("result.txt");
    write_private_file(&display, "display", "HANDFEST v1\n...").unwrap();
    let mut out = Vec::new();
    let popup_outcome = run_popup_prompt_with_io(
        &display,
        &result,
        Duration::from_millis(15),
        BufReader::new(DelayedChunkReader::new(
            vec![
                (Duration::from_millis(12), b"yes\n".as_slice()),
                (Duration::from_millis(5), b"no\n".as_slice()),
            ],
            None,
        )),
        &mut out,
    )
    .expect("popup prompt must time out cleanly");
    assert_eq!(popup_outcome, InternalPopupOutcome::TimedOut);
    assert!(
        !result.exists(),
        "timed-out popup must NEVER write result file"
    );

    // Direct check: wait_for_trailing_popup_input also fails closed if Instant::now() > deadline.
    let (_tx, rx) = mpsc::channel::<PopupStdinEvent>();
    let expired = Instant::now().checked_sub(Duration::from_millis(1));
    assert_eq!(
        wait_for_trailing_popup_input(&rx, Duration::from_millis(1), expired).unwrap(),
        None
    );
}

#[test]
fn popup_prompt_fails_closed_with_io_error_when_stdin_reader_panics_after_yes() {
    let err =
        read_popup_approval_reply(PanicOnSecondFillBuf::new(b"yes\n"), Duration::from_secs(2))
            .expect_err("panicking trailing stdin reader must NEVER approve");
    assert!(
        matches!(err, PromptError::Io(ref msg) if msg.contains("terminated unexpectedly")),
        "expected PromptError::Io on disconnected reader, got {err:?}"
    );

    let temp = PrivateTempDir::create().unwrap();
    let display = temp.path().join("display.txt");
    let result = temp.path().join("result.txt");
    write_private_file(&display, "display", "HANDFEST v1\n...").unwrap();
    let mut out = Vec::new();
    let popup_err = run_popup_prompt_with_io(
        &display,
        &result,
        Duration::from_secs(2),
        PanicOnSecondFillBuf::new(b"yes\n"),
        &mut out,
    )
    .expect_err("popup prompt must fail closed on reader thread panic");
    assert!(
        matches!(popup_err, PromptError::Io(ref msg) if msg.contains("terminated unexpectedly")),
        "expected PromptError::Io, got {popup_err:?}"
    );
    assert!(
        !result.exists(),
        "failed popup must NEVER write result file"
    );
}

#[test]
fn tmux_popup_timeout_issues_dash_c_dismissal_and_ignores_dismiss_errors() {
    let view = sample_unit_view();
    for dismiss_outcome in [
        (|| {
            BoundedCommandOutcome::Completed(Err(AnchorError::CommandFailed {
                program: "tmux".to_string(),
                status: Some(1),
                stderr: "no popup".to_string(),
            }))
        }) as fn() -> BoundedCommandOutcome,
        || BoundedCommandOutcome::TimedOut,
    ] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let runner = RecordingTimeoutRunner {
            calls: Arc::clone(&calls),
            dismiss_outcome,
        };
        let mut prompt = TmuxPrompt::new(runner).with_popup_bin(PathBuf::from("/bin/true"));
        let outcome = prompt
            .prompt_with_timeout(&view, Duration::from_secs(2))
            .expect("timed-out popup denies cleanly even when -C dismiss fails");
        assert_eq!(
            outcome,
            ApprovalOutcome::Denied {
                reason: "tmux approval prompt timed out".to_string(),
            }
        );

        let recorded = calls.lock().unwrap();
        assert_eq!(
            recorded.len(),
            3,
            "expected list-clients, popup, and -C dismiss"
        );
        assert_eq!(recorded[2].0, "tmux");
        assert_eq!(
            recorded[2].1,
            vec!["display-popup", "-C", "-c", "/dev/pts/7"]
        );
        assert_eq!(recorded[2].2, TMUX_POPUP_DISMISS_TIMEOUT);
    }
}

#[test]
fn read_display_bounded_stops_at_max_bytes_plus_one() {
    let mut reader = CountingReader {
        remaining: MAX_DISPLAY_FILE_BYTES + 65_536,
        bytes_read: 0,
    };
    let err = read_display_bounded(&mut reader).unwrap_err();
    assert!(
        matches!(err, PromptError::Io(ref msg) if msg.contains("exceeded maximum size")),
        "expected oversized error, got {err:?}"
    );
    assert_eq!(
        reader.bytes_read,
        MAX_DISPLAY_FILE_BYTES + 1,
        "bounded display reader must stop after reading at most MAX_DISPLAY_FILE_BYTES + 1 bytes"
    );
}

#[cfg(unix)]
#[test]
fn system_bounded_runner_times_out_when_descendant_holds_pipes_open() {
    let started = Instant::now();
    let outcome = SystemCommandRunner.run_bounded(
        "/bin/sh",
        &["-c", "sleep 5 & exit 0"],
        Duration::from_millis(100),
    );
    let elapsed = started.elapsed();

    assert!(
        matches!(outcome, BoundedCommandOutcome::TimedOut),
        "expected TimedOut when background descendant holds pipes open, got {outcome:?}"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "pipe reader wait must be bounded by deadline instead of blocking 5s, took {elapsed:?}"
    );
}
