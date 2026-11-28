//! Unit and integration tests for `TmuxPrompt`, internal popup helper, and `AutoPrompt`.

use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use handfest_anchors::{AnchorError, CommandOutput, CommandRunner, Ed25519Keypair};
use handfest_approver::prompt::{
    ApprovalOutcome, ApprovalPrompt, AutoPrompt, BoundedCommandOutcome, BoundedCommandRunner,
    DesktopBackend, DisplayDetector, PromptError, TmuxPrompt, WysiwysPromptView,
};
use handfest_core::ast::KeyId;
use handfest_core::cnl::{parse_mandate, try_render_canonical};

const LIST_CLIENTS_FORMAT: &str =
    "#{client_control_mode}\t#{client_readonly}\t#{client_activity}\t#{client_name}";

fn approver_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_handfest-approver"))
}

fn sample_view(signer: &Ed25519Keypair) -> WysiwysPromptView {
    let agent = KeyId::new("ed25519", "2".repeat(64)).unwrap();
    let draft = format!(
        "HANDFEST v1\nFROM human \"Valentin\" (key: {})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n",
        signer.key_id()
    );
    let ast = parse_mandate(&draft).unwrap();
    let canonical = try_render_canonical(&ast).unwrap();
    let id = ast.try_mandate_id().unwrap();
    WysiwysPromptView::new(
        canonical,
        id,
        1_760_000_000,
        1_760_003_600,
        signer.key_id(),
        "local-ed25519".to_string(),
    )
    .expect("valid prompt view")
}

type RunnerHook = Box<dyn FnMut(&str, &[&str]) -> Result<CommandOutput, AnchorError> + Send>;
type RecordedCall = (String, Vec<String>);

#[derive(Clone)]
struct ScriptedRunner {
    calls: Arc<Mutex<Vec<RecordedCall>>>,
    steps: Arc<Mutex<VecDeque<RunnerHook>>>,
}

impl ScriptedRunner {
    fn new(steps: Vec<RunnerHook>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            steps: Arc::new(Mutex::new(steps.into())),
        }
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for ScriptedRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        _stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        self.calls.lock().unwrap().push((
            program.to_string(),
            args.iter().map(|a| (*a).to_string()).collect(),
        ));
        let mut hook = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("ScriptedRunner ran out of scripted steps");
        hook(program, args)
    }
}

impl BoundedCommandRunner for ScriptedRunner {
    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> BoundedCommandOutcome {
        if timeout.is_zero() {
            return BoundedCommandOutcome::TimedOut;
        }
        let runner = self.clone();
        let owned_program = program.to_string();
        let owned_args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        let (tx, rx) = mpsc::channel();
        let _worker = std::thread::spawn(move || {
            let arg_refs: Vec<&str> = owned_args.iter().map(String::as_str).collect();
            let outcome = runner.run(&owned_program, &arg_refs, &[]);
            let _ = tx.send(outcome);
        });
        match rx.recv_timeout(timeout) {
            Ok(res) => BoundedCommandOutcome::Completed(res),
            Err(mpsc::RecvTimeoutError::Timeout) => BoundedCommandOutcome::TimedOut,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                BoundedCommandOutcome::Completed(Err(AnchorError::CommandIo {
                    program: program.to_string(),
                    detail: "mock bounded worker terminated unexpectedly".to_string(),
                }))
            }
        }
    }
}

fn list_clients_step(stdout: &'static str) -> RunnerHook {
    Box::new(move |program, args| {
        assert_eq!(program, "tmux");
        assert_eq!(args, ["list-clients", "-F", LIST_CLIENTS_FORMAT]);
        Ok(CommandOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    })
}

fn popup_step_write_result(
    expected_client: &'static str,
    expected_display: String,
    result_bytes: Option<&'static [u8]>,
    exit_result: Result<(), AnchorError>,
    captured_dir: Option<Arc<Mutex<Option<PathBuf>>>>,
) -> RunnerHook {
    Box::new(move |program, args| {
        assert_eq!(program, "tmux");
        assert_eq!(args[0], "display-popup");
        assert_eq!(args[1], "-c");
        assert_eq!(args[2], expected_client);
        assert_eq!(args[3], "-E");
        assert!(args.contains(&"-T"));
        assert!(args.contains(&"Handfest Mandate Approval"));
        let sep_pos = args.iter().position(|&a| a == "--").expect("missing --");
        assert_ne!(args[sep_pos + 1], "/bin/sh", "must never invoke /bin/sh");
        assert_eq!(args[sep_pos + 2], "--internal-popup-prompt");
        assert_eq!(args[sep_pos + 3], "--display-file");
        assert_eq!(args[sep_pos + 5], "--result-file");
        assert_eq!(args[sep_pos + 7], "--timeout-ms");
        let parsed_ms: u64 = args[sep_pos + 8]
            .parse()
            .expect("--timeout-ms must be a valid u64");
        assert!(parsed_ms >= 1, "--timeout-ms must be >= 1");
        for arg in args {
            assert!(
                !arg.contains("HANDFEST v1"),
                "raw mandate text leaked into argv: {arg:?}"
            );
            assert!(
                !arg.contains(&expected_display),
                "raw display text leaked into argv: {arg:?}"
            );
        }
        let display_path = Path::new(args[sep_pos + 4]);
        let result_path = Path::new(args[sep_pos + 6]);
        let parent_dir = display_path.parent().expect("display file parent dir");
        assert_eq!(Some(parent_dir), result_path.parent());

        let actual_display = fs::read_to_string(display_path).expect("display file readable");
        assert_eq!(actual_display, expected_display);
        #[cfg(unix)]
        {
            let dir_mode = fs::metadata(parent_dir).unwrap().permissions().mode() & 0o777;
            let file_mode = fs::metadata(display_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "temp dir must be 0700");
            assert_eq!(file_mode, 0o600, "display file must be 0600");
        }

        if let Some(ref slot) = captured_dir {
            *slot.lock().unwrap() = Some(parent_dir.to_path_buf());
        }
        if let Some(bytes) = result_bytes {
            fs::write(result_path, bytes).expect("write mock result file");
        }
        exit_result.clone().map(|()| CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    })
}

#[test]
fn tmux_prompt_fails_closed_when_no_attached_client_or_invalid_client() {
    let kp = Ed25519Keypair::from_secret_bytes([0x41; 32]);
    let view = sample_view(&kp);

    for empty_stdout in [
        "",
        "\n\n",
        "1\t0\t500\t/dev/pts/1\n",
        "0\t1\t500\t/dev/pts/2\n",
    ] {
        let runner = ScriptedRunner::new(vec![list_clients_step(empty_stdout)]);
        let mut prompt = TmuxPrompt::new(runner);
        let err = prompt.prompt(&view).unwrap_err();
        assert!(matches!(
            err,
            PromptError::CommandFailed { ref program, ref detail }
                if program == "tmux" && detail.contains("no attached tmux client")
        ));
    }

    for bad_client in [
        "0\t0\t100\t-evil\n",
        "0\t0\t100\t/dev/pts/\x1b[2J0\n",
        "0\t0\t100\t/dev/pts/0\u{202E}\n",
        "0\t0\t100\t/dev/pts/9\r\n",
    ] {
        let runner = ScriptedRunner::new(vec![list_clients_step(bad_client)]);
        let mut prompt = TmuxPrompt::new(runner);
        let err = prompt.prompt(&view).unwrap_err();
        assert!(matches!(
            err,
            PromptError::CommandFailed { ref program, .. } if program == "tmux"
        ));
    }

    let io_fail_runner = ScriptedRunner::new(vec![Box::new(|_, _| {
        Err(AnchorError::CommandIo {
            program: "tmux".to_string(),
            detail: "No such file or directory".to_string(),
        })
    })]);
    let mut io_prompt = TmuxPrompt::new(io_fail_runner);
    assert!(matches!(
        io_prompt.prompt(&view),
        Err(PromptError::CommandFailed { ref program, .. }) if program == "tmux"
    ));

    let non_utf8_runner = ScriptedRunner::new(vec![Box::new(|_, _| {
        Ok(CommandOutput {
            stdout: vec![0xff, 0xfe, b'\n'],
            stderr: Vec::new(),
        })
    })]);
    let mut non_utf8_prompt = TmuxPrompt::new(non_utf8_runner);
    assert!(matches!(
        non_utf8_prompt.prompt(&view),
        Err(PromptError::CommandFailed { ref program, ref detail })
            if program == "tmux" && detail.contains("non-UTF-8")
    ));
}

#[test]
fn tmux_prompt_skips_control_and_readonly_clients_and_selects_most_recent() {
    let kp = Ed25519Keypair::from_secret_bytes([0x46; 32]);
    let view = sample_view(&kp);
    let captured_dir = Arc::new(Mutex::new(None));

    let clients = "\
        1\t0\t1760000999\t/dev/pts/1\n\
        0\t1\t1760000888\t/dev/pts/2\n\
        0\t0\t1760000100\t/dev/pts/3\n\
        0\t0\t1760000500\t/dev/pts/4\n\
        0\t0\t1760000200\t/dev/pts/5\n";

    let runner = ScriptedRunner::new(vec![
        list_clients_step(clients),
        popup_step_write_result(
            "/dev/pts/4",
            view.format_display(),
            Some(b"approved\n"),
            Ok(()),
            Some(Arc::clone(&captured_dir)),
        ),
    ]);
    let mut prompt = TmuxPrompt::new(runner.clone()).with_timeout(Duration::from_secs(30));
    assert_eq!(
        prompt.prompt_with_timeout(&view, Duration::from_millis(250)),
        Ok(ApprovalOutcome::Approved)
    );

    let temp_dir_path = captured_dir
        .lock()
        .unwrap()
        .clone()
        .expect("temp dir captured");
    assert!(
        !temp_dir_path.exists(),
        "private temp dir must be cleaned up on drop"
    );

    let calls = runner.calls();
    assert_eq!(calls.len(), 2);
    let timeout_ms: u64 = calls[1]
        .1
        .last()
        .expect("timeout-ms argument")
        .parse()
        .expect("timeout-ms must be u64");
    assert!(
        (1..=250).contains(&timeout_ms),
        "expected --timeout-ms within 1..=250, got {timeout_ms}"
    );
}

#[test]
fn tmux_prompt_fails_closed_on_missing_empty_denied_yes_and_nonzero_exit() {
    let kp = Ed25519Keypair::from_secret_bytes([0x43; 32]);
    let view = sample_view(&kp);

    type DeniedCase<'a> = (&'a str, Option<&'a [u8]>, Result<(), AnchorError>);
    let denied_cases: &[DeniedCase<'_>] = &[
        ("missing result file", None, Ok(())),
        ("empty result file", Some(b""), Ok(())),
        ("denied result file", Some(b"denied\n"), Ok(())),
        ("yes instead of approved", Some(b"yes\n"), Ok(())),
        ("approved with crlf", Some(b"approved\r\n"), Ok(())),
        (
            "non-zero exit 1 even with approved file",
            Some(b"approved\n"),
            Err(AnchorError::CommandFailed {
                program: "tmux".to_string(),
                status: Some(1),
                stderr: String::new(),
            }),
        ),
        (
            "timeout exit 143",
            None,
            Err(AnchorError::CommandFailed {
                program: "tmux".to_string(),
                status: Some(143),
                stderr: String::new(),
            }),
        ),
    ];

    for (label, bytes, exit_res) in denied_cases {
        let runner = ScriptedRunner::new(vec![
            list_clients_step("0\t0\t100\t/dev/pts/7\n"),
            popup_step_write_result(
                "/dev/pts/7",
                view.format_display(),
                *bytes,
                exit_res.clone(),
                None,
            ),
        ]);
        let mut prompt = TmuxPrompt::new(runner);
        let outcome = prompt
            .prompt(&view)
            .unwrap_or_else(|e| panic!("case '{label}' expected Denied, got Err({e})"));
        assert!(
            matches!(outcome, ApprovalOutcome::Denied { .. }),
            "case '{label}' must deny, got {outcome:?}"
        );
    }
}

#[test]
fn tmux_prompt_fails_closed_on_tmux_stderr_oversized_and_non_file_result() {
    let kp = Ed25519Keypair::from_secret_bytes([0x49; 32]);
    let view = sample_view(&kp);

    let err_runner = ScriptedRunner::new(vec![
        list_clients_step("0\t0\t100\t/dev/pts/7\n"),
        popup_step_write_result(
            "/dev/pts/7",
            view.format_display(),
            None,
            Err(AnchorError::CommandFailed {
                program: "tmux".to_string(),
                status: Some(1),
                stderr: "can't find client: /dev/pts/7".to_string(),
            }),
            None,
        ),
    ]);
    let mut err_prompt = TmuxPrompt::new(err_runner);
    assert!(matches!(
        err_prompt.prompt(&view),
        Err(PromptError::CommandFailed { ref program, ref detail })
            if program == "tmux" && detail.contains("can't find client")
    ));

    let oversized = Box::leak(
        format!("approved\n{}", "x".repeat(100))
            .into_bytes()
            .into_boxed_slice(),
    );
    let oversized_runner = ScriptedRunner::new(vec![
        list_clients_step("0\t0\t100\t/dev/pts/7\n"),
        popup_step_write_result(
            "/dev/pts/7",
            view.format_display(),
            Some(oversized),
            Ok(()),
            None,
        ),
    ]);
    let mut oversized_prompt = TmuxPrompt::new(oversized_runner);
    assert!(matches!(
        oversized_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied { .. })
    ));

    let dir_result_runner = ScriptedRunner::new(vec![
        list_clients_step("0\t0\t100\t/dev/pts/7\n"),
        Box::new(|_, args| {
            let sep = args.iter().position(|&a| a == "--").unwrap();
            fs::create_dir(args[sep + 6]).unwrap();
            Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }),
    ]);
    let mut dir_result_prompt = TmuxPrompt::new(dir_result_runner);
    assert!(matches!(
        dir_result_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied { .. })
    ));
}

#[cfg(unix)]
#[test]
fn tmux_internal_popup_binary_rejects_nul_and_missing_display() {
    let kp = Ed25519Keypair::from_secret_bytes([0x44; 32]);
    let view = sample_view(&kp);

    let run_real_popup = |stdin_bytes: &'static [u8],
                          remove_display: bool|
     -> Result<ApprovalOutcome, PromptError> {
        let runner = ScriptedRunner::new(vec![
            list_clients_step("0\t0\t500\t/dev/pts/9\n"),
            Box::new(move |program, args| {
                assert_eq!(program, "tmux");
                let sep = args.iter().position(|&a| a == "--").unwrap();
                if remove_display {
                    fs::remove_file(args[sep + 4]).expect("remove display file");
                }
                let mut child = Command::new(args[sep + 1])
                    .args(&args[sep + 2..])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn handfest-approver --internal-popup-prompt");
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(stdin_bytes)
                    .expect("write stdin");
                let out = child.wait_with_output().expect("wait internal popup");
                if remove_display {
                    assert!(
                        !out.status.success(),
                        "missing display file must exit non-zero"
                    );
                    assert!(
                        out.stdout.is_empty(),
                        "missing display file must NEVER print prompt"
                    );
                    assert!(
                        !Path::new(args[sep + 6]).exists(),
                        "missing display file must NEVER create result file"
                    );
                } else {
                    assert!(String::from_utf8_lossy(&out.stdout).contains("HANDFEST v1"));
                }
                if out.status.success() {
                    Ok(CommandOutput {
                        stdout: out.stdout,
                        stderr: out.stderr,
                    })
                } else {
                    Err(AnchorError::CommandFailed {
                        program: "tmux".to_string(),
                        status: out.status.code(),
                        stderr: String::new(),
                    })
                }
            }),
        ]);
        let mut prompt = TmuxPrompt::new(runner).with_popup_bin(approver_bin());
        prompt.prompt_with_timeout(&view, Duration::from_secs(5))
    };

    assert_eq!(
        run_real_popup(b"yes\n", false),
        Ok(ApprovalOutcome::Approved)
    );
    assert_eq!(
        run_real_popup(b"yes\r\n", false),
        Ok(ApprovalOutcome::Approved)
    );

    for bad_input in [
        b"y\x00es\n".as_slice(),
        b"yes\x00\n",
        b"no\n",
        b"YES\n",
        b"yes",
        b"",
        b"\n",
        b"yes\nno\n",
    ] {
        assert!(
            matches!(
                run_real_popup(bad_input, false),
                Ok(ApprovalOutcome::Denied { .. })
            ),
            "stdin {bad_input:?} must deny"
        );
    }

    // Missing display file MUST fail closed even if stdin supplies "yes\n".
    assert!(matches!(
        run_real_popup(b"yes\n", true),
        Ok(ApprovalOutcome::Denied { .. })
    ));
}

#[cfg(unix)]
#[test]
fn tmux_internal_popup_binary_enforces_timeout() {
    let kp = Ed25519Keypair::from_secret_bytes([0x48; 32]);
    let view = sample_view(&kp);
    let timeout_runner = ScriptedRunner::new(vec![
        list_clients_step("0\t0\t500\t/dev/pts/9\n"),
        Box::new(|_, args| {
            let sep = args.iter().position(|&a| a == "--").unwrap();
            let mut child = Command::new(args[sep + 1])
                .args(&args[sep + 2..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn handfest-approver --internal-popup-prompt");
            let _held_stdin = child.stdin.take();
            let out = child.wait_with_output().expect("wait timed out popup");
            assert_eq!(out.status.code(), Some(143));
            Err(AnchorError::CommandFailed {
                program: "tmux".to_string(),
                status: out.status.code(),
                stderr: String::new(),
            })
        }),
    ]);
    let mut timeout_prompt = TmuxPrompt::new(timeout_runner).with_popup_bin(approver_bin());
    assert_eq!(
        timeout_prompt.prompt_with_timeout(&view, Duration::from_secs(1)),
        Ok(ApprovalOutcome::Denied {
            reason: "tmux approval prompt timed out".to_string(),
        })
    );
}

#[test]
fn tmux_prompt_enforces_caller_side_deadline_on_hung_list_clients_and_popup() {
    let kp = Ed25519Keypair::from_secret_bytes([0x47; 32]);
    let view = sample_view(&kp);

    let (release_list_tx, release_list_rx) = mpsc::channel::<()>();
    let hung_list_runner = ScriptedRunner::new(vec![Box::new(move |_, _| {
        let _ = release_list_rx.recv_timeout(Duration::from_secs(5));
        Ok(CommandOutput {
            stdout: b"0\t0\t100\t/dev/pts/1\n".to_vec(),
            stderr: Vec::new(),
        })
    })]);
    let mut hung_list_prompt = TmuxPrompt::new(hung_list_runner);
    let started = Instant::now();
    let err = hung_list_prompt
        .prompt_with_timeout(&view, Duration::from_millis(120))
        .unwrap_err();
    let elapsed = started.elapsed();
    let _ = release_list_tx.send(());
    assert!(matches!(
        err,
        PromptError::CommandFailed { ref program, ref detail }
            if program == "tmux" && detail.contains("timed out")
    ));
    assert!(
        elapsed < Duration::from_millis(800),
        "hung list-clients exceeded caller deadline: {elapsed:?}"
    );

    let (release_popup_tx, release_popup_rx) = mpsc::channel::<()>();
    let hung_popup_runner = ScriptedRunner::new(vec![
        list_clients_step("0\t0\t100\t/dev/pts/1\n"),
        Box::new(move |_, _| {
            let _ = release_popup_rx.recv_timeout(Duration::from_secs(5));
            Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }),
        Box::new(|program, args| {
            assert_eq!(program, "tmux");
            assert_eq!(args, &["display-popup", "-C", "-c", "/dev/pts/1"]);
            Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }),
    ]);
    let recorded_runner = hung_popup_runner.clone();
    let mut hung_popup_prompt = TmuxPrompt::new(hung_popup_runner);
    let started = Instant::now();
    let outcome = hung_popup_prompt
        .prompt_with_timeout(&view, Duration::from_millis(120))
        .expect("hung popup should deny on timeout");
    let elapsed = started.elapsed();
    let _ = release_popup_tx.send(());
    assert_eq!(
        outcome,
        ApprovalOutcome::Denied {
            reason: "tmux approval prompt timed out".to_string(),
        }
    );
    assert!(
        elapsed < Duration::from_millis(800),
        "hung display-popup exceeded caller deadline: {elapsed:?}"
    );
    let calls = recorded_runner.calls();
    assert_eq!(
        calls.len(),
        3,
        "expected list-clients, popup, and -C dismiss"
    );
    assert_eq!(
        calls[2],
        (
            "tmux".to_string(),
            vec![
                "display-popup".to_string(),
                "-C".to_string(),
                "-c".to_string(),
                "/dev/pts/1".to_string(),
            ]
        )
    );
}

struct ToggleDisplayDetector {
    has_display: Cell<bool>,
}

impl DisplayDetector for &ToggleDisplayDetector {
    fn has_desktop_display(&self) -> bool {
        self.has_display.get()
    }
}

#[test]
fn auto_prompt_covers_all_three_branches_and_re_evaluates_per_request() {
    let kp = Ed25519Keypair::from_secret_bytes([0x45; 32]);
    let view = sample_view(&kp);
    let detector = ToggleDisplayDetector {
        has_display: Cell::new(false),
    };

    let runner = ScriptedRunner::new(vec![
        Box::new(|program, args| {
            assert_eq!(program, "tmux");
            assert_eq!(args, ["list-clients", "-F", LIST_CLIENTS_FORMAT]);
            Err(AnchorError::CommandFailed {
                program: "tmux".to_string(),
                status: Some(1),
                stderr: "no server running".to_string(),
            })
        }),
        list_clients_step("0\t0\t100\t/dev/pts/1\n"),
        popup_step_write_result(
            "/dev/pts/1",
            view.format_display(),
            Some(b"approved\n"),
            Ok(()),
            None,
        ),
        Box::new(|program, args| {
            assert_eq!(program, "zenity");
            assert!(args.contains(&"--question"));
            assert!(args.contains(&"--timeout=20"));
            Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }),
    ]);

    let mut auto = AutoPrompt::with_backend(runner.clone(), &detector, DesktopBackend::Zenity)
        .with_timeout(Duration::from_secs(20))
        .with_popup_bin(approver_bin());

    let err = auto.prompt(&view).unwrap_err();
    assert!(matches!(
        err,
        PromptError::CommandFailed { ref program, ref detail }
            if program == "auto"
                && detail.contains("no GUI display or attached tmux session detected")
                && detail.contains("--prompt tty")
    ));

    assert_eq!(
        auto.prompt_with_timeout(&view, Duration::from_secs(12)),
        Ok(ApprovalOutcome::Approved)
    );

    detector.has_display.set(true);
    assert_eq!(auto.prompt(&view), Ok(ApprovalOutcome::Approved));

    let calls = runner.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].0, "tmux");
    assert_eq!(calls[1].0, "tmux");
    assert_eq!(calls[2].0, "tmux");
    assert_eq!(calls[3].0, "zenity");
}

#[cfg(unix)]
#[test]
fn tmux_prompt_passes_millisecond_timeout_never_exceeding_remaining_budget() {
    let kp = Ed25519Keypair::from_secret_bytes([0x49; 32]);
    let view = sample_view(&kp);
    let observed_ms = Arc::new(Mutex::new(None::<u64>));
    let observed_clone = Arc::clone(&observed_ms);

    let runner = ScriptedRunner::new(vec![
        Box::new(|program, args| {
            assert_eq!(program, "tmux");
            assert_eq!(args, ["list-clients", "-F", LIST_CLIENTS_FORMAT]);
            // Burn ~60ms in list-clients so remaining budget is strictly < 1500ms.
            std::thread::sleep(Duration::from_millis(60));
            Ok(CommandOutput {
                stdout: b"0\t0\t500\t/dev/pts/3\n".to_vec(),
                stderr: Vec::new(),
            })
        }),
        Box::new(move |program, args| {
            assert_eq!(program, "tmux");
            let sep = args.iter().position(|&a| a == "--").unwrap();
            assert_eq!(args[sep + 7], "--timeout-ms");
            let ms: u64 = args[sep + 8].parse().expect("u64 timeout-ms");
            *observed_clone.lock().unwrap() = Some(ms);
            fs::write(args[sep + 6], b"approved\n").unwrap();
            Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }),
    ]);

    let mut prompt = TmuxPrompt::new(runner).with_popup_bin(approver_bin());
    assert_eq!(
        prompt.prompt_with_timeout(&view, Duration::from_millis(1500)),
        Ok(ApprovalOutcome::Approved)
    );
    let ms = observed_ms.lock().unwrap().expect("captured timeout-ms");
    assert!(
        (1..=1450).contains(&ms),
        "expected --timeout-ms <= remaining (~1440ms), never rounded up to 2000ms, got {ms}"
    );
}

#[cfg(unix)]
#[test]
fn tmux_internal_popup_binary_rejects_two_separate_stdin_writes_yes_then_no() {
    let kp = Ed25519Keypair::from_secret_bytes([0x4a; 32]);
    let view = sample_view(&kp);

    let runner = ScriptedRunner::new(vec![
        list_clients_step("0\t0\t500\t/dev/pts/9\n"),
        Box::new(move |program, args| {
            assert_eq!(program, "tmux");
            let sep = args.iter().position(|&a| a == "--").unwrap();
            let mut child = Command::new(args[sep + 1])
                .args(&args[sep + 2..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn handfest-approver --internal-popup-prompt");
            let mut child_stdin = child.stdin.take().unwrap();
            // Deliver "yes\n" and "no\n" in two separate writes (modeling canonical PTY paste).
            child_stdin.write_all(b"yes\n").expect("write yes");
            child_stdin.flush().expect("flush yes");
            std::thread::sleep(Duration::from_millis(5));
            child_stdin.write_all(b"no\n").expect("write no");
            child_stdin.flush().expect("flush no");
            drop(child_stdin);

            let out = child.wait_with_output().expect("wait popup");
            assert!(out.status.success(), "denied popup exits 0");
            assert_eq!(
                fs::read_to_string(args[sep + 6]).expect("result file"),
                "denied\n"
            );
            Ok(CommandOutput {
                stdout: out.stdout,
                stderr: out.stderr,
            })
        }),
    ]);

    let mut prompt = TmuxPrompt::new(runner).with_popup_bin(approver_bin());
    assert_eq!(
        prompt.prompt_with_timeout(&view, Duration::from_secs(5)),
        Ok(ApprovalOutcome::Denied {
            reason: "operator denied tmux prompt".to_string(),
        })
    );
}

#[cfg(unix)]
#[test]
fn tmux_internal_popup_binary_times_out_when_yes_arrives_with_less_than_25ms_remaining() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let display = dir.path().join("display.txt");
    let result = dir.path().join("result.txt");
    fs::write(&display, "HANDFEST v1\n...\n").expect("write display");

    let mut child = Command::new(approver_bin())
        .args([
            "--internal-popup-prompt",
            "--display-file",
            display.to_str().unwrap(),
            "--result-file",
            result.to_str().unwrap(),
            "--timeout-ms",
            "15",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn handfest-approver --internal-popup-prompt");

    let mut child_stdin = child.stdin.take().unwrap();
    std::thread::sleep(Duration::from_millis(12));
    let _ = child_stdin.write_all(b"yes\n");
    let _ = child_stdin.flush();
    std::thread::sleep(Duration::from_millis(5));
    let _ = child_stdin.write_all(b"no\n");
    let _ = child_stdin.flush();
    drop(child_stdin);

    let out = child.wait_with_output().expect("wait popup");
    assert_eq!(
        out.status.code(),
        Some(143),
        "popup with <25ms remaining must exit 143 (TimedOut), stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !result.exists(),
        "timed-out popup must NEVER write result file"
    );
}
