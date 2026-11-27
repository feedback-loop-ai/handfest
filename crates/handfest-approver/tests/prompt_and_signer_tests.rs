//! Unit tests for `TtyPrompt`, `DesktopPrompt`, `WysiwysPromptView`, and `SignerConfig`.

use std::cell::RefCell;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::time::Duration;

use handfest_anchors::{
    AnchorError, AssuranceLevel, CommandOutput, CommandRunner, Ed25519Keypair, MandateSigner,
    PivSignerConfig,
};
use handfest_approver::prompt::{
    ApprovalOutcome, ApprovalPrompt, DesktopBackend, DesktopPrompt, PromptError, TtyPrompt,
    WysiwysPromptView,
};
use handfest_approver::signer::{
    resolve_signer_with_runner, BoxedSigner, SignerConfig, DEFAULT_FIDO2_ANCHOR_ID,
    DEFAULT_LOCAL_ED25519_ANCHOR_ID, DEFAULT_OPENPGP_ANCHOR_ID, DEFAULT_PIV_ANCHOR_ID,
    DEFAULT_SSH_SK_ANCHOR_ID,
};
use handfest_core::ast::{KeyId, MandateId};
use handfest_core::cnl::{parse_mandate, try_render_canonical};

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
fn denied_tty_cases() -> Vec<(Vec<u8>, &'static str)> {
    let not_confirmed = "operator did not confirm approval";
    vec![
        (b"".to_vec(), "operator closed prompt (EOF)"),
        (b"\n".to_vec(), "operator declined (default No)"),
        (b"   \n".to_vec(), "operator declined (default No)"),
        (b"n\n".to_vec(), "operator denied request"),
        (b"NO\n".to_vec(), "operator denied request"),
        (b"y\n".to_vec(), not_confirmed),
        (b"YES\n".to_vec(), not_confirmed),
        (b"Yes\n".to_vec(), not_confirmed),
        (b"  yes\n".to_vec(), not_confirmed),
        (b"yes \n".to_vec(), not_confirmed),
        (b"yes\r\r\n".to_vec(), not_confirmed),
        (b"maybe\n".to_vec(), not_confirmed),
        (b"yy\n".to_vec(), not_confirmed),
        (b"yes!\n".to_vec(), not_confirmed),
    ]
}

#[test]
fn tty_prompt_approves_only_exact_yes_and_fails_closed_otherwise() {
    let kp = Ed25519Keypair::from_secret_bytes([0x22; 32]);
    let view = sample_view(&kp);
    let mandate_id_str = view.mandate_id().to_string();

    let expected_prompt = "Approve and sign this mandate? [yes/N]: ";
    for accepted in ["yes\n", "yes\r\n"] {
        let mut out = Vec::new();
        let mut prompt = TtyPrompt::new(Cursor::new(accepted.as_bytes()), &mut out);
        assert_eq!(prompt.prompt(&view), Ok(ApprovalOutcome::Approved));
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains(view.canonical_mandate()));
        assert!(rendered.contains(&mandate_id_str));
        assert!(rendered.contains(view.valid_from_rfc3339()));
        assert!(rendered.contains(view.valid_until_rfc3339()));
        assert!(rendered.contains(&view.signer_key_id().to_string()));
        assert!(rendered.contains(view.anchor_id()));
        assert_eq!(view.valid_from(), 1_760_000_000);
        assert_eq!(view.valid_until(), 1_760_003_600);
        assert!(rendered.contains(expected_prompt));
    }

    for (input, expected_reason) in denied_tty_cases() {
        let mut out = Vec::new();
        let mut prompt = TtyPrompt::new(Cursor::new(input.as_slice()), &mut out);
        assert_eq!(
            prompt.prompt(&view),
            Ok(ApprovalOutcome::Denied {
                reason: expected_reason.to_string(),
            }),
            "input {:?} must deny",
            String::from_utf8_lossy(&input)
        );
    }

    let huge = format!("{}\n", "y".repeat(2048));
    let mut out = Vec::new();
    let mut prompt = TtyPrompt::new(Cursor::new(huge.as_bytes()), &mut out);
    assert_eq!(
        prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator input exceeded maximum reply length".to_string(),
        })
    );
}

#[test]
fn tty_prompt_maps_interrupt_to_deny_and_other_io_to_error() {
    struct ErrorBufReader(io::ErrorKind);
    impl Read for ErrorBufReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "simulated"))
        }
    }
    impl BufRead for ErrorBufReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::new(self.0, "simulated"))
        }
        fn consume(&mut self, _amt: usize) {}
    }

    let kp = Ed25519Keypair::from_secret_bytes([0x33; 32]);
    let view = sample_view(&kp);

    let mut out = Vec::new();
    let mut interrupted = TtyPrompt::new(ErrorBufReader(io::ErrorKind::Interrupted), &mut out);
    assert_eq!(
        interrupted.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator interrupted prompt".to_string(),
        })
    );

    let mut out2 = Vec::new();
    let mut broken = TtyPrompt::new(ErrorBufReader(io::ErrorKind::BrokenPipe), &mut out2);
    assert!(matches!(broken.prompt(&view), Err(PromptError::Io(_))));
}

struct MockRunner {
    recorded: RefCell<Vec<(String, Vec<String>)>>,
    result: Result<CommandOutput, AnchorError>,
}

impl MockRunner {
    fn new(result: Result<CommandOutput, AnchorError>) -> Self {
        Self {
            recorded: RefCell::new(Vec::new()),
            result,
        }
    }
}

impl CommandRunner for MockRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        _stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        self.recorded.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| (*s).to_string()).collect(),
        ));
        self.result.clone()
    }
}

impl CommandRunner for &MockRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        (*self).run(program, args, stdin)
    }
}

#[test]
fn desktop_prompt_zenity_handles_approve_deny_timeout_and_errors() {
    let kp = Ed25519Keypair::from_secret_bytes([0x44; 32]);
    let view = sample_view(&kp);

    let ok_runner = MockRunner::new(Ok(CommandOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
    }));
    let mut prompt = DesktopPrompt::with_backend(&ok_runner, DesktopBackend::Zenity);
    assert_eq!(prompt.prompt(&view), Ok(ApprovalOutcome::Approved));

    let calls = ok_runner.recorded.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "zenity");
    assert!(calls[0].1.contains(&"--question".to_string()));
    assert!(calls[0].1.contains(&"--no-markup".to_string()));
    assert!(calls[0].1.contains(&view.format_display()));

    let deny_runner = MockRunner::new(Err(AnchorError::CommandFailed {
        program: "zenity".to_string(),
        status: Some(1),
        stderr: String::new(),
    }));
    let mut deny_prompt = DesktopPrompt::with_backend(&deny_runner, DesktopBackend::Zenity);
    assert_eq!(
        deny_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator denied desktop prompt".to_string(),
        })
    );

    let timeout_runner = MockRunner::new(Err(AnchorError::CommandFailed {
        program: "zenity".to_string(),
        status: Some(5),
        stderr: String::new(),
    }));
    let mut timeout_prompt = DesktopPrompt::with_backend(&timeout_runner, DesktopBackend::Zenity);
    assert_eq!(
        timeout_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "desktop prompt timed out".to_string(),
        })
    );

    let io_runner = MockRunner::new(Err(AnchorError::CommandIo {
        program: "zenity".to_string(),
        detail: "not found".to_string(),
    }));
    let mut err_prompt = DesktopPrompt::with_backend(&io_runner, DesktopBackend::Zenity);
    assert!(matches!(
        err_prompt.prompt(&view),
        Err(PromptError::CommandFailed { program, .. }) if program == "zenity"
    ));
}

#[test]
fn desktop_prompt_osascript_passes_text_via_argv_and_fails_closed() {
    let kp = Ed25519Keypair::from_secret_bytes([0x55; 32]);
    let view = sample_view(&kp);

    let ok_runner = MockRunner::new(Ok(CommandOutput {
        stdout: b"button returned:Approve & Sign\n".to_vec(),
        stderr: Vec::new(),
    }));
    let mut prompt = DesktopPrompt::with_backend(&ok_runner, DesktopBackend::Osascript);
    assert_eq!(prompt.prompt(&view), Ok(ApprovalOutcome::Approved));

    let calls = ok_runner.recorded.borrow();
    assert_eq!(calls[0].0, "osascript");
    assert_eq!(calls[0].1[0], "-e");
    assert!(!calls[0].1[1].contains(view.canonical_mandate()));
    assert_eq!(calls[0].1[2], "--");
    assert_eq!(calls[0].1[3], view.format_display());

    let spoof_runner = MockRunner::new(Ok(CommandOutput {
        stdout: b"button returned:Deny\n".to_vec(),
        stderr: Vec::new(),
    }));
    let mut spoof_prompt = DesktopPrompt::with_backend(&spoof_runner, DesktopBackend::Osascript);
    assert!(matches!(
        spoof_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied { .. })
    ));

    let cancel_runner = MockRunner::new(Err(AnchorError::CommandFailed {
        program: "osascript".to_string(),
        status: Some(1),
        stderr: "execution error: User canceled. (-128)".to_string(),
    }));
    let mut cancel_prompt = DesktopPrompt::with_backend(&cancel_runner, DesktopBackend::Osascript);
    assert_eq!(
        cancel_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator denied desktop prompt".to_string(),
        })
    );
}

#[test]
fn signer_config_defaults_and_boxed_signer_delegate_cleanly() {
    let dir = tempfile::TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x66; 32]);
    let key_path = dir.path().join("ed.key.json");
    std::fs::write(&key_path, serde_json::to_string(&kp.to_key_file()).unwrap()).unwrap();

    let cfg = SignerConfig::LocalEd25519 { key_path };
    assert_eq!(cfg.default_anchor_id(), DEFAULT_LOCAL_ED25519_ANCHOR_ID);
    assert_eq!(
        SignerConfig::SshSk {
            key_path: "a".into()
        }
        .default_anchor_id(),
        DEFAULT_SSH_SK_ANCHOR_ID
    );
    assert_eq!(
        SignerConfig::Fido2Ed25519 {
            cred_path: "a".into(),
            device_path: None
        }
        .default_anchor_id(),
        DEFAULT_FIDO2_ANCHOR_ID
    );
    assert_eq!(
        SignerConfig::OpenPgpEd25519 {
            fingerprint: "a".into()
        }
        .default_anchor_id(),
        DEFAULT_OPENPGP_ANCHOR_ID
    );
    assert_eq!(
        SignerConfig::PivEd25519 {
            pubkey_path: "a".into(),
            config: PivSignerConfig::default()
        }
        .default_anchor_id(),
        DEFAULT_PIV_ANCHOR_ID
    );

    let dummy = MockRunner::new(Err(AnchorError::CommandIo {
        program: "none".to_string(),
        detail: "unused".to_string(),
    }));
    let boxed: BoxedSigner = resolve_signer_with_runner(&cfg, dummy).unwrap();
    assert_eq!(boxed.key_id(), kp.key_id());
    assert_eq!(boxed.assurance(), AssuranceLevel::LocalKey);
    assert_eq!(boxed.sign_payload(b"hello").unwrap().len(), 64);
}

#[test]
fn prompt_view_and_osascript_error_branches_fail_closed() {
    let kp = Ed25519Keypair::from_secret_bytes([0x67; 32]);
    let view = sample_view(&kp);
    let bad_view = WysiwysPromptView::new(
        view.canonical_mandate().to_string(),
        view.mandate_id(),
        handfest_core::ast::MIN_RFC3339_TIMESTAMP - 1,
        100,
        kp.key_id(),
        "local-ed25519".to_string(),
    )
    .unwrap_err();
    assert!(matches!(bad_view, PromptError::InvalidView(_)));
    assert!(bad_view.to_string().contains("invalid prompt view"));

    let fail_runner = MockRunner::new(Err(AnchorError::CommandFailed {
        program: "osascript".to_string(),
        status: Some(2),
        stderr: "syntax error".to_string(),
    }));
    let mut prompt = DesktopPrompt::with_backend(&fail_runner, DesktopBackend::Osascript);
    let err = prompt.prompt(&view).unwrap_err();
    assert!(matches!(
        err,
        PromptError::CommandFailed { ref program, .. } if program == "osascript"
    ));
    assert!(err.to_string().contains("osascript"));

    // Platform default constructor executes cleanly with mock runner.
    let ok_runner = MockRunner::new(Ok(CommandOutput {
        stdout: b"button returned:Approve & Sign\n".to_vec(),
        stderr: Vec::new(),
    }));
    let mut default_prompt = DesktopPrompt::new(&ok_runner);
    assert_eq!(default_prompt.prompt(&view), Ok(ApprovalOutcome::Approved));
}

#[test]
fn tty_prompt_fails_closed_on_eof_without_newline_and_multi_line_buffered_input() {
    let kp = Ed25519Keypair::from_secret_bytes([0x68; 32]);
    let view = sample_view(&kp);

    // 1. EOF before newline on "yes" must fail closed (never Approved).
    let mut out = Vec::new();
    let mut prompt = TtyPrompt::new(Cursor::new(b"yes".as_slice()), &mut out);
    assert_eq!(
        prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator closed prompt before newline (EOF)".to_string(),
        })
    );

    // 2. Pasted multi-line "yes\nyes\n" across 2 requests: both Denied.
    let mut out2 = Vec::new();
    let mut multi = TtyPrompt::new(Cursor::new(b"yes\nyes\n".as_slice()), &mut out2);
    assert_eq!(
        multi.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "ambiguous multi-line TTY input rejected".to_string(),
        })
    );
    assert_eq!(
        multi.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator closed prompt (EOF)".to_string(),
        })
    );
}

#[test]
fn desktop_prompt_enforces_default_cancel_timeouts_and_exact_osascript_match() {
    let kp = Ed25519Keypair::from_secret_bytes([0x69; 32]);
    let view = sample_view(&kp);

    // 1. Zenity must pass --default-cancel and --timeout=<secs> (default and custom).
    let zenity_runner = MockRunner::new(Ok(CommandOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
    }));
    let mut zenity = DesktopPrompt::with_backend(&zenity_runner, DesktopBackend::Zenity);
    assert_eq!(zenity.prompt(&view), Ok(ApprovalOutcome::Approved));
    assert_eq!(
        zenity.prompt_with_timeout(&view, Duration::from_secs(15)),
        Ok(ApprovalOutcome::Approved)
    );
    assert_eq!(
        zenity.prompt_with_timeout(&view, Duration::from_millis(250)),
        Ok(ApprovalOutcome::Approved)
    );
    let zcalls = zenity_runner.recorded.borrow();
    assert_eq!(zcalls.len(), 3);
    assert!(zcalls[0].1.contains(&"--default-cancel".to_string()));
    assert!(zcalls[0].1.contains(&"--timeout=60".to_string()));
    assert!(zcalls[1].1.contains(&"--default-cancel".to_string()));
    assert!(zcalls[1].1.contains(&"--timeout=15".to_string()));
    assert!(zcalls[2].1.contains(&"--timeout=1".to_string()));

    // 2. Osascript must include `giving up after <timeout_secs>` and reject non-exact stdout.
    let osa_ok = MockRunner::new(Ok(CommandOutput {
        stdout: b"button returned:Approve & Sign\n".to_vec(),
        stderr: Vec::new(),
    }));
    let mut osa = DesktopPrompt::with_backend(&osa_ok, DesktopBackend::Osascript)
        .with_timeout(Duration::from_secs(25));
    assert_eq!(osa.prompt(&view), Ok(ApprovalOutcome::Approved));
    assert_eq!(
        osa.prompt_with_timeout(&view, Duration::from_secs(12)),
        Ok(ApprovalOutcome::Approved)
    );
    let ocalls = osa_ok.recorded.borrow();
    assert!(ocalls[0].1[1].contains("giving up after 25"));
    assert!(ocalls[1].1[1].contains("giving up after 12"));

    let osa_suffix = MockRunner::new(Ok(CommandOutput {
        stdout: b"button returned:Approve & Sign later\n".to_vec(),
        stderr: Vec::new(),
    }));
    let mut suffix_prompt = DesktopPrompt::with_backend(&osa_suffix, DesktopBackend::Osascript);
    assert_eq!(
        suffix_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator did not confirm approval in desktop dialog".to_string(),
        })
    );

    let osa_timeout = MockRunner::new(Ok(CommandOutput {
        stdout: b"gave up:true\n".to_vec(),
        stderr: Vec::new(),
    }));
    let mut timeout_prompt = DesktopPrompt::with_backend(&osa_timeout, DesktopBackend::Osascript);
    assert_eq!(
        timeout_prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "desktop prompt timed out".to_string(),
        })
    );
}

#[test]
fn tty_prompt_drains_truncated_oversized_multiline_tail_so_subsequent_prompt_never_approves() {
    let kp = Ed25519Keypair::from_secret_bytes([0x6a; 32]);
    let view = sample_view(&kp);

    // 1. Default 8192-byte BufReader splits "n\n" + "a"*8190 + "y\n" right before "y\n".
    // Both sequential prompt calls MUST return Denied (never Approved).
    let payload = format!("n\n{}y\n", "a".repeat(8190));
    let mut out = Vec::new();
    let mut prompt = TtyPrompt::new(BufReader::new(Cursor::new(payload.into_bytes())), &mut out);
    assert_eq!(
        prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "ambiguous multi-line TTY input rejected".to_string(),
        })
    );
    assert_eq!(
        prompt.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator closed prompt (EOF)".to_string(),
        })
    );

    // 2. Multi-chunk truncated trailing line (> 16 KiB) followed by EOF without trailing newline.
    let no_nl_tail = format!("n\n{}y", "a".repeat(17_000));
    let mut out2 = Vec::new();
    let mut prompt2 = TtyPrompt::new(
        BufReader::new(Cursor::new(no_nl_tail.into_bytes())),
        &mut out2,
    );
    assert_eq!(
        prompt2.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "ambiguous multi-line TTY input rejected".to_string(),
        })
    );
    assert_eq!(
        prompt2.prompt(&view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator closed prompt (EOF)".to_string(),
        })
    );
}

#[test]
fn wysiwys_prompt_view_rejects_ansi_newlines_bidi_inverted_window_and_mismatched_id() {
    let kp = Ed25519Keypair::from_secret_bytes([0x6b; 32]);
    let view = sample_view(&kp);
    let canonical = view.canonical_mandate().to_string();
    let valid_id = view.mandate_id();

    // 1. ANSI escape, newline, CR, U+2028, U+2029, and Bidi override in anchor_id.
    for bad_anchor in [
        "local\x1b[2Janchor",
        "local\ninjected",
        "local\rinjected",
        "local\u{2028}anchor",
        "local\u{2029}anchor",
        "local\u{202E}anchor",
        "  ",
    ] {
        let err = WysiwysPromptView::new(
            canonical.clone(),
            valid_id,
            100,
            200,
            kp.key_id(),
            bad_anchor.to_string(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PromptError::InvalidView(_)),
            "anchor {bad_anchor:?} must be rejected, got {err:?}"
        );
    }

    // 2. Inverted [200, 100] validity window.
    let inverted = WysiwysPromptView::new(
        canonical.clone(),
        valid_id,
        200,
        100,
        kp.key_id(),
        "local-ed25519".to_string(),
    )
    .unwrap_err();
    assert!(matches!(inverted, PromptError::InvalidView(_)));

    // 3. Mismatched MandateId.
    let wrong_id = MandateId::sha256(b"different-mandate");
    assert_ne!(wrong_id, valid_id);
    let mismatched = WysiwysPromptView::new(
        canonical.clone(),
        wrong_id,
        100,
        200,
        kp.key_id(),
        "local-ed25519".to_string(),
    )
    .unwrap_err();
    assert!(
        matches!(mismatched, PromptError::InvalidView(ref detail) if detail.contains("mandate_id mismatch"))
    );

    // 4. ANSI escape and Bidi override inside canonical_mandate.
    for bad_mandate in [
        format!("{canonical}\x1b[2J"),
        format!("{canonical}\u{202E}"),
        "   \n  ".to_string(),
        "HANDFEST v1\nNOT VALID\n".to_string(),
        canonical.replacen("HANDFEST v1", "HANDFEST v1  ", 1),
    ] {
        let err = WysiwysPromptView::new(
            bad_mandate,
            valid_id,
            100,
            200,
            kp.key_id(),
            "local-ed25519".to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, PromptError::InvalidView(_)));
    }
}

#[test]
fn tty_prompt_rejects_pretyped_multi_line_buffers() {
    let kp = Ed25519Keypair::from_secret_bytes([0x6c; 32]);
    let benign_view = sample_view(&kp);
    let agent = KeyId::new("ed25519", "2".repeat(64)).unwrap();
    let escalated_draft = format!(
        "HANDFEST v1\nFROM human \"Valentin\" (key: {})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW infra.prod.destroy\nON cluster \"prod-us\"\n",
        kp.key_id()
    );
    let escalated_ast = parse_mandate(&escalated_draft).unwrap();
    let escalated_canonical = try_render_canonical(&escalated_ast).unwrap();
    let escalated_view = WysiwysPromptView::new(
        escalated_canonical,
        escalated_ast.try_mandate_id().unwrap(),
        1_760_000_000,
        1_760_003_600,
        kp.key_id(),
        "local-ed25519".to_string(),
    )
    .unwrap();

    // 1. Pre-typed "y\n".repeat(4097) spans the 8192-byte BufReader boundary; both calls MUST Deny.
    let repeated_y = "y\n".repeat(4097);
    let mut out1 = Vec::new();
    let mut p1 = TtyPrompt::new(
        BufReader::new(Cursor::new(repeated_y.into_bytes())),
        &mut out1,
    );
    assert_eq!(
        p1.prompt(&benign_view),
        Ok(ApprovalOutcome::Denied {
            reason: "ambiguous multi-line TTY input rejected".to_string(),
        })
    );
    assert_eq!(
        p1.prompt(&escalated_view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator did not confirm approval".to_string(),
        })
    );

    // 2. "n\n" + 8190*'a' + "y\n" across BufReader boundary: both calls MUST Deny.
    let split_tail = format!("n\n{}y\n", "a".repeat(8190));
    let mut out2 = Vec::new();
    let mut p2 = TtyPrompt::new(
        BufReader::new(Cursor::new(split_tail.into_bytes())),
        &mut out2,
    );
    assert_eq!(
        p2.prompt(&benign_view),
        Ok(ApprovalOutcome::Denied {
            reason: "ambiguous multi-line TTY input rejected".to_string(),
        })
    );
    assert_eq!(
        p2.prompt(&escalated_view),
        Ok(ApprovalOutcome::Denied {
            reason: "operator closed prompt (EOF)".to_string(),
        })
    );
}

#[test]
fn wysiwys_prompt_view_rejects_mismatched_signer_key_and_valid_canonical_bidi_display_name() {
    let kp = Ed25519Keypair::from_secret_bytes([0x6d; 32]);
    let other_kp = Ed25519Keypair::from_secret_bytes([0x6e; 32]);
    assert_ne!(kp.key_id(), other_kp.key_id());
    let view = sample_view(&kp);

    // 1. Valid canonical mandate + matching MandateId, but wrong signer_key_id != ast.from().key().
    let mismatch = WysiwysPromptView::new(
        view.canonical_mandate().to_string(),
        view.mandate_id(),
        1_760_000_000,
        1_760_003_600,
        other_kp.key_id(),
        "local-ed25519".to_string(),
    )
    .unwrap_err();
    assert!(
        matches!(mismatch, PromptError::InvalidView(ref detail) if detail.contains("signer_key_id mismatch")),
        "expected signer_key_id mismatch error, got {mismatch:?}"
    );

    // 2. Valid canonical HANDFEST v1 mandate with matching MandateId and matching signer_key_id,
    // containing a Bidi override (U+202E) inside a quoted display name: MUST be rejected
    // specifically by the Unicode filter.
    let agent = KeyId::new("ed25519", "2".repeat(64)).unwrap();
    let bidi_draft = format!(
        "HANDFEST v1\nFROM human \"Val\u{202E}entin\" (key: {})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n",
        kp.key_id()
    );
    let bidi_ast =
        parse_mandate(&bidi_draft).expect("CNL accepts UTF-8 inside quoted display name");
    let bidi_canonical = try_render_canonical(&bidi_ast).expect("canonical render succeeds");
    assert_eq!(bidi_canonical, bidi_draft);
    let bidi_id = MandateId::sha256(bidi_canonical.as_bytes());
    assert_eq!(bidi_ast.from().key(), &kp.key_id());

    let bidi_err = WysiwysPromptView::new(
        bidi_canonical,
        bidi_id,
        1_760_000_000,
        1_760_003_600,
        kp.key_id(),
        "local-ed25519".to_string(),
    )
    .unwrap_err();
    assert!(
        matches!(bidi_err, PromptError::InvalidView(ref detail) if detail.contains("forbidden character U+202E")),
        "expected U+202E Unicode filter rejection, got {bidi_err:?}"
    );
}
