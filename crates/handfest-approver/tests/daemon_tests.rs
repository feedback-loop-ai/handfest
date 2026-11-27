//! Integration tests for `ApproverDaemon` over real ephemeral Unix domain sockets.

#![cfg(unix)]

use std::fs;
use std::io::{BufReader, Cursor, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use handfest_anchors::{
    AnchorError, AnchorRegistry, AnchorVerifier, AssuranceLevel, Ed25519Keypair, MandateSigner,
};
use handfest_approver::client::{request_and_verify_signature, request_signature};
use handfest_approver::daemon::{ApproverDaemon, BoundSocket, DaemonError, SocketMode};
use handfest_approver::prompt::{
    ApprovalOutcome, ApprovalPrompt, PromptError, TtyPrompt, WysiwysPromptView,
};
use handfest_approver::protocol::{
    decode_sign_response, FrameReader, SignRequest, SignResponse, ERR_FRAME_TOO_LARGE,
    ERR_INTERNAL, ERR_INVALID_FRAME, ERR_INVALID_MANDATE, ERR_INVALID_REQUEST, ERR_PROMPT_FAILED,
    ERR_SIGNER_MISMATCH, ERR_SIGNING_FAILED, ERR_TIMEOUT, MAX_FRAME_BYTES, MAX_REQUEST_FRAME_BYTES,
    MAX_RESPONSE_FRAME_BYTES,
};
use handfest_core::ast::KeyId;
use handfest_core::cnl::{parse_mandate, try_render_canonical};

struct CountingSigner {
    inner: Ed25519Keypair,
    calls: Arc<AtomicUsize>,
    fail_sign: bool,
}

impl CountingSigner {
    fn new(seed: [u8; 32]) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner: Ed25519Keypair::from_secret_bytes(seed),
                calls: Arc::clone(&calls),
                fail_sign: false,
            },
            calls,
        )
    }

    fn failing(seed: [u8; 32]) -> (Self, Arc<AtomicUsize>) {
        let (mut s, c) = Self::new(seed);
        s.fail_sign = true;
        (s, c)
    }
}

impl MandateSigner for CountingSigner {
    fn key_id(&self) -> KeyId {
        self.inner.key_id()
    }

    fn assurance(&self) -> AssuranceLevel {
        self.inner.assurance()
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_sign {
            return Err(AnchorError::InvalidSignature(
                "injected failure".to_string(),
            ));
        }
        self.inner.sign_payload(payload)
    }
}

struct RecordingPrompt {
    outcome: Result<ApprovalOutcome, PromptError>,
    delay: Duration,
    seen: Vec<WysiwysPromptView>,
    seen_timeouts: Vec<Duration>,
    active_counter: Option<Arc<AtomicUsize>>,
    max_concurrent: Option<Arc<AtomicUsize>>,
}

impl RecordingPrompt {
    fn new(outcome: Result<ApprovalOutcome, PromptError>) -> Self {
        Self {
            outcome,
            delay: Duration::ZERO,
            seen: Vec::new(),
            seen_timeouts: Vec::new(),
            active_counter: None,
            max_concurrent: None,
        }
    }
}

impl ApprovalPrompt for RecordingPrompt {
    fn prompt(&mut self, view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError> {
        if let (Some(active), Some(max_c)) = (&self.active_counter, &self.max_concurrent) {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            max_c.fetch_max(now, Ordering::SeqCst);
        }
        self.seen.push(view.clone());
        if !self.delay.is_zero() {
            thread::sleep(self.delay);
        }
        if let Some(active) = &self.active_counter {
            active.fetch_sub(1, Ordering::SeqCst);
        }
        self.outcome.clone()
    }

    fn prompt_with_timeout(
        &mut self,
        view: &WysiwysPromptView,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, PromptError> {
        self.seen_timeouts.push(timeout);
        self.prompt(view)
    }
}

fn non_canonical_draft(from_key: &KeyId) -> String {
    let agent = KeyId::new("ed25519", "a".repeat(64)).unwrap();
    format!(
        "HANDFEST v1  \nFROM human \"Valentin\" (key: {from_key})\nTO agent \"Claude\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge, git.branch.create\nON repo \"org/app\"\nWHERE zeta == \"last\"\nAND alpha == \"first\"\n"
    )
}

fn restricted_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let canonical_path = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical_path, fs::Permissions::from_mode(0o700)).unwrap();
    (dir, canonical_path)
}

#[test]
fn happy_path_canonicalizes_non_canonical_draft_prompts_and_returns_verified_mandate() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("approver.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).expect("bind socket");

    let (signer, sign_calls) = CountingSigner::new([0x10; 32]);
    let signer_key = signer.key_id();
    let draft = non_canonical_draft(&signer_key);
    let expected_ast = parse_mandate(&draft).unwrap();
    let expected_canonical = try_render_canonical(&expected_ast).unwrap();
    let expected_id = expected_ast.try_mandate_id().unwrap();
    assert_ne!(draft, expected_canonical);

    let prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_secs(10)).unwrap();

    let server_handle = thread::spawn(move || {
        daemon.serve_one(bound.listener()).expect("serve one");
        daemon
    });

    let req = SignRequest {
        mandate_text: draft,
        valid_from: 1_760_000_000,
        valid_until: 1_760_003_600,
        anchor_id: None,
    };
    let registry = AnchorRegistry::default_registry();
    let verified =
        request_and_verify_signature(&sock_path, &req, &registry, Some(Duration::from_secs(5)))
            .expect("approved and verified");

    let daemon = server_handle.join().unwrap();
    assert_eq!(sign_calls.load(Ordering::SeqCst), 1);
    assert_eq!(daemon.prompt().seen.len(), 1);
    let seen = &daemon.prompt().seen[0];
    assert_eq!(seen.canonical_mandate(), expected_canonical);
    assert_eq!(seen.mandate_id(), expected_id);
    assert_eq!(seen.signer_key_id(), &signer_key);
    assert_eq!(seen.valid_from_rfc3339(), "2025-10-09T08:53:20Z");
    assert_eq!(seen.valid_until_rfc3339(), "2025-10-09T09:53:20Z");

    assert_eq!(verified.mandate_id, expected_id);
    assert_eq!(verified.signed_mandate.canonical_words, expected_canonical);
    assert_eq!(verified.signed_mandate.anchor_id, "local-ed25519");
    assert!(registry.verify(&verified.signed_mandate).is_ok());
}

#[test]
fn tty_deny_eof_empty_and_wrong_input_never_invoke_signer_over_socket() {
    for raw_reply in [b"n\n".as_slice(), b"", b"\n", b"definitely\n"] {
        let (_dir, dir_path) = restricted_tempdir();
        let sock_path = dir_path.join("approver.sock");
        let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();

        let (signer, sign_calls) = CountingSigner::new([0x20; 32]);
        let draft = non_canonical_draft(&signer.key_id());
        let tty = TtyPrompt::new(Cursor::new(raw_reply.to_vec()), Vec::new());
        let mut daemon =
            ApproverDaemon::new(signer, tty, "local-ed25519", Duration::from_secs(5)).unwrap();

        let handle = thread::spawn(move || {
            daemon.serve_one(bound.listener()).unwrap();
        });

        let req = SignRequest {
            mandate_text: draft,
            valid_from: 1_760_000_000,
            valid_until: 1_760_003_600,
            anchor_id: None,
        };
        let resp = request_signature(&sock_path, &req, Some(Duration::from_secs(5))).unwrap();
        handle.join().unwrap();

        assert!(matches!(resp, SignResponse::Denied { .. }));
        assert_eq!(sign_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn invalid_requests_are_rejected_before_prompting_or_signing() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("approver.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();

    let (signer, sign_calls) = CountingSigner::new([0x30; 32]);
    let other_key = Ed25519Keypair::from_secret_bytes([0x31; 32]).key_id();
    let valid_draft = non_canonical_draft(&signer.key_id());
    let wrong_principal_draft = non_canonical_draft(&other_key);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_secs(5)).unwrap();

    let handle = thread::spawn(move || {
        daemon
            .serve_until(bound.listener(), &stop_clone)
            .expect("serve_until");
        daemon
    });

    let raw_cases: Vec<(Vec<u8>, &str)> = vec![
        (
            format!(
                "{}\n",
                serde_json::to_string(&SignRequest {
                    mandate_text: wrong_principal_draft,
                    valid_from: 100,
                    valid_until: 200,
                    anchor_id: None,
                })
                .unwrap()
            )
            .into_bytes(),
            ERR_SIGNER_MISMATCH,
        ),
        (
            format!(
                "{}\n",
                serde_json::to_string(&SignRequest {
                    mandate_text: "HANDFEST v1\nNOT VALID SYNTAX\n".to_string(),
                    valid_from: 100,
                    valid_until: 200,
                    anchor_id: None,
                })
                .unwrap()
            )
            .into_bytes(),
            ERR_INVALID_MANDATE,
        ),
        (
            format!(
                "{{\"mandate_text\":{},\"valid_from\":300,\"valid_until\":100}}\n",
                serde_json::to_string(&valid_draft).unwrap()
            )
            .into_bytes(),
            ERR_INVALID_REQUEST,
        ),
        (
            format!(
                "{{\"mandate_text\":{},\"valid_from\":100,\"valid_until\":200,\"rogue\":true}}\n",
                serde_json::to_string(&valid_draft).unwrap()
            )
            .into_bytes(),
            ERR_INVALID_FRAME,
        ),
        (
            format!("{}\n", "x".repeat(MAX_FRAME_BYTES + 16)).into_bytes(),
            ERR_FRAME_TOO_LARGE,
        ),
        (
            b"{\"mandate_text\":\"x\"}\r\n".to_vec(),
            ERR_INVALID_REQUEST,
        ),
    ];

    for (payload, expected_code) in raw_cases {
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream.write_all(&payload).unwrap();
        stream.flush().unwrap();
        let mut reader = FrameReader::new(BufReader::new(&stream));
        let line = reader
            .read_frame_line(MAX_FRAME_BYTES)
            .unwrap()
            .expect("error response frame");
        let resp = decode_sign_response(&line).unwrap();
        match resp {
            SignResponse::Error { code, .. } => assert_eq!(code, expected_code),
            other => panic!("expected Error({expected_code}), got {other:?}"),
        }
    }

    {
        let _silent = UnixStream::connect(&sock_path).unwrap();
    }
    thread::sleep(Duration::from_millis(30));

    stop.store(true, Ordering::Release);
    let daemon = handle.join().unwrap();
    assert_eq!(daemon.prompt().seen.len(), 0);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn prompt_error_signing_error_and_timeout_fail_closed() {
    let (signer, sign_calls) = CountingSigner::new([0x40; 32]);
    let req = SignRequest {
        mandate_text: non_canonical_draft(&signer.key_id()),
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    };

    let mut d1 = ApproverDaemon::new(
        signer,
        RecordingPrompt::new(Err(PromptError::Io("tty gone".to_string()))),
        "local-ed25519",
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(matches!(
        d1.handle_request(&req),
        SignResponse::Error { code, .. } if code == ERR_PROMPT_FAILED
    ));
    assert_eq!(sign_calls.load(Ordering::SeqCst), 0);

    let (signer2, sign_calls2) = CountingSigner::new([0x40; 32]);
    let mut slow_prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    slow_prompt.delay = Duration::from_millis(80);
    let mut d2 = ApproverDaemon::new(
        signer2,
        slow_prompt,
        "local-ed25519",
        Duration::from_millis(20),
    )
    .unwrap();
    assert!(matches!(
        d2.handle_request(&req),
        SignResponse::Error { code, .. } if code == ERR_TIMEOUT
    ));
    assert_eq!(sign_calls2.load(Ordering::SeqCst), 0);

    let (signer3, sign_calls3) = CountingSigner::failing([0x40; 32]);
    let mut d3 = ApproverDaemon::new(
        signer3,
        RecordingPrompt::new(Ok(ApprovalOutcome::Approved)),
        "local-ed25519",
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(matches!(
        d3.handle_request(&req),
        SignResponse::Error { code, .. } if code == ERR_SIGNING_FAILED
    ));
    assert_eq!(sign_calls3.load(Ordering::SeqCst), 1);
}

#[test]
fn daemon_serializes_concurrent_requests_one_at_a_time() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("approver.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();

    let (signer, _) = CountingSigner::new([0x50; 32]);
    let draft = non_canonical_draft(&signer.key_id());
    let active = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));
    let mut prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    prompt.delay = Duration::from_millis(40);
    prompt.active_counter = Some(Arc::clone(&active));
    prompt.max_concurrent = Some(Arc::clone(&max_concurrent));

    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_secs(5)).unwrap();

    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
        daemon.serve_one(bound.listener()).unwrap();
    });

    let p1 = sock_path.clone();
    let d1 = draft.clone();
    let c1 = thread::spawn(move || {
        request_signature(
            &p1,
            &SignRequest {
                mandate_text: d1,
                valid_from: 100,
                valid_until: 200,
                anchor_id: None,
            },
            Some(Duration::from_secs(5)),
        )
    });
    let p2 = sock_path;
    let c2 = thread::spawn(move || {
        request_signature(
            &p2,
            &SignRequest {
                mandate_text: draft,
                valid_from: 100,
                valid_until: 200,
                anchor_id: None,
            },
            Some(Duration::from_secs(5)),
        )
    });

    assert!(matches!(
        c1.join().unwrap(),
        Ok(SignResponse::Approved { .. })
    ));
    assert!(matches!(
        c2.join().unwrap(),
        Ok(SignResponse::Approved { .. })
    ));
    server.join().unwrap();
    assert_eq!(max_concurrent.load(Ordering::SeqCst), 1);
}

#[test]
fn stalled_client_triggers_socket_read_timeout_without_prompting() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("stall.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();

    let (signer, sign_calls) = CountingSigner::new([0x51; 32]);
    let prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_millis(50)).unwrap();

    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
        daemon
    });

    let stream = UnixStream::connect(&sock_path).unwrap();
    let mut reader = FrameReader::new(BufReader::new(&stream));
    let line = reader
        .read_frame_line(MAX_FRAME_BYTES)
        .unwrap()
        .expect("timeout response frame");
    let resp = decode_sign_response(&line).unwrap();
    assert!(matches!(
        resp,
        SignResponse::Error { code, .. } if code == ERR_TIMEOUT
    ));

    let daemon = server.join().unwrap();
    assert_eq!(daemon.prompt().seen.len(), 0);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unicode_wysiwys_spoofing_in_request_is_rejected_over_socket_before_prompting() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("bidi.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();

    let (signer, sign_calls) = CountingSigner::new([0x52; 32]);
    let valid_draft = non_canonical_draft(&signer.key_id());
    let prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_secs(5)).unwrap();

    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
        daemon.serve_one(bound.listener()).unwrap();
        daemon
    });

    for bad_req in [
        SignRequest {
            mandate_text: valid_draft.clone(),
            valid_from: 100,
            valid_until: 200,
            anchor_id: Some("local\u{2028}ed25519".to_string()),
        },
        SignRequest {
            mandate_text: format!("{valid_draft}\u{202E}"),
            valid_from: 100,
            valid_until: 200,
            anchor_id: None,
        },
    ] {
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        let line = format!("{}\n", serde_json::to_string(&bad_req).unwrap());
        stream.write_all(line.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut reader = FrameReader::new(BufReader::new(&stream));
        let resp_line = reader
            .read_frame_line(MAX_FRAME_BYTES)
            .unwrap()
            .expect("error frame");
        assert!(matches!(
            decode_sign_response(&resp_line).unwrap(),
            SignResponse::Error { code, .. } if code == ERR_INVALID_REQUEST
        ));
    }

    let daemon = server.join().unwrap();
    assert_eq!(daemon.prompt().seen.len(), 0);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn slow_drip_client_exceeds_overall_deadline_and_timeout_is_forwarded_to_prompt() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("slow_drip.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();

    let (signer, sign_calls) = CountingSigner::new([0x53; 32]);
    let prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_millis(80)).unwrap();

    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
        daemon
    });

    // Drip 1 byte every 25ms: each individual read is < 80ms, so only overall deadline enforcement stops it.
    let mut stream = UnixStream::connect(&sock_path).unwrap();
    let drip = thread::spawn(move || {
        let payload = b"{\"mandate_text\":\"slow\"}\n";
        for &byte in payload {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            let _ = stream.flush();
            thread::sleep(Duration::from_millis(25));
        }
        stream
    });
    let stream = drip.join().unwrap();
    let mut reader = FrameReader::new(BufReader::new(&stream));
    let line = reader
        .read_frame_line(MAX_FRAME_BYTES)
        .unwrap()
        .expect("timeout response frame");
    assert!(matches!(
        decode_sign_response(&line).unwrap(),
        SignResponse::Error { code, .. } if code == ERR_TIMEOUT
    ));

    let daemon = server.join().unwrap();
    assert_eq!(daemon.prompt().seen.len(), 0);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 0);

    // Also verify ApproverDaemon forwards remaining timeout into ApprovalPrompt::prompt_with_timeout.
    let (signer2, _) = CountingSigner::new([0x54; 32]);
    let draft2 = non_canonical_draft(&signer2.key_id());
    let mut daemon2 = ApproverDaemon::new(
        signer2,
        RecordingPrompt::new(Ok(ApprovalOutcome::Approved)),
        "local-ed25519",
        Duration::from_secs(7),
    )
    .unwrap();
    let resp = daemon2.handle_request(&SignRequest {
        mandate_text: draft2,
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    });
    assert!(matches!(resp, SignResponse::Approved { .. }));
    assert_eq!(daemon2.prompt().seen_timeouts.len(), 1);
    assert!(daemon2.prompt().seen_timeouts[0] <= Duration::from_secs(7));
    assert!(!daemon2.prompt().seen_timeouts[0].is_zero());
}

#[test]
fn serve_forever_handles_two_sequential_requests_end_to_end() {
    struct SequencePrompt(Vec<ApprovalOutcome>);
    impl ApprovalPrompt for SequencePrompt {
        fn prompt(&mut self, _view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError> {
            Ok(self.0.remove(0))
        }
    }

    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("forever.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
    let listener = bound.listener().try_clone().unwrap();

    let (signer, sign_calls) = CountingSigner::new([0x55; 32]);
    let draft = non_canonical_draft(&signer.key_id());
    let prompt = SequencePrompt(vec![
        ApprovalOutcome::Approved,
        ApprovalOutcome::Denied {
            reason: "operator declined second mandate".to_string(),
        },
    ]);
    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_secs(5)).unwrap();

    let bg = thread::spawn(move || daemon.serve_forever(&listener));

    let req = SignRequest {
        mandate_text: draft,
        valid_from: 1_760_000_000,
        valid_until: 1_760_003_600,
        anchor_id: None,
    };
    let registry = AnchorRegistry::default_registry();
    let first =
        request_and_verify_signature(&sock_path, &req, &registry, Some(Duration::from_secs(5)))
            .expect("first request approved and verified");
    assert!(registry.verify(&first.signed_mandate).is_ok());

    let second = request_signature(&sock_path, &req, Some(Duration::from_secs(5)))
        .expect("second request decoded");
    assert_eq!(
        second,
        SignResponse::Denied {
            reason: "operator declined second mandate".to_string(),
        }
    );
    assert_eq!(sign_calls.load(Ordering::SeqCst), 1);

    // Switch the shared listener open file description to non-blocking and wake `accept()` with
    // an immediate-EOF probe so `serve_forever` returns cleanly instead of detaching a thread.
    bound.listener().set_nonblocking(true).unwrap();
    if let Ok(wake) = UnixStream::connect(&sock_path) {
        let _ = wake.shutdown(Shutdown::Both);
    }
    let exit = bg.join().expect("serve_forever thread must not panic");
    assert!(matches!(exit, Err(DaemonError::Io { path: None, .. })));
    drop(bound);
}

#[test]
fn canonical_expansion_past_max_response_frame_rejected_before_prompt_or_sign() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("expand.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();

    let (signer, sign_calls) = CountingSigner::new([0x56; 32]);
    let agent = KeyId::new("ed25519", "b".repeat(64)).unwrap();
    let items: String = (0..10_800)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let compact_draft = format!(
        "HANDFEST v1\nFROM human \"Valentin\" (key: {})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\nWHERE x IN {{{items}}}\n",
        signer.key_id()
    );
    let req = SignRequest {
        mandate_text: compact_draft.clone(),
        valid_from: 1_760_000_000,
        valid_until: 1_760_003_600,
        anchor_id: None,
    };

    // Confirm the wire request fits strictly inside MAX_REQUEST_FRAME_BYTES while canonicalization
    // expands past MAX_RESPONSE_FRAME_BYTES once response framing + signature headroom are counted.
    let encoded_req = serde_json::to_string(&req).unwrap();
    assert!(
        encoded_req.len() < MAX_REQUEST_FRAME_BYTES,
        "compact request must fit in 56 KiB (was {} bytes)",
        encoded_req.len()
    );
    let canonical = try_render_canonical(&parse_mandate(&compact_draft).unwrap()).unwrap();
    assert!(
        canonical.len() + 2048 > MAX_RESPONSE_FRAME_BYTES,
        "canonicalized mandate + headroom must exceed 64 KiB (canonical was {} bytes)",
        canonical.len()
    );

    let prompt = RecordingPrompt::new(Ok(ApprovalOutcome::Approved));
    let mut daemon =
        ApproverDaemon::new(signer, prompt, "local-ed25519", Duration::from_secs(5)).unwrap();

    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
        daemon
    });

    let resp = request_signature(&sock_path, &req, Some(Duration::from_secs(5))).unwrap();
    assert_eq!(
        resp,
        SignResponse::Error {
            code: ERR_INVALID_REQUEST.to_string(),
            message: "canonical mandate exceeds maximum response frame size".to_string(),
        }
    );

    let daemon = server.join().unwrap();
    assert_eq!(daemon.prompt().seen.len(), 0);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn oversized_denial_and_prompt_error_messages_are_truncated_to_bounded_utf8() {
    fn run_single_prompt_outcome(
        seed: u8,
        sock_name: &str,
        outcome: Result<ApprovalOutcome, PromptError>,
    ) -> SignResponse {
        let (_dir, dir_path) = restricted_tempdir();
        let sock_path = dir_path.join(sock_name);
        let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
        let (signer, _) = CountingSigner::new([seed; 32]);
        let req = SignRequest {
            mandate_text: non_canonical_draft(&signer.key_id()),
            valid_from: 1_760_000_000,
            valid_until: 1_760_003_600,
            anchor_id: None,
        };
        let mut daemon = ApproverDaemon::new(
            signer,
            RecordingPrompt::new(outcome),
            "local-ed25519",
            Duration::from_secs(5),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve_one(bound.listener()).unwrap());
        let resp = request_signature(&sock_path, &req, Some(Duration::from_secs(5)))
            .expect("must receive structured response, never EmptyResponse");
        server.join().unwrap();
        resp
    }

    // 1. 66,000-byte denial reason truncates cleanly to 2048 bytes.
    assert_eq!(
        run_single_prompt_outcome(
            0x57,
            "huge_deny.sock",
            Ok(ApprovalOutcome::Denied {
                reason: "r".repeat(66_000),
            }),
        ),
        SignResponse::Denied {
            reason: "r".repeat(2048),
        }
    );

    // 2. 66,000-byte prompt error truncates cleanly to 2048 bytes.
    match run_single_prompt_outcome(
        0x58,
        "huge_prompt_err.sock",
        Err(PromptError::Io("e".repeat(66_000))),
    ) {
        SignResponse::Error { code, message } => {
            assert_eq!(code, ERR_PROMPT_FAILED);
            assert_eq!(message.len(), 2048);
            assert!(message.starts_with("approval prompt I/O error: "));
        }
        other => panic!("expected Error response, got {other:?}"),
    }

    // 3. Multi-byte UTF-8 denial reason truncates on a valid UTF-8 boundary <= 2048 bytes.
    assert_eq!(
        run_single_prompt_outcome(
            0x59,
            "utf8_deny.sock",
            Ok(ApprovalOutcome::Denied {
                reason: "€".repeat(1000),
            }),
        ),
        SignResponse::Denied {
            reason: "€".repeat(682),
        }
    );
}

#[test]
fn oversized_signed_response_falls_back_to_internal_error_instead_of_dropping_connection() {
    struct HugeSignatureSigner(Ed25519Keypair);
    impl MandateSigner for HugeSignatureSigner {
        fn key_id(&self) -> KeyId {
            self.0.key_id()
        }
        fn assurance(&self) -> AssuranceLevel {
            self.0.assurance()
        }
        fn sign_payload(&self, _payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
            // 40,000 raw bytes -> 80,000 hex chars, exceeding 64 KiB MAX_RESPONSE_FRAME_BYTES.
            Ok(vec![0xab; 40_000])
        }
    }

    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("huge_sig.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
    let signer = HugeSignatureSigner(Ed25519Keypair::from_secret_bytes([0x5a; 32]));
    let req = SignRequest {
        mandate_text: non_canonical_draft(&signer.key_id()),
        valid_from: 1_760_000_000,
        valid_until: 1_760_003_600,
        anchor_id: None,
    };
    let mut daemon = ApproverDaemon::new(
        signer,
        RecordingPrompt::new(Ok(ApprovalOutcome::Approved)),
        "local-ed25519",
        Duration::from_secs(5),
    )
    .unwrap();
    let server = thread::spawn(move || daemon.serve_one(bound.listener()).unwrap());

    let resp = request_signature(&sock_path, &req, Some(Duration::from_secs(5)))
        .expect("must receive fallback ERR_INTERNAL response, never EmptyResponse");
    server.join().unwrap();
    assert_eq!(
        resp,
        SignResponse::Error {
            code: ERR_INTERNAL.to_string(),
            message: "signed response exceeded maximum frame size".to_string(),
        }
    );
}

#[test]
fn daemon_rejects_timeouts_exceeding_max_timeout_and_accepts_max_timeout() {
    let kp = Ed25519Keypair::from_secret_bytes([0x5b; 32]);
    for huge in [
        Duration::MAX,
        Duration::from_secs(1 << 54),
        handfest_approver::MAX_TIMEOUT
            .checked_add(Duration::from_secs(1))
            .unwrap(),
    ] {
        let err = ApproverDaemon::new(
            kp.clone(),
            RecordingPrompt::new(Ok(ApprovalOutcome::Approved)),
            "local-ed25519",
            huge,
        )
        .err()
        .expect("excessive daemon timeout must be rejected");
        assert!(
            matches!(err, DaemonError::InvalidConfig(ref msg) if msg.contains("timeout")),
            "expected InvalidConfig for daemon timeout {huge:?}, got {err:?}"
        );
    }

    let ok = ApproverDaemon::new(
        kp,
        RecordingPrompt::new(Ok(ApprovalOutcome::Approved)),
        "local-ed25519",
        handfest_approver::MAX_TIMEOUT,
    );
    assert!(ok.is_ok(), "exact MAX_TIMEOUT must be accepted by daemon");
}

#[cfg(target_os = "linux")]
fn listener_is_nonblocking(listener: &std::os::unix::net::UnixListener) -> bool {
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
fn serve_until_restores_listener_blocking_mode_for_subsequent_serve_one() {
    let (_dir, dir_path) = restricted_tempdir();
    let sock_path = dir_path.join("restore_blocking.sock");
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x5c; 32]);
    let req = SignRequest {
        mandate_text: non_canonical_draft(&kp.key_id()),
        valid_from: 1_760_000_000,
        valid_until: 1_760_003_600,
        anchor_id: None,
    };
    let mut daemon = ApproverDaemon::new(
        kp,
        RecordingPrompt::new(Ok(ApprovalOutcome::Approved)),
        "local-ed25519",
        Duration::from_secs(5),
    )
    .unwrap();

    // Enter serve_until with stop already true; on return the listener MUST be blocking again.
    daemon
        .serve_until(bound.listener(), &AtomicBool::new(true))
        .unwrap();

    #[cfg(target_os = "linux")]
    assert!(
        !listener_is_nonblocking(bound.listener()),
        "serve_until must clear O_NONBLOCK on listener before returning"
    );

    // Deterministic behavioral check with ZERO queued clients: start serve_one and verify
    // it stays blocked waiting in accept() (does NOT return WouldBlock) before any client connects.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        let res = daemon.serve_one(bound.listener());
        done_tx.send(res).unwrap();
    });
    ready_rx.recv().unwrap();
    assert!(
        matches!(
            done_rx.recv_timeout(Duration::from_millis(80)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "serve_one must block when no client is queued instead of failing with WouldBlock"
    );

    let resp = request_signature(&sock_path, &req, Some(Duration::from_secs(5)))
        .expect("subsequent serve_one must block and serve the client once it connects");
    assert!(matches!(resp, SignResponse::Approved { .. }));
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("serve_one must finish after serving client")
        .expect("serve_one must succeed instead of failing with WouldBlock");
    server.join().unwrap();
}
