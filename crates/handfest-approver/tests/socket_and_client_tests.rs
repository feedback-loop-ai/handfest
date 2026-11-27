//! Security tests for `BoundSocket` permissions/symlinks/stale cleanup and client verification.

#![cfg(unix)]

use std::fs;
use std::io::{self, BufReader, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use handfest_anchors::{
    sign_mandate_with, AnchorError, AnchorRegistry, AnchorVerifier, Ed25519Keypair, SignedMandate,
};
use handfest_approver::client::{request_and_verify_signature, request_signature, ClientError};
use handfest_approver::daemon::{BoundSocket, DaemonError, SocketMode};
use handfest_approver::protocol::{
    write_frame, FrameReader, ProtocolError, SignRequest, SignResponse, ERR_TIMEOUT,
    MAX_FRAME_BYTES,
};
use handfest_core::ast::KeyId;
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::VerifiedMandate;

fn draft_for(from_key: &KeyId) -> String {
    let agent = KeyId::new("ed25519", "c".repeat(64)).unwrap();
    format!(
        "HANDFEST v1\nFROM human \"Valentin\" (key: {from_key})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n"
    )
}

fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let canonical = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
    (dir, canonical)
}

#[test]
fn bound_socket_enforces_permissions_symlink_safety_and_stale_cleanup() {
    let (_dir, dir_path) = canonical_tempdir();
    let safe_dir = dir_path.join("restricted");
    fs::create_dir(&safe_dir).unwrap();
    fs::set_permissions(&safe_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // 1. OwnerOnly enforces 0600 on socket and cleans up on drop.
    let sock_path = safe_dir.join("approver.sock");
    {
        let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
        let mode = fs::symlink_metadata(&sock_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o600);
        assert!(matches!(
            BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap_err(),
            DaemonError::SocketAlreadyActive(_)
        ));
        drop(bound);
    }
    assert!(!sock_path.exists());

    // 2. Stale socket (left behind without listener) is safely cleaned up.
    {
        let raw_listener = UnixListener::bind(&sock_path).unwrap();
        drop(raw_listener);
    }
    assert!(sock_path.exists());
    {
        let _bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
    }

    // 3. Symlink at socket path is refused without unlinking target.
    let victim = safe_dir.join("victim.txt");
    fs::write(&victim, "keep").unwrap();
    let link_sock = safe_dir.join("link.sock");
    symlink(&victim, &link_sock).unwrap();
    assert!(matches!(
        BoundSocket::bind(&link_sock, SocketMode::OwnerOnly).unwrap_err(),
        DaemonError::SymlinkRejected(_)
    ));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");

    // 4. Existing regular file at socket path is refused without deleting it.
    assert!(matches!(
        BoundSocket::bind(&victim, SocketMode::OwnerOnly).unwrap_err(),
        DaemonError::PathExistsNotSocket(_)
    ));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");

    // 5. Symlinked parent directory is refused.
    let link_dir = dir_path.join("link_dir");
    symlink(&safe_dir, &link_dir).unwrap();
    assert!(matches!(
        BoundSocket::bind(&link_dir.join("s.sock"), SocketMode::OwnerOnly).unwrap_err(),
        DaemonError::SymlinkRejected(_)
    ));

    // 6. Overly permissive parent directory rejected for OwnerOnly; 0750 allowed for GroupControlled.
    let group_dir = dir_path.join("group_dir");
    fs::create_dir(&group_dir).unwrap();
    fs::set_permissions(&group_dir, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        BoundSocket::bind(&group_dir.join("s.sock"), SocketMode::OwnerOnly).unwrap_err(),
        DaemonError::InsecureParentPermissions { mode: 0o750, .. }
    ));
    {
        let group_sock = group_dir.join("s.sock");
        let _bound = BoundSocket::bind(&group_sock, SocketMode::GroupControlled).unwrap();
        let mode = fs::symlink_metadata(&group_sock)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o660);
    }
    fs::set_permissions(&group_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        BoundSocket::bind(&group_dir.join("s.sock"), SocketMode::GroupControlled).unwrap_err(),
        DaemonError::InsecureParentPermissions { mode: 0o755, .. }
    ));
}

#[test]
fn client_rejects_tampered_mismatched_and_empty_responses_from_rogue_socket() {
    let dir = tempfile::TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x77; 32]);
    let draft = draft_for(&kp.key_id());
    let canonical = try_render_canonical(&parse_mandate(&draft).unwrap()).unwrap();
    let req = SignRequest {
        mandate_text: draft,
        valid_from: 100,
        valid_until: 200,
        anchor_id: Some("expected-anchor".to_string()),
    };

    // Case 1: tampered signature.
    let mut tampered = sign_mandate_with(&kp, &canonical, "expected-anchor", 100, 200).unwrap();
    tampered.signature_hex = "00".repeat(64);
    let sock1 = dir.path().join("rogue1.sock");
    let l1 = UnixListener::bind(&sock1).unwrap();
    let t1 = thread::spawn(move || {
        let (stream, _) = l1.accept().unwrap();
        let mut r = FrameReader::new(BufReader::new(&stream));
        let _ = r.read_frame_line(MAX_FRAME_BYTES).unwrap();
        let mut w = &stream;
        write_frame(
            &mut w,
            &SignResponse::Approved {
                signed_mandate: tampered,
            },
            MAX_FRAME_BYTES,
        )
        .unwrap();
    });
    assert!(matches!(
        request_and_verify_signature(
            &sock1,
            &req,
            &AnchorRegistry::default_registry(),
            Some(Duration::from_secs(5))
        )
        .unwrap_err(),
        ClientError::VerificationFailed(_)
    ));
    t1.join().unwrap();

    // Case 2: validly signed but mismatched anchor_id.
    let wrong_anchor = sign_mandate_with(&kp, &canonical, "other-anchor", 100, 200).unwrap();
    let sock2 = dir.path().join("rogue2.sock");
    let l2 = UnixListener::bind(&sock2).unwrap();
    let t2 = thread::spawn(move || {
        let (stream, _) = l2.accept().unwrap();
        let mut r = FrameReader::new(BufReader::new(&stream));
        let _ = r.read_frame_line(MAX_FRAME_BYTES).unwrap();
        let mut w = &stream;
        write_frame(
            &mut w,
            &SignResponse::Approved {
                signed_mandate: wrong_anchor,
            },
            MAX_FRAME_BYTES,
        )
        .unwrap();
    });
    assert!(matches!(
        request_and_verify_signature(
            &sock2,
            &req,
            &AnchorRegistry::default_registry(),
            Some(Duration::from_secs(5))
        )
        .unwrap_err(),
        ClientError::VerificationFailed(_)
    ));
    t2.join().unwrap();

    // Case 3: immediate close -> EmptyResponse.
    let sock3 = dir.path().join("rogue3.sock");
    let l3 = UnixListener::bind(&sock3).unwrap();
    let t3 = thread::spawn(move || {
        let (stream, _) = l3.accept().unwrap();
        let mut r = FrameReader::new(BufReader::new(&stream));
        let _ = r.read_frame_line(MAX_FRAME_BYTES).unwrap();
    });
    assert!(matches!(
        request_and_verify_signature(
            &sock3,
            &req,
            &AnchorRegistry::default_registry(),
            Some(Duration::from_secs(5))
        )
        .unwrap_err(),
        ClientError::EmptyResponse
    ));
    t3.join().unwrap();
}

#[test]
fn bound_socket_rejects_bad_paths_and_daemon_new_rejects_bad_config() {
    let (_dir, dir_path) = canonical_tempdir();
    let regular_file = dir_path.join("not_a_dir");
    fs::write(&regular_file, "file").unwrap();

    assert!(matches!(
        BoundSocket::bind(std::path::Path::new(""), SocketMode::OwnerOnly).unwrap_err(),
        DaemonError::InvalidConfig(_)
    ));
    assert!(matches!(
        BoundSocket::bind(
            std::path::Path::new("/tmp/bad\n.sock"),
            SocketMode::OwnerOnly
        )
        .unwrap_err(),
        DaemonError::InvalidConfig(_)
    ));
    assert!(matches!(
        BoundSocket::bind(&regular_file.join("s.sock"), SocketMode::OwnerOnly).unwrap_err(),
        DaemonError::NotADirectory(_)
    ));

    let kp = Ed25519Keypair::from_secret_bytes([0x78; 32]);
    let prompt = handfest_approver::prompt::TtyPrompt::new(std::io::Cursor::new(b""), Vec::new());
    let zero_timeout = handfest_approver::daemon::ApproverDaemon::new(
        kp.clone(),
        prompt,
        "local-ed25519",
        Duration::ZERO,
    )
    .unwrap_err();
    assert!(matches!(zero_timeout, DaemonError::InvalidConfig(_)));
    assert!(zero_timeout.to_string().contains("timeout"));

    let prompt2 = handfest_approver::prompt::TtyPrompt::new(std::io::Cursor::new(b""), Vec::new());
    let bad_anchor =
        handfest_approver::daemon::ApproverDaemon::new(kp, prompt2, "", Duration::from_secs(5))
            .unwrap_err();
    assert!(matches!(bad_anchor, DaemonError::InvalidConfig(_)));
}

#[test]
fn client_rejects_mismatched_mandate_window_bad_draft_and_missing_socket() {
    let dir = tempfile::TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x79; 32]);
    let draft = draft_for(&kp.key_id());
    let canonical = try_render_canonical(&parse_mandate(&draft).unwrap()).unwrap();
    let req = SignRequest {
        mandate_text: draft.clone(),
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    };

    // Local invalid draft fails before connecting.
    let bad_draft_req = SignRequest {
        mandate_text: "HANDFEST v1\nBROKEN\n".to_string(),
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    };
    assert!(matches!(
        request_and_verify_signature(
            &dir.path().join("never.sock"),
            &bad_draft_req,
            &AnchorRegistry::default_registry(),
            Some(Duration::from_secs(1)),
        )
        .unwrap_err(),
        ClientError::VerificationFailed(_)
    ));

    // Missing socket -> ClientError::Connect.
    assert!(matches!(
        request_and_verify_signature(
            &dir.path().join("missing.sock"),
            &req,
            &AnchorRegistry::default_registry(),
            Some(Duration::from_secs(1)),
        )
        .unwrap_err(),
        ClientError::Connect { .. }
    ));

    // Mismatched validity window from rogue socket -> VerificationFailed.
    let wrong_window = sign_mandate_with(&kp, &canonical, "local-ed25519", 100, 999).unwrap();
    let sock_w = dir.path().join("wrong_window.sock");
    let lw = UnixListener::bind(&sock_w).unwrap();
    let tw = thread::spawn(move || {
        let (stream, _) = lw.accept().unwrap();
        let mut r = FrameReader::new(BufReader::new(&stream));
        let _ = r.read_frame_line(MAX_FRAME_BYTES).unwrap();
        let mut w = &stream;
        write_frame(
            &mut w,
            &SignResponse::Approved {
                signed_mandate: wrong_window,
            },
            MAX_FRAME_BYTES,
        )
        .unwrap();
    });
    assert!(matches!(
        request_and_verify_signature(
            &sock_w,
            &req,
            &AnchorRegistry::default_registry(),
            Some(Duration::from_secs(5)),
        )
        .unwrap_err(),
        ClientError::VerificationFailed(_)
    ));
    tw.join().unwrap();

    // Mismatched canonical mandate text from rogue socket -> VerificationFailed.
    let other_agent = KeyId::new("ed25519", "d".repeat(64)).unwrap();
    let other_draft = format!(
        "HANDFEST v1\nFROM human \"Valentin\" (key: {})\nTO agent \"Other\" (key: {other_agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/other\"\n",
        kp.key_id()
    );
    let other_canonical = try_render_canonical(&parse_mandate(&other_draft).unwrap()).unwrap();
    let swapped = sign_mandate_with(&kp, &other_canonical, "local-ed25519", 100, 200).unwrap();
    let sock_m = dir.path().join("swapped.sock");
    let lm = UnixListener::bind(&sock_m).unwrap();
    let tm = thread::spawn(move || {
        let (stream, _) = lm.accept().unwrap();
        let mut r = FrameReader::new(BufReader::new(&stream));
        let _ = r.read_frame_line(MAX_FRAME_BYTES).unwrap();
        let mut w = &stream;
        write_frame(
            &mut w,
            &SignResponse::Approved {
                signed_mandate: swapped,
            },
            MAX_FRAME_BYTES,
        )
        .unwrap();
    });
    assert!(matches!(
        request_and_verify_signature(
            &sock_m,
            &req,
            &AnchorRegistry::default_registry(),
            Some(Duration::from_secs(5)),
        )
        .unwrap_err(),
        ClientError::VerificationFailed(_)
    ));
    tm.join().unwrap();
}

#[test]
fn bound_socket_rejects_symlinked_and_non_sticky_world_writable_ancestors() {
    let (_dir, dir_path) = canonical_tempdir();

    // 1. Symlinked ancestor (`/tmp/.../link/sub/approver.sock`) must be rejected.
    let real_parent = dir_path.join("real");
    let real_sub = real_parent.join("sub");
    fs::create_dir_all(&real_sub).unwrap();
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&real_sub, fs::Permissions::from_mode(0o700)).unwrap();

    let link_ancestor = dir_path.join("link");
    symlink(&real_parent, &link_ancestor).unwrap();
    assert!(matches!(
        BoundSocket::bind(
            &link_ancestor.join("sub").join("approver.sock"),
            SocketMode::OwnerOnly,
        )
        .unwrap_err(),
        DaemonError::SymlinkRejected(_)
    ));

    // 2. Non-sticky 0777 ancestor (`/tmp/.../world/sub/approver.sock`) must be rejected
    // even when immediate parent `sub` is strictly 0700.
    let world_ancestor = dir_path.join("world");
    let world_sub = world_ancestor.join("sub");
    fs::create_dir_all(&world_sub).unwrap();
    fs::set_permissions(&world_ancestor, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&world_sub, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        BoundSocket::bind(&world_sub.join("approver.sock"), SocketMode::OwnerOnly).unwrap_err(),
        DaemonError::InsecureParentPermissions { mode: 0o777, .. }
    ));

    // 3. Sticky 1777 ancestor (like `/tmp`) with a strict 0700 immediate parent is allowed.
    let sticky_ancestor = dir_path.join("sticky");
    let sticky_sub = sticky_ancestor.join("sub");
    fs::create_dir_all(&sticky_sub).unwrap();
    fs::set_permissions(&sticky_ancestor, fs::Permissions::from_mode(0o1777)).unwrap();
    fs::set_permissions(&sticky_sub, fs::Permissions::from_mode(0o700)).unwrap();
    let _bound = BoundSocket::bind(&sticky_sub.join("approver.sock"), SocketMode::OwnerOnly)
        .expect("sticky ancestor with 0700 immediate parent should bind");
}

#[test]
fn client_enforces_verify_verifier_postconditions_against_buggy_verifier() {
    struct BuggyAnchorVerifier {
        inner: AnchorRegistry,
    }

    impl AnchorVerifier for BuggyAnchorVerifier {
        fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
            let mut vm = self.inner.verify(signed)?;
            // Buggy verifier returns a mismatched anchor_id in the proof.
            vm.proof.anchor_id = "forged-anchor-id".to_string();
            Ok(vm)
        }
    }

    let dir = tempfile::TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x7a; 32]);
    let draft = draft_for(&kp.key_id());
    let canonical = try_render_canonical(&parse_mandate(&draft).unwrap()).unwrap();
    let req = SignRequest {
        mandate_text: draft,
        valid_from: 100,
        valid_until: 200,
        anchor_id: Some("local-ed25519".to_string()),
    };
    let valid_signed = sign_mandate_with(&kp, &canonical, "local-ed25519", 100, 200).unwrap();

    let sock = dir.path().join("buggy_verifier.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut r = FrameReader::new(BufReader::new(&stream));
        let _ = r.read_frame_line(MAX_FRAME_BYTES).unwrap();
        let mut w = &stream;
        write_frame(
            &mut w,
            &SignResponse::Approved {
                signed_mandate: valid_signed,
            },
            MAX_FRAME_BYTES,
        )
        .unwrap();
    });

    let buggy = BuggyAnchorVerifier {
        inner: AnchorRegistry::default_registry(),
    };
    let err = request_and_verify_signature(&sock, &req, &buggy, Some(Duration::from_secs(5)))
        .unwrap_err();
    server.join().unwrap();
    assert!(matches!(err, ClientError::VerificationFailed(_)));
}

#[test]
fn client_enforces_overall_request_deadline_against_slow_drip_peer() {
    let (_dir, dir_path) = canonical_tempdir();
    let kp = Ed25519Keypair::from_secret_bytes([0x7b; 32]);
    let req = SignRequest {
        mandate_text: draft_for(&kp.key_id()),
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    };

    // Zero timeout must fail closed immediately with a timeout error.
    let zero_err =
        request_signature(&dir_path.join("unused.sock"), &req, Some(Duration::ZERO)).unwrap_err();
    assert!(matches!(
        zero_err,
        ClientError::Protocol(ProtocolError::Io(ref io_err))
            if io_err.kind() == io::ErrorKind::TimedOut
    ));

    // Slow-drip peer writes 10 bytes spaced 25ms apart (250ms total); 80ms overall deadline MUST
    // abort the client in < 200ms with a timeout error.
    let sock = dir_path.join("slow_drip_peer.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        {
            let mut r = FrameReader::new(BufReader::new(&stream));
            let _ = r.read_frame_line(MAX_FRAME_BYTES).unwrap();
        }
        let drip = b"{\"status\":";
        assert_eq!(drip.len(), 10);
        for &byte in drip {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            let _ = stream.flush();
            thread::sleep(Duration::from_millis(25));
        }
    });

    let started = Instant::now();
    let err = request_signature(&sock, &req, Some(Duration::from_millis(80))).unwrap_err();
    let elapsed = started.elapsed();

    server.join().unwrap();
    assert!(
        elapsed < Duration::from_millis(200),
        "slow-drip peer must time out within overall 80ms deadline, elapsed {elapsed:?}"
    );
    match err {
        ClientError::Protocol(ref perr) => {
            assert_eq!(perr.error_code(), ERR_TIMEOUT);
            assert!(
                matches!(
                    perr,
                    ProtocolError::Io(io_err)
                        if matches!(io_err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
                ),
                "expected TimedOut/WouldBlock protocol error, got {perr:?}"
            );
        }
        other => panic!("expected timeout protocol error, got {other:?}"),
    }
}

#[test]
fn client_shared_deadline_bounds_silent_peer_write_plus_read() {
    let (_dir, dir_path) = canonical_tempdir();
    let kp = Ed25519Keypair::from_secret_bytes([0x7c; 32]);
    let req = SignRequest {
        mandate_text: draft_for(&kp.key_id()),
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    };

    let sock = dir_path.join("silent_peer.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        // Hold the connection open without reading or responding longer than the client budget.
        thread::sleep(Duration::from_millis(250));
    });

    let started = Instant::now();
    let err = request_signature(&sock, &req, Some(Duration::from_millis(80))).unwrap_err();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(200),
        "silent peer must time out within shared 80ms budget, elapsed {elapsed:?}"
    );
    match err {
        ClientError::Protocol(ref perr) => {
            assert_eq!(perr.error_code(), ERR_TIMEOUT);
            assert!(matches!(
                perr,
                ProtocolError::Io(io_err)
                    if matches!(io_err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
            ));
        }
        other => panic!("expected timeout protocol error, got {other:?}"),
    }
    server.join().unwrap();
}

#[test]
fn client_rejects_overflowing_timeout_without_hanging() {
    let (_dir, dir_path) = canonical_tempdir();
    let kp = Ed25519Keypair::from_secret_bytes([0x7d; 32]);
    let req = SignRequest {
        mandate_text: draft_for(&kp.key_id()),
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    };

    for huge_timeout in [
        Duration::MAX,
        Duration::from_secs(1 << 54),
        handfest_approver::MAX_TIMEOUT
            .checked_add(Duration::from_secs(1))
            .unwrap(),
    ] {
        let started = Instant::now();
        let err =
            request_signature(&dir_path.join("unused.sock"), &req, Some(huge_timeout)).unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(200),
            "excessive timeout {huge_timeout:?} must fail closed immediately, elapsed {elapsed:?}"
        );
        assert!(
            matches!(
                err,
                ClientError::Protocol(ProtocolError::Io(ref io_err))
                    if io_err.kind() == io::ErrorKind::InvalidInput
            ),
            "expected InvalidInput on timeout {huge_timeout:?}, got {err:?}"
        );
    }
}

#[test]
fn client_enforces_deadline_when_listener_backlog_is_full() {
    let (_dir, dir_path) = canonical_tempdir();
    let kp = Ed25519Keypair::from_secret_bytes([0x7e; 32]);
    let req = SignRequest {
        mandate_text: draft_for(&kp.key_id()),
        valid_from: 100,
        valid_until: 200,
        anchor_id: None,
    };

    let sock = dir_path.join("full_backlog.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    // Fill the kernel accept backlog without exhausting process file descriptors:
    // dropping each connected client stream leaves the server-side socket queued
    // in the listener's accept queue until accept() or listener close.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let fill_sock = sock.clone();
    let filler = thread::spawn(move || {
        let _ = ready_tx.send(());
        while let Ok(stream) = std::os::unix::net::UnixStream::connect(&fill_sock) {
            drop(stream);
            if tx.send(()).is_err() {
                break;
            }
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("backlog filler thread must start");

    let mut queued = 0usize;
    let mut backlog_full = false;
    for _ in 0..8192 {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(()) => queued += 1,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if queued > 0 => {
                backlog_full = true;
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    assert!(
        backlog_full,
        "test must fill listener backlog before verifying connect deadline (queued={queued})"
    );

    let started = Instant::now();
    let err = request_signature(&sock, &req, Some(Duration::from_millis(60))).unwrap_err();
    let elapsed = started.elapsed();

    // Drop listener and receiver so all blocked connects wake up and exit cleanly.
    drop(listener);
    drop(rx);
    let _ = filler.join();

    assert!(
        elapsed < Duration::from_millis(250),
        "connect against full backlog must abort within 60ms deadline, elapsed {elapsed:?}"
    );
    assert!(
        matches!(
            err,
            ClientError::Connect { ref source, .. } if source.kind() == io::ErrorKind::TimedOut
        ),
        "expected ClientError::Connect(TimedOut) on full backlog, got {err:?}"
    );
}
