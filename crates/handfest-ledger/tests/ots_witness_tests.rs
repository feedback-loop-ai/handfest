#![cfg(feature = "witness-ots")]

use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

use handfest_core::ast::{parse_rfc3339_utc, ActorDecl, KeyId, MandateId, MAX_RFC3339_TIMESTAMP};
use handfest_core::base64::encode_standard;
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::gate::{
    ActionRequest, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate, VerifiedRevocation,
};
use handfest_core::revocation::{RevocationAst, RevocationTarget};
use handfest_core::{ActorKind, AssuranceLevel, Verdict};
use handfest_ledger::{
    default_checkpoint_sidecar_path, AnchoredLedger, CheckpointWitness, CommandOutput,
    CommandRunner, LedgerCheckpoint, LedgerError, OtsWitness, ReceiptLedger, SqliteLedger,
    SystemCommandRunner, WitnessError, WitnessPolicy, WitnessProof, WitnessRegistry,
    MAX_OTS_PROOF_BYTES, OTS_PROOF_MAGIC, OTS_WITNESS_KIND,
};
use tempfile::TempDir;

const NOW: i64 = 1_764_000_000;

#[derive(Debug, Clone)]
struct RecordedCall {
    program: String,
    args: Vec<String>,
    digest_bytes: Option<Vec<u8>>,
    ots_bytes: Option<Vec<u8>>,
    temp_dir: PathBuf,
}

enum MockBehavior {
    StampWrite(Vec<u8>),
    StampNoFile,
    VerifyOk,
    FailExit(Option<i32>, String),
    FailIo(String),
}

struct MockOtsRunner {
    behaviors: RefCell<Vec<MockBehavior>>,
    calls: RefCell<Vec<RecordedCall>>,
}

impl MockOtsRunner {
    fn new(mut behaviors: Vec<MockBehavior>) -> Self {
        behaviors.reverse();
        Self {
            behaviors: RefCell::new(behaviors),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<RecordedCall> {
        self.calls.borrow().clone()
    }
}

impl CommandRunner for MockOtsRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, WitnessError> {
        assert!(stdin.is_empty(), "ots witness should pass empty stdin");
        let behavior = self
            .behaviors
            .borrow_mut()
            .pop()
            .expect("unexpected extra CommandRunner invocation");

        let (digest_path, ots_path) = match args {
            ["stamp", digest] => (
                PathBuf::from(digest),
                PathBuf::from(format!("{digest}.ots")),
            ),
            ["verify", "-f", digest, ots] => (PathBuf::from(digest), PathBuf::from(ots)),
            other => panic!("unexpected ots args: {other:?}"),
        };
        let digest_bytes = fs::read(&digest_path).ok();
        let ots_bytes = fs::read(&ots_path).ok();
        let temp_dir = digest_path.parent().expect("temp dir parent").to_path_buf();

        self.calls.borrow_mut().push(RecordedCall {
            program: program.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            digest_bytes,
            ots_bytes,
            temp_dir,
        });

        match behavior {
            MockBehavior::StampWrite(bytes) => {
                fs::write(&ots_path, bytes).expect("write fake ots proof");
                Ok(CommandOutput {
                    stdout: b"stamped\n".to_vec(),
                    stderr: Vec::new(),
                })
            }
            MockBehavior::StampNoFile => Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            MockBehavior::VerifyOk => Ok(CommandOutput {
                stdout: b"Success! Bitcoin block 900000 attests existence\n".to_vec(),
                stderr: Vec::new(),
            }),
            MockBehavior::FailExit(status, stderr) => Err(WitnessError::CommandFailed {
                program: program.to_string(),
                status,
                stderr,
            }),
            MockBehavior::FailIo(detail) => Err(WitnessError::CommandIo {
                program: program.to_string(),
                detail,
            }),
        }
    }
}

fn make_valid_ots_proof(tag: u8) -> Vec<u8> {
    let mut bytes = OTS_PROOF_MAGIC.to_vec();
    bytes.push(0x01); // version
    bytes.push(0x08); // sha256 hash-op
    bytes.extend_from_slice(&[tag; 32]); // 32-byte digest
    bytes.push(0x00); // attestation/op byte
    bytes
}

fn sample_checkpoint() -> LedgerCheckpoint {
    LedgerCheckpoint {
        receipt_seq: 3,
        receipt_hash: [0xab; 32],
        revocation_seq: 1,
        revocation_tip_hash: Some([0xcd; 32]),
        timestamp: NOW,
    }
}

#[test]
fn ots_witness_stamps_only_32_byte_digest_verifies_and_cleans_up_temp_files() {
    let fake_ots_proof = make_valid_ots_proof(0xaa);
    let runner = MockOtsRunner::new(vec![
        MockBehavior::StampWrite(fake_ots_proof.to_vec()),
        MockBehavior::VerifyOk,
    ]);
    let witness = OtsWitness::with_runner(runner)
        .with_anchored_at(NOW + 5)
        .unwrap();
    assert_eq!(witness.witness_kind(), OTS_WITNESS_KIND);

    let cp = sample_checkpoint();
    let proof = witness.anchor(&cp).expect("ots anchor succeeds");
    assert_eq!(proof.witness_kind, "ots");
    assert_eq!(proof.checkpoint_digest_hex, cp.checkpoint_digest_hex());
    assert_eq!(proof.proof_bytes_b64, encode_standard(&fake_ots_proof));
    assert_eq!(proof.anchored_at, NOW + 5);

    witness.verify(&cp, &proof).expect("ots verify succeeds");

    // Inspect recorded calls via a second test using Rc/RefCell or direct verification.
    let shared_runner = std::rc::Rc::new(MockOtsRunner::new(vec![
        MockBehavior::StampWrite(fake_ots_proof.to_vec()),
        MockBehavior::VerifyOk,
    ]));
    struct RcRunner(std::rc::Rc<MockOtsRunner>);
    impl CommandRunner for RcRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            stdin: &[u8],
        ) -> Result<CommandOutput, WitnessError> {
            self.0.run(program, args, stdin)
        }
    }

    let witness2 = OtsWitness::with_runner(RcRunner(shared_runner.clone()))
        .with_program("custom-ots")
        .unwrap()
        .with_anchored_at(NOW + 10)
        .unwrap();
    let proof2 = witness2.anchor(&cp).unwrap();
    witness2.verify(&cp, &proof2).unwrap();

    let calls = shared_runner.calls();
    assert_eq!(calls.len(), 2);

    // Call 0: `ots stamp <digest_file>` with exact 32-byte checkpoint_digest
    assert_eq!(calls[0].program, "custom-ots");
    assert_eq!(calls[0].args.len(), 2);
    assert_eq!(calls[0].args[0], "stamp");
    assert_eq!(
        calls[0].digest_bytes.as_deref(),
        Some(cp.checkpoint_digest().as_slice())
    );
    assert_eq!(calls[0].digest_bytes.as_ref().unwrap().len(), 32);
    assert!(
        !calls[0].temp_dir.exists(),
        "stamp temp dir must be cleaned up on drop"
    );

    // Call 1: `ots verify -f <digest_file> <ots_file>` with exact 32-byte digest & decoded proof
    assert_eq!(calls[1].program, "custom-ots");
    assert_eq!(calls[1].args.len(), 4);
    assert_eq!(calls[1].args[0], "verify");
    assert_eq!(calls[1].args[1], "-f");
    assert_eq!(
        calls[1].digest_bytes.as_deref(),
        Some(cp.checkpoint_digest().as_slice())
    );
    assert_eq!(
        calls[1].ots_bytes.as_deref(),
        Some(fake_ots_proof.as_slice())
    );
    assert!(
        !calls[1].temp_dir.exists(),
        "verify temp dir must be cleaned up on drop"
    );
}

#[test]
fn ots_witness_fails_closed_on_all_error_and_adversarial_paths() {
    let cp = sample_checkpoint();

    // Config validation: empty/control program and invalid timestamp rejected.
    assert!(matches!(
        OtsWitness::new().with_program(""),
        Err(WitnessError::InvalidConfig(_))
    ));
    assert!(matches!(
        OtsWitness::new().with_program("ots\n--bad"),
        Err(WitnessError::InvalidConfig(_))
    ));
    assert!(matches!(
        OtsWitness::new().with_anchored_at(MAX_RFC3339_TIMESTAMP + 1),
        Err(WitnessError::InvalidConfig(_))
    ));

    // Stamp non-zero exit fails closed and cleans up temp dir.
    let fail_runner = std::rc::Rc::new(MockOtsRunner::new(vec![MockBehavior::FailExit(
        Some(1),
        "calendar unreachable".to_string(),
    )]));
    struct RcRunner(std::rc::Rc<MockOtsRunner>);
    impl CommandRunner for RcRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            stdin: &[u8],
        ) -> Result<CommandOutput, WitnessError> {
            self.0.run(program, args, stdin)
        }
    }
    let w_fail = OtsWitness::with_runner(RcRunner(fail_runner.clone()));
    let err = w_fail.anchor(&cp).unwrap_err();
    assert!(matches!(
        err,
        WitnessError::CommandFailed {
            status: Some(1),
            ..
        }
    ));
    assert!(
        !fail_runner.calls()[0].temp_dir.exists(),
        "temp dir must be cleaned up even when ots stamp fails"
    );

    // Spawn I/O failure.
    let w_io = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::FailIo(
        "No such file or directory".to_string(),
    )]));
    assert!(matches!(
        w_io.anchor(&cp),
        Err(WitnessError::CommandIo { .. })
    ));

    // Missing `.ots` output file.
    let w_missing = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::StampNoFile]));
    assert!(matches!(
        w_missing.anchor(&cp),
        Err(WitnessError::Backend(_))
    ));

    // Empty `.ots` output file.
    let w_empty = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::StampWrite(
        Vec::new(),
    )]));
    assert!(matches!(
        w_empty.anchor(&cp),
        Err(WitnessError::InvalidProof(_))
    ));

    // Invalid-magic 1-byte garbage `.ots` output rejected by anchor.
    let w_garbage = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::StampWrite(
        b"x".to_vec(),
    )]));
    assert!(matches!(
        w_garbage.anchor(&cp),
        Err(WitnessError::InvalidProof(_))
    ));

    // Truncated 31-byte magic-only and 64-byte header-without-attestation `.ots` blobs rejected.
    let w_magic_only = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::StampWrite(
        OTS_PROOF_MAGIC.to_vec(),
    )]));
    assert!(matches!(
        w_magic_only.anchor(&cp),
        Err(WitnessError::InvalidProof(ref msg)) if msg.contains("truncated")
    ));
    let mut header_no_attest = OTS_PROOF_MAGIC.to_vec();
    header_no_attest.extend_from_slice(&[0x01, 0x08]);
    header_no_attest.extend_from_slice(&[0x11; 31]); // magic(31) + 33 = 64 bytes (still too short)
    let w_short = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::StampWrite(
        header_no_attest,
    )]));
    assert!(matches!(
        w_short.anchor(&cp),
        Err(WitnessError::InvalidProof(ref msg)) if msg.contains("truncated")
    ));

    // Oversized `.ots` output file (> MAX_OTS_PROOF_BYTES).
    let mut oversized = OTS_PROOF_MAGIC.to_vec();
    oversized.resize(MAX_OTS_PROOF_BYTES + 1, 0x42u8);
    let w_big = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::StampWrite(
        oversized,
    )]));
    assert!(matches!(
        w_big.anchor(&cp),
        Err(WitnessError::InvalidProof(_))
    ));
}

#[test]
fn ots_witness_verify_failure_modes_fail_closed() {
    let cp = sample_checkpoint();
    let oversized = vec![0x42u8; MAX_OTS_PROOF_BYTES + 1];
    // Verify failure modes.
    let w_verify_fail = OtsWitness::with_runner(MockOtsRunner::new(vec![MockBehavior::FailExit(
        Some(1),
        "attestation mismatch".to_string(),
    )]));
    let valid_magic_proof = make_valid_ots_proof(0xbb);
    let valid_proof = WitnessProof {
        witness_kind: "ots".to_string(),
        checkpoint_digest_hex: cp.checkpoint_digest_hex(),
        proof_bytes_b64: encode_standard(&valid_magic_proof),
        anchored_at: NOW,
    };
    assert!(matches!(
        w_verify_fail.verify(&cp, &valid_proof),
        Err(WitnessError::CommandFailed {
            status: Some(1),
            ..
        })
    ));

    // Invalid-magic and truncated magic-only proofs passed to verify fail before running ots.
    let w_no_calls = OtsWitness::with_runner(MockOtsRunner::new(vec![]));
    let bad_magic_proof = WitnessProof {
        proof_bytes_b64: encode_standard(b"not-an-ots-header"),
        ..valid_proof.clone()
    };
    assert!(matches!(
        w_no_calls.verify(&cp, &bad_magic_proof),
        Err(WitnessError::InvalidProof(_))
    ));
    let truncated_magic_proof = WitnessProof {
        proof_bytes_b64: encode_standard(OTS_PROOF_MAGIC),
        ..valid_proof.clone()
    };
    assert!(matches!(
        w_no_calls.verify(&cp, &truncated_magic_proof),
        Err(WitnessError::InvalidProof(ref msg)) if msg.contains("truncated")
    ));

    // Oversized proof passed to verify fails before running ots.
    let big_proof = WitnessProof {
        proof_bytes_b64: encode_standard(&oversized),
        ..valid_proof.clone()
    };
    assert!(matches!(
        w_no_calls.verify(&cp, &big_proof),
        Err(WitnessError::InvalidProof(_))
    ));

    // Wrong witness kind & wrong digest fail before running ots.
    let wrong_kind = WitnessProof {
        witness_kind: "http-log".to_string(),
        ..valid_proof.clone()
    };
    assert!(matches!(
        w_no_calls.verify(&cp, &wrong_kind),
        Err(WitnessError::KindMismatch { .. })
    ));

    let wrong_digest = WitnessProof {
        checkpoint_digest_hex: "0".repeat(64),
        ..valid_proof
    };
    assert!(matches!(
        w_no_calls.verify(&cp, &wrong_digest),
        Err(WitnessError::DigestMismatch { .. })
    ));
}

#[test]
fn anchored_sqlite_ledger_with_ots_witness_and_default_registry() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("ots_anchored.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);

    let root_key =
        KeyId::parse("ed25519:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let actor_key =
        KeyId::parse("ed25519:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();
    let raw = format!(
        "HANDFEST v1\nFROM human \"alice\" (key: {root_key})\nTO agent \"bot\" (key: {actor_key})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\n"
    );
    let ast = parse_mandate(&raw).unwrap();
    let _ = render_canonical(&ast);
    let verified = vec![VerifiedMandate {
        ast,
        proof: VerifiedAnchorProof {
            anchor_id: "local-ed25519".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: root_key.clone(),
            actor_kind: ActorKind::Human,
            valid_from: NOW - 100,
            valid_until: NOW + 10_000,
        },
    }];
    let req = ActionRequest {
        actor_key,
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/repo".to_string(),
    };
    let rev = VerifiedRevocation {
        ast: RevocationAst::new(
            ActorDecl::new(
                ActorKind::Human,
                "alice".to_string(),
                root_key.clone(),
                Default::default(),
            )
            .unwrap(),
            RevocationTarget::Mandate(MandateId::sha256(b"target")),
            NOW + 50,
            Some("secret-revocation-reason".to_string()),
        )
        .unwrap(),
        proof: VerifiedAnchorProof {
            anchor_id: "local-ed25519".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: root_key,
            actor_kind: ActorKind::Human,
            valid_from: NOW,
            valid_until: NOW + 10_000,
        },
    };

    let proof_1 = make_valid_ots_proof(0x01);
    let proof_2 = make_valid_ots_proof(0x02);
    let runner = MockOtsRunner::new(vec![
        MockBehavior::StampWrite(proof_1),
        MockBehavior::StampWrite(proof_2),
        MockBehavior::VerifyOk,
        MockBehavior::VerifyOk,
    ]);
    let witness = OtsWitness::with_runner(runner)
        .with_anchored_at(parse_rfc3339_utc("2026-11-24T18:00:00Z").unwrap())
        .unwrap();
    let sql = SqliteLedger::open(&db_path).unwrap();
    let mut anchored =
        AnchoredLedger::with_checkpoint_file(sql, witness, WitnessPolicy::SyncStrict, &sidecar)
            .unwrap();

    let (verdict, _) = anchored
        .evaluate_and_record(&verified, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert_eq!(verdict, Verdict::Permit);
    anchored.record_revocation(&rev, "deadbeef").unwrap();

    assert_eq!(anchored.verify_witness_checkpoints().unwrap(), 2);

    // WitnessRegistry::with_defaults() registers `"ots"` when witness-ots is enabled.
    let reg = WitnessRegistry::with_defaults();
    assert!(reg.contains("ots"));
}

#[test]
fn system_command_runner_and_error_display_behave_cleanly() {
    // Verify SystemCommandRunner error handling directly.
    let sys = SystemCommandRunner;
    assert!(matches!(
        sys.run("definitely-nonexistent-handfest-ots-bin-xyz", &[], &[]),
        Err(WitnessError::CommandIo { .. })
    ));
    #[cfg(unix)]
    {
        assert!(sys.run("/bin/true", &[], &[]).is_ok());
        assert!(matches!(
            sys.run("/bin/false", &[], &[]),
            Err(WitnessError::CommandFailed {
                status: Some(1),
                ..
            })
        ));
    }

    // Also verify default OtsWitness::default() constructs cleanly.
    let default_ots = OtsWitness::default();
    assert_eq!(default_ots.witness_kind(), OTS_WITNESS_KIND);

    // LedgerError::Witness Display + source coverage.
    let le = LedgerError::from(WitnessError::VerificationFailed("bad".to_string()));
    assert!(le.to_string().contains("witness error"));
    assert!(std::error::Error::source(&le).is_some());
}
