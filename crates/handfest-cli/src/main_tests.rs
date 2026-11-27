use super::*;

#[test]
fn classify_existing_ledger_open_error_maps_all_variants() {
    assert_eq!(
        classify_existing_ledger_open_error(&LedgerError::NotFound("missing".into())),
        "missing_ledger"
    );
    assert_eq!(
        classify_existing_ledger_open_error(&LedgerError::Integrity("bad".into())),
        "invalid_ledger"
    );
    assert_eq!(
        classify_existing_ledger_open_error(&LedgerError::Storage("cantopen".into())),
        "storage_error"
    );
    let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    assert_eq!(
        classify_existing_ledger_open_error(&LedgerError::Json(json_err)),
        "storage_error"
    );
    assert_eq!(
        classify_existing_ledger_open_error(&LedgerError::QuotaAccounting("overflow".into())),
        "storage_error"
    );
    assert_eq!(
        classify_existing_ledger_open_error(&LedgerError::Witness(
            handfest_ledger::WitnessError::Backend("offline".into())
        )),
        "witness_error"
    );
}

#[test]
fn cmd_audit_with_registry_verifies_witness_and_detects_rollback() {
    use handfest_core::ast::parse_rfc3339_utc;
    use handfest_core::base64::encode_standard;
    use handfest_core::cnl::parse_mandate;
    use handfest_core::gate::VerifiedFacts;
    use handfest_ledger::{
        default_checkpoint_sidecar_path, AnchoredLedger, CheckpointWitness, LedgerCheckpoint,
        ReceiptLedger, WitnessError, WitnessPolicy, WitnessProof,
    };

    #[derive(Clone)]
    struct StubMockWitness;
    impl CheckpointWitness for StubMockWitness {
        fn witness_kind(&self) -> &str {
            "mock"
        }
        fn anchor(&self, cp: &LedgerCheckpoint) -> Result<WitnessProof, WitnessError> {
            Ok(WitnessProof {
                witness_kind: "mock".to_string(),
                checkpoint_digest_hex: cp.checkpoint_digest_hex(),
                proof_bytes_b64: encode_standard(&cp.checkpoint_digest()),
                anchored_at: cp.timestamp,
            })
        }
        fn verify(&self, cp: &LedgerCheckpoint, proof: &WitnessProof) -> Result<(), WitnessError> {
            let expected = encode_standard(&cp.checkpoint_digest());
            if proof.proof_bytes_b64 == expected {
                Ok(())
            } else {
                Err(WitnessError::VerificationFailed("bad proof".to_string()))
            }
        }
    }

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("audit_witness.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);

    let root_kp = Ed25519Keypair::from_secret_bytes([0x11; 32]);
    let actor_kp = Ed25519Keypair::from_secret_bytes([0x22; 32]);
    let now = parse_rfc3339_utc("2026-11-24T18:00:00Z").unwrap();
    let raw = format!(
        "HANDFEST v1\nFROM human \"alice\" (key: {})\nTO agent \"bot\" (key: {})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\n",
        root_kp.key_id(),
        actor_kp.key_id()
    );
    let canonical = handfest_core::cnl::render_canonical(&parse_mandate(&raw).unwrap());
    let signed = root_kp
        .sign_mandate(&canonical, "local-ed25519", now - 60, now + 3600)
        .unwrap();
    let verified = handfest_anchors::verify_chain(&[signed]).unwrap();
    let req = ActionRequest {
        actor_key: actor_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };

    let sql = SqliteLedger::open(&db_path).unwrap();
    let mut anchored = AnchoredLedger::with_checkpoint_file(
        sql,
        StubMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    let (verdict, _) = anchored
        .evaluate_and_record(&verified, &req, &VerifiedFacts::new(), now)
        .unwrap();
    assert_eq!(verdict, Verdict::Permit);
    drop(anchored);

    let sidecar_raw = fs::read_to_string(&sidecar).unwrap();
    let stored: handfest_ledger::StoredCheckpoint =
        serde_json::from_str(sidecar_raw.lines().last().unwrap()).unwrap();

    let mut reg = handfest_ledger::WitnessRegistry::new();
    reg.register(StubMockWitness).unwrap();
    assert_eq!(
        crate::witness::cmd_audit_with_registry(&db_path, None, true, None, &reg).unwrap(),
        ExitCode::SUCCESS
    );
    assert_eq!(
        crate::witness::cmd_audit_with_registry(
            &db_path,
            Some(&actor_kp.key_id().to_string()),
            true,
            Some(&stored.record_hash),
            &reg,
        )
        .unwrap(),
        ExitCode::SUCCESS
    );

    // --expected-checkpoint without --verify-witness is rejected.
    let err = crate::witness::cmd_audit_with_registry(
        &db_path,
        None,
        false,
        Some(&stored.record_hash),
        &reg,
    )
    .unwrap_err();
    assert!(err.contains("--expected-checkpoint requires --verify-witness"));

    // Wrong expected checkpoint head fails closed with structured code.
    let wrong_head = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        crate::witness::cmd_audit_with_registry(&db_path, None, true, Some(&wrong_head), &reg)
            .unwrap(),
        ExitCode::FAILURE
    );

    // Unknown witness kind in empty registry fails closed with structured code.
    let empty_reg = handfest_ledger::WitnessRegistry::new();
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let kind_err =
        crate::witness::audit_snapshot_with_witness(&ro, &db_path, None, &empty_reg, None)
            .unwrap_err();
    assert_eq!(kind_err.code, "unsupported_witness_kind");
    assert!(
        kind_err.message.contains("unsupported witness kind 'mock'"),
        "got: {}",
        kind_err.message
    );
    assert_eq!(
        crate::witness::cmd_audit_with_registry(&db_path, None, true, None, &empty_reg).unwrap(),
        ExitCode::FAILURE
    );

    // Missing sidecar fails closed with structured code.
    fs::remove_file(&sidecar).unwrap();
    let missing_err =
        crate::witness::audit_snapshot_with_witness(&ro, &db_path, None, &reg, None).unwrap_err();
    assert_eq!(missing_err.code, "missing_sidecar");
    assert!(
        missing_err.message.contains("not found"),
        "got: {}",
        missing_err.message
    );
    assert_eq!(
        crate::witness::cmd_audit_with_registry(&db_path, None, true, None, &reg).unwrap(),
        ExitCode::FAILURE
    );
}

#[test]
fn classify_witness_audit_error_maps_all_variants() {
    use crate::witness::classify_witness_audit_error;
    use handfest_ledger::WitnessError;

    assert_eq!(
        classify_witness_audit_error(&LedgerError::NotFound("missing".into())),
        "missing_sidecar"
    );
    assert_eq!(
        classify_witness_audit_error(&LedgerError::Integrity("rollback".into())),
        "integrity_or_rollback_mismatch"
    );
    assert_eq!(
        classify_witness_audit_error(&LedgerError::Witness(WitnessError::DigestMismatch {
            expected: "aa".into(),
            actual: "bb".into(),
        })),
        "digest_mismatch"
    );
    assert_eq!(
        classify_witness_audit_error(&LedgerError::Witness(WitnessError::UnsupportedWitnessKind(
            "custom".into()
        ))),
        "unsupported_witness_kind"
    );
    assert_eq!(
        classify_witness_audit_error(&LedgerError::Witness(WitnessError::VerificationFailed(
            "bad".into()
        ))),
        "proof_verification_failed"
    );
    assert_eq!(
        classify_witness_audit_error(&LedgerError::Witness(WitnessError::CommandFailed {
            program: "ots".into(),
            status: Some(1),
            stderr: "err".into(),
        })),
        "proof_verification_failed"
    );
    assert_eq!(
        classify_witness_audit_error(&LedgerError::Witness(WitnessError::InvalidProof(
            "truncated".into()
        ))),
        "invalid_checkpoint_or_proof"
    );
    assert_eq!(
        classify_witness_audit_error(&LedgerError::Storage("io".into())),
        "storage_error"
    );

    use crate::witness::classify_ledger_open_audit_error;
    assert_eq!(
        classify_ledger_open_audit_error(&LedgerError::NotFound("missing".into())),
        "missing_ledger"
    );
    assert_eq!(
        classify_ledger_open_audit_error(&LedgerError::Integrity("corrupt".into())),
        "invalid_or_corrupt_ledger"
    );
    assert_eq!(
        classify_ledger_open_audit_error(&LedgerError::Storage("io".into())),
        "storage_error"
    );
    assert_eq!(
        classify_ledger_open_audit_error(&LedgerError::QuotaAccounting("overflow".into())),
        "storage_error"
    );
    assert_eq!(
        classify_ledger_open_audit_error(&LedgerError::Witness(WitnessError::InvalidProof(
            "bad".into()
        ))),
        "invalid_checkpoint_or_proof"
    );
}

#[test]
fn resolve_signer_loads_ed25519_and_rejects_bad_inputs() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let kp = Ed25519Keypair::from_secret_bytes([0x5a; 32]);
    let key_path = dir.path().join("signer.key.json");
    let key_json = serde_json::to_string_pretty(&kp.to_key_file()).unwrap();
    fs::write(&key_path, &key_json).unwrap();

    let signer = resolve_signer(&SignerConfig::LocalEd25519 {
        key_path: key_path.clone(),
    })
    .expect("resolve valid Ed25519 signer");
    assert_eq!(signer.key_id(), kp.key_id());
    assert_eq!(
        signer.assurance(),
        handfest_anchors::AssuranceLevel::LocalKey
    );

    // Missing file fails cleanly.
    let missing_err = resolve_signer(&SignerConfig::LocalEd25519 {
        key_path: dir.path().join("missing.json"),
    })
    .err()
    .expect("missing key file must fail");
    assert!(missing_err.contains("failed to read"));

    // Malformed JSON fails cleanly.
    let bad_json_path = dir.path().join("bad.json");
    fs::write(&bad_json_path, "{").unwrap();
    let json_err = resolve_signer(&SignerConfig::LocalEd25519 {
        key_path: bad_json_path,
    })
    .err()
    .expect("invalid JSON must fail");
    assert!(json_err.contains("invalid key file JSON"));

    // Key ID mismatch fails cleanly.
    let mut mismatch_file = kp.to_key_file();
    mismatch_file.key_id = format!("ed25519:{}", "0".repeat(64));
    let mismatch_path = dir.path().join("mismatch.json");
    fs::write(
        &mismatch_path,
        serde_json::to_string_pretty(&mismatch_file).unwrap(),
    )
    .unwrap();
    let mismatch_err = resolve_signer(&SignerConfig::LocalEd25519 {
        key_path: mismatch_path,
    })
    .err()
    .expect("mismatched key_id must fail");
    assert!(mismatch_err.contains("failed to load Ed25519 key"));
}

#[test]
fn sign_canonical_with_signer_accepts_non_ed25519_boxed_signer() {
    struct StubHardwareSigner(KeyId);

    impl MandateSigner for StubHardwareSigner {
        fn key_id(&self) -> KeyId {
            self.0.clone()
        }

        fn assurance(&self) -> handfest_anchors::AssuranceLevel {
            handfest_anchors::AssuranceLevel::Passkey
        }

        fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, handfest_anchors::AnchorError> {
            assert!(!payload.is_empty());
            Ok(vec![0xca, 0xfe, 0xba, 0xbe])
        }
    }

    let hw_key = KeyId::new("passkey", "yk-cli-test").unwrap();
    let agent_key = KeyId::new("ed25519", "1".repeat(64)).unwrap();
    let raw = format!(
        "HANDFEST v1\nFROM human \"Valentin\" (key: {hw_key})\nTO agent \"Bot\" (key: {agent_key})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n"
    );
    let ast = parse_mandate(&raw).unwrap();
    let canonical = try_render_canonical(&ast).unwrap();

    let boxed: Box<dyn MandateSigner> = Box::new(StubHardwareSigner(hw_key.clone()));
    let signed = sign_canonical_with_signer(
        &canonical,
        boxed.as_ref(),
        "2026-11-24T17:00:00Z",
        "2026-11-25T01:00:00Z",
        "yubikey-5",
    )
    .expect("sign with boxed custom MandateSigner");

    assert_eq!(signed.signer_key, hw_key.to_string());
    assert_eq!(signed.assurance, "passkey");
    assert_eq!(signed.anchor_id, "yubikey-5");
    assert_eq!(signed.signature_hex, "cafebabe");

    // Invalid timestamp fails cleanly before signing.
    let bad_ts = sign_canonical_with_signer(
        &canonical,
        boxed.as_ref(),
        "not-a-timestamp",
        "2026-11-25T01:00:00Z",
        "yubikey-5",
    )
    .unwrap_err();
    assert!(bad_ts.contains("invalid --valid-from"));
}

#[test]
fn cli_sign_flags_enforce_mutual_exclusion_and_default_anchor_id() {
    // `--key` alone parses and defaults anchor_id to local-ed25519.
    let parsed_local = Cli::try_parse_from([
        "handfest",
        "sign",
        "--mandate",
        "m.hf",
        "--key",
        "k.json",
        "--valid-from",
        "2026-11-24T17:00:00Z",
        "--valid-until",
        "2026-11-25T01:00:00Z",
    ])
    .expect("parse sign --key");
    match parsed_local.command {
        Commands::Sign {
            key,
            ssh_key,
            anchor_id,
            ..
        } => {
            assert_eq!(key, Some(PathBuf::from("k.json")));
            assert_eq!(ssh_key, None);
            assert_eq!(anchor_id, None);
        }
        other => panic!("unexpected command: {other:?}"),
    }
    assert_eq!(
        SignerConfig::LocalEd25519 {
            key_path: PathBuf::from("k.json")
        }
        .default_anchor_id(),
        "local-ed25519"
    );

    // `--ssh-key` alone parses and defaults anchor_id to yubikey-ssh-sk.
    let parsed_sk = Cli::try_parse_from([
        "handfest",
        "sign",
        "--mandate",
        "m.hf",
        "--ssh-key",
        "id_ed25519_sk.pub",
        "--valid-from",
        "2026-11-24T17:00:00Z",
        "--valid-until",
        "2026-11-25T01:00:00Z",
    ])
    .expect("parse sign --ssh-key");
    match parsed_sk.command {
        Commands::Sign {
            key,
            ssh_key,
            anchor_id,
            ..
        } => {
            assert_eq!(key, None);
            assert_eq!(ssh_key, Some(PathBuf::from("id_ed25519_sk.pub")));
            assert_eq!(anchor_id, None);
        }
        other => panic!("unexpected command: {other:?}"),
    }
    assert_eq!(
        SignerConfig::SshSk {
            key_path: PathBuf::from("id_ed25519_sk.pub")
        }
        .default_anchor_id(),
        "yubikey-ssh-sk"
    );
}

#[test]
fn cli_sign_flags_reject_conflict_or_missing_and_parse_keyid() {
    // Passing both `--key` and `--ssh-key` fails closed.
    let conflict = Cli::try_parse_from([
        "handfest",
        "sign",
        "--mandate",
        "m.hf",
        "--key",
        "k.json",
        "--ssh-key",
        "id_ed25519_sk.pub",
        "--valid-from",
        "2026-11-24T17:00:00Z",
        "--valid-until",
        "2026-11-25T01:00:00Z",
    ])
    .expect_err("passing both --key and --ssh-key must fail");
    assert_eq!(conflict.kind(), clap::error::ErrorKind::ArgumentConflict);

    // Passing neither `--key` nor `--ssh-key` fails closed.
    let neither = Cli::try_parse_from([
        "handfest",
        "sign",
        "--mandate",
        "m.hf",
        "--valid-from",
        "2026-11-24T17:00:00Z",
        "--valid-until",
        "2026-11-25T01:00:00Z",
    ])
    .expect_err("passing neither --key nor --ssh-key must fail");
    assert_eq!(
        neither.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );

    // `keyid` parses all 5 mutually exclusive principal key flags cleanly and rejects missing/conflict.
    let parsed_keyid = Cli::try_parse_from(["handfest", "keyid", "--ssh-key", "id_ed25519_sk.pub"])
        .expect("parse keyid --ssh-key");
    match parsed_keyid.command {
        Commands::Keyid(args) => {
            assert_eq!(args.ssh_key, Some(PathBuf::from("id_ed25519_sk.pub")));
            assert_eq!(args.key, None);
            assert_eq!(args.fido2_cred, None);
            assert_eq!(args.gpg_key, None);
            assert_eq!(args.piv_pubkey, None);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let keyid_missing =
        Cli::try_parse_from(["handfest", "keyid"]).expect_err("keyid with no key flag must fail");
    assert_eq!(
        keyid_missing.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );

    let keyid_conflict = Cli::try_parse_from([
        "handfest",
        "keyid",
        "--key",
        "a.json",
        "--piv-pubkey",
        "b.pem",
    ])
    .expect_err("keyid with two key flags must fail");
    assert_eq!(
        keyid_conflict.kind(),
        clap::error::ErrorKind::ArgumentConflict
    );

    let init_conflict = Cli::try_parse_from([
        "handfest",
        "init",
        "--principal-name",
        "Valentin",
        "--ssh-key",
        "a.pub",
        "--gpg-key",
        "0123456789abcdef0123456789abcdef01234567",
    ])
    .expect_err("init with two key flags must fail");
    assert_eq!(
        init_conflict.kind(),
        clap::error::ErrorKind::ArgumentConflict
    );

    let init_missing = Cli::try_parse_from(["handfest", "init", "--principal-name", "Valentin"])
        .expect_err("init with no key flag must fail");
    assert_eq!(
        init_missing.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn resolve_signer_loads_ssh_sk_pub_and_companion_pub_without_reading_private_key() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
    let mut blob = Vec::new();
    for field in [
        handfest_anchors::SSH_SK_ED25519_SSH_TYPE.as_bytes(),
        sk.verifying_key().as_bytes().as_slice(),
        b"ssh:",
    ] {
        blob.extend_from_slice(&(u32::try_from(field.len()).unwrap()).to_be_bytes());
        blob.extend_from_slice(field);
    }
    let pub_line = format!(
        "{} {} test@yubikey\n",
        handfest_anchors::SSH_SK_ED25519_SSH_TYPE,
        encode_test_b64(&blob)
    );

    let key_handle = dir.path().join("id_ed25519_sk");
    let pub_path = dir.path().join("id_ed25519_sk.pub");
    // Write deliberately unreadable/invalid private key placeholder so we prove it is not read.
    fs::write(
        &key_handle,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nDO-NOT-READ\n",
    )
    .unwrap();
    fs::write(&pub_path, &pub_line).unwrap();

    let expected_key_id = format!(
        "{}:{}",
        handfest_anchors::SSH_SK_ED25519_SCHEME,
        hex::encode(sk.verifying_key().as_bytes())
    );

    let from_pub = resolve_signer(&SignerConfig::SshSk {
        key_path: pub_path.clone(),
    })
    .expect("resolve from .pub");
    assert_eq!(from_pub.key_id().to_string(), expected_key_id);
    assert_eq!(
        from_pub.assurance(),
        handfest_anchors::AssuranceLevel::Passkey
    );

    let from_handle = resolve_signer(&SignerConfig::SshSk {
        key_path: key_handle,
    })
    .expect("resolve from key handle via companion .pub");
    assert_eq!(from_handle.key_id().to_string(), expected_key_id);
    assert_eq!(
        from_handle.assurance(),
        handfest_anchors::AssuranceLevel::Passkey
    );

    // Missing companion .pub fails closed without reading private key.
    let orphan = dir.path().join("orphan_key");
    fs::write(&orphan, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
    let err = resolve_signer(&SignerConfig::SshSk { key_path: orphan })
        .err()
        .expect("missing companion .pub must fail");
    assert!(err.contains("failed to load SSH security key"));
    assert!(err.contains("never reads private key"));
}

fn encode_test_b64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn run_sign_rejects_missing_or_both_key_sources_defensively() {
    for (key, ssh_key) in [
        (None, None),
        (Some(PathBuf::from("a.json")), Some(PathBuf::from("b.pub"))),
    ] {
        let err = run(Cli {
            command: Commands::Sign {
                mandate: PathBuf::from("m.hf"),
                key,
                ssh_key,
                fido2_cred: None,
                fido2_device: None,
                gpg_key: None,
                piv_pubkey: None,
                piv_module: None,
                piv_id: None,
                valid_from: "2026-11-24T17:00:00Z".to_string(),
                valid_until: "2026-11-25T01:00:00Z".to_string(),
                anchor_id: None,
                out: None,
            },
        })
        .expect_err("defensive key source guard must fail closed");
        assert!(err.contains("--key") && err.contains("--ssh-key"));
    }
}

#[test]
fn resolve_signer_supports_ssh_sk_p256_pub_and_companion_handle() {
    let dir = tempfile::TempDir::new().unwrap();
    let pub_line = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpkAAAAMc3NoOmhhbmRmZXN0 yubikey-p256@test\n";
    let key_handle = dir.path().join("id_ecdsa_sk");
    let pub_path = dir.path().join("id_ecdsa_sk.pub");
    fs::write(&key_handle, "dummy-handle").unwrap();
    fs::write(&pub_path, pub_line).unwrap();

    let expected_key_id = "ssh-sk-p256:0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

    let from_pub = resolve_signer(&SignerConfig::SshSk { key_path: pub_path })
        .expect("resolve P-256 from .pub");
    assert_eq!(from_pub.key_id().to_string(), expected_key_id);
    assert_eq!(
        from_pub.assurance(),
        handfest_anchors::AssuranceLevel::Passkey
    );

    let from_handle = resolve_signer(&SignerConfig::SshSk {
        key_path: key_handle,
    })
    .expect("resolve P-256 from handle via companion .pub");
    assert_eq!(from_handle.key_id().to_string(), expected_key_id);
    assert_eq!(
        from_handle.assurance(),
        handfest_anchors::AssuranceLevel::Passkey
    );
}

#[derive(Clone)]
struct StubMockWitness;

impl handfest_ledger::CheckpointWitness for StubMockWitness {
    fn witness_kind(&self) -> &str {
        "mock"
    }
    fn anchor(
        &self,
        cp: &handfest_ledger::LedgerCheckpoint,
    ) -> Result<handfest_ledger::WitnessProof, handfest_ledger::WitnessError> {
        Ok(handfest_ledger::WitnessProof {
            witness_kind: "mock".to_string(),
            checkpoint_digest_hex: cp.checkpoint_digest_hex(),
            proof_bytes_b64: handfest_core::base64::encode_standard(&cp.checkpoint_digest()),
            anchored_at: cp.timestamp,
        })
    }
    fn verify(
        &self,
        cp: &handfest_ledger::LedgerCheckpoint,
        proof: &handfest_ledger::WitnessProof,
    ) -> Result<(), handfest_ledger::WitnessError> {
        if proof.proof_bytes_b64 == handfest_core::base64::encode_standard(&cp.checkpoint_digest())
        {
            Ok(())
        } else {
            Err(handfest_ledger::WitnessError::VerificationFailed(
                "bad proof".to_string(),
            ))
        }
    }
}

fn make_signed_test_revocation(
    root_kp: &Ed25519Keypair,
    seed: &[u8],
    reason: &str,
    now: i64,
) -> (handfest_core::gate::VerifiedRevocation, String) {
    use handfest_core::ast::{ActorDecl, MandateId};
    use handfest_core::revocation::{render_canonical_revocation, RevocationAst, RevocationTarget};
    use handfest_core::ActorKind;

    let ast = RevocationAst::new(
        ActorDecl::new(
            ActorKind::Human,
            "alice".to_string(),
            root_kp.key_id(),
            Default::default(),
        )
        .unwrap(),
        RevocationTarget::Mandate(MandateId::sha256(seed)),
        now + 1,
        Some(reason.to_string()),
    )
    .unwrap();
    let words = render_canonical_revocation(&ast);
    let signed = root_kp
        .sign_revocation(&words, "local-ed25519", now - 100, now + 10_000)
        .unwrap();
    let verified = handfest_anchors::verify_revocation(&signed).unwrap();
    (verified, signed.signature_hex)
}

#[test]
fn cmd_audit_with_registry_rejects_malformed_expected_checkpoint_and_real_signed_revocation_substitution(
) {
    use handfest_core::cnl::parse_mandate;
    use handfest_core::gate::VerifiedFacts;
    use handfest_ledger::{
        default_checkpoint_sidecar_path, verify_ledger_witness_checkpoints, AnchoredLedger,
        ReceiptLedger, WitnessPolicy,
    };

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("signed_rev_sub.sqlite");
    let alt_db_path = dir.path().join("signed_rev_alt.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);

    let root_kp = Ed25519Keypair::from_secret_bytes([0x11; 32]);
    let actor_kp = Ed25519Keypair::from_secret_bytes([0x22; 32]);
    let now: i64 = 1_764_000_000;
    let raw = format!(
        "HANDFEST v1\nFROM human \"alice\" (key: {})\nTO agent \"bot\" (key: {})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\n",
        root_kp.key_id(),
        actor_kp.key_id()
    );
    let canonical = handfest_core::cnl::render_canonical(&parse_mandate(&raw).unwrap());
    let signed_m = root_kp
        .sign_mandate(&canonical, "local-ed25519", now - 100, now + 10_000)
        .unwrap();
    let verified_chain = handfest_anchors::verify_chain(&[signed_m]).unwrap();
    let req = ActionRequest {
        actor_key: actor_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };

    let (rev_a, sig_a) = make_signed_test_revocation(&root_kp, b"rev-a", "original rev", now);
    let (rev_b, sig_b) =
        make_signed_test_revocation(&root_kp, b"rev-b", "signed replacement rev", now);

    {
        let mut anchored = AnchoredLedger::with_checkpoint_file(
            SqliteLedger::open(&db_path).unwrap(),
            StubMockWitness,
            WitnessPolicy::SyncStrict,
            &sidecar,
        )
        .unwrap();
        anchored
            .evaluate_and_record(&verified_chain, &req, &VerifiedFacts::new(), now)
            .unwrap();
        anchored.record_revocation(&rev_a, &sig_a).unwrap();
    }
    {
        let mut alt = SqliteLedger::open(&alt_db_path).unwrap();
        alt.evaluate_and_record(&verified_chain, &req, &VerifiedFacts::new(), now)
            .unwrap();
        alt.record_revocation(&rev_b, &sig_b).unwrap();
    }

    let alt_ro = SqliteLedger::open_read_only(&alt_db_path).unwrap();
    let alt_snap = alt_ro.audit_full_snapshot(None, false).unwrap();
    assert_eq!(alt_snap.verified_receipts, 1);
    crate::revoke::verify_stored_revocations_signatures(&alt_snap.stored_revocations)
        .expect("replacement revocation must have a valid Ed25519 signature");

    let mut reg = handfest_ledger::WitnessRegistry::new();
    reg.register(StubMockWitness).unwrap();
    let err =
        verify_ledger_witness_checkpoints(&alt_ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("revocation tip hash mismatch")),
        "expected revocation tip hash mismatch, got: {err}"
    );

    let audit_err = crate::witness::execute_audit_with_registry(
        &db_path,
        None,
        true,
        Some("not-a-sha256-digest"),
        &reg,
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(audit_err.code, "invalid_expected_checkpoint");
    assert_eq!(
        audit_err.to_json_value()["code"],
        "invalid_expected_checkpoint"
    );
}

#[test]
fn execute_audit_with_registry_reports_forged_revocation_sig_as_structured_error() {
    use handfest_ledger::{
        default_checkpoint_sidecar_path, AnchoredLedger, ReceiptLedger, WitnessPolicy,
    };

    let dir = tempfile::TempDir::new().unwrap();
    let mut reg = handfest_ledger::WitnessRegistry::new();
    reg.register(StubMockWitness).unwrap();

    let root_kp = Ed25519Keypair::from_secret_bytes([0x31; 32]);
    let (verified_rev, _) =
        make_signed_test_revocation(&root_kp, b"forged-unit", "forged", 1_764_000_000);
    let forged_db = dir.path().join("forged_rev_sig_unit.sqlite");
    let forged_sc = default_checkpoint_sidecar_path(&forged_db);
    {
        let mut anchored = AnchoredLedger::with_checkpoint_file(
            SqliteLedger::open(&forged_db).unwrap(),
            StubMockWitness,
            WitnessPolicy::SyncStrict,
            &forged_sc,
        )
        .unwrap();
        anchored
            .record_revocation(&verified_rev, "deadbeef")
            .unwrap();
    }

    let err = crate::witness::execute_audit_with_registry(&forged_db, None, true, None, &reg)
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, "invalid_revocation_signature");
    let payload = err.to_json_value();
    assert_eq!(payload["error"], "witness_verification_failed");
    assert_eq!(payload["code"], "invalid_revocation_signature");
}

#[test]
fn execute_audit_with_registry_reports_stationary_duplicate_checkpoint_as_structured_error() {
    use handfest_core::cnl::parse_mandate;
    use handfest_core::gate::VerifiedFacts;
    use handfest_ledger::{
        default_checkpoint_sidecar_path, AnchoredLedger, ReceiptLedger, StoredCheckpoint,
        WitnessPolicy,
    };

    let dir = tempfile::TempDir::new().unwrap();
    let mut reg = handfest_ledger::WitnessRegistry::new();
    reg.register(StubMockWitness).unwrap();

    let root_kp = Ed25519Keypair::from_secret_bytes([0x31; 32]);
    let actor_kp = Ed25519Keypair::from_secret_bytes([0x32; 32]);
    let now: i64 = 1_764_000_000;
    let raw = format!(
        "HANDFEST v1\nFROM human \"alice\" (key: {})\nTO agent \"bot\" (key: {})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\n",
        root_kp.key_id(),
        actor_kp.key_id()
    );
    let canonical = handfest_core::cnl::render_canonical(&parse_mandate(&raw).unwrap());
    let signed_m = root_kp
        .sign_mandate(&canonical, "local-ed25519", now - 100, now + 10_000)
        .unwrap();
    let verified_chain = handfest_anchors::verify_chain(&[signed_m]).unwrap();
    let req = ActionRequest {
        actor_key: actor_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let dup_db = dir.path().join("dup_cp_unit.sqlite");
    let dup_sc = default_checkpoint_sidecar_path(&dup_db);
    {
        let mut anchored = AnchoredLedger::with_checkpoint_file(
            SqliteLedger::open(&dup_db).unwrap(),
            StubMockWitness,
            WitnessPolicy::SyncStrict,
            &dup_sc,
        )
        .unwrap();
        anchored
            .evaluate_and_record(&verified_chain, &req, &VerifiedFacts::new(), now)
            .unwrap();
    }
    let line1 = std::fs::read_to_string(&dup_sc).unwrap();
    let rec1: StoredCheckpoint = serde_json::from_str(line1.trim()).unwrap();
    let rec2_hash = StoredCheckpoint::compute_record_hash(
        2,
        Some(&rec1.record_hash),
        &rec1.checkpoint,
        &rec1.proof,
    );
    let rec2 = StoredCheckpoint {
        seq: 2,
        prev_record_hash: Some(rec1.record_hash.clone()),
        record_hash: rec2_hash,
        checkpoint: rec1.checkpoint.clone(),
        proof: rec1.proof.clone(),
    };
    std::fs::write(
        &dup_sc,
        format!("{}{}\n", line1, serde_json::to_string(&rec2).unwrap()),
    )
    .unwrap();

    let err = crate::witness::execute_audit_with_registry(&dup_db, None, true, None, &reg)
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code, "integrity_or_rollback_mismatch");
    assert!(
        err.message.contains("zero-progress duplicate"),
        "expected zero-progress duplicate message, got: {}",
        err.message
    );
    let payload = err.to_json_value();
    assert_eq!(payload["error"], "witness_verification_failed");
    assert_eq!(payload["code"], "integrity_or_rollback_mismatch");
}

#[cfg(unix)]
#[test]
fn audit_snapshot_with_witness_reports_storage_error_on_sidecar_path_permission_loss() {
    use std::os::unix::fs::PermissionsExt;

    struct RestoreMode(std::path::PathBuf, u32);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
        }
    }

    let dir = tempfile::TempDir::new().unwrap();
    let restricted = dir.path().join("audit_access_loss");
    fs::create_dir(&restricted).unwrap();
    let db_path = restricted.join("ledger.sqlite");
    let _ = SqliteLedger::open(&db_path).unwrap();
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let reg = handfest_ledger::WitnessRegistry::new();

    let _restore = RestoreMode(restricted.clone(), 0o700);
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::canonicalize(&db_path).is_ok() {
        return; // Root / CAP_DAC_OVERRIDE bypasses 0o000 parent dir permissions.
    }

    let err =
        crate::witness::audit_snapshot_with_witness(&ro, &db_path, None, &reg, None).unwrap_err();
    assert_eq!(err.code, "storage_error", "got: {err:?}");
}
