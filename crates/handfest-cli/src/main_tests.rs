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
