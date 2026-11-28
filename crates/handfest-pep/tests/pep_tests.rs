use std::collections::BTreeMap;
use std::error::Error as _;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

use handfest_anchors::{AnchorVerifier, Ed25519Keypair, SignedMandate};
use handfest_core::ast::{ActorDecl, KeyId, MandateId, Scalar};
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::exact_json::parse_exact_json;
use handfest_core::gate::{ActionRequest, VerifiedFacts};
use handfest_core::revocation::{render_canonical_revocation, RevocationAst, RevocationTarget};
use handfest_core::ActorKind;
use handfest_ledger::{LedgerError, SqliteLedger};
use handfest_pep::{
    decode_credential_source, is_valid_env_var_name, load_signed_mandates_files,
    load_signed_revocations_files, validate_absolute_clean_path, validate_verified_chain,
    verify_mandate_chain, verify_revocations, CredentialSource, FixedClock, GateDecision,
    GateEngine, PepError, SecretError,
};
use tempfile::tempdir;

const VALID_FROM: i64 = 1_760_000_000;
const VALID_UNTIL: i64 = 1_760_086_400;
const NOW: i64 = 1_760_000_500;

fn make_signed_mandate(
    signer: &Ed25519Keypair,
    agent_key: &KeyId,
    limit_calls: u64,
) -> (MandateId, SignedMandate) {
    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Valentin\" (key: {})\n\
         TO agent \"Builder\" (key: {agent_key})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/*\"\n\
         WHERE resource.environment == \"staging\"\n\
         LIMIT {limit_calls} calls\n",
        signer.key_id()
    );
    let ast = parse_mandate(&text).expect("valid mandate");
    let id = ast.mandate_id();
    let canonical = render_canonical(&ast);
    let signed = signer
        .sign_mandate(&canonical, "local-ed25519", VALID_FROM, VALID_UNTIL)
        .expect("sign mandate");
    (id, signed)
}

#[test]
fn gate_engine_authorizes_enforces_quotas_and_records_pre_gate_denial() {
    let dir = tempdir().expect("tempdir");
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).expect("open ledger");
    let human = Ed25519Keypair::from_secret_bytes([11u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([22u8; 32]);
    let (_, signed) = make_signed_mandate(&human, &agent.key_id(), 1);
    let verified = verify_mandate_chain(&[signed]).expect("verify chain");

    let mut engine =
        GateEngine::new(verified, agent.key_id(), ledger, FixedClock::new(NOW)).expect("engine");
    assert_eq!(engine.now_unix(), NOW);
    assert!(engine.is_chain_active(NOW).expect("active"));
    assert!(!engine.is_chain_active(VALID_UNTIL + 10).expect("expired"));

    let req = ActionRequest {
        actor_key: agent.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.environment", Scalar::Str("staging".into()));

    // First call succeeds and consumes the 1-call quota.
    let d1 = engine.authorize(&req, &facts).expect("authorize 1");
    assert!(matches!(d1, GateDecision::Permit { .. }));

    // Second call is denied by quota.
    let d2 = engine.authorize(&req, &facts).expect("authorize 2");
    assert!(matches!(d2, GateDecision::Deny { .. }));

    // Pre-gate denial on active chain preserves mapping reason; on expired chain reports chain error.
    let mapping_denial = engine
        .record_pre_gate_denial(&req, "unmapped route".to_string(), NOW)
        .expect("pre-gate denial");
    assert_eq!(mapping_denial.reason, "unmapped route");

    let expired_denial = engine
        .record_pre_gate_denial(&req, "unmapped route".to_string(), VALID_UNTIL + 10)
        .expect("expired pre-gate denial");
    assert_ne!(expired_denial.reason, "unmapped route");

    let count = engine.ledger().verify_integrity().expect("integrity");
    assert_eq!(count, 4);
}

#[test]
fn gate_engine_enforces_revocations_and_precedence() {
    let dir = tempdir().expect("tempdir");
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).expect("open ledger");
    let human = Ed25519Keypair::from_secret_bytes([33u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([44u8; 32]);
    let (mandate_id, signed) = make_signed_mandate(&human, &agent.key_id(), 5);
    let verified = verify_mandate_chain(&[signed]).expect("verify chain");

    let by = ActorDecl::new(
        ActorKind::Human,
        "Valentin",
        human.key_id(),
        BTreeMap::new(),
    )
    .expect("actor");
    let rev_ast = RevocationAst::new(
        by,
        RevocationTarget::Mandate(mandate_id),
        VALID_FROM,
        Some("kill switch".to_string()),
    )
    .expect("revocation ast");
    let rev_canonical = render_canonical_revocation(&rev_ast);
    let signed_rev = human
        .sign_revocation(&rev_canonical, "local-ed25519", VALID_FROM, VALID_UNTIL)
        .expect("sign revocation");
    let snapshot = verify_revocations(&[signed_rev]).expect("verify revocations");

    let mut engine = GateEngine::new(verified, agent.key_id(), ledger, FixedClock::new(NOW))
        .expect("engine")
        .with_revocations(snapshot);

    assert!(!engine.is_chain_active(NOW).expect("revoked"));
    let req = ActionRequest {
        actor_key: agent.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let denial = engine
        .record_pre_gate_denial(&req, "mapping error".to_string(), NOW)
        .expect("revoked denial");
    assert!(denial.reason.contains("revoked"));
}

#[test]
fn empty_chain_and_error_display_contracts() {
    let err = verify_mandate_chain(&[]).unwrap_err();
    assert!(matches!(err, PepError::Anchor(_)));
    assert!(err.source().is_some());

    let struct_err = validate_verified_chain(&[]).unwrap_err();
    assert!(matches!(struct_err, PepError::ChainStructure(_)));
    assert!(struct_err.source().is_some());
}

#[test]
fn credential_source_file_and_env_enforce_security_invariants() {
    let dir = tempdir().expect("tempdir");
    let secret_path = dir.path().join("token.secret");
    fs::write(&secret_path, "ghp_supersecret123\n").expect("write secret");
    #[cfg(unix)]
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");

    let src = CredentialSource::File {
        path: secret_path.clone(),
    };
    let loaded = src.load().expect("load 0600 secret");
    assert_eq!(loaded.as_str(), "ghp_supersecret123");
    assert_eq!(format!("{loaded:?}"), "[REDACTED]");

    // Multiline / control-char secret is rejected.
    let bad_path = dir.path().join("multiline.secret");
    fs::write(&bad_path, "line1\nline2\n").expect("write multiline");
    #[cfg(unix)]
    fs::set_permissions(&bad_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    assert!(matches!(
        CredentialSource::File { path: bad_path }.load(),
        Err(SecretError::InvalidSecretValue(_))
    ));

    // Empty secret is rejected.
    let empty_path = dir.path().join("empty.secret");
    fs::write(&empty_path, "\n").expect("write empty");
    #[cfg(unix)]
    fs::set_permissions(&empty_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    assert!(matches!(
        CredentialSource::File { path: empty_path }.load(),
        Err(SecretError::EmptySecret(_))
    ));

    // Group/world-readable file and symlinks are rejected on Unix.
    #[cfg(unix)]
    {
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
        assert!(matches!(
            src.load(),
            Err(SecretError::InsecurePermissions { mode: 0o644, .. })
        ));
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).expect("restore 0600");

        let link_path = dir.path().join("link.secret");
        symlink(&secret_path, &link_path).expect("symlink");
        assert!(matches!(
            CredentialSource::File { path: link_path }.load(),
            Err(SecretError::SymlinkRejected(_))
        ));
    }

    // Invalid & missing env var names fail closed.
    assert!(matches!(
        CredentialSource::Env {
            var: "BAD-NAME".to_string()
        }
        .load(),
        Err(SecretError::InvalidEnvVarName(_))
    ));
    assert!(matches!(
        CredentialSource::Env {
            var: "HANDFEST_PEP_NONEXISTENT_TEST_VAR_999".to_string()
        }
        .load(),
        Err(SecretError::MissingEnvVar(_))
    ));
}

#[test]
fn credential_source_validate_and_env_var_validator_enforce_fail_closed_rules() {
    assert!(is_valid_env_var_name("GH_TOKEN_1"));
    assert!(is_valid_env_var_name("_PRIVATE"));
    assert!(!is_valid_env_var_name(""));
    assert!(!is_valid_env_var_name("1BAD"));
    assert!(!is_valid_env_var_name("BAD-NAME"));
    assert!(!is_valid_env_var_name("BAD NAME"));

    assert!(CredentialSource::File {
        path: std::path::PathBuf::from("/run/secrets/token"),
    }
    .validate()
    .is_ok());
    assert!(CredentialSource::Env {
        var: "API_KEY".to_string(),
    }
    .validate()
    .is_ok());

    for bad_path in [
        "",
        "relative/secret.txt",
        "/run/secrets/../other",
        "/run/secrets/bad
name",
    ] {
        let src = CredentialSource::File {
            path: std::path::PathBuf::from(bad_path),
        };
        let err = src.validate().expect_err("invalid path must fail validate");
        assert!(
            matches!(err, SecretError::InvalidPath(_)),
            "expected InvalidPath for {bad_path:?}, got {err:?}"
        );
        assert!(err.to_string().contains("invalid credential file path"));
        assert!(matches!(src.load(), Err(SecretError::InvalidPath(_))));
    }

    let bad_env = CredentialSource::Env {
        var: "9INVALID".to_string(),
    };
    assert_eq!(
        bad_env.validate(),
        Err(SecretError::InvalidEnvVarName("9INVALID".to_string()))
    );
}

#[test]
fn load_signed_mandates_and_revocations_files_handle_valid_io_and_json_errors() {
    let dir = tempdir().expect("tempdir");
    let human = Ed25519Keypair::from_secret_bytes([55u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([66u8; 32]);
    let (mandate_id, signed) = make_signed_mandate(&human, &agent.key_id(), 2);

    let mandate_path = dir.path().join("mandate.json");
    fs::write(
        &mandate_path,
        serde_json::to_string_pretty(&signed).expect("serialize mandate"),
    )
    .expect("write mandate");

    let by = ActorDecl::new(
        ActorKind::Human,
        "Valentin",
        human.key_id(),
        BTreeMap::new(),
    )
    .expect("actor");
    let rev_ast = RevocationAst::new(
        by,
        RevocationTarget::Mandate(mandate_id),
        VALID_FROM,
        Some("test".to_string()),
    )
    .expect("revocation ast");
    let signed_rev = human
        .sign_revocation(
            &render_canonical_revocation(&rev_ast),
            "local-ed25519",
            VALID_FROM,
            VALID_UNTIL,
        )
        .expect("sign revocation");
    let rev_path = dir.path().join("revocation.json");
    fs::write(
        &rev_path,
        serde_json::to_string_pretty(&signed_rev).expect("serialize revocation"),
    )
    .expect("write revocation");

    let loaded_mandates = load_signed_mandates_files(&[mandate_path]).expect("load mandates");
    assert_eq!(loaded_mandates.len(), 1);
    assert_eq!(loaded_mandates[0].signature_hex, signed.signature_hex);

    let loaded_revs = load_signed_revocations_files(&[rev_path]).expect("load revocations");
    assert_eq!(loaded_revs.len(), 1);
    assert_eq!(loaded_revs[0].signature_hex, signed_rev.signature_hex);

    let missing = dir.path().join("does-not-exist.json");
    assert!(matches!(
        load_signed_mandates_files(std::slice::from_ref(&missing)),
        Err(PepError::Io(_))
    ));
    assert!(matches!(
        load_signed_revocations_files(&[missing]),
        Err(PepError::Io(_))
    ));

    let corrupt = dir.path().join("corrupt.json");
    fs::write(&corrupt, "{not valid json").expect("write corrupt");
    assert!(matches!(
        load_signed_mandates_files(std::slice::from_ref(&corrupt)),
        Err(PepError::InvalidChain(ref msg)) if msg.contains("SignedMandate")
    ));
    assert!(matches!(
        load_signed_revocations_files(&[corrupt]),
        Err(PepError::InvalidChain(ref msg)) if msg.contains("SignedRevocation")
    ));
}

#[test]
fn record_pre_gate_denial_detects_tampered_revocations_even_when_chain_is_expired() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("tampered_rev.sqlite");
    let human = Ed25519Keypair::from_secret_bytes([77u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([88u8; 32]);
    let (mandate_id, signed) = make_signed_mandate(&human, &agent.key_id(), 5);
    let verified = verify_mandate_chain(&[signed]).expect("verify chain");

    let by = ActorDecl::new(
        ActorKind::Human,
        "Valentin",
        human.key_id(),
        BTreeMap::new(),
    )
    .expect("actor");
    let marker = "UNIQUE_REVOCATION_TAMPER_MARKER_001";
    let rev_ast = RevocationAst::new(
        by,
        RevocationTarget::Mandate(mandate_id),
        VALID_FROM,
        Some(marker.to_string()),
    )
    .expect("revocation ast");
    let signed_rev = human
        .sign_revocation(
            &render_canonical_revocation(&rev_ast),
            "local-ed25519",
            VALID_FROM,
            VALID_UNTIL,
        )
        .expect("sign revocation");
    let verified_rev = handfest_anchors::AnchorRegistry::default_registry()
        .verify_revocation(&signed_rev)
        .expect("verify rev");

    {
        let mut ledger = SqliteLedger::open(&db_path).expect("open ledger");
        ledger
            .record_revocation(&verified_rev, &signed_rev.signature_hex)
            .expect("record revocation");
    }

    // Corrupt the persisted revocations table bytes directly on disk.
    let mut bytes = fs::read(&db_path).expect("read sqlite file");
    let needle = marker.as_bytes();
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("marker present in sqlite file");
    bytes[pos + needle.len() - 1] = b'9';
    fs::write(&db_path, bytes).expect("write tampered sqlite file");

    let ledger = SqliteLedger::open_existing(&db_path).expect("reopen tampered ledger");
    let mut engine =
        GateEngine::new(verified, agent.key_id(), ledger, FixedClock::new(NOW)).expect("engine");
    let req = ActionRequest {
        actor_key: agent.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };

    let err = engine
        .record_pre_gate_denial(&req, "unmapped route".to_string(), VALID_UNTIL + 1)
        .expect_err("tampered revocations must fail closed even on expired chain");
    assert!(
        matches!(err, PepError::Ledger(LedgerError::Integrity(_))),
        "expected PepError::Ledger(LedgerError::Integrity(_)), got {err:?}"
    );
}

#[test]
fn credential_source_file_load_hardening_rejects_symlink_ancestors_0700_non_regular_oversized_and_non_utf8(
) {
    let dir = tempdir().expect("tempdir");

    // Non-regular file: directory is rejected before reading.
    let sub_dir = dir.path().join("as_dir");
    fs::create_dir(&sub_dir).expect("mkdir");
    assert!(matches!(
        CredentialSource::File { path: sub_dir }.load(),
        Err(SecretError::Io(ref msg)) if msg.contains("regular file")
    ));

    // Oversized (> 64 KiB) secret file is rejected fail-closed.
    let big_path = dir.path().join("oversized.secret");
    fs::write(&big_path, vec![b'a'; 64 * 1024 + 16]).expect("write big");
    #[cfg(unix)]
    fs::set_permissions(&big_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    assert!(matches!(
        CredentialSource::File { path: big_path }.load(),
        Err(SecretError::Io(ref msg)) if msg.contains("maximum size")
    ));

    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::path::PathBuf;

        // Non-UTF-8 PathBuf fails validate().
        let non_utf8 = PathBuf::from(OsStr::from_bytes(b"/tmp/\xff/secret"));
        let err = CredentialSource::File { path: non_utf8 }
            .validate()
            .expect_err("non-UTF-8 path must fail validate");
        assert!(matches!(err, SecretError::InvalidPath(ref msg) if msg.contains("UTF-8")));

        // 0700, 0200, and 0000 modes are rejected; only 0400 and 0600 are accepted.
        let exec_path = dir.path().join("exec.secret");
        fs::write(&exec_path, "topsecret\n").expect("write exec secret");
        for bad_mode in [0o700u32, 0o200, 0o000] {
            fs::set_permissions(&exec_path, fs::Permissions::from_mode(bad_mode))
                .expect("chmod bad mode");
            assert!(matches!(
                CredentialSource::File {
                    path: exec_path.clone(),
                }
                .load(),
                Err(SecretError::InsecurePermissions { mode, .. }) if mode == bad_mode
            ));
        }
        fs::set_permissions(&exec_path, fs::Permissions::from_mode(0o400)).expect("chmod 0400");
        assert_eq!(
            CredentialSource::File {
                path: exec_path.clone(),
            }
            .load()
            .expect("0400 must succeed")
            .as_str(),
            "topsecret"
        );
        fs::set_permissions(&exec_path, fs::Permissions::from_mode(0o600)).expect("restore 0600");

        // Symlinked ancestor directory is rejected.
        let real_dir = dir.path().join("real_secrets");
        fs::create_dir(&real_dir).expect("mkdir real");
        let real_file = real_dir.join("token.secret");
        fs::write(&real_file, "topsecret\n").expect("write real secret");
        fs::set_permissions(&real_file, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
        let sym_dir = dir.path().join("sym_secrets");
        symlink(&real_dir, &sym_dir).expect("symlink dir");
        let via_sym = sym_dir.join("token.secret");
        assert!(matches!(
            CredentialSource::File { path: via_sym }.load(),
            Err(SecretError::SymlinkRejected(ref p)) if p == &sym_dir
        ));

        // FIFO is rejected BEFORE open (never hangs!).
        let fifo_path = dir.path().join("hang.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("invoke mkfifo");
        assert!(status.success(), "mkfifo must succeed");
        fs::set_permissions(&fifo_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
        assert!(matches!(
            CredentialSource::File { path: fifo_path }.load(),
            Err(SecretError::Io(ref msg)) if msg.contains("regular file")
        ));
    }
}

#[test]
fn shared_validate_absolute_clean_path_and_decode_credential_source_helpers_work() {
    assert!(validate_absolute_clean_path(std::path::Path::new("/usr/bin/env"), "exec").is_ok());
    assert!(
        validate_absolute_clean_path(std::path::Path::new("rel/path"), "exec")
            .unwrap_err()
            .contains("must be absolute")
    );
    assert!(
        validate_absolute_clean_path(std::path::Path::new("/a/../b"), "exec")
            .unwrap_err()
            .contains("..")
    );

    let file_json = parse_exact_json(r#"{"file":{"path":"/run/secrets/api"}}"#).unwrap();
    assert_eq!(
        decode_credential_source(&file_json, "ctx").unwrap(),
        CredentialSource::File {
            path: std::path::PathBuf::from("/run/secrets/api"),
        }
    );
    let env_json = parse_exact_json(r#"{"env":{"var":"API_TOKEN"}}"#).unwrap();
    assert_eq!(
        decode_credential_source(&env_json, "ctx").unwrap(),
        CredentialSource::Env {
            var: "API_TOKEN".to_string(),
        }
    );
    let bad_tag = parse_exact_json(r#"{"vault":{"key":"x"}}"#).unwrap();
    assert!(decode_credential_source(&bad_tag, "ctx")
        .unwrap_err()
        .contains("unknown credential source"));
    let multi_key = parse_exact_json(r#"{"file":{"path":"/a"},"env":{"var":"A"}}"#).unwrap();
    assert!(decode_credential_source(&multi_key, "ctx")
        .unwrap_err()
        .contains("single-key"));
}

#[test]
fn gate_engine_record_pre_gate_denial_enforces_engine_actor_key_over_request_actor_key() {
    let dir = tempdir().expect("tempdir");
    let ledger = SqliteLedger::open(dir.path().join("actor_mismatch.sqlite")).expect("open ledger");
    let human = Ed25519Keypair::from_secret_bytes([51u8; 32]);
    let actor_a = Ed25519Keypair::from_secret_bytes([52u8; 32]);
    let actor_b = Ed25519Keypair::from_secret_bytes([53u8; 32]);

    // Chain leaf is issued to actor_b, while GateEngine is configured for actor_a.
    let (_, signed_for_b) = make_signed_mandate(&human, &actor_b.key_id(), 5);
    let verified = verify_mandate_chain(&[signed_for_b]).expect("verify chain");
    let mut engine =
        GateEngine::new(verified, actor_a.key_id(), ledger, FixedClock::new(NOW)).expect("engine");

    // Caller supplies denial_request.actor_key == actor_b (matching chain leaf), but
    // record_pre_gate_denial must validate against engine.actor_key() (actor_a).
    let denial_req = ActionRequest {
        actor_key: actor_b.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let denial = engine
        .record_pre_gate_denial(&denial_req, "fallback_reason".to_string(), NOW)
        .expect("record pre-gate denial");

    assert_ne!(
        denial.reason, "fallback_reason",
        "actor-key mismatch must take precedence over fallback_reason"
    );
    assert!(
        denial.reason.contains(&actor_a.key_id().to_string())
            && denial.reason.contains(&actor_b.key_id().to_string()),
        "expected actor-key mismatch error citing both engine actor A and leaf actor B, got '{}'",
        denial.reason
    );
    assert_eq!(denial.receipt.actor_key, *engine.actor_key());
    assert_eq!(denial.receipt.chain_ids, engine.chain_ids());
    assert!(denial.receipt.verify_hash());
    assert_eq!(engine.ledger().verify_integrity().unwrap(), 1);
    assert_eq!(
        engine
            .ledger()
            .track_record(engine.actor_key())
            .unwrap()
            .denies,
        1
    );
    assert_eq!(
        engine
            .ledger()
            .track_record(&actor_b.key_id())
            .unwrap()
            .denies,
        0
    );
}

#[test]
fn gate_engine_authorize_rejects_mismatched_request_actor_key_without_consuming_quota() {
    let dir = tempdir().expect("tempdir");
    let ledger_path = dir.path().join("authorize_actor_mismatch.sqlite");
    let ledger = SqliteLedger::open(&ledger_path).expect("open ledger");
    let human = Ed25519Keypair::from_secret_bytes([61u8; 32]);
    let actor_a = Ed25519Keypair::from_secret_bytes([62u8; 32]);
    let actor_b = Ed25519Keypair::from_secret_bytes([63u8; 32]);

    // Chain leaf is issued to actor_b with LIMIT 1 calls, while GateEngine is configured for actor_a.
    let (_, signed_for_b) = make_signed_mandate(&human, &actor_b.key_id(), 1);
    let verified_for_b = verify_mandate_chain(&[signed_for_b]).expect("verify chain");
    let mut engine_a = GateEngine::new(
        verified_for_b.clone(),
        actor_a.key_id(),
        ledger,
        FixedClock::new(NOW),
    )
    .expect("engine_a");

    let req_for_b = ActionRequest {
        actor_key: actor_b.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.environment", Scalar::Str("staging".into()));

    let decision = engine_a
        .authorize(&req_for_b, &facts)
        .expect("authorize must return Deny rather than error");
    match decision {
        GateDecision::Deny { reason, receipt } => {
            assert!(
                reason.contains(&actor_a.key_id().to_string())
                    && reason.contains(&actor_b.key_id().to_string()),
                "expected actor mismatch citing actor_a and actor_b, got '{reason}'"
            );
            assert_eq!(receipt.actor_key, actor_a.key_id());
            assert_eq!(receipt.chain_ids, engine_a.chain_ids());
            assert!(receipt.verify_hash());
        }
        GateDecision::Permit { .. } => {
            panic!("engine configured for actor_a must never permit request carrying actor_b");
        }
    }

    let tr_a = engine_a.ledger().track_record(&actor_a.key_id()).unwrap();
    let tr_b = engine_a.ledger().track_record(&actor_b.key_id()).unwrap();
    assert_eq!(tr_a.denies, 1);
    assert_eq!(tr_a.permits, 0);
    assert_eq!(tr_b.denies, 0);
    assert_eq!(tr_b.permits, 0);
    assert_eq!(engine_a.ledger().verify_integrity().unwrap(), 1);

    // Zero quota consumption: legitimate engine_b on the same ledger still has its full LIMIT 1 quota.
    let mut engine_b = GateEngine::new(
        verified_for_b,
        actor_b.key_id(),
        engine_a.into_ledger(),
        FixedClock::new(NOW),
    )
    .expect("engine_b");
    let permit = engine_b.authorize(&req_for_b, &facts).expect("authorize b");
    assert!(matches!(permit, GateDecision::Permit { .. }));
}

#[test]
fn gate_engine_authorize_rejects_mismatched_request_actor_key_on_valid_chain_without_consuming_quota(
) {
    let dir = tempdir().expect("tempdir");
    let human = Ed25519Keypair::from_secret_bytes([61u8; 32]);
    let actor_a = Ed25519Keypair::from_secret_bytes([62u8; 32]);
    let actor_b = Ed25519Keypair::from_secret_bytes([63u8; 32]);
    let req_for_b = ActionRequest {
        actor_key: actor_b.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.environment", Scalar::Str("staging".into()));

    // Chain leaf matches engine.actor_key() (actor_a), while caller passes a mismatched
    // request.actor_key (actor_b): must deny with explicit mismatch reason, bind
    // receipt.actor_key to actor_a, and leave LIMIT 1 quota untouched.
    let ledger2 = SqliteLedger::open(
        dir.path()
            .join("authorize_actor_mismatch_valid_chain.sqlite"),
    )
    .expect("open ledger2");
    let (_, signed_for_a) = make_signed_mandate(&human, &actor_a.key_id(), 1);
    let verified_for_a = verify_mandate_chain(&[signed_for_a]).expect("verify chain a");
    let mut engine_a2 = GateEngine::new(
        verified_for_a,
        actor_a.key_id(),
        ledger2,
        FixedClock::new(NOW),
    )
    .expect("engine_a2");
    let expected_reason = format!(
        "request actor_key '{}' does not match engine actor_key '{}'",
        actor_b.key_id(),
        actor_a.key_id()
    );
    match engine_a2
        .authorize(&req_for_b, &facts)
        .expect("mismatched request must deny")
    {
        GateDecision::Deny { reason, receipt } => {
            assert_eq!(reason, expected_reason);
            assert_eq!(receipt.actor_key, actor_a.key_id());
            assert!(receipt.verify_hash());
        }
        GateDecision::Permit { .. } => panic!("mismatched request.actor_key must never permit"),
    }
    assert_eq!(
        engine_a2
            .ledger()
            .track_record(&actor_a.key_id())
            .unwrap()
            .denies,
        1
    );
    assert_eq!(
        engine_a2
            .ledger()
            .track_record(&actor_b.key_id())
            .unwrap()
            .denies,
        0
    );
    let req_for_a = ActionRequest {
        actor_key: actor_a.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    assert!(matches!(
        engine_a2.authorize(&req_for_a, &facts).unwrap(),
        GateDecision::Permit { .. }
    ));
}

#[test]
fn gate_engine_authorize_at_rejects_mismatched_request_actor_key_without_consuming_quota() {
    let dir = tempdir().expect("tempdir");
    let ledger_path = dir.path().join("authorize_at_actor_mismatch.sqlite");
    let ledger = SqliteLedger::open(&ledger_path).expect("open ledger");
    let human = Ed25519Keypair::from_secret_bytes([64u8; 32]);
    let actor_a = Ed25519Keypair::from_secret_bytes([65u8; 32]);
    let actor_b = Ed25519Keypair::from_secret_bytes([66u8; 32]);
    let explicit_now = NOW + 15;

    // Chain leaf is issued to actor_b with LIMIT 1 calls, while GateEngine is configured for actor_a.
    let (_, signed_for_b) = make_signed_mandate(&human, &actor_b.key_id(), 1);
    let verified_for_b = verify_mandate_chain(&[signed_for_b]).expect("verify chain");
    let mut engine_a = GateEngine::new(
        verified_for_b.clone(),
        actor_a.key_id(),
        ledger,
        FixedClock::new(NOW),
    )
    .expect("engine_a");

    let req_for_b = ActionRequest {
        actor_key: actor_b.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.environment", Scalar::Str("staging".into()));

    let decision = engine_a
        .authorize_at(&req_for_b, &facts, explicit_now)
        .expect("authorize_at must return Deny rather than error");
    match decision {
        GateDecision::Deny { reason, receipt } => {
            assert!(
                reason.contains(&actor_a.key_id().to_string())
                    && reason.contains(&actor_b.key_id().to_string()),
                "expected actor mismatch citing actor_a and actor_b, got '{reason}'"
            );
            assert_eq!(receipt.actor_key, actor_a.key_id());
            assert_eq!(receipt.chain_ids, engine_a.chain_ids());
            assert_eq!(receipt.timestamp, explicit_now);
            assert!(receipt.verify_hash());
        }
        GateDecision::Permit { .. } => {
            panic!(
                "authorize_at configured for actor_a must never permit request carrying actor_b"
            );
        }
    }

    let tr_a = engine_a.ledger().track_record(&actor_a.key_id()).unwrap();
    let tr_b = engine_a.ledger().track_record(&actor_b.key_id()).unwrap();
    assert_eq!(tr_a.denies, 1);
    assert_eq!(tr_a.permits, 0);
    assert_eq!(tr_b.denies, 0);
    assert_eq!(tr_b.permits, 0);
    assert_eq!(engine_a.ledger().verify_integrity().unwrap(), 1);

    // Zero quota consumption: legitimate engine_b on the same ledger still has its full LIMIT 1 quota.
    let mut engine_b = GateEngine::new(
        verified_for_b,
        actor_b.key_id(),
        engine_a.into_ledger(),
        FixedClock::new(NOW),
    )
    .expect("engine_b");
    let permit = engine_b
        .authorize_at(&req_for_b, &facts, explicit_now)
        .expect("authorize_at b");
    assert!(matches!(permit, GateDecision::Permit { .. }));
}

#[test]
fn gate_engine_authorize_at_rejects_mismatched_request_actor_key_on_valid_chain_without_consuming_quota(
) {
    let dir = tempdir().expect("tempdir");
    let human = Ed25519Keypair::from_secret_bytes([67u8; 32]);
    let actor_a = Ed25519Keypair::from_secret_bytes([68u8; 32]);
    let actor_b = Ed25519Keypair::from_secret_bytes([69u8; 32]);
    let explicit_now = NOW + 25;
    let req_for_b = ActionRequest {
        actor_key: actor_b.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.environment", Scalar::Str("staging".into()));

    let ledger = SqliteLedger::open(
        dir.path()
            .join("authorize_at_actor_mismatch_valid_chain.sqlite"),
    )
    .expect("open ledger");
    let (_, signed_for_a) = make_signed_mandate(&human, &actor_a.key_id(), 1);
    let verified_for_a = verify_mandate_chain(&[signed_for_a]).expect("verify chain a");
    let mut engine_a = GateEngine::new(
        verified_for_a,
        actor_a.key_id(),
        ledger,
        FixedClock::new(NOW),
    )
    .expect("engine_a");

    let expected_reason = format!(
        "request actor_key '{}' does not match engine actor_key '{}'",
        actor_b.key_id(),
        actor_a.key_id()
    );
    match engine_a
        .authorize_at(&req_for_b, &facts, explicit_now)
        .expect("mismatched authorize_at request must deny")
    {
        GateDecision::Deny { reason, receipt } => {
            assert_eq!(reason, expected_reason);
            assert_eq!(receipt.actor_key, actor_a.key_id());
            assert_eq!(receipt.chain_ids, engine_a.chain_ids());
            assert_eq!(receipt.timestamp, explicit_now);
            assert!(receipt.verify_hash());
        }
        GateDecision::Permit { .. } => {
            panic!("mismatched request.actor_key must never permit via authorize_at")
        }
    }

    let tr_a = engine_a.ledger().track_record(&actor_a.key_id()).unwrap();
    let tr_b = engine_a.ledger().track_record(&actor_b.key_id()).unwrap();
    assert_eq!(tr_a.denies, 1);
    assert_eq!(tr_a.permits, 0);
    assert_eq!(tr_b.denies, 0);
    assert_eq!(tr_b.permits, 0);
    assert_eq!(engine_a.ledger().verify_integrity().unwrap(), 1);

    let req_for_a = ActionRequest {
        actor_key: actor_a.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    assert!(matches!(
        engine_a
            .authorize_at(&req_for_a, &facts, explicit_now)
            .unwrap(),
        GateDecision::Permit { .. }
    ));
}

#[test]
fn authorize_at_mismatched_actor_propagates_ledger_integrity_error() {
    use handfest_core::gate::{
        DecisionReceipt, RevocationSnapshot, VerifiedMandate, VerifiedRevocation,
    };
    use handfest_core::revocation::RevocationId;
    use handfest_core::Verdict;
    use handfest_ledger::{LedgerError, ReceiptLedger, StoredRevocation, TrackRecord};

    struct FailingDenialLedger;
    impl ReceiptLedger for FailingDenialLedger {
        fn evaluate_and_record_with_revocations(
            &mut self,
            _: &[VerifiedMandate],
            _: &ActionRequest,
            _: &VerifiedFacts,
            _: &RevocationSnapshot,
            _: i64,
        ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
            panic!("mismatched actor_key must not call evaluate_and_record_with_revocations")
        }
        fn record_revocation(
            &mut self,
            _: &VerifiedRevocation,
            _: &str,
        ) -> Result<RevocationId, LedgerError> {
            unimplemented!()
        }
        fn load_revocations(&self) -> Result<RevocationSnapshot, LedgerError> {
            Ok(RevocationSnapshot::new())
        }
        fn list_stored_revocations(&self) -> Result<Vec<StoredRevocation>, LedgerError> {
            Ok(Vec::new())
        }
        fn record_denial(
            &mut self,
            _: Vec<MandateId>,
            _: &ActionRequest,
            _: i64,
            _: String,
        ) -> Result<DecisionReceipt, LedgerError> {
            unimplemented!()
        }
        fn record_denial_with_revocations(
            &mut self,
            _: &[VerifiedMandate],
            _: &KeyId,
            _: &ActionRequest,
            _: &RevocationSnapshot,
            _: i64,
            _: String,
        ) -> Result<(String, DecisionReceipt), LedgerError> {
            Err(LedgerError::Integrity("tampered schema on denial".into()))
        }
        fn track_record(&self, _: &KeyId) -> Result<TrackRecord, LedgerError> {
            unimplemented!()
        }
        fn audit_snapshot(
            &self,
            _: Option<&KeyId>,
        ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
            unimplemented!()
        }
        fn verified_chain_hashes(&self) -> Result<handfest_ledger::LedgerChainHashes, LedgerError> {
            unimplemented!()
        }
    }

    let human = Ed25519Keypair::from_secret_bytes([71u8; 32]);
    let actor_a = Ed25519Keypair::from_secret_bytes([72u8; 32]);
    let actor_b = Ed25519Keypair::from_secret_bytes([73u8; 32]);
    let (_, signed_for_a) = make_signed_mandate(&human, &actor_a.key_id(), 1);
    let verified_for_a = verify_mandate_chain(&[signed_for_a]).expect("verify chain");
    let mut engine = GateEngine::new(
        verified_for_a,
        actor_a.key_id(),
        FailingDenialLedger,
        FixedClock::new(NOW),
    )
    .expect("engine");
    let req_for_b = ActionRequest {
        actor_key: actor_b.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.environment", Scalar::Str("staging".into()));
    let err = engine.authorize_at(&req_for_b, &facts, NOW).unwrap_err();
    assert!(
        matches!(err, PepError::Ledger(LedgerError::Integrity(_))),
        "expected PepError::Ledger(LedgerError::Integrity(_)), got: {err:?}"
    );
}

#[test]
fn gate_engine_replace_verified_chain_updates_active_chain_and_rejects_empty() {
    let human = Ed25519Keypair::from_secret_bytes([81u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([82u8; 32]);
    let (_, signed_limit_1) = make_signed_mandate(&human, &agent.key_id(), 1);
    let (_, signed_limit_5) = make_signed_mandate(&human, &agent.key_id(), 5);
    let chain_1 = verify_mandate_chain(&[signed_limit_1]).expect("verify chain 1");
    let chain_5 = verify_mandate_chain(&[signed_limit_5]).expect("verify chain 5");
    let id_1 = chain_1[0].ast.mandate_id();
    let id_5 = chain_5[0].ast.mandate_id();

    let ledger = SqliteLedger::open_in_memory().expect("in-memory ledger");
    let mut engine =
        GateEngine::new(chain_1, agent.key_id(), ledger, FixedClock::new(NOW)).expect("engine");
    assert_eq!(engine.chain_ids(), &[id_1]);

    // Replacing with an empty chain must fail closed and leave the existing chain intact.
    let err = engine.replace_verified_chain(Vec::new()).unwrap_err();
    assert!(matches!(err, PepError::ChainStructure(_)));
    assert_eq!(engine.chain_ids(), &[id_1]);

    // Replacing with a valid chain atomically updates both verified_chain and chain_ids.
    engine
        .replace_verified_chain(chain_5)
        .expect("replace valid chain");
    assert_eq!(engine.chain_ids(), &[id_5]);
    assert_eq!(engine.verified_chain().len(), 1);
    assert_eq!(engine.verified_chain()[0].ast.mandate_id(), id_5);
}

#[test]
fn gate_engine_record_chain_unavailable_denial_uses_empty_chain_ids_and_exact_reason() {
    let dir = tempdir().expect("tempdir");
    let ledger =
        SqliteLedger::open(dir.path().join("chain_unavailable.sqlite")).expect("open ledger");
    let human = Ed25519Keypair::from_secret_bytes([61u8; 32]);
    let actor = Ed25519Keypair::from_secret_bytes([62u8; 32]);
    let spoofed_actor = Ed25519Keypair::from_secret_bytes([63u8; 32]);

    let (_, signed) = make_signed_mandate(&human, &actor.key_id(), 5);
    let verified = verify_mandate_chain(&[signed]).expect("verify chain");
    let mut engine =
        GateEngine::new(verified, actor.key_id(), ledger, FixedClock::new(NOW)).expect("engine");

    // Even when `now` is past the stale chain's `VALID_UNTIL`, `record_chain_unavailable_denial`
    // must NEVER consult the stale chain, must record `chain_ids = []`, must attribute the receipt
    // to `engine.actor_key()`, and must preserve the exact unavailable reason.
    let req = ActionRequest {
        actor_key: spoofed_actor.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    let reason = "mandate chain reload failed: signature verification failed";
    let receipt = engine
        .record_chain_unavailable_denial(&req, reason, VALID_UNTIL + 60)
        .expect("record chain unavailable denial");

    assert!(
        receipt.chain_ids.is_empty(),
        "chain unavailable denial must persist empty chain_ids, got {:?}",
        receipt.chain_ids
    );
    assert_eq!(receipt.actor_key, *engine.actor_key());
    assert_eq!(
        receipt.verdict,
        handfest_pep::Verdict::Deny {
            reason: reason.to_string(),
        }
    );
    assert!(receipt.verify_hash());
    assert_eq!(engine.ledger().verify_integrity().unwrap(), 1);
    let tr = engine.ledger().track_record(engine.actor_key()).unwrap();
    assert_eq!(tr.denies, 1);
    assert_eq!(tr.permits, 0);
    assert_eq!(tr.distinct_mandates, 0);
    assert_eq!(
        engine
            .ledger()
            .track_record(&spoofed_actor.key_id())
            .unwrap()
            .denies,
        0
    );
}
