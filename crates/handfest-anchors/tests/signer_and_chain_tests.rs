use std::cell::Cell;
use std::error::Error as _;

use handfest_anchors::{
    sign_mandate_with, signing_payload, verify_chain, verify_chain_with, AnchorError,
    AnchorRegistry, AnchorVerifier, AssuranceLevel, CommandOutput, CommandRunner, Ed25519Keypair,
    MandateSigner, ProofIdentitySource, SignedMandate, SystemCommandRunner,
};
use handfest_core::ast::{
    parse_rfc3339_utc, KeyId, MandateId, Scalar, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::{parse_canonical, parse_mandate, render_canonical, ParseError};
use handfest_core::gate::{
    authorize, ActionRequest, QuotaSnapshot, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate,
};
use handfest_core::{ActorKind, Verdict};

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 timestamp")
}

fn root_mandate(from_key: &KeyId, to_key: &KeyId) -> String {
    let ast = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: {from_key})\n",
            "TO agent \"brokkr:dispatcher\" (key: {to_key})\n",
            "DELEGATION max 1 hop\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/*\"\n",
            "WHERE context.time >= 2026-11-24T17:00:00Z\n",
            "  AND context.time < 2026-11-25T01:00:00Z\n",
            "  AND resource.author == \"valentin\"\n",
            "LIMIT 5 calls\n",
        ),
        from_key = from_key,
        to_key = to_key,
    ))
    .expect("valid root mandate");
    render_canonical(&ast)
}

fn child_mandate(parent: MandateId, from_key: &KeyId, to_key: &KeyId) -> String {
    let ast = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {parent}\n",
            "FROM agent \"brokkr:dispatcher\" (key: {from_key})\n",
            "TO agent \"brokkr:seat:ship\" (key: {to_key})\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE context.time >= 2026-11-24T18:00:00Z\n",
            "  AND context.time < 2026-11-24T19:00:00Z\n",
            "  AND resource.author == \"valentin\"\n",
            "LIMIT 2 calls\n",
        ),
        parent = parent,
        from_key = from_key,
        to_key = to_key,
    ))
    .expect("valid child mandate");
    render_canonical(&ast)
}

/// Deterministic passkey test signer backed by an internal Ed25519 key so a matching verifier
/// can verify the exact domain-separated `signing_payload` bytes.
struct PasskeyTestSigner {
    key_id: KeyId,
    inner: Ed25519Keypair,
    calls: Cell<usize>,
}

impl PasskeyTestSigner {
    fn new(cred_id: &str, seed: [u8; 32]) -> Self {
        Self {
            key_id: KeyId::new("passkey", cred_id).expect("valid passkey KeyId"),
            inner: Ed25519Keypair::from_secret_bytes(seed),
            calls: Cell::new(0),
        }
    }

    fn expected_sig(&self, payload: &[u8]) -> Vec<u8> {
        self.inner
            .sign_payload(payload)
            .expect("ed25519 sign_payload")
    }
}

impl MandateSigner for PasskeyTestSigner {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::Passkey
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.sign_payload(payload)
    }
}

/// Matching verifier for `PasskeyTestSigner` that checks the exact signature over `signing_payload`.
struct PasskeyTestVerifier {
    expected_key_id: KeyId,
    expected_signer: Ed25519Keypair,
}

impl AnchorVerifier for PasskeyTestVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        let ast =
            parse_canonical(&signed.canonical_words).map_err(AnchorError::NonCanonicalMandate)?;
        let signer_key = KeyId::parse(&signed.signer_key)
            .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))?;
        if signer_key != self.expected_key_id {
            return Err(AnchorError::InvalidPublicKey(format!(
                "unknown passkey '{}'",
                signer_key
            )));
        }
        let payload = signing_payload(signed);
        let expected_sig_hex = hex::encode(
            self.expected_signer
                .sign_payload(&payload)
                .expect("sign_payload"),
        );
        if signed.signature_hex != expected_sig_hex {
            return Err(AnchorError::InvalidSignature(
                "passkey signature mismatch".to_string(),
            ));
        }
        Ok(VerifiedMandate {
            ast,
            proof: VerifiedAnchorProof {
                anchor_id: signed.anchor_id.clone(),
                assurance: AssuranceLevel::Passkey,
                signer_key,
                actor_kind: ActorKind::Human,
                valid_from: signed.valid_from,
                valid_until: signed.valid_until,
            },
        })
    }
}

struct FailingSigner {
    key_id: KeyId,
    assurance: AssuranceLevel,
    behavior: FailingBehavior,
}

enum FailingBehavior {
    EmptySignature,
    Error(AnchorError),
}

impl MandateSigner for FailingSigner {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn assurance(&self) -> AssuranceLevel {
        self.assurance
    }

    fn sign_payload(&self, _payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        match &self.behavior {
            FailingBehavior::EmptySignature => Ok(Vec::new()),
            FailingBehavior::Error(err) => Err(err.clone()),
        }
    }
}

#[test]
fn sign_mandate_with_custom_passkey_signer_and_boxed_trait_object() {
    let passkey = PasskeyTestSigner::new("yubikey-fido2-1", [0x42; 32]);
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x55; 32]);
    let words = root_mandate(&passkey.key_id(), &agent_kp.key_id());
    let from = ts("2026-11-24T17:00:00Z");
    let until = ts("2026-11-25T01:00:00Z");

    let signed = sign_mandate_with(&passkey, &words, "yubikey-5c", from, until)
        .expect("sign with custom passkey signer");
    assert_eq!(passkey.calls.get(), 1);
    assert_eq!(signed.canonical_words, words);
    assert_eq!(signed.anchor_id, "yubikey-5c");
    assert_eq!(signed.assurance, "passkey");
    assert_eq!(signed.actor_kind, "human");
    assert_eq!(signed.signer_key, "passkey:yubikey-fido2-1");
    assert_eq!(signed.valid_from, from);
    assert_eq!(signed.valid_until, until);

    let expected_sig = hex::encode(passkey.expected_sig(&signing_payload(&signed)));
    assert_eq!(signed.signature_hex, expected_sig);

    // Also verify `?Sized` dispatch via `Box<dyn MandateSigner>`.
    let boxed: Box<dyn MandateSigner> =
        Box::new(PasskeyTestSigner::new("yubikey-fido2-1", [0x42; 32]));
    let signed_via_box = sign_mandate_with(boxed.as_ref(), &words, "yubikey-5c", from, until)
        .expect("sign via Box<dyn MandateSigner>");
    assert_eq!(signed_via_box, signed);

    // Ed25519Keypair implements MandateSigner and `sign_mandate` delegates to `sign_mandate_with`.
    let ed_kp = Ed25519Keypair::from_secret_bytes([0x11; 32]);
    assert_eq!(MandateSigner::key_id(&ed_kp), ed_kp.key_id());
    assert_eq!(ed_kp.assurance(), AssuranceLevel::LocalKey);
    assert_eq!(ed_kp.sign_payload(b"probe").unwrap().len(), 64);

    let ed_words = root_mandate(&ed_kp.key_id(), &agent_kp.key_id());
    let via_method = ed_kp
        .sign_mandate(&ed_words, "local-ed25519", from, until)
        .expect("sign_mandate");
    let via_helper = sign_mandate_with(&ed_kp, &ed_words, "local-ed25519", from, until)
        .expect("sign_mandate_with");
    assert_eq!(via_method, via_helper);
}

#[test]
fn sign_mandate_with_fails_closed_before_and_after_signing() {
    let passkey = PasskeyTestSigner::new("yubikey-1", [0x10; 32]);
    let other_key = KeyId::new("passkey", "yubikey-other").unwrap();
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x20; 32]);
    let words = root_mandate(&passkey.key_id(), &agent_kp.key_id());
    let from = ts("2026-11-24T17:00:00Z");
    let until = ts("2026-11-25T01:00:00Z");

    // 1. Non-canonical text rejected before signer is touched.
    let non_canonical = words.replace("DELEGATION max 1 hop", "DELEGATION max 1 hops");
    let err = sign_mandate_with(&passkey, &non_canonical, "yk-1", from, until).unwrap_err();
    assert!(matches!(
        err,
        AnchorError::NonCanonicalMandate(ParseError::NonCanonical { .. })
    ));
    assert_eq!(passkey.calls.get(), 0);

    // 2. Proof shape violations rejected before signer is touched.
    assert!(matches!(
        sign_mandate_with(&passkey, &words, "", from, until),
        Err(AnchorError::InvalidAnchorId(_))
    ));
    assert!(matches!(
        sign_mandate_with(&passkey, &words, "bad\nid", from, until),
        Err(AnchorError::InvalidAnchorId(_))
    ));
    assert_eq!(
        sign_mandate_with(&passkey, &words, "yk-1", MIN_RFC3339_TIMESTAMP - 1, until),
        Err(AnchorError::InvalidTimestamp(MIN_RFC3339_TIMESTAMP - 1))
    );
    assert_eq!(
        sign_mandate_with(&passkey, &words, "yk-1", from, MAX_RFC3339_TIMESTAMP + 1),
        Err(AnchorError::InvalidTimestamp(MAX_RFC3339_TIMESTAMP + 1))
    );
    assert_eq!(
        sign_mandate_with(&passkey, &words, "yk-1", until, from),
        Err(AnchorError::InvalidValidityWindow {
            valid_from: until,
            valid_until: from,
        })
    );
    assert_eq!(passkey.calls.get(), 0);

    // 3. Signer key mismatch rejected before signer is touched.
    let mismatch_words = root_mandate(&other_key, &agent_kp.key_id());
    assert_eq!(
        sign_mandate_with(&passkey, &mismatch_words, "yk-1", from, until),
        Err(AnchorError::SignerMismatch {
            expected: other_key.to_string(),
            actual: passkey.key_id().to_string(),
        })
    );
    assert_eq!(passkey.calls.get(), 0);

    // 4. Empty signature returned by buggy signer fails closed.
    let empty_sig_signer = FailingSigner {
        key_id: passkey.key_id(),
        assurance: AssuranceLevel::Passkey,
        behavior: FailingBehavior::EmptySignature,
    };
    let empty_err = sign_mandate_with(&empty_sig_signer, &words, "yk-1", from, until).unwrap_err();
    assert_eq!(
        empty_err,
        AnchorError::InvalidSignature("signer returned empty signature".to_string())
    );

    // 5. Signer failure error is propagated intact.
    let cmd_err = AnchorError::CommandFailed {
        program: "fido2-assert".to_string(),
        status: Some(1),
        stderr: "user presence required".to_string(),
    };
    let failing_signer = FailingSigner {
        key_id: passkey.key_id(),
        assurance: AssuranceLevel::Passkey,
        behavior: FailingBehavior::Error(cmd_err.clone()),
    };
    assert_eq!(
        sign_mandate_with(&failing_signer, &words, "yk-1", from, until),
        Err(cmd_err)
    );
}

#[test]
fn verify_chain_and_verify_chain_with_dispatch_registry_and_fail_closed() {
    // Empty chains fail closed on both functions.
    assert_eq!(verify_chain(&[]), Err(AnchorError::EmptyChain));
    assert_eq!(
        verify_chain_with(&AnchorRegistry::default_registry(), &[]),
        Err(AnchorError::EmptyChain)
    );

    let passkey = PasskeyTestSigner::new("yubikey-root", [0x77; 32]);
    let disp_kp = Ed25519Keypair::from_secret_bytes([0x88; 32]);
    let seat_kp = Ed25519Keypair::from_secret_bytes([0x99; 32]);

    let root_words = root_mandate(&passkey.key_id(), &disp_kp.key_id());
    let root_ast = parse_mandate(&root_words).unwrap();
    let root_signed = sign_mandate_with(
        &passkey,
        &root_words,
        "yubikey-fido2",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign root with passkey");

    let child_words = child_mandate(root_ast.mandate_id(), &disp_kp.key_id(), &seat_kp.key_id());
    let child_signed = disp_kp
        .sign_mandate(
            &child_words,
            "disp-ed25519",
            ts("2026-11-24T17:30:00Z"),
            ts("2026-11-24T20:00:00Z"),
        )
        .expect("sign child with ed25519");

    // Default `verify_chain` routes through `AnchorRegistry::default_registry()`, so unregistered
    // `passkey` fails with `UnsupportedKeyScheme` (not Ed25519-hardcoded `InvalidPublicKey`).
    let default_err = verify_chain(&[root_signed.clone(), child_signed.clone()]).unwrap_err();
    assert_eq!(
        default_err,
        AnchorError::ChainHop {
            hop: 0,
            source: Box::new(AnchorError::UnsupportedKeyScheme("passkey".to_string())),
        }
    );

    // Unknown scheme at hop 1 is reported with exact hop index 1.
    let ed_root_kp = Ed25519Keypair::from_secret_bytes([0xaa; 32]);
    let ed_root_words = root_mandate(&ed_root_kp.key_id(), &disp_kp.key_id());
    let ed_root_signed = ed_root_kp
        .sign_mandate(
            &ed_root_words,
            "ed-root",
            ts("2026-11-24T17:00:00Z"),
            ts("2026-11-25T01:00:00Z"),
        )
        .unwrap();
    assert_eq!(
        verify_chain(&[ed_root_signed.clone(), root_signed.clone()]),
        Err(AnchorError::ChainHop {
            hop: 1,
            source: Box::new(AnchorError::UnsupportedKeyScheme("passkey".to_string())),
        })
    );

    // Malformed signer_key fails closed with InvalidPublicKey at hop 0.
    let mut bad_key = ed_root_signed.clone();
    bad_key.signer_key = "not-a-key-id".to_string();
    assert!(matches!(
        verify_chain(&[bad_key]),
        Err(AnchorError::ChainHop {
            hop: 0,
            source,
        }) if matches!(*source, AnchorError::InvalidPublicKey(_))
    ));
}

#[test]
fn verify_chain_with_verifies_heterogeneous_chain_and_rejects_tampered_envelopes() {
    let passkey = PasskeyTestSigner::new("yubikey-root", [0x77; 32]);
    let disp_kp = Ed25519Keypair::from_secret_bytes([0x88; 32]);
    let seat_kp = Ed25519Keypair::from_secret_bytes([0x99; 32]);

    let root_words = root_mandate(&passkey.key_id(), &disp_kp.key_id());
    let root_ast = parse_mandate(&root_words).unwrap();
    let root_signed = sign_mandate_with(
        &passkey,
        &root_words,
        "yubikey-fido2",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign root with passkey");

    let child_words = child_mandate(root_ast.mandate_id(), &disp_kp.key_id(), &seat_kp.key_id());
    let child_signed = disp_kp
        .sign_mandate(
            &child_words,
            "disp-ed25519",
            ts("2026-11-24T17:30:00Z"),
            ts("2026-11-24T20:00:00Z"),
        )
        .expect("sign child with ed25519");

    // Registering the passkey verifier into AnchorRegistry verifies the heterogeneous chain end-to-end.
    let mut registry = AnchorRegistry::default_registry();
    registry.register(
        "passkey",
        PasskeyTestVerifier {
            expected_key_id: passkey.key_id(),
            expected_signer: Ed25519Keypair::from_secret_bytes([0x77; 32]),
        },
    );
    let verified =
        verify_chain_with(&registry, &[root_signed.clone(), child_signed.clone()]).expect("verify");
    assert_eq!(verified.len(), 2);
    assert_eq!(verified[0].proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verified[1].proof.assurance, AssuranceLevel::LocalKey);

    let req = ActionRequest {
        actor_key: seat_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.author", Scalar::Str("valentin".to_string()));
    let (verdict, _) = authorize(
        &verified,
        &req,
        &facts,
        &QuotaSnapshot::new(),
        ts("2026-11-24T18:30:00Z"),
        None,
    );
    assert_eq!(verdict, Verdict::Permit);

    // Tampered envelope fields on hop 0 or hop 1 fail closed.
    let mut tampered_anchor = root_signed.clone();
    tampered_anchor.anchor_id = "evil-anchor".to_string();
    assert_eq!(
        verify_chain_with(&registry, &[tampered_anchor, child_signed.clone()]),
        Err(AnchorError::ChainHop {
            hop: 0,
            source: Box::new(AnchorError::InvalidSignature(
                "passkey signature mismatch".to_string()
            )),
        })
    );

    let mut tampered_window = child_signed;
    tampered_window.valid_until += 1;
    assert!(matches!(
        verify_chain_with(&registry, &[root_signed, tampered_window]),
        Err(AnchorError::ChainHop {
            hop: 1,
            source,
        }) if matches!(*source, AnchorError::InvalidSignature(_))
    ));
}

#[derive(Default)]
struct SpoofingVerifier {
    spoof_assurance: Option<AssuranceLevel>,
    spoof_anchor_id: Option<String>,
    spoof_signer_key: Option<KeyId>,
    spoof_window: Option<(i64, i64)>,
}

impl AnchorVerifier for SpoofingVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        let ast =
            parse_canonical(&signed.canonical_words).map_err(AnchorError::NonCanonicalMandate)?;
        let signer_key = self
            .spoof_signer_key
            .clone()
            .unwrap_or_else(|| KeyId::parse(&signed.signer_key).unwrap());
        let (valid_from, valid_until) = self
            .spoof_window
            .unwrap_or((signed.valid_from, signed.valid_until));
        Ok(VerifiedMandate {
            ast,
            proof: VerifiedAnchorProof {
                anchor_id: self
                    .spoof_anchor_id
                    .clone()
                    .unwrap_or_else(|| signed.anchor_id.clone()),
                assurance: self.spoof_assurance.unwrap_or(AssuranceLevel::Passkey),
                signer_key,
                actor_kind: ActorKind::Human,
                valid_from,
                valid_until,
            },
        })
    }
}

#[test]
fn verify_chain_with_enforces_liskov_postconditions_on_direct_non_registry_verifier() {
    let passkey = PasskeyTestSigner::new("yk-post", [0x33; 32]);
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x44; 32]);
    let words = root_mandate(&passkey.key_id(), &agent_kp.key_id());
    let from = ts("2026-11-24T17:00:00Z");
    let until = ts("2026-11-25T01:00:00Z");
    let signed = sign_mandate_with(&passkey, &words, "yk-post-anchor", from, until).unwrap();

    let clean = SpoofingVerifier {
        spoof_assurance: None,
        spoof_anchor_id: None,
        spoof_signer_key: None,
        spoof_window: None,
    };
    let ok = verify_chain_with(&clean, std::slice::from_ref(&signed)).expect("clean verifier");
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].proof.assurance, AssuranceLevel::Passkey);

    let spoof_assurance = SpoofingVerifier {
        spoof_assurance: Some(AssuranceLevel::QualifiedQes),
        spoof_anchor_id: None,
        spoof_signer_key: None,
        spoof_window: None,
    };
    assert_eq!(
        verify_chain_with(&spoof_assurance, std::slice::from_ref(&signed)),
        Err(AnchorError::ChainHop {
            hop: 0,
            source: Box::new(AnchorError::UnsupportedAssurance {
                expected: AssuranceLevel::Passkey,
                actual: AssuranceLevel::QualifiedQes,
            }),
        })
    );

    let spoof_anchor = SpoofingVerifier {
        spoof_assurance: None,
        spoof_anchor_id: Some("forged-anchor".to_string()),
        spoof_signer_key: None,
        spoof_window: None,
    };
    assert!(matches!(
        verify_chain_with(&spoof_anchor, std::slice::from_ref(&signed)),
        Err(AnchorError::ChainHop {
            hop: 0,
            source,
        }) if matches!(*source, AnchorError::InvalidAnchorId(_))
    ));

    let spoof_key = SpoofingVerifier {
        spoof_assurance: None,
        spoof_anchor_id: None,
        spoof_signer_key: Some(KeyId::new("passkey", "other").unwrap()),
        spoof_window: None,
    };
    assert_eq!(
        verify_chain_with(&spoof_key, std::slice::from_ref(&signed)),
        Err(AnchorError::ChainHop {
            hop: 0,
            source: Box::new(AnchorError::ProofSignerMismatch {
                source: ProofIdentitySource::Envelope,
                expected: "passkey:yk-post".to_string(),
                actual: "passkey:other".to_string(),
            }),
        })
    );

    let spoof_window = SpoofingVerifier {
        spoof_assurance: None,
        spoof_anchor_id: None,
        spoof_signer_key: None,
        spoof_window: Some((from, until + 60)),
    };
    assert_eq!(
        verify_chain_with(&spoof_window, &[signed]),
        Err(AnchorError::ChainHop {
            hop: 0,
            source: Box::new(AnchorError::ValidityWindowMismatch {
                expected_from: from,
                expected_until: until,
                actual_from: from,
                actual_until: until + 60,
            }),
        })
    );
}

#[test]
fn command_runner_fake_enables_deterministic_offline_signer_tests() {
    struct FakeRunner {
        expected_program: &'static str,
        response: Result<CommandOutput, AnchorError>,
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            stdin: &[u8],
        ) -> Result<CommandOutput, AnchorError> {
            assert_eq!(program, self.expected_program);
            assert_eq!(args, &["-Y", "sign"]);
            assert!(!stdin.is_empty());
            self.response.clone()
        }
    }

    struct SubprocessSigner<R> {
        key_id: KeyId,
        runner: R,
    }

    impl<R: CommandRunner> MandateSigner for SubprocessSigner<R> {
        fn key_id(&self) -> KeyId {
            self.key_id.clone()
        }

        fn assurance(&self) -> AssuranceLevel {
            AssuranceLevel::Passkey
        }

        fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
            let out = self.runner.run("ssh-keygen", &["-Y", "sign"], payload)?;
            Ok(out.stdout)
        }
    }

    let key_id = KeyId::new("ssh-ed25519-sk", "testfp").unwrap();
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x66; 32]);
    let words = root_mandate(&key_id, &agent_kp.key_id());

    let ok_signer = SubprocessSigner {
        key_id: key_id.clone(),
        runner: FakeRunner {
            expected_program: "ssh-keygen",
            response: Ok(CommandOutput {
                stdout: vec![0xde, 0xad, 0xbe, 0xef],
                stderr: Vec::new(),
            }),
        },
    };
    let signed = sign_mandate_with(
        &ok_signer,
        &words,
        "yubikey-ssh",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("offline fake runner signs cleanly");
    assert_eq!(signed.signature_hex, "deadbeef");
    assert_eq!(signed.assurance, "passkey");

    let err_signer = SubprocessSigner {
        key_id,
        runner: FakeRunner {
            expected_program: "ssh-keygen",
            response: Err(AnchorError::CommandFailed {
                program: "ssh-keygen".to_string(),
                status: Some(255),
                stderr: "token not present".to_string(),
            }),
        },
    };
    assert_eq!(
        sign_mandate_with(
            &err_signer,
            &words,
            "yubikey-ssh",
            ts("2026-11-24T17:00:00Z"),
            ts("2026-11-25T01:00:00Z"),
        ),
        Err(AnchorError::CommandFailed {
            program: "ssh-keygen".to_string(),
            status: Some(255),
            stderr: "token not present".to_string(),
        })
    );
}

#[test]
fn system_command_runner_handles_missing_binary_and_error_display() {
    let runner = SystemCommandRunner;
    assert_eq!(format!("{runner:?}"), "SystemCommandRunner");
    let _copy = runner;

    let missing = "handfest-definitely-missing-binary-for-test";
    let err = runner.run(missing, &["--version"], b"").unwrap_err();
    assert!(matches!(
        err,
        AnchorError::CommandIo { ref program, ref detail }
            if program == missing && !detail.is_empty()
    ));
    assert!(err
        .to_string()
        .starts_with(&format!("failed to run '{missing}': ")));
    assert!(err.source().is_none());

    // Cover all four Display formatting arms of CommandFailed.
    let with_code_and_stderr = AnchorError::CommandFailed {
        program: "gpg".to_string(),
        status: Some(2),
        stderr: "no secret key".to_string(),
    };
    assert_eq!(
        with_code_and_stderr.to_string(),
        "'gpg' exited with status 2: no secret key"
    );
    assert!(with_code_and_stderr.source().is_none());

    let with_code_only = AnchorError::CommandFailed {
        program: "gpg".to_string(),
        status: Some(2),
        stderr: String::new(),
    };
    assert_eq!(with_code_only.to_string(), "'gpg' exited with status 2");

    let signal_and_stderr = AnchorError::CommandFailed {
        program: "ykman".to_string(),
        status: None,
        stderr: "aborted".to_string(),
    };
    assert_eq!(
        signal_and_stderr.to_string(),
        "'ykman' terminated by signal: aborted"
    );

    let signal_only = AnchorError::CommandFailed {
        program: "ykman".to_string(),
        status: None,
        stderr: String::new(),
    };
    assert_eq!(signal_only.to_string(), "'ykman' terminated by signal");
}

#[cfg(unix)]
#[test]
fn system_command_runner_handles_stdio_binary_large_pipes_nonzero_and_signals() {
    let runner = SystemCommandRunner;

    // 1. Exact binary stdin -> stdout capture plus simultaneous stderr capture.
    let binary_input: Vec<u8> = (0u8..=255u8).collect();
    let out = runner
        .run("sh", &["-c", "printf 'diag\\n' >&2; cat"], &binary_input)
        .expect("binary roundtrip succeeds");
    assert_eq!(
        out,
        CommandOutput {
            stdout: binary_input,
            stderr: b"diag\n".to_vec(),
        }
    );

    // 2. Empty stdin succeeds cleanly.
    let empty_out = runner
        .run("sh", &["-c", "printf 'ok'"], b"")
        .expect("empty stdin succeeds");
    assert_eq!(empty_out.stdout, b"ok");
    assert!(empty_out.stderr.is_empty());

    // 3. Large stdin (>128 KiB, exceeding default pipe buffer) round-trips without deadlock.
    let large: Vec<u8> = (0..(192 * 1024)).map(|i| (i % 251) as u8).collect();
    let large_out = runner
        .run("cat", &[], &large)
        .expect("large pipe roundtrip succeeds without deadlock");
    assert_eq!(large_out.stdout, large);

    // 4. Non-zero exit with stderr (even when child ignores large stdin).
    let nonzero_err = runner
        .run("sh", &["-c", "echo 'boom' >&2; exit 42"], &large)
        .unwrap_err();
    assert_eq!(
        nonzero_err,
        AnchorError::CommandFailed {
            program: "sh".to_string(),
            status: Some(42),
            stderr: "boom".to_string(),
        }
    );
    assert_eq!(nonzero_err.to_string(), "'sh' exited with status 42: boom");

    // 5. Non-zero exit with empty stderr.
    let quiet_err = runner.run("sh", &["-c", "exit 7"], b"").unwrap_err();
    assert_eq!(
        quiet_err,
        AnchorError::CommandFailed {
            program: "sh".to_string(),
            status: Some(7),
            stderr: String::new(),
        }
    );

    // 6. Signal termination yields `status: None`.
    let sig_err = runner
        .run("sh", &["-c", "printf 'dying' >&2; kill -9 $$"], b"")
        .unwrap_err();
    assert_eq!(
        sig_err,
        AnchorError::CommandFailed {
            program: "sh".to_string(),
            status: None,
            stderr: "dying".to_string(),
        }
    );

    // 7. Child exits 0 after closing stdin while large payload is still being written -> fail closed.
    let broken_pipe_err = runner
        .run("sh", &["-c", "exec <&-; exit 0"], &large)
        .unwrap_err();
    assert!(matches!(
        broken_pipe_err,
        AnchorError::CommandIo { ref program, ref detail }
            if program == "sh" && !detail.is_empty()
    ));
}
