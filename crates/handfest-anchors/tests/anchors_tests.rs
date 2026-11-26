use handfest_anchors::{
    format_actor_kind, format_assurance, parse_actor_kind, parse_assurance, signing_payload,
    verify_chain, verify_ed25519, AnchorError, AnchorVerifier, AssuranceLevel, Ed25519KeyFile,
    Ed25519Keypair, Ed25519Verifier, SignedMandate, SIGNING_DOMAIN_PREFIX,
};
use handfest_core::ast::{
    parse_rfc3339_utc, KeyId, MandateId, Scalar, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::gate::{authorize, ActionRequest, QuotaSnapshot, VerifiedFacts};
use handfest_core::{ActorKind, Verdict};

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid timestamp")
}

fn root_canonical(from_key: &KeyId, to_key: &KeyId) -> String {
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

fn child_canonical(parent: MandateId, from_key: &KeyId, to_key: &KeyId) -> String {
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

#[test]
fn keypair_generation_hex_roundtrip_and_strict_validation() {
    let kp = Ed25519Keypair::generate();
    let key_id = kp.key_id();
    assert_eq!(key_id.scheme(), "ed25519");
    assert_eq!(key_id.value().len(), 64);
    assert!(key_id
        .value()
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

    let secret_hex = kp.to_secret_hex();
    assert_eq!(secret_hex.len(), 64);
    let reloaded = Ed25519Keypair::from_secret_hex(&secret_hex).expect("reload secret hex");
    assert_eq!(reloaded.key_id(), key_id);

    let key_file = kp.to_key_file();
    let json = serde_json::to_string(&key_file).expect("serialize key file");
    let parsed: Ed25519KeyFile = serde_json::from_str(&json).expect("deserialize key file");
    let from_file = Ed25519Keypair::from_key_file(&parsed).expect("load key file");
    assert_eq!(from_file.key_id(), key_id);

    // Mismatched key_id in key file is rejected.
    let mut bad_file = parsed;
    bad_file.key_id = format!("ed25519:{}", "0".repeat(64));
    assert!(matches!(
        Ed25519Keypair::from_key_file(&bad_file),
        Err(AnchorError::KeyIdMismatch { .. })
    ));

    // Strict hex/length checks on secret key loading.
    assert!(matches!(
        Ed25519Keypair::from_secret_hex("abcd"),
        Err(AnchorError::InvalidSecretKey(_))
    ));
    assert!(matches!(
        Ed25519Keypair::from_secret_hex(&secret_hex.to_uppercase()),
        Err(AnchorError::InvalidSecretKey(_))
    ));
    assert!(matches!(
        Ed25519Keypair::from_secret_hex(&format!("{}zz", &secret_hex[..62])),
        Err(AnchorError::InvalidSecretKey(_))
    ));
}

#[test]
fn sign_and_verify_roundtrip_produces_valid_verified_mandate() {
    let root_kp = Ed25519Keypair::generate();
    let disp_kp = Ed25519Keypair::generate();
    let words = root_canonical(&root_kp.key_id(), &disp_kp.key_id());

    let signed = root_kp
        .sign_mandate(
            &words,
            "local-key-1",
            ts("2026-11-24T17:00:00Z"),
            ts("2026-11-25T01:00:00Z"),
        )
        .expect("sign mandate");
    assert_eq!(signed.signature_hex.len(), 128);
    assert_eq!(signed.assurance, "local_key");
    assert_eq!(signed.actor_kind, "human");

    let json = serde_json::to_string(&signed).expect("serialize SignedMandate");
    let roundtrip: SignedMandate = serde_json::from_str(&json).expect("deserialize SignedMandate");
    let verified = Ed25519Verifier
        .verify(&roundtrip)
        .expect("verify signed mandate");
    assert_eq!(verified.proof.assurance, AssuranceLevel::LocalKey);
    assert_eq!(verified.proof.actor_kind, ActorKind::Human);
    assert_eq!(verified.proof.signer_key, root_kp.key_id());

    let req = ActionRequest {
        actor_key: disp_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.author", Scalar::Str("valentin".to_string()));
    let (verdict, receipt) = authorize(
        &[verified],
        &req,
        &facts,
        &QuotaSnapshot::new(),
        ts("2026-11-24T18:00:00Z"),
        None,
    );
    assert_eq!(verdict, Verdict::Permit);
    assert!(receipt.verify_hash());
}

#[test]
fn tamper_detection_on_canonical_text_signature_signer_and_envelope() {
    let root_kp = Ed25519Keypair::generate();
    let other_kp = Ed25519Keypair::generate();
    let disp_kp = Ed25519Keypair::generate();
    let words = root_canonical(&root_kp.key_id(), &disp_kp.key_id());

    // Refuses signing a mandate whose FROM key belongs to a different keypair.
    assert!(matches!(
        other_kp.sign_mandate(
            &words,
            "local-key",
            ts("2026-11-24T17:00:00Z"),
            ts("2026-11-25T01:00:00Z"),
        ),
        Err(AnchorError::SignerMismatch { .. })
    ));

    let signed = root_kp
        .sign_mandate(
            &words,
            "local-key",
            ts("2026-11-24T17:00:00Z"),
            ts("2026-11-25T01:00:00Z"),
        )
        .expect("sign");

    // 1-byte flip in canonical text (still valid canonical HANDFEST v1, e.g. 5 calls -> 6 calls).
    let mut tampered_words = signed.clone();
    tampered_words.canonical_words = tampered_words
        .canonical_words
        .replace("LIMIT 5 calls", "LIMIT 6 calls");
    assert!(matches!(
        verify_ed25519(&tampered_words),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 1-byte flip in signature_hex.
    let mut tampered_sig = signed.clone();
    let flipped_char = if tampered_sig.signature_hex.starts_with('0') {
        '1'
    } else {
        '0'
    };
    tampered_sig
        .signature_hex
        .replace_range(0..1, &flipped_char.to_string());
    assert!(matches!(
        verify_ed25519(&tampered_sig),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Uppercase hex signature rejected.
    let mut upper_sig = signed.clone();
    upper_sig.signature_hex = upper_sig.signature_hex.to_uppercase();
    assert!(matches!(
        verify_ed25519(&upper_sig),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Tampered signer_key rejected.
    let mut tampered_signer = signed.clone();
    tampered_signer.signer_key = other_kp.key_id().to_string();
    assert!(matches!(
        verify_ed25519(&tampered_signer),
        Err(AnchorError::SignerMismatch { .. })
    ));

    // Assurance elevation spoofing rejected.
    let mut spoofed_assurance = signed.clone();
    spoofed_assurance.assurance = "qualified_qes".to_string();
    assert!(matches!(
        verify_ed25519(&spoofed_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::LocalKey,
            actual: AssuranceLevel::QualifiedQes
        })
    ));

    // Actor kind mismatch rejected.
    let mut bad_actor = signed.clone();
    bad_actor.actor_kind = "agent".to_string();
    assert!(matches!(
        verify_ed25519(&bad_actor),
        Err(AnchorError::ActorKindMismatch { .. })
    ));

    // Invalid validity windows rejected.
    let mut reversed_window = signed.clone();
    reversed_window.valid_from = ts("2026-11-25T01:00:00Z");
    reversed_window.valid_until = ts("2026-11-24T17:00:00Z");
    assert!(matches!(
        verify_ed25519(&reversed_window),
        Err(AnchorError::InvalidValidityWindow { .. })
    ));

    let mut equal_window = signed.clone();
    equal_window.valid_until = equal_window.valid_from;
    assert!(matches!(
        verify_ed25519(&equal_window),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut out_of_bounds = signed;
    out_of_bounds.valid_from = MIN_RFC3339_TIMESTAMP - 1;
    assert!(matches!(
        verify_ed25519(&out_of_bounds),
        Err(AnchorError::InvalidTimestamp(_))
    ));
    out_of_bounds.valid_from = 0;
    out_of_bounds.valid_until = MAX_RFC3339_TIMESTAMP + 1;
    assert!(matches!(
        verify_ed25519(&out_of_bounds),
        Err(AnchorError::InvalidTimestamp(_))
    ));
}

#[test]
fn refuses_non_canonical_input_on_sign_and_verify() {
    let root_kp = Ed25519Keypair::generate();
    let disp_kp = Ed25519Keypair::generate();

    // Unsorted WHERE clauses & non-canonical pluralization ("1 hops").
    let non_canonical = format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: {from})\n",
            "TO agent \"brokkr:dispatcher\" (key: {to})\n",
            "DELEGATION max 1 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/*\"\n",
            "WHERE resource.author == \"valentin\"\n",
            "  AND context.time >= 2026-11-24T17:00:00Z\n",
            "LIMIT 5 calls\n",
        ),
        from = root_kp.key_id(),
        to = disp_kp.key_id(),
    );

    assert!(matches!(
        root_kp.sign_mandate(
            &non_canonical,
            "local-key",
            ts("2026-11-24T17:00:00Z"),
            ts("2026-11-25T01:00:00Z"),
        ),
        Err(AnchorError::NonCanonicalMandate(_))
    ));

    let bogus_signed = SignedMandate {
        canonical_words: non_canonical,
        anchor_id: "local-key".to_string(),
        assurance: "local_key".to_string(),
        actor_kind: "human".to_string(),
        signer_key: root_kp.key_id().to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: "00".repeat(64),
    };
    assert!(matches!(
        verify_ed25519(&bogus_signed),
        Err(AnchorError::NonCanonicalMandate(_))
    ));
}

#[test]
fn multi_hop_verify_chain_and_wire_helpers() {
    for kind in [
        ActorKind::Human,
        ActorKind::Org,
        ActorKind::Agent,
        ActorKind::Service,
    ] {
        assert_eq!(parse_actor_kind(format_actor_kind(kind)).unwrap(), kind);
    }
    for level in [
        AssuranceLevel::LocalKey,
        AssuranceLevel::CryptoWallet,
        AssuranceLevel::Passkey,
        AssuranceLevel::SubstantialEidas,
        AssuranceLevel::QualifiedQes,
    ] {
        assert_eq!(parse_assurance(format_assurance(level)).unwrap(), level);
    }

    assert!(matches!(verify_chain(&[]), Err(AnchorError::EmptyChain)));

    let root_kp = Ed25519Keypair::generate();
    let disp_kp = Ed25519Keypair::generate();
    let seat_kp = Ed25519Keypair::generate();

    let root_words = root_canonical(&root_kp.key_id(), &disp_kp.key_id());
    let root_ast = parse_mandate(&root_words).unwrap();
    let root_signed = root_kp
        .sign_mandate(
            &root_words,
            "root-anchor",
            ts("2026-11-24T17:00:00Z"),
            ts("2026-11-25T01:00:00Z"),
        )
        .unwrap();

    let child_words = child_canonical(root_ast.mandate_id(), &disp_kp.key_id(), &seat_kp.key_id());
    let child_signed = disp_kp
        .sign_mandate(
            &child_words,
            "disp-anchor",
            ts("2026-11-24T17:30:00Z"),
            ts("2026-11-24T20:00:00Z"),
        )
        .unwrap();

    let chain = verify_chain(&[root_signed.clone(), child_signed.clone()]).expect("verify chain");
    assert_eq!(chain.len(), 2);

    let req = ActionRequest {
        actor_key: seat_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.author", Scalar::Str("valentin".to_string()));
    let (verdict, _) = authorize(
        &chain,
        &req,
        &facts,
        &QuotaSnapshot::new(),
        ts("2026-11-24T18:30:00Z"),
        None,
    );
    assert_eq!(verdict, Verdict::Permit);

    // Tampered child hop is reported with exact hop index.
    let mut bad_child = child_signed;
    bad_child.canonical_words = bad_child
        .canonical_words
        .replace("LIMIT 2 calls", "LIMIT 1 call");
    assert!(matches!(
        verify_chain(&[root_signed, bad_child]),
        Err(AnchorError::ChainHop { hop: 1, .. })
    ));
}

#[test]
fn envelope_metadata_tampering_invalidates_signature_and_equal_window_is_signable() {
    let root_kp = Ed25519Keypair::generate();
    let other_kp = Ed25519Keypair::generate();
    let disp_kp = Ed25519Keypair::generate();
    let words = root_canonical(&root_kp.key_id(), &disp_kp.key_id());

    let valid_from = ts("2026-11-24T17:00:00Z");
    let valid_until = ts("2026-11-25T01:00:00Z");
    let signed = root_kp
        .sign_mandate(&words, "local-key-1", valid_from, valid_until)
        .expect("sign mandate");

    let base_payload = signing_payload(&signed);
    assert!(base_payload.starts_with(SIGNING_DOMAIN_PREFIX));

    // Mutating valid_until to another valid timestamp must fail signature verification.
    let mut bad_valid_until = signed.clone();
    bad_valid_until.valid_until = ts("2026-11-26T01:00:00Z");
    assert_ne!(signing_payload(&bad_valid_until), base_payload);
    assert!(matches!(
        verify_ed25519(&bad_valid_until),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Mutating valid_from to another valid timestamp must fail signature verification.
    let mut bad_valid_from = signed.clone();
    bad_valid_from.valid_from = ts("2026-11-24T16:00:00Z");
    assert_ne!(signing_payload(&bad_valid_from), base_payload);
    assert!(matches!(
        verify_ed25519(&bad_valid_from),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Mutating anchor_id must fail signature verification.
    let mut bad_anchor_id = signed.clone();
    bad_anchor_id.anchor_id = "spoofed-anchor".to_string();
    assert_ne!(signing_payload(&bad_anchor_id), base_payload);
    assert!(matches!(
        verify_ed25519(&bad_anchor_id),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Mutating assurance must both change the signed payload and fail verification.
    let mut bad_assurance = signed.clone();
    bad_assurance.assurance = "qualified_qes".to_string();
    assert_ne!(signing_payload(&bad_assurance), base_payload);
    assert!(verify_ed25519(&bad_assurance).is_err());

    // Mutating actor_kind must both change the signed payload and fail verification.
    let mut bad_actor_kind = signed.clone();
    bad_actor_kind.actor_kind = "agent".to_string();
    assert_ne!(signing_payload(&bad_actor_kind), base_payload);
    assert!(verify_ed25519(&bad_actor_kind).is_err());

    // Mutating signer_key must both change the signed payload and fail verification.
    let mut bad_signer = signed.clone();
    bad_signer.signer_key = other_kp.key_id().to_string();
    assert_ne!(signing_payload(&bad_signer), base_payload);
    assert!(verify_ed25519(&bad_signer).is_err());

    // valid_from == valid_until is permitted in anchor signing/verification, while gate rejects empty windows.
    let empty_window_signed = root_kp
        .sign_mandate(&words, "local-key-1", valid_from, valid_from)
        .expect("valid_from == valid_until should sign");
    let empty_window_verified =
        verify_ed25519(&empty_window_signed).expect("valid_from == valid_until should verify");
    let req = ActionRequest {
        actor_key: disp_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.author", Scalar::Str("valentin".to_string()));
    let (verdict, _) = authorize(
        &[empty_window_verified],
        &req,
        &facts,
        &QuotaSnapshot::new(),
        valid_from,
        None,
    );
    assert!(matches!(verdict, Verdict::Deny { ref reason } if reason.contains("validity window")));
}

mod registry_tests {
    use handfest_anchors::{
        AnchorError, AnchorRegistry, AnchorVerifier, AssuranceLevel, Ed25519Keypair, SignedMandate,
    };
    use handfest_core::ast::{
        parse_rfc3339_utc, KeyId, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
    };
    use handfest_core::cnl::{parse_canonical, parse_mandate, try_render_canonical, ParseError};
    use handfest_core::gate::{VerifiedAnchorProof, VerifiedMandate};
    use handfest_core::ActorKind;

    struct StubPasskeyVerifier;

    impl AnchorVerifier for StubPasskeyVerifier {
        fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
            let ast = parse_canonical(&signed.canonical_words)
                .map_err(AnchorError::NonCanonicalMandate)?;
            let signer_key = KeyId::parse(&signed.signer_key)
                .map_err(|err| AnchorError::InvalidPublicKey(format!("invalid KeyId: {err}")))?;
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

    fn sample_signed_ed25519() -> SignedMandate {
        let root = Ed25519Keypair::generate();
        let leaf = Ed25519Keypair::generate();
        let from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
        let until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
        let ast = parse_mandate(&format!(
            "HANDFEST v1\n\
             FROM human \"Root\" (key: {root})\n\
             TO agent \"Leaf\" (key: {leaf})\n\
             DELEGATION max 0 hops\n\
             ALLOW git.pr.merge\n\
             ON repo \"org/*\"\n",
            root = root.key_id(),
            leaf = leaf.key_id(),
        ))
        .unwrap();
        let canonical = try_render_canonical(&ast).unwrap();
        root.sign_mandate(&canonical, "anchor-1", from, until)
            .unwrap()
    }

    #[test]
    fn anchor_registry_dispatches_registered_schemes_and_fails_closed() {
        let signed = sample_signed_ed25519();
        let mut registry = AnchorRegistry::default_registry();
        assert!(format!("{registry:?}").contains("ed25519"));

        let verified = registry
            .verify(&signed)
            .expect("default registry verifies ed25519");
        assert_eq!(verified.proof.assurance, AssuranceLevel::LocalKey);

        let mut tampered = signed.clone();
        tampered.signature_hex = "00".repeat(64);
        assert!(matches!(
            registry.verify(&tampered),
            Err(AnchorError::InvalidSignature(_))
        ));

        let empty = AnchorRegistry::new();
        let err = empty.verify(&signed).unwrap_err();
        assert_eq!(
            err,
            AnchorError::UnsupportedKeyScheme("ed25519".to_string())
        );
        assert_eq!(err.to_string(), "unsupported anchor key scheme 'ed25519'");

        let mut bad_key = signed.clone();
        bad_key.signer_key = "missing-colon".to_string();
        assert!(matches!(
            registry.verify(&bad_key),
            Err(AnchorError::InvalidPublicKey(_))
        ));

        let passkey_ast = parse_mandate(
            "HANDFEST v1\n\
             FROM human \"Root\" (key: passkey:cred1)\n\
             TO agent \"Leaf\" (key: passkey:agent1)\n\
             DELEGATION max 0 hops\n\
             ALLOW git.pr.merge\n\
             ON repo \"org/*\"\n",
        )
        .unwrap();
        let passkey_signed = SignedMandate {
            canonical_words: try_render_canonical(&passkey_ast).unwrap(),
            anchor_id: "passkey-1".to_string(),
            assurance: "passkey".to_string(),
            actor_kind: "human".to_string(),
            signer_key: "passkey:cred1".to_string(),
            valid_from: signed.valid_from,
            valid_until: signed.valid_until,
            signature_hex: "00".repeat(64),
        };
        assert_eq!(
            registry.verify(&passkey_signed),
            Err(AnchorError::UnsupportedKeyScheme("passkey".to_string()))
        );

        registry.register("passkey", StubPasskeyVerifier);
        let verified_pk = registry
            .verify(&passkey_signed)
            .expect("registered passkey verifier succeeds");
        assert_eq!(verified_pk.proof.assurance, AssuranceLevel::Passkey);
    }

    struct MutatingStubVerifier {
        override_assurance: Option<AssuranceLevel>,
        override_anchor_id: Option<String>,
        override_signer_key: Option<KeyId>,
        override_actor_kind: Option<ActorKind>,
        override_window: Option<(i64, i64)>,
        override_ast: Option<handfest_core::ast::HandfestAst>,
    }

    impl MutatingStubVerifier {
        fn clean() -> Self {
            Self {
                override_assurance: None,
                override_anchor_id: None,
                override_signer_key: None,
                override_actor_kind: None,
                override_window: None,
                override_ast: None,
            }
        }
    }

    impl AnchorVerifier for MutatingStubVerifier {
        fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
            let ast = match &self.override_ast {
                Some(a) => a.clone(),
                None => parse_canonical(&signed.canonical_words)
                    .map_err(AnchorError::NonCanonicalMandate)?,
            };
            let signer_key = match &self.override_signer_key {
                Some(k) => k.clone(),
                None => KeyId::parse(&signed.signer_key)
                    .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))?,
            };
            let (valid_from, valid_until) = self
                .override_window
                .unwrap_or((signed.valid_from, signed.valid_until));
            Ok(VerifiedMandate {
                ast,
                proof: VerifiedAnchorProof {
                    anchor_id: self
                        .override_anchor_id
                        .clone()
                        .unwrap_or_else(|| signed.anchor_id.clone()),
                    assurance: self.override_assurance.unwrap_or(AssuranceLevel::Passkey),
                    signer_key,
                    actor_kind: self.override_actor_kind.unwrap_or(ActorKind::Human),
                    valid_from,
                    valid_until,
                },
            })
        }
    }

    #[test]
    fn anchor_registry_enforces_verifier_liskov_postconditions() {
        let from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
        let until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
        let ast = parse_mandate(
            "HANDFEST v1\n\
             FROM human \"Root\" (key: passkey:cred1)\n\
             TO agent \"Leaf\" (key: passkey:agent1)\n\
             DELEGATION max 0 hops\n\
             ALLOW git.pr.merge\n\
             ON repo \"org/*\"\n",
        )
        .unwrap();
        let base_signed = SignedMandate {
            canonical_words: try_render_canonical(&ast).unwrap(),
            anchor_id: "passkey-1".to_string(),
            assurance: "passkey".to_string(),
            actor_kind: "human".to_string(),
            signer_key: "passkey:cred1".to_string(),
            valid_from: from,
            valid_until: until,
            signature_hex: "00".repeat(64),
        };

        // 1. Spoofed assurance (verifier upgrades passkey -> qualified_qes)
        let mut reg = AnchorRegistry::new();
        let mut v = MutatingStubVerifier::clean();
        v.override_assurance = Some(AssuranceLevel::QualifiedQes);
        reg.register("passkey", v);
        assert_eq!(
            reg.verify(&base_signed),
            Err(AnchorError::UnsupportedAssurance {
                expected: AssuranceLevel::Passkey,
                actual: AssuranceLevel::QualifiedQes,
            })
        );

        // 2a. Empty and control-char anchor_id isolated from mismatch (signed.anchor_id matches!)
        for bad_anchor in ["", "bad\nid"] {
            let mut bad_signed = base_signed.clone();
            bad_signed.anchor_id = bad_anchor.to_string();
            let mut reg = AnchorRegistry::new();
            reg.register("passkey", MutatingStubVerifier::clean());
            assert!(
                matches!(
                    reg.verify(&bad_signed),
                    Err(AnchorError::InvalidAnchorId(ref msg)) if !msg.contains("does not match")
                ),
                "isolated invalid anchor_id {bad_anchor:?} must fail anchor_id validation"
            );
        }
        // 2b. Valid but mismatched anchor_id isolated from invalid syntax
        let mut reg = AnchorRegistry::new();
        let mut v = MutatingStubVerifier::clean();
        v.override_anchor_id = Some("other-anchor".to_string());
        reg.register("passkey", v);
        assert!(matches!(
            reg.verify(&base_signed),
            Err(AnchorError::InvalidAnchorId(ref msg)) if msg.contains("does not match")
        ));

        // 3. Mismatched signer_key (proof != envelope) and (proof != ast.from)
        let mut reg = AnchorRegistry::new();
        let mut v = MutatingStubVerifier::clean();
        v.override_signer_key = Some(KeyId::parse("passkey:other").unwrap());
        reg.register("passkey", v);
        assert!(matches!(
            reg.verify(&base_signed),
            Err(AnchorError::SignerMismatch { .. })
        ));
        let mut mismatched_env = base_signed.clone();
        mismatched_env.signer_key = "passkey:other".to_string();
        let mut clean_reg = AnchorRegistry::new();
        clean_reg.register("passkey", MutatingStubVerifier::clean());
        assert!(matches!(
            clean_reg.verify(&mismatched_env),
            Err(AnchorError::SignerMismatch { .. })
        ));

        // 4. Mismatched actor_kind (proof != envelope) and (proof != ast.from)
        let mut reg = AnchorRegistry::new();
        let mut v = MutatingStubVerifier::clean();
        v.override_actor_kind = Some(ActorKind::Agent);
        reg.register("passkey", v);
        assert!(matches!(
            reg.verify(&base_signed),
            Err(AnchorError::ActorKindMismatch { .. })
        ));
        let mut wrong_kind_env = base_signed.clone();
        wrong_kind_env.actor_kind = "agent".to_string();
        let mut reg = AnchorRegistry::new();
        let mut v = MutatingStubVerifier::clean();
        v.override_actor_kind = Some(ActorKind::Agent);
        reg.register("passkey", v);
        assert!(matches!(
            reg.verify(&wrong_kind_env),
            Err(AnchorError::ActorKindMismatch { .. })
        ));

        // 5a. Out-of-range valid_from / valid_until isolated (envelope window matches proof)
        for (wf, wu) in [
            (MIN_RFC3339_TIMESTAMP - 1, until),
            (from, MAX_RFC3339_TIMESTAMP + 1),
        ] {
            let mut bad_signed = base_signed.clone();
            bad_signed.valid_from = wf;
            bad_signed.valid_until = wu;
            let mut reg = AnchorRegistry::new();
            reg.register("passkey", MutatingStubVerifier::clean());
            assert!(matches!(
                reg.verify(&bad_signed),
                Err(AnchorError::InvalidTimestamp(_))
            ));
        }
        // 5b. Inverted window (valid_from > valid_until) isolated (envelope matches proof)
        let mut inverted_signed = base_signed.clone();
        inverted_signed.valid_from = until;
        inverted_signed.valid_until = from;
        let mut reg = AnchorRegistry::new();
        reg.register("passkey", MutatingStubVerifier::clean());
        assert_eq!(
            reg.verify(&inverted_signed),
            Err(AnchorError::InvalidValidityWindow {
                valid_from: until,
                valid_until: from,
            })
        );
        // 5c. Mismatched window isolated (proof window itself is valid_from <= valid_until)
        for (wf, wu) in [(from + 1, until), (from, until + 1)] {
            let mut reg = AnchorRegistry::new();
            let mut v = MutatingStubVerifier::clean();
            v.override_window = Some((wf, wu));
            reg.register("passkey", v);
            assert_eq!(
                reg.verify(&base_signed),
                Err(AnchorError::InvalidValidityWindow {
                    valid_from: wf,
                    valid_until: wu,
                })
            );
        }

        // 6. AST does not match signed.canonical_words
        let widened_ast = parse_mandate(
            "HANDFEST v1\n\
             FROM human \"Root\" (key: passkey:cred1)\n\
             TO agent \"Leaf\" (key: passkey:agent1)\n\
             DELEGATION max 0 hops\n\
             ALLOW git.*\n\
             ON repo \"org/*\"\n",
        )
        .unwrap();
        let mut reg = AnchorRegistry::new();
        let mut v = MutatingStubVerifier::clean();
        v.override_ast = Some(widened_ast);
        reg.register("passkey", v);
        assert!(matches!(
            reg.verify(&base_signed),
            Err(AnchorError::NonCanonicalMandate(
                ParseError::NonCanonical { .. }
            ))
        ));
    }

    #[test]
    fn ed25519_verifier_and_default_registry_agree_on_equal_validity_bounds() {
        use handfest_anchors::{verify_verifier_postconditions, Ed25519Keypair, Ed25519Verifier};
        use handfest_core::gate::{authorize, ActionRequest, QuotaSnapshot, VerifiedFacts};
        use handfest_core::Verdict;

        let kp = Ed25519Keypair::generate();
        let leaf_kp = Ed25519Keypair::generate();
        let text = format!(
            "HANDFEST v1\n\
             FROM human \"Root\" (key: {})\n\
             TO agent \"Leaf\" (key: {})\n\
             DELEGATION max 0 hops\n\
             ALLOW git.pr.merge\n\
             ON repo \"org/*\"\n",
            kp.key_id(),
            leaf_kp.key_id(),
        );
        let t = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
        let signed = kp
            .sign_mandate(&text, "eq-bounds", t, t)
            .expect("equal valid_from == valid_until signs cleanly");

        let direct = Ed25519Verifier
            .verify(&signed)
            .expect("Ed25519Verifier accepts equal bounds");
        let via_registry = AnchorRegistry::default_registry()
            .verify(&signed)
            .expect("AnchorRegistry::default_registry agrees with Ed25519Verifier");
        assert_eq!(direct, via_registry);
        assert_eq!(verify_verifier_postconditions(&signed, &direct), Ok(()));

        // Invalid signer_key in envelope is rejected directly by verify_verifier_postconditions.
        let mut bad_key_signed = signed.clone();
        bad_key_signed.signer_key = "not-a-key-id".to_string();
        assert!(matches!(
            verify_verifier_postconditions(&bad_key_signed, &direct),
            Err(AnchorError::InvalidPublicKey(_))
        ));

        // Gate evaluation still denies the empty [t, t) validity window at `now = t`.
        let (verdict, _) = authorize(
            &[via_registry],
            &ActionRequest {
                actor_key: leaf_kp.key_id(),
                action: "git.pr.merge".into(),
                resource_kind: "repo".into(),
                resource_id: "org/app".into(),
            },
            &VerifiedFacts::new(),
            &QuotaSnapshot::new(),
            t,
            None,
        );
        assert!(matches!(
            verdict,
            Verdict::Deny { ref reason } if reason.contains("outside anchor proof validity window")
        ));
    }
}
