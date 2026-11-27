//! Comprehensive unit, boundary, authority, and cascade tests for `HANDFEST REVOKE v1`.

use std::collections::BTreeMap;
use std::error::Error as _;

use handfest_core::ast::{
    parse_rfc3339_utc, ActionPat, ActorDecl, AstError, Decimal, HandfestAstBuilder, KeyId,
    MandateId, ResourceSel, Scalar, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::ParseError;
use handfest_core::gate::{
    authorize_with_revocations, check_chain_revocations, ActionRequest, DenyReason,
    ProofShapeError, QuotaSnapshot, RevocationProofError, RevocationSnapshot, VerifiedAnchorProof,
    VerifiedFacts, VerifiedMandate, VerifiedRevocation,
};
use handfest_core::revocation::{
    parse_canonical_revocation, parse_revocation, render_canonical_revocation,
    try_render_canonical_revocation, RevocationAst, RevocationId, RevocationTarget,
};
use handfest_core::{ActorKind, AssuranceLevel, Verdict, REVOCATION_VERSION};

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 UTC timestamp")
}

fn key(hex_char: char) -> KeyId {
    KeyId::new("ed25519", hex_char.to_string().repeat(64)).expect("valid key")
}

fn actor(kind: ActorKind, name: &str, key: KeyId) -> ActorDecl {
    ActorDecl::new(kind, name, key, BTreeMap::new()).expect("valid actor")
}

fn proof_for(actor: &ActorDecl, valid_from: i64, valid_until: i64) -> VerifiedAnchorProof {
    VerifiedAnchorProof {
        anchor_id: "local-ed25519".to_string(),
        assurance: AssuranceLevel::LocalKey,
        signer_key: actor.key().clone(),
        actor_kind: actor.kind(),
        valid_from,
        valid_until,
    }
}

fn make_mandate(
    parent: Option<MandateId>,
    from: ActorDecl,
    to: ActorDecl,
    max_hops: u32,
    valid_from: i64,
    valid_until: i64,
) -> VerifiedMandate {
    let proof = proof_for(&from, valid_from, valid_until);
    let ast = HandfestAstBuilder {
        parent,
        from,
        to,
        max_hops,
        allow: vec![ActionPat::parse("git.pr.merge").unwrap()],
        on: vec![ResourceSel::new("repo", "feedback-loop-ai/*").unwrap()],
        where_clauses: vec![],
        limits: vec![],
    }
    .build()
    .expect("valid mandate");
    VerifiedMandate { ast, proof }
}

fn make_revocation(
    by: ActorDecl,
    target: RevocationTarget,
    effective_at: i64,
    reason: Option<&str>,
    valid_from: i64,
    valid_until: i64,
) -> VerifiedRevocation {
    let proof = proof_for(&by, valid_from, valid_until);
    let ast = RevocationAst::new(by, target, effective_at, reason.map(str::to_string))
        .expect("valid revocation");
    VerifiedRevocation { ast, proof }
}

fn sample_three_hop_chain() -> (
    ActorDecl,
    ActorDecl,
    ActorDecl,
    ActorDecl,
    Vec<VerifiedMandate>,
) {
    let alice = actor(ActorKind::Human, "Alice", key('a'));
    let bob = actor(ActorKind::Org, "Bob", key('b'));
    let carol = actor(ActorKind::Service, "Carol", key('c'));
    let agent = actor(ActorKind::Agent, "Agent", key('d'));
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");

    let m0 = make_mandate(None, alice.clone(), bob.clone(), 2, vf, vu);
    let m1 = make_mandate(
        Some(m0.ast.mandate_id()),
        bob.clone(),
        carol.clone(),
        1,
        vf,
        vu,
    );
    let m2 = make_mandate(
        Some(m1.ast.mandate_id()),
        carol.clone(),
        agent.clone(),
        0,
        vf,
        vu,
    );
    (alice, bob, carol, agent, vec![m0, m1, m2])
}

#[test]
fn canonical_round_trip_mandate_and_key_with_and_without_reason() {
    assert_eq!(REVOCATION_VERSION, "HANDFEST REVOKE v1");
    let mid = MandateId::sha256(b"mandate-1");
    let alice_key = key('a');
    let compromised_key = key('f');

    let with_reason = format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin \\\"V\\\" \\\\ Admin\" (key: {alice_key})\n\
         TARGET mandate {mid}\n\
         EFFECTIVE 2026-11-26T17:15:00Z\n\
         REASON \"Task \\\"finished\\\" early \\\\ done\"\n"
    );
    let ast = parse_canonical_revocation(&with_reason).expect("canonical parse");
    assert_eq!(render_canonical_revocation(&ast), with_reason);
    assert_eq!(try_render_canonical_revocation(&ast).unwrap(), with_reason);
    assert_eq!(ast.target(), &RevocationTarget::Mandate(mid));
    assert_eq!(ast.effective_at(), ts("2026-11-26T17:15:00Z"));
    assert_eq!(ast.reason(), Some("Task \"finished\" early \\ done"));

    let rev_id = ast.try_revocation_id().unwrap();
    assert_eq!(rev_id, ast.revocation_id());
    assert_eq!(rev_id, RevocationId::sha256(with_reason.as_bytes()));
    assert_eq!(RevocationId::parse(&rev_id.to_string()).unwrap(), rev_id);
    assert_eq!(rev_id.to_string().parse::<RevocationId>().unwrap(), rev_id);
    assert_eq!(rev_id.as_bytes().len(), 32);
    assert!(format!("{rev_id:?}").starts_with("RevocationId(\"sha256:"));

    let key_rev = format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin\" (key: {alice_key})\n\
         TARGET key {compromised_key}\n\
         EFFECTIVE 0000-01-01T00:00:00Z\n"
    );
    let key_ast = parse_canonical_revocation(&key_rev).expect("canonical key revocation");
    assert_eq!(render_canonical_revocation(&key_ast), key_rev);
    assert_eq!(key_ast.target(), &RevocationTarget::Key(compromised_key));
    assert_eq!(key_ast.effective_at(), MIN_RFC3339_TIMESTAMP);
    assert_eq!(key_ast.reason(), None);

    let max_rev = format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin\" (key: {alice_key})\n\
         TARGET mandate {mid}\n\
         EFFECTIVE 9999-12-31T23:59:59Z\n"
    );
    let max_ast = parse_canonical_revocation(&max_rev).expect("max timestamp");
    assert_eq!(max_ast.effective_at(), MAX_RFC3339_TIMESTAMP);
}

#[test]
fn revocation_grammar_and_canonicality_reject_invalid_inputs() {
    let mid = MandateId::sha256(b"m");
    let k = key('a');

    assert!(matches!(
        parse_revocation(""),
        Err(ParseError::Syntax { line: 1, .. })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET mandate {mid}\nEFFECTIVE 2026-11-26T17:15:00Z"
        )),
        Err(ParseError::Syntax { .. })
    ));
    assert!(matches!(
        parse_revocation("HANDFEST v1\n"),
        Err(ParseError::Syntax { line: 1, .. })
    ));
    assert!(matches!(
        parse_revocation("HANDFEST REVOKE v1\n"),
        Err(ParseError::Syntax { line: 2, .. })
    ));
    assert!(matches!(
        parse_revocation(&format!("HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\n")),
        Err(ParseError::Syntax { line: 3, .. })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET mandate {mid}\n"
        )),
        Err(ParseError::Syntax { line: 4, .. })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET user foo\nEFFECTIVE 2026-11-26T17:15:00Z\n"
        )),
        Err(ParseError::Syntax { line: 3, .. })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET mandate sha256:ZZZZ\nEFFECTIVE 2026-11-26T17:15:00Z\n"
        )),
        Err(ParseError::Ast {
            line: 3,
            error: AstError::InvalidMandateId(_)
        })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET key badkey\nEFFECTIVE 2026-11-26T17:15:00Z\n"
        )),
        Err(ParseError::Ast {
            line: 3,
            error: AstError::InvalidKeyId(_)
        })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET mandate {mid}\nEFFECTIVE 2026-02-29T00:00:00Z\n"
        )),
        Err(ParseError::Ast {
            line: 4,
            error: AstError::InvalidTimestamp(_)
        })
    ));
}

#[test]
fn revocation_reason_canonicality_and_id_validation() {
    let mid = MandateId::sha256(b"m");
    let k = key('a');
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET mandate {mid}\nEFFECTIVE 2026-11-26T17:15:00Z\nREASON \"\"\n"
        )),
        Err(ParseError::Ast {
            error: AstError::InvalidString(_),
            ..
        })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET mandate {mid}\nEFFECTIVE 2026-11-26T17:15:00Z\nREASON \"bad\tctrl\"\n"
        )),
        Err(ParseError::Syntax { line: 5, .. })
    ));
    assert!(matches!(
        parse_revocation(&format!(
            "HANDFEST REVOKE v1\nBY human \"A\" (key: {k})\nTARGET mandate {mid}\nEFFECTIVE 2026-11-26T17:15:00Z\nEXTRA line\n"
        )),
        Err(ParseError::Syntax { line: 5, .. })
    ));

    let crlf = format!(
        "HANDFEST REVOKE v1\r\nBY human \"A\" (key: {k})\r\nTARGET mandate {mid}\r\nEFFECTIVE 2026-11-26T17:15:00Z\r\n"
    );
    assert!(parse_revocation(&crlf).is_ok());
    assert!(matches!(
        parse_canonical_revocation(&crlf),
        Err(ParseError::NonCanonical { .. })
    ));

    let non_canon_attr = format!(
        "HANDFEST REVOKE v1\nBY human \"A\" (key: {k}, score: 10.00)\nTARGET mandate {mid}\nEFFECTIVE 2026-11-26T17:15:00Z\n"
    );
    let parsed_attr = parse_revocation(&non_canon_attr).expect("non-canonical parses");
    assert_eq!(
        parsed_attr.by().attrs().get("score"),
        Some(&Scalar::Decimal(Decimal::parse("10.0").unwrap()))
    );
    assert!(matches!(
        parse_canonical_revocation(&non_canon_attr),
        Err(ParseError::NonCanonical { .. })
    ));

    let by = actor(ActorKind::Human, "Alice", k);
    assert!(matches!(
        RevocationAst::new(
            by.clone(),
            RevocationTarget::Mandate(mid),
            MIN_RFC3339_TIMESTAMP - 1,
            None
        ),
        Err(AstError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        RevocationAst::new(
            by,
            RevocationTarget::Mandate(mid),
            MAX_RFC3339_TIMESTAMP + 1,
            None
        ),
        Err(AstError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        RevocationId::parse("md5:0000"),
        Err(AstError::InvalidRevocationId(_))
    ));
    assert!(matches!(
        RevocationId::parse("sha256:abcd"),
        Err(AstError::InvalidRevocationId(_))
    ));
    assert!(matches!(
        RevocationId::parse(&format!("sha256:{}", "A".repeat(64))),
        Err(AstError::InvalidRevocationId(_))
    ));
}

#[test]
fn revocation_snapshot_validates_proof_bindings_and_rejects_mismatches() {
    let alice = actor(ActorKind::Human, "Alice", key('a'));
    let bob = actor(ActorKind::Org, "Bob", key('b'));
    let mid = MandateId::sha256(b"target");
    let eff = ts("2026-11-26T12:00:00Z");

    let mut snap = RevocationSnapshot::new();
    assert!(snap.is_empty());

    let mut bad_signer = make_revocation(
        alice.clone(),
        RevocationTarget::Mandate(mid),
        eff,
        None,
        eff,
        eff + 60,
    );
    bad_signer.proof.signer_key = bob.key().clone();
    let err = snap.insert(bad_signer).unwrap_err();
    assert!(matches!(err, RevocationProofError::SignerMismatch { .. }));
    assert!(err.source().is_none());
    assert!(err.to_string().contains("does not match BY key"));

    let mut bad_kind = make_revocation(
        alice.clone(),
        RevocationTarget::Mandate(mid),
        eff,
        None,
        eff,
        eff + 60,
    );
    bad_kind.proof.actor_kind = ActorKind::Agent;
    let err = snap.insert(bad_kind).unwrap_err();
    assert!(matches!(
        err,
        RevocationProofError::ActorKindMismatch { .. }
    ));
    assert!(err.to_string().contains("does not match BY kind"));

    let mut bad_anchor = make_revocation(
        alice.clone(),
        RevocationTarget::Mandate(mid),
        eff,
        None,
        eff,
        eff + 60,
    );
    bad_anchor.proof.anchor_id = String::new();
    let err = snap.insert(bad_anchor).unwrap_err();
    assert!(matches!(
        err,
        RevocationProofError::ProofShape(ProofShapeError::EmptyAnchorId)
    ));
    assert!(err.source().is_some());

    let mut inverted = make_revocation(
        alice,
        RevocationTarget::Mandate(mid),
        eff,
        None,
        eff + 10,
        eff,
    );
    inverted.proof.valid_from = eff + 10;
    inverted.proof.valid_until = eff;
    let err = snap.insert(inverted).unwrap_err();
    assert!(matches!(
        err,
        RevocationProofError::ProofShape(ProofShapeError::InvertedValidityWindow { .. })
    ));
    assert!(snap.is_empty());
}

#[test]
fn mandate_revocation_authority_cascade_and_effective_time() {
    let (alice, _bob, _carol, agent, chain) = sample_three_hop_chain();
    let m0_id = chain[0].ast.mandate_id();
    let eff = ts("2026-11-26T14:00:00Z");
    let req = ActionRequest {
        actor_key: agent.key().clone(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };

    // 1. Root principal Alice revoking root m_0 denies [m_0, m_1, m_2] once now >= eff,
    //    permits before eff, and stays denied even after rev.proof.valid_until passes.
    let mut snap = RevocationSnapshot::new();
    let rev_m0 = make_revocation(
        alice.clone(),
        RevocationTarget::Mandate(m0_id),
        eff,
        Some("compromised"),
        eff - 60,
        eff + 60,
    );
    let rev_m0_id = snap.insert(rev_m0).unwrap();

    assert!(check_chain_revocations(&chain, &snap, eff - 1).is_ok());
    let (verdict_before, _) = authorize_with_revocations(
        &chain,
        &req,
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        &snap,
        eff - 1,
        None,
    );
    assert_eq!(verdict_before, Verdict::Permit);

    let deny = check_chain_revocations(&chain, &snap, eff).unwrap_err();
    assert_eq!(
        deny,
        DenyReason::MandateRevoked {
            hop: 0,
            mandate_id: m0_id,
            revocation_id: rev_m0_id,
        }
    );
    let (verdict_at, receipt) = authorize_with_revocations(
        &chain,
        &req,
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        &snap,
        eff,
        None,
    );
    assert_eq!(
        verdict_at,
        Verdict::Deny {
            reason: deny.to_string()
        }
    );
    assert!(receipt.verify_hash());

    // After rev.proof.valid_until -> STILL DENIED (no resurrection).
    assert_eq!(
        check_chain_revocations(&chain, &snap, eff + 3600).unwrap_err(),
        deny
    );
}

#[test]
fn child_revocation_self_renunciation_and_third_party_dos_defense() {
    let (alice, bob, _carol, agent, chain) = sample_three_hop_chain();
    let m0_id = chain[0].ast.mandate_id();
    let m1_id = chain[1].ast.mandate_id();
    let m2_id = chain[2].ast.mandate_id();
    let eff = ts("2026-11-26T14:00:00Z");
    // 2. Root principal Alice revoking child m_1 denies [m_0, m_1] and [m_0, m_1, m_2].
    let mut snap_m1 = RevocationSnapshot::new();
    let rev_m1_id = snap_m1
        .insert(make_revocation(
            alice,
            RevocationTarget::Mandate(m1_id),
            eff,
            None,
            eff,
            eff + 3600,
        ))
        .unwrap();
    assert_eq!(
        check_chain_revocations(&chain[..2], &snap_m1, eff).unwrap_err(),
        DenyReason::MandateRevoked {
            hop: 1,
            mandate_id: m1_id,
            revocation_id: rev_m1_id,
        }
    );
    assert_eq!(
        check_chain_revocations(&chain, &snap_m1, eff).unwrap_err(),
        DenyReason::MandateRevoked {
            hop: 1,
            mandate_id: m1_id,
            revocation_id: rev_m1_id,
        }
    );

    // 3. Self-renunciation by grantee Bob (on m_0) and Agent (on m_2) both deny.
    let mut snap_self_bob = RevocationSnapshot::new();
    let bob_rev_id = snap_self_bob
        .insert(make_revocation(
            bob,
            RevocationTarget::Mandate(m0_id),
            eff,
            Some("self-renounce"),
            eff,
            eff + 60,
        ))
        .unwrap();
    assert_eq!(
        check_chain_revocations(&chain, &snap_self_bob, eff).unwrap_err(),
        DenyReason::MandateRevoked {
            hop: 0,
            mandate_id: m0_id,
            revocation_id: bob_rev_id,
        }
    );

    let mut snap_self_agent = RevocationSnapshot::new();
    let agent_rev_id = snap_self_agent
        .insert(make_revocation(
            agent.clone(),
            RevocationTarget::Mandate(m2_id),
            eff,
            None,
            eff,
            eff + 60,
        ))
        .unwrap();
    assert_eq!(
        check_chain_revocations(&chain, &snap_self_agent, eff).unwrap_err(),
        DenyReason::MandateRevoked {
            hop: 2,
            mandate_id: m2_id,
            revocation_id: agent_rev_id,
        }
    );
}

#[test]
fn unauthorized_third_party_and_downstream_mandate_revocations_are_ignored() {
    let (_alice, _bob, carol, agent, chain) = sample_three_hop_chain();
    let eve = actor(ActorKind::Human, "Eve", key('e'));
    let m0_id = chain[0].ast.mandate_id();
    let m1_id = chain[1].ast.mandate_id();
    let eff = ts("2026-11-26T14:00:00Z");
    let req = ActionRequest {
        actor_key: agent.key().clone(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let mut unauth_snap = RevocationSnapshot::new();
    unauth_snap
        .insert(make_revocation(
            eve,
            RevocationTarget::Mandate(m0_id),
            eff,
            Some("dos attempt"),
            eff,
            eff + 60,
        ))
        .unwrap();
    unauth_snap
        .insert(make_revocation(
            carol,
            RevocationTarget::Mandate(m0_id),
            eff,
            Some("downstream attempt"),
            eff,
            eff + 60,
        ))
        .unwrap();
    unauth_snap
        .insert(make_revocation(
            agent,
            RevocationTarget::Mandate(m1_id),
            eff,
            Some("leaf targeting parent"),
            eff,
            eff + 60,
        ))
        .unwrap();
    assert_eq!(check_chain_revocations(&chain, &unauth_snap, eff), Ok(()));
    let (verdict_unauth, _) = authorize_with_revocations(
        &chain,
        &req,
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        &unauth_snap,
        eff,
        None,
    );
    assert_eq!(verdict_unauth, Verdict::Permit);
}

#[test]
fn key_kill_switch_authority_cascade_and_cycle_defense() {
    let (alice, bob, carol, agent, chain) = sample_three_hop_chain();
    let eve = actor(ActorKind::Human, "Eve", key('e'));
    let eff = ts("2026-11-26T14:00:00Z");

    let mut snap = RevocationSnapshot::new();
    let id = snap
        .insert(make_revocation(
            alice.clone(),
            RevocationTarget::Key(alice.key().clone()),
            eff,
            Some("lost yubikey"),
            eff,
            eff + 60,
        ))
        .unwrap();
    assert_eq!(
        check_chain_revocations(&chain, &snap, eff).unwrap_err(),
        DenyReason::KeyRevoked {
            hop: 0,
            key_id: alice.key().clone(),
            revocation_id: id,
        }
    );

    let mut snap_agent = RevocationSnapshot::new();
    let id_agent = snap_agent
        .insert(make_revocation(
            alice.clone(),
            RevocationTarget::Key(agent.key().clone()),
            eff,
            None,
            eff,
            eff + 60,
        ))
        .unwrap();
    assert_eq!(
        check_chain_revocations(&chain, &snap_agent, eff).unwrap_err(),
        DenyReason::KeyRevoked {
            hop: 2,
            key_id: agent.key().clone(),
            revocation_id: id_agent,
        }
    );

    let mut unauth = RevocationSnapshot::new();
    unauth
        .insert(make_revocation(
            carol,
            RevocationTarget::Key(bob.key().clone()),
            eff,
            None,
            eff,
            eff + 60,
        ))
        .unwrap();
    unauth
        .insert(make_revocation(
            bob.clone(),
            RevocationTarget::Key(alice.key().clone()),
            eff,
            None,
            eff,
            eff + 60,
        ))
        .unwrap();
    unauth
        .insert(make_revocation(
            eve,
            RevocationTarget::Key(agent.key().clone()),
            eff,
            None,
            eff,
            eff + 60,
        ))
        .unwrap();
    assert_eq!(check_chain_revocations(&chain, &unauth, eff), Ok(()));
}

#[test]
fn key_kill_switch_defends_against_cyclic_delegation() {
    let alice = actor(ActorKind::Human, "Alice", key('a'));
    let bob = actor(ActorKind::Org, "Bob", key('b'));
    let eff = ts("2026-11-26T14:00:00Z");
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");
    let c0 = make_mandate(None, alice.clone(), bob.clone(), 1, vf, vu);
    let c1 = make_mandate(
        Some(c0.ast.mandate_id()),
        bob.clone(),
        alice.clone(),
        0,
        vf,
        vu,
    );
    let cyclic_chain = vec![c0, c1];
    let mut bob_revokes_alice = RevocationSnapshot::new();
    let rev_id = bob_revokes_alice
        .insert(make_revocation(
            bob,
            RevocationTarget::Key(alice.key().clone()),
            eff,
            None,
            eff,
            eff + 60,
        ))
        .unwrap();
    // Bob is upstream of Alice at hop 1 (Bob -> Alice), so Bob's key revocation of Alice MUST deny at hop 1.
    assert_eq!(
        check_chain_revocations(&cyclic_chain, &bob_revokes_alice, eff),
        Err(DenyReason::KeyRevoked {
            hop: 1,
            key_id: alice.key().clone(),
            revocation_id: rev_id,
        })
    );
    // Out-of-range evaluation timestamp fails closed.
    assert_eq!(
        check_chain_revocations(
            &cyclic_chain,
            &bob_revokes_alice,
            handfest_core::ast::MIN_RFC3339_TIMESTAMP - 1
        ),
        Err(DenyReason::InvalidTimestamp(
            handfest_core::ast::MIN_RFC3339_TIMESTAMP - 1
        ))
    );
}
