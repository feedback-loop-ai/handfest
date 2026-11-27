//! Domain-separated signing, cross-domain replay rejection, hardware-anchor verification,
//! and Liskov postcondition tests for `HANDFEST REVOKE v1`.

use ed25519_dalek::{Signer as _, SigningKey};
use handfest_anchors::{
    format_fido2_ed25519_key_id, piv_ed25519_key_id, revocation_signing_payload,
    sign_revocation_with, signing_payload, verify_ed25519, verify_revocation,
    verify_revocation_ed25519, verify_revocation_fido2_ed25519, verify_revocation_piv_ed25519,
    verify_revocation_with, verify_revocations, AnchorError, AnchorRegistry, AnchorVerifier,
    AssuranceLevel, Ed25519Keypair, Fido2AssertionEnvelope, MandateSigner, ProofIdentitySource,
    SignedMandate, SignedRevocation, DEFAULT_FIDO2_RP_ID, FIDO2_FLAG_UP,
    REVOCATION_SIGNING_DOMAIN_PREFIX, SIGNING_DOMAIN_PREFIX,
};
use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId};
use handfest_core::gate::{VerifiedMandate, VerifiedRevocation};
use handfest_core::revocation::{parse_canonical_revocation, RevocationTarget};
use handfest_core::ActorKind;
use sha2::{Digest, Sha256};

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid timestamp")
}

fn canonical_revocation_text(by_key: &KeyId, target: &MandateId) -> String {
    format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin\" (key: {by_key})\n\
         TARGET mandate {target}\n\
         EFFECTIVE 2026-11-26T17:15:00Z\n\
         REASON \"Task finished early\"\n"
    )
}

fn canonical_mandate_text(from_key: &KeyId, to_key: &KeyId) -> String {
    format!(
        "HANDFEST v1\n\
         FROM human \"Valentin\" (key: {from_key})\n\
         TO agent \"Bot\" (key: {to_key})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/app\"\n"
    )
}

#[test]
fn ed25519_revocation_round_trip_and_serde_deny_unknown_fields() {
    let kp = Ed25519Keypair::from_secret_bytes([0x11; 32]);
    let target = MandateId::sha256(b"mandate-abc");
    let words = canonical_revocation_text(&kp.key_id(), &target);
    let vf = ts("2026-11-26T17:00:00Z");
    let vu = ts("2026-11-26T18:00:00Z");

    let signed = kp
        .sign_revocation(&words, "local-ed25519", vf, vu)
        .expect("sign revocation");

    let verified = verify_revocation_ed25519(&signed).expect("verify ed25519");
    assert_eq!(verified.ast.target(), &RevocationTarget::Mandate(target));
    assert_eq!(verified.proof.signer_key, kp.key_id());
    assert_eq!(verified.proof.assurance, AssuranceLevel::LocalKey);
    assert_eq!(verified.proof.actor_kind, ActorKind::Human);

    let via_registry = verify_revocation(&signed).expect("verify via default registry");
    assert_eq!(via_registry, verified);

    let snap =
        verify_revocations(std::slice::from_ref(&signed)).expect("verify revocations snapshot");
    assert_eq!(snap.len(), 1);

    let json = serde_json::to_string(&signed).unwrap();
    let decoded: SignedRevocation = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, signed);

    let with_extra = format!("{},\"extra\":true}}", &json[..json.len() - 1]);
    let err = serde_json::from_str::<SignedRevocation>(&with_extra).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn cross_domain_replay_between_mandate_and_revocation_fails_closed() {
    assert_ne!(REVOCATION_SIGNING_DOMAIN_PREFIX, SIGNING_DOMAIN_PREFIX);
    assert_eq!(REVOCATION_SIGNING_DOMAIN_PREFIX, b"handfest-v1-revoke\0");

    let seed = [0x22; 32];
    let kp = Ed25519Keypair::from_secret_bytes(seed);
    let raw_sk = SigningKey::from_bytes(&seed);
    let to_key = Ed25519Keypair::from_secret_bytes([0x33; 32]).key_id();
    let vf = ts("2026-11-26T17:00:00Z");
    let vu = ts("2026-11-26T18:00:00Z");

    let mandate_words = canonical_mandate_text(&kp.key_id(), &to_key);
    let signed_mandate = kp
        .sign_mandate(&mandate_words, "local-ed25519", vf, vu)
        .unwrap();
    let replayed_as_rev = SignedRevocation {
        canonical_words: signed_mandate.canonical_words.clone(),
        anchor_id: signed_mandate.anchor_id.clone(),
        assurance: signed_mandate.assurance.clone(),
        actor_kind: signed_mandate.actor_kind.clone(),
        signer_key: signed_mandate.signer_key.clone(),
        valid_from: signed_mandate.valid_from,
        valid_until: signed_mandate.valid_until,
        signature_hex: signed_mandate.signature_hex.clone(),
    };
    assert!(matches!(
        verify_revocation_ed25519(&replayed_as_rev),
        Err(AnchorError::NonCanonicalRevocation(_))
    ));

    // Sign valid revocation words under SIGNING_DOMAIN_PREFIX -> must fail as revocation.
    let target = MandateId::sha256(b"m0");
    let rev_words = canonical_revocation_text(&kp.key_id(), &target);
    let fake_mandate_envelope = SignedMandate {
        canonical_words: rev_words.clone(),
        anchor_id: "local-ed25519".to_string(),
        assurance: "local_key".to_string(),
        actor_kind: "human".to_string(),
        signer_key: kp.key_id().to_string(),
        valid_from: vf,
        valid_until: vu,
        signature_hex: String::new(),
    };
    let cross_domain_sig = hex::encode(
        raw_sk
            .sign(&signing_payload(&fake_mandate_envelope))
            .to_bytes(),
    );
    let forged_rev = SignedRevocation {
        canonical_words: rev_words,
        anchor_id: "local-ed25519".to_string(),
        assurance: "local_key".to_string(),
        actor_kind: "human".to_string(),
        signer_key: kp.key_id().to_string(),
        valid_from: vf,
        valid_until: vu,
        signature_hex: cross_domain_sig,
    };
    assert!(matches!(
        verify_revocation_ed25519(&forged_rev),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Reverse: sign valid mandate words under REVOCATION_SIGNING_DOMAIN_PREFIX -> must fail as mandate.
    let fake_rev_envelope = SignedRevocation {
        canonical_words: mandate_words.clone(),
        anchor_id: "local-ed25519".to_string(),
        assurance: "local_key".to_string(),
        actor_kind: "human".to_string(),
        signer_key: kp.key_id().to_string(),
        valid_from: vf,
        valid_until: vu,
        signature_hex: String::new(),
    };
    let reverse_sig = hex::encode(
        raw_sk
            .sign(&revocation_signing_payload(&fake_rev_envelope))
            .to_bytes(),
    );
    let forged_mandate = SignedMandate {
        canonical_words: mandate_words,
        anchor_id: "local-ed25519".to_string(),
        assurance: "local_key".to_string(),
        actor_kind: "human".to_string(),
        signer_key: kp.key_id().to_string(),
        valid_from: vf,
        valid_until: vu,
        signature_hex: reverse_sig,
    };
    assert!(matches!(
        verify_ed25519(&forged_mandate),
        Err(AnchorError::InvalidSignature(_))
    ));
}

#[test]
fn revocation_envelope_tampering_and_signing_guards_fail_closed() {
    let kp = Ed25519Keypair::from_secret_bytes([0x44; 32]);
    let other_kp = Ed25519Keypair::from_secret_bytes([0x55; 32]);
    let target = MandateId::sha256(b"tamper-target");
    let words = canonical_revocation_text(&kp.key_id(), &target);
    let vf = ts("2026-11-26T17:00:00Z");
    let vu = ts("2026-11-26T18:00:00Z");

    assert!(matches!(
        other_kp.sign_revocation(&words, "local-ed25519", vf, vu),
        Err(AnchorError::SignerMismatch { .. })
    ));

    struct EmptySigner(KeyId);
    impl MandateSigner for EmptySigner {
        fn key_id(&self) -> KeyId {
            self.0.clone()
        }
        fn assurance(&self) -> AssuranceLevel {
            AssuranceLevel::LocalKey
        }
        fn sign_payload(&self, _payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
            Ok(Vec::new())
        }
    }
    assert!(matches!(
        sign_revocation_with(&EmptySigner(kp.key_id()), &words, "local-ed25519", vf, vu),
        Err(AnchorError::InvalidSignature(_))
    ));

    let signed = kp.sign_revocation(&words, "local-ed25519", vf, vu).unwrap();

    let mut bad_anchor = signed.clone();
    bad_anchor.anchor_id = "other-anchor".to_string();
    assert!(matches!(
        verify_revocation_ed25519(&bad_anchor),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut bad_window = signed.clone();
    bad_window.valid_until += 1;
    assert!(matches!(
        verify_revocation_ed25519(&bad_window),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut bad_assurance = signed.clone();
    bad_assurance.assurance = "passkey".to_string();
    assert!(matches!(
        verify_revocation_ed25519(&bad_assurance),
        Err(AnchorError::UnsupportedAssurance { .. })
    ));

    let mut bad_kind = signed.clone();
    bad_kind.actor_kind = "agent".to_string();
    assert!(matches!(
        verify_revocation_ed25519(&bad_kind),
        Err(AnchorError::ActorKindMismatch { .. })
    ));

    let mut bad_signer = signed;
    bad_signer.signer_key = other_kp.key_id().to_string();
    assert!(matches!(
        verify_revocation_ed25519(&bad_signer),
        Err(AnchorError::SignerMismatch { .. })
    ));
}

#[test]
fn pluggable_hardware_anchors_sign_and_verify_revocations() {
    let seed = [0x77; 32];
    let sk = SigningKey::from_bytes(&seed);
    let piv_key = piv_ed25519_key_id(&sk.verifying_key().to_bytes());
    struct MockPivSigner(SigningKey, KeyId);
    impl MandateSigner for MockPivSigner {
        fn key_id(&self) -> KeyId {
            self.1.clone()
        }
        fn assurance(&self) -> AssuranceLevel {
            AssuranceLevel::Passkey
        }
        fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
            Ok(self.0.sign(payload).to_bytes().to_vec())
        }
    }
    let target = MandateId::sha256(b"piv-target");
    let words = canonical_revocation_text(&piv_key, &target);
    let vf = ts("2026-11-26T17:00:00Z");
    let vu = ts("2026-11-26T18:00:00Z");
    let signed_piv = sign_revocation_with(
        &MockPivSigner(sk.clone(), piv_key),
        &words,
        "yubikey-piv",
        vf,
        vu,
    )
    .expect("sign PIV revocation");
    let vr_piv = verify_revocation_piv_ed25519(&signed_piv).expect("verify PIV revocation");
    assert_eq!(vr_piv.proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verify_revocation(&signed_piv).unwrap(), vr_piv);

    let fido_key = format_fido2_ed25519_key_id(&sk.verifying_key().to_bytes()).unwrap();
    struct MockFido2Signer(SigningKey, KeyId);
    impl MandateSigner for MockFido2Signer {
        fn key_id(&self) -> KeyId {
            self.1.clone()
        }
        fn assurance(&self) -> AssuranceLevel {
            AssuranceLevel::Passkey
        }
        fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&Sha256::digest(DEFAULT_FIDO2_RP_ID.as_bytes()));
            auth_data.push(FIDO2_FLAG_UP);
            auth_data.extend_from_slice(&1u32.to_be_bytes());
            let cdh = Sha256::digest(payload);
            let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
            signed_data.extend_from_slice(&auth_data);
            signed_data.extend_from_slice(&cdh);
            let sig = self.0.sign(&signed_data).to_bytes();
            let env = Fido2AssertionEnvelope {
                rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
                auth_data,
                signature: sig,
            };
            Ok(env.encode().unwrap())
        }
    }
    let fido_words = canonical_revocation_text(&fido_key, &target);
    let signed_fido = sign_revocation_with(
        &MockFido2Signer(sk, fido_key),
        &fido_words,
        "yubikey-fido2",
        vf,
        vu,
    )
    .expect("sign FIDO2 revocation");
    let vr_fido = verify_revocation_fido2_ed25519(&signed_fido).expect("verify FIDO2 revocation");
    assert_eq!(vr_fido.proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verify_revocation(&signed_fido).unwrap(), vr_fido);
}

#[test]
fn registry_enforces_liskov_postconditions_on_revocation_verifiers() {
    let kp = Ed25519Keypair::from_secret_bytes([0x88; 32]);
    let other_key = Ed25519Keypair::from_secret_bytes([0x99; 32]).key_id();
    let target = MandateId::sha256(b"postcond");
    let words = canonical_revocation_text(&kp.key_id(), &target);
    let vf = ts("2026-11-26T17:00:00Z");
    let vu = ts("2026-11-26T18:00:00Z");
    let signed = kp.sign_revocation(&words, "local-ed25519", vf, vu).unwrap();

    struct MandateOnlyVerifier;
    impl AnchorVerifier for MandateOnlyVerifier {
        fn verify(&self, _signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
            unreachable!()
        }
    }
    assert!(matches!(
        verify_revocation_with(&MandateOnlyVerifier, &signed),
        Err(AnchorError::UnsupportedKeyScheme(ref s)) if s == "ed25519"
    ));

    #[derive(Clone, Copy)]
    enum Spoof {
        SignerKey,
        ActorKind,
        Assurance,
        AnchorId,
        Window,
        Ast,
    }
    struct SpoofingRevVerifier(Spoof, KeyId);
    impl AnchorVerifier for SpoofingRevVerifier {
        fn verify(&self, _signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
            unreachable!()
        }
        fn verify_revocation(
            &self,
            signed: &SignedRevocation,
        ) -> Result<VerifiedRevocation, AnchorError> {
            let mut vr = verify_revocation_ed25519(signed)?;
            match self.0 {
                Spoof::SignerKey => vr.proof.signer_key = self.1.clone(),
                Spoof::ActorKind => vr.proof.actor_kind = ActorKind::Service,
                Spoof::Assurance => vr.proof.assurance = AssuranceLevel::QualifiedQes,
                Spoof::AnchorId => vr.proof.anchor_id = "spoofed".to_string(),
                Spoof::Window => vr.proof.valid_until += 10,
                Spoof::Ast => {
                    let alt = format!(
                        "HANDFEST REVOKE v1\nBY human \"Valentin\" (key: {})\nTARGET mandate {}\nEFFECTIVE 2026-11-26T17:15:00Z\n",
                        vr.proof.signer_key,
                        MandateId::sha256(b"different")
                    );
                    vr.ast = parse_canonical_revocation(&alt).unwrap();
                }
            }
            Ok(vr)
        }
    }

    type ErrPred = fn(AnchorError) -> bool;
    let cases: &[(Spoof, ErrPred)] = &[
        (Spoof::SignerKey, |e| {
            matches!(
                e,
                AnchorError::ProofSignerMismatch {
                    source: ProofIdentitySource::Envelope,
                    ..
                }
            )
        }),
        (Spoof::ActorKind, |e| {
            matches!(
                e,
                AnchorError::ProofActorKindMismatch {
                    source: ProofIdentitySource::Envelope,
                    ..
                }
            )
        }),
        (Spoof::Assurance, |e| {
            matches!(e, AnchorError::UnsupportedAssurance { .. })
        }),
        (Spoof::AnchorId, |e| {
            matches!(e, AnchorError::InvalidAnchorId(_))
        }),
        (Spoof::Window, |e| {
            matches!(e, AnchorError::ValidityWindowMismatch { .. })
        }),
        (Spoof::Ast, |e| {
            matches!(e, AnchorError::NonCanonicalRevocation(_))
        }),
    ];
    for &(spoof, check) in cases {
        let mut reg = AnchorRegistry::new();
        reg.register("ed25519", SpoofingRevVerifier(spoof, other_key.clone()));
        let err = reg.verify_revocation(&signed).unwrap_err();
        assert!(check(err.clone()), "unexpected error: {err:?}");
    }
}
