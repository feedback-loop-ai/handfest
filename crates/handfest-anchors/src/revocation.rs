//! Domain-separated WYSIWYS `HANDFEST REVOKE v1` signing and trust-anchor verification.

use ed25519_dalek::{Signature, VerifyingKey};
use handfest_core::ast::KeyId;
use handfest_core::cnl::ParseError;
use handfest_core::gate::{validate_proof_shape, VerifiedAnchorProof};
use handfest_core::revocation::{
    parse_canonical_revocation, try_render_canonical_revocation, RevocationAst, RevocationSnapshot,
    VerifiedRevocation,
};
use handfest_core::ActorKind;
use serde::{Deserialize, Serialize};

use crate::{
    build_envelope_signing_payload, decode_lower_hex_fixed, format_actor_kind, format_assurance,
    map_proof_shape_error, parse_actor_kind, parse_assurance,
    parse_canonical_ed25519_verifying_key, parse_hex32_key_id, AnchorError, AnchorRegistry,
    AnchorVerifier, AssuranceLevel, EnvelopeFields, MandateSigner, ProofIdentitySource,
};

/// Domain-separation prefix prepended to length-prefixed envelope metadata and canonical
/// `HANDFEST REVOKE v1` text before signing.
///
/// Strictly disjoint from [`crate::SIGNING_DOMAIN_PREFIX`] (`b"handfest-v1-envelope\0"`) so a
/// mandate signature can never be replayed as a revocation or vice versa.
pub const REVOCATION_SIGNING_DOMAIN_PREFIX: &[u8] = b"handfest-v1-revoke\0";

/// JSON envelope carrying canonical `HANDFEST REVOKE v1` text and a trust-anchor signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocation {
    pub canonical_words: String,
    pub anchor_id: String,
    pub assurance: String,
    pub actor_kind: String,
    pub signer_key: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub signature_hex: String,
}

/// Builds the domain-separated, length-prefixed payload signed by trust anchors for a
/// [`SignedRevocation`].
///
/// Binds `anchor_id`, `assurance`, `actor_kind`, `signer_key`, `valid_from`, `valid_until`,
/// and `canonical_words` under [`REVOCATION_SIGNING_DOMAIN_PREFIX`].
#[must_use]
pub fn revocation_signing_payload(signed: &SignedRevocation) -> Vec<u8> {
    build_envelope_signing_payload(
        REVOCATION_SIGNING_DOMAIN_PREFIX,
        EnvelopeFields {
            anchor_id: &signed.anchor_id,
            assurance: &signed.assurance,
            actor_kind: &signed.actor_kind,
            signer_key: &signed.signer_key,
            valid_from: signed.valid_from,
            valid_until: signed.valid_until,
            canonical_words: &signed.canonical_words,
        },
    )
}

/// Signs strictly canonical `HANDFEST REVOKE v1` text and all envelope metadata using any
/// [`MandateSigner`] implementation.
///
/// Enforces canonical CNL parsing, proof-shape validation (`anchor_id`, `valid_from`,
/// `valid_until`), and `ast.by().key() == &signer.key_id()` before signing the domain-separated
/// [`revocation_signing_payload`]. Fails closed if the signer returns an error or empty signature.
pub fn sign_revocation_with<S: MandateSigner + ?Sized>(
    signer: &S,
    canonical_words: &str,
    anchor_id: impl Into<String>,
    valid_from: i64,
    valid_until: i64,
) -> Result<SignedRevocation, AnchorError> {
    let ast =
        parse_canonical_revocation(canonical_words).map_err(AnchorError::NonCanonicalRevocation)?;
    let anchor_id = anchor_id.into();
    validate_proof_shape(&anchor_id, valid_from, valid_until).map_err(map_proof_shape_error)?;

    let my_key_id = signer.key_id();
    if ast.by().key() != &my_key_id {
        return Err(AnchorError::SignerMismatch {
            expected: ast.by().key().to_string(),
            actual: my_key_id.to_string(),
        });
    }

    let mut signed = SignedRevocation {
        canonical_words: canonical_words.to_string(),
        anchor_id,
        assurance: format_assurance(signer.assurance()).to_string(),
        actor_kind: format_actor_kind(ast.by().kind()).to_string(),
        signer_key: my_key_id.to_string(),
        valid_from,
        valid_until,
        signature_hex: String::new(),
    };
    let payload = revocation_signing_payload(&signed);
    let signature_bytes = signer.sign_payload(&payload)?;
    if signature_bytes.is_empty() {
        return Err(AnchorError::InvalidSignature(
            "signer returned empty signature".to_string(),
        ));
    }
    signed.signature_hex = hex::encode(signature_bytes);
    Ok(signed)
}

/// Enforces the Liskov substitution postconditions required of every [`AnchorVerifier`] revocation
/// verification output.
pub fn verify_revocation_verifier_postconditions(
    signed: &SignedRevocation,
    vr: &VerifiedRevocation,
) -> Result<(), AnchorError> {
    let expected_key = KeyId::parse(&signed.signer_key).map_err(|err| {
        AnchorError::InvalidPublicKey(format!("invalid KeyId '{}': {err}", signed.signer_key))
    })?;
    enforce_revocation_identity_postconditions(signed, &expected_key, vr)?;
    enforce_revocation_window_and_ast_postconditions(signed, vr)?;
    Ok(())
}

fn enforce_revocation_identity_postconditions(
    signed: &SignedRevocation,
    expected_key: &KeyId,
    vr: &VerifiedRevocation,
) -> Result<(), AnchorError> {
    if &vr.proof.signer_key != expected_key {
        return Err(AnchorError::ProofSignerMismatch {
            source: ProofIdentitySource::Envelope,
            expected: expected_key.to_string(),
            actual: vr.proof.signer_key.to_string(),
        });
    }
    if &vr.proof.signer_key != vr.ast.by().key() {
        return Err(AnchorError::ProofSignerMismatch {
            source: ProofIdentitySource::Revocation,
            expected: vr.ast.by().key().to_string(),
            actual: vr.proof.signer_key.to_string(),
        });
    }
    let expected_actor_kind = parse_actor_kind(&signed.actor_kind)?;
    if vr.proof.actor_kind != expected_actor_kind {
        return Err(AnchorError::ProofActorKindMismatch {
            source: ProofIdentitySource::Envelope,
            expected: expected_actor_kind,
            actual: vr.proof.actor_kind,
        });
    }
    if vr.proof.actor_kind != vr.ast.by().kind() {
        return Err(AnchorError::ProofActorKindMismatch {
            source: ProofIdentitySource::Revocation,
            expected: vr.ast.by().kind(),
            actual: vr.proof.actor_kind,
        });
    }
    let expected_assurance = parse_assurance(&signed.assurance)?;
    if vr.proof.assurance != expected_assurance {
        return Err(AnchorError::UnsupportedAssurance {
            expected: expected_assurance,
            actual: vr.proof.assurance,
        });
    }
    validate_proof_shape(
        &vr.proof.anchor_id,
        vr.proof.valid_from,
        vr.proof.valid_until,
    )
    .map_err(map_proof_shape_error)?;
    if vr.proof.anchor_id != signed.anchor_id {
        return Err(AnchorError::InvalidAnchorId(format!(
            "proof anchor_id '{}' does not match envelope '{}'",
            vr.proof.anchor_id, signed.anchor_id
        )));
    }
    Ok(())
}

fn enforce_revocation_window_and_ast_postconditions(
    signed: &SignedRevocation,
    vr: &VerifiedRevocation,
) -> Result<(), AnchorError> {
    if vr.proof.valid_from != signed.valid_from || vr.proof.valid_until != signed.valid_until {
        return Err(AnchorError::ValidityWindowMismatch {
            expected_from: signed.valid_from,
            expected_until: signed.valid_until,
            actual_from: vr.proof.valid_from,
            actual_until: vr.proof.valid_until,
        });
    }
    let rendered = try_render_canonical_revocation(&vr.ast)
        .map_err(|error| AnchorError::NonCanonicalRevocation(ParseError::Ast { line: 0, error }))?;
    if rendered != signed.canonical_words {
        return Err(AnchorError::NonCanonicalRevocation(
            ParseError::NonCanonical { expected: rendered },
        ));
    }
    Ok(())
}

pub(crate) struct ValidatedRevocationHeader {
    pub(crate) ast: RevocationAst,
    pub(crate) actor_kind: ActorKind,
    pub(crate) assurance: AssuranceLevel,
    pub(crate) signer_key: KeyId,
    pub(crate) verifying_key: VerifyingKey,
}

pub(crate) fn validate_revocation_header(
    signed: &SignedRevocation,
    expected_scheme: &str,
    expected_assurance: AssuranceLevel,
) -> Result<ValidatedRevocationHeader, AnchorError> {
    let ast = parse_canonical_revocation(&signed.canonical_words)
        .map_err(AnchorError::NonCanonicalRevocation)?;
    validate_proof_shape(&signed.anchor_id, signed.valid_from, signed.valid_until)
        .map_err(map_proof_shape_error)?;

    let actor_kind = parse_actor_kind(&signed.actor_kind)?;
    if actor_kind != ast.by().kind() {
        return Err(AnchorError::ActorKindMismatch {
            expected: ast.by().kind(),
            actual: actor_kind,
        });
    }

    let assurance = parse_assurance(&signed.assurance)?;
    if assurance != expected_assurance {
        return Err(AnchorError::UnsupportedAssurance {
            expected: expected_assurance,
            actual: assurance,
        });
    }

    let (signer_key, pub_bytes) = parse_hex32_key_id(&signed.signer_key, expected_scheme)?;
    if &signer_key != ast.by().key() {
        return Err(AnchorError::SignerMismatch {
            expected: ast.by().key().to_string(),
            actual: signer_key.to_string(),
        });
    }

    let verifying_key =
        parse_canonical_ed25519_verifying_key(&pub_bytes).map_err(AnchorError::InvalidPublicKey)?;

    Ok(ValidatedRevocationHeader {
        ast,
        actor_kind,
        assurance,
        signer_key,
        verifying_key,
    })
}

/// Verifies a single Ed25519 [`SignedRevocation`] envelope and returns a [`VerifiedRevocation`].
pub fn verify_revocation_ed25519(
    signed: &SignedRevocation,
) -> Result<VerifiedRevocation, AnchorError> {
    verify_revocation_ed25519_for_scheme(signed, "ed25519", AssuranceLevel::LocalKey)
}

pub(crate) fn verify_revocation_ed25519_for_scheme(
    signed: &SignedRevocation,
    expected_scheme: &str,
    expected_assurance: AssuranceLevel,
) -> Result<VerifiedRevocation, AnchorError> {
    let header = validate_revocation_header(signed, expected_scheme, expected_assurance)?;
    let sig_bytes = decode_lower_hex_fixed::<64>(&signed.signature_hex)
        .map_err(AnchorError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let payload = revocation_signing_payload(signed);
    header
        .verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|err| AnchorError::InvalidSignature(err.to_string()))?;

    Ok(VerifiedRevocation {
        ast: header.ast,
        proof: VerifiedAnchorProof {
            anchor_id: signed.anchor_id.clone(),
            assurance: header.assurance,
            signer_key: header.signer_key,
            actor_kind: header.actor_kind,
            valid_from: signed.valid_from,
            valid_until: signed.valid_until,
        },
    })
}

/// Verifies a single [`SignedRevocation`] using a pluggable [`AnchorVerifier`] and enforces
/// [`verify_revocation_verifier_postconditions`].
pub fn verify_revocation_with<V: AnchorVerifier + ?Sized>(
    verifier: &V,
    signed: &SignedRevocation,
) -> Result<VerifiedRevocation, AnchorError> {
    let vr = verifier.verify_revocation(signed)?;
    verify_revocation_verifier_postconditions(signed, &vr)?;
    Ok(vr)
}

/// Verifies a single [`SignedRevocation`] via [`AnchorRegistry::default_registry`].
pub fn verify_revocation(signed: &SignedRevocation) -> Result<VerifiedRevocation, AnchorError> {
    verify_revocation_with(&AnchorRegistry::default_registry(), signed)
}

/// Verifies a slice of [`SignedRevocation`] envelopes using `verifier` into a [`RevocationSnapshot`].
pub fn verify_revocations_with<V: AnchorVerifier + ?Sized>(
    verifier: &V,
    revocations: &[SignedRevocation],
) -> Result<RevocationSnapshot, AnchorError> {
    let mut snapshot = RevocationSnapshot::new();
    for signed in revocations {
        let vr = verify_revocation_with(verifier, signed)?;
        snapshot
            .insert(vr)
            .map_err(|err| AnchorError::InvalidSignature(err.to_string()))?;
    }
    Ok(snapshot)
}

/// Verifies a slice of [`SignedRevocation`] envelopes via [`AnchorRegistry::default_registry`]
/// into a [`RevocationSnapshot`].
pub fn verify_revocations(
    revocations: &[SignedRevocation],
) -> Result<RevocationSnapshot, AnchorError> {
    verify_revocations_with(&AnchorRegistry::default_registry(), revocations)
}

/// Verifies a single OpenPGP Ed25519 (`openpgp-ed25519:<hex>`) [`SignedRevocation`] envelope and
/// returns a [`VerifiedRevocation`].
pub fn verify_revocation_openpgp_ed25519(
    signed: &SignedRevocation,
) -> Result<VerifiedRevocation, AnchorError> {
    let header = validate_revocation_header(
        signed,
        crate::OPENPGP_ED25519_SCHEME,
        AssuranceLevel::Passkey,
    )?;
    let sig_packet = crate::decode_lower_hex_vec(&signed.signature_hex)
        .map_err(AnchorError::InvalidSignature)?;
    let payload = revocation_signing_payload(signed);
    crate::openpgp::verify_openpgp_detached_signature(
        &header.verifying_key,
        &payload,
        &sig_packet,
    )?;

    Ok(VerifiedRevocation {
        ast: header.ast,
        proof: VerifiedAnchorProof {
            anchor_id: signed.anchor_id.clone(),
            assurance: header.assurance,
            signer_key: header.signer_key,
            actor_kind: header.actor_kind,
            valid_from: signed.valid_from,
            valid_until: signed.valid_until,
        },
    })
}
