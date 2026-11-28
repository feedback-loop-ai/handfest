//! Mandate-chain and revocation-envelope loading and verification helpers shared across PEPs.

use std::fs;
use std::io;
use std::path::PathBuf;

use handfest_anchors::{
    verify_revocations_with as verify_anchor_revocations_with, verify_verifier_postconditions,
    AnchorError, AnchorRegistry, AnchorVerifier, SignedMandate, SignedRevocation,
};
use handfest_core::ast::MandateId;
use handfest_core::gate::{verify_chain_structure, RevocationSnapshot, VerifiedMandate};

use crate::error::PepError;

/// Verifies every mandate in `signed` using a pluggable [`AnchorVerifier`] AND checks root parent
/// absence plus monotonic lattice narrowing (`subsumes`) across every hop.
pub fn verify_mandate_chain_with<V: AnchorVerifier + ?Sized>(
    verifier: &V,
    signed: &[SignedMandate],
) -> Result<Vec<VerifiedMandate>, PepError> {
    if signed.is_empty() {
        return Err(PepError::Anchor(AnchorError::EmptyChain));
    }
    let mut verified = Vec::with_capacity(signed.len());
    for (hop, item) in signed.iter().enumerate() {
        let vm = verifier
            .verify(item)
            .and_then(|vm| {
                verify_verifier_postconditions(item, &vm)?;
                Ok(vm)
            })
            .map_err(|source| {
                PepError::Anchor(AnchorError::ChainHop {
                    hop,
                    source: Box::new(source),
                })
            })?;
        verified.push(vm);
    }
    let _ = validate_verified_chain(&verified)?;
    Ok(verified)
}

/// Convenience wrapper verifying a mandate chain via [`AnchorRegistry::default_registry`].
pub fn verify_mandate_chain(signed: &[SignedMandate]) -> Result<Vec<VerifiedMandate>, PepError> {
    verify_mandate_chain_with(&AnchorRegistry::default_registry(), signed)
}

/// Verifies a slice of [`SignedRevocation`] envelopes using a pluggable [`AnchorVerifier`] into a
/// [`RevocationSnapshot`].
pub fn verify_revocations_with<V: AnchorVerifier + ?Sized>(
    verifier: &V,
    signed: &[SignedRevocation],
) -> Result<RevocationSnapshot, PepError> {
    verify_anchor_revocations_with(verifier, signed).map_err(PepError::Anchor)
}

/// Convenience wrapper verifying [`SignedRevocation`] envelopes via
/// [`AnchorRegistry::default_registry`].
pub fn verify_revocations(signed: &[SignedRevocation]) -> Result<RevocationSnapshot, PepError> {
    verify_revocations_with(&AnchorRegistry::default_registry(), signed)
}

/// Validates structural chain invariants (root parent absence, parent digest linking, and
/// monotonic lattice narrowing) and returns the ordered [`MandateId`] list.
pub fn validate_verified_chain(verified: &[VerifiedMandate]) -> Result<Vec<MandateId>, PepError> {
    verify_chain_structure(verified).map_err(PepError::ChainStructure)
}

/// Reads and deserializes ordered [`SignedMandate`] JSON envelope files from disk.
pub fn load_signed_mandates_files(paths: &[PathBuf]) -> Result<Vec<SignedMandate>, PepError> {
    load_signed_envelope_files(paths, "SignedMandate")
}

/// Reads and deserializes [`SignedRevocation`] JSON envelope files from disk.
pub fn load_signed_revocations_files(paths: &[PathBuf]) -> Result<Vec<SignedRevocation>, PepError> {
    load_signed_envelope_files(paths, "SignedRevocation")
}

/// Deserializes a single [`SignedMandate`] JSON envelope from raw UTF-8 bytes.
pub fn parse_signed_mandate_json(
    bytes: &[u8],
    source_label: &str,
) -> Result<SignedMandate, PepError> {
    parse_signed_envelope_json(bytes, "SignedMandate", source_label)
}

fn parse_signed_envelope_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    kind_label: &str,
    source_label: &str,
) -> Result<T, PepError> {
    serde_json::from_slice(bytes).map_err(|err| {
        PepError::InvalidChain(format!(
            "invalid {kind_label} JSON in '{source_label}': {err}"
        ))
    })
}

fn load_signed_envelope_files<T: serde::de::DeserializeOwned>(
    paths: &[PathBuf],
    kind_label: &str,
) -> Result<Vec<T>, PepError> {
    let mut envelopes = Vec::with_capacity(paths.len());
    for path in paths {
        let raw = fs::read(path).map_err(|err| {
            PepError::Io(io::Error::new(
                err.kind(),
                format!("failed to read '{}': {err}", path.display()),
            ))
        })?;
        let source_label = path.display().to_string();
        envelopes.push(parse_signed_envelope_json(&raw, kind_label, &source_label)?);
    }
    Ok(envelopes)
}
