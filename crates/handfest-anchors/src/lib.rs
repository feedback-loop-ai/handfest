//! Pluggable cryptographic and regulatory trust-anchor verifiers for `handfest`.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use handfest_core::ast::{HandfestAst, KeyId, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP};
use handfest_core::cnl::{parse_canonical, try_render_canonical, ParseError};
use handfest_core::gate::{
    validate_proof_shape, ProofShapeError, VerifiedAnchorProof, VerifiedMandate, VerifiedRevocation,
};
use handfest_core::ActorKind;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

mod base64;
mod fido2;
mod openpgp;
mod p256;
mod piv;
mod revocation;
mod signer;
mod ssh_sk;
mod ssh_sk_p256;

pub use fido2::{
    discover_fido2_device, format_fido2_ed25519_key_id, verify_fido2_ed25519,
    verify_revocation_fido2_ed25519, Fido2AssertionEnvelope, Fido2CredentialFile,
    Fido2Ed25519Signer, Fido2Ed25519Verifier, DEFAULT_FIDO2_RP_ID, FIDO2_ED25519_SCHEME,
    FIDO2_ENVELOPE_VERSION, FIDO2_FLAG_UP, MIN_AUTH_DATA_LEN,
};
pub use handfest_core::AssuranceLevel;
pub use openpgp::{
    extract_ed25519_public_key, extract_ed25519_public_key_for_fingerprint, openpgp_ed25519_key_id,
    verify_openpgp_ed25519, OpenPgpEd25519Signer, OpenPgpEd25519Verifier, OPENPGP_ED25519_SCHEME,
};
pub use p256::{P256Error, P256PublicKey, P256_UNCOMPRESSED_KEY_LEN};
pub use piv::{
    parse_ed25519_spki_der, parse_ed25519_spki_pem, piv_ed25519_key_id, verify_piv_ed25519,
    verify_revocation_piv_ed25519, PivEd25519Signer, PivEd25519Verifier, PivPinSource,
    PivSignerConfig, DEFAULT_PIV_KEY_ID, DEFAULT_PIV_PIN_ENV, DEFAULT_PKCS11_MODULE,
    ED25519_SPKI_DER_PREFIX, PIV_ED25519_SCHEME,
};
pub use revocation::{
    revocation_signing_payload, sign_revocation_with, verify_revocation, verify_revocation_ed25519,
    verify_revocation_openpgp_ed25519, verify_revocation_verifier_postconditions,
    verify_revocation_with, verify_revocations, verify_revocations_with, SignedRevocation,
    REVOCATION_SIGNING_DOMAIN_PREFIX,
};
pub use signer::{
    sign_mandate_with, CommandOutput, CommandRunner, MandateSigner, SystemCommandRunner,
};
pub use ssh_sk::{
    verify_revocation_ssh_sk_ed25519, verify_ssh_sk_ed25519, SshSkEd25519Verifier, SshSkPublicKey,
    SshSkSigner, SSHSIG_NAMESPACE, SSH_SK_ED25519_SCHEME, SSH_SK_ED25519_SSH_TYPE,
};
pub use ssh_sk_p256::{
    verify_revocation_ssh_sk_p256, verify_ssh_sk_p256, SshSkAnyPublicKey, SshSkAnySigner,
    SshSkP256PublicKey, SshSkP256Signer, SshSkP256Verifier, SSHSIG_REVOCATION_NAMESPACE,
    SSH_SK_P256_CURVE_NAME, SSH_SK_P256_SCHEME, SSH_SK_P256_SSH_TYPE,
};

/// Domain-separation prefix prepended to length-prefixed envelope metadata and canonical
/// `HANDFEST v1` text before Ed25519 signing.
pub const SIGNING_DOMAIN_PREFIX: &[u8] = b"handfest-v1-envelope\0";

/// Source of the expected identity value when a verifier proof disagrees with its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofIdentitySource {
    Envelope,
    Mandate,
    Revocation,
}

impl ProofIdentitySource {
    const fn label(self) -> &'static str {
        match self {
            Self::Envelope => "envelope",
            Self::Mandate => "mandate FROM",
            Self::Revocation => "revocation BY",
        }
    }
}

/// Errors returned while loading keys, signing, or verifying trust-anchor envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    InvalidSecretKey(String),
    InvalidPublicKey(String),
    InvalidSignature(String),
    InvalidConfig(String),
    NonCanonicalMandate(ParseError),
    NonCanonicalRevocation(ParseError),
    SignerMismatch {
        expected: String,
        actual: String,
    },
    ProofSignerMismatch {
        source: ProofIdentitySource,
        expected: String,
        actual: String,
    },
    ActorKindMismatch {
        expected: ActorKind,
        actual: ActorKind,
    },
    ProofActorKindMismatch {
        source: ProofIdentitySource,
        expected: ActorKind,
        actual: ActorKind,
    },
    InvalidActorKind(String),
    InvalidAssurance(String),
    UnsupportedAssurance {
        expected: AssuranceLevel,
        actual: AssuranceLevel,
    },
    InvalidAnchorId(String),
    InvalidTimestamp(i64),
    InvalidValidityWindow {
        valid_from: i64,
        valid_until: i64,
    },
    ValidityWindowMismatch {
        expected_from: i64,
        expected_until: i64,
        actual_from: i64,
        actual_until: i64,
    },
    KeyIdMismatch {
        expected: String,
        actual: String,
    },
    UnsupportedKeyScheme(String),
    EmptyChain,
    ChainHop {
        hop: usize,
        source: Box<AnchorError>,
    },
    CommandIo {
        program: String,
        detail: String,
    },
    CommandFailed {
        program: String,
        status: Option<i32>,
        stderr: String,
    },
    InvalidCredential(String),
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey(msg) => write!(f, "invalid anchor secret key: {msg}"),
            Self::InvalidPublicKey(msg) => write!(f, "invalid anchor public key: {msg}"),
            Self::InvalidSignature(msg) => write!(f, "invalid anchor signature: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid anchor configuration: {msg}"),
            Self::NonCanonicalMandate(err) => write!(f, "invalid or non-canonical mandate: {err}"),
            Self::NonCanonicalRevocation(err) => {
                write!(f, "invalid or non-canonical revocation: {err}")
            }
            Self::SignerMismatch { expected, actual } => {
                write!(f, "signer key mismatch: mandate FROM is '{expected}', envelope has '{actual}'")
            }
            Self::ProofSignerMismatch {
                source,
                expected,
                actual,
            } => write!(
                f,
                "signer key mismatch: {} is '{expected}', proof has '{actual}'",
                source.label()
            ),
            Self::ActorKindMismatch { expected, actual } => {
                write!(f, "actor kind mismatch: mandate FROM is {expected:?}, envelope has {actual:?}")
            }
            Self::ProofActorKindMismatch {
                source,
                expected,
                actual,
            } => write!(
                f,
                "actor kind mismatch: {} is {expected:?}, proof has {actual:?}",
                source.label()
            ),
            Self::InvalidActorKind(raw) => write!(f, "unknown actor kind '{raw}'"),
            Self::InvalidAssurance(raw) => write!(f, "unknown assurance level '{raw}'"),
            Self::UnsupportedAssurance { expected, actual } => write!(
                f,
                "unsupported assurance level: expected {expected:?}, got {actual:?}"
            ),
            Self::InvalidAnchorId(msg) => write!(f, "invalid anchor_id: {msg}"),
            Self::InvalidTimestamp(ts) => write!(
                f,
                "timestamp {ts} outside {MIN_RFC3339_TIMESTAMP}..={MAX_RFC3339_TIMESTAMP}"
            ),
            Self::InvalidValidityWindow {
                valid_from,
                valid_until,
            } => write!(
                f,
                "invalid validity window [{valid_from}..{valid_until}): valid_from must be less than or equal to valid_until"
            ),
            Self::ValidityWindowMismatch {
                expected_from,
                expected_until,
                actual_from,
                actual_until,
            } => write!(
                f,
                "validity window mismatch: envelope has [{expected_from}..{expected_until}), proof has [{actual_from}..{actual_until})"
            ),
            Self::KeyIdMismatch { expected, actual } => {
                write!(f, "key_id mismatch in key file: derived '{expected}', file has '{actual}'")
            }
            Self::UnsupportedKeyScheme(scheme) => {
                write!(f, "unsupported anchor key scheme '{scheme}'")
            }
            Self::EmptyChain => f.write_str("mandate chain must contain at least one mandate"),
            Self::ChainHop { hop, source } => write!(f, "chain hop {hop}: {source}"),
            Self::CommandIo { program, detail } => {
                write!(f, "failed to run '{program}': {detail}")
            }
            Self::CommandFailed {
                program,
                status,
                stderr,
            } => match (status, stderr.is_empty()) {
                (Some(code), true) => write!(f, "'{program}' exited with status {code}"),
                (Some(code), false) => write!(f, "'{program}' exited with status {code}: {stderr}"),
                (None, true) => write!(f, "'{program}' terminated by signal"),
                (None, false) => write!(f, "'{program}' terminated by signal: {stderr}"),
            },
            Self::InvalidCredential(msg) => write!(f, "invalid anchor credential: {msg}"),
        }
    }
}

impl std::error::Error for AnchorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NonCanonicalMandate(err) | Self::NonCanonicalRevocation(err) => Some(err),
            Self::ChainHop { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// JSON envelope carrying canonical `HANDFEST v1` text and a trust-anchor signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMandate {
    pub canonical_words: String,
    pub anchor_id: String,
    pub assurance: String,
    pub actor_kind: String,
    pub signer_key: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub signature_hex: String,
}

/// JSON representation of a local Ed25519 keypair file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519KeyFile {
    pub key_id: String,
    pub secret_key_hex: String,
}

impl fmt::Debug for Ed25519KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyFile")
            .field("key_id", &self.key_id)
            .field("secret_key_hex", &"<redacted>")
            .finish()
    }
}

/// Local Ed25519 signing keypair for WYSIWYS `HANDFEST v1` mandates.
#[derive(Clone)]
pub struct Ed25519Keypair {
    signing_key: SigningKey,
}

impl fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Keypair")
            .field("key_id", &self.key_id().to_string())
            .finish()
    }
}

impl Ed25519Keypair {
    /// Generates a fresh Ed25519 keypair using the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Constructs a keypair from a raw 32-byte Ed25519 secret seed.
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    /// Loads a keypair from a strict 64-character lowercase hex string.
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, AnchorError> {
        let bytes =
            decode_lower_hex_fixed::<32>(secret_hex).map_err(AnchorError::InvalidSecretKey)?;
        Ok(Self::from_secret_bytes(bytes))
    }

    /// Exports the 32-byte secret key seed as a 64-character lowercase hex string.
    #[must_use]
    pub fn to_secret_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Returns the 32-byte Ed25519 public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Derives the canonical `KeyId` (`ed25519:<64-lowercase-hex>`).
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let pub_hex = hex::encode(self.public_key_bytes());
        KeyId::new("ed25519", pub_hex).expect("hex-encoded ed25519 key is always a valid KeyId")
    }

    /// Serializes this keypair into an [`Ed25519KeyFile`] payload.
    #[must_use]
    pub fn to_key_file(&self) -> Ed25519KeyFile {
        Ed25519KeyFile {
            key_id: self.key_id().to_string(),
            secret_key_hex: self.to_secret_hex(),
        }
    }

    /// Loads and cross-checks an [`Ed25519KeyFile`], rejecting mismatched `key_id` fields.
    pub fn from_key_file(file: &Ed25519KeyFile) -> Result<Self, AnchorError> {
        let keypair = Self::from_secret_hex(&file.secret_key_hex)?;
        let derived = keypair.key_id().to_string();
        if file.key_id != derived {
            return Err(AnchorError::KeyIdMismatch {
                expected: derived,
                actual: file.key_id.clone(),
            });
        }
        Ok(keypair)
    }

    /// Signs strictly canonical `HANDFEST v1` text and all envelope metadata with domain
    /// separation `b"handfest-v1-envelope\0"`.
    pub fn sign_mandate(
        &self,
        canonical_words: &str,
        anchor_id: impl Into<String>,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<SignedMandate, AnchorError> {
        sign_mandate_with(self, canonical_words, anchor_id, valid_from, valid_until)
    }

    /// Signs strictly canonical `HANDFEST REVOKE v1` text and all envelope metadata with domain
    /// separation `b"handfest-v1-revoke\0"`.
    pub fn sign_revocation(
        &self,
        canonical_words: &str,
        anchor_id: impl Into<String>,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<SignedRevocation, AnchorError> {
        sign_revocation_with(self, canonical_words, anchor_id, valid_from, valid_until)
    }
}

impl MandateSigner for Ed25519Keypair {
    fn key_id(&self) -> KeyId {
        Ed25519Keypair::key_id(self)
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::LocalKey
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        let signature: Signature = self.signing_key.sign(payload);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Pluggable verifier interface turning a [`SignedMandate`] into a [`VerifiedMandate`].
pub trait AnchorVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError>;

    /// Verifies a [`SignedRevocation`] envelope into a [`VerifiedRevocation`].
    fn verify_revocation(
        &self,
        signed: &SignedRevocation,
    ) -> Result<VerifiedRevocation, AnchorError> {
        let scheme = KeyId::parse(&signed.signer_key)
            .map(|k| k.scheme().to_string())
            .unwrap_or_else(|_| signed.signer_key.clone());
        Err(AnchorError::UnsupportedKeyScheme(scheme))
    }
}

/// Strict Ed25519 WYSIWYS trust-anchor verifier (`AssuranceLevel::LocalKey`).
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Verifier;

impl AnchorVerifier for Ed25519Verifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        verify_ed25519(signed)
    }

    fn verify_revocation(
        &self,
        signed: &SignedRevocation,
    ) -> Result<VerifiedRevocation, AnchorError> {
        verify_revocation_ed25519(signed)
    }
}

/// Additive registry mapping `KeyId` schemes to pluggable [`AnchorVerifier`] implementations.
///
/// Fails closed with [`AnchorError::UnsupportedKeyScheme`] for any unregistered scheme and
/// [`AnchorError::InvalidPublicKey`] for malformed `signer_key` values.
#[derive(Default)]
pub struct AnchorRegistry {
    verifiers: BTreeMap<String, Box<dyn AnchorVerifier + Send + Sync>>,
}

impl fmt::Debug for AnchorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let schemes: Vec<&str> = self.verifiers.keys().map(String::as_str).collect();
        f.debug_struct("AnchorRegistry")
            .field("schemes", &schemes)
            .finish()
    }
}

impl AnchorRegistry {
    /// Creates an empty, fail-closed [`AnchorRegistry`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry pre-populated with the built-in trust-anchor verifiers
    /// (`ed25519`, `ssh-sk-ed25519`, `ssh-sk-p256`, `fido2-ed25519`, `openpgp-ed25519`, `piv-ed25519`).
    #[must_use]
    pub fn default_registry() -> Self {
        let mut registry = Self::new();
        registry.register("ed25519", Ed25519Verifier);
        registry.register(SSH_SK_ED25519_SCHEME, SshSkEd25519Verifier);
        registry.register(SSH_SK_P256_SCHEME, SshSkP256Verifier);
        registry.register(FIDO2_ED25519_SCHEME, Fido2Ed25519Verifier);
        registry.register(OPENPGP_ED25519_SCHEME, OpenPgpEd25519Verifier);
        registry.register(PIV_ED25519_SCHEME, PivEd25519Verifier);
        registry
    }

    /// Registers a verifier for `KeyId` `scheme`, replacing any prior verifier for that scheme.
    pub fn register<V>(&mut self, scheme: impl Into<String>, verifier: V) -> &mut Self
    where
        V: AnchorVerifier + Send + Sync + 'static,
    {
        self.verifiers.insert(scheme.into(), Box::new(verifier));
        self
    }
}

impl AnchorVerifier for AnchorRegistry {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        let key_id = KeyId::parse(&signed.signer_key).map_err(|err| {
            AnchorError::InvalidPublicKey(format!("invalid KeyId '{}': {err}", signed.signer_key))
        })?;
        let verifier = self
            .verifiers
            .get(key_id.scheme())
            .ok_or_else(|| AnchorError::UnsupportedKeyScheme(key_id.scheme().to_string()))?;
        let vm = verifier.verify(signed)?;
        verify_verifier_postconditions(signed, &vm)?;
        Ok(vm)
    }

    fn verify_revocation(
        &self,
        signed: &SignedRevocation,
    ) -> Result<VerifiedRevocation, AnchorError> {
        let key_id = KeyId::parse(&signed.signer_key).map_err(|err| {
            AnchorError::InvalidPublicKey(format!("invalid KeyId '{}': {err}", signed.signer_key))
        })?;
        let verifier = self
            .verifiers
            .get(key_id.scheme())
            .ok_or_else(|| AnchorError::UnsupportedKeyScheme(key_id.scheme().to_string()))?;
        let vr = verifier.verify_revocation(signed)?;
        verify_revocation_verifier_postconditions(signed, &vr)?;
        Ok(vr)
    }
}

/// Enforces the Liskov substitution postconditions required of every [`AnchorVerifier`] output:
/// proof identity, actor kind, assurance level, valid `anchor_id`, RFC 3339 validity window
/// (`valid_from <= valid_until`) matching the signed envelope, and canonical AST equality.
pub fn verify_verifier_postconditions(
    signed: &SignedMandate,
    vm: &VerifiedMandate,
) -> Result<(), AnchorError> {
    let expected_key = KeyId::parse(&signed.signer_key).map_err(|err| {
        AnchorError::InvalidPublicKey(format!("invalid KeyId '{}': {err}", signed.signer_key))
    })?;
    enforce_proof_identity_postconditions(signed, &expected_key, vm)?;
    enforce_proof_window_and_ast_postconditions(signed, vm)?;
    Ok(())
}

fn enforce_proof_identity_postconditions(
    signed: &SignedMandate,
    expected_key: &KeyId,
    vm: &VerifiedMandate,
) -> Result<(), AnchorError> {
    if &vm.proof.signer_key != expected_key {
        return Err(AnchorError::ProofSignerMismatch {
            source: ProofIdentitySource::Envelope,
            expected: expected_key.to_string(),
            actual: vm.proof.signer_key.to_string(),
        });
    }
    if &vm.proof.signer_key != vm.ast.from().key() {
        return Err(AnchorError::ProofSignerMismatch {
            source: ProofIdentitySource::Mandate,
            expected: vm.ast.from().key().to_string(),
            actual: vm.proof.signer_key.to_string(),
        });
    }
    let expected_actor_kind = parse_actor_kind(&signed.actor_kind)?;
    if vm.proof.actor_kind != expected_actor_kind {
        return Err(AnchorError::ProofActorKindMismatch {
            source: ProofIdentitySource::Envelope,
            expected: expected_actor_kind,
            actual: vm.proof.actor_kind,
        });
    }
    if vm.proof.actor_kind != vm.ast.from().kind() {
        return Err(AnchorError::ProofActorKindMismatch {
            source: ProofIdentitySource::Mandate,
            expected: vm.ast.from().kind(),
            actual: vm.proof.actor_kind,
        });
    }
    let expected_assurance = parse_assurance(&signed.assurance)?;
    if vm.proof.assurance != expected_assurance {
        return Err(AnchorError::UnsupportedAssurance {
            expected: expected_assurance,
            actual: vm.proof.assurance,
        });
    }
    validate_proof_shape(
        &vm.proof.anchor_id,
        vm.proof.valid_from,
        vm.proof.valid_until,
    )
    .map_err(map_proof_shape_error)?;
    if vm.proof.anchor_id != signed.anchor_id {
        return Err(AnchorError::InvalidAnchorId(format!(
            "proof anchor_id '{}' does not match envelope '{}'",
            vm.proof.anchor_id, signed.anchor_id
        )));
    }
    Ok(())
}

fn enforce_proof_window_and_ast_postconditions(
    signed: &SignedMandate,
    vm: &VerifiedMandate,
) -> Result<(), AnchorError> {
    if vm.proof.valid_from != signed.valid_from || vm.proof.valid_until != signed.valid_until {
        return Err(AnchorError::ValidityWindowMismatch {
            expected_from: signed.valid_from,
            expected_until: signed.valid_until,
            actual_from: vm.proof.valid_from,
            actual_until: vm.proof.valid_until,
        });
    }
    let rendered = try_render_canonical(&vm.ast)
        .map_err(|error| AnchorError::NonCanonicalMandate(ParseError::Ast { line: 0, error }))?;
    if rendered != signed.canonical_words {
        return Err(AnchorError::NonCanonicalMandate(ParseError::NonCanonical {
            expected: rendered,
        }));
    }
    Ok(())
}

pub(crate) struct ValidatedEnvelopeMetadata {
    pub(crate) ast: HandfestAst,
    pub(crate) actor_kind: ActorKind,
    pub(crate) assurance: AssuranceLevel,
    pub(crate) signer_key: KeyId,
}

pub(crate) fn validate_envelope_metadata(
    signed: &SignedMandate,
    expected_scheme: &str,
    expected_assurance: AssuranceLevel,
) -> Result<ValidatedEnvelopeMetadata, AnchorError> {
    let ast = parse_canonical(&signed.canonical_words).map_err(AnchorError::NonCanonicalMandate)?;
    validate_proof_shape(&signed.anchor_id, signed.valid_from, signed.valid_until)
        .map_err(map_proof_shape_error)?;

    let actor_kind = parse_actor_kind(&signed.actor_kind)?;
    if actor_kind != ast.from().kind() {
        return Err(AnchorError::ActorKindMismatch {
            expected: ast.from().kind(),
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

    let signer_key = KeyId::parse(&signed.signer_key).map_err(|err| {
        AnchorError::InvalidPublicKey(format!("invalid KeyId '{}': {err}", signed.signer_key))
    })?;
    if signer_key.scheme() != expected_scheme {
        return Err(AnchorError::InvalidPublicKey(format!(
            "expected '{expected_scheme}' key scheme, got '{}'",
            signer_key.scheme()
        )));
    }
    if &signer_key != ast.from().key() {
        return Err(AnchorError::SignerMismatch {
            expected: ast.from().key().to_string(),
            actual: signer_key.to_string(),
        });
    }

    Ok(ValidatedEnvelopeMetadata {
        ast,
        actor_kind,
        assurance,
        signer_key,
    })
}

pub(crate) struct ValidatedEnvelopeHeader {
    pub(crate) ast: HandfestAst,
    pub(crate) actor_kind: ActorKind,
    pub(crate) assurance: AssuranceLevel,
    pub(crate) signer_key: KeyId,
    pub(crate) verifying_key: VerifyingKey,
}

pub(crate) fn validate_envelope_header(
    signed: &SignedMandate,
    expected_scheme: &str,
    expected_assurance: AssuranceLevel,
) -> Result<ValidatedEnvelopeHeader, AnchorError> {
    let meta = validate_envelope_metadata(signed, expected_scheme, expected_assurance)?;
    let pub_bytes = decode_lower_hex_fixed::<32>(meta.signer_key.value())
        .map_err(AnchorError::InvalidPublicKey)?;
    let verifying_key =
        parse_canonical_ed25519_verifying_key(&pub_bytes).map_err(AnchorError::InvalidPublicKey)?;

    Ok(ValidatedEnvelopeHeader {
        ast: meta.ast,
        actor_kind: meta.actor_kind,
        assurance: meta.assurance,
        signer_key: meta.signer_key,
        verifying_key,
    })
}

pub(crate) fn parse_canonical_ed25519_verifying_key(
    pub_bytes: &[u8; 32],
) -> Result<VerifyingKey, String> {
    // RFC 8032 Section 5.1.3: reject non-canonical field encodings y >= p (p = 2^255 - 19).
    let is_non_canonical_y =
        (pub_bytes[31] & 0x7f) == 0x7f && pub_bytes[1..31] == [0xff; 30] && pub_bytes[0] >= 0xed;
    if is_non_canonical_y {
        return Err("non-canonical Ed25519 public key encoding".to_string());
    }
    let verifying_key = VerifyingKey::from_bytes(pub_bytes).map_err(|err| err.to_string())?;
    if verifying_key.is_weak() {
        return Err("weak small-order Ed25519 public key".to_string());
    }
    Ok(verifying_key)
}

/// Verifies a single Ed25519 [`SignedMandate`] envelope and returns a [`VerifiedMandate`].
pub fn verify_ed25519(signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
    verify_ed25519_for_scheme(signed, "ed25519", AssuranceLevel::LocalKey)
}

pub(crate) fn verify_ed25519_for_scheme(
    signed: &SignedMandate,
    expected_scheme: &str,
    expected_assurance: AssuranceLevel,
) -> Result<VerifiedMandate, AnchorError> {
    let header = validate_envelope_header(signed, expected_scheme, expected_assurance)?;
    let sig_bytes = decode_lower_hex_fixed::<64>(&signed.signature_hex)
        .map_err(AnchorError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let payload = signing_payload(signed);
    header
        .verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|err| AnchorError::InvalidSignature(err.to_string()))?;

    let proof = VerifiedAnchorProof {
        anchor_id: signed.anchor_id.clone(),
        assurance: header.assurance,
        signer_key: header.signer_key,
        actor_kind: header.actor_kind,
        valid_from: signed.valid_from,
        valid_until: signed.valid_until,
    };

    Ok(VerifiedMandate {
        ast: header.ast,
        proof,
    })
}

/// Verifies every mandate in a chain using a pluggable [`AnchorVerifier`], enforcing
/// [`verify_verifier_postconditions`] on every hop and returning `Vec<VerifiedMandate>` ready for
/// `handfest_core::gate::authorize`.
///
/// Fails closed on empty chains (`AnchorError::EmptyChain`) and wraps per-hop verification or
/// postcondition failures in `AnchorError::ChainHop { hop, source }`.
pub fn verify_chain_with(
    verifier: &dyn AnchorVerifier,
    mandates: &[SignedMandate],
) -> Result<Vec<VerifiedMandate>, AnchorError> {
    if mandates.is_empty() {
        return Err(AnchorError::EmptyChain);
    }
    let mut verified = Vec::with_capacity(mandates.len());
    for (hop, signed) in mandates.iter().enumerate() {
        let vm = verifier
            .verify(signed)
            .and_then(|vm| {
                verify_verifier_postconditions(signed, &vm)?;
                Ok(vm)
            })
            .map_err(|source| AnchorError::ChainHop {
                hop,
                source: Box::new(source),
            })?;
        verified.push(vm);
    }
    Ok(verified)
}

/// Verifies every mandate in a chain via [`AnchorRegistry::default_registry`], returning
/// `Vec<VerifiedMandate>` ready for `handfest_core::gate::authorize`.
pub fn verify_chain(mandates: &[SignedMandate]) -> Result<Vec<VerifiedMandate>, AnchorError> {
    verify_chain_with(&AnchorRegistry::default_registry(), mandates)
}

/// Builds the domain-separated, length-prefixed payload signed by Ed25519 anchors.
///
/// Binds `anchor_id`, `assurance`, `actor_kind`, `signer_key`, `valid_from`, `valid_until`,
/// and `canonical_words` unambiguously so tampering with any envelope field invalidates the
/// signature.
pub(crate) struct EnvelopeFields<'a> {
    pub(crate) anchor_id: &'a str,
    pub(crate) assurance: &'a str,
    pub(crate) actor_kind: &'a str,
    pub(crate) signer_key: &'a str,
    pub(crate) valid_from: i64,
    pub(crate) valid_until: i64,
    pub(crate) canonical_words: &'a str,
}

pub(crate) fn build_envelope_signing_payload(
    domain_prefix: &[u8],
    fields: EnvelopeFields<'_>,
) -> Vec<u8> {
    let capacity = domain_prefix.len()
        + (8 * 7)
        + fields.anchor_id.len()
        + fields.assurance.len()
        + fields.actor_kind.len()
        + fields.signer_key.len()
        + fields.canonical_words.len();
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(domain_prefix);
    push_len_prefixed_str(&mut payload, fields.anchor_id);
    push_len_prefixed_str(&mut payload, fields.assurance);
    push_len_prefixed_str(&mut payload, fields.actor_kind);
    push_len_prefixed_str(&mut payload, fields.signer_key);
    payload.extend_from_slice(&fields.valid_from.to_be_bytes());
    payload.extend_from_slice(&fields.valid_until.to_be_bytes());
    push_len_prefixed_str(&mut payload, fields.canonical_words);
    payload
}

#[must_use]
pub fn signing_payload(signed: &SignedMandate) -> Vec<u8> {
    build_envelope_signing_payload(
        SIGNING_DOMAIN_PREFIX,
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

fn push_len_prefixed_str(buf: &mut Vec<u8>, value: &str) {
    let len = u64::try_from(value.len()).expect("string byte length fits in u64");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
}

/// Parses an actor kind string (`"human" | "org" | "agent" | "service"`).
pub fn parse_actor_kind(raw: &str) -> Result<ActorKind, AnchorError> {
    match raw {
        "human" => Ok(ActorKind::Human),
        "org" => Ok(ActorKind::Org),
        "agent" => Ok(ActorKind::Agent),
        "service" => Ok(ActorKind::Service),
        other => Err(AnchorError::InvalidActorKind(other.to_string())),
    }
}

/// Formats an [`ActorKind`] into its canonical wire string.
#[must_use]
pub const fn format_actor_kind(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Org => "org",
        ActorKind::Agent => "agent",
        ActorKind::Service => "service",
    }
}

/// Parses an [`AssuranceLevel`] wire string.
pub fn parse_assurance(raw: &str) -> Result<AssuranceLevel, AnchorError> {
    match raw {
        "local_key" => Ok(AssuranceLevel::LocalKey),
        "crypto_wallet" => Ok(AssuranceLevel::CryptoWallet),
        "passkey" => Ok(AssuranceLevel::Passkey),
        "substantial_eidas" => Ok(AssuranceLevel::SubstantialEidas),
        "qualified_qes" => Ok(AssuranceLevel::QualifiedQes),
        other => Err(AnchorError::InvalidAssurance(other.to_string())),
    }
}

/// Formats an [`AssuranceLevel`] into its canonical wire string.
#[must_use]
pub const fn format_assurance(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::LocalKey => "local_key",
        AssuranceLevel::CryptoWallet => "crypto_wallet",
        AssuranceLevel::Passkey => "passkey",
        AssuranceLevel::SubstantialEidas => "substantial_eidas",
        AssuranceLevel::QualifiedQes => "qualified_qes",
    }
}

pub(crate) fn map_proof_shape_error(err: ProofShapeError) -> AnchorError {
    match err {
        ProofShapeError::EmptyAnchorId => {
            AnchorError::InvalidAnchorId("anchor_id must not be empty".to_string())
        }
        ProofShapeError::InvalidAnchorIdChars => AnchorError::InvalidAnchorId(
            "anchor_id must not contain control characters".to_string(),
        ),
        ProofShapeError::TimestampOutOfRange(ts) => AnchorError::InvalidTimestamp(ts),
        ProofShapeError::InvertedValidityWindow {
            valid_from,
            valid_until,
        } => AnchorError::InvalidValidityWindow {
            valid_from,
            valid_until,
        },
    }
}

pub(crate) fn parse_hex32_key_id(
    raw: &str,
    expected_scheme: &str,
) -> Result<(KeyId, [u8; 32]), AnchorError> {
    let key_id = KeyId::parse(raw)
        .map_err(|err| AnchorError::InvalidPublicKey(format!("invalid KeyId '{raw}': {err}")))?;
    if key_id.scheme() != expected_scheme {
        return Err(AnchorError::InvalidPublicKey(format!(
            "expected '{expected_scheme}' key scheme, got '{}'",
            key_id.scheme()
        )));
    }
    let pub_bytes =
        decode_lower_hex_fixed::<32>(key_id.value()).map_err(AnchorError::InvalidPublicKey)?;
    Ok((key_id, pub_bytes))
}

fn ensure_lower_hex_digits(input: &str) -> Result<(), String> {
    if !input
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("expected lowercase hexadecimal digits only".to_string());
    }
    Ok(())
}

pub(crate) fn decode_lower_hex_fixed<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let expected_len = N * 2;
    if input.len() != expected_len {
        return Err(format!(
            "expected {expected_len} lowercase hex chars, got {}",
            input.len()
        ));
    }
    ensure_lower_hex_digits(input)?;
    let mut out = [0u8; N];
    hex::decode_to_slice(input, &mut out).map_err(|err| err.to_string())?;
    Ok(out)
}

pub(crate) fn decode_lower_hex_vec(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Err("expected non-empty lowercase hex string".to_string());
    }
    if !input.len().is_multiple_of(2) {
        return Err(format!(
            "expected even-length lowercase hex string, got {} chars",
            input.len()
        ));
    }
    ensure_lower_hex_digits(input)?;
    hex::decode(input).map_err(|err| err.to_string())
}

pub(crate) fn decode_lower_hex_var(input: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Err("expected non-empty lowercase hex string".to_string());
    }
    if !input.len().is_multiple_of(2) {
        return Err(format!(
            "expected even-length lowercase hex string, got {} chars",
            input.len()
        ));
    }
    let byte_len = input.len() / 2;
    if byte_len > max_bytes {
        return Err(format!(
            "hex payload length {byte_len} bytes exceeds maximum {max_bytes} bytes"
        ));
    }
    ensure_lower_hex_digits(input)?;
    hex::decode(input).map_err(|err| err.to_string())
}
