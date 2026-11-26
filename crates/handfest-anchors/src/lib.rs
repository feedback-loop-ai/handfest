//! Pluggable cryptographic and regulatory trust-anchor verifiers for `handfest`.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use handfest_core::ast::{
    is_valid_quoted_str, is_valid_timestamp, KeyId, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::{parse_canonical, try_render_canonical, ParseError};
use handfest_core::gate::{VerifiedAnchorProof, VerifiedMandate};
use handfest_core::ActorKind;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

pub use handfest_core::AssuranceLevel;

/// Domain-separation prefix prepended to length-prefixed envelope metadata and canonical
/// `HANDFEST v1` text before Ed25519 signing.
pub const SIGNING_DOMAIN_PREFIX: &[u8] = b"handfest-v1-envelope\0";

/// Errors returned while loading keys, signing, or verifying trust-anchor envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    InvalidSecretKey(String),
    InvalidPublicKey(String),
    InvalidSignature(String),
    NonCanonicalMandate(ParseError),
    SignerMismatch {
        expected: String,
        actual: String,
    },
    ActorKindMismatch {
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
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey(msg) => write!(f, "invalid Ed25519 secret key: {msg}"),
            Self::InvalidPublicKey(msg) => write!(f, "invalid Ed25519 public key: {msg}"),
            Self::InvalidSignature(msg) => write!(f, "invalid Ed25519 signature: {msg}"),
            Self::NonCanonicalMandate(err) => write!(f, "invalid or non-canonical mandate: {err}"),
            Self::SignerMismatch { expected, actual } => {
                write!(f, "signer key mismatch: mandate FROM is '{expected}', envelope has '{actual}'")
            }
            Self::ActorKindMismatch { expected, actual } => {
                write!(f, "actor kind mismatch: mandate FROM is {expected:?}, envelope has {actual:?}")
            }
            Self::InvalidActorKind(raw) => write!(f, "unknown actor kind '{raw}'"),
            Self::InvalidAssurance(raw) => write!(f, "unknown assurance level '{raw}'"),
            Self::UnsupportedAssurance { expected, actual } => write!(
                f,
                "unsupported assurance level for Ed25519 verifier: expected {expected:?}, got {actual:?}"
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
            Self::KeyIdMismatch { expected, actual } => {
                write!(f, "key_id mismatch in key file: derived '{expected}', file has '{actual}'")
            }
            Self::UnsupportedKeyScheme(scheme) => {
                write!(f, "unsupported anchor key scheme '{scheme}'")
            }
            Self::EmptyChain => f.write_str("mandate chain must contain at least one mandate"),
            Self::ChainHop { hop, source } => write!(f, "chain hop {hop}: {source}"),
        }
    }
}

impl std::error::Error for AnchorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NonCanonicalMandate(err) => Some(err),
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
        let ast = parse_canonical(canonical_words).map_err(AnchorError::NonCanonicalMandate)?;
        let anchor_id = anchor_id.into();
        validate_anchor_id(&anchor_id)?;
        validate_validity_window(valid_from, valid_until)?;

        let my_key_id = self.key_id();
        if ast.from().key() != &my_key_id {
            return Err(AnchorError::SignerMismatch {
                expected: ast.from().key().to_string(),
                actual: my_key_id.to_string(),
            });
        }

        let mut signed = SignedMandate {
            canonical_words: canonical_words.to_string(),
            anchor_id,
            assurance: format_assurance(AssuranceLevel::LocalKey).to_string(),
            actor_kind: format_actor_kind(ast.from().kind()).to_string(),
            signer_key: my_key_id.to_string(),
            valid_from,
            valid_until,
            signature_hex: String::new(),
        };
        let payload = signing_payload(&signed);
        let signature: Signature = self.signing_key.sign(&payload);
        signed.signature_hex = hex::encode(signature.to_bytes());
        Ok(signed)
    }
}

/// Pluggable verifier interface turning a [`SignedMandate`] into a [`VerifiedMandate`].
pub trait AnchorVerifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError>;
}

/// Strict Ed25519 WYSIWYS trust-anchor verifier (`AssuranceLevel::LocalKey`).
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Verifier;

impl AnchorVerifier for Ed25519Verifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        verify_ed25519(signed)
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

    /// Creates a registry pre-populated with the built-in trust-anchor verifiers (`ed25519`).
    #[must_use]
    pub fn default_registry() -> Self {
        let mut registry = Self::new();
        registry.register("ed25519", Ed25519Verifier);
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
        return Err(AnchorError::SignerMismatch {
            expected: expected_key.to_string(),
            actual: vm.proof.signer_key.to_string(),
        });
    }
    if &vm.proof.signer_key != vm.ast.from().key() {
        return Err(AnchorError::SignerMismatch {
            expected: vm.ast.from().key().to_string(),
            actual: vm.proof.signer_key.to_string(),
        });
    }
    let expected_actor_kind = parse_actor_kind(&signed.actor_kind)?;
    if vm.proof.actor_kind != expected_actor_kind {
        return Err(AnchorError::ActorKindMismatch {
            expected: expected_actor_kind,
            actual: vm.proof.actor_kind,
        });
    }
    if vm.proof.actor_kind != vm.ast.from().kind() {
        return Err(AnchorError::ActorKindMismatch {
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
    validate_anchor_id(&vm.proof.anchor_id)?;
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
    validate_validity_window(vm.proof.valid_from, vm.proof.valid_until)?;
    if vm.proof.valid_from != signed.valid_from || vm.proof.valid_until != signed.valid_until {
        return Err(AnchorError::InvalidValidityWindow {
            valid_from: vm.proof.valid_from,
            valid_until: vm.proof.valid_until,
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

/// Verifies a single Ed25519 [`SignedMandate`] envelope and returns a [`VerifiedMandate`].
pub fn verify_ed25519(signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
    let ast = parse_canonical(&signed.canonical_words).map_err(AnchorError::NonCanonicalMandate)?;
    validate_anchor_id(&signed.anchor_id)?;
    validate_validity_window(signed.valid_from, signed.valid_until)?;

    let actor_kind = parse_actor_kind(&signed.actor_kind)?;
    if actor_kind != ast.from().kind() {
        return Err(AnchorError::ActorKindMismatch {
            expected: ast.from().kind(),
            actual: actor_kind,
        });
    }

    let assurance = parse_assurance(&signed.assurance)?;
    if assurance != AssuranceLevel::LocalKey {
        return Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::LocalKey,
            actual: assurance,
        });
    }

    let signer_key = parse_ed25519_key_id(&signed.signer_key)?;
    if &signer_key != ast.from().key() {
        return Err(AnchorError::SignerMismatch {
            expected: ast.from().key().to_string(),
            actual: signer_key.to_string(),
        });
    }

    let pub_bytes =
        decode_lower_hex_fixed::<32>(signer_key.value()).map_err(AnchorError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))?;

    let sig_bytes = decode_lower_hex_fixed::<64>(&signed.signature_hex)
        .map_err(AnchorError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let payload = signing_payload(signed);
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|err| AnchorError::InvalidSignature(err.to_string()))?;

    let proof = VerifiedAnchorProof {
        anchor_id: signed.anchor_id.clone(),
        assurance,
        signer_key,
        actor_kind,
        valid_from: signed.valid_from,
        valid_until: signed.valid_until,
    };

    Ok(VerifiedMandate { ast, proof })
}

/// Verifies every Ed25519 mandate in a chain, returning `Vec<VerifiedMandate>` ready for
/// `handfest_core::gate::authorize`.
pub fn verify_chain(mandates: &[SignedMandate]) -> Result<Vec<VerifiedMandate>, AnchorError> {
    if mandates.is_empty() {
        return Err(AnchorError::EmptyChain);
    }
    let mut verified = Vec::with_capacity(mandates.len());
    for (hop, signed) in mandates.iter().enumerate() {
        let vm = verify_ed25519(signed).map_err(|source| AnchorError::ChainHop {
            hop,
            source: Box::new(source),
        })?;
        verified.push(vm);
    }
    Ok(verified)
}

/// Builds the domain-separated, length-prefixed payload signed by Ed25519 anchors.
///
/// Binds `anchor_id`, `assurance`, `actor_kind`, `signer_key`, `valid_from`, `valid_until`,
/// and `canonical_words` unambiguously so tampering with any envelope field invalidates the
/// signature.
#[must_use]
pub fn signing_payload(signed: &SignedMandate) -> Vec<u8> {
    let capacity = SIGNING_DOMAIN_PREFIX.len()
        + (8 * 7)
        + signed.anchor_id.len()
        + signed.assurance.len()
        + signed.actor_kind.len()
        + signed.signer_key.len()
        + signed.canonical_words.len();
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(SIGNING_DOMAIN_PREFIX);
    push_len_prefixed_str(&mut payload, &signed.anchor_id);
    push_len_prefixed_str(&mut payload, &signed.assurance);
    push_len_prefixed_str(&mut payload, &signed.actor_kind);
    push_len_prefixed_str(&mut payload, &signed.signer_key);
    payload.extend_from_slice(&signed.valid_from.to_be_bytes());
    payload.extend_from_slice(&signed.valid_until.to_be_bytes());
    push_len_prefixed_str(&mut payload, &signed.canonical_words);
    payload
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

fn validate_anchor_id(anchor_id: &str) -> Result<(), AnchorError> {
    if anchor_id.is_empty() {
        return Err(AnchorError::InvalidAnchorId(
            "anchor_id must not be empty".to_string(),
        ));
    }
    if !is_valid_quoted_str(anchor_id) {
        return Err(AnchorError::InvalidAnchorId(
            "anchor_id must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_validity_window(valid_from: i64, valid_until: i64) -> Result<(), AnchorError> {
    if !is_valid_timestamp(valid_from) {
        return Err(AnchorError::InvalidTimestamp(valid_from));
    }
    if !is_valid_timestamp(valid_until) {
        return Err(AnchorError::InvalidTimestamp(valid_until));
    }
    if valid_from > valid_until {
        return Err(AnchorError::InvalidValidityWindow {
            valid_from,
            valid_until,
        });
    }
    Ok(())
}

fn parse_ed25519_key_id(raw: &str) -> Result<KeyId, AnchorError> {
    let key_id = KeyId::parse(raw)
        .map_err(|err| AnchorError::InvalidPublicKey(format!("invalid KeyId '{raw}': {err}")))?;
    if key_id.scheme() != "ed25519" {
        return Err(AnchorError::InvalidPublicKey(format!(
            "expected 'ed25519' key scheme, got '{}'",
            key_id.scheme()
        )));
    }
    let _ = decode_lower_hex_fixed::<32>(key_id.value()).map_err(AnchorError::InvalidPublicKey)?;
    Ok(key_id)
}

fn decode_lower_hex_fixed<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let expected_len = N * 2;
    if input.len() != expected_len {
        return Err(format!(
            "expected {expected_len} lowercase hex chars, got {}",
            input.len()
        ));
    }
    if !input
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("expected lowercase hexadecimal digits only".to_string());
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(input, &mut out).map_err(|err| err.to_string())?;
    Ok(out)
}
