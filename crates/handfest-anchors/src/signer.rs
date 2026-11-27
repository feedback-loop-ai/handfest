//! Pluggable signing and audited subprocess seams for trust-anchor backends.

use std::io::Write;
use std::process::{Command, Stdio};

use handfest_core::ast::KeyId;
use handfest_core::cnl::parse_canonical;
use handfest_core::gate::validate_proof_shape;

use crate::{
    format_actor_kind, format_assurance, map_proof_shape_error, signing_payload, AnchorError,
    AssuranceLevel, SignedMandate,
};

/// Pluggable signing backend for WYSIWYS `HANDFEST v1` mandates.
///
/// Implementations may sign in-process (such as [`crate::Ed25519Keypair`]) or delegate to
/// hardware-backed keys (SSH `ed25519-sk`, FIDO2/WebAuthn, OpenPGP smartcard, PIV smartcard).
pub trait MandateSigner {
    /// Returns the canonical `KeyId` bound to this signer.
    fn key_id(&self) -> KeyId;

    /// Returns the trust-anchor [`AssuranceLevel`] asserted by this signer.
    fn assurance(&self) -> AssuranceLevel;

    /// Signs the domain-separated payload produced by [`signing_payload`].
    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError>;
}

/// Signs strictly canonical `HANDFEST v1` text and all envelope metadata using any
/// [`MandateSigner`] implementation.
///
/// Enforces canonical CNL parsing, proof-shape validation (`anchor_id`, `valid_from`,
/// `valid_until`), and `ast.from().key() == &signer.key_id()` before signing the domain-separated
/// [`signing_payload`]. Fails closed if the signer returns an error or empty signature bytes.
pub fn sign_mandate_with<S: MandateSigner + ?Sized>(
    signer: &S,
    canonical_words: &str,
    anchor_id: impl Into<String>,
    valid_from: i64,
    valid_until: i64,
) -> Result<SignedMandate, AnchorError> {
    let ast = parse_canonical(canonical_words).map_err(AnchorError::NonCanonicalMandate)?;
    let anchor_id = anchor_id.into();
    validate_proof_shape(&anchor_id, valid_from, valid_until).map_err(map_proof_shape_error)?;

    let my_key_id = signer.key_id();
    if ast.from().key() != &my_key_id {
        return Err(AnchorError::SignerMismatch {
            expected: ast.from().key().to_string(),
            actual: my_key_id.to_string(),
        });
    }

    let mut signed = SignedMandate {
        canonical_words: canonical_words.to_string(),
        anchor_id,
        assurance: format_assurance(signer.assurance()).to_string(),
        actor_kind: format_actor_kind(ast.from().kind()).to_string(),
        signer_key: my_key_id.to_string(),
        valid_from,
        valid_until,
        signature_hex: String::new(),
    };
    let payload = signing_payload(&signed);
    let signature_bytes = signer.sign_payload(&payload)?;
    if signature_bytes.is_empty() {
        return Err(AnchorError::InvalidSignature(
            "signer returned empty signature".to_string(),
        ));
    }
    signed.signature_hex = hex::encode(signature_bytes);
    Ok(signed)
}

/// Captured stdout and stderr from a successfully completed external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Audited subprocess execution seam shared by external hardware CLI backends
/// (`ssh-keygen`, `fido2-assert`, `gpg`, `ykman`, `pkcs11-tool`).
///
/// Implementations must fail closed on spawn/I/O failures and non-zero exit statuses.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str], stdin: &[u8])
        -> Result<CommandOutput, AnchorError>;
}

/// Production [`CommandRunner`] backed by [`std::process::Command`] with piped stdio.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| AnchorError::CommandIo {
                program: program.to_string(),
                detail: err.to_string(),
            })?;

        let mut child_stdin = child
            .stdin
            .take()
            .expect("child stdin was configured with Stdio::piped()");

        let (write_res, output_res) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || child_stdin.write_all(stdin));
            let output_res = child.wait_with_output();
            let write_res = writer.join().expect("stdin writer thread does not panic");
            (write_res, output_res)
        });

        let output = output_res.map_err(|err| AnchorError::CommandIo {
            program: program.to_string(),
            detail: err.to_string(),
        })?;

        if !output.status.success() {
            return Err(AnchorError::CommandFailed {
                program: program.to_string(),
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        if let Err(err) = write_res {
            return Err(AnchorError::CommandIo {
                program: program.to_string(),
                detail: err.to_string(),
            });
        }

        Ok(CommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}
