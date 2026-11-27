//! Public `KeyId` derivation across all supported trust-anchor interfaces (`handfest keyid`)
//! and shared principal key CLI argument resolution for `handfest init`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use handfest_anchors::{
    parse_ed25519_spki_pem, piv_ed25519_key_id, AnchorError, CommandOutput, CommandRunner,
    Ed25519KeyFile, Ed25519Keypair, Fido2CredentialFile, Fido2Ed25519Signer, MandateSigner,
    OpenPgpEd25519Signer, SshSkPublicKey, SystemCommandRunner,
};
use handfest_core::ast::KeyId;
use serde::{Deserialize, Serialize};

/// Closed set of principal signer interfaces supported by `handfest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SignerKind {
    #[serde(rename = "local-ed25519")]
    LocalEd25519,
    #[serde(rename = "ssh-sk")]
    SshSk,
    #[serde(rename = "fido2")]
    Fido2,
    #[serde(rename = "openpgp")]
    OpenPgp,
    #[serde(rename = "piv")]
    Piv,
}

impl SignerKind {
    /// Returns the `handfest sign` / `handfest revoke` CLI flag for this signer interface.
    pub(crate) const fn sign_flag(self) -> &'static str {
        match self {
            Self::LocalEd25519 => "--key",
            Self::SshSk => "--ssh-key",
            Self::Fido2 => "--fido2-cred",
            Self::OpenPgp => "--gpg-key",
            Self::Piv => "--piv-pubkey",
        }
    }
}

/// Shared mutually exclusive principal key source CLI flags for `handfest keyid` and `handfest init`.
#[derive(Debug, Clone, Args)]
pub(crate) struct PrincipalKeyArgs {
    /// Path to a local Ed25519 key JSON file created by `handfest keygen`.
    #[arg(
        long,
        required_unless_present_any = ["ssh_key", "fido2_cred", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["ssh_key", "fido2_cred", "gpg_key", "piv_pubkey"]
    )]
    pub(crate) key: Option<PathBuf>,
    /// Path to an OpenSSH FIDO2 key handle or `.pub` file (`sk-ssh-ed25519@openssh.com`).
    #[arg(
        long,
        required_unless_present_any = ["key", "fido2_cred", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["key", "fido2_cred", "gpg_key", "piv_pubkey"]
    )]
    pub(crate) ssh_key: Option<PathBuf>,
    /// Path to a FIDO2 Ed25519 credential metadata JSON file (`rp_id`, `credential_id_b64`, `key_id`).
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["key", "ssh_key", "gpg_key", "piv_pubkey"]
    )]
    pub(crate) fido2_cred: Option<PathBuf>,
    /// OpenPGP / GPG smartcard Ed25519 key fingerprint (16-hex or 40-hex, optional trailing `!`).
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "fido2_cred", "piv_pubkey"],
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "piv_pubkey"]
    )]
    pub(crate) gpg_key: Option<String>,
    /// Path to a PEM-encoded RFC 8410 Ed25519 SubjectPublicKeyInfo file exported from a YubiKey PIV slot.
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "fido2_cred", "gpg_key"],
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "gpg_key"]
    )]
    pub(crate) piv_pubkey: Option<PathBuf>,
}

/// Validated principal key source selection (exactly one interface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrincipalKeySource {
    LocalEd25519(PathBuf),
    SshSk(PathBuf),
    Fido2(PathBuf),
    OpenPgp(String),
    Piv(PathBuf),
}

impl PrincipalKeyArgs {
    /// Converts CLI flags into a single validated [`PrincipalKeySource`], failing closed if zero or
    /// more than one flag is present.
    pub(crate) fn into_source(self) -> Result<PrincipalKeySource, String> {
        match (
            self.key,
            self.ssh_key,
            self.fido2_cred,
            self.gpg_key,
            self.piv_pubkey,
        ) {
            (Some(path), None, None, None, None) => Ok(PrincipalKeySource::LocalEd25519(path)),
            (None, Some(path), None, None, None) => Ok(PrincipalKeySource::SshSk(path)),
            (None, None, Some(path), None, None) => Ok(PrincipalKeySource::Fido2(path)),
            (None, None, None, Some(fpr), None) => Ok(PrincipalKeySource::OpenPgp(fpr)),
            (None, None, None, None, Some(path)) => Ok(PrincipalKeySource::Piv(path)),
            _ => Err(
                "exactly one of --key, --ssh-key, --fido2-cred, --gpg-key, or --piv-pubkey must be supplied"
                    .to_string(),
            ),
        }
    }
}

/// Public-only resolution result for a principal key source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPrincipalKey {
    pub(crate) key_id: KeyId,
    pub(crate) signer_kind: SignerKind,
    pub(crate) signer_hint: String,
}

/// Command runner that refuses to spawn subprocesses when validating offline public metadata.
struct NoopCommandRunner;

impl CommandRunner for NoopCommandRunner {
    fn run(
        &self,
        program: &str,
        _args: &[&str],
        _stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        Err(AnchorError::CommandIo {
            program: program.to_string(),
            detail: "subprocess execution is not permitted during offline credential validation"
                .to_string(),
        })
    }
}

/// Resolves the canonical public [`KeyId`], [`SignerKind`], and public signer hint for `source`.
///
/// Never reads private key material for hardware-backed interfaces (`--ssh-key`, `--fido2-cred`,
/// `--gpg-key`, `--piv-pubkey`).
pub(crate) fn resolve_principal_key(
    source: &PrincipalKeySource,
) -> Result<ResolvedPrincipalKey, String> {
    resolve_principal_key_with_runner(source, SystemCommandRunner)
}

pub(crate) fn resolve_principal_key_with_runner<R: CommandRunner>(
    source: &PrincipalKeySource,
    runner: R,
) -> Result<ResolvedPrincipalKey, String> {
    match source {
        PrincipalKeySource::LocalEd25519(path) => resolve_local_ed25519(path),
        PrincipalKeySource::SshSk(path) => resolve_ssh_sk(path),
        PrincipalKeySource::Fido2(path) => resolve_fido2(path),
        PrincipalKeySource::OpenPgp(fingerprint) => resolve_openpgp(runner, fingerprint),
        PrincipalKeySource::Piv(path) => resolve_piv(path),
    }
}

pub(crate) fn run_keyid_cli(args: PrincipalKeyArgs) -> Result<ExitCode, String> {
    let source = args.into_source()?;
    let resolved = resolve_principal_key(&source)?;
    println!("{}", resolved.key_id);
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn path_to_utf8_string(path: &Path, label: &str) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{label} path '{}' is not valid UTF-8", path.display()))
}

fn resolve_local_ed25519(path: &Path) -> Result<ResolvedPrincipalKey, String> {
    let hint = path_to_utf8_string(path, "--key")?;
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read '{}': {err}", path.display()))?;
    let key_file: Ed25519KeyFile =
        serde_json::from_str(&raw).map_err(|err| format!("invalid key file JSON: {err}"))?;
    let keypair = Ed25519Keypair::from_key_file(&key_file)
        .map_err(|err| format!("failed to load Ed25519 key: {err}"))?;
    Ok(ResolvedPrincipalKey {
        key_id: keypair.key_id(),
        signer_kind: SignerKind::LocalEd25519,
        signer_hint: hint,
    })
}

fn resolve_ssh_sk(path: &Path) -> Result<ResolvedPrincipalKey, String> {
    let hint = path_to_utf8_string(path, "--ssh-key")?;
    let pub_key = SshSkPublicKey::from_key_path(path)
        .map_err(|err| format!("failed to load SSH security key: {err}"))?;
    Ok(ResolvedPrincipalKey {
        key_id: pub_key.key_id(),
        signer_kind: SignerKind::SshSk,
        signer_hint: hint,
    })
}

fn resolve_fido2(path: &Path) -> Result<ResolvedPrincipalKey, String> {
    let hint = path_to_utf8_string(path, "--fido2-cred")?;
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read '{}': {err}", path.display()))?;
    let cred_file: Fido2CredentialFile = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid FIDO2 credential file JSON: {err}"))?;
    let signer = Fido2Ed25519Signer::from_credential_file(NoopCommandRunner, &cred_file, None)
        .map_err(|err| format!("failed to load FIDO2 credential: {err}"))?;
    Ok(ResolvedPrincipalKey {
        key_id: signer.key_id(),
        signer_kind: SignerKind::Fido2,
        signer_hint: hint,
    })
}

fn resolve_openpgp<R: CommandRunner>(
    runner: R,
    fingerprint: &str,
) -> Result<ResolvedPrincipalKey, String> {
    let signer = OpenPgpEd25519Signer::from_gpg_export_with(runner, fingerprint)
        .map_err(|err| format!("failed to load OpenPGP key '{fingerprint}': {err}"))?;
    Ok(ResolvedPrincipalKey {
        key_id: signer.key_id(),
        signer_kind: SignerKind::OpenPgp,
        signer_hint: signer.gpg_key_fingerprint().to_string(),
    })
}

fn resolve_piv(path: &Path) -> Result<ResolvedPrincipalKey, String> {
    let hint = path_to_utf8_string(path, "--piv-pubkey")?;
    let pem = fs::read_to_string(path)
        .map_err(|err| format!("failed to read '{}': {err}", path.display()))?;
    let public_key = parse_ed25519_spki_pem(&pem)
        .map_err(|err| format!("failed to load PIV Ed25519 public key: {err}"))?;
    Ok(ResolvedPrincipalKey {
        key_id: piv_ed25519_key_id(&public_key),
        signer_kind: SignerKind::Piv,
        signer_hint: hint,
    })
}

#[cfg(test)]
#[path = "keyid_tests.rs"]
mod tests;
