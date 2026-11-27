//! Single-source-of-truth signer configuration and resolution for all supported trust-anchor
//! signing backends (local Ed25519, SSH security keys, FIDO2, OpenPGP, and PIV smartcards).

use std::fmt;
use std::fs;
use std::path::PathBuf;

use handfest_anchors::{
    parse_ed25519_spki_pem, AnchorError, AssuranceLevel, CommandRunner, Ed25519KeyFile,
    Ed25519Keypair, Fido2CredentialFile, Fido2Ed25519Signer, MandateSigner, OpenPgpEd25519Signer,
    PivEd25519Signer, PivPinSource, PivSignerConfig, SshSkAnySigner, SystemCommandRunner,
    DEFAULT_PIV_KEY_ID, DEFAULT_PIV_PIN_ENV, DEFAULT_PKCS11_MODULE,
};
use handfest_core::ast::KeyId;

/// Default `anchor_id` for local software Ed25519 keys.
pub const DEFAULT_LOCAL_ED25519_ANCHOR_ID: &str = "local-ed25519";
/// Default `anchor_id` for OpenSSH FIDO2 (`sk-*`) security keys.
pub const DEFAULT_SSH_SK_ANCHOR_ID: &str = "yubikey-ssh-sk";
/// Default `anchor_id` for direct FIDO2 Ed25519 credentials.
pub const DEFAULT_FIDO2_ANCHOR_ID: &str = "yubikey-fido2";
/// Default `anchor_id` for OpenPGP smartcard Ed25519 keys.
pub const DEFAULT_OPENPGP_ANCHOR_ID: &str = "yubikey-openpgp";
/// Default `anchor_id` for PIV smartcard Ed25519 keys.
pub const DEFAULT_PIV_ANCHOR_ID: &str = "yubikey-piv";

/// Typed error returned while resolving a configured [`MandateSigner`].
#[derive(Debug)]
pub enum SignerLoadError {
    ReadFile {
        path: PathBuf,
        detail: String,
    },
    InvalidKeyFileJson(String),
    InvalidFido2CredentialJson(String),
    InvalidEnvVar(String),
    Anchor {
        context: &'static str,
        source: AnchorError,
    },
}

impl fmt::Display for SignerLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile { path, detail } => {
                write!(f, "failed to read '{}': {detail}", path.display())
            }
            Self::InvalidKeyFileJson(detail) => write!(f, "invalid key file JSON: {detail}"),
            Self::InvalidFido2CredentialJson(detail) => {
                write!(f, "invalid FIDO2 credential file JSON: {detail}")
            }
            Self::InvalidEnvVar(detail) => f.write_str(detail),
            Self::Anchor { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for SignerLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Anchor { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Declarative configuration selecting one of the supported `MandateSigner` backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerConfig {
    LocalEd25519 {
        key_path: PathBuf,
    },
    SshSk {
        key_path: PathBuf,
    },
    Fido2Ed25519 {
        cred_path: PathBuf,
        device_path: Option<String>,
    },
    OpenPgpEd25519 {
        fingerprint: String,
    },
    PivEd25519 {
        pubkey_path: PathBuf,
        config: PivSignerConfig,
    },
}

impl SignerConfig {
    /// Returns the default `anchor_id` for this signer backend.
    #[must_use]
    pub const fn default_anchor_id(&self) -> &'static str {
        match self {
            Self::LocalEd25519 { .. } => DEFAULT_LOCAL_ED25519_ANCHOR_ID,
            Self::SshSk { .. } => DEFAULT_SSH_SK_ANCHOR_ID,
            Self::Fido2Ed25519 { .. } => DEFAULT_FIDO2_ANCHOR_ID,
            Self::OpenPgpEd25519 { .. } => DEFAULT_OPENPGP_ANCHOR_ID,
            Self::PivEd25519 { .. } => DEFAULT_PIV_ANCHOR_ID,
        }
    }
}

/// Newtype adapter allowing a dynamically dispatched `Box<dyn MandateSigner>` to satisfy
/// `S: MandateSigner` generics (such as [`crate::daemon::ApproverDaemon`]).
pub struct BoxedSigner(Box<dyn MandateSigner>);

impl BoxedSigner {
    /// Wraps a boxed [`MandateSigner`].
    #[must_use]
    pub fn new(inner: Box<dyn MandateSigner>) -> Self {
        Self(inner)
    }

    /// Returns the inner boxed signer.
    #[must_use]
    pub fn into_inner(self) -> Box<dyn MandateSigner> {
        self.0
    }
}

impl MandateSigner for BoxedSigner {
    fn key_id(&self) -> KeyId {
        self.0.key_id()
    }

    fn assurance(&self) -> AssuranceLevel {
        self.0.assurance()
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        self.0.sign_payload(payload)
    }
}

/// Builds a [`PivSignerConfig`] from optional CLI overrides and `HANDFEST_PIV_PIN`.
pub fn build_piv_signer_config(
    piv_module: Option<String>,
    piv_id: Option<String>,
) -> Result<PivSignerConfig, SignerLoadError> {
    let pin_source = match std::env::var_os(DEFAULT_PIV_PIN_ENV) {
        None => PivPinSource::Interactive,
        Some(raw) => {
            let text = raw.to_str().ok_or_else(|| {
                SignerLoadError::InvalidEnvVar(format!(
                    "{DEFAULT_PIV_PIN_ENV} must be valid UTF-8 when set"
                ))
            })?;
            if text.is_empty() {
                return Err(SignerLoadError::InvalidEnvVar(format!(
                    "{DEFAULT_PIV_PIN_ENV} must not be empty when set"
                )));
            }
            PivPinSource::EnvVar(DEFAULT_PIV_PIN_ENV.to_string())
        }
    };
    Ok(PivSignerConfig {
        pkcs11_module: piv_module.unwrap_or_else(|| DEFAULT_PKCS11_MODULE.to_string()),
        key_id: piv_id.unwrap_or_else(|| DEFAULT_PIV_KEY_ID.to_string()),
        pin_source,
    })
}

/// Resolves a [`SignerConfig`] into a [`BoxedSigner`] using [`SystemCommandRunner`].
pub fn resolve_signer(config: &SignerConfig) -> Result<BoxedSigner, SignerLoadError> {
    resolve_signer_with_runner(config, SystemCommandRunner)
}

/// Resolves a [`SignerConfig`] into a [`BoxedSigner`] using an injected [`CommandRunner`].
pub fn resolve_signer_with_runner<R: CommandRunner + 'static>(
    config: &SignerConfig,
    runner: R,
) -> Result<BoxedSigner, SignerLoadError> {
    let inner: Box<dyn MandateSigner> = match config {
        SignerConfig::LocalEd25519 { key_path } => {
            let key_raw = read_utf8_file(key_path)?;
            let key_file: Ed25519KeyFile = serde_json::from_str(&key_raw)
                .map_err(|err| SignerLoadError::InvalidKeyFileJson(err.to_string()))?;
            let keypair = Ed25519Keypair::from_key_file(&key_file).map_err(|source| {
                SignerLoadError::Anchor {
                    context: "failed to load Ed25519 key",
                    source,
                }
            })?;
            Box::new(keypair)
        }
        SignerConfig::SshSk { key_path } => {
            let signer = SshSkAnySigner::from_key_path(key_path, runner).map_err(|source| {
                SignerLoadError::Anchor {
                    context: "failed to load SSH security key",
                    source,
                }
            })?;
            Box::new(signer)
        }
        SignerConfig::Fido2Ed25519 {
            cred_path,
            device_path,
        } => {
            let cred_raw = read_utf8_file(cred_path)?;
            let cred_file: Fido2CredentialFile = serde_json::from_str(&cred_raw)
                .map_err(|err| SignerLoadError::InvalidFido2CredentialJson(err.to_string()))?;
            let signer =
                Fido2Ed25519Signer::from_credential_file(runner, &cred_file, device_path.clone())
                    .map_err(|source| SignerLoadError::Anchor {
                    context: "failed to load FIDO2 credential",
                    source,
                })?;
            Box::new(signer)
        }
        SignerConfig::OpenPgpEd25519 { fingerprint } => {
            let signer = OpenPgpEd25519Signer::from_gpg_export_with(runner, fingerprint).map_err(
                |source| SignerLoadError::Anchor {
                    context: "failed to load OpenPGP key",
                    source,
                },
            )?;
            Box::new(signer)
        }
        SignerConfig::PivEd25519 {
            pubkey_path,
            config,
        } => {
            let pem = read_utf8_file(pubkey_path)?;
            let public_key =
                parse_ed25519_spki_pem(&pem).map_err(|source| SignerLoadError::Anchor {
                    context: "failed to load PIV Ed25519 public key",
                    source,
                })?;
            let signer =
                PivEd25519Signer::new(runner, config.clone(), public_key).map_err(|source| {
                    SignerLoadError::Anchor {
                        context: "failed to initialize PIV signer",
                        source,
                    }
                })?;
            Box::new(signer)
        }
    };
    Ok(BoxedSigner::new(inner))
}

fn read_utf8_file(path: &PathBuf) -> Result<String, SignerLoadError> {
    fs::read_to_string(path).map_err(|err| SignerLoadError::ReadFile {
        path: path.clone(),
        detail: err.to_string(),
    })
}
