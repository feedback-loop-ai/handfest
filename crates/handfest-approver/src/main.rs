//! Out-of-band WYSIWYS signing daemon CLI (`handfest-approver`).

#[cfg(unix)]
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use clap::{Args, Parser, ValueEnum};
#[cfg(unix)]
use handfest_anchors::MandateSigner;
#[cfg(unix)]
use handfest_approver::daemon::{ApproverDaemon, BoundSocket, SocketMode, DEFAULT_TIMEOUT_SECS};
#[cfg(unix)]
use handfest_approver::prompt::{
    ApprovalOutcome, ApprovalPrompt, DesktopPrompt, PromptError, TtyPrompt, WysiwysPromptView,
};
#[cfg(unix)]
use handfest_approver::signer::{build_piv_signer_config, resolve_signer, SignerConfig};

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PromptMode {
    Tty,
    Desktop,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SocketModeArg {
    #[value(name = "0600")]
    OwnerOnly,
    #[value(name = "0660")]
    GroupControlled,
}

#[cfg(unix)]
impl From<SocketModeArg> for SocketMode {
    fn from(arg: SocketModeArg) -> Self {
        match arg {
            SocketModeArg::OwnerOnly => Self::OwnerOnly,
            SocketModeArg::GroupControlled => Self::GroupControlled,
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Args)]
struct SignerFlags {
    /// Path to the Ed25519 secret key JSON file created by `handfest keygen`.
    #[arg(
        long,
        required_unless_present_any = ["ssh_key", "fido2_cred", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["ssh_key", "fido2_cred", "fido2_device", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    key: Option<PathBuf>,
    /// Path to an OpenSSH FIDO2 key handle or `.pub` file (`sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`).
    #[arg(
        long,
        required_unless_present_any = ["key", "fido2_cred", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["key", "fido2_cred", "fido2_device", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    ssh_key: Option<PathBuf>,
    /// Path to a FIDO2 Ed25519 credential metadata JSON file (`rp_id`, `credential_id_b64`, `key_id`).
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "gpg_key", "piv_pubkey"],
        conflicts_with_all = ["key", "ssh_key", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    fido2_cred: Option<PathBuf>,
    /// Optional FIDO2 HID device path (e.g. `/dev/hidraw0`); auto-discovered when omitted.
    #[arg(
        long,
        requires = "fido2_cred",
        conflicts_with_all = ["key", "ssh_key", "gpg_key", "piv_pubkey", "piv_module", "piv_id"]
    )]
    fido2_device: Option<String>,
    /// OpenPGP / GPG smartcard Ed25519 key fingerprint (40-hex or 64-hex).
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "fido2_cred", "piv_pubkey"],
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "piv_pubkey", "piv_module", "piv_id"]
    )]
    gpg_key: Option<String>,
    /// Path to a PEM-encoded RFC 8410 Ed25519 SubjectPublicKeyInfo file exported from a YubiKey PIV slot.
    #[arg(
        long,
        required_unless_present_any = ["key", "ssh_key", "fido2_cred", "gpg_key"],
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "gpg_key"]
    )]
    piv_pubkey: Option<PathBuf>,
    /// Path to the PKCS#11 shared library (used with --piv-pubkey).
    #[arg(
        long,
        requires = "piv_pubkey",
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "gpg_key"]
    )]
    piv_module: Option<String>,
    /// PKCS#11 object ID hex string for the PIV slot (default `02` for slot 9c).
    #[arg(
        long,
        requires = "piv_pubkey",
        conflicts_with_all = ["key", "ssh_key", "fido2_cred", "fido2_device", "gpg_key"]
    )]
    piv_id: Option<String>,
}

#[cfg(unix)]
impl SignerFlags {
    fn into_config(self) -> Result<SignerConfig, String> {
        match (
            self.key,
            self.ssh_key,
            self.fido2_cred,
            self.gpg_key,
            self.piv_pubkey,
        ) {
            (Some(key_path), None, None, None, None) => Ok(SignerConfig::LocalEd25519 { key_path }),
            (None, Some(key_path), None, None, None) => Ok(SignerConfig::SshSk { key_path }),
            (None, None, Some(cred_path), None, None) => Ok(SignerConfig::Fido2Ed25519 {
                cred_path,
                device_path: self.fido2_device,
            }),
            (None, None, None, Some(fingerprint), None) => {
                Ok(SignerConfig::OpenPgpEd25519 { fingerprint })
            }
            (None, None, None, None, Some(pubkey_path)) => Ok(SignerConfig::PivEd25519 {
                pubkey_path,
                config: build_piv_signer_config(self.piv_module, self.piv_id)
                    .map_err(|err| err.to_string())?,
            }),
            _ => Err(
                "specify exactly one of --key, --ssh-key, --fido2-cred, --gpg-key, or --piv-pubkey"
                    .to_string(),
            ),
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Parser)]
#[command(
    name = "handfest-approver",
    version,
    about = "Out-of-band WYSIWYS signing daemon for HANDFEST v1 mandates"
)]
struct Cli {
    /// Path to the restricted Unix domain socket to listen on.
    #[arg(long)]
    socket: PathBuf,
    #[command(flatten)]
    signer: SignerFlags,
    /// Human approval prompt mode (`tty` reads from `/dev/tty`; `desktop` shows a native dialog).
    #[arg(long, value_enum, default_value_t = PromptMode::Tty)]
    prompt: PromptMode,
    /// Per-request socket and approval timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,
    /// Optional default trust anchor identifier (defaults to the signer backend's standard ID).
    #[arg(long)]
    anchor_id: Option<String>,
    /// Unix socket permission mode (`0600` owner-only default, or `0660` group-controlled).
    #[arg(long, value_enum, default_value_t = SocketModeArg::OwnerOnly)]
    socket_mode: SocketModeArg,
}

#[cfg(unix)]
enum RuntimePrompt {
    Tty(TtyPrompt<std::io::BufReader<std::fs::File>, std::fs::File>),
    Desktop(DesktopPrompt),
}

#[cfg(unix)]
impl ApprovalPrompt for RuntimePrompt {
    fn prompt(&mut self, view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError> {
        match self {
            Self::Tty(prompt) => prompt.prompt(view),
            Self::Desktop(prompt) => prompt.prompt(view),
        }
    }

    fn prompt_with_timeout(
        &mut self,
        view: &WysiwysPromptView,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, PromptError> {
        match self {
            Self::Tty(prompt) => prompt.prompt_with_timeout(view, timeout),
            Self::Desktop(prompt) => prompt.prompt_with_timeout(view, timeout),
        }
    }
}

#[cfg(unix)]
fn build_prompt(mode: PromptMode, timeout: Duration) -> Result<RuntimePrompt, String> {
    match mode {
        PromptMode::Tty => TtyPrompt::open_dev_tty()
            .map(RuntimePrompt::Tty)
            .map_err(|err| err.to_string()),
        PromptMode::Desktop => Ok(RuntimePrompt::Desktop(
            DesktopPrompt::system().with_timeout(timeout),
        )),
    }
}

#[cfg(unix)]
fn run(cli: Cli) -> Result<ExitCode, String> {
    let timeout = handfest_approver::validate_timeout_secs(cli.timeout_secs)?;
    let signer_config = cli.signer.into_config()?;
    let default_anchor_id = cli
        .anchor_id
        .unwrap_or_else(|| signer_config.default_anchor_id().to_string());
    let signer = resolve_signer(&signer_config).map_err(|err| err.to_string())?;
    let prompt = build_prompt(cli.prompt, timeout)?;

    let mut daemon = ApproverDaemon::new(signer, prompt, default_anchor_id, timeout)
        .map_err(|err| err.to_string())?;

    let bound =
        BoundSocket::bind(&cli.socket, cli.socket_mode.into()).map_err(|err| err.to_string())?;
    eprintln!(
        "handfest-approver listening on {} (signer: {}, prompt: {:?}, timeout: {}s)",
        bound.path().display(),
        daemon.signer().key_id(),
        cli.prompt,
        cli.timeout_secs
    );
    daemon
        .serve_forever(bound.listener())
        .map_err(|err| err.to_string())?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(unix)]
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("error: handfest-approver requires a Unix platform with Unix domain socket support");
    ExitCode::FAILURE
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_local_ssh_and_fido2_signers() {
        let cli = Cli::try_parse_from([
            "handfest-approver",
            "--socket",
            "/tmp/handfest/approver.sock",
            "--key",
            "/tmp/handfest/root.key.json",
            "--prompt",
            "desktop",
            "--timeout-secs",
            "45",
            "--socket-mode",
            "0660",
        ])
        .expect("parse local key CLI args");
        assert_eq!(cli.prompt, PromptMode::Desktop);
        assert_eq!(cli.timeout_secs, 45);
        assert_eq!(
            SocketMode::from(cli.socket_mode),
            SocketMode::GroupControlled
        );
        assert_eq!(
            cli.signer.into_config().unwrap(),
            SignerConfig::LocalEd25519 {
                key_path: PathBuf::from("/tmp/handfest/root.key.json"),
            }
        );

        let ssh_cli = Cli::try_parse_from([
            "handfest-approver",
            "--socket",
            "/tmp/approver.sock",
            "--ssh-key",
            "/tmp/id_ed25519_sk.pub",
        ])
        .expect("parse ssh-key CLI args");
        assert_eq!(ssh_cli.prompt, PromptMode::Tty);
        assert_eq!(ssh_cli.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(SocketMode::from(ssh_cli.socket_mode), SocketMode::OwnerOnly);
        assert_eq!(
            ssh_cli.signer.into_config().unwrap(),
            SignerConfig::SshSk {
                key_path: PathBuf::from("/tmp/id_ed25519_sk.pub"),
            }
        );

        let fido2_cli = Cli::try_parse_from([
            "handfest-approver",
            "--socket",
            "/tmp/approver.sock",
            "--fido2-cred",
            "/tmp/cred.json",
            "--fido2-device",
            "/dev/hidraw0",
        ])
        .expect("parse fido2 CLI args");
        assert_eq!(
            fido2_cli.signer.into_config().unwrap(),
            SignerConfig::Fido2Ed25519 {
                cred_path: PathBuf::from("/tmp/cred.json"),
                device_path: Some("/dev/hidraw0".to_string()),
            }
        );
    }

    #[test]
    fn cli_parses_gpg_piv_and_rejects_invalid_combinations() {
        let gpg_cli = Cli::try_parse_from([
            "handfest-approver",
            "--socket",
            "/tmp/approver.sock",
            "--gpg-key",
            "0123456789ABCDEF0123456789ABCDEF01234567",
        ])
        .expect("parse gpg CLI args");
        assert_eq!(
            gpg_cli.signer.into_config().unwrap(),
            SignerConfig::OpenPgpEd25519 {
                fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
            }
        );

        let piv_cli = Cli::try_parse_from([
            "handfest-approver",
            "--socket",
            "/tmp/approver.sock",
            "--piv-pubkey",
            "/tmp/piv.pem",
            "--piv-module",
            "/tmp/libykcs11.so",
            "--piv-id",
            "02",
        ])
        .expect("parse piv CLI args");
        match piv_cli.signer.into_config().unwrap() {
            SignerConfig::PivEd25519 {
                pubkey_path,
                config,
            } => {
                assert_eq!(pubkey_path, PathBuf::from("/tmp/piv.pem"));
                assert_eq!(config.pkcs11_module, "/tmp/libykcs11.so");
                assert_eq!(config.key_id, "02");
            }
            other => panic!("unexpected config: {other:?}"),
        }

        assert!(Cli::try_parse_from([
            "handfest-approver",
            "--socket",
            "/tmp/approver.sock",
            "--key",
            "/tmp/a.json",
            "--ssh-key",
            "/tmp/b.pub",
        ])
        .is_err());

        assert!(
            Cli::try_parse_from(["handfest-approver", "--socket", "/tmp/approver.sock"]).is_err()
        );

        let zero_cli = Cli::try_parse_from([
            "handfest-approver",
            "--socket",
            "/tmp/approver.sock",
            "--key",
            "/tmp/a.json",
            "--timeout-secs",
            "0",
        ])
        .unwrap();
        let err = run(zero_cli).unwrap_err();
        assert!(err.contains("--timeout-secs must be greater than 0"));

        for huge in [
            (handfest_approver::MAX_TIMEOUT.as_secs() + 1).to_string(),
            (1u64 << 54).to_string(),
        ] {
            let huge_cli = Cli::try_parse_from([
                "handfest-approver",
                "--socket",
                "/tmp/approver.sock",
                "--key",
                "/tmp/a.json",
                "--timeout-secs",
                &huge,
            ])
            .unwrap();
            let err = run(huge_cli).unwrap_err();
            assert!(err.contains("--timeout-secs must not exceed"));
        }
    }
}
