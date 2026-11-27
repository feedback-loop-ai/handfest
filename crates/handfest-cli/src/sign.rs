//! Mandate signing configuration, signer resolution, and `handfest sign` execution.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(test)]
use handfest_anchors::CommandRunner;
use handfest_anchors::{sign_mandate_with, MandateSigner, PivSignerConfig, SignedMandate};
pub(crate) use handfest_approver::signer::SignerConfig;
#[cfg(test)]
use handfest_approver::signer::{DEFAULT_FIDO2_ANCHOR_ID, DEFAULT_LOCAL_ED25519_ANCHOR_ID};
use handfest_core::cnl::{parse_mandate, try_render_canonical};

use crate::parse_timestamp_arg;

pub(crate) fn build_piv_signer_config(
    piv_module: Option<String>,
    piv_id: Option<String>,
) -> Result<PivSignerConfig, String> {
    handfest_approver::signer::build_piv_signer_config(piv_module, piv_id)
        .map_err(|err| err.to_string())
}

pub(crate) struct SignArgs {
    pub(crate) mandate_path: PathBuf,
    pub(crate) signer: SignerConfig,
    pub(crate) valid_from: String,
    pub(crate) valid_until: String,
    pub(crate) anchor_id: String,
    pub(crate) out: Option<PathBuf>,
}

pub(crate) fn resolve_signer(config: &SignerConfig) -> Result<Box<dyn MandateSigner>, String> {
    handfest_approver::signer::resolve_signer(config)
        .map(handfest_approver::signer::BoxedSigner::into_inner)
        .map_err(|err| err.to_string())
}

#[cfg(test)]
fn resolve_signer_with_runner<R: CommandRunner + 'static>(
    config: &SignerConfig,
    runner: R,
) -> Result<Box<dyn MandateSigner>, String> {
    handfest_approver::signer::resolve_signer_with_runner(config, runner)
        .map(handfest_approver::signer::BoxedSigner::into_inner)
        .map_err(|err| err.to_string())
}

pub(crate) fn sign_canonical_with_signer(
    canonical: &str,
    signer: &dyn MandateSigner,
    valid_from_raw: &str,
    valid_until_raw: &str,
    anchor_id: &str,
) -> Result<SignedMandate, String> {
    let valid_from = parse_timestamp_arg("valid-from", valid_from_raw)?;
    let valid_until = parse_timestamp_arg("valid-until", valid_until_raw)?;
    sign_mandate_with(signer, canonical, anchor_id, valid_from, valid_until)
        .map_err(|err| format!("failed to sign mandate: {err}"))
}

pub(crate) fn cmd_sign(args: &SignArgs) -> Result<ExitCode, String> {
    let mandate_raw = fs::read_to_string(&args.mandate_path)
        .map_err(|err| format!("failed to read '{}': {err}", args.mandate_path.display()))?;
    let ast = parse_mandate(&mandate_raw).map_err(|err| format!("invalid mandate: {err}"))?;
    let canonical = try_render_canonical(&ast).map_err(|err| format!("render error: {err}"))?;

    let signer = resolve_signer(&args.signer)?;
    let signed = sign_canonical_with_signer(
        &canonical,
        signer.as_ref(),
        &args.valid_from,
        &args.valid_until,
        &args.anchor_id,
    )?;
    let mandate_id = ast
        .try_mandate_id()
        .map_err(|err| format!("failed to hash mandate: {err}"))?;
    let json_text =
        serde_json::to_string_pretty(&signed).map_err(|err| format!("serialize error: {err}"))?;

    if let Some(path) = args.out.as_deref() {
        fs::write(path, format!("{json_text}\n"))
            .map_err(|err| format!("failed to write '{}': {err}", path.display()))?;
        println!("{mandate_id}");
    } else {
        println!("{json_text}");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use handfest_anchors::{
        format_fido2_ed25519_key_id, AnchorError, AssuranceLevel, CommandOutput, Ed25519Keypair,
        Fido2CredentialFile, DEFAULT_FIDO2_RP_ID,
    };
    use handfest_core::ast::KeyId;

    struct DummyRunner;

    impl CommandRunner for DummyRunner {
        fn run(
            &self,
            program: &str,
            _args: &[&str],
            _stdin: &[u8],
        ) -> Result<CommandOutput, AnchorError> {
            Err(AnchorError::CommandIo {
                program: program.to_string(),
                detail: "dummy runner not expected to execute".to_string(),
            })
        }
    }

    #[test]
    fn resolve_signer_loads_ed25519_and_rejects_bad_inputs() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let kp = Ed25519Keypair::from_secret_bytes([0x5a; 32]);
        let key_path = dir.path().join("signer.key.json");
        let key_json = serde_json::to_string_pretty(&kp.to_key_file()).unwrap();
        fs::write(&key_path, &key_json).unwrap();

        let cfg = SignerConfig::LocalEd25519 {
            key_path: key_path.clone(),
        };
        assert_eq!(cfg.default_anchor_id(), DEFAULT_LOCAL_ED25519_ANCHOR_ID);

        let signer = resolve_signer(&cfg).expect("resolve valid Ed25519 signer");
        assert_eq!(signer.key_id(), kp.key_id());
        assert_eq!(signer.assurance(), AssuranceLevel::LocalKey);

        let missing_err = resolve_signer(&SignerConfig::LocalEd25519 {
            key_path: dir.path().join("missing.json"),
        })
        .err()
        .expect("missing key file must fail");
        assert!(missing_err.contains("failed to read"));

        let bad_json_path = dir.path().join("bad.json");
        fs::write(&bad_json_path, "{").unwrap();
        let json_err = resolve_signer(&SignerConfig::LocalEd25519 {
            key_path: bad_json_path,
        })
        .err()
        .expect("invalid JSON must fail");
        assert!(json_err.contains("invalid key file JSON"));

        let mut mismatch_file = kp.to_key_file();
        mismatch_file.key_id = format!("ed25519:{}", "0".repeat(64));
        let mismatch_path = dir.path().join("mismatch.json");
        fs::write(
            &mismatch_path,
            serde_json::to_string_pretty(&mismatch_file).unwrap(),
        )
        .unwrap();
        let mismatch_err = resolve_signer(&SignerConfig::LocalEd25519 {
            key_path: mismatch_path,
        })
        .err()
        .expect("mismatched key_id must fail");
        assert!(mismatch_err.contains("failed to load Ed25519 key"));
    }

    #[test]
    fn resolve_signer_loads_fido2_cred_and_rejects_bad_inputs() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let kp = Ed25519Keypair::from_secret_bytes([0x6b; 32]);
        let fido2_key_id = format_fido2_ed25519_key_id(&kp.public_key_bytes()).unwrap();
        let cred = Fido2CredentialFile {
            rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
            credential_id_b64: "AQIDBA==".to_string(),
            key_id: fido2_key_id.to_string(),
        };
        let cred_path = dir.path().join("yubikey.fido2.json");
        fs::write(&cred_path, serde_json::to_string_pretty(&cred).unwrap()).unwrap();

        let cfg = SignerConfig::Fido2Ed25519 {
            cred_path: cred_path.clone(),
            device_path: Some("/dev/hidraw0".to_string()),
        };
        assert_eq!(cfg.default_anchor_id(), DEFAULT_FIDO2_ANCHOR_ID);

        let signer =
            resolve_signer_with_runner(&cfg, DummyRunner).expect("resolve valid FIDO2 credential");
        assert_eq!(signer.key_id(), fido2_key_id);
        assert_eq!(signer.assurance(), AssuranceLevel::Passkey);

        let missing_err = resolve_signer_with_runner(
            &SignerConfig::Fido2Ed25519 {
                cred_path: dir.path().join("missing.fido2.json"),
                device_path: None,
            },
            DummyRunner,
        )
        .err()
        .expect("missing credential file must fail");
        assert!(missing_err.contains("failed to read"));

        let unknown_field_path = dir.path().join("unknown.fido2.json");
        fs::write(
            &unknown_field_path,
            format!(
                r#"{{"rp_id":"handfest.local","credential_id_b64":"AQIDBA==","key_id":"{fido2_key_id}","extra":true}}"#
            ),
        )
        .unwrap();
        let unknown_err = resolve_signer_with_runner(
            &SignerConfig::Fido2Ed25519 {
                cred_path: unknown_field_path,
                device_path: None,
            },
            DummyRunner,
        )
        .err()
        .expect("unknown field must fail");
        assert!(unknown_err.contains("invalid FIDO2 credential file JSON"));

        let bad_cred_path = dir.path().join("bad_rp.fido2.json");
        let bad_cred = Fido2CredentialFile {
            rp_id: String::new(),
            credential_id_b64: "AQIDBA==".to_string(),
            key_id: fido2_key_id.to_string(),
        };
        fs::write(
            &bad_cred_path,
            serde_json::to_string_pretty(&bad_cred).unwrap(),
        )
        .unwrap();
        let bad_cred_err = resolve_signer_with_runner(
            &SignerConfig::Fido2Ed25519 {
                cred_path: bad_cred_path,
                device_path: None,
            },
            DummyRunner,
        )
        .err()
        .expect("empty rp_id must fail");
        assert!(bad_cred_err.contains("failed to load FIDO2 credential"));
    }

    #[test]
    fn sign_canonical_with_signer_accepts_non_ed25519_boxed_signer() {
        struct StubHardwareSigner(KeyId);

        impl MandateSigner for StubHardwareSigner {
            fn key_id(&self) -> KeyId {
                self.0.clone()
            }

            fn assurance(&self) -> AssuranceLevel {
                AssuranceLevel::Passkey
            }

            fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
                assert!(!payload.is_empty());
                Ok(vec![0xca, 0xfe, 0xba, 0xbe])
            }
        }

        let hw_key = KeyId::new("passkey", "yk-cli-test").unwrap();
        let agent_key = KeyId::new("ed25519", "1".repeat(64)).unwrap();
        let raw = format!(
            "HANDFEST v1\nFROM human \"Valentin\" (key: {hw_key})\nTO agent \"Bot\" (key: {agent_key})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n"
        );
        let ast = parse_mandate(&raw).unwrap();
        let canonical = try_render_canonical(&ast).unwrap();

        let boxed: Box<dyn MandateSigner> = Box::new(StubHardwareSigner(hw_key.clone()));
        let signed = sign_canonical_with_signer(
            &canonical,
            boxed.as_ref(),
            "2026-11-24T17:00:00Z",
            "2026-11-25T01:00:00Z",
            "yubikey-5",
        )
        .expect("sign with boxed custom MandateSigner");

        assert_eq!(signed.signer_key, hw_key.to_string());
        assert_eq!(signed.assurance, "passkey");
        assert_eq!(signed.anchor_id, "yubikey-5");
        assert_eq!(signed.signature_hex, "cafebabe");

        let bad_ts = sign_canonical_with_signer(
            &canonical,
            boxed.as_ref(),
            "not-a-timestamp",
            "2026-11-25T01:00:00Z",
            "yubikey-5",
        )
        .unwrap_err();
        assert!(bad_ts.contains("invalid --valid-from"));
    }
}
