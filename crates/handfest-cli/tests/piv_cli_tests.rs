use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use handfest_anchors::{
    piv_ed25519_key_id, signing_payload, Ed25519Keypair, MandateSigner, SignedMandate,
    DEFAULT_PIV_KEY_ID, DEFAULT_PIV_PIN_ENV, DEFAULT_PKCS11_MODULE, ED25519_SPKI_DER_PREFIX,
};
use handfest_core::ast::{parse_rfc3339_utc, KeyId};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use serde_json::Value;
use tempfile::TempDir;

const VALID_FROM: &str = "2026-11-24T17:00:00Z";
const VALID_UNTIL: &str = "2026-11-25T17:00:00Z";

fn handfest_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_handfest"))
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let (chunks, rem) = input.as_chunks::<3>();
    for &[a, b, c] in chunks {
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        out.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        out.push(TABLE[(c & 0x3f) as usize] as char);
    }
    match rem {
        [] => {}
        [a] => {
            out.push(TABLE[(a >> 2) as usize] as char);
            out.push(TABLE[((a & 0x03) << 4) as usize] as char);
            out.push_str("==");
        }
        [a, b] => {
            out.push(TABLE[(a >> 2) as usize] as char);
            out.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            out.push(TABLE[((b & 0x0f) << 2) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

fn spki_pem(pubkey: &[u8; 32]) -> String {
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&ED25519_SPKI_DER_PREFIX);
    der.extend_from_slice(pubkey);
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64(&der)
    )
}

#[cfg(unix)]
struct PivCliFixture {
    dir: TempDir,
    bin_dir: PathBuf,
    pem_path: PathBuf,
    mandate_path: PathBuf,
    payload_file: PathBuf,
    sig_file: PathBuf,
    args_log: PathBuf,
    piv_key_id: KeyId,
    agent_kp: Ed25519Keypair,
}

#[cfg(unix)]
impl PivCliFixture {
    fn new(seed: u8, anchor_id: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).unwrap();

        let piv_kp = Ed25519Keypair::from_secret_bytes([seed; 32]);
        let piv_key_id = piv_ed25519_key_id(&piv_kp.public_key_bytes());
        let pem_path = dir.path().join("yubikey-9c.pem");
        fs::write(&pem_path, spki_pem(&piv_kp.public_key_bytes())).unwrap();

        let agent_kp = Ed25519Keypair::from_secret_bytes([seed.wrapping_add(1); 32]);
        let raw_mandate = format!(
            "HANDFEST v1\n\
             FROM human \"Valentin\" (key: {piv_key_id})\n\
             TO agent \"CodeAgent\" (key: {})\n\
             DELEGATION max 0 hops\n\
             ALLOW git.pr.merge\n\
             ON repo \"feedback-loop-ai/handfest\"\n\
             WHERE context.time < 2026-12-01T00:00:00Z\n",
            agent_kp.key_id()
        );
        let mandate_path = dir.path().join("root.hf");
        fs::write(&mandate_path, &raw_mandate).unwrap();

        let canonical = try_render_canonical(&parse_mandate(&raw_mandate).unwrap()).unwrap();
        let unsigned = SignedMandate {
            canonical_words: canonical,
            anchor_id: anchor_id.to_string(),
            assurance: "passkey".to_string(),
            actor_kind: "human".to_string(),
            signer_key: piv_key_id.to_string(),
            valid_from: parse_rfc3339_utc(VALID_FROM).unwrap(),
            valid_until: parse_rfc3339_utc(VALID_UNTIL).unwrap(),
            signature_hex: String::new(),
        };
        let expected_payload = signing_payload(&unsigned);
        let expected_sig = piv_kp.sign_payload(&expected_payload).unwrap();

        let payload_file = dir.path().join("expected.payload");
        let sig_file = dir.path().join("expected.sig");
        let args_log = dir.path().join("pkcs11.args");
        fs::write(&payload_file, &expected_payload).unwrap();
        fs::write(&sig_file, &expected_sig).unwrap();

        let fixture = Self {
            dir,
            bin_dir,
            pem_path,
            mandate_path,
            payload_file,
            sig_file,
            args_log,
            piv_key_id,
            agent_kp,
        };
        fixture.install_fake_pkcs11_tool(0);
        fixture
    }

    fn install_fake_pkcs11_tool(&self, exit_code: i32) {
        use std::os::unix::fs::PermissionsExt;

        let script_path = self.bin_dir.join("pkcs11-tool");
        let script = format!(
            "#!/bin/sh\n\
             set -eu\n\
             printf '%s\\n' \"$@\" > '{args_log}'\n\
             in_file=''\n\
             out_file=''\n\
             while [ \"$#\" -gt 0 ]; do\n\
               case \"$1\" in\n\
                 --input-file) in_file=\"$2\"; shift 2 ;;\n\
                 --output-file) out_file=\"$2\"; shift 2 ;;\n\
                 *) shift ;;\n\
               esac\n\
             done\n\
             if [ '{exit_code}' -ne 0 ]; then\n\
               echo 'simulated pkcs11-tool error' >&2\n\
               exit {exit_code}\n\
             fi\n\
             cmp -s \"$in_file\" '{expected_payload}'\n\
             cp '{sig_source}' \"$out_file\"\n",
            args_log = self.args_log.display(),
            exit_code = exit_code,
            expected_payload = self.payload_file.display(),
            sig_source = self.sig_file.display(),
        );
        fs::write(&script_path, script).unwrap();
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn run_with_path(&self, args: &[&str], pin_env: Option<&str>) -> Output {
        let existing_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{existing_path}", self.bin_dir.display());
        let mut cmd = handfest_bin();
        cmd.args(args).env("PATH", new_path);
        match pin_env {
            Some(val) => {
                cmd.env(DEFAULT_PIV_PIN_ENV, val);
            }
            None => {
                cmd.env_remove(DEFAULT_PIV_PIN_ENV);
            }
        }
        cmd.output().expect("spawn handfest")
    }
}

#[cfg(unix)]
#[test]
fn cli_piv_sign_verify_check_and_audit_end_to_end() {
    let fx = PivCliFixture::new(0x41, "yubikey-piv");
    let signed_path = fx.dir.path().join("root.signed.json");

    let sign_out = fx.run_with_path(
        &[
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--piv-pubkey",
            path_str(&fx.pem_path),
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
            "--out",
            path_str(&signed_path),
        ],
        None,
    );
    assert!(
        sign_out.status.success(),
        "piv sign failed: {}",
        String::from_utf8_lossy(&sign_out.stderr)
    );
    assert!(String::from_utf8(sign_out.stdout)
        .unwrap()
        .trim()
        .starts_with("sha256:"));

    let logged_args: Vec<String> = fs::read_to_string(&fx.args_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(logged_args[0], "--module");
    assert_eq!(logged_args[1], DEFAULT_PKCS11_MODULE);
    assert!(logged_args.contains(&"--login".to_string()));
    assert!(!logged_args.contains(&"--pin".to_string()));
    let id_pos = logged_args.iter().position(|a| a == "--id").unwrap();
    assert_eq!(logged_args[id_pos + 1], DEFAULT_PIV_KEY_ID);

    let signed: SignedMandate =
        serde_json::from_str(&fs::read_to_string(&signed_path).unwrap()).unwrap();
    assert_eq!(signed.anchor_id, "yubikey-piv");
    assert_eq!(signed.assurance, "passkey");
    assert_eq!(signed.signer_key, fx.piv_key_id.to_string());

    let verify_out = handfest_bin()
        .args(["verify", path_str(&signed_path)])
        .output()
        .unwrap();
    assert!(verify_out.status.success());
    let verify_json: Value = serde_json::from_slice(&verify_out.stdout).unwrap();
    assert_eq!(verify_json["status"], "verified");
    assert_eq!(verify_json["hops"], 1);

    let ledger_path = fx.dir.path().join("ledger.sqlite");
    let agent_key_str = fx.agent_kp.key_id().to_string();
    let check_out = handfest_bin()
        .args([
            "check",
            "--ledger",
            path_str(&ledger_path),
            "--chain",
            path_str(&signed_path),
            "--actor-key",
            &agent_key_str,
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "feedback-loop-ai/handfest",
            "--now",
            "2026-11-24T18:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(check_out.status.success());
    let check_json: Value = serde_json::from_slice(&check_out.stdout).unwrap();
    assert_eq!(check_json["verdict"], "permit");

    let audit_out = handfest_bin()
        .args([
            "audit",
            "--ledger",
            path_str(&ledger_path),
            "--actor-key",
            &agent_key_str,
        ])
        .output()
        .unwrap();
    assert!(audit_out.status.success());
    let audit_json: Value = serde_json::from_slice(&audit_out.stdout).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 1);
    assert_eq!(audit_json["track_record"]["permits"], 1);
}

#[cfg(unix)]
#[test]
fn cli_piv_supports_custom_flags_and_env_pin_without_leaking_secret_on_argv() {
    let fx = PivCliFixture::new(0x51, "yubikey-5c-nano");
    let secret_pin = "987654-never-on-argv";
    let out = fx.run_with_path(
        &[
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--piv-pubkey",
            path_str(&fx.pem_path),
            "--piv-module",
            "/opt/ykcs11/libykcs11.so",
            "--piv-id",
            "04",
            "--anchor-id",
            "yubikey-5c-nano",
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
        ],
        Some(secret_pin),
    );
    assert!(
        out.status.success(),
        "custom piv sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let signed: SignedMandate = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(signed.anchor_id, "yubikey-5c-nano");

    let logged_raw = fs::read_to_string(&fx.args_log).unwrap();
    assert!(
        !logged_raw.contains(secret_pin),
        "PIN secret must never appear on argv"
    );
    let logged_args: Vec<&str> = logged_raw.lines().collect();
    assert_eq!(logged_args[1], "/opt/ykcs11/libykcs11.so");
    assert!(logged_args
        .windows(2)
        .any(|w| w == ["--pin", "env:HANDFEST_PIV_PIN"]));
    assert!(logged_args.windows(2).any(|w| w == ["--id", "04"]));
}

#[cfg(unix)]
#[test]
fn cli_piv_fails_closed_on_empty_pin_env_tool_exit_and_flag_conflicts() {
    let fx = PivCliFixture::new(0x61, "yubikey-piv");

    let empty_pin_out = fx.run_with_path(
        &[
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--piv-pubkey",
            path_str(&fx.pem_path),
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
        ],
        Some(""),
    );
    assert!(!empty_pin_out.status.success());
    assert!(String::from_utf8_lossy(&empty_pin_out.stderr).contains(DEFAULT_PIV_PIN_ENV));

    fx.install_fake_pkcs11_tool(2);
    let fail_out = fx.run_with_path(
        &[
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--piv-pubkey",
            path_str(&fx.pem_path),
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
        ],
        None,
    );
    assert!(!fail_out.status.success());
    assert!(String::from_utf8_lossy(&fail_out.stderr).contains("simulated pkcs11-tool error"));

    let key_path = fx.dir.path().join("local.key.json");
    fs::write(
        &key_path,
        serde_json::to_string(&fx.agent_kp.to_key_file()).unwrap(),
    )
    .unwrap();

    for bad_args in [
        vec![
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--key",
            path_str(&key_path),
            "--piv-pubkey",
            path_str(&fx.pem_path),
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
        ],
        vec![
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
        ],
        vec![
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--key",
            path_str(&key_path),
            "--piv-module",
            "/tmp/fake.so",
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
        ],
        vec![
            "sign",
            "--mandate",
            path_str(&fx.mandate_path),
            "--key",
            path_str(&key_path),
            "--piv-id",
            "02",
            "--valid-from",
            VALID_FROM,
            "--valid-until",
            VALID_UNTIL,
        ],
    ] {
        let res = handfest_bin().args(&bad_args).output().unwrap();
        assert!(
            !res.status.success(),
            "expected CLI rejection for {bad_args:?}"
        );
    }
}
