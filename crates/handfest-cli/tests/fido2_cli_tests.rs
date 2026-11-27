use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use handfest_anchors::{
    format_fido2_ed25519_key_id, signing_payload, Ed25519Keypair, Fido2CredentialFile,
    MandateSigner, SignedMandate, DEFAULT_FIDO2_RP_ID, FIDO2_FLAG_UP,
};
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::cnl::{parse_mandate, render_canonical};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn b64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(unix)]
fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
struct FakeToolSpec<'a> {
    bin_dir: &'a Path,
    signer_kp: &'a Ed25519Keypair,
    canonical_words: &'a str,
    anchor_id: &'a str,
    valid_from: &'a str,
    valid_until: &'a str,
    rp_id: &'a str,
    cred_id_b64: &'a str,
    device_path: &'a str,
    install_token_tool: bool,
}

#[cfg(unix)]
fn install_fake_fido2_tools(spec: &FakeToolSpec<'_>) {
    let fido2_key = format_fido2_ed25519_key_id(&spec.signer_kp.public_key_bytes()).unwrap();
    let skeleton = SignedMandate {
        canonical_words: spec.canonical_words.to_string(),
        anchor_id: spec.anchor_id.to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: fido2_key.to_string(),
        valid_from: parse_rfc3339_utc(spec.valid_from).unwrap(),
        valid_until: parse_rfc3339_utc(spec.valid_until).unwrap(),
        signature_hex: String::new(),
    };
    let cdh = sha256(&signing_payload(&skeleton));
    let cdh_b64 = b64_encode(&cdh);

    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&sha256(spec.rp_id.as_bytes()));
    auth_data.push(FIDO2_FLAG_UP);
    auth_data.extend_from_slice(&11u32.to_be_bytes());

    let mut signed_msg = auth_data.clone();
    signed_msg.extend_from_slice(&cdh);
    let sig_bytes = spec.signer_kp.sign_payload(&signed_msg).unwrap();

    let mut cbor_auth = vec![0x58, 37];
    cbor_auth.extend_from_slice(&auth_data);
    let cbor_auth_b64 = b64_encode(&cbor_auth);
    let sig_b64 = b64_encode(&sig_bytes);

    if spec.install_token_tool {
        let token_script = format!(
            "#!/bin/sh\n\
             set -eu\n\
             if [ \"$#\" -ne 1 ] || [ \"$1\" != \"-L\" ]; then\n\
               echo \"unexpected args: $*\" >&2\n\
               exit 2\n\
             fi\n\
             printf '%s: vendor=0x1050, product=0x0407 (Yubico YubiKey)\\n' '{}'\n",
            spec.device_path
        );
        write_executable(&spec.bin_dir.join("fido2-token"), &token_script);
    }

    let assert_script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         if [ \"$#\" -ne 4 ] || [ \"$1\" != \"-G\" ] || [ \"$2\" != \"-t\" ] || [ \"$3\" != \"up=true\" ] || [ \"$4\" != \"{}\" ]; then\n\
           echo \"unexpected args: $*\" >&2\n\
           exit 2\n\
         fi\n\
         IFS= read -r l1\n\
         IFS= read -r l2\n\
         IFS= read -r l3\n\
         if [ \"$l1\" != \"{cdh_b64}\" ] || [ \"$l2\" != \"{}\" ] || [ \"$l3\" != \"{}\" ]; then\n\
           echo \"unexpected stdin: $l1 | $l2 | $l3\" >&2\n\
           exit 3\n\
         fi\n\
         printf '%s\\n%s\\n%s\\n%s\\n' '{cdh_b64}' '{}' '{cbor_auth_b64}' '{sig_b64}'\n",
        spec.device_path, spec.rp_id, spec.cred_id_b64, spec.rp_id
    );
    write_executable(&spec.bin_dir.join("fido2-assert"), &assert_script);
}

#[cfg(unix)]
fn path_with_bin(bin_dir: &Path) -> String {
    let existing = std::env::var("PATH").unwrap_or_default();
    format!("{}:{existing}", bin_dir.display())
}

#[cfg(unix)]
#[test]
fn cli_fido2_sign_verify_check_and_audit_end_to_end() {
    let dir = TempDir::new().unwrap();
    let bin_dir = dir.path().join("bin");
    fs::create_dir(&bin_dir).unwrap();

    let human_kp = Ed25519Keypair::from_secret_bytes([0x81; 32]);
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x82; 32]);
    let human_key = format_fido2_ed25519_key_id(&human_kp.public_key_bytes()).unwrap();
    let cred_b64 = b64_encode(b"cli-e2e-cred");

    let cred_path = dir.path().join("yubikey.fido2.json");
    let cred = Fido2CredentialFile {
        rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
        credential_id_b64: cred_b64.clone(),
        key_id: human_key.to_string(),
    };
    fs::write(&cred_path, serde_json::to_string_pretty(&cred).unwrap()).unwrap();

    let raw_mandate = format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: {human_key})\n",
            "TO agent \"brokkr:ship\" (key: {agent_key})\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE context.time >= 2026-11-24T17:00:00Z\n",
            "  AND context.time < 2026-11-25T01:00:00Z\n",
            "  AND resource.author == \"valentin\"\n",
            "LIMIT 2 calls\n",
        ),
        human_key = human_key,
        agent_key = agent_kp.key_id(),
    );
    let canonical = render_canonical(&parse_mandate(&raw_mandate).unwrap());
    let mandate_path = dir.path().join("root.handfest");
    fs::write(&mandate_path, &raw_mandate).unwrap();

    install_fake_fido2_tools(&FakeToolSpec {
        bin_dir: &bin_dir,
        signer_kp: &human_kp,
        canonical_words: &canonical,
        anchor_id: "yubikey-fido2",
        valid_from: "2026-11-24T17:00:00Z",
        valid_until: "2026-11-25T01:00:00Z",
        rp_id: DEFAULT_FIDO2_RP_ID,
        cred_id_b64: &cred_b64,
        device_path: "/dev/hidraw0",
        install_token_tool: true,
    });

    let signed_path = dir.path().join("root.signed.json");
    let sign_out = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .env("PATH", path_with_bin(&bin_dir))
        .args([
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
            "--out",
            signed_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        sign_out.status.success(),
        "fido2 sign failed: stderr={}",
        String::from_utf8_lossy(&sign_out.stderr)
    );

    let signed: SignedMandate =
        serde_json::from_str(&fs::read_to_string(&signed_path).unwrap()).unwrap();
    assert_eq!(signed.anchor_id, "yubikey-fido2");
    assert_eq!(signed.assurance, "passkey");
    assert_eq!(signed.signer_key, human_key.to_string());

    assert_verify_check_and_audit(
        &signed_path,
        &dir.path().join("fido2.sqlite"),
        &agent_kp.key_id().to_string(),
    );

    // Also verify stdout emission when --out is omitted.
    let stdout_sign = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .env("PATH", path_with_bin(&bin_dir))
        .args([
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(
        stdout_sign.status.success(),
        "fido2 stdout sign failed: stderr={}",
        String::from_utf8_lossy(&stdout_sign.stderr)
    );
    let stdout_signed: SignedMandate = serde_json::from_slice(&stdout_sign.stdout).unwrap();
    assert_eq!(stdout_signed, signed);
}

#[cfg(unix)]
fn assert_verify_check_and_audit(signed_path: &Path, ledger_path: &Path, actor_key: &str) {
    let verify_out = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args(["verify", signed_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        verify_out.status.success(),
        "verify failed: stderr={}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let verify_json: serde_json::Value = serde_json::from_slice(&verify_out.stdout).unwrap();
    assert_eq!(verify_json["status"], "verified");
    assert_eq!(verify_json["hops"], 1);

    let run_check = |facts: &str, now: &str| {
        Command::new(env!("CARGO_BIN_EXE_handfest"))
            .args([
                "check",
                "--ledger",
                ledger_path.to_str().unwrap(),
                "--chain",
                signed_path.to_str().unwrap(),
                "--actor-key",
                actor_key,
                "--action",
                "git.pr.merge",
                "--resource-kind",
                "repo",
                "--resource-id",
                "feedback-loop-ai/handfest",
                "--facts",
                facts,
                "--now",
                now,
            ])
            .output()
            .unwrap()
    };

    let permit_out = run_check(r#"{"resource.author":"valentin"}"#, "2026-11-24T18:00:00Z");
    assert!(
        permit_out.status.success(),
        "check permit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&permit_out.stdout),
        String::from_utf8_lossy(&permit_out.stderr)
    );
    let permit_json: serde_json::Value = serde_json::from_slice(&permit_out.stdout).unwrap();
    assert_eq!(permit_json["verdict"], "permit");

    let deny_out = run_check(r#"{"resource.author":"mallory"}"#, "2026-11-24T18:05:00Z");
    assert!(!deny_out.status.success());
    let deny_json: serde_json::Value = serde_json::from_slice(&deny_out.stdout).unwrap();
    assert_eq!(deny_json["verdict"], "deny");

    let audit_out = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "audit",
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--actor-key",
            actor_key,
        ])
        .output()
        .unwrap();
    assert!(
        audit_out.status.success(),
        "audit failed: stderr={}",
        String::from_utf8_lossy(&audit_out.stderr)
    );
    let audit_json: serde_json::Value = serde_json::from_slice(&audit_out.stdout).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 2);
}

#[cfg(unix)]
#[test]
fn cli_fido2_explicit_device_and_mixed_delegation_chain() {
    let dir = TempDir::new().unwrap();
    let bin_dir = dir.path().join("bin");
    fs::create_dir(&bin_dir).unwrap();

    let human_kp = Ed25519Keypair::from_secret_bytes([0x91; 32]);
    let dispatcher_kp = Ed25519Keypair::from_secret_bytes([0x92; 32]);
    let worker_kp = Ed25519Keypair::from_secret_bytes([0x93; 32]);
    let human_key = format_fido2_ed25519_key_id(&human_kp.public_key_bytes()).unwrap();
    let cred_b64 = b64_encode(b"cli-explicit-device-cred");

    let cred_path = dir.path().join("yubikey.fido2.json");
    let cred = Fido2CredentialFile {
        rp_id: "corp.example.com".to_string(),
        credential_id_b64: cred_b64.clone(),
        key_id: human_key.to_string(),
    };
    fs::write(&cred_path, serde_json::to_string_pretty(&cred).unwrap()).unwrap();

    let dispatcher_key_path = dir.path().join("dispatcher.key.json");
    fs::write(
        &dispatcher_key_path,
        serde_json::to_string_pretty(&dispatcher_kp.to_key_file()).unwrap(),
    )
    .unwrap();

    let root_raw = format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: {human_key})\n",
            "TO agent \"brokkr:dispatcher\" (key: {dispatcher_key})\n",
            "DELEGATION max 1 hop\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/*\"\n",
            "WHERE context.time >= 2026-11-24T17:00:00Z\n",
            "  AND context.time < 2026-11-25T01:00:00Z\n",
            "LIMIT 5 calls\n",
        ),
        human_key = human_key,
        dispatcher_key = dispatcher_kp.key_id(),
    );
    let root_ast = parse_mandate(&root_raw).unwrap();
    let root_canonical = render_canonical(&root_ast);
    let root_mandate_path = dir.path().join("root.handfest");
    fs::write(&root_mandate_path, &root_raw).unwrap();

    install_fake_fido2_tools(&FakeToolSpec {
        bin_dir: &bin_dir,
        signer_kp: &human_kp,
        canonical_words: &root_canonical,
        anchor_id: "yubikey-5c-nfc",
        valid_from: "2026-11-24T17:00:00Z",
        valid_until: "2026-11-25T01:00:00Z",
        rp_id: "corp.example.com",
        cred_id_b64: &cred_b64,
        device_path: "/dev/hidraw7",
        install_token_tool: false,
    });

    let root_signed_path = dir.path().join("root.signed.json");
    let sign_root = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .env("PATH", path_with_bin(&bin_dir))
        .args([
            "sign",
            "--mandate",
            root_mandate_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "--fido2-device",
            "/dev/hidraw7",
            "--anchor-id",
            "yubikey-5c-nfc",
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
            "--out",
            root_signed_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        sign_root.status.success(),
        "fido2 root sign failed: stderr={}",
        String::from_utf8_lossy(&sign_root.stderr)
    );

    let child_raw = format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {parent}\n",
            "FROM agent \"brokkr:dispatcher\" (key: {dispatcher_key})\n",
            "TO agent \"brokkr:worker\" (key: {worker_key})\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE context.time >= 2026-11-24T18:00:00Z\n",
            "  AND context.time < 2026-11-24T19:00:00Z\n",
            "LIMIT 2 calls\n",
        ),
        parent = root_ast.mandate_id(),
        dispatcher_key = dispatcher_kp.key_id(),
        worker_key = worker_kp.key_id(),
    );
    let child_mandate_path = dir.path().join("child.handfest");
    fs::write(&child_mandate_path, &child_raw).unwrap();
    let child_signed_path = dir.path().join("child.signed.json");
    let sign_child = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "sign",
            "--mandate",
            child_mandate_path.to_str().unwrap(),
            "--key",
            dispatcher_key_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:30:00Z",
            "--valid-until",
            "2026-11-24T20:00:00Z",
            "--out",
            child_signed_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        sign_child.status.success(),
        "child sign failed: stderr={}",
        String::from_utf8_lossy(&sign_child.stderr)
    );

    let verify_chain_out = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "verify",
            root_signed_path.to_str().unwrap(),
            child_signed_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify_chain_out.status.success(),
        "mixed chain verify failed: stderr={}",
        String::from_utf8_lossy(&verify_chain_out.stderr)
    );
    let vjson: serde_json::Value = serde_json::from_slice(&verify_chain_out.stdout).unwrap();
    assert_eq!(vjson["hops"], 2);

    let ledger_path = dir.path().join("mixed.sqlite");
    let check_out = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "check",
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--chain",
            root_signed_path.to_str().unwrap(),
            child_signed_path.to_str().unwrap(),
            "--actor-key",
            &worker_kp.key_id().to_string(),
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "feedback-loop-ai/handfest",
            "--now",
            "2026-11-24T18:30:00Z",
        ])
        .output()
        .unwrap();
    assert!(
        check_out.status.success(),
        "mixed chain check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&check_out.stdout),
        String::from_utf8_lossy(&check_out.stderr)
    );
}

#[test]
fn cli_sign_fido2_flag_conflicts_and_bad_credential_json() {
    let dir = TempDir::new().unwrap();
    let mandate_path = dir.path().join("m.handfest");
    let kp = Ed25519Keypair::from_secret_bytes([0xa1; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0xa2; 32]);
    let raw = format!(
        "HANDFEST v1\nFROM human \"v\" (key: {})\nTO agent \"a\" (key: {})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n",
        kp.key_id(),
        agent.key_id(),
    );
    fs::write(&mandate_path, &raw).unwrap();

    let key_path = dir.path().join("k.json");
    fs::write(&key_path, serde_json::to_string(&kp.to_key_file()).unwrap()).unwrap();
    let cred_path = dir.path().join("c.json");
    fs::write(
        &cred_path,
        r#"{"rp_id":"handfest.local","credential_id_b64":"AQID","key_id":"fido2-ed25519:00","extra":true}"#,
    )
    .unwrap();

    let both = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(!both.status.success());
    let both_err = String::from_utf8_lossy(&both.stderr);
    assert!(both_err.contains("--key") && both_err.contains("--fido2-cred"));

    let neither = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(!neither.status.success());

    let bad_dev_flag = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--fido2-device",
            "/dev/hidraw0",
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(!bad_dev_flag.status.success());

    let bad_json = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(!bad_json.status.success());
    assert!(
        String::from_utf8_lossy(&bad_json.stderr).contains("invalid FIDO2 credential file JSON")
    );
}

#[test]
fn cli_sign_fido2_rejects_mismatched_mandate_signer() {
    let dir = TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0xa3; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([0xa4; 32]);
    let raw = format!(
        "HANDFEST v1\nFROM human \"v\" (key: {})\nTO agent \"a\" (key: {})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n",
        kp.key_id(),
        agent.key_id(),
    );
    let mandate_path = dir.path().join("m.handfest");
    fs::write(&mandate_path, &raw).unwrap();

    let fido2_key = format_fido2_ed25519_key_id(&kp.public_key_bytes()).unwrap();
    let cred_path = dir.path().join("valid.fido2.json");
    let cred = Fido2CredentialFile {
        rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
        credential_id_b64: b64_encode(b"mismatch-cred"),
        key_id: fido2_key.to_string(),
    };
    fs::write(&cred_path, serde_json::to_string_pretty(&cred).unwrap()).unwrap();

    let mismatch = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--fido2-cred",
            cred_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("failed to sign mandate"));
}
