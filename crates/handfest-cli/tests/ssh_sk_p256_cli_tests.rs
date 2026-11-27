//! End-to-end offline CLI integration tests for YubiKey Slice 5 (`sk-ecdsa-sha2-nistp256@openssh.com`
//! / `ssh-sk-p256:`): `keyid`, `init`, `sign`, `verify`, `check`, `revoke`, and `audit`.

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

// RFC 6979 Appendix A.2.5 NIST P-256 test key (`ssh:handfest` application).
const P256_KEY_ID: &str = "ssh-sk-p256:0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const P256_PUB_LINE: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpkAAAAMc3NoOmhhbmRmZXN0 yubikey-p256@test\n";
const MANDATE_SSHSIG_B64: &str = "U1NIU0lHAAAAAQAAAIcAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBvcGVuc3NoLmNvbQAAAAhuaXN0cDI1NgAAAEEEYP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Z5A/4QCLi8maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQAAAAxzc2g6aGFuZGZlc3QAAAAUaGFuZGZlc3QtdjEtZW52ZWxvcGUAAAAAAAAABnNoYTUxMgAAAHgAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBvcGVuc3NoLmNvbQAAAEkAAAAgAhfmF/C2RDkoJ4+WmZ5pojpPLBUr321s32bluAKC1O0AAAAhAMigBlpdCEGRgUq9eytWWtm42mC1ILJujs+uJuJDqHy8AQAAABE=";
const REVOCATION_SSHSIG_B64: &str = "U1NIU0lHAAAAAQAAAIcAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBvcGVuc3NoLmNvbQAAAAhuaXN0cDI1NgAAAEEEYP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Z5A/4QCLi8maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQAAAAxzc2g6aGFuZGZlc3QAAAASaGFuZGZlc3QtdjEtcmV2b2tlAAAAAAAAAAZzaGE1MTIAAAB5AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAABKAAAAIQDWWpOXfKo9GwgYUv9Xp55GXxZgV3MEuurVBd06SFic8wAAACEA8ivOq8+6eeCL8ZlcWvRvaPeebL4QdsBqi4kCyPqXXogFAAAAEg==";

fn wrap_pem(b64: &str) -> String {
    format!("-----BEGIN SSH SIGNATURE-----\n{b64}\n-----END SSH SIGNATURE-----\n")
}

fn run_handfest_ok(args: &[&str], path_env: Option<&str>) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_handfest"));
    cmd.args(args);
    if let Some(p) = path_env {
        cmd.env("PATH", p);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "handfest {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[cfg(unix)]
fn install_dual_ns_fake_ssh_keygen(
    dir: &Path,
    expected_key_path: &Path,
    mandate_pem: &str,
    revocation_pem: &str,
) -> String {
    use std::os::unix::fs::PermissionsExt;

    let mandate_pem_path = dir.join("mandate.sig");
    let rev_pem_path = dir.join("revocation.sig");
    fs::write(&mandate_pem_path, mandate_pem).unwrap();
    fs::write(&rev_pem_path, revocation_pem).unwrap();

    let bin_dir = dir.join("bin");
    fs::create_dir(&bin_dir).unwrap();
    let fake_bin = bin_dir.join("ssh-keygen");
    let sh_quote =
        |p: &Path| -> String { format!("'{}'", p.display().to_string().replace('\'', "'\\''")) };
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         if [ \"$1\" != '-Y' ] || [ \"$2\" != 'sign' ] || [ \"$3\" != '-f' ] || [ \"$4\" != {key} ] || [ \"$5\" != '-n' ]; then\n\
           echo \"unexpected args: $*\" >&2\n\
           exit 42\n\
         fi\n\
         cat >/dev/null\n\
         if [ \"$6\" = 'handfest-v1-envelope' ]; then\n\
           cat {mpem}\n\
         elif [ \"$6\" = 'handfest-v1-revoke' ]; then\n\
           cat {rpem}\n\
         else\n\
           echo \"unexpected namespace: $6\" >&2\n\
           exit 43\n\
         fi\n",
        key = sh_quote(expected_key_path),
        mpem = sh_quote(&mandate_pem_path),
        rpem = sh_quote(&rev_pem_path),
    );
    fs::write(&fake_bin, script).unwrap();
    fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o755)).unwrap();

    format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

#[test]
fn cli_keyid_and_init_support_ssh_sk_p256_via_pub_and_companion_handle() {
    let dir = TempDir::new().unwrap();
    let handle_path = dir.path().join("id_ecdsa_sk");
    let pub_path = dir.path().join("id_ecdsa_sk.pub");
    fs::write(&handle_path, "dummy-handle-never-read").unwrap();
    fs::write(&pub_path, P256_PUB_LINE).unwrap();

    // 1. `handfest keyid --ssh-key` works for both `.pub` and companion handle.
    let from_pub = run_handfest_ok(&["keyid", "--ssh-key", pub_path.to_str().unwrap()], None);
    assert_eq!(from_pub.trim(), P256_KEY_ID);
    let from_handle = run_handfest_ok(&["keyid", "--ssh-key", handle_path.to_str().unwrap()], None);
    assert_eq!(from_handle.trim(), P256_KEY_ID);

    // 2. `handfest init --ssh-key` records signer_kind: "ssh-sk" and ssh-sk-p256 KeyId.
    let home_dir = dir.path().join("handfest-home");
    let init_stdout = run_handfest_ok(
        &[
            "init",
            "--dir",
            home_dir.to_str().unwrap(),
            "--principal-name",
            "Valentin",
            "--ssh-key",
            pub_path.to_str().unwrap(),
        ],
        None,
    );
    let init_json: serde_json::Value = serde_json::from_str(&init_stdout).unwrap();
    assert_eq!(init_json["status"], "initialized");
    assert_eq!(init_json["signer_kind"], "ssh-sk");
    assert_eq!(init_json["principal_key_id"], P256_KEY_ID);

    let profile: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home_dir.join("profile.json")).unwrap()).unwrap();
    assert_eq!(profile["signer_kind"], "ssh-sk");
    assert_eq!(profile["principal_key_id"], P256_KEY_ID);
}

#[cfg(unix)]
#[test]
fn cli_ssh_sk_p256_end_to_end_sign_verify_check_revoke_and_audit() {
    let dir = TempDir::new().unwrap();
    let pub_path = dir.path().join("id_ecdsa_sk.pub");
    fs::write(&pub_path, P256_PUB_LINE).unwrap();

    let agent_key_id = format!("ed25519:{}", "b".repeat(64));
    let mandate_raw = format!(
        "HANDFEST v1\n\
         FROM human \"Valentin\" (key: {P256_KEY_ID})\n\
         TO agent \"Claude\" (key: {agent_key_id})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"feedback-loop-ai/handfest\"\n\
         WHERE context.time >= 2026-11-24T17:00:00Z\n\
           AND context.time < 2026-11-25T01:00:00Z\n\
           AND resource.author == \"valentin\"\n\
         LIMIT 2 calls\n"
    );
    let mandate_path = dir.path().join("p256_root.hf");
    fs::write(&mandate_path, &mandate_raw).unwrap();

    let path_env = install_dual_ns_fake_ssh_keygen(
        dir.path(),
        &pub_path,
        &wrap_pem(MANDATE_SSHSIG_B64),
        &wrap_pem(REVOCATION_SSHSIG_B64),
    );

    // 1. `handfest sign --ssh-key`
    let signed_path = dir.path().join("p256_root.signed.json");
    let _ = run_handfest_ok(
        &[
            "sign",
            "--mandate",
            mandate_path.to_str().unwrap(),
            "--ssh-key",
            pub_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
            "--out",
            signed_path.to_str().unwrap(),
        ],
        Some(&path_env),
    );
    let signed_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&signed_path).unwrap()).unwrap();
    assert_eq!(signed_json["anchor_id"], "yubikey-ssh-sk");
    assert_eq!(signed_json["assurance"], "passkey");
    assert_eq!(signed_json["signer_key"], P256_KEY_ID);

    // 2. `handfest verify` succeeds, and tampered signature fails closed.
    let verify_stdout = run_handfest_ok(&["verify", signed_path.to_str().unwrap()], None);
    let verify_json: serde_json::Value = serde_json::from_str(&verify_stdout).unwrap();
    assert_eq!(verify_json["status"], "verified");
    assert_eq!(verify_json["hops"], 1);

    let mut tampered = signed_json.clone();
    let mut sig_hex = tampered["signature_hex"].as_str().unwrap().to_string();
    let last = sig_hex.pop().unwrap();
    sig_hex.push(if last == '0' { '1' } else { '0' });
    tampered["signature_hex"] = serde_json::Value::String(sig_hex);
    let tampered_path = dir.path().join("tampered.signed.json");
    fs::write(
        &tampered_path,
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let tampered_out = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args(["verify", tampered_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!tampered_out.status.success());

    assert_check_revoke_and_audit(
        dir.path(),
        &pub_path,
        &signed_path,
        &agent_key_id,
        &path_env,
    );
}

#[cfg(unix)]
fn run_check_cmd(ledger: &Path, signed: &Path, actor: &str, now: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "check",
            "--ledger",
            ledger.to_str().unwrap(),
            "--chain",
            signed.to_str().unwrap(),
            "--actor-key",
            actor,
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "feedback-loop-ai/handfest",
            "--facts",
            r#"{"resource.author":"valentin"}"#,
            "--now",
            now,
        ])
        .output()
        .unwrap()
}

#[cfg(unix)]
fn assert_check_revoke_and_audit(
    dir: &Path,
    pub_path: &Path,
    signed_path: &Path,
    agent_key_id: &str,
    path_env: &str,
) {
    let ledger_path = dir.join("p256_ledger.sqlite");
    let before = run_check_cmd(
        &ledger_path,
        signed_path,
        agent_key_id,
        "2026-11-24T18:30:00Z",
    );
    assert!(before.status.success());
    let before_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8(before.stdout).unwrap()).unwrap();
    assert_eq!(before_json["verdict"], "permit");

    let rev_path = dir.join("p256_revoke.signed.json");
    let revoke_stdout = run_handfest_ok(
        &[
            "revoke",
            "--mandate",
            signed_path.to_str().unwrap(),
            "--effective",
            "2026-11-24T19:00:00Z",
            "--reason",
            "p256 compromised",
            "--ssh-key",
            pub_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--out",
            rev_path.to_str().unwrap(),
        ],
        Some(path_env),
    );
    let revoke_json: serde_json::Value = serde_json::from_str(&revoke_stdout).unwrap();
    assert_eq!(revoke_json["status"], "revoked");
    assert_eq!(revoke_json["recorded_in_ledger"], true);

    let verify_revoked = Command::new(env!("CARGO_BIN_EXE_handfest"))
        .args([
            "verify",
            signed_path.to_str().unwrap(),
            "--revocation",
            rev_path.to_str().unwrap(),
            "--now",
            "2026-11-24T19:30:00Z",
        ])
        .output()
        .unwrap();
    assert!(!verify_revoked.status.success());
    let verify_revoked_err = String::from_utf8(verify_revoked.stderr).unwrap();
    assert!(
        verify_revoked_err.contains("mandate chain revoked")
            && verify_revoked_err.contains("revoked by sha256:"),
        "expected revocation error in verify stderr, got: {verify_revoked_err}"
    );

    let after = run_check_cmd(
        &ledger_path,
        signed_path,
        agent_key_id,
        "2026-11-24T19:30:00Z",
    );
    assert!(!after.status.success());
    let after_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8(after.stdout).unwrap()).unwrap();
    assert_eq!(after_json["verdict"], "deny");
    let deny_reason = after_json["reason"].as_str().unwrap_or("");
    assert!(
        deny_reason.contains("revoked by sha256:"),
        "expected revocation reason in check deny JSON, got: {after_json}"
    );

    let audit_stdout = run_handfest_ok(
        &[
            "audit",
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--actor-key",
            agent_key_id,
        ],
        None,
    );
    let audit_json: serde_json::Value = serde_json::from_str(&audit_stdout).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 2);
    assert_eq!(audit_json["track_record"]["permits"], 1);
    assert_eq!(audit_json["track_record"]["denies"], 1);
}
