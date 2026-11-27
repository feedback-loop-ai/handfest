use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use handfest_anchors::{
    format_fido2_ed25519_key_id, openpgp_ed25519_key_id, piv_ed25519_key_id, Ed25519Keypair,
    Fido2CredentialFile, DEFAULT_FIDO2_RP_ID, ED25519_SPKI_DER_PREFIX, SSH_SK_ED25519_SCHEME,
    SSH_SK_ED25519_SSH_TYPE,
};
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;

const ED25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    schema: String,
    principal_name: String,
    principal_key_id: String,
    signer_kind: String,
    signer_hint: String,
    agent_name: String,
    agent_key_id: String,
    mandates_dir: String,
    ledger_path: String,
    policy_map_path: String,
}

fn handfest_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_handfest"))
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn encode_b64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
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

fn write_ssh_sk_fixture(dir: &Path, kp: &Ed25519Keypair) -> (PathBuf, PathBuf, String) {
    let mut blob = Vec::new();
    for field in [
        SSH_SK_ED25519_SSH_TYPE.as_bytes(),
        kp.public_key_bytes().as_slice(),
        b"ssh:",
    ] {
        blob.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(field);
    }
    let handle = dir.join("id_ed25519_sk");
    let pub_path = dir.join("id_ed25519_sk.pub");
    fs::write(
        &handle,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nMUST-NOT-BE-READ\n",
    )
    .unwrap();
    fs::write(
        &pub_path,
        format!(
            "{SSH_SK_ED25519_SSH_TYPE} {} yk@handfest\n",
            encode_b64(&blob)
        ),
    )
    .unwrap();
    let expected = format!(
        "{SSH_SK_ED25519_SCHEME}:{}",
        hex::encode(kp.public_key_bytes())
    );
    (handle, pub_path, expected)
}

fn write_fido2_fixture(dir: &Path, kp: &Ed25519Keypair) -> (PathBuf, String) {
    let key_id = format_fido2_ed25519_key_id(&kp.public_key_bytes()).unwrap();
    let cred_path = dir.join("yubikey.fido2.json");
    let cred = Fido2CredentialFile {
        rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
        credential_id_b64: "AQIDBA==".to_string(),
        key_id: key_id.to_string(),
    };
    fs::write(&cred_path, serde_json::to_string_pretty(&cred).unwrap()).unwrap();
    (cred_path, key_id.to_string())
}

fn write_piv_fixture(dir: &Path, kp: &Ed25519Keypair) -> (PathBuf, String) {
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&ED25519_SPKI_DER_PREFIX);
    der.extend_from_slice(&kp.public_key_bytes());
    let pem_path = dir.join("yubikey-9c.pem");
    fs::write(
        &pem_path,
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            encode_b64(&der)
        ),
    )
    .unwrap();
    let expected = piv_ed25519_key_id(&kp.public_key_bytes()).to_string();
    (pem_path, expected)
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for block in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc_u32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(unix)]
fn write_fake_gpg_fixture(dir: &Path, kp: &Ed25519Keypair) -> (PathBuf, String, String) {
    use std::os::unix::fs::PermissionsExt;

    let mut body = Vec::with_capacity(51);
    body.push(4);
    body.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    body.push(22);
    body.push(u8::try_from(ED25519_OID.len()).unwrap());
    body.extend_from_slice(ED25519_OID);
    body.extend_from_slice(&263u16.to_be_bytes());
    body.push(0x40);
    body.extend_from_slice(&kp.public_key_bytes());

    let mut preimage = Vec::with_capacity(3 + body.len());
    preimage.push(0x99);
    preimage.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    preimage.extend_from_slice(&body);
    let fpr = hex::encode_upper(sha1_digest(&preimage));

    let mut pkt = Vec::with_capacity(2 + body.len());
    pkt.push(0xc0 | 6);
    pkt.push(u8::try_from(body.len()).unwrap());
    pkt.extend_from_slice(&body);

    let bin_dir = dir.join("fake-bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let pkt_path = dir.join("exported-pub.pgp");
    fs::write(&pkt_path, &pkt).unwrap();

    let gpg_script = bin_dir.join("gpg");
    fs::write(
        &gpg_script,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--batch\" ] && [ \"$2\" = \"--export\" ] && [ \"$3\" = \"{fpr}\" ]; then\n  cat \"{}\"\n  exit 0\nfi\necho \"unexpected gpg args: $*\" >&2\nexit 1\n",
            pkt_path.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&gpg_script, fs::Permissions::from_mode(0o755)).unwrap();

    let expected = openpgp_ed25519_key_id(&kp.public_key_bytes()).to_string();
    (bin_dir, fpr, expected)
}

fn run_ok(cmd: &mut Command) -> String {
    let out: Output = cmd.output().expect("spawn handfest");
    assert!(
        out.status.success(),
        "expected success, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

#[test]
fn cli_keyid_supports_all_five_interfaces_and_rejects_conflicts() {
    let tmp = TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x51; 32]);

    // 1. --key
    let key_path = tmp.path().join("human.key.json");
    fs::write(
        &key_path,
        serde_json::to_string_pretty(&kp.to_key_file()).unwrap(),
    )
    .unwrap();
    let out_key = run_ok(handfest_bin().args(["keyid", "--key", path_str(&key_path)]));
    assert_eq!(out_key.trim(), kp.key_id().to_string());

    // 2. --ssh-key (both .pub and handle without reading private key)
    let (ssh_handle, ssh_pub, expected_ssh) = write_ssh_sk_fixture(tmp.path(), &kp);
    let out_ssh_pub = run_ok(handfest_bin().args(["keyid", "--ssh-key", path_str(&ssh_pub)]));
    assert_eq!(out_ssh_pub.trim(), expected_ssh);
    let out_ssh_handle = run_ok(handfest_bin().args(["keyid", "--ssh-key", path_str(&ssh_handle)]));
    assert_eq!(out_ssh_handle.trim(), expected_ssh);

    // 3. --fido2-cred
    let (fido2_path, expected_fido2) = write_fido2_fixture(tmp.path(), &kp);
    let out_fido2 = run_ok(handfest_bin().args(["keyid", "--fido2-cred", path_str(&fido2_path)]));
    assert_eq!(out_fido2.trim(), expected_fido2);

    // 4. --piv-pubkey
    let (piv_path, expected_piv) = write_piv_fixture(tmp.path(), &kp);
    let out_piv = run_ok(handfest_bin().args(["keyid", "--piv-pubkey", path_str(&piv_path)]));
    assert_eq!(out_piv.trim(), expected_piv);

    // 5. --gpg-key (via fake gpg on PATH)
    #[cfg(unix)]
    {
        let (fake_bin, fpr, expected_pgp) = write_fake_gpg_fixture(tmp.path(), &kp);
        let path_env = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out_pgp =
            run_ok(
                handfest_bin()
                    .env("PATH", &path_env)
                    .args(["keyid", "--gpg-key", &fpr]),
            );
        assert_eq!(out_pgp.trim(), expected_pgp);
    }

    // Missing flag fails closed.
    let missing = handfest_bin().args(["keyid"]).output().unwrap();
    assert!(!missing.status.success());

    // Conflicting flags fail closed.
    let conflict = handfest_bin()
        .args([
            "keyid",
            "--key",
            path_str(&key_path),
            "--piv-pubkey",
            path_str(&piv_path),
        ])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("cannot be used with"));
}

fn write_signed_limit1_mandate(
    cfg_dir: &Path,
    human_key_path: &Path,
    principal_key_id: &str,
    agent_key_id: &str,
) -> PathBuf {
    let mandate_path = cfg_dir.join("mandates/draft.hf");
    fs::write(
        &mandate_path,
        format!(
            "HANDFEST v1\nFROM human \"Valentin\" (key: {principal_key_id})\nTO agent \"coder\" (key: {agent_key_id})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"handfest\"\nLIMIT 1 calls\n",
        ),
    )
    .unwrap();
    let signed_path = cfg_dir.join("mandates/root.signed.json");
    let _ = run_ok(handfest_bin().args([
        "sign",
        "--mandate",
        path_str(&mandate_path),
        "--key",
        path_str(human_key_path),
        "--valid-from",
        "2026-11-24T17:00:00Z",
        "--valid-until",
        "2026-11-25T17:00:00Z",
        "--out",
        path_str(&signed_path),
    ]));
    signed_path
}

fn run_check_once(ledger_path: &Path, signed_path: &Path, agent_key_id: &str, now: &str) -> Output {
    handfest_bin()
        .args([
            "check",
            "--ledger",
            path_str(ledger_path),
            "--require-existing-ledger",
            "--chain",
            path_str(signed_path),
            "--actor-key",
            agent_key_id,
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "handfest",
            "--now",
            now,
        ])
        .output()
        .expect("spawn handfest check")
}

#[test]
fn cli_init_bootstrap_permissions_and_public_only_profile() {
    let tmp = TempDir::new().unwrap();
    let human_kp = Ed25519Keypair::from_secret_bytes([0x61; 32]);
    let human_key_file = human_kp.to_key_file();
    let human_key_path = tmp.path().join("human.key.json");
    fs::write(
        &human_key_path,
        serde_json::to_string_pretty(&human_key_file).unwrap(),
    )
    .unwrap();

    let cfg_dir = tmp.path().join("handfest-home");
    let stdout = run_ok(handfest_bin().args([
        "init",
        "--dir",
        path_str(&cfg_dir),
        "--principal-name",
        "Valentin",
        "--agent-name",
        "coder",
        "--key",
        path_str(&human_key_path),
    ]));
    let summary: Value = serde_json::from_str(&stdout).expect("valid summary JSON");
    assert_eq!(summary["status"], "initialized");
    assert_eq!(summary["agent_key_created"], true);
    assert_eq!(summary["ledger_created"], true);
    assert_eq!(summary["signer_kind"], "local-ed25519");
    assert!(summary["next_step_sign_command"]
        .as_str()
        .unwrap()
        .contains("--key "));

    for sub in ["mandates", "state", "hooks", "templates"] {
        assert!(cfg_dir.join(sub).is_dir(), "missing subdir {sub}");
    }
    let agent_key_path = cfg_dir.join("agent.key.json");
    let profile_path = cfg_dir.join("profile.json");
    let ledger_path = cfg_dir.join("state/handfest-ledger.sqlite");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&cfg_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&agent_key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&profile_path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    let profile_raw = fs::read_to_string(&profile_path).unwrap();
    let agent_key_json: Value =
        serde_json::from_str(&fs::read_to_string(&agent_key_path).unwrap()).unwrap();
    let agent_secret_hex = agent_key_json["secret_key_hex"].as_str().unwrap();
    assert!(!profile_raw.contains(&human_key_file.secret_key_hex));
    assert!(!profile_raw.contains(agent_secret_hex));
    assert!(!profile_raw.contains("secret_key_hex"));

    let profile: ProfileFile = serde_json::from_str(&profile_raw).expect("strict profile schema");
    assert_eq!(profile.schema, "handfest.profile/v1");
    assert_eq!(profile.principal_name, "Valentin");
    assert_eq!(profile.principal_key_id, human_kp.key_id().to_string());
    assert_eq!(profile.signer_kind, "local-ed25519");
    assert_eq!(profile.signer_hint, path_str(&human_key_path));
    assert_eq!(profile.agent_name, "coder");
    assert_eq!(
        profile.agent_key_id,
        summary["agent_key_id"].as_str().unwrap()
    );
    assert_eq!(profile.mandates_dir, path_str(&cfg_dir.join("mandates")));
    assert_eq!(profile.ledger_path, path_str(&ledger_path));
    assert_eq!(
        profile.policy_map_path,
        path_str(&cfg_dir.join("policy-map.json"))
    );

    let audit_out = run_ok(handfest_bin().args(["audit", "--ledger", path_str(&ledger_path)]));
    let audit_json: Value = serde_json::from_str(&audit_out).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 0);
}

#[test]
fn cli_init_rerun_is_idempotent_and_preserves_agent_key_and_consumed_quotas() {
    let tmp = TempDir::new().unwrap();
    let human_kp = Ed25519Keypair::from_secret_bytes([0x62; 32]);
    let human_key_path = tmp.path().join("human.key.json");
    fs::write(
        &human_key_path,
        serde_json::to_string_pretty(&human_kp.to_key_file()).unwrap(),
    )
    .unwrap();

    let cfg_dir = tmp.path().join("handfest-home");
    let out1 = run_ok(handfest_bin().args([
        "init",
        "--dir",
        path_str(&cfg_dir),
        "--principal-name",
        "Valentin",
        "--agent-name",
        "coder",
        "--key",
        path_str(&human_key_path),
    ]));
    let s1: Value = serde_json::from_str(&out1).unwrap();
    let agent_key_id = s1["agent_key_id"].as_str().unwrap().to_string();
    let agent_key_path = cfg_dir.join("agent.key.json");
    let agent_key_raw = fs::read_to_string(&agent_key_path).unwrap();
    let ledger_path = cfg_dir.join("state/handfest-ledger.sqlite");

    let signed_path = write_signed_limit1_mandate(
        &cfg_dir,
        &human_key_path,
        &human_kp.key_id().to_string(),
        &agent_key_id,
    );
    let permit = run_check_once(
        &ledger_path,
        &signed_path,
        &agent_key_id,
        "2026-11-24T18:00:00Z",
    );
    assert!(permit.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&permit.stdout).unwrap()["verdict"],
        "permit"
    );

    // Re-run `handfest init`: must preserve agent.key.json AND consumed quota!
    let out2 = run_ok(handfest_bin().args([
        "init",
        "--dir",
        path_str(&cfg_dir),
        "--principal-name",
        "Valentin",
        "--agent-name",
        "coder",
        "--key",
        path_str(&human_key_path),
    ]));
    let s2: Value = serde_json::from_str(&out2).unwrap();
    assert_eq!(s2["agent_key_created"], false);
    assert_eq!(s2["ledger_created"], false);
    assert_eq!(s2["agent_key_id"], s1["agent_key_id"]);
    assert_eq!(fs::read_to_string(&agent_key_path).unwrap(), agent_key_raw);

    let deny = run_check_once(
        &ledger_path,
        &signed_path,
        &agent_key_id,
        "2026-11-24T18:01:00Z",
    );
    assert!(!deny.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&deny.stdout).unwrap()["verdict"],
        "deny"
    );
}

#[test]
fn cli_init_supports_ssh_sk_fido2_piv_and_reuses_explicit_agent_key() {
    let tmp = TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x72; 32]);
    let reused_agent_kp = Ed25519Keypair::from_secret_bytes([0x73; 32]);
    let reused_agent_path = tmp.path().join("external-agent.key.json");
    fs::write(
        &reused_agent_path,
        serde_json::to_string_pretty(&reused_agent_kp.to_key_file()).unwrap(),
    )
    .unwrap();

    // 1. --ssh-key + --agent-key reuse
    let (_, ssh_pub, expected_ssh) = write_ssh_sk_fixture(tmp.path(), &kp);
    let dir_ssh = tmp.path().join("init-ssh");
    let out_ssh = run_ok(handfest_bin().args([
        "init",
        "--dir",
        path_str(&dir_ssh),
        "--principal-name",
        "Valentin",
        "--agent-key",
        path_str(&reused_agent_path),
        "--ssh-key",
        path_str(&ssh_pub),
    ]));
    let s_ssh: Value = serde_json::from_str(&out_ssh).unwrap();
    assert_eq!(s_ssh["signer_kind"], "ssh-sk");
    assert_eq!(s_ssh["principal_key_id"], expected_ssh);
    assert_eq!(s_ssh["agent_key_id"], reused_agent_kp.key_id().to_string());
    assert_eq!(s_ssh["agent_key_created"], false);
    assert_eq!(s_ssh["agent_name"], "agent");
    assert!(!dir_ssh.join("agent.key.json").exists());
    assert!(s_ssh["next_step_sign_command"]
        .as_str()
        .unwrap()
        .contains("--ssh-key "));

    // 2. --fido2-cred
    let (fido2_path, expected_fido2) = write_fido2_fixture(tmp.path(), &kp);
    let dir_fido2 = tmp.path().join("init-fido2");
    let out_fido2 = run_ok(handfest_bin().args([
        "init",
        "--dir",
        path_str(&dir_fido2),
        "--principal-name",
        "Valentin",
        "--fido2-cred",
        path_str(&fido2_path),
    ]));
    let s_fido2: Value = serde_json::from_str(&out_fido2).unwrap();
    assert_eq!(s_fido2["signer_kind"], "fido2");
    assert_eq!(s_fido2["principal_key_id"], expected_fido2);
    assert!(s_fido2["next_step_sign_command"]
        .as_str()
        .unwrap()
        .contains("--fido2-cred "));

    // 3. --piv-pubkey
    let (piv_path, expected_piv) = write_piv_fixture(tmp.path(), &kp);
    let dir_piv = tmp.path().join("init-piv");
    let out_piv = run_ok(handfest_bin().args([
        "init",
        "--dir",
        path_str(&dir_piv),
        "--principal-name",
        "Valentin",
        "--piv-pubkey",
        path_str(&piv_path),
    ]));
    let s_piv: Value = serde_json::from_str(&out_piv).unwrap();
    assert_eq!(s_piv["signer_kind"], "piv");
    assert_eq!(s_piv["principal_key_id"], expected_piv);
    assert!(s_piv["next_step_sign_command"]
        .as_str()
        .unwrap()
        .contains("--piv-pubkey "));
}

#[test]
fn cli_init_supports_openpgp_default_home_and_enforces_git_worktree_guard() {
    let tmp = TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x74; 32]);
    let (piv_path, _) = write_piv_fixture(tmp.path(), &kp);

    #[cfg(unix)]
    {
        let (fake_bin, fpr, expected_pgp) = write_fake_gpg_fixture(tmp.path(), &kp);
        let fake_home = tmp.path().join("fake-home");
        fs::create_dir_all(&fake_home).unwrap();
        let path_env = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out_pgp = run_ok(
            handfest_bin()
                .env("PATH", &path_env)
                .env("HOME", &fake_home)
                .env_remove("HANDFEST_HOME")
                .args(["init", "--principal-name", "Valentin", "--gpg-key", &fpr]),
        );
        let s_pgp: Value = serde_json::from_str(&out_pgp).unwrap();
        assert_eq!(s_pgp["signer_kind"], "openpgp");
        assert_eq!(s_pgp["principal_key_id"], expected_pgp);
        assert_eq!(s_pgp["dir"], path_str(&fake_home.join(".handfest")));
        assert!(s_pgp["next_step_sign_command"]
            .as_str()
            .unwrap()
            .contains("--gpg-key "));
    }

    let fake_repo = tmp.path().join("fake-repo");
    fs::create_dir_all(fake_repo.join(".git")).unwrap();
    let in_repo_dir = fake_repo.join("handfest-cfg");
    let rejected = handfest_bin()
        .args([
            "init",
            "--dir",
            path_str(&in_repo_dir),
            "--principal-name",
            "Valentin",
            "--piv-pubkey",
            path_str(&piv_path),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("inside git working tree"));
    assert!(!in_repo_dir.exists());

    let allowed = run_ok(handfest_bin().args([
        "init",
        "--dir",
        path_str(&in_repo_dir),
        "--allow-in-repo",
        "--principal-name",
        "Valentin",
        "--piv-pubkey",
        path_str(&piv_path),
    ]));
    assert_eq!(
        serde_json::from_str::<Value>(&allowed).unwrap()["status"],
        "initialized"
    );
}
