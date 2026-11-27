use super::*;
use handfest_anchors::{
    format_fido2_ed25519_key_id, openpgp_ed25519_key_id, DEFAULT_FIDO2_RP_ID,
    ED25519_SPKI_DER_PREFIX, SSH_SK_ED25519_SCHEME, SSH_SK_ED25519_SSH_TYPE,
};

const ED25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

struct StubExportRunner {
    stdout: Vec<u8>,
}

impl CommandRunner for StubExportRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        _stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        assert_eq!(program, "gpg");
        assert_eq!(args[0], "--batch");
        assert_eq!(args[1], "--export");
        Ok(CommandOutput {
            stdout: self.stdout.clone(),
            stderr: Vec::new(),
        })
    }
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

fn build_openpgp_pubkey_packet_and_fpr(pubkey: &[u8; 32]) -> (Vec<u8>, String) {
    let mut body = Vec::with_capacity(51);
    body.push(4);
    body.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    body.push(22);
    body.push(u8::try_from(ED25519_OID.len()).unwrap());
    body.extend_from_slice(ED25519_OID);
    body.extend_from_slice(&263u16.to_be_bytes());
    body.push(0x40);
    body.extend_from_slice(pubkey);

    let mut preimage = Vec::with_capacity(3 + body.len());
    preimage.push(0x99);
    preimage.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    preimage.extend_from_slice(&body);
    let fpr_hex = hex::encode_upper(sha1_for_test(&preimage));

    let mut pkt = Vec::with_capacity(2 + body.len());
    pkt.push(0xc0 | 6);
    pkt.push(u8::try_from(body.len()).unwrap());
    pkt.extend_from_slice(&body);
    (pkt, fpr_hex)
}

fn sha1_for_test(data: &[u8]) -> [u8; 20] {
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

#[test]
fn principal_key_args_into_source_and_signer_kind_flags() {
    assert_eq!(SignerKind::LocalEd25519.sign_flag(), "--key");
    assert_eq!(SignerKind::SshSk.sign_flag(), "--ssh-key");
    assert_eq!(SignerKind::Fido2.sign_flag(), "--fido2-cred");
    assert_eq!(SignerKind::OpenPgp.sign_flag(), "--gpg-key");
    assert_eq!(SignerKind::Piv.sign_flag(), "--piv-pubkey");

    let empty = PrincipalKeyArgs {
        key: None,
        ssh_key: None,
        fido2_cred: None,
        gpg_key: None,
        piv_pubkey: None,
    };
    assert!(empty.into_source().unwrap_err().contains("exactly one of"));

    let two = PrincipalKeyArgs {
        key: Some(PathBuf::from("a.json")),
        ssh_key: Some(PathBuf::from("b.pub")),
        fido2_cred: None,
        gpg_key: None,
        piv_pubkey: None,
    };
    assert!(two.into_source().unwrap_err().contains("exactly one of"));

    let noop_err = NoopCommandRunner.run("gpg", &[], &[]).unwrap_err();
    assert!(matches!(noop_err, AnchorError::CommandIo { .. }));
}

#[test]
fn resolve_principal_key_succeeds_for_all_five_interfaces() {
    let dir = tempfile::TempDir::new().unwrap();
    let kp = Ed25519Keypair::from_secret_bytes([0x31; 32]);

    // 1. Local Ed25519
    let key_path = dir.path().join("local.key.json");
    fs::write(
        &key_path,
        serde_json::to_string_pretty(&kp.to_key_file()).unwrap(),
    )
    .unwrap();
    let local = resolve_principal_key(&PrincipalKeySource::LocalEd25519(key_path.clone()))
        .expect("resolve local ed25519");
    assert_eq!(local.key_id, kp.key_id());
    assert_eq!(local.signer_kind, SignerKind::LocalEd25519);
    assert_eq!(local.signer_hint, key_path.to_str().unwrap());

    // 2. SSH-SK (via handle, never reading private key)
    let mut blob = Vec::new();
    for field in [
        SSH_SK_ED25519_SSH_TYPE.as_bytes(),
        kp.public_key_bytes().as_slice(),
        b"ssh:",
    ] {
        blob.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(field);
    }
    let handle = dir.path().join("id_ed25519_sk");
    let pub_path = dir.path().join("id_ed25519_sk.pub");
    fs::write(&handle, "UNREADABLE PRIVATE KEY").unwrap();
    fs::write(
        &pub_path,
        format!("{SSH_SK_ED25519_SSH_TYPE} {} yk@test\n", encode_b64(&blob)),
    )
    .unwrap();
    let ssh =
        resolve_principal_key(&PrincipalKeySource::SshSk(handle.clone())).expect("resolve ssh-sk");
    assert_eq!(
        ssh.key_id.to_string(),
        format!(
            "{SSH_SK_ED25519_SCHEME}:{}",
            hex::encode(kp.public_key_bytes())
        )
    );
    assert_eq!(ssh.signer_kind, SignerKind::SshSk);
    assert_eq!(ssh.signer_hint, handle.to_str().unwrap());

    // 3. FIDO2 credential file
    let fido2_id = format_fido2_ed25519_key_id(&kp.public_key_bytes()).unwrap();
    let cred_path = dir.path().join("yk.fido2.json");
    let cred = Fido2CredentialFile {
        rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
        credential_id_b64: "AQIDBA==".to_string(),
        key_id: fido2_id.to_string(),
    };
    fs::write(&cred_path, serde_json::to_string_pretty(&cred).unwrap()).unwrap();
    let fido2 = resolve_principal_key(&PrincipalKeySource::Fido2(cred_path.clone()))
        .expect("resolve fido2");
    assert_eq!(fido2.key_id, fido2_id);
    assert_eq!(fido2.signer_kind, SignerKind::Fido2);
    assert_eq!(fido2.signer_hint, cred_path.to_str().unwrap());

    // 4. OpenPGP via stubbed `gpg --export`
    let (pkt, fpr) = build_openpgp_pubkey_packet_and_fpr(&kp.public_key_bytes());
    let pgp = resolve_principal_key_with_runner(
        &PrincipalKeySource::OpenPgp(fpr.clone()),
        StubExportRunner { stdout: pkt },
    )
    .expect("resolve openpgp");
    assert_eq!(pgp.key_id, openpgp_ed25519_key_id(&kp.public_key_bytes()));
    assert_eq!(pgp.signer_kind, SignerKind::OpenPgp);
    assert_eq!(pgp.signer_hint, fpr);

    // 5. PIV SPKI PEM
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&ED25519_SPKI_DER_PREFIX);
    der.extend_from_slice(&kp.public_key_bytes());
    let pem_path = dir.path().join("yk-9c.pem");
    fs::write(
        &pem_path,
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            encode_b64(&der)
        ),
    )
    .unwrap();
    let piv =
        resolve_principal_key(&PrincipalKeySource::Piv(pem_path.clone())).expect("resolve piv");
    assert_eq!(piv.key_id, piv_ed25519_key_id(&kp.public_key_bytes()));
    assert_eq!(piv.signer_kind, SignerKind::Piv);
    assert_eq!(piv.signer_hint, pem_path.to_str().unwrap());
}

#[test]
fn resolve_principal_key_rejects_malformed_inputs_fail_closed() {
    let dir = tempfile::TempDir::new().unwrap();

    let missing = dir.path().join("missing");
    assert!(
        resolve_principal_key(&PrincipalKeySource::LocalEd25519(missing.clone()))
            .unwrap_err()
            .contains("failed to read")
    );
    assert!(
        resolve_principal_key(&PrincipalKeySource::Fido2(missing.clone()))
            .unwrap_err()
            .contains("failed to read")
    );
    assert!(resolve_principal_key(&PrincipalKeySource::Piv(missing))
        .unwrap_err()
        .contains("failed to read"));

    let bad_json = dir.path().join("bad.json");
    fs::write(&bad_json, "{").unwrap();
    assert!(
        resolve_principal_key(&PrincipalKeySource::LocalEd25519(bad_json.clone()))
            .unwrap_err()
            .contains("invalid key file JSON")
    );
    assert!(
        resolve_principal_key(&PrincipalKeySource::Fido2(bad_json.clone()))
            .unwrap_err()
            .contains("invalid FIDO2 credential file JSON")
    );

    let kp = Ed25519Keypair::from_secret_bytes([0x32; 32]);
    let mut mismatch = kp.to_key_file();
    mismatch.key_id = format!("ed25519:{}", "0".repeat(64));
    let mismatch_path = dir.path().join("mismatch.key.json");
    fs::write(&mismatch_path, serde_json::to_string(&mismatch).unwrap()).unwrap();
    assert!(
        resolve_principal_key(&PrincipalKeySource::LocalEd25519(mismatch_path))
            .unwrap_err()
            .contains("failed to load Ed25519 key")
    );

    let bad_fido2 = dir.path().join("bad.fido2.json");
    fs::write(
        &bad_fido2,
        serde_json::to_string(&Fido2CredentialFile {
            rp_id: String::new(),
            credential_id_b64: "AQID".to_string(),
            key_id: format_fido2_ed25519_key_id(&kp.public_key_bytes())
                .unwrap()
                .to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(resolve_principal_key(&PrincipalKeySource::Fido2(bad_fido2))
        .unwrap_err()
        .contains("failed to load FIDO2 credential"));

    let bad_pem = dir.path().join("bad.pem");
    fs::write(&bad_pem, "not a pem").unwrap();
    assert!(resolve_principal_key(&PrincipalKeySource::Piv(bad_pem))
        .unwrap_err()
        .contains("failed to load PIV Ed25519 public key"));

    assert!(resolve_principal_key_with_runner(
        &PrincipalKeySource::OpenPgp("not-hex".to_string()),
        NoopCommandRunner,
    )
    .unwrap_err()
    .contains("failed to load OpenPGP key"));
}

#[test]
fn resolve_principal_key_supports_ssh_sk_p256() {
    let dir = tempfile::TempDir::new().unwrap();
    let pub_line = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpkAAAAMc3NoOmhhbmRmZXN0 yubikey-p256@test\n";
    let handle = dir.path().join("id_ecdsa_sk");
    let pub_path = dir.path().join("id_ecdsa_sk.pub");
    fs::write(&handle, "dummy-handle").unwrap();
    fs::write(&pub_path, pub_line).unwrap();

    let resolved = resolve_principal_key(&PrincipalKeySource::SshSk(handle.clone()))
        .expect("resolve ssh-sk-p256");
    assert_eq!(
        resolved.key_id.to_string(),
        "ssh-sk-p256:0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    );
    assert_eq!(resolved.signer_kind, SignerKind::SshSk);
    assert_eq!(resolved.signer_hint, handle.to_str().unwrap());
}
