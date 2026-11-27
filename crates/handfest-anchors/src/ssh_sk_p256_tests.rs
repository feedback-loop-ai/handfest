use std::cell::RefCell;
use std::fs;

use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId, Scalar};
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::gate::{authorize, ActionRequest, QuotaSnapshot, VerifiedFacts};
use handfest_core::Verdict;
use sha2::{Digest, Sha256, Sha512};

use super::*;
use crate::p256::{test_public_key_from_secret, test_sign_prehash_with_nonce};
use crate::{
    sign_mandate_with, sign_revocation_with, verify_chain, verify_revocation, CommandOutput,
    Ed25519Keypair,
};
use handfest_core::base64::encode_standard;

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 timestamp")
}

fn push_ssh_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("len fits u32");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_mpint_positive(val: &[u8; 32]) -> Vec<u8> {
    let first_nonzero = val.iter().position(|&b| b != 0).unwrap_or(val.len());
    let trimmed = &val[first_nonzero..];
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(trimmed.len() + 1);
    if (trimmed[0] & 0x80) != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

fn build_p256_pubkey_blob(key_type: &str, curve: &str, sec1: &[u8], application: &str) -> Vec<u8> {
    let mut blob = Vec::new();
    push_ssh_bytes(&mut blob, key_type.as_bytes());
    push_ssh_bytes(&mut blob, curve.as_bytes());
    push_ssh_bytes(&mut blob, sec1);
    push_ssh_bytes(&mut blob, application.as_bytes());
    blob
}

fn format_openssh_p256_pub(secret: &[u8; 32], application: &str, comment: Option<&str>) -> String {
    let sec1 = test_public_key_from_secret(secret);
    let blob = build_p256_pubkey_blob(
        SSH_SK_P256_SSH_TYPE,
        SSH_SK_P256_CURVE_NAME,
        &sec1,
        application,
    );
    let b64 = encode_standard(&blob);
    match comment {
        Some(c) => format!("{SSH_SK_P256_SSH_TYPE} {b64} {c}\n"),
        None => format!("{SSH_SK_P256_SSH_TYPE} {b64}\n"),
    }
}

struct P256SshSigSpec<'a> {
    magic: &'a [u8],
    version: u32,
    pk_blob: Vec<u8>,
    namespace: &'a str,
    reserved: &'a [u8],
    hash_alg: &'a str,
    sig_type: &'a str,
    flags: u8,
    counter: u32,
    application_for_signing: &'a str,
    nonce: [u8; 32],
    inner_trailing: &'a [u8],
    sig_trailing: &'a [u8],
    top_trailing: &'a [u8],
    r_mpint_override: Option<Vec<u8>>,
    s_mpint_override: Option<Vec<u8>>,
}

impl<'a> P256SshSigSpec<'a> {
    fn valid(secret: &[u8; 32], application: &'a str, namespace: &'a str) -> Self {
        let sec1 = test_public_key_from_secret(secret);
        Self {
            magic: b"SSHSIG",
            version: 1,
            pk_blob: build_p256_pubkey_blob(
                SSH_SK_P256_SSH_TYPE,
                SSH_SK_P256_CURVE_NAME,
                &sec1,
                application,
            ),
            namespace,
            reserved: b"",
            hash_alg: "sha512",
            sig_type: SSH_SK_P256_SSH_TYPE,
            flags: 0x01,
            counter: 42,
            application_for_signing: application,
            nonce: [0x23; 32],
            inner_trailing: b"",
            sig_trailing: b"",
            top_trailing: b"",
            r_mpint_override: None,
            s_mpint_override: None,
        }
    }
}

fn sign_sk_p256_sshsig(secret: &[u8; 32], payload: &[u8], spec: &P256SshSigSpec<'_>) -> Vec<u8> {
    let payload_sha512 = Sha512::digest(payload);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"SSHSIG");
    push_ssh_bytes(&mut preimage, spec.namespace.as_bytes());
    push_ssh_bytes(&mut preimage, spec.reserved);
    push_ssh_bytes(&mut preimage, spec.hash_alg.as_bytes());
    push_ssh_bytes(&mut preimage, &payload_sha512);

    let mut sk_signed = [0u8; 69];
    sk_signed[0..32].copy_from_slice(&Sha256::digest(spec.application_for_signing.as_bytes()));
    sk_signed[32] = spec.flags;
    sk_signed[33..37].copy_from_slice(&spec.counter.to_be_bytes());
    sk_signed[37..69].copy_from_slice(&Sha256::digest(&preimage));
    let digest: [u8; 32] = Sha256::digest(sk_signed).into();

    let (r, s) = test_sign_prehash_with_nonce(secret, &spec.nonce, &digest);
    let r_mpint = spec
        .r_mpint_override
        .clone()
        .unwrap_or_else(|| encode_mpint_positive(&r));
    let s_mpint = spec
        .s_mpint_override
        .clone()
        .unwrap_or_else(|| encode_mpint_positive(&s));

    let mut inner_sig = Vec::new();
    push_ssh_bytes(&mut inner_sig, &r_mpint);
    push_ssh_bytes(&mut inner_sig, &s_mpint);
    inner_sig.extend_from_slice(spec.inner_trailing);

    let mut sig_blob = Vec::new();
    push_ssh_bytes(&mut sig_blob, spec.sig_type.as_bytes());
    push_ssh_bytes(&mut sig_blob, &inner_sig);
    sig_blob.push(spec.flags);
    sig_blob.extend_from_slice(&spec.counter.to_be_bytes());
    sig_blob.extend_from_slice(spec.sig_trailing);

    let mut sshsig = Vec::new();
    sshsig.extend_from_slice(spec.magic);
    sshsig.extend_from_slice(&spec.version.to_be_bytes());
    push_ssh_bytes(&mut sshsig, &spec.pk_blob);
    push_ssh_bytes(&mut sshsig, spec.namespace.as_bytes());
    push_ssh_bytes(&mut sshsig, spec.reserved);
    push_ssh_bytes(&mut sshsig, spec.hash_alg.as_bytes());
    push_ssh_bytes(&mut sshsig, &sig_blob);
    sshsig.extend_from_slice(spec.top_trailing);
    sshsig
}

fn wrap_sshsig_pem(raw: &[u8]) -> Vec<u8> {
    let b64 = encode_standard(raw);
    let mut pem = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).expect("ascii b64"));
        pem.push('\n');
    }
    pem.push_str("-----END SSH SIGNATURE-----\n");
    pem.into_bytes()
}

struct RecordedCall {
    program: String,
    args: Vec<String>,
    stdin: Vec<u8>,
}

struct FakeP256Runner {
    secret: [u8; 32],
    application: String,
    flags: u8,
    calls: RefCell<Vec<RecordedCall>>,
}

impl FakeP256Runner {
    fn new(secret: [u8; 32], application: &str) -> Self {
        Self {
            secret,
            application: application.to_string(),
            flags: 0x01,
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl CommandRunner for &FakeP256Runner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        self.calls.borrow_mut().push(RecordedCall {
            program: program.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            stdin: stdin.to_vec(),
        });
        let ns = args.get(5).copied().unwrap_or(SSHSIG_NAMESPACE);
        let mut spec = P256SshSigSpec::valid(&self.secret, &self.application, ns);
        spec.flags = self.flags;
        let raw = sign_sk_p256_sshsig(&self.secret, stdin, &spec);
        Ok(CommandOutput {
            stdout: wrap_sshsig_pem(&raw),
            stderr: Vec::new(),
        })
    }
}

fn root_mandate(from_key: &KeyId, to_key: &KeyId) -> String {
    let ast = parse_mandate(&format!(
        "HANDFEST v1\n\
         FROM human \"valentin\" (key: {from_key})\n\
         TO agent \"brokkr:dispatcher\" (key: {to_key})\n\
         DELEGATION max 1 hop\n\
         ALLOW git.pr.merge\n\
         ON repo \"feedback-loop-ai/*\"\n\
         WHERE context.time >= 2026-11-24T17:00:00Z\n\
           AND context.time < 2026-11-25T01:00:00Z\n\
           AND resource.author == \"valentin\"\n\
         LIMIT 5 calls\n",
    ))
    .expect("valid root mandate");
    render_canonical(&ast)
}

#[test]
fn ssh_sk_p256_end_to_end_mandate_chain_authorize_and_revocation() {
    let dir = tempfile::TempDir::new().unwrap();
    let root_secret = [0x42u8; 32];
    let pub_str = format_openssh_p256_pub(&root_secret, "ssh:handfest", Some("yubikey-p256"));
    let key_path = dir.path().join("id_ecdsa_sk");
    let pub_path = dir.path().join("id_ecdsa_sk.pub");
    fs::write(&key_path, "dummy-private-handle").unwrap();
    fs::write(&pub_path, &pub_str).unwrap();

    // Load from companion .pub via handle and directly from .pub
    let pk_from_handle = SshSkP256PublicKey::from_key_path(&key_path).expect("companion .pub");
    let pk_from_pub = SshSkP256PublicKey::from_key_path(&pub_path).expect("direct .pub");
    assert_eq!(pk_from_handle, pk_from_pub);
    assert_eq!(pk_from_handle.application(), "ssh:handfest");
    assert_eq!(pk_from_handle.public_key_bytes().len(), 65);
    assert!(pk_from_handle
        .key_id()
        .to_string()
        .starts_with("ssh-sk-p256:04"));
    assert_eq!(pk_from_handle.key_id().value().len(), 130);

    let runner = FakeP256Runner::new(root_secret, "ssh:handfest");
    let signer = SshSkP256Signer::from_key_path(&key_path, &runner).expect("p256 signer");
    assert_eq!(signer.public_key(), &pk_from_handle);
    assert_eq!(signer.assurance(), AssuranceLevel::Passkey);

    let dispatcher = Ed25519Keypair::from_secret_bytes([0x11; 32]);
    let worker = Ed25519Keypair::from_secret_bytes([0x22; 32]);
    let root_words = root_mandate(&signer.key_id(), &dispatcher.key_id());

    let root_signed = sign_mandate_with(
        &signer,
        &root_words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign P-256 root mandate");

    // Verify ssh-keygen invocation used mandate namespace
    {
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "ssh-keygen");
        assert_eq!(
            calls[0].args,
            vec![
                "-Y",
                "sign",
                "-f",
                key_path.to_str().unwrap(),
                "-n",
                SSHSIG_NAMESPACE
            ]
        );
        assert_eq!(calls[0].stdin, signing_payload(&root_signed));
    }

    // Child mandate delegated by dispatcher Ed25519 to worker
    let root_id = parse_mandate(&root_words).unwrap().mandate_id();
    let child_ast = parse_mandate(&format!(
        "HANDFEST v1\n\
         PARENT {root_id}\n\
         FROM agent \"brokkr:dispatcher\" (key: {})\n\
         TO agent \"brokkr:worker\" (key: {})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"feedback-loop-ai/handfest\"\n\
         WHERE context.time >= 2026-11-24T18:00:00Z\n\
           AND context.time < 2026-11-24T20:00:00Z\n\
           AND resource.author == \"valentin\"\n\
         LIMIT 2 calls\n",
        dispatcher.key_id(),
        worker.key_id()
    ))
    .unwrap();
    let child_signed = dispatcher
        .sign_mandate(
            &render_canonical(&child_ast),
            "dispatcher-ed25519",
            ts("2026-11-24T17:30:00Z"),
            ts("2026-11-24T20:00:00Z"),
        )
        .unwrap();

    // Verify heterogeneous 2-hop chain [ssh-sk-p256 -> ed25519] via AnchorRegistry::default_registry!
    let verified = verify_chain(&[root_signed.clone(), child_signed]).expect("verify chain");
    assert_eq!(verified.len(), 2);
    assert_eq!(verified[0].proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verified[1].proof.assurance, AssuranceLevel::LocalKey);

    let req = ActionRequest {
        actor_key: worker.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let mut facts = VerifiedFacts::new();
    facts.insert("resource.author", Scalar::Str("valentin".to_string()));
    let (verdict, _receipt) = authorize(
        &verified,
        &req,
        &facts,
        &QuotaSnapshot::default(),
        ts("2026-11-24T18:30:00Z"),
        None,
    );
    assert_eq!(verdict, Verdict::Permit);
}

#[test]
fn ssh_sk_p256_revocation_with_uv_flag_and_revocation_namespace() {
    let dir = tempfile::TempDir::new().unwrap();
    let root_secret = [0x42u8; 32];
    let pub_str = format_openssh_p256_pub(&root_secret, "ssh:handfest", Some("yubikey-p256"));
    let pub_path = dir.path().join("id_ecdsa_sk.pub");
    fs::write(&pub_path, &pub_str).unwrap();
    let root_id = MandateId::sha256(b"ssh-sk-p256-rev-target");

    // Sign and verify revocation with UP+UV (0x05) and revocation namespace!
    let mut uv_runner = FakeP256Runner::new(root_secret, "ssh:handfest");
    uv_runner.flags = 0x05;
    let uv_signer = SshSkP256Signer::from_pub_str(&pub_path, &pub_str, &uv_runner).unwrap();
    let rev_words = format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin\" (key: {})\n\
         TARGET mandate {root_id}\n\
         EFFECTIVE 2026-11-24T19:00:00Z\n\
         REASON \"p256 kill\"\n",
        uv_signer.key_id()
    );
    let signed_rev = sign_revocation_with(
        &uv_signer,
        &rev_words,
        "yubikey-ssh-sk",
        ts("2026-11-24T18:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign P-256 revocation with UP+UV");
    assert_eq!(
        uv_runner.calls.borrow()[0].args[5],
        SSHSIG_REVOCATION_NAMESPACE
    );

    let verified_rev = verify_revocation_ssh_sk_p256(&signed_rev).expect("verify revocation");
    assert_eq!(verified_rev.proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verify_revocation(&signed_rev).unwrap(), verified_rev);
}

#[test]
fn pub_parsing_hardening_and_dotfile_support() {
    let secret = [0x33u8; 32];
    let sec1 = test_public_key_from_secret(&secret);
    let blob = build_p256_pubkey_blob(SSH_SK_P256_SSH_TYPE, SSH_SK_P256_CURVE_NAME, &sec1, "ssh:");
    let b64 = encode_standard(&blob);

    // Non-UTF-8 trailing comment & CRLF accepted
    let mut raw_pub = format!("{SSH_SK_P256_SSH_TYPE} {b64} ").into_bytes();
    raw_pub.extend_from_slice(&[0xff, 0xfe, b'\r', b'\n']);
    let pk = SshSkP256PublicKey::parse_openssh_pub_bytes(&raw_pub).expect("non-UTF-8 comment ok");
    assert_eq!(pk.public_key_bytes(), &sec1);

    // Dotfile `.pub` supported
    let dir = tempfile::TempDir::new().unwrap();
    let dot_pub = dir.path().join(".id_ecdsa_sk.pub");
    fs::write(&dot_pub, format!("{SSH_SK_P256_SSH_TYPE} {b64}\n")).unwrap();
    assert_eq!(SshSkP256PublicKey::from_key_path(&dot_pub).unwrap(), pk);

    // Bare CR, NUL, control chars, wrong key type, wrong curve, off-curve point, trailing bytes
    let bare_cr = format!("{SSH_SK_P256_SSH_TYPE} {b64} a\rb\n");
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&bare_cr),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("control characters or bare CR")
    ));
    let with_nul = format!("{SSH_SK_P256_SSH_TYPE} {b64}\0\n");
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&with_nul),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("NUL")
    ));
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&format!("ssh-ed25519 {b64}\n")),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains(SSH_SK_P256_SSH_TYPE)
    ));

    let bad_curve = build_p256_pubkey_blob(SSH_SK_P256_SSH_TYPE, "nistp384", &sec1, "ssh:");
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_P256_SSH_TYPE} {}\n",
            encode_standard(&bad_curve)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("nistp256")
    ));

    let mut bad_pt = sec1;
    bad_pt[64] ^= 0x01;
    let off_curve_blob = build_p256_pubkey_blob(
        SSH_SK_P256_SSH_TYPE,
        SSH_SK_P256_CURVE_NAME,
        &bad_pt,
        "ssh:",
    );
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_P256_SSH_TYPE} {}\n",
            encode_standard(&off_curve_blob)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("not on curve")
    ));

    let mut trailing = blob.clone();
    trailing.push(0x99);
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_P256_SSH_TYPE} {}\n",
            encode_standard(&trailing)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("trailing")
    ));

    let bad_app = build_p256_pubkey_blob(
        SSH_SK_P256_SSH_TYPE,
        SSH_SK_P256_CURVE_NAME,
        &sec1,
        "https:",
    );
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_P256_SSH_TYPE} {}\n",
            encode_standard(&bad_app)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("must start with 'ssh:'")
    ));

    // Empty and NUL key paths rejected; missing companion never reads private key
    let runner = FakeP256Runner::new(secret, "ssh:");
    assert!(matches!(
        SshSkP256Signer::from_key_path("", &runner),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("empty")
    ));
    assert!(matches!(
        SshSkP256Signer::from_key_path("bad\0path.pub", &runner),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("NUL")
    ));
    let orphan = dir.path().join("id_ecdsa_orphan");
    fs::write(&orphan, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
    assert!(matches!(
        SshSkP256PublicKey::from_key_path(&orphan),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("never reads private key")
    ));
}

#[test]
fn adversarial_sshsig_mpint_flags_domain_replay_and_assurance_fail_closed() {
    let secret = [0x51u8; 32];
    let pub_str = format_openssh_p256_pub(&secret, "ssh:app", None);
    let pk = SshSkP256PublicKey::parse_openssh_pub(&pub_str).unwrap();
    let runner = FakeP256Runner::new(secret, "ssh:app");
    let signer = SshSkP256Signer::from_pub_str("id_ecdsa_sk.pub", &pub_str, &runner).unwrap();
    let agent = Ed25519Keypair::from_secret_bytes([0x77; 32]);

    let words = root_mandate(&pk.key_id(), &agent.key_id());
    let base_signed = sign_mandate_with(
        &signer,
        &words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .unwrap();
    let payload = signing_payload(&base_signed);

    // 1. UP = 0 (flags = 0x00 and flags = 0x04 UV-only) rejected
    for bad_flags in [0x00u8, 0x04] {
        let mut spec = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_NAMESPACE);
        spec.flags = bad_flags;
        let mut bad = base_signed.clone();
        bad.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &payload, &spec));
        assert!(matches!(
            verify_ssh_sk_p256(&bad),
            Err(AnchorError::InvalidSignature(m)) if m.contains("user-presence")
        ));
    }

    // 2. Non-canonical / negative / zero / oversized mpint for r and s rejected
    let bad_mpints: &[(&[u8], &str)] = &[
        (&[], "must be positive"),
        (&[0x00], "non-canonical leading zero"),
        (&[0x00, 0x7f], "non-canonical leading zero"),
        (&[0x00, 0x00, 0x80], "non-canonical leading zero"),
        (&[0x80, 0x01], "must not be negative"),
        (&[0x01; 33], "exceeds 32 bytes"),
    ];
    for &(raw_mpint, expected_msg) in bad_mpints {
        let mut spec_r = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_NAMESPACE);
        spec_r.r_mpint_override = Some(raw_mpint.to_vec());
        let mut bad_r = base_signed.clone();
        bad_r.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &payload, &spec_r));
        assert!(matches!(
            verify_ssh_sk_p256(&bad_r),
            Err(AnchorError::InvalidSignature(m)) if m.contains(expected_msg)
        ));

        let mut spec_s = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_NAMESPACE);
        spec_s.s_mpint_override = Some(raw_mpint.to_vec());
        let mut bad_s = base_signed.clone();
        bad_s.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &payload, &spec_s));
        assert!(matches!(
            verify_ssh_sk_p256(&bad_s),
            Err(AnchorError::InvalidSignature(m)) if m.contains(expected_msg)
        ));
    }

    // 3. Trailing bytes at all three layers rejected
    for (it, st, tt) in [
        (&b"\x00"[..], &b""[..], &b""[..]),
        (&b""[..], &b"\x00"[..], &b""[..]),
        (&b""[..], &b""[..], &b"\x00"[..]),
    ] {
        let mut spec = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_NAMESPACE);
        spec.inner_trailing = it;
        spec.sig_trailing = st;
        spec.top_trailing = tt;
        let mut bad = base_signed.clone();
        bad.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &payload, &spec));
        assert!(matches!(
            verify_ssh_sk_p256(&bad),
            Err(AnchorError::InvalidSignature(m)) if m.contains("trailing")
        ));
    }
}

#[test]
fn adversarial_wrong_curve_domain_replay_assurance_and_signer_mismatch_fail_closed() {
    let secret = [0x51u8; 32];
    let other_secret = [0x52u8; 32];
    let pub_str = format_openssh_p256_pub(&secret, "ssh:app", None);
    let pk = SshSkP256PublicKey::parse_openssh_pub(&pub_str).unwrap();
    let runner = FakeP256Runner::new(secret, "ssh:app");
    let signer = SshSkP256Signer::from_pub_str("id_ecdsa_sk.pub", &pub_str, &runner).unwrap();
    let agent = Ed25519Keypair::from_secret_bytes([0x77; 32]);

    let words = root_mandate(&pk.key_id(), &agent.key_id());
    let base_signed = sign_mandate_with(
        &signer,
        &words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .unwrap();
    let payload = signing_payload(&base_signed);

    // 4. Wrong curve, wrong sig type, wrong embedded public key, wrong magic/version/reserved/hash
    let mut bad_curve = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_NAMESPACE);
    bad_curve.pk_blob = build_p256_pubkey_blob(
        SSH_SK_P256_SSH_TYPE,
        "nistp384",
        pk.public_key_bytes(),
        "ssh:app",
    );
    let mut bad = base_signed.clone();
    bad.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &payload, &bad_curve));
    assert!(matches!(
        verify_ssh_sk_p256(&bad),
        Err(AnchorError::InvalidSignature(m)) if m.contains("nistp256")
    ));

    let mut bad_sig_type = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_NAMESPACE);
    bad_sig_type.sig_type = SSH_SK_ED25519_SSH_TYPE;
    bad.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &payload, &bad_sig_type));
    assert!(matches!(
        verify_ssh_sk_p256(&bad),
        Err(AnchorError::InvalidSignature(m)) if m.contains("signature type")
    ));

    let other_spec = P256SshSigSpec::valid(&other_secret, "ssh:app", SSHSIG_NAMESPACE);
    bad.signature_hex = hex::encode(sign_sk_p256_sshsig(&other_secret, &payload, &other_spec));
    assert!(matches!(
        verify_ssh_sk_p256(&bad),
        Err(AnchorError::InvalidSignature(m)) if m.contains("does not match expected signer key")
    ));

    // 5. Cross-domain replay: mandate signed under revocation namespace rejected;
    //    revocation signed under mandate namespace rejected!
    let wrong_ns_mandate = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_REVOCATION_NAMESPACE);
    bad.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &payload, &wrong_ns_mandate));
    assert!(matches!(
        verify_ssh_sk_p256(&bad),
        Err(AnchorError::InvalidSignature(m)) if m.contains("invalid SSHSIG namespace")
    ));

    let rev_words = format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin\" (key: {})\n\
         TARGET mandate {}\n\
         EFFECTIVE 2026-11-24T19:00:00Z\n",
        pk.key_id(),
        MandateId::sha256(b"target")
    );
    let signed_rev = sign_revocation_with(
        &signer,
        &rev_words,
        "yubikey-ssh-sk",
        ts("2026-11-24T18:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .unwrap();
    let rev_payload = revocation_signing_payload(&signed_rev);
    let wrong_ns_rev = P256SshSigSpec::valid(&secret, "ssh:app", SSHSIG_NAMESPACE);
    let mut bad_rev = signed_rev.clone();
    bad_rev.signature_hex = hex::encode(sign_sk_p256_sshsig(&secret, &rev_payload, &wrong_ns_rev));
    assert!(matches!(
        verify_revocation_ssh_sk_p256(&bad_rev),
        Err(AnchorError::InvalidSignature(m)) if m.contains("invalid SSHSIG namespace")
    ));

    // 6. Wrong assurance (`local_key`) rejected on both mandate and revocation
    let mut bad_assurance = base_signed.clone();
    bad_assurance.assurance = "local_key".to_string();
    assert_eq!(
        verify_ssh_sk_p256(&bad_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::Passkey,
            actual: AssuranceLevel::LocalKey,
        })
    );
    let mut bad_rev_assurance = signed_rev;
    bad_rev_assurance.assurance = "local_key".to_string();
    assert_eq!(
        verify_revocation_ssh_sk_p256(&bad_rev_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::Passkey,
            actual: AssuranceLevel::LocalKey,
        })
    );
}

#[test]
fn signer_fails_closed_on_unknown_prefix_and_mismatched_application() {
    let secret = [0x51u8; 32];
    let pub_str = format_openssh_p256_pub(&secret, "ssh:app", None);
    let pk = SshSkP256PublicKey::parse_openssh_pub(&pub_str).unwrap();
    let runner = FakeP256Runner::new(secret, "ssh:app");
    let signer = SshSkP256Signer::from_pub_str("id_ecdsa_sk.pub", &pub_str, &runner).unwrap();
    let agent = Ed25519Keypair::from_secret_bytes([0x77; 32]);
    let words = root_mandate(&pk.key_id(), &agent.key_id());
    let base_signed = sign_mandate_with(
        &signer,
        &words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .unwrap();
    let payload = signing_payload(&base_signed);

    assert!(matches!(
        signer.sign_payload(b"unknown-domain\0data"),
        Err(AnchorError::InvalidSignature(m)) if m.contains("signing domain prefix")
    ));
    let wrong_app_runner = FakeP256Runner::new(secret, "ssh:different-app");
    let wrong_app_signer =
        SshSkP256Signer::from_pub_str("id_ecdsa_sk.pub", &pub_str, &wrong_app_runner).unwrap();
    assert!(matches!(
        wrong_app_signer.sign_payload(&payload),
        Err(AnchorError::InvalidSignature(m)) if m.contains("does not match public key application")
    ));
}

#[test]
fn unified_ssh_sk_any_dispatches_both_ed25519_and_p256_and_rejects_other_types() {
    let dir = tempfile::TempDir::new().unwrap();

    // P-256 fixture
    let p256_secret = [0x88u8; 32];
    let p256_pub_str = format_openssh_p256_pub(&p256_secret, "ssh:unified", Some("p256"));
    let p256_path = dir.path().join("id_ecdsa_sk.pub");
    fs::write(&p256_path, &p256_pub_str).unwrap();

    let any_p256 = SshSkAnyPublicKey::from_key_path(&p256_path).unwrap();
    assert_eq!(any_p256.application(), "ssh:unified");
    assert_eq!(any_p256.key_id().scheme(), SSH_SK_P256_SCHEME);

    let p256_runner = FakeP256Runner::new(p256_secret, "ssh:unified");
    let any_p256_signer = SshSkAnySigner::from_key_path(&p256_path, &p256_runner).unwrap();
    assert_eq!(any_p256_signer.key_id(), any_p256.key_id());
    assert_eq!(any_p256_signer.assurance(), AssuranceLevel::Passkey);
    let any_p256_from_str =
        SshSkAnySigner::from_pub_str(&p256_path, &p256_pub_str, &p256_runner).unwrap();
    assert_eq!(any_p256_from_str.key_id(), any_p256.key_id());

    // Ed25519-SK fixture
    let ed_kp = Ed25519Keypair::from_secret_bytes([0x99; 32]);
    let mut ed_blob = Vec::new();
    push_ssh_bytes(&mut ed_blob, SSH_SK_ED25519_SSH_TYPE.as_bytes());
    push_ssh_bytes(&mut ed_blob, &ed_kp.public_key_bytes());
    push_ssh_bytes(&mut ed_blob, b"ssh:ed");
    let ed_pub_str = format!("{SSH_SK_ED25519_SSH_TYPE} {}\n", encode_standard(&ed_blob));
    let ed_path = dir.path().join("id_ed25519_sk.pub");
    fs::write(&ed_path, &ed_pub_str).unwrap();

    let any_ed = SshSkAnyPublicKey::from_key_path(&ed_path).unwrap();
    assert_eq!(any_ed.application(), "ssh:ed");
    assert_eq!(any_ed.key_id().scheme(), crate::SSH_SK_ED25519_SCHEME);

    let any_ed_signer = SshSkAnySigner::from_key_path(&ed_path, &p256_runner).unwrap();
    assert_eq!(any_ed_signer.key_id(), any_ed.key_id());
    assert_eq!(any_ed_signer.assurance(), AssuranceLevel::Passkey);
    let any_ed_from_str =
        SshSkAnySigner::from_pub_str(&ed_path, &ed_pub_str, &p256_runner).unwrap();
    assert_eq!(any_ed_from_str.key_id(), any_ed.key_id());

    // Non-SK key type fails closed naming both supported SK types
    let err = SshSkAnyPublicKey::parse_openssh_pub(&format!(
        "ssh-ed25519 {}\n",
        encode_standard(&ed_blob)
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        AnchorError::InvalidPublicKey(m)
            if m.contains(SSH_SK_ED25519_SSH_TYPE) && m.contains(SSH_SK_P256_SSH_TYPE)
    ));
}

#[test]
fn remaining_error_branches_and_any_signer_dispatch_coverage() {
    let dir = tempfile::TempDir::new().unwrap();
    let missing_pub = dir.path().join("does_not_exist.pub");
    assert!(matches!(
        SshSkP256PublicKey::from_key_path(&missing_pub),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("failed to read")
    ));
    assert!(matches!(
        SshSkAnyPublicKey::from_key_path(&missing_pub),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("failed to read")
    ));

    // Inner pubkey blob key_type mismatch (outer line says P-256, inner says Ed25519)
    let secret = [0x44u8; 32];
    let sec1 = test_public_key_from_secret(&secret);
    let inner_mismatch = build_p256_pubkey_blob(
        SSH_SK_ED25519_SSH_TYPE,
        SSH_SK_P256_CURVE_NAME,
        &sec1,
        "ssh:",
    );
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_P256_SSH_TYPE} {}\n",
            encode_standard(&inner_mismatch)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("expected publickey type")
    ));

    // public_key() accessor matches P256PublicKey
    let pub_str = format_openssh_p256_pub(&secret, "ssh:cov", None);
    let pk = SshSkP256PublicKey::parse_openssh_pub(&pub_str).unwrap();
    assert_eq!(pk.public_key().as_sec1_bytes(), &sec1);

    // Off-curve P-256 KeyId in SignedMandate rejected by parse_p256_key_from_key_id
    let mut bad_sec1 = sec1;
    bad_sec1[64] ^= 0x01;
    let bad_kid = KeyId::new(SSH_SK_P256_SCHEME, hex::encode(bad_sec1)).unwrap();
    let agent = Ed25519Keypair::from_secret_bytes([0x66; 32]);
    let bad_words = root_mandate(&bad_kid, &agent.key_id());
    let bad_signed = SignedMandate {
        canonical_words: bad_words,
        anchor_id: "yubikey-ssh-sk".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: bad_kid.to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: "00".to_string(),
    };
    assert!(matches!(
        verify_ssh_sk_p256(&bad_signed),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("not on curve")
    ));

    // SshSkAnySigner::sign_payload dispatches both P256 and Ed25519 cleanly
    let p256_runner = FakeP256Runner::new(secret, "ssh:cov");
    let any_p256 = SshSkAnySigner::from_pub_str("id_ecdsa_sk.pub", &pub_str, &p256_runner).unwrap();
    let words = root_mandate(&any_p256.key_id(), &agent.key_id());
    let signed_p256 = sign_mandate_with(
        &any_p256,
        &words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign via SshSkAnySigner::P256");
    verify_ssh_sk_p256(&signed_p256).expect("verify SshSkAnySigner::P256 output");

    // SshSkAnySigner::Ed25519 sign_payload delegates to SshSkSigner (fails closed on runner error)
    struct FailRunner;
    impl CommandRunner for FailRunner {
        fn run(&self, p: &str, _: &[&str], _: &[u8]) -> Result<CommandOutput, AnchorError> {
            Err(AnchorError::CommandFailed {
                program: p.to_string(),
                status: Some(1),
                stderr: "boom".to_string(),
            })
        }
    }
    let ed_kp = Ed25519Keypair::from_secret_bytes([0x99; 32]);
    let mut ed_blob = Vec::new();
    push_ssh_bytes(&mut ed_blob, SSH_SK_ED25519_SSH_TYPE.as_bytes());
    push_ssh_bytes(&mut ed_blob, &ed_kp.public_key_bytes());
    push_ssh_bytes(&mut ed_blob, b"ssh:ed");
    let ed_pub_str = format!("{SSH_SK_ED25519_SSH_TYPE} {}\n", encode_standard(&ed_blob));
    let any_ed =
        SshSkAnySigner::from_pub_str("id_ed25519_sk.pub", &ed_pub_str, FailRunner).unwrap();
    assert!(matches!(
        any_ed.sign_payload(b"unknown-domain\0test"),
        Err(AnchorError::InvalidSignature(m)) if m.contains("signing domain prefix")
    ));
    assert!(matches!(
        any_ed.sign_payload(b"handfest-v1-envelope\0test"),
        Err(AnchorError::CommandFailed { .. })
    ));

    // OpenSSH .pub framing: CRLF is accepted, bare CR at EOF is rejected.
    let secret = [0x42u8; 32];
    let clean_pub = format_openssh_p256_pub(&secret, "ssh:app", None);
    let crlf_pub = format!("{}\r\n", clean_pub.trim_end());
    SshSkP256PublicKey::parse_openssh_pub(&crlf_pub).expect("CRLF .pub must be accepted");
    let bare_cr_eof = format!("{}\r", clean_pub.trim_end());
    assert!(matches!(
        SshSkP256PublicKey::parse_openssh_pub(&bare_cr_eof),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("bare CR")
    ));
}
