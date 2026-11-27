use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use handfest_anchors::{
    sign_mandate_with, signing_payload, verify_chain, verify_ssh_sk_ed25519, AnchorError,
    AnchorRegistry, AnchorVerifier, AssuranceLevel, CommandOutput, CommandRunner, Ed25519Keypair,
    MandateSigner, SignedMandate, SshSkEd25519Verifier, SshSkPublicKey, SshSkSigner,
    SSHSIG_NAMESPACE, SSH_SK_ED25519_SCHEME, SSH_SK_ED25519_SSH_TYPE,
};
use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId, Scalar};
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::gate::{authorize, ActionRequest, QuotaSnapshot, VerifiedFacts};
use handfest_core::{ActorKind, Verdict};
use sha2::{Digest, Sha256, Sha512};

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 timestamp")
}

fn push_ssh_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("len fits u32");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn build_sk_pubkey_blob(key_type: &str, pk_bytes: &[u8], application: &str) -> Vec<u8> {
    let mut blob = Vec::new();
    push_ssh_bytes(&mut blob, key_type.as_bytes());
    push_ssh_bytes(&mut blob, pk_bytes);
    push_ssh_bytes(&mut blob, application.as_bytes());
    blob
}

fn format_openssh_pub(
    signing_key: &SigningKey,
    application: &str,
    comment: Option<&str>,
) -> String {
    let blob = build_sk_pubkey_blob(
        SSH_SK_ED25519_SSH_TYPE,
        signing_key.verifying_key().as_bytes(),
        application,
    );
    let b64 = encode_base64(&blob);
    match comment {
        Some(c) => format!("{SSH_SK_ED25519_SSH_TYPE} {b64} {c}\n"),
        None => format!("{SSH_SK_ED25519_SSH_TYPE} {b64}\n"),
    }
}

struct SshSigSpec<'a> {
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
    sig_trailing: &'a [u8],
    top_trailing: &'a [u8],
}

impl<'a> SshSigSpec<'a> {
    fn valid(signing_key: &SigningKey, application: &'a str) -> Self {
        Self {
            magic: b"SSHSIG",
            version: 1,
            pk_blob: build_sk_pubkey_blob(
                SSH_SK_ED25519_SSH_TYPE,
                signing_key.verifying_key().as_bytes(),
                application,
            ),
            namespace: SSHSIG_NAMESPACE,
            reserved: b"",
            hash_alg: "sha512",
            sig_type: SSH_SK_ED25519_SSH_TYPE,
            flags: 0x01,
            counter: 42,
            application_for_signing: application,
            sig_trailing: b"",
            top_trailing: b"",
        }
    }
}

fn sign_sk_sshsig(signing_key: &SigningKey, payload: &[u8], spec: &SshSigSpec<'_>) -> Vec<u8> {
    let payload_sha512 = Sha512::digest(payload);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"SSHSIG");
    push_ssh_bytes(&mut preimage, spec.namespace.as_bytes());
    push_ssh_bytes(&mut preimage, spec.reserved);
    push_ssh_bytes(&mut preimage, spec.hash_alg.as_bytes());
    push_ssh_bytes(&mut preimage, &payload_sha512);

    let app_hash = Sha256::digest(spec.application_for_signing.as_bytes());
    let preimage_hash = Sha256::digest(&preimage);
    let mut sk_signed = [0u8; 69];
    sk_signed[0..32].copy_from_slice(&app_hash);
    sk_signed[32] = spec.flags;
    sk_signed[33..37].copy_from_slice(&spec.counter.to_be_bytes());
    sk_signed[37..69].copy_from_slice(&preimage_hash);

    let ed_sig = signing_key.sign(&sk_signed);

    let mut sig_blob = Vec::new();
    push_ssh_bytes(&mut sig_blob, spec.sig_type.as_bytes());
    push_ssh_bytes(&mut sig_blob, &ed_sig.to_bytes());
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
    let b64 = encode_base64(raw);
    let mut pem = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).expect("ascii b64"));
        pem.push('\n');
    }
    pem.push_str("-----END SSH SIGNATURE-----\n");
    pem.into_bytes()
}

fn root_mandate(from_key: &KeyId, to_key: &KeyId) -> String {
    let ast = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: {from_key})\n",
            "TO agent \"brokkr:dispatcher\" (key: {to_key})\n",
            "DELEGATION max 1 hop\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/*\"\n",
            "WHERE context.time >= 2026-11-24T17:00:00Z\n",
            "  AND context.time < 2026-11-25T01:00:00Z\n",
            "  AND resource.author == \"valentin\"\n",
            "LIMIT 5 calls\n",
        ),
        from_key = from_key,
        to_key = to_key,
    ))
    .expect("valid root mandate");
    render_canonical(&ast)
}

fn child_mandate(parent: MandateId, from_key: &KeyId, to_key: &KeyId) -> String {
    let ast = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {parent}\n",
            "FROM agent \"brokkr:dispatcher\" (key: {from_key})\n",
            "TO agent \"brokkr:worker\" (key: {to_key})\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE context.time >= 2026-11-24T18:00:00Z\n",
            "  AND context.time < 2026-11-24T19:00:00Z\n",
            "  AND resource.author == \"valentin\"\n",
            "LIMIT 2 calls\n",
        ),
        parent = parent,
        from_key = from_key,
        to_key = to_key,
    ))
    .expect("valid child mandate");
    render_canonical(&ast)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedCall {
    program: String,
    args: Vec<String>,
    stdin: Vec<u8>,
}

struct FakeSshKeygenRunner {
    signing_key: SigningKey,
    application: String,
    flags: u8,
    counter: u32,
    calls: RefCell<Vec<RecordedCall>>,
    override_result: Option<Result<CommandOutput, AnchorError>>,
}

impl FakeSshKeygenRunner {
    fn new(signing_key: SigningKey, application: &str) -> Self {
        Self {
            signing_key,
            application: application.to_string(),
            flags: 0x01,
            counter: 7,
            calls: RefCell::new(Vec::new()),
            override_result: None,
        }
    }
}

impl CommandRunner for FakeSshKeygenRunner {
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
        if let Some(res) = &self.override_result {
            return res.clone();
        }
        let mut spec = SshSigSpec::valid(&self.signing_key, &self.application);
        spec.flags = self.flags;
        spec.counter = self.counter;
        let raw = sign_sk_sshsig(&self.signing_key, stdin, &spec);
        Ok(CommandOutput {
            stdout: wrap_sshsig_pem(&raw),
            stderr: b"Signing data on standard input\n".to_vec(),
        })
    }
}

#[test]
fn parse_openssh_pub_derives_key_id_and_handles_comments_and_apps() {
    let sk = SigningKey::from_bytes(&[0x11; 32]);
    let pub_line = format_openssh_pub(&sk, "ssh:handfest", Some("valentin@yubikey 5c"));
    let parsed = SshSkPublicKey::parse_openssh_pub(&pub_line).expect("parse valid .pub");

    assert_eq!(parsed.public_key_bytes(), sk.verifying_key().as_bytes());
    assert_eq!(parsed.application(), "ssh:handfest");
    assert_eq!(
        parsed.key_id().to_string(),
        format!(
            "{SSH_SK_ED25519_SCHEME}:{}",
            hex::encode(sk.verifying_key().as_bytes())
        )
    );

    // Without comment and with CRLF line ending.
    let no_comment = format!("{}\r\n", format_openssh_pub(&sk, "ssh:", None).trim_end());
    let parsed_default = SshSkPublicKey::parse_openssh_pub(&no_comment).expect("no comment");
    assert_eq!(parsed_default.application(), "ssh:");
    assert_eq!(parsed_default.key_id(), parsed.key_id());
}

#[test]
fn parse_openssh_pub_rejects_malformed_inputs_and_trailing_bytes() {
    let sk = SigningKey::from_bytes(&[0x22; 32]);
    let valid_line = format_openssh_pub(&sk, "ssh:", None);

    // Empty / whitespace-only
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub("   \n\t\n"),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("empty")
    ));

    // NUL byte
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&format!("{valid_line}\0")),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("NUL")
    ));

    // Multiple lines
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&format!("{valid_line}{valid_line}")),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("exactly one")
    ));

    // Wrong key type (software ssh-ed25519)
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("ssh-ed25519")
    ));

    // Missing base64 blob
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(SSH_SK_ED25519_SSH_TYPE),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("missing base64")
    ));

    // Invalid base64: bad length, bad char, mid-stream padding, non-canonical pad bits (== and =)
    for bad_b64 in [
        "ABC", "AAA!", "AA==AAAA", "AAA=AAAA", "AB==AAAA", "AB==", "AAB=",
    ] {
        let line = format!("{SSH_SK_ED25519_SSH_TYPE} {bad_b64}");
        assert!(
            matches!(
                SshSkPublicKey::parse_openssh_pub(&line),
                Err(AnchorError::InvalidPublicKey(m)) if m.contains("base64")
            ),
            "expected base64 rejection for '{bad_b64}'"
        );
    }

    // Inner key type mismatch
    let wrong_inner = build_sk_pubkey_blob("ssh-ed25519", sk.verifying_key().as_bytes(), "ssh:");
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_ED25519_SSH_TYPE} {}",
            encode_base64(&wrong_inner)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("expected publickey type")
    ));

    // Wrong pubkey length (31 bytes)
    let short_pk = build_sk_pubkey_blob(SSH_SK_ED25519_SSH_TYPE, &[0x33; 31], "ssh:");
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_ED25519_SSH_TYPE} {}",
            encode_base64(&short_pk)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("32-byte")
    ));

    // Invalid application (not starting with "ssh:" or containing control char)
    for bad_app in ["", "https://evil.example", "ssh:\x07bell"] {
        let bad_app_blob = build_sk_pubkey_blob(
            SSH_SK_ED25519_SSH_TYPE,
            sk.verifying_key().as_bytes(),
            bad_app,
        );
        assert!(
            matches!(
                SshSkPublicKey::parse_openssh_pub(&format!(
                    "{SSH_SK_ED25519_SSH_TYPE} {}",
                    encode_base64(&bad_app_blob)
                )),
                Err(AnchorError::InvalidPublicKey(m)) if m.contains("application")
            ),
            "expected application rejection for '{bad_app:?}'"
        );
    }

    // Trailing garbage byte inside .pub wire blob
    let mut trailing = build_sk_pubkey_blob(
        SSH_SK_ED25519_SSH_TYPE,
        sk.verifying_key().as_bytes(),
        "ssh:",
    );
    trailing.push(0x99);
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_ED25519_SSH_TYPE} {}",
            encode_base64(&trailing)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("trailing")
    ));

    // Non-UTF-8 string inside wire blob
    let mut bad_utf8 = Vec::new();
    push_ssh_bytes(&mut bad_utf8, &[0xff, 0xfe]);
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&format!(
            "{SSH_SK_ED25519_SSH_TYPE} {}",
            encode_base64(&bad_utf8)
        )),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("UTF-8")
    ));
}

impl CommandRunner for &FakeSshKeygenRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        (*self).run(program, args, stdin)
    }
}

#[test]
fn ssh_sk_signer_from_key_path_resolves_pub_and_companion_without_reading_private_key() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sk = SigningKey::from_bytes(&[0x33; 32]);
    let pub_content = format_openssh_pub(&sk, "ssh:", Some("yk5c"));

    let handle_path = dir.path().join("id_ed25519_sk");
    let pub_path = dir.path().join("id_ed25519_sk.pub");
    fs::write(&handle_path, b"\xff\xfeNOT-A-PUB-KEY-DO-NOT-READ").expect("write handle");
    fs::write(&pub_path, &pub_content).expect("write .pub");

    // 1. Direct `.pub` path
    let runner_pub = FakeSshKeygenRunner::new(sk.clone(), "ssh:");
    let signer_pub = SshSkSigner::from_key_path(&pub_path, runner_pub).expect("from .pub");
    assert_eq!(signer_pub.public_key().application(), "ssh:");
    assert_eq!(signer_pub.assurance(), AssuranceLevel::Passkey);

    // 2. Key handle path resolves companion `.pub` without reading handle file,
    //    and passes the handle path itself to `ssh-keygen -Y sign -f <handle>`.
    let runner_handle = FakeSshKeygenRunner::new(sk.clone(), "ssh:");
    let signer_handle =
        SshSkSigner::from_key_path(&handle_path, runner_handle).expect("from handle");
    assert_eq!(signer_handle.key_id(), signer_pub.key_id());

    let dispatcher = Ed25519Keypair::from_secret_bytes([0x44; 32]);
    let words = root_mandate(&signer_handle.key_id(), &dispatcher.key_id());
    let signed = sign_mandate_with(
        &signer_handle,
        &words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign via handle path");
    assert_eq!(signed.assurance, "passkey");
    assert_eq!(signed.anchor_id, "yubikey-ssh-sk");
    assert_eq!(signed.signer_key, signer_handle.key_id().to_string());

    // Verify exact verification via default AnchorRegistry!
    let verified = verify_chain(&[signed]).expect("verify_chain via default_registry");
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verified[0].proof.actor_kind, ActorKind::Human);
    assert_eq!(verified[0].proof.signer_key, signer_handle.key_id());

    // 3. Non-existent `.pub` fails cleanly.
    let missing_pub = dir.path().join("missing.pub");
    assert!(matches!(
        SshSkPublicKey::from_key_path(&missing_pub),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("failed to read")
    ));

    // 4. Key handle without companion `.pub` fails closed without opening private key.
    let orphan = dir.path().join("orphan_sk");
    fs::write(&orphan, "-----BEGIN OPENSSH PRIVATE KEY-----\n").expect("write orphan");
    assert!(matches!(
        SshSkPublicKey::from_key_path(&orphan),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("never reads private key")
    ));
}

#[test]
fn ssh_sk_signer_invokes_exact_ssh_keygen_args_and_verifies_heterogeneous_chain_end_to_end() {
    let root_sk = SigningKey::from_bytes(&[0x51; 32]);
    let dispatcher = Ed25519Keypair::from_secret_bytes([0x52; 32]);
    let worker = Ed25519Keypair::from_secret_bytes([0x53; 32]);

    let pub_str = format_openssh_pub(&root_sk, "ssh:handfest", Some("yubikey@dev"));
    let mut runner = FakeSshKeygenRunner::new(root_sk.clone(), "ssh:handfest");
    runner.flags = 0x05; // UP (0x01) + UV (0x04)
    runner.counter = 1024;

    let key_path = PathBuf::from("/fake/home/.ssh/id_ed25519_sk.pub");
    let signer = SshSkSigner::from_pub_str(&key_path, &pub_str, runner).expect("signer");

    let root_words = root_mandate(&signer.key_id(), &dispatcher.key_id());
    let root_signed = sign_mandate_with(
        &signer,
        &root_words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign root mandate with SshSkSigner");

    // Child mandate delegated by software Ed25519 dispatcher to worker.
    let root_id = parse_mandate(&root_words).expect("parse root").mandate_id();
    let child_words = child_mandate(root_id, &dispatcher.key_id(), &worker.key_id());
    let child_signed = dispatcher
        .sign_mandate(
            &child_words,
            "dispatcher-ed25519",
            ts("2026-11-24T17:30:00Z"),
            ts("2026-11-24T20:00:00Z"),
        )
        .expect("sign child mandate");

    // Verify heterogeneous 2-hop chain [ssh-sk-ed25519 -> ed25519] via default_registry!
    let verified = verify_chain(&[root_signed.clone(), child_signed])
        .expect("heterogeneous YubiKey + Ed25519 chain verifies");
    assert_eq!(verified.len(), 2);
    assert_eq!(verified[0].proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verified[1].proof.assurance, AssuranceLevel::LocalKey);

    // Authorize an action against the verified chain!
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

    // Confirm SshSkSigner called `ssh-keygen -Y sign -f <path> -n handfest-v1-envelope`
    // with exact `signing_payload(&root_signed)` on stdin.
    let runner_check = FakeSshKeygenRunner::new(root_sk, "ssh:handfest");
    let signer_check =
        SshSkSigner::from_pub_str(&key_path, &pub_str, &runner_check).expect("signer ref");
    let _ = signer_check
        .sign_payload(&signing_payload(&root_signed))
        .expect("sign_payload");
    let calls = runner_check.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "ssh-keygen");
    assert_eq!(
        calls[0].args,
        vec![
            "-Y",
            "sign",
            "-f",
            "/fake/home/.ssh/id_ed25519_sk.pub",
            "-n",
            SSHSIG_NAMESPACE,
        ]
    );
    assert_eq!(calls[0].stdin, signing_payload(&root_signed));
}

#[test]
fn ssh_sk_signer_fails_closed_on_command_error_bad_pem_or_mismatched_output() {
    let sk = SigningKey::from_bytes(&[0x61; 32]);
    let other_sk = SigningKey::from_bytes(&[0x62; 32]);
    let pub_str = format_openssh_pub(&sk, "ssh:app1", None);
    let payload = b"handfest-v1-envelope\0sample-payload";

    // 1. Non-zero ssh-keygen exit
    let mut runner = FakeSshKeygenRunner::new(sk.clone(), "ssh:app1");
    runner.override_result = Some(Err(AnchorError::CommandFailed {
        program: "ssh-keygen".to_string(),
        status: Some(255),
        stderr: "Signing failed: user presence timed out".to_string(),
    }));
    let signer = SshSkSigner::from_pub_str("k.pub", &pub_str, runner).unwrap();
    assert_eq!(
        signer.sign_payload(payload),
        Err(AnchorError::CommandFailed {
            program: "ssh-keygen".to_string(),
            status: Some(255),
            stderr: "Signing failed: user presence timed out".to_string(),
        })
    );

    // 2. Non-UTF-8 stdout
    let mut runner = FakeSshKeygenRunner::new(sk.clone(), "ssh:app1");
    runner.override_result = Some(Ok(CommandOutput {
        stdout: vec![0xff, 0xfe],
        stderr: vec![],
    }));
    let signer = SshSkSigner::from_pub_str("k.pub", &pub_str, runner).unwrap();
    assert!(matches!(
        signer.sign_payload(payload),
        Err(AnchorError::InvalidSignature(m)) if m.contains("UTF-8")
    ));

    // 3. Invalid PEM armor / blank body line / bad base64 in PEM
    for bad_pem in [
        b"not a pem".as_slice(),
        b"-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n",
        b"-----BEGIN SSH SIGNATURE-----\nAAAA\n\nBBBB\n-----END SSH SIGNATURE-----\n",
        b"-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----\n",
        b"junk\n-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n",
        b"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\njunk\n",
    ] {
        let mut runner = FakeSshKeygenRunner::new(sk.clone(), "ssh:app1");
        runner.override_result = Some(Ok(CommandOutput {
            stdout: bad_pem.to_vec(),
            stderr: vec![],
        }));
        let signer = SshSkSigner::from_pub_str("k.pub", &pub_str, runner).unwrap();
        assert!(
            matches!(
                signer.sign_payload(payload),
                Err(AnchorError::InvalidSignature(_))
            ),
            "expected InvalidSignature for PEM {:?}",
            String::from_utf8_lossy(bad_pem)
        );
    }

    // 4. ssh-keygen returned signature with missing UP bit (flags = 0)
    let mut runner = FakeSshKeygenRunner::new(sk.clone(), "ssh:app1");
    runner.flags = 0x00;
    let signer = SshSkSigner::from_pub_str("k.pub", &pub_str, runner).unwrap();
    assert!(matches!(
        signer.sign_payload(payload),
        Err(AnchorError::InvalidSignature(m)) if m.contains("user-presence")
    ));

    // 5. ssh-keygen signed with wrong key
    let runner = FakeSshKeygenRunner::new(other_sk, "ssh:app1");
    let signer = SshSkSigner::from_pub_str("k.pub", &pub_str, runner).unwrap();
    assert!(matches!(
        signer.sign_payload(payload),
        Err(AnchorError::InvalidSignature(m)) if m.contains("does not match expected signer key")
    ));

    // 6. ssh-keygen returned different application than `.pub`
    let runner = FakeSshKeygenRunner::new(sk, "ssh:other-app");
    let signer = SshSkSigner::from_pub_str("k.pub", &pub_str, runner).unwrap();
    assert!(matches!(
        signer.sign_payload(payload),
        Err(AnchorError::InvalidSignature(m)) if m.contains("application")
    ));
}

fn make_signed_mandate(
    sk: &SigningKey,
    spec_mut: impl FnOnce(&mut SshSigSpec<'_>),
) -> SignedMandate {
    let pub_key =
        SshSkPublicKey::parse_openssh_pub(&format_openssh_pub(sk, "ssh:", None)).expect("pub");
    let agent = Ed25519Keypair::from_secret_bytes([0x99; 32]);
    let words = root_mandate(&pub_key.key_id(), &agent.key_id());

    let mut signed = SignedMandate {
        canonical_words: words,
        anchor_id: "yubikey-ssh-sk".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: pub_key.key_id().to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: String::new(),
    };
    let payload = signing_payload(&signed);
    let mut spec = SshSigSpec::valid(sk, "ssh:");
    spec_mut(&mut spec);
    let raw = sign_sk_sshsig(sk, &payload, &spec);
    signed.signature_hex = hex::encode(raw);
    signed
}

#[test]
fn verifier_rejects_missing_up_bit_wrong_namespace_reserved_hash_magic_version_and_trailing_bytes()
{
    let sk = SigningKey::from_bytes(&[0x71; 32]);
    let other_sk = SigningKey::from_bytes(&[0x72; 32]);
    let registry = AnchorRegistry::default_registry();

    // Baseline valid signature passes both direct verifier and default_registry.
    let valid = make_signed_mandate(&sk, |_| {});
    assert!(SshSkEd25519Verifier.verify(&valid).is_ok());
    assert!(registry.verify(&valid).is_ok());

    // 1. Missing UP flag (flags = 0x00 and flags = 0x04 UV-only without UP)
    for bad_flags in [0x00, 0x04] {
        let m = make_signed_mandate(&sk, |s| s.flags = bad_flags);
        assert!(
            matches!(
                registry.verify(&m),
                Err(AnchorError::InvalidSignature(msg)) if msg.contains("user-presence")
            ),
            "flags=0x{bad_flags:02x} must be rejected"
        );
    }

    // 2. Wrong namespace
    for bad_ns in ["file", "git", "", "handfest-v1-envelope\0"] {
        let m = make_signed_mandate(&sk, |s| s.namespace = bad_ns);
        assert!(
            matches!(
                verify_ssh_sk_ed25519(&m),
                Err(AnchorError::InvalidSignature(msg)) if msg.contains("namespace")
            ),
            "namespace={bad_ns:?} must be rejected"
        );
    }

    // 3. Non-empty reserved field
    let non_empty_reserved = make_signed_mandate(&sk, |s| s.reserved = b"x");
    assert!(matches!(
        verify_ssh_sk_ed25519(&non_empty_reserved),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("reserved")
    ));

    // 4. Unsupported hash algorithm
    let sha256_alg = make_signed_mandate(&sk, |s| s.hash_alg = "sha256");
    assert!(matches!(
        verify_ssh_sk_ed25519(&sha256_alg),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("hash algorithm")
    ));

    // 5. Bad magic
    let bad_magic = make_signed_mandate(&sk, |s| s.magic = b"NOTSIG");
    assert!(matches!(
        verify_ssh_sk_ed25519(&bad_magic),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("magic")
    ));

    // 6. Bad version (0 and 2)
    for bad_ver in [0u32, 2u32] {
        let m = make_signed_mandate(&sk, |s| s.version = bad_ver);
        assert!(matches!(
            verify_ssh_sk_ed25519(&m),
            Err(AnchorError::InvalidSignature(msg)) if msg.contains("version")
        ));
    }

    // 7. Trailing bytes at top-level SSHSIG, inside signature blob, and inside publickey blob
    let top_trailing = make_signed_mandate(&sk, |s| s.top_trailing = b"\x00");
    assert!(matches!(
        verify_ssh_sk_ed25519(&top_trailing),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("trailing")
    ));

    let sig_trailing = make_signed_mandate(&sk, |s| s.sig_trailing = b"\x01");
    assert!(matches!(
        verify_ssh_sk_ed25519(&sig_trailing),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("trailing")
    ));

    let pk_trailing = make_signed_mandate(&sk, |s| s.pk_blob.push(0x02));
    assert!(matches!(
        verify_ssh_sk_ed25519(&pk_trailing),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("trailing")
    ));

    // 8. Wrong signature type inside signature blob
    let wrong_sig_type = make_signed_mandate(&sk, |s| s.sig_type = "ssh-ed25519");
    assert!(matches!(
        verify_ssh_sk_ed25519(&wrong_sig_type),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("expected signature type")
    ));

    // 9. Mismatched pubkey inside SSHSIG vs signer_key / mandate FROM
    let wrong_pk_in_sig = make_signed_mandate(&sk, |s| {
        s.pk_blob = build_sk_pubkey_blob(
            SSH_SK_ED25519_SSH_TYPE,
            other_sk.verifying_key().as_bytes(),
            "ssh:",
        );
    });
    assert!(matches!(
        verify_ssh_sk_ed25519(&wrong_pk_in_sig),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("does not match expected signer key")
    ));

    // 10. Signature computed with wrong application string fails Ed25519 verify
    let wrong_app_sig = make_signed_mandate(&sk, |s| s.application_for_signing = "ssh:other");
    assert!(matches!(
        verify_ssh_sk_ed25519(&wrong_app_sig),
        Err(AnchorError::InvalidSignature(_))
    ));
}

#[test]
fn verifier_rejects_tampered_envelope_wrong_assurance_hex_encoding_and_truncation() {
    let sk = SigningKey::from_bytes(&[0x81; 32]);
    let valid = make_signed_mandate(&sk, |_| {});

    // 1. Tampered canonical_words
    let mut tampered_words = valid.clone();
    tampered_words.canonical_words = tampered_words.canonical_words.replace("LIMIT 5", "LIMIT 9");
    assert!(matches!(
        verify_ssh_sk_ed25519(&tampered_words),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 2. Tampered valid_until
    let mut tampered_until = valid.clone();
    tampered_until.valid_until += 60;
    assert!(matches!(
        verify_ssh_sk_ed25519(&tampered_until),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 3. Tampered valid_from
    let mut tampered_from = valid.clone();
    tampered_from.valid_from -= 60;
    assert!(matches!(
        verify_ssh_sk_ed25519(&tampered_from),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 4. Tampered anchor_id
    let mut tampered_anchor = valid.clone();
    tampered_anchor.anchor_id = "other-yubikey".to_string();
    assert!(matches!(
        verify_ssh_sk_ed25519(&tampered_anchor),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 5. Wrong assurance (`local_key` instead of `passkey`)
    let mut wrong_assurance = valid.clone();
    wrong_assurance.assurance = "local_key".to_string();
    assert_eq!(
        verify_ssh_sk_ed25519(&wrong_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::Passkey,
            actual: AssuranceLevel::LocalKey,
        })
    );

    // 6. Uppercase / empty / odd-length signature_hex
    let mut upper_hex = valid.clone();
    upper_hex.signature_hex = upper_hex.signature_hex.to_uppercase();
    assert!(matches!(
        verify_ssh_sk_ed25519(&upper_hex),
        Err(AnchorError::InvalidSignature(m)) if m.contains("lowercase")
    ));

    let mut empty_hex = valid.clone();
    empty_hex.signature_hex.clear();
    assert!(matches!(
        verify_ssh_sk_ed25519(&empty_hex),
        Err(AnchorError::InvalidSignature(m)) if m.contains("non-empty")
    ));

    let mut odd_hex = valid.clone();
    odd_hex.signature_hex.pop();
    assert!(matches!(
        verify_ssh_sk_ed25519(&odd_hex),
        Err(AnchorError::InvalidSignature(m)) if m.contains("even-length")
    ));

    // 7. Truncated SSHSIG at every byte prefix fails cleanly without panicking.
    let raw = hex::decode(&valid.signature_hex).expect("valid hex");
    for cut in [0, 3, 6, 9, 10, 14, 40, raw.len() - 1] {
        let mut truncated = valid.clone();
        truncated.signature_hex = hex::encode(&raw[..cut]);
        assert!(
            matches!(
                verify_ssh_sk_ed25519(&truncated),
                Err(AnchorError::InvalidSignature(_))
            ),
            "truncation at {cut} bytes must fail cleanly"
        );
    }

    // 8. Wrong Ed25519 signature length (63 bytes inside signature blob)
    let mut bad_sig_blob = Vec::new();
    push_ssh_bytes(&mut bad_sig_blob, SSH_SK_ED25519_SSH_TYPE.as_bytes());
    push_ssh_bytes(&mut bad_sig_blob, &[0u8; 63]);
    bad_sig_blob.push(0x01);
    bad_sig_blob.extend_from_slice(&1u32.to_be_bytes());

    let mut bad_sshsig = Vec::new();
    bad_sshsig.extend_from_slice(b"SSHSIG");
    bad_sshsig.extend_from_slice(&1u32.to_be_bytes());
    push_ssh_bytes(
        &mut bad_sshsig,
        &build_sk_pubkey_blob(
            SSH_SK_ED25519_SSH_TYPE,
            sk.verifying_key().as_bytes(),
            "ssh:",
        ),
    );
    push_ssh_bytes(&mut bad_sshsig, SSHSIG_NAMESPACE.as_bytes());
    push_ssh_bytes(&mut bad_sshsig, b"");
    push_ssh_bytes(&mut bad_sshsig, b"sha512");
    push_ssh_bytes(&mut bad_sshsig, &bad_sig_blob);

    let mut bad_len_sig = valid.clone();
    bad_len_sig.signature_hex = hex::encode(bad_sshsig);
    assert!(matches!(
        verify_ssh_sk_ed25519(&bad_len_sig),
        Err(AnchorError::InvalidSignature(m)) if m.contains("64-byte")
    ));

    // 9. Wrong key scheme passed directly to verify_ssh_sk_ed25519
    let mut wrong_scheme = valid;
    wrong_scheme.signer_key = format!("ed25519:{}", hex::encode(sk.verifying_key().as_bytes()));
    assert!(matches!(
        verify_ssh_sk_ed25519(&wrong_scheme),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("ssh-sk-ed25519")
    ));
}

#[cfg(unix)]
#[test]
fn ssh_sk_signer_rejects_non_utf8_key_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let sk = SigningKey::from_bytes(&[0x91; 32]);
    let pub_str = format_openssh_pub(&sk, "ssh:", None);
    let bad_path = PathBuf::from(OsStr::from_bytes(b"non_utf8_\xff.pub"));
    let runner = FakeSshKeygenRunner::new(sk, "ssh:");

    assert!(matches!(
        SshSkSigner::from_pub_str(&bad_path, &pub_str, runner),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("UTF-8")
    ));
}

#[test]
fn ssh_sk_review_remediation_guards_cr_smuggling_weak_keys_dotfiles_and_up_uv() {
    let sk = SigningKey::from_bytes(&[0x55; 32]);
    let other_sk = SigningKey::from_bytes(&[0x66; 32]);
    let valid_pub = format_openssh_pub(&sk, "ssh:", Some("victim@yubikey"));
    let other_pub = format_openssh_pub(&other_sk, "ssh:", None);

    // 1. Bare CR and form-feed control-character smuggling must fail closed.
    let smuggled = format!("{}\r{}\n", other_pub.trim_end(), valid_pub.trim_end());
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&smuggled),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("control characters or bare CR")
    ));
    let cr_sep = valid_pub.replacen(' ', "\r", 1);
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&cr_sep),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("control characters or bare CR")
    ));
    let ff_sep = valid_pub.replacen(' ', "\x0c", 1);
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&ff_sep),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("control characters or bare CR")
    ));

    // 2. Non-UTF-8 optional comment bytes are accepted (matching OpenSSH), while
    //    bare CR / control bytes remain rejected.
    let mut non_utf8_comment = format_openssh_pub(&sk, "ssh:", None)
        .trim_end()
        .as_bytes()
        .to_vec();
    non_utf8_comment.extend_from_slice(b" bob\xff@yubikey\n");
    let parsed_non_utf8 = SshSkPublicKey::parse_openssh_pub_bytes(&non_utf8_comment)
        .expect("non-UTF-8 trailing comment should be accepted");
    assert_eq!(
        parsed_non_utf8.public_key_bytes(),
        sk.verifying_key().as_bytes()
    );

    // 3. Weak/small-order torsion, non-canonical, and non-curve Ed25519 keys are rejected.
    let weak_blob = build_sk_pubkey_blob(SSH_SK_ED25519_SSH_TYPE, &[0u8; 32], "ssh:");
    let weak_pub = format!("{SSH_SK_ED25519_SSH_TYPE} {}\n", encode_base64(&weak_blob));
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&weak_pub),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("weak small-order")
    ));

    // y = p + 3 (non-canonical encoding of y = 3: 0xf0, 0xff..0xff, 0x7f)
    let mut non_canonical_pk = [0xffu8; 32];
    non_canonical_pk[0] = 0xf0;
    non_canonical_pk[31] = 0x7f;
    let nc_blob = build_sk_pubkey_blob(SSH_SK_ED25519_SSH_TYPE, &non_canonical_pk, "ssh:");
    let nc_pub = format!("{SSH_SK_ED25519_SSH_TYPE} {}\n", encode_base64(&nc_blob));
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&nc_pub),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("non-canonical")
    ));

    // Non-curve point ([2, 0, ..., 0] is not a valid compressed Edwards Y point).
    let mut non_curve_pk = [0u8; 32];
    non_curve_pk[0] = 2;
    let bad_pt_blob = build_sk_pubkey_blob(SSH_SK_ED25519_SSH_TYPE, &non_curve_pk, "ssh:");
    let bad_pt_pub = format!(
        "{SSH_SK_ED25519_SSH_TYPE} {}\n",
        encode_base64(&bad_pt_blob)
    );
    assert!(matches!(
        SshSkPublicKey::parse_openssh_pub(&bad_pt_pub),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("invalid Ed25519 public key")
    ));

    // 4. Empty/NUL key paths fail closed, and `.pub` dotfiles resolve cleanly.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let dotpub = dir.path().join(".pub");
    fs::write(&dotpub, &valid_pub).expect("write .pub dotfile");
    let loaded_dotpub = SshSkPublicKey::from_key_path(&dotpub).expect("load .pub dotfile");
    assert_eq!(
        loaded_dotpub.public_key_bytes(),
        sk.verifying_key().as_bytes()
    );

    assert!(matches!(
        SshSkPublicKey::from_key_path(std::path::Path::new("")),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("empty")
    ));
    let runner_empty = FakeSshKeygenRunner::new(sk.clone(), "ssh:");
    assert!(matches!(
        SshSkSigner::from_pub_str("", &valid_pub, runner_empty),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("empty")
    ));
    let runner_nul = FakeSshKeygenRunner::new(sk.clone(), "ssh:");
    assert!(matches!(
        SshSkSigner::from_pub_str("a\0b.pub", &valid_pub, runner_nul),
        Err(AnchorError::InvalidPublicKey(m)) if m.contains("NUL")
    ));
}

#[test]
fn ssh_sk_review_remediation_up_uv_flags_and_inner_sig_blob_truncation() {
    let sk = SigningKey::from_bytes(&[0x55; 32]);
    let valid_pub = format_openssh_pub(&sk, "ssh:", Some("victim@yubikey"));
    let dir = tempfile::TempDir::new().expect("tempdir");
    let dotpub = dir.path().join(".pub");
    fs::write(&dotpub, &valid_pub).expect("write .pub dotfile");

    // 5. Valid UP+UV (flags = 0x05) signature succeeds (not hardcoded to flags == 0x01).
    let parsed_pk = SshSkPublicKey::parse_openssh_pub(&valid_pub).expect("parse valid_pub");
    let agent = Ed25519Keypair::from_secret_bytes([0x77; 32]);
    let words = root_mandate(&parsed_pk.key_id(), &agent.key_id());
    let mut runner_uv = FakeSshKeygenRunner::new(sk.clone(), "ssh:");
    runner_uv.flags = 0x05;
    let signer_uv = SshSkSigner::from_pub_str(dotpub, &valid_pub, runner_uv).expect("signer_uv");
    let signed_uv = sign_mandate_with(
        &signer_uv,
        &words,
        "yubikey-ssh-sk",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign with UP+UV flags=0x05");
    verify_ssh_sk_ed25519(&signed_uv).expect("verify UP+UV flags=0x05");

    // 6. Truncated inner sig_blob (missing flags byte and truncated counter) fails closed.
    let mut inner_no_flags = Vec::new();
    push_ssh_bytes(&mut inner_no_flags, SSH_SK_ED25519_SSH_TYPE.as_bytes());
    push_ssh_bytes(&mut inner_no_flags, &[0x11; 64]);
    for (trunc_inner, expected_msg) in [
        (inner_no_flags.clone(), "FIDO2 flags"),
        (
            {
                let mut v = inner_no_flags;
                v.push(0x01);
                v.extend_from_slice(&[0x00, 0x01]);
                v
            },
            "FIDO2 counter",
        ),
    ] {
        let mut outer = Vec::new();
        outer.extend_from_slice(b"SSHSIG");
        outer.extend_from_slice(&1u32.to_be_bytes());
        push_ssh_bytes(
            &mut outer,
            &build_sk_pubkey_blob(
                SSH_SK_ED25519_SSH_TYPE,
                sk.verifying_key().as_bytes(),
                "ssh:",
            ),
        );
        push_ssh_bytes(&mut outer, SSHSIG_NAMESPACE.as_bytes());
        push_ssh_bytes(&mut outer, b"");
        push_ssh_bytes(&mut outer, b"sha512");
        push_ssh_bytes(&mut outer, &trunc_inner);
        let mut bad = signed_uv.clone();
        bad.signature_hex = hex::encode(outer);
        assert!(matches!(
            verify_ssh_sk_ed25519(&bad),
            Err(AnchorError::InvalidSignature(m)) if m.contains(expected_msg)
        ));
    }
}

#[test]
fn ssh_sk_signer_signs_and_verifies_revocation_via_registry() {
    let dir = tempfile::TempDir::new().unwrap();
    let sk = SigningKey::from_bytes(&[0x61; 32]);
    let pub_line = format_openssh_pub(&sk, "ssh:", Some("yubikey-rev"));
    let key_path = dir.path().join("id_ed25519_sk");
    let pub_path = dir.path().join("id_ed25519_sk.pub");
    fs::write(&key_path, "dummy-handle").unwrap();
    fs::write(&pub_path, &pub_line).unwrap();

    let runner = FakeSshKeygenRunner::new(sk, "ssh:");
    let signer = SshSkSigner::from_key_path(&key_path, runner).unwrap();
    let target = MandateId::sha256(b"ssh-sk-rev-target");
    let words = format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin\" (key: {})\n\
         TARGET mandate {target}\n\
         EFFECTIVE 2026-11-26T17:15:00Z\n\
         REASON \"ssh-sk kill\"\n",
        signer.key_id()
    );
    let signed = handfest_anchors::sign_revocation_with(
        &signer,
        &words,
        "yubikey-ssh-sk",
        ts("2026-11-26T17:00:00Z"),
        ts("2026-11-26T18:00:00Z"),
    )
    .expect("sign SSH-SK revocation");

    let verified = handfest_anchors::verify_revocation_ssh_sk_ed25519(&signed)
        .expect("verify SSH-SK revocation");
    assert_eq!(verified.proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(
        handfest_anchors::verify_revocation(&signed).expect("verify via default registry"),
        verified
    );
}
