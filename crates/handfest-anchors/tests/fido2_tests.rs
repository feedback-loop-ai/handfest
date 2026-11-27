use std::cell::RefCell;
use std::error::Error as _;

use ed25519_dalek::{Signer, SigningKey};
use handfest_anchors::{
    discover_fido2_device, format_fido2_ed25519_key_id, sign_mandate_with, signing_payload,
    verify_chain, verify_fido2_ed25519, AnchorError, AnchorRegistry, AnchorVerifier,
    AssuranceLevel, CommandOutput, CommandRunner, Ed25519Keypair, Fido2AssertionEnvelope,
    Fido2CredentialFile, Fido2Ed25519Signer, Fido2Ed25519Verifier, MandateSigner, SignedMandate,
    DEFAULT_FIDO2_RP_ID, FIDO2_ED25519_SCHEME, FIDO2_ENVELOPE_VERSION, FIDO2_FLAG_UP,
    MIN_AUTH_DATA_LEN,
};
use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId, Scalar};
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::gate::{authorize, ActionRequest, QuotaSnapshot, VerifiedFacts};
use handfest_core::{ActorKind, Verdict};
use sha2::{Digest, Sha256};

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 timestamp")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

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

fn build_auth_data(rp_id: &str, flags: u8, sign_count: u32, extensions: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MIN_AUTH_DATA_LEN + extensions.len());
    out.extend_from_slice(&sha256(rp_id.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out.extend_from_slice(extensions);
    out
}

fn wrap_cbor_bstr(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if raw.len() <= 255 {
        out.push(0x58);
        out.push(u8::try_from(raw.len()).unwrap());
    } else {
        out.push(0x59);
        out.extend_from_slice(&u16::try_from(raw.len()).unwrap().to_be_bytes());
    }
    out.extend_from_slice(raw);
    out
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
            "TO agent \"brokkr:seat:ship\" (key: {to_key})\n",
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

struct RecordedCall {
    _program: String,
    _args: Vec<String>,
    _stdin: Vec<u8>,
}

struct FakeFido2Runner {
    signing_key: SigningKey,
    expected_device: String,
    expected_rp_id: String,
    expected_cred_b64: String,
    token_list_stdout: String,
    wrap_auth_data_cbor: bool,
    flags: u8,
    extensions: Vec<u8>,
    recorded_calls: RefCell<Vec<RecordedCall>>,
}

impl FakeFido2Runner {
    fn new(seed: [u8; 32], device: &str, rp_id: &str, cred_b64: &str) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            expected_device: device.to_string(),
            expected_rp_id: rp_id.to_string(),
            expected_cred_b64: cred_b64.to_string(),
            token_list_stdout: format!(
                "{device}: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n"
            ),
            wrap_auth_data_cbor: true,
            flags: FIDO2_FLAG_UP,
            extensions: Vec::new(),
            recorded_calls: RefCell::new(Vec::new()),
        }
    }
}

impl CommandRunner for FakeFido2Runner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        self.recorded_calls.borrow_mut().push(RecordedCall {
            _program: program.to_string(),
            _args: args.iter().map(|s| (*s).to_string()).collect(),
            _stdin: stdin.to_vec(),
        });

        match program {
            "fido2-token" => {
                assert_eq!(args, &["-L"]);
                assert!(stdin.is_empty());
                Ok(CommandOutput {
                    stdout: self.token_list_stdout.as_bytes().to_vec(),
                    stderr: Vec::new(),
                })
            }
            "fido2-assert" => {
                assert_eq!(args, &["-G", "-t", "up=true", &self.expected_device]);
                let stdin_text = std::str::from_utf8(stdin).expect("utf-8 stdin");
                let lines: Vec<&str> = stdin_text.trim_end_matches('\n').split('\n').collect();
                assert_eq!(lines.len(), 3, "expected 3 stdin lines for fido2-assert");
                assert_eq!(lines[1], self.expected_rp_id);
                assert_eq!(lines[2], self.expected_cred_b64);

                let cdh_b64 = lines[0];
                let cdh = decode_b64_test(cdh_b64);
                assert_eq!(cdh.len(), 32);

                let auth_data =
                    build_auth_data(&self.expected_rp_id, self.flags, 7, &self.extensions);
                let mut signed_msg = auth_data.clone();
                signed_msg.extend_from_slice(&cdh);
                let sig = self.signing_key.sign(&signed_msg);

                let auth_wire = if self.wrap_auth_data_cbor {
                    wrap_cbor_bstr(&auth_data)
                } else {
                    auth_data
                };
                let stdout = format!(
                    "{cdh_b64}\n{}\n{}\n{}\n",
                    self.expected_rp_id,
                    b64_encode(&auth_wire),
                    b64_encode(&sig.to_bytes()),
                );
                Ok(CommandOutput {
                    stdout: stdout.into_bytes(),
                    stderr: Vec::new(),
                })
            }
            other => panic!("unexpected program '{other}'"),
        }
    }
}

fn decode_b64_test(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    for chunk in bytes.as_chunks::<4>().0 {
        let val = |b: u8| -> u8 {
            match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => panic!("bad b64 byte {b}"),
            }
        };
        let (v0, v1, v2, v3) = (val(chunk[0]), val(chunk[1]), val(chunk[2]), val(chunk[3]));
        out.push((v0 << 2) | (v1 >> 4));
        if chunk[2] != b'=' {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if chunk[3] != b'=' {
            out.push((v2 << 6) | v3);
        }
    }
    out
}

fn sign_raw_fido2_envelope(
    signing_key: &SigningKey,
    mut signed: SignedMandate,
    rp_id: &str,
    auth_data: Vec<u8>,
) -> SignedMandate {
    let cdh = sha256(&signing_payload(&signed));
    let mut msg = auth_data.clone();
    msg.extend_from_slice(&cdh);
    let sig = signing_key.sign(&msg).to_bytes();
    let envelope = Fido2AssertionEnvelope {
        rp_id: rp_id.to_string(),
        auth_data,
        signature: sig,
    };
    signed.signature_hex = hex::encode(envelope.encode().expect("encode envelope"));
    signed
}

#[derive(Debug)]
struct StaticRunner(Result<CommandOutput, AnchorError>);

impl CommandRunner for StaticRunner {
    fn run(
        &self,
        _program: &str,
        _args: &[&str],
        _stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        self.0.clone()
    }
}

#[test]
fn fido2_signer_cbor_stdout_end_to_end_verify_chain_and_authorize() {
    let seed = [0x33u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pub_bytes = sk.verifying_key().to_bytes();
    let cred_b64 = b64_encode(b"yubikey-cred-id-01");
    let key_id = format_fido2_ed25519_key_id(&pub_bytes).expect("valid fido2 KeyId");
    assert_eq!(key_id.scheme(), FIDO2_ED25519_SCHEME);

    let cred_file = Fido2CredentialFile {
        rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
        credential_id_b64: cred_b64.clone(),
        key_id: key_id.to_string(),
    };

    let runner = FakeFido2Runner::new(seed, "/dev/hidraw0", DEFAULT_FIDO2_RP_ID, &cred_b64);
    let signer = Fido2Ed25519Signer::from_credential_file(
        runner,
        &cred_file,
        Some("/dev/hidraw0".to_string()),
    )
    .expect("construct signer from credential file");
    assert_eq!(signer.key_id(), key_id);
    assert_eq!(signer.assurance(), AssuranceLevel::Passkey);
    assert_eq!(signer.rp_id(), DEFAULT_FIDO2_RP_ID);

    let dispatcher_kp = Ed25519Keypair::from_secret_bytes([0x44; 32]);
    let worker_kp = Ed25519Keypair::from_secret_bytes([0x55; 32]);

    let root_words = root_mandate(&key_id, &dispatcher_kp.key_id());
    let root_signed = sign_mandate_with(
        &signer,
        &root_words,
        "yubikey-fido2",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign root mandate with Fido2Ed25519Signer");

    assert_eq!(root_signed.assurance, "passkey");
    assert_eq!(root_signed.anchor_id, "yubikey-fido2");
    assert_eq!(root_signed.signer_key, key_id.to_string());
    assert_eq!(root_signed.actor_kind, "human");

    // Verify directly, via trait impl, via default_registry, and via verify_chain.
    let vm_direct = verify_fido2_ed25519(&root_signed).expect("verify_fido2_ed25519");
    let vm_trait = Fido2Ed25519Verifier
        .verify(&root_signed)
        .expect("Fido2Ed25519Verifier::verify");
    let vm_registry = AnchorRegistry::default_registry()
        .verify(&root_signed)
        .expect("AnchorRegistry::default_registry verifies fido2-ed25519");
    assert_eq!(vm_direct, vm_trait);
    assert_eq!(vm_direct, vm_registry);
    assert_eq!(vm_direct.proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(vm_direct.proof.actor_kind, ActorKind::Human);
    assert_eq!(vm_direct.proof.signer_key, key_id);
    assert_eq!(vm_direct.proof.anchor_id, "yubikey-fido2");

    // Mixed delegation chain: FIDO2 Passkey root -> Ed25519 LocalKey child -> authorize().
    let parent_id = vm_direct.ast.mandate_id();
    let child_words = child_mandate(parent_id, &dispatcher_kp.key_id(), &worker_kp.key_id());
    let child_signed = dispatcher_kp
        .sign_mandate(
            &child_words,
            "local-ed25519",
            ts("2026-11-24T17:30:00Z"),
            ts("2026-11-24T20:00:00Z"),
        )
        .expect("sign child mandate");

    let verified_chain =
        verify_chain(&[root_signed, child_signed]).expect("verify mixed fido2 + ed25519 chain");
    assert_eq!(verified_chain.len(), 2);
    assert_eq!(verified_chain[0].proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verified_chain[1].proof.assurance, AssuranceLevel::LocalKey);

    let req = ActionRequest {
        actor_key: worker_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let mut facts = VerifiedFacts::new();
    facts.insert("resource.author", Scalar::Str("valentin".to_string()));
    let (verdict, _receipt) = authorize(
        &verified_chain,
        &req,
        &facts,
        &QuotaSnapshot::default(),
        ts("2026-11-24T18:30:00Z"),
        None,
    );
    assert_eq!(verdict, Verdict::Permit);
}

#[test]
fn fido2_signer_auto_discovery_raw_auth_data_and_large_extensions() {
    let seed = [0x66u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pub_bytes = sk.verifying_key().to_bytes();
    let cred_b64 = b64_encode(b"cred-extensions-02");
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x77; 32]);

    // Case 1: Auto-discover macOS ioreg:// path + raw (non-CBOR) auth_data with UP | UV flags.
    let mut raw_runner =
        FakeFido2Runner::new(seed, "ioreg://4294971234", "corp.example.com", &cred_b64);
    raw_runner.wrap_auth_data_cbor = false;
    raw_runner.flags = FIDO2_FLAG_UP | 0x04;
    raw_runner.extensions = vec![0xa1, 0x63, b'f', b'o', b'o', 0xf5]; // small extension
    let signer = Fido2Ed25519Signer::new(
        raw_runner,
        None,
        "corp.example.com",
        cred_b64.clone(),
        pub_bytes,
    )
    .expect("construct auto-discovering signer");

    let words = root_mandate(&signer.key_id(), &agent_kp.key_id());
    let signed = sign_mandate_with(
        &signer,
        &words,
        "yubikey-fido2",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign with auto-discovery and raw auth_data");
    let verified = verify_chain(&[signed]).expect("verify raw auth_data with extensions");
    assert_eq!(verified[0].proof.assurance, AssuranceLevel::Passkey);

    // Case 2: Large CTAP2 extensions (>= 256 bytes total auth_data -> CBOR 0x59 header).
    let mut large_runner =
        FakeFido2Runner::new(seed, "/dev/hidraw3", DEFAULT_FIDO2_RP_ID, &cred_b64);
    large_runner.wrap_auth_data_cbor = true;
    large_runner.extensions = vec![0xab; 300];
    let large_signer = Fido2Ed25519Signer::new(
        large_runner,
        Some("/dev/hidraw3".to_string()),
        DEFAULT_FIDO2_RP_ID,
        cred_b64,
        pub_bytes,
    )
    .expect("construct large-extension signer");
    let large_signed = sign_mandate_with(
        &large_signer,
        &words,
        "yubikey-fido2",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign with >= 256-byte CBOR auth_data");
    let verified_large = verify_chain(&[large_signed]).expect("verify large CBOR auth_data");
    assert_eq!(verified_large.len(), 1);
}

#[test]
fn fido2_verifier_rejects_missing_up_flag() {
    let sk = SigningKey::from_bytes(&[0x11; 32]);
    let key_id = format_fido2_ed25519_key_id(&sk.verifying_key().to_bytes()).unwrap();
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x22; 32]);
    let words = root_mandate(&key_id, &agent_kp.key_id());

    let skeleton = SignedMandate {
        canonical_words: words,
        anchor_id: "yubikey-fido2".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: key_id.to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: String::new(),
    };

    // UP=0, UV=0 and UP=0, UV=1 (0x04) must BOTH be rejected even with a valid Ed25519 signature.
    for bad_flags in [0x00u8, 0x04u8, 0xfe_u8] {
        let auth_data = build_auth_data(DEFAULT_FIDO2_RP_ID, bad_flags, 1, &[]);
        let signed = sign_raw_fido2_envelope(&sk, skeleton.clone(), DEFAULT_FIDO2_RP_ID, auth_data);
        let err = verify_fido2_ed25519(&signed).unwrap_err();
        assert!(
            matches!(&err, AnchorError::InvalidSignature(msg) if msg.contains("UP")),
            "expected UP flag rejection for flags=0x{bad_flags:02x}, got {err:?}"
        );
        assert!(matches!(
            AnchorRegistry::default_registry().verify(&signed),
            Err(AnchorError::InvalidSignature(_))
        ));
    }

    // Control check: UP=1 | UV=1 (0x05) succeeds.
    let good_auth = build_auth_data(DEFAULT_FIDO2_RP_ID, FIDO2_FLAG_UP | 0x04, 1, &[]);
    let good_signed = sign_raw_fido2_envelope(&sk, skeleton, DEFAULT_FIDO2_RP_ID, good_auth);
    assert!(verify_fido2_ed25519(&good_signed).is_ok());
}

#[test]
fn fido2_verifier_rejects_rpid_hash_mismatch_and_invalid_rpid() {
    let sk = SigningKey::from_bytes(&[0x12; 32]);
    let key_id = format_fido2_ed25519_key_id(&sk.verifying_key().to_bytes()).unwrap();
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x23; 32]);
    let words = root_mandate(&key_id, &agent_kp.key_id());

    let skeleton = SignedMandate {
        canonical_words: words,
        anchor_id: "yubikey-fido2".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: key_id.to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: String::new(),
    };

    // Mismatched rpIdHash inside auth_data vs envelope rp_id.
    let wrong_rp_auth = build_auth_data("evil.example", FIDO2_FLAG_UP, 1, &[]);
    let signed_mismatch =
        sign_raw_fido2_envelope(&sk, skeleton.clone(), DEFAULT_FIDO2_RP_ID, wrong_rp_auth);
    let err = verify_fido2_ed25519(&signed_mismatch).unwrap_err();
    assert!(
        matches!(&err, AnchorError::InvalidSignature(msg) if msg.contains("rpIdHash")),
        "expected rpIdHash mismatch error, got {err:?}"
    );

    // Envelope encode/decode rejects invalid rp_ids: empty, control char, whitespace, >255 bytes.
    let valid_auth = build_auth_data(DEFAULT_FIDO2_RP_ID, FIDO2_FLAG_UP, 1, &[]);
    let too_long_rp = "a".repeat(256);
    for bad_rp in [
        "",
        "handfest\n.local",
        "handfest\0.local",
        "handfest .local",
        &too_long_rp,
    ] {
        let env = Fido2AssertionEnvelope {
            rp_id: bad_rp.to_string(),
            auth_data: valid_auth.clone(),
            signature: [0u8; 64],
        };
        assert!(
            matches!(env.encode(), Err(AnchorError::InvalidSignature(_))),
            "encode must reject bad rp_id '{bad_rp:?}'"
        );

        // Also craft raw wire bytes directly to test decode() and verify_fido2_ed25519().
        let mut raw = vec![FIDO2_ENVELOPE_VERSION];
        raw.extend_from_slice(&u16::try_from(bad_rp.len()).unwrap().to_be_bytes());
        raw.extend_from_slice(bad_rp.as_bytes());
        raw.extend_from_slice(&u32::try_from(valid_auth.len()).unwrap().to_be_bytes());
        raw.extend_from_slice(&valid_auth);
        raw.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            Fido2AssertionEnvelope::decode(&raw),
            Err(AnchorError::InvalidSignature(_))
        ));
        let mut bad_signed = skeleton.clone();
        bad_signed.signature_hex = hex::encode(&raw);
        assert!(matches!(
            verify_fido2_ed25519(&bad_signed),
            Err(AnchorError::InvalidSignature(_))
        ));
    }

    // Non-UTF-8 rp_id bytes rejected by decode().
    let mut non_utf8 = vec![FIDO2_ENVELOPE_VERSION, 0, 2, 0xff, 0xfe];
    non_utf8.extend_from_slice(&u32::try_from(valid_auth.len()).unwrap().to_be_bytes());
    non_utf8.extend_from_slice(&valid_auth);
    non_utf8.extend_from_slice(&[0u8; 64]);
    assert!(matches!(
        Fido2AssertionEnvelope::decode(&non_utf8),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("UTF-8")
    ));
}

#[test]
fn fido2_verifier_rejects_truncated_oversized_and_trailing_envelope_bytes() {
    let sk = SigningKey::from_bytes(&[0x13; 32]);
    let key_id = format_fido2_ed25519_key_id(&sk.verifying_key().to_bytes()).unwrap();
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x24; 32]);
    let words = root_mandate(&key_id, &agent_kp.key_id());

    let skeleton = SignedMandate {
        canonical_words: words,
        anchor_id: "yubikey-fido2".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: key_id.to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: String::new(),
    };

    let valid_auth = build_auth_data(DEFAULT_FIDO2_RP_ID, FIDO2_FLAG_UP, 3, &[]);
    let valid_signed = sign_raw_fido2_envelope(
        &sk,
        skeleton.clone(),
        DEFAULT_FIDO2_RP_ID,
        valid_auth.clone(),
    );

    // Trailing byte(s) appended to signature_hex must be rejected.
    let mut with_trailing = valid_signed.clone();
    with_trailing.signature_hex.push_str("00");
    let err = verify_fido2_ed25519(&with_trailing).unwrap_err();
    assert!(
        matches!(&err, AnchorError::InvalidSignature(msg) if msg.contains("trailing")),
        "expected trailing bytes rejection, got {err:?}"
    );

    // Truncated auth_data (< 37 bytes: 0 and 36 bytes) and oversized auth_data (> 16384).
    for bad_len in [0usize, 36, 16_385] {
        let bad_env = Fido2AssertionEnvelope {
            rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
            auth_data: vec![0u8; bad_len],
            signature: [0u8; 64],
        };
        assert!(matches!(
            bad_env.encode(),
            Err(AnchorError::InvalidSignature(_))
        ));

        let mut raw = vec![FIDO2_ENVELOPE_VERSION];
        raw.extend_from_slice(
            &u16::try_from(DEFAULT_FIDO2_RP_ID.len())
                .unwrap()
                .to_be_bytes(),
        );
        raw.extend_from_slice(DEFAULT_FIDO2_RP_ID.as_bytes());
        raw.extend_from_slice(&u32::try_from(bad_len).unwrap().to_be_bytes());
        if bad_len <= 40 {
            raw.extend_from_slice(&vec![0u8; bad_len]);
            raw.extend_from_slice(&[0u8; 64]);
        }
        assert!(matches!(
            Fido2AssertionEnvelope::decode(&raw),
            Err(AnchorError::InvalidSignature(_))
        ));
    }

    // Wrong version byte (0 and 2) and truncation at every prefix length.
    let valid_raw = hex::decode(&valid_signed.signature_hex).unwrap();
    for bad_ver in [0u8, 2u8] {
        let mut wrong_ver = valid_raw.clone();
        wrong_ver[0] = bad_ver;
        assert!(matches!(
            Fido2AssertionEnvelope::decode(&wrong_ver),
            Err(AnchorError::InvalidSignature(msg)) if msg.contains("version")
        ));
    }
    for prefix_len in [0usize, 1, 2, 5, 18, 21, valid_raw.len() - 1] {
        assert!(matches!(
            Fido2AssertionEnvelope::decode(&valid_raw[..prefix_len]),
            Err(AnchorError::InvalidSignature(_))
        ));
    }

    // Hex encoding guards: empty, odd-length, uppercase, non-hex, oversized.
    let oversized_hex = "aa".repeat(20_000);
    for bad_hex in [
        "",
        "abc",
        &valid_signed.signature_hex.to_uppercase(),
        "zzzz",
        &oversized_hex,
    ] {
        let mut bad = valid_signed.clone();
        bad.signature_hex = bad_hex.to_string();
        assert!(matches!(
            verify_fido2_ed25519(&bad),
            Err(AnchorError::InvalidSignature(_))
        ));
    }
}

#[test]
fn fido2_verifier_rejects_envelope_and_mandate_tampering() {
    let sk = SigningKey::from_bytes(&[0x14; 32]);
    let key_id = format_fido2_ed25519_key_id(&sk.verifying_key().to_bytes()).unwrap();
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x25; 32]);
    let words = root_mandate(&key_id, &agent_kp.key_id());

    let cred_b64 = b64_encode(b"tamper-cred");
    let runner = FakeFido2Runner::new([0x14; 32], "/dev/hidraw0", DEFAULT_FIDO2_RP_ID, &cred_b64);
    let signer = Fido2Ed25519Signer::new(
        runner,
        Some("/dev/hidraw0".to_string()),
        DEFAULT_FIDO2_RP_ID,
        cred_b64,
        sk.verifying_key().to_bytes(),
    )
    .unwrap();
    let valid = sign_mandate_with(
        &signer,
        &words,
        "yubikey-fido2",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .unwrap();

    // 1. Tampered canonical_words (still canonical, changed LIMIT 5 -> LIMIT 6).
    let mut bad_words = valid.clone();
    bad_words.canonical_words = valid
        .canonical_words
        .replace("LIMIT 5 calls", "LIMIT 6 calls");
    assert!(matches!(
        verify_fido2_ed25519(&bad_words),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 2. Tampered valid_from / valid_until / anchor_id.
    let mut bad_from = valid.clone();
    bad_from.valid_from += 1;
    assert!(matches!(
        verify_fido2_ed25519(&bad_from),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut bad_until = valid.clone();
    bad_until.valid_until -= 1;
    assert!(matches!(
        verify_fido2_ed25519(&bad_until),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut bad_anchor = valid.clone();
    bad_anchor.anchor_id = "other-anchor".to_string();
    assert!(matches!(
        verify_fido2_ed25519(&bad_anchor),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 3. Wrong assurance ("local_key" -> UnsupportedAssurance).
    let mut bad_assurance = valid.clone();
    bad_assurance.assurance = "local_key".to_string();
    assert_eq!(
        verify_fido2_ed25519(&bad_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::Passkey,
            actual: AssuranceLevel::LocalKey,
        })
    );

    // 4. Wrong actor_kind -> ActorKindMismatch.
    let mut bad_actor = valid.clone();
    bad_actor.actor_kind = "agent".to_string();
    assert_eq!(
        verify_fido2_ed25519(&bad_actor),
        Err(AnchorError::ActorKindMismatch {
            expected: ActorKind::Human,
            actual: ActorKind::Agent,
        })
    );

    // 5. Wrong scheme in signer_key -> InvalidPublicKey; different fido2 key -> SignerMismatch.
    let mut wrong_scheme = valid.clone();
    wrong_scheme.signer_key = format!("ed25519:{}", key_id.value());
    assert!(matches!(
        verify_fido2_ed25519(&wrong_scheme),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    let other_sk = SigningKey::from_bytes(&[0x99; 32]);
    let other_key = format_fido2_ed25519_key_id(&other_sk.verifying_key().to_bytes()).unwrap();
    let mut wrong_key = valid.clone();
    wrong_key.signer_key = other_key.to_string();
    assert_eq!(
        verify_fido2_ed25519(&wrong_key),
        Err(AnchorError::SignerMismatch {
            expected: key_id.to_string(),
            actual: other_key.to_string(),
        })
    );

    // 6. Bit-flipped Ed25519 signature bytes -> InvalidSignature.
    let mut raw = hex::decode(&valid.signature_hex).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let mut bad_sig = valid.clone();
    bad_sig.signature_hex = hex::encode(raw);
    assert!(matches!(
        verify_fido2_ed25519(&bad_sig),
        Err(AnchorError::InvalidSignature(_))
    ));
}

#[test]
fn fido2_credential_file_and_signer_constructor_validation() {
    let sk = SigningKey::from_bytes(&[0x15; 32]);
    let pub_bytes = sk.verifying_key().to_bytes();
    let key_id = format_fido2_ed25519_key_id(&pub_bytes).unwrap();
    let ok_cred = b64_encode(b"valid-cred-id");

    // Serde deny_unknown_fields rejects unknown fields and missing required fields.
    let unknown_json = format!(
        r#"{{"rp_id":"handfest.local","credential_id_b64":"{ok_cred}","key_id":"{key_id}","extra":1}}"#
    );
    assert!(serde_json::from_str::<Fido2CredentialFile>(&unknown_json).is_err());
    let missing_rp_json = format!(r#"{{"credential_id_b64":"{ok_cred}","key_id":"{key_id}"}}"#);
    assert!(serde_json::from_str::<Fido2CredentialFile>(&missing_rp_json).is_err());

    let dummy = || {
        StaticRunner(Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }))
    };

    // Invalid rp_id values.
    let too_long_rp = "x".repeat(256);
    for bad_rp in ["", "bad\nrp", "bad rp", &too_long_rp] {
        let err = Fido2Ed25519Signer::new(dummy(), None, bad_rp, &ok_cred, pub_bytes).unwrap_err();
        assert!(matches!(err, AnchorError::InvalidCredential(_)));
    }

    // Invalid credential_id_b64 values: empty, bad base64, non-canonical padding, oversized > 1024 bytes.
    let huge_cred = b64_encode(&vec![0xaa; 1025]);
    for bad_cred in ["", "not-valid-b64!", "Zh==", &huge_cred] {
        let err = Fido2Ed25519Signer::new(dummy(), None, DEFAULT_FIDO2_RP_ID, bad_cred, pub_bytes)
            .unwrap_err();
        assert!(matches!(err, AnchorError::InvalidCredential(_)));
    }

    // Invalid device paths: empty, leading '-', control char.
    for bad_dev in ["", "-G", "/dev/hidraw0\n"] {
        let err = Fido2Ed25519Signer::new(
            dummy(),
            Some(bad_dev.to_string()),
            DEFAULT_FIDO2_RP_ID,
            &ok_cred,
            pub_bytes,
        )
        .unwrap_err();
        assert!(matches!(err, AnchorError::InvalidCredential(_)));
    }

    // Invalid public key (not a valid compressed Edwards25519 point: y = 2 has no square root).
    let mut bad_point = [0u8; 32];
    bad_point[0] = 2;
    assert!(matches!(
        format_fido2_ed25519_key_id(&bad_point),
        Err(AnchorError::InvalidPublicKey(_))
    ));
    assert!(matches!(
        Fido2Ed25519Signer::new(dummy(), None, DEFAULT_FIDO2_RP_ID, &ok_cred, bad_point),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // Wrong scheme in Fido2CredentialFile.
    let wrong_scheme_file = Fido2CredentialFile {
        rp_id: DEFAULT_FIDO2_RP_ID.to_string(),
        credential_id_b64: ok_cred,
        key_id: format!("ed25519:{}", hex::encode(pub_bytes)),
    };
    assert!(matches!(
        Fido2Ed25519Signer::from_credential_file(dummy(), &wrong_scheme_file, None),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // Display + Error::source coverage for InvalidCredential.
    let err = AnchorError::InvalidCredential("missing token".to_string());
    assert_eq!(err.to_string(), "invalid anchor credential: missing token");
    assert!(err.source().is_none());
}

#[test]
fn discover_fido2_device_handles_all_outputs_and_failures() {
    let linux = StaticRunner(Ok(CommandOutput {
        stdout: b"/dev/hidraw0: vendor=0x1050, product=0x0407 (Yubico YubiKey)\n".to_vec(),
        stderr: Vec::new(),
    }));
    assert_eq!(discover_fido2_device(&linux).unwrap(), "/dev/hidraw0");

    let macos = StaticRunner(Ok(CommandOutput {
        stdout: b"\nioreg://4294971234: vendor=0x1050, product=0x0407 (YubiKey)\n\n".to_vec(),
        stderr: Vec::new(),
    }));
    assert_eq!(discover_fido2_device(&macos).unwrap(), "ioreg://4294971234");

    let bare = StaticRunner(Ok(CommandOutput {
        stdout: b"/dev/hidraw2\n".to_vec(),
        stderr: Vec::new(),
    }));
    assert_eq!(discover_fido2_device(&bare).unwrap(), "/dev/hidraw2");

    // 0 devices -> InvalidCredential.
    let none = StaticRunner(Ok(CommandOutput {
        stdout: b"   \n".to_vec(),
        stderr: Vec::new(),
    }));
    assert!(matches!(
        discover_fido2_device(&none),
        Err(AnchorError::InvalidCredential(msg)) if msg.contains("no FIDO2")
    ));

    // 2 devices -> InvalidCredential (ambiguous).
    let two = StaticRunner(Ok(CommandOutput {
        stdout: b"/dev/hidraw0: vendor=0x1050\n/dev/hidraw1: vendor=0x1050\n".to_vec(),
        stderr: Vec::new(),
    }));
    assert!(matches!(
        discover_fido2_device(&two),
        Err(AnchorError::InvalidCredential(msg)) if msg.contains("multiple FIDO2")
    ));

    // Non-UTF-8 stdout -> InvalidCredential.
    let non_utf8 = StaticRunner(Ok(CommandOutput {
        stdout: vec![0xff, 0xfe],
        stderr: Vec::new(),
    }));
    assert!(matches!(
        discover_fido2_device(&non_utf8),
        Err(AnchorError::InvalidCredential(msg)) if msg.contains("UTF-8")
    ));

    // Leading '-' or empty path before ': ' -> InvalidCredential.
    for bad_line in [b": vendor=0x1050\n".as_slice(), b"-bad: vendor=0x1050\n"] {
        let runner = StaticRunner(Ok(CommandOutput {
            stdout: bad_line.to_vec(),
            stderr: Vec::new(),
        }));
        assert!(matches!(
            discover_fido2_device(&runner),
            Err(AnchorError::InvalidCredential(_))
        ));
    }

    // Command failure propagates cleanly.
    let failed = StaticRunner(Err(AnchorError::CommandFailed {
        program: "fido2-token".to_string(),
        status: Some(1),
        stderr: "permission denied".to_string(),
    }));
    assert!(matches!(
        discover_fido2_device(&failed),
        Err(AnchorError::CommandFailed { .. })
    ));
}

#[test]
fn fido2_signer_rejects_malformed_fido2_assert_stdout_and_errors() {
    let sk = SigningKey::from_bytes(&[0x16; 32]);
    let pub_bytes = sk.verifying_key().to_bytes();
    let payload = b"handfest-test-payload";
    let cdh = sha256(payload);
    let cdh_b64 = b64_encode(&cdh);
    let cred_b64 = b64_encode(b"cred-stdout-tests");

    let valid_auth = build_auth_data(DEFAULT_FIDO2_RP_ID, FIDO2_FLAG_UP, 9, &[]);
    let mut signed_msg = valid_auth.clone();
    signed_msg.extend_from_slice(&cdh);
    let valid_sig = sk.sign(&signed_msg).to_bytes();
    let valid_auth_b64 = b64_encode(&wrap_cbor_bstr(&valid_auth));
    let valid_sig_b64 = b64_encode(&valid_sig);

    let run_with_stdout = |stdout: Vec<u8>| {
        let signer = Fido2Ed25519Signer::new(
            StaticRunner(Ok(CommandOutput {
                stdout,
                stderr: Vec::new(),
            })),
            Some("/dev/hidraw0".to_string()),
            DEFAULT_FIDO2_RP_ID,
            cred_b64.clone(),
            pub_bytes,
        )
        .unwrap();
        signer.sign_payload(payload)
    };

    // Valid CRLF stdout succeeds.
    let crlf_ok =
        format!("{cdh_b64}\r\n{DEFAULT_FIDO2_RP_ID}\r\n{valid_auth_b64}\r\n{valid_sig_b64}\r\n");
    assert!(run_with_stdout(crlf_ok.into_bytes()).is_ok());

    // 1. Non-UTF-8 stdout.
    assert!(matches!(
        run_with_stdout(vec![0xff, 0xfe]),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("UTF-8")
    ));

    // 2. Wrong line count (empty, 3 lines, 5 lines).
    for bad_lines in [
        "".to_string(),
        format!("{cdh_b64}\n{DEFAULT_FIDO2_RP_ID}\n{valid_auth_b64}\n"),
        format!("{cdh_b64}\n{DEFAULT_FIDO2_RP_ID}\n{valid_auth_b64}\n{valid_sig_b64}\nextra\n"),
    ] {
        assert!(matches!(
            run_with_stdout(bad_lines.into_bytes()),
            Err(AnchorError::InvalidSignature(msg)) if msg.contains("expected 4 lines")
        ));
    }

    // 3. Invalid base64 cdh and mismatched cdh.
    let bad_cdh_b64 = format!("!!!\n{DEFAULT_FIDO2_RP_ID}\n{valid_auth_b64}\n{valid_sig_b64}\n");
    assert!(matches!(
        run_with_stdout(bad_cdh_b64.into_bytes()),
        Err(AnchorError::InvalidSignature(_))
    ));
    let wrong_cdh = b64_encode(&[0xaa; 32]);
    let mismatch_cdh =
        format!("{wrong_cdh}\n{DEFAULT_FIDO2_RP_ID}\n{valid_auth_b64}\n{valid_sig_b64}\n");
    assert!(matches!(
        run_with_stdout(mismatch_cdh.into_bytes()),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("client_data_hash")
    ));

    // 4. Echoed rp_id mismatch.
    let wrong_rp = format!("{cdh_b64}\nevil.local\n{valid_auth_b64}\n{valid_sig_b64}\n");
    assert!(matches!(
        run_with_stdout(wrong_rp.into_bytes()),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("rp_id")
    ));
}

#[test]
fn fido2_signer_rejects_bad_auth_data_signature_and_command_errors() {
    let sk = SigningKey::from_bytes(&[0x16; 32]);
    let pub_bytes = sk.verifying_key().to_bytes();
    let payload = b"handfest-test-payload";
    let cdh = sha256(payload);
    let cdh_b64 = b64_encode(&cdh);
    let cred_b64 = b64_encode(b"cred-stdout-tests");

    let valid_auth = build_auth_data(DEFAULT_FIDO2_RP_ID, FIDO2_FLAG_UP, 9, &[]);
    let mut signed_msg = valid_auth.clone();
    signed_msg.extend_from_slice(&cdh);
    let valid_sig = sk.sign(&signed_msg).to_bytes();
    let valid_auth_b64 = b64_encode(&wrap_cbor_bstr(&valid_auth));
    let valid_sig_b64 = b64_encode(&valid_sig);

    let run_with_stdout = |stdout: Vec<u8>| {
        let signer = Fido2Ed25519Signer::new(
            StaticRunner(Ok(CommandOutput {
                stdout,
                stderr: Vec::new(),
            })),
            Some("/dev/hidraw0".to_string()),
            DEFAULT_FIDO2_RP_ID,
            cred_b64.clone(),
            pub_bytes,
        )
        .unwrap();
        signer.sign_payload(payload)
    };

    // 5. Invalid base64 auth_data, malformed CBOR, wrong rpIdHash, UP=0.
    let bad_auth_b64 = format!("{cdh_b64}\n{DEFAULT_FIDO2_RP_ID}\n!!!\n{valid_sig_b64}\n");
    assert!(matches!(
        run_with_stdout(bad_auth_b64.into_bytes()),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Non-canonical CBOR headers: 0x58 with len < 24, 0x59 with len < 256, truncated 0x59, wrong rpIdHash.
    let bad_auth_blobs: [Vec<u8>; 7] = [
        Vec::new(),
        vec![0x58],
        vec![0x58, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        {
            let mut b = vec![0x59, 0x00, 0x25];
            b.extend_from_slice(&valid_auth);
            b
        },
        vec![0x59, 0x01],
        wrap_cbor_bstr(&build_auth_data("wrong.rp", FIDO2_FLAG_UP, 1, &[])),
        build_auth_data(DEFAULT_FIDO2_RP_ID, 0x00, 1, &[]),
    ];
    for blob in bad_auth_blobs {
        let out = format!(
            "{cdh_b64}\n{DEFAULT_FIDO2_RP_ID}\n{}\n{valid_sig_b64}\n",
            b64_encode(&blob)
        );
        assert!(matches!(
            run_with_stdout(out.into_bytes()),
            Err(AnchorError::InvalidSignature(_))
        ));
    }

    // 6. Invalid base64 signature, wrong signature length (63 bytes), and wrong-key signature.
    let bad_sig_b64 = format!("{cdh_b64}\n{DEFAULT_FIDO2_RP_ID}\n{valid_auth_b64}\n!!!\n");
    assert!(matches!(
        run_with_stdout(bad_sig_b64.into_bytes()),
        Err(AnchorError::InvalidSignature(_))
    ));

    let short_sig = format!(
        "{cdh_b64}\n{DEFAULT_FIDO2_RP_ID}\n{valid_auth_b64}\n{}\n",
        b64_encode(&[0u8; 63])
    );
    assert!(matches!(
        run_with_stdout(short_sig.into_bytes()),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("64-byte")
    ));

    let other_sk = SigningKey::from_bytes(&[0x99; 32]);
    let wrong_key_sig = b64_encode(&other_sk.sign(&signed_msg).to_bytes());
    let wrong_sig_out =
        format!("{cdh_b64}\n{DEFAULT_FIDO2_RP_ID}\n{valid_auth_b64}\n{wrong_key_sig}\n");
    assert!(matches!(
        run_with_stdout(wrong_sig_out.into_bytes()),
        Err(AnchorError::InvalidSignature(_))
    ));
}

#[test]
fn fido2_signer_propagates_command_and_discovery_errors() {
    let sk = SigningKey::from_bytes(&[0x16; 32]);
    let pub_bytes = sk.verifying_key().to_bytes();
    let payload = b"handfest-test-payload";
    let cred_b64 = b64_encode(b"cred-stdout-tests");

    // 7. Command failure propagates cleanly.
    let fail_signer = Fido2Ed25519Signer::new(
        StaticRunner(Err(AnchorError::CommandFailed {
            program: "fido2-assert".to_string(),
            status: Some(1),
            stderr: "FIDO_ERR_UP_REQUIRED".to_string(),
        })),
        Some("/dev/hidraw0".to_string()),
        DEFAULT_FIDO2_RP_ID,
        cred_b64,
        pub_bytes,
    )
    .unwrap();
    assert!(matches!(
        fail_signer.sign_payload(payload),
        Err(AnchorError::CommandFailed { .. })
    ));

    // 8. Auto-discovery failure during sign_payload propagates InvalidCredential.
    let no_device_signer = Fido2Ed25519Signer::new(
        StaticRunner(Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        })),
        None,
        DEFAULT_FIDO2_RP_ID,
        b64_encode(b"cred-no-dev"),
        pub_bytes,
    )
    .unwrap();
    assert!(matches!(
        no_device_signer.sign_payload(payload),
        Err(AnchorError::InvalidCredential(_))
    ));
}
