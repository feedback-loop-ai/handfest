use std::cell::RefCell;
use std::rc::Rc;

use ed25519_dalek::{Signer, SigningKey};
use handfest_anchors::{
    extract_ed25519_public_key, extract_ed25519_public_key_for_fingerprint, openpgp_ed25519_key_id,
    sign_mandate_with, signing_payload, verify_chain, verify_openpgp_ed25519, AnchorError,
    AnchorRegistry, AnchorVerifier, AssuranceLevel, CommandOutput, CommandRunner, Ed25519Keypair,
    MandateSigner, OpenPgpEd25519Signer, OpenPgpEd25519Verifier, SignedMandate,
    OPENPGP_ED25519_SCHEME,
};
use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId, Scalar};
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::gate::{authorize, ActionRequest, QuotaSnapshot, VerifiedFacts};
use handfest_core::Verdict;
use sha2::{Digest, Sha256, Sha512};

// Real GnuPG 2.4.8 captured fixture (primary certify-only Ed25519 + Ed25519 signing subkey):
const GPG_PRIMARY_FPR: &str = "756878CA12DE0126F5DF550CF97D8F5818FCA00A";
const GPG_SUBKEY_FPR: &str = "4612CBB5F1D1C8D6FF9B7F885351A67FB2E038C2";
const GPG_SUBKEY_LONG_ID: &str = "5351A67FB2E038C2";
const GPG_PRIMARY_PUB_HEX: &str =
    "51fb4c4702a53588dc17250ee24fac2fe596d77225e0dab05f71937f861409c1";
const GPG_SUBKEY_PUB_HEX: &str = "9e9015d13c1e225eaa426b857f4fbf2ff151a6f1af566824dca2cf145863a269";
const GPG_EXPORT_HEX: &str = concat!(
    "9833046b088eaa16092b06010401da470f0101074051fb4c4702a53588dc17250ee24fac2fe596d77225e0dab05f71937f861409c1",
    "b41f56616c656e74696e203c76616c656e74696e406578616d706c652e636f6d3e",
    "88900413160a0038162104756878ca12de0126f5df550cf97d8f5818fca00a05026b088eaa021b01050b0908070206150a09080b020416020301021e01021780000a0910f97d8f5818fca00a59590100e04c8399185b031b3c069ab5ef06839c65268a15d0da4bdc3af5006e525570610100ca1d13d28d1c2852babf886f708f4dfcce12eac61244ea585182a33e9bb92206",
    "b833046b088eaa16092b06010401da470f010107409e9015d13c1e225eaa426b857f4fbf2ff151a6f1af566824dca2cf145863a269",
    "88ef0418160a0020162104756878ca12de0126f5df550cf97d8f5818fca00a05026b088eaa021b0200810910f97d8f5818fca00a76200419160a001d1621044612cbb5f1d1c8d6ff9b7f885351a67fb2e038c205026b088eaa000a09105351a67fb2e038c2abd900ff74bbeec46e1cb5d548ba271dfe60def26c4c9cf09e8edfd91cf6b61344ea094100ff5717611ffd0c789b35b004e2f219a8b3e49eab82ff8ca895121878c2f7b0c3053b820100edd1c81eb83b3789c007284522b140b9d68461c73706833ef4ac199256e736730100c37e4bd709b2d1e493c551231d556af2d6d7ce7fd1a291b7430bd20b8a67530d"
);
const GPG_SIG_HEX: &str = "887504001608001d1621044612cbb5f1d1c8d6ff9b7f885351a67fb2e038c205026b088eaa000a09105351a67fb2e038c2bee701008b279ee1e178c911cb7ff2a59b8bedbeaae42159c418b799811b6d16132cff880100b486ac47348ed17e47aae6804a947a4a66d780276892a9905a104d250fe22201";

const ED25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 UTC timestamp")
}

#[derive(Clone, Copy)]
enum PacketHeaderFormat {
    Old1,
    Old2,
    Old4,
    New1,
    New2,
    New5,
}

fn wrap_packet(tag: u8, body: &[u8], fmt: PacketHeaderFormat) -> Vec<u8> {
    let mut out = Vec::new();
    match fmt {
        PacketHeaderFormat::Old1 => {
            assert!(tag < 16 && body.len() <= 255);
            out.push(0x80 | (tag << 2));
            out.push(u8::try_from(body.len()).unwrap());
        }
        PacketHeaderFormat::Old2 => {
            assert!(tag < 16 && body.len() <= usize::from(u16::MAX));
            out.push(0x80 | (tag << 2) | 1);
            out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        }
        PacketHeaderFormat::Old4 => {
            assert!(tag < 16);
            out.push(0x80 | (tag << 2) | 2);
            out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        }
        PacketHeaderFormat::New1 => {
            assert!(body.len() < 192);
            out.push(0xc0 | (tag & 0x3f));
            out.push(u8::try_from(body.len()).unwrap());
        }
        PacketHeaderFormat::New2 => {
            assert!(body.len() >= 192 && body.len() <= 8383);
            let adj = body.len() - 192;
            out.push(0xc0 | (tag & 0x3f));
            out.push(u8::try_from((adj >> 8) + 192).unwrap());
            out.push(u8::try_from(adj & 0xff).unwrap());
        }
        PacketHeaderFormat::New5 => {
            out.push(0xc0 | (tag & 0x3f));
            out.push(0xff);
            out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        }
    }
    out.extend_from_slice(body);
    out
}

fn encode_mpi(raw: &[u8]) -> Vec<u8> {
    let stripped = match raw.iter().position(|&b| b != 0) {
        Some(idx) => &raw[idx..],
        None => &[],
    };
    let mut out = Vec::with_capacity(2 + stripped.len());
    if stripped.is_empty() {
        out.extend_from_slice(&0u16.to_be_bytes());
    } else {
        let bits =
            (stripped.len() - 1) * 8 + usize::try_from(8 - stripped[0].leading_zeros()).unwrap();
        out.extend_from_slice(&u16::try_from(bits).unwrap().to_be_bytes());
        out.extend_from_slice(stripped);
    }
    out
}

fn build_v4_sig_packet(
    signing_key: &SigningKey,
    payload: &[u8],
    hash_alg: u8,
    hashed_subpackets: &[u8],
    unhashed_subpackets: &[u8],
    fmt: PacketHeaderFormat,
) -> Vec<u8> {
    let mut body = vec![4, 0x00, 22, hash_alg];
    body.extend_from_slice(
        &u16::try_from(hashed_subpackets.len())
            .unwrap()
            .to_be_bytes(),
    );
    body.extend_from_slice(hashed_subpackets);
    let hashed_header_len = body.len();
    let header_len_be = u32::try_from(hashed_header_len).unwrap().to_be_bytes();
    let trailer = [
        4u8,
        0xff,
        header_len_be[0],
        header_len_be[1],
        header_len_be[2],
        header_len_be[3],
    ];

    let digest: Vec<u8> = match hash_alg {
        8 => {
            let mut h = Sha256::new();
            h.update(payload);
            h.update(&body[..hashed_header_len]);
            h.update(trailer);
            h.finalize().to_vec()
        }
        10 => {
            let mut h = Sha512::new();
            h.update(payload);
            h.update(&body[..hashed_header_len]);
            h.update(trailer);
            h.finalize().to_vec()
        }
        other => panic!("unsupported test hash_alg {other}"),
    };

    let sig = signing_key.sign(&digest).to_bytes();
    body.extend_from_slice(
        &u16::try_from(unhashed_subpackets.len())
            .unwrap()
            .to_be_bytes(),
    );
    body.extend_from_slice(unhashed_subpackets);
    body.extend_from_slice(&digest[..2]);
    body.extend_from_slice(&encode_mpi(&sig[..32]));
    body.extend_from_slice(&encode_mpi(&sig[32..]));

    wrap_packet(2, &body, fmt)
}

fn build_v4_ed25519_pubkey_body(pubkey: &[u8; 32], created_unix: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(51);
    body.push(4);
    body.extend_from_slice(&created_unix.to_be_bytes());
    body.push(22);
    body.push(u8::try_from(ED25519_OID.len()).unwrap());
    body.extend_from_slice(ED25519_OID);
    let mut point = [0u8; 33];
    point[0] = 0x40;
    point[1..].copy_from_slice(pubkey);
    body.extend_from_slice(&encode_mpi(&point));
    body
}

type RecordedCall = (String, Vec<String>, Vec<u8>);
type SignCallback = Box<dyn Fn(&[u8]) -> Result<CommandOutput, AnchorError>>;

struct RecordingRunner {
    calls: Rc<RefCell<Vec<RecordedCall>>>,
    export_output: Result<CommandOutput, AnchorError>,
    sign_fn: SignCallback,
}

impl CommandRunner for RecordingRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        self.calls.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| (*s).to_string()).collect(),
            stdin.to_vec(),
        ));
        if args.contains(&"--export") {
            self.export_output.clone()
        } else {
            (self.sign_fn)(stdin)
        }
    }
}

fn make_mandate(from_key: &KeyId, to_key: &KeyId, hops: u8) -> String {
    let ast = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: {from_key})\n",
            "TO agent \"brokkr:seat\" (key: {to_key})\n",
            "DELEGATION max {hops} hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE context.time >= 2026-11-24T17:00:00Z\n",
            "  AND context.time < 2026-11-25T01:00:00Z\n",
            "LIMIT 2 calls\n",
        ),
        from_key = from_key,
        to_key = to_key,
        hops = hops,
    ))
    .expect("valid mandate");
    render_canonical(&ast)
}

#[test]
fn real_gpg_2_4_8_export_and_detached_signature_verify_end_to_end() {
    let export_bytes = hex::decode(GPG_EXPORT_HEX).unwrap();
    let sig_bytes = hex::decode(GPG_SIG_HEX).unwrap();

    // Unfiltered extraction fails closed when primary and subkey are both Ed25519.
    let ambig = extract_ed25519_public_key(&export_bytes).unwrap_err();
    assert!(matches!(ambig, AnchorError::InvalidPublicKey(ref m) if m.contains("multiple")));

    // Fingerprint-targeted extraction selects primary or signing subkey unambiguously.
    let primary = extract_ed25519_public_key_for_fingerprint(&export_bytes, GPG_PRIMARY_FPR)
        .expect("extract primary key");
    assert_eq!(hex::encode(primary), GPG_PRIMARY_PUB_HEX);

    let subkey =
        extract_ed25519_public_key_for_fingerprint(&export_bytes, &format!("{GPG_SUBKEY_FPR}!"))
            .expect("extract subkey with ! suffix");
    assert_eq!(hex::encode(subkey), GPG_SUBKEY_PUB_HEX);

    let subkey_lower = extract_ed25519_public_key_for_fingerprint(
        &export_bytes,
        &GPG_SUBKEY_FPR.to_ascii_lowercase(),
    )
    .expect("extract subkey lowercase");
    assert_eq!(subkey_lower, subkey);

    let subkey_long = extract_ed25519_public_key_for_fingerprint(&export_bytes, GPG_SUBKEY_LONG_ID)
        .expect("extract subkey by 16-hex long key ID");
    assert_eq!(subkey_long, subkey);

    // End-to-end sign_mandate_with via OpenPgpEd25519Signer::from_gpg_export_with -> verify_chain.
    let runner = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Ok(CommandOutput {
            stdout: export_bytes,
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(move |_stdin| {
            Ok(CommandOutput {
                stdout: sig_bytes.clone(),
                stderr: b"[GNUPG:] SIG_CREATED D 22 8 00 1795722442\n".to_vec(),
            })
        }),
    };

    let fpr_pinned = format!("{GPG_SUBKEY_FPR}!");
    let signer = OpenPgpEd25519Signer::from_gpg_export_with(runner, &fpr_pinned)
        .expect("construct signer from gpg --export");
    assert_eq!(signer.gpg_key_fingerprint(), fpr_pinned);
    assert_eq!(signer.public_key_bytes(), subkey);
    assert_eq!(
        signer.key_id().to_string(),
        format!("{OPENPGP_ED25519_SCHEME}:{GPG_SUBKEY_PUB_HEX}")
    );
    assert_eq!(signer.assurance(), AssuranceLevel::Passkey);
    assert!(format!("{signer:?}").contains("OpenPgpEd25519Signer"));

    let agent_key = KeyId::new("ed25519", "11".repeat(32)).unwrap();
    let canonical = make_mandate(&signer.key_id(), &agent_key, 0);
    let signed = sign_mandate_with(
        &signer,
        &canonical,
        "yubikey-openpgp",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign mandate with real gpg signature fixture");
    assert_eq!(signed.signature_hex, GPG_SIG_HEX);
    assert_eq!(signed.assurance, "passkey");
    assert_eq!(signed.anchor_id, "yubikey-openpgp");

    // Verify both directly and through AnchorRegistry::default_registry() / verify_chain().
    let verified_direct = OpenPgpEd25519Verifier
        .verify(&signed)
        .expect("direct verify");
    let verified_chain = verify_chain(&[signed]).expect("verify_chain default_registry");
    assert_eq!(verified_chain.len(), 1);
    assert_eq!(verified_chain[0], verified_direct);
    assert_eq!(verified_chain[0].proof.assurance, AssuranceLevel::Passkey);
}

#[test]
fn verifies_sha256_sha512_all_packet_header_formats_and_short_mpis() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let root_key = openpgp_ed25519_key_id(&pubkey);
    let agent_key = KeyId::new("ed25519", "22".repeat(32)).unwrap();
    let canonical = make_mandate(&root_key, &agent_key, 0);

    let base_signed = SignedMandate {
        canonical_words: canonical,
        anchor_id: "yubikey-openpgp".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: root_key.to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: String::new(),
    };
    let payload = signing_payload(&base_signed);

    // 1. Both SHA-256 (8) and SHA-512 (10) across old and new packet header formats.
    let formats = [
        (
            8u8,
            PacketHeaderFormat::Old1,
            vec![0x05, 0x02, 0x67, 0x00, 0x00, 0x01],
            vec![0x01, 0x02],
        ),
        (
            10u8,
            PacketHeaderFormat::Old2,
            vec![0x05, 0x02, 0x67, 0x00, 0x00, 0x02],
            vec![],
        ),
        (8u8, PacketHeaderFormat::Old4, vec![], vec![0xaa; 4]),
        (
            10u8,
            PacketHeaderFormat::New1,
            vec![0x05, 0x02, 0x67, 0x00, 0x00, 0x03],
            vec![],
        ),
        // Body >= 192 bytes exercises 2-octet new-format packet length decoding.
        (
            8u8,
            PacketHeaderFormat::New2,
            vec![0x05, 0x02, 0x67, 0x00, 0x00, 0x04],
            vec![0x77; 160],
        ),
        (10u8, PacketHeaderFormat::New5, vec![], vec![]),
    ];

    let registry = AnchorRegistry::default_registry();
    for (hash_alg, fmt, hashed, unhashed) in formats {
        let pkt = build_v4_sig_packet(&signing_key, &payload, hash_alg, &hashed, &unhashed, fmt);
        let mut signed = base_signed.clone();
        signed.signature_hex = hex::encode(&pkt);
        let vm = registry
            .verify(&signed)
            .expect("valid v4 signature packet must verify");
        assert_eq!(vm.proof.assurance, AssuranceLevel::Passkey);
        assert_eq!(vm.proof.signer_key, root_key);
    }

    // 2. Deterministically find signatures whose r (< 32 bytes) and s (< 32 bytes) require
    //    left-zero-padding from short canonical OpenPGP MPIs.
    let mut found_short_r = false;
    let mut found_short_s = false;
    for nonce in 0u32..4096 {
        let hashed = nonce.to_be_bytes();
        let pkt = build_v4_sig_packet(
            &signing_key,
            &payload,
            8,
            &hashed,
            &[],
            PacketHeaderFormat::New1,
        );
        // Inspect MPI bit lengths inside packet body (after 2-byte new1 header).
        let body = &pkt[2..];
        let r_off = 6 + hashed.len() + 2 + 2;
        let r_bits = u16::from_be_bytes([body[r_off], body[r_off + 1]]);
        let r_len = usize::from(r_bits).div_ceil(8);
        let s_off = r_off + 2 + r_len;
        let s_bits = u16::from_be_bytes([body[s_off], body[s_off + 1]]);
        let s_len = usize::from(s_bits).div_ceil(8);

        if (r_len < 32 && !found_short_r) || (s_len < 32 && !found_short_s) {
            let mut signed = base_signed.clone();
            signed.signature_hex = hex::encode(&pkt);
            verify_openpgp_ed25519(&signed).expect("short MPI left-padded to 32 bytes must verify");
            if r_len < 32 {
                found_short_r = true;
            }
            if s_len < 32 {
                found_short_s = true;
            }
            if found_short_r && found_short_s {
                break;
            }
        }
    }
    assert!(
        found_short_r,
        "must exercise short-encoded r MPI (< 32 bytes)"
    );
    assert!(
        found_short_s,
        "must exercise short-encoded s MPI (< 32 bytes)"
    );
}

#[test]
fn heterogeneous_openpgp_root_to_ed25519_leaf_chain_authorizes_end_to_end() {
    let hw_sk = SigningKey::from_bytes(&[0x7a; 32]);
    let hw_pub = hw_sk.verifying_key().to_bytes();
    let hw_key_id = openpgp_ed25519_key_id(&hw_pub);
    let disp_kp = Ed25519Keypair::from_secret_bytes([0x3b; 32]);
    let seat_kp = Ed25519Keypair::from_secret_bytes([0x5c; 32]);

    let root_canonical = make_mandate(&hw_key_id, &disp_kp.key_id(), 1);
    let root_ast = parse_mandate(&root_canonical).unwrap();
    let root_id: MandateId = root_ast.mandate_id();

    let hw_sk_clone = hw_sk.clone();
    let runner = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(move |stdin| {
            let sig = build_v4_sig_packet(
                &hw_sk_clone,
                stdin,
                8,
                &[0x05, 0x02, 0x67, 0x44, 0x11, 0x22],
                &[],
                PacketHeaderFormat::Old1,
            );
            Ok(CommandOutput {
                stdout: sig,
                stderr: Vec::new(),
            })
        }),
    };

    let fpr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let signer = OpenPgpEd25519Signer::new(runner, fpr, hw_pub).expect("construct signer");
    let root_signed = sign_mandate_with(
        &signer,
        &root_canonical,
        "yubikey-openpgp",
        ts("2026-11-24T17:00:00Z"),
        ts("2026-11-25T01:00:00Z"),
    )
    .expect("sign root with OpenPgpEd25519Signer");

    let child_raw = format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {root_id}\n",
            "FROM agent \"brokkr:seat\" (key: {disp_key})\n",
            "TO agent \"brokkr:worker\" (key: {seat_key})\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE context.time >= 2026-11-24T18:00:00Z\n",
            "  AND context.time < 2026-11-24T20:00:00Z\n",
            "LIMIT 1 call\n",
        ),
        root_id = root_id,
        disp_key = disp_kp.key_id(),
        seat_key = seat_kp.key_id(),
    );
    let child_canonical = render_canonical(&parse_mandate(&child_raw).unwrap());
    let child_signed = disp_kp
        .sign_mandate(
            &child_canonical,
            "local-ed25519",
            ts("2026-11-24T18:00:00Z"),
            ts("2026-11-24T20:00:00Z"),
        )
        .expect("sign child with Ed25519Keypair");

    let verified = verify_chain(&[root_signed, child_signed]).expect("verify heterogeneous chain");
    assert_eq!(verified[0].proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verified[1].proof.assurance, AssuranceLevel::LocalKey);

    let req = ActionRequest {
        actor_key: seat_kp.key_id(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let mut facts = VerifiedFacts::new();
    facts.insert(
        "resource.author".to_string(),
        Scalar::Str("valentin".into()),
    );
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
fn signer_validates_gpg_args_fingerprints_keys_and_command_errors() {
    let sk = SigningKey::from_bytes(&[0x19; 32]);
    let pubkey = sk.verifying_key().to_bytes();

    // Invalid fingerprints rejected before touching CommandRunner.
    for bad_fpr in [
        "",
        "--output=/tmp/pwn",
        "12345678", // 8-hex short key ID rejected
        "GGGGGGGGGGGGGGGG",
        "4612CBB5F1D1C8D6FF9B7F885351A67FB2E038C2!!",
        "4612CBB5F1D1C8D6FF9B7F885351A67FB2E038C", // 39 chars
    ] {
        let runner = RecordingRunner {
            calls: Rc::new(RefCell::new(Vec::new())),
            export_output: Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            sign_fn: Box::new(|_| unreachable!("runner must not be called")),
        };
        let err = OpenPgpEd25519Signer::new(runner, bad_fpr, pubkey).unwrap_err();
        assert!(
            matches!(err, AnchorError::InvalidPublicKey(_)),
            "{bad_fpr}: {err}"
        );
    }

    // Invalid curve point rejected by new().
    // y = 2^255 - 19 + 1 wraps to non-canonical/off-curve or small-order test; use a known
    // non-decompressible Ed25519 y-coordinate (y = 2 has no square root mod p).
    let mut bad_point = [0u8; 32];
    bad_point[0] = 2;
    let runner_bad_pt = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(|_| unreachable!()),
    };
    let err = OpenPgpEd25519Signer::new(runner_bad_pt, GPG_SUBKEY_FPR, bad_point).unwrap_err();
    assert!(matches!(err, AnchorError::InvalidPublicKey(_)));
}

#[test]
fn signer_passes_exact_gpg_args_and_handles_runner_failures() {
    let sk = SigningKey::from_bytes(&[0x19; 32]);
    let pubkey = sk.verifying_key().to_bytes();

    // Verify exact gpg argv and stdin passed by sign_payload.
    let sk_copy = sk.clone();
    let expected_payload = b"exact-payload-bytes".to_vec();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let runner = RecordingRunner {
        calls: Rc::clone(&calls),
        export_output: Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(move |stdin| {
            let sig = build_v4_sig_packet(&sk_copy, stdin, 8, &[], &[], PacketHeaderFormat::Old1);
            Ok(CommandOutput {
                stdout: sig,
                stderr: Vec::new(),
            })
        }),
    };
    let signer = OpenPgpEd25519Signer::new(runner, GPG_SUBKEY_FPR, pubkey).unwrap();
    let sig = signer
        .sign_payload(&expected_payload)
        .expect("sign_payload succeeds");
    assert!(!sig.is_empty());
    let recorded = calls.borrow();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, "gpg");
    assert_eq!(
        recorded[0].1,
        vec![
            "--batch",
            "--yes",
            "--status-fd",
            "2",
            "--local-user",
            GPG_SUBKEY_FPR,
            "--digest-algo",
            "SHA256",
            "--detach-sign",
        ]
    );
    assert_eq!(recorded[0].2, expected_payload);

    // Empty stdout from gpg fails closed.
    let empty_runner = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(|_| {
            Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }),
    };
    let signer_empty = OpenPgpEd25519Signer::new(empty_runner, GPG_SUBKEY_FPR, pubkey).unwrap();
    let err = signer_empty.sign_payload(b"payload").unwrap_err();
    assert!(matches!(err, AnchorError::InvalidSignature(ref m) if m.contains("empty")));

    // Armored / wrong-key stdout from gpg fails closed in sign_payload.
    let wrong_sk = SigningKey::from_bytes(&[0x99; 32]);
    let wrong_runner = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(move |stdin| {
            let sig = build_v4_sig_packet(&wrong_sk, stdin, 8, &[], &[], PacketHeaderFormat::Old1);
            Ok(CommandOutput {
                stdout: sig,
                stderr: Vec::new(),
            })
        }),
    };
    let signer_wrong = OpenPgpEd25519Signer::new(wrong_runner, GPG_SUBKEY_FPR, pubkey).unwrap();
    let err = signer_wrong.sign_payload(b"payload").unwrap_err();
    assert!(matches!(err, AnchorError::InvalidSignature(_)));

    // CommandFailed propagated cleanly.
    let fail_runner = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Err(AnchorError::CommandFailed {
            program: "gpg".to_string(),
            status: Some(2),
            stderr: "No public key".to_string(),
        }),
        sign_fn: Box::new(|_| {
            Err(AnchorError::CommandIo {
                program: "gpg".to_string(),
                detail: "not found".to_string(),
            })
        }),
    };
    let err = OpenPgpEd25519Signer::from_gpg_export_with(fail_runner, GPG_SUBKEY_FPR).unwrap_err();
    assert!(matches!(
        err,
        AnchorError::CommandFailed {
            status: Some(2),
            ..
        }
    ));
}

#[test]
fn signer_propagates_sign_io_error_and_validates_from_gpg_export() {
    let sk = SigningKey::from_bytes(&[0x19; 32]);
    let pubkey = sk.verifying_key().to_bytes();

    let sign_io_runner = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(|_| {
            Err(AnchorError::CommandIo {
                program: "gpg".to_string(),
                detail: "not found".to_string(),
            })
        }),
    };
    let signer_io_err = OpenPgpEd25519Signer::new(sign_io_runner, GPG_SUBKEY_FPR, pubkey).unwrap();
    let err = signer_io_err.sign_payload(b"payload").unwrap_err();
    assert!(matches!(
        err,
        AnchorError::CommandIo { ref program, .. } if program == "gpg"
    ));

    let err = OpenPgpEd25519Signer::from_gpg_export("not-a-valid-fpr").unwrap_err();
    assert!(matches!(err, AnchorError::InvalidPublicKey(_)));
}

#[test]
fn public_key_extraction_handles_single_key_mixed_subkeys_and_rejects_malformed_exports() {
    let sk = SigningKey::from_bytes(&[0x55; 32]);
    let pubkey = sk.verifying_key().to_bytes();
    let pk_body = build_v4_ed25519_pubkey_body(&pubkey, 0x6700_0001);

    // 1. Single Ed25519 public key packet (old and new format) + Cv25519 encryption subkey (alg 18)
    //    + non-Ed25519 EdDSA OID (Ed448) are skipped cleanly when unambiguous.
    let mut mixed_export = wrap_packet(6, &pk_body, PacketHeaderFormat::New1);
    let userid = wrap_packet(13, b"Alice <alice@example.com>", PacketHeaderFormat::Old1);
    mixed_export.extend_from_slice(&userid);
    // Encryption subkey alg 18 (ECDH) — skipped cleanly.
    let mut ecdh_body = vec![4, 0x67, 0x00, 0x00, 0x01, 18, 0x0a];
    ecdh_body.extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);
    mixed_export.extend_from_slice(&wrap_packet(14, &ecdh_body, PacketHeaderFormat::Old1));
    // EdDSA subkey with non-Ed25519 OID — skipped cleanly in unfiltered extraction.
    let other_oid_body = vec![4, 0x67, 0x00, 0x00, 0x01, 22, 3, 0x01, 0x02, 0x03];
    mixed_export.extend_from_slice(&wrap_packet(14, &other_oid_body, PacketHeaderFormat::New1));

    let extracted = extract_ed25519_public_key(&mixed_export).expect("extract single Ed25519 key");
    assert_eq!(extracted, pubkey);

    // 2. Empty export rejected.
    assert!(matches!(
        extract_ed25519_public_key(&[]),
        Err(AnchorError::InvalidPublicKey(_))
    ));
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&[], GPG_SUBKEY_FPR),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // 3. No Ed25519 key packet (only User ID).
    assert!(matches!(
        extract_ed25519_public_key(&userid),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("no OpenPGP Ed25519")
    ));

    // 4. Truncated EdDSA OID inside public key packet fails closed.
    let trunc_oid = wrap_packet(
        6,
        &[4, 0, 0, 0, 1, 22, 9, 0x2b, 0x06],
        PacketHeaderFormat::Old1,
    );
    assert!(matches!(
        extract_ed25519_public_key(&trunc_oid),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("truncated")
    ));

    // 5. Wrong native point prefix (0x41 instead of 0x40) fails closed.
    let mut bad_prefix_body = pk_body.clone();
    bad_prefix_body[18] = 0x41;
    let bad_prefix_pkt = wrap_packet(6, &bad_prefix_body, PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key(&bad_prefix_pkt),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("0x40")
    ));

    // 6. Wrong point byte length (32 bytes instead of 33) fails closed.
    let mut short_point_body = vec![4, 0, 0, 0, 1, 22, u8::try_from(ED25519_OID.len()).unwrap()];
    short_point_body.extend_from_slice(ED25519_OID);
    short_point_body.extend_from_slice(&encode_mpi(&[0x40; 32]));
    let short_point_pkt = wrap_packet(6, &short_point_body, PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key(&short_point_pkt),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // 7. Trailing bytes inside public key packet body fails closed.
    let mut trailing_body = pk_body.clone();
    trailing_body.push(0x00);
    let trailing_pkt = wrap_packet(6, &trailing_body, PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key(&trailing_pkt),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("trailing")
    ));

    // 8. Fingerprint not found in export fails closed.
    let single_pkt = wrap_packet(6, &pk_body, PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&single_pkt, "0000000000000000000000000000000000000000"),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("matched fingerprint")
    ));

    // 9. Duplicate fingerprint match fails closed.
    let export_bytes = hex::decode(GPG_EXPORT_HEX).unwrap();
    let mut doubled = export_bytes.clone();
    doubled.extend_from_slice(&export_bytes);
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&doubled, GPG_SUBKEY_FPR),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("multiple")
    ));

    // 10. Non-Ed25519 packet matching target fingerprint fails closed (ECDH alg 18).
    let non_v4_pkt = wrap_packet(6, &[3, 0, 0, 0, 1, 1], PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&non_v4_pkt, GPG_SUBKEY_FPR),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // 11. Malformed packet headers and invalid fingerprint fail closed in both extractors.
    assert!(matches!(
        extract_ed25519_public_key(&[0x00]),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("bit 7")
    ));
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&[0x00], GPG_SUBKEY_FPR),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("bit 7")
    ));
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&single_pkt, "not-a-fpr"),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("invalid GPG key fingerprint")
    ));
}

fn signed_openpgp_fixture() -> ([u8; 32], SignedMandate, Vec<u8>) {
    let sk = SigningKey::from_bytes(&[0x61; 32]);
    let pubkey = sk.verifying_key().to_bytes();
    let root_key = openpgp_ed25519_key_id(&pubkey);
    let agent_key = KeyId::new("ed25519", "33".repeat(32)).unwrap();
    let canonical = make_mandate(&root_key, &agent_key, 0);
    let mut base = SignedMandate {
        canonical_words: canonical,
        anchor_id: "yubikey-openpgp".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: root_key.to_string(),
        valid_from: ts("2026-11-24T17:00:00Z"),
        valid_until: ts("2026-11-25T01:00:00Z"),
        signature_hex: String::new(),
    };
    let payload = signing_payload(&base);
    let valid_pkt = build_v4_sig_packet(
        &sk,
        &payload,
        8,
        &[0x05, 0x02, 0x67, 0x01, 0x02, 0x03],
        &[0x09, 0x10, 1, 2, 3, 4, 5, 6, 7, 8],
        PacketHeaderFormat::Old1,
    );
    base.signature_hex = hex::encode(&valid_pkt);
    (pubkey, base, valid_pkt)
}

#[test]
fn adversarial_signature_packets_and_envelope_tampering_fail_closed() {
    let (_pubkey, base, valid_pkt) = signed_openpgp_fixture();
    verify_openpgp_ed25519(&base).expect("baseline valid signature verifies");

    // 1. Bad 2-byte hash prefix (flip 1 bit of prefix at body offset 6+6+2+10 = 24, pkt offset 26).
    let mut bad_prefix = valid_pkt.clone();
    bad_prefix[26] ^= 0x01;
    let mut m = base.clone();
    m.signature_hex = hex::encode(&bad_prefix);
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("prefix")
    ));

    // 2. Valid hash prefix, corrupted Ed25519 signature scalar byte.
    let mut bad_sig_byte = valid_pkt.clone();
    let last = bad_sig_byte.len() - 1;
    bad_sig_byte[last] ^= 0x01;
    let mut m = base.clone();
    m.signature_hex = hex::encode(&bad_sig_byte);
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(_))
    ));

    // 3. Wrong sig_type (0x01 canonical text document instead of 0x00 binary).
    let mut wrong_sig_type = valid_pkt.clone();
    wrong_sig_type[3] = 0x01;
    let mut m = base.clone();
    m.signature_hex = hex::encode(&wrong_sig_type);
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("signature type")
    ));

    // 4. Unsupported signature version (3 and 6).
    for ver in [3u8, 6u8] {
        let mut bad_ver = valid_pkt.clone();
        bad_ver[2] = ver;
        let mut m = base.clone();
        m.signature_hex = hex::encode(&bad_ver);
        assert!(matches!(
            verify_openpgp_ed25519(&m),
            Err(AnchorError::InvalidSignature(ref s)) if s.contains("version")
        ));
    }

    // 5. Non-EdDSA public-key algorithm (1 = RSA, 19 = ECDSA).
    for alg in [1u8, 19u8] {
        let mut bad_alg = valid_pkt.clone();
        bad_alg[4] = alg;
        let mut m = base.clone();
        m.signature_hex = hex::encode(&bad_alg);
        assert!(matches!(
            verify_openpgp_ed25519(&m),
            Err(AnchorError::InvalidSignature(ref s)) if s.contains("public-key algorithm")
        ));
    }

    // 6. Unsupported hash algorithm (2 = SHA-1, 9 = SHA-384).
    for halg in [2u8, 9u8] {
        let mut bad_halg = valid_pkt.clone();
        bad_halg[5] = halg;
        let mut m = base.clone();
        m.signature_hex = hex::encode(&bad_halg);
        assert!(matches!(
            verify_openpgp_ed25519(&m),
            Err(AnchorError::InvalidSignature(ref s)) if s.contains("hash algorithm")
        ));
    }

    // 7. Wrong packet tag (Tag 6 Public Key instead of Tag 2 Signature).
    let wrong_tag = wrap_packet(6, &valid_pkt[2..], PacketHeaderFormat::Old1);
    let mut m = base.clone();
    m.signature_hex = hex::encode(&wrong_tag);
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("tag")
    ));

    // 8. Trailing packet / trailing bytes after signature packet.
    let mut trailing_pkt = valid_pkt.clone();
    trailing_pkt.extend_from_slice(&valid_pkt);
    let mut m = base.clone();
    m.signature_hex = hex::encode(&trailing_pkt);
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("trailing")
    ));

    // 9. Trailing byte inside signature packet body.
    let mut inner_trailing_body = valid_pkt[2..].to_vec();
    inner_trailing_body.push(0x00);
    let inner_trailing_pkt = wrap_packet(2, &inner_trailing_body, PacketHeaderFormat::Old1);
    let mut m = base.clone();
    m.signature_hex = hex::encode(&inner_trailing_pkt);
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("trailing")
    ));
}

#[test]
fn adversarial_mpi_encoding_fail_closed() {
    let (_pubkey, base, _valid_pkt) = signed_openpgp_fixture();

    // 10. Oversized MPI (bit_len = 257 -> 33 bytes), non-canonical leading-zero MPI, and
    //     non-canonical bit-length MPI constructed from a mathematically valid short-r signature
    //     so only the MPI canonicalization guards reject them.
    let sk = SigningKey::from_bytes(&[0x61; 32]);
    let payload = signing_payload(&base);
    let (short_hashed, short_sig_bytes, short_prefix) = (0u32..4096)
        .find_map(|nonce| {
            let hashed = nonce.to_be_bytes();
            let mut hdr = vec![4, 0x00, 22, 8];
            hdr.extend_from_slice(&4u16.to_be_bytes());
            hdr.extend_from_slice(&hashed);
            let hlen = u32::try_from(hdr.len()).unwrap().to_be_bytes();
            let mut h = Sha256::new();
            h.update(&payload);
            h.update(&hdr);
            h.update([4u8, 0xff, hlen[0], hlen[1], hlen[2], hlen[3]]);
            let digest = h.finalize();
            let sig = sk.sign(&digest).to_bytes();
            if sig[0] == 0x00 && sig[1] != 0x00 && sig[1] < 0x80 {
                Some((hashed, sig, [digest[0], digest[1]]))
            } else {
                None
            }
        })
        .expect("deterministic short-r signature");
    let build_custom_mpi_sig = |r_mpi: Vec<u8>, s_mpi: Vec<u8>| -> Vec<u8> {
        let mut b = vec![4, 0x00, 22, 8];
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&short_hashed);
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&short_prefix);
        b.extend_from_slice(&r_mpi);
        b.extend_from_slice(&s_mpi);
        wrap_packet(2, &b, PacketHeaderFormat::Old1)
    };
    // Control: canonical encoding of the same short-r signature passes!
    let mut ctrl = base.clone();
    ctrl.signature_hex = hex::encode(build_custom_mpi_sig(
        encode_mpi(&short_sig_bytes[..32]),
        encode_mpi(&short_sig_bytes[32..]),
    ));
    verify_openpgp_ed25519(&ctrl).expect("canonical short-r control must verify");

    // Non-canonical leading zero byte (256 bits, raw[0] == 0x00).
    let mut leading_zero_r = Vec::with_capacity(34);
    leading_zero_r.extend_from_slice(&256u16.to_be_bytes());
    leading_zero_r.extend_from_slice(&short_sig_bytes[..32]);
    let mut m = base.clone();
    m.signature_hex = hex::encode(build_custom_mpi_sig(
        leading_zero_r,
        encode_mpi(&short_sig_bytes[32..]),
    ));
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("leading zero")
    ));

    // Non-canonical bit length (declared 248 bits for 31-byte r starting with < 0x80).
    let mut bad_bits_r = Vec::with_capacity(33);
    bad_bits_r.extend_from_slice(&248u16.to_be_bytes());
    bad_bits_r.extend_from_slice(&short_sig_bytes[1..32]);
    let mut m = base.clone();
    m.signature_hex = hex::encode(build_custom_mpi_sig(
        bad_bits_r,
        encode_mpi(&short_sig_bytes[32..]),
    ));
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("declared")
    ));

    // Oversized MPI (257 bits, 33 bytes) on both r and s.
    let mut oversized_r = Vec::with_capacity(35);
    oversized_r.extend_from_slice(&257u16.to_be_bytes());
    oversized_r.push(0x01);
    oversized_r.extend_from_slice(&short_sig_bytes[..32]);
    let mut m = base.clone();
    m.signature_hex = hex::encode(build_custom_mpi_sig(
        oversized_r.clone(),
        encode_mpi(&short_sig_bytes[32..]),
    ));
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("exceeds maximum")
    ));

    let mut m = base.clone();
    m.signature_hex = hex::encode(build_custom_mpi_sig(
        encode_mpi(&short_sig_bytes[..32]),
        oversized_r,
    ));
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(ref s)) if s.contains("exceeds maximum")
    ));

    // Zero-length MPI (0 bits) fails cleanly at signature verification.
    let mut m = base.clone();
    m.signature_hex = hex::encode(build_custom_mpi_sig(vec![0, 0], vec![0, 0]));
    assert!(matches!(
        verify_openpgp_ed25519(&m),
        Err(AnchorError::InvalidSignature(_))
    ));
}

#[test]
fn adversarial_packet_headers_and_hex_fail_closed() {
    let (_pubkey, base, valid_pkt) = signed_openpgp_fixture();

    // 11. Malformed packet headers (bit 7 unset, indeterminate old length, partial new length, truncated).
    for bad_pkt in [
        {
            let mut pkt = valid_pkt.clone();
            pkt[0] &= 0x7f;
            pkt
        }, // bit 7 == 0 on otherwise valid sig
        vec![0x8b, 0x04, 0x00], // old format indeterminate length (lt=3)
        vec![0xc2, 224, 0x04],  // new format partial body length
        vec![0xc2],             // truncated new header
        vec![0xc2, 192],        // truncated new 2-octet length
        vec![0xc2, 255, 0, 0],  // truncated new 5-octet length
        vec![0x88],             // truncated old 1-octet length
        vec![0x89, 0x00],       // truncated old 2-octet length
        vec![0x8a, 0x00, 0x00], // truncated old 4-octet length
        valid_pkt[..valid_pkt.len() - 1].to_vec(), // truncated body
    ] {
        let mut m = base.clone();
        m.signature_hex = hex::encode(&bad_pkt);
        assert!(matches!(
            verify_openpgp_ed25519(&m),
            Err(AnchorError::InvalidSignature(_))
        ));
    }

    // 12. Malformed signature_hex (empty, odd length, uppercase hex).
    for bad_hex in ["", "abc", &base.signature_hex.to_ascii_uppercase()] {
        let mut m = base.clone();
        m.signature_hex = bad_hex.to_string();
        assert!(matches!(
            verify_openpgp_ed25519(&m),
            Err(AnchorError::InvalidSignature(_))
        ));
    }
}

#[test]
fn adversarial_envelope_tampering_assurance_and_scheme_fail_closed() {
    let (pubkey, base, _valid_pkt) = signed_openpgp_fixture();

    // 13. Envelope tampering: canonical_words, valid_until, valid_from, anchor_id, assurance, scheme.
    let mut tampered_words = base.clone();
    tampered_words.canonical_words = base
        .canonical_words
        .replace("LIMIT 2 calls", "LIMIT 3 calls");
    assert!(matches!(
        verify_openpgp_ed25519(&tampered_words),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut tampered_until = base.clone();
    tampered_until.valid_until += 1;
    assert!(matches!(
        verify_openpgp_ed25519(&tampered_until),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut tampered_from = base.clone();
    tampered_from.valid_from -= 1;
    assert!(matches!(
        verify_openpgp_ed25519(&tampered_from),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut tampered_anchor = base.clone();
    tampered_anchor.anchor_id = "other-anchor".to_string();
    assert!(matches!(
        verify_openpgp_ed25519(&tampered_anchor),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut wrong_assurance = base.clone();
    wrong_assurance.assurance = "local_key".to_string();
    assert_eq!(
        verify_openpgp_ed25519(&wrong_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::Passkey,
            actual: AssuranceLevel::LocalKey,
        })
    );

    let mut wrong_scheme = base.clone();
    wrong_scheme.signer_key = format!("ed25519:{}", hex::encode(pubkey));
    assert!(matches!(
        verify_openpgp_ed25519(&wrong_scheme),
        Err(AnchorError::InvalidPublicKey(_))
    ));
}

fn test_v4_fpr(body: &[u8]) -> String {
    // Use a known 1-packet export against a fake fingerprint check or compute via sha1?
    // Actually we can compute SHA-1 cleanly via a tiny RFC 3174 helper or fixed vector!
    let mut pre = Vec::with_capacity(3 + body.len());
    pre.push(0x99);
    pre.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    pre.extend_from_slice(body);
    let bit_len = (pre.len() as u64) * 8;
    pre.push(0x80);
    while pre.len() % 64 != 56 {
        pre.push(0);
    }
    pre.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for blk in pre.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, &c) in blk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(c);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
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
    hex::encode(out)
}

#[test]
fn public_key_extraction_rejects_matched_non_ed25519_invalid_point_and_oversized_packet() {
    // Matched ECDH (alg 18) packet -> rejected as unsupported pubkey alg.
    let ecdh_body = vec![4, 0, 0, 0, 1, 18, 3, 1, 2, 3];
    let ecdh_fpr = test_v4_fpr(&ecdh_body);
    let ecdh_pkt = wrap_packet(6, &ecdh_body, PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&ecdh_pkt, &ecdh_fpr),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("public-key algorithm")
    ));

    // Matched EdDSA (alg 22) packet with non-Ed25519 OID -> rejected.
    let wrong_oid_body = vec![4, 0, 0, 0, 1, 22, 3, 0x01, 0x02, 0x03];
    let wrong_oid_fpr = test_v4_fpr(&wrong_oid_body);
    let wrong_oid_pkt = wrap_packet(6, &wrong_oid_body, PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&wrong_oid_pkt, &wrong_oid_fpr),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("OID")
    ));

    // Invalid Ed25519 curve point inside Tag 6 packet -> rejected.
    let mut bad_pt = [0u8; 32];
    bad_pt[0] = 2;
    let bad_pt_body = build_v4_ed25519_pubkey_body(&bad_pt, 1);
    let bad_pt_pkt = wrap_packet(6, &bad_pt_body, PacketHeaderFormat::Old1);
    assert!(matches!(
        extract_ed25519_public_key(&bad_pt_pkt),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // Oversized (> 65535 byte) v4 public-key packet -> rejected by v4 fingerprint u16 guard.
    let mut huge_body = vec![4u8; 65536];
    huge_body[5] = 22;
    let huge_pkt = wrap_packet(6, &huge_body, PacketHeaderFormat::Old4);
    assert!(matches!(
        extract_ed25519_public_key_for_fingerprint(&huge_pkt, GPG_SUBKEY_FPR),
        Err(AnchorError::InvalidPublicKey(ref m)) if m.contains("65535")
    ));

    // Bad fingerprint passed to from_gpg_export_with fails before invoking CommandRunner.
    let runner = RecordingRunner {
        calls: Rc::new(RefCell::new(Vec::new())),
        export_output: Ok(CommandOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        sign_fn: Box::new(|_| unreachable!()),
    };
    assert!(matches!(
        OpenPgpEd25519Signer::from_gpg_export_with(runner, "--bad-flag"),
        Err(AnchorError::InvalidPublicKey(_))
    ));
}

#[test]
fn adversarial_truncated_signature_and_pubkey_bodies_fail_closed() {
    // Every byte-prefix truncation of a valid Tag 6 v4 Ed25519 public-key body fails closed
    // without panicking (covering creation_time, alg, oid_len, oid, and MPI truncation).
    let valid_pk_body = build_v4_ed25519_pubkey_body(
        &SigningKey::from_bytes(&[0x55; 32])
            .verifying_key()
            .to_bytes(),
        1,
    );
    for trunc_len in 1..valid_pk_body.len() {
        let prefix = &valid_pk_body[..trunc_len];
        let fpr = test_v4_fpr(prefix);
        let pkt = wrap_packet(6, prefix, PacketHeaderFormat::Old1);
        assert!(
            matches!(
                extract_ed25519_public_key_for_fingerprint(&pkt, &fpr),
                Err(AnchorError::InvalidPublicKey(_))
            ),
            "truncated public key body len={trunc_len} must fail closed"
        );
    }

    // Every byte-prefix truncation of a valid Tag 2 v4 EdDSA signature body fails closed
    // without panicking (covering version, sig_type, pubkey_alg, hash_alg, subpackets,
    // hash prefix, and both MPIs).
    let (_pubkey, base, valid_pkt) = signed_openpgp_fixture();
    let valid_sig_body = &valid_pkt[2..];
    for trunc_len in 0..valid_sig_body.len() {
        let pkt = wrap_packet(2, &valid_sig_body[..trunc_len], PacketHeaderFormat::Old1);
        let mut m = base.clone();
        m.signature_hex = hex::encode(&pkt);
        assert!(
            matches!(
                verify_openpgp_ed25519(&m),
                Err(AnchorError::InvalidSignature(_))
            ),
            "truncated signature body len={trunc_len} must fail closed"
        );
    }
}

#[test]
fn openpgp_revocation_signs_and_verifies_via_registry() {
    let sk = SigningKey::from_bytes(&[0x62; 32]);
    let pubkey = sk.verifying_key().to_bytes();
    let key_id = openpgp_ed25519_key_id(&pubkey);
    let target = handfest_core::ast::MandateId::sha256(b"openpgp-rev-target");
    let words = format!(
        "HANDFEST REVOKE v1\n\
         BY human \"Valentin\" (key: {key_id})\n\
         TARGET mandate {target}\n\
         EFFECTIVE 2026-11-26T17:15:00Z\n\
         REASON \"openpgp kill\"\n"
    );
    let vf = ts("2026-11-26T17:00:00Z");
    let vu = ts("2026-11-26T18:00:00Z");

    let mut env = handfest_anchors::SignedRevocation {
        canonical_words: words,
        anchor_id: "yubikey-openpgp".to_string(),
        assurance: "passkey".to_string(),
        actor_kind: "human".to_string(),
        signer_key: key_id.to_string(),
        valid_from: vf,
        valid_until: vu,
        signature_hex: String::new(),
    };
    let payload = handfest_anchors::revocation_signing_payload(&env);
    let sig_pkt = build_v4_sig_packet(&sk, &payload, 8, &[], &[], PacketHeaderFormat::Old1);
    env.signature_hex = hex::encode(sig_pkt);

    let verified = handfest_anchors::verify_revocation_openpgp_ed25519(&env)
        .expect("verify OpenPGP revocation");
    assert_eq!(verified.proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(
        handfest_anchors::verify_revocation(&env).expect("verify via default registry"),
        verified
    );
}
