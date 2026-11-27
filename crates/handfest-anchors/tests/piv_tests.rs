use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

use ed25519_dalek::{Signature, Signer, SigningKey};
use handfest_anchors::{
    parse_ed25519_spki_der, parse_ed25519_spki_pem, piv_ed25519_key_id, sign_mandate_with,
    verify_chain, verify_ed25519, verify_piv_ed25519, AnchorError, AnchorRegistry, AnchorVerifier,
    AssuranceLevel, CommandOutput, CommandRunner, Ed25519Keypair, Ed25519Verifier, MandateSigner,
    PivEd25519Signer, PivEd25519Verifier, PivPinSource, PivSignerConfig, DEFAULT_PIV_KEY_ID,
    DEFAULT_PIV_PIN_ENV, DEFAULT_PKCS11_MODULE, ED25519_SPKI_DER_PREFIX, PIV_ED25519_SCHEME,
};
use handfest_core::ast::{parse_rfc3339_utc, KeyId, MandateId};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::ActorKind;

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid test timestamp")
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

fn spki_der(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&ED25519_SPKI_DER_PREFIX);
    der.extend_from_slice(pubkey);
    der
}

fn spki_pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64(der)
    )
}

fn root_mandate(from_key: &KeyId, to_key: &KeyId) -> String {
    let raw = format!(
        "HANDFEST v1\n\
         FROM human \"Valentin\" (key: {from_key})\n\
         TO agent \"Dispatcher\" (key: {to_key})\n\
         DELEGATION max 1 hop\n\
         ALLOW git.pr.merge\n\
         ON repo \"feedback-loop-ai/*\"\n\
         WHERE context.time < 2026-12-01T00:00:00Z\n"
    );
    let ast = parse_mandate(&raw).expect("parse root mandate");
    try_render_canonical(&ast).expect("render canonical root")
}

fn child_mandate(parent: MandateId, from_key: &KeyId, to_key: &KeyId) -> String {
    let raw = format!(
        "HANDFEST v1\n\
         PARENT {parent}\n\
         FROM agent \"Dispatcher\" (key: {from_key})\n\
         TO agent \"Worker\" (key: {to_key})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"feedback-loop-ai/handfest\"\n\
         WHERE context.time < 2026-11-30T00:00:00Z\n"
    );
    let ast = parse_mandate(&raw).expect("parse child mandate");
    try_render_canonical(&ast).expect("render canonical child")
}

enum FakeOutcome {
    SignWith(SigningKey),
    WriteRaw(Vec<u8>),
    RemoveOutputFile,
    FailExit(i32, String),
    FailIo(String),
}

struct RecordedCall {
    program: String,
    args: Vec<String>,
    stdin_len: usize,
    temp_dir: PathBuf,
    payload_len: usize,
}

struct FakePkcs11Runner {
    outcome: FakeOutcome,
    calls: RefCell<Vec<RecordedCall>>,
}

impl FakePkcs11Runner {
    fn new(outcome: FakeOutcome) -> Self {
        Self {
            outcome,
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl CommandRunner for FakePkcs11Runner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        let input_idx = args
            .iter()
            .position(|a| *a == "--input-file")
            .expect("--input-file present");
        let output_idx = args
            .iter()
            .position(|a| *a == "--output-file")
            .expect("--output-file present");
        let input_path = PathBuf::from(args[input_idx + 1]);
        let output_path = PathBuf::from(args[output_idx + 1]);
        let temp_dir = input_path.parent().expect("temp dir parent").to_path_buf();
        assert_eq!(output_path.parent(), Some(temp_dir.as_path()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&temp_dir).unwrap().permissions().mode() & 0o777;
            let in_mode = fs::metadata(&input_path).unwrap().permissions().mode() & 0o777;
            let out_mode = fs::metadata(&output_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "private temp dir must be 0700");
            assert_eq!(in_mode, 0o600, "payload temp file must be 0600");
            assert_eq!(out_mode, 0o600, "signature temp file must be 0600");
        }

        let payload = fs::read(&input_path).expect("read payload temp file");
        self.calls.borrow_mut().push(RecordedCall {
            program: program.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            stdin_len: stdin.len(),
            temp_dir,
            payload_len: payload.len(),
        });

        match &self.outcome {
            FakeOutcome::SignWith(signing_key) => {
                let sig: Signature = signing_key.sign(&payload);
                fs::write(&output_path, sig.to_bytes()).expect("write signature");
                Ok(CommandOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            FakeOutcome::WriteRaw(bytes) => {
                fs::write(&output_path, bytes).expect("write raw bytes");
                Ok(CommandOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            FakeOutcome::RemoveOutputFile => {
                fs::remove_file(&output_path).expect("remove output file");
                Ok(CommandOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            FakeOutcome::FailExit(code, stderr) => Err(AnchorError::CommandFailed {
                program: program.to_string(),
                status: Some(*code),
                stderr: stderr.clone(),
            }),
            FakeOutcome::FailIo(detail) => Err(AnchorError::CommandIo {
                program: program.to_string(),
                detail: detail.clone(),
            }),
        }
    }
}

#[test]
fn spki_der_and_pem_parser_accepts_valid_rfc8410_and_rejects_malformed_inputs() {
    // RFC 8410 Section 10.1 Ed25519 public key test vector:
    // MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
    let rfc8410_pem = "\
-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
-----END PUBLIC KEY-----\n";
    let expected_rfc8410_pub: [u8; 32] =
        hex::decode("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(
        parse_ed25519_spki_pem(rfc8410_pem).expect("valid RFC 8410 vector"),
        expected_rfc8410_pub
    );
    assert_eq!(
        parse_ed25519_spki_der(&spki_der(&expected_rfc8410_pub)).unwrap(),
        expected_rfc8410_pub
    );

    // Valid PEM with CRLF, leading/trailing blank lines, and multi-line wrapped base64 body.
    let b64 = encode_base64(&spki_der(&expected_rfc8410_pub));
    let wrapped_crlf = format!(
        "\r\n-----BEGIN PUBLIC KEY-----\r\n{}\r\n{}\r\n-----END PUBLIC KEY-----\r\n\r\n",
        &b64[..32],
        &b64[32..]
    );
    assert_eq!(
        parse_ed25519_spki_pem(&wrapped_crlf).expect("wrapped CRLF PEM"),
        expected_rfc8410_pub
    );

    // Real Ed25519 public key whose RFC 8410 SPKI base64 contains both '+' and '/'.
    let plus_slash_pk = (0u8..=255)
        .map(|seed| {
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes()
        })
        .find(|pk| {
            let b64 = encode_base64(&spki_der(pk));
            b64.contains('+') && b64.contains('/')
        })
        .expect("deterministic seed whose SPKI base64 exercises '+' and '/'");
    let plus_slash_pem = spki_pem(&spki_der(&plus_slash_pk));
    assert!(plus_slash_pem.contains('+') && plus_slash_pem.contains('/'));
    assert_eq!(
        parse_ed25519_spki_pem(&plus_slash_pem).expect("SPKI PEM with '+' and '/'"),
        plus_slash_pk
    );

    // Wrong OID: X25519 (1.3.101.110 -> 2b 65 6e instead of 2b 65 70).
    let mut x25519_der = spki_der(&expected_rfc8410_pub);
    x25519_der[8] = 0x6e;
    assert!(matches!(
        parse_ed25519_spki_der(&x25519_der),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("header or OID")
    ));
    assert!(matches!(
        parse_ed25519_spki_pem(&spki_pem(&x25519_der)),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("header or OID")
    ));

    // Wrong BIT STRING unused bits byte (0x01 instead of 0x00).
    let mut bad_unused = spki_der(&expected_rfc8410_pub);
    bad_unused[11] = 0x01;
    assert!(matches!(
        parse_ed25519_spki_der(&bad_unused),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // Wrong lengths: empty, 12-byte header only, 43-byte truncated (also exercises `==` b64 pad),
    // and 45-byte trailing byte (exercises unpadded b64).
    assert!(matches!(
        parse_ed25519_spki_der(&[]),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("got 0 bytes")
    ));
    assert!(matches!(
        parse_ed25519_spki_der(&ED25519_SPKI_DER_PREFIX),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("got 12 bytes")
    ));
    let truncated_43 = &spki_der(&expected_rfc8410_pub)[..43];
    assert!(encode_base64(truncated_43).ends_with("=="));
    assert!(matches!(
        parse_ed25519_spki_pem(&spki_pem(truncated_43)),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("got 43 bytes")
    ));
    let mut trailing_45 = spki_der(&expected_rfc8410_pub);
    trailing_45.push(0x00);
    assert!(!encode_base64(&trailing_45).ends_with('='));
    assert!(matches!(
        parse_ed25519_spki_pem(&spki_pem(&trailing_45)),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("got 45 bytes")
    ));

    // Invalid Ed25519 curve point inside otherwise valid 44-byte SPKI DER.
    let mut invalid_point = [0u8; 32];
    invalid_point[0] = 0x02;
    assert!(matches!(
        parse_ed25519_spki_der(&spki_der(&invalid_point)),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("point")
    ));
}

#[test]
fn spki_pem_parser_rejects_malformed_inputs() {
    // Malformed PEM cases.
    let malformed_pems = [
        "",
        "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
        "-----BEGIN RSA PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END RSA PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n",
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\nextra\n",
        "-----BEGIN PUBLIC KEY-----\nMCow\n\nBQYD\n-----END PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\rMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n",
        // Non-multiple-of-4 base64
        "-----BEGIN PUBLIC KEY-----\nMCowA\n-----END PUBLIC KEY-----\n",
        // Trailing bare CR at EOF without LF
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\r",
        // Invalid base64 char in quartet positions 0, 1, 2, 3, and index 2 before '='
        "-----BEGIN PUBLIC KEY-----\nMCow!QYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nA!AA\n-----END PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nAA!A\n-----END PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nAAA!\n-----END PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nAA!=\n-----END PUBLIC KEY-----\n",
        // Misplaced padding in middle and `=A` at end
        "-----BEGIN PUBLIC KEY-----\nAA==AAAA\n-----END PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nAA=A\n-----END PUBLIC KEY-----\n",
        // Non-canonical padding bits (`=` with low 2 bits set, `==` with low 4 bits set)
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuF=\n-----END PUBLIC KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nAB==\n-----END PUBLIC KEY-----\n",
        // Duplicate concatenated PEM blocks
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n",
    ];
    for pem in malformed_pems {
        assert!(
            matches!(
                parse_ed25519_spki_pem(pem),
                Err(AnchorError::InvalidPublicKey(_))
            ),
            "expected InvalidPublicKey for malformed PEM: {pem:?}"
        );
    }
}

#[test]
fn piv_signer_config_validation_fails_closed() {
    let sk = SigningKey::from_bytes(&[0x11; 32]);
    let pk = sk.verifying_key().to_bytes();

    let default_cfg = PivSignerConfig::default();
    assert_eq!(default_cfg.pkcs11_module, DEFAULT_PKCS11_MODULE);
    assert_eq!(default_cfg.key_id, DEFAULT_PIV_KEY_ID);
    assert_eq!(default_cfg.pin_source, PivPinSource::Interactive);

    let signer = PivEd25519Signer::from_spki_pem(
        FakePkcs11Runner::new(FakeOutcome::SignWith(sk.clone())),
        default_cfg.clone(),
        &spki_pem(&spki_der(&pk)),
    )
    .expect("valid PIV signer from SPKI PEM");
    assert_eq!(signer.public_key_bytes(), pk);
    assert_eq!(signer.config(), &default_cfg);
    assert_eq!(signer.key_id(), piv_ed25519_key_id(&pk));
    assert_eq!(MandateSigner::key_id(&signer), piv_ed25519_key_id(&pk));
    assert_eq!(signer.assurance(), AssuranceLevel::Passkey);

    // Invalid pkcs11_module paths (empty, whitespace, control chars, leading dash).
    for bad_mod in ["", "   ", "/lib/foo\nbar.so", "/lib/foo\0.so", "--module"] {
        let cfg = PivSignerConfig {
            pkcs11_module: bad_mod.to_string(),
            ..PivSignerConfig::default()
        };
        let err = PivEd25519Signer::new(
            FakePkcs11Runner::new(FakeOutcome::SignWith(sk.clone())),
            cfg,
            pk,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnchorError::InvalidConfig(_)),
            "expected InvalidConfig for module {bad_mod:?}, got {err:?}"
        );
        assert!(err.to_string().contains("invalid anchor configuration:"));
    }

    // Invalid PIV key IDs (empty, odd length, >64 chars, non-hex, leading dash).
    let long_hex = "ab".repeat(33);
    for bad_id in ["", "2", "0g", "--id", "02\n", long_hex.as_str()] {
        let cfg = PivSignerConfig {
            key_id: bad_id.to_string(),
            ..PivSignerConfig::default()
        };
        assert!(matches!(
            PivEd25519Signer::new(
                FakePkcs11Runner::new(FakeOutcome::SignWith(sk.clone())),
                cfg,
                pk,
            ),
            Err(AnchorError::InvalidConfig(_))
        ));
    }

    // Invalid PIN env var names (empty, numeric PIN, equals, colon, dash, control char).
    for bad_var in ["", "123456", "PIN=1234", "env:PIN", "--pin", "BAD\nVAR"] {
        let cfg = PivSignerConfig {
            pin_source: PivPinSource::EnvVar(bad_var.to_string()),
            ..PivSignerConfig::default()
        };
        assert!(matches!(
            PivEd25519Signer::new(
                FakePkcs11Runner::new(FakeOutcome::SignWith(sk.clone())),
                cfg,
                pk,
            ),
            Err(AnchorError::InvalidConfig(_))
        ));
    }

    // Malformed SPKI PEM passed to `PivEd25519Signer::from_spki_pem` fails closed.
    assert!(matches!(
        PivEd25519Signer::from_spki_pem(
            FakePkcs11Runner::new(FakeOutcome::SignWith(sk.clone())),
            PivSignerConfig::default(),
            "not-a-pem",
        ),
        Err(AnchorError::InvalidPublicKey(_))
    ));

    // Invalid Ed25519 curve point passed directly to `PivEd25519Signer::new`.
    let mut bad_pk = [0u8; 32];
    bad_pk[0] = 0x02;
    assert!(matches!(
        PivEd25519Signer::new(
            FakePkcs11Runner::new(FakeOutcome::SignWith(sk)),
            PivSignerConfig::default(),
            bad_pk,
        ),
        Err(AnchorError::InvalidPublicKey(_))
    ));
}

#[test]
fn piv_signer_interactive_and_env_pin_invokes_pkcs11_tool_with_private_temp_files_and_verifies() {
    let piv_sk = SigningKey::from_bytes(&[0x22; 32]);
    let piv_pk = piv_sk.verifying_key().to_bytes();
    let piv_key = piv_ed25519_key_id(&piv_pk);
    assert_eq!(piv_key.scheme(), PIV_ED25519_SCHEME);

    let disp_kp = Ed25519Keypair::from_secret_bytes([0x23; 32]);
    let worker_kp = Ed25519Keypair::from_secret_bytes([0x24; 32]);
    let root_words = root_mandate(&piv_key, &disp_kp.key_id());

    // 1. Interactive PIN mode: --login without --pin on argv.
    let runner_interactive = FakePkcs11Runner::new(FakeOutcome::SignWith(piv_sk.clone()));
    let signer_interactive =
        PivEd25519Signer::new(runner_interactive, PivSignerConfig::default(), piv_pk)
            .expect("construct interactive PIV signer");
    let vf = ts("2026-11-24T17:00:00Z");
    let vu = ts("2026-11-25T17:00:00Z");
    let signed_root = sign_mandate_with(&signer_interactive, &root_words, "yubikey-piv", vf, vu)
        .expect("sign root mandate with PIV signer");

    assert_eq!(signed_root.assurance, "passkey");
    assert_eq!(signed_root.signer_key, piv_key.to_string());
    assert_eq!(signed_root.anchor_id, "yubikey-piv");
    assert_eq!(signed_root.signature_hex.len(), 128);

    // Verify exact pkcs11-tool invocation and temp dir cleanup.
    let calls_interactive = signer_interactive.config();
    assert_eq!(calls_interactive.key_id, "02");

    // 2. EnvVar PIN mode: --login --pin env:HANDFEST_PIV_PIN (never literal PIN).
    let env_cfg = PivSignerConfig {
        pkcs11_module: "/opt/custom/libykcs11.so".to_string(),
        key_id: "04".to_string(),
        pin_source: PivPinSource::EnvVar(DEFAULT_PIV_PIN_ENV.to_string()),
    };
    let signer_env = PivEd25519Signer::new(
        FakePkcs11Runner::new(FakeOutcome::SignWith(piv_sk)),
        env_cfg,
        piv_pk,
    )
    .expect("construct env-pin PIV signer");
    let signed_root_env = sign_mandate_with(&signer_env, &root_words, "yubikey-piv", vf, vu)
        .expect("sign with env pin");
    // Ed25519 is deterministic: identical payload produces identical signature.
    assert_eq!(signed_root_env.signature_hex, signed_root.signature_hex);

    // Inspect recorded runner calls directly via a separate runner wrapped in RefCell-checked signer.
    let inspect_sk = SigningKey::from_bytes(&[0x25; 32]);
    let inspect_pk = inspect_sk.verifying_key().to_bytes();
    let inspect_runner = FakePkcs11Runner::new(FakeOutcome::SignWith(inspect_sk));
    let inspect_signer = PivEd25519Signer::new(
        &inspect_runner,
        PivSignerConfig {
            pkcs11_module: "/usr/lib/libykcs11.so".to_string(),
            key_id: "02".to_string(),
            pin_source: PivPinSource::EnvVar("HANDFEST_PIV_PIN".to_string()),
        },
        inspect_pk,
    )
    .unwrap();
    let _ = inspect_signer.sign_payload(b"hello-piv").unwrap();
    let recorded = inspect_runner.calls.borrow();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].program, "pkcs11-tool");
    assert_eq!(recorded[0].stdin_len, 0);
    assert_eq!(recorded[0].payload_len, b"hello-piv".len());
    assert_eq!(
        &recorded[0].args[..10],
        &[
            "--module",
            "/usr/lib/libykcs11.so",
            "--login",
            "--pin",
            "env:HANDFEST_PIV_PIN",
            "--sign",
            "--mechanism",
            "EDDSA",
            "--id",
            "02",
        ]
    );
    assert!(
        !recorded[0].temp_dir.exists(),
        "private temp dir must be cleaned up on drop after success"
    );

    // Verify via PivEd25519Verifier, verify_piv_ed25519, AnchorRegistry::default_registry(),
    // and heterogeneous 2-hop verify_chain (PIV root -> local Ed25519 child).
    let verified_direct = PivEd25519Verifier
        .verify(&signed_root)
        .expect("PivEd25519Verifier verifies signed root");
    assert_eq!(verified_direct.proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(verified_direct.proof.signer_key, piv_key);
    assert_eq!(verified_direct.proof.actor_kind, ActorKind::Human);

    let registry = AnchorRegistry::default_registry();
    assert!(format!("{registry:?}").contains(PIV_ED25519_SCHEME));
    let verified_reg = registry
        .verify(&signed_root)
        .expect("default_registry verifies piv-ed25519");
    assert_eq!(verified_reg, verified_direct);

    let root_id = verified_direct.ast.try_mandate_id().unwrap();
    let child_words = child_mandate(root_id, &disp_kp.key_id(), &worker_kp.key_id());
    let signed_child = disp_kp
        .sign_mandate(&child_words, "local-ed25519", vf, vu)
        .unwrap();
    let chain = verify_chain(&[signed_root, signed_child])
        .expect("verify_chain verifies heterogeneous PIV + Ed25519 chain");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].proof.assurance, AssuranceLevel::Passkey);
    assert_eq!(chain[1].proof.assurance, AssuranceLevel::LocalKey);
}

impl CommandRunner for &FakePkcs11Runner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        FakePkcs11Runner::run(self, program, args, stdin)
    }
}

#[test]
fn piv_signer_fails_closed_on_pkcs11_errors_and_bad_signatures() {
    let sk = SigningKey::from_bytes(&[0x31; 32]);
    let pk = sk.verifying_key().to_bytes();

    // Non-zero exit cleans up private temp dir and returns CommandFailed.
    let fail_runner =
        FakePkcs11Runner::new(FakeOutcome::FailExit(1, "CKR_PIN_INCORRECT".to_string()));
    let signer = PivEd25519Signer::new(&fail_runner, PivSignerConfig::default(), pk).unwrap();
    let err = signer.sign_payload(b"payload").unwrap_err();
    assert_eq!(
        err,
        AnchorError::CommandFailed {
            program: "pkcs11-tool".to_string(),
            status: Some(1),
            stderr: "CKR_PIN_INCORRECT".to_string(),
        }
    );
    assert!(
        !fail_runner.calls.borrow()[0].temp_dir.exists(),
        "private temp dir must be cleaned up on drop after error"
    );

    // Spawn/IO error propagates CommandIo.
    let io_runner = FakePkcs11Runner::new(FakeOutcome::FailIo("not found".to_string()));
    let io_signer = PivEd25519Signer::new(&io_runner, PivSignerConfig::default(), pk).unwrap();
    assert_eq!(
        io_signer.sign_payload(b"payload").unwrap_err(),
        AnchorError::CommandIo {
            program: "pkcs11-tool".to_string(),
            detail: "not found".to_string(),
        }
    );

    // Wrong signature lengths (0, 63, 65) fail closed with InvalidSignature.
    for bad_len in [0usize, 63, 65] {
        let bad_len_runner = FakePkcs11Runner::new(FakeOutcome::WriteRaw(vec![0xaa; bad_len]));
        let s = PivEd25519Signer::new(&bad_len_runner, PivSignerConfig::default(), pk).unwrap();
        assert!(matches!(
            s.sign_payload(b"payload"),
            Err(AnchorError::InvalidSignature(msg)) if msg.contains("expected 64")
        ));
    }

    // 64 bytes signed by a different key fail closed on self-verification.
    let other_sk = SigningKey::from_bytes(&[0x32; 32]);
    let wrong_key_runner = FakePkcs11Runner::new(FakeOutcome::SignWith(other_sk));
    let s = PivEd25519Signer::new(&wrong_key_runner, PivSignerConfig::default(), pk).unwrap();
    assert!(matches!(
        s.sign_payload(b"payload"),
        Err(AnchorError::InvalidSignature(msg)) if msg.contains("failed verification")
    ));

    // Deleted output file fails closed with CommandIo.
    let del_runner = FakePkcs11Runner::new(FakeOutcome::RemoveOutputFile);
    let s = PivEd25519Signer::new(&del_runner, PivSignerConfig::default(), pk).unwrap();
    assert!(matches!(
        s.sign_payload(b"payload"),
        Err(AnchorError::CommandIo { program, detail })
            if program == "pkcs11-tool" && detail.contains("failed to read signature output")
    ));
}

#[test]
fn piv_verifier_adversarial_tamper_and_downgrade_checks() {
    let piv_sk = SigningKey::from_bytes(&[0x71; 32]);
    let piv_pk = piv_sk.verifying_key().to_bytes();
    let piv_key = piv_ed25519_key_id(&piv_pk);
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x72; 32]);
    let words = root_mandate(&piv_key, &agent_kp.key_id());

    let signer = PivEd25519Signer::new(
        FakePkcs11Runner::new(FakeOutcome::SignWith(piv_sk.clone())),
        PivSignerConfig::default(),
        piv_pk,
    )
    .unwrap();
    let vf = ts("2026-11-24T17:00:00Z");
    let vu = ts("2026-11-25T17:00:00Z");
    let valid = sign_mandate_with(&signer, &words, "yubikey-piv", vf, vu).unwrap();

    // Wrong assurance level (`local_key` instead of `passkey`) rejected.
    let mut wrong_assurance = valid.clone();
    wrong_assurance.assurance = "local_key".to_string();
    assert_eq!(
        verify_piv_ed25519(&wrong_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::Passkey,
            actual: AssuranceLevel::LocalKey,
        })
    );
    assert_eq!(
        AnchorRegistry::default_registry().verify(&wrong_assurance),
        Err(AnchorError::UnsupportedAssurance {
            expected: AssuranceLevel::Passkey,
            actual: AssuranceLevel::LocalKey,
        })
    );

    // Tampered actor_kind rejected.
    let mut wrong_actor_kind = valid.clone();
    wrong_actor_kind.actor_kind = "agent".to_string();
    assert_eq!(
        verify_piv_ed25519(&wrong_actor_kind),
        Err(AnchorError::ActorKindMismatch {
            expected: ActorKind::Human,
            actual: ActorKind::Agent,
        })
    );

    // Wrong signature length (63 bytes and 65 bytes) and uppercase hex rejected.
    let mut short_sig = valid.clone();
    short_sig.signature_hex = "aa".repeat(63);
    assert!(matches!(
        verify_piv_ed25519(&short_sig),
        Err(AnchorError::InvalidSignature(_))
    ));
    let mut long_sig = valid.clone();
    long_sig.signature_hex = "aa".repeat(65);
    assert!(matches!(
        verify_piv_ed25519(&long_sig),
        Err(AnchorError::InvalidSignature(_))
    ));
    let mut upper_sig = valid.clone();
    upper_sig.signature_hex = valid.signature_hex.to_uppercase();
    assert!(matches!(
        verify_piv_ed25519(&upper_sig),
        Err(AnchorError::InvalidSignature(_))
    ));

    // Tampered canonical_words, valid_from, valid_until, anchor_id all fail strict verification.
    let mut tampered_words = valid.clone();
    tampered_words.canonical_words = tampered_words
        .canonical_words
        .replace("Valentin", "Mallory");
    assert!(matches!(
        verify_piv_ed25519(&tampered_words),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut tampered_vf = valid.clone();
    tampered_vf.valid_from += 1;
    assert!(matches!(
        verify_piv_ed25519(&tampered_vf),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut tampered_vu = valid.clone();
    tampered_vu.valid_until += 1;
    assert!(matches!(
        verify_piv_ed25519(&tampered_vu),
        Err(AnchorError::InvalidSignature(_))
    ));

    let mut tampered_anchor = valid.clone();
    tampered_anchor.anchor_id = "attacker-piv".to_string();
    assert!(matches!(
        verify_piv_ed25519(&tampered_anchor),
        Err(AnchorError::InvalidSignature(_))
    ));
}

#[test]
fn piv_verifier_enforces_cross_scheme_and_signer_isolation() {
    let piv_sk = SigningKey::from_bytes(&[0x71; 32]);
    let piv_pk = piv_sk.verifying_key().to_bytes();
    let piv_key = piv_ed25519_key_id(&piv_pk);
    let agent_kp = Ed25519Keypair::from_secret_bytes([0x72; 32]);
    let words = root_mandate(&piv_key, &agent_kp.key_id());
    let signer = PivEd25519Signer::new(
        FakePkcs11Runner::new(FakeOutcome::SignWith(piv_sk)),
        PivSignerConfig::default(),
        piv_pk,
    )
    .unwrap();
    let vf = ts("2026-11-24T17:00:00Z");
    let vu = ts("2026-11-25T17:00:00Z");
    let valid = sign_mandate_with(&signer, &words, "yubikey-piv", vf, vu).unwrap();

    // Cross-scheme isolation: Ed25519Verifier rejects piv-ed25519, and verify_piv_ed25519 rejects ed25519.
    assert!(matches!(
        Ed25519Verifier.verify(&valid),
        Err(AnchorError::UnsupportedAssurance { .. })
    ));
    assert!(matches!(
        verify_ed25519(&valid),
        Err(AnchorError::UnsupportedAssurance { .. })
    ));

    let mut ed_scheme_envelope = valid.clone();
    ed_scheme_envelope.signer_key = format!("ed25519:{}", hex::encode(piv_pk));
    assert!(matches!(
        verify_piv_ed25519(&ed_scheme_envelope),
        Err(AnchorError::InvalidPublicKey(msg)) if msg.contains("piv-ed25519")
    ));

    // Mismatched signer_key vs mandate FROM rejected.
    let other_piv_key = piv_ed25519_key_id(
        &SigningKey::from_bytes(&[0x73; 32])
            .verifying_key()
            .to_bytes(),
    );
    let mut wrong_signer = valid.clone();
    wrong_signer.signer_key = other_piv_key.to_string();
    assert_eq!(
        verify_piv_ed25519(&wrong_signer),
        Err(AnchorError::SignerMismatch {
            expected: piv_key.to_string(),
            actual: other_piv_key.to_string(),
        })
    );
}
