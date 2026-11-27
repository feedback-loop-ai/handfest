//! Unit and boundary tests for bounded fail-closed wire protocol framing and validation.

use std::io::{self, BufRead, BufReader, Cursor, Read};

use handfest_anchors::{sign_mandate_with, Ed25519Keypair};
use handfest_approver::protocol::{
    decode_sign_request, decode_sign_response, write_frame, FrameReader, ProtocolError,
    SignRequest, SignResponse, ERR_FRAME_TOO_LARGE, ERR_INVALID_FRAME, ERR_INVALID_REQUEST,
    ERR_TIMEOUT, MAX_FRAME_BYTES, MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES,
};
use handfest_core::ast::{KeyId, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP};
use handfest_core::cnl::{parse_mandate, try_render_canonical};

fn canonical_sample(signer: &Ed25519Keypair) -> String {
    let agent = KeyId::new("ed25519", "2".repeat(64)).unwrap();
    let draft = format!(
        "HANDFEST v1\nFROM human \"Valentin\" (key: {})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/app\"\n",
        signer.key_id()
    );
    try_render_canonical(&parse_mandate(&draft).unwrap()).unwrap()
}

#[test]
fn protocol_roundtrips_requests_and_all_response_variants() {
    let kp = Ed25519Keypair::from_secret_bytes([0x11; 32]);
    let canonical = canonical_sample(&kp);
    let req = SignRequest {
        mandate_text: canonical.clone(),
        valid_from: 1_760_000_000,
        valid_until: 1_760_003_600,
        anchor_id: Some("custom-anchor".to_string()),
    };

    let mut wire = Vec::new();
    write_frame(&mut wire, &req, MAX_FRAME_BYTES).expect("write request");
    assert_eq!(wire.last(), Some(&b'\n'));

    let mut reader = FrameReader::new(Cursor::new(wire));
    let line = reader
        .read_frame_line(MAX_FRAME_BYTES)
        .expect("read frame")
        .expect("non-eof");
    assert_eq!(decode_sign_request(&line).expect("decode req"), req);
    assert_eq!(
        reader.read_frame_line(MAX_FRAME_BYTES).expect("clean eof"),
        None
    );

    let signed = sign_mandate_with(
        &kp,
        &canonical,
        "local-ed25519",
        1_760_000_000,
        1_760_003_600,
    )
    .unwrap();
    let responses = [
        SignResponse::Approved {
            signed_mandate: signed,
        },
        SignResponse::Denied {
            reason: "operator declined".to_string(),
        },
        SignResponse::Error {
            code: ERR_INVALID_REQUEST.to_string(),
            message: "bad window".to_string(),
        },
    ];
    for expected in responses {
        let mut buf = Vec::new();
        write_frame(&mut buf, &expected, MAX_FRAME_BYTES).unwrap();
        let mut r = FrameReader::new(Cursor::new(buf));
        let line = r.read_frame_line(MAX_FRAME_BYTES).unwrap().unwrap();
        let decoded = decode_sign_response(&line).unwrap();
        assert_eq!(decoded, expected);
    }
}

#[test]
fn protocol_rejects_oversized_truncated_utf8_and_control_byte_frames() {
    let oversized = format!("{}\n", "a".repeat(MAX_FRAME_BYTES + 1));
    let mut r = FrameReader::new(Cursor::new(oversized.as_bytes()));
    let err = r.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::FrameTooLarge {
            max_bytes: MAX_FRAME_BYTES
        }
    ));
    assert_eq!(err.error_code(), ERR_FRAME_TOO_LARGE);

    let mut truncated = FrameReader::new(Cursor::new(b"{\"mandate_text\":\"x\"}".as_slice()));
    let trunc_err = truncated.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(matches!(trunc_err, ProtocolError::TruncatedFrame));
    assert_eq!(trunc_err.error_code(), ERR_INVALID_FRAME);

    let mut bad_utf8 = FrameReader::new(Cursor::new(vec![0xff, 0xfe, b'\n']));
    let utf8_err = bad_utf8.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(matches!(utf8_err, ProtocolError::InvalidUtf8));

    for bad_byte in [0x00u8, b'\r', b'\t', 0x1b, 0x7f] {
        let mut raw = FrameReader::new(Cursor::new(vec![b'{', bad_byte, b'}', b'\n']));
        let ctrl_err = raw.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(ctrl_err, ProtocolError::ControlChar(_)));
        assert_eq!(ctrl_err.error_code(), ERR_INVALID_REQUEST);
    }

    let big_req = SignRequest {
        mandate_text: "x".repeat(MAX_FRAME_BYTES),
        valid_from: 10,
        valid_until: 20,
        anchor_id: None,
    };
    let mut sink = Vec::new();
    let write_err = write_frame(&mut sink, &big_req, MAX_FRAME_BYTES).unwrap_err();
    assert!(matches!(
        write_err,
        ProtocolError::FrameTooLarge {
            max_bytes: MAX_FRAME_BYTES
        }
    ));

    let timeout_err = ProtocolError::Io(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
    assert_eq!(timeout_err.error_code(), ERR_TIMEOUT);
    assert!(std::error::Error::source(&timeout_err).is_some());
}

#[test]
fn protocol_rejects_unknown_fields_duplicate_keys_and_invalid_request_semantics() {
    let unknown = r#"{"mandate_text":"HANDFEST v1","valid_from":10,"valid_until":20,"extra":1}"#;
    assert!(matches!(
        decode_sign_request(unknown).unwrap_err(),
        ProtocolError::InvalidJson(_)
    ));

    let dup_key = r#"{"mandate_text":"HANDFEST v1","mandate_text":"HANDFEST v1","valid_from":10,"valid_until":20}"#;
    assert!(matches!(
        decode_sign_request(dup_key).unwrap_err(),
        ProtocolError::InvalidJson(_)
    ));

    let inverted = r#"{"mandate_text":"HANDFEST v1","valid_from":200,"valid_until":100}"#;
    assert!(matches!(
        decode_sign_request(inverted).unwrap_err(),
        ProtocolError::InvalidValidityWindow {
            valid_from: 200,
            valid_until: 100
        }
    ));

    let nul_in_mandate =
        r#"{"mandate_text":"HANDFEST v1\u0000","valid_from":100,"valid_until":200}"#;
    assert!(matches!(
        decode_sign_request(nul_in_mandate).unwrap_err(),
        ProtocolError::ControlChar(_)
    ));

    let ansi_in_mandate =
        r#"{"mandate_text":"HANDFEST v1\u001b[31m","valid_from":100,"valid_until":200}"#;
    assert!(matches!(
        decode_sign_request(ansi_in_mandate).unwrap_err(),
        ProtocolError::ControlChar(_)
    ));

    let empty_mandate = r#"{"mandate_text":"   \n  ","valid_from":100,"valid_until":200}"#;
    assert!(matches!(
        decode_sign_request(empty_mandate).unwrap_err(),
        ProtocolError::InvalidRequest(_)
    ));

    let out_of_range = SignRequest {
        mandate_text: "HANDFEST v1".to_string(),
        valid_from: MIN_RFC3339_TIMESTAMP - 1,
        valid_until: MAX_RFC3339_TIMESTAMP + 1,
        anchor_id: None,
    };
    assert!(matches!(
        out_of_range.validate().unwrap_err(),
        ProtocolError::InvalidRequest(_)
    ));

    let bad_anchor = SignRequest {
        mandate_text: "HANDFEST v1".to_string(),
        valid_from: 10,
        valid_until: 20,
        anchor_id: Some("bad\nanchor".to_string()),
    };
    assert!(matches!(
        bad_anchor.validate().unwrap_err(),
        ProtocolError::ControlChar(_)
    ));

    let unknown_resp = r#"{"status":"denied","reason":"no","extra":true}"#;
    assert!(matches!(
        decode_sign_response(unknown_resp).unwrap_err(),
        ProtocolError::InvalidJson(_)
    ));

    let ctrl_resp = r#"{"status":"denied","reason":"bad\nline"}"#;
    assert!(matches!(
        decode_sign_response(ctrl_resp).unwrap_err(),
        ProtocolError::ControlChar(_)
    ));
}

#[test]
fn protocol_covers_remaining_error_variants_and_display_messages() {
    let empty_anchor = SignRequest {
        mandate_text: "HANDFEST v1".to_string(),
        valid_from: 10,
        valid_until: 20,
        anchor_id: Some(String::new()),
    };
    let err = empty_anchor.validate().unwrap_err();
    assert!(matches!(err, ProtocolError::InvalidRequest(_)));
    assert!(err.to_string().contains("anchor_id"));

    let huge_line = "x".repeat(MAX_REQUEST_FRAME_BYTES + 1);
    assert!(matches!(
        decode_sign_request(&huge_line).unwrap_err(),
        ProtocolError::FrameTooLarge {
            max_bytes: MAX_REQUEST_FRAME_BYTES
        }
    ));

    let empty_err_code = r#"{"status":"error","code":"","message":"boom"}"#;
    assert!(matches!(
        decode_sign_response(empty_err_code).unwrap_err(),
        ProtocolError::InvalidRequest(_)
    ));

    let empty_err_msg = r#"{"status":"error","code":"bad","message":""}"#;
    assert!(matches!(
        decode_sign_response(empty_err_msg).unwrap_err(),
        ProtocolError::InvalidRequest(_)
    ));

    let ctrl_err_code = r#"{"status":"error","code":"bad\ncode","message":"boom"}"#;
    assert!(matches!(
        decode_sign_response(ctrl_err_code).unwrap_err(),
        ProtocolError::ControlChar(_)
    ));

    let other_io = ProtocolError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "pipe"));
    assert_eq!(other_io.error_code(), ERR_INVALID_FRAME);
    assert!(other_io.to_string().contains("protocol I/O error"));
}

#[test]
fn protocol_rejects_unicode_wysiwys_spoofing_in_mandate_and_anchor_id() {
    let kp = Ed25519Keypair::from_secret_bytes([0x12; 32]);
    let valid_mandate = canonical_sample(&kp);

    for bad_char in [
        '\u{2028}', '\u{2029}', '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}',
        '\u{2066}', '\u{2069}',
    ] {
        let req_anchor = SignRequest {
            mandate_text: valid_mandate.clone(),
            valid_from: 100,
            valid_until: 200,
            anchor_id: Some(format!("local{bad_char}ed25519")),
        };
        let anchor_err = req_anchor.validate().unwrap_err();
        assert!(
            matches!(anchor_err, ProtocolError::ControlChar(_)),
            "U+{:04X} in anchor_id must fail with ControlChar, got {anchor_err:?}",
            u32::from(bad_char)
        );
        assert_eq!(anchor_err.error_code(), ERR_INVALID_REQUEST);

        let req_mandate = SignRequest {
            mandate_text: format!("{valid_mandate}{bad_char}"),
            valid_from: 100,
            valid_until: 200,
            anchor_id: None,
        };
        let mandate_err = req_mandate.validate().unwrap_err();
        assert!(
            matches!(mandate_err, ProtocolError::ControlChar(_)),
            "U+{:04X} in mandate_text must fail with ControlChar, got {mandate_err:?}",
            u32::from(bad_char)
        );
        assert_eq!(mandate_err.error_code(), ERR_INVALID_REQUEST);

        let wire = serde_json::to_string(&req_mandate).unwrap();
        let decoded_err = decode_sign_request(&wire).unwrap_err();
        assert!(matches!(decoded_err, ProtocolError::ControlChar(_)));
        assert_eq!(decoded_err.error_code(), ERR_INVALID_REQUEST);
    }
}

#[test]
fn read_frame_line_drains_oversized_tail_so_json_tail_is_never_smuggled() {
    // Use a 16-byte BufReader capacity so the oversized line spans multiple fill_buf chunks.
    let single_oversized = format!(
        "{}{{\"status\":\"denied\",\"reason\":\"smuggled\"}}\n",
        "a".repeat(100)
    );
    let mut reader = FrameReader::new(BufReader::with_capacity(
        16,
        Cursor::new(single_oversized.into_bytes()),
    ));
    let first = reader.read_frame_line(64).unwrap_err();
    assert!(matches!(
        first,
        ProtocolError::FrameTooLarge { max_bytes: 64 }
    ));
    assert!(!reader.is_poisoned());
    assert_eq!(reader.read_frame_line(64).unwrap(), None);

    // A genuine second frame after the oversized line's `\n` is read cleanly without the smuggled tail.
    let with_next = format!("{}{{\"smuggled\":true}}\n{{\"next\":2}}\n", "b".repeat(100));
    let mut reader2 = FrameReader::new(BufReader::with_capacity(
        16,
        Cursor::new(with_next.into_bytes()),
    ));
    assert!(matches!(
        reader2.read_frame_line(64).unwrap_err(),
        ProtocolError::FrameTooLarge { max_bytes: 64 }
    ));
    assert!(!reader2.is_poisoned());
    assert_eq!(
        reader2.read_frame_line(64).unwrap(),
        Some("{\"next\":2}".to_string())
    );
}

#[test]
fn frame_reader_poisons_when_oversized_line_exceeds_drain_limit() {
    let smuggled_tail = r#"{"mandate_text":"HANDFEST v1","valid_from":10,"valid_until":20}"#;
    let payload = format!(
        "{}{smuggled_tail}\n",
        "a".repeat(MAX_FRAME_BYTES + 1_048_576)
    );
    let mut reader = FrameReader::new(BufReader::new(Cursor::new(payload.into_bytes())));

    let first = reader.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(matches!(
        first,
        ProtocolError::FrameTooLarge {
            max_bytes: MAX_FRAME_BYTES
        }
    ));
    assert!(reader.is_poisoned());

    // Subsequent call MUST fail closed and NEVER return the smuggled JSON tail as Ok(Some(_)).
    let second = reader.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(matches!(
        second,
        ProtocolError::FrameTooLarge {
            max_bytes: MAX_FRAME_BYTES
        }
    ));

    // Read error during oversized drain must also poison the reader so no tail is returned later.
    struct FailOnSecondChunk {
        calls: usize,
        first_chunk: Vec<u8>,
    }
    impl Read for FailOnSecondChunk {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "drain io error"))
        }
    }
    impl BufRead for FailOnSecondChunk {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.calls += 1;
            if self.calls == 1 {
                Ok(&self.first_chunk)
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "drain io error"))
            }
        }
        fn consume(&mut self, amt: usize) {
            if self.calls == 1 {
                self.first_chunk.drain(..amt);
            }
        }
    }

    let mut err_reader = FrameReader::new(FailOnSecondChunk {
        calls: 0,
        first_chunk: vec![b'x'; 80],
    });
    assert!(matches!(
        err_reader.read_frame_line(64).unwrap_err(),
        ProtocolError::FrameTooLarge { max_bytes: 64 }
    ));
    assert!(err_reader.is_poisoned());
    assert!(matches!(
        err_reader.read_frame_line(64).unwrap_err(),
        ProtocolError::FrameTooLarge { max_bytes: 64 }
    ));
}

#[test]
fn protocol_enforces_request_response_size_headroom() {
    const { assert!(MAX_REQUEST_FRAME_BYTES == 56 * 1024) };
    const { assert!(MAX_RESPONSE_FRAME_BYTES == 64 * 1024) };
    const { assert!(MAX_REQUEST_FRAME_BYTES < MAX_RESPONSE_FRAME_BYTES) };

    // Response larger than MAX_REQUEST_FRAME_BYTES but <= MAX_RESPONSE_FRAME_BYTES is accepted.
    let big_msg = "m".repeat(MAX_REQUEST_FRAME_BYTES + 128);
    let resp_line = serde_json::to_string(&SignResponse::Denied {
        reason: big_msg.clone(),
    })
    .unwrap();
    assert!(resp_line.len() > MAX_REQUEST_FRAME_BYTES);
    assert!(resp_line.len() <= MAX_RESPONSE_FRAME_BYTES);
    assert_eq!(
        decode_sign_response(&resp_line).unwrap(),
        SignResponse::Denied { reason: big_msg }
    );
}

#[test]
fn sign_response_validate_rejects_malformed_approved_denied_and_error_fields() {
    for bad_resp in [
        r#"{"status":"denied","reason":"   "}"#,
        r#"{"status":"error","code":"   ","message":"ok"}"#,
        r#"{"status":"error","code":"bad","message":"   "}"#,
    ] {
        assert!(matches!(
            decode_sign_response(bad_resp).unwrap_err(),
            ProtocolError::InvalidRequest(_)
        ));
    }

    let kp = Ed25519Keypair::from_secret_bytes([0x13; 32]);
    let canonical = canonical_sample(&kp);
    let valid_signed = sign_mandate_with(
        &kp,
        &canonical,
        "local-ed25519",
        1_760_000_000,
        1_760_003_600,
    )
    .unwrap();

    let decode_approved = |signed_mandate: handfest_anchors::SignedMandate| {
        let wire = serde_json::to_string(&SignResponse::Approved { signed_mandate }).unwrap();
        decode_sign_response(&wire).unwrap_err()
    };

    let mut empty_words = valid_signed.clone();
    empty_words.canonical_words = "  \n ".to_string();
    assert!(matches!(
        decode_approved(empty_words),
        ProtocolError::InvalidRequest(_)
    ));

    let mut ansi_words = valid_signed.clone();
    ansi_words.canonical_words.push_str("\x1b[31m");
    assert!(matches!(
        decode_approved(ansi_words),
        ProtocolError::ControlChar(_)
    ));

    let mut bidi_words = valid_signed.clone();
    bidi_words.canonical_words.push('\u{202E}');
    assert!(matches!(
        decode_approved(bidi_words),
        ProtocolError::ControlChar(_)
    ));

    let mut bidi_anchor = valid_signed.clone();
    bidi_anchor.anchor_id = "local\u{2028}anchor".to_string();
    assert!(matches!(
        decode_approved(bidi_anchor),
        ProtocolError::ControlChar(_)
    ));

    let mut nl_anchor = valid_signed.clone();
    nl_anchor.anchor_id = "local\nanchor".to_string();
    assert!(matches!(
        decode_approved(nl_anchor),
        ProtocolError::ControlChar(_)
    ));

    let mut inverted = valid_signed.clone();
    inverted.valid_from = 200;
    inverted.valid_until = 100;
    assert!(matches!(
        decode_approved(inverted),
        ProtocolError::InvalidValidityWindow {
            valid_from: 200,
            valid_until: 100,
        }
    ));

    for mutate in [
        (|s: &mut handfest_anchors::SignedMandate| s.anchor_id = "  ".to_string()) as fn(&mut _),
        |s| s.assurance = String::new(),
        |s| s.actor_kind = " ".to_string(),
        |s| s.signer_key = String::new(),
        |s| s.signature_hex = "  ".to_string(),
    ] {
        let mut bad = valid_signed.clone();
        mutate(&mut bad);
        assert!(matches!(
            decode_approved(bad),
            ProtocolError::InvalidRequest(_)
        ));
    }

    let mut nul_sig = valid_signed;
    nul_sig.signature_hex = "ab\0cd".to_string();
    assert!(matches!(
        decode_approved(nul_sig),
        ProtocolError::ControlChar(_)
    ));
}

#[test]
fn frame_reader_poisons_on_partial_line_io_error_and_blocks_tail_smuggling() {
    struct PartialIoReader {
        step: usize,
        chunk1: Vec<u8>,
        chunk3: Vec<u8>,
    }

    impl Read for PartialIoReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "unused"))
        }
    }

    impl BufRead for PartialIoReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.step += 1;
            match self.step {
                1 => Ok(&self.chunk1),
                2 => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "simulated mid-line EAGAIN",
                )),
                3 => Ok(&self.chunk3),
                _ => Ok(&[]),
            }
        }

        fn consume(&mut self, amt: usize) {
            match self.step {
                1 => {
                    self.chunk1.drain(..amt);
                }
                3 => {
                    self.chunk3.drain(..amt);
                }
                _ => {}
            }
        }
    }

    let mut reader = FrameReader::new(PartialIoReader {
        step: 0,
        chunk1: b"bad\x00prefix".to_vec(),
        chunk3: b"{\"status\":\"denied\",\"reason\":\"smuggled\"}\n".to_vec(),
    });
    assert!(!reader.is_poisoned());

    let first_err = reader.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(
        matches!(
            first_err,
            ProtocolError::Io(ref err) if err.kind() == io::ErrorKind::WouldBlock
        ),
        "expected WouldBlock IO error on call 1, got {first_err:?}"
    );
    assert!(reader.is_poisoned());

    let second_err = reader.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(
        matches!(second_err, ProtocolError::StreamPoisoned),
        "call 2 MUST fail closed with StreamPoisoned, got {second_err:?}"
    );
    assert_eq!(second_err.error_code(), ERR_INVALID_FRAME);
    assert!(second_err.to_string().contains("poisoned"));

    // Contrast: an I/O error BEFORE any byte of the frame has been consumed does NOT poison the
    // reader, so a retry cleanly reads the next complete frame.
    struct LeadingWouldBlockReader {
        step: usize,
        frame: Vec<u8>,
    }
    impl Read for LeadingWouldBlockReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "unused"))
        }
    }
    impl BufRead for LeadingWouldBlockReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.step += 1;
            match self.step {
                1 => Err(io::Error::new(io::ErrorKind::WouldBlock, "no bytes yet")),
                2 => Ok(&self.frame),
                _ => Ok(&[]),
            }
        }
        fn consume(&mut self, amt: usize) {
            if self.step == 2 {
                self.frame.drain(..amt);
            }
        }
    }

    let mut clean_retry = FrameReader::new(LeadingWouldBlockReader {
        step: 0,
        frame: b"{\"ok\":true}\n".to_vec(),
    });
    assert!(matches!(
        clean_retry.read_frame_line(MAX_FRAME_BYTES).unwrap_err(),
        ProtocolError::Io(ref err) if err.kind() == io::ErrorKind::WouldBlock
    ));
    assert!(!clean_retry.is_poisoned());
    assert_eq!(
        clean_retry.read_frame_line(MAX_FRAME_BYTES).unwrap(),
        Some("{\"ok\":true}".to_string())
    );
}

#[test]
fn frame_reader_poisons_on_mid_line_eof_and_oversized_eof_blocking_file_append_smuggling() {
    use std::fs::{File, OpenOptions};
    use std::io::Write;

    let dir = tempfile::TempDir::new().unwrap();

    // 1. Mid-line EOF (partial frame without '\n') poisons the reader so subsequently appended
    // bytes on a growable File cannot be smuggled as a fresh valid frame.
    let partial_path = dir.path().join("partial_eof.log");
    {
        let mut f = File::create(&partial_path).unwrap();
        f.write_all(b"bad\x00prefix").unwrap();
        f.flush().unwrap();
    }
    let mut partial_reader = FrameReader::new(BufReader::new(File::open(&partial_path).unwrap()));
    assert!(!partial_reader.is_poisoned());
    let first_err = partial_reader.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(
        matches!(first_err, ProtocolError::TruncatedFrame),
        "expected TruncatedFrame on mid-line EOF, got {first_err:?}"
    );
    assert!(partial_reader.is_poisoned());

    {
        let mut append = OpenOptions::new().append(true).open(&partial_path).unwrap();
        append
            .write_all(b"{\"status\":\"denied\",\"reason\":\"smuggled\"}\n")
            .unwrap();
        append.flush().unwrap();
    }
    let second_err = partial_reader.read_frame_line(MAX_FRAME_BYTES).unwrap_err();
    assert!(
        matches!(second_err, ProtocolError::StreamPoisoned),
        "expected StreamPoisoned after mid-line EOF + append, got {second_err:?}"
    );

    // 2. Oversized newline-free prefix ending in EOF poisons the reader with Oversized { max_bytes }
    // so subsequently appended bytes cannot be smuggled as a fresh valid frame.
    let oversized_path = dir.path().join("oversized_eof.log");
    {
        let mut f = File::create(&oversized_path).unwrap();
        f.write_all(&[b'a'; 80]).unwrap();
        f.flush().unwrap();
    }
    let mut oversized_reader =
        FrameReader::new(BufReader::new(File::open(&oversized_path).unwrap()));
    assert!(!oversized_reader.is_poisoned());
    let over_err = oversized_reader.read_frame_line(64).unwrap_err();
    assert!(
        matches!(over_err, ProtocolError::FrameTooLarge { max_bytes: 64 }),
        "expected FrameTooLarge {{ max_bytes: 64 }}, got {over_err:?}"
    );
    assert!(oversized_reader.is_poisoned());

    {
        let mut append = OpenOptions::new()
            .append(true)
            .open(&oversized_path)
            .unwrap();
        append
            .write_all(b"{\"status\":\"denied\",\"reason\":\"smuggled\"}\n")
            .unwrap();
        append.flush().unwrap();
    }
    let over_second_err = oversized_reader.read_frame_line(64).unwrap_err();
    assert!(
        matches!(
            over_second_err,
            ProtocolError::FrameTooLarge { max_bytes: 64 }
        ),
        "expected FrameTooLarge {{ max_bytes: 64 }} after oversized EOF + append, got {over_second_err:?}"
    );
}
