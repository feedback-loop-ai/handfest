use std::io::Cursor;

use crate::exact_json::parse_exact_json;

use super::*;

#[test]
fn read_bounded_line_rejects_bare_cr_and_accepts_clean_crlf() {
    let mut crlf = Cursor::new(b"{\"a\":1}\r\n".as_slice());
    assert_eq!(
        read_bounded_line(&mut crlf, 64).unwrap(),
        Some("{\"a\":1}".to_string())
    );

    let mut mid_cr = Cursor::new(b"{\"a\":1}\r{\"b\":2}\r\n".as_slice());
    assert!(matches!(
        read_bounded_line(&mut mid_cr, 64),
        Err(LineReadError::BareCr)
    ));

    let mut double_cr = Cursor::new(b"{\"a\":1}\r\r\n".as_slice());
    assert!(matches!(
        read_bounded_line(&mut double_cr, 64),
        Err(LineReadError::BareCr)
    ));

    let mut eof_cr = Cursor::new(b"{\"a\":1}\r".as_slice());
    assert!(matches!(
        read_bounded_line(&mut eof_cr, 64),
        Err(LineReadError::BareCr)
    ));
}

#[test]
fn read_bounded_line_accepts_exact_limit_payload_with_lf_and_crlf_across_chunk_splits() {
    use std::io::BufReader;

    let payload = br#"{"a":1}"#;
    let limit = payload.len();

    let mut lf = Cursor::new(b"{\"a\":1}\n".as_slice());
    assert_eq!(
        read_bounded_line(&mut lf, limit).unwrap(),
        Some("{\"a\":1}".to_string())
    );

    let mut crlf = Cursor::new(b"{\"a\":1}\r\n".as_slice());
    assert_eq!(
        read_bounded_line(&mut crlf, limit).unwrap(),
        Some("{\"a\":1}".to_string())
    );

    let mut crlf_split = BufReader::with_capacity(1, Cursor::new(b"{\"a\":1}\r\n".as_slice()));
    assert_eq!(
        read_bounded_line(&mut crlf_split, limit).unwrap(),
        Some("{\"a\":1}".to_string())
    );

    let mut crlf_over = Cursor::new(b"{\"a\":12}\r\n".as_slice());
    assert!(matches!(
        read_bounded_line(&mut crlf_over, limit),
        Err(LineReadError::TooLong)
    ));

    let mut crlf_over_split =
        BufReader::with_capacity(1, Cursor::new(b"{\"a\":12}\r\n".as_slice()));
    assert!(matches!(
        read_bounded_line(&mut crlf_over_split, limit),
        Err(LineReadError::TooLong)
    ));

    let mut eof_trailing_cr = BufReader::with_capacity(1, Cursor::new(b"{\"a\":1}\r".as_slice()));
    assert!(matches!(
        read_bounded_line(&mut eof_trailing_cr, limit),
        Err(LineReadError::TooLong)
    ));

    let mut double_cr_at_limit = Cursor::new(b"{\"a\":1}\r\r\n".as_slice());
    assert!(matches!(
        read_bounded_line(&mut double_cr_at_limit, limit),
        Err(LineReadError::TooLong)
    ));
}

#[test]
fn write_raw_line_refuses_embedded_cr_or_lf() {
    let mut out = Vec::new();
    assert!(matches!(
        write_raw_line(&mut out, "{\"a\":1}\r{\"b\":2}"),
        Err(ProxyError::UpstreamProtocol(_))
    ));
    assert!(out.is_empty());

    assert!(matches!(
        write_raw_line(&mut out, "{\"a\":1}\n{\"b\":2}"),
        Err(ProxyError::UpstreamProtocol(_))
    ));
    assert!(out.is_empty());
}

#[test]
fn jsonrpc_id_restricts_numbers_to_plain_ieee754_safe_integers() {
    let id_1 = extract_id_value(&ExactJson::Number("1".to_string())).unwrap();
    let id_str = JsonRpcId::Str("1".to_string());
    assert_ne!(id_1, id_str);

    let zero = extract_id_value(&ExactJson::Number("0".to_string())).unwrap();
    assert_ne!(zero, id_1);

    let max_safe = extract_id_value(&ExactJson::Number("9007199254740991".to_string())).unwrap();
    let max_safe_minus_one =
        extract_id_value(&ExactJson::Number("9007199254740990".to_string())).unwrap();
    assert_ne!(max_safe, max_safe_minus_one);

    let min_safe = extract_id_value(&ExactJson::Number("-9007199254740991".to_string())).unwrap();
    assert_ne!(min_safe, max_safe);

    let hundred_plain = extract_id_value(&ExactJson::Number("100".to_string())).unwrap();
    assert_ne!(hundred_plain, id_1);

    for non_plain in [
        "-0",
        "1.0",
        "1e0",
        "1E0",
        "-0.0",
        "1e2",
        "9.007199254740991e15",
        "90071992547409910e-1",
        "9007199254740990e0",
        "1.5",
        "1.0000000000000001",
        "1e-400",
        "-0.1",
        "9007199254740991.5",
        "1e16",
        "1e100000000000000000000",
        "00",
        "-01",
        "+1",
        "",
        "-",
    ] {
        let err = extract_id_value(&ExactJson::Number(non_plain.to_string())).unwrap_err();
        assert_eq!(
            err, "JSON-RPC numeric id must be a plain integer without decimal point or exponent",
            "non-plain id {non_plain} must fail"
        );
    }

    for out_of_range in [
        "9007199254740992",
        "9007199254740993",
        "-9007199254740992",
        "10000000000000000",
        "10000000000000001",
        "18446744073709551617",
        "-18446744073709551617",
    ] {
        let err = extract_id_value(&ExactJson::Number(out_of_range.to_string())).unwrap_err();
        assert_eq!(
            err, "JSON-RPC numeric id outside IEEE-754 safe integer range",
            "out-of-range id {out_of_range} must fail"
        );
    }
}

#[test]
fn error_object_guard_requires_closed_keys_integer_code_and_string_message() {
    let valid = parse_exact_json(r#"{"code":-32601,"message":"not found"}"#).unwrap();
    assert!(is_valid_jsonrpc_error_object(&valid));

    let valid_with_data =
        parse_exact_json(r#"{"code":-32601,"message":"not found","data":{"detail":1}}"#).unwrap();
    assert!(is_valid_jsonrpc_error_object(&valid_with_data));

    let missing_msg = parse_exact_json(r#"{"code":-32601}"#).unwrap();
    assert!(!is_valid_jsonrpc_error_object(&missing_msg));

    let non_string_msg = parse_exact_json(r#"{"code":-32601,"message":42}"#).unwrap();
    assert!(!is_valid_jsonrpc_error_object(&non_string_msg));

    let null_msg = parse_exact_json(r#"{"code":-32601,"message":null}"#).unwrap();
    assert!(!is_valid_jsonrpc_error_object(&null_msg));

    let float_code = parse_exact_json(r#"{"code":1.5,"message":"bad"}"#).unwrap();
    assert!(!is_valid_jsonrpc_error_object(&float_code));

    let neg_zero_code = parse_exact_json(r#"{"code":-0,"message":"bad"}"#).unwrap();
    assert!(!is_valid_jsonrpc_error_object(&neg_zero_code));

    let smuggled_and_extra =
        parse_exact_json(r#"{"code":-32601,"CODE":"not_an_int","message":"fail","extra":true}"#)
            .unwrap();
    assert!(!is_valid_jsonrpc_error_object(&smuggled_and_extra));

    let smuggled_only =
        parse_exact_json(r#"{"code":-32601,"CODE":"not_an_int","message":"fail"}"#).unwrap();
    assert!(!is_valid_jsonrpc_error_object(&smuggled_only));

    let extra_only = parse_exact_json(r#"{"code":-32601,"message":"fail","extra":true}"#).unwrap();
    assert!(!is_valid_jsonrpc_error_object(&extra_only));
}

#[test]
fn client_envelope_rejects_response_fields_and_primitive_params() {
    let bad_cases = [
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}"#,
            "client request/notification must not contain result or error",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","error":{"code":-1,"message":"x"}}"#,
            "client request/notification must not contain result or error",
        ),
        (
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","result":null}"#,
            "client request/notification must not contain result or error",
        ),
        (
            r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":123}"#,
            "JSON-RPC params must be a JSON object or array",
        ),
        (
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":"bad"}"#,
            "JSON-RPC params must be a JSON object or array",
        ),
        (
            r#"{"jsonrpc":"2.0","id":3,"method":"ping","params":null}"#,
            "JSON-RPC params must be a JSON object or array",
        ),
    ];

    for (raw, expected_msg) in bad_cases {
        let parsed = parse_exact_json(raw).unwrap();
        let err = validate_client_envelope(parsed.as_object().unwrap()).unwrap_err();
        assert_eq!(err.message, expected_msg, "input: {raw}");
    }

    let valid_obj =
        parse_exact_json(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#).unwrap();
    assert!(validate_client_envelope(valid_obj.as_object().unwrap()).is_ok());

    let valid_arr =
        parse_exact_json(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}"#).unwrap();
    assert!(validate_client_envelope(valid_arr.as_object().unwrap()).is_ok());
}

#[test]
fn closed_envelope_keys_reject_case_colliding_and_unknown_top_level_fields() {
    let bad_client = [
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","METHOD":"tools/call"}"#,
            "unexpected JSON-RPC client envelope key 'METHOD'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","ID":2}"#,
            "unexpected JSON-RPC client envelope key 'ID'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","RESULT":{}}"#,
            "unexpected JSON-RPC client envelope key 'RESULT'",
        ),
        (
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","ERROR":{}}"#,
            "unexpected JSON-RPC client envelope key 'ERROR'",
        ),
    ];
    for (raw, expected) in bad_client {
        let parsed = parse_exact_json(raw).unwrap();
        let err = validate_client_envelope(parsed.as_object().unwrap()).unwrap_err();
        assert_eq!(err.message, expected, "client input: {raw}");
    }

    let bad_upstream = [
        (
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"fail"},"RESULT":{"tools":[]}}"#,
            "unexpected upstream JSON-RPC response key 'RESULT'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"ERROR":{"code":-1,"message":"x"}}"#,
            "unexpected upstream JSON-RPC response key 'ERROR'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"extra":1}"#,
            "unexpected upstream JSON-RPC response key 'extra'",
        ),
        (
            r#"{"jsonrpc":"2.0","method":"notifications/progress","RESULT":{}}"#,
            "unexpected upstream JSON-RPC request/notification key 'RESULT'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","METHOD":"ping"}"#,
            "unexpected upstream JSON-RPC request/notification key 'METHOD'",
        ),
    ];
    for (raw, expected) in bad_upstream {
        let parsed = parse_exact_json(raw).unwrap();
        let err = classify_upstream_frame(parsed.as_object().unwrap())
            .err()
            .expect("malformed upstream envelope must fail");
        assert_eq!(err, expected, "upstream input: {raw}");
    }
}

#[test]
fn upstream_response_id_matches_exact_safe_integers_and_rejects_negative_zero_or_fractional() {
    let client_one = extract_id_value(&ExactJson::Number("1".to_string())).unwrap();
    let client_zero = extract_id_value(&ExactJson::Number("0".to_string())).unwrap();
    let client_max = extract_id_value(&ExactJson::Number("9007199254740991".to_string())).unwrap();
    let client_min = extract_id_value(&ExactJson::Number("-9007199254740991".to_string())).unwrap();

    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Number("1.0".to_string())).unwrap(),
        client_one
    );
    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Number("1e0".to_string())).unwrap(),
        client_one
    );
    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Number("0.0".to_string())).unwrap(),
        client_zero
    );
    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Number("9007199254740991.0".to_string()))
            .unwrap(),
        client_max
    );
    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Number("90071992547409910e-1".to_string()))
            .unwrap(),
        client_max
    );
    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Number("-9.007199254740991e15".to_string()))
            .unwrap(),
        client_min
    );
    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Str("req-1".to_string())).unwrap(),
        JsonRpcId::Str("req-1".to_string())
    );
    assert_eq!(
        extract_upstream_response_id_value(&ExactJson::Null).unwrap_err(),
        "JSON-RPC id must be a string or number"
    );

    for neg_zero in ["-0", "-0.0", "-0e5"] {
        assert_eq!(
            extract_upstream_response_id_value(&ExactJson::Number(neg_zero.to_string()))
                .unwrap_err(),
            "JSON-RPC numeric id must not be negative zero",
            "upstream response id {neg_zero} must be rejected"
        );
    }

    for fractional in [
        "1.5",
        "1.0000000000000001",
        "1e-400",
        "-0.1",
        "9007199254740991.5",
    ] {
        assert_eq!(
            extract_upstream_response_id_value(&ExactJson::Number(fractional.to_string()))
                .unwrap_err(),
            "JSON-RPC numeric id must be an exact integer without fractional part",
            "fractional upstream response id {fractional} must fail"
        );
    }

    for out_of_range in [
        "9007199254740992",
        "-9007199254740992",
        "9007199254740992.0",
        "-9007199254740992.0",
        "9007199254740992e0",
        "1e16",
        "1e18446744073709551616",
        "1e100000000000000000000",
        "18446744073709551617",
    ] {
        assert_eq!(
            extract_upstream_response_id_value(&ExactJson::Number(out_of_range.to_string()))
                .unwrap_err(),
            "JSON-RPC numeric id outside IEEE-754 safe integer range",
            "out-of-range upstream response id {out_of_range} must fail"
        );
    }

    let resp_obj = parse_exact_json(r#"{"jsonrpc":"2.0","id":1.0,"result":{}}"#).unwrap();
    let frame = classify_upstream_frame(resp_obj.as_object().unwrap()).unwrap();
    let UpstreamFrame::Response { id: float_one } = frame else {
        panic!("expected upstream response frame");
    };
    assert_eq!(float_one, client_one);
    assert!(!client_one.has_same_spelling(&float_one));
    assert!(client_one.has_same_spelling(&client_one));
    let str_id = JsonRpcId::Str("1".to_string());
    assert!(str_id.has_same_spelling(&JsonRpcId::Str("1".to_string())));
    assert!(!str_id.has_same_spelling(&client_one));
    assert!(!client_one.has_same_spelling(&str_id));
    assert_eq!(
        client_one.to_exact_json(),
        ExactJson::Number("1".to_string())
    );
    assert_eq!(str_id.to_exact_json(), ExactJson::Str("1".to_string()));
}

#[test]
fn upstream_response_id_scales_positive_exponents_and_checks_safe_range() {
    let client_ten = extract_id_value(&ExactJson::Number("10".to_string())).unwrap();
    let client_hundred = extract_id_value(&ExactJson::Number("100".to_string())).unwrap();
    let client_neg_hundred = extract_id_value(&ExactJson::Number("-100".to_string())).unwrap();
    let client_scaled_max =
        extract_id_value(&ExactJson::Number("9007199254740990".to_string())).unwrap();

    for (raw, expected) in [
        ("10.0", &client_ten),
        ("1e1", &client_ten),
        ("1e2", &client_hundred),
        ("-1e2", &client_neg_hundred),
        ("9.00719925474099e15", &client_scaled_max),
    ] {
        assert_eq!(
            extract_upstream_response_id_value(&ExactJson::Number(raw.to_string())).unwrap(),
            *expected,
            "positive-exponent upstream response id {raw} must correlate"
        );
    }

    for out_of_range in ["9.1e15", "-9.1e15"] {
        assert_eq!(
            extract_upstream_response_id_value(&ExactJson::Number(out_of_range.to_string()))
                .unwrap_err(),
            "JSON-RPC numeric id outside IEEE-754 safe integer range",
            "positive-exponent overflow {out_of_range} must be rejected"
        );
    }
}

#[test]
fn read_bounded_line_retries_eintr_mid_frame() {
    use std::collections::VecDeque;
    use std::io::{self, Read};

    struct InterruptingBufReader {
        steps: VecDeque<io::Result<Vec<u8>>>,
        current: Vec<u8>,
        pos: usize,
    }

    impl Read for InterruptingBufReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            unreachable!("read_bounded_line uses BufRead::fill_buf")
        }
    }

    impl BufRead for InterruptingBufReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.pos < self.current.len() {
                return Ok(&self.current[self.pos..]);
            }
            match self.steps.pop_front() {
                Some(Ok(chunk)) => {
                    self.current = chunk;
                    self.pos = 0;
                    Ok(&self.current[..])
                }
                Some(Err(err)) => Err(err),
                None => Ok(&[]),
            }
        }

        fn consume(&mut self, amt: usize) {
            self.pos = (self.pos + amt).min(self.current.len());
        }
    }

    let mut reader = InterruptingBufReader {
        steps: VecDeque::from([
            Ok(br#"{"jsonrpc":"2.0","#.to_vec()),
            Err(io::Error::new(io::ErrorKind::Interrupted, "EINTR 1")),
            Err(io::Error::new(io::ErrorKind::Interrupted, "EINTR 2")),
            Ok(b"\"id\":1,\"method\":\"ping\"}\n".to_vec()),
        ]),
        current: Vec::new(),
        pos: 0,
    };
    assert_eq!(
        read_bounded_line(&mut reader, 1024).unwrap(),
        Some(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string())
    );

    let mut failing_reader = InterruptingBufReader {
        steps: VecDeque::from([
            Ok(br#"{"partial":"#.to_vec()),
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken")),
        ]),
        current: Vec::new(),
        pos: 0,
    };
    assert!(matches!(
        read_bounded_line(&mut failing_reader, 1024),
        Err(LineReadError::Io(err)) if err.kind() == io::ErrorKind::BrokenPipe
    ));
}

#[test]
fn write_raw_line_retries_eintr_on_write_and_flush() {
    use std::io;

    struct InterruptingWriter {
        out: Vec<u8>,
        write_step: usize,
        flush_calls: usize,
        flush_interrupts_left: usize,
        fail_write_zero: bool,
        fail_write_broken_after_prefix: bool,
        fail_flush_broken: bool,
    }

    impl Write for InterruptingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_write_zero {
                return Ok(0);
            }
            self.write_step += 1;
            match self.write_step {
                1 => {
                    let n = buf.len().min(6);
                    self.out.extend_from_slice(&buf[..n]);
                    Ok(n)
                }
                2 if self.fail_write_broken_after_prefix => {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "write broken"))
                }
                2 => Err(io::Error::new(io::ErrorKind::Interrupted, "write EINTR")),
                _ => {
                    self.out.extend_from_slice(buf);
                    Ok(buf.len())
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_calls += 1;
            if self.fail_flush_broken {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush broken"));
            }
            if self.flush_interrupts_left > 0 {
                self.flush_interrupts_left -= 1;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "flush EINTR"));
            }
            Ok(())
        }
    }

    let line = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
    let mut writer = InterruptingWriter {
        out: Vec::new(),
        write_step: 0,
        flush_calls: 0,
        flush_interrupts_left: 2,
        fail_write_zero: false,
        fail_write_broken_after_prefix: false,
        fail_flush_broken: false,
    };
    write_raw_line(&mut writer, line).expect("write_raw_line must retry EINTR on write and flush");
    assert_eq!(writer.out, format!("{line}\n").into_bytes());
    assert_eq!(writer.flush_interrupts_left, 0);

    let mut zero_writer = InterruptingWriter {
        out: Vec::new(),
        write_step: 0,
        flush_calls: 0,
        flush_interrupts_left: 0,
        fail_write_zero: true,
        fail_write_broken_after_prefix: false,
        fail_flush_broken: false,
    };
    assert!(matches!(
        write_raw_line(&mut zero_writer, line),
        Err(ProxyError::Io(err)) if err.kind() == io::ErrorKind::WriteZero
    ));

    let mut partial_broken_writer = InterruptingWriter {
        out: Vec::new(),
        write_step: 0,
        flush_calls: 0,
        flush_interrupts_left: 0,
        fail_write_zero: false,
        fail_write_broken_after_prefix: true,
        fail_flush_broken: false,
    };
    assert!(matches!(
        write_raw_line(&mut partial_broken_writer, line),
        Err(ProxyError::Io(err)) if err.kind() == io::ErrorKind::BrokenPipe
    ));
    assert_eq!(partial_broken_writer.out, &line.as_bytes()[..6]);
    assert_eq!(partial_broken_writer.flush_calls, 0);

    let mut broken_flush = InterruptingWriter {
        out: Vec::new(),
        write_step: 3,
        flush_calls: 0,
        flush_interrupts_left: 0,
        fail_write_zero: false,
        fail_write_broken_after_prefix: false,
        fail_flush_broken: true,
    };
    assert!(matches!(
        write_raw_line(&mut broken_flush, line),
        Err(ProxyError::Io(err)) if err.kind() == io::ErrorKind::BrokenPipe
    ));
}
