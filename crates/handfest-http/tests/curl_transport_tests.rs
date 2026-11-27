use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use handfest_anchors::{AnchorError, CommandOutput, CommandRunner};
use handfest_http::{
    CurlTlsTransport, HttpMethod, TransportError, UpstreamRequest, UpstreamTransport,
};

#[derive(Debug, Clone)]
struct RecordedCall {
    program: String,
    args: Vec<String>,
    stdin: String,
    header_file_path: Option<PathBuf>,
    header_file_mode: Option<u32>,
    body_file_path: Option<PathBuf>,
    body_file_bytes: Option<Vec<u8>>,
    body_file_mode: Option<u32>,
}

struct MockCurlRunner {
    calls: Arc<Mutex<Vec<RecordedCall>>>,
    dump_headers: Vec<u8>,
    response: Result<CommandOutput, AnchorError>,
}

impl MockCurlRunner {
    fn ok(
        headers: impl Into<Vec<u8>>,
        body: impl Into<Vec<u8>>,
    ) -> (Self, Arc<Mutex<Vec<RecordedCall>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let runner = Self {
            calls: Arc::clone(&calls),
            dump_headers: headers.into(),
            response: Ok(CommandOutput {
                stdout: body.into(),
                stderr: Vec::new(),
            }),
        };
        (runner, calls)
    }

    fn err(err: AnchorError) -> (Self, Arc<Mutex<Vec<RecordedCall>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let runner = Self {
            calls: Arc::clone(&calls),
            dump_headers: Vec::new(),
            response: Err(err),
        };
        (runner, calls)
    }
}

impl CommandRunner for MockCurlRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, AnchorError> {
        let stdin_str = String::from_utf8(stdin.to_vec()).expect("curl config stdin is UTF-8");
        let header_file_path = extract_directive_path(&stdin_str, "dump-header = \"");
        let header_file_mode = match &header_file_path {
            Some(path) => {
                assert!(
                    path.exists(),
                    "temp header file must exist during curl call"
                );
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(fs::metadata(path).unwrap().permissions().mode() & 0o777)
                };
                #[cfg(not(unix))]
                let mode = None;
                if self.response.is_ok() {
                    fs::write(path, &self.dump_headers).expect("mock curl writes dump-header file");
                }
                mode
            }
            None => None,
        };
        let body_file_path = extract_directive_path(&stdin_str, "data-binary = \"@");
        let (body_file_bytes, body_file_mode) = match &body_file_path {
            Some(path) => {
                let bytes = fs::read(path).expect("temp body file must exist during curl call");
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(fs::metadata(path).unwrap().permissions().mode() & 0o777)
                };
                #[cfg(not(unix))]
                let mode = None;
                (Some(bytes), mode)
            }
            None => (None, None),
        };
        self.calls.lock().unwrap().push(RecordedCall {
            program: program.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            stdin: stdin_str,
            header_file_path,
            header_file_mode,
            body_file_path,
            body_file_bytes,
            body_file_mode,
        });
        self.response.clone()
    }
}

fn extract_directive_path(config: &str, prefix: &str) -> Option<PathBuf> {
    for line in config.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            let unquoted = rest.strip_suffix('"').expect("closing quote");
            let unescaped = unquoted.replace("\\\\", "\\").replace("\\\"", "\"");
            return Some(PathBuf::from(unescaped));
        }
    }
    None
}

fn sample_https_request(method: HttpMethod, body: Vec<u8>) -> UpstreamRequest {
    UpstreamRequest {
        method,
        url: "https://api.example.com/v1/transfers?currency=USD".to_string(),
        target: "/v1/transfers?currency=USD".to_string(),
        host_header: "api.example.com".to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Authorization".to_string(),
                "Bearer super-secret-token-xyz".to_string(),
            ),
            ("X-Quoted".to_string(), r#"val"with\escapes"#.to_string()),
            ("X-Empty".to_string(), String::new()),
        ],
        body,
    }
}

#[test]
fn curl_transport_enforces_tls12_stdin_config_zero_argv_secrets_and_0600_temp_body_cleanup() {
    let raw_headers = concat!(
        "HTTP/1.1 100 Continue\r\n\r\n",
        "HTTP/1.1 201 Created\r\n",
        "Content-Type: application/json\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Connection: keep-alive\r\n",
        "X-Upstream: ok\r\n",
        "\r\n",
    );
    let (runner, calls) = MockCurlRunner::ok(
        raw_headers.as_bytes(),
        br#"{"id":"tx_1","status":"settled"}"#,
    );
    let transport = CurlTlsTransport::with_runner(runner)
        .with_timeout_secs(15)
        .expect("valid timeout");

    let body = br#"{"amount":42.50}"#.to_vec();
    let req = sample_https_request(HttpMethod::Post, body.clone());

    // Debug format must redact secret header values and body bytes.
    let dbg_str = format!("{req:?}");
    assert!(!dbg_str.contains("super-secret-token-xyz"));
    assert!(!dbg_str.contains("42.50"));

    let resp = transport.send(&req).expect("curl send succeeds");
    assert_eq!(resp.status, 201);
    assert_eq!(resp.reason, "Created");
    assert_eq!(resp.body, br#"{"id":"tx_1","status":"settled"}"#);
    // Hop-by-hop headers stripped without double-decoding body.
    assert!(resp
        .headers
        .iter()
        .all(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding")
            && !k.eq_ignore_ascii_case("connection")));
    assert!(resp
        .headers
        .iter()
        .any(|(k, v)| k == "X-Upstream" && v == "ok"));

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.program, "curl");
    assert_eq!(
        call.args,
        vec![
            "--disable",
            "--globoff",
            "--suppress-connect-headers",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "--config",
            "-",
        ]
    );
    // Zero secrets, URL, or headers in argv!
    let joined_args = call.args.join(" ");
    assert!(!joined_args.contains("super-secret-token-xyz"));
    assert!(!joined_args.contains("api.example.com"));
    assert!(!joined_args.contains("Authorization"));

    // Stdin config contains properly escaped directives.
    assert!(call.stdin.contains("request = \"POST\"\n"));
    assert!(call
        .stdin
        .contains("url = \"https://api.example.com/v1/transfers?currency=USD\"\n"));
    assert!(call
        .stdin
        .contains("header = \"Authorization: Bearer super-secret-token-xyz\"\n"));
    assert!(call
        .stdin
        .contains("header = \"X-Quoted: val\\\"with\\\\escapes\"\n"));
    assert!(call.stdin.contains("header = \"X-Empty;\"\n"));

    // Temp header file existed with 0600 mode during call, and is now deleted.
    let hdr_path = call
        .header_file_path
        .as_ref()
        .expect("temp header file used");
    #[cfg(unix)]
    assert_eq!(call.header_file_mode, Some(0o600));
    assert!(
        !hdr_path.exists(),
        "temp header file '{}' must be deleted after curl completes",
        hdr_path.display()
    );

    // Temp body file existed with exact bytes and 0600 mode during call, and is now deleted.
    let path = call.body_file_path.as_ref().expect("temp body file used");
    assert_eq!(call.body_file_bytes.as_deref(), Some(body.as_slice()));
    #[cfg(unix)]
    assert_eq!(call.body_file_mode, Some(0o600));
    assert!(
        !path.exists(),
        "temp body file '{}' must be deleted after curl completes",
        path.display()
    );
}

#[test]
fn curl_transport_empty_body_creates_no_temp_file_and_parses_http2_status() {
    let raw_headers = "HTTP/2 200 \r\ncontent-type: application/json\r\n\r\n";
    let (runner, calls) = MockCurlRunner::ok(raw_headers.as_bytes(), br#"{"ok":true}"#);
    let transport = CurlTlsTransport::with_runner(runner);

    let req = sample_https_request(HttpMethod::Get, Vec::new());
    let resp = transport.send(&req).expect("HTTP/2 response succeeds");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.body, br#"{"ok":true}"#);

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(!calls[0].stdin.contains("data-binary"));
    assert!(calls[0].body_file_path.is_none());
}

#[test]
fn curl_transport_rejects_http_scheme_without_invoking_runner() {
    let (runner, calls) = MockCurlRunner::ok(b"HTTP/1.1 200 OK\r\n\r\n", b"");
    let transport = CurlTlsTransport::with_runner(runner);

    let mut req = sample_https_request(HttpMethod::Get, Vec::new());
    req.url = "http://api.example.com/v1/transfers".to_string();

    let err = transport.send(&req).expect_err("http:// must be rejected");
    assert_eq!(
        err,
        TransportError::UnsupportedScheme {
            expected: "https",
            actual: "http".to_string(),
        }
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn curl_transport_cleans_up_temp_file_on_command_failure_and_enforces_response_caps() {
    let (runner, calls) = MockCurlRunner::err(AnchorError::CommandFailed {
        program: "curl".to_string(),
        status: Some(28),
        stderr: "Operation timed out".to_string(),
    });
    let transport = CurlTlsTransport::with_runner(runner);
    let req = sample_https_request(HttpMethod::Post, b"{\"x\":1}".to_vec());

    let err = transport
        .send(&req)
        .expect_err("command failure propagates");
    assert!(matches!(err, TransportError::CommandFailed(_)));
    let call0 = calls.lock().unwrap()[0].clone();
    let hdr_path = call0.header_file_path.expect("temp header file created");
    assert!(
        !hdr_path.exists(),
        "temp header file must be deleted on error"
    );
    let path = call0.body_file_path.expect("temp body file created");
    assert!(!path.exists(), "temp body file must be deleted on error");

    // Oversized response body rejected fail-closed.
    let (runner2, _) = MockCurlRunner::ok(b"HTTP/1.1 200 OK\r\n\r\n", b"0123456789");
    let capped = CurlTlsTransport::with_runner(runner2).with_max_response_bytes(5);
    let err2 = capped
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect_err("oversized body rejected");
    assert_eq!(err2, TransportError::ResponseTooLarge { max_bytes: 5 });

    // Malformed curl output rejected fail-closed.
    let (runner3, _) = MockCurlRunner::ok(b"NOT-HTTP\n\n", b"body");
    let err3 = CurlTlsTransport::with_runner(runner3)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect_err("malformed output rejected");
    assert!(matches!(err3, TransportError::InvalidResponse(_)));

    // Zero timeout rejected fail-closed.
    let (runner4, _) = MockCurlRunner::ok(b"", b"");
    let err4 = CurlTlsTransport::with_runner(runner4)
        .with_timeout_secs(0)
        .expect_err("zero timeout rejected");
    assert!(matches!(err4, TransportError::InvalidRequest(_)));
}

#[test]
fn both_transports_enforce_upstream_request_url_target_and_host_consistency() {
    use handfest_http::Http1TcpTransport;

    // 1. CurlTlsTransport rejects mismatched target, mismatched host_header, and invalid target
    // without invoking curl.
    let (runner, calls) = MockCurlRunner::ok(b"HTTP/1.1 200 OK\r\n\r\n", b"ok");
    let curl = CurlTlsTransport::with_runner(runner);

    let mut bad_target_url = sample_https_request(HttpMethod::Get, Vec::new());
    bad_target_url.target = "/v1/other".to_string();
    assert!(matches!(
        curl.send(&bad_target_url),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("does not match origin + target")
    ));

    let mut bad_host = sample_https_request(HttpMethod::Get, Vec::new());
    bad_host.host_header = "evil.example.com".to_string();
    assert!(matches!(
        curl.send(&bad_host),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("host_header")
    ));

    let mut rel_target = sample_https_request(HttpMethod::Get, Vec::new());
    rel_target.target = "v1/no-slash".to_string();
    assert!(matches!(
        curl.send(&rel_target),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("origin-form")
    ));
    assert!(
        calls.lock().unwrap().is_empty(),
        "curl must never run on inconsistent request"
    );

    // 2. Http1TcpTransport enforces the exact same consistency checks before connecting.
    let http1 = Http1TcpTransport::new();
    let base_http = UpstreamRequest {
        method: HttpMethod::Get,
        url: "http://127.0.0.1:9/v1/items".to_string(),
        target: "/v1/items".to_string(),
        host_header: "127.0.0.1:9".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };

    let mut http_bad_target = base_http.clone();
    http_bad_target.target = "/v1/evil".to_string();
    assert!(matches!(
        http1.send(&http_bad_target),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("does not match origin + target")
    ));

    let mut http_bad_host = base_http.clone();
    http_bad_host.host_header = "evil.local".to_string();
    assert!(matches!(
        http1.send(&http_bad_host),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("host_header")
    ));

    let mut http_rel_target = base_http;
    http_rel_target.target = "not-origin-form".to_string();
    assert!(matches!(
        http1.send(&http_rel_target),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("origin-form")
    ));
}

#[test]
fn round2_transports_reject_101_excessive_1xx_and_bodyless_payloads() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use handfest_http::Http1TcpTransport;

    // 1. CurlTlsTransport rejects 101 Switching Protocols.
    let (runner_101, _) = MockCurlRunner::ok(b"HTTP/1.1 101 Switching Protocols\r\n\r\n", b"");
    let err_101 = CurlTlsTransport::with_runner(runner_101)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect_err("101 must fail in curl transport");
    assert!(matches!(err_101, TransportError::InvalidResponse(ref msg) if msg.contains("101")));

    // 2. Http1TcpTransport rejects 101 Switching Protocols over TCP.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock 101 server");
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n");
        let _ = stream.flush();
    });
    let http1 = Http1TcpTransport::new();
    let http1_101 = http1
        .send(&UpstreamRequest {
            method: HttpMethod::Get,
            url: format!("http://{addr}/v1/items"),
            target: "/v1/items".to_string(),
            host_header: addr.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("101 must fail in http1 transport");
    handle.join().unwrap();
    assert!(matches!(http1_101, TransportError::InvalidResponse(ref msg) if msg.contains("101")));

    // 3. CurlTlsTransport caps interim 1xx responses at 4 (5 interim 100s rejected).
    let five_1xx = "HTTP/1.1 100 Continue\r\n\r\n".repeat(5) + "HTTP/1.1 200 OK\r\n\r\n";
    let (runner_1xx, _) = MockCurlRunner::ok(five_1xx.as_bytes(), b"ok");
    let err_1xx = CurlTlsTransport::with_runner(runner_1xx)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect_err(">4 interim 1xx must fail");
    assert!(matches!(
        err_1xx,
        TransportError::InvalidResponse(ref msg) if msg.contains("too many interim 1xx")
    ));

    // 4. CurlTlsTransport rejects non-empty body on 204 and 304.
    for status_line in ["HTTP/1.1 204 No Content", "HTTP/1.1 304 Not Modified"] {
        let raw = format!("{status_line}\r\n\r\n");
        let (runner_bl, _) = MockCurlRunner::ok(raw.as_bytes(), b"smuggled-body");
        let err_bl = CurlTlsTransport::with_runner(runner_bl)
            .send(&sample_https_request(HttpMethod::Get, Vec::new()))
            .expect_err("non-empty body on 204/304 must fail");
        assert!(matches!(
            err_bl,
            TransportError::InvalidResponse(ref msg) if msg.contains("bodyless")
        ));
    }
}

#[test]
fn round2_transports_reject_forbidden_outbound_headers_fragments_and_htab() {
    use handfest_http::Http1TcpTransport;

    let (runner_ok, calls) = MockCurlRunner::ok(b"HTTP/1.1 200 OK\r\n\r\n", b"ok");
    let curl = CurlTlsTransport::with_runner(runner_ok);
    let http1 = Http1TcpTransport::new();

    let base_http = UpstreamRequest {
        method: HttpMethod::Get,
        url: "http://127.0.0.1:9/v1/items".to_string(),
        target: "/v1/items".to_string(),
        host_header: "127.0.0.1:9".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };

    for forbidden in ["Host", "Transfer-Encoding", "Content-Length", "Connection"] {
        let mut req_https = sample_https_request(HttpMethod::Get, Vec::new());
        req_https
            .headers
            .push((forbidden.to_string(), "evil".to_string()));
        assert!(matches!(
            curl.send(&req_https),
            Err(TransportError::InvalidRequest(ref msg)) if msg.contains("forbidden")
        ));

        let mut req_http = base_http.clone();
        req_http
            .headers
            .push((forbidden.to_string(), "evil".to_string()));
        assert!(matches!(
            http1.send(&req_http),
            Err(TransportError::InvalidRequest(ref msg)) if msg.contains("forbidden")
        ));
    }

    // Fragment '#' in url/target rejected in both transports.
    let mut frag_https = sample_https_request(HttpMethod::Get, Vec::new());
    frag_https.target = "/v1/transfers#frag".to_string();
    frag_https.url = "https://api.example.com/v1/transfers#frag".to_string();
    assert!(matches!(
        curl.send(&frag_https),
        Err(TransportError::InvalidUrl(_))
    ));

    let mut frag_http = base_http.clone();
    frag_http.target = "/v1/items#frag".to_string();
    frag_http.url = "http://127.0.0.1:9/v1/items#frag".to_string();
    assert!(matches!(
        http1.send(&frag_http),
        Err(TransportError::InvalidUrl(_))
    ));

    // HTAB in header value rejected identically in both transports.
    let mut tab_https = sample_https_request(HttpMethod::Get, Vec::new());
    tab_https
        .headers
        .push(("X-Tag".to_string(), "a\tb".to_string()));
    assert!(matches!(
        curl.send(&tab_https),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("invalid header value")
    ));

    let mut tab_http = base_http;
    tab_http
        .headers
        .push(("X-Tag".to_string(), "a\tb".to_string()));
    assert!(matches!(
        http1.send(&tab_http),
        Err(TransportError::InvalidRequest(ref msg)) if msg.contains("invalid header value")
    ));

    assert!(
        calls.lock().unwrap().is_empty(),
        "curl must never execute on rejected request"
    );
}

#[test]
fn round3_curl_rejects_bodyless_framing_headers_and_target_fragment_with_clean_url() {
    use handfest_http::Http1TcpTransport;

    // 1. Interim 100 Continue / 103 Early Hints with Content-Length or Transfer-Encoding rejected.
    let bad_interim_cases: [(&str, &[u8]); 7] = [
        (
            "HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
            b"ok",
        ),
        (
            "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
            b"ok",
        ),
        (
            "HTTP/1.1 103 Early Hints\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
            b"ok",
        ),
        (
            "HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
            b"ok",
        ),
        ("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", b""),
        (
            "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"",
        ),
        (
            "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"",
        ),
    ];
    for (raw, body) in bad_interim_cases {
        let (runner, _) = MockCurlRunner::ok(raw.as_bytes(), body);
        let err = CurlTlsTransport::with_runner(runner)
            .send(&sample_https_request(HttpMethod::Get, Vec::new()))
            .expect_err("forbidden framing header on 1xx/204/304 must fail in curl transport");
        assert!(
            matches!(err, TransportError::InvalidResponse(ref msg) if msg.contains("forbidden on HTTP")),
            "unexpected error for {raw:?}: {err:?}"
        );
    }

    // 2. Clean URL without '#' + target containing '#frag' must hit the target guard.
    let (runner_ok, calls) = MockCurlRunner::ok(b"HTTP/1.1 200 OK\r\n\r\n", b"ok");
    let curl = CurlTlsTransport::with_runner(runner_ok);
    let mut clean_url_bad_target_https = sample_https_request(HttpMethod::Get, Vec::new());
    clean_url_bad_target_https.url = "https://api.example.com/v1/items".to_string();
    clean_url_bad_target_https.target = "/v1/items#frag".to_string();
    let err_https = curl
        .send(&clean_url_bad_target_https)
        .expect_err("clean URL + #frag target must be rejected by target guard");
    assert!(
        matches!(err_https, TransportError::InvalidRequest(ref msg) if msg.contains("fragment")),
        "expected InvalidRequest fragment error, got {err_https:?}"
    );

    let http1 = Http1TcpTransport::new();
    let clean_url_bad_target_http = UpstreamRequest {
        method: HttpMethod::Get,
        url: "http://127.0.0.1:9/v1/items".to_string(),
        target: "/v1/items#frag".to_string(),
        host_header: "127.0.0.1:9".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let err_http = http1
        .send(&clean_url_bad_target_http)
        .expect_err("clean HTTP URL + #frag target must be rejected by target guard");
    assert!(
        matches!(err_http, TransportError::InvalidRequest(ref msg) if msg.contains("fragment")),
        "expected InvalidRequest fragment error, got {err_http:?}"
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn round4_curl_enforces_response_framing_and_content_length_invariants() {
    let bad_framing_cases: [(&str, &str, &[u8]); 7] = [
        (
            "TE + CL conflict",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n",
            b"ok",
        ),
        (
            "duplicate Transfer-Encoding",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"ok",
        ),
        (
            "304 malformed Content-Length",
            "HTTP/1.1 304 Not Modified\r\nContent-Length: abc\r\n\r\n",
            b"",
        ),
        (
            "304 duplicate Content-Length",
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\nContent-Length: 10\r\n\r\n",
            b"",
        ),
        (
            "200 Content-Length 0 with smuggled body",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"smuggled",
        ),
        (
            "200 Content-Length too long",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            b"hi",
        ),
        (
            "200 Content-Length too short",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            b"smuggled",
        ),
    ];
    for (label, raw, body) in bad_framing_cases {
        let (runner, _) = MockCurlRunner::ok(raw.as_bytes(), body);
        let err = CurlTlsTransport::with_runner(runner)
            .send(&sample_https_request(HttpMethod::Get, Vec::new()))
            .expect_err(&format!("{label} must fail closed in curl transport"));
        assert!(
            matches!(err, TransportError::InvalidResponse(_)),
            "expected InvalidResponse for {label}, got {err:?}"
        );
    }

    let (runner_304, _) = MockCurlRunner::ok(
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 42\r\n\r\n",
        b"",
    );
    let resp_304 = CurlTlsTransport::with_runner(runner_304)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect("valid 304 with empty body");
    assert_eq!(resp_304.status, 304);
    assert!(resp_304.body.is_empty());

    let (runner_200, _) =
        MockCurlRunner::ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", b"ok");
    let resp_200 = CurlTlsTransport::with_runner(runner_200)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect("valid 200 with exact Content-Length");
    assert_eq!(resp_200.status, 200);
    assert_eq!(resp_200.body, b"ok");
}

#[test]
fn round5_curl_rejects_trailing_header_file_bytes_and_http2_transfer_encoding() {
    // 1. Chunked/H2 trailer headers appended after final \r\n\r\n in dump-header file are rejected.
    let trailer_cases = [
        (
            "chunked trailer header",
            concat!(
                "HTTP/1.1 200 OK\r\n",
                "Transfer-Encoding: chunked\r\n",
                "\r\n",
                "X-Trailer: smuggled\r\n",
                "\r\n",
            ),
        ),
        (
            "raw trailing garbage after header terminator",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nextra",
        ),
    ];
    for (label, raw_headers) in trailer_cases {
        let (runner, _) = MockCurlRunner::ok(raw_headers.as_bytes(), b"ok");
        let err = CurlTlsTransport::with_runner(runner)
            .send(&sample_https_request(HttpMethod::Get, Vec::new()))
            .expect_err(&format!("{label} must fail closed"));
        assert!(
            matches!(err, TransportError::InvalidResponse(ref msg) if msg.contains("trailing bytes")),
            "expected InvalidResponse trailing bytes error for {label}, got {err:?}"
        );
    }

    // 2. HTTP/2 (and HTTP/2.0) responses carrying Transfer-Encoding are rejected per RFC 9113 §8.2.2.
    for status_line in ["HTTP/2 200", "HTTP/2.0 200 OK"] {
        let raw_headers = format!("{status_line}\r\nTransfer-Encoding: chunked\r\n\r\n");
        let (runner, _) = MockCurlRunner::ok(raw_headers.as_bytes(), b"ok");
        let err = CurlTlsTransport::with_runner(runner)
            .send(&sample_https_request(HttpMethod::Get, Vec::new()))
            .expect_err("Transfer-Encoding on HTTP/2 must be rejected");
        assert!(
            matches!(
                err,
                TransportError::InvalidResponse(ref msg)
                    if msg.contains("Transfer-Encoding") && msg.contains("HTTP/2")
            ),
            "expected HTTP/2 Transfer-Encoding error for {status_line}, got {err:?}"
        );
    }

    // 3. Body bytes resembling HTTP headers on stdout never confuse separate dump-header parsing.
    let body_looking_like_headers = b"HTTP/1.1 403 Forbidden\r\nX-Fake: 1\r\n\r\nbody";
    let (runner_sep, _) = MockCurlRunner::ok(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body_looking_like_headers.len()
        )
        .into_bytes(),
        body_looking_like_headers.as_slice(),
    );
    let resp = CurlTlsTransport::with_runner(runner_sep)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect("separated headers and body must succeed");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, body_looking_like_headers);
}

#[test]
fn round6_curl_rejects_one_trailing_byte_past_exact_max_header_bytes_boundary() {
    let valid_headers = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";
    let exact_limit = valid_headers.len();

    // Control: header block of exactly `max_header_bytes` with no trailing bytes succeeds.
    let (ok_runner, _) = MockCurlRunner::ok(valid_headers.as_slice(), b"ok");
    let ok_resp = CurlTlsTransport::with_runner(ok_runner)
        .with_max_header_bytes(exact_limit)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect("exact max_header_bytes header block without trailing byte must succeed");
    assert_eq!(ok_resp.status, 200);
    assert_eq!(ok_resp.body, b"ok");

    // Boundary: valid header block of exactly `max_header_bytes` followed by 1 trailing byte
    // must be read via the `max_header_bytes + 1` bounded read and rejected as InvalidResponse.
    let mut headers_plus_one = valid_headers.to_vec();
    headers_plus_one.push(b'x');
    let (bad_runner, _) = MockCurlRunner::ok(headers_plus_one, b"ok");
    let err = CurlTlsTransport::with_runner(bad_runner)
        .with_max_header_bytes(exact_limit)
        .send(&sample_https_request(HttpMethod::Get, Vec::new()))
        .expect_err("1 trailing byte after exact max_header_bytes block must fail closed");
    assert!(
        matches!(err, TransportError::InvalidResponse(ref msg) if msg.contains("trailing bytes")),
        "expected InvalidResponse citing trailing bytes, got {err:?}"
    );
}
