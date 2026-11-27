use std::fs;
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use handfest_anchors::{AnchorRegistry, Ed25519Keypair};
use handfest_core::ast::ActorDecl;
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::exact_json::{parse_exact_json, ExactJson};
use handfest_core::gate::VerifiedMandate;
use handfest_core::revocation::{render_canonical_revocation, RevocationAst, RevocationTarget};
use handfest_core::ActorKind;
use handfest_http::{
    read_http_request, read_http_response, verify_mandate_chain_with, verify_revocations_with,
    write_http_response_wire, FixedClock, Http1TcpTransport, HttpMethod, HttpPolicyMap, HttpProxy,
    HttpRequest, HttpResponse, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADER_BYTES,
};
use handfest_ledger::SqliteLedger;
use std::collections::BTreeMap;
use tempfile::TempDir;

const NOW_UNIX: i64 = 1_760_000_000;
const VALID_FROM: i64 = 1_759_900_000;
const VALID_UNTIL: i64 = 1_760_100_000;

#[derive(Debug, Clone)]
struct CapturedUpstreamReq {
    method: HttpMethod,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct MockUpstreamServer {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    captured: Arc<Mutex<Vec<CapturedUpstreamReq>>>,
    _handle: thread::JoinHandle<()>,
}

impl MockUpstreamServer {
    fn start(max_requests: usize, response_body: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let hits_bg = Arc::clone(&hits);
        let captured_bg = Arc::clone(&captured);

        let handle = thread::spawn(move || {
            for _ in 0..max_requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let req = {
                    let mut reader = BufReader::new(&stream);
                    read_http_request(
                        &mut reader,
                        DEFAULT_MAX_HEADER_BYTES,
                        DEFAULT_MAX_BODY_BYTES,
                    )
                    .expect("mock upstream parses forwarded HTTP/1.1 request")
                };
                hits_bg.fetch_add(1, Ordering::SeqCst);
                captured_bg.lock().unwrap().push(CapturedUpstreamReq {
                    method: req.method,
                    target: req.target,
                    headers: req.headers,
                    body: req.body,
                });
                let mut resp = HttpResponse::json(200, response_body);
                resp.headers
                    .push(("X-Upstream-Reply".to_string(), "confirmed".to_string()));
                resp.headers
                    .push(("Keep-Alive".to_string(), "timeout=99".to_string()));
                let wire = write_http_response_wire(&resp);
                let _ = stream.write_all(&wire);
                let _ = stream.flush();
            }
        });

        Self {
            addr,
            hits,
            captured,
            _handle: handle,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn hit_count(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn write_secret_file(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn build_signed_chain(
    root_kp: &Ed25519Keypair,
    agent_kp: &Ed25519Keypair,
    extra_clause: &str,
) -> (Vec<VerifiedMandate>, handfest_anchors::SignedMandate) {
    let words = format!(
        "HANDFEST v1\n\
         FROM human \"Owner\" (key: {root})\n\
         TO agent \"Agent\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW payments.create\n\
         ON account \"acct-*\"\n\
         WHERE payment.amount <= 100.00\n\
           AND payment.currency == \"USD\"\n\
         {extra_clause}",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let ast = parse_mandate(&words).expect("valid mandate CNL");
    let canonical = render_canonical(&ast);
    let signed = root_kp
        .sign_mandate(&canonical, "anchor:test", VALID_FROM, VALID_UNTIL)
        .unwrap();
    let verified = verify_mandate_chain_with(
        &AnchorRegistry::default_registry(),
        std::slice::from_ref(&signed),
    )
    .unwrap();
    (verified, signed)
}

fn payment_policy_json(base_url: &str, auth_json: &str) -> String {
    format!(
        r#"{{
            "upstream_base_url": "{base_url}",
            {auth_json}
            "routes": [
                {{
                    "method": "POST",
                    "path_template": "/v1/accounts/{{account_id}}/payments",
                    "action": "payments.create",
                    "resource_kind": "account",
                    "resource_id": {{ "path_param": "account_id" }},
                    "query_facts": {{
                        "currency": {{ "field": "payment.currency", "type": "str" }}
                    }},
                    "body_facts": {{
                        "amount": {{ "field": "payment.amount", "type": "decimal" }}
                    }},
                    "max_body_bytes": 1024
                }}
            ]
        }}"#
    )
}

fn parse_denial_json(resp: &HttpResponse) -> (String, String) {
    assert_eq!(resp.status, 403);
    let body = std::str::from_utf8(&resp.body).expect("UTF-8 denial JSON");
    let parsed = parse_exact_json(body).expect("valid denial JSON");
    let obj = parsed.as_object().expect("JSON object");
    assert_eq!(
        obj.get("error"),
        Some(&ExactJson::Str("handfest_denied".into()))
    );
    let reason = obj
        .get("reason")
        .and_then(ExactJson::as_str)
        .expect("reason field")
        .to_string();
    let hash = obj
        .get("receipt_hash")
        .and_then(ExactJson::as_str)
        .expect("receipt_hash field")
        .to_string();
    assert!(
        hash.starts_with("sha256:") && hash.len() == 71,
        "receipt_hash must be canonical sha256:<64 hex>"
    );
    (reason, hash)
}

#[test]
fn permit_injects_bearer_header_strips_client_auth_and_hop_headers_and_records_receipt() {
    let dir = TempDir::new().unwrap();
    let secret_path = write_secret_file(dir.path(), "token.txt", "operator-secret-999\n");
    let upstream = MockUpstreamServer::start(1, br#"{"status":"paid"}"#);

    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");

    let auth_json = format!(
        r#""upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        secret_path.display()
    );
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json(&upstream.base_url(), &auth_json))
            .unwrap();
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).unwrap();

    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap();

    let req = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Host".into(), "127.0.0.1:8080".into()),
            ("Authorization".into(), "Bearer attacker-spoofed".into()),
            ("Connection".into(), "X-Evil-Hop".into()),
            ("X-Evil-Hop".into(), "should-strip".into()),
            ("Keep-Alive".into(), "timeout=5".into()),
            ("Content-Type".into(), "application/json".into()),
            ("X-Trace-Id".into(), "trace-123".into()),
        ],
        body: br#"{"amount":49.95}"#.to_vec(),
    };

    let resp = proxy
        .handle_request(&req)
        .expect("permitted request succeeds");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, br#"{"status":"paid"}"#);
    assert!(resp
        .headers
        .iter()
        .any(|(k, v)| k == "X-Upstream-Reply" && v == "confirmed"));
    assert!(resp
        .headers
        .iter()
        .all(|(k, _)| !k.eq_ignore_ascii_case("keep-alive")));

    assert_eq!(upstream.hit_count(), 1);
    let captured = upstream.captured.lock().unwrap();
    let fwd = &captured[0];
    assert_eq!(fwd.method, HttpMethod::Post);
    assert_eq!(fwd.target, "/v1/accounts/acct-1/payments?currency=USD");
    assert_eq!(fwd.body, br#"{"amount":49.95}"#);

    let auth_headers: Vec<&str> = fwd
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(auth_headers, vec!["Bearer operator-secret-999"]);
    assert!(fwd.headers.iter().all(
        |(k, _)| !k.eq_ignore_ascii_case("x-evil-hop") && !k.eq_ignore_ascii_case("keep-alive")
    ));
    assert!(fwd
        .headers
        .iter()
        .any(|(k, v)| k == "X-Trace-Id" && v == "trace-123"));

    assert_eq!(
        proxy
            .ledger()
            .verify_integrity()
            .expect("ledger hash chain audits cleanly"),
        1
    );
}

#[test]
fn deny_returns_403_with_receipt_hash_never_hits_upstream_and_never_loads_secret() {
    let dir = TempDir::new().unwrap();
    // Point auth at a NONEXISTENT secret file to prove secrets are NEVER touched on Deny.
    let missing_secret = dir.path().join("must-not-be-read.txt");
    let upstream = MockUpstreamServer::start(1, br#"{"should":"never_run"}"#);

    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");

    let auth_json = format!(
        r#""upstream_auth": {{ "header": {{ "name": "X-Api-Key", "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        missing_secret.display()
    );
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json(&upstream.base_url(), &auth_json))
            .unwrap();
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).unwrap();

    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap();

    // 1. Mandate WHERE predicate violation (amount > 100.00).
    let over_limit = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Host".into(), "localhost".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: br#"{"amount":100.01}"#.to_vec(),
    };
    let resp1 = proxy.handle_request(&over_limit).unwrap();
    let (reason1, hash1) = parse_denial_json(&resp1);
    assert!(reason1.contains("payment.amount") || reason1.contains("predicate"));

    // 2. Unmapped route -> pre-gate denial.
    let unmapped = HttpRequest {
        method: HttpMethod::Delete,
        target: "/v1/accounts/acct-1".to_string(),
        headers: vec![("Host".into(), "localhost".into())],
        body: Vec::new(),
    };
    let resp2 = proxy.handle_request(&unmapped).unwrap();
    let (reason2, hash2) = parse_denial_json(&resp2);
    assert!(reason2.contains("unmapped HTTP route"));
    assert_ne!(hash1, hash2);

    // 3. Path traversal -> pre-gate denial.
    let traversal = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/%2e%2e/payments?currency=USD".to_string(),
        headers: vec![("Host".into(), "localhost".into())],
        body: br#"{"amount":10.00}"#.to_vec(),
    };
    let resp3 = proxy.handle_request(&traversal).unwrap();
    let (reason3, hash3) = parse_denial_json(&resp3);
    assert!(reason3.contains("traversal") || reason3.contains("forbidden"));

    // 4. Missing required body fact -> pre-gate denial.
    let missing_fact = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Host".into(), "localhost".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: br#"{}"#.to_vec(),
    };
    let resp4 = proxy.handle_request(&missing_fact).unwrap();
    let (reason4, hash4) = parse_denial_json(&resp4);
    assert!(reason4.contains("missing required fact"));

    // Upstream was NEVER hit across all 4 denials; all 4 receipts chained and persisted in SQLite.
    assert_eq!(upstream.hit_count(), 0);
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 4);
    let receipts = proxy.ledger().list_receipts().unwrap();
    assert_eq!(receipts.len(), 4);
    for (idx, (expected_hash, expected_reason)) in [
        (&hash1, &reason1),
        (&hash2, &reason2),
        (&hash3, &reason3),
        (&hash4, &reason4),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(receipts[idx].receipt_hash.to_string(), *expected_hash);
        assert_eq!(
            receipts[idx].verdict,
            handfest_core::Verdict::Deny {
                reason: expected_reason.clone()
            }
        );
    }
}

#[test]
fn quota_exhaustion_and_revocation_block_upstream_calls() {
    let dir = TempDir::new().unwrap();
    let upstream = MockUpstreamServer::start(3, br#"{"ok":true}"#);

    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, signed_mandate) = build_signed_chain(
        &root_kp,
        &agent_kp,
        "LIMIT 100.00 USD sum(payment.amount)\n",
    );
    let mandate_id = chain[0].ast.mandate_id();

    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json(&upstream.base_url(), "")).unwrap();
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).unwrap();

    let mut proxy = HttpProxy::new(
        chain.clone(),
        agent_kp.key_id(),
        policy.clone(),
        ledger,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap();

    let make_req = |amt: &str| HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-9/payments?currency=USD".to_string(),
        headers: vec![
            ("Host".into(), "localhost".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: format!(r#"{{"amount":{amt}}}"#).into_bytes(),
    };

    // 60.00 + 40.00 = 100.00 permitted (2 calls).
    assert_eq!(
        proxy.handle_request(&make_req("60.00")).unwrap().status,
        200
    );
    assert_eq!(
        proxy.handle_request(&make_req("40.00")).unwrap().status,
        200
    );
    // 3rd call (even 0.01) denied by quota.
    let denied = proxy.handle_request(&make_req("0.01")).unwrap();
    let (quota_reason, quota_hash) = parse_denial_json(&denied);
    assert!(quota_reason.contains("quota") || quota_reason.contains("exceeded"));
    assert_eq!(upstream.hit_count(), 2);
    let q_receipts = proxy.ledger().list_receipts().unwrap();
    assert_eq!(q_receipts.len(), 3);
    assert_eq!(q_receipts[2].receipt_hash.to_string(), quota_hash);
    assert_eq!(
        q_receipts[2].verdict,
        handfest_core::Verdict::Deny {
            reason: quota_reason
        }
    );

    // Now test revocation on a fresh ledger with static verified revocation.
    let by = ActorDecl::new(ActorKind::Human, "Owner", root_kp.key_id(), BTreeMap::new()).unwrap();
    let rev_ast = RevocationAst::new(
        by,
        RevocationTarget::Mandate(mandate_id),
        VALID_FROM,
        Some("compromised agent key".to_string()),
    )
    .unwrap();
    let rev_canonical = render_canonical_revocation(&rev_ast);
    let signed_rev = root_kp
        .sign_revocation(&rev_canonical, "anchor:rev", VALID_FROM, VALID_UNTIL)
        .unwrap();
    let rev_snapshot =
        verify_revocations_with(&AnchorRegistry::default_registry(), &[signed_rev]).unwrap();
    let _ = signed_mandate;

    let ledger2 = SqliteLedger::open(dir.path().join("ledger2.sqlite")).unwrap();
    let mut revoked_proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger2,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap()
    .with_revocations(rev_snapshot);

    let rev_resp = revoked_proxy.handle_request(&make_req("1.00")).unwrap();
    let (rev_reason, rev_hash) = parse_denial_json(&rev_resp);
    assert!(rev_reason.contains("revoked"));
    assert_eq!(upstream.hit_count(), 2);
    let rev_receipts = revoked_proxy.ledger().list_receipts().unwrap();
    assert_eq!(rev_receipts.len(), 1);
    assert_eq!(rev_receipts[0].receipt_hash.to_string(), rev_hash);
    assert_eq!(
        rev_receipts[0].verdict,
        handfest_core::Verdict::Deny { reason: rev_reason }
    );
}

#[test]
fn serve_connection_enforces_wire_smuggling_and_relays_loopback_http() {
    let dir = TempDir::new().unwrap();
    let secret_path = write_secret_file(dir.path(), "key.txt", "live-bearer-secret");
    let upstream = MockUpstreamServer::start(2, br#"{"relayed":true}"#);

    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");

    let auth_json = format!(
        r#""upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        secret_path.display()
    );
    let policy_str = payment_policy_json(&upstream.base_url(), &auth_json);
    let policy = HttpPolicyMap::from_json_str(&policy_str).unwrap();
    let ledger = SqliteLedger::open(dir.path().join("tcp.sqlite")).unwrap();

    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap();

    // Serve 2 real TCP connections: (1) wire-smuggled request -> 400, (2) valid permitted POST -> 200.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let srv_thread = thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = proxy_listener.accept().unwrap();
            proxy.serve_connection(stream).unwrap();
        }
        proxy
    });

    // Connection 1: Transfer-Encoding + Content-Length smuggling -> 400 Bad Request.
    {
        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client
            .write_all(
                b"POST /v1/accounts/acct-1/payments?currency=USD HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
            )
            .unwrap();
        let resp = read_http_response(
            &mut BufReader::new(&client),
            DEFAULT_MAX_HEADER_BYTES,
            DEFAULT_MAX_BODY_BYTES,
        )
        .unwrap();
        assert_eq!(resp.status, 400);
        assert!(String::from_utf8_lossy(&resp.body).contains("http_framing_error"));
    }

    // Connection 2: Valid HTTP/1.1 POST -> 200 OK relayed from mock upstream.
    {
        let mut client = TcpStream::connect(proxy_addr).unwrap();
        let body = br#"{"amount":12.34}"#;
        let wire = format!(
            "POST /v1/accounts/acct-1/payments?currency=USD HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer evil\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        client.write_all(wire.as_bytes()).unwrap();
        client.write_all(body).unwrap();
        let resp = read_http_response(
            &mut BufReader::new(&client),
            DEFAULT_MAX_HEADER_BYTES,
            DEFAULT_MAX_BODY_BYTES,
        )
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, br#"{"relayed":true}"#);
    }

    let _proxy = srv_thread.join().unwrap();
    assert_eq!(upstream.hit_count(), 1);
}

#[test]
fn cli_binary_rejects_non_loopback_and_serves_loopback_requests() {
    let dir = TempDir::new().unwrap();
    let secret_path = write_secret_file(dir.path(), "key.txt", "live-bearer-secret");
    let upstream = MockUpstreamServer::start(1, br#"{"relayed":true}"#);

    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (_chain, signed_mandate) = build_signed_chain(&root_kp, &agent_kp, "");

    let auth_json = format!(
        r#""upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        secret_path.display()
    );
    let policy_str = payment_policy_json(&upstream.base_url(), &auth_json);

    // Test the `handfest-http` CLI binary: reject non-loopback --bind cleanly with structured JSON.
    let bin = env!("CARGO_BIN_EXE_handfest-http");
    let chain_path = dir.path().join("mandate.json");
    let policy_path = dir.path().join("policy.json");
    let cli_ledger = dir.path().join("cli.sqlite");
    fs::write(
        &chain_path,
        serde_json::to_string_pretty(&signed_mandate).unwrap(),
    )
    .unwrap();
    fs::write(&policy_path, &policy_str).unwrap();

    let bad_bind = Command::new(bin)
        .args([
            "--bind",
            "0.0.0.0:8080",
            "--ledger",
            cli_ledger.to_str().unwrap(),
            "--chain",
            chain_path.to_str().unwrap(),
            "--actor-key",
            &agent_kp.key_id().to_string(),
            "--policy-map",
            policy_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!bad_bind.status.success());
    let stderr = String::from_utf8_lossy(&bad_bind.stderr);
    let parsed_err = parse_exact_json(stderr.trim()).expect("structured JSON startup error");
    assert_eq!(
        parsed_err.as_object().unwrap().get("code"),
        Some(&ExactJson::Str("cli_args".into()))
    );

    // Spawn live `handfest-http` binary on a free loopback port and verify 200 Permit + 403 Deny.
    let free_port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let bind_arg = format!("127.0.0.1:{free_port}");
    let mut child = Command::new(bin)
        .args([
            "--bind",
            &bind_arg,
            "--ledger",
            cli_ledger.to_str().unwrap(),
            "--chain",
            chain_path.to_str().unwrap(),
            "--actor-key",
            &agent_kp.key_id().to_string(),
            "--policy-map",
            policy_path.to_str().unwrap(),
            "--now",
            "2025-10-09T09:00:00Z",
            "--timeout-secs",
            "5",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait briefly until the listener accepts connections.
    let mut connected = None;
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(&bind_arg) {
            connected = Some(stream);
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut stream = connected.expect("handfest-http binary should listen on loopback");
    let body = br#"{"amount":25.00}"#;
    let req_wire = format!(
        "POST /v1/accounts/acct-2/payments?currency=USD HTTP/1.1\r\nHost: {bind_arg}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(req_wire.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let resp = read_http_response(
        &mut BufReader::new(&stream),
        DEFAULT_MAX_HEADER_BYTES,
        DEFAULT_MAX_BODY_BYTES,
    )
    .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, br#"{"relayed":true}"#);

    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(upstream.hit_count(), 1);
}

#[test]
fn custom_header_auth_expired_chain_precedence_and_transport_scheme_guards() {
    use handfest_http::{
        AutoUpstreamTransport, CurlTlsTransport, HttpProxyError, TransportError, UpstreamRequest,
        UpstreamTransport,
    };

    let dir = TempDir::new().unwrap();
    let secret_path = write_secret_file(dir.path(), "api.key", "custom-api-key-777");
    let upstream = MockUpstreamServer::start(1, br#"{"custom":true}"#);

    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");

    let auth_json = format!(
        r#""upstream_auth": {{ "header": {{ "name": "X-Api-Key", "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        secret_path.display()
    );
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json(&upstream.base_url(), &auth_json))
            .unwrap();
    let ledger = SqliteLedger::open(dir.path().join("custom.sqlite")).unwrap();

    let mut proxy = HttpProxy::new(
        chain.clone(),
        agent_kp.key_id(),
        policy.clone(),
        ledger,
        FixedClock::new(NOW_UNIX),
        AutoUpstreamTransport::from_parts(Http1TcpTransport::new(), CurlTlsTransport::new()),
    )
    .unwrap();

    let req = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-5/payments?currency=USD".to_string(),
        headers: vec![
            ("Host".into(), "localhost".into()),
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer client-must-strip".into()),
            ("X-Api-Key".into(), "forged-client-key".into()),
        ],
        body: br#"{"amount":10.00}"#.to_vec(),
    };
    let resp = proxy.handle_request(&req).unwrap();
    assert_eq!(resp.status, 200);
    let captured = upstream.captured.lock().unwrap();
    let fwd = &captured[0];
    assert!(fwd
        .headers
        .iter()
        .all(|(k, _)| !k.eq_ignore_ascii_case("authorization")));
    let api_keys: Vec<&str> = fwd
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("x-api-key"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(api_keys, vec!["custom-api-key-777"]);

    // Expired mandate chain takes strict precedence over unmapped route reason.
    let ledger_exp = SqliteLedger::open(dir.path().join("expired.sqlite")).unwrap();
    let mut expired_proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger_exp,
        FixedClock::new(VALID_UNTIL + 60),
        Http1TcpTransport::new(),
    )
    .unwrap();
    let unmapped = HttpRequest {
        method: HttpMethod::Get,
        target: "/v1/unmapped".to_string(),
        headers: vec![("Host".into(), "localhost".into())],
        body: Vec::new(),
    };
    let exp_resp = expired_proxy.handle_request(&unmapped).unwrap();
    let (exp_reason, _) = parse_denial_json(&exp_resp);
    assert!(
        !exp_reason.contains("unmapped HTTP route"),
        "expired chain reason must take precedence, got: {exp_reason}"
    );

    // Http1TcpTransport rejects https:// fail-closed.
    let https_req = UpstreamRequest {
        method: HttpMethod::Get,
        url: "https://example.com/v1/x".to_string(),
        target: "/v1/x".to_string(),
        host_header: "example.com".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    assert_eq!(
        Http1TcpTransport::new().send(&https_req),
        Err(TransportError::UnsupportedScheme {
            expected: "http",
            actual: "https".to_string(),
        })
    );

    // Non-loopback listener rejected by serve_listener.
    if let Ok(non_loopback) = TcpListener::bind("0.0.0.0:0") {
        let err = expired_proxy.serve_listener(non_loopback).unwrap_err();
        assert!(matches!(err, HttpProxyError::NonLoopbackBind(_)));
    }
}

#[test]
fn security_remediations_polyglot_query_interim_and_dup_serde() {
    use std::io::Cursor;

    // 1. Polyglot form-urlencoded & Content-Encoding on JSON body route are rejected.
    let dir = TempDir::new().unwrap();
    let upstream = MockUpstreamServer::start(0, br#"{}"#);
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json(&upstream.base_url(), "")).unwrap();
    let ledger = SqliteLedger::open(dir.path().join("sec.sqlite")).unwrap();
    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap();

    let polyglot = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Host".into(), "localhost".into()),
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
        ],
        body: br#"{"x":"=1&amount=999999&y=","amount":1}"#.to_vec(),
    };
    let (poly_reason, _) = parse_denial_json(&proxy.handle_request(&polyglot).unwrap());
    assert!(poly_reason.contains("application/json"));

    let encoded = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Host".into(), "localhost".into()),
            ("Content-Type".into(), "application/json".into()),
            ("Content-Encoding".into(), "gzip".into()),
        ],
        body: br#"{"amount":1}"#.to_vec(),
    };
    let (enc_reason, _) = parse_denial_json(&proxy.handle_request(&encoded).unwrap());
    assert!(enc_reason.contains("Content-Encoding"));

    // 2. Ambiguous `+` in query string is rejected fail-closed.
    let plus_query = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=US+D".to_string(),
        headers: vec![
            ("Host".into(), "localhost".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: br#"{"amount":1}"#.to_vec(),
    };
    let (plus_reason, _) = parse_denial_json(&proxy.handle_request(&plus_query).unwrap());
    assert!(plus_reason.contains("ambiguous character '+'"));
    assert_eq!(upstream.hit_count(), 0);

    // 3. Interim 1xx responses are skipped before returning final 200 OK.
    let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    let resp = read_http_response(
        &mut Cursor::new(&wire[..]),
        DEFAULT_MAX_HEADER_BYTES,
        DEFAULT_MAX_BODY_BYTES,
    )
    .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"{}");

    // 4. Public serde::Deserialize rejects duplicate static_facts keys.
    let dup = r#"{"upstream_base_url":"https://api.example.com","routes":[{"method":"GET","path_template":"/v1/items","action":"items.list","resource_kind":"item","resource_id":{"static":"all"},"static_facts":{"ctx.tier":{"str":"high"},"ctx.tier":{"str":"low"}}}]}"#;
    assert!(serde_json::from_str::<HttpPolicyMap>(dup).is_err());
}

struct CountingTransport {
    calls: Arc<AtomicUsize>,
    fail_with: Option<handfest_http::TransportError>,
}

impl handfest_http::UpstreamTransport for CountingTransport {
    fn send(
        &self,
        _req: &handfest_http::UpstreamRequest,
    ) -> Result<handfest_http::UpstreamResponse, handfest_http::TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = &self.fail_with {
            return Err(err.clone());
        }
        Ok(handfest_http::UpstreamResponse {
            status: 200,
            reason: "OK".to_string(),
            headers: Vec::new(),
            body: b"{}".to_vec(),
        })
    }
}

struct FailingLedger;

impl handfest_ledger::ReceiptLedger for FailingLedger {
    fn evaluate_and_record_with_revocations(
        &mut self,
        _chain: &[handfest_core::gate::VerifiedMandate],
        _request: &handfest_core::gate::ActionRequest,
        _facts: &handfest_core::gate::VerifiedFacts,
        _extra_revocations: &handfest_core::gate::RevocationSnapshot,
        _now: i64,
    ) -> Result<
        (handfest_core::Verdict, handfest_core::gate::DecisionReceipt),
        handfest_ledger::LedgerError,
    > {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn record_revocation(
        &mut self,
        _revocation: &handfest_core::gate::VerifiedRevocation,
        _signature_hex: &str,
    ) -> Result<handfest_core::revocation::RevocationId, handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn load_revocations(
        &self,
    ) -> Result<handfest_core::gate::RevocationSnapshot, handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn list_stored_revocations(
        &self,
    ) -> Result<Vec<handfest_ledger::StoredRevocation>, handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn record_denial(
        &mut self,
        _chain_ids: Vec<handfest_core::ast::MandateId>,
        _request: &handfest_core::gate::ActionRequest,
        _now: i64,
        _reason: String,
    ) -> Result<handfest_core::gate::DecisionReceipt, handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn record_denial_with_revocations(
        &mut self,
        _chain: &[handfest_core::gate::VerifiedMandate],
        _actor_key: &handfest_core::ast::KeyId,
        _request: &handfest_core::gate::ActionRequest,
        _extra_revocations: &handfest_core::gate::RevocationSnapshot,
        _now: i64,
        _fallback_reason: String,
    ) -> Result<(String, handfest_core::gate::DecisionReceipt), handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn verify_integrity(&self) -> Result<usize, handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn track_record(
        &self,
        _actor_key: &handfest_core::ast::KeyId,
    ) -> Result<handfest_ledger::TrackRecord, handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }

    fn audit_snapshot(
        &self,
        _actor_key: Option<&handfest_core::ast::KeyId>,
    ) -> Result<(usize, Option<handfest_ledger::TrackRecord>), handfest_ledger::LedgerError> {
        Err(handfest_ledger::LedgerError::Storage("disk full".into()))
    }
}

#[test]
fn handle_request_validates_headers_and_injected_secret_before_transport() {
    use handfest_http::{HttpProxyError, SecretError};

    let dir = TempDir::new().unwrap();
    let non_ascii_secret = write_secret_file(dir.path(), "non_ascii.txt", "tok\u{00e9}n");
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");

    let auth_json = format!(
        r#""upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        non_ascii_secret.display()
    );
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", &auth_json))
            .unwrap();
    let ledger_path = dir.path().join("hdr.sqlite");
    let ledger = SqliteLedger::open(&ledger_path).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        CountingTransport {
            calls: Arc::clone(&calls),
            fail_with: None,
        },
    )
    .unwrap();

    let bad_name = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Bad Header".into(), "ok".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: br#"{"amount":10.00}"#.to_vec(),
    };
    let (reason1, hash1) = parse_denial_json(&proxy.handle_request(&bad_name).unwrap());
    assert!(reason1.contains("invalid HTTP header name"));

    let bad_val = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("X-Custom".into(), "ok\r\nInjected: evil".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: br#"{"amount":10.00}"#.to_vec(),
    };
    let (reason2, hash2) = parse_denial_json(&proxy.handle_request(&bad_val).unwrap());
    assert!(reason2.contains("invalid HTTP header value"));

    let good_req = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"amount":10.00}"#.to_vec(),
    };
    let secret_err = proxy
        .handle_request(&good_req)
        .expect_err("non-ASCII secret must not reach transport");
    assert!(matches!(
        secret_err,
        HttpProxyError::Credential(SecretError::InvalidSecretValue(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let receipts = proxy.ledger().list_receipts().unwrap();
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].receipt_hash.to_string(), hash1);
    assert_eq!(
        receipts[0].verdict,
        handfest_core::Verdict::Deny { reason: reason1 }
    );
    assert_eq!(receipts[1].receipt_hash.to_string(), hash2);
    assert_eq!(
        receipts[1].verdict,
        handfest_core::Verdict::Deny { reason: reason2 }
    );
}

#[test]
fn serve_connection_handles_empty_stream_and_transport_error() {
    use handfest_http::TransportError;

    let dir = TempDir::new().unwrap();
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", "")).unwrap();
    let ledger = SqliteLedger::open(dir.path().join("t.sqlite")).unwrap();
    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        CountingTransport {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_with: Some(TransportError::ConnectFailed("refused".into())),
        },
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = thread::spawn(move || {
        for _ in 0..2 {
            let (s, _) = listener.accept().unwrap();
            proxy.serve_connection(s).unwrap();
        }
    });

    drop(TcpStream::connect(addr).unwrap());

    let mut client = TcpStream::connect(addr).unwrap();
    client
        .write_all(b"POST /v1/accounts/acct-1/payments?currency=USD HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"amount\":5.00}")
        .unwrap();
    let resp = read_http_response(
        &mut BufReader::new(&client),
        DEFAULT_MAX_HEADER_BYTES,
        DEFAULT_MAX_BODY_BYTES,
    )
    .unwrap();
    assert_eq!(resp.status, 502);
    assert!(String::from_utf8_lossy(&resp.body).contains("upstream_transport_error"));
    srv.join().unwrap();
}

#[test]
fn serve_connection_handles_credential_and_fatal_ledger_errors() {
    use handfest_http::{HttpProxyError, PepError};

    let dir = TempDir::new().unwrap();
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let valid_wire = b"POST /v1/accounts/acct-1/payments?currency=USD HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"amount\":5.00}";

    let missing = dir.path().join("missing-on-permit.txt");
    let auth_json = format!(
        r#""upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        missing.display()
    );
    let policy_cred =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", &auth_json))
            .unwrap();
    let ledger_cred = SqliteLedger::open(dir.path().join("c.sqlite")).unwrap();
    let mut cred_proxy = HttpProxy::new(
        chain.clone(),
        agent_kp.key_id(),
        policy_cred,
        ledger_cred,
        FixedClock::new(NOW_UNIX),
        CountingTransport {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_with: None,
        },
    )
    .unwrap();
    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let a1 = l1.local_addr().unwrap();
    let s1 = thread::spawn(move || {
        let (s, _) = l1.accept().unwrap();
        cred_proxy.serve_connection(s)
    });
    let mut c1 = TcpStream::connect(a1).unwrap();
    c1.write_all(valid_wire).unwrap();
    let r1 = read_http_response(
        &mut BufReader::new(&c1),
        DEFAULT_MAX_HEADER_BYTES,
        DEFAULT_MAX_BODY_BYTES,
    )
    .unwrap();
    assert_eq!(r1.status, 500);
    assert!(String::from_utf8_lossy(&r1.body).contains("credential_error"));
    assert!(s1.join().unwrap().is_ok());

    let policy_led =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", "")).unwrap();
    let mut led_proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy_led,
        FailingLedger,
        FixedClock::new(NOW_UNIX),
        CountingTransport {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_with: None,
        },
    )
    .unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let a2 = l2.local_addr().unwrap();
    let s2 = thread::spawn(move || {
        let (s, _) = l2.accept().unwrap();
        led_proxy.serve_connection(s)
    });
    let mut c2 = TcpStream::connect(a2).unwrap();
    c2.write_all(valid_wire).unwrap();
    let r2 = read_http_response(
        &mut BufReader::new(&c2),
        DEFAULT_MAX_HEADER_BYTES,
        DEFAULT_MAX_BODY_BYTES,
    )
    .unwrap();
    assert_eq!(r2.status, 500);
    assert!(String::from_utf8_lossy(&r2.body).contains("ledger_error"));
    assert!(matches!(
        s2.join().unwrap(),
        Err(HttpProxyError::Pep(PepError::Ledger(_)))
    ));
}

#[test]
fn cli_binary_reports_structured_startup_errors_and_help() {
    let dir = TempDir::new().unwrap();
    let bin = env!("CARGO_BIN_EXE_handfest-http");

    let help = Command::new(bin).arg("--help").output().unwrap();
    assert!(help.status.success());

    let missing_args = Command::new(bin).output().unwrap();
    assert!(!missing_args.status.success());
    let err_json = parse_exact_json(String::from_utf8_lossy(&missing_args.stderr).trim()).unwrap();
    assert_eq!(
        err_json.as_object().unwrap().get("code"),
        Some(&ExactJson::Str("cli_args".into()))
    );

    let missing_chain = Command::new(bin)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--ledger",
            dir.path().join("l.sqlite").to_str().unwrap(),
            "--chain",
            dir.path().join("missing.json").to_str().unwrap(),
            "--actor-key",
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
            "--policy-map",
            dir.path().join("policy.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!missing_chain.status.success());
    let chain_err =
        parse_exact_json(String::from_utf8_lossy(&missing_chain.stderr).trim()).unwrap();
    assert_eq!(
        chain_err.as_object().unwrap().get("code"),
        Some(&ExactJson::Str("chain_io".into()))
    );
}

#[test]
fn content_type_charset_enforces_strict_utf8_only_and_rejects_utf7_and_malformed_params() {
    let dir = TempDir::new().unwrap();
    let secret = write_secret_file(dir.path(), "ct-secret.txt", "ct-token\n");
    let upstream = MockUpstreamServer::start(3, br#"{"ok":true}"#);
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let auth_json = format!(
        r#""upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        secret.display()
    );
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json(&upstream.base_url(), &auth_json))
            .unwrap();
    let ledger = SqliteLedger::open(dir.path().join("ct.sqlite")).unwrap();
    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap();

    let make_req = |ct: &str| HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![("Content-Type".to_string(), ct.to_string())],
        body: br#"{"amount": 5.00}"#.to_vec(),
    };

    // Accepted: utf-8 unquoted and "UTF-8" double-quoted (case-insensitive).
    for ok_ct in [
        "application/json; charset=utf-8",
        "application/json; charset=\"UTF-8\"",
        "application/json; CHARSET=utf-8",
    ] {
        let resp = proxy.handle_request(&make_req(ok_ct)).unwrap();
        assert_eq!(resp.status, 200, "expected 200 for Content-Type '{ok_ct}'");
    }
    assert_eq!(upstream.hit_count(), 3);

    // Denied with 403 handfest_denied: charset=utf-7, duplicate charset, unknown param, malformed param.
    for bad_ct in [
        "application/json; charset=utf-7",
        "application/json; charset=utf-8; charset=utf-8",
        "application/json; charset=utf-8; boundary=foo",
        "application/json;",
        "application/json; bogus",
        "application/json; charset=\"utf-8",
    ] {
        let resp = proxy.handle_request(&make_req(bad_ct)).unwrap();
        assert_eq!(resp.status, 403, "expected 403 for Content-Type '{bad_ct}'");
        let (reason, hash) = parse_denial_json(&resp);
        assert!(
            reason.contains("Content-Type"),
            "expected Content-Type denial reason for '{bad_ct}', got '{reason}'"
        );
        assert!(hash.starts_with("sha256:"));
    }
    assert_eq!(upstream.hit_count(), 3);
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 9);
}

#[test]
fn round3_proxy_blocks_connection_content_type_and_encoding_stripping() {
    let dir = TempDir::new().unwrap();
    let secret = write_secret_file(dir.path(), "r3-secret.txt", "r3-token\n");
    let upstream = MockUpstreamServer::start(0, br#"{"ok":true}"#);
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let auth_json = format!(
        r#""upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{}" }} }} }} }},"#,
        secret.display()
    );
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json(&upstream.base_url(), &auth_json))
            .unwrap();
    let ledger = SqliteLedger::open(dir.path().join("r3-ct.sqlite")).unwrap();
    let mut proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        ledger,
        FixedClock::new(NOW_UNIX),
        Http1TcpTransport::new(),
    )
    .unwrap();

    let req_strip_ct = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Connection".to_string(), "Content-Type".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: br#"{"amount": 5.00}"#.to_vec(),
    };
    let resp = proxy.handle_request(&req_strip_ct).unwrap();
    assert_eq!(resp.status, 403);
    let (reason, hash) = parse_denial_json(&resp);
    assert!(
        reason.contains("Content-Type"),
        "expected Content-Type denial reason, got '{reason}'"
    );
    assert!(hash.starts_with("sha256:"));
    assert_eq!(upstream.hit_count(), 0);

    let req_strip_ce = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![
            ("Connection".to_string(), "Content-Encoding".to_string()),
            ("Content-Encoding".to_string(), "gzip".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: br#"{"amount": 5.00}"#.to_vec(),
    };
    let resp_ce = proxy.handle_request(&req_strip_ce).unwrap();
    assert_eq!(resp_ce.status, 403);
    let (reason_ce, _) = parse_denial_json(&resp_ce);
    assert!(reason_ce.contains("Content-Encoding"));
    assert_eq!(upstream.hit_count(), 0);
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 2);
}

#[test]
fn round3_proxy_rejects_invalid_upstream_statuses() {
    use handfest_http::{
        HttpProxyError, TransportError, UpstreamRequest, UpstreamResponse, UpstreamTransport,
    };
    struct FixedStatusTransport(u16);
    impl UpstreamTransport for FixedStatusTransport {
        fn send(&self, _req: &UpstreamRequest) -> Result<UpstreamResponse, TransportError> {
            Ok(UpstreamResponse {
                status: self.0,
                reason: "Bad".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
        }
    }

    let dir = TempDir::new().unwrap();
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", "")).unwrap();

    for bad_status in [100u16, 101, 9999] {
        let l = SqliteLedger::open(dir.path().join(format!("status-{bad_status}.sqlite"))).unwrap();
        let mut p = HttpProxy::new(
            chain.clone(),
            agent_kp.key_id(),
            policy.clone(),
            l,
            FixedClock::new(NOW_UNIX),
            FixedStatusTransport(bad_status),
        )
        .unwrap();
        let ok_req = HttpRequest {
            method: HttpMethod::Post,
            target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: br#"{"amount": 5.00}"#.to_vec(),
        };
        let err = p
            .handle_request(&ok_req)
            .expect_err("invalid upstream status must fail");
        assert!(
            matches!(
                err,
                HttpProxyError::Transport(TransportError::InvalidResponse(ref msg))
                    if msg.contains(&bad_status.to_string())
            ),
            "expected InvalidResponse for status {bad_status}, got {err:?}"
        );
    }
}

struct StaticResponseTransport(handfest_http::UpstreamResponse);

impl handfest_http::UpstreamTransport for StaticResponseTransport {
    fn send(
        &self,
        _req: &handfest_http::UpstreamRequest,
    ) -> Result<handfest_http::UpstreamResponse, handfest_http::TransportError> {
        Ok(self.0.clone())
    }
}

#[test]
fn round4_proxy_rejects_invalid_upstream_response_postconditions() {
    use handfest_http::{HttpProxyError, TransportError, UpstreamResponse};

    let dir = TempDir::new().unwrap();
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", "")).unwrap();
    let ok_req = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: br#"{"amount": 5.00}"#.to_vec(),
    };

    let bad_responses = [
        (
            "204-body",
            UpstreamResponse {
                status: 204,
                reason: "No Content".to_string(),
                headers: Vec::new(),
                body: b"smuggled".to_vec(),
            },
            "bodyless HTTP 204",
        ),
        (
            "304-body",
            UpstreamResponse {
                status: 304,
                reason: "Not Modified".to_string(),
                headers: Vec::new(),
                body: b"smuggled".to_vec(),
            },
            "bodyless HTTP 304",
        ),
        (
            "bad-header-name",
            UpstreamResponse {
                status: 200,
                reason: "OK".to_string(),
                headers: vec![("Bad Name".to_string(), "val".to_string())],
                body: b"ok".to_vec(),
            },
            "invalid header name",
        ),
        (
            "bad-header-value",
            UpstreamResponse {
                status: 200,
                reason: "OK".to_string(),
                headers: vec![("X-Test".to_string(), "val\r\nInjected: 1".to_string())],
                body: b"ok".to_vec(),
            },
            "invalid header value",
        ),
    ];

    for (label, resp, expected_substr) in bad_responses {
        let l = SqliteLedger::open(dir.path().join(format!("{label}.sqlite"))).unwrap();
        let mut p = HttpProxy::new(
            chain.clone(),
            agent_kp.key_id(),
            policy.clone(),
            l,
            FixedClock::new(NOW_UNIX),
            StaticResponseTransport(resp),
        )
        .unwrap();
        let err = p
            .handle_request(&ok_req)
            .expect_err(&format!("{label} must fail postcondition"));
        assert!(
            matches!(
                err,
                HttpProxyError::Transport(TransportError::InvalidResponse(ref msg))
                    if msg.contains(expected_substr)
            ),
            "expected InvalidResponse containing '{expected_substr}' for {label}, got {err:?}"
        );
    }
}

#[test]
fn round4_proxy_maps_upstream_response_postcondition_failure_to_502() {
    use handfest_http::UpstreamResponse;

    let dir = TempDir::new().unwrap();
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", "")).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let l502 = SqliteLedger::open(dir.path().join("r4-502.sqlite")).unwrap();
    let mut p502 = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        policy,
        l502,
        FixedClock::new(NOW_UNIX),
        StaticResponseTransport(UpstreamResponse {
            status: 204,
            reason: "No Content".to_string(),
            headers: Vec::new(),
            body: b"smuggled".to_vec(),
        }),
    )
    .unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        p502.serve_connection(stream).unwrap();
    });
    let raw_wire = concat!(
        "POST /v1/accounts/acct-1/payments?currency=USD HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: 16\r\n\r\n",
        r#"{"amount": 5.00}"#,
    );
    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(raw_wire.as_bytes()).unwrap();
    let mut reader = BufReader::new(&client);
    let wire_resp = read_http_response(&mut reader, 8192, 8192).unwrap();
    server.join().unwrap();
    assert_eq!(wire_resp.status, 502);
}

fn assert_upstream_response_rejected_and_502(
    dir: &std::path::Path,
    chain: &[handfest_core::gate::VerifiedMandate],
    actor_key: &handfest_core::ast::KeyId,
    policy: &HttpPolicyMap,
    label: &str,
    resp: handfest_http::UpstreamResponse,
    expected_substr: &str,
) {
    use handfest_http::{HttpProxyError, TransportError};

    let ok_req = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/accounts/acct-1/payments?currency=USD".to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: br#"{"amount": 5.00}"#.to_vec(),
    };
    let l = SqliteLedger::open(dir.join(format!("r5-{label}.sqlite"))).unwrap();
    let mut p = HttpProxy::new(
        chain.to_vec(),
        actor_key.clone(),
        policy.clone(),
        l,
        FixedClock::new(NOW_UNIX),
        StaticResponseTransport(resp.clone()),
    )
    .unwrap();
    let err = p
        .handle_request(&ok_req)
        .expect_err(&format!("{label} must fail upstream postcondition"));
    assert!(
        matches!(
            err,
            HttpProxyError::Transport(TransportError::InvalidResponse(ref msg))
                if msg.contains(expected_substr)
        ),
        "expected InvalidResponse containing '{expected_substr}' for {label}, got {err:?}"
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let l502 = SqliteLedger::open(dir.join(format!("r5-502-{label}.sqlite"))).unwrap();
    let mut p502 = HttpProxy::new(
        chain.to_vec(),
        actor_key.clone(),
        policy.clone(),
        l502,
        FixedClock::new(NOW_UNIX),
        StaticResponseTransport(resp),
    )
    .unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        p502.serve_connection(stream).unwrap();
    });
    let raw_wire = concat!(
        "POST /v1/accounts/acct-1/payments?currency=USD HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: 16\r\n\r\n",
        r#"{"amount": 5.00}"#,
    );
    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(raw_wire.as_bytes()).unwrap();
    let mut reader = BufReader::new(&client);
    let wire_resp = read_http_response(&mut reader, 8192, 8192).unwrap();
    server.join().unwrap();
    assert_eq!(wire_resp.status, 502, "expected 502 for {label}");
}

#[test]
fn round5_proxy_validates_upstream_reason_and_response_framing_postconditions() {
    use handfest_http::UpstreamResponse;

    let dir = TempDir::new().unwrap();
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let policy =
        HttpPolicyMap::from_json_str(&payment_policy_json("http://127.0.0.1:9", "")).unwrap();

    let bad_responses = [
        (
            "crlf-reason",
            UpstreamResponse {
                status: 200,
                reason: "OK\r\nX-Injected: 1".to_string(),
                headers: Vec::new(),
                body: b"ok".to_vec(),
            },
            "reason phrase",
        ),
        (
            "te-and-cl",
            UpstreamResponse {
                status: 200,
                reason: "OK".to_string(),
                headers: vec![
                    ("Transfer-Encoding".to_string(), "chunked".to_string()),
                    ("Content-Length".to_string(), "2".to_string()),
                ],
                body: b"ok".to_vec(),
            },
            "Transfer-Encoding",
        ),
        (
            "204-with-cl",
            UpstreamResponse {
                status: 204,
                reason: "No Content".to_string(),
                headers: vec![("Content-Length".to_string(), "5".to_string())],
                body: Vec::new(),
            },
            "forbidden on HTTP 204",
        ),
        (
            "cl-body-mismatch",
            UpstreamResponse {
                status: 200,
                reason: "OK".to_string(),
                headers: vec![("Content-Length".to_string(), "10".to_string())],
                body: b"short".to_vec(),
            },
            "Content-Length 10",
        ),
        (
            "cl-zero-with-body",
            UpstreamResponse {
                status: 200,
                reason: "OK".to_string(),
                headers: vec![("Content-Length".to_string(), "0".to_string())],
                body: b"smuggled".to_vec(),
            },
            "Content-Length 0",
        ),
    ];

    let actor_key = agent_kp.key_id();
    for (label, resp, expected_substr) in bad_responses {
        assert_upstream_response_rejected_and_502(
            dir.path(),
            &chain,
            &actor_key,
            &policy,
            label,
            resp,
            expected_substr,
        );
    }
}

#[test]
fn round5_proxy_does_not_parse_rejected_json_body_into_denial_resource_id() {
    use handfest_http::UpstreamResponse;

    let dir = TempDir::new().unwrap();
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let (chain, _) = build_signed_chain(&root_kp, &agent_kp, "");
    let body_field_policy_json = r#"{
        "upstream_base_url": "http://127.0.0.1:9",
        "routes": [
            {
                "method": "POST",
                "path_template": "/v1/payments",
                "action": "payments.send",
                "resource_kind": "account",
                "resource_id": { "body_field": "id" },
                "body_facts": {
                    "amount": { "field": "payment.amount", "type": "decimal" }
                }
            }
        ]
    }"#;
    let body_field_policy = HttpPolicyMap::from_json_str(body_field_policy_json).unwrap();
    let denial_ledger = SqliteLedger::open(dir.path().join("r5-utf7-denial.sqlite")).unwrap();
    let mut denial_proxy = HttpProxy::new(
        chain,
        agent_kp.key_id(),
        body_field_policy,
        denial_ledger,
        FixedClock::new(NOW_UNIX),
        StaticResponseTransport(UpstreamResponse {
            status: 200,
            reason: "OK".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }),
    )
    .unwrap();
    let utf7_req = HttpRequest {
        method: HttpMethod::Post,
        target: "/v1/payments".to_string(),
        headers: vec![(
            "Content-Type".to_string(),
            "application/json; charset=utf-7".to_string(),
        )],
        body: br#"{"id":"acct-benign","amount":5.00}"#.to_vec(),
    };
    let resp = denial_proxy
        .handle_request(&utf7_req)
        .expect("utf-7 request returns 403 denial response");
    assert_eq!(resp.status, 403);
    let receipts = denial_proxy.ledger().list_receipts().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].resource, r#"account """#,
        "rejected Content-Type body must never be parsed for resource_id"
    );
}
