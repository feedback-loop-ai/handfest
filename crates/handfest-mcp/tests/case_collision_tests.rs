//! Round 5 regression tests closing case-colliding JSON key smuggling across JSON-RPC 2.0
//! client envelopes, upstream envelopes, `tools/call` params, and `tools/call` arguments.

use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_core::ast::{parse_rfc3339_utc, Decimal, KeyId, Scalar};
use handfest_core::cnl::{parse_mandate, try_render_canonical};
use handfest_core::gate::VerifiedMandate;
use handfest_ledger::SqliteLedger;
use handfest_mcp::{
    verify_mandate_chain, FixedClock, MappingError, McpProxy, ProxyError, ToolPolicyMap,
    HANDFEST_DENIED_ERROR_CODE,
};
use serde_json::{json, Value};

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl SharedWriter {
    fn snapshot(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PipeWriter(mpsc::Sender<Vec<u8>>);

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PipeReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) if chunk.is_empty() => continue,
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn mem_pipe() -> (PipeWriter, BufReader<PipeReader>) {
    let (tx, rx) = mpsc::channel();
    (
        PipeWriter(tx),
        BufReader::new(PipeReader {
            rx,
            buf: Vec::new(),
            pos: 0,
        }),
    )
}

fn sign_mandate(
    signer: &Ed25519Keypair,
    text: &str,
    valid_from: i64,
    valid_until: i64,
) -> SignedMandate {
    let ast = parse_mandate(text).expect("valid HANDFEST v1 mandate");
    let canonical = try_render_canonical(&ast).expect("canonical render");
    signer
        .sign_mandate(&canonical, "test-anchor", valid_from, valid_until)
        .expect("sign mandate")
}

fn single_hop_chain() -> (Vec<VerifiedMandate>, Ed25519Keypair) {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();

    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Admin\" (key: {root})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/*\"\n",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let signed = sign_mandate(&root_kp, &text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();
    (verified, agent_kp)
}

fn merge_pr_policy_map() -> ToolPolicyMap {
    ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "merge_pr": {
                    "action": "git.pr.merge",
                    "resource_kind": "repo",
                    "resource_id_arg": "repo",
                    "arg_facts": {
                        "branch": { "field": "resource.branch", "type": "str" }
                    }
                }
            }
        }"#,
    )
    .unwrap()
}

fn make_proxy() -> (McpProxy<FixedClock, SqliteLedger>, Ed25519Keypair) {
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    let (verified, agent_kp) = single_hop_chain();
    let proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        merge_pr_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    (proxy, agent_kp)
}

#[test]
fn case_a_client_envelope_rejects_case_colliding_top_level_keys_with_32600() {
    let (mut proxy, _agent_kp) = make_proxy();
    let client_in = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","METHOD":"tools/call","params":{"name":"delete_repo","arguments":{"repo":"org/prod"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"ping","ID":99}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"ping","RESULT":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","ERROR":{"code":-1,"message":"x"}}"#,
        "\n",
    );

    let mut client_out = Vec::new();
    let upstream_in = SharedWriter::default();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            upstream_in.clone(),
            BufReader::new(Cursor::new(Vec::<u8>::new())),
        )
        .expect("invalid client frames return -32600 without crashing session");

    let forwarded = upstream_in.snapshot();
    assert!(
        forwarded.is_empty(),
        "upstream must receive 0 calls for smuggled top-level keys, got: {}",
        String::from_utf8_lossy(&forwarded)
    );

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 4);

    assert_eq!(responses[0]["id"], json!(1));
    assert_eq!(responses[0]["error"]["code"], json!(-32600));
    assert!(responses[0]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("METHOD"));

    assert_eq!(responses[1]["id"], json!(2));
    assert_eq!(responses[1]["error"]["code"], json!(-32600));
    assert!(responses[1]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("ID"));

    assert_eq!(responses[2]["id"], json!(3));
    assert_eq!(responses[2]["error"]["code"], json!(-32600));
    assert!(responses[2]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("RESULT"));

    assert_eq!(responses[3]["id"], json!(null));
    assert_eq!(responses[3]["error"]["code"], json!(-32600));
    assert!(responses[3]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("ERROR"));
}

#[test]
fn case_b_tools_call_rejects_smuggled_params_and_case_colliding_arguments() {
    let (mut proxy, _agent_kp) = make_proxy();
    let client_in = concat!(
        // Case B1: smuggled uppercase NAME in tools/call params
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"merge_pr","NAME":"delete_repo","arguments":{"repo":"org/app","branch":"main"}}}"#,
        "\n",
        // Case B2: case-colliding REPO alongside repo in arguments
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app","REPO":"evil/prod","branch":"main"}}}"#,
        "\n",
        // Case B3: standalone case-mismatched REPO colliding with configured resource_id_arg "repo"
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"merge_pr","arguments":{"REPO":"evil/prod","branch":"main"}}}"#,
        "\n",
        // Case B4: nested object case-collision inside arguments
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app","branch":"main","opts":{"force":false,"FORCE":true}}}}"#,
        "\n",
        // Case B5: smuggled ARGUMENTS key in params
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"org/app","branch":"main"},"ARGUMENTS":{"repo":"evil/prod"}}}"#,
        "\n",
    );

    let mut client_out = Vec::new();
    let upstream_in = SharedWriter::default();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.as_bytes().to_vec())),
            &mut client_out,
            upstream_in.clone(),
            BufReader::new(Cursor::new(Vec::<u8>::new())),
        )
        .expect("denied tools/call frames must not terminate session");

    let forwarded = upstream_in.snapshot();
    assert!(
        forwarded.is_empty(),
        "upstream must receive 0 calls for smuggled params/arguments, got: {}",
        String::from_utf8_lossy(&forwarded)
    );
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 5);

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 5);
    for (idx, resp) in responses.iter().enumerate() {
        assert_eq!(resp["id"], json!(idx + 1));
        assert_eq!(
            resp["error"]["code"],
            json!(HANDFEST_DENIED_ERROR_CODE),
            "response {idx} must be denied: {resp}"
        );
        assert!(resp["error"]["data"]["receipt_hash"].is_string());
    }
    assert!(responses[0]["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("NAME"));
    assert!(responses[1]["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("collides case-insensitively"));
    assert!(responses[2]["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("REPO"));
    assert!(responses[3]["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("collides case-insensitively"));
    assert!(responses[4]["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("ARGUMENTS"));
}

#[test]
fn tools_call_allows_standard_meta_param_and_reports_typed_mapping_collisions() {
    let (mut proxy, agent_kp) = make_proxy();
    let map = merge_pr_policy_map();

    // Direct typed MappingError assertions for every case-collision path.
    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "merge_pr",
            Some(r#"{"repo":"org/app","REPO":"evil/prod","branch":"main"}"#),
        ),
        Err(MappingError::CaseCollidingArgumentKey {
            tool: "merge_pr".to_string(),
            key: "repo".to_string(),
            collides_with: "REPO".to_string(),
        })
    );
    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "merge_pr",
            Some(r#"{"REPO":"evil/prod","branch":"main"}"#),
        ),
        Err(MappingError::CaseCollidingArgumentKey {
            tool: "merge_pr".to_string(),
            key: "REPO".to_string(),
            collides_with: "repo".to_string(),
        })
    );
    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "merge_pr",
            Some(r#"{"repo":"org/app","BRANCH":"main"}"#),
        ),
        Err(MappingError::CaseCollidingArgumentKey {
            tool: "merge_pr".to_string(),
            key: "BRANCH".to_string(),
            collides_with: "branch".to_string(),
        })
    );
    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "merge_pr",
            Some(r#"{"repo":"org/app","branch":"main","items":[{"x":1,"X":2}]}"#),
        ),
        Err(MappingError::CaseCollidingArgumentKey {
            tool: "merge_pr".to_string(),
            key: "x".to_string(),
            collides_with: "X".to_string(),
        })
    );

    // Valid tools/call with standard `_meta` key is permitted and forwarded.
    let client_in = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"merge_pr","_meta":{"progressToken":"t1"},"arguments":{"repo":"org/app","branch":"main"}}}"#.to_string() + "\n";
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut req = String::new();
        up_in_r.read_line(&mut req).unwrap();
        writeln!(
            up_out_w,
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"merged":true}}}}"#
        )
        .unwrap();
        req
    });
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.into_bytes())),
            &mut client_out,
            up_in_w,
            up_out_r,
        )
        .expect("valid tools/call with _meta must succeed");

    let forwarded_line = upstream.join().unwrap();
    let forwarded: Value = serde_json::from_str(forwarded_line.trim_end()).unwrap();
    assert_eq!(forwarded["params"]["_meta"]["progressToken"], json!("t1"));
    let resp: Value =
        serde_json::from_str(String::from_utf8(client_out).unwrap().trim_end()).unwrap();
    assert_eq!(resp["result"]["merged"], json!(true));
}

#[test]
fn case_c_upstream_tools_list_rejects_smuggled_result_alongside_error() {
    let (mut proxy, _agent_kp) = make_proxy();
    let client_in =
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#.to_string() + "\n";
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut req = String::new();
        up_in_r.read_line(&mut req).unwrap();
        writeln!(
            up_out_w,
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32603,"message":"fail"}},"RESULT":{{"tools":[{{"name":"delete_repo"}}]}}}}"#
        )
        .unwrap();
    });

    let mut client_out = Vec::new();
    let res = proxy.run(
        BufReader::new(Cursor::new(client_in.into_bytes())),
        &mut client_out,
        up_in_w,
        up_out_r,
    );
    upstream.join().unwrap();
    assert!(
        matches!(res, Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains("RESULT")),
        "expected UpstreamProtocol mentioning RESULT, got {res:?}"
    );

    let out_str = String::from_utf8(client_out).unwrap();
    assert!(
        !out_str.contains("delete_repo"),
        "malicious upstream RESULT must never be relayed verbatim: {out_str}"
    );
    let resp: Value = serde_json::from_str(out_str.trim_end()).unwrap();
    assert_eq!(resp["id"], json!(1));
    assert_eq!(resp["error"]["code"], json!(-32603));
    assert!(resp["RESULT"].is_null());
}

#[test]
fn maps_all_five_fact_types_losslessly_with_static_resource_and_override() {
    let actor =
        KeyId::parse("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    let json = r#"{
        "tools": {
            "submit": {
                "action": "finance.invoice.submit",
                "resource_kind": "ledger",
                "static_resource_id": "prod-main",
                "arg_facts": {
                    "tag": { "field": "resource.tag", "type": "str" },
                    "count": { "field": "resource.count", "type": "int" },
                    "amount": { "field": "resource.amount", "type": "decimal" },
                    "urgent": { "field": "resource.urgent", "type": "bool" },
                    "due": { "field": "resource.due", "type": "timestamp" }
                },
                "static_facts": {
                    "resource.tag": { "str": "broker-enforced" }
                }
            }
        }
    }"#;
    let map = ToolPolicyMap::from_json_str(json).unwrap();
    let args = r#"{
        "tag": "spoofed",
        "count": 7,
        "amount": 100.000000000000001,
        "urgent": true,
        "due": "2026-06-01T12:00:00Z"
    }"#;
    let (req, facts) = map.map_call_json(&actor, "submit", Some(args)).unwrap();
    assert_eq!(req.action, "finance.invoice.submit");
    assert_eq!(req.resource_kind, "ledger");
    assert_eq!(req.resource_id, "prod-main");
    assert_eq!(
        facts.get("resource.tag"),
        Some(&Scalar::Str("broker-enforced".to_string()))
    );
    assert_eq!(facts.get("resource.count"), Some(&Scalar::Int(7)));
    assert_eq!(
        facts.get("resource.amount"),
        Some(&Scalar::Decimal(
            Decimal::parse("100.000000000000001").unwrap()
        ))
    );
    assert_eq!(facts.get("resource.urgent"), Some(&Scalar::Bool(true)));
    assert_eq!(
        facts.get("resource.due"),
        Some(&Scalar::Timestamp(
            parse_rfc3339_utc("2026-06-01T12:00:00Z").unwrap()
        ))
    );
}

fn deploy_and_pay_policy_map() -> ToolPolicyMap {
    ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "deploy": {
                    "action": "infra.deploy",
                    "resource_kind": "host",
                    "resource_id_arg": "host"
                },
                "pay": {
                    "action": "finance.pay",
                    "resource_kind": "account",
                    "static_resource_id": "acct-main",
                    "arg_facts": {
                        "amount_usd": { "field": "resource.amount_usd", "type": "decimal" }
                    }
                }
            }
        }"#,
    )
    .unwrap()
}

fn deploy_and_pay_proxy() -> (McpProxy<FixedClock, SqliteLedger>, Ed25519Keypair) {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let now = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();

    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Admin\" (key: {root})\n\
         TO agent \"Worker\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW infra.deploy, finance.pay\n\
         ON host \"staging/*\", account \"acct-*\"\n\
         WHERE resource.amount_usd <= 10.00\n",
        root = root_kp.key_id(),
        agent = agent_kp.key_id(),
    );
    let signed = sign_mandate(&root_kp, &text, valid_from, valid_until);
    let verified = verify_mandate_chain(&[signed]).unwrap();
    let proxy = McpProxy::new(
        verified,
        agent_kp.key_id(),
        deploy_and_pay_policy_map(),
        SqliteLedger::open_in_memory().unwrap(),
        FixedClock::new(now),
    )
    .unwrap();
    (proxy, agent_kp)
}

#[test]
fn round6_unicode_simplefold_argument_keys_denied_with_zero_upstream_calls() {
    let (mut proxy, agent_kp) = deploy_and_pay_proxy();
    let map = deploy_and_pay_policy_map();

    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "deploy",
            Some("{\"host\":\"staging/web\",\"ho\u{017f}t\":\"prod/db\"}"),
        ),
        Err(MappingError::NonAsciiArgumentKey {
            tool: "deploy".to_string(),
            key: "ho\u{017f}t".to_string(),
        })
    );
    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "pay",
            Some("{\"amount_usd\":1.00,\"amount_u\u{017f}d\":999999.00}"),
        ),
        Err(MappingError::NonAsciiArgumentKey {
            tool: "pay".to_string(),
            key: "amount_u\u{017f}d".to_string(),
        })
    );
    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "deploy",
            Some("{\"host\":\"staging/web\",\"\u{212a}ey\":\"evil\"}"),
        ),
        Err(MappingError::NonAsciiArgumentKey {
            tool: "deploy".to_string(),
            key: "\u{212a}ey".to_string(),
        })
    );
    assert_eq!(
        map.map_call_json(
            &agent_kp.key_id(),
            "deploy",
            Some("{\"host\":\"staging/web\",\"items\":[{\"ho\u{017f}t\":\"prod/db\"}]}"),
        ),
        Err(MappingError::NonAsciiArgumentKey {
            tool: "deploy".to_string(),
            key: "ho\u{017f}t".to_string(),
        })
    );
    assert!(map
        .map_call_json(
            &agent_kp.key_id(),
            "deploy",
            Some("{\"host\":\"staging/café\"}"),
        )
        .is_ok());

    let client_in = format!(
        "{}\n{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","arguments":{"host":"staging/web","ho\u017ft":"prod/db"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pay","arguments":{"amount_usd":1.00,"amount_u\u017fd":999999.00}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"deploy","arguments":{"host":"staging/web","\u212aey":"evil"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"deploy","arguments":{"host":"staging/web","opts":{"ho\u017ft":"prod/db"}}}}"#,
    );
    let mut client_out = Vec::new();
    let upstream_in = SharedWriter::default();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.into_bytes())),
            &mut client_out,
            upstream_in.clone(),
            BufReader::new(Cursor::new(Vec::<u8>::new())),
        )
        .expect("denied tools/call frames must not terminate session");

    let forwarded = upstream_in.snapshot();
    assert!(
        forwarded.is_empty(),
        "upstream must receive 0 calls for Unicode SimpleFold smuggled keys, got: {}",
        String::from_utf8_lossy(&forwarded)
    );
    assert_eq!(proxy.ledger().verify_integrity().unwrap(), 4);

    let responses: Vec<Value> = String::from_utf8(client_out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 4);
    for (idx, resp) in responses.iter().enumerate() {
        assert_eq!(resp["id"], json!(idx + 1));
        assert_eq!(resp["error"]["code"], json!(HANDFEST_DENIED_ERROR_CODE));
        assert!(resp["error"]["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("must be ASCII"));
        assert!(resp["error"]["data"]["receipt_hash"].is_string());
    }
}

#[test]
fn round6_policy_map_validate_rejects_case_colliding_and_non_ascii_arg_keys() {
    assert!(matches!(
        ToolPolicyMap::from_json_str(
            r#"{
                "tools": {
                    "merge_pr": {
                        "action": "git.pr.merge",
                        "resource_kind": "repo",
                        "resource_id_arg": "repo",
                        "arg_facts": {
                            "REPO": { "field": "resource.repo", "type": "str" }
                        }
                    }
                }
            }"#,
        ),
        Err(MappingError::InvalidPolicy(ref msg))
            if msg.contains("collides case-insensitively with resource_id_arg")
    ));
    assert!(matches!(
        ToolPolicyMap::from_json_str(
            r#"{
                "tools": {
                    "pay": {
                        "action": "finance.pay",
                        "resource_kind": "account",
                        "static_resource_id": "acct-1",
                        "arg_facts": {
                            "amount": { "field": "resource.amount", "type": "decimal" },
                            "AMOUNT": { "field": "resource.other", "type": "decimal" }
                        }
                    }
                }
            }"#,
        ),
        Err(MappingError::InvalidPolicy(ref msg)) if msg.contains("collides case-insensitively")
    ));
    assert!(matches!(
        ToolPolicyMap::from_json_str(
            r#"{
                "tools": {
                    "deploy": {
                        "action": "infra.deploy",
                        "resource_kind": "host",
                        "resource_id_arg": "ho\u017ft"
                    }
                }
            }"#,
        ),
        Err(MappingError::InvalidPolicy(ref msg)) if msg.contains("must be ASCII")
    ));
    assert!(matches!(
        ToolPolicyMap::from_json_str(
            r#"{
                "tools": {
                    "pay": {
                        "action": "finance.pay",
                        "resource_kind": "account",
                        "static_resource_id": "acct-1",
                        "arg_facts": {
                            "amount_u\u017fd": { "field": "resource.amount", "type": "decimal" }
                        }
                    }
                }
            }"#,
        ),
        Err(MappingError::InvalidPolicy(ref msg)) if msg.contains("must be ASCII")
    ));
    assert!(ToolPolicyMap::from_json_str(
        r#"{
            "tools": {
                "merge_pr": {
                    "action": "git.pr.merge",
                    "resource_kind": "repo",
                    "resource_id_arg": "repo",
                    "arg_facts": {
                        "repo": { "field": "resource.repo", "type": "str" }
                    }
                }
            }
        }"#,
    )
    .is_ok());
}

#[test]
fn round6_tools_list_rejects_smuggled_result_and_tool_keys_with_32603() {
    let malicious_responses = [
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[],"tool\u017f":[{"name":"delete_repo"}]}}"#,
            "unexpected upstream tools/list result key",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[],"TOOLS":[{"name":"delete_repo"}]}}"#,
            "unexpected upstream tools/list result key 'TOOLS'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"merge_pr","NAME":"delete_repo"}]}}"#,
            "collides case-insensitively with 'name'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"NAME":"delete_repo"}]}}"#,
            "collides case-insensitively with 'name'",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"merge_pr","na\u017fe":"delete_repo"}]}}"#,
            "non-ASCII key",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"merge_pr","title":"ok","TITLE":"delete_repo"}]}}"#,
            "collides case-insensitively",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":["delete_repo"]}}"#,
            "expected JSON object",
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":[]}"#,
            "missing result object",
        ),
    ];

    for (raw_resp, expected_substr) in malicious_responses {
        let (mut proxy, _agent_kp) = make_proxy();
        let client_in =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#.to_string() + "\n";
        let (up_in_w, mut up_in_r) = mem_pipe();
        let (mut up_out_w, up_out_r) = mem_pipe();
        let resp_owned = raw_resp.to_string();
        let upstream = thread::spawn(move || {
            let mut req = String::new();
            up_in_r.read_line(&mut req).unwrap();
            writeln!(up_out_w, "{resp_owned}").unwrap();
        });

        let mut client_out = Vec::new();
        let res = proxy.run(
            BufReader::new(Cursor::new(client_in.into_bytes())),
            &mut client_out,
            up_in_w,
            up_out_r,
        );
        upstream.join().unwrap();
        assert!(
            matches!(res, Err(ProxyError::UpstreamProtocol(ref msg)) if msg.contains(expected_substr)),
            "expected UpstreamProtocol containing {expected_substr:?} for {raw_resp}, got {res:?}"
        );
        let out_str = String::from_utf8(client_out).unwrap();
        assert!(
            !out_str.contains("delete_repo"),
            "malicious tools/list leaked delete_repo for {raw_resp}: {out_str}"
        );
        let parsed: Value = serde_json::from_str(out_str.trim_end()).unwrap();
        assert_eq!(parsed["id"], json!(1));
        assert_eq!(parsed["error"]["code"], json!(-32603));
    }
}

#[test]
fn round6_tools_list_accepts_valid_next_cursor_and_meta() {
    let (mut proxy, _agent_kp) = make_proxy();
    let client_in =
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#.to_string() + "\n";
    let (up_in_w, mut up_in_r) = mem_pipe();
    let (mut up_out_w, up_out_r) = mem_pipe();
    let upstream = thread::spawn(move || {
        let mut req = String::new();
        up_in_r.read_line(&mut req).unwrap();
        writeln!(
            up_out_w,
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{{"name":"merge_pr","description":"Merge"}},{{"name":"delete_repo"}}],"nextCursor":"cursor-2","_meta":{{"page":1}}}}}}"#
        )
        .unwrap();
    });
    let mut client_out = Vec::new();
    proxy
        .run(
            BufReader::new(Cursor::new(client_in.into_bytes())),
            &mut client_out,
            up_in_w,
            up_out_r,
        )
        .expect("valid tools/list with nextCursor and _meta must succeed");
    upstream.join().unwrap();
    let parsed: Value =
        serde_json::from_str(String::from_utf8(client_out).unwrap().trim_end()).unwrap();
    assert_eq!(parsed["result"]["nextCursor"], json!("cursor-2"));
    assert_eq!(parsed["result"]["_meta"]["page"], json!(1));
    let tools = parsed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], json!("merge_pr"));
}

#[test]
fn round6_notifications_cancelled_rejects_smuggled_and_unknown_params_keys() {
    use std::time::Duration;

    let (mut proxy, _agent_kp) = make_proxy();
    let (mut client_in_w, client_in_r) = mem_pipe();
    let (mut client_out_w, mut client_out_r) = mem_pipe();
    let (up_in_tx, up_in_rx) = mpsc::channel::<Vec<u8>>();
    let up_in_w = PipeWriter(up_in_tx);
    let (mut up_out_w, up_out_r) = mem_pipe();

    let proxy_thread =
        thread::spawn(move || proxy.run(client_in_r, &mut client_out_w, up_in_w, up_out_r));

    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
    let f1 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f1.trim_end()).unwrap()["id"],
        json!(1)
    );

    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":1,"REQUESTID":99}}}}"#
    )
    .unwrap();
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":1,"reque\u017ftId":99}}}}"#
    )
    .unwrap();
    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":1,"extra":true}}}}"#
    )
    .unwrap();
    writeln!(client_in_w, r#"{{"jsonrpc":"2.0","id":2,"method":"ping"}}"#).unwrap();

    assert!(
        up_in_rx.recv_timeout(Duration::from_millis(80)).is_err(),
        "smuggled notifications/cancelled must be dropped without cancelling active id: 1 or forwarding upstream"
    );

    writeln!(
        up_out_w,
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"pong":1}}}}"#
    )
    .unwrap();
    let mut resp1 = String::new();
    client_out_r.read_line(&mut resp1).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(resp1.trim_end()).unwrap()["id"],
        json!(1)
    );

    let f2 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(f2.trim_end()).unwrap()["id"],
        json!(2)
    );

    writeln!(
        client_in_w,
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":2,"reason":"user abort","_meta":{{"trace":"t1"}}}}}}"#
    )
    .unwrap();
    let f3 = String::from_utf8(up_in_rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let p3: Value = serde_json::from_str(f3.trim_end()).unwrap();
    assert_eq!(p3["method"], json!("notifications/cancelled"));
    assert_eq!(p3["params"]["requestId"], json!(2));
    assert_eq!(p3["params"]["reason"], json!("user abort"));

    drop(client_in_w);
    drop(up_out_w);
    proxy_thread.join().unwrap().unwrap();
}
