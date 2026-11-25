//! Round 5 regression tests closing case-colliding JSON key smuggling across JSON-RPC 2.0
//! client envelopes, upstream envelopes, `tools/call` params, and `tools/call` arguments.

use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_core::ast::parse_rfc3339_utc;
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
