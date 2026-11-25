#!/usr/bin/env bash
# Deterministic, zero-network end-to-end tests for plugins/claude-code/hooks/pre-tool-use.sh
# and syntax/invariant checks for all declarative plugin configuration examples.

set -euo pipefail

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
HOOK="$REPO_ROOT/plugins/claude-code/hooks/pre-tool-use.sh"
HANDFEST_BIN="${HANDFEST_BIN:-$REPO_ROOT/target/debug/handfest}"

if [[ ! -x "$HANDFEST_BIN" ]]; then
  echo "Building handfest binary..."
  (cd "$REPO_ROOT" && cargo build --bin handfest --locked --offline >/dev/null)
fi

if [[ ! -x "$HANDFEST_BIN" ]]; then
  echo "FAIL: handfest binary not executable at $HANDFEST_BIN" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

PASS_COUNT=0
assert_eq() {
  local label="$1" actual="$2" expected="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "FAIL [$label]: expected '$expected', got '$actual'" >&2
    exit 1
  fi
}

assert_json() {
  local label="$1" json_text="$2" expr="$3"
  python3 -I - "$label" "$json_text" "$expr" <<'PY_ASSERT'
import json, sys
label, raw, expr = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    data = json.loads(raw)
except Exception as exc:
    sys.stderr.write(f"FAIL [{label}]: invalid JSON: {exc}\nraw: {raw}\n")
    sys.exit(1)
if not eval(expr, {"__builtins__": {"isinstance": isinstance, "str": str, "int": int, "bool": bool, "len": len}}, {"d": data}):
    sys.stderr.write(f"FAIL [{label}]: assertion failed: {expr}\ndata: {data}\n")
    sys.exit(1)
PY_ASSERT
}

run_hook() {
  local payload="$1"
  HOOK_RC=0
  printf '%s' "$payload" | "$HOOK" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  HOOK_OUT="$(cat "$TMP_DIR/stdout.txt")"
  HOOK_ERR="$(cat "$TMP_DIR/stderr.txt")"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS [$PASS_COUNT]: $1"
}

# 1. Generate real Ed25519 keys for principal (human), agent, and attenuated leaf seat
HUMAN_KEY_FILE="$TMP_DIR/human.key.json"
AGENT_KEY_FILE="$TMP_DIR/agent.key.json"
LEAF_KEY_FILE="$TMP_DIR/leaf.key.json"

HUMAN_KEY="$("$HANDFEST_BIN" keygen --out "$HUMAN_KEY_FILE")"
AGENT_KEY="$("$HANDFEST_BIN" keygen --out "$AGENT_KEY_FILE")"
LEAF_KEY="$("$HANDFEST_BIN" keygen --out "$LEAF_KEY_FILE")"

# 2. Draft, format (WYSIWYS), sign, and verify root mandate (LIMIT 2 calls)
ROOT_HF="$TMP_DIR/root.hf"
cat <<MANDATE_EOF >"$ROOT_HF"
HANDFEST v1
FROM human "valentin" (key: $HUMAN_KEY)
TO agent "claude:coder" (key: $AGENT_KEY)
DELEGATION max 1 hop
ALLOW git.pr.merge
ON repo "handfest*"
WHERE context.time >= 2026-11-24T17:00:00Z
  AND context.time < 2026-11-25T01:00:00Z
  AND resource.owner == "feedback-loop-ai"
  AND resource.environment == "staging"
  AND resource.pr >= 1
LIMIT 2 calls
MANDATE_EOF

"$HANDFEST_BIN" fmt "$ROOT_HF" >"$TMP_DIR/root.canon.hf"
ROOT_SIGNED="$TMP_DIR/root.signed.json"
ROOT_ID="$("$HANDFEST_BIN" sign \
  --mandate "$TMP_DIR/root.canon.hf" \
  --key "$HUMAN_KEY_FILE" \
  --valid-from 2026-11-24T17:00:00Z \
  --valid-until 2026-11-25T01:00:00Z \
  --out "$ROOT_SIGNED")"
"$HANDFEST_BIN" verify "$ROOT_SIGNED" >/dev/null

# Prepare attenuated leaf mandate (DELEGATION max 0 hops, single repo, pr == 42, LIMIT 1 call)
LEAF_HF="$TMP_DIR/leaf.hf"
cat <<MANDATE_EOF >"$LEAF_HF"
HANDFEST v1
PARENT $ROOT_ID
FROM agent "claude:coder" (key: $AGENT_KEY)
TO agent "claude:seat" (key: $LEAF_KEY)
DELEGATION max 0 hops
ALLOW git.pr.merge
ON repo "handfest"
WHERE context.time >= 2026-11-24T18:00:00Z
  AND context.time < 2026-11-24T20:00:00Z
  AND resource.owner == "feedback-loop-ai"
  AND resource.environment == "staging"
  AND resource.pr == 42
LIMIT 1 call
MANDATE_EOF

"$HANDFEST_BIN" fmt "$LEAF_HF" >"$TMP_DIR/leaf.canon.hf"
LEAF_SIGNED="$TMP_DIR/leaf.signed.json"
"$HANDFEST_BIN" sign \
  --mandate "$TMP_DIR/leaf.canon.hf" \
  --key "$AGENT_KEY_FILE" \
  --valid-from 2026-11-24T18:00:00Z \
  --valid-until 2026-11-24T20:00:00Z \
  --out "$LEAF_SIGNED" >/dev/null
"$HANDFEST_BIN" verify "$ROOT_SIGNED" "$LEAF_SIGNED" >/dev/null

export HANDFEST_BIN
export HANDFEST_POLICY_MAP="$REPO_ROOT/plugins/policy-map.example.json"
export HANDFEST_LEDGER="$TMP_DIR/ledger.sqlite"
export HANDFEST_CHAIN="$ROOT_SIGNED"
export HANDFEST_ACTOR_KEY="$AGENT_KEY"
export HANDFEST_NOW="2026-11-24T18:30:00Z"

# Test 1: Permitted call #1 via pre-tool-use.sh -> exit 0 + Permit receipt
run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":10}}'
assert_eq "permit-1 rc" "$HOOK_RC" "0"
assert_json "permit-1 stdout" "$HOOK_OUT" "d['verdict'] == 'permit' and d['hookSpecificOutput']['permissionDecision'] == 'allow' and isinstance(d['receipt_hash'], str) and d['receipt_hash'].startswith('sha256:')"
pass "Permitted call #1 exited 0 and recorded Permit receipt"

# Test 2: Out-of-scope resource -> exit 2 + mandate_denied + Deny receipt
run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"secret-repo","pull_number":10}}'
assert_eq "out-of-scope repo rc" "$HOOK_RC" "2"
assert_json "out-of-scope repo stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and d['hookSpecificOutput']['permissionDecision'] == 'deny' and isinstance(d.get('receipt_hash'), str) and d['receipt_hash'].startswith('sha256:')"
pass "Out-of-scope resource failed closed (exit 2) and recorded Deny receipt"

# Test 3: Out-of-scope predicate (pull_number: 0 violates resource.pr >= 1) -> exit 2 + mandate_denied
run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":0}}'
assert_eq "out-of-scope predicate rc" "$HOOK_RC" "2"
assert_json "out-of-scope predicate stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"
pass "Predicate violation (pull_number=0) failed closed (exit 2)"

# Test 4: Unmapped tool -> exit 2 + unmapped_tool
run_hook '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
assert_eq "unmapped tool rc" "$HOOK_RC" "2"
assert_json "unmapped tool stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'unmapped_tool'"
pass "Unmapped tool failed closed (exit 2)"

# Test 5: Malformed JSON stdin -> exit 2 + invalid_input
run_hook '{not-valid-json'
assert_eq "malformed json rc" "$HOOK_RC" "2"
assert_json "malformed json stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Malformed JSON stdin failed closed (exit 2)"

# Test 6: Empty stdin -> exit 2 + invalid_input
run_hook ''
assert_eq "empty stdin rc" "$HOOK_RC" "2"
assert_json "empty stdin stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Empty stdin failed closed (exit 2)"

# Test 7: Duplicate JSON keys in stdin -> exit 2 + invalid_input
run_hook '{"tool_name":"merge_pull_request","tool_name":"Bash","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":10}}'
assert_eq "dup keys rc" "$HOOK_RC" "2"
assert_json "dup keys stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Duplicate JSON keys in stdin failed closed (exit 2)"

# Test 8: Case-colliding keys in tool_input -> exit 2 + invalid_input
run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","Repo":"evil","pull_number":10}}'
assert_eq "case-colliding keys rc" "$HOOK_RC" "2"
assert_json "case-colliding keys stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Case-colliding argument keys failed closed (exit 2)"

# Test 9: Type confusion (bool true passed for int pull_number) -> exit 2 + invalid_argument
run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":true}}'
assert_eq "bool-as-int rc" "$HOOK_RC" "2"
assert_json "bool-as-int stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"
pass "Bool-as-int type confusion failed closed (exit 2)"

# Test 10: Missing required env vars -> each fails closed (exit 2 + missing_config)
VALID_PAYLOAD='{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":10}}'
for var in HANDFEST_POLICY_MAP HANDFEST_LEDGER HANDFEST_CHAIN HANDFEST_ACTOR_KEY; do
  HOOK_RC=0
  env -u "$var" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "missing $var rc" "$HOOK_RC" "2"
  assert_json "missing $var stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'missing_config'"
done
pass "Missing HANDFEST_POLICY_MAP / LEDGER / CHAIN / ACTOR_KEY all failed closed (exit 2)"

# Test 11: Missing handfest binary -> exit 2 + missing_binary
HOOK_RC=0
HANDFEST_BIN="$TMP_DIR/does-not-exist-handfest" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "missing binary rc" "$HOOK_RC" "2"
assert_json "missing binary stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'missing_binary'"
pass "Missing handfest binary failed closed (exit 2)"

# Test 12: Unknown field in policy map -> exit 2 + invalid_policy_map
BAD_MAP="$TMP_DIR/bad-policy-map.json"
cat <<'BAD_MAP_EOF' >"$BAD_MAP"
{
  "tools": {
    "merge_pull_request": {
      "action": "git.pr.merge",
      "resource_kind": "repo",
      "resource_id_arg": "repo",
      "unexpected_extra_field": true
    }
  }
}
BAD_MAP_EOF
HOOK_RC=0
HANDFEST_POLICY_MAP="$BAD_MAP" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "unknown field policy map rc" "$HOOK_RC" "2"
assert_json "unknown field policy map stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_policy_map'"
pass "Policy map with unknown field failed closed (exit 2)"

# Test 13: Binding clock-spoof defense on an ACTIVE (non-expired) mandate whose WHERE context.time fails
# Envelope is valid 17:00..01:00, WHERE context.time is 18:00..20:00, and host clock is 21:00 (active envelope, outside WHERE).
TIME_HF="$TMP_DIR/time-window.hf"
cat <<MANDATE_EOF >"$TIME_HF"
HANDFEST v1
FROM human "valentin" (key: $HUMAN_KEY)
TO agent "claude:coder" (key: $AGENT_KEY)
DELEGATION max 0 hops
ALLOW git.pr.merge
ON repo "handfest"
WHERE context.time >= 2026-11-24T18:00:00Z
  AND context.time < 2026-11-24T20:00:00Z
  AND resource.owner == "feedback-loop-ai"
  AND resource.environment == "staging"
  AND resource.pr >= 1
LIMIT 5 calls
MANDATE_EOF
"$HANDFEST_BIN" fmt "$TIME_HF" >"$TMP_DIR/time-window.canon.hf"
TIME_SIGNED="$TMP_DIR/time-window.signed.json"
"$HANDFEST_BIN" sign \
  --mandate "$TMP_DIR/time-window.canon.hf" \
  --key "$HUMAN_KEY_FILE" \
  --valid-from 2026-11-24T17:00:00Z \
  --valid-until 2026-11-25T01:00:00Z \
  --out "$TIME_SIGNED" >/dev/null

CAPTURE_SHIM="$TMP_DIR/capture-handfest.sh"
CAPTURED_FACTS="$TMP_DIR/captured-facts.json"
cat <<SHIM_EOF >"$CAPTURE_SHIM"
#!/usr/bin/env bash
for arg in "\$@"; do
  case "\$arg" in
    --facts=*) printf '%s' "\${arg#--facts=}" >"$CAPTURED_FACTS" ;;
  esac
done
exec "$HANDFEST_BIN" "\$@"
SHIM_EOF
chmod +x "$CAPTURE_SHIM"

SPOOF_ARG_MAP="$TMP_DIR/spoof-arg-policy-map.json"
cat <<'SPOOF_MAP_EOF' >"$SPOOF_ARG_MAP"
{
  "tools": {
    "merge_pull_request": {
      "action": "git.pr.merge",
      "resource_kind": "repo",
      "resource_id_arg": "repo",
      "arg_facts": {
        "owner": { "field": "resource.owner", "type": "str" },
        "pull_number": { "field": "resource.pr", "type": "int" },
        "fake_time": { "field": "context.time", "type": "timestamp" },
        "claimed_env": { "field": "resource.environment", "type": "str" }
      },
      "static_facts": {
        "resource.environment": { "str": "staging" }
      }
    }
  }
}
SPOOF_MAP_EOF

SPOOF_STATIC_MAP="$TMP_DIR/spoof-static-policy-map.json"
cat <<'SPOOF_STATIC_EOF' >"$SPOOF_STATIC_MAP"
{
  "tools": {
    "merge_pull_request": {
      "action": "git.pr.merge",
      "resource_kind": "repo",
      "resource_id_arg": "repo",
      "arg_facts": {
        "owner": { "field": "resource.owner", "type": "str" },
        "pull_number": { "field": "resource.pr", "type": "int" }
      },
      "static_facts": {
        "resource.environment": { "str": "staging" },
        "context.time": { "timestamp": "2026-11-24T18:30:00Z" }
      }
    }
  }
}
SPOOF_STATIC_EOF

TIME_LEDGER="$TMP_DIR/time-ledger.sqlite"
SPOOF_PAYLOAD='{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":11,"fake_time":"2026-11-24T18:30:00Z","claimed_env":"prod"}}'
HOOK_RC=0
rm -f "$CAPTURED_FACTS"
HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_LEDGER="$TIME_LEDGER" HANDFEST_CHAIN="$TIME_SIGNED" \
  HANDFEST_POLICY_MAP="$SPOOF_ARG_MAP" HANDFEST_NOW="2026-11-24T21:00:00Z" \
  "$HOOK" <<<"$SPOOF_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "clock spoof arg rc" "$HOOK_RC" "2"
assert_json "clock spoof arg stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and 'context.time' in d['reason']"
assert_json "clock spoof arg stripped" "$(cat "$CAPTURED_FACTS")" "'context.time' not in d"

HOOK_RC=0
rm -f "$CAPTURED_FACTS"
HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_LEDGER="$TIME_LEDGER" HANDFEST_CHAIN="$TIME_SIGNED" \
  HANDFEST_POLICY_MAP="$SPOOF_STATIC_MAP" HANDFEST_NOW="2026-11-24T21:00:00Z" \
  "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "clock spoof static rc" "$HOOK_RC" "2"
assert_json "clock spoof static stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and 'context.time' in d['reason']"
assert_json "clock spoof static stripped" "$(cat "$CAPTURED_FACTS")" "'context.time' not in d"
pass "Active-mandate WHERE context.time clock spoof denied and hook stripped context.time from arg_facts & static_facts"

# Test 14: Permitted call #2 (also verifies static_facts overrides claimed_env='prod' -> 'staging') -> exit 0
HOOK_RC=0
HANDFEST_POLICY_MAP="$SPOOF_ARG_MAP" "$HOOK" <<<"$SPOOF_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "permit-2 rc" "$HOOK_RC" "0"
assert_json "permit-2 stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit' and isinstance(d['receipt_hash'], str) and d['receipt_hash'].startswith('sha256:')"
pass "Permitted call #2 exited 0 (and operator static_facts overrode argument fact)"

# Test 15: 3rd permitted call fails closed on quota exhaustion (LIMIT 2 calls) -> exit 2
run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":12}}'
assert_eq "quota-exhausted rc" "$HOOK_RC" "2"
assert_json "quota-exhausted stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and 'quota' in d['reason'].lower()"
pass "3rd call failed closed on quota exhaustion (LIMIT 2 calls)"

# Test 16: handfest audit verifies the ledger hash chain cleanly (exit 0)
AUDIT_JSON="$("$HANDFEST_BIN" audit --ledger "$HANDFEST_LEDGER" --actor-key "$AGENT_KEY")"
assert_json "audit output" "$AUDIT_JSON" "d['status'] == 'ok' and d['verified_receipts'] == 5 and d['track_record']['permits'] == 2 and d['track_record']['denies'] == 3"
pass "handfest audit verified all 5 hash-chained receipts (2 permits, 3 denies)"

# Test 17: Multi-hop delegation chain (HANDFEST_CHAIN=root:leaf) narrows scope and enforces leaf quota
CHAIN_LEDGER="$TMP_DIR/chain-ledger.sqlite"
HOOK_RC=0
HANDFEST_LEDGER="$CHAIN_LEDGER" HANDFEST_CHAIN="$ROOT_SIGNED:$LEAF_SIGNED" HANDFEST_ACTOR_KEY="$LEAF_KEY" \
  "$HOOK" <<<'{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":42}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "chain permit rc" "$HOOK_RC" "0"
assert_json "chain permit stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"

HOOK_RC=0
HANDFEST_LEDGER="$CHAIN_LEDGER" HANDFEST_CHAIN="$ROOT_SIGNED:$LEAF_SIGNED" HANDFEST_ACTOR_KEY="$LEAF_KEY" \
  "$HOOK" <<<'{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pull_number":42}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "chain quota rc" "$HOOK_RC" "2"
assert_json "chain quota stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"

CHAIN_AUDIT="$("$HANDFEST_BIN" audit --ledger "$CHAIN_LEDGER" --actor-key "$LEAF_KEY")"
assert_json "chain audit" "$CHAIN_AUDIT" "d['status'] == 'ok' and d['verified_receipts'] == 2 and d['track_record']['permits'] == 1 and d['track_record']['denies'] == 1"
pass "Multi-hop delegation chain (root:leaf) enforced narrowed scope, leaf quota, and clean audit"

# Test 18: Validate all declarative example config files parse strictly and uphold security invariants
python3 -I - "$REPO_ROOT" <<'PY_CFG'
import json, os, sys
root = sys.argv[1]
json_files = [
    "plugins/policy-map.example.json",
    "plugins/claude-code/settings.example.json",
    "plugins/claude-code/mcp.example.json",
    "plugins/dsh/mcp.example.json",
    "plugins/agy/mcp.example.json",
]
def no_dups(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate key {k}")
        obj[k] = v
    return obj

loaded = {}
for rel in json_files:
    with open(os.path.join(root, rel), "r", encoding="utf-8") as fh:
        raw = fh.read()
    assert "./plugins/" not in raw, f"{rel} must not use workspace-relative ./plugins/ paths"
    loaded[rel] = json.loads(raw, object_pairs_hook=no_dups)

# Policy map must not hardcode dynamic resource.ci_status in static_facts
pm = loaded["plugins/policy-map.example.json"]
assert "merge_pull_request" in pm["tools"]
mpr = pm["tools"]["merge_pull_request"]
assert "resource.ci_status" not in mpr.get("static_facts", {}), "policy-map must not hardcode dynamic resource.ci_status"
assert mpr["static_facts"].get("resource.environment") == {"str": "staging"}

# Claude Code settings.example.json must separate mcpServers into mcp.example.json, use outside-workspace paths,
# and scope PreToolUse matcher to explicit non-MCP tools (not '.*')
cc_settings = loaded["plugins/claude-code/settings.example.json"]
assert "mcpServers" not in cc_settings, "mcpServers must live in plugins/claude-code/mcp.example.json"
pre = cc_settings["hooks"]["PreToolUse"]
assert len(pre) >= 1
for entry in pre:
    assert entry["matcher"] != ".*", "PreToolUse matcher must not be wildcard '.*'"
    for h in entry["hooks"]:
        assert h["command"].startswith("/path/to/handfest-config/"), f"hook command must be outside-workspace: {h['command']}"

for mcp_rel in ("plugins/claude-code/mcp.example.json", "plugins/dsh/mcp.example.json", "plugins/agy/mcp.example.json"):
    srv = loaded[mcp_rel]["mcpServers"]["github-handfest"]
    assert srv["command"] == "handfest-mcp"
    for arg in srv["args"]:
        assert not arg.startswith("./"), f"{mcp_rel} contains relative path {arg}"
        assert "plugins/policy-map.example.json" not in arg, f"{mcp_rel} must not point inside repo plugins/"

try:
    import tomllib
except ImportError:
    tomllib = None

if tomllib is not None:
    with open(os.path.join(root, "plugins/codex/config.example.toml"), "rb") as fh:
        cfg = tomllib.load(fh)
    assert "mcp_servers" in cfg and "github_handfest" in cfg["mcp_servers"]
    for arg in cfg["mcp_servers"]["github_handfest"]["args"]:
        assert not arg.startswith("./")
        assert "plugins/policy-map.example.json" not in arg
PY_CFG
pass "All declarative JSON/TOML plugin example configs parsed cleanly and upheld security invariants"

# Test 19: static_resource_id + all scalar types (including PascalCase) + canonical decimal normalization + scale/i128 bounds
PAY_HF="$TMP_DIR/pay.hf"
cat <<MANDATE_EOF >"$PAY_HF"
HANDFEST v1
FROM human "valentin" (key: $HUMAN_KEY)
TO agent "claude:coder" (key: $AGENT_KEY)
DELEGATION max 0 hops
ALLOW billing.charge
ON account "acct-prod"
WHERE context.time >= 2026-11-24T17:00:00Z
  AND context.time < 2026-11-25T01:00:00Z
  AND resource.currency == "USD"
  AND resource.approved == true
  AND resource.scheduled_at >= 2026-11-24T18:00:00Z
  AND resource.amount <= 20.00
LIMIT 25.00 USD sum(resource.amount)
MANDATE_EOF
"$HANDFEST_BIN" fmt "$PAY_HF" >"$TMP_DIR/pay.canon.hf"
PAY_SIGNED="$TMP_DIR/pay.signed.json"
"$HANDFEST_BIN" sign --mandate "$TMP_DIR/pay.canon.hf" --key "$HUMAN_KEY_FILE" --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z --out "$PAY_SIGNED" >/dev/null

PAY_MAP="$TMP_DIR/pay-map.json"
cat <<'PAY_MAP_EOF' >"$PAY_MAP"
{
  "tools": {
    "charge_card": {
      "action": "billing.charge",
      "resource_kind": "account",
      "static_resource_id": "acct-prod",
      "arg_facts": {
        "currency": { "field": "resource.currency", "type": "Str" },
        "approved": { "field": "resource.approved", "type": "Bool" },
        "scheduled_at": { "field": "resource.scheduled_at", "type": "Timestamp" },
        "amount": { "field": "resource.amount", "type": "Decimal" }
      }
    }
  }
}
PAY_MAP_EOF

# Zero-scale JSON integer 15 -> normalized to 15.0 and permitted
PAY_LEDGER="$TMP_DIR/pay-ledger.sqlite"
HOOK_RC=0
rm -f "$CAPTURED_FACTS"
HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":15}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal int-15 permit rc" "$HOOK_RC" "0"
assert_json "decimal int-15 stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"
assert_json "decimal int-15 formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '15.0'}"

# Zero, trailing zeros beyond 18 digits (1.0000000000000000000 -> 1.0), and scale 28 all normalized and permitted
for amt_json in '0' '"1.0000000000000000000"' '"0.0000000000000000000000000001"'; do
  HOOK_RC=0
  HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
    "$HOOK" <<<"{\"tool_name\":\"charge_card\",\"tool_input\":{\"currency\":\"USD\",\"approved\":true,\"scheduled_at\":\"2026-11-24T18:30:00Z\",\"amount\":$amt_json}}" \
    >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "decimal norm $amt_json rc" "$HOOK_RC" "0"
  assert_json "decimal norm $amt_json stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"
done

# Scientific notation "1.5e1" (15.0) pushes cumulative 16.0000000000000000000000000001 + 15.0 > 25.00 USD -> mandate_denied
HOOK_RC=0
rm -f "$CAPTURED_FACTS"
HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":"1.5e1"}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal sci quota rc" "$HOOK_RC" "2"
assert_json "decimal sci quota stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"
assert_json "decimal sci formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '15.0'}"

# Reject pathological exponent, scale 29, i128::MAX+1, and i128::MIN-1
for bad_amt in '"1e1000000"' '"0.00000000000000000000000000001"' '"170141183460469231731687303715884105728"' '"-170141183460469231731687303715884105729"'; do
  HOOK_RC=0
  HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
    "$HOOK" <<<"{\"tool_name\":\"charge_card\",\"tool_input\":{\"currency\":\"USD\",\"approved\":true,\"scheduled_at\":\"2026-11-24T18:30:00Z\",\"amount\":$bad_amt}}" \
    >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "bad decimal $bad_amt rc" "$HOOK_RC" "2"
  assert_json "bad decimal $bad_amt stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"
done
pass "static_resource_id + PascalCase types + canonical decimal normalization, scale<=28, and i128 bounds verified"

# Test 20: Defense-in-depth: broken gate exiting 0 without Permit JSON OR malformed receipt_hash fails closed
FAKE_BIN="$TMP_DIR/fake-handfest"
for fake_out in \
  '{"verdict":"deny","reason":"spoofed-exit-0"}' \
  '{"verdict":"permit","receipt_hash":"garbage"}' \
  '{"verdict":"permit","receipt_hash":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' \
  '{"verdict":"permit","receipt_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000\n"}'; do
  cat <<FAKE_EOF >"$FAKE_BIN"
#!/usr/bin/env bash
printf '%s\n' '$fake_out'
exit 0
FAKE_EOF
  chmod +x "$FAKE_BIN"
  HOOK_RC=0
  HANDFEST_BIN="$FAKE_BIN" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "spoofed exit-0 rc" "$HOOK_RC" "2"
  assert_json "spoofed exit-0 stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_gate_output'"
done
pass "Defense-in-depth rejected exit-0 non-Permit and malformed receipt_hash outputs (exit 2)"

# Test 21: python3 -I isolation blocks malicious ./json.py in CWD and PYTHONPATH
EVIL_CWD="$TMP_DIR/evil-cwd"
mkdir -p "$EVIL_CWD"
cat <<'EVIL_PY' >"$EVIL_CWD/json.py"
import os, sys
sys.stdout.write('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"},"verdict":"permit","receipt_hash":"sha256:' + '0'*64 + '"}\n')
sys.stdout.flush()
os._exit(0)
EVIL_PY
HOOK_RC=0
(cd "$EVIL_CWD" && PYTHONPATH="$EVIL_CWD" "$HOOK" <<<'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}') \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "cwd json.py hijack rc" "$HOOK_RC" "2"
assert_json "cwd json.py hijack stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'unmapped_tool'"
pass "python3 -I isolation blocked malicious ./json.py in CWD and PYTHONPATH (exit 2, unmapped_tool)"

# Test 22: Strict re.ASCII + \Z regexes reject Unicode digits & trailing \n; reject uppercase "INT" type name
# Arabic-Indic Unicode digits "٠.٠١"
HOOK_RC=0
HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":"\u0660.\u0660\u0661"}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "unicode decimal rc" "$HOOK_RC" "2"
assert_json "unicode decimal stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"

# Trailing \n on decimal
HOOK_RC=0
HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":"1.0\n"}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal trailing newline rc" "$HOOK_RC" "2"
assert_json "decimal trailing newline stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"

# Trailing \n on timestamp
HOOK_RC=0
HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z\n","amount":1}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "timestamp trailing newline rc" "$HOOK_RC" "2"
assert_json "timestamp trailing newline stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"

# Trailing \n on identifier in policy map
NL_IDENT_MAP="$TMP_DIR/nl-ident-map.json"
cat <<'NL_MAP_EOF' >"$NL_IDENT_MAP"
{
  "tools": {
    "merge_pull_request": {
      "action": "git.pr.merge\n",
      "resource_kind": "repo",
      "resource_id_arg": "repo"
    }
  }
}
NL_MAP_EOF
HOOK_RC=0
HANDFEST_POLICY_MAP="$NL_IDENT_MAP" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "ident trailing newline rc" "$HOOK_RC" "2"
assert_json "ident trailing newline stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_policy_map'"

# Uppercase "INT" rejected in arg_facts
BAD_TYPE_MAP="$TMP_DIR/bad-type-map.json"
cat <<'BAD_TYPE_EOF' >"$BAD_TYPE_MAP"
{
  "tools": {
    "merge_pull_request": {
      "action": "git.pr.merge",
      "resource_kind": "repo",
      "resource_id_arg": "repo",
      "arg_facts": {
        "pull_number": { "field": "resource.pr", "type": "INT" }
      }
    }
  }
}
BAD_TYPE_EOF
HOOK_RC=0
HANDFEST_POLICY_MAP="$BAD_TYPE_MAP" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "uppercase INT type rc" "$HOOK_RC" "2"
assert_json "uppercase INT type stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_policy_map'"
pass "re.ASCII + \\Z rejected Unicode digits & trailing newlines, and exact type check rejected 'INT'"

# Test 23: Hyphen-prefixed resource_id ("-repo") permitted via --flag=value argv syntax
HYPHEN_HF="$TMP_DIR/hyphen.hf"
cat <<MANDATE_EOF >"$HYPHEN_HF"
HANDFEST v1
FROM human "valentin" (key: $HUMAN_KEY)
TO agent "claude:coder" (key: $AGENT_KEY)
DELEGATION max 0 hops
ALLOW git.pr.merge
ON repo "-repo"
WHERE context.time >= 2026-11-24T17:00:00Z
  AND context.time < 2026-11-25T01:00:00Z
  AND resource.owner == "feedback-loop-ai"
  AND resource.environment == "staging"
  AND resource.pr >= 1
LIMIT 2 calls
MANDATE_EOF
"$HANDFEST_BIN" fmt "$HYPHEN_HF" >"$TMP_DIR/hyphen.canon.hf"
HYPHEN_SIGNED="$TMP_DIR/hyphen.signed.json"
"$HANDFEST_BIN" sign --mandate "$TMP_DIR/hyphen.canon.hf" --key "$HUMAN_KEY_FILE" --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z --out "$HYPHEN_SIGNED" >/dev/null

HYPHEN_LEDGER="$TMP_DIR/hyphen-ledger.sqlite"
HOOK_RC=0
HANDFEST_LEDGER="$HYPHEN_LEDGER" HANDFEST_CHAIN="$HYPHEN_SIGNED" \
  "$HOOK" <<<'{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"-repo","pull_number":1}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "hyphen resource_id rc" "$HOOK_RC" "0"
assert_json "hyphen resource_id stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit' and d['receipt_hash'].startswith('sha256:')"
pass "Hyphen-prefixed resource_id ('-repo') permitted cleanly via --flag=value argv"

echo "ALL $PASS_COUNT HOOK & PLUGIN TESTS PASSED."
