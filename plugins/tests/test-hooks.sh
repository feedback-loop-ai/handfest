#!/usr/bin/env bash
# Deterministic, zero-network end-to-end tests for plugins/claude-code/hooks/pre-tool-use.sh
# and syntax/invariant checks for all declarative plugin configuration examples.
# Requires: bash, python3 (3.11+, standard library including tomllib).

set -euo pipefail
unset HANDFEST_ALLOW_CREATE_LEDGER

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

assert_strict_rfc8259_json_line() {
  local label="$1" file_path="$2" expr="$3"
  python3 -I - "$label" "$file_path" "$expr" <<'PY_STRICT'
import json, re, sys, unicodedata
label, file_path, expr = sys.argv[1], sys.argv[2], sys.argv[3]
raw_bytes = open(file_path, "rb").read()
try:
    text = raw_bytes.decode("utf-8", errors="strict")
except UnicodeDecodeError as exc:
    sys.stderr.write(f"FAIL [{label}]: not valid UTF-8: {exc}\n")
    sys.exit(1)
lines = text.splitlines()
if len(lines) != 1:
    sys.stderr.write(f"FAIL [{label}]: expected single JSON line, got {len(lines)} lines:\n{text!r}\n")
    sys.exit(1)
if re.search(r"\\u[dD][89a-fA-F][0-9a-fA-F]{2}", lines[0]):
    sys.stderr.write(f"FAIL [{label}]: escaped lone surrogate in JSON text: {lines[0]!r}\n")
    sys.exit(1)
try:
    data = json.loads(lines[0])
except Exception as exc:
    sys.stderr.write(f"FAIL [{label}]: invalid JSON: {exc}\nraw: {lines[0]}\n")
    sys.exit(1)
stack = [data]
while stack:
    cur = stack.pop()
    if isinstance(cur, str):
        if any(unicodedata.category(c) == "Cs" for c in cur):
            sys.stderr.write(f"FAIL [{label}]: lone surrogate found in decoded JSON string\n")
            sys.exit(1)
    elif isinstance(cur, dict):
        for k, v in cur.items():
            stack.append(k)
            stack.append(v)
    elif isinstance(cur, list):
        stack.extend(cur)
if not eval(expr, {"__builtins__": {"isinstance": isinstance, "str": str, "int": int, "bool": bool, "len": len}}, {"d": data}):
    sys.stderr.write(f"FAIL [{label}]: assertion failed: {expr}\ndata: {data}\n")
    sys.exit(1)
PY_STRICT
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

# Test 1: Permitted call #1 via pre-tool-use.sh (initial ledger bootstrap) -> exit 0 + Permit receipt
HANDFEST_ALLOW_CREATE_LEDGER=1 run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10}}'
assert_eq "permit-1 rc" "$HOOK_RC" "0"
assert_json "permit-1 stdout" "$HOOK_OUT" "d['verdict'] == 'permit' and d['hookSpecificOutput']['permissionDecision'] == 'allow' and isinstance(d['receipt_hash'], str) and d['receipt_hash'].startswith('sha256:')"
pass "Permitted call #1 exited 0 and recorded Permit receipt"

# Test 2: Out-of-scope resource -> exit 2 + mandate_denied + Deny receipt
run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"secret-repo","pullNumber":10}}'
assert_eq "out-of-scope repo rc" "$HOOK_RC" "2"
assert_json "out-of-scope repo stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and d['hookSpecificOutput']['permissionDecision'] == 'deny' and isinstance(d.get('receipt_hash'), str) and d['receipt_hash'].startswith('sha256:')"
pass "Out-of-scope resource failed closed (exit 2) and recorded Deny receipt"

# Test 3: Out-of-scope predicate (pullNumber: 0 violates resource.pr >= 1) -> exit 2 + mandate_denied
run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":0}}'
assert_eq "out-of-scope predicate rc" "$HOOK_RC" "2"
assert_json "out-of-scope predicate stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"
pass "Predicate violation (pullNumber=0) failed closed (exit 2)"

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
run_hook '{"tool_name":"merge_pull_request","tool_name":"Bash","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10}}'
assert_eq "dup keys rc" "$HOOK_RC" "2"
assert_json "dup keys stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Duplicate JSON keys in stdin failed closed (exit 2)"

# Test 8: Case-colliding keys in tool_input -> exit 2 + invalid_input
run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","Repo":"evil","pullNumber":10}}'
assert_eq "case-colliding keys rc" "$HOOK_RC" "2"
assert_json "case-colliding keys stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Case-colliding argument keys failed closed (exit 2)"

# Test 9: Type confusion (bool true passed for int pullNumber) -> exit 2 + invalid_argument
run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":true}}'
assert_eq "bool-as-int rc" "$HOOK_RC" "2"
assert_json "bool-as-int stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"
pass "Bool-as-int type confusion failed closed (exit 2)"

# Test 10: Missing required env vars -> each fails closed (exit 2 + missing_config)
VALID_PAYLOAD='{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10}}'
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
        "pullNumber": { "field": "resource.pr", "type": "int" },
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
        "pullNumber": { "field": "resource.pr", "type": "int" }
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
SPOOF_PAYLOAD='{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":11,"fake_time":"2026-11-24T18:30:00Z","claimed_env":"prod"}}'
HOOK_RC=0
rm -f "$CAPTURED_FACTS"
HANDFEST_ALLOW_CREATE_LEDGER=1 HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_LEDGER="$TIME_LEDGER" HANDFEST_CHAIN="$TIME_SIGNED" \
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
run_hook '{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":12}}'
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
HANDFEST_ALLOW_CREATE_LEDGER=1 HANDFEST_LEDGER="$CHAIN_LEDGER" HANDFEST_CHAIN="$ROOT_SIGNED:$LEAF_SIGNED" HANDFEST_ACTOR_KEY="$LEAF_KEY" \
  "$HOOK" <<<'{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":42}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "chain permit rc" "$HOOK_RC" "0"
assert_json "chain permit stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"

HOOK_RC=0
HANDFEST_LEDGER="$CHAIN_LEDGER" HANDFEST_CHAIN="$ROOT_SIGNED:$LEAF_SIGNED" HANDFEST_ACTOR_KEY="$LEAF_KEY" \
  "$HOOK" <<<'{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":42}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "chain quota rc" "$HOOK_RC" "2"
assert_json "chain quota stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"

CHAIN_AUDIT="$("$HANDFEST_BIN" audit --ledger "$CHAIN_LEDGER" --actor-key "$LEAF_KEY")"
assert_json "chain audit" "$CHAIN_AUDIT" "d['status'] == 'ok' and d['verified_receipts'] == 2 and d['track_record']['permits'] == 1 and d['track_record']['denies'] == 1"
pass "Multi-hop delegation chain (root:leaf) enforced narrowed scope, leaf quota, and clean audit"

# Test 18: Validate all declarative example config files parse strictly and uphold security invariants
python3 -I - "$REPO_ROOT" <<'PY_CFG'
import json, os, re, sys
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

# Policy map must match GitHub MCP merge_pull_request schema (owner, repo, pullNumber) and not hardcode dynamic resource.ci_status
pm = loaded["plugins/policy-map.example.json"]
assert "merge_pull_request" in pm["tools"]
mpr = pm["tools"]["merge_pull_request"]
assert mpr.get("resource_id_arg") == "repo"
assert "owner" in mpr.get("arg_facts", {}) and "pullNumber" in mpr.get("arg_facts", {}), (
    "policy-map merge_pull_request must map owner and pullNumber"
)
assert "pull_number" not in mpr.get("arg_facts", {}), "policy-map must use pullNumber, not pull_number"
assert "resource.ci_status" not in mpr.get("static_facts", {}), "policy-map must not hardcode dynamic resource.ci_status"
assert mpr["static_facts"].get("resource.environment") == {"str": "staging"}

root_norm = os.path.normpath(root)
def assert_safe_outside_path(p, loc):
    assert p.startswith("/"), f"{loc} must be an absolute outside-workspace path: {p}"
    assert ".." not in p.split("/"), f"{loc} must not contain '..' traversal: {p}"
    resolved = os.path.normpath(p)
    assert resolved.startswith("/path/to/handfest-config/"), (
        f"{loc} resolved path '{resolved}' must stay under /path/to/handfest-config/"
    )
    assert resolved != root_norm and not resolved.startswith(root_norm + "/"), (
        f"{loc} resolved path '{resolved}' must not point inside workspace '{root_norm}'"
    )

# Claude Code settings.example.json must separate mcpServers into mcp.example.json, use outside-workspace paths,
# and scope PreToolUse matcher to explicit non-MCP tools (Bash, Write, Edit) while NOT matching MCP tools
cc_settings = loaded["plugins/claude-code/settings.example.json"]
assert "mcpServers" not in cc_settings, "mcpServers must live in plugins/claude-code/mcp.example.json"
pre = cc_settings["hooks"]["PreToolUse"]
assert len(pre) >= 1
for entry in pre:
    matcher = entry["matcher"]
    assert matcher != ".*", "PreToolUse matcher must not be wildcard '.*'"
    for expected_tool in ("Bash", "Write", "Edit"):
        assert re.fullmatch(matcher, expected_tool) is not None, (
            f"PreToolUse matcher '{matcher}' must match '{expected_tool}'"
        )
    assert re.search(matcher, "mcp__github-handfest__merge_pull_request") is None, (
        f"PreToolUse matcher '{matcher}' must not match MCP tool mcp__github-handfest__merge_pull_request"
    )
    for h in entry["hooks"]:
        assert_safe_outside_path(h["command"], "settings.example.json hook command")

def assert_all_paths_safe(node, loc):
    if isinstance(node, dict):
        for k, v in node.items():
            assert_all_paths_safe(v, f"{loc}.{k}")
    elif isinstance(node, list):
        for idx, v in enumerate(node):
            assert_all_paths_safe(v, f"{loc}[{idx}]")
    elif isinstance(node, str) and ("/" in node or node.endswith(".sh") or node.endswith(".json") or node.endswith(".sqlite")):
        assert_safe_outside_path(node, loc)

assert_all_paths_safe(cc_settings, "settings.example.json")

def assert_mcp_args_safe(args, loc):
    assert "--" in args, f"{loc} must separate upstream server command with '--'"
    proxy_args = args[:args.index("--")]
    path_flags = {"--chain", "--ledger", "--policy-map"}
    seen_flags = set()
    i = 0
    while i < len(proxy_args):
        arg = proxy_args[i]
        assert not arg.startswith("./"), f"{loc} contains relative path {arg}"
        assert ".." not in arg.split("/"), f"{loc} contains '..' traversal in {arg}"
        assert "plugins/policy-map.example.json" not in arg, f"{loc} must not point inside repo plugins/"
        if arg in path_flags:
            seen_flags.add(arg)
            assert i + 1 < len(proxy_args), f"{loc} missing value after {arg}"
            assert_safe_outside_path(proxy_args[i + 1], f"{loc} {arg}")
            i += 2
            continue
        i += 1
    assert seen_flags == path_flags, f"{loc} must include {sorted(path_flags)}, got {sorted(seen_flags)}"

for mcp_rel in ("plugins/claude-code/mcp.example.json", "plugins/dsh/mcp.example.json", "plugins/agy/mcp.example.json"):
    srv = loaded[mcp_rel]["mcpServers"]["github-handfest"]
    assert srv["command"] == "handfest-mcp"
    assert_mcp_args_safe(srv["args"], mcp_rel)

try:
    import tomllib
except ImportError as exc:
    raise SystemExit("FAIL: Python 3.11+ (stdlib tomllib) is required to validate plugins/codex/config.example.toml") from exc

codex_rel = "plugins/codex/config.example.toml"
with open(os.path.join(root, codex_rel), "r", encoding="utf-8") as fh:
    codex_raw = fh.read()
assert "./plugins/" not in codex_raw, f"{codex_rel} must not use workspace-relative ./plugins/ paths"
cfg = tomllib.loads(codex_raw)
assert "mcp_servers" in cfg and "github_handfest" in cfg["mcp_servers"]
assert cfg["mcp_servers"]["github_handfest"].get("command") == "handfest-mcp", (
    f"{codex_rel} command must be 'handfest-mcp'"
)
assert_mcp_args_safe(cfg["mcp_servers"]["github_handfest"]["args"], codex_rel)
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
LIMIT 40.00 USD sum(resource.amount)
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
HANDFEST_ALLOW_CREATE_LEDGER=1 HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":15}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal int-15 permit rc" "$HOOK_RC" "0"
assert_json "decimal int-15 stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"
assert_json "decimal int-15 formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '15.0'}"

# Zero, trailing zeros up to scale 28 in strings, bare JSON number 1. + 127 zeros, scale 28, and mixed "12.34"
MAX_SCALE_ZEROS="$(python3 -I -c 'print("1." + "0" * 28)')"
OVER_SCALE_ONE_ZEROS="$(python3 -I -c 'print("1." + "0" * 29)')"
OVER_SCALE_ZERO_ZEROS="$(python3 -I -c 'print("0." + "0" * 29)')"
LONG_ZEROS="$(python3 -I -c 'print("1." + "0" * 127)')"
for amt_json in '0' '"1.0000000000000000000"' '"0.0000000000000000000000000001"' "\"$MAX_SCALE_ZEROS\"" "$LONG_ZEROS"; do
  HOOK_RC=0
  rm -f "$CAPTURED_FACTS"
  HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
    "$HOOK" <<<"{\"tool_name\":\"charge_card\",\"tool_input\":{\"currency\":\"USD\",\"approved\":true,\"scheduled_at\":\"2026-11-24T18:30:00Z\",\"amount\":$amt_json}}" \
    >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "decimal norm $amt_json rc" "$HOOK_RC" "0"
  assert_json "decimal norm $amt_json stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"
  if [[ "$amt_json" == "0" ]]; then
    assert_json "decimal zero formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '0.0'}"
  elif [[ "$amt_json" == '"1.0000000000000000000"' ]]; then
    assert_json "decimal trailing zeros formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '1.0'}"
  elif [[ "$amt_json" == '"0.0000000000000000000000000001"' ]]; then
    assert_json "decimal scale 28 formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '0.0000000000000000000000000001'}"
  elif [[ "$amt_json" == "\"$MAX_SCALE_ZEROS\"" || "$amt_json" == "$LONG_ZEROS" ]]; then
    assert_json "decimal trailing zeros formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '1.0'}"
  fi
done

# Mixed integer+fraction decimal ("12.34") preserved verbatim and permitted (cumulative 30.3400... <= 40.00)
HOOK_RC=0
rm -f "$CAPTURED_FACTS"
HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":"12.34"}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal mixed 12.34 rc" "$HOOK_RC" "0"
assert_json "decimal mixed 12.34 stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"
assert_json "decimal mixed 12.34 formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '12.34'}"

# Bare JSON scientific notation 1.5e1 (15.0) pushes cumulative 30.34... + 15.0 > 40.00 USD -> mandate_denied
HOOK_RC=0
rm -f "$CAPTURED_FACTS"
HANDFEST_BIN="$CAPTURE_SHIM" HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":1.5e1}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal bare sci quota rc" "$HOOK_RC" "2"
assert_json "decimal bare sci quota stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"
assert_json "decimal bare sci formatted" "$(cat "$CAPTURED_FACTS")" "d['resource.amount'] == {'decimal': '15.0'}"

# Bare JSON scientific over-scale decimal 1e-29 must deny with invalid_argument BEFORE invoking handfest check
NO_CALL_SHIM="$TMP_DIR/no-call-handfest.sh"
NO_CALL_MARKER="$TMP_DIR/no-call-invoked"
cat <<SHIM_EOF >"$NO_CALL_SHIM"
#!/usr/bin/env bash
touch "$NO_CALL_MARKER"
exit 99
SHIM_EOF
chmod +x "$NO_CALL_SHIM"
rm -f "$NO_CALL_MARKER"
HOOK_RC=0
HANDFEST_BIN="$NO_CALL_SHIM" HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":1e-29}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal bare sci over-scale 1e-29 rc" "$HOOK_RC" "2"
assert_json "decimal bare sci over-scale 1e-29 stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"
assert_eq "decimal bare sci over-scale 1e-29 handfest not invoked" "$([[ -e "$NO_CALL_MARKER" ]] && echo called || echo not-called)" "not-called"

# Reject integer-like typed decimal strings without '.', leading-zero decimals ("00.5"), negative zero (-0.0, -0.00, -0, -0e0), quoted scientific notation "1.5e1", pathological exponents, raw fractional scale > 28, i128::MAX+1, and i128::MIN-1
for bad_amt in '"1"' '"-1"' '"0"' '"00.5"' '"-00.5"' '"01.5"' '"-0.0"' '"-0.00"' '-0.0' '-0.00' '-0' '-0e0' '"1.5e1"' '1e1000000' '"1e1000000"' '"0.00000000000000000000000000001"' "\"$OVER_SCALE_ONE_ZEROS\"" "\"$OVER_SCALE_ZERO_ZEROS\"" "\"$LONG_ZEROS\"" '"170141183460469231731687303715884105728.0"' '"-170141183460469231731687303715884105729.0"'; do
  HOOK_RC=0
  HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
    "$HOOK" <<<"{\"tool_name\":\"charge_card\",\"tool_input\":{\"currency\":\"USD\",\"approved\":true,\"scheduled_at\":\"2026-11-24T18:30:00Z\",\"amount\":$bad_amt}}" \
    >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "bad decimal $bad_amt rc" "$HOOK_RC" "2"
  assert_json "bad decimal $bad_amt stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"
done

# Reject negative zero in static_facts {"decimal": "-0.0"} and integer tool argument -0
NEG_ZERO_MAP="$TMP_DIR/neg-zero-map.json"
cat <<'NEG_ZERO_MAP_EOF' >"$NEG_ZERO_MAP"
{
  "tools": {
    "charge_card": {
      "action": "billing.charge",
      "resource_kind": "account",
      "static_resource_id": "acct-prod",
      "static_facts": {
        "resource.amount": { "decimal": "-0.0" }
      }
    }
  }
}
NEG_ZERO_MAP_EOF
HOOK_RC=0
HANDFEST_POLICY_MAP="$NEG_ZERO_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "static_facts negative zero decimal rc" "$HOOK_RC" "2"
assert_json "static_facts negative zero decimal stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_policy_map' and 'negative zero' in d['reason']"

run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":-0}}'
assert_eq "negative zero int arg rc" "$HOOK_RC" "2"
assert_json "negative zero int arg stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument' and 'negative zero' in d['reason']"
pass "static_resource_id + PascalCase types + canonical decimal normalization, no-negative-zero, scale<=28, and i128 bounds verified"

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
cat <<'FAKE_DENY_EOF' >"$FAKE_BIN"
#!/usr/bin/env bash
printf '%s
' '{"verdict":"deny","reason":"spoofed-hash-deny","receipt_hash":"garbage"}'
exit 1
FAKE_DENY_EOF
chmod +x "$FAKE_BIN"
HOOK_RC=0
HANDFEST_BIN="$FAKE_BIN" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "non-zero deny garbage receipt_hash rc" "$HOOK_RC" "2"
assert_json "non-zero deny garbage receipt_hash omitted" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and 'receipt_hash' not in d"
pass "Defense-in-depth rejected exit-0 non-Permit/malformed receipt_hash and stripped garbage receipt_hash on non-zero deny"

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

# Arabic-Indic Unicode year digits in timestamp (٢٠٢٦-11-24T18:30:00Z)
HOOK_RC=0
HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED" \
  "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"\u0662\u0660\u0662\u0666-11-24T18:30:00Z","amount":1}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "unicode timestamp rc" "$HOOK_RC" "2"
assert_json "unicode timestamp stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"

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
        "pullNumber": { "field": "resource.pr", "type": "INT" }
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
HANDFEST_ALLOW_CREATE_LEDGER=1 HANDFEST_LEDGER="$HYPHEN_LEDGER" HANDFEST_CHAIN="$HYPHEN_SIGNED" \
  "$HOOK" <<<'{"hook_event_name":"PreToolUse","tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"-repo","pullNumber":1}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "hyphen resource_id rc" "$HOOK_RC" "0"
assert_json "hyphen resource_id stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit' and d['receipt_hash'].startswith('sha256:')"
pass "Hyphen-prefixed resource_id ('-repo') permitted cleanly via --flag=value argv"

# Test 24: stderr write failure (ENOSPC via /dev/full) deterministically exits 2 (never 1)
HOOK_RC=0
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | "$HOOK" >/dev/null 2>/dev/full || HOOK_RC=$?
assert_eq "stderr /dev/full unmapped tool rc" "$HOOK_RC" "2"

EMPTY_BIN="$TMP_DIR/empty-bin"
mkdir -p "$EMPTY_BIN"
HOOK_RC=0
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}' \
  | env PATH="$EMPTY_BIN" "$(command -v bash)" "$HOOK" >/dev/null 2>/dev/full || HOOK_RC=$?
assert_eq "stderr /dev/full missing python3 rc" "$HOOK_RC" "2"

# Execute the embedded Python directly via python3 -I (without bash rc->2 wrapper) under
# 2>/dev/full and broken-pipe stderr to prove emit_deny's OSError handler exits 2 directly.
python3 -I - "$HOOK" <<'PY_DIRECT_STDERR'
import os, re, subprocess, sys
hook_path = sys.argv[1]
with open(hook_path, "r", encoding="utf-8") as fh:
    hook_src = fh.read()
m = re.search(r"IFS= read -r -d '' PY_CODE[^\n]*<<'PY'[^\n]*\n(.*?)\nPY\n", hook_src, re.DOTALL)
assert m, "failed to extract embedded PY_CODE from hook"
py_code = m.group(1)
payload = b'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}'

with open("/dev/full", "wb") as devfull:
    p_full = subprocess.run(
        [sys.executable, "-I", "-c", py_code],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=devfull,
    )
assert p_full.returncode == 2, f"direct python3 -I /dev/full expected rc 2, got {p_full.returncode}"
assert p_full.stdout == b"", f"direct python3 -I /dev/full expected empty stdout, got {p_full.stdout!r}"

r, w = os.pipe()
os.close(r)
try:
    p_pipe = subprocess.run(
        [sys.executable, "-I", "-c", py_code],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=w,
    )
finally:
    os.close(w)
assert p_pipe.returncode == 2, f"direct python3 -I broken-pipe stderr expected rc 2, got {p_pipe.returncode}"
assert p_pipe.stdout == b"", f"direct python3 -I broken-pipe stderr expected empty stdout, got {p_pipe.stdout!r}"
PY_DIRECT_STDERR
pass "stderr OSError/ENOSPC (2>/dev/full & broken pipe) exited 2 directly in python3 -I and bash fallback"

# Test 25: Strict UTF-8 decoding, lone UTF-16 surrogates, and recursive nested key checks
# Place raw 0xff inside an otherwise valid permitted payload/policy so errors="replace" would pass instead of denying
HOOK_RC=0
UTF8_LEDGER="$TMP_DIR/utf8-ledger.sqlite"
printf '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10,"note":"bad\xff"}}' \
  | HANDFEST_LEDGER="$UTF8_LEDGER" "$HOOK" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "invalid utf8 stdin rc" "$HOOK_RC" "2"
assert_json "invalid utf8 stdin stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"

BAD_UTF8_MAP="$TMP_DIR/bad-utf8-policy-map.json"
printf '{"tools":{"merge_pull_request":{"action":"git.pr.merge","resource_kind":"repo","static_resource_id":"handfest","static_facts":{"resource.note":{"str":"bad\xff"}}}}}' >"$BAD_UTF8_MAP"
HOOK_RC=0
HANDFEST_LEDGER="$UTF8_LEDGER" HANDFEST_POLICY_MAP="$BAD_UTF8_MAP" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "invalid utf8 policy map rc" "$HOOK_RC" "2"
assert_json "invalid utf8 policy map stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_policy_map'"

# Lone UTF-16 surrogate in tool_name
run_hook '{"tool_name":"merge_\ud800","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10}}'
assert_eq "surrogate tool_name rc" "$HOOK_RC" "2"
assert_json "surrogate tool_name stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"

# Lone UTF-16 surrogate in tool_input (both mapped and unmapped nested string)
run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest\ud800","pullNumber":10}}'
assert_eq "surrogate tool_input mapped rc" "$HOOK_RC" "2"
assert_json "surrogate tool_input mapped stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"

run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10,"extra":["ok","bad\ud800"]}}'
assert_eq "surrogate tool_input nested rc" "$HOOK_RC" "2"
assert_json "surrogate tool_input nested stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"

# Nested case-colliding keys and nested non-ASCII key inside array
run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10,"extra":{"force":false,"Force":true}}}'
assert_eq "nested case collision rc" "$HOOK_RC" "2"
assert_json "nested case collision stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"

run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10,"items":[{"caf\u00e9":1}]}}'
assert_eq "nested non-ascii key rc" "$HOOK_RC" "2"
assert_json "nested non-ascii key stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Strict UTF-8, lone UTF-16 surrogates, and recursive nested key checks all failed closed (exit 2)"

# Test 26: Binding boundary tests (i64 overflow, NUL control char, NaN JSON constant)
run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":9223372036854775808}}'
assert_eq "i64 overflow rc" "$HOOK_RC" "2"
assert_json "i64 overflow stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"

run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest\u0000","pullNumber":10}}'
assert_eq "nul control char rc" "$HOOK_RC" "2"
assert_json "nul control char stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"

run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":NaN}}'
assert_eq "NaN json constant rc" "$HOOK_RC" "2"
assert_json "NaN json constant stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "i64 overflow, NUL control char, and NaN JSON constant all failed closed (exit 2)"

# Test 27: Example mandates in claude-code/SKILL.md and agy/SKILL.md align with policy-map.example.json and permit the example call
for skill_rel in "plugins/claude-code/SKILL.md" "plugins/agy/SKILL.md"; do
  SKILL_HF="$TMP_DIR/$(echo "$skill_rel" | tr '/' '_').hf"
  python3 -I - "$REPO_ROOT/$skill_rel" "$HUMAN_KEY" "$AGENT_KEY" "$SKILL_HF" <<'PY_SKILL'
import re, sys
skill_path, human_key, agent_key, out_path = sys.argv[1:]
with open(skill_path, "r", encoding="utf-8") as fh:
    text = fh.read()
m = re.search(r"```text\n(HANDFEST v1\n.*?)```", text, re.DOTALL)
assert m, f"HANDFEST v1 example block not found in {skill_path}"
mandate = (
    m.group(1)
    .replace("<principal>", "valentin")
    .replace("ed25519:<principal-pub-hex>", human_key)
    .replace("<agent-name>", "claude:coder")
    .replace("ed25519:<agent-pub-hex>", agent_key)
)
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(mandate)
PY_SKILL
  "$HANDFEST_BIN" fmt "$SKILL_HF" >"$SKILL_HF.canon"
  SKILL_SIGNED="$SKILL_HF.signed.json"
  "$HANDFEST_BIN" sign --mandate "$SKILL_HF.canon" --key "$HUMAN_KEY_FILE" \
    --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z --out "$SKILL_SIGNED" >/dev/null
  SKILL_LEDGER="$SKILL_HF.ledger.sqlite"
  HOOK_RC=0
  HANDFEST_ALLOW_CREATE_LEDGER=1 HANDFEST_LEDGER="$SKILL_LEDGER" HANDFEST_CHAIN="$SKILL_SIGNED" \
    "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "skill example $skill_rel permit rc" "$HOOK_RC" "0"
  assert_json "skill example $skill_rel permit stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit' and d['receipt_hash'].startswith('sha256:')"
done
pass "Example mandates in claude-code/SKILL.md and agy/SKILL.md aligned with policy-map.example.json and permitted the example call"

# Test 28: Missing/deleted HANDFEST_LEDGER fails closed (missing_ledger) and prevents quota reset
DEL_LEDGER="$TMP_DIR/deleted-ledger.sqlite"
HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "absent ledger rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "absent ledger stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'missing_ledger'"
if [[ -e "$DEL_LEDGER" ]]; then
  echo "FAIL [absent ledger created]: $DEL_LEDGER should not have been created" >&2
  exit 1
fi

HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" HANDFEST_ALLOW_CREATE_LEDGER="yes" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "invalid allow_create_ledger rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "invalid allow_create_ledger stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'missing_config'"

# Exhaust LIMIT 2 calls mandate, delete ledger, re-run -> MUST exit 2 (missing_ledger), NOT reset quota to Permit
HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" HANDFEST_ALLOW_CREATE_LEDGER=1 "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "quota-reset call 1 rc" "$HOOK_RC" "0"
assert_strict_rfc8259_json_line "quota-reset call 1 stdout" "$TMP_DIR/stdout.txt" "d['verdict'] == 'permit'"

HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "quota-reset call 2 rc" "$HOOK_RC" "0"
assert_strict_rfc8259_json_line "quota-reset call 2 stdout" "$TMP_DIR/stdout.txt" "d['verdict'] == 'permit'"

HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "quota-reset call 3 exhausted rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "quota-reset call 3 exhausted stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and 'quota' in d['reason'].lower()"

# (a) Truncating exhausted ledger to 0 bytes must fail closed (gate_error, exit 2) and NOT reset quota or initialize tables
: > "$DEL_LEDGER"
HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "0-byte truncated ledger rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "0-byte truncated ledger stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'gate_error'"
ZERO_SIZE="$(python3 -I -c 'import os, sys; print(os.path.getsize(sys.argv[1]))' "$DEL_LEDGER")"
assert_eq "0-byte ledger remained 0 bytes" "$ZERO_SIZE" "0"

# (b) Replacing exhausted ledger with an empty SQLite DB (valid header, no Handfest tables) must fail closed
#     with gate_error (exit 2) and NOT initialize fresh tables or reset quota
rm -f "$DEL_LEDGER"
python3 -I -c 'import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); c.execute("VACUUM"); c.close()' "$DEL_LEDGER"
HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "empty-schema sqlite ledger rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "empty-schema sqlite ledger stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'gate_error'"
SCHEMA_COUNT="$(python3 -I -c 'import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); print(c.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]); c.close()' "$DEL_LEDGER")"
assert_eq "empty-schema sqlite remained uninitialized" "$SCHEMA_COUNT" "0"

# (c) Corrupt non-SQLite ledger must fail closed (gate_error, exit 2) without modifying the file
rm -f "$DEL_LEDGER"
python3 -I -c 'import pathlib, sys; pathlib.Path(sys.argv[1]).write_bytes(b"X" * 256)' "$DEL_LEDGER"
HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "corrupt ledger rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "corrupt ledger stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'gate_error'"
CORRUPT_OK="$(python3 -I -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).read_bytes() == b"X" * 256)' "$DEL_LEDGER")"
assert_eq "corrupt ledger untouched" "$CORRUPT_OK" "True"

# (d) Deleting ledger must fail closed (missing_ledger, exit 2) and NOT recreate it
rm -f "$DEL_LEDGER"
HOOK_RC=0
HANDFEST_LEDGER="$DEL_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "deleted ledger re-run rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "deleted ledger re-run stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'missing_ledger'"
if [[ -e "$DEL_LEDGER" ]]; then
  echo "FAIL [deleted ledger recreated]: $DEL_LEDGER must not be recreated after deletion" >&2
  exit 1
fi

# (e) Hook-to-CLI --require-existing-ledger TOCTOU boundary: unlink ledger AFTER pre-tool-use.sh
#     passes its os.stat precheck and BEFORE exec'ing the real handfest binary.
TOCTOU_LEDGER="$TMP_DIR/toctou-ledger.sqlite"
HOOK_RC=0
HANDFEST_LEDGER="$TOCTOU_LEDGER" HANDFEST_ALLOW_CREATE_LEDGER=1 "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "toctou setup permit rc" "$HOOK_RC" "0"
TOCTOU_WRAPPER="$TMP_DIR/toctou-unlink-handfest.sh"
cat <<TOCTOU_EOF >"$TOCTOU_WRAPPER"
#!/usr/bin/env bash
set -euo pipefail
rm -f "\$HANDFEST_LEDGER"
exec "$HANDFEST_BIN" "\$@"
TOCTOU_EOF
chmod +x "$TOCTOU_WRAPPER"
HOOK_RC=0
HANDFEST_BIN="$TOCTOU_WRAPPER" HANDFEST_LEDGER="$TOCTOU_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "hook-to-cli toctou rc" "$HOOK_RC" "2"
assert_eq "hook-to-cli toctou stdout empty" "$(cat "$TMP_DIR/stdout.txt")" ""
assert_strict_rfc8259_json_line "hook-to-cli toctou stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'gate_error' and 'missing_ledger' in d['reason']"
if [[ -e "$TOCTOU_LEDGER" ]]; then
  echo "FAIL [toctou ledger recreated]: $TOCTOU_LEDGER must not be recreated by handfest check" >&2
  exit 1
fi
# (f) 2-symlink cycle (ELOOP) must fall through to `handfest check --require-existing-ledger`
#     and fail closed with gate_error (NOT missing_ledger).
LOOP_A="$TMP_DIR/loop_a.sqlite"
LOOP_B="$TMP_DIR/loop_b.sqlite"
ln -s "$LOOP_B" "$LOOP_A"
ln -s "$LOOP_A" "$LOOP_B"
HOOK_RC=0
HANDFEST_LEDGER="$LOOP_A" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "symlink cycle ledger rc" "$HOOK_RC" "2"
assert_eq "symlink cycle ledger stdout empty" "$(cat "$TMP_DIR/stdout.txt")" ""
assert_strict_rfc8259_json_line "symlink cycle ledger stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'gate_error'"
pass "Missing, 0-byte truncated, empty-schema SQLite, deleted, hook-to-CLI TOCTOU, and symlink-cycle HANDFEST_LEDGER all failed closed (exit 2) and blocked quota reset"

# Test 29: Closed stderr pipe (EPIPE), closed fd 2>&-, stdout >/dev/full, and python3-only PATH (no cat)
python3 -I - "$HOOK" "$EMPTY_BIN" "$(command -v bash)" <<'PY_EPIPE'
import os, subprocess, sys
hook, empty_bin, bash_bin = sys.argv[1:]
payload = b'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}'

def run_with_epipe(cmd, env=None):
    r, w = os.pipe()
    os.close(r)
    try:
        proc = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE, stderr=w, env=env)
    finally:
        os.close(w)
    return proc

p1 = run_with_epipe([hook])
assert p1.returncode == 2, f"Python deny EPIPE expected rc 2, got {p1.returncode}"
assert p1.stdout == b"", f"Python deny EPIPE expected empty stdout, got {p1.stdout!r}"

env_no_py = dict(os.environ)
env_no_py["PATH"] = empty_bin
p2 = run_with_epipe([bash_bin, hook], env=env_no_py)
assert p2.returncode == 2, f"Bash fallback EPIPE expected rc 2, got {p2.returncode}"
assert p2.stdout == b"", f"Bash fallback EPIPE expected empty stdout, got {p2.stdout!r}"
PY_EPIPE

HOOK_RC=0
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}' \
  | "$HOOK" >"$TMP_DIR/stdout.txt" 2>&- || HOOK_RC=$?
assert_eq "closed fd 2>&- python deny rc" "$HOOK_RC" "2"
assert_eq "closed fd 2>&- python deny stdout" "$(cat "$TMP_DIR/stdout.txt")" ""

HOOK_RC=0
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}' \
  | env PATH="$EMPTY_BIN" "$(command -v bash)" "$HOOK" >"$TMP_DIR/stdout.txt" 2>&- || HOOK_RC=$?
assert_eq "closed fd 2>&- bash fallback rc" "$HOOK_RC" "2"
assert_eq "closed fd 2>&- bash fallback stdout" "$(cat "$TMP_DIR/stdout.txt")" ""

FULL_LEDGER="$TMP_DIR/stdout-full-ledger.sqlite"
HOOK_RC=0
HANDFEST_LEDGER="$FULL_LEDGER" HANDFEST_ALLOW_CREATE_LEDGER=1 "$HOOK" <<<"$VALID_PAYLOAD" >/dev/full 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "stdout /dev/full permit rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "stdout /dev/full permit stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'internal_error'"

PY_ONLY_BIN="$TMP_DIR/py-only-bin"
mkdir -p "$PY_ONLY_BIN"
ln -s "$(command -v python3)" "$PY_ONLY_BIN/python3"

# Direct execution of "$HOOK" (no explicit bash wrapper) tests the #!/bin/bash shebang under python3-only PATH
HOOK_RC=0
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}' \
  | env PATH="$PY_ONLY_BIN" "$HOOK" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "py-only PATH direct deny rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "py-only PATH direct deny stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'unmapped_tool'"

PY_ONLY_LEDGER="$TMP_DIR/py-only-ledger.sqlite"
HOOK_RC=0
printf '%s' "$VALID_PAYLOAD" \
  | env PATH="$PY_ONLY_BIN" HANDFEST_LEDGER="$PY_ONLY_LEDGER" HANDFEST_ALLOW_CREATE_LEDGER=1 "$HOOK" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "py-only PATH direct permit rc" "$HOOK_RC" "0"
assert_strict_rfc8259_json_line "py-only PATH direct permit stdout" "$TMP_DIR/stdout.txt" "d['verdict'] == 'permit' and d['receipt_hash'].startswith('sha256:')"

# Closed stdout (1>&-) against active LIMIT 2 calls mandate + initialized ledger (1 call used, 1 remaining):
# MUST exit 2 before invoking handfest check so NO quota is consumed (subsequent normal call still succeeds).
FD1_LEDGER="$TMP_DIR/fd1-closed-ledger.sqlite"
HOOK_RC=0
HANDFEST_LEDGER="$FD1_LEDGER" HANDFEST_ALLOW_CREATE_LEDGER=1 "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "fd1-closed setup call 1 rc" "$HOOK_RC" "0"

HOOK_RC=0
HANDFEST_LEDGER="$FD1_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" 1>&- 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "closed stdout 1>&- rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "closed stdout 1>&- stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'internal_error'"

HOOK_RC=0
HANDFEST_LEDGER="$FD1_LEDGER" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "fd1-closed subsequent normal call rc" "$HOOK_RC" "0"
assert_strict_rfc8259_json_line "fd1-closed subsequent normal call stdout" "$TMP_DIR/stdout.txt" "d['verdict'] == 'permit' and d['receipt_hash'].startswith('sha256:')"
FD1_AUDIT="$("$HANDFEST_BIN" audit --ledger "$FD1_LEDGER" --actor-key "$AGENT_KEY")"
assert_json "fd1-closed audit confirms zero quota burned" "$FD1_AUDIT" "d['status'] == 'ok' and d['verified_receipts'] == 2 and d['track_record']['permits'] == 2 and d['track_record']['denies'] == 0"
pass "Closed stderr pipe (EPIPE), closed fd 2>&-, closed stdout 1>&- (zero quota burned), stdout >/dev/full, and direct python3-only PATH all behaved deterministically"

# Test 30: Strict os.environb UTF-8 validation & lone UTF-16 surrogate inside top-level JSON key
HOOK_RC=0
HANDFEST_NOW=$'2026-11-24T18:30:00Z\xff' "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "non-utf8 HANDFEST_NOW rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "non-utf8 HANDFEST_NOW stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'missing_config' and 'UTF-8' in d['reason'] and '\ufffd' not in d['reason']"

for env_var in HANDFEST_POLICY_MAP HANDFEST_LEDGER HANDFEST_CHAIN HANDFEST_ACTOR_KEY HANDFEST_BIN HANDFEST_ALLOW_CREATE_LEDGER; do
  HOOK_RC=0
  env "${env_var}="$'bad\xffval' "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "non-utf8 $env_var rc" "$HOOK_RC" "2"
  assert_strict_rfc8259_json_line "non-utf8 $env_var stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'missing_config' and 'UTF-8' in d['reason'] and '\ufffd' not in d['reason']"
done

run_hook '{"tool_name":"merge_pull_request","tool_input":{"owner":"feedback-loop-ai","repo":"handfest","pullNumber":10},"bad\ud800key":1}'
assert_eq "surrogate top-level key rc" "$HOOK_RC" "2"
assert_strict_rfc8259_json_line "surrogate top-level key stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'invalid_input' and 'key' in d['reason'].lower()"
pass "Non-UTF-8 HANDFEST_* env vars (zero lone surrogates in RFC 8259 JSON) and lone surrogate in top-level JSON key all failed closed (exit 2)"

# Test 31: Hardened PY_CODE heredoc loading (unset + sentinel check + env inheritance + ulimit -f 0)
DENY_PAYLOAD='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"}}'

for poisoned_py in "" "import sys; sys.exit(0)" "import sys; sys.exit(0) # HANDFEST_PY_SENTINEL_EOF"; do
  HOOK_RC=0
  printf '%s' "$DENY_PAYLOAD" \
    | env PY_CODE="$poisoned_py" "$HOOK" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
  assert_eq "inherited PY_CODE deny rc" "$HOOK_RC" "2"
  assert_eq "inherited PY_CODE deny stdout" "$(cat "$TMP_DIR/stdout.txt")" ""
  assert_strict_rfc8259_json_line "inherited PY_CODE deny stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'unmapped_tool'"
done

# Exercise the sentinel failure branch deterministically (even when bash uses pipes for <64KiB heredocs):
# a hook copy whose heredoc misses the sentinel MUST ignore inherited PY_CODE (even containing sentinel)
# and fail closed with exit 2 + internal_error.
BROKEN_HOOK="$TMP_DIR/broken-sentinel-hook.sh"
python3 -I - "$HOOK" "$BROKEN_HOOK" <<'PY_STRIP_SENTINEL'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
marker = "# HANDFEST_PY_SENTINEL_EOF\nPY\n"
assert marker in src, "expected sentinel marker at end of heredoc"
pathlib.Path(sys.argv[2]).write_text(src.replace(marker, "PY\n", 1), encoding="utf-8")
PY_STRIP_SENTINEL
chmod +x "$BROKEN_HOOK"

HOOK_RC=0
printf '%s' "$DENY_PAYLOAD" \
  | env PY_CODE="import sys; sys.exit(0) # HANDFEST_PY_SENTINEL_EOF" "$BROKEN_HOOK" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "missing sentinel with poisoned PY_CODE rc" "$HOOK_RC" "2"
assert_eq "missing sentinel with poisoned PY_CODE stdout" "$(cat "$TMP_DIR/stdout.txt")" ""
assert_strict_rfc8259_json_line "missing sentinel with poisoned PY_CODE stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'internal_error' and 'validator' in d['reason']"

# Also simulate heredoc redirection failure (e.g. ENOSPC/EFBIG/unwritable TMPDIR on bash versions
# that back heredocs with temp files): proves `unset PY_CODE` clears inherited env BEFORE `read`
# so poisoned `PY_CODE` containing the sentinel can NEVER survive a failed redirection.
REDIR_FAIL_HOOK="$TMP_DIR/redir-fail-hook.sh"
python3 -I - "$HOOK" "$REDIR_FAIL_HOOK" "$TMP_DIR/does-not-exist-heredoc" <<'PY_REDIR_FAIL'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = "IFS= read -r -d '' PY_CODE"
end = "# HANDFEST_PY_SENTINEL_EOF\nPY\n"
s_idx = src.index(start)
e_idx = src.index(end, s_idx) + len(end)
mutated = src[:s_idx] + f"IFS= read -r -d '' PY_CODE 2>/dev/null < '{sys.argv[3]}' || true\n" + src[e_idx:]
pathlib.Path(sys.argv[2]).write_text(mutated, encoding="utf-8")
PY_REDIR_FAIL
chmod +x "$REDIR_FAIL_HOOK"

HOOK_RC=0
printf '%s' "$DENY_PAYLOAD" \
  | env PY_CODE="import sys; sys.exit(0) # HANDFEST_PY_SENTINEL_EOF" "$REDIR_FAIL_HOOK" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "redirection failure with poisoned PY_CODE rc" "$HOOK_RC" "2"
assert_eq "redirection failure with poisoned PY_CODE stdout" "$(cat "$TMP_DIR/stdout.txt")" ""
assert_strict_rfc8259_json_line "redirection failure with poisoned PY_CODE stderr" "$TMP_DIR/stderr.txt" "d['verdict'] == 'deny' and d['code'] == 'internal_error' and 'validator' in d['reason']"

# Test inherited PY_CODE, SIGXFSZ trapping (file-backed stderr), and BASH_COMPAT=5.0 heredoc
# temp-file failure (clean single JSON deny on pipe-backed stderr) under RLIMIT_FSIZE=(0, 0).
if ( ulimit -f 0 ) 2>/dev/null; then
  python3 -I - "$HOOK" "$DENY_PAYLOAD" "$EMPTY_BIN" "$TMP_DIR/fsize-stderr.txt" <<'PY_ULIMIT'
import json, os, resource, subprocess, sys
hook, payload, empty_bin, stderr_file = sys.argv[1], sys.argv[2].encode("utf-8"), sys.argv[3], sys.argv[4]

def set_fsize_zero():
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

def set_fsize_zero_and_close_stdout():
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    os.close(1)

for poisoned in ("", "import sys; sys.exit(0)", "import sys; sys.exit(0) # HANDFEST_PY_SENTINEL_EOF"):
    env = dict(os.environ)
    env["PY_CODE"] = poisoned
    proc = subprocess.run(
        [hook],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        preexec_fn=set_fsize_zero,
    )
    assert proc.returncode == 2, f"ulimit -f 0 expected rc 2 for PY_CODE={poisoned!r}, got {proc.returncode}; stderr={proc.stderr!r}"
    assert proc.stdout == b"", f"ulimit -f 0 expected empty stdout, got {proc.stdout!r}"
    text = proc.stderr.decode("utf-8", errors="strict")
    lines = text.splitlines()
    assert len(lines) == 1, f"ulimit -f 0 expected single JSON deny line on stderr, got {proc.stderr!r}"
    data = json.loads(text)
    assert data.get("verdict") == "deny" and data.get("code") in ("unmapped_tool", "internal_error"), (
        f"unexpected deny payload under ulimit -f 0: {data!r}"
    )

# 1. File-backed stderr under RLIMIT_FSIZE=(0, 0) on bash-level fail-closed paths:
#    trap '' XFSZ prevents SIGXFSZ (-25 / 153) termination so the hook still exits 2.
for label, extra_env, preexec in (
    ("PATH=/empty", {"PATH": empty_bin}, set_fsize_zero),
    ("closed stdout 1>&-", {}, set_fsize_zero_and_close_stdout),
    ("BASH_COMPAT=5.0", {"BASH_COMPAT": "5.0"}, set_fsize_zero),
):
    env = dict(os.environ)
    env.update(extra_env)
    with open(stderr_file, "wb") as err_f:
        proc = subprocess.run(
            [hook],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=err_f,
            env=env,
            preexec_fn=preexec,
        )
    assert proc.returncode == 2, (
        f"RLIMIT_FSIZE=0 file-backed stderr ({label}) expected rc 2 (never SIGXFSZ -25), got {proc.returncode}"
    )
    assert proc.stdout == b"", f"RLIMIT_FSIZE=0 ({label}) expected empty stdout, got {proc.stdout!r}"

# 2. BASH_COMPAT=5.0 forces temp-file heredocs on Bash 5.1+: under RLIMIT_FSIZE=(0, 0) with
#    pipe-backed stderr, heredoc creation fails and the ENTIRE stderr must be a single clean
#    structured JSON denial object (zero leading Bash error prose).
for poisoned in (None, "", "import sys; sys.exit(0) # HANDFEST_PY_SENTINEL_EOF"):
    env = dict(os.environ)
    env["BASH_COMPAT"] = "5.0"
    if poisoned is None:
        env.pop("PY_CODE", None)
    else:
        env["PY_CODE"] = poisoned
    proc = subprocess.run(
        [hook],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        preexec_fn=set_fsize_zero,
    )
    assert proc.returncode == 2, (
        f"BASH_COMPAT=5.0 + RLIMIT_FSIZE=0 expected rc 2 for PY_CODE={poisoned!r}, got {proc.returncode}; stderr={proc.stderr!r}"
    )
    assert proc.stdout == b"", f"BASH_COMPAT=5.0 + RLIMIT_FSIZE=0 expected empty stdout, got {proc.stdout!r}"
    text = proc.stderr.decode("utf-8", errors="strict")
    lines = text.splitlines()
    assert len(lines) == 1, (
        f"BASH_COMPAT=5.0 + RLIMIT_FSIZE=0 expected clean single JSON line without Bash prose, got {proc.stderr!r}"
    )
    data = json.loads(text)
    assert (
        data.get("verdict") == "deny"
        and data.get("code") == "internal_error"
        and "validator" in data.get("reason", "")
        and data.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
    ), f"unexpected deny payload under BASH_COMPAT=5.0 + RLIMIT_FSIZE=0: {data!r}"
PY_ULIMIT
fi
pass "PY_CODE heredoc hardening (unset + sentinel + SIGXFSZ trap + BASH_COMPAT=5.0 + ulimit -f 0) failed closed (exit 2)"

echo "ALL $PASS_COUNT HOOK & PLUGIN TESTS PASSED."
