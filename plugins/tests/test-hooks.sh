#!/usr/bin/env bash
# Deterministic, zero-network end-to-end tests for plugins/claude-code/hooks/pre-tool-use.sh
# and syntax checks for all declarative plugin configuration examples.

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
  python3 - "$label" "$json_text" "$expr" <<'PY_ASSERT'
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
ON repo "feedback-loop-ai/*"
WHERE context.time >= 2026-11-24T17:00:00Z
  AND context.time < 2026-11-25T01:00:00Z
  AND resource.author == "valentin"
  AND resource.ci_status == "passing"
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
ON repo "feedback-loop-ai/handfest"
WHERE context.time >= 2026-11-24T18:00:00Z
  AND context.time < 2026-11-24T20:00:00Z
  AND resource.author == "valentin"
  AND resource.ci_status == "passing"
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
run_hook '{"hook_event_name":"PreToolUse","tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":10}}'
assert_eq "permit-1 rc" "$HOOK_RC" "0"
assert_json "permit-1 stdout" "$HOOK_OUT" "d['verdict'] == 'permit' and d['hookSpecificOutput']['permissionDecision'] == 'allow' and isinstance(d['receipt_hash'], str) and d['receipt_hash'].startswith('sha256:')"
pass "Permitted call #1 exited 0 and recorded Permit receipt"

# Test 2: Out-of-scope resource -> exit 2 + mandate_denied + Deny receipt
run_hook '{"hook_event_name":"PreToolUse","tool_name":"github_merge_pr","tool_input":{"repository":"other-org/secret","pr_number":10}}'
assert_eq "out-of-scope repo rc" "$HOOK_RC" "2"
assert_json "out-of-scope repo stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and d['hookSpecificOutput']['permissionDecision'] == 'deny' and isinstance(d.get('receipt_hash'), str) and d['receipt_hash'].startswith('sha256:')"
pass "Out-of-scope resource failed closed (exit 2) and recorded Deny receipt"

# Test 3: Out-of-scope predicate (pr_number: 0 violates resource.pr >= 1) -> exit 2 + mandate_denied
run_hook '{"hook_event_name":"PreToolUse","tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":0}}'
assert_eq "out-of-scope predicate rc" "$HOOK_RC" "2"
assert_json "out-of-scope predicate stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"
pass "Predicate violation (pr_number=0) failed closed (exit 2)"

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
run_hook '{"tool_name":"github_merge_pr","tool_name":"Bash","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":10}}'
assert_eq "dup keys rc" "$HOOK_RC" "2"
assert_json "dup keys stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Duplicate JSON keys in stdin failed closed (exit 2)"

# Test 8: Case-colliding keys in tool_input -> exit 2 + invalid_input
run_hook '{"tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","Repository":"evil/repo","pr_number":10}}'
assert_eq "case-colliding keys rc" "$HOOK_RC" "2"
assert_json "case-colliding keys stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_input'"
pass "Case-colliding argument keys failed closed (exit 2)"

# Test 9: Type confusion (bool true passed for int pr_number) -> exit 2 + invalid_argument
run_hook '{"tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":true}}'
assert_eq "bool-as-int rc" "$HOOK_RC" "2"
assert_json "bool-as-int stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"
pass "Bool-as-int type confusion failed closed (exit 2)"

# Test 10: Missing required env vars -> each fails closed (exit 2 + missing_config)
VALID_PAYLOAD='{"hook_event_name":"PreToolUse","tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":10}}'
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
    "github_merge_pr": {
      "action": "git.pr.merge",
      "resource_kind": "repo",
      "resource_id_arg": "repository",
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

# Test 13: Clock-spoof & static-fact override defense
SPOOF_MAP="$TMP_DIR/spoof-policy-map.json"
cat <<'SPOOF_MAP_EOF' >"$SPOOF_MAP"
{
  "tools": {
    "github_merge_pr": {
      "action": "git.pr.merge",
      "resource_kind": "repo",
      "resource_id_arg": "repository",
      "arg_facts": {
        "pr_number": { "field": "resource.pr", "type": "int" },
        "fake_time": { "field": "context.time", "type": "timestamp" },
        "claimed_author": { "field": "resource.author", "type": "str" }
      },
      "static_facts": {
        "resource.author": { "str": "valentin" },
        "resource.ci_status": { "str": "passing" }
      }
    }
  }
}
SPOOF_MAP_EOF
SPOOF_PAYLOAD='{"tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":11,"fake_time":"2026-11-24T18:30:00Z","claimed_author":"mallory"}}'
HOOK_RC=0
HANDFEST_POLICY_MAP="$SPOOF_MAP" HANDFEST_NOW="2026-11-26T00:00:00Z" "$HOOK" <<<"$SPOOF_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "clock spoof rc" "$HOOK_RC" "2"
assert_json "clock spoof stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"
pass "Model-supplied context.time cannot bypass expired host clock (exit 2)"

# Test 14: Permitted call #2 (also verifies static_facts overrides claimed_author='mallory') -> exit 0
HOOK_RC=0
HANDFEST_POLICY_MAP="$SPOOF_MAP" "$HOOK" <<<"$SPOOF_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "permit-2 rc" "$HOOK_RC" "0"
assert_json "permit-2 stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit' and isinstance(d['receipt_hash'], str) and d['receipt_hash'].startswith('sha256:')"
pass "Permitted call #2 exited 0 (and operator static_facts overrode argument fact)"

# Test 15: 3rd permitted call fails closed on quota exhaustion (LIMIT 2 calls) -> exit 2
run_hook '{"hook_event_name":"PreToolUse","tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":12}}'
assert_eq "quota-exhausted rc" "$HOOK_RC" "2"
assert_json "quota-exhausted stderr" "$HOOK_ERR" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied' and 'quota' in d['reason'].lower()"
pass "3rd call failed closed on quota exhaustion (LIMIT 2 calls)"

# Test 16: handfest audit verifies the ledger hash chain cleanly (exit 0)
AUDIT_JSON="$("$HANDFEST_BIN" audit --ledger "$HANDFEST_LEDGER" --actor-key "$AGENT_KEY")"
assert_json "audit output" "$AUDIT_JSON" "d['status'] == 'ok' and d['verified_receipts'] == 6 and d['track_record']['permits'] == 2 and d['track_record']['denies'] == 4"
pass "handfest audit verified all 6 hash-chained receipts (2 permits, 4 denies)"

# Test 17: Multi-hop delegation chain (HANDFEST_CHAIN=root:leaf) narrows scope and enforces leaf quota
CHAIN_LEDGER="$TMP_DIR/chain-ledger.sqlite"
HOOK_RC=0
HANDFEST_LEDGER="$CHAIN_LEDGER" HANDFEST_CHAIN="$ROOT_SIGNED:$LEAF_SIGNED" HANDFEST_ACTOR_KEY="$LEAF_KEY" \
  "$HOOK" <<<'{"tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":42}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "chain permit rc" "$HOOK_RC" "0"
assert_json "chain permit stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"

HOOK_RC=0
HANDFEST_LEDGER="$CHAIN_LEDGER" HANDFEST_CHAIN="$ROOT_SIGNED:$LEAF_SIGNED" HANDFEST_ACTOR_KEY="$LEAF_KEY" \
  "$HOOK" <<<'{"tool_name":"github_merge_pr","tool_input":{"repository":"feedback-loop-ai/handfest","pr_number":42}}' \
  >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "chain quota rc" "$HOOK_RC" "2"
assert_json "chain quota stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"

CHAIN_AUDIT="$("$HANDFEST_BIN" audit --ledger "$CHAIN_LEDGER" --actor-key "$LEAF_KEY")"
assert_json "chain audit" "$CHAIN_AUDIT" "d['status'] == 'ok' and d['verified_receipts'] == 2 and d['track_record']['permits'] == 1 and d['track_record']['denies'] == 1"
pass "Multi-hop delegation chain (root:leaf) enforced narrowed scope, leaf quota, and clean audit"

# Test 18: Validate all declarative example config files parse strictly
python3 - "$REPO_ROOT" <<'PY_CFG'
import json, os, sys
root = sys.argv[1]
json_files = [
    "plugins/policy-map.example.json",
    "plugins/claude-code/settings.example.json",
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

for rel in json_files:
    with open(os.path.join(root, rel), "r", encoding="utf-8") as fh:
        json.load(fh, object_pairs_hook=no_dups)

try:
    import tomllib
except ImportError:
    tomllib = None

if tomllib is not None:
    with open(os.path.join(root, "plugins/codex/config.example.toml"), "rb") as fh:
        cfg = tomllib.load(fh)
    assert "mcp_servers" in cfg and "github_handfest" in cfg["mcp_servers"]
PY_CFG
pass "All declarative JSON/TOML plugin example configs parsed cleanly"

# Test 19: static_resource_id + all scalar types (str, int, decimal, bool, timestamp) + decimal quota
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
"$HANDFEST_BIN" sign   --mandate "$TMP_DIR/pay.canon.hf"   --key "$HUMAN_KEY_FILE"   --valid-from 2026-11-24T17:00:00Z   --valid-until 2026-11-25T01:00:00Z   --out "$PAY_SIGNED" >/dev/null

PAY_MAP="$TMP_DIR/pay-map.json"
cat <<'PAY_MAP_EOF' >"$PAY_MAP"
{
  "tools": {
    "charge_card": {
      "action": "billing.charge",
      "resource_kind": "account",
      "static_resource_id": "acct-prod",
      "arg_facts": {
        "currency": { "field": "resource.currency", "type": "str" },
        "approved": { "field": "resource.approved", "type": "bool" },
        "scheduled_at": { "field": "resource.scheduled_at", "type": "timestamp" },
        "amount": { "field": "resource.amount", "type": "decimal" }
      }
    }
  }
}
PAY_MAP_EOF

PAY_LEDGER="$TMP_DIR/pay-ledger.sqlite"
HOOK_RC=0
HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED"   "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":15.50}}'   >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal permit rc" "$HOOK_RC" "0"
assert_json "decimal permit stdout" "$(cat "$TMP_DIR/stdout.txt")" "d['verdict'] == 'permit'"

# Second charge (10.00) pushes cumulative 25.50 > 25.00 USD -> fails closed
HOOK_RC=0
HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED"   "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":"10.00"}}'   >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "decimal quota rc" "$HOOK_RC" "2"
assert_json "decimal quota stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'mandate_denied'"

# Pathological exponent decimal fails closed cleanly without OOM
HOOK_RC=0
HANDFEST_POLICY_MAP="$PAY_MAP" HANDFEST_LEDGER="$PAY_LEDGER" HANDFEST_CHAIN="$PAY_SIGNED"   "$HOOK" <<<'{"tool_name":"charge_card","tool_input":{"currency":"USD","approved":true,"scheduled_at":"2026-11-24T18:30:00Z","amount":"1e1000000"}}'   >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "huge exponent rc" "$HOOK_RC" "2"
assert_json "huge exponent stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_argument'"
pass "static_resource_id + lossless decimal/bool/timestamp/str facts & sum quota verified"

# Test 20: Defense-in-depth: broken gate exiting 0 without Permit JSON still fails closed
FAKE_BIN="$TMP_DIR/fake-handfest"
cat <<'FAKE_EOF' >"$FAKE_BIN"
#!/usr/bin/env bash
printf '{"verdict":"deny","reason":"spoofed-exit-0"}
'
exit 0
FAKE_EOF
chmod +x "$FAKE_BIN"
HOOK_RC=0
HANDFEST_BIN="$FAKE_BIN" "$HOOK" <<<"$VALID_PAYLOAD" >"$TMP_DIR/stdout.txt" 2>"$TMP_DIR/stderr.txt" || HOOK_RC=$?
assert_eq "spoofed exit-0 rc" "$HOOK_RC" "2"
assert_json "spoofed exit-0 stderr" "$(cat "$TMP_DIR/stderr.txt")" "d['verdict'] == 'deny' and d['code'] == 'invalid_gate_output'"
pass "Defense-in-depth rejected exit-0 non-Permit gate output (exit 2)"

echo "ALL $PASS_COUNT HOOK & PLUGIN TESTS PASSED."
