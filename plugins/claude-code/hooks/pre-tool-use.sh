#!/usr/bin/env bash
# Deterministic, fail-closed Claude Code PreToolUse hook for HANDFEST v1 mandates.
#
# Required env:
#   HANDFEST_POLICY_MAP  ToolPolicyMap JSON path (shared schema with handfest-mcp)
#   HANDFEST_LEDGER      SQLite receipt/quota ledger database path
#   HANDFEST_CHAIN       Colon-separated ordered SignedMandate JSON path(s), root first
#   HANDFEST_ACTOR_KEY   Concrete requesting actor KeyId (e.g. ed25519:<64-hex>)
#
# Optional env:
#   HANDFEST_BIN         Path or command name for `handfest` CLI (default: handfest)
#   HANDFEST_NOW         Fixed RFC 3339 UTC timestamp (defaults to host UTC clock)
#
# Exit codes:
#   0  ONLY when `handfest check` returns Permit with a valid receipt_hash
#   2  All denials, unmapped tools, malformed inputs, and config/runtime errors (fail closed)

set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"handfest hook requires python3 (fail closed)"},"verdict":"deny","code":"missing_dependency","reason":"python3 not found on PATH"}' >&2
  exit 2
fi

PY_CODE="$(cat <<'PY'
import datetime, decimal, json, os, re, shutil, subprocess, sys, unicodedata

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
RFC3339_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$")
DECIMAL_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
DECIMAL_INPUT_RE = re.compile(r"^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$")
I64_MIN, I64_MAX, MAX_DEC_SCALE = -(1 << 63), (1 << 63) - 1, 18
POLICY_KEYS = {"action", "resource_kind", "resource_id_arg", "static_resource_id", "arg_facts", "static_facts"}
FACT_TYPES = {"str", "int", "decimal", "bool", "timestamp"}


class RawNumber(str):
    pass


class HookError(Exception):
    def __init__(self, code: str, reason: str, receipt_hash: str | None = None):
        super().__init__(reason)
        self.code, self.reason, self.receipt_hash = code, reason, receipt_hash


def emit_deny(code: str, reason: str, receipt_hash: str | None = None) -> None:
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"handfest {code}: {reason}",
        },
        "verdict": "deny",
        "code": code,
        "reason": reason,
    }
    if receipt_hash is not None:
        out["receipt_hash"] = receipt_hash
    sys.stderr.write(json.dumps(out, separators=(",", ":")) + "\n")
    sys.stderr.flush()
    sys.exit(2)


def emit_permit(receipt_hash: str) -> None:
    out = {
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        "verdict": "permit",
        "receipt_hash": receipt_hash,
    }
    sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    sys.exit(0)


def is_ident(s: str) -> bool:
    return bool(IDENT_RE.match(s))


def is_dotted_ident(s: str) -> bool:
    return bool(s) and all(is_ident(p) for p in s.split("."))


def has_ctrl(s: str) -> bool:
    return any(unicodedata.category(c) == "Cc" for c in s)


def is_rfc3339_utc(s: str) -> bool:
    m = RFC3339_RE.match(s)
    if not m:
        return False
    y, mo, d, h, mi, sec = (int(g) for g in m.groups())
    try:
        datetime.datetime(2000 if y == 0 else y, mo, d, h, mi, sec, tzinfo=datetime.timezone.utc)
        return True
    except ValueError:
        return False


def parse_strict_json(raw: str, code: str, ctx: str):
    if not raw or not raw.strip():
        raise HookError(code, f"{ctx}: empty JSON input")

    def no_dups(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise HookError(code, f"{ctx}: duplicate JSON key '{k}'")
            obj[k] = v
        return obj

    def no_const(tok: str):
        raise HookError(code, f"{ctx}: unsupported JSON constant '{tok}'")

    try:
        return json.loads(raw, object_pairs_hook=no_dups, parse_constant=no_const,
                          parse_int=RawNumber, parse_float=RawNumber)
    except HookError:
        raise
    except Exception as exc:
        raise HookError(code, f"{ctx}: malformed JSON ({exc})")


def parse_i64(raw: RawNumber, code: str, ctx: str) -> int:
    if any(c in raw for c in (".", "e", "E")):
        raise HookError(code, f"{ctx}: expected 64-bit signed integer")
    try:
        n = int(raw, 10)
    except ValueError:
        raise HookError(code, f"{ctx}: invalid integer '{raw}'")
    if not (I64_MIN <= n <= I64_MAX):
        raise HookError(code, f"{ctx}: integer outside 64-bit signed range")
    return n


def parse_decimal(raw: str, code: str, ctx: str) -> str:
    if len(raw) > 64 or not DECIMAL_INPUT_RE.match(raw):
        raise HookError(code, f"{ctx}: invalid decimal '{raw}'")
    try:
        d = decimal.Decimal(raw)
    except decimal.InvalidOperation:
        raise HookError(code, f"{ctx}: invalid decimal '{raw}'")
    if not d.is_finite() or d.adjusted() > 38 or d.adjusted() < -MAX_DEC_SCALE:
        raise HookError(code, f"{ctx}: decimal out of supported range '{raw}'")
    fixed = format(d, "f")
    if not DECIMAL_RE.match(fixed):
        raise HookError(code, f"{ctx}: invalid decimal '{raw}'")
    if "." in fixed and len(fixed.split(".", 1)[1]) > MAX_DEC_SCALE:
        raise HookError(code, f"{ctx}: decimal scale exceeds {MAX_DEC_SCALE}")
    return fixed


def validate_typed_scalar(field: str, obj, code: str) -> dict:
    if not isinstance(obj, dict) or len(obj) != 1:
        raise HookError(code, f"static fact '{field}': expected single-key typed scalar object")
    tag, val = next(iter(obj.items()))
    t = tag.lower()
    if t == "str":
        if type(val) is not str or has_ctrl(val):
            raise HookError(code, f"static fact '{field}': invalid str value")
        return {"str": val}
    if t == "int":
        if not isinstance(val, RawNumber):
            raise HookError(code, f"static fact '{field}': invalid int value")
        return {"int": parse_i64(val, code, f"static fact '{field}'")}
    if t == "decimal":
        if type(val) is not str:
            raise HookError(code, f"static fact '{field}': decimal value must be a string")
        return {"decimal": parse_decimal(val, code, f"static fact '{field}'")}
    if t == "bool":
        if type(val) is not bool:
            raise HookError(code, f"static fact '{field}': invalid bool value")
        return {"bool": val}
    if t == "timestamp":
        if type(val) is not str or not is_rfc3339_utc(val):
            raise HookError(code, f"static fact '{field}': invalid RFC 3339 UTC timestamp")
        return {"timestamp": val}
    raise HookError(code, f"static fact '{field}': unsupported scalar tag '{tag}'")


def validate_policy(tool: str, pol) -> dict:
    c = "invalid_policy_map"
    if not tool or has_ctrl(tool) or not isinstance(pol, dict):
        raise HookError(c, f"tool '{tool}': invalid policy entry")
    unknown = set(pol.keys()) - POLICY_KEYS
    if unknown:
        raise HookError(c, f"tool '{tool}': unknown policy fields {sorted(unknown)}")
    action, rkind = pol.get("action"), pol.get("resource_kind")
    if type(action) is not str or not is_dotted_ident(action):
        raise HookError(c, f"tool '{tool}': invalid concrete action")
    if type(rkind) is not str or not is_ident(rkind):
        raise HookError(c, f"tool '{tool}': invalid resource_kind")
    res_arg, static_res = pol.get("resource_id_arg"), pol.get("static_resource_id")
    if (res_arg is None) == (static_res is None):
        raise HookError(c, f"tool '{tool}': declare exactly one of resource_id_arg or static_resource_id")
    if res_arg is not None and (type(res_arg) is not str or not res_arg or not res_arg.isascii()):
        raise HookError(c, f"tool '{tool}': invalid resource_id_arg")
    if static_res is not None and (type(static_res) is not str or has_ctrl(static_res)):
        raise HookError(c, f"tool '{tool}': invalid static_resource_id")

    arg_facts_raw = pol.get("arg_facts", {})
    if not isinstance(arg_facts_raw, dict):
        raise HookError(c, f"tool '{tool}': arg_facts must be an object")
    target_fields, folded, arg_facts = set(), {}, {}
    for k, spec in arg_facts_raw.items():
        if not k or not k.isascii():
            raise HookError(c, f"tool '{tool}': arg_facts key must be non-empty ASCII")
        if res_arg is not None and k != res_arg and k.lower() == res_arg.lower():
            raise HookError(c, f"tool '{tool}': arg_facts key '{k}' collides with resource_id_arg")
        low = k.lower()
        if low in folded:
            raise HookError(c, f"tool '{tool}': arg_facts key '{k}' collides with '{folded[low]}'")
        folded[low] = k
        if not isinstance(spec, dict) or set(spec.keys()) != {"field", "type"}:
            raise HookError(c, f"tool '{tool}': invalid fact spec for '{k}'")
        field, ftype = spec["field"], spec["type"]
        if type(field) is not str or not is_dotted_ident(field):
            raise HookError(c, f"tool '{tool}': invalid arg_facts field '{field}'")
        if type(ftype) is not str or ftype.lower() not in FACT_TYPES:
            raise HookError(c, f"tool '{tool}': invalid fact type '{ftype}'")
        if field in target_fields:
            raise HookError(c, f"tool '{tool}': duplicate arg_facts target field '{field}'")
        target_fields.add(field)
        arg_facts[k] = (field, ftype.lower())

    static_raw = pol.get("static_facts", {})
    if not isinstance(static_raw, dict):
        raise HookError(c, f"tool '{tool}': static_facts must be an object")
    static_facts = {}
    for field, typed in static_raw.items():
        if not is_dotted_ident(field):
            raise HookError(c, f"tool '{tool}': invalid static_facts field '{field}'")
        static_facts[field] = validate_typed_scalar(field, typed, c)

    return {
        "action": action, "resource_kind": rkind,
        "resource_id_arg": res_arg, "static_resource_id": static_res,
        "arg_facts": arg_facts, "static_facts": static_facts,
    }


def load_policy_map(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise HookError("invalid_policy_map", f"failed to read policy map '{path}': {exc}")
    parsed = parse_strict_json(raw, "invalid_policy_map", "policy map")
    if not isinstance(parsed, dict) or set(parsed.keys()) != {"tools"} or not isinstance(parsed["tools"], dict):
        raise HookError("invalid_policy_map", "policy map must be a JSON object with only object key 'tools'")
    return {name: validate_policy(name, pol) for name, pol in parsed["tools"].items()}


def parse_arg_scalar(tool: str, arg: str, expected: str, val) -> dict:
    c, ctx = "invalid_argument", f"tool '{tool}': argument '{arg}'"
    if expected == "str":
        if type(val) is not str or has_ctrl(val):
            raise HookError(c, f"{ctx}: expected string without control characters")
        return {"str": val}
    if expected == "bool":
        if type(val) is not bool:
            raise HookError(c, f"{ctx}: expected boolean")
        return {"bool": val}
    if expected == "int":
        if not isinstance(val, RawNumber):
            raise HookError(c, f"{ctx}: expected 64-bit signed integer")
        return {"int": parse_i64(val, c, ctx)}
    if expected == "decimal":
        if isinstance(val, RawNumber) or type(val) is str:
            return {"decimal": parse_decimal(str(val), c, ctx)}
        raise HookError(c, f"{ctx}: expected number or decimal string")
    if expected == "timestamp":
        if type(val) is not str or not is_rfc3339_utc(val):
            raise HookError(c, f"{ctx}: expected RFC 3339 UTC timestamp")
        return {"timestamp": val}
    raise HookError("invalid_policy_map", f"{ctx}: unsupported fact type '{expected}'")


def require_env(name: str) -> str:
    val = os.environ.get(name, "")
    if not val:
        raise HookError("missing_config", f"required environment variable {name} is not set")
    return val


def resolve_bin() -> str:
    raw = os.environ.get("HANDFEST_BIN", "").strip() or "handfest"
    if "/" in raw:
        if os.path.isfile(raw) and os.access(raw, os.X_OK):
            return raw
        raise HookError("missing_binary", f"handfest binary '{raw}' is not executable")
    found = shutil.which(raw)
    if not found:
        raise HookError("missing_binary", f"handfest binary '{raw}' not found on PATH")
    return found


def resolve_chain(raw_chain: str) -> list[str]:
    parts = raw_chain.split(":")
    if not parts or any(not p for p in parts):
        raise HookError("missing_config", "HANDFEST_CHAIN contains an empty path segment")
    for p in parts:
        if not os.path.isfile(p):
            raise HookError("missing_config", f"mandate chain file not found: '{p}'")
    return parts


def resolve_now() -> str:
    override = os.environ.get("HANDFEST_NOW", "")
    if override:
        if not is_rfc3339_utc(override):
            raise HookError("missing_config", f"invalid HANDFEST_NOW '{override}': expected RFC 3339 UTC")
        return override
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stdin() -> tuple[str, dict]:
    payload = parse_strict_json(sys.stdin.read(), "invalid_input", "hook stdin")
    if not isinstance(payload, dict):
        raise HookError("invalid_input", "hook stdin must be a JSON object")
    tool = payload.get("tool_name")
    if type(tool) is not str or not tool or has_ctrl(tool):
        raise HookError("invalid_input", "missing or invalid 'tool_name'")
    if "tool_input" not in payload or not isinstance(payload["tool_input"], dict):
        raise HookError("invalid_input", "missing or non-object 'tool_input'")
    args = payload["tool_input"]
    seen = {}
    for k in args.keys():
        if not k.isascii():
            raise HookError("invalid_input", f"tool '{tool}': argument key '{k}' must be ASCII")
        low = k.lower()
        if low in seen:
            raise HookError("invalid_input", f"tool '{tool}': argument key '{k}' collides with '{seen[low]}'")
        seen[low] = k
    return tool, args


def main() -> None:
    policy_path = require_env("HANDFEST_POLICY_MAP")
    ledger_path = require_env("HANDFEST_LEDGER")
    chain_raw = require_env("HANDFEST_CHAIN")
    actor_key = require_env("HANDFEST_ACTOR_KEY")
    if has_ctrl(actor_key) or any(ch.isspace() for ch in actor_key):
        raise HookError("missing_config", "HANDFEST_ACTOR_KEY contains invalid characters")

    handfest_bin = resolve_bin()
    chain_paths = resolve_chain(chain_raw)
    now_utc = resolve_now()
    policy_map = load_policy_map(policy_path)
    tool_name, tool_input = parse_stdin()

    pol = policy_map.get(tool_name)
    if pol is None:
        raise HookError("unmapped_tool", f"tool '{tool_name}' is not admitted in HANDFEST_POLICY_MAP")

    if pol["static_resource_id"] is not None:
        resource_id = pol["static_resource_id"]
    else:
        res_arg = pol["resource_id_arg"]
        if res_arg not in tool_input:
            raise HookError("invalid_argument", f"tool '{tool_name}': missing resource_id argument '{res_arg}'")
        raw_res = tool_input[res_arg]
        if type(raw_res) is not str or has_ctrl(raw_res):
            raise HookError("invalid_argument", f"tool '{tool_name}': invalid resource_id argument '{res_arg}'")
        resource_id = raw_res

    facts = {}
    for arg_key, (field, ftype) in pol["arg_facts"].items():
        if arg_key not in tool_input:
            raise HookError("invalid_argument", f"tool '{tool_name}': missing required argument '{arg_key}'")
        typed_val = parse_arg_scalar(tool_name, arg_key, ftype, tool_input[arg_key])
        if field != "context.time":
            facts[field] = typed_val

    # Operator-supplied static facts ALWAYS override argument-derived facts.
    # context.time is exclusively sourced from the host clock (--now).
    for field, typed_val in pol["static_facts"].items():
        if field != "context.time":
            facts[field] = typed_val

    cmd = [
        handfest_bin, "check",
        "--ledger", ledger_path,
        "--chain", *chain_paths,
        "--actor-key", actor_key,
        "--action", pol["action"],
        "--resource-kind", pol["resource_kind"],
        "--resource-id", resource_id,
        "--facts", json.dumps(facts, separators=(",", ":")),
        "--now", now_utc,
    ]
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    except OSError as exc:
        raise HookError("gate_error", f"failed to invoke handfest check: {exc}")

    if proc.returncode == 0:
        out = parse_strict_json(proc.stdout, "invalid_gate_output", "handfest check stdout")
        if isinstance(out, dict) and out.get("verdict") == "permit" and type(out.get("receipt_hash")) is str and out["receipt_hash"]:
            emit_permit(out["receipt_hash"])
        raise HookError("invalid_gate_output", "handfest check exited 0 without valid Permit JSON")

    if proc.stdout.strip():
        try:
            out = parse_strict_json(proc.stdout, "gate_error", "handfest check deny stdout")
        except HookError:
            out = None
        if isinstance(out, dict) and out.get("verdict") == "deny":
            reason = out.get("reason")
            reason_str = reason if isinstance(reason, str) else json.dumps(reason, separators=(",", ":"))
            rhash = out.get("receipt_hash") if type(out.get("receipt_hash")) is str else None
            raise HookError("mandate_denied", reason_str, receipt_hash=rhash)

    detail = (proc.stderr or proc.stdout or f"exit status {proc.returncode}").strip()
    raise HookError("gate_error", detail)


try:
    main()
except HookError as err:
    emit_deny(err.code, err.reason, receipt_hash=err.receipt_hash)
except Exception as exc:
    emit_deny("internal_error", f"unexpected hook error: {exc}")
PY
)"

rc=0
python3 -c "$PY_CODE" || rc=$?
if [[ "$rc" -eq 0 ]]; then
  exit 0
fi
if [[ "$rc" -ne 2 ]]; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"handfest hook internal failure (fail closed)"},"verdict":"deny","code":"internal_error","reason":"hook exited unexpectedly"}' >&2
fi
exit 2
