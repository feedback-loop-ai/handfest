#!/bin/bash
# Deterministic, fail-closed Claude Code PreToolUse hook for HANDFEST v1 mandates.
#
# Required env:
#   HANDFEST_POLICY_MAP  ToolPolicyMap JSON path (shared schema with handfest-mcp)
#   HANDFEST_LEDGER      SQLite receipt/quota ledger database path
#   HANDFEST_CHAIN       Colon-separated ordered SignedMandate JSON path(s), root first
#   HANDFEST_ACTOR_KEY   Concrete requesting actor KeyId (e.g. ed25519:<64-hex>)
#
# Optional env:
#   HANDFEST_BIN                  Path or command name for `handfest` CLI (default: handfest)
#   HANDFEST_NOW                  Fixed RFC 3339 UTC timestamp (defaults to host UTC clock)
#   HANDFEST_ALLOW_CREATE_LEDGER  Set to "1" only during initial setup to allow creating/initializing a ledger file
#
# Requirements: /bin/bash, python3 (3.10+, standard library only; test suite requires 3.11+)
#
# Exit codes:
#   0  ONLY when `handfest check` returns Permit with a valid sha256 receipt_hash
#   2  All denials, unmapped tools, malformed inputs, and config/runtime errors (fail closed)

trap '' PIPE XFSZ 2>/dev/null || trap '' PIPE
set -euo pipefail

if ! { : 3>&1; } 2>/dev/null; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"handfest hook requires open stdout (fail closed)"},"verdict":"deny","code":"internal_error","reason":"stdout (fd 1) is closed"}' >&2 || true
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"handfest hook requires python3 (fail closed)"},"verdict":"deny","code":"missing_dependency","reason":"python3 not found on PATH"}' >&2 || true
  exit 2
fi

unset PY_CODE
IFS= read -r -d '' PY_CODE 2>/dev/null <<'PY' || true
import datetime, errno, json, os, re, shutil, subprocess, unicodedata

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\Z", re.ASCII)
RFC3339_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z", re.ASCII)
DECIMAL_NUM_RE = re.compile(r"^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\Z", re.ASCII)
DECIMAL_STR_RE = re.compile(r"^-?(?:0|[1-9]\d*)\.\d+\Z", re.ASCII)
RECEIPT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z", re.ASCII)
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
I128_MIN, I128_MAX = -(1 << 127), (1 << 127) - 1
MAX_DEC_SCALE = 28
POLICY_KEYS = {"action", "resource_kind", "resource_id_arg", "static_resource_id", "arg_facts", "static_facts"}
FACT_TYPES = {
    "str": "str", "Str": "str",
    "int": "int", "Int": "int",
    "decimal": "decimal", "Decimal": "decimal",
    "bool": "bool", "Bool": "bool",
    "timestamp": "timestamp", "Timestamp": "timestamp",
}


class RawNumber(str):
    pass


class HookError(Exception):
    def __init__(self, code: str, reason: str, receipt_hash: str | None = None):
        super().__init__(reason)
        self.code, self.reason, self.receipt_hash = code, reason, receipt_hash


def sanitize_surrogates(s: str) -> str:
    if has_surrogate(s):
        return s.encode("utf-8", errors="replace").decode("utf-8")
    return s


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise OSError(f"short write on fd {fd}")
        written += n


def emit_deny(code: str, reason: str, receipt_hash: str | None = None) -> None:
    safe_code = sanitize_surrogates(code)
    safe_reason = sanitize_surrogates(reason)
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"handfest {safe_code}: {safe_reason}",
        },
        "verdict": "deny",
        "code": safe_code,
        "reason": safe_reason,
    }
    if receipt_hash is not None:
        out["receipt_hash"] = sanitize_surrogates(receipt_hash)
    payload = (json.dumps(out, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8", errors="strict")
    try:
        write_all(2, payload)
    except OSError:
        pass
    os._exit(2)


def emit_permit(receipt_hash: str) -> None:
    out = {
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        "verdict": "permit",
        "receipt_hash": receipt_hash,
    }
    payload = (json.dumps(out, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8", errors="strict")
    try:
        write_all(1, payload)
    except OSError as exc:
        emit_deny("internal_error", f"failed to write permit output to stdout: {exc}")
    os._exit(0)


def is_ident(s: str) -> bool:
    return bool(IDENT_RE.match(s))


def is_dotted_ident(s: str) -> bool:
    return bool(s) and all(is_ident(p) for p in s.split("."))


def has_surrogate(s: str) -> bool:
    return any(unicodedata.category(c) == "Cs" for c in s)


def has_ctrl(s: str) -> bool:
    return any(unicodedata.category(c) in ("Cc", "Cs") for c in s)


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


def reject_surrogates(root, code: str, ctx: str) -> None:
    stack = [root]
    while stack:
        cur = stack.pop()
        if type(cur) is str:
            if has_surrogate(cur):
                raise HookError(code, f"{ctx}: lone UTF-16 surrogate in JSON string")
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def parse_strict_json(raw: str, code: str, ctx: str):
    if not raw or not raw.strip():
        raise HookError(code, f"{ctx}: empty JSON input")

    def no_dups(pairs):
        obj = {}
        for k, v in pairs:
            if has_surrogate(k):
                raise HookError(code, f"{ctx}: lone UTF-16 surrogate in JSON key")
            if k in obj:
                raise HookError(code, f"{ctx}: duplicate JSON key '{k}'")
            obj[k] = v
        return obj

    def no_const(tok: str):
        raise HookError(code, f"{ctx}: unsupported JSON constant '{tok}'")

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=no_dups,
            parse_constant=no_const,
            parse_int=RawNumber,
            parse_float=RawNumber,
        )
    except HookError:
        raise
    except Exception as exc:
        raise HookError(code, f"{ctx}: malformed JSON ({exc})")
    reject_surrogates(parsed, code, ctx)
    return parsed


def parse_i64(raw: RawNumber, code: str, ctx: str) -> int:
    if any(c in raw for c in (".", "e", "E")):
        raise HookError(code, f"{ctx}: expected 64-bit signed integer")
    if raw == "-0":
        raise HookError(code, f"{ctx}: negative zero integer '-0' is not allowed")
    if len(raw) > 21:
        raise HookError(code, f"{ctx}: integer outside 64-bit signed range")
    n = int(raw, 10)
    if not (I64_MIN <= n <= I64_MAX):
        raise HookError(code, f"{ctx}: integer outside 64-bit signed range")
    return n


def parse_decimal_exp(exp_str: str, raw: str, code: str, ctx: str) -> int:
    exp_neg = exp_str.startswith("-")
    exp_digits = exp_str.lstrip("+-").lstrip("0")
    if not exp_digits:
        return 0
    if len(exp_digits) > 18:
        raise HookError(code, f"{ctx}: decimal exponent out of supported range '{raw}'")
    val = int(exp_digits, 10)
    return -val if exp_neg else val


def format_decimal(neg: bool, acc: int, scale: int) -> str:
    sign = "-" if neg else ""
    s = str(acc)
    if scale == 0:
        return f"{sign}{s}.0"
    if len(s) <= scale:
        return f"{sign}0.{'0' * (scale - len(s))}{s}"
    split = len(s) - scale
    return f"{sign}{s[:split]}.{s[split:]}"


def split_decimal_exp(raw: str) -> tuple[str, str | None]:
    for sep in ("e", "E"):
        if sep in raw:
            mant_part, exp_str = raw.split(sep, 1)
            return mant_part, exp_str
    return raw, None


def scale_decimal_mantissa(
    trimmed: str, net_exp: int, neg: bool, raw: str, code: str, ctx: str
) -> tuple[int, int]:
    if net_exp >= 0:
        if len(trimmed) + net_exp > 39:
            raise HookError(code, f"{ctx}: decimal out of supported range '{raw}'")
        acc, scale = int(trimmed, 10) * (10 ** net_exp), 0
    else:
        scale = -net_exp
        if scale > MAX_DEC_SCALE or len(trimmed) > 39:
            raise HookError(code, f"{ctx}: decimal out of supported scale/range '{raw}'")
        acc = int(trimmed, 10)
    mantissa = -acc if neg else acc
    if not (I128_MIN <= mantissa <= I128_MAX):
        raise HookError(code, f"{ctx}: decimal out of supported range '{raw}'")
    return acc, scale


def parse_decimal(raw: str, code: str, ctx: str, allow_exponent: bool = False) -> str:
    regex = DECIMAL_NUM_RE if allow_exponent else DECIMAL_STR_RE
    if not regex.match(raw):
        raise HookError(code, f"{ctx}: invalid decimal '{raw}'")
    mant_part, exp_str = split_decimal_exp(raw)
    neg = mant_part.startswith("-")
    unsigned = mant_part[1:] if neg else mant_part
    int_digits, frac_digits = unsigned.split(".", 1) if "." in unsigned else (unsigned, "")
    if not allow_exponent and len(frac_digits) > MAX_DEC_SCALE:
        raise HookError(code, f"{ctx}: decimal fractional scale exceeds {MAX_DEC_SCALE} '{raw}'")
    digits = (int_digits + frac_digits).lstrip("0")
    if not digits:
        if neg:
            raise HookError(code, f"{ctx}: negative zero decimal '{raw}' is not allowed")
        return "0.0"
    exp = parse_decimal_exp(exp_str, raw, code, ctx) if exp_str is not None else 0
    trimmed = digits.rstrip("0")
    net_exp = exp - len(frac_digits) + (len(digits) - len(trimmed))
    acc, scale = scale_decimal_mantissa(trimmed, net_exp, neg, raw, code, ctx)
    return format_decimal(neg, acc, scale)


def parse_decimal_val(val, code: str, ctx: str, allow_num: bool) -> dict:
    if allow_num and isinstance(val, RawNumber):
        return {"decimal": parse_decimal(str(val), code, ctx, allow_exponent=True)}
    if type(val) is str:
        return {"decimal": parse_decimal(val, code, ctx, allow_exponent=False)}
    msg = "expected number or decimal string" if allow_num else "decimal value must be a string"
    raise HookError(code, f"{ctx}: {msg}")


def parse_scalar_val(expected: str, val, code: str, ctx: str, allow_num_decimal: bool) -> dict:
    if expected == "str":
        if type(val) is not str or has_ctrl(val):
            raise HookError(code, f"{ctx}: expected string without control characters")
        return {"str": val}
    if expected == "bool":
        if type(val) is not bool:
            raise HookError(code, f"{ctx}: expected boolean")
        return {"bool": val}
    if expected == "int":
        if not isinstance(val, RawNumber):
            raise HookError(code, f"{ctx}: expected 64-bit signed integer")
        return {"int": parse_i64(val, code, ctx)}
    if expected == "decimal":
        return parse_decimal_val(val, code, ctx, allow_num_decimal)
    if expected == "timestamp":
        if type(val) is not str or not is_rfc3339_utc(val):
            raise HookError(code, f"{ctx}: expected RFC 3339 UTC timestamp")
        return {"timestamp": val}
    raise HookError("invalid_policy_map", f"{ctx}: unsupported fact type '{expected}'")


def validate_typed_scalar(field: str, obj, code: str) -> dict:
    if not isinstance(obj, dict) or len(obj) != 1:
        raise HookError(code, f"static fact '{field}': expected single-key typed scalar object")
    tag, val = next(iter(obj.items()))
    t = FACT_TYPES.get(tag)
    if t is None:
        raise HookError(code, f"static fact '{field}': unsupported scalar tag '{tag}'")
    return parse_scalar_val(t, val, code, f"static fact '{field}'", allow_num_decimal=False)


def validate_resource_source(tool: str, pol: dict, c: str) -> tuple[str | None, str | None]:
    res_arg, static_res = pol.get("resource_id_arg"), pol.get("static_resource_id")
    if (res_arg is None) == (static_res is None):
        raise HookError(c, f"tool '{tool}': declare exactly one of resource_id_arg or static_resource_id")
    if res_arg is not None and (type(res_arg) is not str or not res_arg or not res_arg.isascii()):
        raise HookError(c, f"tool '{tool}': invalid resource_id_arg")
    if static_res is not None and (type(static_res) is not str or has_ctrl(static_res)):
        raise HookError(c, f"tool '{tool}': invalid static_resource_id")
    return res_arg, static_res


def validate_arg_fact_spec(tool: str, k: str, spec, c: str) -> tuple[str, str]:
    if not isinstance(spec, dict) or set(spec.keys()) != {"field", "type"}:
        raise HookError(c, f"tool '{tool}': invalid fact spec for '{k}'")
    field, ftype = spec["field"], spec["type"]
    if type(field) is not str or not is_dotted_ident(field):
        raise HookError(c, f"tool '{tool}': invalid arg_facts field '{field}'")
    if type(ftype) is not str or ftype not in FACT_TYPES:
        raise HookError(c, f"tool '{tool}': invalid fact type '{ftype}'")
    return field, FACT_TYPES[ftype]


def validate_arg_facts(tool: str, raw, res_arg: str | None, c: str) -> dict:
    if not isinstance(raw, dict):
        raise HookError(c, f"tool '{tool}': arg_facts must be an object")
    target_fields, folded, arg_facts = set(), {}, {}
    res_low = res_arg.lower() if res_arg is not None else None
    for k, spec in raw.items():
        if not k or not k.isascii():
            raise HookError(c, f"tool '{tool}': arg_facts key must be non-empty ASCII")
        low = k.lower()
        if res_low is not None and k != res_arg and low == res_low:
            raise HookError(c, f"tool '{tool}': arg_facts key '{k}' collides with resource_id_arg")
        if low in folded:
            raise HookError(c, f"tool '{tool}': arg_facts key '{k}' collides with '{folded[low]}'")
        folded[low] = k
        field, ftype = validate_arg_fact_spec(tool, k, spec, c)
        if field in target_fields:
            raise HookError(c, f"tool '{tool}': duplicate arg_facts target field '{field}'")
        target_fields.add(field)
        arg_facts[k] = (field, ftype)
    return arg_facts


def validate_static_facts(tool: str, raw, c: str) -> dict:
    if not isinstance(raw, dict):
        raise HookError(c, f"tool '{tool}': static_facts must be an object")
    static_facts = {}
    for field, typed in raw.items():
        if not is_dotted_ident(field):
            raise HookError(c, f"tool '{tool}': invalid static_facts field '{field}'")
        static_facts[field] = validate_typed_scalar(field, typed, c)
    return static_facts


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
    res_arg, static_res = validate_resource_source(tool, pol, c)
    arg_facts = validate_arg_facts(tool, pol.get("arg_facts", {}), res_arg, c)
    static_facts = validate_static_facts(tool, pol.get("static_facts", {}), c)
    return {
        "action": action, "resource_kind": rkind,
        "resource_id_arg": res_arg, "static_resource_id": static_res,
        "arg_facts": arg_facts, "static_facts": static_facts,
    }


def load_policy_map(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            raw_bytes = fh.read()
    except OSError as exc:
        raise HookError("invalid_policy_map", f"failed to read policy map '{path}': {exc}")
    try:
        raw = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HookError("invalid_policy_map", f"policy map '{path}' is not valid UTF-8: {exc}")
    parsed = parse_strict_json(raw, "invalid_policy_map", "policy map")
    if not isinstance(parsed, dict) or set(parsed.keys()) != {"tools"} or not isinstance(parsed["tools"], dict):
        raise HookError("invalid_policy_map", "policy map must be a JSON object with only object key 'tools'")
    return {name: validate_policy(name, pol) for name, pol in parsed["tools"].items()}


def parse_arg_scalar(tool: str, arg: str, expected: str, val) -> dict:
    return parse_scalar_val(
        expected, val, "invalid_argument", f"tool '{tool}': argument '{arg}'", allow_num_decimal=True
    )


def get_env_strict(name: str) -> str | None:
    raw = os.environb.get(name.encode("ascii"))
    if raw is None:
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HookError("missing_config", f"environment variable {name} is not valid UTF-8: {exc}")


def require_env(name: str) -> str:
    val = get_env_strict(name)
    if not val:
        raise HookError("missing_config", f"required environment variable {name} is not set")
    return val


def resolve_bin() -> str:
    raw = (get_env_strict("HANDFEST_BIN") or "").strip() or "handfest"
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
    override = get_env_strict("HANDFEST_NOW")
    if override:
        if not is_rfc3339_utc(override):
            raise HookError("missing_config", f"invalid HANDFEST_NOW '{override}': expected RFC 3339 UTC")
        return override
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_allow_create_ledger() -> bool:
    raw = get_env_strict("HANDFEST_ALLOW_CREATE_LEDGER")
    if raw is None or raw in ("", "0"):
        return False
    if raw == "1":
        return True
    raise HookError("missing_config", f"invalid HANDFEST_ALLOW_CREATE_LEDGER '{raw}': expected '0' or '1'")


def validate_tool_input_keys(tool: str, root: dict) -> None:
    stack = [root]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            seen = {}
            for k, v in cur.items():
                if not k.isascii():
                    raise HookError("invalid_input", f"tool '{tool}': argument key '{k}' must be ASCII")
                low = k.lower()
                if low in seen:
                    raise HookError("invalid_input", f"tool '{tool}': argument key '{k}' collides with '{seen[low]}'")
                seen[low] = k
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)


def read_stdin_bytes() -> bytes:
    chunks = []
    while True:
        chunk = os.read(0, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def parse_stdin() -> tuple[str, dict]:
    try:
        raw_bytes = read_stdin_bytes()
    except OSError as exc:
        raise HookError("invalid_input", f"failed to read hook stdin: {exc}")
    try:
        raw = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HookError("invalid_input", f"hook stdin is not valid UTF-8: {exc}")
    payload = parse_strict_json(raw, "invalid_input", "hook stdin")
    if not isinstance(payload, dict):
        raise HookError("invalid_input", "hook stdin must be a JSON object")
    tool = payload.get("tool_name")
    if type(tool) is not str or not tool or has_ctrl(tool):
        raise HookError("invalid_input", "missing or invalid 'tool_name'")
    if "tool_input" not in payload or not isinstance(payload["tool_input"], dict):
        raise HookError("invalid_input", "missing or non-object 'tool_input'")
    args = payload["tool_input"]
    validate_tool_input_keys(tool, args)
    return tool, args


def extract_resource_and_facts(tool_name: str, tool_input: dict, pol: dict) -> tuple[str, dict]:
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
    return resource_id, facts


def parse_gate_deny(stdout_bytes: bytes) -> tuple[str, str | None] | None:
    try:
        out = parse_strict_json(
            stdout_bytes.decode("utf-8", errors="strict"), "gate_error", "handfest check deny stdout"
        )
    except (HookError, UnicodeDecodeError):
        return None
    if not isinstance(out, dict) or out.get("verdict") != "deny":
        return None
    reason = out.get("reason")
    reason_str = reason if isinstance(reason, str) else json.dumps(reason, separators=(",", ":"))
    raw_rhash = out.get("receipt_hash")
    rhash = raw_rhash if type(raw_rhash) is str and RECEIPT_HASH_RE.match(raw_rhash) else None
    return reason_str, rhash


def handle_gate_result(proc: subprocess.CompletedProcess) -> None:
    if proc.returncode == 0:
        try:
            stdout_text = proc.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise HookError("invalid_gate_output", f"handfest check stdout is not valid UTF-8: {exc}")
        out = parse_strict_json(stdout_text, "invalid_gate_output", "handfest check stdout")
        if (
            isinstance(out, dict)
            and out.get("verdict") == "permit"
            and type(out.get("receipt_hash")) is str
            and RECEIPT_HASH_RE.match(out["receipt_hash"])
        ):
            emit_permit(out["receipt_hash"])
        raise HookError("invalid_gate_output", "handfest check exited 0 without valid Permit JSON")

    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    if stdout_text.strip():
        denied = parse_gate_deny(proc.stdout)
        if denied is not None:
            raise HookError("mandate_denied", denied[0], receipt_hash=denied[1])

    stderr_text = proc.stderr.decode("utf-8", errors="replace")
    detail = (stderr_text or stdout_text or f"exit status {proc.returncode}").strip()
    raise HookError("gate_error", detail)


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
    allow_create_ledger = resolve_allow_create_ledger()
    policy_map = load_policy_map(policy_path)
    tool_name, tool_input = parse_stdin()

    pol = policy_map.get(tool_name)
    if pol is None:
        raise HookError("unmapped_tool", f"tool '{tool_name}' is not admitted in HANDFEST_POLICY_MAP")

    resource_id, facts = extract_resource_and_facts(tool_name, tool_input, pol)

    require_existing_ledger = not allow_create_ledger
    if require_existing_ledger:
        try:
            os.stat(ledger_path)
        except FileNotFoundError as exc:
            if exc.errno == errno.ENOENT:
                raise HookError(
                    "missing_ledger",
                    f"HANDFEST_LEDGER '{ledger_path}' does not exist; initialize it first or set HANDFEST_ALLOW_CREATE_LEDGER=1",
                )
        except OSError:
            pass
    cmd = [
        handfest_bin, "check",
        f"--ledger={ledger_path}",
        *(f"--chain={p}" for p in chain_paths),
        f"--actor-key={actor_key}",
        f"--action={pol['action']}",
        f"--resource-kind={pol['resource_kind']}",
        f"--resource-id={resource_id}",
        f"--facts={json.dumps(facts, separators=(',', ':'))}",
        f"--now={now_utc}",
    ]
    if require_existing_ledger:
        cmd.append("--require-existing-ledger")
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True)
    except OSError as exc:
        raise HookError("gate_error", f"failed to invoke handfest check: {exc}")

    handle_gate_result(proc)


try:
    main()
except HookError as err:
    emit_deny(err.code, err.reason, receipt_hash=err.receipt_hash)
except BaseException as exc:
    emit_deny("internal_error", f"unexpected hook error: {exc}")
# HANDFEST_PY_SENTINEL_EOF
PY

if [[ "${PY_CODE:-}" != *"# HANDFEST_PY_SENTINEL_EOF"* ]]; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"handfest hook failed to load embedded validator (fail closed)"},"verdict":"deny","code":"internal_error","reason":"embedded python validator failed to load"}' >&2 || true
  exit 2
fi

rc=0
python3 -I -c "$PY_CODE" || rc=$?
if [[ "$rc" -eq 0 ]]; then
  exit 0
fi
if [[ "$rc" -ne 2 ]]; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"handfest hook internal failure (fail closed)"},"verdict":"deny","code":"internal_error","reason":"hook exited unexpectedly"}' >&2 || true
fi
exit 2
