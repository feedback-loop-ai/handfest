#!/bin/bash
# Deterministic, fail-closed Claude Code PreToolUse hook for HANDFEST v1 mandates.
#
# Required env:
#   HANDFEST_POLICY_MAP  ToolPolicyMap JSON path (validated by handfest-mcp's single codec via `handfest check --policy-map`)
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
import datetime, json, os, re, shutil, subprocess, unicodedata

RFC3339_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z", re.ASCII)
RECEIPT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z", re.ASCII)
MAX_JSON_DEPTH = 128
MAPPING_ERROR_CODES = frozenset(
    {"invalid_policy_map", "unmapped_tool", "invalid_input", "invalid_argument"}
)


class RawNumber(str):
    pass


class HookError(Exception):
    def __init__(self, code: str, reason: str, receipt_hash: str | None = None):
        super().__init__(reason)
        self.code, self.reason, self.receipt_hash = code, reason, receipt_hash


def has_surrogate(s: str) -> bool:
    return any(unicodedata.category(c) == "Cs" for c in s)


def has_ctrl(s: str) -> bool:
    return any(unicodedata.category(c) in ("Cc", "Cs") for c in s)


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


def validate_json_tree(root, code: str, ctx: str) -> None:
    stack = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if type(cur) is str:
            if has_surrogate(cur):
                raise HookError(code, f"{ctx}: lone UTF-16 surrogate in JSON string")
        elif isinstance(cur, (dict, list)):
            next_depth = depth + 1
            if next_depth > MAX_JSON_DEPTH:
                raise HookError(code, f"{ctx}: JSON nesting depth exceeds {MAX_JSON_DEPTH}")
            for item in (cur.values() if isinstance(cur, dict) else cur):
                stack.append((item, next_depth))


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
    validate_json_tree(parsed, code, ctx)
    return parsed


def encode_exact_json(val) -> str:
    if isinstance(val, RawNumber):
        return str(val)
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if type(val) is str:
        return json.dumps(val, ensure_ascii=False, allow_nan=False)
    if isinstance(val, list):
        return "[" + ",".join(encode_exact_json(item) for item in val) + "]"
    if isinstance(val, dict):
        items = (
            f"{json.dumps(k, ensure_ascii=False, allow_nan=False)}:{encode_exact_json(v)}"
            for k, v in val.items()
        )
        return "{" + ",".join(items) + "}"
    raise HookError("invalid_input", f"unsupported JSON value type: {type(val).__name__}")


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
    return tool, payload["tool_input"]


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


def parse_gate_stderr_error(stderr_bytes: bytes) -> tuple[str, str] | None:
    try:
        text = stderr_bytes.decode("utf-8", errors="strict").strip()
        if not text:
            return None
        out = parse_strict_json(text, "gate_error", "handfest check stderr")
    except (HookError, UnicodeDecodeError):
        return None
    if not isinstance(out, dict):
        return None
    err_kind, code, msg = out.get("error"), out.get("code"), out.get("message")
    if type(msg) is not str or not msg:
        return None
    if err_kind == "policy_mapping_failed" and code in MAPPING_ERROR_CODES:
        return code, msg
    if err_kind == "ledger_open_failed" and code == "missing_ledger":
        return "missing_ledger", msg
    return None


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

    structured = parse_gate_stderr_error(proc.stderr)
    if structured is not None:
        raise HookError(structured[0], structured[1])

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
    tool_name, tool_input = parse_stdin()
    raw_tool_input = encode_exact_json(tool_input).encode("utf-8", errors="strict")

    cmd = [
        handfest_bin, "check",
        f"--ledger={ledger_path}",
        *(f"--chain={p}" for p in chain_paths),
        f"--actor-key={actor_key}",
        f"--policy-map={policy_path}",
        f"--tool-name={tool_name}",
        "--tool-input=-",
        f"--now={now_utc}",
    ]
    if not allow_create_ledger:
        cmd.append("--require-existing-ledger")
    try:
        proc = subprocess.run(cmd, input=raw_tool_input, capture_output=True)
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
