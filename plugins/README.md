# Handfest Harness Plugins (`plugins/`)

Thin, declarative, configuration-over-code integrations for vesting bounded `HANDFEST v1` authority into AI harnesses — **Claude Code**, **Codex**, **`dsh`**, and **Antigravity (`agy`)** — with zero harness-specific Rust code in `crates/`.

> **Prerequisites & binary availability:**
> - The `handfest` CLI (`handfest keygen`, `keyid`, `init`, `fmt`, `sign`, `revoke`, `verify`, `check`, `audit`) ships in this workspace (`crates/handfest-cli`).
> - The `handfest-mcp` stdio JSON-RPC 2.0 proxy (`crates/handfest-mcp`) ships in this workspace and is built with `cargo build --release -p handfest-mcp`. The `mcp.example.json` and `codex/config.example.toml` templates target its CLI contract.
> - **Python 3.10+** (`python3`, standard library only, invoked via `python3 -I` isolated mode) is required on `PATH` to run `plugins/claude-code/hooks/pre-tool-use.sh`, and **Python 3.11+** (standard library only, including `tomllib`) is required to run `plugins/tests/test-hooks.sh`.

## 1-Command Onboarding (YubiKey or Local Key)

1. **Install skills, hook, and localized templates** (zero external deps beyond POSIX `cp`/`install`/`sed`):
   ```bash
   ./plugins/install.sh
   ```
   This installs `/handfest` `SKILL.md` into `~/.gemini/config/skills/handfest/SKILL.md` (`agy`), `~/.claude/skills/handfest/SKILL.md` (Claude Code), and `~/.codex/skills/handfest/SKILL.md` (Codex), installs `pre-tool-use.sh` (`0755`), and writes localized templates under `${HANDFEST_HOME:-$HOME/.handfest}/templates/`.

2. **Derive your public `KeyId` (`handfest keyid`)** for any of the 4 YubiKey interfaces (never reads private keys) or a local key:
   ```bash
   handfest keyid --ssh-key ~/.ssh/id_ed25519_sk.pub       # ssh-sk-ed25519:<hex>
   handfest keyid --fido2-cred ~/.handfest/yk.fido2.json  # fido2-ed25519:<hex>
   handfest keyid --gpg-key <40-hex-fingerprint>          # openpgp-ed25519:<hex>
   handfest keyid --piv-pubkey ~/.handfest/yk-9c.pem      # piv-ed25519:<hex>
   handfest keyid --key ~/.handfest/human.key.json        # ed25519:<hex>
   ```

3. **Bootstrap `~/.handfest` out-of-band (`handfest init`)**:
   ```bash
   handfest init --principal-name "Valentin" --ssh-key ~/.ssh/id_ed25519_sk.pub
   # Or use --fido2-cred, --gpg-key, --piv-pubkey, or --key
   ```
   `handfest init` creates a `0700` outside-workspace directory, initializes (or verifies without resetting quotas) `~/.handfest/state/handfest-ledger.sqlite`, generates (or reuses without overwriting) `0600` `~/.handfest/agent.key.json`, and writes a **public-only** `0644` `~/.handfest/profile.json` (`schema: "handfest.profile/v1"`). `/handfest` skills read `~/.handfest/profile.json` automatically to pre-fill public `KeyId`s without ever touching private keys.

## Architecture & Trust Boundary

```text
  [1. INSIDE THE HARNESS — Untrusted / Stochastic]
    AI Agent + `/handfest` SKILL.md
      - Reads public-only `~/.handfest/profile.json` (NEVER private keys)
      - Helps draft HANDFEST v1 text
      - Runs `handfest fmt` (canonical WYSIWYS preview)
      - Runs read-only `handfest verify` / `handfest audit`
      - NEVER holds or reads private signing keys
      - NEVER decides Permit or Deny in prose
                          |
                          v  (canonical text handed to human)
  [2. OUT-OF-BAND PRINCIPAL — WYSIWYS Signing & Kill Switch]
    Human / Org (own terminal + YubiKey SSH-SK / FIDO2 / OpenPGP / PIV or local key)
      - Inspects canonical HANDFEST v1 text verbatim
      - Signs with `handfest sign` (--ssh-key | --fido2-cred | --gpg-key | --piv-pubkey | --key)
      - Revokes immediately with `handfest revoke --effective now --ledger ...`
                          |
                          v  (signed chain + public actor KeyId + ToolPolicyMap
                              stored outside the agent-writable workspace)
  [3. OUTSIDE THE MODEL — Deterministic Fail-Closed Gate]
    Option A (all 4 harnesses): `handfest-mcp` stdio JSON-RPC 2.0 proxy
      - Filters `tools/list` to granted tools
      - Maps `tools/call` via `ToolPolicyMap` + host clock + static facts
      - Evaluates chain + revocations via `handfest-core`, updates atomic quotas &
        hash-chained receipts in `handfest-ledger`, denies with JSON-RPC `-32001`
    Option B (Claude Code non-MCP hooks): `plugins/claude-code/hooks/pre-tool-use.sh`
      - Installed at `~/.handfest/hooks/pre-tool-use.sh` (`0755`)
      - Reads Claude Code `PreToolUse` JSON stdin for scoped non-MCP tools
      - Maps via the exact same `ToolPolicyMap` schema (`HANDFEST_POLICY_MAP`)
      - Invokes `handfest check`; exits `0` ONLY on Permit with a valid `sha256:` receipt,
        exits `2` + structured JSON deny payload on stderr for any Deny, revocation,
        unmapped tool, malformed input, or missing configuration
                          |
                          v
  [4. TAMPER-EVIDENT AUDIT]
    `handfest audit --ledger <sqlite> [--actor-key <key_id>]`
```

## Shared `ToolPolicyMap` Configuration

Both `handfest-mcp --policy-map` and `plugins/claude-code/hooks/pre-tool-use.sh` (`HANDFEST_POLICY_MAP`) consume one canonical, schema-validated JSON format ([`policy-map.example.json`](policy-map.example.json)):

- `tools.<tool_name>.action`: concrete `HANDFEST v1` action (e.g. `git.pr.merge`).
- `tools.<tool_name>.resource_kind`: resource kind identifier (e.g. `repo`).
- Exactly one of `resource_id_arg` (argument name in tool call) or `static_resource_id`.
- `arg_facts`: map from tool argument name to `{"field": "<field.path>", "type": "str|int|decimal|bool|timestamp"}` (or exact PascalCase `Str|Int|Decimal|Bool|Timestamp`).
- `static_facts`: strictly for **genuinely static operator-pinned constants** (`{"str": ...}`, `{"int": ...}`, `{"decimal": "..."}`, `{"bool": ...}`, `{"timestamp": "..."}`), such as `"resource.environment": {"str": "staging"}`. Operator `static_facts` **always override** model-supplied `arg_facts`.
  - For `decimal` facts (`static_facts` `"decimal"` strings and `decimal` tool arguments — **not** `int` facts, which are signed 64-bit JSON integers), `handfest check --policy-map` and `handfest-mcp` validate decimals and tool policies through the shared Rust `handfest-core` codec (`handfest_core::policy` and `handfest_core::json_num`), while `pre-tool-use.sh` preserves raw JSON number tokens losslessly and validates the Claude Code hook envelope (duplicate-key rejection, strict UTF-8 / no lone surrogates, and `MAX_JSON_DEPTH = 128`, matching `handfest_core::exact_json::DEFAULT_MAX_JSON_DEPTH`).
  - **Never hardcode dynamic runtime facts** (such as `resource.ci_status` or live PR approval counts) in `static_facts`; dynamic facts must be queried and injected by a trusted broker outside the model.
- `context.time` is always supplied by the host clock and can never be overridden by tool arguments or static facts.

[`policy-map.example.json`](policy-map.example.json) maps `@modelcontextprotocol/server-github`'s `merge_pull_request` tool (`owner`, `repo`, `pullNumber`) to `git.pr.merge` on `repo` with `resource.owner`, `resource.pr`, and operator-pinned `resource.environment: "staging"`.

## Harness Quickstarts

### Claude Code ([`plugins/claude-code/`](claude-code/))

- Run `./plugins/install.sh` to install `~/.claude/skills/handfest/SKILL.md`, `~/.handfest/hooks/pre-tool-use.sh`, and localized templates under `~/.handfest/templates/`.
- **Non-MCP Hook (`PreToolUse`):** Requires **Python 3.10+** (`python3`) on `PATH`. Export `HANDFEST_POLICY_MAP`, `HANDFEST_LEDGER`, `HANDFEST_CHAIN` (colon-separated root-to-leaf signed mandates), and `HANDFEST_ACTOR_KEY` (public `agent_key_id` from `~/.handfest/profile.json`), then merge `~/.handfest/templates/claude-settings.json` into `.claude/settings.json`.
  - `HANDFEST_LEDGER` must already exist and be initialized on disk (created cleanly by `handfest init`; enforced atomically via `handfest check --require-existing-ledger`).
  - Scope `PreToolUse` `matcher` to explicit non-MCP tools (e.g. `"Bash|Write|Edit"`) rather than `".*"` so MCP tools already gated by `handfest-mcp` are never double-gated or double-charged in the SQLite ledger.
- **MCP proxy (`.mcp.json`):** Copy `~/.handfest/templates/claude-mcp.json` into `.mcp.json` and fill in `agent_key_id` from `~/.handfest/profile.json`.

### Codex ([`plugins/codex/`](codex/))

- Run `./plugins/install.sh` to install `~/.codex/skills/handfest/SKILL.md` and `~/.handfest/templates/codex-config.toml`.
- Merge `~/.handfest/templates/codex-config.toml` into `~/.codex/config.toml` or `.codex/config.toml` with `agent_key_id` from `~/.handfest/profile.json`.
- See [`codex/README.md`](codex/README.md) for the full YubiKey `init`, `sign`, `revoke`, and `audit` workflow.

### `dsh` ([`plugins/dsh/`](dsh/))

- Run `./plugins/install.sh` and copy `~/.handfest/templates/dsh-mcp.json` into your `dsh` MCP configuration with `agent_key_id` from `~/.handfest/profile.json`.
- See [`dsh/README.md`](dsh/README.md) for setup, YubiKey signing, revocation, and audit commands.

### Antigravity / `agy` ([`plugins/agy/`](agy/))

- Run `./plugins/install.sh` to install `~/.gemini/config/skills/handfest/SKILL.md` and `~/.handfest/templates/agy-mcp.json`.
- Configure MCP wrapping using `~/.handfest/templates/agy-mcp.json` and `agent_key_id` from `~/.handfest/profile.json`.

## Verification

Run the self-contained, zero-network deterministic hook and installer test suite:

```bash
./plugins/tests/test-hooks.sh
```
