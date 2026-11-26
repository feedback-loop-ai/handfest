# Handfest Harness Plugins (`plugins/`)

Thin, declarative, configuration-over-code integrations for vesting bounded `HANDFEST v1` authority into AI harnesses — **Claude Code**, **Codex**, **`dsh`**, and **Antigravity (`agy`)** — with zero harness-specific Rust code in `crates/`.

> **Prerequisites & binary availability:**
> - The `handfest` CLI (`handfest keygen`, `fmt`, `sign`, `verify`, `check`, `audit`) ships in this workspace (`crates/handfest-cli`).
> - The `handfest-mcp` stdio JSON-RPC 2.0 proxy (`crates/handfest-mcp`) ships in this workspace and is built with `cargo build --release -p handfest-mcp`. The `mcp.example.json` and `codex/config.example.toml` templates target its CLI contract.
> - **Python 3.10+** (`python3`, standard library only, invoked via `python3 -I` isolated mode) is required on `PATH` to run `plugins/claude-code/hooks/pre-tool-use.sh`, and **Python 3.11+** (standard library only, including `tomllib`) is required to run `plugins/tests/test-hooks.sh`.

## Architecture & Trust Boundary

```text
  [1. INSIDE THE HARNESS — Untrusted / Stochastic]
    AI Agent + `/handfest` SKILL.md
      - Helps draft HANDFEST v1 text
      - Runs `handfest fmt` (canonical WYSIWYS preview)
      - Runs read-only `handfest verify` / `handfest audit`
      - NEVER holds or reads private signing keys
      - NEVER decides Permit or Deny in prose
                          |
                          v  (canonical text handed to human)
  [2. OUT-OF-BAND PRINCIPAL — WYSIWYS Signing]
    Human / Org (own terminal, hardware key, or wallet)
      - Inspects canonical HANDFEST v1 text verbatim
      - Signs with `handfest sign` -> SignedMandate JSON
                          |
                          v  (signed chain + public actor KeyId + ToolPolicyMap
                              stored outside the agent-writable workspace)
  [3. OUTSIDE THE MODEL — Deterministic Fail-Closed Gate]
    Option A (all 4 harnesses): `handfest-mcp` stdio JSON-RPC 2.0 proxy
      - Filters `tools/list` to granted tools
      - Maps `tools/call` via `ToolPolicyMap` + host clock + static facts
      - Evaluates chain via `handfest-core`, updates atomic quotas & hash-chained
        receipts in `handfest-ledger`, denies with JSON-RPC `-32001`
    Option B (Claude Code non-MCP hooks): `plugins/claude-code/hooks/pre-tool-use.sh`
      - Installed outside the workspace (e.g. `/path/to/handfest-config/hooks/pre-tool-use.sh`)
      - Reads Claude Code `PreToolUse` JSON stdin for scoped non-MCP tools
      - Maps via the exact same `ToolPolicyMap` schema (`HANDFEST_POLICY_MAP`)
      - Invokes `handfest check`; exits `0` ONLY on Permit with a valid `sha256:` receipt,
        exits `2` + structured JSON deny payload on stderr for any Deny, unmapped tool,
        malformed input, or missing configuration
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
  - For `decimal` facts (`static_facts` `"decimal"` strings and `decimal` tool arguments — **not** `int` facts, which are signed 64-bit JSON integers), `handfest-core::ast::Decimal::parse` enforces the required decimal point and `<= 28` raw fractional-digit scale, while `handfest-cli` and `pre-tool-use.sh` wire validation additionally reject leading zeros (e.g., `"01.5"`) and negative zero (`"-0.0"`, `"-0.00"`, `-0.0`, `-0e0`, and `-0` for `int`/`decimal` JSON numbers). Portable `ToolPolicyMap` configurations used across `handfest-cli`, `handfest-mcp`, and `pre-tool-use.sh` must match `-?(?:0|[1-9]\d*)\.\d{1,28}` (e.g., `"1.0"`, never negative zero) for `decimal` strings and avoid `-0` for `int` values.
  - **Never hardcode dynamic runtime facts** (such as `resource.ci_status` or live PR approval counts) in `static_facts`; dynamic facts must be queried and injected by a trusted broker outside the model.
- `context.time` is always supplied by the host clock and can never be overridden by tool arguments or static facts.

[`policy-map.example.json`](policy-map.example.json) maps `@modelcontextprotocol/server-github`'s `merge_pull_request` tool (`owner`, `repo`, `pullNumber`) to `git.pr.merge` on `repo` with `resource.owner`, `resource.pr`, and operator-pinned `resource.environment: "staging"`. Copy the policy map, hook script, signed mandates, and SQLite ledger to an outside-workspace directory (e.g. `/path/to/handfest-config/`) that the agent cannot modify.

## Harness Quickstarts

### Claude Code ([`plugins/claude-code/`](claude-code/))

- **Non-MCP Hook (`PreToolUse`):** Requires **Python 3.10+** (`python3`) on `PATH`. Copy [`pre-tool-use.sh`](claude-code/hooks/pre-tool-use.sh) and your non-MCP `ToolPolicyMap` to an outside-workspace location (`/path/to/handfest-config/`), export `HANDFEST_POLICY_MAP`, `HANDFEST_LEDGER`, `HANDFEST_CHAIN` (colon-separated root-to-leaf signed mandates), and `HANDFEST_ACTOR_KEY` (agent public `KeyId`), then merge [`claude-code/settings.example.json`](claude-code/settings.example.json) into `.claude/settings.json`.
  - `HANDFEST_LEDGER` must already exist and be initialized on disk by default (enforced atomically via `handfest check --require-existing-ledger`): a ledger absent at hook startup exits `2` with `missing_ledger`, while a 0-byte, empty-schema, corrupt, or concurrently deleted ledger caught by `handfest check --require-existing-ledger` exits `2` with `gate_error`, ensuring deleted, truncated, or uninitialized SQLite files cannot reset quotas. Set `HANDFEST_ALLOW_CREATE_LEDGER=1` only during initial ledger creation.
  - Scope `PreToolUse` `matcher` to explicit non-MCP tools (e.g. `"Bash|Write|Edit"`) rather than `".*"` so MCP tools already gated by `handfest-mcp` are never double-gated or double-charged in the SQLite ledger.
- **MCP proxy (`.mcp.json`):** Copy [`claude-code/mcp.example.json`](claude-code/mcp.example.json) into your project's `.mcp.json` (separate from `.claude/settings.json`) to wrap upstream MCP servers via `handfest-mcp` using outside-workspace config paths.
- **Drafting & audit skill:** Install [`claude-code/SKILL.md`](claude-code/SKILL.md) as a Claude Code `/handfest` skill.

### Codex ([`plugins/codex/`](codex/))

- Copy the `[mcp_servers.*]` stanza from [`codex/config.example.toml`](codex/config.example.toml) into `~/.codex/config.toml` or `.codex/config.toml` with outside-workspace `/path/to/handfest-config/...` paths.
- See [`codex/README.md`](codex/README.md) for the full keygen, signing, and audit workflow.

### `dsh` ([`plugins/dsh/`](dsh/))

- Copy [`dsh/mcp.example.json`](dsh/mcp.example.json) into your `dsh` MCP configuration with outside-workspace `/path/to/handfest-config/...` paths.
- See [`dsh/README.md`](dsh/README.md) for setup and audit commands.

### Antigravity / `agy` ([`plugins/agy/`](agy/))

- Install [`agy/SKILL.md`](agy/SKILL.md) under `.gemini/antigravity/skills/handfest/SKILL.md` (or `~/.gemini/antigravity/skills/handfest/SKILL.md`) for `/handfest` drafting, `handfest fmt` WYSIWYS handoff, and `handfest audit`.
- Configure MCP wrapping using [`agy/mcp.example.json`](agy/mcp.example.json) with outside-workspace `/path/to/handfest-config/...` paths.

## Verification

Run the self-contained, zero-network deterministic hook test suite:

```bash
./plugins/tests/test-hooks.sh
```
