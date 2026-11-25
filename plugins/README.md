# Handfest Harness Plugins (`plugins/`)

Thin, declarative, configuration-over-code integrations for vesting bounded `HANDFEST v1` authority into AI harnesses — **Claude Code**, **Codex**, **`dsh`**, and **Antigravity (`agy`)** — with zero harness-specific Rust code in `crates/`.

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
                          v  (signed chain + public actor KeyId + ToolPolicyMap)
  [3. OUTSIDE THE MODEL — Deterministic Fail-Closed Gate]
    Option A (all 4 harnesses): `handfest-mcp` stdio JSON-RPC 2.0 proxy
      - Filters `tools/list` to granted tools
      - Maps `tools/call` via `ToolPolicyMap` + host clock + static facts
      - Evaluates chain via `handfest-core`, updates atomic quotas & hash-chained
        receipts in `handfest-ledger`, denies with JSON-RPC `-32001`
    Option B (Claude Code hooks): `plugins/claude-code/hooks/pre-tool-use.sh`
      - Reads Claude Code `PreToolUse` JSON stdin
      - Maps via the exact same `ToolPolicyMap` schema (`HANDFEST_POLICY_MAP`)
      - Invokes `handfest check`; exits `0` ONLY on Permit, exits `2` + structured
        JSON deny payload on stderr for any Deny, unmapped tool, malformed input,
        or missing configuration
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
- `arg_facts`: map from tool argument name to `{"field": "<field.path>", "type": "str|int|decimal|bool|timestamp"}`.
- `static_facts`: operator-supplied typed facts (`{"str": ...}`, `{"int": ...}`, `{"decimal": "..."}`, `{"bool": ...}`, `{"timestamp": "..."}`) that **always override** model-supplied `arg_facts`.
- `context.time` is always supplied by the host clock and can never be overridden by tool arguments or static facts.

## Harness Quickstarts

### Claude Code ([`plugins/claude-code/`](claude-code/))

- **Hook (`PreToolUse`):** Export `HANDFEST_POLICY_MAP`, `HANDFEST_LEDGER`, `HANDFEST_CHAIN` (colon-separated root-to-leaf signed mandates), and `HANDFEST_ACTOR_KEY` (agent public `KeyId`), then merge `hooks` from [`claude-code/settings.example.json`](claude-code/settings.example.json) into `.claude/settings.json`.
- **MCP proxy:** Merge `mcpServers` from [`claude-code/settings.example.json`](claude-code/settings.example.json) to wrap any upstream MCP server via `handfest-mcp`.
- **Drafting & audit skill:** Install [`claude-code/SKILL.md`](claude-code/SKILL.md) as a Claude Code `/handfest` skill.

### Codex ([`plugins/codex/`](codex/))

- Copy the `[mcp_servers.*]` stanza from [`codex/config.example.toml`](codex/config.example.toml) into `~/.codex/config.toml` or `.codex/config.toml`.
- See [`codex/README.md`](codex/README.md) for the full keygen, signing, and audit workflow.

### `dsh` ([`plugins/dsh/`](dsh/))

- Copy [`dsh/mcp.example.json`](dsh/mcp.example.json) into your `dsh` MCP configuration.
- See [`dsh/README.md`](dsh/README.md) for setup and audit commands.

### Antigravity / `agy` ([`plugins/agy/`](agy/))

- Install [`agy/SKILL.md`](agy/SKILL.md) under `.gemini/antigravity/skills/handfest/SKILL.md` (or `~/.gemini/antigravity/skills/handfest/SKILL.md`) for `/handfest` drafting, `handfest fmt` WYSIWYS handoff, and `handfest audit`.
- Configure MCP wrapping using [`agy/mcp.example.json`](agy/mcp.example.json).

## Verification

Run the self-contained, zero-network deterministic hook test suite:

```bash
./plugins/tests/test-hooks.sh
```
