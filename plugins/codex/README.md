# Handfest Plugin for Codex

This plugin configures OpenAI Codex to route MCP tool calls through `handfest-mcp`, enforcing signed `HANDFEST v1` mandates deterministically outside the model.

## Trust Boundary

- **Out-of-band principal:** Generates keys and signs `HANDFEST v1` mandates in an external terminal (`handfest keygen`, `handfest fmt`, `handfest sign`). Private signing keys never enter Codex config, environment, or workspace.
- **Deterministic gate (`handfest-mcp`):** Intercepts MCP stdio JSON-RPC 2.0 traffic between Codex and the upstream MCP server:
  - Filters `tools/list` so unmapped or ungranted tools are never advertised to the model.
  - Maps `tools/call` payloads through `ToolPolicyMap` (`plugins/policy-map.example.json`) with operator-supplied `static_facts` overriding model arguments and host UTC clock supplying `context.time`.
  - Evaluates the full mandate chain (`handfest-core`), atomically updates chain-wide quotas, and appends a hash-chained `DecisionReceipt` to `handfest-ledger`.
  - Returns JSON-RPC error `-32001` on `Deny` without invoking the upstream tool.

## Setup

1. Ensure `handfest` and `handfest-mcp` are on your `PATH`.
2. Out-of-band (human terminal), generate keys and sign a mandate:
   ```bash
   handfest keygen --out ~/.handfest/human.key.json
   handfest keygen --out ~/.handfest/codex-agent.key.json
   handfest fmt mandate.hf
   handfest sign \
     --mandate mandate.hf \
     --key ~/.handfest/human.key.json \
     --valid-from 2026-11-24T17:00:00Z \
     --valid-until 2026-11-25T01:00:00Z \
     --out /path/to/mandates/root.signed.json
   ```
3. Copy `plugins/policy-map.example.json` and map each admitted MCP tool to its `HANDFEST v1` `(action, resource_kind, resource_id, facts)`.
4. Merge [`config.example.toml`](config.example.toml) into `~/.codex/config.toml` (or project `.codex/config.toml`) with your real `--chain`, `--ledger`, `--actor-key` (public `ed25519:<hex>`), and `--policy-map` paths.
   - For multi-hop delegation chains, pass ordered files after `--chain` (root first, leaf last):
     `"--chain", "/path/to/root.signed.json", "/path/to/leaf.signed.json"`.

## Audit

Verify ledger integrity and inspect Codex's track record at any time (read-only):

```bash
handfest audit \
  --ledger /path/to/state/handfest-ledger.sqlite \
  --actor-key ed25519:<agent-public-key-hex>
```
