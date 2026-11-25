# Handfest Plugin for `dsh`

This plugin wraps upstream MCP servers in `dsh` behind `handfest-mcp` so every tool call is authorized deterministically against a signed `HANDFEST v1` mandate chain outside the model.

## Trust Boundary

- **Human principal (out-of-band):** Reviews canonical `HANDFEST v1` text (`handfest fmt`) and signs it with their private key (`handfest sign`) outside `dsh`. Private keys never enter `dsh` config or agent context.
- **Deterministic proxy (`handfest-mcp`):** Wraps each upstream MCP server over stdio JSON-RPC 2.0, filters ungranted tools from `tools/list`, enforces `ToolPolicyMap` + mandate chain + atomic quotas on `tools/call`, records every `Permit` and `Deny` in the hash-chained SQLite ledger, and fails closed (`-32001`) on any violation.

## Setup

1. Ensure `handfest` (`crates/handfest-cli` on `main`) and `handfest-mcp` (planned `crates/handfest-mcp`, not yet shipped in this workspace) are installed and on `PATH`.
2. Out-of-band, create keys and sign a `HANDFEST v1` mandate for your `dsh` agent's public `KeyId`:
   ```bash
   handfest keygen --out ~/.handfest/human.key.json
   handfest keygen --out ~/.handfest/dsh-agent.key.json
   handfest fmt mandate.hf
   handfest sign \
     --mandate mandate.hf \
     --key ~/.handfest/human.key.json \
     --valid-from 2026-11-24T17:00:00Z \
     --valid-until 2026-11-25T01:00:00Z \
     --out /path/to/mandates/root.signed.json
   ```
3. Copy `plugins/policy-map.example.json` outside the agent-writable workspace (e.g. `/path/to/handfest-config/policy-map.json`) and map each admitted upstream MCP tool to `(action, resource_kind, resource_id, facts)`.
4. Copy [`mcp.example.json`](mcp.example.json) into your `dsh` MCP configuration and replace the placeholder paths and public `--actor-key`.
   - For attenuated multi-hop chains, list all signed mandate files after `--chain` in root-to-leaf order.

## Audit

Verify the SQLite receipt hash chain and review the agent's track record (read-only):

```bash
handfest audit \
  --ledger /path/to/state/handfest-ledger.sqlite \
  --actor-key ed25519:<agent-public-key-hex>
```
