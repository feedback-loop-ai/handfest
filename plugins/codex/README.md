# Handfest Plugin for Codex

This plugin configures OpenAI Codex to route MCP tool calls through `handfest-mcp`, enforcing signed `HANDFEST v1` mandates and revocations deterministically outside the model.

## Trust Boundary

- **Out-of-band principal:** Bootstraps `~/.handfest` (`handfest init`), inspects public KeyIds (`handfest keyid`), signs mandates (`handfest sign`), and issues emergency revocations (`handfest revoke`) in an external terminal. Private signing keys never enter Codex config, environment, or workspace.
- **Public profile only:** Codex's `/handfest` skill (`~/.codex/skills/handfest/SKILL.md`) reads `~/.handfest/profile.json` (`0644`, public `KeyId`s only) when drafting mandates — never private keys.
- **Deterministic gate (`handfest-mcp`):** Intercepts MCP stdio JSON-RPC 2.0 traffic between Codex and the upstream MCP server:
  - Filters `tools/list` so unmapped or ungranted tools are never advertised to the model.
  - Maps `tools/call` payloads through `ToolPolicyMap` (`~/.handfest/policy-map.json`) with operator-supplied `static_facts` overriding model arguments and host UTC clock supplying `context.time`.
  - Evaluates the full mandate chain and ledger revocations (`handfest-core`), atomically updates chain-wide quotas, and appends a hash-chained `DecisionReceipt` to `handfest-ledger`.
  - Returns JSON-RPC error `-32001` on `Deny` without invoking the upstream tool.

## Setup

1. Ensure `handfest` (`crates/handfest-cli`) and `handfest-mcp` (`crates/handfest-mcp`, built with `cargo build --release -p handfest-mcp`) are on your `PATH`.
2. Install `/handfest` skill and localized templates:
   ```bash
   ./plugins/install.sh
   ```
3. Out-of-band (human terminal), inspect your public `KeyId` and bootstrap `~/.handfest` with any YubiKey interface (or local key):
   ```bash
   # Derive public KeyId (pick one):
   handfest keyid --ssh-key ~/.ssh/id_ed25519_sk.pub
   handfest keyid --fido2-cred ~/.handfest/yubikey.fido2.json
   handfest keyid --gpg-key <40-hex-fingerprint>
   handfest keyid --piv-pubkey ~/.handfest/yubikey-9c.pem
   handfest keyid --key ~/.handfest/human.key.json

   # Bootstrap ~/.handfest (creates 0700 dir, ledger, 0600 agent.key.json, public-only profile.json):
   handfest init --principal-name "Valentin" --agent-name "codex" --ssh-key ~/.ssh/id_ed25519_sk.pub
   ```
4. Draft and canonicalize a mandate (`handfest fmt mandate.hf`), then sign out-of-band using your chosen signer flag (`--ssh-key`, `--fido2-cred`, `--gpg-key`, `--piv-pubkey`, or `--key`):
   ```bash
   handfest sign \
     --mandate ~/.handfest/mandates/draft.hf \
     --ssh-key ~/.ssh/id_ed25519_sk.pub \
     --valid-from 2026-11-24T17:00:00Z \
     --valid-until 2026-11-25T01:00:00Z \
     --out ~/.handfest/mandates/root.signed.json
   ```
5. Review `~/.handfest/policy-map.json` and merge `~/.handfest/templates/codex-config.toml` into `~/.codex/config.toml` (or `.codex/config.toml`), replacing `ed25519:<agent-public-key-hex>` with `agent_key_id` from `~/.handfest/profile.json`.
   - For multi-hop delegation chains, pass ordered files after `--chain` (root first, leaf last):
     `"--chain", "/home/you/.handfest/mandates/root.signed.json", "/home/you/.handfest/mandates/leaf.signed.json"`.

## Out-of-Band Kill Switch & Audit

Revoke a mandate or agent key immediately from your human terminal:

```bash
handfest revoke \
  --mandate ~/.handfest/mandates/root.signed.json \
  --effective now \
  --reason "operator kill-switch" \
  --ssh-key ~/.ssh/id_ed25519_sk.pub \
  --ledger ~/.handfest/state/handfest-ledger.sqlite
```

Verify ledger integrity and inspect Codex's track record at any time (read-only):

```bash
handfest audit \
  --ledger ~/.handfest/state/handfest-ledger.sqlite \
  --actor-key ed25519:<agent-public-key-hex>
```
