# Handfest Plugin for `dsh`

This plugin wraps upstream MCP servers in `dsh` behind `handfest-mcp` so every tool call is authorized deterministically against a signed `HANDFEST v1` mandate chain and revocation ledger outside the model.

## Trust Boundary

- **Human principal (out-of-band):** Bootstraps `~/.handfest` (`handfest init`), inspects public KeyIds (`handfest keyid`), reviews canonical `HANDFEST v1` text (`handfest fmt`), signs with a YubiKey or local key (`handfest sign`), and issues emergency revocations (`handfest revoke`) outside `dsh`. Private keys never enter `dsh` config or agent context.
- **Public profile only:** `~/.handfest/profile.json` (`0644`) exposes only public `KeyId`s and non-secret paths.
- **Deterministic proxy (`handfest-mcp`):** Wraps each upstream MCP server over stdio JSON-RPC 2.0, filters ungranted tools from `tools/list`, enforces `ToolPolicyMap` + mandate chain + revocations + atomic quotas on `tools/call`, records every `Permit` and `Deny` in the hash-chained SQLite ledger, and fails closed (`-32001`) on any violation.

## Setup

1. Ensure `handfest` (`crates/handfest-cli`) and `handfest-mcp` (`crates/handfest-mcp`, built with `cargo build --release -p handfest-mcp`) are installed and on `PATH`.
2. Install localized templates:
   ```bash
   ./plugins/install.sh
   ```
3. Out-of-band, inspect your public `KeyId` (`handfest keyid`) and bootstrap `~/.handfest` with any of the 4 YubiKey interfaces (`--ssh-key`, `--fido2-cred`, `--gpg-key`, `--piv-pubkey`) or a local key (`--key`):
   ```bash
   handfest keyid --ssh-key ~/.ssh/id_ed25519_sk.pub
   handfest keyid --fido2-cred ~/.handfest/yubikey.fido2.json
   handfest keyid --gpg-key <40-hex-fingerprint>
   handfest keyid --piv-pubkey ~/.handfest/yubikey-9c.pem
   handfest keyid --key ~/.handfest/human.key.json

   handfest init --principal-name "Valentin" --agent-name "dsh" --ssh-key ~/.ssh/id_ed25519_sk.pub
   ```
4. Canonicalize and sign a `HANDFEST v1` mandate for your `dsh` agent's public `agent_key_id` from `~/.handfest/profile.json`:
   ```bash
   handfest fmt ~/.handfest/mandates/draft.hf
   handfest sign \
     --mandate ~/.handfest/mandates/draft.hf \
     --ssh-key ~/.ssh/id_ed25519_sk.pub \
     --valid-from 2026-11-24T17:00:00Z \
     --valid-until 2026-11-25T01:00:00Z \
     --out ~/.handfest/mandates/root.signed.json
   ```
5. Review `~/.handfest/policy-map.json`, then copy `~/.handfest/templates/dsh-mcp.json` into your `dsh` MCP configuration and replace `ed25519:<agent-public-key-hex>` with `agent_key_id` from `~/.handfest/profile.json`.
   - For attenuated multi-hop chains, list all signed mandate files after `--chain` in root-to-leaf order.

## Out-of-Band Kill Switch & Audit

Revoke a signed mandate or agent key immediately from your human terminal:

```bash
handfest revoke \
  --mandate ~/.handfest/mandates/root.signed.json \
  --effective now \
  --reason "operator kill-switch" \
  --ssh-key ~/.ssh/id_ed25519_sk.pub \
  --ledger ~/.handfest/state/handfest-ledger.sqlite
```

Verify the SQLite receipt hash chain and review the agent's track record (read-only):

```bash
handfest audit \
  --ledger ~/.handfest/state/handfest-ledger.sqlite \
  --actor-key ed25519:<agent-public-key-hex>
```
