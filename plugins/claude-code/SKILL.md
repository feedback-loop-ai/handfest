---
name: handfest
description: Draft canonical HANDFEST v1 mandates using public KeyIds from ~/.handfest/profile.json, format them with `handfest fmt` for WYSIWYS human review, hand off out-of-band YubiKey/local signing or `handfest revoke` kill-switch commands, verify delegation chains, and inspect audit trails with `handfest audit`.
---

# `/handfest` — Ricardian Mandate Drafting & Audit Skill (Claude Code)

Use this skill to help a human principal draft, format, verify, and audit `HANDFEST v1` mandates.

## Hard Security Boundary (Non-Negotiable)

1. **Never hold, read, request, or touch private signing keys or PINs.** The human principal's private key (`*.key.json`, SSH private handles, GPG secret keys, PIV PINs) and `agent.key.json` must stay strictly outside the workspace, prompt context, and agent environment. Never run `handfest sign` or `handfest revoke` with the human's root key.
2. **Read public metadata only (`~/.handfest/profile.json`).** When `~/.handfest/profile.json` is present, read it (read-only) to automatically populate `principal_name`, `principal_key_id`, `signer_kind`, `signer_hint`, `agent_name`, `agent_key_id`, `mandates_dir`, `ledger_path`, and `policy_map_path`. Never open `agent.key.json` or any secret key file.
3. **Never decide `Permit` or `Deny` in prose.** Runtime authorization happens deterministically outside the model — via `pre-tool-use.sh` (`handfest check`) or the `handfest-mcp` stdio proxy.
4. **Always show canonical WYSIWYS text.** Before handing a mandate to the human for signing, run `handfest fmt <file>` so the human reviews the exact canonical text bound alongside envelope metadata (`anchor_id`, `assurance`, `actor_kind`, `signer_key`, `valid_from`, `valid_until`) into the domain-separated signing payload.

## Workflows

### 0. One-Time Out-of-Band Setup (Human Terminal Only)

If `~/.handfest/profile.json` does not exist yet, instruct the human principal to derive their public `KeyId` and bootstrap `~/.handfest` out-of-band:

```bash
# Inspect public KeyId for any of the 4 YubiKey interfaces (or local Ed25519 key):
handfest keyid --ssh-key ~/.ssh/id_ed25519_sk.pub
handfest keyid --fido2-cred ~/.handfest/yubikey.fido2.json
handfest keyid --gpg-key <40-hex-fingerprint>
handfest keyid --piv-pubkey ~/.handfest/yubikey-9c.pem
handfest keyid --key ~/.handfest/human.key.json

# Bootstrap ~/.handfest (creates 0700 dir, initialized ledger, 0600 agent.key.json, public-only 0644 profile.json):
handfest init --principal-name "<principal>" --ssh-key ~/.ssh/id_ed25519_sk.pub
```

### 1. Draft a `HANDFEST v1` Mandate

Read `~/.handfest/profile.json` first (if present) so you do not have to ask the human to paste public KeyIds. Write a draft `.hf` file conforming to `specs/grammar.ebnf`:

```text
HANDFEST v1
FROM human "<principal>" (key: ed25519:<principal-pub-hex>)
TO agent "<agent-name>" (key: ed25519:<agent-pub-hex>)
DELEGATION max 0 hops
ALLOW git.pr.merge
ON repo "handfest"
WHERE context.time >= 2026-11-24T17:00:00Z
  AND context.time < 2026-11-25T01:00:00Z
  AND resource.owner == "feedback-loop-ai"
  AND resource.environment == "staging"
  AND resource.pr >= 1
LIMIT 5 calls
```

> Replace `ed25519:<principal-pub-hex>` with the principal's actual `principal_key_id` from `~/.handfest/profile.json` (`ssh-sk-ed25519:<hex>`, `fido2-ed25519:<hex>`, `openpgp-ed25519:<hex>`, `piv-ed25519:<hex>`, or `ed25519:<hex>`).
> Dynamic predicates (such as `resource.ci_status`) must be queried and injected by a trusted broker outside the model — never hardcode dynamic runtime state in `static_facts`.

Confirm with the human:
- Principal name and public `KeyId` (pre-filled from `~/.handfest/profile.json` when available)
- Target agent name and public `KeyId` (pre-filled from `~/.handfest/profile.json` when available)
- Exact actions (`ALLOW`), resource globs (`ON`), time window and predicates (`WHERE`), hop ceiling (`DELEGATION max N hop(s)`), and quotas (`LIMIT`)

### 2. Canonicalize for WYSIWYS Review

Run:

```bash
handfest fmt draft.hf
```

Present the exact stdout verbatim to the human principal so they verify every clause before signing.

### 3. Out-of-Band Human Signing Handoff

Do **not** sign on the human's behalf. Print the exact command matching `signer_kind` and `signer_hint` from `~/.handfest/profile.json` for the human to run in their own terminal:

```bash
# YubiKey OpenSSH FIDO2 (`ssh-sk`):
handfest sign --mandate draft.hf --ssh-key ~/.ssh/id_ed25519_sk.pub \
  --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z \
  --out ~/.handfest/mandates/root.signed.json

# YubiKey FIDO2/CTAP2 (`fido2`):
handfest sign --mandate draft.hf --fido2-cred ~/.handfest/yubikey.fido2.json \
  --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z \
  --out ~/.handfest/mandates/root.signed.json

# YubiKey OpenPGP smartcard (`openpgp`):
handfest sign --mandate draft.hf --gpg-key <40-hex-fingerprint> \
  --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z \
  --out ~/.handfest/mandates/root.signed.json

# YubiKey PIV slot 9c (`piv`):
handfest sign --mandate draft.hf --piv-pubkey ~/.handfest/yubikey-9c.pem \
  --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z \
  --out ~/.handfest/mandates/root.signed.json

# Local software Ed25519 key (`local-ed25519`):
handfest sign --mandate draft.hf --key ~/.handfest/human.key.json \
  --valid-from 2026-11-24T17:00:00Z --valid-until 2026-11-25T01:00:00Z \
  --out ~/.handfest/mandates/root.signed.json
```

### 4. Out-of-Band Kill Switch (`handfest revoke`)

When the human principal wants to revoke a mandate or an entire agent key immediately, print the exact out-of-band `handfest revoke` command matching their `signer_kind` / `signer_hint` (never run it with the principal's key inside Claude Code):

```bash
# Revoke a signed mandate and persist it directly in the ledger:
handfest revoke \
  --mandate ~/.handfest/mandates/root.signed.json \
  --effective now \
  --reason "operator kill-switch" \
  --ssh-key ~/.ssh/id_ed25519_sk.pub \
  --ledger ~/.handfest/state/handfest-ledger.sqlite \
  --out ~/.handfest/mandates/root.revoked.json

# Or revoke an agent's KeyId across chains rooted at this principal (or self-revoked by the agent):
handfest revoke \
  --target-key ed25519:<agent-pub-hex> \
  --effective now \
  --reason "agent key retired" \
  --ssh-key ~/.ssh/id_ed25519_sk.pub \
  --ledger ~/.handfest/state/handfest-ledger.sqlite
```

### 5. Verify a Signed Chain

Once the human provides the signed JSON envelope(s), verify signatures, monotonic lattice attenuation, and persisted ledger revocations:

```bash
handfest verify ~/.handfest/mandates/root.signed.json --ledger ~/.handfest/state/handfest-ledger.sqlite
```

### 6. Inspect Receipts & Track Record

Verify hash-chain integrity of the SQLite ledger (read-only) and optionally inspect an actor's track record:

```bash
handfest audit --ledger ~/.handfest/state/handfest-ledger.sqlite
handfest audit --ledger ~/.handfest/state/handfest-ledger.sqlite --actor-key ed25519:<agent-pub-hex>
```
