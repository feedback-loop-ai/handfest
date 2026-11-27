---
name: handfest
description: Draft canonical HANDFEST v1 mandates using public KeyIds from ~/.handfest/profile.json, format them with `handfest fmt` for WYSIWYS human review, hand off out-of-band YubiKey/local signing or `handfest revoke` kill-switch commands, verify delegation chains, and inspect audit trails with `handfest audit`.
---

# `/handfest` — Ricardian Mandate Drafting & Audit Skill (Antigravity / `agy`)

Use this skill to help a human principal draft, canonicalize, verify, and audit `HANDFEST v1` mandates in Antigravity (`agy`).

## Hard Security Boundary (Non-Negotiable)

1. **Never access, read, request, or store private signing keys or PINs.** The principal's signing key (`*.key.json`, SSH private handles, GPG secret keys, PIV PINs) and `agent.key.json` stay strictly outside the agent workspace and conversation context. Never invoke `handfest sign` or `handfest revoke` with a human root key.
2. **Read public metadata only (`~/.handfest/profile.json`).** If `~/.handfest/profile.json` exists, you may read it (read-only) to pre-fill `principal_name`, `principal_key_id`, `signer_kind`, `signer_hint`, `agent_name`, `agent_key_id`, `mandates_dir`, `ledger_path`, and `policy_map_path`. Never open `agent.key.json` or any secret key file.
3. **Never make allow/deny rulings in prose.** Tool authorization is enforced deterministically outside the model by `handfest-mcp` (configured via `mcp.example.json`) or an external broker invoking `handfest-core`.
4. **Canonical WYSIWYS first.** Always run `handfest fmt` on every drafted mandate and present its exact canonical output to the principal before signing.

## Workflows

### 0. One-Time Out-of-Band Setup (Human Terminal Only)

If `~/.handfest/profile.json` does not exist yet, instruct the principal to inspect their public `KeyId` and bootstrap `~/.handfest` out-of-band:

```bash
# Derive public KeyId for any of the 4 YubiKey interfaces (or local Ed25519 key):
handfest keyid --ssh-key ~/.ssh/id_ed25519_sk.pub
handfest keyid --fido2-cred ~/.handfest/yubikey.fido2.json
handfest keyid --gpg-key <40-hex-fingerprint>
handfest keyid --piv-pubkey ~/.handfest/yubikey-9c.pem
handfest keyid --key ~/.handfest/human.key.json

# Bootstrap ~/.handfest (creates 0700 dir, initialized ledger, 0600 agent.key.json, public-only 0644 profile.json):
handfest init --principal-name "<principal>" --ssh-key ~/.ssh/id_ed25519_sk.pub
```

### 1. Draft a `HANDFEST v1` Mandate

Check `~/.handfest/profile.json` first to automatically fill `principal_name`, `principal_key_id`, `agent_name`, and `agent_key_id`. Gather allowed actions, resource globs, time bounds, predicates, hop limit, and quotas, then write a `.hf` draft matching `specs/grammar.ebnf`:

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

### 2. Canonicalize for WYSIWYS Review

```bash
handfest fmt draft.hf
```

Show the formatted text verbatim to the principal. Because `render(parse(text)) == text`, the words displayed are byte-for-byte identical to what will be signed.

### 3. Out-of-Band Human Signing Handoff

Instruct the principal to sign out-of-band in their own terminal using the flag matching `signer_kind` and `signer_hint` in `~/.handfest/profile.json` (one of the 4 YubiKey interfaces or local key):

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

When the principal asks to revoke an active mandate or an entire agent key immediately, print the out-of-band `handfest revoke` command matching their `signer_kind` / `signer_hint` (never execute it with the principal's key inside the harness):

```bash
# Revoke one signed mandate and record it directly into the ledger:
handfest revoke \
  --mandate ~/.handfest/mandates/root.signed.json \
  --effective now \
  --reason "operator kill-switch" \
  --ssh-key ~/.ssh/id_ed25519_sk.pub \
  --ledger ~/.handfest/state/handfest-ledger.sqlite \
  --out ~/.handfest/mandates/root.revoked.json

# Or revoke an agent's public KeyId across chains rooted at this principal (or self-revoked by the agent):
handfest revoke \
  --target-key ed25519:<agent-pub-hex> \
  --effective now \
  --reason "agent key retired" \
  --ssh-key ~/.ssh/id_ed25519_sk.pub \
  --ledger ~/.handfest/state/handfest-ledger.sqlite
```

### 5. Verify & Audit (Read-Only)

Verify a signed chain (signatures + lattice narrowing + persisted ledger revocations):

```bash
handfest verify ~/.handfest/mandates/root.signed.json --ledger ~/.handfest/state/handfest-ledger.sqlite
```

Verify ledger hash-chain integrity and inspect an actor's track record:

```bash
handfest audit --ledger ~/.handfest/state/handfest-ledger.sqlite
handfest audit --ledger ~/.handfest/state/handfest-ledger.sqlite --actor-key ed25519:<agent-pub-hex>
```
