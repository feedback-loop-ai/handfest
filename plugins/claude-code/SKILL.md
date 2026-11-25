---
name: handfest
description: Draft canonical HANDFEST v1 mandates, format them with `handfest fmt` for WYSIWYS human review, hand off out-of-band signing, verify delegation chains, and inspect audit trails with `handfest audit`.
---

# `/handfest` — Ricardian Mandate Drafting & Audit Skill (Claude Code)

Use this skill to help a human principal draft, format, verify, and audit `HANDFEST v1` mandates.

## Hard Security Boundary (Non-Negotiable)

1. **Never hold, read, request, or touch private signing keys.** The human principal's private key (`*.key.json`) must stay strictly outside the workspace, prompt context, and agent environment. Never run `handfest sign` with the human's root key.
2. **Never decide `Permit` or `Deny` in prose.** Runtime authorization happens deterministically outside the model — via `plugins/claude-code/hooks/pre-tool-use.sh` (`handfest check`) or the `handfest-mcp` stdio proxy.
3. **Always show canonical WYSIWYS text.** Before handing a mandate to the human for signing, run `handfest fmt <file>` so the human reviews the exact canonical text whose SHA-256 digest is signed.

## Workflows

### 1. Draft a `HANDFEST v1` Mandate

Write a draft `.hf` file conforming to `specs/grammar.ebnf`:

```text
HANDFEST v1
FROM human "<principal>" (key: ed25519:<principal-pub-hex>)
TO agent "<agent-name>" (key: ed25519:<agent-pub-hex>)
DELEGATION max 0 hops
ALLOW git.pr.merge
ON repo "org/repo"
WHERE context.time >= 2026-11-24T17:00:00Z
  AND context.time < 2026-11-25T01:00:00Z
  AND resource.author == "<principal>"
  AND resource.ci_status == "passing"
LIMIT 5 calls
```

Ask the human for:
- Principal name and public `KeyId` (`ed25519:<hex>`)
- Target agent name and public `KeyId`
- Exact actions (`ALLOW`), resource globs (`ON`), time window and predicates (`WHERE`), hop ceiling (`DELEGATION max N hop(s)`), and quotas (`LIMIT`)

### 2. Canonicalize for WYSIWYS Review

Run:

```bash
handfest fmt draft.hf
```

Present the exact stdout verbatim to the human principal so they verify every clause before signing.

### 3. Out-of-Band Human Signing Handoff

Do **not** sign on the human's behalf. Print the exact command for the human to run in their own terminal where their private key lives:

```bash
handfest sign \
  --mandate draft.hf \
  --key /path/to/human.key.json \
  --valid-from 2026-11-24T17:00:00Z \
  --valid-until 2026-11-25T01:00:00Z \
  --out root.signed.json
```

### 4. Verify a Signed Chain

Once the human provides the signed JSON envelope(s), verify signatures and monotonic lattice attenuation:

```bash
handfest verify root.signed.json [leaf.signed.json ...]
```

### 5. Inspect Receipts & Track Record

Verify hash-chain integrity of the SQLite ledger (read-only) and optionally inspect an actor's track record:

```bash
handfest audit --ledger /path/to/handfest-ledger.sqlite
handfest audit --ledger /path/to/handfest-ledger.sqlite --actor-key ed25519:<agent-pub-hex>
```
