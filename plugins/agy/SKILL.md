---
name: handfest
description: Draft canonical HANDFEST v1 mandates, format them with `handfest fmt` for WYSIWYS human review, hand off out-of-band signing, verify delegation chains, and inspect audit trails with `handfest audit`.
---

# `/handfest` — Ricardian Mandate Drafting & Audit Skill (Antigravity / `agy`)

Use this skill to help a human principal draft, canonicalize, verify, and audit `HANDFEST v1` mandates in Antigravity (`agy`).

## Hard Security Boundary (Non-Negotiable)

1. **Never access, read, request, or store private signing keys.** The principal's signing key stays strictly outside the agent workspace and conversation context. Never invoke `handfest sign` with a human root key.
2. **Never make allow/deny rulings in prose.** Tool authorization is enforced deterministically outside the model by `handfest-mcp` (configured via `mcp.example.json`) or an external broker invoking `handfest-core`.
3. **Canonical WYSIWYS first.** Always run `handfest fmt` on every drafted mandate and present its exact canonical output to the principal before signing.

## Workflows

### 1. Draft a `HANDFEST v1` Mandate

Gather the principal's public `KeyId`, the agent's public `KeyId`, allowed actions, resource globs, time bounds, predicates, hop limit, and quotas, then write a `.hf` draft matching `specs/grammar.ebnf`:

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

> Dynamic predicates (such as `resource.ci_status`) must be queried and injected by a trusted broker outside the model — never hardcode dynamic runtime state in `static_facts`.

### 2. Canonicalize for WYSIWYS Review

```bash
handfest fmt draft.hf
```

Show the formatted text verbatim to the principal. Because `render(parse(text)) == text`, the words displayed are byte-for-byte identical to what will be signed.

### 3. Out-of-Band Human Signing Handoff

Instruct the principal to sign out-of-band in their own terminal:

```bash
handfest sign \
  --mandate draft.hf \
  --key /path/to/human.key.json \
  --valid-from 2026-11-24T17:00:00Z \
  --valid-until 2026-11-25T01:00:00Z \
  --out root.signed.json
```

### 4. Verify & Audit (Read-Only)

Verify a signed chain (signatures + lattice narrowing):

```bash
handfest verify root.signed.json [leaf.signed.json ...]
```

Verify ledger hash-chain integrity and inspect an actor's track record:

```bash
handfest audit --ledger /path/to/handfest-ledger.sqlite
handfest audit --ledger /path/to/handfest-ledger.sqlite --actor-key ed25519:<agent-pub-hex>
```
