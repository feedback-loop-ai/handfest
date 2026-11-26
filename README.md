# Handfest

[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![rust](https://img.shields.io/badge/rust-1.88%2B-orange)](Cargo.toml)

**Executable Ricardian mandates for humans, organizations, and AI agents.**

From Old Norse *handfæstning* — the written charter a ruler signed before taking office, fixing in plain words the exact bounds of granted power.

`handfest` lets a principal vest bounded authority in another actor — human, service, or autonomous AI agent — **in structured plain English**, backed by **pluggable cryptographic trust anchors** (local/SSH keys, crypto wallets, Passkeys, EUDI Wallets, eIDAS QES), enforced by a **pure deterministic gate**, and recorded in a **hash-chained receipt ledger** that builds a verifiable track record.

## Architecture at a Glance

```text
====================================================================================================
  1. INTENT & SIGNING (WYSIWYS)                 2. MONOTONIC ATTENUATION (LATTICE)
====================================================================================================

  +-----------------------------------+         +-----------------------------------+
  |  Principal (Human / Org)          |         |  Orchestrator (e.g. Brokkr)       |
  |  "Merge my passing PRs for 8h,    |         |  Verifies M0, then narrows to     |
  |   at most 5 calls"                |         |  ephemeral per-seat mandate M1:   |
  +-----------------+-----------------+         |                                   |
                    |                           |  HANDFEST v1                      |
                    v  1:1 canonical bijection  |  PARENT sha256:8f4e...            |
  +-----------------------------------+         |  FROM agent "brokkr:dispatcher"   |
  |  HANDFEST v1 (Canonical Text)     |         |  TO   agent "brokkr:seat:ship"    |
  |  FROM human "valentin" (key: ...) |         |  DELEGATION max 0 hops            |
  |  TO   agent "brokkr:dispatcher"   |         |  ALLOW git.pr.merge               |
  |  DELEGATION max 1 hop             |         |  ON repo "feedback-loop-ai/..."   |
  |  ALLOW git.pr.merge               |  =====> |  WHERE pr == 492 AND 3m window    |
  |  ON repo "feedback-loop-ai/*"     |  sub-   |  LIMIT 1 call                     |
  |  WHERE author=="valentin" & 8h    |  sumes  +-----------------+-----------------+
  |  LIMIT 5 calls                    | (pure                     |
  +-----------------+-----------------+  Rust,                    |  Signed Chain [M0 -> M1]
                    |                    no SMT)                  v
                    v  signed by ANY Trust Anchor
  +---------------------------------------------------------------------------------+
  |  handfest-anchors (Pluggable Trust Anchors -> normalized VerifiedAnchorProof)   |
  |  [x] Ed25519 / local keys   [ ] Passkeys & EIP-712 Wallets                      |
  |  [ ] EUDI SD-JWT VC         [ ] eIDAS QES / QSeal (ETSI TS 119 612 EU LOTL)     |
  +---------------------------------------------------------------------------------+

====================================================================================================
  3. DETERMINISTIC ENFORCEMENT & AUDITABLE TRACK RECORD (OUTSIDE THE MODEL)
====================================================================================================

  +-------------------------+    MCP stdio JSON-RPC     +-----------------------------------+
  |  AI Model / Agent Seat  | ------------------------> |  handfest-mcp  (or Brokkr Broker) |
  |  (Claude / Codex / Agy) |   tools/list (filtered)   |  - Hides ungranted tools          |
  |  - Never holds root key |   tools/call (intercepted)|  - Supplies broker VerifiedFacts  |
  |  - Prompt-injected text | <------------------------ |    & host Clock (model can't spoof|
  |    cannot widen M0->M1  |   Permit -> forward       |    author, CI status, or time)    |
  +-------------------------+   Deny   -> -32001 error  +-----------------+-----------------+
                                (upstream NEVER called)                   |
                                                                          v
  +-----------------------------------------------------------------------------------------+
  |  handfest-core::authorize()  (PURE #![no_std], zero I/O, zero clock, zero unsafe)       |
  |  1. Verify every hop signature + ActorKind + valid window + subsumes(M_i, M_{i+1})      |
  |  2. Evaluate EVERY mandate in chain in conjunction (M0 && M1 && ...)                    |
  |  3. Check chain-wide quotas (anti-splitting: M0=5 calls caps ALL children combined)     |
  +-----------------------------------+-----------------------------------------------------+
                                      |
             +------------------------+------------------------+
             | Verdict::Permit                                 | Verdict::Deny { reason }
             v                                                 v
  +-------------------------+                       +---------------------------------------+
  | Forward to Upstream MCP |                       |  handfest-ledger (SQLite, WAL mode)   |
  | (GitHub, Cloud, Bank,   |                       |  - Single IMMEDIATE transaction:      |
  |  Filesystem, etc.)      |                       |    * Atomic chain-wide quota update   |
  +-------------------------+                       |    * Append hash-chained Receipt      |
                                                    |      (prev_hash -> SHA-256 knot)      |
                                                    |  - handfest audit (read-only):        |
                                                    |    * Byte-for-byte replay & tamper    |
                                                    |      detection + Actor TrackRecord    |
                                                    +---------------------------------------+
```

### Crate Dependency Graph (Strictly One-Way)

```text
          [ handfest-cli ]      [ handfest-mcp ]
              /   |   \            /   |   \
             /    |    \          /    |    \
            v     |     v        v     |     v
  [ handfest-anchors ]  |  [ handfest-ledger ]
            \           |           /
             \          v          /
              ---> [ handfest-core ] <---   (pure #![no_std], zero I/O)
```

## What a Handfest Looks Like

```text
HANDFEST v1
FROM human "valentin" (key: ed25519:9b1e...44a0, anchor: eidas-qes, github: "valentin")
TO agent "brokkr:dispatcher" (key: ed25519:3c8d...19f2)
DELEGATION max 1 hop
ALLOW git.pr.merge
ON repo "feedback-loop-ai/*"
WHERE context.time >= 2026-11-24T17:10:00Z
  AND context.time <  2026-11-25T01:10:00Z
  AND resource.author == "valentin"
  AND resource.ci_status == "passing"
LIMIT 5 calls
```

* **One artifact, two readings (WYSIWYS):** The canonical English text parses 1:1 into a typed lattice AST and renders back byte-for-byte (`render(parse(text)) == text`). There is no hidden code diverging from the words you signed.
* **Pure monotonic attenuation:** An orchestrator can narrow an 8-hour root mandate down to a 3-minute, single-PR, `max 0 hops` child mandate for an ephemeral agent seat. Containment (`child <= parent`) is proven in pure Rust with zero SMT solvers, and quotas are enforced atomically across the whole chain.
* **Actor-agnostic & anchor-agnostic:** Humans, legal entities, services, and AI agents are all first-class actors. External cryptographic and regulatory trust anchors normalize into one canonical `VerifiedAnchorProof` before reaching `handfest-core`.
* **Deterministic receipts & track record:** Every `Permit` or `Deny` ruling emits a signed, hash-chained `DecisionReceipt` that replays offline byte-for-byte.

## Workspace Layout

* [`crates/handfest-core`](crates/handfest-core) — Pure, `#![no_std]`-capable AST, Controlled-English parser/renderer, lattice narrowing proofs, chain evaluator, and receipt types.
* [`crates/handfest-anchors`](crates/handfest-anchors) — Pluggable verifiers for Ed25519 keys, wallets/Passkeys, EUDI `SD-JWT VC` / `mdoc`, and eIDAS ETSI TS 119 612 QES.
* [`crates/handfest-ledger`](crates/handfest-ledger) — Hash-chained SQLite receipt persistence, atomic chain-wide quota tracking, read-only integrity audit, and actor `TrackRecord` queries.
* [`crates/handfest-cli`](crates/handfest-cli) — Reference CLI (`handfest fmt`, `keygen`, `sign`, `verify`, `check`, `audit`).
* [`specs/`](specs/) — Formal `HANDFEST v1` grammar (`grammar.ebnf`) and architecture specification.
* [`plugins/`](plugins/) — Thin declarative harness integrations (`Claude Code`, `Codex`, `dsh`, `agy`) and deterministic `PreToolUse` hook.

## Concept & Literature: Executable Ricardian Mandates

`handfest` builds on **Ian Grigg's Ricardian Contract** (1996, formalized in 2004) — a single cryptographically hashed artifact that is simultaneously human-readable intent (for principals, wallets, and courts) and machine-parsable structure (for deterministic execution and ledgers), linked by Grigg's *Bow-Tie* hash knot.

Where a *contract* is a bilateral agreement, a **Ricardian Mandate** (from civil-law *mandatum* / Power of Attorney) is unilateral, bounded delegation of authority from a principal to an actor (human, service, or AI agent). Unlike earlier template-based Ricardian systems where prose only parameterized external code, a `HANDFEST v1` mandate compiles **1:1** between canonical Controlled English and a typed meet-semilattice AST — so there is no hidden program that can diverge from the words you signed (*WYSIWYS*).

### Foundational Papers, Standards & Prior Art

* **Ricardian Contracts & The Bow-Tie Model:** Ian Grigg, [*The Ricardian Contract*](https://iang.org/papers/ricardian_contract.html) (IEEE Workshop on Electronic Contracting, 2004).
* **Human-Readable Cryptographic Capability Delegation:** SpruceID, [*ERC-5573: Sign-In with Ethereum Capabilities (ReCaps)*](https://eips.ethereum.org/EIPS/eip-5573) — deterministic English capability rendering inside wallet signing prompts.
* **Offline Monotonic Capability Attenuation:** [*Eclipse Biscuit*](https://www.biscuitsec.org/) — public-key capability tokens with offline attenuation and Datalog checks; [*UCAN (User-Controlled Authorization Networks)*](https://ucan.xyz/).
* **Controlled Natural Language & Computational Law:** Norbert E. Fuchs et al., [*Attempto Controlled English (ACE)*](http://attempto.ifi.uzh.ch/site/) — unambiguous Controlled English compiled 1:1 into formal logic; [*CNCF / AWS Cedar Policy Language*](https://www.cedarpolicy.com/) (formally verified authorization semantics).
* **Trust Anchors, eIDAS 2.0 & Agent Delegation:** [*EU Digital Identity Wallet Architecture and Reference Framework (ARF)*](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/), [*ETSI TS 119 612 (Trusted Lists / LOTL)*](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/), [*W3C Verifiable Credentials Data Model 2.0*](https://www.w3.org/TR/vc-data-model-2.0/), and [*IETF RFC 8693 (OAuth 2.0 Token Exchange / `act` claim)*](https://datatracker.ietf.org/doc/html/rfc8693).

## Status

Active development (`v0.1.0-dev`): `handfest-core`, `handfest-anchors` (Ed25519), `handfest-ledger` (SQLite), and `handfest-cli` are live on `main`, with `handfest-mcp` in progress. See [`specs/architecture.md`](specs/architecture.md) and [`specs/grammar.ebnf`](specs/grammar.ebnf).

## License

Dual-licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
