# Handfest

[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![rust](https://img.shields.io/badge/rust-1.88%2B-orange)](Cargo.toml)

**Executable Ricardian mandates for humans, organizations, and AI agents.**

From Old Norse *handfæstning* — the written charter a ruler signed before taking office, fixing in plain words the exact bounds of granted power.

`handfest` lets a principal vest bounded authority in another actor — human, service, or autonomous AI agent — **in structured plain English**, backed by **pluggable cryptographic trust anchors** (local/SSH keys, crypto wallets, Passkeys, EUDI Wallets, eIDAS QES), enforced by a **pure deterministic gate**, and recorded in a **hash-chained receipt ledger** that builds a verifiable track record.

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

* [`crates/handfest-core`](crates/handfest-core) — Pure, `no_std`-capable AST, Controlled-English parser/renderer, lattice narrowing proofs, chain evaluator, and receipt types.
* [`crates/handfest-anchors`](crates/handfest-anchors) — Pluggable verifiers for Ed25519/OpenSSH keys, wallets/Passkeys, EUDI `SD-JWT VC` / `mdoc`, and eIDAS ETSI TS 119 612 QES.
* [`crates/handfest-ledger`](crates/handfest-ledger) — Hash-chained receipt persistence, atomic chain-wide quota tracking, and deterministic offline replay / track-record queries.
* [`crates/handfest-cli`](crates/handfest-cli) — Reference CLI (`handfest fmt`, `sign`, `narrow`, `verify`, `audit`).
* [`specs/`](specs/) — Formal `HANDFEST v1` grammar (`grammar.ebnf`) and architecture specification.

## Status

Early scaffolding (`v0.1.0-dev`). See [`specs/architecture.md`](specs/architecture.md) and [`specs/grammar.ebnf`](specs/grammar.ebnf) for the v0.1 design.

## License

Dual-licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
