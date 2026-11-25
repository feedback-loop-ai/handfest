# Handfest House Rules

This repository is a permissive (`MIT OR Apache-2.0`) Rust workspace under `crates/`. Every implementer and reviewer seat builds to and judges against these rules.

Tests are part of every change. Leave `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked` green before reporting success. Commit completed work on the branch with `git`; never push.

---

## Architectural Principles

### 1. Sound Abstractions & SOLID (Extensibility Is Core)

`handfest` is a generic authorization library, not a single-vendor tool. Adding a new trust anchor (Passkeys, EIP-712 wallets, EUDI `SD-JWT VC`, eIDAS QES), a new storage backend (Postgres, JSONL), or a new AI harness/tool server (Claude, Codex, Agy, MCP) must be **additive** — implementing one cohesive adapter/module without rewriting `core`, `ledger`, `mcp`, or `cli`.

* **Single Responsibility (S):** Each crate and module owns one clear concern. Keep parsing/wire framing, cryptographic verification, authorization policy, and persistence strictly separated.
* **Open/Closed (O):** Open for extension via clean seams and declarative configuration; closed for modification in core evaluation and consumers.
* **Liskov Substitution (L):** Every implementation of a trait seam (`AnchorVerifier`, `ReceiptLedger`, `Clock`, `FactProvider`) must uphold the exact same fail-closed contract — e.g. any `AnchorVerifier` must authenticate both the canonical mandate text and all envelope metadata, and reject invalid timestamps or assurance spoofing.
* **Interface Segregation (I):** Keep traits small, focused, and cohesive. Do not build "god traits" that bundle unrelated signing, keygen, storage, and display methods.
* **Dependency Inversion (D):** High-level crates (`handfest-cli`, `handfest-mcp`, future brokers) depend on **abstractions** (`AnchorVerifier` / `AnchorRegistry`, `ReceiptLedger`, `Clock`), never on concrete cryptographic schemes (`Ed25519`-only paths) or concrete database internals (`rusqlite` SQL).

### 2. Configuration Over Code

* Never hardcode harness names (`claude`, `codex`, `agy`), specific tool providers (`github`, `jira`), or specific trust roots into business logic.
* Tool-to-action mappings, trusted broker facts, anchor roots, and policy constraints live in **typed, schema-validated configuration data** (`HANDFEST v1` mandates, `ToolPolicyMap` JSON, trust-anchor bundles), parsed once at the boundary into strongly typed structs (`#[serde(deny_unknown_fields)]` where the contract is closed).
* `serde_json::Value` never leaks past the wire/config edge into domain logic, state, or ledger storage.

### 3. Composition Over Inheritance

* Model **closed sets** (`ActorKind`, `AssuranceLevel`, `Verdict`, `PredicateOp`, `Quota`, `NarrowError`) as exhaustive Rust enums matched without catch-all wildcards that hide new variants.
* Model **open extension seams** (`AnchorVerifier`, `ReceiptLedger`, `Clock`) as small composable traits and registries — assemble behaviors by composing pure structs and narrow trait implementations, never deep wrappers or simulated class hierarchies.

### 4. DRY — One Source of Truth

* Every protocol codec, parser, validator, and security invariant has **one home**.
* Never copy-paste nontrivial logic (such as exact lossless JSON decimal/fact parsing, canonical hex validation, or timestamp range checks) across crates. If two crates need the same codec or helper, place it once in the lowest appropriate layer (`handfest-core` or a shared module) and import it.

### 5. YAGNI — Nothing Speculative or Unused

* Add no speculative config flags, dead trait methods, unused enum variants, or `pub` items without a real consumer. Prefer `pub(crate)` unless an item is part of the intentional public crate API.
* Introduce an abstraction only at a genuine architectural seam (trust anchors, ledger storage, time/clock, transport/harness adapters) — never wrap a single internal helper in boilerplate traits.

### 6. CRAP (Change Risk Anti-Patterns) & Complexity Ceilings

High cyclomatic complexity paired with thin test coverage is a design defect:

* **Hard ceilings** (`clippy.toml`): functions `<= 100` lines, nesting depth `<= 5`, parameters `<= 7`, cyclomatic complexity `<= 15`. Production files should stay `<= 800` lines and test files `<= 2,000` lines; split cohesive submodules rather than growing monoliths.
* **Zero `unsafe`:** `#![forbid(unsafe_code)]` workspace-wide.
* **Typed errors:** Use structured error enums (`Display` + `Error`), never `Result<_, String>` across crate boundaries.
* **No silent suppressions:** Never add `#[allow(...)]`; any necessary lint override uses `#[expect(..., reason = "...")]`.
* **Binding, mutation-proved tests:** Assert exact variants and values (never bare `is_err()`). Every security boundary (crypto verification, lattice subsumption, wire framing, quota anti-splitting, audit integrity) must have negative/adversarial tests that fail when the guard is removed.

### 7. Pure Functional Core & Fail-Closed Security

* `handfest-core` is strictly `#![no_std]` + `alloc`: **zero I/O, zero system clock, zero RNG, zero network.** Timestamps, verified anchor proofs, verified facts, and quota snapshots enter as pure arguments so every ruling replays byte-for-byte.
* **Fail closed everywhere:** Ambiguous wire frames (e.g. bare `\r`, `result` + `error` together), missing facts, unknown tools, negative/corrupt quotas, unauthenticated metadata, or non-canonical mandate text must always refuse cleanly.

### 8. AI-Native Implementation

* **First-class actors everywhere:** Humans, organizations, services, and AI agents (`ActorKind::Agent`) are native, equal peers across every crate — never model AI agents as a hacky subtype of human sessions or ambient API keys.
* **Machine-first, human-legible surfaces:** Every CLI response, JSON-RPC refusal, error payload, and receipt must be structured, typed, and unambiguously parseable so both autonomous agents and human auditors can consume it deterministically without scraping prose.

### 9. Deterministic Over Stochastic — Everywhere Possible

* Never put an LLM, heuristic, fuzzy matcher, or stochastic classifier in parsing, canonicalization, signature verification, lattice narrowing, policy evaluation, quota accounting, wire framing, or audit replay.
* Any optional natural-language drafting helper lives strictly *outside* the trust boundary and *before* WYSIWYS signing — once signed, **100% deterministic code** decides every ruling, byte-for-byte replayable offline.

### 10. 100% Test Coverage (On All Levels)

* Hold **100% line and branch coverage across all levels**: unit tests, boundary/property tests, integration tests, adversarial/negative security tests, and end-to-end binary/wire tests.
* Every production guard, error path, and refusal branch must be bound by a test that fails when the guard is mutated or removed. Prefer making invalid states unrepresentable in the type system over leaving unreachable defensive branches; any genuinely unreachable branch must be explicitly justified.

---

## Reviewer Severity Table

Judges (`correctness`, `adversarial`, `chief`) rate findings against these rules using this table:

* **`info`:** Minor style or clarity suggestion already covered by a deterministic gate, or a non-blocking documentation note.
* **`low`:** Function/file over complexity ceiling, unused `pub` item, minor DRY duplication within one module, or a non-security branch lacking a dedicated coverage test.
* **`medium`:** Violation of architectural decoupling (hardcoding concrete `Ed25519`/SQLite/harness logic into a consumer instead of using the abstraction seam), cross-crate DRY duplication (copy-pasting parsers/codecs), untyped `Value` crossing a crate boundary, error matched by message string, stochastic/heuristic logic where a deterministic rule belongs, or an untested security/error branch or test that cannot fail.
* **`high` or `critical` (security-hold):** Any fail-open path, signature/metadata bypass, frame smuggling, quota bypass, tampering undetected by audit, secret permission leak, or weakened refusal boundary.
