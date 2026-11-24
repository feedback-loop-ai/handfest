# Handfest Architecture

## Design Invariants

1. **Functional core, imperative shell:** `handfest-core` performs no I/O, no clock reads, no randomness, and no network access. Timestamps, trust-anchor snapshots, verified facts, and prior quota counts enter as pure arguments so every authorization ruling replays byte-for-byte.
2. **Canonical WYSIWYS bijection:** Every `HandfestAst` has one canonical Controlled-English rendering (`HANDFEST v1`), and `render(parse(canon)) == canon`. Signers always sign the exact canonical text whose digest locks the AST.
3. **Monotonic lattice attenuation:** Every sub-mandate (`PARENT sha256:...`) must satisfy `subsumes(parent, child)`:
   - `child.from.key == parent.to.key`
   - `parent.max_hops >= 1` and `child.max_hops <= parent.max_hops - 1`
   - `child.allow <= parent.allow` and `child.on <= parent.on`
   - Every `parent.where` predicate is implied by `child.where`
   - `child.limit <= parent.limit`, with runtime usage incremented atomically across every mandate in the chain.
4. **Interchangeable trust anchors:** External identity and signature systems (Ed25519/OpenSSH, crypto wallets, Passkeys, EUDI `SD-JWT VC`/`mdoc`, eIDAS ETSI TS 119 612 QES) live in `handfest-anchors` and normalize into `VerifiedAnchorProof`.
5. **Verifiable track record:** Every `Permit` or `Deny` ruling produces a hash-chained `DecisionReceipt` in `handfest-ledger`, enabling deterministic audit replay and actor track-record projections.

## Roadmap

- **Slice 1 (`v0.1`):** `handfest-core` (parser, canonical formatter, lattice checker, chain evaluator, receipt types), `handfest-ledger` (SQLite/JSONL), Ed25519/OpenSSH anchor, `handfest-cli`.
- **Slice 2 (`v0.2`):** `handfest-mcp` proxy/middleware + Brokkr capability broker integration.
- **Slice 3 (`v0.3`):** WebAuthn Passkeys, EIP-191/712 wallets, optional `handfest-cedar` bridge.
- **Slice 4 (`v0.4`):** EUDI `SD-JWT VC` / `mdoc` + ETSI TS 119 612 EU LOTL / JAdES QES verification.
