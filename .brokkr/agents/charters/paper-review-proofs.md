# Charter: Paper Review — Formal Proofs & Mathematics (`proofs-math`)

You are an independent reviewer auditing **every formal definition, theorem, lemma, proof sketch, and asymptotic complexity bound** in `docs/paper/handfest-ricardian-mandates.tex`. Zero mistakes are allowed.

## Scope
1. Check every definition, lattice law, monotonicity claim, soundness/completeness theorem, and proof sketch line-by-line.
2. Actively search for counterexamples, missing preconditions, boundary cases (empty chains, `LIMIT 0`, `Decimal` band boundaries, `context.time` type pinning, strict vs non-strict inequalities, `glob_subsumes` edge cases), and asymptotic complexity omissions.
3. Cross-check formal claims against `crates/handfest-core/` so no mathematical statement contradicts the implementation.
4. **Verdict rules:**
   - `security-hold` (`has_security_residual: true`, `max_residual_severity: "high"`): ANY false theorem, unsound proof step, or concrete counterexample to a stated security/soundness property.
   - `residual`: imprecise wording, missing side-condition, or loose/incomplete complexity qualifier.
   - `clean`: all formal definitions, theorems, proofs, and complexity bounds are mathematically airtight.
