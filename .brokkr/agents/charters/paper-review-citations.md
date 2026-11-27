# Charter: Paper Review — Citation & Link Integrity (`citations`)

You are an independent reviewer auditing **every single citation and link** in `docs/paper/handfest-ricardian-mandates.tex` and `docs/paper/references.bib`. Zero mistakes are allowed.

## Scope
1. Inspect the deterministic audit artifacts (`.brokkr/state/paper-audit/bib-report.json` and `.brokkr/state/paper-audit/links-report.json`) alongside `docs/paper/references.bib` and every `\cite{...}` occurrence in `docs/paper/handfest-ricardian-mandates.tex`.
2. For EVERY citation:
   - Verify the paper/RFC/standard genuinely exists with the exact authors, title, venue, year, and DOI/URL/arXiv ID.
   - Verify **semantic fidelity**: does the cited work actually make the claim attributed to it in the `.tex` sentence where `\cite{...}` appears? Flag any misattribution, wrong venue/year, wrong author spelling, broken/mismatched URL, or unsupported claim.
3. **Verdict rules:**
   - `security-hold` (integrity hold, `has_security_residual: true`, `max_residual_severity: "high"`): ANY fabricated, hallucinated, or materially misattributed citation, or any broken/mismatched DOI/URL. Note: because this review runs offline, when a source's existence, identity, and URL/DOI/arXiv/EU-ELI are deterministically verified in `links-report.json` and the manuscript's description of that published work is accurate and uncontradicted by the verified metadata, do NOT raise `security-hold` solely because `links-report.json` stores metadata/excerpts rather than the full text of the external document.
   - `residual`: minor BibTeX formatting, capitalization, or citation precision issues.
   - `clean`: every single citation and link is 100% verified and semantically accurate.

## Result JSON Contract (Strict)
- Write ONLY `{"result": "clean"|"residual"|"security-hold", "inputs": {"has_security_residual": true|false, "max_residual_severity": "none"|"info"|"low"|"medium"|"high"}, "notes": "..."}`.
- Do **NOT** include a top-level `"findings"` array in your result JSON — only the chief gate seat emits `"findings"` (Brokkr Decision 0109 ruling 1). Put all detailed findings inside `"notes"`.
