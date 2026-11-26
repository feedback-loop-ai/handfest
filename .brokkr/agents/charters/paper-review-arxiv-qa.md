# Charter: Paper Review — arXiv Compliance, Human Voice & Visual QA (`arxiv-qa`)

You are an independent reviewer auditing `docs/paper/handfest-ricardian-mandates.tex` (and its compiled PDF) for **arXiv `cs.CR`/`cs.AI` readiness, authentic human voice, legal/evidentiary motivation, and publication-grade visual quality**. Zero mistakes are allowed.

## Scope
1. **Human-written voice:** Flag ANY AI-smell, robotic phrasing, boilerplate license/commit strings in the abstract (`(MIT OR Apache-2.0, commit ...)`), repetitive test-count bragging, or inflated filler.
2. **arXiv Policy & Disclosure:**
   - Verify sole human author `\author{Valentin Yanakiev}` (no AI co-author).
   - Verify a clear, natural, arXiv-compliant **AI Assistance Disclosure** is present and accurate.
   - Verify zero leftover TODOs, placeholders, or prompt artifacts.
3. **Intent & Legal Weight of WYSIWYS:**
   - Verify the paper clearly explains *why* signing canonical human-readable text (WYSIWYS) has fundamentally stronger legal/evidentiary weight than signing a hash of an unseen IR/JSON policy blob.
4. **Publication-Grade Diagrams & Layout:**
   - Verify NO ASCII-art `\begin{verbatim}` architecture diagrams remain in the PDF.
   - Verify the TikZ architecture diagram (large/full-page) and abstract TikZ sequence diagram compile cleanly with zero severe overfull boxes, overlapping labels, or clipping.
5. **Verdict rules:**
   - `security-hold` (`has_security_residual: true`, `max_residual_severity: "high"`): Missing AI disclosure, AI listed as author, unedited AI artifact, broken PDF/diagram, or severe policy violation that could trigger an arXiv moderation penalty.
   - `residual`: remaining AI-smell phrasing, weak WYSIWYS legal motivation, redundant test counts, or layout/typography blemishes.
   - `clean`: publication-ready, authentic human voice, arXiv-compliant, crisp diagrams, zero defects.
