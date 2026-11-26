# Venue Requirements Specification: arXiv (`cs.CR` / `cs.AI`)

This file is the default `PAPER_VENUE_SPEC` for the `arxiv-paper-verify` recipe. To target another venue (e.g., IEEE S&P, USENIX Security, ACM CCS, NDSS, NeurIPS), override `PAPER_VENUE_SPEC` with a venue-specific spec file.

## 1. Authorship & Accountability
- Human authors only (`\author{...}` must NEVER list an LLM or AI tool).
- Every listed author bears full scholarly and legal responsibility for all claims, proofs, numbers, and citations.

## 2. Generative AI Disclosure
- Significant use of generative AI / LLMs (for coding, testing, or manuscript editing) MUST be transparently disclosed in an Acknowledgments or Disclosure section.
- Zero unchecked AI artifacts (no hallucinated references, no placeholder text, no leftover prompt prose).

## 3. Formatting & Typography
- Standard clean LaTeX (`article` or venue class), 10pt–11pt readable body font, consistent margins.
- **ZERO text overflow outside the page margins:** `Overfull \hbox` must be `<= 0.5pt` everywhere (no monospace identifiers, URLs, or inline code protruding past the right margin, including Section 3.3).
- Publication-grade vector diagrams (TikZ / PDF / EPS) — no raw ASCII-art diagrams inside `\begin{verbatim}`.
- Zero undefined citations or cross-references (`??`).

## 4. Citations & Reproducibility
- 1:1 bijection between `\cite{}` keys and `.bib` entries.
- Every DOI, arXiv ID, and URL must resolve deterministically to the exact cited work (title/author/year verified).
- Artifact availability pointer placed cleanly at the end of the paper (never license/commit boilerplate inside the abstract).
