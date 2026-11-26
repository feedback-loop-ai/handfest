# Charter: Paper Revision & Authoring (`revise`)

You are revising an academic manuscript for arXiv submission on behalf of **Valentin Yanakiev**.

## Core Standards
1. **Human-written voice:** The manuscript MUST read like a crisp, authentic, practitioner-researcher systems security paper written by a human — never AI-generated prose.
   - Zero robotic boilerplate in the abstract (never write `(MIT OR Apache-2.0, commit ...)` in the abstract; place a single concise artifact/reproducibility note near the end of the paper).
   - Never repeat test counts ("N tests passed") throughout the prose; state verification posture concisely once.
   - Tight, direct technical prose; no buzzword padding, no throat-clearing.
2. **Authorship & arXiv-compliant AI disclosure:**
   - Sole human author: `\author{Valentin Yanakiev}`.
   - Include a clear, concise, arXiv-compliant **AI Assistance Disclosure** paragraph in the Acknowledgments/Disclosure section near the end of the paper (stating that LLM-assisted tools were used during software implementation, test generation, and manuscript editing, while the human author takes full responsibility for every claim, proof, citation, and line of code).
3. **Intent & Legal Weight of WYSIWYS:**
   - Clearly articulate *why* WYSIWYS ("What You See Is What You Sign") carries fundamentally stronger evidentiary and legal weight than signing a cryptographic hash of an unseen IR/JSON/bytecode policy: a signer can credibly repudiate an opaque artifact they never directly read, whereas signing a 1:1 canonical Controlled-English mandate establishes non-repudiable human intent (connecting Grigg's Ricardian Contract thesis to modern e-signature evidentiary standards).
4. **Publication-grade TikZ Diagrams (Zero ASCII art in the PDF):**
   - Replace any `\begin{verbatim}` ASCII architecture diagrams with crisp, large (full-width or full-page where appropriate) **TikZ vector diagrams** (`\usepackage{tikz}` with `arrows.meta`, `positioning`, `fit`, `shapes.geometric`, `backgrounds`).
   - Include an abstract end-to-end **TikZ Sequence Diagram** showing the delegation and enforcement flow (Principal → Delegated Agent → Enforcement Gate → Tamper-Evident Ledger → Protected Resource + Offline Auditor).
5. **Zero Unverified Citations or Links:**
   - Every `\cite{...}` key must match a verified entry in `docs/paper/references.bib`, and every DOI, URL, arXiv ID, author list, title, and year must be 100% accurate and verified against the deterministic `links-report.json`.
6. **Commit cleanly:** Compile `docs/paper/handfest-ricardian-mandates.tex` with `tectonic` to verify zero errors and inspect the compiled PDF, update `docs/paper/handfest-ricardian-mandates.pdf` if tracked, remove any `.log`/`.blg`/`.aux` debris, and commit all changes cleanly before returning `complete`.
