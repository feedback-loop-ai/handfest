# Handfest arXiv Technical Paper (`docs/paper/`)

This directory contains the arXiv-ready LaTeX manuscript (`cs.CR` / `cs.AI`) for **`handfest`**:

> *Executable Ricardian Mandates: Deterministic, Multi-Anchor Authority Vesting for Autonomous AI Agents*

All architectural claims, `HANDFEST v1` grammar rules, lattice attenuation laws, workspace metrics, and adversarial threat-model defenses in this manuscript are grounded directly in the `handfest` repository at commit `60f105e`.

## Files

- `handfest-ricardian-mandates.tex` — Complete two-column LaTeX manuscript using only standard TeX Live packages (`geometry`, `inputenc`, `fontenc`, `lmodern`, `microtype`, `amsmath`, `amssymb`, `amsthm`, `booktabs`, `array`, `enumitem`, `listings`, `xcolor`, `url`, `hyperref`).
- `references.bib` — Complete BibTeX bibliography matching every `\cite{...}` key in the manuscript.
- `README.md` — Build and arXiv packaging instructions (this file).

## Prerequisites

Any standard TeX Live installation (`texlive-latex-base`, `texlive-latex-recommended`, `texlive-latex-extra`, `texlive-fonts-recommended`, and `latexmk` or `pdflatex` + `bibtex`). No custom class files (`acmart`, `IEEEtran`, etc.) are required.

## Building the PDF

### Option 1: `latexmk` (recommended)

```bash
cd docs/paper
latexmk -pdf -interaction=nonstopmode handfest-ricardian-mandates.tex
```

To clean intermediate build artifacts while keeping the generated PDF:

```bash
latexmk -c handfest-ricardian-mandates.tex
```

### Option 2: `pdflatex` + `bibtex`

```bash
cd docs/paper
pdflatex -interaction=nonstopmode handfest-ricardian-mandates.tex
bibtex handfest-ricardian-mandates
pdflatex -interaction=nonstopmode handfest-ricardian-mandates.tex
pdflatex -interaction=nonstopmode handfest-ricardian-mandates.tex
```

## Preparing an arXiv Source Tarball

arXiv compiles uploaded LaTeX sources using `pdflatex` and expects the pre-generated `.bbl` file (produced by `bibtex`) alongside the `.tex` file rather than running `bibtex` itself.

1. Build the PDF once locally so `handfest-ricardian-mandates.bbl` is generated and verified with zero undefined references or warnings:
   ```bash
   cd docs/paper
   latexmk -pdf -interaction=nonstopmode handfest-ricardian-mandates.tex
   ```
2. Update the `\author{...}` block in `handfest-ricardian-mandates.tex` with the final author list and affiliations if submitting under individual author names.
3. Package the clean source tarball (excluding `.aux`, `.log`, `.out`, `.fls`, `.fdb_latexmk`, and `.pdf`):
   ```bash
   tar -czf handfest-arxiv-source.tar.gz \
     handfest-ricardian-mandates.tex \
     handfest-ricardian-mandates.bbl \
     references.bib
   ```
4. Upload `handfest-arxiv-source.tar.gz` to arXiv under primary category **`cs.CR` (Cryptography and Security)** and secondary category **`cs.AI` (Artificial Intelligence)**.

## Reproducing Codebase Verification

From the repository root, the exact Rust workspace verified against this manuscript can be checked offline via:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```
