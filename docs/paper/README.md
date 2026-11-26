# Handfest arXiv Technical Paper (`docs/paper/`)

This directory contains the arXiv-ready LaTeX manuscript (`cs.CR` / `cs.AI`) for **`handfest`**:

> *Executable Ricardian Mandates: Deterministic, Multi-Anchor Authority Vesting for Autonomous AI Agents*

All architectural claims, `HANDFEST v1` grammar rules, lattice attenuation laws, workspace metrics, and implemented adversarial defenses in this manuscript are grounded directly in the `handfest` repository at commit `60f105e` (with unimplemented Slice 2 MCP proxy defenses explicitly marked as proposed specifications).

## Files

- `handfest-ricardian-mandates.tex` — Complete two-column LaTeX manuscript using only standard TeX Live packages (`geometry`, `inputenc`, `fontenc`, `lmodern`, `microtype`, `amsmath`, `amssymb`, `amsthm`, `booktabs`, `array`, `enumitem`, `listings`, `xcolor`, `url`, `hyperref`).
- `references.bib` — Complete BibTeX bibliography matching every `\cite{...}` key in the manuscript, with rendered stable identifiers and URLs compatible with `\bibliographystyle{plain}`.
- `README.md` — Build and arXiv packaging instructions (this file).

## Prerequisites

Any standard TeX Live installation (`texlive-latex-base`, `texlive-latex-recommended`, `texlive-latex-extra`, `texlive-fonts-recommended`, the `lmodern` package on Debian/Ubuntu, and `latexmk` or `pdflatex` + `bibtex`). No custom class files (`acmart`, `IEEEtran`, etc.) are required.

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

1. Finalize any metadata edits—such as updating the `\author{...}` block in `handfest-ricardian-mandates.tex` with individual author names and affiliations—**before** the final build.
2. Build the final PDF locally so `handfest-ricardian-mandates.bbl` matches the exact source being submitted, and inspect both the rendered PDF and `handfest-ricardian-mandates.log` for zero undefined references, zero missing citations, and zero overfull-box warnings:
   ```bash
   cd docs/paper
   latexmk -pdf -interaction=nonstopmode handfest-ricardian-mandates.tex
   ```
3. Package the clean source tarball (excluding `.aux`, `.log`, `.out`, `.fls`, `.fdb_latexmk`, and `.pdf`):
   ```bash
   tar -czf handfest-arxiv-source.tar.gz \
     handfest-ricardian-mandates.tex \
     handfest-ricardian-mandates.bbl \
     references.bib
   ```
4. Upload `handfest-arxiv-source.tar.gz` to arXiv under primary category **`cs.CR` (Cryptography and Security)** and secondary category **`cs.AI` (Artificial Intelligence)**.

## Reproducing Codebase Verification Offline

Offline verification assumes a locally cached Rust `1.98.0` toolchain (`rust-toolchain.toml`, with `clippy` and `rustfmt` components) and a pre-populated Cargo dependency cache matching `Cargo.lock`. From the repository root, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
```

License, source, advisory, and crate-graph policies declared in `deny.toml` are checked separately when `cargo-deny` is installed; they are not enforced automatically by `cargo fmt`, `cargo clippy`, or `cargo test`. Running `cargo deny --offline check` offline additionally requires a locally cached RustSec advisory database for the `advisories` check (whereas `cargo deny --offline check licenses sources` passes offline without an advisory cache). At the pinned commit `60f105e`, `cargo deny --offline check bans` fails under `multiple-versions = "deny"` due to duplicate transitive versions of `getrandom` (`0.2.17`, `0.4.3`) and `syn` (`2.0.119`, `3.0.10`) in `Cargo.lock` (the one-way internal crate-wrapper bans themselves do not fail), and `cargo deny --offline check advisories` depends on the local advisory database snapshot (e.g., newer snapshots flag `RUSTSEC-2026-0459` on `libsqlite3-sys 0.30.1` via `rusqlite 0.32.1`).
