# Handfest paper (`docs/paper/`)

LaTeX source and compiled PDF of

> *Executable Ricardian Mandates: Deterministic, Multi-Anchor Authority Vesting for Autonomous AI Agents*
> Valentin Yanakiev

intended for arXiv (`cs.CR`, cross-listed `cs.AI`). The paper describes the code at commit `344df89`, the last commit that touches `crates/`.

## Files

- `handfest-ricardian-mandates.tex` — the manuscript: two-column `article`, with the architecture figure and the sequence diagram drawn in TikZ.
- `references.bib` — bibliography. Every `\cite` key has exactly one entry and every entry is cited. Entries carry a Crossref `doi`, an arXiv `eprint`, or a `url`, so that the recipe's `check-links` gate can verify them. The three EU regulations are cited by Official Journal reference and ELI only, because EUR-Lex answers scripted requests with an interstitial page.
- `handfest-ricardian-mandates.pdf` — the PDF built from the two files above.

## Building

The PDF in this directory is built with [Tectonic](https://tectonic-typesetting.github.io/), which fetches the TeX packages it needs on first use:

```bash
tectonic -X compile docs/paper/handfest-ricardian-mandates.tex
```

Any TeX Live installation works as well. The manuscript uses `geometry`, `inputenc`, `fontenc`, `lmodern`, `microtype`, `amsmath`, `amssymb`, `amsthm`, `booktabs`, `array`, `enumitem`, `xcolor`, `listings`, `tikz`, `natbib` (with `plainnat.bst`), `url`, `hyperref` and `doi`, and no custom class:

```bash
cd docs/paper
latexmk -pdf -interaction=nonstopmode handfest-ricardian-mandates.tex
latexmk -c handfest-ricardian-mandates.tex   # remove intermediate files, keep the PDF
```

Do not commit `.aux`, `.bbl`, `.blg`, `.log` or `.out` files.

## Packaging for arXiv

arXiv runs `pdflatex` but not `bibtex`, so the source upload needs the generated `.bbl`:

```bash
cd docs/paper
latexmk -pdf -interaction=nonstopmode handfest-ricardian-mandates.tex
tar -czf handfest-arxiv-source.tar.gz \
  handfest-ricardian-mandates.tex handfest-ricardian-mandates.bbl references.bib
```

Check the log of that build for undefined references and overfull boxes before uploading. The manuscript carries an AI assistance disclosure, as arXiv's policy on generative AI tools requires.

## Checking the code the paper describes

From the repository root, with the pinned toolchain (`rust-toolchain.toml`):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```
