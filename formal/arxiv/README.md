# arXiv LaTeX Sources

This directory contains an arXiv-ready LaTeX conversion of the submission
manuscript:

- `main.tex`
- `main.bbl`
- `references.bib`
- `SUBMISSION_CHECKLIST.md`

## Build

```bash
cd formal/arxiv
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

The source uses only standard packages expected to work in a normal arXiv TeX
environment and does not depend on a custom class.

`main.bbl` is checked in so the upload bundle compiles even if arXiv skips a
BibTeX pass.

For the final upload bundle steps, see `SUBMISSION_CHECKLIST.md`.
