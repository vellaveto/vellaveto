# arXiv Submission Checklist

Use this checklist to produce a zip-ready arXiv submission from
`formal/arxiv/`.

## 1. Clean Build

Run a full local build first:

```bash
cd formal/arxiv
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

Confirm:

- `main.pdf` renders correctly.
- citations are resolved.
- author block shows `Paolo Vella`, `Vellaveto`, and `security@vellaveto.online`.
- hyperlinks and URLs wrap correctly.

## 2. Files To Include In The arXiv Upload

Include:

- `main.tex`
- `references.bib`
- `main.bbl`

Optional but useful:

- `README.md`
- this checklist

Do not include:

- `main.pdf`
- `*.aux`
- `*.blg`
- `*.log`
- `*.out`

## 3. Why Include `main.bbl`

arXiv can process BibTeX, but the safest upload is to include the generated
`main.bbl` as well as `references.bib`. That way the source still compiles even
if arXiv skips a BibTeX step during processing.

## 4. Zip Command

From `formal/arxiv/`:

```bash
zip vellaveto-formal-verification-arxiv.zip \
  main.tex \
  main.bbl \
  references.bib \
  README.md \
  SUBMISSION_CHECKLIST.md
```

## 5. arXiv Metadata To Enter

Suggested title:

`Formal Verification of a Runtime Security Boundary for Model Context Protocol Tool Calls`

Author:

- Paolo Vella

Contact email:

- `security@vellaveto.online`

Suggested abstract source:

- copy from `main.tex`

## 6. Final Pre-Upload Checks

- open the zip and verify the expected files are present.
- confirm there are no absolute local filesystem paths in the source.
- confirm the bibliography is present in `main.bbl`.
- confirm the source does not rely on non-standard classes or custom `.sty` files.
- confirm the generated PDF matches the source bundle you are uploading.
