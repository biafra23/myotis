# Myotis Rust Tour

A guided reading of every Rust file in the Myotis workspace, written for a developer who knows
Java and Kotlin and is still building a feel for Rust's ownership and borrowing. Each stop
explains one part of the code through verbatim excerpts, teaches the Rust concepts those
excerpts use, and ends with a checkpoint. A workbook of ten exercises makes you write the
mechanisms yourself.

**Read it here: [the book](book/README.md)** (Markdown, renders on GitHub). The version is in
[`source/VERSION`](source/VERSION); changes are in the [changelog](CHANGELOG.md).

The tour quotes the code at one pinned commit ([`source/COMMIT`](source/COMMIT)), not the
moving `main`: every excerpt is cut from that commit with its real line numbers, so
`git show <commit>:rust/<path>` finds it again. Moving the tour to a newer commit is a new major
version.

## What is where

| Path | What it is |
|---|---|
| [`book/`](book/) | The book as Markdown, generated: do not edit by hand |
| [`source/stops/`](source/stops/) | The text, one HTML file per stop, in the format described in [`source/AUTHORING.md`](source/AUTHORING.md) |
| [`source/shell/`](source/shell/) | The HTML page's script and styles, the progress page, the concept list and reading list (`reading.json`), the EPUB's stylesheet |
| [`source/*.py`](source/) | The generators: `build.py` (HTML), `epub.py` (EPUB), `markdown.py` (this book), `route.py` (Stop 0's reading route), `highlight.py` |
| [`workbook/`](workbook/) | The exercises as a cargo crate: `solution/` is the source, `starter/` is generated from it by `make_starter.py` |

## Building the other editions

From `docs/tour/source/`, with Python 3.12 or newer and this commit in your clone:

```bash
python3 route.py       # after a stop's reading time changed: rewrites the route in Stop 0
python3 build.py       # out/myotis-rust-tour-<version>.html: one offline page, graded quizzes, saved progress
python3 epub.py        # out/myotis-rust-tour-<version>.epub: the ebook (cover rendered with Google Chrome if present)
python3 markdown.py    # ../book/: this Markdown edition (commit it)
```

The first run extracts the pinned commit into `source/.cache/` with `git archive`. Stop 17
quotes UniFFI's own sources from your cargo registry (`cargo fetch` in `rust/` provides them).
Links to the Rust documentation point to the copy rustup installed when there is one (the HTML
and EPUB editions are meant to work offline), and to doc.rust-lang.org otherwise.

The HTML and EPUB files are build outputs and are not committed: build them, or take them from
wherever a release of the tour is published.

## The workbook

```bash
cd docs/tour/workbook
cp -R starter mine && cd mine
cargo test --offline e01      # one exercise at a time; the solutions are in ../solution
```

It uses the same tokio and futures versions as the Myotis workspace, so `--offline` works once
the workspace has been built. To change an exercise, edit `solution/` and run
`python3 make_starter.py`.
