# Changelog

The tour's version (`source/VERSION`) is `MAJOR.MINOR`. MINOR goes up for corrections and
additions at the same pinned commit (`source/COMMIT`); MAJOR goes up when the tour moves to a
newer commit of the code. Every output carries it: the HTML page and EPUB in their file names,
title and metadata, the Markdown book in its README and chapter footers, and the workbook crate
as `MAJOR.MINOR.0`.

## 1.0

The first versioned edition, quoting the code at `5263a421` (2026-11-06).

- 24 stops covering all 176 `.rs` files in 12 crates, 293 checkpoint questions, about 56 hours
  of reading; Stop 0 ends with the full route in 11 legs.
- New since the unversioned September draft: the crates `myotis-wire` and `myotis-rpcd`, a
  primer section on methods and `self`, a deep dive into UniFFI (Stop 17), a ten-exercise
  workbook (Stop 22).
- Three outputs from one source: an offline HTML page with graded quizzes and saved progress,
  an EPUB, and the Markdown book in `book/`.
