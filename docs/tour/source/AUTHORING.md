# Authoring guide: Myotis Rust Tour, edition 2 (snapshot 5263a421, 2026-11-06)

You are writing one or more **stop files** for a guided tour of the Myotis Rust
workspace. The reader is Dirk, the project owner. He is an experienced
**Java/Kotlin** developer and a **Rust beginner**: the ownership/borrowing
memory model is his weak spot. He reads the tour **offline** (the
first edition was written for a long flight), so it must teach on its own: no
"ask Claude" button works and no web link opens, only his local checkout and the
Rust docs rustup installed. Link Rust documentation as `rustdoc:<path>` (for
example `rustdoc:book/ch04-01-what-is-ownership.html`) and the repo's own docs
as `repodoc:<path under docs/>`; each output resolves them.

## Paths

All paths are relative to `docs/tour/` in the Myotis repository.

- `source/COMMIT`: the commit every excerpt is cut from. The build extracts the
  tree at that commit with `git archive` into `source/.cache/` (once, ignored by
  git), so the tour never quotes the moving working tree. Read the code there,
  or with `git show <COMMIT>:<path>`.
- `source/stops/NN-*.html`: one file per stop, in the format below.
- `source/shell/`: the HTML page's script, styles, progress page and
  `reading.json` (the concepts and reading list), plus `book.css` for the EPUB.
- `workbook/`: the exercises. Edit `solution/` only; `make_starter.py`
  regenerates `starter/`. Stops embed workbook files with
  `<x-wb file="starter/src/…">` or `<x-wb file="solution-clean/…">` (the
  solution without its `//@begin` / `//@end` markers).
- Outputs: `python3 build.py` writes `source/out/index.html`, `python3 epub.py`
  writes `source/out/myotis-rust-tour.epub`, and `python3 markdown.py` writes
  the Markdown book to `book/` (committed). Run `python3 route.py` first when a
  stop's reading time changed: it rewrites the full route in Stop 0.
- `python3 build.py --check stops/NN-x.html --scope rust/<dir>` validates one
  stop and lists the `.rs` files under the scope that no stop covers yet.

## The stop file format (must be exact)

```
<!--meta {"id":"stop-05","num":5,"title":"...","short":"...","sub":"16 files · 5,785 lines","part":"Pure foundations"} -->
<header class="stop-head">
  <div class="eyebrow">Stop 5 · crate <code>myotis-wire</code> <span>16 files · 5,785 lines · about 50 minutes</span></div>
  <h1>...</h1>
  <p class="lede">...</p>
</header>
<div class="learn"><h2>Rust you will practise</h2><div><b>Short label</b>one sentence</div> ×3</div>
... content ...
<x-file path="rust/myotis-wire/src/eth.rs" kind="..." twin="JavaClass (optional)">
  <p class="purpose">What the file is for, in 2-5 sentences.</p>
  <x-code src="myotis-wire/src/eth.rs" from="57" to="72"></x-code>
  <ul class="concepts">
    <li><x-tags>ownership borrowing</x-tags> <strong>Short lead.</strong> Explanation…</li>
  </ul>
  <p class="code-note"><x-tags>async</x-tags> A paragraph-style note after an excerpt.</p>
</x-file>
<x-quiz>[ ...questions JSON... ]</x-quiz>
```

- `id`, `num`, `title`, `short` and `part` are given in your assignment. `sub`
  is a file/line summary.
- `<x-file path=...>` is the repo-relative path (starts with `rust/`). Every
  `.rs` file in your scope must get exactly one `<x-file>`, including tiny
  stubs (a 4-line re-export file gets a one-paragraph entry). `kind` is a short
  label such as "library", "integration test", "example binary", "re-export
  shim", "test fixture".
- `<x-code src=... from=N to=M>`: `src` is relative to `rust/`, or
  `repo:<path>` relative to the snapshot root (for Kotlin, Java or Gradle files),
  or `cargo:<crate>-<version>/<path>` for a crate in the local cargo registry
  (uniffi's sources; `cargo fetch` in `rust/` provides them).
  Add `lang="kotlin"`, `lang="toml"`, `lang="java"`, `lang="c"` or `lang="text"`
  for non-Rust files. The build cuts the excerpt VERBATIM from the snapshot, so
  only the line numbers matter. **Before using a range, print it**
  (`sed -n 'N,Mp' file`) and confirm it starts and ends at sensible boundaries
  (a whole item, a whole statement). Keep excerpts at about 5–60 lines, and
  split longer ones.
- `<x-tags>` takes space-separated concept tags from exactly this list:
  `ownership borrowing lifetimes smart-pointers interior-mutability concurrency
  async traits-generics methods enums-patterns error-handling iterators-closures
  modules-cargo unsafe-ffi macros testing bytes-strings cli domain`
- You may use the plain HTML from the old stops: `<section class="prose">`,
  `<h4>` inside an x-file, `<div class="table-wrap"><table class="map">`,
  `<div class="callout jvm|rust|watch"><span class="k">Label</span>…</div>`,
  `<figure class="diagram">` with inline SVG (give the arrow marker a unique id
  `m-<yourstop>-arrow`; colors only via CSS variables such as `var(--ink)`,
  `var(--oxide)`, `var(--jvm)`, `var(--ok)`, `var(--bad)`, `var(--warn)`,
  `var(--surface)`, `var(--ground-2)`, `var(--rule)`, `var(--ink-2)`,
  `var(--ink-3)`, with `-wash`/`-ink` variants for oxide/jvm/ok/bad/warn), and
  `<details class="deep"><summary>Deeper: …</summary>…</details>` for optional
  deep dives. Escape `<`, `>` and `&` in prose (`&lt;` `&gt;` `&amp;`).
- Link to other stops only with `#stop-<id>` ids from the stop list below, and
  to primer sections with `#primer-<tag>`. Link to a file entry with
  `#f-<slug>`, where slug = the path after `rust/`, lowercased, with every run
  of non-alphanumerics replaced by `-` (e.g. `#f-myotis-net-src-el-reader-rs`).

### Quiz JSON (inside `<x-quiz>`)

8–14 questions per stop (fewer for a tiny stop), mixing about 60% multiple
choice and 40% open:

```
{"id":"wire-q1","type":"mcq","tags":["ownership"],"q":"HTML question","options":["…","…","…","…"],"answer":1,"explain":"why"}
{"id":"wire-q2","type":"open","tags":["borrowing"],"q":"HTML question","model":"model answer (HTML)","points":["checkable point","…"],"context":"file + line refs + the key code, plain text (used for grading)"}
```

- ids are `<shortslug>-q<N>`. Your slug is given in your assignment.
- **Offline grading**: open answers are self-graded by ticking `points`, so
  each point must be concrete and checkable ("the guard is dropped at the
  closing brace, releasing the lock"), not vague ("understands locking").
  3–5 points each.
- Questions test understanding of THIS code and of the Rust concept behind it.
  Avoid trivia such as line numbers or constant values unless the value is the
  lesson. Make distractors plausible, and vary the correct option's position.
- Valid JSON: escape `"` inside strings, and no trailing commas.

## Content rules

1. **Truth over everything.** Every statement about the code must be checked
   against the snapshot. Never describe behaviour you did not read. If a
   comment in the code contradicts the code, say so in a
   `<div class="callout watch">` ("Stale or inaccurate comments").
2. **Teach Rust through this code.** When an excerpt shows a Rust concept (a
   move, a borrow, a lifetime, `Arc`, `Mutex`, `async`, traits, `?`, a macro,
   `unsafe`), explain the concept right there, briefly, with a Java/Kotlin
   comparison where it helps. The memory model is the priority: say who owns
   what, what is borrowed, what is copied, and when things are dropped.
3. **Explain the domain enough to follow** (Ethereum p2p, light client, snap,
   EVM, ENS…), but the stop is about the code.
4. **Big files** (more than 1,000 lines) get a section map table (line ranges →
   what happens) and several excerpts that cover the important mechanisms.
   Small files get a short entry with zero to two excerpts.
5. **When you move the tour to a newer commit**, keep what is still true
   (reuse the wording freely), fix what changed, drop what no longer exists,
   and add the new material. A short "What changed since …" note is welcome
   where the code changed substantially.
6. **Style**: plain, precise English with short sentences. Use no marketing
   words, no emoji, and no exclamation marks. Use "you" for the reader. Use
   British or American spelling consistently within your file. Name a Java twin
   in `twin="..."` only when the code says so.
7. Reading time: estimate honestly (about 150 words/min of prose plus about
   1 min per 10 excerpt lines plus 2 min per question) and put it in the
   eyebrow.

## Verify before you finish

```
cd docs/tour/source && python3 build.py --check stops/<your file>.html --scope rust/<your crate or dir>
```

It must print no `ERROR:` lines, and no `not covered:` warning for files in
your assignment (files in the same directory that belong to other agents may
show up; ignore those). Then re-read each excerpt in the rendered context: does
the prose next to it describe exactly those lines?

## Report what you found

When you finish, report (to whoever asked for the stop, or in the PR):
- the files covered;
- notable changes since the previous version of the stop;
- anything you were unsure about;
- stale or wrong code comments you found (path:line + one sentence each);
- any bug you suspect in the code (path:line, why). Do not fix it in the tour's
  PR; file it.

## Stop list (ids for cross-links)

stop-00 map · stop-01 primer · stop-02 workspace · stop-03 bls · stop-04 core ·
stop-05 wire · stop-06 consensus · stop-07 evm · stop-08 evm-sim · stop-09 net-cl ·
stop-10 net-sync · stop-11 el-transport · stop-12 el-pool · stop-13 el-services ·
stop-14 el-reader · stop-15 net-tests · stop-16 engine · stop-17 uniffi ·
stop-18 node · stop-19 rpcd · stop-20 roost · stop-21 torpoc · stop-22 workbook ·
stop-23 final

Primer anchors (`#primer-<tag>`): one per concept tag above, plus
`#primer-methods`.
