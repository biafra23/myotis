#!/usr/bin/env python3
"""Assemble the Myotis Rust Tour into one self-contained HTML page.

Stop files (stops/NN-*.html) use a few custom tags that this script expands:

  <!--meta {...json...} -->                  per-stop metadata (first line)
  <x-file path="rust/..." twin=".." kind="..">...</x-file>
                                            one file entry; the line count is read from disk
  <x-code src="myotis-core/src/rlp.rs" from="10" to="20" lang="rust" title=".."></x-code>
                                            a VERBATIM excerpt cut from the repo at build time
  <x-tags>ownership borrowing</x-tags>      concept chips linking to the primer
  <x-quiz>[...json...]</x-quiz>             the stop's checkpoint questions
"""
import glob
import html
import io
import json
import os
import re
import subprocess
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from highlight import highlight  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))       # docs/tour/source
TOUR = os.path.dirname(HERE)                             # docs/tour
COMMIT = open(os.path.join(HERE, "COMMIT")).read().strip()
# The tour's own version, MAJOR.MINOR: MINOR for fixes and additions at the same COMMIT,
# MAJOR when the tour moves to a newer COMMIT. Every output carries it.
VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
CACHE = os.path.join(HERE, ".cache")
# What the stops quote, extracted from COMMIT (never the working tree, which moves on).
SNAPSHOT_PATHS = ["rust", "docs", "CLAUDE.md", "build.gradle.kts", "settings.gradle.kts", "gradle",
                  "myotis-api", "myotis-engine", "myotis-engine-rust", "myotis-engines", "myotis-engine-ios"]


def snapshot_dir():
    """The tree at COMMIT, extracted once with `git archive` into .cache/."""
    d = os.path.join(CACHE, "snapshot-" + COMMIT[:12])
    if os.path.isdir(d):
        return d
    top = subprocess.run(["git", "-C", HERE, "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=True).stdout.strip()
    if subprocess.run(["git", "-C", top, "cat-file", "-e", COMMIT + "^{commit}"]).returncode != 0:
        sys.exit(f"commit {COMMIT} is not in this clone: run `git fetch origin` (a shallow clone needs "
                 f"`git fetch --unshallow`)")
    print(f"extracting the snapshot at {COMMIT[:8]} into {os.path.relpath(d)} (once)")
    data = subprocess.run(["git", "-C", top, "archive", COMMIT, *SNAPSHOT_PATHS],
                          capture_output=True, check=True).stdout
    tmp = d + ".tmp"
    os.makedirs(tmp, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(tmp, filter="data")
    os.rename(tmp, d)
    return d


REPO = snapshot_dir()
RUST = os.path.join(REPO, "rust")
CARGO_REGISTRY = os.path.join(os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo")), "registry", "src")
ONLINE_RUSTDOC = "https://doc.rust-lang.org/"
# `repodoc:<path>` links name a file under the repo's docs/ as it is NOW (not at COMMIT):
# GitHub in the HTML and EPUB (they get copied away from the checkout), relative in book/.
ONLINE_REPODOC = "https://github.com/biafra23/myotis/blob/main/docs/"


def rustdoc_base(local=True):
    """Where `rustdoc:` links point: the docs rustup installed with the active toolchain
    (offline), or doc.rust-lang.org when they are missing or `local` is False."""
    if local:
        try:
            sysroot = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True,
                                     check=True).stdout.strip()
            html_root = os.path.join(sysroot, "share", "doc", "rust", "html")
            if os.path.isfile(os.path.join(html_root, "book", "index.html")):
                return "file://" + html_root + "/"
        except (OSError, subprocess.CalledProcessError):
            pass
        warnings.append("local Rust docs not found (rustup component add rust-docs): "
                        "rustdoc: links point online")
    return ONLINE_RUSTDOC

READING = json.load(open(os.path.join(HERE, "shell", "reading.json")))
CONCEPTS = READING["concepts"]

errors = []
warnings = []
covered_files = set()
file_entries = []   # (shown_path, lines, fid, stop_id)
CURRENT_STOP = {"id": None}
_line_cache = {}


def lines_of(path):
    if path not in _line_cache:
        with open(path, encoding="utf-8") as f:
            _line_cache[path] = f.read().split("\n")
            if _line_cache[path] and _line_cache[path][-1] == "":
                _line_cache[path].pop()
    return _line_cache[path]


def attrs(s):
    return dict(re.findall(r'([\w-]+)="([^"]*)"', s))


def slug(path):
    return "f-" + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")


def fmt_int(n):
    return f"{n:,}"


def resolve(src):
    """x-code sources: `rust/`-relative (default), `repo:<path>` from the snapshot root, or
    `cargo:<crate>-<version>/<path>` from the local cargo registry (e.g. uniffi's crates)."""
    if src.startswith("repo:"):
        return os.path.join(REPO, src[5:])
    if src.startswith("cargo:"):
        hits = sorted(glob.glob(os.path.join(CARGO_REGISTRY, "*", src[6:])))
        return hits[0] if hits else os.path.join(CARGO_REGISTRY, "<not in your cargo registry>", src[6:])
    return os.path.join(RUST, src)


def shown_path(src):
    if src.startswith("repo:"):
        return src[5:]
    if src.startswith("cargo:"):
        return "cargo registry: " + src[6:]
    return "rust/" + src


def missing_hint(src):
    if src.startswith("cargo:"):
        return " (fetch the crate: `cargo fetch` in rust/)"
    return ""


def excerpt(a, where):
    """Validate an x-code tag's attributes and cut its excerpt: (src, from, to, body) with the
    common indentation trimmed (numbering stays exact), or None after recording an error.
    Shared by every output (build.py, epub.py, markdown.py)."""
    src = a.get("src")
    if not src:
        errors.append(f"{where}: x-code without src")
        return None
    path = resolve(src)
    if not os.path.exists(path):
        errors.append(f"{where}: x-code src missing: {src}{missing_hint(src)}")
        return None
    ls = lines_of(path)
    fr = int(a.get("from", "1"))
    to = int(a.get("to", str(len(ls))))
    if fr < 1 or to > len(ls) or fr > to:
        errors.append(f"{where}: x-code range {fr}-{to} out of bounds for {src} ({len(ls)} lines)")
        return None
    chunk = ls[fr - 1:to]
    indents = [len(l) - len(l.lstrip(" ")) for l in chunk if l.strip()]
    cut = min(indents) if indents else 0
    return src, fr, to, "\n".join(l[cut:] if len(l) >= cut else l.lstrip(" ") for l in chunk)


def expand_code(m, where):
    a = attrs(m.group(1))
    cut = excerpt(a, where)
    if cut is None:
        return ""
    src, fr, to, body = cut
    gutter = "\n".join(str(i) for i in range(fr, to + 1))
    lang = a.get("lang", "rust")
    shown = shown_path(src)
    title = a.get("title", "")
    cap_right = f"lines {fr}–{to}" if fr != to else f"line {fr}"
    cap_left = html.escape(shown)
    if title:
        cap_left = html.escape(title) + " · " + cap_left
    return (
        f'<figure class="code"><figcaption class="code-cap"><span>{cap_left}</span><span>{cap_right}</span></figcaption>'
        f'<div class="code-scroll"><div class="code-grid"><div class="gutter" aria-hidden="true">{gutter}</div>'
        f'<pre><code class="lang-{lang}">{highlight(body, lang)}</code></pre></div></div></figure>'
    )


WORKBOOK = os.path.join(TOUR, "workbook")


def workbook_text(name):
    """A workbook file. `solution-clean/<file>` is solution/src/<file> without its
    `//@begin` / `//@end` markers (make_starter.py turns those blocks into todo!s)."""
    if name.startswith("solution-clean/"):
        path = os.path.join(WORKBOOK, "solution", "src", name[len("solution-clean/"):])
        if not os.path.exists(path):
            return None
        return re.sub(r"^[ \t]*//@(begin|end)\n", "", open(path, encoding="utf-8").read(), flags=re.M)
    path = os.path.join(WORKBOOK, name)
    return open(path, encoding="utf-8").read() if os.path.exists(path) else None


def expand_wb(m, where):
    """<x-wb file="starter/src/e01_cursor.rs" lang="rust"></x-wb>: a whole
    workbook file, highlighted, with a copy button (added by app.js)."""
    a = attrs(m.group(1))
    text = workbook_text(a.get("file", ""))
    if text is None:
        errors.append(f"{where}: x-wb file missing: {a.get('file')}")
        return ""
    text = text.rstrip("\n")
    lang = a.get("lang", "rust")
    label = html.escape(a.get("label", a.get("file", "")))
    return (f'<figure class="code wb"><figcaption class="code-cap"><span>{label}</span>'
            f'<span>{len(text.splitlines())} lines</span></figcaption>'
            f'<pre class="workbook" data-copy><code class="lang-{lang}">{highlight(text, lang)}</code></pre></figure>')


def expand_tags(m, where):
    out = []
    for t in m.group(1).split():
        if t not in CONCEPTS:
            errors.append(f"{where}: unknown concept tag '{t}'")
            continue
        out.append(f'<a class="tag" href="#primer-{t}">{html.escape(CONCEPTS[t]["label"])}</a>')
    return '<span class="tags">' + "".join(out) + "</span>"


def expand_file(m, where):
    a = attrs(m.group(1))
    inner = m.group(2)
    path = a.get("path", "")
    full = os.path.join(REPO, path)
    if not os.path.exists(full):
        errors.append(f"{where}: x-file path missing: {path}")
        return ""
    covered_files.add(os.path.normpath(full))
    n = len(lines_of(full))
    shown = path[5:] if path.startswith("rust/") else path
    d, base = os.path.split(shown)
    chips = [f'<span class="chip">{fmt_int(n)} lines</span>']
    if a.get("kind"):
        chips.insert(0, f'<span class="chip kind">{html.escape(a["kind"])}</span>')
    if a.get("twin"):
        chips.append(f'<span class="chip twin">Java twin · {html.escape(a["twin"])}</span>')
    fid = slug(shown)
    file_entries.append((shown, n, fid, CURRENT_STOP["id"]))
    head = (
        f'<header class="file-head"><h3 class="file-path"><a href="#{fid}">'
        f'<span class="dir">{html.escape(d)}/</span>{html.escape(base)}</a></h3>'
        f'<div class="chips">{"".join(chips)}</div></header>'
    )
    return f'<article class="file" id="{fid}" data-lines="{n}">{head}<div class="body">{inner}</div></article>'


REQ_MCQ = {"id", "q", "options", "answer", "explain", "tags"}
REQ_OPEN = {"id", "q", "model", "points", "tags"}
seen_q = set()


def expand_quiz(m, where, stop_id):
    raw = m.group(1)
    try:
        qs = json.loads(raw)
    except json.JSONDecodeError as e:
        errors.append(f"{where}: quiz JSON invalid: {e}")
        return ""
    for q in qs:
        t = q.get("type")
        need = REQ_MCQ if t == "mcq" else REQ_OPEN if t == "open" else None
        if need is None:
            errors.append(f"{where}: question {q.get('id')} has bad type {t}")
            continue
        missing = need - set(q)
        if missing:
            errors.append(f"{where}: question {q.get('id')} missing {sorted(missing)}")
        if q.get("id") in seen_q:
            errors.append(f"{where}: duplicate question id {q.get('id')}")
        seen_q.add(q.get("id"))
        for tg in q.get("tags", []):
            if tg not in CONCEPTS:
                errors.append(f"{where}: question {q.get('id')} unknown tag {tg}")
        if t == "mcq" and not (0 <= q.get("answer", -1) < len(q.get("options", []))):
            errors.append(f"{where}: question {q.get('id')} answer index out of range")
    data = json.dumps(qs, ensure_ascii=False).replace("</", "<\\/")
    return (
        f'<section class="checkpoint" data-stop="{stop_id}" aria-labelledby="cp-{stop_id}">'
        f'<div class="checkpoint-head"><h2 id="cp-{stop_id}">Checkpoint</h2><span class="tally"></span></div>'
        f'<p>Answer before moving on. Multiple-choice answers are checked instantly. For written answers, '
        f'write yours first, then compare it with the model answer and tick the key points you covered. '
        f'Your results feed the reading list on the progress page.</p>'
        f'<div class="q-list"></div>'
        f'<script type="application/json" class="quiz-data" data-stop="{stop_id}">{data}</script></section>'
    )


def process_stop(fname):
    where = os.path.basename(fname)
    text = open(fname, encoding="utf-8").read()
    mm = re.match(r"\s*<!--meta\s+(\{.*?\})\s*-->", text, re.S)
    if not mm:
        errors.append(f"{where}: missing meta")
        return None
    meta = json.loads(mm.group(1))
    CURRENT_STOP["id"] = meta["id"]
    body = text[mm.end():]
    body = re.sub(r"<x-code\b([^>]*)>\s*</x-code>", lambda m: expand_code(m, where), body)
    body = re.sub(r"<x-code\b([^>]*)/>", lambda m: expand_code(m, where), body)
    body = re.sub(r"<x-wb\b([^>]*)>\s*</x-wb>", lambda m: expand_wb(m, where), body)
    body = re.sub(r"<x-tags>(.*?)</x-tags>", lambda m: expand_tags(m, where), body, flags=re.S)
    body = re.sub(r"<x-file\b([^>]*)>(.*?)</x-file>", lambda m: expand_file(m, where), body, flags=re.S)
    body = re.sub(r"<x-quiz>(.*?)</x-quiz>", lambda m: expand_quiz(m, where, meta["id"]), body, flags=re.S)
    leftovers = [t for t in re.findall(r"<x-[a-z-]+", body) if t != "<x-file-index"]
    if leftovers:
        errors.append(f"{where}: unexpanded tags {set(leftovers)}")
    return meta, body


def check(paths, scopes):
    """--check mode for authors: validate the given stop files only and list
    the .rs files under each --scope prefix that those stops do not cover."""
    for p in paths:
        process_stop(p)
    for sc in scopes:
        base = os.path.join(REPO, sc)
        for root, dirs, fs in os.walk(base):
            for f in sorted(fs):
                if f.endswith(".rs"):
                    full = os.path.normpath(os.path.join(root, f))
                    if full not in covered_files:
                        warnings.append("not covered: " + os.path.relpath(full, REPO))
    qs = len(seen_q)
    print(f"checked {len(paths)} stop file(s): {qs} questions, {len(covered_files)} files covered")
    for w in warnings:
        print("WARN:", w)
    for e in errors:
        print("ERROR:", e)
    sys.exit(1 if errors else 0)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        args = sys.argv[2:]
        scopes = [args[i + 1] for i, a in enumerate(args) if a == "--scope"]
        paths = [a for i, a in enumerate(args) if a != "--scope" and (i == 0 or args[i - 1] != "--scope")]
        check(paths, scopes)
        return
    stop_dir = os.path.join(HERE, "stops")
    files = sorted(f for f in os.listdir(stop_dir) if f.endswith(".html"))
    stops = []
    for f in files:
        r = process_stop(os.path.join(stop_dir, f))
        if r:
            stops.append(r)

    # file index (only .rs files), grouped by crate
    groups = {}
    for shown, n, fid, sid in file_entries:
        if not shown.endswith(".rs"):
            continue
        crate = shown.split("/")[0]
        groups.setdefault(crate, []).append((shown, n, fid))
    order = ["myotis-bls", "myotis-core", "myotis-wire", "myotis-consensus", "myotis-evm", "myotis-net",
             "myotis-engine", "uniffi-bindgen", "myotis-node", "myotis-rpcd", "roost", "tor-poc"]
    idx = ['<div class="file-index">']
    for crate in order + sorted(set(groups) - set(order)):
        items = groups.get(crate)
        if not items:
            continue
        total = sum(n for _, n, _ in items)
        idx.append(f'<h3 class="index-crate">{html.escape(crate)} <span>{len(items)} files · {fmt_int(total)} lines</span></h3><ul class="toc-files">')
        for shown, n, fid in items:
            rel = shown[len(crate) + 1:]
            idx.append(f'<li><a href="#{fid}">{html.escape(rel)}</a><span>{fmt_int(n)}</span></li>')
        idx.append("</ul>")
    idx.append("</div>")
    index_html = "".join(idx)
    stops = [(m, b.replace("<x-file-index></x-file-index>", index_html)) for m, b in stops]
    rs_in_index = sum(len([1 for s_, *_ in v]) for v in groups.values())
    print(f"file index: {rs_in_index} .rs files")

    # pager links
    sections = []
    for i, (meta, body) in enumerate(stops):
        prev_a = next_a = ""
        if i > 0:
            pm = stops[i - 1][0]
            prev_a = f'<a class="prev" href="#{pm["id"]}"><small>Previous stop</small><b>{html.escape(pm["title"])}</b></a>'
        if i + 1 < len(stops):
            nm = stops[i + 1][0]
            next_a = f'<a class="next" href="#{nm["id"]}"><small>Next stop</small><b>{html.escape(nm["title"])}</b></a>'
        else:
            next_a = '<a class="next" href="#progress"><small>Finish</small><b>Your progress &amp; reading list</b></a>'
        sections.append(
            f'<section class="stop" id="{meta["id"]}" aria-label="{html.escape(meta["title"])}">{body}'
            f'<nav class="pager" aria-label="Tour navigation">{prev_a}{next_a}</nav></section>'
        )

    # rail
    rail = []
    last_part = None
    for meta, _ in stops:
        if meta.get("part") and meta["part"] != last_part:
            rail.append(f'<li class="part">{html.escape(meta["part"])}</li>')
            last_part = meta["part"]
        rail.append(
            f'<li><a href="#{meta["id"]}" data-stop="{meta["id"]}"><span class="dot">{meta["num"]}</span>'
            f'<span class="label"><b>{html.escape(meta["short"])}</b><small>{html.escape(meta.get("sub", ""))}</small></span>'
            f'<span class="score"></span></a></li>'
        )

    # coverage check
    all_rs = set()
    for root, dirs, fs in os.walk(RUST):
        dirs[:] = [d for d in dirs if d not in ("target", "node_modules", ".git")]
        for f in fs:
            if f.endswith(".rs"):
                all_rs.add(os.path.normpath(os.path.join(root, f)))
    missing = sorted(p[len(RUST) + 1:] for p in all_rs - covered_files)
    if missing:
        warnings.append(f"{len(missing)} .rs files not covered: " + ", ".join(missing))

    n_lines = sum(len(lines_of(p)) for p in all_rs)
    crates = {os.path.relpath(p, RUST).split(os.sep)[0] for p in all_rs}
    BRAND_SUB = f"edition {VERSION} · {fmt_int(n_lines)} lines · {len(all_rs)} files · {len(crates)} crates · snapshot {COMMIT[:8]}"
    progress = open(os.path.join(HERE, "shell", "progress.html"), encoding="utf-8").read()
    css = open(os.path.join(HERE, "shell", "style.css"), encoding="utf-8").read()
    js = open(os.path.join(HERE, "shell", "app.js"), encoding="utf-8").read()
    reading = json.dumps(READING, ensure_ascii=False).replace("</", "<\\/")

    page = f"""<title>Myotis Rust Tour {VERSION}</title>
<meta name="version" content="{VERSION}">
<meta name="description" content="A guided tour of the Myotis Rust workspace for Java and Kotlin developers, with checkpoints.">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- Web fonts are a bonus: loaded without blocking, so offline the page renders at once in system fonts. -->
<link rel="stylesheet" media="print" onload="this.media='all'" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,400..800&family=JetBrains+Mono:ital,wght@0,400..700;1,400&family=Literata:ital,opsz,wght@0,7..72,300..700;1,7..72,400&display=swap">
<style>
{css}
</style>
<div class="mobile-bar"><b>Myotis <span>Rust</span> Tour</b><button class="btn" id="menu-btn" type="button" aria-controls="rail">Stops</button></div>
<div class="scrim" hidden></div>
<div class="app">
<aside class="rail" id="rail" aria-label="Tour stops">
  <div class="brand"><div class="brand-name">Myotis <span>Rust</span> Tour</div>
  <div class="brand-sub">{BRAND_SUB}</div></div>
  <nav aria-label="Stops"><ol class="route">{''.join(rail)}</ol></nav>
  <div class="rail-foot">
    <a class="btn-progress" id="progress-link" href="#progress"><span>Progress &amp; reading list</span><span class="meter" id="progress-meter"></span></a>
    <p class="sync-note" id="sync-note"></p>
  </div>
</aside>
<main id="main">
{''.join(sections)}
{progress}
</main>
</div>
<script type="application/json" id="reading-data">{reading}</script>
<script>
{js}
</script>
"""
    for c in CONCEPTS:
        if f'id="primer-{c}"' not in page:
            errors.append(f"primer anchor missing for concept {c}")
    ids = re.findall(r'\sid="([^"]+)"', page)
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        errors.append(f"duplicate ids: {dup[:10]}")
    for href in set(re.findall(r'href="#([^"]+)"', page)):
        if f'id="{href}"' not in page:
            errors.append(f"broken internal link #{href}")
    page = page.replace("rustdoc:", rustdoc_base(local=True)).replace("repodoc:", ONLINE_REPODOC)
    out = os.path.join(HERE, "out", f"myotis-rust-tour-{VERSION}.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)

    qcount = len(seen_q)
    print(f"stops={len(stops)} questions={qcount} files_covered={len(covered_files)} size={len(page):,} bytes")
    for w in warnings:
        print("WARN:", w)
    for e in errors:
        print("ERROR:", e)
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
