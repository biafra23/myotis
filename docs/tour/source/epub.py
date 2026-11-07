#!/usr/bin/env python3
"""Build the Myotis Rust Tour as an EPUB 3 ebook from the same stop sources.

Reuses build.py's tag expansion (x-file, x-tags, x-wb), but replaces:
  * x-code  -> line-numbered rows that wrap with a hanging indent (no side gutter)
  * x-quiz  -> static questions; every answer goes to an appendix chapter
and converts each stop's HTML into well-formed XHTML (stdlib only).

    python3 epub.py            -> out/myotis-rust-tour.epub
"""
import datetime
import html
import json
import os
import re
import subprocess
import sys
import uuid
import zipfile
from html.parser import HTMLParser
from xml.etree import ElementTree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build as B  # noqa: E402
from highlight import highlight  # noqa: E402

HERE = B.HERE
OUT = os.path.join(HERE, "out")
EPUB_PATH = os.path.join(OUT, f"myotis-rust-tour-{B.VERSION}.epub")

# ---------------------------------------------------------------- code rows

TOKEN = re.compile(r"(<span[^>]*>|</span>|\n|[^<\n]+)")


def split_highlighted(hl):
    """Split highlighted HTML into lines, closing and reopening spans at each
    line end so every line is balanced on its own."""
    lines, cur, open_ = [], [], []
    for tok in TOKEN.findall(hl):
        if tok == "\n":
            cur.extend("</span>" for _ in open_)
            lines.append("".join(cur))
            cur = list(open_)
        elif tok.startswith("<span"):
            open_.append(tok)
            cur.append(tok)
        elif tok == "</span>":
            if open_:
                open_.pop()
            cur.append(tok)
        else:
            cur.append(tok)
    cur.extend("</span>" for _ in open_)
    lines.append("".join(cur))
    return lines


def code_rows(hl, first):
    lines = split_highlighted(hl)
    last = first + len(lines) - 1
    w = len(str(last))
    rows = []
    for i, line in enumerate(lines):
        n = str(first + i).rjust(w)
        rows.append(f'<span class="row"><span class="ln">{n} </span>{line or " "}</span>')
    return w, "".join(rows)


def ep_code(m, where):
    a = B.attrs(m.group(1))
    cut = B.excerpt(a, where)
    if cut is None:
        return ""
    src, fr, to, body = cut
    lang = a.get("lang", "rust")
    shown = B.shown_path(src)
    title = a.get("title", "")
    cap = html.escape(shown)
    if title:
        cap = f"<b>{html.escape(title)}</b> · {cap}"
    rng = f"lines {fr}–{to}" if fr != to else f"line {fr}"
    w, rows = code_rows(highlight(body, lang), fr)
    return (f'<figure class="code"><figcaption>{cap} <span class="rng">{rng}</span></figcaption>'
            f'<pre class="code w{w}"><code>{rows}</code></pre></figure>')


def ep_wb(m, where):
    a = B.attrs(m.group(1))
    text = B.workbook_text(a.get("file", ""))
    if text is None:
        B.errors.append(f"{where}: x-wb file missing: {a.get('file')}")
        return ""
    text = text.rstrip("\n")
    label = html.escape(a.get("label", a.get("file", "")))
    w, rows = code_rows(highlight(text, a.get("lang", "rust")), 1)
    return (f'<figure class="code wb"><figcaption><b>{label}</b> '
            f'<span class="rng">workbook/{html.escape(a.get("file", ""))}</span></figcaption>'
            f'<pre class="code w{w}"><code>{rows}</code></pre></figure>')


# ---------------------------------------------------------------- quizzes

ANSWERS = []          # (stop_id, [(n, q), ...])
LETTERS = "ABCDEFGH"


def ep_quiz(m, where, stop_id):
    try:
        qs = json.loads(m.group(1))
    except json.JSONDecodeError as e:
        B.errors.append(f"{where}: quiz JSON invalid: {e}")
        return ""
    ANSWERS.append((stop_id, list(enumerate(qs, 1))))
    items = []
    for n, q in enumerate(qs, 1):
        qid = q["id"]
        kind = "Multiple choice" if q["type"] == "mcq" else "Written answer"
        parts = [f'<li class="question" id="q-{qid}"><p class="qhead"><b>Q{n}</b> · {kind}</p>',
                 f'<p class="qtext">{q["q"]}</p>']
        if q["type"] == "mcq":
            opts = "".join(f"<li>{o}</li>" for o in q["options"])
            parts.append(f'<ol class="opts" type="A">{opts}</ol>')
        else:
            parts.append('<p class="write">Answer it in your own words first, on paper or out loud. '
                         'Then compare it with the model answer and its key points.</p>')
        parts.append(f'<p class="to-answer"><a href="#a-{qid}">Answer →</a></p></li>')
        items.append("".join(parts))
    return (f'<section class="checkpoint" id="cp-{stop_id}"><h2>Checkpoint</h2>'
            f'<p class="cp-intro">{len(qs)} questions. Decide on your answer before you follow the link: '
            f'the answers are collected in the appendix “Checkpoint answers”, each with a link back here.</p>'
            f'<ol class="quiz">{"".join(items)}</ol></section>')


# ---------------------------------------------------------------- HTML -> XHTML

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
BLOCK = {"address", "article", "aside", "blockquote", "details", "div", "dl", "fieldset", "figcaption", "figure",
         "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "main", "nav", "ol", "p", "pre",
         "section", "table", "ul", "svg"}
SVG_TAGS = {t.lower(): t for t in [
    "linearGradient", "radialGradient", "clipPath", "textPath", "foreignObject", "feGaussianBlur", "feOffset",
    "feBlend", "feMerge", "feMergeNode", "feFlood", "feComposite", "feColorMatrix", "feDropShadow",
    "animateTransform", "animateMotion"]}
SVG_ATTRS = {a.lower(): a for a in [
    "viewBox", "preserveAspectRatio", "markerWidth", "markerHeight", "refX", "refY", "markerUnits",
    "gradientUnits", "gradientTransform", "patternUnits", "patternContentUnits", "patternTransform",
    "textLength", "lengthAdjust", "startOffset", "stdDeviation", "pathLength", "maskUnits", "maskContentUnits",
    "clipPathUnits", "spreadMethod", "attributeName", "repeatCount", "calcMode", "keyTimes", "keySplines",
    "baseFrequency", "numOctaves", "tableValues", "dominantBaseline"]}
NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]*")
DROP = {"script", "button", "input", "textarea", "select", "style", "noscript"}


class XConv(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.stack = []
        self.skip = 0

    # -- helpers
    def _close_to(self, name):
        while self.stack:
            t = self.stack.pop()
            self.out.append(f"</{t}>")
            if t == name:
                return

    def _in_svg(self):
        return "svg" in self.stack

    def _attrs(self, attrs, svg):
        out = []
        seen = set()
        for k, v in attrs:
            if svg:
                k = SVG_ATTRS.get(k, k)
            if k in seen or k.startswith("on"):
                continue
            seen.add(k)
            v = k if v is None else v
            out.append(f' {k}="{html.escape(v, quote=True)}"')
        return "".join(out)

    def _implied(self, tag):
        if not self.stack:
            return
        if tag in BLOCK and self.stack[-1] == "p":
            self._close_to("p")
        if tag == "li":
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i] in ("ul", "ol"):
                    break
                if self.stack[i] == "li":
                    self._close_to("li")
                    break
        if tag in ("dt", "dd"):
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i] == "dl":
                    break
                if self.stack[i] in ("dt", "dd"):
                    self._close_to(self.stack[i])
                    break
        if tag in ("tr", "td", "th", "thead", "tbody", "tfoot"):
            stops = {"tr": ("tr",), "td": ("td", "th"), "th": ("td", "th"),
                     "thead": ("thead", "tbody", "tfoot"), "tbody": ("thead", "tbody", "tfoot"),
                     "tfoot": ("thead", "tbody", "tfoot")}[tag]
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i] == "table":
                    break
                if self.stack[i] in stops:
                    self._close_to(self.stack[i])
                    break

    # -- parser callbacks
    def handle_starttag(self, tag, attrs, selfclose=False):
        if not NAME.fullmatch(tag):
            B.warnings.append(f"text that looks like a tag kept as text: {self.get_starttag_text()[:60]}")
            return self.handle_data(self.get_starttag_text())
        if self.skip or tag in DROP:
            if tag not in VOID and not selfclose:
                self.skip += 1
            return
        svg = self._in_svg() or tag == "svg"
        name = SVG_TAGS.get(tag, tag) if svg else tag
        attrs = list(attrs)
        if name == "details":
            name = "div"
            cls = dict(attrs).get("class", "")
            attrs = [(k, v) for k, v in attrs if k not in ("class", "open")] + [("class", (cls + " deep").strip())]
        elif name == "summary":
            name = "p"
            attrs = [("class", "deep-sum")]
        if name == "svg" and not any(k == "xmlns" for k, _ in attrs):
            attrs.append(("xmlns", "http://www.w3.org/2000/svg"))
        if not svg:
            self._implied(name)
        a = self._attrs(attrs, svg)
        if name in VOID and not svg:
            self.out.append(f"<{name}{a}/>")
        elif selfclose:
            self.out.append(f"<{name}{a}/>")
        else:
            self.out.append(f"<{name}{a}>")
            self.stack.append(name)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs, selfclose=True)

    def handle_endtag(self, tag):
        if not NAME.fullmatch(tag):
            return self.handle_data(f"</{tag}>")
        if self.skip:
            if tag in DROP:
                self.skip -= 1
            return
        if tag in DROP:
            return
        name = {"details": "div", "summary": "p"}.get(tag, tag)
        if self._in_svg():
            name = SVG_TAGS.get(name, name)
        if name in VOID:
            return
        if name in self.stack:
            self._close_to(name)

    def handle_data(self, data):
        if self.skip:
            return
        self.out.append(html.escape(data, quote=False))

    def handle_comment(self, data):
        pass

    def handle_decl(self, decl):
        pass

    def result(self):
        self.close()
        while self.stack:
            self.out.append(f"</{self.stack.pop()}>")
        return "".join(self.out)


def to_xhtml(fragment):
    c = XConv()
    c.feed(fragment)
    return c.result()


# ---------------------------------------------------------------- pages

def page(title, body, file_label):
    return ('<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE html>\n'
            '<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops" '
            'xml:lang="en" lang="en">\n<head>\n<meta charset="utf-8"/>\n'
            f'<title>{html.escape(title)}</title>\n'
            '<link rel="stylesheet" type="text/css" href="css/book.css"/>\n</head>\n'
            f'<body class="{file_label}">\n{body}\n</body>\n</html>\n')


def reading_chapter(progress_html):
    lib = re.search(r'<h2 class="section-title">Your offline library</h2>.*?</ul>', progress_html, re.S).group(0)
    rows = []
    for key, c in B.CONCEPTS.items():
        items = []
        for it in c["items"]:
            t = html.escape(it["title"])
            if it.get("href"):
                t = f'<a href="{html.escape(it["href"])}">{t}</a>'
            note = f' <span class="note">— {html.escape(it["note"])}</span>' if it.get("note") else ""
            off = "" if it.get("offline", False) else ' <span class="note">(online only)</span>'
            items.append(f'<li><b>{html.escape(it["src"])}</b>: {t}{note}{off}</li>')
        rows.append(f'<section class="concept" id="read-{key}"><h3>{html.escape(c["label"])}</h3>'
                    f'<p>{html.escape(c["blurb"])} <a href="#{c["stop"]}">{html.escape(c["stopLabel"])}</a></p>'
                    f'<ul>{"".join(items)}</ul></section>')
    return (
        '<section class="stop" id="progress"><header class="stop-head"><div class="eyebrow">After the tour</div>'
        '<h1>Reading list</h1><p class="lede">Every checkpoint question is tagged with the Rust concepts it tests. '
        'When a concept keeps tripping you up, read the chapters listed under it. Links that start with '
        '<code>file://</code> point to the documentation rustup installed on your Mac; in an ebook reader they '
        'may not open, so the chapter titles are given in full: find them in the same book with '
        '<code>rustup doc --book</code> (or <code>--std</code>, <code>--rust-by-example</code>).</p></header>'
        f'<h2 class="section-title">By concept</h2>{"".join(rows)}{lib}</section>'
    )


def answers_chapter(titles):
    out = ['<section class="stop answers" id="answers"><header class="stop-head"><div class="eyebrow">Appendix</div>'
           '<h1>Checkpoint answers</h1><p class="lede">One section per stop. For multiple choice, the correct option '
           'and why. For written answers, a model answer and the points a good answer covers: count how many of '
           'yours hit. Four of five is solid; two or fewer means the concept deserves a second pass with the '
           'reading list.</p></header>']
    for stop_id, qs in ANSWERS:
        out.append(f'<section class="ans-stop" id="ans-{stop_id}"><h2><a href="#{stop_id}">{html.escape(titles[stop_id])}</a></h2>')
        for n, q in qs:
            qid = q["id"]
            out.append(f'<div class="answer" id="a-{qid}"><p class="qhead"><b>Q{n}</b> · {q["q"]}</p>')
            if q["type"] == "mcq":
                k = q["answer"]
                out.append(f'<p class="verdict"><b>Answer: {LETTERS[k]}.</b> {q["options"][k]}</p>')
                out.append(f'<p>{q["explain"]}</p>')
            else:
                out.append(f'<p class="verdict"><b>Model answer.</b> {q["model"]}</p>')
                pts = "".join(f"<li>{p}</li>" for p in q["points"])
                out.append(f'<p class="pts-head">A good answer covers:</p><ul class="pts">{pts}</ul>')
            out.append(f'<p class="back"><a href="#q-{qid}">← Back to the question</a></p></div>')
        out.append("</section>")
    out.append("</section>")
    return "".join(out)


def about_chapter(n_stops, n_q, brand_sub, hours):
    return f'''<section class="stop" id="about"><header class="stop-head"><div class="eyebrow">Before you start</div>
<h1>About this edition ({B.VERSION})</h1>
<p class="lede">This is the ebook edition of the Myotis Rust Tour: a guided walk through every Rust file in
the Myotis workspace, written for a developer who knows Java and Kotlin well and is still building a feel for
Rust's memory model. It is the same text as the HTML tour, rebuilt so it needs nothing but an ebook reader.</p></header>
<div class="prose">
<p><b>What it covers.</b> {html.escape(brand_sub)}. {n_stops} stops and {n_q} checkpoint questions. Every code
excerpt is cut verbatim from that commit at build time, with its real line numbers, so you can find any of them
again with <code>git show 5263a421:rust/&lt;path&gt;</code>.</p>
<p><b>How to read it.</b> Front to back. Stop 0 is a map of the workspace and ends with the full route: the
same order in legs of a few hours, with each workbook exercise placed after the stop it practises. Stop 1 is a primer on the
Rust ideas the rest leans on: ownership, borrowing, lifetimes, traits, smart pointers, async, and methods and
<code>self</code>. The whole book reads in about {hours} hours; eight hours of reading cover the first leg and most of
the second.</p>
<p><b>Checkpoints.</b> Each stop ends with a checkpoint. In this edition nothing is graded for you: decide on
your answer, then follow “Answer →” to the appendix and come back with “← Back to the question”. For written
questions, say or write your answer first, then count the key points you covered.</p>
<p><b>Code on a small screen.</b> Excerpts keep their line numbers; long lines wrap with a hanging indent. The
diagrams are drawn as light plates so they read in every reader theme. Landscape on a phone, or any tablet,
reads best.</p>
<p><b>The workbook.</b> Stop 22 has ten exercises with their starter code, hints and solutions printed in full.
The runnable copy is in the Myotis repository at <code>docs/tour/workbook</code>
(<code>cp -R starter mine</code>, then <code>cargo test --offline</code>); with only the ebook, work them on paper.</p>
<p><b>Links.</b> Links inside the book work everywhere. Links to <code>file://</code> paths open the Rust
documentation installed on your Mac and may do nothing in an ebook reader; the reading list names every chapter
in full so you can look it up in the books themselves.</p>
</div></section>'''


def title_chapter(brand_sub):
    return f'''<section class="titlepage" id="title"><p class="t-kicker">Edition {B.VERSION} · code at {B.COMMIT[:8]}</p>
<h1 class="t-title">Myotis <span>Rust</span> Tour</h1>
<p class="t-sub">A guided tour of a light-client wallet engine, for Java and Kotlin developers</p>
<p class="t-meta">{html.escape(brand_sub)}</p></section>'''


# ---------------------------------------------------------------- cover

COVER_HTML = """<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;width:1600px;height:2400px;background:#141b22;overflow:hidden}
.c{position:absolute;inset:0;padding:150px 130px;box-sizing:border-box;display:flex;flex-direction:column;
font-family:"Avenir Next","Helvetica Neue",Arial,sans-serif;color:#eef1f4}
.k{font:600 38px/1.2 Menlo,monospace;letter-spacing:.08em;color:#8a96a3;text-transform:uppercase}
h1{font-weight:800;font-size:230px;line-height:.9;margin:70px 0 0;letter-spacing:-.03em}
h1 span{color:#e0663a}
.s{font-family:Charter,"Iowan Old Style",Georgia,serif;font-size:64px;line-height:1.3;color:#c9d1d9;margin-top:70px;max-width:1250px}
.crates{margin-top:auto;font:500 36px/1.75 Menlo,monospace;color:#8a96a3;columns:2;column-gap:80px}
.crates b{color:#e0663a;font-weight:600}
.f{margin-top:80px;padding-top:40px;border-top:3px solid #3a4652;display:flex;justify-content:space-between;
font:500 34px/1.3 Menlo,monospace;color:#8a96a3}
</style><div class="c"><div class="k">Edition VERSION</div>
<h1>Myotis<br><span>Rust</span><br>Tour</h1>
<div class="s">Every Rust file of a light-client Ethereum wallet engine, read slowly, for Java and Kotlin developers.</div>
<div class="crates">CRATES</div>
<div class="f"><span>STATS</span><span>COMMIT</span></div></div>"""

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def make_cover(tmp, stats, commit):
    """Render the cover with headless Chrome; None (a book without a cover image) without it."""
    if not os.path.exists(CHROME):
        B.warnings.append("Google Chrome not found: the EPUB has no cover image")
        return None
    crates = ["myotis-core", "myotis-bls", "myotis-wire", "myotis-consensus", "myotis-evm", "myotis-net",
              "myotis-engine", "uniffi-bindgen", "myotis-node", "myotis-rpcd", "roost", "tor-poc"]
    ch = "<br>".join(f"<b>›</b> {c}" for c in crates)
    doc = COVER_HTML.replace("CRATES", ch).replace("STATS", stats).replace("COMMIT", commit[:8]).replace("VERSION", B.VERSION)
    src = os.path.join(tmp, "cover.html")
    png = os.path.join(tmp, "cover.png")
    open(src, "w", encoding="utf-8").write(doc)
    if os.path.exists(png):
        os.remove(png)
    subprocess.run([CHROME, "--headless=new", f"--user-data-dir={os.path.join(tmp, 'chrome-profile')}",
                    "--hide-scrollbars", "--force-device-scale-factor=1", "--window-size=1600,2400",
                    f"--screenshot={png}", "file://" + src],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    return open(png, "rb").read()


# ---------------------------------------------------------------- main

def total_hours(stops):
    import route
    return round(sum(route.minutes(int(m["num"])) for m, _ in stops) / 60)


def collect(code=None, wb=None):
    """Expand every stop and assemble the book's chapters as XHTML fragments:
    [(file, title, body, nav label, part)], plus the stop metadata and counts.
    `code`/`wb` replace the excerpt renderers (markdown.py passes its own)."""
    B.expand_code = code or ep_code
    B.expand_wb = wb or ep_wb
    B.expand_quiz = ep_quiz
    stop_dir = os.path.join(HERE, "stops")
    stops = []
    for f in sorted(x for x in os.listdir(stop_dir) if x.endswith(".html")):
        r = B.process_stop(os.path.join(stop_dir, f))
        if r:
            stops.append(r)

    # the file index, as in build.py
    groups = {}
    for shown, n, fid, sid in B.file_entries:
        if shown.endswith(".rs"):
            groups.setdefault(shown.split("/")[0], []).append((shown, n, fid))
    order = ["myotis-bls", "myotis-core", "myotis-wire", "myotis-consensus", "myotis-evm", "myotis-net",
             "myotis-engine", "uniffi-bindgen", "myotis-node", "myotis-rpcd", "roost", "tor-poc"]
    idx = ['<div class="file-index">']
    for crate in order + sorted(set(groups) - set(order)):
        items = groups.get(crate)
        if not items:
            continue
        total = sum(n for _, n, _ in items)
        idx.append(f'<h3 class="index-crate">{html.escape(crate)} <span>{len(items)} files · {B.fmt_int(total)} lines</span></h3><ul class="toc-files">')
        for shown, n, fid in items:
            idx.append(f'<li><a href="#{fid}">{html.escape(shown[len(crate) + 1:])}</a> <span>{B.fmt_int(n)}</span></li>')
        idx.append("</ul>")
    idx.append("</div>")
    index_html = "".join(idx)

    all_rs = []
    for root, dirs, fs in os.walk(B.RUST):
        dirs[:] = [d for d in dirs if d not in ("target", "node_modules", ".git")]
        all_rs += [os.path.join(root, f) for f in fs if f.endswith(".rs")]
    n_lines = sum(len(B.lines_of(p)) for p in all_rs)
    n_crates = len({os.path.relpath(p, B.RUST).split(os.sep)[0] for p in all_rs})
    brand_sub = (f"{B.fmt_int(n_lines)} lines in {len(all_rs)} files and {n_crates} crates, "
                 f"at commit {B.COMMIT[:8]}")

    titles = {m["id"]: f'Stop {m["num"]} · {m["title"]}' for m, _ in stops}
    n_q = sum(len(qs) for _, qs in ANSWERS)

    chapters = []  # (file, title, xhtml body, nav label, part)
    chapters.append(("title.xhtml", "Myotis Rust Tour", to_xhtml(title_chapter(brand_sub)), None, None))
    chapters.append(("about.xhtml", "About this edition", to_xhtml(about_chapter(len(stops), n_q, brand_sub, total_hours(stops))),
                     "About this edition", None))
    for meta, body in stops:
        body = body.replace("<x-file-index></x-file-index>", index_html)
        sec = f'<section class="stop" id="{meta["id"]}">{body}</section>'
        fname = f'stop-{int(meta["num"]):02d}.xhtml'
        chapters.append((fname, titles[meta["id"]], to_xhtml(sec), titles[meta["id"]], meta.get("part")))
    progress = open(os.path.join(HERE, "shell", "progress.html"), encoding="utf-8").read()
    chapters.append(("answers.xhtml", "Checkpoint answers", to_xhtml(answers_chapter(titles)),
                     "Checkpoint answers", "Appendices"))
    chapters.append(("reading.xhtml", "Reading list", to_xhtml(reading_chapter(progress)),
                     "Reading list", "Appendices"))
    return chapters, stops, n_q


def main():
    chapters, stops, n_q = collect()

    # cross-file links
    where = {}
    for fname, _, body, _, _ in chapters:
        for i in re.findall(r'\sid="([^"]+)"', body):
            if i in where:
                B.errors.append(f"duplicate id {i} in {fname} and {where[i]}")
            where[i] = fname
    broken = set()

    def relink(fname, body):
        def sub(m):
            target = m.group(1)
            f = where.get(target)
            if f is None:
                broken.add(target)
                return m.group(0)
            return f'href="#{target}"' if f == fname else f'href="{f}#{target}"'
        return re.sub(r'href="#([^"]+)"', sub, body)

    chapters = [(f, t, relink(f, b), n, p) for f, t, b, n, p in chapters]
    if broken:
        B.errors.append(f"broken links: {sorted(broken)[:20]}")

    css = open(os.path.join(HERE, "shell", "book.css"), encoding="utf-8").read()
    docs_base = B.rustdoc_base(local=True)
    files = {}
    for fname, title, body, _, _ in chapters:
        doc = page(title, body.replace("rustdoc:", docs_base).replace("repodoc:", B.ONLINE_REPODOC), fname.split(".")[0])
        try:
            ElementTree.fromstring(doc.replace("<!DOCTYPE html>", ""))
        except ElementTree.ParseError as e:
            B.errors.append(f"{fname}: not well-formed: {e}")
            line = int(str(e).split("line ")[1].split(",")[0])
            print("\n".join(doc.splitlines()[max(0, line - 3):line + 1])[:2000])
        files[fname] = doc

    # navigation
    nav = ['<nav epub:type="toc" id="toc"><h1>Contents</h1><ol>']
    ncx_points = []
    last_part, open_part = None, False
    play = 0
    for fname, title, _, label, part in chapters:
        if not label:
            continue
        if part != last_part:
            if open_part:
                nav.append("</ol></li>")
                open_part = False
            if part:
                nav.append(f"<li><span>{html.escape(part)}</span><ol>")
                open_part = True
            last_part = part
        nav.append(f'<li><a href="{fname}">{html.escape(label)}</a></li>')
        play += 1
        ncx_points.append(f'<navPoint id="np{play}" playOrder="{play}"><navLabel><text>{html.escape(label)}</text>'
                          f'</navLabel><content src="{fname}"/></navPoint>')
    if open_part:
        nav.append("</ol></li>")
    nav.append("</ol></nav>")
    tmp = os.path.join(B.CACHE, "epub")
    os.makedirs(tmp, exist_ok=True)
    cover = make_cover(tmp, f"{len(stops)} stops · {n_q} questions", B.COMMIT)
    nav.append('<nav epub:type="landmarks" hidden="hidden"><ol>'
               + ('<li><a epub:type="cover" href="cover.xhtml">Cover</a></li>' if cover else '') +
               '<li><a epub:type="toc" href="nav.xhtml">Contents</a></li>'
               '<li><a epub:type="bodymatter" href="stop-00.xhtml">Start of the tour</a></li></ol></nav>')
    files["nav.xhtml"] = page("Contents", "".join(nav), "nav")
    if cover:
        files["cover.xhtml"] = page("Cover", '<div class="cover"><img src="images/cover.png" alt="Myotis Rust Tour"/></div>', "cover")

    book_id = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"myotis-rust-tour/{B.VERSION}"))
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    spine_files = (["cover.xhtml"] if cover else []) + [c[0] for c in chapters]
    manifest = ['<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>',
                '<item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>',
                '<item id="css" href="css/book.css" media-type="text/css"/>']
    if cover:
        manifest.append('<item id="cover-img" href="images/cover.png" media-type="image/png" properties="cover-image"/>')
    for f in spine_files:
        props = ' properties="svg"' if "<svg" in files[f] else ""
        manifest.append(f'<item id="{f.split(".")[0]}" href="{f}" media-type="application/xhtml+xml"{props}/>')
    spine = "".join(f'<itemref idref="{f.split(".")[0]}"/>' for f in spine_files)
    opf = f'''<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bookid" xml:lang="en" prefix="schema: http://schema.org/">
<metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:identifier id="bookid">{book_id}</dc:identifier>
<dc:title>Myotis Rust Tour {B.VERSION}</dc:title>
<dc:creator>Claude, for Dirk Jäckel</dc:creator>
<dc:language>en</dc:language>
<dc:date>{now[:10]}</dc:date>
<dc:description>A guided tour of every Rust file in the Myotis workspace (commit {B.COMMIT[:8]}) for Java and Kotlin developers, with checkpoints, a workbook and a reading list.</dc:description>
<meta property="dcterms:modified">{now}</meta>
<meta property="schema:version">{B.VERSION}</meta>
{'<meta name="cover" content="cover-img"/>' if cover else ''}
</metadata>
<manifest>
{chr(10).join(manifest)}
</manifest>
<spine toc="ncx">{spine}</spine>
{'<guide><reference type="cover" title="Cover" href="cover.xhtml"/></guide>' if cover else ''}
</package>
'''
    ncx = f'''<?xml version="1.0" encoding="utf-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1"><head><meta name="dtb:uid" content="{book_id}"/></head>
<docTitle><text>Myotis Rust Tour</text></docTitle><navMap>{"".join(ncx_points)}</navMap></ncx>
'''
    container = ('<?xml version="1.0" encoding="utf-8"?>\n<container version="1.0" '
                 'xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles>'
                 '<rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>'
                 '</rootfiles></container>\n')
    for name, doc in (("content.opf", opf), ("toc.ncx", ncx), ("nav.xhtml", files["nav.xhtml"])):
        try:
            ElementTree.fromstring(doc.replace("<!DOCTYPE html>", ""))
        except ElementTree.ParseError as e:
            B.errors.append(f"{name}: not well-formed: {e}")

    if B.errors:
        for e in B.errors:
            print("ERROR:", e)
        sys.exit(1)

    os.makedirs(OUT, exist_ok=True)
    if os.path.exists(EPUB_PATH):
        os.remove(EPUB_PATH)
    with zipfile.ZipFile(EPUB_PATH, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), "application/epub+zip", compress_type=zipfile.ZIP_STORED)
        z.writestr("META-INF/container.xml", container, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/content.opf", opf, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/toc.ncx", ncx, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/css/book.css", css, compress_type=zipfile.ZIP_DEFLATED)
        if cover:
            z.writestr("OEBPS/images/cover.png", cover, compress_type=zipfile.ZIP_DEFLATED)
        for f, doc in files.items():
            z.writestr("OEBPS/" + f, doc, compress_type=zipfile.ZIP_DEFLATED)
    sizes = sorted(((len(d), f) for f, d in files.items()), reverse=True)[:5]
    print(f"chapters={len(chapters)} questions={n_q} largest="
          + ", ".join(f"{f} {s // 1024} KB" for s, f in sizes))
    print(f"wrote {EPUB_PATH} ({os.path.getsize(EPUB_PATH) // 1024} KB)")
    for w in B.warnings:
        print("WARN:", w)


if __name__ == "__main__":
    main()
