#!/usr/bin/env python3
"""Render the Myotis Rust Tour as GitHub-flavoured Markdown into ../book/.

Same stops and assembly as the EPUB (epub.collect), then a converter from the
chapters' well-formed XHTML to Markdown:
  * code excerpts -> fenced blocks with their path and line range
  * diagrams      -> standalone SVG files in book/img/ (light plate, inlined palette)
  * callouts      -> GitHub alerts; deep dives -> <details>
  * checkpoints   -> static questions, answers in answers.md

    python3 markdown.py      (rewrites ../book/ completely)
"""
import html
import os
import re
import shutil
import sys
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build as B  # noqa: E402
import epub as E  # noqa: E402

HERE = B.HERE
BOOK = os.path.join(B.TOUR, "book")
IMG = os.path.join(BOOK, "img")
SVGNS = "http://www.w3.org/2000/svg"
ET.register_namespace("", SVGNS)

SVG_STYLE = (
    "svg{color:#121a22;--ground:#eef1f4;--ground-2:#e6eaee;--surface:#f8fafb;--ink:#121a22;--ink-2:#47525f;"
    "--ink-3:#6b7784;--rule:#d3dae1;--rule-strong:#b7c1cb;--oxide:#b4441a;--oxide-ink:#8f3310;"
    "--oxide-wash:#f6e4dc;--jvm:#6a4bd8;--jvm-ink:#4f33b3;--jvm-wash:#ebe6fb;--ok:#1f7a4d;--ok-ink:#1f7a4d;"
    "--ok-wash:#dcefe4;--warn:#9a620a;--warn-ink:#7a4d08;--warn-wash:#f5ead3;--bad:#b42335;--bad-ink:#8f1c2a;"
    "--bad-wash:#f7dfe2}"
    "text{font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif}"
    ".mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.muted{color:#6b7784}"
)

# ---------------------------------------------------------------- excerpt renderers


def md_code(m, where):
    a = B.attrs(m.group(1))
    cut = B.excerpt(a, where)
    if cut is None:
        return ""
    src, fr, to, body = cut
    rng = f"lines {fr}–{to}" if fr != to else f"line {fr}"
    return (f'<figure class="mdcode" data-lang="{html.escape(a.get("lang", "rust"))}" '
            f'data-title="{html.escape(a.get("title", ""), quote=True)}" '
            f'data-path="{html.escape(B.shown_path(src), quote=True)}" data-range="{rng}">'
            f'<pre>{html.escape(body)}</pre></figure>')


def wb_path(name):
    """The real file behind a workbook name: solution-clean/ is solution/src/ without markers."""
    return "solution/src/" + name[len("solution-clean/"):] if name.startswith("solution-clean/") else name


def md_wb(m, where):
    a = B.attrs(m.group(1))
    text = B.workbook_text(a.get("file", ""))
    if text is None:
        B.errors.append(f"{where}: x-wb file missing: {a.get('file')}")
        return ""
    return (f'<figure class="mdcode" data-lang="{html.escape(a.get("lang", "rust"))}" '
            f'data-title="{html.escape(a.get("label", ""), quote=True)}" '
            f'data-path="docs/tour/workbook/{html.escape(wb_path(a.get("file", "")), quote=True)}" data-range="">'
            f'<pre>{html.escape(text.rstrip(chr(10)))}</pre></figure>')


# ---------------------------------------------------------------- XHTML -> Markdown

BLOCK_TAGS = {"address", "article", "aside", "blockquote", "details", "div", "dl", "fieldset", "figcaption",
              "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol",
              "p", "pre", "section", "table", "ul", "svg"}
ALERTS = {"watch": "WARNING", "jvm": "NOTE", "rust": "TIP"}


def local(tag):
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def classes(el):
    return el.get("class", "").split()


def esc(text):
    if not text:
        return ""
    t = re.sub(r"\s+", " ", text)
    t = t.replace("\\", "\\\\").replace("<", "&lt;")
    t = re.sub(r"&(?=#?\w+;)", "&amp;", t)
    return re.sub(r"([*_\[\]`|])", r"\\\1", t)


def code_span(text):
    t = re.sub(r"\s+", " ", text)
    if not t.strip():
        return ""
    n = max((len(r) for r in re.findall(r"`+", t)), default=0) + 1
    fence = "`" * n
    pad = " " if t.startswith("`") or t.endswith("`") or n > 1 else ""
    return f"{fence}{pad}{t}{pad}{fence}"


def wrap(mark, inner):
    """**inner** with the surrounding spaces moved outside the markers."""
    if not inner.strip():
        return inner
    lead = inner[:len(inner) - len(inner.lstrip())]
    trail = inner[len(inner.rstrip()):]
    return f"{lead}{mark}{inner.strip()}{mark}{trail}"


class Conv:
    def __init__(self, fname, where, ref_ids, img_prefix):
        self.fname = fname
        self.where = where          # id -> md file
        self.ref_ids = ref_ids      # ids some link points at
        self.img_prefix = img_prefix
        self.svg_n = 0

    # ---- links and anchors
    def href(self, h):
        if h.startswith("#"):
            target = h[1:]
            f = self.where.get(target)
            if f is None:
                B.warnings.append(f"{self.fname}: broken link {h}")
                return h
            if re.fullmatch(r"stop-\d\d", target):
                return f if f != self.fname else "#"
            return h if f == self.fname else f"{f}#{target}"
        if h.startswith("rustdoc:"):
            return B.ONLINE_RUSTDOC + h[len("rustdoc:"):]
        if h.startswith("repodoc:"):
            return "../../" + h[len("repodoc:"):]
        return h

    def anchor(self, el):
        i = el.get("id")
        return f'<a id="{i}"></a>' if i and i in self.ref_ids and not re.fullmatch(r"stop-\d\d", i) else ""

    # ---- inline
    def inline(self, el, links=True):
        out = [esc(el.text)]
        prev_el = False
        for c in el:
            piece = self.inline_el(c, links)
            if prev_el and piece and out and out[-1] and not out[-1][-1].isspace() and not piece[0].isspace():
                out.append(" ")
            out.append(piece)
            tail = esc(c.tail)
            out.append(tail)
            prev_el = not (c.tail and c.tail.strip())
        return "".join(out)

    def inline_el(self, c, links=True):
        tag, cls = local(c.tag), classes(c)
        if tag == "code":
            return code_span("".join(c.itertext()))
        if tag in ("b", "strong") or (tag == "span" and "k" in cls):
            return wrap("**", self.inline(c, links))
        if tag in ("em", "i"):
            return wrap("*", self.inline(c, links))
        if tag == "br":
            return "<br>"
        if tag == "a":
            inner = self.inline(c, links)
            anc = self.anchor(c)
            if not links or not c.get("href"):
                return anc + inner
            return f"{anc}[{inner.strip() or c.get('href')}]({self.href(c.get('href'))})"
        if tag == "span" and "tags" in cls:
            parts = [self.inline_el(t, links) for t in c if local(t.tag) == "a"]
            return "*" + " · ".join(p for p in parts if p) + "*" if parts else ""
        if tag == "span" and ("t" in cls or "hint" in cls or "rng" in cls or "note" in cls):
            inner = self.inline(c, links).strip()
            return f"*({inner})*" if inner else ""
        if tag == "span" and "offline-ok" in cls:
            return ""
        if tag == "small":
            inner = self.inline(c, links).strip()
            return f"— {inner}" if inner else ""
        if tag in BLOCK_TAGS:
            return " ".join(b.replace("\n", " ") for b in self.blocks(c))
        return self.inline(c, links)

    # ---- blocks
    def mixed(self, el):
        """Children of a container: runs of text and inline elements become paragraphs."""
        out, run = [], [esc(el.text)]

        def flush():
            p = "".join(run).strip()
            if p:
                out.append(self.para(p))
            run.clear()

        prev_el = False
        for c in el:
            if local(c.tag) in BLOCK_TAGS:
                flush()
                out.extend(self.blocks(c))
                prev_el = False
            else:
                piece = self.inline_el(c)
                if prev_el and piece and run and run[-1] and not run[-1][-1].isspace() and not piece[0].isspace():
                    run.append(" ")
                run.append(piece)
                prev_el = not (c.tail and c.tail.strip())
            run.append(esc(c.tail))
        flush()
        return out

    @staticmethod
    def para(p):
        p = p.strip()
        if re.match(r"(#|\d+[.)]\s|[-+]\s|>)", p):
            p = "\\" + p
        return p

    def blocks(self, el):
        tag, cls = local(el.tag), classes(el)
        anc = self.anchor(el)
        res = self._blocks(el, tag, cls)
        return ([anc] if anc else []) + res

    def _blocks(self, el, tag, cls):
        if tag == "svg":
            return [self.svg(el, el.get("aria-label", "diagram"))]
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            text = self.inline(el, links=False).strip()
            return ["#" * int(tag[1]) + " " + text] if text else []
        if tag == "p":
            if "deep-sum" in cls:
                return []
            text = self.inline(el).strip()
            return [self.para(text)] if text else []
        if tag == "hr":
            return ["---"]
        if tag in ("ul", "ol"):
            return [self.list_(el, tag, cls)]
        if tag == "table":
            return [self.table(el)]
        if tag == "pre":
            return [self.fence("".join(el.itertext()), "text")]
        if tag == "figure":
            return self.figure(el, cls)
        if tag == "figcaption":
            text = self.inline(el).strip()
            return [f"*{text}*"] if text else []
        if tag == "div" and "callout" in cls:
            kind = next((ALERTS[c] for c in cls if c in ALERTS), "NOTE")
            inner = "\n\n".join(self.mixed(el))
            return [f"> [!{kind}]\n" + "\n".join("> " + l if l else ">" for l in inner.split("\n"))]
        if tag == "div" and "deep" in cls:
            sum_el = next((c for c in el if local(c.tag) == "p" and "deep-sum" in classes(c)), None)
            summary = html.escape("".join(sum_el.itertext()).strip()) if sum_el is not None else "More"
            body = "\n\n".join(self.mixed(el))
            return [f"<details>\n<summary>{summary}</summary>\n\n{body}\n\n</details>"]
        if tag == "div" and "learn" in cls:
            out = []
            for c in el:
                if local(c.tag) == "h2":
                    out.extend(self.blocks(c))
            items = []
            for c in el:
                if local(c.tag) == "div":
                    line = self.inline(c).strip()
                    items.append("- " + re.sub(r"^(\*\*.+?\*\*)(?=\S)", r"\1 — ", line))
            return out + (["\n".join(items)] if items else [])
        if tag == "div" and "eyebrow" in cls:
            span = next((c for c in el if local(c.tag) == "span"), None)
            main = esc(el.text) + "".join(self.inline_el(c) + esc(c.tail) for c in el if c is not span)
            extra = self.inline(span).strip() if span is not None else ""
            return [f"*{main.strip()}*" + (f" · {extra}" if extra else "")]
        if tag == "div" and "chips" in cls:
            chips = [self.inline(c).strip() for c in el]
            return ["*" + " · ".join(c for c in chips if c) + "*"]
        if tag == "header" and "stop-head" in cls:
            kids = list(el)
            h1 = [c for c in kids if local(c.tag) == "h1"]
            rest = [c for c in kids if local(c.tag) != "h1"]
            out = []
            for c in h1 + rest:
                out.extend(self.blocks(c))
            return out
        # generic containers
        return self.mixed(el)

    def list_(self, el, tag, cls):
        lines = []
        letters = tag == "ol" and el.get("type") == "A"
        plain = tag == "ul" or {"quiz", "route-legs"} & set(cls)
        n = 0
        for li in el:
            if local(li.tag) != "li":
                continue
            n += 1
            if "question" in classes(li):
                anc = self.anchor(li)
                body = "\n\n".join(([anc] if anc else []) + self.mixed(li))
                lines.append(body + "\n")
                continue
            marker = f"- **{E.LETTERS[n - 1]}.** " if letters else ("- " if plain else f"{n}. ")
            indent = " " * (2 if marker.startswith("-") else len(marker))
            anc = self.anchor(li)
            bl = self.mixed(li)
            if not bl:
                bl = [""]
            first = (anc + bl[0]) if anc else bl[0]
            item = marker + first.replace("\n", "\n" + indent)
            for b in bl[1:]:
                item += "\n\n" + indent + b.replace("\n", "\n" + indent)
            lines.append(item)
        if "quiz" in cls:
            return "\n".join(lines).rstrip()
        sep = "\n\n" if any("\n\n" in l for l in lines) else "\n"
        return sep.join(lines)

    def table(self, el):
        rows = []
        for part in el:
            if local(part.tag) in ("thead", "tbody", "tfoot"):
                rows.extend(r for r in part if local(r.tag) == "tr")
            elif local(part.tag) == "tr":
                rows.append(part)
        if not rows:
            return ""

        def cell(c):
            text = " <br> ".join(b.replace("\n", " ") for b in self.mixed(c))
            text = re.sub(r"(?<!\\)\|", r"\\|", text)
            return text.strip() or " "

        grid = [[cell(c) for c in r if local(c.tag) in ("td", "th")] for r in rows]
        width = max(len(r) for r in grid)
        grid = [r + [" "] * (width - len(r)) for r in grid]
        head, body = grid[0], grid[1:]
        out = ["| " + " | ".join(head) + " |", "|" + "---|" * width]
        out += ["| " + " | ".join(r) + " |" for r in body]
        return "\n".join(out)

    @staticmethod
    def fence(text, lang):
        n = max(3, max((len(r) for r in re.findall(r"`{3,}", text)), default=0) + 1)
        return f"{'`' * n}{lang}\n{text}\n{'`' * n}"

    def figure(self, el, cls):
        if "mdcode" in cls:
            pre = next(c for c in el if local(c.tag) == "pre")
            title, path, rng = el.get("data-title", ""), el.get("data-path", ""), el.get("data-range", "")
            cap = (f"**{esc(title)}** · " if title else "") + code_span(path) + (f" · {rng}" if rng else "")
            lang = el.get("data-lang", "rust")
            return [cap, self.fence("".join(pre.itertext()), "text" if lang == "text" else lang)]
        out = []
        svg = next((c for c in el.iter() if local(c.tag) == "svg"), None)
        if svg is not None:
            out.append(self.svg(svg, svg.get("aria-label", "diagram")))
        for c in el:
            if local(c.tag) == "figcaption":
                out.extend(self.blocks(c))
            elif svg is None or (c is not svg and svg not in list(c.iter())):
                out.extend(self.blocks(c))
        return out

    def svg(self, svg, alt):
        self.svg_n += 1
        name = f"{self.img_prefix}-{self.svg_n}.svg"
        vb = [float(x) for x in re.split(r"[\s,]+", svg.get("viewBox", "0 0 800 400").strip())]
        svg = ET.fromstring(ET.tostring(svg))  # a copy
        svg.set("width", str(int(vb[2])))
        svg.set("height", str(int(vb[3])))
        style = ET.Element(f"{{{SVGNS}}}style")
        style.text = SVG_STYLE
        bg = ET.Element(f"{{{SVGNS}}}rect", {"x": str(vb[0]), "y": str(vb[1]), "width": str(vb[2]),
                                               "height": str(vb[3]), "fill": "#f8fafb"})
        svg.insert(0, bg)
        svg.insert(0, style)
        with open(os.path.join(IMG, name), "w", encoding="utf-8") as f:
            f.write(ET.tostring(svg, encoding="unicode"))
        alt = re.sub(r"[\[\]\n]", " ", alt).strip()
        return f"![{alt}](img/{name})"


def to_markdown(conv, body):
    root = ET.fromstring(f"<root>{body}</root>")
    out = []
    for c in root:
        out.extend(conv.blocks(c))
    text = "\n\n".join(b for b in out if b and b.strip())
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


# ---------------------------------------------------------------- the book

def readme(stops_meta, md_names, n_q, total_hours):
    lines = [
        f"# Myotis Rust Tour {B.VERSION}",
        "",
        "A guided reading of every Rust file in the Myotis workspace, for a developer who knows Java "
        "and Kotlin and is still building a feel for Rust's memory model. Each stop explains one part of "
        "the code through verbatim excerpts, teaches the Rust concepts those excerpts use, and ends with a "
        "checkpoint.",
        "",
        f"- **Pinned to commit `{B.COMMIT[:8]}`.** Every excerpt is cut from that commit with its real line "
        f"numbers, so `git show {B.COMMIT[:8]}:rust/<path>` finds it again. Paths of other documents in the "
        "text are as they were then (the docs have since been grouped into folders).",
        f"- **{len(stops_meta)} stops, {n_q} checkpoint questions, about {total_hours} hours of reading.** "
        "Read it front to back; [Stop 0](00-map.md) ends with the full route in legs of a few hours, with "
        "each workbook exercise placed after the stop it practises.",
        "- **Checkpoints** are static here: decide on your answer, then follow *Answer →* to "
        "[the answers](answers.md). The interactive HTML edition grades and tracks them.",
        "- **Other editions**, built from the same sources in [`../source`](../source/): an offline HTML page "
        "with graded quizzes and saved progress, and an EPUB. See [the tour's README](../README.md).",
        "",
        "## Contents",
        "",
    ]
    part = None
    for meta in stops_meta:
        if meta.get("part") != part:
            part = meta.get("part")
            lines += ["", f"**{part}**" if part else "", ""]
        lines.append(f"- [Stop {meta['num']} · {meta['title']}]({md_names[meta['id']]})")
    lines += ["", "**Appendices**", "", "- [Checkpoint answers](answers.md)", "- [Reading list](reading-list.md)", ""]
    return "\n".join(l for l in lines) .replace("\n\n\n", "\n\n")


def main():
    chapters, stops, n_q = E.collect(code=md_code, wb=md_wb)
    if B.errors:
        for e in B.errors:
            print("ERROR:", e)
        sys.exit(1)

    stop_files = sorted(f for f in os.listdir(os.path.join(HERE, "stops")) if f.endswith(".html"))
    by_num = {int(f[:2]): f[:-5] + ".md" for f in stop_files}
    md_of = {}
    md_names = {}
    for fname, *_ in chapters:
        if fname.startswith("stop-"):
            md_of[fname] = by_num[int(fname[5:7])]
    md_of["answers.xhtml"] = "answers.md"
    md_of["reading.xhtml"] = "reading-list.md"
    for meta, _ in stops:
        md_names[meta["id"]] = by_num[int(meta["num"])]

    where, ref_ids = {}, set()
    for fname, _, body, _, _ in chapters:
        if fname in md_of:
            for i in re.findall(r'\sid="([^"]+)"', body):
                where[i] = md_of[fname]
            ref_ids.update(re.findall(r'href="#([^"]+)"', body))

    if os.path.isdir(BOOK):
        shutil.rmtree(BOOK)
    os.makedirs(IMG)
    sizes = []
    for fname, title, body, _, _ in chapters:
        if fname not in md_of:
            continue
        name = md_of[fname]
        conv = Conv(name, where, ref_ids, name[:-3])
        text = to_markdown(conv, body) + f"\n---\n\n*Myotis Rust Tour {B.VERSION} · code at `{B.COMMIT[:8]}` · [contents](README.md)*\n"
        with open(os.path.join(BOOK, name), "w", encoding="utf-8") as f:
            f.write(text)
        sizes.append((len(text), name))
    hours = E.total_hours(stops)
    with open(os.path.join(BOOK, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme([m for m, _ in stops], md_names, n_q, hours))
    total = sum(s for s, _ in sizes)
    print(f"markdown: {len(sizes)} files, {total // 1024} KB, {len(os.listdir(IMG))} diagrams -> {os.path.relpath(BOOK)}")
    for w in sorted(set(B.warnings)):
        print("WARN:", w)


if __name__ == "__main__":
    main()
