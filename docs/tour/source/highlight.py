"""Tiny build-time syntax highlighter (no dependencies).

Emits <span class="tk-…"> tokens: k keyword, t type, s string, n number,
c comment, f function name, a attribute/annotation, m macro, l lifetime.
Good enough for reading code on a plane; not a parser.
"""
import html
import re

RUST_KW = set("""as async await break const continue crate dyn else enum extern false fn for if impl in let loop
match mod move mut pub ref return self static struct super trait true type unsafe use where while union yield
macro_rules""".split())
RUST_PRIM = set("""u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize f32 f64 bool char str Self""".split())

KT_KW = set("""package import class interface object fun val var if else when for while do return break continue
throw try catch finally is as in out by get set init constructor companion data sealed enum abstract open
override private protected public internal lateinit suspend inline reified external annotation null true false
this super typealias vararg operator infix const crossinline noinline actual expect""".split())
JAVA_KW = set("""abstract assert boolean break byte case catch char class const continue default do double else enum
extends final finally float for goto if implements import instanceof int interface long native new package
private protected public return short static strictfp super switch synchronized this throw throws transient try
void volatile while var record sealed permits yield null true false""".split())
C_KW = set("""auto break case char const continue default do double else enum extern float for goto if inline int long
register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while
bool true false NULL int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t size_t""".split())

def _esc(s):
    return html.escape(s, quote=False)

def _span(cls, s):
    return f'<span class="tk-{cls}">{_esc(s)}</span>'

RUST_RE = re.compile(r"""
 (?P<c>//[^\n]*|/\*[\s\S]*?\*/)
|(?P<a>\#!?\[(?:[^\[\]\n]|\[[^\[\]\n]*\])*\])
|(?P<rs>b?r(?P<h>\#*)"[\s\S]*?"(?P=h))
|(?P<s>b?"(?:\\[\s\S]|[^"\\])*")
|(?P<ch>b?'(?:\\u\{[0-9a-fA-F]+\}|\\[^\n]|[^'\\\n])')
|(?P<l>'[A-Za-z_]\w*)
|(?P<n>\b(?:0x[0-9a-fA-F_]+|0b[01_]+|0o[0-7_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)(?:[iu](?:8|16|32|64|128|size)|f32|f64)?\b)
|(?P<m>\b[A-Za-z_]\w*!(?=\s*[(\[{]))
|(?P<id>\b[A-Za-z_]\w*\b)
""", re.X)

GEN_RE = re.compile(r"""
 (?P<c>//[^\n]*|/\*[\s\S]*?\*/)
|(?P<a>@[A-Za-z_][\w.]*)
|(?P<s>\"\"\"[\s\S]*?\"\"\"|"(?:\\[\s\S]|[^"\\\n])*"|'(?:\\[\s\S]|[^'\\\n])+')
|(?P<n>\b(?:0x[0-9a-fA-F_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)[LlFfuU]*\b)
|(?P<id>\b[A-Za-z_]\w*\b)
""", re.X)

C_RE = re.compile(r"""
 (?P<c>//[^\n]*|/\*[\s\S]*?\*/)
|(?P<a>^[ \t]*\#[^\n]*)
|(?P<s>"(?:\\[\s\S]|[^"\\\n])*"|'(?:\\[\s\S]|[^'\\\n])+')
|(?P<n>\b(?:0x[0-9a-fA-F]+|\d+)[uUlL]*\b)
|(?P<id>\b[A-Za-z_]\w*\b)
""", re.X | re.M)

TOML_RE = re.compile(r"""
 (?P<c>\#[^\n]*)
|(?P<a>^[ \t]*\[\[?[^\]\n]+\]\]?)
|(?P<s>\"\"\"[\s\S]*?\"\"\"|"(?:\\[\s\S]|[^"\\\n])*"|'[^'\n]*')
|(?P<key>^[ \t]*[A-Za-z0-9_.\-"]+(?=[ \t]*=))
|(?P<n>\b(?:true|false|\d[\d_.]*)\b)
""", re.X | re.M)


def _ident_class(lang, word, text, end):
    nxt = text[end:end + 1]
    if lang == "rust":
        if word in RUST_KW:
            return "k"
        if word in RUST_PRIM:
            return "t"
    elif lang == "kotlin":
        if word in KT_KW:
            return "k"
    elif lang == "java":
        if word in JAVA_KW:
            return "k"
    elif lang == "c":
        if word in C_KW:
            return "k"
    if word[:1].isupper() and (len(word) == 1 or not word.isupper()):
        return "t"
    if nxt == "(" or (lang == "rust" and text[end:end + 3] == "::<"):
        return "f"
    return None


def highlight(text, lang):
    lang = (lang or "rust").lower()
    if lang in ("text", "plain", "json", "sh", "bash"):
        return _esc(text)
    rx = {"rust": RUST_RE, "kotlin": GEN_RE, "java": GEN_RE, "c": C_RE, "toml": TOML_RE}.get(lang)
    if rx is None:
        return _esc(text)
    out, pos = [], 0
    for m in rx.finditer(text):
        if m.start() > pos:
            out.append(_esc(text[pos:m.start()]))
        kind = m.lastgroup
        tok = m.group(0)
        if kind == "h":
            kind = "rs"
        if kind in ("rs", "s", "ch"):
            out.append(_span("s", tok))
        elif kind == "id":
            cls = _ident_class(lang, tok, text, m.end())
            out.append(_span(cls, tok) if cls else _esc(tok))
        elif kind == "key":
            out.append(_span("f", tok))
        else:
            out.append(_span(kind, tok))
        pos = m.end()
    out.append(_esc(text[pos:]))
    return "".join(out)
