#!/usr/bin/env python3
"""Generate the Android launcher / status-bar icons from assets/myotis_logo.svg.

Usage: python3 scripts/gen_android_icons.py [--preview DIR]

Writes android-app/src/main/res/{drawable/ic_launcher_foreground.xml,
drawable/ic_stat_myotis.xml, values/ic_launcher_background.xml,
mipmap-anydpi-v26/ic_launcher.xml}. Needs only the stdlib; --preview DIR also
renders a check sheet there (needs cairosvg + Pillow: pip install cairosvg pillow).
CI re-runs it and fails on a diff, so the committed resources never drift from
the logo (ci.yml, "Verify generated Android icons").

The SVG's <path> fills are taken as they are, path data normalised to one line
with two decimals (Android's PathParser treats only ' ' and ',' as separators),
so the SVG must stay plain: no transform= anywhere, fill-only paths, absolute
M/L/C/Z commands. The VectorDrawable <group> then places the bat on a square
canvas; Android applies scale first, then translate (pivot 0), so p' = s*p + t.
"""
import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVG = os.path.join(ROOT, 'assets', 'myotis_logo.svg')
RES = os.path.join(ROOT, 'android-app', 'src', 'main', 'res')
BG = '#1A1A24'              # brand dark (assets/social-preview.svg) behind the white bat
FG_SIZE = 108               # dp: the adaptive-icon canvas; launchers show the inner 72dp
SAFE_ZONE_RADIUS = 33.0     # dp: the 66dp safe-zone circle no launcher mask clips
STAT_SIZE, STAT_WIDTH = 24, 22.0   # dp: status-bar icon canvas, and the bat's width on it

PREVIEW = None
if '--preview' in sys.argv:
    i = sys.argv.index('--preview')
    if i + 1 >= len(sys.argv):
        sys.exit('usage: gen_android_icons.py [--preview DIR]')
    PREVIEW = sys.argv[i + 1]

# ---- read the SVG: plain fill paths only ----
with open(SVG, encoding='utf-8') as fh:
    svg = fh.read()
if 'transform=' in svg:
    sys.exit('refusing %s: it carries a transform= (paths are read untransformed; flatten it first)' % SVG)
paths = []
for elem in re.findall(r'<path\b[^>]*>', svg):
    d = re.search(r'\bd="\s*([^"]+)"', elem)
    fill = re.search(r'\bfill="([^"]*)"', elem)
    stroke = re.search(r'\bstroke="([^"]*)"', elem)
    opacity = re.search(r'\bopacity="([^"]*)"', elem)
    if (not d or not fill or fill.group(1) == 'none'
            or (stroke and stroke.group(1) != 'none')
            or (opacity and float(opacity.group(1)) != 1.0)):
        sys.exit('refusing %s: every <path> must be an opaque plain fill with a d= attribute, got %s'
                 % (SVG, re.sub(r'\s+', ' ', elem)[:100]))
    paths.append(d.group(1))
if not paths:
    sys.exit('no <path> elements in ' + SVG)

TOKEN = re.compile(r'[A-Za-z]|-?\d*\.?\d+(?:e-?\d+)?')


def f(v, places=2):
    """Shortest fixed-point text: 297.18, 14.91, 0.1335, 54."""
    return ('%.*f' % (places, round(float(v), places))).rstrip('0').rstrip('.') or '0'


def walk(d):
    """Yield (command, points) for absolute M/L/C/Z; refuse anything else."""
    toks = TOKEN.findall(d)
    i = 0
    while i < len(toks):
        t = toks[i]
        n = {'M': 1, 'L': 1, 'C': 3, 'Z': 0, 'z': 0}.get(t)
        if n is None:
            sys.exit('refusing %s: unsupported path command %r (absolute M/L/C/Z only)' % (SVG, t))
        pts = [(float(toks[i + 1 + 2 * k]), float(toks[i + 2 + 2 * k])) for k in range(n)]
        yield t.upper(), pts
        i += 1 + 2 * n


def normalise(d):
    return ' '.join(c + ' '.join('%s,%s' % (f(x), f(y)) for x, y in pts) for c, pts in walk(d))


def samples(ds):
    """Points on the paths' flattened curves (16 per cubic) — the silhouette's extent."""
    out = []
    for d in ds:
        cur = start = None
        for c, pts in walk(d):
            if c == 'M':
                cur = start = pts[0]
                out.append(cur)
            elif c == 'L':
                cur = pts[0]
                out.append(cur)
            elif c == 'C':
                p0, (p1, p2, p3) = cur, pts
                for k in range(1, 17):
                    u = k / 16
                    a, b, cc, e = (1 - u) ** 3, 3 * (1 - u) ** 2 * u, 3 * (1 - u) * u * u, u ** 3
                    out.append((a * p0[0] + b * p1[0] + cc * p2[0] + e * p3[0],
                                a * p0[1] + b * p1[1] + cc * p2[1] + e * p3[1]))
                cur = p3
            else:
                cur = start
    return out


norm = [normalise(d) for d in paths]
pts = samples(paths)
X0, X1 = min(x for x, _ in pts), max(x for x, _ in pts)
Y0, Y1 = min(y for _, y in pts), max(y for _, y in pts)
CX, CY = (X0 + X1) / 2, (Y0 + Y1) / 2
# The farthest point of the silhouette from the bounding box's centre (a wing tip):
# the launcher icon is scaled so that it lies ON the safe-zone circle.
MAX_R = max(math.hypot(x - CX, y - CY) for x, y in pts)
FG_SCALE = float(f(SAFE_ZONE_RADIUS / MAX_R, 4))
STAT_SCALE = float(f(STAT_WIDTH / (X1 - X0), 4))


def vector(size, scale, comment):
    """A VectorDrawable of the bat, white, centred on a size x size dp canvas."""
    tx, ty = size / 2 - CX * scale, size / 2 - CY * scale
    body = '\n'.join(
        '        <path\n            android:fillColor="#FFFFFFFF"\n            android:pathData="%s" />' % d
        for d in norm)
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<!--\n%s\n-->\n'
           '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
           '    android:width="%ddp"\n    android:height="%ddp"\n'
           '    android:viewportWidth="%d"\n    android:viewportHeight="%d">\n'
           '    <group\n        android:scaleX="%s"\n        android:scaleY="%s"\n'
           '        android:translateX="%s"\n        android:translateY="%s">\n%s\n    </group>\n</vector>\n'
           % (comment, size, size, size, size, f(scale, 4), f(scale, 4), f(tx), f(ty), body))
    return xml, (tx, ty)


def write(rel, text):
    path = os.path.join(RES, *rel.split('/'))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(text)


fg, (fgtx, fgty) = vector(FG_SIZE, FG_SCALE,
    "  The bat from assets/myotis_logo.svg (its own fill paths, path data normalised to one\n"
    "  line) as the adaptive launcher icon's foreground layer. GENERATED by\n"
    "  scripts/gen_android_icons.py — edit the SVG and re-run; CI fails on a hand edit.\n"
    "  The 108dp canvas is what launchers mask: the inner 72dp is visible, and the scale puts\n"
    "  the silhouette's farthest point (a wing tip) on the 66dp safe-zone circle, so no mask\n"
    "  shape clips it. Also the <monochrome> layer of the themed icon.")
stat, (sttx, stty) = vector(STAT_SIZE, STAT_SCALE,
    "  The same bat as a 24dp status-bar icon for the foreground-service notification (white on\n"
    "  transparent, as small icons must be — the system tints it). GENERATED by\n"
    "  scripts/gen_android_icons.py from assets/myotis_logo.svg; CI fails on a hand edit.")
write('drawable/ic_launcher_foreground.xml', fg)
write('drawable/ic_stat_myotis.xml', stat)
write('values/ic_launcher_background.xml',
    '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
    '    <!-- Adaptive launcher icon background: the brand dark from assets/social-preview.svg,\n'
    '         behind the white bat (the dark-scheme logo, assets/myotis_logo_dark.svg).\n'
    '         GENERATED by scripts/gen_android_icons.py (BG there); CI fails on a hand edit. -->\n'
    '    <color name="ic_launcher_background">%s</color>\n</resources>\n' % BG)
write('mipmap-anydpi-v26/ic_launcher.xml',
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<!-- GENERATED by scripts/gen_android_icons.py. minSdk 29 > 26, so this adaptive icon is the\n'
    '     only launcher-icon form the app needs: no density PNGs, and no roundIcon (launchers\n'
    '     that ask for one fall back to android:icon, i.e. this same file). -->\n'
    '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
    '    <background android:drawable="@color/ic_launcher_background" />\n'
    '    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
    "    <!-- Android 13+ themed icons use the foreground's alpha, tinted by the launcher. -->\n"
    '    <monochrome android:drawable="@drawable/ic_launcher_foreground" />\n'
    '</adaptive-icon>\n')
print('bat bounds x %s..%s y %s..%s; farthest point %s from centre' % (f(X0), f(X1), f(Y0), f(Y1), f(MAX_R)))
print('launcher scale %s translate %s,%s | status-bar scale %s translate %s,%s'
      % (f(FG_SCALE, 4), f(fgtx), f(fgty), f(STAT_SCALE, 4), f(sttx), f(stty)))

# ---- preview sheet (opt-in: --preview DIR; cairosvg + Pillow) ----
if PREVIEW is None:
    sys.exit(0)
import io  # noqa: E402
import cairosvg  # noqa: E402
from PIL import Image, ImageDraw  # noqa: E402

os.makedirs(PREVIEW, exist_ok=True)


def render(size, scale, tx, ty, bg, px):
    g = ''.join('<path fill="#FFFFFF" d="%s"/>' % d for d in norm)
    rect = '<rect width="%d" height="%d" fill="%s"/>' % (size, size, bg) if bg else ''
    s = ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">'
         '%s<g transform="translate(%s,%s) scale(%s)">%s</g></svg>'
         % (px, px, size, size, rect, tx, ty, scale, g))
    return Image.open(io.BytesIO(cairosvg.svg2png(bytestring=s.encode()))).convert('RGBA')


full = render(FG_SIZE, FG_SCALE, fgtx, fgty, BG, 432)        # 4 px per dp
insp = full.copy()
draw = ImageDraw.Draw(insp)
draw.rectangle([72, 72, 360, 360], outline='#FF5252', width=2)   # the visible 72dp window
draw.ellipse([84, 84, 348, 348], outline='#69F0AE', width=2)     # the 66dp safe zone


def masked(shape):
    win = full.crop((72, 72, 360, 360))
    m = Image.new('L', win.size, 0)
    md = ImageDraw.Draw(m)
    if shape == 'circle':
        md.ellipse([0, 0, 287, 287], fill=255)
    else:
        md.rounded_rectangle([0, 0, 287, 287], radius=72, fill=255)
    out = Image.new('RGBA', win.size, (0, 0, 0, 0))
    out.paste(win, (0, 0), m)
    return out


stat_img = render(STAT_SIZE, STAT_SCALE, sttx, stty, None, 96)
sheet = Image.new('RGBA', (432 + 288 + 288 + 96 + 5 * 24, 432 + 48), '#607D8B')
sheet.paste(insp, (24, 24))
for x, shape in ((480, 'circle'), (792, 'squircle')):
    layer = masked(shape)
    sheet.paste(layer, (x, 96), layer)
bar = Image.new('RGBA', (96, 96), '#000000')
bar.paste(stat_img, (0, 0), stat_img)
sheet.paste(bar, (1104, 96))
out = os.path.join(PREVIEW, 'preview.png')
sheet.save(out)
print('wrote', out)
