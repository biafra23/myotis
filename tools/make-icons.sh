#!/usr/bin/env bash
#
# Generate the per-OS application icons for the :desktop-app installer from the
# source SVG (assets/myotis_logo.svg).
#
# Outputs (consumed by desktop-app/build.gradle.kts when present):
#   desktop-app/icons/myotis.png    — Linux  (512x512)
#   desktop-app/icons/myotis.ico    — Windows (multi-size)
#   desktop-app/icons/myotis.icns   — macOS   (iconset)
#
# Requirements: rsvg-convert (librsvg) or inkscape, ImageMagick (`magick`/`convert`),
# and either `iconutil` (macOS) or `png2icns` (libicns) for the .icns.
#
# This is intentionally a manual/CI step rather than a Gradle task so the build
# stays toolchain-only (no native image deps required just to compile).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SVG="$ROOT/assets/myotis_logo.svg"
OUT="$ROOT/desktop-app/icons"
mkdir -p "$OUT"

rasterize() { # rasterize <size> <outfile>
    local size="$1" out="$2"
    if command -v rsvg-convert >/dev/null 2>&1; then
        rsvg-convert -w "$size" -h "$size" "$SVG" -o "$out"
    elif command -v inkscape >/dev/null 2>&1; then
        inkscape "$SVG" --export-type=png --export-filename="$out" -w "$size" -h "$size"
    else
        echo "Need rsvg-convert or inkscape to rasterize the SVG." >&2
        exit 1
    fi
}

im() { command -v magick >/dev/null 2>&1 && magick "$@" || convert "$@"; }

# Linux PNG
rasterize 512 "$OUT/myotis.png"

# Windows .ico (bundle common sizes)
tmp="$(mktemp -d)"
for s in 16 32 48 64 128 256; do rasterize "$s" "$tmp/icon_$s.png"; done
im "$tmp"/icon_*.png "$OUT/myotis.ico"

# macOS .icns
iconset="$tmp/myotis.iconset"; mkdir -p "$iconset"
for s in 16 32 64 128 256 512; do
    rasterize "$s"            "$iconset/icon_${s}x${s}.png"
    rasterize "$((s*2))"      "$iconset/icon_${s}x${s}@2x.png"
done
if command -v iconutil >/dev/null 2>&1; then
    iconutil -c icns "$iconset" -o "$OUT/myotis.icns"
elif command -v png2icns >/dev/null 2>&1; then
    png2icns "$OUT/myotis.icns" "$iconset"/icon_512x512.png "$iconset"/icon_256x256.png \
        "$iconset"/icon_128x128.png "$iconset"/icon_32x32.png "$iconset"/icon_16x16.png
else
    echo "No iconutil/png2icns; skipped .icns (Windows/Linux icons still generated)." >&2
fi

rm -rf "$tmp"
echo "Icons written to $OUT"
