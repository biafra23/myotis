#!/usr/bin/env bash
# Reproducible zips for release assets (#734, Part 4, D7).
#
#   scripts/repro_zip.sh DIR ENTRY OUT.zip   zip DIR/ENTRY into OUT.zip
#                                            (ENTRY at the archive root)
#
# A plain `zip -r` records each file's mtime (when the build wrote it), the
# directory's traversal order and extra attributes (uid/gid, atime), so the
# same tree zipped twice gives different bytes. Here every file and directory
# gets ONE mtime — SOURCE_DATE_EPOCH (reproducible-builds.org), else the HEAD
# commit time — modes are normalized (644/755, executables kept), entries go
# in sorted byte order, and -X drops the extras (uid/gid, atime).
# TZ=UTC throughout: `touch -t` and zip's DOS timestamps are both local time.
# Symlinks are stored as links (-y), as framework bundles need. Works with GNU
# and BSD date/touch (Linux and macOS runners).
set -euo pipefail

sde=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
[[ "$sde" =~ ^[0-9]+$ ]] || { echo "repro_zip.sh: bad SOURCE_DATE_EPOCH '$sde'" >&2; exit 2; }
stamp=$(TZ=UTC date -d "@$sde" +%Y%m%d%H%M.%S 2>/dev/null || TZ=UTC date -r "$sde" +%Y%m%d%H%M.%S)

# One mtime, and modes from the content rather than the builder's umask:
# u=rw, go=r for files, plus x for directories and files already executable
# (644/755 whatever umask wrote them; symlinks are left alone).
normalize() {
    chmod -R u=rwX,go=rX "$1"
    TZ=UTC find "$1" -exec touch -h -t "$stamp" {} +
}

[[ $# -eq 3 ]] || { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;/^set -euo/d' >&2; exit 2; }

dir=$1 entry=$2
out="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
rm -f "$out"
cd "$dir"
normalize "$entry"
LC_ALL=C find "$entry" -print | LC_ALL=C sort | TZ=UTC zip -X -y -q "$out" -@
