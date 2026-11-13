#!/usr/bin/env bash
# Pinned contract: EVERY function myotis_engine.h declares must be an
# exported symbol of the Go c-shared library — functional or refusal,
# but present — so a JNA binding written against the Rust engine loads
# libmyotis_engine_go.so by name alone (desktop-embed part 1b). Run
# from the go/ directory after building:
#
#   go build -buildmode=c-shared -o build/libmyotis_engine_go.so ./cmd/myotis-capi
#   scripts/check_capi_symbols.sh
#
# Extra exports beyond the header (myotis_go_capabilities_json) are
# allowed; missing ones fail.
set -euo pipefail

LIB=${1:-build/libmyotis_engine_go.so}
HEADER=${2:-../rust/include/myotis_engine.h}

[ -f "$LIB" ] || { echo "no library at $LIB (build it first)" >&2; exit 1; }
[ -f "$HEADER" ] || { echo "no header at $HEADER" >&2; exit 1; }

# Header-declared names: any `myotis_<name>(` in a declaration line.
grep -oE '\bmyotis_[a-z0-9_]+\(' "$HEADER" | sed 's/($//; s/(//' | sort -u >/tmp/capi-header.$$

# Library-exported names: the dynamic T symbols cgo emits as `myotis_*`
# (the _cgoexp_* shims are internal and ignored)..
nm -D --defined-only "$LIB" | awk '$2 == "T" && $3 ~ /^myotis_/ { print $3 }' | sort -u >/tmp/capi-exports.$$

missing=$(comm -23 /tmp/capi-header.$$ /tmp/capi-exports.$$)
rm -f /tmp/capi-header.$$ /tmp/capi-exports.$$

if [ -n "$missing" ]; then
	echo "library is missing header symbols:" >&2
	echo "$missing" >&2
	exit 1
fi
n=$(nm -D --defined-only "$LIB" | awk '$2 == "T" && $3 ~ /^myotis_/' | wc -l)
echo "capi symbols OK: every myotis_engine.h export is present (library exports $n myotis_* symbols)"
