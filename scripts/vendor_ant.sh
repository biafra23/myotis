#!/usr/bin/env bash
# Vendors ant (https://github.com/freedom-hq/ant), the embedded Swarm node behind
# rust/swarm, into rust/vendor/ant: the crates rust/swarm builds, copied verbatim at one
# commit, so that no build fetches ant from GitHub (owner's decision, 2026-11-20).
#
#   scripts/vendor_ant.sh <commit>   replace rust/vendor/ant with ant at <commit>
#   scripts/vendor_ant.sh --check    compare rust/vendor/ant with upstream at its recorded commit
#
# Both fetch ant from GitHub; nothing else in the build does. An update is a PR whose diff
# is ant's own change between the two commits, reviewed like code (rust/vendor/ant/VENDORED.md).
# The only file that is not upstream's is the workspace manifest: its `members` list names
# the vendored crates instead of all of ant's.
set -euo pipefail

REPO=https://github.com/freedom-hq/ant
CRATES=(ant-chain ant-control ant-crypto ant-node ant-p2p ant-postage ant-retrieval)
# contracts/: ant-chain embeds contracts/BzzSwapHelper.bin (include_str!); its .sol source
# comes with it.
FILES=(LICENSE-APACHE LICENSE-MIT contracts)

root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/rust/vendor/ant

usage() { echo "usage: $0 <40-hex commit> | --check" >&2; exit 2; }
[ $# -eq 1 ] || usage
mode=update
commit=$1
if [ "$1" = "--check" ]; then
  mode=check
  commit=$(sed -n 's/^Commit: *\([0-9a-f]\{40\}\)$/\1/p' "$dest/VENDORED.md")
  [ -n "$commit" ] || { echo "no 'Commit: <40 hex>' line in $dest/VENDORED.md" >&2; exit 1; }
fi
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || usage

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$work" init -q src
# Upstream's bytes, whatever this machine's git does with line endings (core.autocrlf on
# Windows) and whatever upstream's own .gitattributes say.
git -C "$work/src" config core.autocrlf false
git -C "$work/src" config core.eol lf
echo '* -text' > "$work/src/.git/info/attributes"
git -C "$work/src" fetch -q --depth 1 "$REPO" "$commit"
git -C "$work/src" -c advice.detachedHead=false checkout -q FETCH_HEAD
[ "$(git -C "$work/src" rev-parse HEAD)" = "$commit" ] || { echo "fetched another commit" >&2; exit 1; }

# The tree as it is committed here: the crates and licenses verbatim, the workspace
# manifest with only the vendored crates as members.
out=$work/out
mkdir -p "$out/crates"
for c in "${CRATES[@]}"; do
  cp -R "$work/src/crates/$c" "$out/crates/$c"
done
for f in "${FILES[@]}"; do
  cp -R "$work/src/$f" "$out/$f"
done
members=$(printf '  "crates/%s",\n' "${CRATES[@]}")
python3 - "$work/src/Cargo.toml" "$out/Cargo.toml" "$members" <<'EOF'
import re, sys
src, dst, members = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src, 'rb').read()
lines = members.rstrip('\n').encode()
new, n = re.subn(rb'(?ms)^members = \[\n.*?^\]', b'members = [\n' + lines + b'\n]', text, count=1)
if n != 1:
    sys.exit("ant's Cargo.toml has no `members = [ ... ]` list in the expected form")
open(dst, 'wb').write(new)
EOF

if [ "$mode" = check ]; then
  # What git tracks (the index: a commit in CI, staged changes locally), not the working
  # tree: build leftovers there (a target/, a Cargo.lock from building inside the copy) are
  # not part of the copy. File modes count, and the top-level VENDORED.md, ours, does not.
  tracked=$work/tracked
  (cd "$root" && git ls-files -z -- rust/vendor/ant | git checkout-index -z --stdin --prefix="$tracked/")
  rm -f "$tracked/rust/vendor/ant/VENDORED.md"
  if git -c core.autocrlf=false diff --no-index --stat --exit-code "$out" "$tracked/rust/vendor/ant"; then
    echo "rust/vendor/ant matches $REPO at $commit"
  else
    echo "rust/vendor/ant differs from $REPO at $commit (above)" >&2
    exit 1
  fi
  exit 0
fi

notes=""
[ -f "$dest/VENDORED.md" ] && notes=$(cat "$dest/VENDORED.md")
rm -rf "$dest"
mkdir -p "$(dirname "$dest")"
cp -R "$out" "$dest"
if [ -n "$notes" ]; then
  printf '%s\n' "$notes" | sed "s/^Commit: *[0-9a-f]\{40\}$/Commit: $commit/" > "$dest/VENDORED.md"
else
  echo "Commit: $commit" > "$dest/VENDORED.md"
fi
grep -qx "Commit: $commit" "$dest/VENDORED.md" \
  || { echo "VENDORED.md does not record Commit: $commit; fix its Commit line by hand" >&2; exit 1; }
echo "rust/vendor/ant is now $REPO at $commit; review the diff, then update rust/swarm/Cargo.lock"
