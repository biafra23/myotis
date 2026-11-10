#!/usr/bin/env bash
# Upload assets to a `v*` tag's GitHub release and keep the release's ONE
# checksum file, SHA256SUMS, complete (#734, Part 5c). Every workflow that
# publishes to a release uploads through this script (the list is in
# release-version-guard.yml's header), in place of `gh release upload`:
#
#   release-assets.sh <tag> <file>...
#
# 1. Uploads the files (`--clobber`: a re-run replaces its own assets).
# 2. Checks that the release now serves THESE bytes: GitHub records a SHA-256
#    digest for every asset, and each one must equal the hash of the file this
#    job built. A mismatch fails the job.
# 3. Makes SHA256SUMS list every asset of the release except itself, from those
#    digests, in `sha256sum -c` format, sorted by name. No asset is downloaded:
#    step 2 is what ties a digest to a build, and every publisher runs it for
#    its own files.
# 4. Appends the uploaded files' checksums to $RELEASE_ASSETS_SUBJECTS (default
#    $RUNNER_TEMP/release-assets.SHA256SUMS), the subject list the job's
#    attest-build-provenance step signs. After the upload on purpose: a Sigstore
#    outage then leaves the assets published and the job red, and a re-run
#    repairs it.
#
# Why step 3 loops: there is no cross-workflow ordering, so nine publishers
# write the same file, each from the asset list it saw. One that listed before
# another's upload and wrote after it would drop that asset's line. So each
# re-reads the release SETTLE seconds after its own write and writes again when
# file and release disagree; the last one to finish leaves it complete. (The
# same read-modify-write race, and the same repair, as release-notes.sh.) An
# asset another publisher is still uploading has no digest yet: wait for it.
#
# The per-component files that existed before (myotis-engine.SHA256SUMS,
# myotis-node.SHA256SUMS, *.xcframework.zip.sha256) stay, for the consumers
# that read them; they are assets like any other, so SHA256SUMS covers them.
#
# scripts/test_release_assets.sh tests this script against a stubbed `gh`.
#
# Env: GH_TOKEN; GH_REPO outside a full checkout. RELEASE_ASSETS_SETTLE
# overrides the 10 s settle time and RELEASE_ASSETS_WAIT the 5 s between
# digest polls (for tests).
set -euo pipefail

fail() { echo "::error::release-assets.sh: $*" >&2; exit 1; }
[ $# -ge 2 ] || { echo "usage: $0 <tag> <file>..." >&2; exit 2; }
tag=$1; shift
settle=${RELEASE_ASSETS_SETTLE:-10}
wait_s=${RELEASE_ASSETS_WAIT:-5}
sums_name=SHA256SUMS

if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
else sha() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

for f in "$@"; do
  [ -f "$f" ] || fail "no such file: $f"
  name=$(basename "$f")
  # A name is a line of SHA256SUMS and a column of the listing below.
  case "$name" in *[[:space:]]*) fail "asset name with whitespace: '$name'" ;; esac
  [ "$name" != "$sums_name" ] || fail "$sums_name is written by this script, not uploaded through it"
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# name <TAB> state <TAB> sha256 hex ('' until GitHub has computed it), one
# asset per line. By release id, paginated: the release object's own `assets`
# array is not.
rid=$(gh api "repos/{owner}/{repo}/releases/tags/$tag" --jq .id) || fail "no release for tag $tag"
assets() {
  gh api --paginate "repos/{owner}/{repo}/releases/$rid/assets?per_page=100" \
    --jq '.[] | [.name, .state, ((.digest // "") | sub("^sha256:"; ""))] | @tsv'
}

gh release upload "$tag" "$@" --clobber

# --- 2. the release serves the bytes this job built ---------------------------
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  assets > "$tmp/list"
  pending=""
  for f in "$@"; do
    name=$(basename "$f")
    got=$(awk -F'\t' -v n="$name" '$1 == n && $2 == "uploaded" { print $3 }' "$tmp/list")
    if [ -z "$got" ]; then pending="$pending $name"; continue; fi
    want=$(sha "$f")
    [ "$got" = "$want" ] \
      || fail "$name on the release of $tag has SHA-256 $got, the file this job built has $want"
  done
  [ -n "$pending" ] || break
  [ "$attempt" -lt 12 ] || fail "no digest on the release of $tag for:$pending"
  sleep "$wait_s"
done
echo "release-assets.sh: $# asset(s) of $tag match the files this job built"

# --- 4. the subjects of this job's attestation --------------------------------
subjects=${RELEASE_ASSETS_SUBJECTS:-${RUNNER_TEMP:-$tmp}/release-assets.SHA256SUMS}
for f in "$@"; do printf '%s  %s\n' "$(sha "$f")" "$(basename "$f")"; done >> "$subjects"

# --- 3. SHA256SUMS lists every asset ------------------------------------------
# Prints the file's wanted content, or fails (status 1) while an asset other
# than SHA256SUMS itself has no digest yet.
wanted() {
  assets > "$tmp/list"
  awk -F'\t' -v s="$sums_name" '
    $1 == s { next }
    $2 != "uploaded" || $3 == "" { bad = 1 }
    { print $3 "  " $1 }
    END { exit bad }' "$tmp/list" | LC_ALL=C sort -k2
}
published() { gh release download "$tag" --pattern "$sums_name" --output - 2>/dev/null || true; }

writes=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if ! wanted > "$tmp/want"; then
    echo "release-assets.sh: an asset of $tag is still uploading; waiting"
    sleep "$wait_s"; continue
  fi
  # Every read after a write of ours comes `settle` later (the sleep below), so
  # agreement here is agreement that outlived a concurrent writer's window.
  if [ "$(published)" = "$(cat "$tmp/want")" ]; then
    echo "release-assets.sh: $sums_name of $tag lists all $(wc -l < "$tmp/want" | tr -d ' ') assets (after $writes write(s) by this job)"
    exit 0
  fi
  [ "$writes" -lt 6 ] || break
  mkdir -p "$tmp/up"; cp "$tmp/want" "$tmp/up/$sums_name"
  # Two publishers replacing the same asset at once can make one upload fail
  # (the delete or the name is taken): not an error, the next pass re-checks.
  gh release upload "$tag" "$tmp/up/$sums_name" --clobber \
    || echo "release-assets.sh: could not write $sums_name this pass (another publisher writing it?); re-checking"
  writes=$((writes + 1))
  sleep "$settle"
done
fail "$sums_name of $tag kept disagreeing with the release's assets (another publisher writing in a loop, or an upload that never finished?); re-run this job once the other publishers are done"
