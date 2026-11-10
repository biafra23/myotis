#!/usr/bin/env bash
# Upload assets to a `v*` tag's GitHub release, and keep the release's ONE
# checksum file, SHA256SUMS, complete (#734, Part 5c). Every workflow that
# publishes to a release goes through this script (the list is in
# release-version-guard.yml's header), in place of `gh release upload`:
#
#   release-assets.sh <tag> <file>...
#       1. Uploads the files (`--clobber`: a re-run replaces its own assets).
#       2. Checks that the release now serves THESE bytes: GitHub records a
#          SHA-256 digest for every asset, and each one must equal the hash of
#          the file this job built. A mismatch fails the job.
#       3. Appends the files' checksums to $RELEASE_ASSETS_SUBJECTS (default
#          $RUNNER_TEMP/release-assets.SHA256SUMS), the subject list the job's
#          attest-build-provenance step signs.
#
#   release-assets.sh --checksums <tag>
#       Makes SHA256SUMS list every asset of the release except itself, from
#       GitHub's digests, in `sha256sum -c` format, sorted by name. No asset is
#       downloaded. A line is what the release serves; what ties a digest to a
#       build is step 2 above, which every publisher runs for its own files,
#       and the attestation.
#
# A publishing job calls the first form where it used to upload, then attests,
# then calls the second as its LAST step, with `if: ${{ !cancelled() }}`. Three
# steps on purpose: SHA256SUMS is state all publishers share, and trouble with
# it (or a Sigstore outage in the attest step) must not keep a job from
# finishing what is its own. Each form is idempotent, so "re-run failed jobs"
# repairs whichever part failed.
#
# Why --checksums loops: there is no cross-workflow ordering, so nine
# publishers write the same file, each from the asset list it saw. One that
# listed before another's upload and wrote after it would drop that asset's
# line. So each re-reads the release SETTLE seconds after its own write and
# writes again when file and release disagree; the last one to finish leaves it
# complete. (The same read-modify-write race, and the same repair, as
# release-notes.sh.) An asset another publisher is still uploading has no
# digest yet: it is waited for, for up to WAIT_FOR seconds, and after that left
# out with a warning (its own publisher lists it when it gets there; an upload
# that died leaves such an asset behind for good, and must not block every
# other publisher).
#
# The per-component files that existed before (myotis-engine.SHA256SUMS,
# myotis-node.SHA256SUMS, *.xcframework.zip.sha256) stay, for the consumers
# that read them; they are assets like any other, so SHA256SUMS covers them.
#
# scripts/test_release_assets.sh tests this script against a stubbed `gh`.
#
# Env: GH_TOKEN; GH_REPO outside a full checkout. For tests:
# RELEASE_ASSETS_SETTLE (10 s after a write of SHA256SUMS), RELEASE_ASSETS_WAIT
# (5 s between polls), RELEASE_ASSETS_WAIT_FOR (600 s for another publisher's
# upload).
set -euo pipefail

fail() { echo "::error::release-assets.sh: $*" >&2; exit 1; }
usage() { echo "usage: $0 <tag> <file>... | --checksums <tag>" >&2; exit 2; }
settle=${RELEASE_ASSETS_SETTLE:-10}
wait_s=${RELEASE_ASSETS_WAIT:-5}
wait_for=${RELEASE_ASSETS_WAIT_FOR:-600}
sums_name=SHA256SUMS

mode=upload
if [ "${1:-}" = "--checksums" ]; then mode=checksums; shift; [ $# -eq 1 ] || usage
else [ $# -ge 2 ] || usage; fi
tag=$1; shift

if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
else sha() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

for f in "$@"; do
  [ -f "$f" ] || fail "no such file: $f"
  name=$(basename "$f")
  # A name is a line of SHA256SUMS and a column of the listing below.
  case "$name" in *[[:space:]]*) fail "asset name with whitespace: '$name'" ;; esac
  [ "$name" != "$sums_name" ] || fail "$sums_name is written by --checksums, not uploaded"
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

if [ "$mode" = upload ]; then
  gh release upload "$tag" "$@" --clobber

  # The release serves the bytes this job built.
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

  # The subjects of this job's attestation.
  subjects=${RELEASE_ASSETS_SUBJECTS:-${RUNNER_TEMP:-.}/release-assets.SHA256SUMS}
  for f in "$@"; do printf '%s  %s\n' "$(sha "$f")" "$(basename "$f")"; done >> "$subjects"
  exit 0
fi

# --- --checksums: SHA256SUMS lists every asset --------------------------------
# Writes the file's wanted content to $tmp/want and the names of assets that
# have no digest yet (still uploading, or left behind by an upload that died)
# to $tmp/unready.
wanted() {
  assets > "$tmp/list"
  awk -F'\t' -v s="$sums_name" '$1 != s && ($2 != "uploaded" || $3 == "") { print $1 }' "$tmp/list" > "$tmp/unready"
  awk -F'\t' -v s="$sums_name" '$1 != s && $2 == "uploaded" && $3 != "" { print $3 "  " $1 }' "$tmp/list" \
    | LC_ALL=C sort -k2 > "$tmp/want"
}
published() { gh release download "$tag" --pattern "$sums_name" --output - 2>/dev/null || true; }

writes=0 waited=0
while :; do
  wanted
  if [ -s "$tmp/unready" ] && [ "$waited" -lt "$wait_for" ]; then
    [ "$waited" -gt 0 ] || echo "release-assets.sh: waiting for $(paste -sd' ' "$tmp/unready") of $tag to finish uploading"
    sleep "$wait_s"; waited=$((waited + (wait_s > 0 ? wait_s : 1))); continue
  fi
  # Every read after a write of ours comes `settle` later (the sleep below), so
  # agreement here is agreement that outlived a concurrent writer's window.
  if [ "$(published)" = "$(cat "$tmp/want")" ]; then
    if [ -s "$tmp/unready" ]; then
      echo "::warning::release-assets.sh: $sums_name of $tag leaves out $(paste -sd' ' "$tmp/unready"): no digest after ${wait_for}s (an upload still running, or one that died and left its asset behind)"
    fi
    echo "release-assets.sh: $sums_name of $tag lists $(wc -l < "$tmp/want" | tr -d ' ') asset(s) (after $writes write(s) by this job)"
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
fail "$sums_name of $tag kept disagreeing with the release's assets after 6 writes (another publisher writing in a loop?); re-run this job once the other publishers are done"
