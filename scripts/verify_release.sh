#!/usr/bin/env bash
# Verify the evidence a release publishes about its own assets (#734, Part 5c).
#
#   scripts/verify_release.sh [--no-attestations] <tag> [DIR]
#
# Downloads every asset of the release into DIR (default: a temporary
# directory, removed afterwards), then checks, in this order. The assets are
# the ones the release lists (GitHub's API: name and SHA-256 of each), not
# whatever DIR holds. With a DIR, a file there that has an asset's name and
# the SHA-256 the release records for it is reused, so a re-run does not
# download 2 GB again; one with an asset's name and other bytes (an asset
# replaced since, a truncated download) is fetched again. NO OTHER FILE IN DIR
# IS TOUCHED OR LOOKED AT: pointing this at a directory that holds other
# things is safe.
#
#   1. SHA256SUMS is there, lists every asset except itself and nothing that is
#      not an asset, and every hash matches (`sha256sum -c`).
#   2. Every asset has a build-provenance attestation, signed for a workflow of
#      this repository that ran on the tag's own ref
#      (`gh attestation verify --repo … --source-ref refs/tags/<tag>`). An asset
#      uploaded from another ref (a workflow dispatched on a branch, onto an
#      existing release) fails here: that is the point.
#   3. The signed release APK is the unsigned one plus its signature and
#      nothing else (scripts/repro/compare_signed_apk.py), when both are there.
#
# Every failure is listed before the script exits 1: one bad asset does not
# hide the next. What this does NOT show is that the assets can be REBUILT from
# the tag: that is the `reproducible builds` run of the tag, and
# docs/guides/reproducible-builds.md for doing it yourself.
#
# --no-attestations skips step 2 (a release from before attestations, or no
# network path to Sigstore). The `verify release` workflow runs this on every
# tag, once the tag's publishing workflows are done, and on dispatch for any tag.
#
# Needs gh (2.49 or newer for `gh attestation`), python3, sha256sum or shasum.
# Env: GH_TOKEN; GH_REPO outside a checkout of the repository.
set -euo pipefail

attest=true
[ "${1:-}" != "--no-attestations" ] || { attest=false; shift; }
[ $# -ge 1 ] && [ $# -le 2 ] || { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;/^set -euo/d' >&2; exit 2; }
tag=$1
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ $# -eq 2 ]; then dir=$2; mkdir -p "$dir"
else dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT; fi
repo=${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}

if command -v sha256sum >/dev/null 2>&1; then check() { sha256sum -c "$@"; }; sha() { sha256sum "$1" | cut -d' ' -f1; }
else check() { shasum -a 256 -c "$@"; }; sha() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

failures=0
bad() { echo "FAIL  $*"; failures=$((failures + 1)); }

echo "release $tag of $repo, assets in $dir"
# What the release HAS: each asset's name, state and the SHA-256 GitHub
# recorded for it. Everything below goes by this list and by nothing else, so
# with a DIR of your own (your Downloads, say) only files that carry a release
# asset's name are ever looked at, replaced or checked; any other file there is
# left alone and ignored.
rid=$(gh api "repos/$repo/releases/tags/$tag" --jq .id) \
  || { echo "verify_release.sh: no release for tag $tag in $repo (or it cannot be read)" >&2; exit 1; }
listing=$(gh api --paginate "repos/$repo/releases/$rid/assets?per_page=100" \
  --jq '.[] | [.name, .state, ((.digest // "") | sub("^sha256:"; ""))] | @tsv')
[ -n "$listing" ] || { echo "verify_release.sh: the release of $tag has no assets" >&2; exit 1; }
names=$(printf '%s\n' "$listing" | cut -f1 | LC_ALL=C sort)
assets=$(printf '%s\n' "$names" | { grep -vx SHA256SUMS || true; })
has() { printf '%s\n' "$names" | grep -qxF "$1"; }

# A kept copy of an asset is reused only when it is the bytes the release
# serves now (GitHub's digest); otherwise that one file is fetched again.
while IFS=$'\t' read -r name state digest; do
  case "$name" in */*|""|.|..) echo "verify_release.sh: refusing the asset name '$name'" >&2; exit 1 ;; esac
  [ "$state" = uploaded ] || bad "$name is on the release but not fully uploaded (state: $state)"
  if [ -f "$dir/$name" ] && { [ -z "$digest" ] || [ "$(sha "$dir/$name")" != "$digest" ]; }; then
    echo "      $name in $dir is not what the release serves now: fetching it again"
    rm -f "$dir/$name"
  fi
done <<< "$listing"
gh release download "$tag" --repo "$repo" --dir "$dir" --skip-existing
cd "$dir"

# --- 1. SHA256SUMS ------------------------------------------------------------
if ! has SHA256SUMS; then
  bad "the release has no SHA256SUMS"
else
  listed=$(sed 's/^[0-9a-f]\{64\}  //' SHA256SUMS | LC_ALL=C sort)
  if [ "$listed" != "$assets" ]; then
    bad "SHA256SUMS and the release's assets are not the same set (< listed, > published):"
    diff <(printf '%s\n' "$listed") <(printf '%s\n' "$assets") | grep '^[<>]' | sed 's/^/        /' || true
  fi
  if out=$(check SHA256SUMS 2>&1); then
    echo "ok    SHA256SUMS: all $(wc -l < SHA256SUMS | tr -d ' ') listed files match"
  else
    bad "SHA256SUMS does not verify:"
    printf '%s\n' "$out" | grep -v ': OK$' | sed 's/^/        /'
  fi
fi

# --- 2. attestations ----------------------------------------------------------
if $attest; then
  n=0
  for f in $assets; do
    if out=$(gh attestation verify "$f" --repo "$repo" --source-ref "refs/tags/$tag" 2>&1); then
      n=$((n + 1))
    else
      bad "no valid attestation for $f from refs/tags/$tag of $repo:"
      printf '%s\n' "$out" | tail -n 3 | sed 's/^/        /'
    fi
  done
  echo "ok    $n asset(s) have a build-provenance attestation from refs/tags/$tag of $repo"
else
  echo "skip  attestations (--no-attestations)"
fi

# --- 3. the signed APK is the unsigned APK plus its signature -----------------
signed="Myotis-$tag-android.apk" unsigned="Myotis-$tag-android-unsigned.apk"
if has "$signed" && has "$unsigned"; then
  if out=$(python3 "$here/repro/compare_signed_apk.py" "$signed" "$unsigned" 2>&1); then
    echo "ok    $out"
  else
    bad "$out"
  fi
elif has "$signed"; then
  bad "the release has $signed but no $unsigned to check it against"
else
  echo "skip  signed against unsigned APK: the release has no $signed"
fi

[ "$failures" -eq 0 ] || { echo "verify_release.sh: $failures check(s) failed for $tag" >&2; exit 1; }
echo "release $tag: its checksums, attestations and signed APK all check out"
