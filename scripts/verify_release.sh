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
#   2. Every asset has a build-provenance attestation that names: this
#      repository; the tag's own ref; the COMMIT the tag points at (a tag that
#      was moved leaves assets of its earlier commit behind, under the same ref
#      name); and the workflow that is supposed to build that asset (the APKs
#      android-apk.yml, the debs desktop-linux-deb.yml, and so on). An asset
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
# Needs gh (one whose `gh attestation verify` has --source-ref,
# --source-digest and --signer-workflow: checked before anything is verified),
# python3, sha256sum or shasum.
# Env: GH_TOKEN; GH_REPO outside a checkout of the repository.
set -euo pipefail

attest=true
[ "${1:-}" != "--no-attestations" ] || { attest=false; shift; }
[ $# -ge 1 ] && [ $# -le 2 ] || { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;/^set -euo/d' >&2; exit 2; }
tag=$1
printf '%s' "$tag" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' \
  || { echo "verify_release.sh: '$tag' is not a usable release tag" >&2; exit 2; }
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
# (`gh release view` also finds a draft by its tag name, for the rehearsal.)
rid=$(gh release view "$tag" --repo "$repo" --json databaseId --jq .databaseId) \
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
# The workflow that is supposed to build each asset: an attestation signed for
# another workflow of the repository does not count. One line per publisher of
# release-version-guard.yml's list; a new publisher adds its family here, and
# an asset that matches none FAILS (scripts/test_release_assets.sh checks that
# every publishing workflow is named).
workflow_of() {
  case "$1" in
    Myotis-*-android.apk|Myotis-*-android-unsigned.apk|Myotis-*-android-debug.apk) echo android-apk.yml ;;
    Myotis-*-railgun-poc-*.dmg) echo railgun-dmg.yml ;;
    Myotis-*.dmg) echo desktop-dmg.yml ;;
    Myotis-*.deb) echo desktop-linux-deb.yml ;;
    myotis-engine-*.aar|myotis-engine-*.zip|myotis-engine.SHA256SUMS) echo engine-library.yml ;;
    MyotisKit.xcframework.zip|MyotisKit.xcframework.zip.sha256) echo ios-framework.yml ;;
    MyotisEngine.xcframework.zip|MyotisEngine.xcframework.zip.sha256) echo ios-xcframework.yml ;;
    myotis-node.*) echo node-binding.yml ;;
    *.jar) echo ci.yml ;;
    *) return 1 ;;
  esac
}
if $attest; then
  # The flags this needs arrived in gh one by one; an older gh would fail every
  # asset with "unknown flag", which reads like a missing attestation.
  usage=$(gh attestation verify --help 2>&1 || true)
  for flag in --source-ref --source-digest --signer-workflow; do
    printf '%s' "$usage" | grep -q -- "$flag" \
      || { echo "verify_release.sh: this gh ($(gh --version | head -n1)) has no \`gh attestation verify $flag\`: update gh, or pass --no-attestations" >&2; exit 1; }
  done
  # The commit the tag points at (peeled, for an annotated tag). A tag that
  # was moved leaves assets of its earlier commit behind: same ref name, other
  # commit, and --source-ref alone would accept them.
  commit=$(gh api "repos/$repo/commits/tags/$tag" --jq .sha) \
    || { echo "verify_release.sh: cannot resolve the commit of tag $tag in $repo" >&2; exit 1; }
  n=0
  for f in $assets; do
    if ! wf=$(workflow_of "$f"); then
      bad "no workflow is known to publish $f (scripts/verify_release.sh, workflow_of): not an asset of a release workflow, or a new one that was not added"
      continue
    fi
    if out=$(gh attestation verify "$f" --repo "$repo" --source-ref "refs/tags/$tag" --source-digest "$commit" \
               --signer-workflow "$repo/.github/workflows/$wf" 2>&1); then
      n=$((n + 1))
    else
      bad "no valid attestation for $f by $wf at refs/tags/$tag ($commit) of $repo:"
      printf '%s\n' "$out" | tail -n 3 | sed 's/^/        /'
    fi
  done
  echo "ok    $n asset(s) have a build-provenance attestation by their own workflow, from $tag's commit $commit"
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
if $attest; then echo "release $tag: its checksums, attestations and signed APK all check out"
else echo "release $tag: its checksums check out (attestations were not checked)"; fi
