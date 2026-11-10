#!/usr/bin/env bash
# Tests .github/release-assets.sh against a stubbed `gh` that keeps one
# release's assets in a temp dir: the upload, the digest check against the
# built files, SHA256SUMS and its repair after a concurrent publisher's stale
# write, the waits for a digest that is not there yet, and the input checks.
# Then scripts/verify_release.sh against the same stub: what it accepts is what
# the first script publishes, and each way the evidence can be wrong fails.
# Nothing touches GitHub. Like release-notes.sh, the script's failure modes
# otherwise surface only on a real tag, so run this after any edit to it:
#
#   scripts/test_release_assets.sh
#
# Runs on macOS and Linux (bash, awk, sed, grep, sha256sum or shasum).
#
# Each check's condition is a single-quoted string that `check` evals
# (SC2016), and the variables it reads look unused to shellcheck (SC2034).
# shellcheck disable=SC2016,SC2034
set -u
cd "$(dirname "$0")/.." || exit 1
R=.github/release-assets.sh
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# The stub. $STUB_DIR/assets/<name> are the release's assets; the listing's
# digest is the file's real SHA-256, except:
#   corrupt/<name>     the release serves other bytes than were uploaded
#   pending/<name>     holds N: no digest for the next N listings
#   uploading/<name>   holds N: state "open" for the next N listings
#   stale_writer       a concurrent publisher: right after our FIRST write of
#                      SHA256SUMS it uploads late.bin and overwrites SHA256SUMS
#                      with the list it read before our assets were there
#   never_settles      every write of SHA256SUMS is overwritten with junk
#   fail_sums          holds N: the next N uploads of SHA256SUMS fail
#   unattested/<name>  `gh attestation verify` finds nothing for the asset
mkdir -p "$T/stub"
cat > "$T/stub/gh" <<'STUB'
#!/usr/bin/env bash
set -eu
d=$STUB_DIR; echo "gh $*" >> "$d/log"; mkdir -p "$d/assets"
if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
else sha() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi
tick() { # FILE: true while its counter is above 0, counting it down
  [ -f "$1" ] || return 1
  local c; c=$(cat "$1"); [ "$c" -gt 0 ] || return 1
  echo $((c - 1)) > "$1"
}
case "$1 ${2:-}" in
  "api repos/{owner}/{repo}/releases/tags/"*)
    [ -f "$d/exists" ] || { echo "Not Found" >&2; exit 1; }
    echo 42 ;;
  "api --paginate")
    case "$3" in "repos/{owner}/{repo}/releases/42/assets?per_page=100") ;; *) exit 97 ;; esac
    for f in "$d"/assets/*; do
      [ -f "$f" ] || continue
      n=$(basename "$f"); state=uploaded; digest=$(sha "$f")
      [ ! -f "$d/corrupt/$n" ] || digest=$(printf x | cat - "$f" | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | cut -d' ' -f1)
      if tick "$d/pending/$n"; then digest=""; fi
      if tick "$d/uploading/$n"; then state=open; digest=""; fi
      printf '%s\t%s\t%s\n' "$n" "$state" "$digest"
    done ;;
  "release upload")
    shift 3
    for f in "$@"; do
      [ "$f" != --clobber ] || continue
      n=$(basename "$f")
      if [ "$n" = SHA256SUMS ]; then
        if tick "$d/fail_sums"; then echo "HTTP 422: already_exists" >&2; exit 1; fi
        echo x >> "$d/sums_writes"
        cp "$f" "$d/assets/$n"
        if [ -f "$d/stale_writer" ]; then
          rm "$d/stale_writer"; printf late > "$d/assets/late.bin"
          printf '%s  %s\n' "$(sha "$d/assets/late.bin")" late.bin > "$d/assets/$n"
        fi
        [ ! -f "$d/never_settles" ] || echo junk > "$d/assets/$n"
      else
        cp "$f" "$d/assets/$n"
      fi
    done ;;
  "release download")
    case " $* " in
      *" --dir "*) # into the directory after --dir (verify_release.sh):
        dest=$(a=("$@"); for i in "${!a[@]}"; do [ "${a[$i]}" != --dir ] || echo "${a[$((i + 1))]}"; done)
        case " $* " in
          *" --pattern SHA256SUMS "*) # that one asset
            [ -f "$d/assets/SHA256SUMS" ] || { echo "no assets match the file pattern" >&2; exit 1; }
            cp "$d/assets/SHA256SUMS" "$dest/" ;;
          *" --skip-existing "*) # every asset the directory does not have
            for f in "$d"/assets/*; do [ -e "$dest/$(basename "$f")" ] || cp "$f" "$dest/"; done ;;
          *) exit 96 ;;
        esac ;;
      *)
        [ -f "$d/assets/SHA256SUMS" ] || { echo "no assets match the file pattern" >&2; exit 1; }
        cat "$d/assets/SHA256SUMS" ;;
    esac ;;
  "attestation verify")
    [ ! -f "$d/unattested/$3" ] || { echo "no attestations found for $3" >&2; exit 1; }
    case " $* " in *" --source-ref refs/tags/v1 "*) ;; *) echo "wrong --source-ref" >&2; exit 1 ;; esac ;;
  *) exit 98 ;;
esac
STUB
chmod +x "$T/stub/gh"
export PATH="$T/stub:$PATH" RELEASE_ASSETS_SETTLE=0 RELEASE_ASSETS_WAIT=0 RELEASE_ASSETS_WAIT_FOR=20

pass=0 failed=0
check() {
  if eval "$2"; then echo "PASS $1"; pass=$((pass + 1)); else echo "FAIL $1"; failed=$((failed + 1)); fi
}
n=0
fresh() {
  n=$((n + 1)); export STUB_DIR="$T/case$n" RELEASE_ASSETS_SUBJECTS="$T/case$n/subjects"
  mkdir -p "$STUB_DIR/assets" "$STUB_DIR/corrupt" "$STUB_DIR/pending" "$STUB_DIR/uploading" "$STUB_DIR/unattested"
  touch "$STUB_DIR/exists"
}
writes() { [ -f "$STUB_DIR/sums_writes" ] && echo $(($(wc -l < "$STUB_DIR/sums_writes"))) || echo 0; }
# SHA256SUMS verifies, and lists exactly the release's other assets.
complete() {
  (cd "$STUB_DIR/assets" && { if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi; } > /dev/null 2>&1) \
    && [ "$(sed 's/^[0-9a-f]*  //' "$STUB_DIR/assets/SHA256SUMS")" = "$(cd "$STUB_DIR/assets" && ls | grep -vx SHA256SUMS | LC_ALL=C sort)" ]
}
mkdir -p "$T/in"; printf one > "$T/in/a.apk"; printf two > "$T/in/b.dmg"

# --- the upload form ----------------------------------------------------------
fresh
bash $R v1 "$T/in/a.apk" "$T/in/b.dmg" > /dev/null; rc=$?
check "uploads the files" '[ $rc = 0 ] && cmp -s "$T/in/a.apk" "$STUB_DIR/assets/a.apk" && cmp -s "$T/in/b.dmg" "$STUB_DIR/assets/b.dmg"'
check "the attestation subjects are the uploaded files, in sha256sum format" \
  '[ "$(sed "s/^[0-9a-f]\{64\}  //" "$RELEASE_ASSETS_SUBJECTS" | tr "\n" " ")" = "a.apk b.dmg " ]'
check "the upload form leaves SHA256SUMS to --checksums" '[ "$(writes)" = 0 ]'

fresh; touch "$STUB_DIR/corrupt/a.apk"
bash $R v1 "$T/in/a.apk" > /dev/null 2> "$STUB_DIR/err"; rc=$?
check "an asset whose digest is not the built file's fails, and is not a subject" \
  '[ $rc = 1 ] && grep -q "::error::.*a.apk" "$STUB_DIR/err" && [ ! -f "$RELEASE_ASSETS_SUBJECTS" ]'

fresh; echo 3 > "$STUB_DIR/pending/a.apk"
bash $R v1 "$T/in/a.apk" > /dev/null; rc=$?
check "a digest that arrives late is waited for" '[ $rc = 0 ] && [ -f "$RELEASE_ASSETS_SUBJECTS" ]'

fresh; echo 99 > "$STUB_DIR/pending/a.apk"
bash $R v1 "$T/in/a.apk" > /dev/null 2> "$STUB_DIR/err"; rc=$?
check "a digest that never arrives fails" '[ $rc = 1 ] && grep -q "no digest" "$STUB_DIR/err"'

fresh; rm "$STUB_DIR/exists"
bash $R v1 "$T/in/a.apk" > /dev/null 2> "$STUB_DIR/err"; rc=$?
check "a tag with no release fails before anything is uploaded" '[ $rc = 1 ] && ! grep -q "release upload" "$STUB_DIR/log"'

fresh
bash $R v1 "$T/in/missing.apk" > /dev/null 2>&1; rc=$?
check "a missing file is refused before anything is uploaded" '[ $rc = 1 ] && [ ! -f "$STUB_DIR/log" ]'
printf x > "$T/in/with space.apk"
bash $R v1 "$T/in/with space.apk" > /dev/null 2>&1; rc=$?
check "an asset name with whitespace is refused" '[ $rc = 1 ] && [ ! -f "$STUB_DIR/log" ]'
printf x > "$T/in/SHA256SUMS"
bash $R v1 "$T/in/SHA256SUMS" > /dev/null 2>&1; rc=$?
check "SHA256SUMS itself is refused as an upload" '[ $rc = 1 ] && [ ! -f "$STUB_DIR/log" ]'
rm "$T/in/SHA256SUMS" "$T/in/with space.apk"
bash $R v1 > /dev/null 2>&1; rc=$?
check "no file is a usage error" '[ $rc = 2 ]'
bash $R --checksums > /dev/null 2>&1; rc=$?
check "--checksums without a tag is a usage error" '[ $rc = 2 ]'
bash $R --checksums v1 "$T/in/a.apk" > /dev/null 2>&1; rc=$?
check "--checksums takes no files" '[ $rc = 2 ]'

# --- --checksums --------------------------------------------------------------
# The release as a publisher leaves it before its last step.
uploaded() { fresh; bash $R v1 "$T/in/a.apk" "$T/in/b.dmg" > /dev/null; }

uploaded; printf other > "$STUB_DIR/assets/zz-other.deb"
bash $R --checksums v1 > /dev/null; rc=$?
check "SHA256SUMS lists every asset, another publisher's included, and verifies" \
  '[ $rc = 0 ] && complete && [ "$(wc -l < "$STUB_DIR/assets/SHA256SUMS" | tr -d " ")" = 3 ]'
check "SHA256SUMS is sorted by name and does not list itself" \
  '[ "$(sed "s/^[0-9a-f]*  //" "$STUB_DIR/assets/SHA256SUMS" | tr "\n" " ")" = "a.apk b.dmg zz-other.deb " ]'
check "one write is enough when nobody else writes" '[ "$(writes)" = 1 ]'
bash $R --checksums v1 > /dev/null; rc=$?
check "a re-run writes nothing when SHA256SUMS is complete" '[ $rc = 0 ] && [ "$(writes)" = 1 ]'

uploaded; printf other > "$STUB_DIR/assets/zz-other.deb"; echo 3 > "$STUB_DIR/uploading/zz-other.deb"
bash $R --checksums v1 > /dev/null; rc=$?
check "another publisher's asset still uploading is waited for, not left out" '[ $rc = 0 ] && complete && [ "$(writes)" = 1 ]'

uploaded; printf dead > "$STUB_DIR/assets/zz-dead.dmg"; echo 9999 > "$STUB_DIR/uploading/zz-dead.dmg"
bash $R --checksums v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "an upload that never finishes does not block: it is left out, with a warning" \
  '[ $rc = 0 ] && grep -q "::warning::.*leaves out zz-dead.dmg" "$STUB_DIR/out" && [ "$(sed "s/^[0-9a-f]*  //" "$STUB_DIR/assets/SHA256SUMS" | tr "\n" " ")" = "a.apk b.dmg " ]'

uploaded; touch "$STUB_DIR/stale_writer"
bash $R --checksums v1 > /dev/null; rc=$?
check "a line a concurrent publisher's stale write dropped is written again" '[ $rc = 0 ] && complete && [ "$(writes)" = 2 ]'
check "the concurrent publisher's asset is listed too" 'grep -q "  late.bin$" "$STUB_DIR/assets/SHA256SUMS"'

uploaded; echo 1 > "$STUB_DIR/fail_sums"
bash $R --checksums v1 > /dev/null 2>&1; rc=$?
check "a failed write of SHA256SUMS (two publishers replacing it at once) is retried" '[ $rc = 0 ] && complete'

uploaded; touch "$STUB_DIR/never_settles"
bash $R --checksums v1 > /dev/null 2> "$STUB_DIR/err"; rc=$?
check "a SHA256SUMS that never sticks fails after six writes" '[ $rc = 1 ] && grep -q "::error::" "$STUB_DIR/err" && [ "$(writes)" = 6 ]'

fresh; rm "$STUB_DIR/exists"
bash $R --checksums v1 > /dev/null 2>&1; rc=$?
check "--checksums for a tag with no release fails" '[ $rc = 1 ]'

# --- scripts/verify_release.sh, on the release the script above leaves -------
V=scripts/verify_release.sh
export GH_REPO=owner/repo
published() { fresh; bash $R v1 "$T/in/a.apk" "$T/in/b.dmg" > /dev/null; bash $R --checksums v1 > /dev/null; }

published
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "a release published through the script verifies" \
  '[ $rc = 0 ] && grep -q "all 2 listed files match" "$STUB_DIR/out" && grep -q "2 asset(s) have a build-provenance attestation" "$STUB_DIR/out"'

published; printf late > "$STUB_DIR/assets/late.bin"
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "an asset SHA256SUMS does not list fails" '[ $rc = 1 ] && grep -q "> late.bin" "$STUB_DIR/out"'

published; rm "$STUB_DIR/assets/b.dmg"
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "a listed file the release does not have fails" '[ $rc = 1 ] && grep -q "< b.dmg" "$STUB_DIR/out"'

published; printf tampered > "$STUB_DIR/assets/a.apk"
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "an asset whose bytes changed after it was listed fails" '[ $rc = 1 ] && grep -q "a.apk: FAILED" "$STUB_DIR/out"'

published; rm "$STUB_DIR/assets/SHA256SUMS"
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "a release without SHA256SUMS fails" '[ $rc = 1 ] && grep -q "no SHA256SUMS" "$STUB_DIR/out"'

published; touch "$STUB_DIR/unattested/b.dmg"
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "an asset without an attestation fails, and the others are still checked" \
  '[ $rc = 1 ] && grep -q "no valid attestation for b.dmg" "$STUB_DIR/out" && grep -q "1 asset(s) have" "$STUB_DIR/out"'
bash $V --no-attestations v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "--no-attestations skips that check" '[ $rc = 0 ] && grep -q "^skip  attestations" "$STUB_DIR/out"'

fresh; printf signed > "$T/in/Myotis-v1-android.apk"
bash $R v1 "$T/in/Myotis-v1-android.apk" > /dev/null; bash $R --checksums v1 > /dev/null
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "a signed APK with no unsigned twin fails" '[ $rc = 1 ] && grep -q "no Myotis-v1-android-unsigned.apk" "$STUB_DIR/out"'

published; keep="$T/kept"; mkdir -p "$keep"
bash $V v1 "$keep" > /dev/null 2>&1; rc=$?
check "a given directory keeps the downloaded assets" '[ $rc = 0 ] && [ -f "$keep/a.apk" ] && [ -f "$keep/SHA256SUMS" ]'
# A publisher is re-run: the asset and SHA256SUMS change on the release.
mkdir -p "$T/in/a2"; printf rebuilt > "$T/in/a2/a.apk"
bash $R v1 "$T/in/a2/a.apk" > /dev/null; bash $R --checksums v1 > /dev/null
bash $V v1 "$keep" > "$STUB_DIR/out" 2>&1; rc=$?
check "a kept directory is checked against the release as it is now, not as it was" \
  '[ $rc = 0 ] && cmp -s "$keep/a.apk" "$T/in/a2/a.apk" && grep -q "a.apk in .* is not what the release lists" "$STUB_DIR/out"'

fresh; bash $R --checksums v1 > /dev/null 2>&1; printf '%s  %s\n' "$(printf gone | { sha256sum 2> /dev/null || shasum -a 256; } | cut -d" " -f1)" gone.apk > "$STUB_DIR/assets/SHA256SUMS"
bash $V v1 > "$STUB_DIR/out" 2>&1; rc=$?
check "a release that has only SHA256SUMS fails with a reason, not silently" '[ $rc = 1 ] && grep -q "^FAIL .*not the same set" "$STUB_DIR/out"'

# Every publisher goes through the script: a bare `gh release upload` in a
# workflow would publish an asset SHA256SUMS may never list.
# And every job that uploads through it also lists the release in SHA256SUMS.
nosums=$(for wf in $(grep -l 'release-assets.sh "' .github/workflows/*.yml); do grep -q 'release-assets.sh --checksums' "$wf" || echo "$wf"; done)
check "every workflow that uploads also runs --checksums" '[ -z "$nosums" ]'
[ -z "$nosums" ] || echo "$nosums"
bare=$(grep -n 'gh release upload' .github/workflows/*.yml | grep -v '^\S*: *#' | grep -v '^[^:]*:[0-9]*: *#' || true)
check "no workflow uploads to a release with a bare gh release upload" '[ -z "$bare" ]'
[ -z "$bare" ] || echo "$bare"
# ... nor through action-gh-release's `files:` (ci.yml creates the release with
# it and uploads its jars through the script).
viaaction=$(grep -n -A12 'softprops/action-gh-release' .github/workflows/*.yml | grep -E '^\S+-[0-9]+- +files:' || true)
check "no workflow uploads through action-gh-release files:" '[ -z "$viaaction" ]'
[ -z "$viaaction" ] || echo "$viaaction"

echo "passed=$pass failed=$failed"
[ "$failed" = 0 ]
