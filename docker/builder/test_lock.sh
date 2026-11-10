#!/usr/bin/env bash
# Tests publish.sh and pull.sh against a stubbed `docker` (no daemon, no
# registry): what gets pushed, that a published image is never replaced, and
# that image.lock must name exactly the published digest for this tree's pins.
#
#   docker/builder/test_lock.sh
#
# The scripts are run from a copy of this directory, so the test can write the
# copy's image.lock; build.sh there still reads the pins from this checkout.
# shellcheck disable=SC2016,SC2034
set -u
here=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# The copy sits two levels below a fake root that links the files build.sh reads.
root="$T/root"; B="$root/docker/builder"
mkdir -p "$B" "$root/gradle" "$root/rust" "$root/android-app" "$root/myotis-engine" "$root/ui"
cp "$here"/*.sh "$here/Dockerfile" "$here/pins.env" "$B/"
repo=$(cd "$here/../.." && pwd)
cp "$repo/.java-version" "$root/"; cp "$repo/rust/rust-toolchain.toml" "$root/rust/"
cp "$repo/gradle/libs.versions.toml" "$root/gradle/"
for m in android-app myotis-engine ui; do cp "$repo/$m/build.gradle.kts" "$root/$m/"; done

# The stub: $STUB/registry/<ref with / and : and @ as _> holds that ref's digest.
mkdir -p "$T/bin"
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -eu
d=$STUB; mkdir -p "$d/registry" "$d/local"; echo "docker $*" >> "$d/log"
f() { printf '%s' "$1" | tr '/:@' '___'; }
case "$1" in
  pull)
    ref=${@: -1}
    case "$ref" in
      *@sha256:*) grep -rqx "${ref##*@}" "$d/registry" || { echo "manifest unknown" >&2; exit 1; }; echo "${ref##*@}" > "$d/local/$(f "$ref")" ;;
      *) [ -f "$d/registry/$(f "$ref")" ] || { echo "manifest unknown" >&2; exit 1; }; cp "$d/registry/$(f "$ref")" "$d/local/$(f "$ref")" ;;
    esac ;;
  tag) [ -f "$d/local/$(f "$2")" ] && cp "$d/local/$(f "$2")" "$d/local/$(f "$3")" || : > "$d/local/$(f "$3")" ;;
  push) cat "$d/next_digest" > "$d/registry/$(f "$2")"; cp "$d/registry/$(f "$2")" "$d/local/$(f "$2")"; echo x >> "$d/pushes" ;;
  buildx) # buildx imagetools inspect REF [--format ...]: the registry's answer for REF
    [ ! -f "$d/registry_down" ] || { echo "ERROR: unexpected status from HEAD request: 503 Service Unavailable" >&2; exit 1; }
    [ ! -f "$d/registry_denies" ] || { echo "ERROR: denied: denied" >&2; exit 1; }
    [ -f "$d/registry/$(f "$4")" ] || { echo "ERROR: $4: not found" >&2; exit 1; }
    dg=$(cat "$d/registry/$(f "$4")")
    case " $* " in
      *" --format "*) # As buildx prints it (copied from a real run's shape): indented, one
        # field per line, and an index lists its manifests' own digests further in.
        cat <<JSON
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "digest": "$dg",
  "size": 856,
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "size": 2011,
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "size": 566
    }
  ]
}
JSON
        ;;
      *) printf 'Name:      %s\nMediaType: application/vnd.oci.image.index.v1+json\nDigest:    %s\n' "$4" "$dg" ;;
    esac ;;
  *) exit 98 ;;
esac
STUB
chmod +x "$T/bin/docker"
export PATH="$T/bin:$PATH"

pass=0 failed=0
check() { if eval "$2"; then echo "PASS $1"; pass=$((pass + 1)); else echo "FAIL $1"; failed=$((failed + 1)); fi; }
n=0
fresh() { n=$((n + 1)); export STUB="$T/case$n"; mkdir -p "$STUB/registry" "$STUB/local"; echo "$D1" > "$STUB/next_digest"; rm -f "$B/image.lock"; }
pushes() { [ -f "$STUB/pushes" ] && echo $(($(wc -l < "$STUB/pushes"))) || echo 0; }
R=$(sed -n 's/^IMAGE_REPOSITORY=//p' "$B/pins.env")
# check.sh needs a daemon; the test records that publish.sh called it, and on what.
printf '#!/bin/sh\necho "$1" >> "$STUB/checked"\n' > "$T/bin/check"; chmod +x "$T/bin/check"
export PUBLISH_CHECK="$T/bin/check" PUBLISH_RETRY_PAUSE=0 PULL_RETRY_PAUSE=0
D1=sha256:$(printf 1 | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)
D2=sha256:$(printf 2 | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)
KEY=$("$B/build.sh" --print-key)
lock() { printf '# a comment\nkey=%s\nimage=%s\n' "$1" "$2" > "$B/image.lock"; }

check "the key is a SHA-256 and the same as this checkout's" '[ ${#KEY} = 64 ] && [ "$KEY" = "$("$here/build.sh" --print-key)" ]'
cp "$B/Dockerfile" "$T/Dockerfile.orig"; echo "# changed" >> "$B/Dockerfile"
check "the key moves with the Dockerfile" '[ "$("$B/build.sh" --print-key)" != "$KEY" ]'
cp "$T/Dockerfile.orig" "$B/Dockerfile"

fresh
"$B/publish.sh" > "$STUB/out" 2>&1; rc=$?
check "a first publish pushes <repository>:<key>, and fails until the lock is committed" \
  '[ $rc = 1 ] && [ "$(pushes)" = 1 ] && grep -q "^docker push $R:$KEY$" "$STUB/log"'
check "it prints the lock to commit" 'grep -qx "key=$KEY" "$STUB/out" && grep -qx "image=$R@$D1" "$STUB/out"'
lock "$KEY" "$R@$D1"; echo "$D2" > "$STUB/next_digest"
"$B/publish.sh" > /dev/null 2>&1; rc=$?
check "with the lock committed it passes, and the published image is not replaced" '[ $rc = 0 ] && [ "$(pushes)" = 1 ]'
lock "$KEY" "$R@$D2"
"$B/publish.sh" > /dev/null 2>&1; rc=$?
check "a lock that names another digest fails" '[ $rc = 1 ] && [ "$(pushes)" = 1 ]'
lock "0000" "$R@$D1"
"$B/publish.sh" > /dev/null 2>&1; rc=$?
check "a lock for other pins fails" '[ $rc = 1 ]'

touch "$STUB/registry_down"; lock "$KEY" "$R@$D1"
"$B/publish.sh" > "$STUB/out" 2>&1; rc=$?
check "with the lock claiming the key, a registry that does not answer is an error, never a second push" \
  '[ $rc = 1 ] && [ "$(pushes)" = 1 ] && grep -q "Not publishing again" "$STUB/out"'

# Another branch moved the same pin first: the tag is there, the lock is not.
fresh; echo "$D1" > "$STUB/registry/$(printf '%s' "$R:$KEY" | tr '/:@' '___')"
"$B/publish.sh" > "$STUB/out" 2>&1; rc=$?
check "an image published by someone else is not replaced, and is checked before its lock is printed" \
  '[ $rc = 1 ] && [ "$(pushes)" = 0 ] && grep -qx "image=$R@$D1" "$STUB/out" && [ "$(cat "$STUB/checked")" = "$R@$D1" ] && grep -q "^# Published by an earlier run" "$STUB/out"'
touch "$STUB/registry_down"
"$B/publish.sh" > "$STUB/out" 2>&1; rc=$?
check "key not claimed, tag published, registry down: an error, never a push over it" \
  '[ $rc = 1 ] && [ "$(pushes)" = 0 ] && grep -q "did not say whether" "$STUB/out" && grep -q "503" "$STUB/out"'
rm "$STUB/registry_down"; touch "$STUB/registry_denies"
"$B/publish.sh" > /dev/null 2>&1; rc=$?
check "a refusal is not 'does not exist' either" '[ $rc = 1 ] && [ "$(pushes)" = 0 ]'

fresh; touch "$STUB/registry_denies"
PUBLISH_ASSUME_ABSENT=true "$B/publish.sh" > "$STUB/out" 2>&1 || true
check "PUBLISH_ASSUME_ABSENT=true pushes when the registry will not say (a package's first publish)" \
  '[ "$(pushes)" = 1 ] && grep -q "taking it as not published" "$STUB/out"'

fresh
"$B/publish.sh" > "$STUB/out" 2>&1 || true
check "a push records the run that built the image, for the lock's comment" 'grep -q "^# Built and published by .*/actions/runs/" "$STUB/out"'
check "the digest read back is the top-level one, not a manifest's inside the index" \
  'grep -qx "image=$R@$D1" "$STUB/out" && ! grep -q "aaaaaaaa" "$STUB/out"'

fresh
PUBLISH_PUSH=false "$B/publish.sh" > /dev/null 2>&1; rc=$?
check "a run that may not push fails without pushing when nothing is published" '[ $rc = 1 ] && [ "$(pushes)" = 0 ]'

fresh
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh without a lock exits 3" '[ $rc = 3 ] && [ ! -f "$STUB/log" ]'
lock "0000" "$R@$D1"
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh with a lock for other pins exits 3 and pulls nothing" '[ $rc = 3 ] && [ ! -f "$STUB/log" ]'
lock "$KEY" "ghcr.io/someone-else/builder@$D1"
"$B/pull.sh" > "$STUB/out" 2>&1; rc=$?
check "pull.sh refuses a lock that names another repository" '[ $rc = 1 ] && [ ! -f "$STUB/log" ] && grep -q "refusing to pull" "$STUB/out"'
lock "$KEY" "$R:latest"
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh refuses a lock that names a tag, not a digest" '[ $rc = 1 ] && [ ! -f "$STUB/log" ]'
lock "$KEY" "$R@$D1"
"$B/pull.sh" > "$STUB/out" 2>&1; rc=$?
check "pull.sh fails when the locked digest cannot be pulled" '[ $rc = 1 ] && grep -q "build.sh builds the same image" "$STUB/out"'
check "it tried three times and says what to do instead" \
  '[ "$(grep -c "^docker pull" "$STUB/log")" = 3 ]'
echo "$D1" > "$STUB/registry/published"
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh pulls the locked digest and tags it" \
  '[ $rc = 0 ] && grep -q "^docker pull --platform linux/amd64 $R@$D1$" "$STUB/log" && grep -q "^docker tag $R@$D1 myotis-builder:local$" "$STUB/log"'

echo "passed=$pass failed=$failed"
[ "$failed" = 0 ]
