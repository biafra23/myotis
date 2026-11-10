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
  buildx) # buildx imagetools inspect REF --format ...: the registry's digest for REF
    [ ! -f "$d/registry_down" ] || { echo "503 Service Unavailable" >&2; exit 1; }
    [ -f "$d/registry/$(f "$4")" ] || { echo "manifest unknown" >&2; exit 1; }
    # As buildx prints it: indented, one field per line, a space after the colon.
    printf '{\n  "mediaType": "application/vnd.oci.image.index.v1+json",\n  "digest": "%s",\n  "size": 856\n}\n' "$(cat "$d/registry/$(f "$4")")" ;;
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
R=ghcr.io/owner/myotis-builder
D1=sha256:$(printf 1 | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)
D2=sha256:$(printf 2 | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)
KEY=$("$B/build.sh" --print-key)
lock() { printf '# a comment\nkey=%s\nimage=%s\n' "$1" "$2" > "$B/image.lock"; }

check "the key is a SHA-256 and the same as this checkout's" '[ ${#KEY} = 64 ] && [ "$KEY" = "$("$here/build.sh" --print-key)" ]'
cp "$B/Dockerfile" "$T/Dockerfile.orig"; echo "# changed" >> "$B/Dockerfile"
check "the key moves with the Dockerfile" '[ "$("$B/build.sh" --print-key)" != "$KEY" ]'
cp "$T/Dockerfile.orig" "$B/Dockerfile"

fresh
"$B/publish.sh" $R > "$STUB/out" 2>&1; rc=$?
check "a first publish pushes <repository>:<key>, and fails until the lock is committed" \
  '[ $rc = 1 ] && [ "$(pushes)" = 1 ] && grep -q "^docker push $R:$KEY$" "$STUB/log"'
check "it prints the lock to commit" 'grep -qx "key=$KEY" "$STUB/out" && grep -qx "image=$R@$D1" "$STUB/out"'
lock "$KEY" "$R@$D1"; echo "$D2" > "$STUB/next_digest"
"$B/publish.sh" $R > /dev/null 2>&1; rc=$?
check "with the lock committed it passes, and the published image is not replaced" '[ $rc = 0 ] && [ "$(pushes)" = 1 ]'
lock "$KEY" "$R@$D2"
"$B/publish.sh" $R > /dev/null 2>&1; rc=$?
check "a lock that names another digest fails" '[ $rc = 1 ] && [ "$(pushes)" = 1 ]'
lock "0000" "$R@$D1"
"$B/publish.sh" $R > /dev/null 2>&1; rc=$?
check "a lock for other pins fails" '[ $rc = 1 ]'

touch "$STUB/registry_down"; lock "$KEY" "$R@$D1"
PUBLISH_RETRY_PAUSE=0 "$B/publish.sh" $R > "$STUB/out" 2>&1; rc=$?
check "with the lock claiming the key, a registry that does not answer is an error, never a second push" \
  '[ $rc = 1 ] && [ "$(pushes)" = 1 ] && grep -q "Not publishing again" "$STUB/out"'

fresh
PUBLISH_PUSH=false "$B/publish.sh" $R > /dev/null 2>&1; rc=$?
check "a run that may not push fails without pushing when nothing is published" '[ $rc = 1 ] && [ "$(pushes)" = 0 ]'

fresh
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh without a lock exits 3" '[ $rc = 3 ] && [ ! -f "$STUB/log" ]'
lock "0000" "$R@$D1"
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh with a lock for other pins exits 3 and pulls nothing" '[ $rc = 3 ] && [ ! -f "$STUB/log" ]'
lock "$KEY" "$R:latest"
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh refuses a lock that names a tag, not a digest" '[ $rc = 1 ] && [ ! -f "$STUB/log" ]'
lock "$KEY" "$R@$D1"
PULL_RETRY_PAUSE=0 "$B/pull.sh" > "$STUB/out" 2>&1; rc=$?
check "pull.sh fails when the locked digest cannot be pulled" '[ $rc = 1 ] && grep -q "build.sh builds the same image" "$STUB/out"'
check "it tried three times and says what to do instead" \
  '[ "$(grep -c "^docker pull" "$STUB/log")" = 3 ]'
echo "$D1" > "$STUB/registry/published"
"$B/pull.sh" > /dev/null 2>&1; rc=$?
check "pull.sh pulls the locked digest and tags it" \
  '[ $rc = 0 ] && grep -q "^docker pull --platform linux/amd64 $R@$D1$" "$STUB/log" && grep -q "^docker tag $R@$D1 myotis-builder:local$" "$STUB/log"'

echo "passed=$pass failed=$failed"
[ "$failed" = 0 ]
