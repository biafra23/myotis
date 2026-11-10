#!/usr/bin/env bash
# Publish the builder image for this tree's pins, and hold image.lock to it (#734).
#
#   docker/builder/publish.sh REPOSITORY [TAG]
#       REPOSITORY  e.g. ghcr.io/biafra23/myotis-builder (already logged in)
#       TAG         the local image to publish (default: myotis-builder:local)
#
# Run by the `builder image` workflow after build.sh and check.sh, never by
# hand. The image goes up as REPOSITORY:<key>, <key> being `build.sh
# --print-key`: one tag per set of pins. A tag can be moved, so nothing reads
# it: image.lock names the image by digest, and this script fails unless the
# committed lock says exactly
#
#   key=<this tree's key>
#   image=REPOSITORY@<the published digest>
#
# printing those lines to commit when it does not. So moving a pin moves
# image.lock in the same change, like apt-packages.txt: the first run on the
# change publishes and fails with the new lock, the commit of it goes green.
#
# An image already published under this key is NOT replaced (a rebuild has
# other bytes, and a lock someone committed would stop matching): its digest
# is the one the lock must name. The digest is always the REGISTRY's answer for
# the tag (`docker buildx imagetools inspect`), never the local image store's,
# which can know several digests for one image, or none right after a push.
#
# When the committed lock already claims this key, the image IS published and
# this script never pushes: a tag it cannot read is then an error, not a
# reason to publish again. Only for a key the lock does not claim yet does an
# unreadable tag mean "not published".
#
# PUBLISH_PUSH=false checks without pushing (a pull request from a fork has no
# token to push with).
#
# Works with bash 3.2.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 REPOSITORY [TAG]" >&2; exit 2; }
repository=$1 tag=${2:-myotis-builder:local}
lock="$here/image.lock"
key=$("$here/build.sh" --print-key)
ref="$repository:$key"
locked_key=$( [[ -f "$lock" ]] && sed -n 's/^key=//p' "$lock" || true)

# The digest the registry serves for a reference; empty (status 1) when it
# cannot be read. buildx prints the descriptor as indented JSON, one field per
# line ("digest": "sha256:..."); the first run against a real registry found
# that out, after the push.
remote_digest() {
    local d
    d=$(docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' 2>/dev/null \
        | sed -n 's/.*"digest":[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' | head -n1) || true
    # And its plain report ("Digest:    sha256:..."), should the JSON's shape move again.
    [[ -n "$d" ]] || d=$(docker buildx imagetools inspect "$1" 2>/dev/null \
        | sed -n 's/^Digest:[[:space:]]*\(sha256:[0-9a-f]\{64\}\)[[:space:]]*$/\1/p' | head -n1) || true
    [[ -n "$d" ]] && printf '%s\n' "$d"
}

if [[ "$locked_key" == "$key" ]]; then
    digest=""
    for attempt in 1 2 3; do
        digest=$(remote_digest "$ref") && break
        [[ $attempt -eq 3 ]] || sleep "${PUBLISH_RETRY_PAUSE:-20}"
    done
    [[ -n "$digest" ]] || { echo "publish.sh: image.lock says $ref is published, but the registry does not answer for it. Not publishing again; re-run." >&2; exit 1; }
elif digest=$(remote_digest "$ref"); then
    echo "publish.sh: $ref is already published; not replacing it"
elif [[ "${PUBLISH_PUSH:-true}" == "true" ]]; then
    docker tag "$tag" "$ref"
    docker push "$ref"
    digest=$(remote_digest "$ref") || { echo "publish.sh: pushed $ref but could not read its digest back; re-run" >&2; exit 1; }
else
    echo "publish.sh: $ref is not published, and this run may not push (PUBLISH_PUSH=false)." >&2
    echo "            Run the workflow from a branch of the repository itself." >&2
    exit 1
fi

want=$(printf 'key=%s\nimage=%s@%s\n' "$key" "$repository" "$digest")
have=$( [[ -f "$lock" ]] && grep -v '^#' "$lock" | sed '/^$/d' || true)
if [[ "$have" == "$want" ]]; then
    echo "publish.sh: image.lock names the published image: $repository@$digest"
    exit 0
fi
echo "publish.sh: docker/builder/image.lock does not name the image published for these pins." >&2
echo "            Commit these two lines as its content (below its comment lines):" >&2
echo "----- BEGIN image.lock -----"; printf '%s\n' "$want"; echo "----- END image.lock -----"
exit 1
