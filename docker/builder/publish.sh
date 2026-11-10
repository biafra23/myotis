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
# is the one the lock must name. PUBLISH_PUSH=false checks without pushing
# (a pull request from a fork has no token to push with).
#
# Works with bash 3.2.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 REPOSITORY [TAG]" >&2; exit 2; }
repository=$1 tag=${2:-myotis-builder:local}
lock="$here/image.lock"
key=$("$here/build.sh" --print-key)
ref="$repository:$key"

digest_of() { docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$1" | sed -n "s|^$repository@||p" | head -n1; }

if docker pull --platform linux/amd64 "$ref" >/dev/null 2>&1; then
    echo "publish.sh: $ref is already published; not replacing it"
    digest=$(digest_of "$ref")
elif [[ "${PUBLISH_PUSH:-true}" == "true" ]]; then
    docker tag "$tag" "$ref"
    docker push "$ref"
    digest=$(digest_of "$ref")
else
    echo "publish.sh: $ref is not published, and this run may not push (PUBLISH_PUSH=false)." >&2
    echo "            Run the workflow from a branch of the repository itself." >&2
    exit 1
fi
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "publish.sh: could not read the digest of $ref" >&2; exit 1; }

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
