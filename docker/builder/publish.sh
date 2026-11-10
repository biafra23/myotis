#!/usr/bin/env bash
# Publish the builder image for this tree's pins, and hold image.lock to it (#734).
#
#   docker/builder/publish.sh [TAG]      the local image to publish
#                                        (default: myotis-builder:local)
#
# Run by the `builder image` workflow after build.sh and check.sh, never by
# hand; the registry login is the caller's. The image goes up as
# <IMAGE_REPOSITORY of pins.env>:<key>, <key> being `build.sh --print-key`:
# one tag per set of pins. A tag can be moved, so nothing reads it: image.lock
# names the image by digest, and this script fails unless the committed lock
# says exactly
#
#   key=<this tree's key>
#   image=<repository>@<the published digest>
#
# printing those lines to commit when it does not. So moving a pin moves
# image.lock in the same change, like apt-packages.txt: the first run on the
# change publishes and fails with the new lock, the commit of it goes green.
#
# AN IMAGE ALREADY PUBLISHED UNDER A KEY IS NOT REPLACED (a rebuild has other
# bytes, and a lock someone committed would stop matching). The script pushes
# only when the registry has said that the tag does not exist. An answer it
# cannot read, a timeout or a refusal is an error to re-run after three tries,
# never a reason to push. One case cannot be told from a refusal: the very
# first publish of a package, which a registry may answer with "denied"
# because the package does not exist yet. PUBLISH_ASSUME_ABSENT=true pushes
# then; it is for that bootstrap only.
#
# The digest is always the registry's answer for the tag (`docker buildx
# imagetools inspect`), never the local image store's, which can know several
# digests for one image or none right after a push.
#
# When the tag exists and the lock does not name it yet (a re-run before the
# lock commit, another branch that moved the same pin), the published image is
# not this run's build: the script pulls it by digest and runs check.sh on IT
# before printing its lock.
#
# PUBLISH_PUSH=false checks without pushing (a pull request from a fork has no
# token to push with).
#
# Works with bash 3.2.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ $# -le 1 ]] || { echo "usage: $0 [TAG]" >&2; exit 2; }
tag=${1:-myotis-builder:local}
lock="$here/image.lock"
repository=$(sed -n 's/^IMAGE_REPOSITORY=//p' "$here/pins.env")
[[ -n "$repository" ]] || { echo "publish.sh: no IMAGE_REPOSITORY in pins.env" >&2; exit 1; }
key=$("$here/build.sh" --print-key)
ref="$repository:$key"
locked_key=$( [[ -f "$lock" ]] && sed -n 's/^key=//p' "$lock" || true)
pause=${PUBLISH_RETRY_PAUSE:-20}

# Ask the registry for a reference. 0: it is there, and `digest` is its digest.
# 1: the registry says it does not exist. 2: no usable answer after three
# tries; `answer` holds the last one.
# buildx prints the descriptor as indented JSON, one field per line, the
# top-level ones indented by two spaces ("  \"digest\": \"sha256:...\","); an
# index lists its manifests' digests further in. The plain report's "Digest:"
# line is the same value, should the JSON's shape move.
digest="" answer=""
ask() {
    local attempt
    for attempt in 1 2 3; do
        if answer=$(docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' 2>&1); then
            digest=$(printf '%s\n' "$answer" | sed -n 's/^  "digest": "\(sha256:[0-9a-f]\{64\}\)",\{0,1\}$/\1/p' | head -n1)
            [[ -n "$digest" ]] || digest=$(docker buildx imagetools inspect "$1" 2>/dev/null \
                | sed -n 's/^Digest:[[:space:]]*\(sha256:[0-9a-f]\{64\}\)[[:space:]]*$/\1/p' | head -n1) || true
            [[ -z "$digest" ]] || return 0
            answer="the registry answered, but no top-level digest was found in: $(printf '%s' "$answer" | head -c 400)"
        elif printf '%s' "$answer" | grep -qiE 'not found|manifest unknown|name unknown'; then
            return 1
        fi
        [[ $attempt -eq 3 ]] || sleep "$pause"
    done
    return 2
}
no_answer() { echo "publish.sh: $1" >&2; printf '%s\n' "$answer" | tail -n 5 | sed 's/^/            /' >&2; exit 1; }

origin=""
state=0; ask "$ref" || state=$?
if [[ "$locked_key" == "$key" ]]; then
    case $state in
        0) ;;
        1) no_answer "image.lock says $ref is published, and the registry says it does not exist. Not publishing again: the lock would name another image than the one it was committed for." ;;
        *) no_answer "image.lock says $ref is published, but the registry did not say so. Not publishing again; re-run. Its last answer:" ;;
    esac
else
    if [[ $state -eq 2 && "${PUBLISH_ASSUME_ABSENT:-false}" == "true" ]]; then
        echo "publish.sh: the registry did not say whether $ref exists; PUBLISH_ASSUME_ABSENT=true, so taking it as not published"
        state=1
    fi
    case $state in
        0)  echo "publish.sh: $ref is already published; not replacing it"
            # Not this run's build: hold it to the pins before telling anyone to lock it.
            docker pull --platform linux/amd64 "$repository@$digest"
            "${PUBLISH_CHECK:-$here/check.sh}" "$repository@$digest"
            origin="# Published by an earlier run; pulled and checked against the pins by ${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-?}." ;;
        1)  if [[ "${PUBLISH_PUSH:-true}" != "true" ]]; then
                echo "publish.sh: $ref is not published, and this run may not push (PUBLISH_PUSH=false)." >&2
                echo "            Run the workflow from a branch of the repository itself." >&2
                exit 1
            fi
            docker tag "$tag" "$ref"
            docker push "$ref"
            state=0; ask "$ref" || state=$?
            [[ $state -eq 0 ]] || no_answer "pushed $ref but could not read its digest back; re-run (the image stays, and is found under its key). The registry's last answer:"
            origin="# Built and published by ${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-?} at commit ${GITHUB_SHA:-?}." ;;
        *)  no_answer "the registry did not say whether $ref exists, so nothing is pushed (an image already there must not be replaced); re-run. Its last answer:" ;;
    esac
fi

want=$(printf 'key=%s\nimage=%s@%s\n' "$key" "$repository" "$digest")
have=$( [[ -f "$lock" ]] && grep -v '^#' "$lock" | sed '/^$/d' || true)
if [[ "$have" == "$want" ]]; then
    echo "publish.sh: image.lock names the published image: $repository@$digest"
    exit 0
fi
echo "publish.sh: docker/builder/image.lock does not name the image published for these pins." >&2
echo "            Commit these lines as its content (below its header comment):" >&2
echo "----- BEGIN image.lock -----"; [[ -z "$origin" ]] || printf '%s\n' "$origin"; printf '%s\n' "$want"; echo "----- END image.lock -----"
exit 1
