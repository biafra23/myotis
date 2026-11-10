#!/usr/bin/env bash
# Pull the published builder image for THIS tree's pins (#734).
#
#   docker/builder/pull.sh [TAG]         default tag: myotis-builder:local
#
# docker/builder/image.lock names the image published for one set of pins: the
# key of those pins (`build.sh --print-key`) and the image by DIGEST. This
# pulls that digest and tags it TAG, so the next commands are the usual ones:
#
#   docker/builder/pull.sh && docker/builder/check.sh
#   docker/builder/run.sh -- scripts/repro/build_linux.sh
#
# Exit 3, and nothing pulled, when the lock is not for this tree's pins (a pin
# moved and the lock has not followed yet, or there is no lock): build the
# image with build.sh instead. Exit 1 when the locked image cannot be pulled.
#
# Pulled or built is a choice of whom to trust. build.sh trusts only the
# sources the Dockerfile pins by digest and hash. pull.sh trusts whoever
# published the image: the digest is committed, so it is the same image for
# everyone and for every later run, and check.sh holds it to the pins (every
# tool's version, the apt package list), but nothing compares it byte for byte
# with a build from the Dockerfile; an image build is not bit-for-bit
# repeatable. CI pulls, because a build needs snapshot.ubuntu.com, which
# refuses requests for minutes at a time; `builder image` still builds from
# the pins on every pin change and weekly.
#
# Works with bash 3.2.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tag=${1:-myotis-builder:local}
lock="$here/image.lock"

key=$("$here/build.sh" --print-key)
[[ -f "$lock" ]] || { echo "pull.sh: no $lock: no image is published for this tree; build it with build.sh" >&2; exit 3; }
locked_key=$(sed -n 's/^key=//p' "$lock")
image=$(sed -n 's/^image=//p' "$lock")
[[ "$image" =~ ^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$ ]] \
    || { echo "pull.sh: $lock has no image=<repository>@sha256:<digest> line" >&2; exit 1; }
if [[ "$locked_key" != "$key" ]]; then
    echo "pull.sh: image.lock is for pins $locked_key, this tree's are $key:" >&2
    echo "         a pin moved and the published image has not followed. Build it with build.sh." >&2
    exit 3
fi

docker pull --platform linux/amd64 "$image"
docker tag "$image" "$tag"
echo "pulled $image as $tag"
