#!/usr/bin/env bash
# Build the Myotis builder image (#734, Part 5b).
#
#   docker/builder/build.sh [TAG]        default tag: myotis-builder:local
#
# Passes the Dockerfile its build args: the image-only pins from pins.env, and
# the versions the build itself pins, each read from its ONE source (see
# pins.env's header). A JDK version in .java-version that pins.env has no hash
# for, or a compileSdk the image does not carry, fails here rather than
# producing an image that is not the one the build expects.
#
# `--print-args` prints the resolved build args and exits (what check.sh and
# the workflow compare the finished image against).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
print_only=false
[[ "${1:-}" == "--print-args" ]] && { print_only=true; shift; }
tag=${1:-myotis-builder:local}

set -a
# shellcheck source=docker/builder/pins.env
. "$here/pins.env"
set +a

toml() { sed -n "s/^$1 *= *\"\([^\"]*\)\".*/\1/p" "$root/gradle/libs.versions.toml"; }
jdk=$(tr -d '[:space:]' < "$root/.java-version")
rust=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$root/rust/rust-toolchain.toml")
ndk=$(toml android-ndk) build_tools=$(toml android-build-tools) cargo_ndk=$(toml cargo-ndk)
for name in jdk rust ndk build_tools cargo_ndk; do
    [[ -n "${!name}" ]] || { echo "build.sh: could not read the $name pin" >&2; exit 1; }
done

[[ "$jdk" == "$JDK_VERSION" ]] || {
    echo "build.sh: .java-version says $jdk, but docker/builder/pins.env has the build number and hash of $JDK_VERSION." >&2
    echo "          Move JDK_VERSION, JDK_BUILD and JDK_SHA256 there in the same change." >&2
    exit 1
}
for f in android-app/build.gradle.kts myotis-engine/build.gradle.kts ui/build.gradle.kts; do
    sdk=$(sed -n 's/^ *compileSdk *= *\([0-9]*\).*/\1/p' "$root/$f" | head -n1)
    [[ "$sdk" == "$ANDROID_PLATFORM" ]] || {
        echo "build.sh: $f has compileSdk $sdk, but pins.env's ANDROID_PLATFORM is $ANDROID_PLATFORM" >&2
        exit 1
    }
done

args=(
    "BASE_IMAGE=$BASE_IMAGE"
    "APT_SNAPSHOT=$APT_SNAPSHOT"
    "JDK_VERSION=$JDK_VERSION" "JDK_BUILD=$JDK_BUILD" "JDK_SHA256=$JDK_SHA256"
    "RUSTUP_VERSION=$RUSTUP_VERSION" "RUSTUP_SHA256=$RUSTUP_SHA256"
    "RUST_VERSION=$rust" "CARGO_NDK_VERSION=$cargo_ndk"
    "ANDROID_CMDLINE_TOOLS=$ANDROID_CMDLINE_TOOLS"
    "ANDROID_CMDLINE_TOOLS_SHA256=$ANDROID_CMDLINE_TOOLS_SHA256"
    "ANDROID_NDK=$ndk" "ANDROID_BUILD_TOOLS=$build_tools"
    "ANDROID_PLATFORM=$ANDROID_PLATFORM" "ANDROID_PLATFORM_REVISION=$ANDROID_PLATFORM_REVISION"
    "ANDROID_PLATFORM_ARCHIVE=$ANDROID_PLATFORM_ARCHIVE" "ANDROID_PLATFORM_SHA256=$ANDROID_PLATFORM_SHA256"
)
if $print_only; then
    printf '%s\n' "${args[@]}"
    exit 0
fi

build_args=()
for a in "${args[@]}"; do build_args+=(--build-arg "$a"); done
# The context is this directory only: the image contains no source.
docker build --platform linux/amd64 "${build_args[@]}" -t "$tag" -f "$here/Dockerfile" "$here"
echo "built $tag: $(docker image inspect --format '{{.Id}}' "$tag")"
