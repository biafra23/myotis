#!/usr/bin/env bash
# Check a builder image against the pins it was built from (#734, Part 5b).
#
#   docker/builder/check.sh [TAG]        default tag: myotis-builder:local
#
# Runs each tool INSIDE the image, as an unprivileged uid with a read-only
# root file system (how the build uses it), and compares its version with
# `build.sh --print-args`. A cached layer from an older pin, or a tool that
# resolved to something else, fails here.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tag=${1:-myotis-builder:local}

declare -A want
while IFS='=' read -r k v; do want[$k]=$v; done < <("$here/build.sh" --print-args)

in_image() { docker run --rm --read-only --tmpfs /tmp --user 4242:4242 -e HOME=/tmp "$tag" bash -euo pipefail -c "$1"; }
fail=0
check() { # NAME EXPECTED ACTUAL
    if [[ "$2" == "$3" ]]; then echo "  ok   $1: $3"; else echo "  FAIL $1: expected '$2', got '$3'"; fail=1; fi
}

echo "checking $tag:"
check "JDK" "${want[JDK_VERSION]}+${want[JDK_BUILD]}" \
    "$(in_image 'sed -n "s/^JAVA_RUNTIME_VERSION=\"\(.*\)-LTS\"$/\1/p" "$JAVA_HOME/release"')"
check "JDK vendor" "Eclipse Adoptium" "$(in_image 'sed -n "s/^IMPLEMENTOR=\"\(.*\)\"$/\1/p" "$JAVA_HOME/release"')"
check "rustc" "rustc ${want[RUST_VERSION]}" "$(in_image 'rustc --version | cut -d" " -f1,2')"
check "rust targets" "aarch64-linux-android x86_64-linux-android x86_64-unknown-linux-gnu" \
    "$(in_image 'rustup target list --installed | sort | tr "\n" " " | sed "s/ $//"')"
check "cargo-ndk" "cargo-ndk ${want[CARGO_NDK_VERSION]}" "$(in_image 'cargo ndk --version')"
check "NDK" "${want[ANDROID_NDK]}" \
    "$(in_image 'sed -n "s/^Pkg.Revision *= *//p" "$ANDROID_NDK_HOME/source.properties" | tr -d "\r "')"
check "build-tools" "${want[ANDROID_BUILD_TOOLS]}" \
    "$(in_image 'sed -n "s/^Pkg.Revision *= *//p" "$ANDROID_HOME/build-tools/'"${want[ANDROID_BUILD_TOOLS]}"'/source.properties" | tr -d "\r "')"
check "platform" "android-${want[ANDROID_PLATFORM]}" \
    "$(in_image 'ls "$ANDROID_HOME/platforms"')"
check "apt snapshot" "https://snapshot.ubuntu.com/ubuntu/${want[APT_SNAPSHOT]}" \
    "$(in_image 'sed -n "s/^URIs: //p" /etc/apt/sources.list.d/ubuntu.sources')"
check "en_US.UTF-8 locale" "en_US.utf8" "$(in_image 'locale -a | grep -ix "en_US.utf8"')"
check "fakeroot + dpkg-deb" "ok" "$(in_image 'command -v fakeroot >/dev/null && command -v dpkg-deb >/dev/null && echo ok')"

[[ $fail -eq 0 ]] || { echo "check.sh: $tag does not match its pins" >&2; exit 1; }
echo "$tag matches its pins"
