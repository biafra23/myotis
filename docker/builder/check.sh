#!/usr/bin/env bash
# Check a builder image against the pins it was built from (#734, Part 5b).
#
#   docker/builder/check.sh [TAG]        default tag: myotis-builder:local
#
# Runs each tool INSIDE the image, as an unprivileged uid with a read-only
# root file system (how the build uses it), and compares its version with
# `build.sh --print-args`. A cached layer from an older pin, or a tool that
# resolved to something else, fails here. Works with bash 3.2.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tag=${1:-myotis-builder:local}

pins=$("$here/build.sh" --print-args)
want() { printf '%s\n' "$pins" | sed -n "s/^$1=//p"; }
in_image() { docker run --rm --read-only --tmpfs /tmp --user 4242:4242 -e HOME=/tmp "$tag" bash -euo pipefail -c "$1"; }
fail=0
check() { # NAME EXPECTED ACTUAL
    if [[ "$2" == "$3" ]]; then echo "  ok   $1: $3"; else echo "  FAIL $1: expected '$2', got '$3'"; fail=1; fi
}
revision() { in_image "sed -n 's/^Pkg.Revision *= *//p' \"$1/source.properties\" | tr -d '\\r '"; }

echo "checking $tag:"
# JAVA_RUNTIME_VERSION is e.g. 21.0.13+9-LTS (no suffix on a non-LTS release).
check "JDK" "$(want JDK_VERSION)+$(want JDK_BUILD)" \
    "$(in_image 'sed -n "s/^JAVA_RUNTIME_VERSION=\"\(.*\)\"$/\1/p" "$JAVA_HOME/release" | sed "s/-LTS$//"')"
check "JDK vendor" "Eclipse Adoptium" "$(in_image 'sed -n "s/^IMPLEMENTOR=\"\(.*\)\"$/\1/p" "$JAVA_HOME/release"')"
check "rustc" "rustc $(want RUST_VERSION)" "$(in_image 'rustc --version | cut -d" " -f1,2')"
check "rust targets" "aarch64-linux-android x86_64-linux-android x86_64-unknown-linux-gnu" \
    "$(in_image 'rustup target list --installed | sort | tr "\n" " " | sed "s/ $//"')"
check "cargo-ndk" "cargo-ndk $(want CARGO_NDK_VERSION)" "$(in_image 'cargo ndk --version')"
check "NDK" "$(want ANDROID_NDK)" "$(revision '$ANDROID_NDK_HOME')"
check "build-tools (the only one)" "$(want ANDROID_BUILD_TOOLS)" "$(in_image 'ls "$ANDROID_HOME/build-tools" | tr "\n" " " | sed "s/ $//"')"
check "platform (the only one)" "android-$(want ANDROID_PLATFORM)" "$(in_image 'ls "$ANDROID_HOME/platforms" | tr "\n" " " | sed "s/ $//"')"
# The Android tools must RUN as another uid, not merely be there: sdkmanager
# installs executables owner-only, and the first build in the image died at
# "clang: Permission denied" with every version check above green.
check "NDK clang runs" "ok" "$(in_image '"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" --version >/dev/null && echo ok' 2>&1 | tail -1)"
check "build-tools run (aapt2, d8, apksigner)" "ok" \
    "$(in_image 'bt="$ANDROID_HOME/build-tools/'"$(want ANDROID_BUILD_TOOLS)"'"; "$bt/aapt2" version >/dev/null 2>&1 && "$bt/d8" --version >/dev/null && "$bt/apksigner" --version >/dev/null && echo ok' 2>&1 | tail -1)"
# And nothing else under /opt is closed to it: every file readable, and
# executable (searchable, for a directory) wherever its owner may.
check "/opt open to any uid" "" \
    "$(in_image 'find /opt ! -type l \( ! -perm -o=r -o \( -perm -u=x ! -perm -o=x \) \) -print 2>&1 | head -5 | tr "\n" " "' || true)"
check "platform revision" "$(want ANDROID_PLATFORM_REVISION)" "$(revision "\$ANDROID_HOME/platforms/android-$(want ANDROID_PLATFORM)")"
# What apt INSTALLED, not only where it points: every package and version in
# the image against the committed list. A package from another state of the
# archive (the bootstrap fetch runs without TLS verification), or a toolchain
# package that moved, shows as a diff here; and a red comparison can be traced
# to gcc, binutils or libc by reading the list's history.
list="$here/apt-packages.txt"
actual=$(in_image "dpkg-query -W -f '\${Package}=\${Version}\n' | LC_ALL=C sort")
if [[ ! -f "$list" ]]; then
    echo "  FAIL apt packages: $list does not exist. The image has these; review and commit them:"
    echo "----- BEGIN apt-packages.txt -----"; printf '%s\n' "$actual"; echo "----- END apt-packages.txt -----"
    fail=1
elif [[ "$actual" == "$(grep -v '^#' "$list")" ]]; then
    echo "  ok   apt packages: $(printf '%s\n' "$actual" | wc -l | tr -d ' ') packages match apt-packages.txt"
else
    echo "  FAIL apt packages differ from apt-packages.txt (< committed, > image):"
    diff <(grep -v '^#' "$list") <(printf '%s\n' "$actual") | sed 's/^/    /' || true
    echo "----- BEGIN apt-packages.txt -----"; printf '%s\n' "$actual"; echo "----- END apt-packages.txt -----"
    fail=1
fi
check "apt sources (the only ones)" "https://snapshot.ubuntu.com/ubuntu/$(want APT_SNAPSHOT)" \
    "$(in_image 'cat /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | sed -n "s/^URIs: //p; s/^deb [^ ]* \([^ ]*\).*/\1/p" | sort -u | tr "\n" " " | sed "s/ $//"')"
check "en_US.UTF-8 locale" "en_US.utf8" "$(in_image 'locale -a | grep -ix "en_US.utf8"')"
check "fakeroot + dpkg-deb + cc" "ok" "$(in_image 'command -v fakeroot >/dev/null && command -v dpkg-deb >/dev/null && command -v cc >/dev/null && echo ok')"

[[ $fail -eq 0 ]] || { echo "check.sh: $tag does not match its pins" >&2; exit 1; }
echo "$tag matches its pins"
