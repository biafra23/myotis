#!/usr/bin/env bash
# Cross-compile the workspace's Android cdylibs (myotis-bls today; myotis-engine once
# it grows a real JNI surface) for Android ABIs into the engine library's jniLibs, so
# NativeBlsBackend.isAvailable() is true on-device and the ~4-15x faster BLS verify
# kicks in. See docs/design-history/bls-rust-acceleration.md.
#
# One-time setup:
#   rustup target add aarch64-linux-android x86_64-linux-android   (inside rust/)
#   cargo install cargo-ndk --version <cargo-ndk> --locked
#   sdkmanager "ndk;<android-ndk>"; export ANDROID_NDK_HOME=<sdk>/ndk/<android-ndk>
# with <cargo-ndk> and <android-ndk> the EXACT versions pinned in
# gradle/libs.versions.toml (#734). `./gradlew cargoNdkAndroid` finds and checks
# both itself and refuses any other version; run directly, this script uses
# whatever ANDROID_NDK_HOME and cargo-ndk you give it.
#
# The pinned NDK is r28 or newer, which defaults to 16 KB-aligned LOAD segments
# (required by Android 15+ devices with 16 KB memory pages). .cargo/config.toml forces
# the alignment too via -Wl,-z,max-page-size=16384, and the check at the end of this
# script fails the build if anything slips through.
#
# Then: rust/build-android.sh
#
# MYOTIS_TOR_ENGINE=1 also compiles Tor into the engine (`--features
# myotis-engine/tor`: Arti on rustls + ring, SQLite bundled — see the TLS note in
# myotis-net/Cargo.toml and docs/how-it-works/privacy-and-tor.md). It adds megabytes per ABI,
# so it stays off unless asked for; Gradle sets it for `-PtorEngine`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# Fixed source-path prefixes in the shipped libs (#734 D2; the file says why).
. "$here/repro-env.sh"
jniLibs="$here/../myotis-engine/src/androidMain/jniLibs"

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the pinned NDK (\$ANDROID_SDK/ndk/<android-ndk from gradle/libs.versions.toml>)}"

# arm64-v8a covers all modern phones; x86_64 covers the emulator. Add armeabi-v7a for
# very old 32-bit devices if you still target them.
cd "$here"
# Build from the workspace root so the workspace [profile.release] and
# .cargo/config.toml apply. Ships myotis-bls (native BLS) and myotis-engine
# (the Rust engine behind :myotis-engine-rust's RustEngineNative). 16 KB-aligned
# LOAD segments (.cargo/config.toml passes -Wl,-z,max-page-size=16384) so the
# libs load on Android 15+ devices with 16 KB memory pages.
# A plain string, not an array: macOS's bash 3.2 rejects an empty array
# expansion under `set -u`.
tor_features=""
case "${MYOTIS_TOR_ENGINE:-0}" in
    0) ;;
    1)
        tor_features="--features myotis-engine/tor"
        echo "building with Tor (myotis-engine/tor)"
        ;;
    *) echo "MYOTIS_TOR_ENGINE must be 0 or 1 (got '${MYOTIS_TOR_ENGINE}')" >&2; exit 1 ;;
esac
# shellcheck disable=SC2086 # $tor_features is empty or two words, split on purpose
cargo ndk -t arm64-v8a -t x86_64 -o "$jniLibs" build --locked --release -p myotis-bls -p myotis-engine $tor_features

# cargo-ndk copies EVERY dynamic library the build graph produces, including
# hash-named dependency artifacts (e.g. libif_watch-<hash>.so) that
# libmyotis_engine.so does not link against (its only NEEDED entries are
# libc/libm/libdl). Keep jniLibs to exactly the libs we ship.
find "$jniLibs" -name '*.so' ! -name 'libmyotis_*.so' -print -delete

# Strip the shipped libraries with the pinned NDK's llvm-strip, as the AGP
# library plugin used to when it packaged the AAR (`--strip-unneeded`, AGP's
# StripDebugSymbols): the KMP Android library plugin (AGP 9) has no strip
# step and puts jniLibs into the AAR as built, symbol tables included (#837:
# jni/ 33.2 MB instead of 26.2 MB). Stripped here, the AAR carries what it
# always did, and what a consumer ships no longer depends on whether its own
# build has an NDK to strip with. The Myotis APK strips again; a stripped
# library comes out of that unchanged.
strip_tool=""
for candidate in "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-strip \
                 "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-strip.exe; do
    if [ -x "$candidate" ]; then strip_tool="$candidate"; break; fi
done
[ -n "$strip_tool" ] || { echo "no llvm-strip under $ANDROID_NDK_HOME/toolchains/llvm/prebuilt" >&2; exit 1; }
find "$jniLibs" -name 'libmyotis_*.so' -print0 | while IFS= read -r -d '' lib; do
    "$strip_tool" --strip-unneeded "$lib"
done

echo "built:"
find "$jniLibs" -name 'libmyotis_*.so' -exec ls -la {} \;

# Fail loudly if any PT_LOAD segment is <16 KB aligned — a 4 KB-aligned .so is
# rejected by the dynamic linker on 16 KB-page devices, and the symptom (BLS
# silently falling back to the slow JVM backend) is easy to miss. Every .so that
# survives the prune above is checked, and an empty jniLibs fails. The same
# script checks the APKs in android-apk.yml (#734).
echo "checking 16 KB alignment:"
python3 -I "$here/../scripts/check_16k_alignment.py" "$jniLibs"
