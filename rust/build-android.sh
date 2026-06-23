#!/usr/bin/env bash
# Cross-compile the native blst lib (rust/myotis-bls) for Android ABIs into the app's
# jniLibs, so NativeBlsBackend.isAvailable() is true on-device and the ~4-15x faster BLS
# verify kicks in. See docs/bls-rust-acceleration.md.
#
# One-time setup:
#   rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME=<sdk>/ndk/<version>   # e.g. 27.0.11718014
#
# Then: rust/build-android.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
crate="$here/myotis-bls"
jniLibs="$here/../android-app/src/main/jniLibs"

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your NDK path (e.g. \$ANDROID_SDK/ndk/27.0.11718014)}"

# arm64-v8a covers all modern phones; x86_64 covers the emulator. Add armeabi-v7a for
# very old 32-bit devices if you still target them.
cd "$crate"
cargo ndk -t arm64-v8a -t x86_64 -o "$jniLibs" build --release

echo "built:"
find "$jniLibs" -name 'libmyotis_bls.so' -exec ls -la {} \;
