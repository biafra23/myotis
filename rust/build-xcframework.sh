#!/usr/bin/env bash
# Build MyotisEngine.xcframework: the Rust engine as a plain-C-ABI static
# library packaged for iOS device + simulator, for Swift hosts that embed the
# engine directly (wallets/browsers) without the Kotlin/Native MyotisKit
# framework. The C surface is rust/include/myotis_engine.h (see capi.rs);
# hosts must gate on myotis_init() returning MYOTIS_ABI_VERSION.
#
# Slices: aarch64-apple-ios (device) and a fat simulator slice
# (aarch64-apple-ios-sim + x86_64-apple-ios via lipo). macOS only (needs
# xcodebuild + lipo).
#
# One-time setup:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Then: rust/build-xcframework.sh
#   -> rust/target/ios-xcframework/MyotisEngine.xcframework
#
# NOTE for apps that already embed another Rust staticlib (e.g. another
# embedded node): two Rust staticlibs in one binary collide on the Rust
# runtime/allocator. Don't link this xcframework next to another one — build
# ONE aggregator staticlib crate that depends on both engines as rlibs and
# re-exports their C symbols, so there is a single compilation graph (one
# std/allocator/tokio/libp2p). This xcframework is for hosts where Myotis is
# the only Rust member.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/target/ios-xcframework"
hdrs="$out/headers"
framework="$out/MyotisEngine.xcframework"
libname=libmyotis_engine.a

DEVICE=aarch64-apple-ios
SIM_ARM=aarch64-apple-ios-sim
SIM_X86=x86_64-apple-ios

# Match the iOS host app's deployment target (ios-app/project.yml).
export IPHONEOS_DEPLOYMENT_TARGET=15.2

cd "$here"
echo "==> Building release staticlibs"
# crate-type in myotis-engine's Cargo.toml is cdylib+rlib (Android/JNI and
# in-workspace consumers); --crate-type staticlib overrides it for the iOS
# slices, which is the documented path (see the Cargo.toml comment).
for t in "$DEVICE" "$SIM_ARM" "$SIM_X86"; do
  echo "    - $t"
  cargo rustc -p myotis-engine --release --crate-type staticlib --target "$t"
done

echo "==> Staging header + modulemap"
rm -rf "$out"
mkdir -p "$hdrs" "$out/sim"
cp "$here/include/myotis_engine.h" "$hdrs/myotis_engine.h"
# One Clang module over the C header so Swift hosts `import MyotisEngine`.
# Linked frameworks are what the engine's networking stack pulls on Apple
# platforms: rustls keychain roots (Security), if-watch interface monitoring
# (SystemConfiguration), and CoreFoundation underneath both.
cat > "$hdrs/module.modulemap" <<'EOF'
module MyotisEngine {
    header "myotis_engine.h"
    link framework "Security"
    link framework "SystemConfiguration"
    link framework "CoreFoundation"
    export *
}
EOF

echo "==> lipo fat simulator slice"
lipo -create -output "$out/sim/$libname" \
  "$here/target/$SIM_ARM/release/$libname" \
  "$here/target/$SIM_X86/release/$libname"

echo "==> Assembling xcframework"
xcodebuild -create-xcframework \
  -library "$here/target/$DEVICE/release/$libname" -headers "$hdrs" \
  -library "$out/sim/$libname" -headers "$hdrs" \
  -output "$framework"

echo "==> Done: $framework"
