#!/usr/bin/env bash
# Cross-compile the workspace's Android cdylibs (myotis-bls today; myotis-engine once
# it grows a real JNI surface) for Android ABIs into the app's jniLibs, so
# NativeBlsBackend.isAvailable() is true on-device and the ~4-15x faster BLS verify
# kicks in. See docs/bls-rust-acceleration.md.
#
# One-time setup:
#   rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME=<sdk>/ndk/<version>   # r28+ recommended, e.g. 28.2.13676358
#
# Prefer NDK r28 or newer: it defaults to 16 KB-aligned LOAD segments (required by
# Android 15+ devices with 16 KB memory pages). On older NDKs .cargo/config.toml still
# forces the alignment via -Wl,-z,max-page-size=16384, and the check at the end of this
# script fails the build if anything slips through.
#
# Then: rust/build-android.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
jniLibs="$here/../android-app/src/main/jniLibs"

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your NDK path (e.g. \$ANDROID_SDK/ndk/27.0.11718014)}"

# arm64-v8a covers all modern phones; x86_64 covers the emulator. Add armeabi-v7a for
# very old 32-bit devices if you still target them.
cd "$here"
# Build from the workspace root so the workspace [profile.release] and
# .cargo/config.toml apply. Ships myotis-bls (native BLS) and myotis-engine
# (the Rust engine behind :myotis-engines' RustEngineNative). 16 KB-aligned
# LOAD segments (.cargo/config.toml passes -Wl,-z,max-page-size=16384) so the
# libs load on Android 15+ devices with 16 KB memory pages.
cargo ndk -t arm64-v8a -t x86_64 -o "$jniLibs" build --release -p myotis-bls -p myotis-engine

# cargo-ndk copies EVERY dynamic library the build graph produces, including
# hash-named dependency artifacts (e.g. libif_watch-<hash>.so) that
# libmyotis_engine.so does not link against (its only NEEDED entries are
# libc/libm/libdl). Keep jniLibs to exactly the libs we ship.
find "$jniLibs" -name '*.so' ! -name 'libmyotis_*.so' -delete

echo "built:"
find "$jniLibs" -name 'libmyotis_*.so' -exec ls -la {} \;

# Fail loudly if any PT_LOAD segment is <16 KB aligned — a 4 KB-aligned .so is
# rejected by the dynamic linker on 16 KB-page devices, and the symptom (BLS
# silently falling back to the slow JVM backend) is easy to miss. Guards against
# an NDK/flag regression silently shipping a misaligned lib.
echo "checking 16 KB alignment:"
python3 - "$jniLibs" <<'PY'
import struct, sys, glob, os
bad = []
# *.so, not libmyotis_*.so: anything that survives the prune above must at
# least pass the alignment gate rather than ship unchecked.
for f in glob.glob(os.path.join(sys.argv[1], "*", "*.so")):
    with open(f, "rb") as fh:
        d = fh.read()
    if d[:4] != b"\x7fELF":
        sys.exit(f"not an ELF file: {f}")
    end = "<" if d[5] == 1 else ">"
    # Handle both classes: arm64-v8a / x86_64 are ELF64, but armeabi-v7a (32-bit,
    # mentioned in the build comments) is ELF32 with different header offsets.
    if d[4] == 2:   # ELFCLASS64
        phoff = struct.unpack_from(end + "Q", d, 0x20)[0]
        phentsize = struct.unpack_from(end + "H", d, 0x36)[0]
        phnum = struct.unpack_from(end + "H", d, 0x38)[0]
        align_off, align_fmt = 0x30, end + "Q"   # p_align in Elf64_Phdr
    else:           # ELFCLASS32
        phoff = struct.unpack_from(end + "I", d, 0x1C)[0]
        phentsize = struct.unpack_from(end + "H", d, 0x2A)[0]
        phnum = struct.unpack_from(end + "H", d, 0x2C)[0]
        align_off, align_fmt = 0x1C, end + "I"     # p_align in Elf32_Phdr
    aligns = [struct.unpack_from(align_fmt, d, phoff + i * phentsize + align_off)[0]
              for i in range(phnum)
              if struct.unpack_from(end + "I", d, phoff + i * phentsize)[0] == 1]  # PT_LOAD
    ok = all(a >= 0x4000 for a in aligns)
    abi = os.path.basename(os.path.dirname(f))
    print(f"  {abi}: LOAD align {[hex(a) for a in aligns]} -> {'OK' if ok else 'NOT 16 KB'}")
    if not ok:
        bad.append(abi)
if bad:
    sys.exit(f"FAIL: not 16 KB aligned: {bad}. "
             "Ensure NDK is installed and .cargo/config.toml is in effect.")
print("  all 16 KB aligned")
PY
