#!/usr/bin/env python3
"""Fail if an Android native library has a PT_LOAD segment below 16 KB alignment.

    check_16k_alignment.py PATH...

Each PATH is a directory (every *.so below it is checked, e.g. a jniLibs tree)
or an .apk / .aar (its lib/<abi>/*.so or jni/<abi>/*.so entries, i.e. the
libraries that actually ship). A 4 KB-aligned .so is rejected by the dynamic
linker on Android 15+ devices with 16 KB pages, and the symptom (the Rust
engine or BLS quietly falling back to the JVM) is easy to miss. The alignment
comes from rust/.cargo/config.toml's -Wl,-z,max-page-size=16384 and the
pinned NDK's default; since #734 Part 4b the flag reaches the linker through a
MERGE of per-target rustflags (a RUSTFLAGS would drop it), so this check pins
that merge on every build that ships the libs, not only rust/build-android.sh.

Fail-closed: a PATH with no .so at all is an error, never a vacuous pass.
Stdlib only.
"""
import os
import struct
import sys
import zipfile

PT_LOAD = 1
MIN_ALIGN = 0x4000


def load_aligns(name, d):
    if d[:4] != b"\x7fELF":
        sys.exit(f"check_16k_alignment: not an ELF file: {name}")
    end = "<" if d[5] == 1 else ">"
    if d[4] == 2:  # ELFCLASS64 (arm64-v8a, x86_64)
        phoff = struct.unpack_from(end + "Q", d, 0x20)[0]
        phentsize = struct.unpack_from(end + "H", d, 0x36)[0]
        phnum = struct.unpack_from(end + "H", d, 0x38)[0]
        align_off, align_fmt = 0x30, end + "Q"
    else:  # ELFCLASS32 (armeabi-v7a)
        phoff = struct.unpack_from(end + "I", d, 0x1C)[0]
        phentsize = struct.unpack_from(end + "H", d, 0x2A)[0]
        phnum = struct.unpack_from(end + "H", d, 0x2C)[0]
        align_off, align_fmt = 0x1C, end + "I"
    return [struct.unpack_from(align_fmt, d, phoff + i * phentsize + align_off)[0]
            for i in range(phnum)
            if struct.unpack_from(end + "I", d, phoff + i * phentsize)[0] == PT_LOAD]


def libraries(path):
    """Yield (display name, bytes) for every .so under PATH."""
    if os.path.isdir(path):
        for root, _, files in sorted(os.walk(path)):
            for f in sorted(files):
                if f.endswith(".so"):
                    p = os.path.join(root, f)
                    with open(p, "rb") as fh:
                        yield os.path.relpath(p, path), fh.read()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for n in sorted(z.namelist()):
                if n.endswith(".so") and (n.startswith("lib/") or n.startswith("jni/")):
                    yield n, z.read(n)
    else:
        sys.exit(f"check_16k_alignment: {path} is neither a directory nor an apk/aar")


def main(paths):
    bad = []
    for path in paths:
        seen = 0
        for name, data in libraries(path):
            seen += 1
            aligns = load_aligns(name, data)
            ok = bool(aligns) and all(a >= MIN_ALIGN for a in aligns)
            print(f"  {path}: {name}: LOAD align {[hex(a) for a in aligns]} -> {'OK' if ok else 'NOT 16 KB'}")
            if not ok:
                bad.append(f"{path}:{name}")
        if not seen:
            # An empty jniLibs or an APK without libs is a broken build, not a pass.
            sys.exit(f"check_16k_alignment: FAIL: no .so found in {path}")
    if bad:
        sys.exit("check_16k_alignment: FAIL: not 16 KB aligned: " + ", ".join(bad)
                 + ". Check the pinned NDK and that rust/.cargo/config.toml's per-target"
                   " rustflags reached the linker (a RUSTFLAGS replaces them).")
    print("  all 16 KB aligned")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
