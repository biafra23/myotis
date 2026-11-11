#!/usr/bin/env python3
"""Make an xcframework deterministic (#734, Part 5a).

    normalize_xcframework.py PATH.xcframework...

`xcodebuild -create-xcframework` (and the Kotlin plugin's XCFramework task,
which drives it) lists AvailableLibraries in no fixed order: the two legs of
reproducible-builds.yml wrote the device and simulator slices in opposite
orders. This sorts them by LibraryIdentifier, sorts each entry's
SupportedArchitectures, and writes the plist back as sorted-key XML. The
contents are unchanged, so Xcode reads the same xcframework.

And every static archive in it (a static framework's binary, a .a), thin or
universal: each member header's mtime, uid and gid are set to 0 and its mode
to 0644 (what Apple's libtool writes under ZERO_AR_DATE=1). The Kotlin/Native
link stamped them with the build time and the builder's umask. A universal
(fat) file, as `lipo -create` makes MyotisEngine's simulator slice, has each
of its slices normalized the same way. The headers are fixed-width, so this
rewrites them in place; member contents are untouched. A file that looks like
an archive and cannot be walked to its end is an ERROR, never skipped. Stdlib
only.
"""
import os
import plistlib
import struct
import sys


AR_MAGIC = b"!<arch>\n"
FAT_MAGIC = 0xCAFEBABE      # fat_header + fat_arch (32-bit offsets), big-endian
FAT_MAGIC_64 = 0xCAFEBABF   # fat_header + fat_arch_64 (64-bit offsets)


def normalize_ar(data, start, end, path):
    """Normalize the ar archive in data[start:end] in place; its member count."""
    i, n = start + 8, 0
    while i < end:
        if i + 60 > end and not data[i:end].strip(b"\n\0"):
            break  # trailing padding after the last member
        if i + 60 > end or data[i + 58:i + 60] != b"`\n":
            sys.exit(f"normalize_xcframework: {path}: a member header at offset {i} is not an ar header")
        size = int(data[i + 48:i + 58].decode().strip())
        data[i + 16:i + 28] = b"0".ljust(12)        # mtime
        data[i + 28:i + 34] = b"0".ljust(6)         # uid
        data[i + 34:i + 40] = b"0".ljust(6)         # gid
        data[i + 40:i + 48] = b"100644".ljust(8)    # mode
        i += 60 + size + (size & 1)
        n += 1
    return n


def slices(data, path):
    """(start, end) of each ar archive in a thin or universal file; [] if it is neither."""
    if data[:8] == AR_MAGIC:
        return [(0, len(data))]
    if len(data) < 8:
        return []
    magic, count = struct.unpack(">II", data[:8])
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return []
    wide = magic == FAT_MAGIC_64
    entry, fmt = (32, ">iiQQII") if wide else (20, ">iiIII")
    found = []
    for k in range(count):
        at = 8 + k * entry
        fields = struct.unpack(fmt, data[at:at + entry])
        offset, size = fields[2], fields[3]
        if offset + size > len(data):
            sys.exit(f"normalize_xcframework: {path}: slice {k} runs past the end of the file")
        if data[offset:offset + 8] != AR_MAGIC:
            # A universal file whose slices are not archives (a dylib, an
            # executable) has nothing of this kind to normalize.
            if found:
                sys.exit(f"normalize_xcframework: {path}: slice {k} is not a static archive, slice 0 is")
            return []
        found.append((offset, offset + size))
    return found


def normalize_archive(path):
    """Normalize a thin or universal static archive in place; its member count (0: not one)."""
    data = bytearray(open(path, "rb").read())
    parts = slices(data, path)
    if not parts:
        return 0
    n = sum(normalize_ar(data, start, end, path) for start, end in parts)
    with open(path, "wb") as f:
        f.write(data)
    return n


def main(paths):
    for xc in paths:
        archives = 0
        for dirpath, _, files in os.walk(xc):
            for name in files:
                p = os.path.join(dirpath, name)
                if not os.path.islink(p) and os.path.getsize(p) > 8 and normalize_archive(p):
                    archives += 1
        path = os.path.join(xc, "Info.plist")
        with open(path, "rb") as f:
            plist = plistlib.load(f)
        libs = plist.get("AvailableLibraries")
        if not isinstance(libs, list) or not libs:
            sys.exit(f"normalize_xcframework: no AvailableLibraries in {path}")
        for lib in libs:
            if isinstance(lib.get("SupportedArchitectures"), list):
                lib["SupportedArchitectures"] = sorted(lib["SupportedArchitectures"])
        plist["AvailableLibraries"] = sorted(libs, key=lambda lib: lib.get("LibraryIdentifier", ""))
        with open(path, "wb") as f:
            plistlib.dump(plist, f, fmt=plistlib.FMT_XML, sort_keys=True)
        print(f"normalize_xcframework: {xc}: {len(libs)} libraries in a fixed order, "
              f"{archives} static archive(s) normalized")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
