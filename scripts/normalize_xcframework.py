#!/usr/bin/env python3
"""Make an xcframework deterministic (#734, Part 5a).

    normalize_xcframework.py PATH.xcframework...

`xcodebuild -create-xcframework` (and the Kotlin plugin's XCFramework task,
which drives it) lists AvailableLibraries in no fixed order: the two legs of
reproducible-builds.yml wrote the device and simulator slices in opposite
orders. This sorts them by LibraryIdentifier, sorts each entry's
SupportedArchitectures, and writes the plist back as sorted-key XML. The
contents are unchanged, so Xcode reads the same xcframework.

And every static archive in it (a static framework's binary, a .a): each
member header's mtime is set to 0 and its mode to 0644 (what Apple's libtool
writes under ZERO_AR_DATE=1). The Kotlin/Native link stamped them with the
build time and the builder's umask. The headers are fixed-width, so this
rewrites them in place; member contents are untouched. Stdlib only.
"""
import os
import plistlib
import sys


AR_MAGIC = b"!<arch>\n"


def normalize_archive(path):
    data = bytearray(open(path, "rb").read())
    if data[:8] != AR_MAGIC:
        return 0
    i, n = 8, 0
    while i + 60 <= len(data):
        size = int(data[i + 48:i + 58].decode().strip())
        data[i + 16:i + 28] = b"0".ljust(12)        # mtime
        data[i + 28:i + 34] = b"0".ljust(6)         # uid
        data[i + 34:i + 40] = b"0".ljust(6)         # gid
        data[i + 40:i + 48] = b"100644".ljust(8)    # mode
        i += 60 + size + (size & 1)
        n += 1
    with open(path, "wb") as f:
        f.write(data)
    return n


def main(paths):
    for xc in paths:
        archives = 0
        for dirpath, _, files in os.walk(xc):
            for name in files:
                p = os.path.join(dirpath, name)
                if not os.path.islink(p) and os.path.getsize(p) > 8:
                    with open(p, "rb") as f:
                        if f.read(8) == AR_MAGIC:
                            normalize_archive(p)
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
