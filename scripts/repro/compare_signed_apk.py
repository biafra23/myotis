#!/usr/bin/env python3
"""Check that a signed APK is an unsigned APK plus its signature, and nothing else.

    compare_signed_apk.py SIGNED.apk UNSIGNED.apk

A release APK is built unsigned and signed in a job of its own (android-apk.yml,
sign-release). The unsigned file is what a rebuild reproduces bit for bit
(docs/guides/reproducible-builds.md); this script ties the signed file, which
is what people install, to it. apksigner, run with `--alignment-preserved
true`, leaves every zip entry of its input where it was and ADDS:

  - the v1 (JAR) signature files, META-INF/<signer>.SF, .RSA and MANIFEST.MF,
    as zip entries after the last existing one;
  - the APK Signing Block (the v2/v3 signature), between the entries and the
    central directory;
  - those files' records at the end of the central directory, and the new
    counts and offsets in the end record.

So the signed APK must be, in this order and with nothing in between:

  1. the unsigned APK's entries, byte for byte, at the same offsets;
  2. zip entries that are signature files and nothing else, then zero bytes
     up to the next 4096-byte boundary (where apksigner starts the block);
  3. one APK Signing Block;
  4. the unsigned APK's central directory records, byte for byte and in the
     same order, then the records of the entries in 2;
  5. an end record that differs from the unsigned one only in what 2 and 3
     move (the counts, the directory's size and its offset).

Exit 0 when all of that holds, 1 with the first thing that does not. It
refuses what it does not understand instead of guessing (zip64, an unsigned
input that already has a signing block). The release job runs it on every tag,
so a published signed APK always matches its published unsigned twin.

An independent tool for the same question is apksigcopier (`apksigcopier
compare SIGNED.apk --unsigned UNSIGNED.apk`), which F-Droid's verification
uses. Stdlib only.
"""
import re
import struct
import sys

EOCD = b"PK\x05\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
CD_ENTRY = b"PK\x01\x02"
LOCAL = b"PK\x03\x04"
SIG_BLOCK_MAGIC = b"APK Sig Block 42"
# The names apksigner may add: the JAR manifest and one signer's .SF plus its
# signature block file.
SIGNATURE_FILE = re.compile(r"^META-INF/(MANIFEST\.MF|[^/]+\.(SF|RSA|DSA|EC))$")


class Mismatch(Exception):
    pass


def parse(data, name):
    """The zip's end record and central directory records."""
    eocd = data.rfind(EOCD, max(0, len(data) - 22 - 0xFFFF))
    if eocd < 0 or eocd + 22 > len(data):
        raise Mismatch(f"{name}: no zip end-of-central-directory record")
    disk, cd_disk, here, total, cd_size, cd_offset, comment_len = struct.unpack("<HHHHIIH", data[eocd + 4:eocd + 22])
    if eocd + 22 + comment_len != len(data):
        raise Mismatch(f"{name}: bytes after the end record that its comment length does not cover")
    if cd_offset == 0xFFFFFFFF or total == 0xFFFF or data[max(0, eocd - 20):max(0, eocd - 16)] == ZIP64_LOCATOR:
        raise Mismatch(f"{name}: zip64 archives are not supported")
    if disk or cd_disk or here != total:
        raise Mismatch(f"{name}: a multi-disk archive")
    if cd_offset + cd_size != eocd:
        raise Mismatch(f"{name}: the central directory does not end at the end record")
    records, pos = [], cd_offset
    while pos < eocd:
        if data[pos:pos + 4] != CD_ENTRY:
            raise Mismatch(f"{name}: malformed central directory at offset {pos}")
        flags, = struct.unpack("<H", data[pos + 8:pos + 10])
        csize, = struct.unpack("<I", data[pos + 20:pos + 24])
        n, e, c = struct.unpack("<HHH", data[pos + 28:pos + 34])
        offset, = struct.unpack("<I", data[pos + 42:pos + 46])
        end = pos + 46 + n + e + c
        records.append({"name": data[pos + 46:pos + 46 + n].decode("utf-8", "replace"), "raw": data[pos:end],
                        "offset": offset, "csize": csize, "flags": flags})
        pos = end
    if len(records) != total:
        raise Mismatch(f"{name}: the end record counts {total} entries, the central directory has {len(records)}")
    return {"eocd": eocd, "cd_offset": cd_offset, "records": records, "comment": data[eocd + 20:]}


def local_end(data, record, name):
    """Where the entry's local header, name, extra field, data and data descriptor end."""
    o = record["offset"]
    if data[o:o + 4] != LOCAL:
        raise Mismatch(f"{name}: no local header for {record['name']} at offset {o}")
    n, e = struct.unpack("<HH", data[o + 26:o + 30])
    end = o + 30 + n + e + record["csize"]
    if record["flags"] & 0x08:  # a data descriptor follows, with or without its optional signature
        end += 16 if data[end:end + 4] == b"PK\x07\x08" else 12
    return end


def compare(signed, unsigned, signed_name, unsigned_name):
    u = parse(unsigned, unsigned_name)
    s = parse(signed, signed_name)
    if unsigned[max(0, u["cd_offset"] - 16):u["cd_offset"]] == SIG_BLOCK_MAGIC:
        raise Mismatch(f"{unsigned_name}: has an APK Signing Block itself, so it is not the unsigned APK")

    # 1. the unsigned APK's entries, in place
    entries_end = u["cd_offset"]
    if signed[:entries_end] != unsigned[:entries_end]:
        first = next(i for i in range(min(entries_end, len(signed))) if signed[i] != unsigned[i]) \
            if len(signed) >= entries_end else len(signed)
        raise Mismatch(f"the entries differ: first at offset {first} (of {entries_end})")

    # 3. one signing block, right before the signed APK's central directory
    cd = s["cd_offset"]
    if cd < entries_end + 32 or signed[cd - 16:cd] != SIG_BLOCK_MAGIC:
        raise Mismatch(f"{signed_name}: no APK Signing Block before the central directory (not signed with v2/v3?)")
    size, = struct.unpack("<Q", signed[cd - 24:cd - 16])
    block = cd - size - 8
    if block < entries_end or struct.unpack("<Q", signed[block:block + 8])[0] != size:
        raise Mismatch(f"{signed_name}: the APK Signing Block's two size fields disagree, or it overlaps the entries")

    # 4. the same central directory records, then the added ones
    nu = len(u["records"])
    if [r["raw"] for r in s["records"][:nu]] != [r["raw"] for r in u["records"]]:
        i = next((i for i, (a, b) in enumerate(zip(s["records"], u["records"])) if a["raw"] != b["raw"]), nu)
        which = u["records"][i]["name"] if i < nu else "(fewer records than the unsigned APK)"
        raise Mismatch(f"the central directory differs at record {i}: {which}")
    added = s["records"][nu:]
    for r in added:
        if not SIGNATURE_FILE.match(r["name"]):
            raise Mismatch(f"{signed_name} has an entry the unsigned APK lacks that is not a signature file: {r['name']}")

    # 2. the added entries, and only they, between the unsigned entries and the block
    pos = entries_end
    for r in sorted(added, key=lambda r: r["offset"]):
        if r["offset"] != pos:
            raise Mismatch(f"{signed_name}: {pos - entries_end} bytes into the added entries, {r['offset'] - pos} "
                           f"bytes that belong to no entry (before {r['name']})")
        pos = local_end(signed, r, signed_name)
    # apksigner starts the signing block on a 4096-byte boundary (what fs-verity
    # hashes by), filling up to it with zero bytes.
    pad = signed[pos:block]
    if pos > block or len(pad) >= 4096 or pad != bytes(len(pad)) or (pad and block % 4096):
        raise Mismatch(f"{signed_name}: {block - pos} bytes between the last added entry and the signing block "
                       "that are not zero padding up to a 4096-byte boundary")

    # 5. the end record: same comment (the counts and offsets follow from the above)
    if s["comment"] != u["comment"]:
        raise Mismatch("the end records' comments differ")
    return [r["name"] for r in added], cd - block, len(pad)


def main(argv):
    if len(argv) != 3 or argv[1].startswith("-"):
        sys.exit(__doc__)
    signed_name, unsigned_name = argv[1], argv[2]
    with open(signed_name, "rb") as f:
        signed = f.read()
    with open(unsigned_name, "rb") as f:
        unsigned = f.read()
    try:
        added, block, pad = compare(signed, unsigned, signed_name, unsigned_name)
    except Mismatch as e:
        print(f"compare_signed_apk.py: {signed_name} is NOT {unsigned_name} plus a signature: {e}", file=sys.stderr)
        return 1
    files = ", ".join(added) if added else "no v1 signature files"
    print(f"{signed_name} is {unsigned_name} plus a signature and nothing else: "
          f"{files}; {pad} bytes of zero padding; a {block}-byte APK Signing Block")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
