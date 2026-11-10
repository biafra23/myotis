#!/usr/bin/env python3
"""Tests scripts/repro/compare_signed_apk.py on synthetic APKs (no apksigner needed).

    python3 scripts/repro/test_compare_signed_apk.py

`sign()` below lays a signed APK out the way apksigner does with
--alignment-preserved (checked against a real one, build-tools 37.0.0): the
input's entries untouched, the v1 signature entries after them, zero bytes up
to a 4096-byte boundary, the APK Signing Block, then the central directory
with the new records at its end. Each test then breaks one of those properties.
"""
import io
import os
import struct
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_signed_apk as c  # noqa: E402


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files:
            info = zipfile.ZipInfo(name, date_time=(1981, 1, 1, 1, 1, 2))
            z.writestr(info, data, zipfile.ZIP_DEFLATED if name.endswith(".xml") else zipfile.ZIP_STORED)
    return buf.getvalue()


def split(data):
    eocd = data.rfind(b"PK\x05\x06")
    total, cd_size, cd_offset = struct.unpack("<HII", data[eocd + 10:eocd + 20])
    return data[:cd_offset], data[cd_offset:eocd], data[eocd:], total


def sign(unsigned, added=(("META-INF/R.SF", b"sf"), ("META-INF/R.RSA", b"rsa"), ("META-INF/MANIFEST.MF", b"mf")),
         pad=True, block_payload=b"\x00" * 64):
    entries, cd, eocd, total = split(unsigned)
    # The added entries, as a zip of their own, re-based behind the unsigned entries.
    extra_entries, extra_cd, _, extra_total = split(zipped(added)) if added else (b"", b"", b"", 0)
    rebased, pos = b"", 0
    while pos < len(extra_cd):
        n, e, k = struct.unpack("<HHH", extra_cd[pos + 28:pos + 34])
        rec = bytearray(extra_cd[pos:pos + 46 + n + e + k])
        off, = struct.unpack("<I", rec[42:46])
        rec[42:46] = struct.pack("<I", off + len(entries))
        rebased += bytes(rec)
        pos += 46 + n + e + k
    body = entries + extra_entries
    if pad:
        body += b"\x00" * (-len(body) % 4096)
    size = len(block_payload) + 24
    block = struct.pack("<Q", size) + block_payload + struct.pack("<Q", size) + b"APK Sig Block 42"
    new_cd = cd + rebased
    new_eocd = bytearray(eocd)
    new_eocd[8:12] = struct.pack("<HH", total + extra_total, total + extra_total)
    new_eocd[12:20] = struct.pack("<II", len(new_cd), len(body) + len(block))
    return body + block + new_cd + bytes(new_eocd)


UNSIGNED = zipped([("AndroidManifest.xml", b"<manifest/>" * 50), ("classes.dex", os.urandom(5000)),
                   ("lib/arm64-v8a/libmyotis_engine.so", os.urandom(9000)), ("META-INF/versions/9/OSGI-INF/MANIFEST.MF", b"x")])


def verdict(signed, unsigned=UNSIGNED):
    try:
        return c.compare(signed, unsigned, "signed.apk", "unsigned.apk")
    except c.Mismatch as e:
        return str(e)


class CompareSignedApk(unittest.TestCase):
    def test_a_signed_apk_is_its_input_plus_a_signature(self):
        added, block, pad = verdict(sign(UNSIGNED))
        self.assertEqual(added, ["META-INF/R.SF", "META-INF/R.RSA", "META-INF/MANIFEST.MF"])
        self.assertEqual(block, 64 + 32)
        self.assertLess(pad, 4096)

    def test_a_v2_only_signature_adds_no_entries(self):
        self.assertEqual(verdict(sign(UNSIGNED, added=()))[0], [])

    def test_the_synthetic_apks_are_real_zips(self):
        with zipfile.ZipFile(io.BytesIO(sign(UNSIGNED))) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(z.read("META-INF/R.SF"), b"sf")

    def test_a_changed_entry_byte_fails(self):
        signed = bytearray(sign(UNSIGNED))
        signed[200] ^= 1
        self.assertIn("the entries differ: first at offset 200", verdict(bytes(signed)))

    def test_an_added_entry_that_is_not_a_signature_file_fails(self):
        signed = sign(UNSIGNED, added=(("META-INF/R.SF", b"sf"), ("assets/extra.bin", b"payload")))
        self.assertIn("not a signature file: assets/extra.bin", verdict(signed))

    def test_a_signature_named_file_in_a_subdirectory_is_not_a_signature_file(self):
        signed = sign(UNSIGNED, added=(("META-INF/services/X.SF", b"sf"),))
        self.assertIn("not a signature file", verdict(signed))

    def test_bytes_that_are_not_zero_padding_before_the_block_fail(self):
        signed = bytearray(sign(UNSIGNED))
        cd = struct.unpack("<I", signed[signed.rfind(b"PK\x05\x06") + 16:][:4])[0]
        block = cd - (64 + 32)
        signed[block - 3] = 0x41
        self.assertIn("not zero padding", verdict(bytes(signed)))

    def test_a_changed_central_directory_record_fails(self):
        signed = bytearray(sign(UNSIGNED))
        cd = struct.unpack("<I", signed[signed.rfind(b"PK\x05\x06") + 16:][:4])[0]
        signed[cd + 38] ^= 1  # the first record's external attributes
        self.assertIn("the central directory differs at record 0: AndroidManifest.xml", verdict(bytes(signed)))

    def test_a_dropped_entry_fails(self):
        smaller = zipped([("AndroidManifest.xml", b"<manifest/>" * 50)])
        self.assertIn("differ", verdict(sign(smaller)))

    def test_an_unsigned_apk_as_the_signed_one_fails(self):
        self.assertIn("no APK Signing Block", verdict(UNSIGNED))

    def test_a_signed_apk_as_the_unsigned_one_fails(self):
        signed = sign(UNSIGNED)
        self.assertIn("is not the unsigned APK", verdict(signed, signed))

    def test_a_changed_archive_comment_fails(self):
        signed = sign(UNSIGNED)
        signed = signed[:-2] + struct.pack("<H", 3) + b"hey"
        self.assertIn("comments differ", verdict(signed))

    def test_a_block_whose_sizes_disagree_fails(self):
        signed = bytearray(sign(UNSIGNED))
        cd = struct.unpack("<I", signed[signed.rfind(b"PK\x05\x06") + 16:][:4])[0]
        signed[cd - 24:cd - 16] = struct.pack("<Q", 40)
        self.assertIn("size fields disagree", verdict(bytes(signed)))


if __name__ == "__main__":
    unittest.main()
