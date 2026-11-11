#!/usr/bin/env python3
"""Tests of scripts/normalize_xcframework.py on made-up archives: thin, universal, broken.

    python3 scripts/test_normalize_xcframework.py
"""

import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "normalize_xcframework.py"


def member(name, body, mtime=1767225600, uid=501, gid=20, mode=0o100755):
    header = (name.ljust(16).encode() + str(mtime).ljust(12).encode() + str(uid).ljust(6).encode()
              + str(gid).ljust(6).encode() + oct(mode)[2:].ljust(8).encode() + str(len(body)).ljust(10).encode()
              + b"`\n")
    return header + body + (b"\n" if len(body) & 1 else b"")


def archive(*members):
    return b"!<arch>\n" + b"".join(members)


def fat(*slices):
    head = struct.pack(">II", 0xCAFEBABE, len(slices))
    offset = 4096
    entries, body = b"", b""
    for k, data in enumerate(slices):
        entries += struct.pack(">iiIII", 0x0100000C + k, 0, offset + len(body), len(data), 12)
        body += data + b"\0" * (-len(data) % 4096)
    return (head + entries).ljust(offset, b"\0") + body


def headers(data, start=0):
    """(mtime, uid, gid, mode) of every member of the ar archive at data[start:]."""
    out, i = [], start + 8
    while i + 60 <= len(data) and data[i + 58:i + 60] == b"`\n":
        size = int(data[i + 48:i + 58])
        out.append(tuple(data[i + a:i + b].decode().strip() for a, b in ((16, 28), (28, 34), (34, 40), (40, 48))))
        i += 60 + size + (size & 1)
    return out


class Normalize(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.xc = Path(self.directory.name) / "Test.xcframework"
        (self.xc / "ios-arm64").mkdir(parents=True)
        (self.xc / "sim").mkdir()
        with open(self.xc / "Info.plist", "wb") as f:
            plistlib.dump({"AvailableLibraries": [{"LibraryIdentifier": "sim"}, {"LibraryIdentifier": "ios-arm64"}]}, f)

    def run_script(self):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.xc)], capture_output=True, text=True)

    def test_a_thin_archive_is_normalized_and_its_contents_kept(self):
        path = self.xc / "ios-arm64" / "lib.a"
        path.write_bytes(archive(member("a.o", b"abc"), member("b.o", b"defg")))
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        data = path.read_bytes()
        self.assertEqual(headers(data), [("0", "0", "0", "100644")] * 2)
        self.assertIn(b"abc", data)
        self.assertIn(b"defg", data)
        self.assertIn("1 static archive(s) normalized", done.stdout)

    def test_every_slice_of_a_universal_archive_is_normalized(self):
        one, two = archive(member("x.o", b"x86")), archive(member("a.o", b"arm64"), member("b.o", b"more"))
        path = self.xc / "sim" / "lib.a"
        path.write_bytes(fat(one, two))
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        data = path.read_bytes()
        _, count = struct.unpack(">II", data[:8])
        for k in range(count):
            offset = struct.unpack(">iiIII", data[8 + 20 * k:28 + 20 * k])[2]
            with self.subTest(slice=k):
                self.assertTrue(headers(data, offset))
                self.assertEqual(set(headers(data, offset)), {("0", "0", "0", "100644")})
        self.assertIn("1 static archive(s) normalized", done.stdout)

    def test_two_builds_that_differ_only_in_stamps_come_out_identical(self):
        a = fat(archive(member("x.o", b"code", mtime=1)), archive(member("y.o", b"more", uid=0)))
        b = fat(archive(member("x.o", b"code", mtime=2)), archive(member("y.o", b"more", uid=1, mode=0o100775)))
        results = []
        for data in (a, b):
            (self.xc / "sim" / "lib.a").write_bytes(data)
            self.assertEqual(self.run_script().returncode, 0)
            results.append((self.xc / "sim" / "lib.a").read_bytes())
        self.assertEqual(results[0], results[1])

    def test_trailing_padding_after_the_last_member_is_accepted(self):
        path = self.xc / "ios-arm64" / "lib.a"
        path.write_bytes(archive(member("a.o", b"abcd")) + b"\n\0\0\0")
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(headers(path.read_bytes()), [("0", "0", "0", "100644")])

    def test_a_broken_archive_fails_instead_of_being_skipped(self):
        broken = archive(member("a.o", b"abc"))[:-6] + b"garbage-not-a-header-" * 4
        (self.xc / "ios-arm64" / "lib.a").write_bytes(broken)
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("is not an ar header", done.stderr)

    def test_a_universal_file_of_other_things_is_left_alone(self):
        dylib = fat(b"\xcf\xfa\xed\xfe" + b"\0" * 60)
        path = self.xc / "sim" / "Thing"
        path.write_bytes(dylib)
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(path.read_bytes(), dylib)
        self.assertIn("0 static archive(s) normalized", done.stdout)

    def test_the_plist_is_sorted(self):
        self.assertEqual(self.run_script().returncode, 0)
        with open(self.xc / "Info.plist", "rb") as f:
            libs = plistlib.load(f)["AvailableLibraries"]
        self.assertEqual([lib["LibraryIdentifier"] for lib in libs], ["ios-arm64", "sim"])


if __name__ == "__main__":
    unittest.main()
