#!/usr/bin/env python3
"""Tests of scripts/repro/compare.py: what fails a comparison, and what only reports.

    python3 scripts/repro/test_compare.py

The gate of reproducible-builds.yml is this script's DEFAULT: its three
a-against-b comparisons pass no --gate and no --report-only, so "everything
fails" must stay what no argument means. CLAUDE.md forbids loosening
compare.py to make a comparison green; these tests are what notices.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

COMPARE = Path(__file__).resolve().parent / "compare.py"


class Compare(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for leg in ("a", "b"):
            self.write(leg, "android/app.apk", "apk")
            self.write(leg, "desktop/app/lib.so", "lib")
            self.write(leg, "host/tool.dll", "dll")

    def write(self, leg, relative, text, mode=0o644):
        path = self.root / leg / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)

    def compare(self, *flags, known=None):
        """(exit code, output) of compare.py on the two legs, as the workflow calls it."""
        argv = [sys.executable, "-I", str(COMPARE), str(self.root / "a"), str(self.root / "b"),
                str(self.root / "report")]
        if known is not None:
            (self.root / "known.txt").write_text(known)
            argv.append(str(self.root / "known.txt"))
        # No diffoscope: it only explains a difference, and must not be needed for the verdict.
        environment = {**os.environ, "PATH": os.path.dirname(sys.executable)}
        done = subprocess.run(argv + list(flags), capture_output=True, text=True, env=environment)
        return done.returncode, done.stdout + done.stderr

    # --- no argument: everything is gated (the workflow's three a-against-b comparisons)

    def test_identical_trees_pass(self):
        code, output = self.compare()
        self.assertEqual(code, 0, output)
        self.assertIn("everything gated; 0 failing", output)
        self.assertIn("all artifacts are identical", output)

    def test_a_changed_byte_fails_wherever_it_is(self):
        for relative in ("android/app.apk", "desktop/app/lib.so", "host/tool.dll"):
            with self.subTest(file=relative):
                self.setUp()
                self.write("b", relative, "other")
                code, output = self.compare()
                self.assertEqual(code, 1, output)
                self.assertIn(f"DIFFERS    {relative}", output)

    def test_a_file_in_one_leg_only_fails(self):
        self.write("b", "desktop/extra.txt", "extra")
        code, output = self.compare()
        self.assertEqual(code, 1, output)
        self.assertIn("desktop/extra.txt", output)
        self.setUp()
        self.write("a", "desktop/only-in-a.txt", "extra")
        self.assertEqual(self.compare()[0], 1)

    def test_a_changed_mode_fails(self):
        self.write("b", "desktop/app/lib.so", "lib", mode=0o664)
        code, output = self.compare()
        self.assertEqual(code, 1, output)
        self.assertIn("DIFFERS    desktop/app/lib.so", output)

    def test_a_directory_mode_fails(self):
        (self.root / "b" / "desktop" / "app").chmod(0o775)
        (self.root / "a" / "desktop" / "app").chmod(0o755)
        code, output = self.compare()
        self.assertEqual(code, 1, output)
        self.assertIn("desktop/app/", output)

    def test_an_empty_directory_in_one_leg_only_fails(self):
        (self.root / "b" / "desktop" / "empty").mkdir()
        self.assertEqual(self.compare()[0], 1)

    # --- --report-only: the comparisons whose second side is not a second build of the same kind

    def test_report_only_lists_a_difference_and_passes(self):
        self.write("b", "host/tool.dll", "other")
        code, output = self.compare("--report-only")
        self.assertEqual(code, 0, output)
        self.assertIn("nothing gated (report only)", output)
        self.assertIn("DIFFERS    host/tool.dll  (not gated)", output)

    def test_an_empty_tree_is_a_failed_leg_under_any_gate(self):
        empty = self.root / "b"
        for path in sorted(empty.rglob("*"), reverse=True):
            path.rmdir() if path.is_dir() else path.unlink()
        for flags in ((), ("--report-only",), ("--gate", "android/*")):
            with self.subTest(flags=flags):
                code, output = self.compare(*flags)
                self.assertNotEqual(code, 0, output)
                self.assertIn("an empty tree", output)

    # --- --gate / --no-gate: a narrower gate, when one is asked for

    def test_gate_limits_what_fails_and_still_lists_the_rest(self):
        self.write("b", "desktop/app/lib.so", "other")
        code, output = self.compare("--gate", "android/*")
        self.assertEqual(code, 0, output)
        self.assertIn("DIFFERS    desktop/app/lib.so  (not gated)", output)
        self.write("b", "android/app.apk", "other")
        self.assertEqual(self.compare("--gate", "android/*")[0], 1)

    def test_no_gate_takes_paths_back_out(self):
        self.write("b", "host/tool.dll", "other")
        self.assertEqual(self.compare("--no-gate", "host/*")[0], 0)
        self.assertEqual(self.compare()[0], 1)

    # --- known differences

    def test_a_known_difference_does_not_fail_and_is_named_with_its_reason(self):
        self.write("b", "host/tool.dll", "other")
        code, output = self.compare(known="host/tool.dll\tthe linker stamps it\n")
        self.assertEqual(code, 0, output)
        self.assertIn("the linker stamps it", output)

    def test_the_committed_list_of_known_differences_is_empty(self):
        # A gated artifact that stopped reproducing must be fixed, not listed
        # (CLAUDE.md): an entry here is the owner's decision, and this test is
        # where adding one becomes visible in review.
        listed = [line for line in (COMPARE.parent / "known-differences.txt").read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(listed, [])


if __name__ == "__main__":
    unittest.main()
