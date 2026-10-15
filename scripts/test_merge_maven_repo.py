#!/usr/bin/env python3
"""Regression tests for scripts/merge_maven_repo.py's version ordering — Maven's
ComparableVersion order for the suffix shapes the release guard accepts.
Run: python3 scripts/test_merge_maven_repo.py"""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    "merge_maven_repo", pathlib.Path(__file__).with_name("merge_maven_repo.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
version_key = mod.version_key


def ordered(*versions):
    return sorted(versions, key=version_key)


class VersionOrderTest(unittest.TestCase):
    def test_pre_release_below_release_sp_above_unknown_highest(self):
        self.assertEqual(
            ordered("0.1.16-hotfix1", "0.1.16-sp1", "0.1.16", "0.1.16-rc1", "0.1.16-beta2",
                    "0.1.16-alpha1", "0.1.16-milestone1", "0.1.16-SNAPSHOT"),
            ["0.1.16-alpha1", "0.1.16-beta2", "0.1.16-milestone1", "0.1.16-rc1",
             "0.1.16-SNAPSHOT", "0.1.16", "0.1.16-sp1", "0.1.16-hotfix1"])

    def test_qualifier_numbers_compare_numerically(self):
        self.assertEqual(ordered("0.1.16-rc10", "0.1.16-rc9", "0.1.16-rc1"),
                         ["0.1.16-rc1", "0.1.16-rc9", "0.1.16-rc10"])

    def test_aliases_fold_as_maven_does(self):
        self.assertEqual(version_key("0.1.16-cr10"), version_key("0.1.16-rc10"))
        self.assertLess(version_key("0.1.16-rc9"), version_key("0.1.16-cr10"))
        self.assertEqual(version_key("0.1.16-ga")[:2], version_key("0.1.16")[:2])
        self.assertEqual(ordered("0.1.16-a1", "0.1.16-b1", "0.1.16-m1"),
                         ["0.1.16-a1", "0.1.16-b1", "0.1.16-m1"])

    def test_unknown_qualifiers_lexical_among_themselves_and_above_sp(self):
        self.assertEqual(ordered("0.1.16-zeta", "0.1.16-sp2", "0.1.16-hotfix3", "0.1.16-patch1"),
                         ["0.1.16-sp2", "0.1.16-hotfix3", "0.1.16-patch1", "0.1.16-zeta"])

    def test_numeric_core_dominates(self):
        self.assertEqual(ordered("0.2.0-alpha1", "0.1.16-hotfix9", "0.1.9", "0.1.16"),
                         ["0.1.9", "0.1.16", "0.1.16-hotfix9", "0.2.0-alpha1"])

    def test_latest_and_release_never_move_backwards(self):
        # Publishing an older hotfix after a newer release keeps the pointers.
        self.assertGreater(version_key("0.1.17"), version_key("0.1.16-hotfix1"))
        self.assertGreater(version_key("0.1.16-sp1"), version_key("0.1.16"))


if __name__ == "__main__":
    unittest.main()
