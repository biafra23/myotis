#!/usr/bin/env python3
"""Tests of scripts/check_pins_additive.py: what may change in the pins, and what may not.

    python3 scripts/test_check_pins_additive.py
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_pins_additive.py"
REPO = Path(__file__).resolve().parent.parent

HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">\n'
CONF = ('<configuration><verify-metadata>true</verify-metadata><verify-signatures>false</verify-signatures>'
        '<trusted-artifacts><trust file=".*-sources[.]jar" regex="true"/></trusted-artifacts></configuration>\n')


def component(group, name, version, files):
    arts = "".join(f'<artifact name="{f}"><sha256 value="{h}" origin="test"/></artifact>' for f, h in files.items())
    return f'<component group="{group}" name="{name}" version="{version}">{arts}</component>\n'


OLD_COMPS = component("g", "a", "1", {"a-1.jar": "11" * 32}) + component("g", "b", "2", {"b-2.jar": "22" * 32})


def doc(conf=CONF, comps=OLD_COMPS, after=""):
    return HEAD + conf + "<components>\n" + comps + "</components>\n" + after + "</verification-metadata>\n"


class Additive(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.old = Path(self.directory.name) / "old.xml"
        self.new = Path(self.directory.name) / "new.xml"
        self.old.write_text(doc())

    def check(self, new_text):
        self.new.write_text(new_text)
        done = subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.old), str(self.new)],
                              capture_output=True, text=True)
        return done.returncode, done.stdout + done.stderr

    def test_the_same_file_passes(self):
        self.assertEqual(self.check(doc())[0], 0)

    def test_a_new_pin_passes(self):
        code, out = self.check(doc(comps=OLD_COMPS + component("g", "c", "3", {"c-3.jar": "33" * 32})))
        self.assertEqual(code, 0, out)
        self.assertIn("1 new artifact pin(s)", out)

    def test_a_changed_hash_fails(self):
        code, out = self.check(doc(comps=OLD_COMPS.replace("11" * 32, "ff" * 32)))
        self.assertEqual(code, 1)
        self.assertIn("pinned artifact entry changed: g:a:1 a-1.jar", out)

    def test_an_also_trust_fails(self):
        widened = OLD_COMPS.replace('origin="test"/>', 'origin="test"><also-trust value="' + "ee" * 32 + '"/></sha256>', 1)
        code, out = self.check(doc(comps=widened))
        self.assertEqual(code, 1, out)
        self.assertIn("pinned artifact entry changed", out)

    def test_a_removed_pin_fails(self):
        self.assertEqual(self.check(doc(comps=component("g", "a", "1", {"a-1.jar": "11" * 32})))[0], 1)

    def test_a_loosened_configuration_fails(self):
        code, out = self.check(doc(conf=CONF.replace("<verify-metadata>true", "<verify-metadata>false")))
        self.assertEqual(code, 1)
        self.assertIn("the <configuration> block changed", out)

    # --- the shapes the comparison does not model

    def test_a_second_configuration_block_fails(self):
        extra = '<configuration><trusted-artifacts><trust group=".*" regex="true"/></trusted-artifacts></configuration>\n'
        code, out = self.check(doc(after=extra))
        self.assertEqual(code, 1, out)
        self.assertIn("not exactly one <configuration> and one <components>", out)

    def test_an_element_outside_the_namespace_fails(self):
        foreign = ('<component xmlns="urn:x" group="g" name="a" version="1"><artifact name="a-1.jar">'
                   '<sha256 value="' + "dd" * 32 + '"/></artifact></component>\n')
        code, out = self.check(doc(comps=OLD_COMPS + foreign))
        self.assertEqual(code, 1, out)
        self.assertIn("is not in the Gradle namespace", out)

    def test_a_nested_artifact_fails(self):
        nested = ('<component group="g" name="a" version="1"><wrapper><artifact name="a-1.jar">'
                  '<sha256 value="' + "dd" * 32 + '"/></artifact></wrapper></component>\n')
        code, out = self.check(doc(comps=OLD_COMPS + nested))
        self.assertEqual(code, 1, out)
        self.assertIn("<wrapper> in component g:a", out)

    def test_a_doctype_fails(self):
        text = doc().replace('<verification-metadata ', '<!DOCTYPE x [<!ENTITY e "x">]>\n<verification-metadata ', 1)
        code, out = self.check(text)
        self.assertEqual(code, 1, out)
        self.assertIn("DOCTYPE", out)

    def test_the_committed_metadata_has_the_shape_it_models(self):
        committed = REPO / "gradle/verification-metadata.xml"
        done = subprocess.run([sys.executable, "-I", str(SCRIPT), str(committed), str(committed)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
