#!/usr/bin/env python3
"""Tests of scripts/sbom.py: the parsers and refusals on made-up inputs, then the real tree.

    python3 scripts/test_sbom.py
"""

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sbom  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

METADATA_HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                 '<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">\n'
                 '<components>\n')


def metadata(components):
    """components: {(group, name, version): {file: sha256}}."""
    out = [METADATA_HEAD]
    for (group, name, version), files in components.items():
        out.append(f'<component group="{group}" name="{name}" version="{version}">\n')
        for file, digest in files.items():
            out.append(f'<artifact name="{file}"><sha256 value="{digest}" origin="test"/></artifact>\n')
        out.append('</component>\n')
    out.append('</components>\n</verification-metadata>\n')
    return "".join(out)


def sha(char):
    return char * 64


class Tree:
    """A made-up repository with one Gradle project and one Cargo workspace."""

    LOCK = ("# This is a Gradle generated file for dependency locking.\n"
            "g.one:lib:1.0=compileClasspath,runtimeClasspath\n"
            "g.one:android-lib:2.0=runtimeClasspath\n"
            "g.one:root:3.0=runtimeClasspath\n"
            "g.one:variants:4.0=runtimeClasspath\n"
            "g.ui:ui-core:5.0=runtimeClasspath\n"
            "g.test:only-tests:9.0=testRuntimeClasspath\n"
            "empty=annotationProcessor,nothingHere\n")
    PINNED = {
        ("g.one", "lib", "1.0"): {"lib-1.0.jar": sha("a"), "lib-1.0.pom": sha("0")},
        ("g.one", "android-lib", "2.0"): {"android-lib-2.0.aar": sha("b"), "android-lib-2.0.module": sha("0")},
        ("g.one", "root", "3.0"): {"root-3.0.module": sha("0")},
        ("g.one", "variants", "4.0"): {"variants-4.0.jar": sha("c"), "variants-4.0-linux.jar": sha("d")},
        ("g.ui", "ui-core", "5.0"): {"ui-core-5.0.jar": sha("e")},
        ("g.ui", "ui-host-linux-x64", "5.0"): {"ui-host-linux-x64-5.0.jar": sha("f")},
        ("g.ui", "ui-host-macos-arm64", "5.0"): {"ui-host-macos-arm64-5.0.jar": sha("1")},
        ("g.ui", "ui-host-macos-arm64", "4.9"): {"ui-host-macos-arm64-4.9.jar": sha("2")},
        ("g.test", "only-tests", "9.0"): {"only-tests-9.0.jar": sha("3")},
    }
    CARGO = '''
version = 4

[[package]]
name = "ours"
version = "0.1.0"
dependencies = ["helper", "dup 1.0.0", "from-git"]

[[package]]
name = "helper"
version = "0.1.0"
dependencies = ["leaf", "dup 2.0.0"]

[[package]]
name = "leaf"
version = "0.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + sha("4") + '''"

[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + sha("5") + '''"

[[package]]
name = "dup"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + sha("6") + '''"

[[package]]
name = "from-git"
version = "0.9.0"
source = "git+https://example.org/x.git?rev=abc#abcdef"

[[package]]
name = "unreachable"
version = "7.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + sha("7") + '''"

[[package]]
name = "other-tool"
version = "0.1.0"
dependencies = ["unreachable"]
'''
    PRODUCTS = {
        "app": {
            "name": "The app", "description": "made up",
            "gradle": [("proj", ["runtimeClasspath"])],
            "cargo": [("rust/Cargo.lock", ["ours"])],
            "hosts": ["linux-x64", "macos-arm64"], "jdk": True,
        },
        "native": {
            "name": "The addon", "description": "made up",
            "gradle": [], "cargo": [("rust/Cargo.lock", ["ours"])],
        },
    }
    HOST_MODULES = [("g.ui", "ui-host-", "g.ui:ui-core")]

    def __init__(self, directory):
        self.root = Path(directory)
        self.write("build.gradle.kts", 'allprojects {\n    version = "1.2.3-SNAPSHOT"\n}\n')
        self.write(".java-version", "21.0.13\n")
        self.write("rust/rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n')
        self.write("proj/gradle.lockfile", self.LOCK)
        self.write("gradle/verification-metadata.xml", metadata(self.PINNED))
        self.write("rust/Cargo.lock", self.CARGO)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class MadeUp(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tree = Tree(self.directory.name)
        for name in ("PRODUCTS", "HOST_MODULES"):
            patcher = mock.patch.object(sbom, name, getattr(Tree, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def build(self, key="app", **kwargs):
        return sbom.build(self.tree.root, key, "1.2.3", **kwargs)

    def components(self, key="app"):
        return {c["bom-ref"]: c for c in self.build(key)["components"]}

    @staticmethod
    def properties(component):
        return [(p["name"], p["value"]) for p in component["properties"]]

    # --- Gradle

    def test_lockfile_configurations_and_empty_ones(self):
        locked = sbom.read_lockfile(self.tree.root / "proj/gradle.lockfile")
        self.assertEqual(locked["compileClasspath"], {("g.one", "lib", "1.0")})
        self.assertEqual(len(locked["runtimeClasspath"]), 5)
        self.assertEqual(locked["nothingHere"], set())

    def test_a_line_that_is_not_a_lock_line_is_refused(self):
        self.tree.write("proj/gradle.lockfile", "g.one:lib=runtimeClasspath\n")
        with self.assertRaisesRegex(sbom.SbomError, "not group:name:version"):
            self.build()

    def test_only_the_named_configuration_is_listed(self):
        refs = self.components()
        self.assertIn("pkg:maven/g.one/lib@1.0", refs)
        self.assertNotIn("pkg:maven/g.test/only-tests@9.0", refs)

    def test_one_payload_file_is_the_component(self):
        lib = self.components()["pkg:maven/g.one/lib@1.0"]
        self.assertEqual(lib["hashes"], [{"alg": "SHA-256", "content": sha("a")}])
        self.assertEqual(lib["purl"], "pkg:maven/g.one/lib@1.0")
        self.assertEqual((lib["group"], lib["name"], lib["version"]), ("g.one", "lib", "1.0"))
        self.assertIn(("myotis:pinned-by", "proj/gradle.lockfile#runtimeClasspath"), self.properties(lib))

    def test_an_aar_says_so_in_its_purl(self):
        aar = self.components()["pkg:maven/g.one/android-lib@2.0"]
        self.assertEqual(aar["purl"], "pkg:maven/g.one/android-lib@2.0?type=aar")
        self.assertEqual(aar["hashes"][0]["content"], sha("b"))

    def test_a_metadata_only_module_has_no_hash(self):
        root = self.components()["pkg:maven/g.one/root@3.0"]
        self.assertNotIn("hashes", root)
        self.assertEqual([n for n, _ in self.properties(root)], ["myotis:pinned-by"])

    def test_several_payload_files_are_each_named(self):
        variants = self.components()["pkg:maven/g.one/variants@4.0"]
        self.assertNotIn("hashes", variants)
        self.assertIn(("myotis:pinned-file:sha256:variants-4.0-linux.jar", sha("d")), self.properties(variants))
        self.assertIn(("myotis:pinned-file:sha256:variants-4.0.jar", sha("c")), self.properties(variants))

    def test_a_build_only_module_is_left_out_and_the_document_says_so(self):
        with mock.patch.dict(sbom.PRODUCTS["app"], {"build_only": {"g.one:root": "read by the build"}}):
            document = self.build()
        self.assertNotIn("pkg:maven/g.one/root@3.0", [c["bom-ref"] for c in document["components"]])
        self.assertIn({"name": "myotis:sbom:left-out", "value": "g.one:root: read by the build"},
                      document["metadata"]["properties"])

    def test_a_build_only_module_that_is_not_locked_is_an_error(self):
        with mock.patch.dict(sbom.PRODUCTS["app"], {"build_only": {"g.one:gone": "why"}}):
            with self.assertRaisesRegex(sbom.SbomError, "leaves out g.one:gone as build-only, and locks no such"):
                self.build()

    def test_a_configuration_that_is_gone_is_an_error_not_an_empty_list(self):
        self.tree.write("proj/gradle.lockfile", "g.one:lib:1.0=compileClasspath\n")
        with self.assertRaisesRegex(sbom.SbomError, "no lock state for the configuration 'runtimeClasspath'"):
            self.build()

    def test_a_locked_module_the_metadata_does_not_pin_is_an_error(self):
        pinned = dict(Tree.PINNED)
        del pinned[("g.one", "lib", "1.0")]
        self.tree.write("gradle/verification-metadata.xml", metadata(pinned))
        with self.assertRaisesRegex(sbom.SbomError, "g.one:lib:1.0 is locked .* pins no file"):
            self.build()

    def test_host_modules_of_every_host_at_the_locked_version(self):
        refs = self.components()
        linux = refs["pkg:maven/g.ui/ui-host-linux-x64@5.0"]
        self.assertIn(("myotis:host", "linux-x64"), self.properties(linux))
        self.assertIn(("myotis:pinned-by", "gradle/verification-metadata.xml"), self.properties(linux))
        self.assertIn("pkg:maven/g.ui/ui-host-macos-arm64@5.0", refs)
        self.assertNotIn("pkg:maven/g.ui/ui-host-macos-arm64@4.9", refs)

    def test_a_host_the_product_is_built_for_and_nothing_pins_is_an_error(self):
        pinned = {k: v for k, v in Tree.PINNED.items() if k != ("g.ui", "ui-host-macos-arm64", "5.0")}
        self.tree.write("gradle/verification-metadata.xml", metadata(pinned))
        with self.assertRaisesRegex(sbom.SbomError, "is built for macos-arm64, and .* pins no g.ui:ui-host-macos-arm64:5.0"):
            self.build()

    def test_a_pinned_host_the_product_does_not_state_is_an_error(self):
        pinned = {**Tree.PINNED, ("g.ui", "ui-host-macos-x64", "5.0"): {"ui-host-macos-x64-5.0.jar": sha("9")}}
        self.tree.write("gradle/verification-metadata.xml", metadata(pinned))
        with self.assertRaisesRegex(sbom.SbomError, "pins g.ui:ui-host-macos-x64:5.0, and macos-x64 is not among"):
            self.build()

    def test_the_document_says_which_hosts(self):
        self.assertIn({"name": "myotis:sbom:hosts", "value": "with the per-host modules of: linux-x64, macos-arm64"},
                      self.build()["metadata"]["properties"])

    def test_host_modules_need_one_version_of_the_module_they_follow(self):
        self.tree.write("proj/gradle.lockfile", Tree.LOCK + "g.ui:ui-core:4.9=otherRuntime\n")
        self.tree.write("gradle/verification-metadata.xml",
                        metadata({**Tree.PINNED, ("g.ui", "ui-core", "4.9"): {"ui-core-4.9.jar": sha("8")}}))
        both = {"gradle": [("proj", ["runtimeClasspath", "otherRuntime"])]}
        with mock.patch.dict(sbom.PRODUCTS["app"], both):
            with self.assertRaisesRegex(sbom.SbomError, "locks that at 4.9, 5.0: one version is needed"):
                self.build()

    def test_a_product_without_host_modules_gets_none(self):
        self.assertFalse([r for r in self.components("native") if "ui-host" in r])

    # --- Cargo

    def test_crates_reachable_from_the_products_crates(self):
        refs = self.components()
        self.assertEqual(refs["pkg:cargo/leaf@0.3.0"]["hashes"], [{"alg": "SHA-256", "content": sha("4")}])
        self.assertIn(("myotis:pinned-by", "rust/Cargo.lock"), self.properties(refs["pkg:cargo/leaf@0.3.0"]))
        self.assertNotIn("pkg:cargo/unreachable@7.0.0", refs)

    def test_two_versions_of_one_crate_are_two_components(self):
        refs = self.components()
        self.assertEqual(refs["pkg:cargo/dup@1.0.0"]["hashes"][0]["content"], sha("5"))
        self.assertEqual(refs["pkg:cargo/dup@2.0.0"]["hashes"][0]["content"], sha("6"))

    def test_the_workspaces_own_crates_are_the_product_not_components(self):
        self.assertFalse([r for r in self.components() if "ours" in r or "helper" in r])

    def test_a_git_source_is_part_of_the_identity_and_has_no_checksum(self):
        ref = "pkg:cargo/from-git@0.9.0?vcs_url=git%2Bhttps%3A%2F%2Fexample.org%2Fx.git%3Frev%3Dabc%23abcdef"
        git = self.components()[ref]
        self.assertNotIn("hashes", git)
        self.assertIn(("myotis:cargo:source", "git+https://example.org/x.git?rev=abc#abcdef"), self.properties(git))

    def test_a_crate_two_lockfiles_pin_is_one_component_pinned_by_both(self):
        self.tree.write("other/Cargo.lock", Tree.CARGO)
        two = {"cargo": [("rust/Cargo.lock", ["ours"]), ("other/Cargo.lock", ["ours"])]}
        with mock.patch.dict(sbom.PRODUCTS["native"], two):
            leaf = self.components("native")["pkg:cargo/leaf@0.3.0"]
        self.assertEqual([v for n, v in self.properties(leaf) if n == "myotis:pinned-by"],
                         ["other/Cargo.lock", "rust/Cargo.lock"])

    def test_one_name_and_version_with_two_checksums_is_an_error(self):
        self.tree.write("other/Cargo.lock", Tree.CARGO.replace(sha("4"), sha("9")))
        two = {"cargo": [("rust/Cargo.lock", ["ours"]), ("other/Cargo.lock", ["ours"])]}
        with mock.patch.dict(sbom.PRODUCTS["native"], two):
            with self.assertRaisesRegex(sbom.SbomError, "pkg:cargo/leaf@0.3.0 is not the package another lockfile pins"):
                self.build("native")

    def test_a_crate_that_is_gone_is_an_error(self):
        with mock.patch.dict(sbom.PRODUCTS["native"], {"cargo": [("rust/Cargo.lock", ["renamed"])]}):
            with self.assertRaisesRegex(sbom.SbomError, "no workspace crate 'renamed'"):
                self.build("native")

    def test_a_registry_crate_cannot_be_a_products_own_crate(self):
        with mock.patch.dict(sbom.PRODUCTS["native"], {"cargo": [("rust/Cargo.lock", ["leaf"])]}):
            with self.assertRaisesRegex(sbom.SbomError, "no workspace crate 'leaf'"):
                self.build("native")

    def test_a_dependency_the_lock_cannot_tell_apart_is_an_error(self):
        self.tree.write("rust/Cargo.lock", Tree.CARGO.replace('"dup 1.0.0"', '"dup"'))
        with self.assertRaisesRegex(sbom.SbomError, "ours depends on 'dup', which names 2 packages"):
            self.build()

    # --- Toolchains

    def test_the_jdk_only_where_one_is_bundled_and_rust_where_crates_are(self):
        app, native = self.components("app"), self.components("native")
        jdk = app["myotis:toolchain:temurin-jdk@21.0.13"]
        self.assertEqual(jdk["cpe"], "cpe:2.3:a:eclipse:temurin:21.0.13:*:*:*:*:*:*:*")
        self.assertEqual(app["myotis:toolchain:rust-std@1.99.1"]["cpe"], "cpe:2.3:a:rust-lang:rust:1.99.1:*:*:*:*:*:*:*")
        self.assertNotIn("myotis:toolchain:temurin-jdk@21.0.13", native)
        self.assertIn("myotis:toolchain:rust-std@1.99.1", native)

    def test_a_toolchain_that_is_not_pinned_exactly_is_refused(self):
        self.tree.write(".java-version", "21\n")
        with self.assertRaisesRegex(sbom.SbomError, "not an exact JDK release"):
            self.build()
        self.tree.write(".java-version", "21.0.13\n")
        self.tree.write("rust/rust-toolchain.toml", '[toolchain]\nchannel = "stable"\n')
        with self.assertRaisesRegex(sbom.SbomError, "not an exact release"):
            self.build()

    # --- The document

    def test_the_document_is_a_cyclonedx_bom_of_the_product(self):
        document = self.build()
        self.assertEqual((document["bomFormat"], document["specVersion"], document["version"]),
                         ("CycloneDX", "1.5", 1))
        self.assertRegex(document["serialNumber"],
                         r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        product = document["metadata"]["component"]
        self.assertEqual((product["type"], product["name"], product["version"]), ("application", "The app", "1.2.3"))
        self.assertNotIn("timestamp", document["metadata"])
        refs = [c["bom-ref"] for c in document["components"]]
        self.assertEqual(refs, sorted(refs))
        self.assertEqual(len(refs), len(set(refs)))
        self.assertNotIn(product["bom-ref"], refs)

    def test_the_same_tree_gives_the_same_bytes(self):
        self.assertEqual(json.dumps(self.build()), json.dumps(self.build()))

    def test_the_serial_number_follows_the_content(self):
        before = self.build()["serialNumber"]
        self.tree.write("proj/gradle.lockfile", Tree.LOCK.replace("g.one:root:3.0=runtimeClasspath\n", ""))
        self.assertNotEqual(self.build()["serialNumber"], before)

    def test_a_timestamp_only_when_one_is_given(self):
        self.assertEqual(self.build(timestamp=0)["metadata"]["timestamp"], "1970-01-01T00:00:00Z")

    def test_two_documents_that_differ_have_two_serial_numbers(self):
        # A serial number and `version` identify a BOM: the same pins at
        # another commit time are another document.
        self.assertEqual(self.build(timestamp=5)["serialNumber"], self.build(timestamp=5)["serialNumber"])
        self.assertNotEqual(self.build(timestamp=5)["serialNumber"], self.build(timestamp=6)["serialNumber"])
        self.assertNotEqual(self.build(timestamp=5)["serialNumber"], self.build()["serialNumber"])

    def test_the_version_is_the_trees_without_snapshot(self):
        self.assertEqual(sbom.release_version(self.tree.root), "1.2.3")

    # --- The command

    def run_main(self, *argv, epoch=None):
        """main() on the made-up tree, with SOURCE_DATE_EPOCH set to `epoch` or not set at all."""
        environment = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
        if epoch is not None:
            environment["SOURCE_DATE_EPOCH"] = epoch
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, environment, clear=True), redirect_stdout(out), redirect_stderr(err):
            try:
                code = sbom.main(["--root", str(self.tree.root), *argv])
            except SystemExit as exit_:
                code = exit_.code
        return code, out.getvalue(), err.getvalue()

    def test_files_are_named_after_the_tag(self):
        out = self.tree.root / "out"
        code, stdout, _ = self.run_main("--tag", "v1.2.3-rc1", "--out", str(out))
        self.assertEqual(code, 0, stdout)
        self.assertEqual(sorted(p.name for p in out.iterdir()),
                         ["Myotis-v1.2.3-rc1-app.cdx.json", "Myotis-v1.2.3-rc1-native.cdx.json"])
        document = json.loads((out / "Myotis-v1.2.3-rc1-app.cdx.json").read_text())
        self.assertEqual(document["metadata"]["component"]["version"], "1.2.3")
        self.assertTrue((out / "Myotis-v1.2.3-rc1-app.cdx.json").read_text().endswith("}\n"))

    def test_without_a_tag_the_files_are_named_after_the_version(self):
        out = self.tree.root / "out"
        self.assertEqual(self.run_main("--out", str(out), "native")[0], 0)
        self.assertEqual([p.name for p in out.iterdir()], ["Myotis-v1.2.3-native.cdx.json"])

    def test_source_date_epoch_is_the_timestamp(self):
        out = self.tree.root / "out"
        self.assertEqual(self.run_main("--out", str(out), "native", epoch="86400")[0], 0)
        document = json.loads((out / "Myotis-v1.2.3-native.cdx.json").read_text())
        self.assertEqual(document["metadata"]["timestamp"], "1970-01-02T00:00:00Z")

    def test_an_error_is_one_line_and_exit_1_and_no_file(self):
        self.tree.write("proj/gradle.lockfile", "g.one:lib:1.0=compileClasspath\n")
        out = self.tree.root / "out"
        # "native" comes first and is fine; "app" is not: neither is written.
        code, _, stderr = self.run_main("--out", str(out), "native", "app")
        self.assertEqual(code, 1)
        self.assertRegex(stderr, r"^sbom\.py: proj/gradle\.lockfile has no lock state")
        self.assertEqual(stderr.count("\n"), 1)
        self.assertFalse(out.exists())

    def test_pins_that_cannot_be_read_are_the_same_refusal(self):
        out = self.tree.root / "out"
        for relative, text in ((".java-version", None), ("rust/Cargo.lock", "[[package\n"),
                               ("gradle/verification-metadata.xml", "<not xml")):
            tree = Tree(self.directory.name)  # every file back as it was
            if text is None:
                (tree.root / relative).unlink()
            else:
                tree.write(relative, text)
            code, _, stderr = self.run_main("--out", str(out))
            with self.subTest(file=relative):
                self.assertEqual(code, 1)
                self.assertRegex(stderr, r"^sbom\.py: cannot read the pins: ")
                self.assertFalse(out.exists())

    def test_a_source_date_epoch_that_is_not_a_number_is_refused(self):
        for epoch in ("yesterday", ""):  # empty: `export X=$(a command that failed)`
            code, _, stderr = self.run_main("--out", str(self.tree.root / "out"), epoch=epoch)
            with self.subTest(epoch=epoch):
                self.assertEqual(code, 1)
                self.assertIn(f"SOURCE_DATE_EPOCH is {epoch!r}", stderr)
                self.assertFalse((self.tree.root / "out").exists())

    def test_the_files_carry_nothing_of_the_host_that_wrote_them(self):
        out = self.tree.root / "out"
        self.assertEqual(self.run_main("--out", str(out))[0], 0)
        for path in out.iterdir():
            data = path.read_bytes()
            with self.subTest(file=path.name):
                self.assertNotIn(b"\r", data)
                self.assertNotIn(b"\\\\", data)  # a backslash, as JSON writes one: a Windows path
                self.assertNotIn(str(self.tree.root).encode(), data)

    def test_a_tag_that_is_not_a_tag_name_and_an_unknown_product_are_refused(self):
        self.assertEqual(self.run_main("--tag", "../x", "--out", str(self.tree.root / "out"))[0], 1)
        self.assertEqual(self.run_main("nonsense")[0], 2)


class RealTree(unittest.TestCase):
    """The products as they are defined, against the pins as they are committed."""

    @classmethod
    def setUpClass(cls):
        cls.version = sbom.release_version(REPO)
        pinned = sbom.read_verification_metadata(REPO / "gradle/verification-metadata.xml")
        cls.documents = {key: sbom.build(REPO, key, cls.version, pinned=pinned) for key in sbom.PRODUCTS}

    def test_two_processes_with_other_hash_seeds_write_the_same_bytes(self):
        # In one process a set iterates the same way twice; what must not leak
        # into the files is the order it happens to have in THIS process.
        with tempfile.TemporaryDirectory() as directory:
            for seed in ("1", "2"):
                environment = {**os.environ, "PYTHONHASHSEED": seed, "SOURCE_DATE_EPOCH": "1700000000"}
                subprocess.run([sys.executable, str(REPO / "scripts/sbom.py"), "--out", f"{directory}/{seed}"],
                               check=True, env=environment, stdout=subprocess.DEVNULL)
            first, second = Path(directory, "1"), Path(directory, "2")
            names = sorted(p.name for p in first.iterdir())
            self.assertEqual(names, sorted(sbom.asset_name(f"v{self.version}", key) for key in sbom.PRODUCTS))
            for name in names:
                with self.subTest(file=name):
                    self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    def test_the_debug_app_is_described_by_its_own_classpath(self):
        release = {c["bom-ref"] for c in self.documents["android"]["components"]}
        debug = {c["bom-ref"] for c in self.documents["android-debug"]["components"]}
        # The Compose tooling ships in the debug app only (ui-tooling-preview is in both).
        tooling = "pkg:maven/androidx.compose.ui/ui-tooling@"
        self.assertTrue(any(ref.startswith(tooling) for ref in debug - release), sorted(debug - release))
        self.assertFalse(any(ref.startswith(tooling) for ref in release))

    def test_what_is_compiled_into_the_apk_without_being_on_its_classpath(self):
        # Named here on purpose, not derived from PRODUCTS: the round trip
        # above checks the documents against the table, and cannot see a
        # configuration the table does not name. Core-library desugaring is on
        # for the app (android-app/build.gradle.kts), so L8 puts
        # desugar_jdk_libs into both APKs' dex.
        build = (REPO / "android-app/build.gradle.kts").read_text()
        self.assertIn("isCoreLibraryDesugaringEnabled = true", build)
        for key in ("android", "android-debug"):
            components = {c["name"]: c for c in self.documents[key]["components"] if c.get("group") == "com.android.tools"}
            with self.subTest(product=key):
                self.assertRegex(components["desugar_jdk_libs"]["hashes"][0]["content"], r"^[0-9a-f]{64}$")
                self.assertNotIn("desugar_jdk_libs_configuration", components)
                left_out = [p["value"] for p in self.documents[key]["metadata"]["properties"]
                            if p["name"] == "myotis:sbom:left-out"]
                self.assertEqual(len(left_out), 1)
                self.assertTrue(left_out[0].startswith("com.android.tools:desugar_jdk_libs_configuration: "))

    def test_the_ios_framework_names_the_kotlin_native_distribution_it_links(self):
        # Named here like the desugaring library: linked into MyotisKit's
        # binary, on no classpath.
        native = [c for c in self.documents["ios"]["components"] if c["name"] == "kotlin-native-prebuilt"]
        self.assertEqual(len(native), 1)
        files = [p["name"] for p in native[0]["properties"] if p["name"].startswith("myotis:pinned-file:sha256:")]
        self.assertTrue(any("macos-aarch64" in name for name in files), files)

    def test_the_engine_library_lists_its_ios_modules_klibs(self):
        pinned_by = {p["value"] for c in self.documents["engine-library"]["components"]
                     for p in c["properties"] if p["name"] == "myotis:pinned-by"}
        self.assertIn("myotis-engine-ios/gradle.lockfile#iosArm64CompileKlibraries", pinned_by)

    def test_every_product_has_components_of_what_it_is_defined_by(self):
        for key, product in sbom.PRODUCTS.items():
            refs = [c["bom-ref"] for c in self.documents[key]["components"]]
            with self.subTest(product=key):
                self.assertEqual(bool(product["gradle"]), any(r.startswith("pkg:maven/") for r in refs))
                self.assertEqual(bool(product["cargo"]), any(r.startswith("pkg:cargo/") for r in refs))
                self.assertEqual(len(refs), len(set(refs)))

    def test_every_maven_component_is_a_line_of_the_lock_it_names(self):
        # Read the lockfiles again, as text, without the parser under test.
        for key, document in self.documents.items():
            for component in document["components"]:
                if not component["bom-ref"].startswith("pkg:maven/"):
                    continue
                coordinate = f"{component['group']}:{component['name']}:{component['version']}"
                for prop in component["properties"]:
                    if prop["name"] != "myotis:pinned-by" or "#" not in prop["value"]:
                        continue
                    lockfile, configuration = prop["value"].split("#")
                    lines = [line for line in (REPO / lockfile).read_text().splitlines()
                             if line.startswith(coordinate + "=")]
                    with self.subTest(product=key, component=coordinate):
                        self.assertEqual(len(lines), 1)
                        self.assertIn(configuration, lines[0].split("=", 1)[1].split(","))

    def test_every_component_of_a_runtime_configuration_is_in_the_sbom(self):
        for key, product in sbom.PRODUCTS.items():
            refs = {c["bom-ref"] for c in self.documents[key]["components"]}
            for project, configurations in product["gradle"]:
                for line in (REPO / project / "gradle.lockfile").read_text().splitlines():
                    if line.startswith(("#", "empty=")) or "=" not in line:
                        continue
                    coordinate, locked_for = line.split("=", 1)
                    if set(configurations) & set(locked_for.split(",")):
                        group, name, version = coordinate.split(":")
                        if f"{group}:{name}" in product.get("build_only", {}):
                            with self.subTest(product=key, left_out=coordinate):
                                self.assertNotIn(f"pkg:maven/{group}/{name}@{version}", refs)
                            continue
                        with self.subTest(product=key, component=coordinate):
                            self.assertIn(f"pkg:maven/{group}/{name}@{version}", refs)

    def test_every_crates_io_component_has_the_locks_checksum(self):
        for key, document in self.documents.items():
            for component in document["components"]:
                if component["bom-ref"].startswith("pkg:cargo/") and "?" not in component["bom-ref"]:
                    with self.subTest(product=key, component=component["bom-ref"]):
                        self.assertRegex(component["hashes"][0]["content"], r"^[0-9a-f]{64}$")

    def test_the_modules_the_build_keeps_out_of_the_locks_are_the_ones_taken_from_the_metadata(self):
        # dependencyLocking.ignoredDependencies in the root build: a pattern
        # added there and not here would leave its modules out of every SBOM.
        text = (REPO / "build.gradle.kts").read_text()
        block = re.search(r"ignoredDependencies\.addAll\(\s*listOf\(([^)]*)\)", text)
        self.assertIsNotNone(block, "build.gradle.kts: no `ignoredDependencies.addAll(listOf(...))` to compare "
                                    "sbom.HOST_MODULES with")
        ignored = sorted(re.findall(r'"([^"]+)"', block.group(1)))
        self.assertEqual(ignored, sorted(f"{group}:{prefix}*" for group, prefix, _ in sbom.HOST_MODULES))

    def test_the_desktop_app_lists_each_hosts_modules_and_its_jdk(self):
        components = self.documents["desktop"]["components"]
        hosts = {p["value"] for c in components for p in c["properties"] if p["name"] == "myotis:host"}
        # Named here, not read from PRODUCTS. The installers a release builds:
        # the dmg (arm64), the deb (x64 and arm64), the msi. The Intel dmg
        # (macos-x64) is missing on purpose until its modules are pinned: add
        # it here in the change that pins them.
        self.assertEqual(hosts, {"linux-x64", "linux-arm64", "macos-arm64", "windows-x64"})
        for _, prefix, _ in sbom.HOST_MODULES:
            listed = {c["name"][len(prefix):] for c in components if c["name"].startswith(prefix)}
            with self.subTest(modules=prefix):
                self.assertEqual(listed, hosts)
        java = (REPO / ".java-version").read_text().strip()
        self.assertIn(f"myotis:toolchain:temurin-jdk@{java}", [c["bom-ref"] for c in components])

    def test_the_shape_cyclonedx_1_5_requires(self):
        types = {"application", "framework", "library", "container", "platform", "operating-system", "device",
                 "device-driver", "firmware", "file", "machine-learning-model", "data"}
        for key, document in self.documents.items():
            self.assertEqual(document["bomFormat"], "CycloneDX")
            self.assertEqual(document["specVersion"], "1.5")
            self.assertIsInstance(document["version"], int)
            for component in document["components"] + [document["metadata"]["component"]]:
                with self.subTest(product=key, component=component["bom-ref"]):
                    self.assertIn(component["type"], types)
                    self.assertTrue(component["name"])
                    for digest in component.get("hashes", []):
                        self.assertEqual(digest["alg"], "SHA-256")
                        self.assertRegex(digest["content"], r"^[0-9a-f]{64}$")
                    for prop in component.get("properties", []):
                        self.assertEqual(set(prop), {"name", "value"})
                        self.assertIsInstance(prop["value"], str)
                    if "purl" in component:
                        self.assertRegex(component["purl"], r"^pkg:(maven|cargo)/[^ ]+@[^ ]+$")

    def test_the_verifier_knows_who_publishes_these_files(self):
        script = (REPO / "scripts/verify_release.sh").read_text()
        self.assertTrue("Myotis-*.cdx.json) echo sbom.yml ;;" in script,
                        "scripts/verify_release.sh (workflow_of) does not name sbom.yml for Myotis-*.cdx.json")
        self.assertRegex(sbom.asset_name("v0.0.0", "android"), r"^Myotis-.*\.cdx\.json$")


if __name__ == "__main__":
    unittest.main()
