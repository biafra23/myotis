#!/usr/bin/env python3
"""Tests of scripts/sbom.py: the parsers and refusals on made-up inputs, then the real tree.

    python3 scripts/test_sbom.py
"""

import io
import json
import os
import re
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
            "host_modules": True, "jdk": True,
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

    def test_host_modules_that_are_not_pinned_are_an_error(self):
        pinned = {k: v for k, v in Tree.PINNED.items() if not (k[1].startswith("ui-host-") and k[2] == "5.0")}
        self.tree.write("gradle/verification-metadata.xml", metadata(pinned))
        with self.assertRaisesRegex(sbom.SbomError, "pins no g.ui:ui-host-<host>:5.0"):
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
        # ... and it is not part of what the serial number names.
        self.assertEqual(self.build(timestamp=0)["serialNumber"], self.build()["serialNumber"])

    def test_the_version_is_the_trees_without_snapshot(self):
        self.assertEqual(sbom.release_version(self.tree.root), "1.2.3")

    # --- The command

    def run_main(self, *argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=False), redirect_stdout(out), redirect_stderr(err):
            os.environ.pop("SOURCE_DATE_EPOCH", None) if env is None else None
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
        self.assertEqual(self.run_main("--out", str(out), "native", env={"SOURCE_DATE_EPOCH": "86400"})[0], 0)
        document = json.loads((out / "Myotis-v1.2.3-native.cdx.json").read_text())
        self.assertEqual(document["metadata"]["timestamp"], "1970-01-02T00:00:00Z")

    def test_an_error_is_one_line_and_exit_1_and_no_file(self):
        self.tree.write("proj/gradle.lockfile", "g.one:lib:1.0=compileClasspath\n")
        out = self.tree.root / "out"
        code, _, stderr = self.run_main("--out", str(out), "app")
        self.assertEqual(code, 1)
        self.assertRegex(stderr, r"^sbom\.py: proj/gradle\.lockfile has no lock state")
        self.assertEqual(list(out.iterdir()), [])

    def test_a_tag_that_is_not_a_tag_name_and_an_unknown_product_are_refused(self):
        self.assertEqual(self.run_main("--tag", "../x", "--out", str(self.tree.root / "out"))[0], 1)
        self.assertEqual(self.run_main("nonsense")[0], 2)


class RealTree(unittest.TestCase):
    """The products as they are defined, against the pins as they are committed."""

    @classmethod
    def setUpClass(cls):
        cls.version = sbom.release_version(REPO)
        cls.documents = {key: sbom.build(REPO, key, cls.version) for key in sbom.PRODUCTS}

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
        block = text[text.index("ignoredDependencies.addAll("):]
        block = block[:block.index("),\n        )")]
        ignored = sorted(re.findall(r'"([^"]+)"', block))
        self.assertEqual(ignored, sorted(f"{group}:{prefix}*" for group, prefix, _ in sbom.HOST_MODULES))

    def test_the_desktop_app_lists_each_hosts_modules_and_its_jdk(self):
        components = self.documents["desktop"]["components"]
        hosts = {p["value"] for c in components for p in c["properties"] if p["name"] == "myotis:host"}
        self.assertTrue({"linux-x64", "linux-arm64", "macos-arm64", "windows-x64"} <= hosts, hosts)
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
