#!/usr/bin/env python3
"""CycloneDX SBOMs of what a release ships, generated from the committed pins (#734, Part 5e).

    scripts/sbom.py [--tag vX.Y.Z] [--out DIR] [PRODUCT ...]
    scripts/sbom.py --list

One CycloneDX 1.5 JSON document per shipped product (PRODUCTS below), written
to DIR as Myotis-<tag>-<product>.cdx.json (all of them, or none: an error
writes no file). Nothing is built and nothing is
downloaded: the inputs are the files that already pin the build,

  - <project>/gradle.lockfile       the modules Gradle may resolve, per
                                    configuration (strict: a build fails on
                                    any other version);
  - gradle/verification-metadata.xml  the SHA-256 of every file of them;
  - rust/Cargo.lock                 every crate, with the registry's checksum;
  - .java-version, rust/rust-toolchain.toml  the JDK a desktop installer
                                    bundles and the Rust whose std is linked
                                    into the native libraries.

So an SBOM says exactly what the pins of the tagged tree say, it is the same
bytes for the same tree (no clock unless SOURCE_DATE_EPOCH is set, no host),
and a dependency bump changes it without anyone remembering to. Python 3.11
or newer, standard library only.

What that makes each part:

  Gradle  EXACT. A product's components are the modules its project's runtime
          configuration is locked to, plus those of a configuration whose
          modules are compiled into it without being on that classpath (the
          Android apps' coreLibraryDesugaring), minus the ones named as
          build-only, which the document lists as left out.
  Cargo   A SUPERSET. Cargo.lock records one graph for all targets and all
          dependency kinds, so "reachable from the product's crates" includes
          build dependencies, the dev dependencies of the workspace's own
          crates, optional dependencies (Arti, behind -PtorEngine) and crates
          only another operating system compiles. Every crate that is linked
          is listed; not every listed crate is linked.

What a lockfile does not record, and these documents therefore do not carry:
licenses, and the dependency graph between Maven modules. They are inventories
(flat component lists), which is what matching against advisories needs.

A product names the configuration it is locked by; one that no longer exists
(a renamed source set, a module that left) is an ERROR, never an empty list:
an SBOM that silently lost a product's components would read like a clean one.
"""

import sys

if sys.version_info < (3, 11):  # tomllib
    sys.exit("sbom.py: needs Python 3.11 or newer")

import argparse
import hashlib
import json
import os
import re
import tomllib
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SPEC_VERSION = "1.5"
REPOSITORY = "https://github.com/biafra23/myotis"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"

# Modules whose coordinates depend on the build host. The root build keeps them
# out of the lock state (dependencyLocking.ignoredDependencies) while
# verification-metadata.xml pins their bytes for every host, so a product that
# ships them takes them from there: every host's module, at the version of the
# locked module they belong to. (group, name prefix, the locked module whose
# version they follow.)
HOST_MODULES = [
    ("org.jetbrains.compose.desktop", "desktop-jvm-", "org.jetbrains.compose.desktop:desktop-jvm"),
    ("org.jetbrains.skiko", "skiko-awt-runtime-", "org.jetbrains.skiko:skiko-awt"),
]

# What a release ships. `gradle`: (project directory, the configurations whose
# lock state is what the product is made of: its runtime classpath, and any
# other configuration whose modules end up INSIDE it). `build_only`: modules of
# those configurations that the build reads and does not ship, each with the
# reason, which the document repeats. `cargo`: (lockfile, the workspace crates
# the product links). `hosts`: the hosts it is built for, when it bundles the
# per-host modules above; they must be exactly the hosts the verification
# metadata pins those modules for. `jdk`: it bundles a JDK runtime image
# (jlink, from .java-version).
#
# coreLibraryDesugaring, for the Android apps: L8 compiles desugar_jdk_libs
# into the APK's dex (the j$.* classes), and it is on no runtime classpath.
DESUGARING = {
    "com.android.tools:desugar_jdk_libs_configuration":
        "the rules D8 and L8 desugar by: read by the build, not in the APK",
}
PRODUCTS = {
    "android": {
        "name": "Myotis for Android",
        "description": "The Android app: Myotis-<tag>-android.apk and the same app before its signature, "
                       "-android-unsigned.apk.",
        "gradle": [("android-app", ["releaseRuntimeClasspath", "coreLibraryDesugaring"])],
        "build_only": DESUGARING,
        "cargo": [("rust/Cargo.lock", ["myotis-engine", "myotis-bls"])],
    },
    # Its own document: the debug variant's classpath is not the release one
    # (the Compose tooling comes with it).
    "android-debug": {
        "name": "Myotis for Android, debug app",
        "description": "The debug app, Myotis-<tag>-android-debug.apk.",
        "gradle": [("android-app", ["debugRuntimeClasspath", "coreLibraryDesugaring"])],
        "build_only": DESUGARING,
        "cargo": [("rust/Cargo.lock", ["myotis-engine", "myotis-bls"])],
    },
    "desktop": {
        "name": "Myotis for desktop",
        "description": "The desktop app in its installers: Myotis-<tag>-<arch>.dmg (and the PoC dmgs), "
                       "Myotis-<tag>-<arch>.deb, the Windows msi.",
        "gradle": [("app-desktop", ["runtimeClasspath"])],
        "cargo": [("rust/Cargo.lock", ["myotis-engine"])],
        # The dmg (arm64, and x64 for Intel Macs), the deb (x64, arm64) and
        # the msi. A host is the JVM Gradle runs on: the Intel dmg is built by
        # an x86_64 JDK on an Apple Silicon runner. The generator refuses a
        # host stated here that the verification metadata does not pin, and a
        # pinned host that is not stated here, so the two cannot drift apart.
        "hosts": ["linux-arm64", "linux-x64", "macos-arm64", "macos-x64", "windows-x64"],
        "jdk": True,
    },
    "daemon": {
        "name": "Myotis daemon",
        "description": "What the daemon runs with: the classpath of the published jars (app, core, "
                       "networking, consensus) and the Rust engine it loads. The jars are thin: none of "
                       "these components is inside them.",
        "gradle": [("app", ["runtimeClasspath"])],
        "cargo": [("rust/Cargo.lock", ["myotis-engine", "myotis-bls"])],
    },
    "engine-library": {
        "name": "Myotis engine library",
        "description": "eth.myotis:myotis-engine as published: the Android AAR, the desktop jar, the natives "
                       "jars and the iOS module (myotis-engine-<tag>-android.aar, "
                       "myotis-engine-<tag>-maven-repo.zip).",
        "gradle": [("myotis-engine", ["releaseRuntimeClasspath", "jvmRuntimeClasspath"]),
                   ("myotis-engine-ios", ["iosArm64CompileKlibraries", "iosSimulatorArm64CompileKlibraries"])],
        "cargo": [("rust/Cargo.lock", ["myotis-engine", "myotis-bls"])],
    },
    "ios": {
        "name": "Myotis for iOS",
        "description": "MyotisKit.xcframework.zip (the Kotlin/Native framework with the Rust engine) and "
                       "MyotisEngine.xcframework.zip (the Rust engine alone: the cargo components).",
        # kotlinNativeBundleConfiguration: the Kotlin/Native distribution, whose
        # runtime (memory manager, standard library) is linked into the
        # framework binary and is on no klib classpath.
        "gradle": [("app-ios", ["iosArm64CompileKlibraries", "iosSimulatorArm64CompileKlibraries",
                                "kotlinNativeBundleConfiguration"])],
        "cargo": [("rust/Cargo.lock", ["myotis-engine"])],
    },
    "node": {
        "name": "Myotis Node.js addon",
        "description": "myotis-node.<platform>.node, the napi addon.",
        "gradle": [],
        "cargo": [("rust/Cargo.lock", ["myotis-node"])],
    },
}

# The files of a module that are its payload (the rest of what the verification
# metadata pins for it is the build's own metadata: .pom, .module).
BINARY_SUFFIXES = (".jar", ".aar", ".klib", ".tar.gz", ".zip")


class SbomError(Exception):
    """An input does not say what a product claims of it. Never papered over."""


def quote(part):
    return urllib.parse.quote(part, safe="")


# --- Gradle -------------------------------------------------------------------

def read_lockfile(path):
    """{configuration: {(group, name, version), ...}} of one gradle.lockfile."""
    if not path.is_file():
        raise SbomError(f"{path}: no such lockfile")
    by_configuration = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        coordinate, sep, configurations = line.partition("=")
        if not sep:
            raise SbomError(f"{path}:{number}: not a lock line: {line!r}")
        if coordinate == "empty":
            # Configurations that resolve to nothing: they exist, with no module.
            for configuration in filter(None, configurations.split(",")):
                by_configuration.setdefault(configuration, set())
            continue
        parts = coordinate.split(":")
        if len(parts) != 3 or not all(parts):
            raise SbomError(f"{path}:{number}: not group:name:version: {coordinate!r}")
        for configuration in filter(None, configurations.split(",")):
            by_configuration.setdefault(configuration, set()).add(tuple(parts))
    return by_configuration


def read_verification_metadata(path):
    """{(group, name, version): {file name: sha256}} of gradle/verification-metadata.xml."""
    if not path.is_file():
        raise SbomError(f"{path}: no verification metadata")
    namespace = "{https://schema.gradle.org/dependency-verification}"
    pinned = {}
    for component in ET.parse(path).getroot().iter(f"{namespace}component"):
        key = (component.get("group"), component.get("name"), component.get("version"))
        files = pinned.setdefault(key, {})
        for artifact in component.iter(f"{namespace}artifact"):
            digest = artifact.find(f"{namespace}sha256")
            if digest is not None:
                files[artifact.get("name")] = digest.get("value")
    return pinned


def maven_component(coordinate, pinned, pinned_by, extra=()):
    group, name, version = coordinate
    if coordinate not in pinned:
        raise SbomError(
            f"{group}:{name}:{version} is locked ({', '.join(sorted(pinned_by))}) but "
            "gradle/verification-metadata.xml pins no file of it: the two disagree "
            "(scripts/update_gradle_pins.sh regenerates both)")
    purl = f"pkg:maven/{quote(group)}/{quote(name)}@{quote(version)}"
    component = {"type": "library", "bom-ref": purl, "group": group, "name": name, "version": version}
    binaries = {f: h for f, h in pinned[coordinate].items() if f.endswith(BINARY_SUFFIXES)}
    properties = [("myotis:pinned-by", source) for source in sorted(pinned_by)] + list(extra)
    plain = [f for f in binaries if f.rsplit(".", 1)[0] == f"{name}-{version}"]
    if len(binaries) == 1 and plain:
        # One payload file, the unclassified one: it IS the component.
        suffix = plain[0].rsplit(".", 1)[1]
        component["purl"] = purl if suffix == "jar" else f"{purl}?type={suffix}"
        component["hashes"] = [{"alg": "SHA-256", "content": binaries[plain[0]]}]
    else:
        # None (a module that is only metadata: a BOM, the root of a
        # multiplatform library) or several (variants, classifiers, one per
        # host): which file a build takes depends on the consumer, so each
        # pinned file is named instead of one being called "the" component.
        component["purl"] = purl
        properties += [(f"myotis:pinned-file:sha256:{f}", h) for f, h in sorted(binaries.items())]
    component["properties"] = [{"name": n, "value": v} for n, v in properties]
    return component


def gradle_components(root, product, pinned):
    members = {}  # coordinate -> {source, ...}
    for project, configurations in product["gradle"]:
        lockfile = f"{project}/gradle.lockfile"  # as written into the document: never a host's separator
        locked = read_lockfile(root / lockfile)
        for configuration in configurations:
            if configuration not in locked:
                raise SbomError(
                    f"{lockfile} has no lock state for the configuration {configuration!r}, which "
                    f"{product['name']} is defined by (scripts/sbom.py, PRODUCTS): renamed or gone?")
            for coordinate in locked[configuration]:
                members.setdefault(coordinate, set()).add(f"{lockfile}#{configuration}")
    for module in product.get("build_only", {}):
        build_only = [c for c in members if f"{c[0]}:{c[1]}" == module]
        if not build_only:
            # A filter that matches nothing is a filter nobody is checking.
            raise SbomError(f"{product['name']} leaves out {module} as build-only, and locks no such module "
                            "(scripts/sbom.py, PRODUCTS): renamed or gone?")
        for coordinate in build_only:
            del members[coordinate]
    components = [maven_component(c, pinned, sources) for c, sources in members.items()]
    if product.get("hosts"):
        stated = set(product["hosts"])
        for group, prefix, follows in HOST_MODULES:
            locked_at = sorted(v for g, n, v in members if f"{g}:{n}" == follows)
            if len(locked_at) != 1:
                raise SbomError(
                    f"{product['name']} bundles {group}:{prefix}<host>, which follows the version of {follows}, "
                    f"and locks that at {', '.join(locked_at) or 'no version'}: one version is needed to pick them")
            by_host = {k[1][len(prefix):]: k for k in pinned
                       if k[0] == group and k[1].startswith(prefix) and k[2] == locked_at[0]}
            # Both ways, so neither list can fall behind the other: a host the
            # product is built for and no pin covers would be missing from the
            # document without a word, and so would a host that was pinned and
            # never added to the product.
            for host in sorted(stated - set(by_host)):
                raise SbomError(
                    f"{product['name']} is built for {host}, and gradle/verification-metadata.xml pins no "
                    f"{group}:{prefix}{host}:{locked_at[0]}")
            for host in sorted(set(by_host) - stated):
                raise SbomError(
                    f"gradle/verification-metadata.xml pins {group}:{prefix}{host}:{locked_at[0]}, and {host} is "
                    f"not among the hosts {product['name']} is built for (scripts/sbom.py, PRODUCTS)")
            for host in sorted(by_host):
                components.append(maven_component(
                    by_host[host], pinned, {"gradle/verification-metadata.xml"}, extra=[("myotis:host", host)]))
    return components


# --- Cargo --------------------------------------------------------------------

def cargo_components(root, product):
    crates = {}  # purl -> (name, version, source, checksum, {lockfile, ...})
    for lockfile, roots in product["cargo"]:
        path = root / lockfile
        if not path.is_file():
            raise SbomError(f"{path}: no such lockfile")
        packages = tomllib.loads(path.read_text(encoding="utf-8")).get("package", [])
        by_name = {}
        for package in packages:
            by_name.setdefault(package["name"], []).append(package)

        def resolve(reference, owner):
            # "name", "name version" or "name version (source)": as much as
            # the lock needs to tell two packages of one name apart.
            name, _, rest = reference.partition(" ")
            version, _, source = rest.partition(" ")
            found = [p for p in by_name.get(name, [])
                     if (not version or p["version"] == version)
                     and (not source or f"({p.get('source', '')})" == source)]
            if len(found) != 1:
                raise SbomError(f"{lockfile}: {owner} depends on {reference!r}, which names "
                                f"{len(found)} packages")
            return found[0]

        pending = []
        for name in roots:
            mine = [p for p in by_name.get(name, []) if "source" not in p]
            if len(mine) != 1:
                raise SbomError(f"{lockfile} has no workspace crate {name!r}, which {product['name']} "
                                "is defined by (scripts/sbom.py, PRODUCTS): renamed or gone?")
            pending.append(mine[0])
        seen = set()
        while pending:
            package = pending.pop()
            key = (package["name"], package["version"], package.get("source", ""))
            if key in seen:
                continue
            seen.add(key)
            pending += [resolve(d, package["name"]) for d in package.get("dependencies", [])]
            if "source" not in package:
                continue  # one of the workspace's own crates: part of the product itself
            name, version, source = key
            purl = f"pkg:cargo/{quote(name)}@{quote(version)}"
            if source != CRATES_IO:
                # Another registry, or a git revision: the same name and version
                # there is another package, so the source is part of its identity.
                purl += "?" + ("vcs_url=" if source.startswith("git+") else "repository_url=") + quote(source)
            crate = crates.setdefault(purl, (name, version, source, package.get("checksum"), set()))
            if crate[:4] != (name, version, source, package.get("checksum")):
                raise SbomError(f"{lockfile}: {purl} is not the package another lockfile pins under that name "
                                f"(checksum {package.get('checksum')} here, {crate[3]} there)")
            crate[4].add(lockfile)
    components = []
    for purl, (name, version, source, checksum, lockfiles) in crates.items():
        component = {"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl}
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        properties = [("myotis:pinned-by", lockfile) for lockfile in sorted(lockfiles)]
        if source != CRATES_IO:
            properties.append(("myotis:cargo:source", source))
        component["properties"] = [{"name": n, "value": v} for n, v in properties]
        components.append(component)
    return components


# --- The toolchains whose code ends up inside the product ----------------------

def toolchain_components(root, product):
    components = []
    if product.get("jdk"):
        version = (root / ".java-version").read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+(\.\d+)*", version):
            raise SbomError(f".java-version is {version!r}, not an exact JDK release")
        components.append({
            "type": "platform",
            "bom-ref": f"myotis:toolchain:temurin-jdk@{version}",
            "group": "org.eclipse.adoptium",
            "name": "Eclipse Temurin JDK",
            "version": version,
            "description": "The Java runtime jlink builds into the installer (jpackage), from the JDK the build runs on.",
            "cpe": f"cpe:2.3:a:eclipse:temurin:{version}:*:*:*:*:*:*:*",
            "properties": [{"name": "myotis:pinned-by", "value": ".java-version"}],
        })
    if product["cargo"]:
        toolchain = tomllib.loads((root / "rust/rust-toolchain.toml").read_text(encoding="utf-8"))
        version = toolchain.get("toolchain", {}).get("channel", "")
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise SbomError(f"rust/rust-toolchain.toml pins the channel {version!r}, not an exact release")
        components.append({
            "type": "library",
            "bom-ref": f"myotis:toolchain:rust-std@{version}",
            "group": "rust-lang",
            "name": "Rust standard library",
            "version": version,
            "description": "std, core and alloc of the pinned toolchain, linked into the native libraries.",
            "cpe": f"cpe:2.3:a:rust-lang:rust:{version}:*:*:*:*:*:*:*",
            "properties": [{"name": "myotis:pinned-by", "value": "rust/rust-toolchain.toml"}],
        })
    return components


# --- The document --------------------------------------------------------------

def release_version(root):
    """The version of the tree: the root build's `version`, without -SNAPSHOT."""
    text = (root / "build.gradle.kts").read_text(encoding="utf-8")
    found = re.findall(r'^\s+version = "([^"]+)"\s*$', text, flags=re.M)
    if len(found) != 1:
        raise SbomError(f"build.gradle.kts has {len(found)} `version = \"…\"` lines; expected the one in allprojects")
    return found[0].removesuffix("-SNAPSHOT")


def build(root, key, version, timestamp=None, pinned=None):
    """The CycloneDX document of one product, as a dict.

    `pinned`: read_verification_metadata's result, for a caller that builds
    several products and wants the file parsed once.
    """
    product = PRODUCTS[key]
    if pinned is None and product["gradle"]:
        pinned = read_verification_metadata(root / "gradle/verification-metadata.xml")
    components = (gradle_components(root, product, pinned) + cargo_components(root, product)
                  + toolchain_components(root, product))
    components.sort(key=lambda c: c["bom-ref"])
    refs = [c["bom-ref"] for c in components]
    if len(set(refs)) != len(refs):
        raise SbomError(f"{key}: duplicate component references")
    if not components:
        raise SbomError(f"{key}: no component at all")

    sources = [f"{project}/gradle.lockfile#{c}" for project, cs in product["gradle"] for c in cs]
    crates = [f"{lockfile}: {', '.join(roots)}" for lockfile, roots in product["cargo"]]
    properties = [("myotis:sbom:generator", "scripts/sbom.py, from the committed pins of the tree: nothing was built")]
    if sources:
        properties.append(("myotis:sbom:gradle",
                           "exact: the modules these configurations are locked to: " + "; ".join(sources)))
    if product.get("hosts"):
        properties.append(("myotis:sbom:hosts",
                           "with the per-host modules of: " + ", ".join(sorted(product["hosts"]))))
    for module, why in sorted(product.get("build_only", {}).items()):
        properties.append(("myotis:sbom:left-out", f"{module}: {why}"))
    if crates:
        properties.append(("myotis:sbom:cargo",
                           "a superset: every package reachable from these workspace crates, for all targets "
                           "and including build, dev and optional dependencies: " + "; ".join(crates)))
    properties.append(("myotis:sbom:not-recorded",
                       "licenses, and the dependency graph: the lockfiles carry neither"))

    metadata = {}
    if timestamp is not None:
        metadata["timestamp"] = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata["tools"] = {"components": [{
        "type": "application", "name": "scripts/sbom.py",
        "externalReferences": [{"type": "vcs", "url": REPOSITORY}],
    }]}
    metadata["component"] = {
        "type": "application",
        "bom-ref": f"myotis:{key}@{version}",
        "name": product["name"],
        "version": version,
        "description": product["description"],
        "externalReferences": [{"type": "vcs", "url": REPOSITORY}],
    }
    metadata["properties"] = [{"name": n, "value": v} for n, v in properties]

    # A serial number that is a function of the whole document: the same tree
    # and commit time give the same number, and anything else that differs
    # (another commit's timestamp with the same pins, a release candidate and
    # its release) another one, since a serial number and `version` together
    # are what identifies a BOM.
    content = json.dumps([metadata, components], sort_keys=True, separators=(",", ":"))
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{REPOSITORY}/sbom/{hashlib.sha256(content.encode()).hexdigest()}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }


def asset_name(tag, key):
    return f"Myotis-{tag}-{key}.cdx.json"


def main(argv=None):
    parser = argparse.ArgumentParser(description="CycloneDX SBOMs from the committed pins.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                        help="the repository (default: the one this script is in)")
    parser.add_argument("--tag", help="the release tag the files are named after (default: v<version>)")
    parser.add_argument("--out", type=Path, default=Path("build/sbom"), help="where the files go")
    parser.add_argument("--list", action="store_true", help="print the products and stop")
    parser.add_argument("products", nargs="*", metavar="PRODUCT", help="default: every product")
    args = parser.parse_args(argv)
    if args.list:
        for key, product in PRODUCTS.items():
            print(f"{key}\t{product['name']}")
        return 0
    unknown = [p for p in args.products if p not in PRODUCTS]
    if unknown:
        parser.error(f"no such product: {', '.join(unknown)} (--list names them)")
    keys = args.products or list(PRODUCTS)
    try:
        version = release_version(args.root)
        tag = args.tag or f"v{version}"
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
            raise SbomError(f"{tag!r} is not a tag name")
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if epoch is not None and not re.fullmatch(r"\d+", epoch):
            # Set and empty is a command that failed (`export X=$(git log ...)`),
            # not a wish for no timestamp: that is the variable not being set.
            raise SbomError(f"SOURCE_DATE_EPOCH is {epoch!r}, not a number of seconds")
        timestamp = int(epoch) if epoch is not None else None
        pinned = None
        if any(PRODUCTS[key]["gradle"] for key in keys):
            pinned = read_verification_metadata(args.root / "gradle/verification-metadata.xml")
        # Every document first, then the files: a product that cannot be
        # described leaves no half of a set behind.
        documents = [(key, build(args.root, key, version, timestamp, pinned)) for key in keys]
    except SbomError as error:
        print(f"sbom.py: {error}", file=sys.stderr)
        return 1
    except (OSError, tomllib.TOMLDecodeError, ET.ParseError) as error:
        # A pin file that is missing or does not parse: the same refusal.
        print(f"sbom.py: cannot read the pins: {error}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    for key, document in documents:
        path = args.out / asset_name(tag, key)
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                        newline="\n")  # the same bytes on Windows
        print(f"{path}: {len(document['components'])} components")
    return 0


if __name__ == "__main__":
    sys.exit(main())
