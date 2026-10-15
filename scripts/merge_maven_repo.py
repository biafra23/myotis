#!/usr/bin/env python3
"""Merge a staged Maven repository into a published one, version by version.

Usage: scripts/merge_maven_repo.py <staged-repo> <target-repo>

Used by .github/workflows/engine-library.yml to add a release's artifacts to the
`maven-repo` branch — the static Maven repository that raw.githubusercontent.com
serves without a token. A plain copy would do for the artifacts themselves (each
version has its own directory), but NOT for the artifact-level maven-metadata.xml:
Gradle stages the one it knows, listing only the version it just published, and
copying that over the published file would drop every earlier version from the
listing that dynamic versions (`0.1.+`, `latest.release`) resolve through.

So: every file under a version directory is copied as is (checksums included —
Gradle wrote them); an artifact-level maven-metadata.xml the target already has
is MERGED — the union of both version lists in order, `latest` / `release` the
newest version of the union by Maven's ordering (a hotfix of an older line does
not move them backwards), `lastUpdated` from the staged side — and its four
checksum files (.md5/.sha1/.sha256/.sha512, the set Gradle writes) are
regenerated, since a checksum that no longer matches is a resolution error in
Gradle, while a missing one is tolerated. A metadata file the target does not
have yet (a first publish, a new artifact) is copied with its checksums.

Exact versions never read the metadata, so a republish of one version is a plain
overwrite of its directory. Nothing is ever deleted. Running it twice with the
same input changes nothing.
"""

import hashlib
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

CHECKSUMS = ("md5", "sha1", "sha256", "sha512")
METADATA = "maven-metadata.xml"


# Maven's ComparableVersion qualifier order, for the shapes the release guard
# accepts (X.Y.Z, X.Y.Z-<suffix>): alpha < beta < milestone < rc < snapshot <
# the bare release < sp < any other qualifier (compared among themselves
# lexically). Aliases as Maven resolves them: a=alpha, b=beta, m=milestone,
# cr=rc, ga/final/release = the bare release.
_QUALIFIER_RANK = {"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4, "": 5, "sp": 6}
_QUALIFIER_ALIAS = {"a": "alpha", "b": "beta", "m": "milestone", "cr": "rc",
                    "ga": "", "final": "", "release": ""}
_UNKNOWN_RANK = 7


def version_key(version: str):
    """Order versions as Maven's ComparableVersion does for the accepted shapes:
    numeric parts numerically; then the qualifier by Maven's rank (a pre-release
    qualifier below the bare release, `sp` above it, an unknown qualifier such
    as `hotfix` above `sp`, unknown ones lexically among themselves), its
    trailing number numerically (rc10 > rc9), aliases folded (cr10 == rc10)."""
    core, _, qualifier = version.partition("-")
    parts = tuple(int(p) if p.isdigit() else 0 for p in core.split("."))
    m = re.fullmatch(r"([A-Za-z]*)[.-]?(\d*)(.*)", qualifier)
    word, number, rest = (m.group(1).lower(), m.group(2), m.group(3)) if m else (qualifier.lower(), "", "")
    word = _QUALIFIER_ALIAS.get(word, word)
    rank = _QUALIFIER_RANK.get(word, _UNKNOWN_RANK)
    # Maven: "1.0-1" (a bare number after the dash) is a build number ABOVE the
    # release; the guard never produces it, but keep the order right anyway.
    if qualifier and word == "" and number:
        rank = _UNKNOWN_RANK
    lexical = word if rank == _UNKNOWN_RANK else ""
    return (parts, rank, lexical, int(number) if number else -1, rest)


def merge_metadata(existing: Path, staged: Path) -> bytes:
    new = ET.parse(staged).getroot()
    old = ET.parse(existing).getroot()
    new_versions = [v.text for v in new.findall("./versioning/versions/version")]
    old_versions = [v.text for v in old.findall("./versioning/versions/version")]
    merged = old_versions + [v for v in new_versions if v not in old_versions]
    versions = new.find("./versioning/versions")
    for child in list(versions):
        versions.remove(child)
    for v in merged:
        el = ET.SubElement(versions, "version")
        el.text = v
    newest = max(merged, key=version_key)
    for tag in ("latest", "release"):
        el = new.find("./versioning/" + tag)
        if el is not None:
            el.text = newest
    # Keep the 2-space, one-element-per-line layout Gradle writes.
    ET.indent(new, space="  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(new, encoding="utf-8") + b"\n"


def write_checksums(file: Path) -> None:
    data = file.read_bytes()
    for name in CHECKSUMS:
        (file.parent / (file.name + "." + name)).write_text(hashlib.new(name, data).hexdigest())


def main(staged_root: Path, target_root: Path) -> None:
    copied = merged = 0
    merged_dirs: set = set()  # directories whose metadata was merged: their checksums are regenerated, not copied
    # Sorted, so each directory's maven-metadata.xml is seen before its .md5/.sha* files.
    for src in sorted(staged_root.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(staged_root)
        dst = target_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.name == METADATA and dst.exists():
            dst.write_bytes(merge_metadata(dst, src))
            write_checksums(dst)
            merged_dirs.add(rel.parent)
            merged += 1
        elif src.name.startswith(METADATA + ".") and rel.parent in merged_dirs:
            continue  # regenerated above from the merged file
        else:
            shutil.copyfile(src, dst)
            copied += 1
    print(f"merged {staged_root} into {target_root}: {copied} files copied, {merged} metadata files merged")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
