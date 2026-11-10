#!/usr/bin/env python3
"""Refuse a gradle/verification-metadata.xml change that is not purely additive.

    check_pins_additive.py OLD.xml NEW.xml

Used by .github/workflows/gradle-pins-dependabot.yml (#734) before it commits
pins that an UNTRUSTED job produced (that job ran the bumped plugins' code).
A dependency bump only ever needs NEW entries: hashes for artifacts the new
versions bring. So the new file must

  * keep the <configuration> block exactly (verify-metadata, verify-signatures,
    trusted artifacts and keys): a bump never needs to loosen verification;
  * keep every existing artifact entry exactly — the same checksums, no
    <also-trust> alternates added, no duplicate entries: a bump never needs to
    re-hash or widen a version that was already pinned.

Anything else (verification turned off, a trusted-artifact wildcard added, a
pinned hash replaced) exits 1 and names the change. Stdlib only; run with -I.
"""
import sys
import xml.etree.ElementTree as ET

NS = "{https://schema.gradle.org/dependency-verification}"


def canonical(elem):
    """Element as a whitespace-insensitive string, for comparing blocks."""
    for e in elem.iter():
        e.text = (e.text or "").strip() or None
        e.tail = None
    return ET.tostring(elem, encoding="unicode")


def artifacts(root):
    """(group, name, version, artifact) -> [canonical <artifact> element, ...].

    The WHOLE element, not just its direct checksum children: Gradle nests
    alternate accepted values inside a checksum (<sha256 value=…><also-trust
    value=…/></sha256>), and an added also-trust would widen what an
    already-pinned artifact may be while its direct children compare equal.
    A list, because Gradle merges duplicate entries and a dict would keep only
    the last copy.
    """
    out = {}
    for comp in root.iter(NS + "component"):
        key = (comp.get("group"), comp.get("name"), comp.get("version"))
        for art in comp.findall(NS + "artifact"):
            out.setdefault(key + (art.get("name"),), []).append(canonical(art))
    return out


def main(old_path, new_path):
    old, new = ET.parse(old_path).getroot(), ET.parse(new_path).getroot()
    problems = []

    old_conf, new_conf = old.find(NS + "configuration"), new.find(NS + "configuration")
    if old_conf is None or new_conf is None:
        problems.append("a <configuration> block is missing")
    elif canonical(old_conf) != canonical(new_conf):
        problems.append("the <configuration> block changed (verification settings, trusted artifacts or keys)")

    old_arts, new_arts = artifacts(old), artifacts(new)
    for key, copies in sorted(new_arts.items()):
        if len(copies) > 1:
            problems.append("artifact listed more than once: {}:{}:{} {}".format(*key))
    for key, copies in sorted(old_arts.items()):
        label = "{}:{}:{} {}".format(*key)
        if key not in new_arts:
            problems.append("pinned artifact removed: " + label)
        elif new_arts[key] != copies:
            # Byte-for-byte (canonically) the same entry: same checksums, no
            # also-trust added, origin and all. A legitimate also-trust (Gradle
            # writes one when two hosts saw different bytes) lands here too —
            # and belongs in the reviewed --from-ci lane, not an automatic push.
            problems.append("pinned artifact entry changed: " + label)

    if problems:
        for p in problems:
            print("check_pins_additive: " + p, file=sys.stderr)
        return 1
    print("check_pins_additive: OK — {} new artifact pin(s), nothing existing changed".format(
        len(set(new_arts) - set(old_arts))))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
