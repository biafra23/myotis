#!/usr/bin/env python3
"""Refuse a gradle/verification-metadata.xml change that is not purely additive.

    check_pins_additive.py OLD.xml NEW.xml

Used by .github/workflows/gradle-pins-dependabot.yml (#734) before it commits
pins that an UNTRUSTED job produced (that job ran the bumped plugins' code).
A dependency bump only ever needs NEW entries: hashes for artifacts the new
versions bring. So the new file must

  * keep the <configuration> block exactly (verify-metadata, verify-signatures,
    trusted artifacts and keys): a bump never needs to loosen verification;
  * keep every existing artifact with exactly the checksums it had: a bump never
    needs to re-hash a version that was already pinned.

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
    """(group, name, version, artifact) -> frozenset of (algorithm, value)."""
    out = {}
    for comp in root.iter(NS + "component"):
        key = (comp.get("group"), comp.get("name"), comp.get("version"))
        for art in comp.findall(NS + "artifact"):
            sums = frozenset(
                (child.tag[len(NS):], child.get("value"))
                for child in art
                if child.get("value") is not None
            )
            out[key + (art.get("name"),)] = sums
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
    for key, sums in sorted(old_arts.items()):
        label = "{}:{}:{} {}".format(*key)
        if key not in new_arts:
            problems.append("pinned artifact removed: " + label)
        elif new_arts[key] != sums:
            problems.append("pinned checksum changed: " + label)

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
