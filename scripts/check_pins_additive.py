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
pinned hash replaced) exits 1 and names the change.

Before comparing, both files must have exactly the SHAPE this script models,
because Gradle reads more than that: its reader goes by element name with
namespaces off, keeps no "configuration already seen" state, and accepts a
second checksum of an artifact as an alternative. So a second <configuration>
block, an element outside the Gradle namespace, an <artifact> nested anywhere
but directly in a <component>, or a DOCTYPE would each pass a comparison that
only looks at the parts it knows. They are refused instead: the root holds one
<configuration> and one <components>, below <components> there is only
component > artifact > checksum (> also-trust), and every element is in the
Gradle namespace. Stdlib only; run with -I.
"""
import sys
import xml.etree.ElementTree as ET

NS = "{https://schema.gradle.org/dependency-verification}"
CHECKSUMS = {"md5", "sha1", "sha256", "sha512"}


def shape_problems(path, raw, root):
    """What makes this file a document the comparison below does not model."""
    out = []
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        out.append(f"{path}: has a DOCTYPE or an entity")
    for e in root.iter():
        if not isinstance(e.tag, str) or not e.tag.startswith(NS):
            out.append(f"{path}: element {e.tag!r} is not in the Gradle namespace")
    if out:
        return out
    if root.tag != NS + "verification-metadata":
        return [f"{path}: the root is not <verification-metadata>"]
    names = [c.tag[len(NS):] for c in root]
    if names != ["configuration", "components"]:
        out.append(f"{path}: the root holds {names}, not exactly one <configuration> and one <components>")
    for comps in root.findall(NS + "components"):
        for comp in comps:
            if comp.tag != NS + "component":
                out.append(f"{path}: <{comp.tag[len(NS):]}> directly under <components>")
                continue
            for art in comp:
                if art.tag != NS + "artifact":
                    out.append(f"{path}: <{art.tag[len(NS):]}> in component {comp.get('group')}:{comp.get('name')}")
                    continue
                for sumel in art:
                    kind = sumel.tag[len(NS):]
                    if kind not in CHECKSUMS:
                        out.append(f"{path}: <{kind}> in artifact {art.get('name')}")
                    for alt in sumel:
                        if alt.tag != NS + "also-trust" or len(alt):
                            out.append(f"{path}: <{alt.tag[len(NS):]}> inside a checksum of {art.get('name')}")
    return out


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
    problems = []
    roots = []
    for path in (old_path, new_path):
        with open(path, "rb") as f:
            raw = f.read()
        root = ET.fromstring(raw)
        problems += shape_problems(path, raw, root)
        roots.append(root)
    if problems:
        for p in problems:
            print("check_pins_additive: " + p, file=sys.stderr)
        return 1
    old, new = roots

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
