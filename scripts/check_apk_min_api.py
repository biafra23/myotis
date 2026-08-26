#!/usr/bin/env python3
"""Fail if the APK references java.*/javax.* APIs newer than minSdk.

The dex files in a built APK are the post-desugaring ground truth: everything
D8 backports or desugar_jdk_libs rewrites is already gone, so any remaining
reference to a java.* / javax.* method or field whose `since` in the SDK's
api-versions.xml is above minSdk WILL throw NoSuchMethod/FieldError the first
time it executes on a device running that API level (Android 10/11 never get
ART module updates, so there is no backport safety net there).

Two failure modes source-level checks miss are covered here:
  * calls that reach a JDK method through a THIRD-PARTY SUBCLASS — e.g.
    `snappyIn.readAllBytes()` where the receiver type is snappy's stream class:
    the dex owner is the subclass, so the checker walks the app's own class
    hierarchy (parsed from the same dexdump output) up into java.* and resolves
    the member there;
  * everything in third-party bytecode, which no source lint ever sees.

This is the enforcement for the "minSdk 29 JDK-API budget" rule in CLAUDE.md.
Known third-party residue lives in the allowlist next to this script, each
entry with its reviewed rationale; a first-party violation never belongs there.

android.* framework APIs are deliberately OUT of scope: those are routinely
guarded with Build.VERSION.SDK_INT checks that a bytecode scan cannot see —
Android lint's NewApi check owns that side. Note also that api-versions.xml
has gaps (e.g. no entry at all for Files.readString) — a member this script
cannot resolve is skipped, so the scan is sound only for APIs the database
actually records.

Usage:
  python3 scripts/check_apk_min_api.py --apk path/to/app.apk \
      [--min-api 29] [--allowlist scripts/min-api-allowlist.txt] [--sdk <dir>]

Needs: an Android SDK with at least one platforms/android-N/data/api-versions.xml
and one build-tools/*/dexdump (any recent version of either).
Exit codes: 0 clean, 1 new violations, 2 environment/usage error.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict


def find_sdk(explicit):
    candidates = [explicit, os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    lp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "local.properties")
    if os.path.exists(lp):
        for line in open(lp):
            if line.startswith("sdk.dir="):
                candidates.append(line.split("=", 1)[1].strip())
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    sys.exit("error: Android SDK not found (pass --sdk or set ANDROID_HOME)")


def newest(dirpath, pattern):
    if not os.path.isdir(dirpath):
        return None
    best, best_key = None, ()
    for name in os.listdir(dirpath):
        if re.fullmatch(pattern, name):
            key = tuple(int(x) for x in re.findall(r"\d+", name))
            if key > best_key:
                best, best_key = name, key
    return os.path.join(dirpath, best) if best else None


def load_api_versions(sdk):
    plat = newest(os.path.join(sdk, "platforms"), r"android-\d+")
    xml = plat and os.path.join(plat, "data", "api-versions.xml")
    if not xml or not os.path.exists(xml):
        sys.exit("error: no platforms/android-N/data/api-versions.xml in SDK")
    classes = {}
    for c in ET.parse(xml).getroot().iter("class"):
        since = int(c.get("since", "1"))
        supers, methods, fields = [], {}, {}
        for ch in c:
            if ch.tag in ("extends", "implements"):
                supers.append(ch.get("name"))
            elif ch.tag == "method":
                methods[ch.get("name")] = int(ch.get("since", str(since)))
            elif ch.tag == "field":
                fields[ch.get("name")] = int(ch.get("since", str(since)))
        classes[c.get("name")] = (since, supers, methods, fields)
    return classes


CLASS_RE = re.compile(r"Class descriptor\s*:\s*'L([\w/$\-]+);'")
SUPER_RE = re.compile(r"Superclass\s*:\s*'L([\w/$\-]+);'")
IFACE_RE = re.compile(r"^\s+#\d+\s+:\s+'L([\w/$\-]+);'")
DEF_NAME_RE = re.compile(r"^\s+name\s+:\s+'([^']+)'")
DEF_TYPE_RE = re.compile(r"^\s+type\s+:\s+'([^']+)'")
MEMBER_RE = re.compile(r" L([\w/$\-]+);\.([\w$<>-]+):(\S+?)(?:;)?\s*//\s*(method|field)@")


class DexModel:
    def __init__(self):
        self.supers = {}          # class -> [superclass + interfaces]
        self.defined = defaultdict(set)  # class -> {"name:type", ...}
        self.refs = set()         # (referrer, owner, member, kind)


def parse_dexdump(dexdump, dex_path, model):
    proc = subprocess.Popen([dexdump, "-d", dex_path], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, errors="replace")
    cur = "?"
    in_ifaces = False
    pending_name = None
    for line in proc.stdout:
        m = CLASS_RE.search(line)
        if m:
            cur, in_ifaces, pending_name = m.group(1), False, None
            model.supers.setdefault(cur, [])
            continue
        m = SUPER_RE.search(line)
        if m:
            model.supers[cur] = [m.group(1)] + model.supers.get(cur, [])
            continue
        if "Interfaces" in line and "-" in line:
            in_ifaces = True
            continue
        if in_ifaces:
            m = IFACE_RE.match(line)
            if m:
                model.supers.setdefault(cur, []).append(m.group(1))
                continue
            in_ifaces = False
        m = DEF_NAME_RE.match(line)
        if m:
            pending_name = m.group(1)
            continue
        m = DEF_TYPE_RE.match(line)
        if m and pending_name is not None:
            model.defined[cur].add(pending_name + ":" + m.group(1))
            pending_name = None
            continue
        if " L" not in line or "//" not in line:
            continue
        m = MEMBER_RE.search(line)
        if m:
            owner, name, desc, kind = m.groups()
            if kind == "method":
                # dexdump prints `.name:(args)ret // method@…`; the regex may have
                # eaten a trailing ';' of an object(-array) return type — restore it.
                ret = desc.split(")")[-1]
                member = name + desc + (";" if ret.lstrip("[").startswith("L") else "")
            else:
                member = name
            model.refs.add((cur, owner, member, kind))
    proc.wait()


def resolve_api(classes, owner, member, is_field):
    """Walk the api-versions hierarchy; lowest `since` declaring `member`, or None."""
    best, stack, seen = None, [owner], set()
    while stack:
        cn = stack.pop()
        if cn in seen:
            continue
        seen.add(cn)
        info = classes.get(cn)
        if not info:
            continue
        s = (info[3] if is_field else info[2]).get(member)
        if s is not None:
            best = s if best is None else min(best, s)
        stack.extend(info[1])
    return best


def member_defined(model, cn, member, is_method):
    if is_method:
        sig = member.split("(")[0] + ":(" + member.split("(", 1)[1]
        return sig in model.defined.get(cn, ())
    return any(e.startswith(member + ":") for e in model.defined.get(cn, ()))


def java_ancestors(model, owner, member, kind):
    """For a non-java owner: java/javax ancestors reachable WITHOUT passing a
    class that defines the member itself (an in-app definition handles the call)."""
    is_method = kind == "method"
    if member_defined(model, owner, member, is_method):
        return []
    out, stack, seen = [], list(model.supers.get(owner, [])), {owner}
    while stack:
        cn = stack.pop()
        if cn in seen:
            continue
        seen.add(cn)
        if cn.startswith("java/") or cn.startswith("javax/"):
            out.append(cn)
            continue
        if member_defined(model, cn, member, is_method):
            continue  # overridden inside the app — the call resolves there
        stack.extend(model.supers.get(cn, []))
    return out


def load_allowlist(path):
    entries = []
    if path and os.path.exists(path):
        for raw in open(path):
            # Full-line comments only: targets themselves contain '#'
            # (owner#member), so inline comments are not supported.
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            prefix, target = line.split(None, 1)
            entries.append((prefix, target.strip()))
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--min-api", type=int, default=29)
    ap.add_argument("--allowlist", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                        "min-api-allowlist.txt"))
    ap.add_argument("--sdk")
    args = ap.parse_args()

    sdk = find_sdk(args.sdk)
    bt = newest(os.path.join(sdk, "build-tools"), r"\d+\.\d+\.\d+(-rc\d+)?")
    dexdump = bt and os.path.join(bt, "dexdump")
    if not dexdump or not os.path.exists(dexdump):
        sys.exit("error: no build-tools/*/dexdump in SDK")
    classes = load_api_versions(sdk)
    allow = load_allowlist(args.allowlist)

    model = DexModel()
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(args.apk) as z:
            dexes = [n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
            if not dexes:
                sys.exit(f"error: no classes*.dex in {args.apk}")
            for n in dexes:
                z.extract(n, tmp)
                parse_dexdump(dexdump, os.path.join(tmp, n), model)

    violations = {}
    for referrer, owner, member, kind in model.refs:
        is_field = kind == "field"
        if owner.startswith("java/") or owner.startswith("javax/"):
            since = resolve_api(classes, owner, member, is_field)
            if since is not None and since > args.min_api:
                violations[(referrer, f"{owner}#{member}")] = since
        else:
            # A subclass-owned ref may still bind to an inherited JDK member.
            for anc in java_ancestors(model, owner, member, kind):
                since = resolve_api(classes, anc, member, is_field)
                if since is not None and since > args.min_api:
                    violations[(referrer, f"{owner}#{member} (inherited from {anc})")] = since
                    break

    used_allow = set()
    new = defaultdict(list)
    for (ref, target), since in sorted(violations.items()):
        for i, (prefix, atarget) in enumerate(allow):
            if ref.startswith(prefix) and target == atarget:
                used_allow.add(i)
                break
        else:
            new[target, since].append(ref)

    for i, (prefix, target) in enumerate(allow):
        if i not in used_allow:
            print(f"note: stale allowlist entry (no longer referenced): {prefix} {target}")

    if new:
        print(f"\nFAIL: references to java/javax APIs above API {args.min_api} "
              f"that neither D8 backports nor desugar_jdk_libs cover:\n")
        for (target, since), refs in sorted(new.items()):
            print(f"  API {since}: {target}")
            for ref in sorted(set(refs)):
                print(f"      referenced from {ref}")
        print(f"\nThese crash at runtime on devices below that API level (minSdk is "
              f"{args.min_api}). Fix the call (see the minSdk API budget in CLAUDE.md "
              f"— core Futures/Hex/BigIntegers, Paths.get, manual stream drains), or, "
              f"for a reviewed third-party case, add an entry to {args.allowlist}.")
        sys.exit(1)
    print(f"OK: no unexpected java/javax references above API {args.min_api} "
          f"({len(violations)} allowlisted third-party refs)")


if __name__ == "__main__":
    main()
