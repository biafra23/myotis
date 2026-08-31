#!/usr/bin/env python3
"""Fail if the APK references java.*/javax.* APIs newer than minSdk.

The dex files in a built APK are the post-desugaring ground truth: everything
D8 backports or desugar_jdk_libs rewrites is already gone, so any remaining
reference to a java.* / javax.* class, method, or field whose `since` in the
SDK's api-versions.xml is above minSdk WILL throw NoClassDefFoundError /
NoSuchMethod/FieldError the first time it executes on a device running that
API level (Android 10/11 never get ART module updates, so there is no
backport safety net there).

Coverage that source-level checks miss:
  * calls that reach a JDK method through a THIRD-PARTY SUBCLASS — e.g.
    `snappyIn.readAllBytes()` where the receiver type is snappy's stream class:
    the dex owner is the subclass, so the checker walks the app's own class
    hierarchy (parsed from the same dexdump output) up into java.* and resolves
    the member there;
  * CLASS-level references — extends/implements of a java.* type, and
    checkcast/instanceof/const-class/new-instance type refs — which crash at
    class load/use even when no individual member is new; a member ref's OWNER
    class is checked too (a since-34 class can inherit a since-1 member);
  * everything in third-party bytecode, which no source lint ever sees.

This is the enforcement for the "minSdk 29 JDK-API budget" rule in CLAUDE.md.
Known third-party residue lives in the allowlist next to this script, each
entry with its reviewed rationale. A first-party referrer (com/jaeckel/*,
io/myotis/*) can NEVER be allowlisted: entries with such a prefix are refused,
and a first-party violation fails the gate even when an entry would match it.

android.* framework APIs are deliberately OUT of scope: those are routinely
guarded with Build.VERSION.SDK_INT checks that a bytecode scan cannot see —
Android lint's NewApi check owns that side.

Fail-closed design: a member this script cannot resolve in the database is
skipped (api-versions.xml only records the platform's own surface), so the
scan is sound only for APIs the database records — therefore the script
REFUSES to run when the database cannot resolve a canary set of known
post-29 APIs (an old SDK yields exit 2, never a vacuous OK), when dexdump
fails or yields no refs, or when most of the allowlist goes stale at once
(the signature of a dexdump output-format change).

Usage:
  python3 scripts/check_apk_min_api.py --apk path/to/app.apk \
      [--min-api N] [--allowlist scripts/min-api-allowlist.txt] [--sdk <dir>]

--min-api defaults to the APK's own manifest minSdkVersion (via aapt), so the
gate follows android-app/build.gradle.kts automatically; pass it explicitly
only to scan for a different floor. --allowlist must exist if passed
(/dev/null works for regenerating candidates); --sdk must be a directory.

Needs: an Android SDK with a platforms/android-N/data/api-versions.xml new
enough to know the canary APIs below, and build-tools (dexdump + aapt).
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
from concurrent.futures import ProcessPoolExecutor
from typing import NamedTuple

# Referrers under these prefixes are first-party: never allowlistable. Beyond
# the repo's own packages, this covers first-party code living under
# foreign-looking prefixes: the hand-written log4j shims in android-app
# (org.apache.logging.log4j.*) and the committed UniFFI-generated bindings in
# :myotis-engines (uniffi.myotis_engine.*) — for generated code the wanted
# remediation is fix/regenerate, never an allowlist entry.
FIRST_PARTY_PREFIXES = ("com/jaeckel/", "io/myotis/",
                        "org/apache/logging/log4j/", "uniffi/myotis_engine/")

# The database must resolve these, or the whole scan would be vacuously green
# exactly where it matters (each is an API this repo's budget polices; the
# last has no entry before the android-36.1 database).
DB_CANARIES = [
    ("java/util/HexFormat", "of()Ljava/util/HexFormat;", "method"),
    ("java/lang/Math", "unsignedMultiplyHigh(JJ)J", "method"),
    ("java/util/concurrent/CompletableFuture",
     "orTimeout(JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/CompletableFuture;", "method"),
    ("java/nio/file/Files", "readString(Ljava/nio/file/Path;)Ljava/lang/String;", "method"),
]


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def find_sdk(explicit):
    if explicit is not None:
        if not os.path.isdir(explicit):
            die(f"--sdk is not a directory: {explicit}")
        return explicit
    candidates = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    lp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "local.properties")
    if os.path.exists(lp):
        for line in open(lp):
            if line.startswith("sdk.dir="):
                candidates.append(line.split("=", 1)[1].strip())
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    die("Android SDK not found (pass --sdk or set ANDROID_HOME)")


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


def parse_level(s, default=None):
    """api-versions levels are usually ints but minor releases exist ("36.1")."""
    if s is None:
        return default
    return float(s) if "." in s else int(s)


def fmt_level(lv):
    return str(int(lv)) if float(lv).is_integer() else str(lv)


class ApiClass(NamedTuple):
    since: float
    supers: list
    methods: dict
    fields: dict


def parse_api_versions(xml):
    classes = {}
    for c in ET.parse(xml).getroot().iter("class"):
        since = parse_level(c.get("since"), 1)
        supers, methods, fields = [], {}, {}
        for ch in c:
            if ch.tag in ("extends", "implements"):
                supers.append(ch.get("name"))
            elif ch.tag == "method":
                methods[ch.get("name")] = parse_level(ch.get("since"), since)
            elif ch.tag == "field":
                fields[ch.get("name")] = parse_level(ch.get("since"), since)
        classes[c.get("name")] = ApiClass(since, supers, methods, fields)
    return classes


def load_api_versions(sdk):
    """The OLDEST installed platform database that resolves every canary.

    Oldest-passing, not newest-available: preview platforms (CI runners
    preinstall them) reshuffle `since` data — the android-37 preview records
    StringBuilder#getChars as since=37 where every stable database resolves it
    to 1, which made the gate report phantom violations. Canary coverage sets
    the floor (>= android-36.1); preferring the oldest passing database keeps
    the choice pinned to stable releases and identical across machines."""
    pdir = os.path.join(sdk, "platforms")
    if not os.path.isdir(pdir):
        die("no platforms/ directory in SDK")
    plats = sorted(
        (name for name in os.listdir(pdir) if re.fullmatch(r"android-\d+(\.\d+)?", name)),
        key=lambda n: tuple(int(x) for x in re.findall(r"\d+", n)))
    tried = []
    for name in plats:
        xml = os.path.join(pdir, name, "data", "api-versions.xml")
        if not os.path.exists(xml):
            continue
        tried.append(name)
        classes = parse_api_versions(xml)
        if all(resolve_api(classes, o, m, k == "field") is not None
               for o, m, k in DB_CANARIES):
            return classes
    die(f"no installed platform database resolves the canary APIs "
        f"(tried: {', '.join(tried) or 'none'}) — this gate needs "
        f"platforms;android-36.1 or newer stable (see DB_CANARIES in this script)")


CLASS_RE = re.compile(r"Class descriptor\s*:\s*'L([\w/$\-]+);'")
SUPER_RE = re.compile(r"Superclass\s*:\s*'L([\w/$\-]+);'")
IFACE_RE = re.compile(r"^\s+#\d+\s+:\s+'L([\w/$\-]+);'")
DEF_NAME_RE = re.compile(r"^\s+name\s+:\s+'([^']+)'")
DEF_TYPE_RE = re.compile(r"^\s+type\s+:\s+'([^']+)'")
MEMBER_RE = re.compile(r" L([\w/$\-]+);\.([\w$<>-]+):(\S+?)(?:;)?\s*//\s*(method|field)@")
TYPE_RE = re.compile(r" \[*L([\w/$\-]+);\s*//\s*type@")


class DexModel:
    def __init__(self):
        self.supers = {}          # class -> [superclass + interfaces]
        self.defined = defaultdict(set)   # class -> {"name:type", ...}
        self.defined_names = defaultdict(set)  # class -> {field/method name, ...}
        self.refs = set()         # (referrer, owner, member, kind); kind "class" => member ""

    def merge(self, other):
        self.supers.update(other.supers)
        for k, v in other.defined.items():
            self.defined[k] |= v
        for k, v in other.defined_names.items():
            self.defined_names[k] |= v
        self.refs |= other.refs


def parse_dexdump(dexdump, dex_path):
    model = DexModel()
    proc = subprocess.Popen([dexdump, "-d", dex_path], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, errors="replace")
    cur = "?"
    in_ifaces = False
    pending_name = None
    for line in proc.stdout:
        # Hot path first: the overwhelming majority of lines are instructions,
        # and only member/type refs among them matter.
        if "//" in line and " L" in line:
            m = MEMBER_RE.search(line)
            if m:
                owner, name, desc, kind = m.groups()
                if kind == "method":
                    # dexdump prints `.name:(args)ret // method@…`; the regex may
                    # have eaten a trailing ';' of an object(-array) return type.
                    ret = desc.split(")")[-1]
                    member = name + desc + (";" if ret.lstrip("[").startswith("L") else "")
                else:
                    member = name
                model.refs.add((cur, owner, member, kind))
                continue
            m = TYPE_RE.search(line)
            if m:
                model.refs.add((cur, m.group(1), "", "class"))
                continue
        if "Class descriptor" in line:
            m = CLASS_RE.search(line)
            if m:
                cur, in_ifaces, pending_name = m.group(1), False, None
                model.supers.setdefault(cur, [])
                continue
        if "Superclass" in line:
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
            model.defined_names[cur].add(pending_name)
            pending_name = None
            continue
    err = proc.stderr.read()
    if proc.wait() != 0:
        # RuntimeError, not die(): this runs in a pool worker, and SystemExit
        # does not cross the process boundary cleanly — main() converts it.
        raise RuntimeError(
            f"dexdump failed on {os.path.basename(dex_path)}: "
            f"{err.strip().splitlines()[-1] if err.strip() else 'exit ' + str(proc.returncode)}")
    # No per-dex minimum-yield check: a small trailing multidex file can
    # legitimately parse to almost nothing. Vacuity is judged on the MERGED
    # model in main() (plus the mass-stale-allowlist refusal).
    return model


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
        s = (info.fields if is_field else info.methods).get(member)
        if s is not None:
            best = s if best is None else min(best, s)
        stack.extend(info.supers)
    return best


def member_defined(model, cn, member, sig, is_method):
    if is_method:
        return sig in model.defined.get(cn, ())
    return member in model.defined_names.get(cn, ())


def java_ancestors(model, owner, member, kind):
    """For a non-java owner: java/javax ancestors reachable WITHOUT passing a
    class that defines the member itself (an in-app definition handles the call)."""
    is_method = kind == "method"
    sig = member.replace("(", ":(", 1) if is_method else None
    if member_defined(model, owner, member, sig, is_method):
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
        if member_defined(model, cn, member, sig, is_method):
            continue  # overridden inside the app — the call resolves there
        stack.extend(model.supers.get(cn, []))
    return out


def load_allowlist(path):
    if not path:
        return []
    if not os.path.exists(path):
        die(f"--allowlist file does not exist: {path} (use /dev/null to run bare)")
    entries = []
    for lineno, raw in enumerate(open(path), 1):
        # Full-line comments only: targets themselves contain '#'
        # (owner#member), so inline comments are not supported.
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            die(f"malformed allowlist line {lineno} (want '<referrer-prefix> "
                f"<owner#member>'): {line!r}")
        prefix, target = parts[0], parts[1].strip()
        # Historical entries carried a ' (inherited from X)' suffix; the named
        # ancestor is a traversal accident of the toolchain, so matching
        # ignores it (it still appears in failure output as a diagnostic).
        target = target.split(" (inherited from ", 1)[0]
        if prefix.startswith(FIRST_PARTY_PREFIXES):
            die(f"allowlist line {lineno} has a FIRST-PARTY prefix ({prefix}) — "
                f"first-party violations must be fixed, never allowlisted")
        entries.append((prefix, target))
    return entries


def apk_min_sdk(aapt, apk):
    if not aapt or not os.path.exists(aapt):
        die("no build-tools/*/aapt in SDK (needed to read the APK's minSdkVersion; "
            "or pass --min-api explicitly)")
    out = subprocess.run([aapt, "dump", "badging", apk], capture_output=True, text=True)
    m = re.search(r"sdkVersion:'(\d+)'", out.stdout)
    if out.returncode != 0 or not m:
        die(f"could not read minSdkVersion from {apk} via aapt "
            f"(pass --min-api explicitly): {out.stderr.strip()[:200]}")
    return int(m.group(1))


def _parse_one(dexdump_and_path):
    return parse_dexdump(*dexdump_and_path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--min-api", type=int, default=None,
                    help="default: the APK manifest's own minSdkVersion")
    ap.add_argument("--allowlist", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                        "min-api-allowlist.txt"))
    ap.add_argument("--sdk")
    args = ap.parse_args()

    sdk = find_sdk(args.sdk)
    bt = newest(os.path.join(sdk, "build-tools"), r"\d+\.\d+\.\d+(-rc\d+)?")
    dexdump = bt and os.path.join(bt, "dexdump")
    if not dexdump or not os.path.exists(dexdump):
        die("no build-tools/*/dexdump in SDK")
    classes = load_api_versions(sdk)
    allow = load_allowlist(args.allowlist)
    min_api = args.min_api if args.min_api is not None \
        else apk_min_sdk(os.path.join(bt, "aapt"), args.apk)

    model = DexModel()
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(args.apk) as z:
            dexes = [n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
            if not dexes:
                die(f"no classes*.dex in {args.apk}")
            paths = [z.extract(n, tmp) for n in dexes]
            # Dex files are independent (multidex partitions classes), so
            # disassembly — the dominant cost — parallelizes cleanly.
            try:
                with ProcessPoolExecutor() as pool:
                    for part in pool.map(_parse_one, [(dexdump, p) for p in paths]):
                        model.merge(part)
            except RuntimeError as e:
                die(str(e))
    if not model.refs or not model.supers:
        die("dexdump produced no usable output for any dex in the APK — "
            "output format drift? (the gate refuses to pass vacuously)")

    def class_since(cn):
        info = classes.get(cn)
        return info.since if info else None

    violations = {}

    def record(referrer, target, since):
        violations[(referrer, target)] = max(since, violations.get((referrer, target), 0))

    # Class-level: extends/implements of java.* types crash at class load.
    for cls, supers in model.supers.items():
        for sup in supers:
            if sup.startswith(("java/", "javax/")):
                s = class_since(sup)
                if s is not None and s > min_api:
                    record(cls, f"{sup}#<class>", s)

    resolve_cache = {}
    anc_cache = {}
    for referrer, owner, member, kind in model.refs:
        if kind == "class":
            if owner.startswith(("java/", "javax/")):
                s = class_since(owner)
                if s is not None and s > min_api:
                    record(referrer, f"{owner}#<class>", s)
            continue
        is_field = kind == "field"
        if owner.startswith(("java/", "javax/")):
            key = (owner, member, kind)
            if key not in resolve_cache:
                since = resolve_api(classes, owner, member, is_field)
                # Loading the owner class is a precondition of any member
                # access: a new class's inherited old member still crashes.
                cs = class_since(owner)
                if cs is not None and cs > min_api:
                    since = max(since or 0, cs)
                resolve_cache[key] = since
            since = resolve_cache[key]
            if since is not None and since > min_api:
                record(referrer, f"{owner}#{member}", since)
        else:
            # A subclass-owned ref may still bind to an inherited JDK member.
            key = (owner, member, kind)
            if key not in anc_cache:
                hit = None
                for anc in java_ancestors(model, owner, member, kind):
                    since = resolve_api(classes, anc, member, is_field)
                    if since is not None and since > min_api:
                        hit = (anc, since)
                        break
                anc_cache[key] = hit
            if anc_cache[key]:
                anc, since = anc_cache[key]
                record(referrer, f"{owner}#{member} (inherited from {anc})", since)

    def match_key(target):
        return target.split(" (inherited from ", 1)[0]

    used_allow = set()
    new = defaultdict(list)
    for (ref, target), since in sorted(violations.items()):
        if not ref.startswith(FIRST_PARTY_PREFIXES):
            for i, (prefix, atarget) in enumerate(allow):
                if ref.startswith(prefix) and match_key(target) == atarget:
                    used_allow.add(i)
                    break
            else:
                new[target, since].append(ref)
        else:
            new[target, since].append(ref)

    stale = [i for i in range(len(allow)) if i not in used_allow]
    for i in stale:
        print(f"note: stale allowlist entry (no longer referenced): {allow[i][0]} {allow[i][1]}")
    if allow and len(stale) > len(allow) // 2:
        die(f"{len(stale)} of {len(allow)} allowlist entries are stale at once — "
            f"that is the signature of a dexdump/api-versions format change, not "
            f"of real cleanups; refusing to trust this scan")

    if new:
        print(f"\nFAIL: references to java/javax APIs above API {min_api} "
              f"that neither D8 backports nor desugar_jdk_libs cover:\n")
        for (target, since), refs in sorted(new.items()):
            print(f"  API {fmt_level(since)}: {target}")
            for ref in sorted(refs):
                print(f"      referenced from {ref}")
        print(f"\nThese crash at runtime on devices below that API level (minSdk is "
              f"{min_api}). Fix the call (see the minSdk API budget in CLAUDE.md "
              f"— core Futures/Hex/BigIntegers, Paths.get, manual stream drains), or, "
              f"for a reviewed third-party case, add an entry to {args.allowlist}.")
        sys.exit(1)
    print(f"OK: no unexpected java/javax references above API {min_api} "
          f"({len(violations)} allowlisted third-party refs)")


if __name__ == "__main__":
    main()
