#!/usr/bin/env python3
"""Compare two rebuild legs' artifact trees (#734, Part 5a).

    compare.py A_DIR B_DIR REPORT_DIR [KNOWN_DIFFERENCES] [--gate GLOB]... [--no-gate GLOB]...
               [--report-only] [--labels FIRST SECOND]

Both trees come from scripts/repro/collect.sh, carried as tarballs (an
uploaded artifact keeps neither modes nor symlinks). The VERDICT is a SHA-256
manifest of every file (relative path, permission bits and hash) and every
symlink target: equal manifests pass, anything else fails, and the verdict
never depends on which tools happen to be installed. diffoscope only EXPLAINS a failure: for each file
that differs it writes REPORT_DIR/<path>.html (and a text summary), if
diffoscope is on PATH. REPORT_DIR always gets both manifests and summary.txt.

KNOWN_DIFFERENCES (scripts/repro/known-differences.txt) lists paths, as
globs, that are known not to reproduce yet, each with its reason: a matching
difference is reported as KNOWN and does not fail; anything else still does.
A listed pattern that no longer matches any difference is reported, so the
list shrinks as fixes land instead of hiding new regressions.

--gate GLOB (repeatable) limits what FAILS to the matching paths: every other
difference is still listed, marked "(not gated)", and does not fail. Without
--gate everything is gated. --no-gate GLOB takes matching paths back out of
the gate (it wins over --gate): for a comparison whose two sides are not
expected to agree on them. --labels names the two legs in the output (default
a and b). --report-only gates nothing (a platform whose
artifacts are compared and reported but not yet held to reproducibility).
reproducible-builds.yml gates everything in its three a-against-b comparisons
(owner's decisions: Android first, 2026-11-10; all of it, 2026-11-11) and
reports the two that have another second side.
Stdlib only.
"""
import fnmatch
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import time


MAX_EXPLAINED = 25
EXPLAIN_TIMEOUT = 600  # seconds per file
EXPLAIN_BUDGET = 30 * 60  # seconds for all of them: the job's timeout is 90 min


def manifest(root):
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        # Directories too: their modes ship in a .app, and an empty directory
        # present in one leg only must not pass unseen.
        if dirpath != root:
            rel = os.path.relpath(dirpath, root).replace(os.sep, "/") + "/"
            entries[rel] = f"dir {stat.S_IMODE(os.lstat(dirpath).st_mode):04o}"
        for name in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if os.path.islink(path):
                entries[rel] = "symlink:" + os.readlink(path)
            else:
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                # The mode too: a .app's files ship with theirs, and leg b builds
                # under another umask to catch exactly that leak.
                entries[rel] = f"{h.hexdigest()} {stat.S_IMODE(os.lstat(path).st_mode):04o}"
    return entries


def write_summary(report, lines):
    summary = "\n".join(lines) + "\n"
    with open(os.path.join(report, "summary.txt"), "w") as f:
        f.write(summary)
    return summary


def write_manifest(entries, path):
    with open(path, "w") as f:
        for rel in sorted(entries):
            f.write(f"{entries[rel]}  {rel}\n")


def load_known(path):
    known = []
    if path:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.strip() and not line.lstrip().startswith("#"):
                    pattern, _, reason = line.partition("\t")
                    known.append((pattern.strip(), reason.strip() or "(no reason given)"))
    return known


def main(a, b, report, known_file=None, gates=None, report_only=False, no_gates=None, labels=("a", "b")):
    os.makedirs(report, exist_ok=True)
    ma, mb = manifest(a), manifest(b)
    if not ma or not mb:
        sys.exit(f"compare.py: an empty tree ({len(ma)} vs {len(mb)} files) is a failed leg, not a match")
    write_manifest(ma, os.path.join(report, "SHA256SUMS.a"))
    write_manifest(mb, os.path.join(report, "SHA256SUMS.b"))

    known = load_known(known_file)
    used = set()

    def reason(rel):
        for pattern, why in known:
            if fnmatch.fnmatchcase(rel, pattern):
                used.add(pattern)
                return why
        return None

    only_a = sorted(set(ma) - set(mb))
    only_b = sorted(set(mb) - set(ma))
    differ = sorted(r for r in set(ma) & set(mb) if ma[r] != mb[r])
    known_hits = {r: reason(r) for r in only_a + only_b + differ}
    known_hits = {r: why for r, why in known_hits.items() if why}
    only_a = [r for r in only_a if r not in known_hits]
    only_b = [r for r in only_b if r not in known_hits]
    unexplained = [r for r in differ if r not in known_hits]

    def gated(rel):
        if report_only or any(fnmatch.fnmatchcase(rel, g) for g in no_gates or ()):
            return False
        return not gates or any(fnmatch.fnmatchcase(rel, g) for g in gates)

    failing = [r for r in only_a + only_b + unexplained if gated(r)]
    mark = lambda r: "" if gated(r) else "  (not gated)"
    scope = ("nothing gated (report only)" if report_only
             else "gated: " + ", ".join(gates) if gates else "everything gated")
    if no_gates and not report_only:
        scope += " except " + ", ".join(no_gates)
    la, lb = labels
    lines = [f"{len(ma)} files in leg {la}, {len(mb)} in leg {lb}; "
             f"{len(unexplained)} differ, {len(only_a)} only in {la}, {len(only_b)} only in {lb}, "
             f"{len(known_hits)} known differences; {scope}; {len(failing)} failing"]
    lines += [f"ONLY IN {la.upper()}  {r}{mark(r)}" for r in only_a]
    lines += [f"ONLY IN {lb.upper()}  {r}{mark(r)}" for r in only_b]
    lines += [f"DIFFERS    {r}{mark(r)}" for r in unexplained]
    lines += [f"KNOWN      {r}: {why}" for r, why in sorted(known_hits.items())]
    # "No longer seen" only where the pattern applies to this platform's tree
    # (the .deb's entry means nothing to the Windows legs).
    present = set(ma) | set(mb)
    lines += [f"(known difference no longer seen, remove it: {p})" for p, _ in known
              if p not in used and any(fnmatch.fnmatchcase(r, p) for r in present)]

    # The verdict and the full list first, so a job killed while diffoscope
    # runs still ships them; rewritten below with diffoscope's notes.
    write_summary(report, lines)

    diffoscope = shutil.which("diffoscope")
    # One systematic leak can make hundreds of files differ: explain the first
    # MAX_EXPLAINED (the summary lists them all), each within a time limit, all
    # within EXPLAIN_BUDGET so the job ends inside its timeout.
    started = time.monotonic()
    # Failing differences first, then the other unexplained ones, then the
    # known ones, while time is left.
    queue = sorted(unexplained, key=lambda r: not gated(r)) + [r for r in differ if r in known_hits]
    for n, rel in enumerate(queue):
        if diffoscope is None:
            break
        if n == MAX_EXPLAINED or time.monotonic() - started > EXPLAIN_BUDGET:
            lines.append(f"(diffoscope explained only the first {n} of {len(differ)} differing files)")
            break
        out = os.path.join(report, rel + ".html")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        # Exit 1 means "differences found", which is the expected case here.
        try:
            r = subprocess.run([diffoscope, "--html", out, "--text", out[:-5] + ".txt",
                                "--max-report-size", str(50 << 20),
                                os.path.join(a, rel), os.path.join(b, rel)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                               timeout=min(EXPLAIN_TIMEOUT, max(1, EXPLAIN_BUDGET - (time.monotonic() - started))))
        except subprocess.TimeoutExpired:
            lines.append(f"  (diffoscope timed out after {EXPLAIN_TIMEOUT}s on {rel})")
            continue
        if r.returncode not in (0, 1):
            lines.append(f"  (diffoscope failed on {rel}: {r.stderr.strip()[-300:]})")
    if differ and diffoscope is None:
        lines.append("(diffoscope not installed: no per-file report)")

    print(write_summary(report, lines), end="")
    if failing:
        sys.exit(1)
    ungated = len(only_a) + len(only_b) + len(unexplained)
    if ungated:
        print(f"the gated artifacts reproduce; {ungated} difference(s) outside the gate (reported above, not failing)")
    elif known_hits:
        print(f"no unexplained differences; {len(known_hits)} known (listed above with their reasons)")
    else:
        print("all artifacts are identical across the two builds")


if __name__ == "__main__":
    args, gates, no_gates, report_only, labels = [], [], [], False, ("a", "b")
    it = iter(sys.argv[1:])
    for arg in it:
        if arg == "--gate":
            gates.append(next(it, None) or sys.exit("compare.py: --gate needs a glob"))
        elif arg == "--no-gate":
            no_gates.append(next(it, None) or sys.exit("compare.py: --no-gate needs a glob"))
        elif arg == "--report-only":
            report_only = True
        elif arg == "--labels":
            labels = (next(it, None), next(it, None))
            all(labels) or sys.exit("compare.py: --labels needs two names")
        else:
            args.append(arg)
    if len(args) not in (3, 4):
        sys.exit(__doc__)
    main(*args, gates=gates or None, report_only=report_only, no_gates=no_gates or None, labels=labels)
