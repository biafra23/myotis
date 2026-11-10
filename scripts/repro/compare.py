#!/usr/bin/env python3
"""Compare two rebuild legs' artifact trees (#734, Part 5a).

    compare.py A_DIR B_DIR REPORT_DIR

Both trees come from scripts/repro/collect.sh, carried as tarballs (an
uploaded artifact keeps neither modes nor symlinks). The VERDICT is a SHA-256
manifest of every file (relative path, permission bits and hash) and every
symlink target: equal manifests pass, anything else fails, and the verdict
never depends on which tools happen to be installed. diffoscope only EXPLAINS a failure: for each file
that differs it writes REPORT_DIR/<path>.html (and a text summary), if
diffoscope is on PATH. REPORT_DIR always gets both manifests and summary.txt.
Stdlib only.
"""
import hashlib
import os
import shutil
import stat
import subprocess
import sys


MAX_EXPLAINED = 25
EXPLAIN_TIMEOUT = 600  # seconds per file


def manifest(root):
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
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


def write_manifest(entries, path):
    with open(path, "w") as f:
        for rel in sorted(entries):
            f.write(f"{entries[rel]}  {rel}\n")


def main(a, b, report):
    os.makedirs(report, exist_ok=True)
    ma, mb = manifest(a), manifest(b)
    if not ma or not mb:
        sys.exit(f"compare.py: an empty tree ({len(ma)} vs {len(mb)} files) is a failed leg, not a match")
    write_manifest(ma, os.path.join(report, "SHA256SUMS.a"))
    write_manifest(mb, os.path.join(report, "SHA256SUMS.b"))

    only_a = sorted(set(ma) - set(mb))
    only_b = sorted(set(mb) - set(ma))
    differ = sorted(r for r in set(ma) & set(mb) if ma[r] != mb[r])
    lines = [f"{len(ma)} files in leg a, {len(mb)} in leg b; "
             f"{len(differ)} differ, {len(only_a)} only in a, {len(only_b)} only in b"]
    lines += [f"ONLY IN A  {r}" for r in only_a]
    lines += [f"ONLY IN B  {r}" for r in only_b]
    lines += [f"DIFFERS    {r}" for r in differ]

    diffoscope = shutil.which("diffoscope")
    # One systematic leak can make hundreds of files differ: explain the first
    # MAX_EXPLAINED (the summary lists them all), each within a time limit.
    for n, rel in enumerate(differ):
        if diffoscope is None:
            break
        if n == MAX_EXPLAINED:
            lines.append(f"(diffoscope reports only the first {MAX_EXPLAINED} of {len(differ)} differing files)")
            break
        out = os.path.join(report, rel + ".html")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        # Exit 1 means "differences found", which is the expected case here.
        try:
            r = subprocess.run([diffoscope, "--html", out, "--text", out[:-5] + ".txt",
                                "--max-report-size", str(50 << 20),
                                os.path.join(a, rel), os.path.join(b, rel)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                               timeout=EXPLAIN_TIMEOUT)
        except subprocess.TimeoutExpired:
            lines.append(f"  (diffoscope timed out after {EXPLAIN_TIMEOUT}s on {rel})")
            continue
        if r.returncode not in (0, 1):
            lines.append(f"  (diffoscope failed on {rel}: {r.stderr.strip()[-300:]})")
    if differ and diffoscope is None:
        lines.append("(diffoscope not installed: no per-file report)")

    summary = "\n".join(lines) + "\n"
    with open(os.path.join(report, "summary.txt"), "w") as f:
        f.write(summary)
    print(summary, end="")
    if only_a or only_b or differ:
        sys.exit(1)
    print("all artifacts are identical across the two builds")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
