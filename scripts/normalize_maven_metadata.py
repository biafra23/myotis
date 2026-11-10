#!/usr/bin/env python3
"""Make a staged Maven repository's metadata deterministic (#734, Part 4b).

    normalize_maven_metadata.py REPO_DIR

Gradle writes every maven-metadata.xml with <lastUpdated> = the wall-clock time
of the publish, plus .md5/.sha1/.sha256/.sha512 sidecars of it, so the staged
repository (zipped as a release asset, pushed to the maven-repo branch) differed
between two builds of one tag even when every jar was identical. This sets each
<lastUpdated> to SOURCE_DATE_EPOCH (reproducible-builds.org), else the HEAD
commit time, and rewrites the sidecars that exist. Nothing else is touched: the
artifacts, their poms and modules are already deterministic. Stdlib only.
"""
import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SIDECARS = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


def epoch():
    sde = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not sde:
        sde = subprocess.run(["git", "log", "-1", "--format=%ct"], capture_output=True,
                             text=True, check=True).stdout.strip()
    if not sde.isdigit():
        sys.exit(f"normalize_maven_metadata: bad SOURCE_DATE_EPOCH {sde!r}")
    return int(sde)


def main(repo):
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(epoch()))
    files = sorted(Path(repo).rglob("maven-metadata.xml"))
    for meta in files:
        text = meta.read_text(encoding="utf-8")
        new, n = re.subn(r"<lastUpdated>\d{14}</lastUpdated>", f"<lastUpdated>{stamp}</lastUpdated>", text)
        if n != 1:
            sys.exit(f"normalize_maven_metadata: expected one <lastUpdated> in {meta}, found {n}")
        meta.write_text(new, encoding="utf-8")
        data = meta.read_bytes()
        for ext, algo in SIDECARS.items():
            side = meta.with_name(meta.name + "." + ext)
            if side.exists():
                side.write_text(algo(data).hexdigest(), encoding="ascii")
    print(f"normalize_maven_metadata: {len(files)} maven-metadata.xml set to lastUpdated {stamp}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
