#!/usr/bin/env python3
"""Regenerate starter/ from solution/: every block between `//@begin` and `//@end`
becomes `todo!("your code here")` at the block's indentation. Edit only solution/,
then run this. `--check` fails if starter/ is out of date (nothing is written)."""
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOL, START = os.path.join(HERE, "solution"), os.path.join(HERE, "starter")
BLOCK = re.compile(r"^([ \t]*)//@begin\n.*?^[ \t]*//@end\n", re.S | re.M)


def starter_text(text):
    return BLOCK.sub(lambda m: f'{m.group(1)}todo!("your code here")\n', text)


def main():
    check = "--check" in sys.argv
    stale = []
    for name in sorted(os.listdir(os.path.join(SOL, "src"))):
        want = starter_text(open(os.path.join(SOL, "src", name), encoding="utf-8").read())
        path = os.path.join(START, "src", name)
        have = open(path, encoding="utf-8").read() if os.path.exists(path) else None
        if have != want:
            stale.append(name)
            if not check:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "w", encoding="utf-8").write(want)
    wanted = set(os.listdir(os.path.join(SOL, "src")))
    for name in sorted(set(os.listdir(os.path.join(START, "src"))) - wanted):
        stale.append(name + " (no longer in solution/)")
        if not check:
            os.remove(os.path.join(START, "src", name))
    for f in ("Cargo.toml", "Cargo.lock"):
        same = os.path.exists(os.path.join(START, f)) and \
            open(os.path.join(SOL, f), "rb").read() == open(os.path.join(START, f), "rb").read()
        if not same:
            stale.append(f)
            if not check:
                shutil.copyfile(os.path.join(SOL, f), os.path.join(START, f))
    if check and stale:
        sys.exit(f"starter/ is out of date for: {', '.join(stale)} (run make_starter.py)")
    print("starter/ " + ("is up to date" if not stale else f"rewritten: {', '.join(stale)}"))


if __name__ == "__main__":
    main()
