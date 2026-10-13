#!/usr/bin/env python3
"""Top up the PoC log-index seeds to the nodes' finalized blocks, for a release.

DEBUG / DEMO ONLY — NOT A PRODUCTION DATA PATH. Each seed is a full node's
``eth_getLogs`` output, unverified (no receipt-root proof); see
docs/railgun-poc.md and docs/bee-rpc-service.md.

Every release ships the Bee PoC and RAILGUN PoC dmgs, and a seed is usable for
500,000 blocks above its top (``MAX_GAP``, el/reader.rs): ~29 days on Gnosis,
~69 on mainnet and Sepolia. So every release refreshes all three (CLAUDE.md,
*Releases*, step 5):

    bee-gnosis       data/bee/gnosis/ in this checkout — commit the result in the
                     release PR; the Bee PoC leg of desktop-dmg.yml frames it
    railgun-mainnet  railgun-seed.tar.gz (+ .sha256) on the railgun-seed release,
                     which railgun-dmg.yml downloads on every build
    railgun-sepolia  railgun-seed-sepolia.tar.gz (+ .sha256), same release

    scripts/refresh_poc_seeds.py                     # all three
    scripts/refresh_poc_seeds.py --seed bee-gnosis   # just one (repeatable)
    scripts/refresh_poc_seeds.py --no-publish        # build the RAILGUN archives, leave the release alone

INCREMENTAL. Finalized history cannot change, so a refresh fetches only the
blocks above a seed's current top and appends their logs; the low edge never
moves (``LogIndex::merge`` drops a span that does not reach the old low). The
Bee seed's new logs go in as one more gzip MEMBER: every byte already committed
stays as it is, so git stores the refresh as a delta about the size of the new
data instead of another full copy of the file.

Nothing is replaced until the result has passed every check: the node is on the
seed's chain (its hash at the seed's top matches the seed's own), the new logs
all sit above the old top, the combined file has exactly the old count plus the
new, and it frames — with scripts/synth_logindex.py and the build's own
arguments — into the coverage the build will claim. A RAILGUN asset is uploaded
under a temporary name, checked against GitHub's own digest of it, and only
then swapped in, so the release never lacks an archive while a slow upload runs.

Runs where a synced full node per network answers JSON-RPC: zbox, whose geths
serve on loopback (Gnosis 8562, mainnet 8561, Sepolia 8560; ``--rpc`` overrides
them). That is also why this is a script and not a workflow: no GitHub runner
can reach those nodes, and they are the seeds' only source. Resumable — run it
again after an interruption and each delta fetch continues where it stopped.
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
BEE_DIR = REPO / "data" / "bee" / "gnosis"
RELEASE_TAG = "railgun-seed"
# The head bridge maps at most this many blocks above an imported file's top
# (MAX_GAP, rust/myotis-net/src/el/reader.rs); a seed older than that never catches up.
MAX_GAP = 500_000


@dataclass(frozen=True)
class Seed:
    name: str
    network: str
    chain_id: int
    address: str
    # The REAL deployment block — the watch entry app-desktop/build.gradle.kts frames with.
    deploy: int
    rpc: str
    # The JSONL's basename without extension; the meta is <stem>-<from>-<to>.meta.json.
    stem: str
    # The margin the build frames with: the Bee task keeps synth_logindex's default,
    # the RAILGUN task passes 0 for a meta whose toBlockTag is "finalized".
    finality_margin: int
    # The railgun-seed release asset, or None for the seed committed in the tree.
    asset: str | None = None
    # The paragraph of the release body that names this seed's range.
    body_label: str | None = None


SEEDS = {s.name: s for s in (
    Seed("bee-gnosis", "gnosis", 100, "0x45a1502382541cd610cc9068e88727426b696293", 31_305_656,
         "http://127.0.0.1:8562", "postagestamp-logs", 128),
    Seed("railgun-sepolia", "sepolia", 11_155_111, "0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea", 5_784_774,
         "http://127.0.0.1:8560", "railgun-logs", 0, "railgun-seed-sepolia.tar.gz", "Sepolia"),
    Seed("railgun-mainnet", "mainnet", 1, "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9", 14_737_691,
         "http://127.0.0.1:8561", "railgun-logs", 0, "railgun-seed.tar.gz", "Mainnet"),
)}


def die(msg):
    raise SystemExit(f"refresh_poc_seeds: {msg}")


def say(msg):
    print(f"==> {msg}", flush=True)


def rpc(url, method, params):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            body = json.load(r)
    except OSError as e:
        die(f"cannot reach {url} ({e}); is the node running?")
    if "error" in body:
        die(f"{url} {method}: {body['error'].get('message', 'rpc error')}")
    return body["result"]


def block(url, tag):
    b = rpc(url, "eth_getBlockByNumber", [tag, False])
    if b is None:
        die(f"{url} has no block {tag}")
    return b


def finalized(url):
    return int(block(url, "finalized")["number"], 16)


def sha256_file(path, opener=open):
    h = hashlib.sha256()
    with opener(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def opener_for(path):
    return gzip.open if str(path).endswith(".gz") else open


def block_of(line):
    return int(json.loads(line)["blockNumber"], 16)


def last_block(path):
    """The block of a JSONL's last log, or None for an empty file."""
    last = None
    with opener_for(path)(path, "rb") as f:
        if not str(path).endswith(".gz"):
            f.seek(max(0, f.seek(0, os.SEEK_END) - (1 << 20)))  # a plain file: read only its tail
        for line in f:
            if line.strip():
                last = line
    return None if last is None else block_of(last)


def run(cmd, capture=False, hide=None):
    """Run a step; `hide` drops output lines starting with it (a sub-script's own advice
    on what to run next, which this script does itself)."""
    cmd = [str(c) for c in cmd]
    print("    $ " + " ".join(cmd), flush=True)
    if hide:
        with subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE) as proc:
            for line in proc.stdout:
                if not line.startswith(hide):
                    print(line, end="", flush=True)
        r = subprocess.CompletedProcess(cmd, proc.returncode)
    else:
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE if capture else None)
    if r.returncode != 0:
        die(f"{Path(cmd[1]).name if cmd[0] == sys.executable else cmd[0]} failed (exit {r.returncode}); "
            f"nothing was replaced")
    return r.stdout


def gh_api(repo, method, path, payload=None):
    cmd = ["gh", "api", "-X", method, f"repos/{repo}/{path}"]
    if payload is not None:
        cmd += ["--input", "-"]
    r = subprocess.run(cmd, text=True, capture_output=True,
                       input=None if payload is None else json.dumps(payload))
    if r.returncode != 0:
        die(f"gh api -X {method} {path}: {r.stderr.strip() or r.stdout.strip()}")
    return json.loads(r.stdout) if r.stdout.strip() else None


def release(repo):
    return gh_api(repo, "GET", f"releases/tags/{RELEASE_TAG}")


def asset_named(rel, name):
    return next((a for a in rel["assets"] if a["name"] == name), None)


def asset_sha256(a):
    d = a.get("digest") or ""
    return d.removeprefix("sha256:") if d.startswith("sha256:") else None


# --------------------------------------------------------------------------- current seed


@dataclass
class Current:
    meta: dict
    meta_path: Path
    # The JSONL as the build reads it: .jsonl.gz in the tree, .jsonl from a release archive.
    logs: Path


def single_meta(directory, what):
    metas = sorted(directory.glob("*.meta.json"))
    if len(metas) != 1:
        die(f"{what}: expected exactly one *.meta.json in {directory}, found {[m.name for m in metas]}")
    return metas[0]


def current_from_tree(seed):
    meta_path = single_meta(BEE_DIR, seed.name)
    logs = meta_path.with_name(meta_path.name.removesuffix(".meta.json") + ".jsonl.gz")
    if not logs.is_file():
        die(f"{seed.name}: no {logs.name} beside {meta_path.name}")
    return Current(json.loads(meta_path.read_text()), meta_path, logs)


def finish_swap(seed, repo, rel):
    """A run that died between deleting an old asset and renaming its replacement leaves
    only `<name>.new`, which was verified against the local file BEFORE the delete
    (publish). Finish the rename rather than leave the release without the asset."""
    for name in (seed.asset, f"{seed.asset}.sha256"):
        pending = asset_named(rel, f"{name}.new")
        if asset_named(rel, name) is None and pending is not None:
            say(f"{seed.name}: finishing an interrupted swap: {name}.new -> {name}")
            gh_api(repo, "PATCH", f"releases/assets/{pending['id']}", {"name": name})
            rel = release(repo)
    return rel


def current_from_release(seed, repo, state):
    """The published archive, from the local copy when it is byte-identical to the asset."""
    a = asset_named(finish_swap(seed, repo, release(repo)), seed.asset)
    if a is None:
        die(f"{seed.name}: the {RELEASE_TAG} release has no {seed.asset}")
    want = asset_sha256(a)
    if want is None:
        die(f"{seed.name}: GitHub reports no digest for {seed.asset}; cannot tell whether a local copy is current")
    home = state / seed.name
    cache = home / seed.asset
    if cache.is_file() and sha256_file(cache) == want:
        print(f"    the published {seed.asset} is the local copy {cache}")
    else:
        say(f"{seed.name}: downloading {seed.asset} ({a['size']:,} bytes)")
        dl = home / "download"
        shutil.rmtree(dl, ignore_errors=True)
        dl.mkdir(parents=True)
        run(["gh", "release", "download", RELEASE_TAG, "-R", repo, "-p", seed.asset, "-D", dl])
        if sha256_file(dl / seed.asset) != want:
            die(f"{seed.name}: the downloaded {seed.asset} does not match GitHub's digest {want}")
        os.replace(dl / seed.asset, cache)
        dl.rmdir()
    cur = home / "current"
    shutil.rmtree(cur, ignore_errors=True)
    cur.mkdir(parents=True)
    with tarfile.open(cache) as t:
        if hasattr(tarfile, "data_filter"):
            t.extractall(cur, filter="data")
        else:  # Python < 3.12: the archive is our own, checked against GitHub's digest above
            t.extractall(cur)
    # The CI build accepts the pair flat or one directory down; so does this.
    metas = sorted(cur.glob("*.meta.json")) + sorted(cur.glob("*/*.meta.json"))
    if len(metas) != 1:
        die(f"{seed.name}: {seed.asset} holds {len(metas)} *.meta.json files, expected exactly one")
    logs = metas[0].with_name(f"{seed.stem}.jsonl")
    if not logs.is_file():
        die(f"{seed.name}: no {logs.name} beside {metas[0].name} in {seed.asset}")
    return Current(json.loads(metas[0].read_text()), metas[0], logs)


def check_current(seed, cur):
    m = cur.meta
    say(f"{seed.name}: checking {cur.logs.name} against {cur.meta_path.name}")
    if m.get("chainId") != seed.chain_id:
        die(f"{seed.name}: {cur.meta_path.name} is chain {m.get('chainId')}, expected {seed.chain_id}")
    if str(m["filter"]["address"]).lower() != seed.address:
        die(f"{seed.name}: {cur.meta_path.name} is a fetch of {m['filter']['address']}, not {seed.address}")
    # The RAILGUN seeds start AT the deployment block (docs/railgun-poc.md); Bee's starts
    # above it, where Bee's embedded snapshot ends. Either way the low edge never moves.
    if m["fromBlock"] < seed.deploy or (seed.asset and m["fromBlock"] != seed.deploy):
        die(f"{seed.name}: {cur.meta_path.name} starts at {m['fromBlock']}, not at the expected low edge")
    if sha256_file(cur.logs, opener_for(cur.logs)) != m["sha256Jsonl"]:
        die(f"{seed.name}: {cur.logs.name} does not match its meta's sha256Jsonl; it is not the fetch the meta describes")
    last = last_block(cur.logs)
    if last is not None and last > m["toBlock"]:
        die(f"{seed.name}: {cur.logs.name} holds a log at {last}, above its meta's toBlock {m['toBlock']}")
    print(f"    seed: {m['fromBlock']:,}..{m['toBlock']:,}, {m['logCount']:,} logs")


# --------------------------------------------------------------------------- refresh


def refresh(seed, cur, url, state):
    """Fetch the new blocks, build the combined seed and check it. Returns None when
    the seed is already at the node's finalized block, else what install needs."""
    m = cur.meta
    top, low = m["toBlock"], m["fromBlock"]
    chain = int(rpc(url, "eth_chainId", []), 16)
    if chain != seed.chain_id:
        die(f"{seed.name}: {url} is chain {chain}, not {seed.network}")
    # The delta continues the seed only if the node and the seed agree on the seed's top
    # block. A different hash there means another chain (or a fork the seed was fetched
    # on) and the new logs would be glued onto history the node does not have.
    if m.get("headHash"):
        node_hash = block(url, hex(top))["hash"]
        if node_hash.lower() != m["headHash"].lower():
            die(f"{seed.name}: the node's block {top} is {node_hash}, the seed's is {m['headHash']}")
    if m.get("genesisHash"):
        node_genesis = block(url, "0x0")["hash"]
        if node_genesis.lower() != m["genesisHash"].lower():
            die(f"{seed.name}: the node's genesis is {node_genesis}, the seed's is {m['genesisHash']}")

    work = state / seed.name / "work"
    work.mkdir(parents=True, exist_ok=True)
    delta = work / "delta.jsonl"
    progress = work / "delta.jsonl.progress.json"
    target = None
    if progress.is_file():
        p = json.loads(progress.read_text())
        if p.get("fromBlock") == top + 1:
            target = p["toBlock"]
            print(f"    resuming the delta {top + 1:,}..{target:,}")
        else:  # a delta for an older seed
            delta.unlink(missing_ok=True)
            progress.unlink()
    if target is None:
        target = finalized(url)
        if target <= top:
            say(f"{seed.name}: already at the node's finalized block {top:,}; nothing to do")
            return None

    say(f"{seed.name}: fetching blocks {top + 1:,}..{target:,} from {url}")
    run([sys.executable, SCRIPTS / "fetch_contract_logs.py", "--rpc", url, "--address", seed.address,
         "--from-block", top + 1, "--to-block", target, "--out", delta], hide="now run:")
    p = json.loads(progress.read_text())
    if p.get("next") != target + 1:
        die(f"{seed.name}: the delta fetch stopped at {p.get('next')}; run again to resume")
    delta_bytes = delta.read_bytes()
    blocks = [block_of(line) for line in delta_bytes.splitlines() if line.strip()]
    if not all(top < b <= target for b in blocks):
        die(f"{seed.name}: the delta holds logs outside {top + 1}..{target}")
    added = len(blocks)

    # write_logs_meta refuses a top above the node's CURRENT finalized block, which moves
    # backwards when the node's beacon client falls behind. Say so plainly; the delta is kept.
    now_final = finalized(url)
    if now_final < target:
        die(f"{seed.name}: the node's finalized block is now {now_final:,}, below the {target:,} this delta "
            f"was fetched to — its beacon client has fallen behind. Nothing was replaced and the fetched "
            f"blocks are kept: run again once the node is synced")

    say(f"{seed.name}: {added:,} new logs; building the combined seed")
    new = work / "new"
    shutil.rmtree(new, ignore_errors=True)
    new.mkdir()
    combined = new / f"{seed.stem}.jsonl"
    with opener_for(cur.logs)(cur.logs, "rb") as src, open(combined, "wb") as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
        dst.write(delta_bytes)
    new_meta = new / f"{seed.stem}-{low}-{target}.meta.json"
    run([sys.executable, SCRIPTS / "write_logs_meta.py", "--rpc", url, "--address", m["filter"]["address"],
         "--from-block", low, "--to-block", target, "--to-block-tag", "finalized",
         "--logs", combined, "--out", new_meta], capture=True)
    nm = json.loads(new_meta.read_text())
    if nm["logCount"] != m["logCount"] + added:
        die(f"{seed.name}: the combined seed has {nm['logCount']} logs, expected {m['logCount']} + {added}")
    if nm["genesisHash"].lower() != m["genesisHash"].lower():
        die(f"{seed.name}: the new meta's genesis disagrees with the seed's")
    low_key = f"block{low}Hash"
    if m.get(low_key) and nm[low_key].lower() != m[low_key].lower():
        die(f"{seed.name}: the node's block {low} disagrees with the seed's")

    if seed.asset is None:
        # Append the new logs as one more gzip member: the committed bytes stay byte-identical
        # (git deltas the refresh down to about the new data), and gzip readers — Python's,
        # zcat — read a multi-member file as the concatenation.
        logs_out = new / f"{seed.stem}-{low}-{target}.jsonl.gz"
        shutil.copyfile(cur.logs, logs_out)
        if delta_bytes:
            with open(logs_out, "ab") as f:
                f.write(gzip.compress(delta_bytes, compresslevel=9, mtime=0))
        if sha256_file(logs_out, gzip.open) != nm["sha256Jsonl"]:
            die(f"{seed.name}: {logs_out.name} does not decompress to the combined JSONL")
        combined.unlink()
    else:
        logs_out = combined

    # Frame it the way the build will, and check the frame claims exactly this seed.
    high = target - seed.finality_margin
    framed = new / "framed.db"
    cmd = [sys.executable, SCRIPTS / "synth_logindex.py", "--meta", new_meta, "--logs", logs_out,
           "--watch", f"{seed.address}:{seed.deploy}", "--network-id", seed.chain_id, "--out", framed]
    if seed.finality_margin == 0:
        cmd += ["--finality-margin", "0"]
    info = json.loads(run(cmd, capture=True))
    if seed.finality_margin == 0:
        expected_logs = nm["logCount"]
    else:
        with opener_for(logs_out)(logs_out, "rb") as f:
            expected_logs = sum(1 for line in f if line.strip() and block_of(line) <= high)
    want = {"network_id": seed.chain_id, "coverage": [[low, high]], "logs": expected_logs,
            "watch": [{"address": seed.address, "from_block": seed.deploy, "name": ""}]}
    got = {k: info.get(k) for k in want}
    if got != want:
        die(f"{seed.name}: the framed seed does not claim what it should:\n  got  {got}\n  want {want}")
    print(f"    frames as {low:,}..{high:,}, {expected_logs:,} logs: OK")
    return {"meta": nm, "meta_path": new_meta, "logs": logs_out, "framed": framed, "added": added,
            "high": high, "work": work, "delta": delta, "progress": progress}


# --------------------------------------------------------------------------- install


def install_tree(seed, cur, r):
    # New pair first, then the old one goes: a crash in between leaves two metas, which
    # the build refuses loudly rather than picking one.
    for src in (r["logs"], r["meta_path"]):
        shutil.copyfile(src, BEE_DIR / src.name)
    cur.logs.unlink()
    cur.meta_path.unlink()
    print(f"    {BEE_DIR.relative_to(REPO)}: {cur.logs.name} -> {r['logs'].name}")


def package_release(seed, r):
    new = r["logs"].parent
    archive = new / seed.asset
    run(["tar", "-czf", archive, "-C", new, r["logs"].name, r["meta_path"].name])
    # Read the archive back: it must hold exactly the pair, the JSONL byte for byte.
    with tarfile.open(archive) as t:
        names = sorted(t.getnames())
        if names != sorted([r["logs"].name, r["meta_path"].name]):
            die(f"{seed.name}: {seed.asset} holds {names}")
        h = hashlib.sha256()
        with t.extractfile(r["logs"].name) as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    if h.hexdigest() != r["meta"]["sha256Jsonl"]:
        die(f"{seed.name}: the JSONL inside {seed.asset} does not match its meta")
    sha = sha256_file(archive)
    sidecar = new / f"{seed.asset}.sha256"
    sidecar.write_text(f"{sha}  {seed.asset}\n")
    return archive, sidecar


def updated_body(body, label, meta):
    """The release body with this seed's range line rewritten, or None if it has none."""
    pattern = re.compile(r"to [\d,]+ \(finalized at fetch time\), [\d,]+ logs\. Fetched \d{4}-\d{2}-\d{2}")
    text = (f"to {meta['toBlock']:,} (finalized at fetch time), {meta['logCount']:,} logs. "
            f"Fetched {meta['fetchedAtUtc'][:10]}")
    lines, hit = body.split("\n"), False
    for i, line in enumerate(lines):
        if line.startswith(f"{label}:"):
            lines[i], n = pattern.subn(text, line, count=1)
            hit = hit or n == 1
    return "\n".join(lines) if hit else None


def publish(seed, repo, archive, sidecar, meta):
    pairs = [(archive, seed.asset), (sidecar, f"{seed.asset}.sha256")]
    rel = release(repo)
    for _, name in pairs:  # left behind by an interrupted run
        stale = asset_named(rel, f"{name}.new")
        if stale:
            gh_api(repo, "DELETE", f"releases/assets/{stale['id']}")
    upload = archive.parent / "upload"
    shutil.rmtree(upload, ignore_errors=True)
    upload.mkdir()
    staged = []
    for local, name in pairs:
        dst = upload / f"{name}.new"
        os.link(local, dst)
        staged.append(dst)
    say(f"{seed.name}: uploading {archive.stat().st_size:,} bytes as {seed.asset}.new "
        f"(the published asset stays in place until it is checked)")
    run(["gh", "release", "upload", RELEASE_TAG, "-R", repo, *staged])
    # GitHub may report an asset's digest a moment after the upload returns.
    for _ in range(12):
        rel = release(repo)
        if all(asset_sha256(asset_named(rel, f"{n}.new") or {}) for _, n in pairs):
            break
        time.sleep(5)
    fresh = {}
    for local, name in pairs:
        a = asset_named(rel, f"{name}.new")
        if a is None or a.get("state") != "uploaded" or a["size"] != local.stat().st_size \
                or asset_sha256(a) != sha256_file(local):
            die(f"{seed.name}: the uploaded {name}.new does not match the local file "
                f"(GitHub: {a and (a.get('state'), a['size'], a.get('digest'))}); the published asset is untouched")
        fresh[name] = a
    # The swap: a few seconds in which a build that fetches the archive and then the
    # sidecar can see a mismatched pair. It fails its checksum check loudly; never silently.
    # A run that dies between a delete and its rename is finished by the next run (finish_swap).
    for _, name in pairs:
        old = asset_named(rel, name)
        if old:
            gh_api(repo, "DELETE", f"releases/assets/{old['id']}")
        gh_api(repo, "PATCH", f"releases/assets/{fresh[name]['id']}", {"name": name})
    shutil.rmtree(upload)
    return rel


def update_release_body(seed, repo, rel, meta):
    body = updated_body(rel.get("body") or "", seed.body_label, meta)
    if body is None:
        print(f"    WARNING: no '{seed.body_label}: ... to N (finalized at fetch time), N logs. Fetched DATE' "
              f"line in the release body; update its {seed.network} range by hand")
    elif body != rel.get("body"):
        gh_api(repo, "PATCH", f"releases/{rel['id']}", {"body": body})
        print("    release body: range line updated")


def keep_published(seed, state, archive):
    """The published archive becomes the local copy the next run starts from; the one it
    replaced is kept until then, as the rollback."""
    home = state / seed.name
    previous = home / "previous"
    shutil.rmtree(previous, ignore_errors=True)
    previous.mkdir()
    if (home / seed.asset).is_file():
        os.replace(home / seed.asset, previous / seed.asset)
    os.replace(archive, home / seed.asset)
    shutil.rmtree(home / "current", ignore_errors=True)


# --------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", action="append", choices=list(SEEDS),
                    help="refresh only this seed (repeatable; default: all three)")
    ap.add_argument("--no-publish", action="store_true",
                    help="build and check the RAILGUN archives but do not touch the release "
                         "(the Bee seed is still written into the tree, where git shows the change)")
    ap.add_argument("--rpc", action="append", default=[], metavar="NETWORK=URL",
                    help="a network's JSON-RPC endpoint (default: zbox's loopback ports)")
    ap.add_argument("--state-dir", default="~/myotis-node/poc-seeds",
                    help="the published RAILGUN archives, the delta fetches and the scratch space "
                         "(default %(default)s; put a copy of a published archive at "
                         "<state-dir>/<seed>/<asset> to skip its download)")
    ap.add_argument("--github-repo", help="OWNER/REPO holding the railgun-seed release (default: this checkout's)")
    args = ap.parse_args()

    rpcs = {s.network: s.rpc for s in SEEDS.values()}
    for spec in args.rpc:
        net, sep, url = spec.partition("=")
        if not sep or net not in rpcs:
            die(f"--rpc expects NETWORK=URL with NETWORK one of {sorted(rpcs)}, got {spec!r}")
        rpcs[net] = url
    chosen = [SEEDS[n] for n in SEEDS if n in (args.seed or SEEDS)]
    state = Path(args.state_dir).expanduser()
    state.mkdir(parents=True, exist_ok=True)
    lock = open(state / ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        die(f"another refresh holds {state / '.lock'}")

    repo = None
    if any(s.asset for s in chosen):
        repo = args.github_repo or subprocess.run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            cwd=REPO, text=True, capture_output=True).stdout.strip()
        if not repo:
            die("cannot tell which GitHub repository holds the railgun-seed release; pass --github-repo")

    summary, published = [], False
    for seed in chosen:
        print(flush=True)
        cur = current_from_release(seed, repo, state) if seed.asset else current_from_tree(seed)
        check_current(seed, cur)
        r = refresh(seed, cur, rpcs[seed.network], state)
        if r is None:
            summary.append(f"{seed.name}: unchanged at {cur.meta['toBlock']:,}")
            continue
        old_top, m = cur.meta["toBlock"], r["meta"]
        line = (f"{seed.name}: {old_top:,} -> {m['toBlock']:,} (+{m['toBlock'] - old_top:,} blocks, "
                f"+{r['added']:,} logs, {m['logCount']:,} in all); usable until block {r['high'] + MAX_GAP:,}")
        if seed.asset is None:
            install_tree(seed, cur, r)
            line += f"\n    commit {BEE_DIR.relative_to(REPO)}/ in the release PR"
        else:
            archive, sidecar = package_release(seed, r)
            r["logs"].unlink()  # in the archive now; the mainnet one is ~600 MB
            if args.no_publish:
                line += f"\n    NOT published (--no-publish): {archive} and {sidecar.name}"
            else:
                rel = publish(seed, repo, archive, sidecar, m)
                keep_published(seed, state, archive)  # before anything else can fail
                update_release_body(seed, repo, rel, m)
                published = True
                line += f"\n    published to the {RELEASE_TAG} release as {seed.asset}"
        line += f"\n    framed index (importable in the app's Index tab): {r['framed']}"
        for f in (r["delta"], r["progress"]):
            f.unlink(missing_ok=True)
        summary.append(line)

    print("\n" + "\n".join(summary))
    if published:
        print("\nA tag's railgun-dmg build picks the new assets up; to refresh main's artifact now:\n"
              "    gh workflow run railgun-dmg.yml")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nrefresh_poc_seeds: interrupted; run it again to resume (nothing was replaced)")
