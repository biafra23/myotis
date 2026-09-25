#!/usr/bin/env python3
"""Synthesize a portable Myotis log-index snapshot (MLIX v2) from raw
``eth_getLogs`` output. DEBUG / DEMO ONLY — NOT A PRODUCTION DATA PATH.

The engine's own generator walks history over devp2p and verifies every log
against receipt roots (docs/eth-getlogs-design.md). This script does none of
that: it takes logs a full node returned over JSON-RPC and frames them in the
exact byte layout ``LogIndex::serialize_impl`` writes
(rust/myotis-net/src/el/logindex.rs), so the engine's portable import path
(``import-logindex <file>`` or the ``dataDir/logindex-<net>.db`` drop-in)
accepts it. The import path treats a file as "claimed verified by whoever
generated it" — this file claims exactly that, on the authority of the RPC
node it was fetched from, and the engine serves its logs indistinguishably
from walked ones. The repo rule (CLAUDE.md, Data sources): a local client
over http "may only be used for debugging purposes, it is not an option for
production". Use it to stand up a demo today; never ship its output as if it
were walked.

What the frame asserts, and how the flags keep it honest:

* ``--watch ADDR:DEPLOY_BLOCK`` — the entry's ``from_block``, which the engine
  treats as the contract's deployment block: it answers ``[]`` for anything
  below it WITHOUT consulting coverage (``LogIndex::query`` clamps the
  required range to it). So it must be the real deployment block (PostageStamp
  on Gnosis: 31,305,656), never the fetch's low edge — otherwise every query
  below the fetch gets a plausible-but-empty answer instead of the honest
  ``-32000`` refusal.
* ``--from-block/--to-block`` (or ``--meta``) — the range the fetch actually
  covered; it becomes the coverage span. Queries below it (down to the
  deployment block) are refused as out of coverage and the walker backfills
  them over devp2p in the background, verified.
* ``--finality-margin N`` (default 128 blocks ≈ 11 min on Gnosis) — the span
  high is ``to_block - N`` and logs above it are dropped: a fetch that ran to
  the node's ``latest`` may include blocks that were later reorged out, and
  the walker only fills holes, it never evicts a seeded log. The dropped band
  is re-fetched verified by the head bridge after import. Fetch to
  ``finalized`` and pass ``--finality-margin 0`` when you know the range is
  final.
* ``--meta FILE`` — the sidecar written next to the fetch (see
  data/bee/gnosis/*.meta.json): supplies chain id, genesis, address, range,
  and the sha256 of the uncompressed JSONL, and every one of them is checked
  against the flags and the input. Prefer it over typing the range by hand.
* Any log outside the declared range, for an unwatched address, with a
  conflicting duplicate key, or with two block hashes for one block is a
  hard error — the frame must never claim more than the input shows.

Shelf life: the engine's head bridge closes at most 500,000 blocks (~29 days
of Gnosis) above the file's top (``MAX_GAP`` in el/reader.rs); a seed older
than that imports fine and then never catches up. Re-seed by re-fetching from
the SAME low edge (``LogIndex::merge`` clamps to the lowest high and drops a
span that does not reach it), into a fresh index or one whose coverage already
reaches the new file's low.

Layout (all integers little-endian; see logindex.rs ``serialize_impl``):
  "MLIX" | u32 version=2 | u64 network_id | 32B genesis_hash |
  u64 config fingerprint | u64 FNV-1a checksum of everything after it |
  u32 n_watch | per entry: 20B address, u64 from_block, u32 n_topic0=0,
    u32 name_len=0 |
  u32 n_coverage (== n_watch, parallel) | per entry: 1 u64 low u64 high |
  cursor: 0 (the appender re-seeds the walker's trust edge itself) |
  u64 n_logs | per log: u64 block, 32B block_hash, 32B tx_hash, u32 tx_index,
    u32 log_index, 20B address, u32 n_topics, 32B each, u32 data_len + data

Example (the committed Bee demo seed):
  scripts/synth_logindex.py \
      --meta data/bee/gnosis/postagestamp-logs-47000000-48262804.meta.json \
      --logs data/bee/gnosis/postagestamp-logs-47000000-48262804.jsonl.gz \
      --watch 0x45a1502382541Cd610CC9068e88727426b696293:31305656 \
      --out /tmp/bee-logindex-gnosis-seed.db
  ./gradlew :app:run -Pnetwork=gnosis -Pargs="import-logindex /tmp/bee-logindex-gnosis-seed.db"

``--check FILE`` parses an existing snapshot with the same strictness as the
engine's loader and prints its header, watch table, coverage and log count.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b"MLIX"
VERSION = 2
V2_CHECKSUM_AT = 56  # magic(4) + version(4) + network_id(8) + genesis(32) + fingerprint(8)
FNV_OFFSET = 0xCBF2_9CE4_8422_2325
FNV_PRIME = 0x0000_0100_0000_01B3
MASK64 = (1 << 64) - 1
U32_MAX = (1 << 32) - 1

# The one chain whose genesis this script knows; any other --network-id must
# name its genesis explicitly (the engine compares both, so a mismatch is a
# refused import that names only the ids).
KNOWN_GENESIS = {100: "0x4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756"}


def die(msg: str) -> "NoReturn":  # noqa: F821 - typing.NoReturn without the import
    raise SystemExit(f"synth_logindex: error: {msg}")


def fnv64(data: bytes, h: int = FNV_OFFSET) -> int:
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return h


def config_fingerprint(watch: list[tuple[bytes, int]]) -> int:
    """FNV-1a over the SORTED entry encodings (address ‖ from_block LE ‖ the
    sorted topic0s, none here), each followed by a 0xff separator step —
    mirrors ``LogIndexConfig::fingerprint``."""
    encoded = sorted(address + struct.pack("<Q", from_block) for address, from_block in watch)
    h = FNV_OFFSET
    for e in encoded:
        h = fnv64(e, h)
        h ^= 0xFF
        h = (h * FNV_PRIME) & MASK64
    return h


def hex_bytes(s: object, n: int, what: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("0x"):
        die(f"{what}: expected a 0x-hex string, got {s!r}")
    try:
        b = bytes.fromhex(s[2:])
    except ValueError:
        die(f"{what}: not valid hex ({s})")
    if len(b) != n:
        die(f"{what}: expected {n} bytes, got {len(b)} ({s})")
    return b


def hex_data(s: object, what: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("0x"):
        die(f"{what}: expected a 0x-hex string, got {s!r}")
    try:
        return bytes.fromhex(s[2:])
    except ValueError:
        die(f"{what}: not valid hex (odd length or non-hex digit)")


def hex_quantity(s: object, what: str, max_value: int | None = None) -> int:
    if isinstance(s, bool) or not isinstance(s, (str, int)):
        die(f"{what}: expected a 0x-hex quantity, got {s!r}")
    if isinstance(s, str):
        if not s.startswith("0x"):
            die(f"{what}: expected a 0x-hex quantity, got {s!r}")
        try:
            v = int(s, 16)
        except ValueError:
            die(f"{what}: not a hex quantity ({s})")
    else:
        v = s
    if v < 0 or (max_value is not None and v > max_value):
        die(f"{what}: {v} is out of range (max {max_value})")
    return v


def parse_watch(spec: str) -> tuple[bytes, int]:
    addr, sep, deploy = spec.rpartition(":")
    if not sep or not deploy.isdigit():
        raise argparse.ArgumentTypeError(f"expected ADDR:DEPLOY_BLOCK, got {spec!r}")
    return hex_bytes(addr, 20, "--watch address"), int(deploy)


def read_logs(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                die(f"{path}:{lineno}: bad JSON ({e})")
            if not isinstance(obj, dict):
                die(f"{path}:{lineno}: expected a JSON object per line")
            yield f"{path}:{lineno}", obj


def sha256_of_uncompressed(path: Path) -> str:
    opener = gzip.open if path.suffix == ".gz" else open
    h = hashlib.sha256()
    with opener(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_meta(path: Path) -> dict:
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        die(f"--meta {path}: {e}")
    for key in ("chainId", "genesisHash", "fromBlock", "toBlock", "sha256Jsonl", "filter"):
        if key not in meta:
            die(f"--meta {path}: missing {key!r}")
    if not isinstance(meta["filter"], dict):
        die(f"--meta {path}: filter must be an object")
    for key in ("address", "fromBlock", "toBlock"):
        if key not in meta["filter"]:
            die(f"--meta {path}: filter.{key} missing")
    # The sidecar states the range twice — the top-level ints that become the
    # coverage claim and the hex range actually sent to eth_getLogs. They must
    # agree: a slip between them would claim coverage over blocks the fetch
    # never queried, and an empty phantom band is indistinguishable from a
    # genuinely empty one.
    for key in ("fromBlock", "toBlock"):
        sent = hex_quantity(meta["filter"][key], f"--meta filter.{key}")
        if sent != meta[key]:
            die(f"--meta {path}: {key} {meta[key]} disagrees with filter.{key} {sent} (the range actually fetched)")
    return meta


def put_bytes(out: bytearray, b: bytes) -> None:
    out += struct.pack("<I", len(b)) + b


def build(args) -> tuple[bytes, dict]:
    watch = args.watch
    deploy_by_addr: dict[bytes, int] = {}
    for address, deploy in watch:
        if address in deploy_by_addr:
            die(f"--watch: duplicate address 0x{address.hex()}")
        deploy_by_addr[address] = deploy

    # The fetched range: --meta is authoritative when given, and every flag
    # that overlaps it must agree — a frame's coverage is a claim about what
    # the input holds, so it comes from the fetch, not from the keyboard.
    meta = load_meta(Path(args.meta)) if args.meta else None
    if meta is not None:
        if len(args.logs) != 1:
            die("--meta describes exactly one JSONL file; pass exactly one --logs with it")
        if args.network_id is not None and args.network_id != meta["chainId"]:
            die(f"--network-id {args.network_id} disagrees with meta chainId {meta['chainId']}")
        network_id = int(meta["chainId"])
        if args.genesis is not None and args.genesis.lower() != str(meta["genesisHash"]).lower():
            die("--genesis disagrees with meta genesisHash")
        genesis = str(meta["genesisHash"])
        if args.from_block is not None and args.from_block != meta["fromBlock"]:
            die(f"--from-block {args.from_block} disagrees with meta fromBlock {meta['fromBlock']}")
        if args.to_block is not None and args.to_block != meta["toBlock"]:
            die(f"--to-block {args.to_block} disagrees with meta toBlock {meta['toBlock']}")
        from_block, to_block = int(meta["fromBlock"]), int(meta["toBlock"])
        meta_address = hex_bytes(meta["filter"]["address"], 20, "meta filter.address")
        if set(deploy_by_addr) != {meta_address}:
            die(f"--watch must name exactly the meta filter address 0x{meta_address.hex()}")
        actual = sha256_of_uncompressed(Path(args.logs[0]))
        if actual != str(meta["sha256Jsonl"]).lower():
            die(f"sha256 of the uncompressed JSONL is {actual}, meta says {meta['sha256Jsonl']}")
    else:
        if args.from_block is None or args.to_block is None:
            die("--from-block and --to-block are required without --meta")
        if args.network_id is None:
            die("--network-id is required without --meta")
        network_id = args.network_id
        genesis = args.genesis or KNOWN_GENESIS.get(network_id)
        if genesis is None:
            die(f"--genesis is required for network id {network_id}")
        from_block, to_block = args.from_block, args.to_block
        if len(watch) > 1:
            # Logs can only ever show positive results: nothing in the input
            # distinguishes "queried and empty" from "never queried" for an
            # address, so this claim rests on the operator alone.
            print(
                "synth_logindex: warning: coverage will assert the fetch queried ALL "
                f"{len(watch)} watched addresses over {from_block}..{to_block}; the input "
                "cannot prove this — an address the fetch skipped would be served [] "
                "inside claimed coverage",
                file=sys.stderr,
            )
    if from_block > to_block:
        die(f"from-block {from_block} is above to-block {to_block}")
    for address, deploy in watch:
        if deploy > from_block:
            die(
                f"--watch 0x{address.hex()}:{deploy} puts the deployment block above the fetched "
                f"low edge {from_block}; below from_block the engine answers [] without "
                "consulting coverage, so this would hide the contract's earlier events"
            )
    if args.finality_margin < 0:
        die("--finality-margin must be >= 0")
    high = to_block - args.finality_margin
    if high < from_block:
        die(f"--finality-margin {args.finality_margin} leaves no span ({from_block}..{to_block})")

    logs: dict[tuple[int, int], tuple] = {}
    hashes_by_block: dict[int, bytes] = {}
    dropped_removed = 0
    dropped_margin = 0
    for path in args.logs:
        for where, obj in read_logs(Path(path)):
            if obj.get("removed"):
                dropped_removed += 1
                continue
            address = hex_bytes(obj.get("address"), 20, f"{where} address")
            if address not in deploy_by_addr:
                die(f"{where}: log for unwatched address 0x{address.hex()}")
            block = hex_quantity(obj.get("blockNumber"), f"{where} blockNumber")
            if block < from_block or block > to_block:
                die(f"{where}: block {block} is outside the declared fetch range {from_block}..{to_block}")
            if block > high:
                dropped_margin += 1
                continue
            topics = [hex_bytes(t, 32, f"{where} topic") for t in obj.get("topics") or []]
            if len(topics) > 4:
                die(f"{where}: {len(topics)} topics (max 4)")
            rec = (
                block,
                hex_bytes(obj.get("blockHash"), 32, f"{where} blockHash"),
                hex_bytes(obj.get("transactionHash"), 32, f"{where} transactionHash"),
                hex_quantity(obj.get("transactionIndex"), f"{where} transactionIndex", U32_MAX),
                hex_quantity(obj.get("logIndex"), f"{where} logIndex", U32_MAX),
                address,
                topics,
                hex_data(obj.get("data", "0x"), f"{where} data"),
            )
            key = (block, rec[4])
            prev = logs.get(key)
            if prev is not None and prev != rec:
                die(f"{where}: conflicting duplicate for block {block} logIndex {rec[4]}")
            logs[key] = rec
            # One block hash per block — a mixed set means the input straddles
            # a reorg; refuse rather than frame it.
            if hashes_by_block.setdefault(block, rec[1]) != rec[1]:
                die(f"{where}: block {block} carries two different block hashes (reorg in input?)")

    out = bytearray()
    out += MAGIC
    out += struct.pack("<I", VERSION)
    out += struct.pack("<Q", network_id)
    out += hex_bytes(genesis, 32, "genesis")
    out += struct.pack("<Q", config_fingerprint(watch))
    assert len(out) == V2_CHECKSUM_AT
    out += b"\0" * 8  # checksum, patched below
    out += struct.pack("<I", len(watch))
    for address, deploy in watch:
        out += address
        out += struct.pack("<Q", deploy)
        out += struct.pack("<I", 0)  # no topic0 restriction
        put_bytes(out, b"")  # names are the importing wallet's job
    out += struct.pack("<I", len(watch))
    for _ in watch:
        out += b"\x01" + struct.pack("<QQ", from_block, high)
    out += b"\x00"  # no cursor: the appender re-seeds the trust edge on first append
    out += struct.pack("<Q", len(logs))
    for key in sorted(logs):
        block, bh, th, ti, li, address, topics, data = logs[key]
        out += struct.pack("<Q", block) + bh + th + struct.pack("<II", ti, li) + address
        out += struct.pack("<I", len(topics))
        for t in topics:
            out += t
        put_bytes(out, data)
    out[V2_CHECKSUM_AT:V2_CHECKSUM_AT + 8] = struct.pack("<Q", fnv64(out[V2_CHECKSUM_AT + 8:]))

    stats = {
        "logs_kept": len(logs),
        "dropped_removed": dropped_removed,
        "dropped_above_finality_margin": dropped_margin,
        "span": (from_block, high),
    }
    return bytes(out), stats


class Reader:
    def __init__(self, d: bytes):
        self.d, self.pos = d, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.d):
            raise ValueError(f"truncated at {self.pos}+{n} > {len(self.d)}")
        b = self.d[self.pos:self.pos + n]
        self.pos += n
        return b

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def flag(self, what: str) -> bool:
        b = self.take(1)[0]
        if b not in (0, 1):
            raise ValueError(f"{what}: flag byte {b} is neither 0 nor 1")
        return b == 1


def check(data: bytes) -> dict:
    """Parse a frame with the loader's strictness (magic, version, checksum,
    self-consistent fingerprint, parallel coverage, 0/1 flags, no trailing
    bytes). Raises ValueError on the first inconsistency."""
    r = Reader(data)
    if r.take(4) != MAGIC:
        raise ValueError("bad magic")
    version = r.u32()
    if version != VERSION:
        raise ValueError(f"unsupported version {version}")
    network_id = r.u64()
    genesis = r.take(32)
    fingerprint = r.u64()
    stored_sum = r.u64()
    if fnv64(data[V2_CHECKSUM_AT + 8:]) != stored_sum:
        raise ValueError("checksum mismatch")
    n_watch = r.u32()
    watch = []
    for _ in range(n_watch):
        address = r.take(20)
        from_block = r.u64()
        topic0s = [r.take(32) for _ in range(r.u32())]
        name = r.take(r.u32())
        watch.append((address, from_block, topic0s, name))
    if any(t for _, _, t, _ in watch):
        raise ValueError("topic0-restricted entries are not produced by this script")
    addresses = [a for a, _, _, _ in watch]
    if len(set(addresses)) != len(addresses):
        raise ValueError("duplicate watch address (LogIndex::new refuses it)")
    if config_fingerprint([(a, f) for a, f, _, _ in watch]) != fingerprint:
        raise ValueError("fingerprint does not match the watch table")
    n_cov = r.u32()
    if n_cov != n_watch:
        raise ValueError(f"coverage count {n_cov} != watch count {n_watch}")
    coverage = []
    for _ in range(n_cov):
        coverage.append((r.u64(), r.u64()) if r.flag("coverage") else None)
    cursor = (r.u64(), "0x" + r.take(32).hex()) if r.flag("cursor") else None
    n_logs = r.u64()
    lo = hi = None
    for _ in range(n_logs):
        block = r.u64()
        r.take(64)
        r.u32()
        r.u32()
        r.take(20)
        n_topics = r.u32()
        if n_topics > 4:
            raise ValueError(f"log at block {block} has {n_topics} topics (max 4; parse_body refuses it)")
        for _ in range(n_topics):
            r.take(32)
        r.take(r.u32())
        lo = block if lo is None else min(lo, block)
        hi = block if hi is None else max(hi, block)
    if r.pos != len(data):
        raise ValueError(f"trailing bytes: {len(data) - r.pos}")
    return {
        "network_id": network_id,
        "genesis": "0x" + genesis.hex(),
        "watch": [
            {"address": "0x" + a.hex(), "from_block": f, "name": n.decode(errors="replace")}
            for a, f, _, n in watch
        ],
        "coverage": coverage,
        "cursor": cursor,
        "logs": n_logs,
        "log_block_range": None if lo is None else (lo, hi),
        "bytes": len(data),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", metavar="FILE", help="parse and describe an existing snapshot, then exit")
    ap.add_argument("--logs", nargs="+", metavar="JSONL[.gz]", help="raw eth_getLogs output, one log per line")
    ap.add_argument("--meta", metavar="FILE", help="the fetch's sidecar .meta.json (chain, genesis, address, range, sha256) — checked against everything else")
    ap.add_argument("--watch", action="append", type=parse_watch, metavar="ADDR:DEPLOY_BLOCK", help="watched address and its REAL deployment block (repeatable)")
    ap.add_argument("--from-block", type=int, help="first block the fetch covered (required without --meta)")
    ap.add_argument("--to-block", type=int, help="last block the fetch covered (required without --meta)")
    ap.add_argument("--finality-margin", type=int, default=128, help="blocks dropped below --to-block so an unfinalized fetch head cannot seed orphaned logs (default 128; 0 when the fetch ran to finalized)")
    ap.add_argument("--network-id", type=int, help="EL network id (required without --meta; 100 = Gnosis)")
    ap.add_argument("--genesis", help="EL genesis block hash (known for network id 100; required for others)")
    ap.add_argument("--out", help="output snapshot path")
    ap.add_argument("--manifest", metavar="FILE", help="also write a Java-properties manifest describing the frame (coverage, usable-until block, sha256) — one --watch entry only")
    args = ap.parse_args()

    if args.check:
        try:
            info = check(Path(args.check).read_bytes())
        except (OSError, ValueError) as e:
            die(f"--check {args.check}: {e}")
        print(json.dumps(info, indent=2))
        return 0
    missing = [n for n in ("logs", "watch", "out") if not getattr(args, n)]
    if missing:
        ap.error("required: --" + ", --".join(missing))

    data, stats = build(args)
    try:
        info = check(data)  # our own frame must pass the loader's checks before it is written
    except ValueError as e:
        die(f"internal: the frame just built fails its own check: {e}")
    Path(args.out).write_bytes(data)
    print(
        f"wrote {args.out}: {info['bytes']} bytes, {stats['logs_kept']} logs, coverage {stats['span']} "
        f"(dropped: {stats['dropped_removed']} removed, {stats['dropped_above_finality_margin']} above the finality margin)",
        file=sys.stderr,
    )
    if args.manifest:
        if len(args.watch) != 1:
            die("--manifest describes exactly one watch entry; pass exactly one --watch with it")
        address, deploy = args.watch[0]
        low, high = stats["span"]
        # The engine's head bridge maps at most MAX_GAP = 500_000 blocks above a
        # file's top (el/reader.rs); beyond that a seed never catches up.
        lines = [
            "# Log-index seed manifest — written by scripts/synth_logindex.py (see docs/bee-rpc-service.md)",
            f"network={ {100: 'gnosis', 1: 'mainnet', 11155111: 'sepolia'}.get(info['network_id'], info['network_id']) }",
            f"address=0x{address.hex()}",
            f"deploymentBlock={deploy}",
            f"coveredLow={low}",
            f"coveredHigh={high}",
            f"usableUntilBlock={high + 500_000}",
            f"logs={stats['logs_kept']}",
            f"sha256={hashlib.sha256(data).hexdigest()}",
            f"source={Path(args.meta).name if args.meta else '-'}",
            f"builtAtUtc={datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')}",
        ]
        Path(args.manifest).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {args.manifest}", file=sys.stderr)
    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
