#!/usr/bin/env python3
"""Synthesize a portable Myotis log-index snapshot (MLIX v2) from raw
``eth_getLogs`` output — an UNVERIFIED seed for demos and for bootstrapping
the Bee (Swarm) index without days of devp2p backfill.

The engine's own generator walks history over devp2p and verifies every log
against receipt roots (docs/eth-getlogs-design.md). This script does none of
that: it takes logs a full node returned over JSON-RPC and frames them in the
exact byte layout ``LogIndex::serialize_impl`` writes
(rust/myotis-net/src/el/logindex.rs), so the engine's portable import path
(``import-logindex <file>`` or the ``dataDir/logindex-<net>.db`` drop-in)
accepts the file. The import path treats a file as "claimed verified by
whoever generated it" — this file claims exactly that, on the authority of
the RPC node it was fetched from. Never ship one as if it were walked.

Input: one or more JSONL files (optionally gzipped), one log object per line
as returned by ``eth_getLogs`` (address, topics, data, blockNumber,
blockHash, transactionHash, transactionIndex, logIndex, removed). Every
watch entry given with ``--watch ADDR:FROM`` declares the file's coverage
for that address as [FROM, --to-block]: FROM is both the entry's
``from_block`` (the engine treats it as the deployment block — anything
below is asserted log-free) and the span's low edge. Overshooting the real
deployment block silently hides earlier events, so choose FROM knowingly.

Layout (all integers little-endian; see logindex.rs ``serialize_impl``):
  "MLIX" | u32 version=2 | u64 network_id | 32B genesis_hash |
  u64 config fingerprint | u64 FNV-1a checksum of everything after it |
  u32 n_watch | per entry: 20B address, u64 from_block, u32 n_topic0,
    32B each, u32 name_len + name |
  u32 n_coverage (== n_watch, parallel) | per entry: 0 | 1 u64 low u64 high |
  cursor: 0 | 1 u64 number 32B hash |
  u64 n_logs | per log: u64 block, 32B block_hash, 32B tx_hash, u32 tx_index,
    u32 log_index, 20B address, u32 n_topics, 32B each, u32 data_len + data

Example (Bee on Gnosis, logs fetched from block 47,000,000 to the node's
head 48,300,000, file dropped in for the daemon):
  scripts/synth_logindex.py \
      --network-id 100 \
      --genesis 0x4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756 \
      --watch 0x45a1502382541Cd610CC9068e88727426b696293:47000000 \
      --to-block 48300000 \
      --logs data/bee/gnosis/postagestamp-logs-47000000-48300000.jsonl.gz \
      --out app/logindex-gnosis.db

``--check FILE`` parses an existing snapshot and prints its header, watch
table, coverage and log count (also used as the self-check after writing).
"""

from __future__ import annotations

import argparse
import gzip
import json
import struct
import sys
from pathlib import Path

MAGIC = b"MLIX"
VERSION = 2
V2_CHECKSUM_AT = 56  # magic(4) + version(4) + network_id(8) + genesis(32) + fingerprint(8)
FNV_OFFSET = 0xCBF2_9CE4_8422_2325
FNV_PRIME = 0x0000_0100_0000_01B3
MASK64 = (1 << 64) - 1

GNOSIS_GENESIS = "0x4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756"


def fnv64(data: bytes, h: int = FNV_OFFSET) -> int:
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return h


def config_fingerprint(watch: list[tuple[bytes, int, list[bytes]]]) -> int:
    """FNV-1a over the SORTED entry encodings, each followed by a 0xff
    separator step — mirrors ``LogIndexConfig::fingerprint``."""
    encoded = []
    for address, from_block, topic0s in watch:
        e = address + struct.pack("<Q", from_block) + b"".join(sorted(topic0s))
        encoded.append(e)
    encoded.sort()
    h = FNV_OFFSET
    for e in encoded:
        h = fnv64(e, h)
        h ^= 0xFF
        h = (h * FNV_PRIME) & MASK64
    return h


def hex_bytes(s: str, n: int, what: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("0x"):
        raise ValueError(f"{what}: expected 0x-hex string, got {s!r}")
    b = bytes.fromhex(s[2:])
    if len(b) != n:
        raise ValueError(f"{what}: expected {n} bytes, got {len(b)} ({s})")
    return b


def hex_int(s: str | int, what: str) -> int:
    if isinstance(s, int):
        return s
    if not isinstance(s, str) or not s.startswith("0x"):
        raise ValueError(f"{what}: expected 0x-hex quantity, got {s!r}")
    return int(s, 16)


def parse_watch(spec: str) -> tuple[bytes, int, list[bytes]]:
    try:
        addr, frm = spec.rsplit(":", 1)
        return hex_bytes(addr, 20, "--watch address"), int(frm), []
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"--watch expects ADDR:FROM_BLOCK ({e})")


def read_logs(paths: list[Path]):
    for p in paths:
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield p, lineno, json.loads(line)
                except json.JSONDecodeError as e:
                    raise SystemExit(f"{p}:{lineno}: bad JSON ({e})")


def put_bytes(out: bytearray, b: bytes) -> None:
    out += struct.pack("<I", len(b)) + b


def build(args) -> bytes:
    watch = [parse_watch(w) for w in args.watch]
    by_addr = {a: (frm, i) for i, (a, frm, _) in enumerate(watch)}
    if len(by_addr) != len(watch):
        raise SystemExit("--watch: duplicate address")
    to_block = args.to_block
    for a, frm, _ in watch:
        if frm > to_block:
            raise SystemExit(f"--watch 0x{a.hex()}:{frm} is above --to-block {to_block}")

    logs: dict[tuple[int, int], tuple] = {}
    skipped_removed = 0
    skipped_range = 0
    for p, lineno, obj in read_logs([Path(x) for x in args.logs]):
        where = f"{p}:{lineno}"
        if obj.get("removed"):
            skipped_removed += 1
            continue
        address = hex_bytes(obj["address"], 20, f"{where} address")
        if address not in by_addr:
            raise SystemExit(f"{where}: log for unwatched address 0x{address.hex()}")
        block = hex_int(obj["blockNumber"], f"{where} blockNumber")
        frm = by_addr[address][0]
        if block < frm or block > to_block:
            skipped_range += 1
            continue
        topics = [hex_bytes(t, 32, f"{where} topic") for t in obj.get("topics", [])]
        if len(topics) > 4:
            raise SystemExit(f"{where}: {len(topics)} topics (max 4)")
        data_hex = obj.get("data", "0x")
        if not data_hex.startswith("0x"):
            raise SystemExit(f"{where}: data is not 0x-hex")
        rec = (
            block,
            hex_bytes(obj["blockHash"], 32, f"{where} blockHash"),
            hex_bytes(obj["transactionHash"], 32, f"{where} transactionHash"),
            hex_int(obj["transactionIndex"], f"{where} transactionIndex"),
            hex_int(obj["logIndex"], f"{where} logIndex"),
            address,
            topics,
            bytes.fromhex(data_hex[2:]),
        )
        key = (block, rec[4])
        prev = logs.get(key)
        if prev is not None and prev != rec:
            raise SystemExit(f"{where}: conflicting duplicate for block {block} logIndex {rec[4]}")
        logs[key] = rec

    # Every block's logs must agree on one block hash — a mixed set would mean
    # the input straddles a reorg; refuse rather than frame it.
    hashes_by_block: dict[int, bytes] = {}
    for (block, _), rec in logs.items():
        h = hashes_by_block.setdefault(block, rec[1])
        if h != rec[1]:
            raise SystemExit(f"block {block}: logs carry two different block hashes (reorg in input?)")

    out = bytearray()
    out += MAGIC
    out += struct.pack("<I", VERSION)
    out += struct.pack("<Q", args.network_id)
    out += hex_bytes(args.genesis, 32, "--genesis")
    out += struct.pack("<Q", config_fingerprint(watch))
    assert len(out) == V2_CHECKSUM_AT
    out += b"\0" * 8  # checksum, patched below
    out += struct.pack("<I", len(watch))
    for address, frm, topic0s in watch:
        out += address
        out += struct.pack("<Q", frm)
        out += struct.pack("<I", len(topic0s))
        for t in topic0s:
            out += t
        put_bytes(out, b"")  # names are the importing wallet's job
    out += struct.pack("<I", len(watch))
    for address, frm, _ in watch:
        out += b"\x01" + struct.pack("<QQ", frm, to_block)
    if args.cursor_block is not None:
        out += b"\x01" + struct.pack("<Q", args.cursor_block) + hex_bytes(args.cursor_hash, 32, "--cursor-hash")
    else:
        out += b"\x00"  # the appender re-seeds the trust edge on first append
    out += struct.pack("<Q", len(logs))
    for key in sorted(logs):
        block, bh, th, ti, li, address, topics, data = logs[key]
        out += struct.pack("<Q", block) + bh + th + struct.pack("<II", ti, li) + address
        out += struct.pack("<I", len(topics))
        for t in topics:
            out += t
        put_bytes(out, data)
    out[V2_CHECKSUM_AT:V2_CHECKSUM_AT + 8] = struct.pack("<Q", fnv64(bytes(out[V2_CHECKSUM_AT + 8:])))

    print(
        f"logs kept: {len(logs)}  (skipped removed: {skipped_removed}, outside span: {skipped_range})",
        file=sys.stderr,
    )
    return bytes(out)


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


def check(data: bytes, verbose: bool = True) -> dict:
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
    if config_fingerprint([(a, f, t) for a, f, t, _ in watch]) != fingerprint:
        raise ValueError("fingerprint does not match the watch table")
    n_cov = r.u32()
    if n_cov != n_watch:
        raise ValueError(f"coverage count {n_cov} != watch count {n_watch}")
    coverage = []
    for _ in range(n_cov):
        flag = r.take(1)[0]
        coverage.append((r.u64(), r.u64()) if flag == 1 else None)
    cursor = None
    if r.take(1)[0] == 1:
        cursor = (r.u64(), r.take(32))
    n_logs = r.u64()
    lo = hi = None
    for _ in range(n_logs):
        block = r.u64()
        r.take(64)
        r.u32()
        r.u32()
        r.take(20)
        for _ in range(r.u32()):
            r.take(32)
        r.take(r.u32())
        lo = block if lo is None else min(lo, block)
        hi = block if hi is None else max(hi, block)
    if r.pos != len(data):
        raise ValueError(f"trailing bytes: {len(data) - r.pos}")
    info = {
        "network_id": network_id,
        "genesis": "0x" + genesis.hex(),
        "watch": [
            {"address": "0x" + a.hex(), "from_block": f, "topic0s": len(t), "name": n.decode(errors="replace")}
            for a, f, t, n in watch
        ],
        "coverage": coverage,
        "cursor": None if cursor is None else (cursor[0], "0x" + cursor[1].hex()),
        "logs": n_logs,
        "log_block_range": None if lo is None else (lo, hi),
        "bytes": len(data),
    }
    if verbose:
        print(json.dumps(info, indent=2))
    return info


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", metavar="FILE", help="parse and describe an existing snapshot, then exit")
    ap.add_argument("--logs", nargs="+", metavar="JSONL[.gz]", help="raw eth_getLogs output, one log per line")
    ap.add_argument("--watch", action="append", metavar="ADDR:FROM_BLOCK", help="watched address and its span low / from_block (repeatable)")
    ap.add_argument("--to-block", type=int, help="span high: the LAST block the logs are complete to (the fetch's fixed toBlock)")
    ap.add_argument("--network-id", type=int, default=100, help="EL network id (default 100 = Gnosis)")
    ap.add_argument("--genesis", default=GNOSIS_GENESIS, help="EL genesis block hash (default: Gnosis)")
    ap.add_argument("--cursor-block", type=int, help="optional walker cursor block (with --cursor-hash); default: none")
    ap.add_argument("--cursor-hash", help="hash of --cursor-block")
    ap.add_argument("--out", help="output snapshot path (e.g. app/logindex-gnosis.db)")
    args = ap.parse_args()

    if args.check:
        check(Path(args.check).read_bytes())
        return 0
    missing = [n for n in ("logs", "watch", "to_block", "out") if not getattr(args, n)]
    if missing:
        ap.error("required: --" + ", --".join(m.replace("_", "-") for m in missing))
    if (args.cursor_block is None) != (args.cursor_hash is None):
        ap.error("--cursor-block and --cursor-hash go together")

    data = build(args)
    info = check(data, verbose=False)  # self-check: our own reader must accept our own frame
    Path(args.out).write_bytes(data)
    print(f"wrote {args.out}: {info['bytes']} bytes, {info['logs']} logs, coverage {info['coverage']}", file=sys.stderr)
    check(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
