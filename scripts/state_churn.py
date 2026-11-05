#!/usr/bin/env python3
"""Measure how many state-trie nodes a block (or a run of blocks) rewrites.

RESEARCH ONLY: it reads a node over JSON-RPC and verifies nothing. It backs
the numbers in docs/state-on-swarm.md.

For each block it collects the changed keys:

- every account and storage slot a transaction changed (`prestateTracer` in
  `diffMode`, via `debug_traceBlockByNumber`), less the slots the block
  left at their starting value;
- the fee recipient, and the withdrawal recipients except on Gnosis chains,
  which pay withdrawals into the deposit contract, not to the recipient;
- the EIP-4788 and EIP-2935 system slots.

It then calls `eth_getProof` for every changed key at the last block of the
window. Every node on the path to a changed leaf has a new hash, so the union
of those proofs is the set of trie nodes the window wrote. That is what a
publisher would have to upload to make the new state root walkable. Nodes a
deletion restructures are the exception.

`--window N` merges N consecutive blocks into one delta: the nodes that are
new between root(first - 1) and root(first + N - 1). That is the upload when
only every N-th root is published.

Not traced, so the counts run slightly low: post-block system calls other than
EIP-4788/2935, i.e. Gnosis withdrawals (a system call into the deposit
contract) and the EIP-7002/7251 request queues. An account whose balance or
nonce changed and changed back within the block is still counted, so the
account side can run slightly high. With `--window`, the start-value filter
still works per block: a slot that changes in one block of the window and
reverts in a later one stays in the proved set, so a merged window can run
slightly high too.

The RPC must serve `debug_traceBlockByNumber` and `eth_getProof` at the
measured block. Public endpoints that did on 2026-11-05: eth.drpc.org
(free plan: at most 3 calls per batch, recent state only) and
rpc.gnosischain.com (proofs within a short window of the head). So measure
near the head:

    ./scripts/state_churn.py --rpc https://rpc.gnosischain.com --head-offset 2 --batch 8
    ./scripts/state_churn.py --rpc https://eth.drpc.org --head-offset 34 --window 32 --workers 4

Prints one JSON object per measured window. HTTP goes through the system
`curl`; everything else is the standard library.
"""
import argparse
import collections
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

BEACON_ROOTS = "0x000f3df6d732807ef1319fb7b8bb8522d0beac02"  # EIP-4788
HISTORY = "0x0000f90827f1c53a10cb7a02335b175320002935"  # EIP-2935
RING = 8191  # both system contracts' ring-buffer length
GNOSIS_CHAINS = {100, 10200}  # Gnosis, Chiado
ZERO = "0x" + "00" * 32
MAX_SLOTS_PER_CALL = 256


class RpcRefused(RuntimeError):
    """A JSON-RPC error the node will give again: not worth a retry."""


def rpc(url, calls):
    """One JSON-RPC batch; returns the results in call order. Retries with backoff."""
    body = json.dumps([{"jsonrpc": "2.0", "id": i, "method": m, "params": p}
                       for i, (m, p) in enumerate(calls)]).encode()
    last = None
    for attempt in range(8):
        try:
            raw = subprocess.run(
                ["curl", "-sS", "-m", "120", "-X", "POST", "-H", "content-type: application/json",
                 "--data-binary", "@-", url],
                input=body, capture_output=True, check=True).stdout
            out = json.loads(raw)
            # A single error object answers the whole batch (e.g. an endpoint
            # that refuses batches or the method); a list carries one per call.
            if isinstance(out, dict):
                errors = [out.get("error") or {"message": f"not a batch response: {out}"}]
            else:
                errors = [r["error"] for r in out if "error" in r]
            if errors:
                # A refusal (bad params, proof window passed, method not served)
                # will not change on retry; only rate limits and transport
                # failures are retried.
                if "rate" not in str(errors[0]).lower():
                    raise RpcRefused(errors[0])
                raise RuntimeError(errors[0])
            by_id = {r["id"]: r["result"] for r in out}
            return [by_id[i] for i in range(len(calls))]
        except RpcRefused:
            raise
        except (subprocess.CalledProcessError, ValueError, RuntimeError, KeyError) as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"rpc failed after retries: {last}")


def slot32(n):
    return "0x%064x" % n


def changed_keys(url, number, chain_id):
    """{address: {slot, ...}} for everything block `number` changed, and its tx count."""
    block = rpc(url, [("eth_getBlockByNumber", [hex(number), False])])[0]
    traces = rpc(url, [("debug_traceBlockByNumber", [hex(number), {
        "tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}])])[0]
    keys = collections.defaultdict(set)
    first, last = {}, {}  # (address, slot) -> value before the block / after it
    for t in traces:
        result = t["result"]
        pre, post = result.get("pre", {}), result.get("post", {})
        # diffMode lists only what a transaction changed; a slot it set to zero
        # is in `pre` alone.
        for address in set(pre) | set(post):
            keys[address.lower()]
            before = pre.get(address, {}).get("storage", {})
            after = post.get(address, {}).get("storage", {})
            for slot in set(before) | set(after):
                key = (address.lower(), slot)
                first.setdefault(key, before.get(slot, ZERO))
                last[key] = after.get(slot, ZERO)
    for (address, slot), value in last.items():
        if int(value, 16) != int(first[(address, slot)], 16):
            keys[address].add(slot)
    if chain_id not in GNOSIS_CHAINS:
        for w in block.get("withdrawals") or []:
            keys[w["address"].lower()]
    keys[block["miner"].lower()]
    ts = int(block["timestamp"], 16)
    if block.get("parentBeaconBlockRoot"):
        keys[BEACON_ROOTS].update({slot32(ts % RING), slot32(ts % RING + RING)})
    keys[HISTORY].add(slot32((number - 1) % RING))
    return keys, len(traces)


def rlp_list_items(b):
    """Item count of an RLP list: 17 for a branch node, 2 for a leaf or extension."""
    p = b[0]
    if p <= 0xf7:
        i, end = 1, 1 + (p - 0xc0)
    else:
        ll = p - 0xf7
        i, end = 1 + ll, 1 + ll + int.from_bytes(b[1:1 + ll], "big")
    n = 0
    while i < end:
        q = b[i]
        if q < 0x80:
            i += 1
        elif q <= 0xb7:
            i += 1 + q - 0x80
        elif q <= 0xbf:
            ll = q - 0xb7
            i += 1 + ll + int.from_bytes(b[i + 1:i + 1 + ll], "big")
        elif q <= 0xf7:
            i += 1 + q - 0xc0
        else:
            ll = q - 0xf7
            i += 1 + ll + int.from_bytes(b[i + 1:i + 1 + ll], "big")
        n += 1
    return n


def prove(url, keys, number, batch, workers):
    """Union of the proof nodes for `keys` at block `number`, by trie, with depths."""
    # Nodes cap the storage keys of one eth_getProof call (geth: 1024), so a
    # contract with more changed slots is proved in several calls.
    items = []
    for address, slots in sorted(keys.items()):
        slots = sorted(slots)
        parts = [slots[i:i + MAX_SLOTS_PER_CALL] for i in range(0, len(slots), MAX_SLOTS_PER_CALL)]
        for i, part in enumerate(parts or [[]]):
            items.append((address, part, i == 0))
    batches = [items[i:i + batch] for i in range(0, len(items), batch)]

    def fetch(chunk):
        return chunk, rpc(url, [("eth_getProof", [a, s, hex(number)]) for a, s, _ in chunk])

    account_nodes, storage_nodes = {}, {}
    account_len, storage_len = collections.Counter(), collections.Counter()
    with ThreadPoolExecutor(workers) as pool:
        for chunk, results in pool.map(fetch, batches):
            for (_, _, first), r in zip(chunk, results):
                path = [bytes.fromhex(n[2:]) for n in r["accountProof"]]
                if first:
                    account_len[len(path)] += 1
                for depth, node in enumerate(path):
                    account_nodes[node] = depth
                for sp in r["storageProof"]:
                    path = [bytes.fromhex(n[2:]) for n in sp["proof"]]
                    storage_len[len(path)] += 1
                    for depth, node in enumerate(path):
                        storage_nodes[node] = depth
    return account_nodes, storage_nodes, account_len, storage_len


def summary(nodes):
    kinds = collections.Counter("branch" if rlp_list_items(n) == 17 else "short" for n in nodes)
    return {"count": len(nodes), "bytes": sum(map(len, nodes)), "kinds": dict(kinds),
            "by_depth": dict(sorted(collections.Counter(nodes.values()).items()))}


def head(url):
    return int(rpc(url, [("eth_blockNumber", [])])[0], 16)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rpc", required=True)
    start = ap.add_mutually_exclusive_group(required=True)
    start.add_argument("--first", type=int, help="first block of the first window")
    start.add_argument("--head-offset", type=int,
                       help="start at head - OFFSET (use at least --window + 2)")
    ap.add_argument("--window", type=int, default=1, help="blocks merged into one delta")
    ap.add_argument("--count", type=int, default=1, help="consecutive windows to measure")
    ap.add_argument("--batch", type=int, default=3, help="eth_getProof calls per JSON-RPC batch")
    ap.add_argument("--workers", type=int, default=1, help="batches in flight")
    args = ap.parse_args()

    chain_id = int(rpc(args.rpc, [("eth_chainId", [])])[0], 16)
    first = args.first if args.first is not None else head(args.rpc) - args.head_offset
    for w in range(args.count):
        t0 = time.time()
        lo = first + w * args.window
        keys, txs = collections.defaultdict(set), 0
        for number in range(lo, lo + args.window):
            block_keys, n = changed_keys(args.rpc, number, chain_id)
            txs += n
            for address, slots in block_keys.items():
                keys[address].update(slots)
        an, sn, al, sl = prove(args.rpc, keys, lo + args.window - 1, args.batch, args.workers)
        print(json.dumps({
            "block": lo, "window": args.window, "txs": txs,
            "accounts": len(keys), "slots": sum(len(s) for s in keys.values()),
            "contracts_with_slot_writes": sum(1 for s in keys.values() if s),
            "acct": summary(an), "stor": summary(sn),
            "acct_proof_len": dict(sorted(al.items())), "stor_proof_len": dict(sorted(sl.items())),
            "secs": round(time.time() - t0, 1)}), flush=True)


if __name__ == "__main__":
    sys.exit(main())
