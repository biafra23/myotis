#!/usr/bin/env python3
"""Write the ``.meta.json`` sidecar ``synth_logindex.py`` checks a fetch against.

DEBUG / DEMO ONLY. Every field is read back from the node that served the logs,
so the frame cannot claim a range, a chain or a finality tag the fetch did not
actually have. See docs/railgun-poc.md.

    ./scripts/write_logs_meta.py \\
        --rpc http://127.0.0.1:8545 \\
        --address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 \\
        --from-block 14737691 --to-block 26029586 --to-block-tag finalized \\
        --logs ~/myotis-node/railgun/railgun-logs.jsonl
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
import urllib.request
from collections import Counter


def rpc(url, method, params, timeout=120):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r).get("result")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--address", required=True)
    ap.add_argument("--from-block", type=int, required=True)
    ap.add_argument("--to-block", type=int, required=True)
    ap.add_argument(
        "--to-block-tag",
        choices=["finalized", "safe", "latest"],
        help="the tag the fetch's high edge came from. Recorded so the build knows "
             "whether the range can still reorg: only a finalized range may be framed "
             "with no reorg margin.",
    )
    ap.add_argument("--logs", required=True)
    ap.add_argument("--out", help="default: <logs-dir>/<basename>-<from>-<to>.meta.json")
    args = ap.parse_args()

    logs_path = os.path.expanduser(args.logs)
    h, topics, n, removed = hashlib.sha256(), Counter(), 0, 0
    with open(logs_path, "rb") as f:
        for raw in f:
            h.update(raw)
            log = json.loads(raw)
            n += 1
            removed += 1 if log.get("removed") else 0
            t = log.get("topics") or []
            if t:
                topics[t[0]] += 1

    version = rpc(args.rpc, "web3_clientVersion", []) or (rpc(args.rpc, "admin_nodeInfo", []) or {}).get("name")
    meta = {
        "rpcClientVersion": version,
        "chainId": int(rpc(args.rpc, "eth_chainId", []), 16),
        "fromBlock": args.from_block,
        "toBlock": args.to_block,
        # Load-bearing: the seed may only be framed with --finality-margin 0 when
        # the high edge cannot reorg. A fetch to `latest` framed that way would
        # freeze a since-orphaned block into the seed and the engine would serve
        # it as fully covered.
        "toBlockTag": args.to_block_tag,
        "headHash": rpc(args.rpc, "eth_getBlockByNumber", [hex(args.to_block), False])["hash"],
        "genesisHash": rpc(args.rpc, "eth_getBlockByNumber", ["0x0", False])["hash"],
        f"block{args.from_block}Hash": rpc(args.rpc, "eth_getBlockByNumber", [hex(args.from_block), False])["hash"],
        "logCount": n,
        "removedCount": removed,
        "countsByTopic0": dict(sorted(topics.items())),
        "fetchedAtUtc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256Jsonl": h.hexdigest(),
        "filter": {
            "address": args.address,
            "fromBlock": hex(args.from_block),
            "toBlock": hex(args.to_block),
        },
        "note": (
            "Raw eth_getLogs output from a local full node, one log object per line exactly as "
            "returned. UNVERIFIED (no receipt-root proof); demo seed only."
        ),
    }
    stem = os.path.splitext(os.path.basename(logs_path))[0]
    out = os.path.expanduser(args.out) if args.out else os.path.join(
        os.path.dirname(logs_path), f"{stem}-{args.from_block}-{args.to_block}.meta.json"
    )
    with open(out, "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    print(out)
    print(json.dumps({k: meta[k] for k in ("chainId", "fromBlock", "toBlock", "toBlockTag", "logCount")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
