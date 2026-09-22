#!/usr/bin/env python3
"""Fetch one contract's logs from a full node over JSON-RPC, as seed input.

DEBUG / DEMO ONLY — NOT A PRODUCTION DATA PATH. The output carries no
receipt-root proof; it is framed by ``scripts/synth_logindex.py`` into a
snapshot the engine serves indistinguishably from logs it walked and verified
itself. See docs/railgun-poc.md and docs/bee-rpc-service.md.

Writes one JSON object per line, exactly as the node returned it, which is what
``synth_logindex.py`` expects. Resumable: a re-run continues from the last fully
fetched page recorded beside the output, so a timeout costs one page rather than
the whole walk.

    ./scripts/fetch_contract_logs.py \\
        --rpc http://127.0.0.1:8545 \\
        --address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 \\
        --from-block 14737691 --to-block finalized \\
        --out ~/myotis-node/railgun/railgun-logs.jsonl
"""
import argparse
import json
import os
import sys
import time
import urllib.request

MIN_PAGE = 1_000


def rpc(url, method, params, timeout=180):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.load(r)
    if "error" in body:
        raise RuntimeError(body["error"].get("message", "rpc error"))
    return body["result"]


def resolve_block(url, value):
    """A number stays a number; a tag is resolved to the number it meant NOW.

    Returns (number, tag_or_None). The tag is recorded in the sidecar, because
    whether the range can reorg decides the seed's reorg margin.
    """
    if isinstance(value, str) and not value.isdigit():
        block = rpc(url, "eth_getBlockByNumber", [value, False])
        if block is None:
            raise SystemExit(f"fetch_contract_logs: the node has no '{value}' block")
        return int(block["number"], 16), value
    return int(value), None


def get_page(url, address, lo, hi):
    """One page, halving the span on a timeout rather than giving up."""
    span = hi - lo + 1
    while True:
        end = lo + span - 1
        try:
            return rpc(url, "eth_getLogs", [{
                "address": address, "fromBlock": hex(lo), "toBlock": hex(end),
            }]), end
        except Exception as e:
            if span <= MIN_PAGE:
                raise
            span = max(MIN_PAGE, span // 2)
            print(f"  [{lo}] {e}; retrying with span {span}", flush=True)
            time.sleep(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc", required=True, help="JSON-RPC endpoint of a synced full node")
    ap.add_argument("--address", required=True, help="the one contract to index")
    ap.add_argument("--from-block", required=True, help="the contract's REAL deployment block")
    ap.add_argument("--to-block", default="finalized", help="a number, or a tag (default: finalized)")
    ap.add_argument("--page", type=int, default=50_000, help="blocks per eth_getLogs call")
    ap.add_argument("--out", required=True, help="JSONL output path")
    args = ap.parse_args()

    out = os.path.expanduser(args.out)
    prog_path = out + ".progress.json"
    from_block, _ = resolve_block(args.rpc, args.from_block)
    to_block, to_tag = resolve_block(args.rpc, args.to_block)
    if to_block < from_block:
        raise SystemExit(f"fetch_contract_logs: to-block {to_block} is below from-block {from_block}")

    start, mode, count = from_block, "w", 0
    if os.path.exists(prog_path) and os.path.exists(out):
        p = json.load(open(prog_path))
        # Resume only into the SAME range: a different to-block is a different
        # fetch, and appending one onto another would claim coverage the file
        # does not have.
        #
        # A MISMATCH IS REFUSED, never silently restarted. `finalized` advances
        # every epoch, so the documented "just rerun it" recovery would otherwise
        # re-resolve to a new high edge, miss this check, and truncate hours of
        # fetched pages with no signal but the absence of a line of output. State
        # that changes the outcome is applied or refused (CLAUDE.md, Trust).
        if p.get("next") and (p.get("toBlock") != to_block or p.get("fromBlock") != from_block):
            tag = p.get("toBlockTag")
            tag_note = " ({})".format(tag) if tag else ""
            raise SystemExit(
                "fetch_contract_logs: {prog} is a partial fetch of {pf}..{pt}{tag}, but this run "
                "resolved {f}..{t}.\n"
                "  To resume it:   --from-block {pf} --to-block {pt}\n"
                "  To start over:  rm {prog} {out}".format(
                    prog=prog_path, pf=p.get("fromBlock"), pt=p.get("toBlock"),
                    tag=tag_note, f=from_block, t=to_block, out=out,
                )
            )
        if p.get("next"):
            start, mode, count = p["next"], "a", p.get("count", 0)
            print(f"resuming at {start} ({count} logs so far)", flush=True)

    t0 = time.time()
    with open(out, mode) as f:
        lo = start
        while lo <= to_block:
            logs, end = get_page(args.rpc, args.address, lo, min(lo + args.page - 1, to_block))
            for log in logs:
                f.write(json.dumps(log, separators=(",", ":"), sort_keys=True) + "\n")
            f.flush()
            count += len(logs)
            lo = end + 1
            json.dump(
                {"fromBlock": from_block, "toBlock": to_block, "toBlockTag": to_tag, "next": lo, "count": count},
                open(prog_path, "w"),
            )
            done, total = lo - from_block, to_block - from_block + 1
            rate = done / max(1e-9, time.time() - t0)
            print(
                f"{lo - 1:>9} {100.0 * done / total:5.1f}%  logs={count:>7}  "
                f"eta={(total - done) / rate / 60 if rate else 0:5.1f} min",
                flush=True,
            )
    print(f"DONE: {count} logs, {time.time() - t0:.0f}s -> {out}", flush=True)
    print(f"now run: scripts/write_logs_meta.py --rpc {args.rpc} --address {args.address} "
          f"--from-block {from_block} --to-block {to_block}"
          f"{f' --to-block-tag {to_tag}' if to_tag else ''} --logs {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
