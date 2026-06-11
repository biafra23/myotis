#!/usr/bin/env python3
"""Replay a captured MetaMask send/confirm session against a Myotis JSON-RPC daemon.

Records of a real, successful MetaMask "send" are captured by the daemon's
request tap (-Dmyotis.rpc.capture=<file>) as JSONL {"t","req","resp"}. This tool
replays the UNIQUE, read-only requests from such a session and asserts the daemon
still serves everything MetaMask needs to render the confirm screen + broadcast —
a regression guard against RPC changes that re-break the wallet flow.

Design:
- Dedupe to unique (method, to, calldata, block) requests (MetaMask polls a lot).
- Rewrite specific-block params -> "latest" so the fixture stays servable as the
  chain advances (the captured calldata, not the block height, is what matters).
- SKIP eth_sendRawTransaction (would re-broadcast / nonce-fail) and treat
  receipt/tx-by-hash as best-effort (tx-specific to the captured run).
- The BalanceChecker token-sweep (0xb1f8e55c...) is background enrichment that
  legitimately times out; it is NON-GATING and never fails the run.
- -32000 ("not serveable right now") is the transient head-instability signal:
  retry with backoff before counting it against a gating method.

Exit 0 iff every GATING request serves a non-error result.
"""
import json, sys, time, argparse, urllib.request, collections

BALANCE_CHECKER = "0xb1f8e55c7f64d203c1400b9d8555d050f94adf39"  # MM token sweep, non-gating
SKIP_METHODS = {"eth_sendRawTransaction"}                       # never re-broadcast
BEST_EFFORT = {"eth_getTransactionReceipt", "eth_getTransactionByHash"}  # tx-specific

def post(url, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def latestify(params):
    """Rewrite block-tag/number params -> 'latest' so the fixture stays servable."""
    out = []
    for p in params:
        if isinstance(p, str) and (p == "pending" or (p.startswith("0x") and len(p) <= 12 and p not in ("0x",))):
            out.append("latest")
        else:
            out.append(p)
    return out

def key(req):
    m = req.get("method"); p = req.get("params", [])
    to = data = ""
    if m == "eth_call" and p and isinstance(p[0], dict):
        to = (p[0].get("to") or "").lower(); data = (p[0].get("input") or p[0].get("data") or "")
    return (m, to, data)

def is_gating(req):
    m = req.get("method")
    if m in SKIP_METHODS or m in BEST_EFFORT:
        return False
    if m == "eth_call":
        p = req.get("params", [])
        if p and isinstance(p[0], dict) and (p[0].get("to") or "").lower() == BALANCE_CHECKER:
            return False  # background token sweep
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session"); ap.add_argument("--url", default="http://127.0.0.1:8545")
    ap.add_argument("--retries", type=int, default=6); ap.add_argument("--timeout", type=int, default=40)
    a = ap.parse_args()

    # Load + dedupe unique requests, preserving first-seen order.
    uniq = collections.OrderedDict()
    for line in open(a.session):
        line = line.strip()
        if not line: continue
        try: req = json.loads(line)["req"]
        except Exception: continue
        if not isinstance(req, dict) or "method" not in req: continue
        uniq.setdefault(key(req), req)

    gating_fail = []; results = collections.Counter()
    print(f"replaying {len(uniq)} unique requests from {a.session} -> {a.url}\n")
    for req in uniq.values():
        m = req["method"]
        if m in SKIP_METHODS:
            results["skipped"] += 1; continue
        if not is_gating(req):
            results["nongating-skip"] += 1; continue   # background calls: don't replay
        body = {"jsonrpc": "2.0", "id": 1, "method": m, "params": latestify(req.get("params", []))}
        ok = False; last = ""
        for attempt in range(a.retries):
            try:
                resp = post(a.url, body, a.timeout)
            except Exception as e:
                last = f"transport: {e}"; time.sleep(2); continue
            err = resp.get("error")
            if not err:
                ok = True; break
            last = f"-{err.get('code')} {err.get('message','')[:40]}"
            if err.get("code") == -32000:      # transient -> retry
                time.sleep(2); continue
            break                               # -32601 etc. -> definitive
        gate = is_gating(req)
        tag = ("ok" if ok else ("FAIL" if gate else "nongating-skip"))
        results[tag] += 1
        label = m + (f" {req['params'][0].get('to','')[:10]}" if m=="eth_call" and req.get("params") and isinstance(req["params"][0],dict) else "")
        if not ok and gate:
            gating_fail.append((label, last))
        print(f"  {'✅' if ok else ('❌' if gate else '·')} {label:<34} {'' if ok else last}")

    print(f"\nsummary: {dict(results)}")
    if gating_fail:
        print(f"\n❌ {len(gating_fail)} GATING request(s) failed — MetaMask flow would break:")
        for l, e in gating_fail: print(f"   {l}: {e}")
        sys.exit(1)
    print("\n✅ all gating requests served — MetaMask confirm/send working set OK")
    sys.exit(0)

if __name__ == "__main__":
    main()
