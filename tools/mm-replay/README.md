# MetaMask RPC replay harness

A **regression test for the verified JSON-RPC daemon**, built from a real,
*successful* MetaMask send: render the confirm screen (with a network fee),
broadcast, and fetch the receipt. It replays that session and asserts the daemon
still serves everything MetaMask needs — catching RPC changes that re-break the
wallet flow, without driving a browser.

## How the fixture was captured
The daemon taps requests when launched with `-Dmyotis.rpc.capture=<file>`
(see `MyotisRpcServer`), writing JSONL `{"t","req","resp"}`. A live MetaMask
send against `127.0.0.1:8545` was recorded into
`sessions/metamask-send-mainnet.jsonl` (199 exchanges).

## Running
```bash
# 1. start a synced daemon (serves http://127.0.0.1:8545)
./gradlew :app:run            # wait until stdout shows it serving

# 2. replay the golden session against it
python3 tools/mm-replay/replay.py tools/mm-replay/sessions/metamask-send-mainnet.jsonl
# exit 0 = every GATING call served (MetaMask flow OK); exit 1 = a regression
```

## What it checks (and deliberately ignores)
- Dedupes the session to unique requests and rewrites pinned blocks → `latest`,
  so the fixture stays servable as the chain advances.
- **Gating** = everything MetaMask needs to render+send: the Multicall3
  simulation, token metadata, ENS, `eth_estimateGas`, `eth_getBalance`,
  `eth_getCode`, `eth_getBlockByNumber`, `eth_feeHistory`, `eth_getTransactionCount`.
  All must serve (with retry-on-`-32000` to ride transient sync gaps).
- **Non-gating / skipped:** the `0xb1f8e55c` BalanceChecker token sweep
  (~1000 tokens — background enrichment that legitimately times out), and
  `eth_sendRawTransaction` (never re-broadcast).

## Pre-PR use
Run it against a synced daemon before opening a PR that touches the RPC backend.
A `-32000` failure means either a genuine regression OR the daemon is in a
transient head-instability window — re-run; persistent failure on a healthy
daemon is the regression signal.

## Automated tests (CI)
The full replay needs a live daemon, so it stays a manual check. The harness's
*pure* logic — `latestify` (block→`latest`), `key` (dedup), `is_gating`
(what MetaMask must have served) — and the golden fixture's contract are covered
by stdlib `unittest` (no daemon, no pip), run in CI by `.github/workflows/mm-replay-tests.yml`:

```bash
python3 -m unittest discover -s tools/mm-replay -p 'test_*.py'
```

These guard against a silent change to the gating classification or fixture that
would quietly weaken the manual replay gate.
