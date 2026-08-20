# Running Myotis as the RPC service for a Bee (Swarm) node

Bee needs a Gnosis Chain RPC endpoint for everything it does on-chain: reading
the postage-stamp batch store, following the price oracle, staking and playing
the redistribution game, and operating its chequebook. Normally that endpoint
is a full node or a hosted RPC provider — either one a trust anchor Bee simply
believes. Myotis replaces it with a **light client whose every answer is
cryptographically verified**: state reads against snap/1 Merkle-Patricia proofs
anchored to sync-committee-signed beacon roots, logs against receipt roots, and
nothing served on trust. See the README's *Trust model* and *Wallet API*
sections for the full verification story.

## What Bee gets, and from where

| Bee's need | Myotis serving path |
|---|---|
| `eth_chainId`, `net_version`, `eth_blockNumber` | config / verified beacon head |
| `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` | snap-proof-verified state reads |
| `eth_call` (batch store, oracle, chequebook reads) | local EVM over proof-served state |
| `eth_estimateGas`, `eth_gasPrice`, `eth_feeHistory` | local EVM metering / verified headers |
| `eth_getBlockByNumber`, `eth_getTransactionByHash`, `eth_getTransactionReceipt` | verified header/block window |
| `eth_sendRawTransaction` (stake, redistribution plays, cheques) | gossiped to devp2p peers; Myotis never signs |
| `eth_getLogs` (batch created/topped-up/diluted events, …) | **the log index** — this is the part that needs the one-time setup below |

`eth_getLogs` is the special one. A light client holds no historical chain, so
Myotis serves logs from an **opt-in per-contract index** it builds by walking
history over devp2p, verifying every log against the block's receipt root
(docs/eth-getlogs-design.md). Ranges the index has not covered are refused
with an error — never answered with a plausible-but-empty `[]` — so Bee can
retry rather than silently believe a gap.

The index for Bee watches the four Swarm system contracts on Gnosis (the
PostageStamp contract and its companions, per Bee's chain config), each from
its deployment block:

| Contract | Indexed from block |
|---|---|
| `0x45a1502382541cd610cc9068e88727426b696293` (PostageStamp) | 31,305,656 |
| `0x47eef336e7fe5bed98499a4696bce8f28c1b0a8b` | 37,339,168 |
| `0xda2a16ee889e7f04980a8d597b48c8d51b9518f4` | 40,430,237 |
| `0x5069cdfb3d9e56d23b1caee83ce6109a7e4fd62d` | 41,105,199 |

## Setup

1. **Refresh the trust anchor** (multi-operator checkpoint — refuses a root
   fewer than two operators agree on):

   ```bash
   ./gradlew refreshCheckpoint -Pnetwork=gnosis
   ```

2. **Start the Gnosis daemon.** The default engine selection (`auto`) uses the
   Rust engine, which is the one that serves the log index:

   ```bash
   ./gradlew :app:run -Pnetwork=gnosis
   ```

3. **Give it the log index.** Two ways:

   - **Import the prebuilt snapshot** (seconds — see *Distributing the
     snapshot* below for where to get it):

     ```bash
     gunzip bee-logindex-gnosis.db.gz
     # daemon: drop the file in place as app/logindex-gnosis.db before first
     # start, or import into a running desktop/mobile app via the Index tab.
     ```

     After import the node automatically catches up from the snapshot's top
     to the live head and then follows the head — nothing to re-run.

   - **Build it from scratch** (days — timings below):

     ```bash
     ./gradlew :app:run -Pnetwork=gnosis -Pargs="build-logindex 0x45a1502382541cd610cc9068e88727426b696293 --from 31305656"
     # repeat for the other three contracts with their fromBlocks, then poll:
     ./gradlew :app:run -Pnetwork=gnosis -Pargs=logindex-status
     ```

4. **Wait for readiness.** `beacon-status` must say `"state":"SYNCED"`, and
   `logindex-status` must show the coverage you need (for full Bee function,
   `backfillCursor` at the target and a small `headGap`).

5. **Point Bee at it.** Myotis serves verified JSON-RPC on
   `http://127.0.0.1:8546` for Gnosis (per-network ports; mainnet is 8545).
   In Bee's config:

   ```yaml
   blockchain-rpc-endpoint: http://127.0.0.1:8546
   ```

## Known limits (honest ones)

- **HTTP polling only.** Myotis serves plain HTTP JSON-RPC. There is no
  WebSocket endpoint and no `eth_newFilter`/`eth_subscribe` family; Bee's
  default HTTP polling mode works, a subscription-configured Bee does not.
- **Coverage is explicit.** A query outside the indexed contracts or below
  their fromBlocks errors out (`-32000`, the **retryable** class — backfill may
  cover the range later, so a client should retry, not give up) instead of
  returning `[]`. That is deliberate: an honest refusal can be retried, a
  fabricated empty answer is silent corruption. Only a malformed request gets
  the permanent `-32602`.
- **Historical state pins are rejected.** Reads pinned to old blocks answer
  from the verified head or refuse — a light client cannot prove deep
  historical state.
- The end-to-end Bee-against-Myotis compatibility run is still to be done;
  this document describes the serving surface, not a completed certification.

## Distributing the prebuilt snapshot

The exported index (`bee-logindex-gnosis.db`, ~247 MB raw, **~58 MB gzipped**)
is fine to publish:

- It contains only public chain data (logs of four public contracts), is
  **chain-tagged** (network id + Gnosis genesis hash — a wrong-chain import is
  rejected), and carries **no display names** (the importing wallet resolves
  those itself via verified reverse-ENS, so a file cannot lie about who a
  contract is). Every imported log is re-served only within coverage the
  receiving node can itself verify going forward.
- **Publish it as a GitHub Release asset**, not a committed repo file. The
  58 MB gzip is under GitHub's 100 MB per-file limit, but a data blob in git
  history bloats every clone forever; release assets take files up to 2 GiB
  and can be replaced per release. Put the **sha256 of the raw .db** in the
  release notes so importers can check integrity after gunzip.
- **Mind the shelf life.** After import, the node bridges the gap from the
  snapshot's top to the live head automatically — but the bridge spans at
  most **500,000 blocks** (~29 days of Gnosis blocks). A snapshot older than
  that still imports, but the gap to head will not close by itself. So:
  re-export a fresh snapshot every couple of weeks (seconds on a node whose
  index is current), or let the Swarm team run their own daemon after the
  first import — it stays current on its own.

## Timings (measured on zbox, an x86-64 Linux workstation)

- **Recreating the index from scratch** means walking ~16.5 M Gnosis blocks
  (head → 31,305,656) over devp2p with receipt-root verification. With the
  current engine (throughput-ranked peers, adaptive chunk sizing, rate-bounded
  checkpoints — PRs #378/#379/#380) the measured sustained rate was
  **30–83 blk/s (≈41 avg)**: the final 2.21 M blocks took **≈15 h**, putting a
  full rebuild at **≈4–5 days** of continuous running.
- **The original build on zbox took about five days wall-clock** (first
  `build-logindex` to a complete backfill), most of it on the pre-fix engine
  that averaged ~2 blk/s over its last day and rewrote 366 GB of checkpoints
  in one 6.5 h stretch — the pathologies those three PRs removed. A clean
  rebuild today should not repeat that.
- **Importing the snapshot takes well under a minute**, plus a few minutes of
  automatic catch-up to the live head. This is the intended path; rebuilding
  from scratch is only for creating a snapshot where none exists.
