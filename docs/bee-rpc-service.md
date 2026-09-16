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

   (There is also a debug-only third way for a demo box — see *Demo only:
   seeding from a full node* below. It is not a production path.)

4. **Wait for readiness.** `beacon-status` must say `"state":"SYNCED"`, and
   `logindex-status` must show the coverage you need: for full Bee function,
   `backfillCursor` at the target and a small `headGap`; for the demo seed,
   `coveredLow` at or below Bee's resume block (47,061,408 for Bee v2.8.2 —
   the seed's own low is 47,000,000) and `headGap` closed.

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
- **Coverage is explicit.** A query outside the indexed contracts or outside
  their covered range errors out (`-32000`, the **retryable** class — backfill
  may cover the range later, so a client should retry, not give up) instead of
  returning `[]`. The one range answered empty by definition is below an
  entry's `fromBlock`, which is why that value must be the contract's real
  deployment block. That is deliberate: an honest refusal can be retried, a
  fabricated empty answer is silent corruption. Only a malformed request gets
  the permanent `-32602`.
- **Historical state pins are rejected.** Reads pinned to old blocks answer
  from the verified head or refuse — a light client cannot prove deep
  historical state.
- **Bee v2.8.2's actual RPC needs, checked against the router (2026-09-15).**
  Every chain access in Bee goes through one `transaction.Backend`; the
  complete method set is `web3_clientVersion` (its first call — fatal if
  missing), `eth_chainId` (must be 100), `eth_getBlockByNumber("latest",
  false)` (needs `baseFeePerGas`; go-ethereum's decoder also requires
  `logsBloom`, `sha3Uncles`, `difficulty`, `extraData`), `eth_getBalance`,
  `eth_call` and `eth_estimateGas` (calldata arrives as `input`, which the
  router accepts alongside `data`), `eth_maxPriorityFeePerGas`,
  `eth_getTransactionCount` (incl. `"pending"`), `eth_sendRawTransaction`,
  `eth_getTransactionReceipt`, `eth_getTransactionByHash`, and
  `eth_getLogs` with `address` as a one-element array and five topic0
  alternatives in 5,000-block pages. All served; nothing subscribes,
  filters or batches. Operational gates on Bee's side: it refuses to
  proceed while the latest header is more than 60 s old (Myotis must be
  `SYNCED` and following the optimistic head), and a full node blocks
  startup on postage sync with a 10-minute stall timeout — so the index must
  cover Bee's range BEFORE Bee starts; an uncovered page is a `-32000` Bee
  retries every 5 s while that clock runs.
- **End-to-end run, 2026-09-15 (Bee v2.8.2, macOS arm64, Rust engine, the
  demo seed):** Bee connected (`connected to blockchain backend
  version=Myotis/verified-light-client`, chain id 100 accepted), loaded its
  embedded batch snapshot, then synced the postage store from 47,061,408 to
  the chain tip through Myotis's `eth_getLogs` in about four minutes, went
  `beeMode: full` with 24 Swarm peers and started filling its reserve. That
  first run used `chequebook-enable: false`; the same evening, against the
  packaged *Bee PoC* desktop app as the RPC, the funded node was restarted
  with `chequebook-enable: true`: Bee passed the balance check
  (`eth_getBalance`, 4.5 xDAI), broadcast its chequebook deployment through
  `eth_sendRawTransaction` (accepted by a snap peer at once), polled
  `eth_getTransactionReceipt` every 5 s and logged `chequebook deployed`
  25 s after the broadcast — every call in Myotis's access log
  `outcome=VERIFIED`, none `ERROR`. Read path and settlement path are both
  exercised. A zero-stake run with `storage-incentives-enable: true` then
  exercised the redistribution agent's polling (`IsOverlayFrozen`/`IsPlaying`
  `eth_call`s per phase; `IsPlaying` reverts for an unstaked overlay, which
  Bee logs as `phase failed` and moves on — a verified answer, correctly
  relayed). Playing the game (staking) stays untested by choice.
- **Peer starvation is the failure mode to watch on Gnosis.** During that run
  the desktop app's snap-peer pool — started cold, no warm cache — sank to a
  single unresponsive peer for ~10 minutes: the head bridge could not fetch
  new blocks, the index's top froze, every page Bee asked for above it was
  refused (`-32000`, honestly), `eth_call`s waited 20–97 s on proofs, and
  Bee's 10-minute stall rule shut it down while the app's log showed 102
  `VERIFIED` and 3 `-32000` outcomes. The pool recovered on its own (7 snap
  peers) and Bee resumed on restart. The daemon never hit this because it
  ran on a warm `peers-gnosis.cache`; the PoC now bundles that cache (public
  enodes, like the seed). The fetch side has since been hedged: block,
  receipt and `eth_call` state reads ask a second peer after 3 s without an
  answer (up to three in flight), so a dead first peer no longer costs a full
  15 s request timeout. The optimistic tail's own candidate fetch — the head
  edge that 23 s `eth_getLogs` waited on — is not hedged yet: it runs under a
  2 s tick budget, shorter than the hedge delay, and needs its own treatment.
  NOT a faster refusal, either way: Bee retries a
  failed page every 5 s and its stall rule counts *successful* pages, so
  for Bee a slow success beats a fast `-32000` every time.
- **…and App Nap sat underneath it.** Once its window was covered by other
  windows, the same app ran throttled to macOS's background scheduling band
  for the rest of the evening (the second packaging note in the PoC section
  below): the "unresponsive" pool and the 20–97 s proof waits were in part
  the app itself being starved of CPU on a loaded host, and a later relaunch
  on the bundled warm caches still showed 5–60 s gaps before connections were
  even accepted until App Nap was switched off — after which the same host,
  same minute, answered in 16–144 ms. The bundle now opts out of App Nap.

## Demo only: seeding from a full node (not for production)

`scripts/synth_logindex.py` frames a full node's raw `eth_getLogs` output as
an MLIX v2 snapshot the import path accepts. The repo rule stands: a local
client over http "may only be used for debugging purposes, it is not an
option for production" (CLAUDE.md, *Data sources*), and the engine serves an
imported file's logs indistinguishably from walked ones (the provenance
marker is tracked follow-up work in docs/eth-getlogs-design.md §Import). Use
this to stand up a demo today; the verified paths above are the product.

Why it is small: only the PostageStamp contract's logs are ever requested
(Bee reads the staking, redistribution and oracle contracts with `eth_call`),
and Bee v2.8.2 embeds a batch snapshot up to block **47,061,407**
(`batch-archive v0.0.9`) that it replays in-process, so it asks the RPC for
logs only above that. Fetch the ~40k logs from 47,000,000 to the node's
**`finalized`** block with one `eth_getLogs` per 50,000 blocks (seconds), one
JSON object per line exactly as returned, write the sidecar `.meta.json` the
script checks against (chain id, genesis, address, range, sha256 — see the
committed example), then frame and import:

```bash
scripts/synth_logindex.py \
    --meta data/bee/gnosis/postagestamp-logs-47000000-48262804.meta.json \
    --logs data/bee/gnosis/postagestamp-logs-47000000-48262804.jsonl.gz \
    --watch 0x45a1502382541Cd610CC9068e88727426b696293:31305656 \
    --out /tmp/bee-logindex-gnosis-seed.db
./gradlew :app:run -Pnetwork=gnosis -Pargs="import-logindex /tmp/bee-logindex-gnosis-seed.db"
```

What the frame claims, and what stays honest:

- `--watch …:31305656` is the contract's real deployment block. Coverage is
  the fetched range only, so a query between the two (Bee never makes one
  while its snapshot is in use) gets the `-32000` refusal, and the walker
  backfills that band over devp2p in the background, verified — never a
  fabricated `[]`. Passing the fetch's low edge as the deployment block is
  refused by the script for exactly that reason.
- The span high is `toBlock − 128` by default: a fetch that ran to `latest`
  can hold a block that was reorged out afterwards, and the walker's
  re-descent only fills holes — it never evicts a seeded log. The dropped
  band is re-fetched verified by the head bridge, which takes minutes for
  today's gap, not seconds. Fetch to `finalized` and pass
  `--finality-margin 0` when the range is known final.
- **Shelf life: 500,000 blocks (~29 days on Gnosis).** The head bridge maps
  at most that much above a file's top (`MAX_GAP`, el/reader.rs); a seed
  older than that imports fine and then never catches up, and Bee's pages
  above it stay `-32000` until its 10-minute stall timeout stops it. The
  committed data set tops out at 48,262,804, i.e. it is usable until about
  block 48,762,804 (~2026-10-14); after that, re-fetch.
- **Fresh index, or re-seed from the same low.** `LogIndex::merge` clamps
  coverage to the lowest high among the sources and drops a span that does
  not reach it: importing the seed into an index whose own coverage tops out
  below 47,000,000 (a from-scratch build in progress) silently discards the
  seed, and a later top-up must start at 47,000,000 again, not at the old
  top.
- The seed is one address, not the four-contract index above.

The committed data set (`data/bee/gnosis/`, 2026-09-15, zbox's Gnosis geth,
47,000,000–48,262,804, 39,225 logs, 3.2 MB gzipped) is a one-off demo
artifact. Do not refresh it in git — the rule in the next section applies to
any recurring data set.

## Bee PoC desktop build (`-PbeePoc`)

The hand-off for the Swarm team: a macOS app that a Bee full node can point at
**from the first minute**. It is a separate flavour of the desktop app — its
own name (*Myotis Bee PoC*), bundle id (`io.myotis.desktop.beepoc`) and data
dir (`~/.myotis-bee-poc`), so it coexists with a regular Myotis install —
with the seed above bundled inside:

- **Build**: `./gradlew :app-desktop:packageDmg -PbeePoc`, with Gradle
  running under a JDK of the TARGET architecture (as the dmg workflow does:
  `JAVA_HOME=<aarch64 JDK 21>` plus
  `-Porg.gradle.java.installations.paths=$JAVA_HOME`). Compose picks its
  Skiko natives by the Gradle JVM's arch while jpackage follows the
  toolchain JDK's, so a mixed pair (x86_64 Gradle, aarch64 toolchain — one
  dev Mac's default) produces an app that dies at launch with
  `Can't load library: libskiko-macos-arm64.dylib`. The
  `prepareBeePocSeed` task runs `scripts/synth_logindex.py` on the committed
  `data/bee/gnosis/` set at build time, stages the seed into the app bundle
  next to a manifest (coverage, usable-until block, sha256), and a build
  without the flag removes any staged seed. `-PbeePoc` also works with
  `:app-desktop:run`.
- **CI builds it on every PR, every push to `main` and every release tag**
  (`desktop-dmg.yml`, the `bee-poc` matrix leg): the artifact
  `myotis-bee-poc-dmg-arm64-<sha>` holds `Myotis-bee-poc-arm64.dmg`, and the
  leg fails unless the dmg carries the seed, its manifest and the peer caches
  (the standard leg fails if it carries a seed). On a tag the dmg is attached
  to the GitHub release as a best-effort asset: the leg is
  `continue-on-error`, so a PoC-only failure never blocks the standard dmgs,
  and the release simply lacks the PoC in that case. Mind the shelf life: a
  release older than ~29 days carries a PoC whose seed no longer catches up.
- **First start** (`BeePoc.kt`): the app copies the seed into its data dir —
  when no index file exists there yet, or when the bundled seed is newer than
  the one this flavour installed before (a rebuilt app after the shelf life;
  an index the flavour did not install is never touched), and only if the
  seed's sha256 matches the manifest — where the engine activates it on its
  own (`activate_log_index_from_disk`), then enables Gnosis (only) with the
  log index on and the PostageStamp watch entry at its real deployment block.
  Later starts leave settings alone. The Index tab shows the seed's provenance
  and its usable-until block while the engine's index is on, or says why the
  bundled seed did not get installed. The bundle also carries **warm Gnosis
  peer caches** (`data/bee/gnosis/peers-gnosis.cache`,
  `cl-peers-gnosis.cache` — the engine's own text formats, public peers only,
  re-verified on dial), installed the same way when the data dir has none,
  so the app starts with known snap peers instead of a cold pool. Refresh
  them when refreshing the seed, from a node that has run Gnosis for a while:
  the daemon writes `app/peers-gnosis.cache` and `app/cl-peers-gnosis.cache`
  (its data dir), the desktop app the same names under `~/.myotis`; drop the
  lines the engine has already demoted (`fails=5` and above, or `snapbad`)
  so the shipped set is warm, not just long. *Purge cache* in the PoC
  deletes both files, so the next start re-installs the shipped ones — the
  PoC never truly starts cold, by design.
- **Point Bee at it**: `blockchain-rpc-endpoint: http://127.0.0.1:8546` with
  the config from *Setup* step 5. Once the beacon sync reaches `SYNCED`
  (seconds with a fresh anchor; the stale-anchor dialog first if the build is
  older than ~34 h) Bee's first page at 47,061,408 is served, and the head
  bridge closes the gap between the seed's top and the live head within
  minutes. The PoC has its own data dir but the same default RPC port as a
  regular Myotis running Gnosis — stop that one or move its port, or Bee
  talks to the unseeded instance.
- **Expiry**: the seed is usable until roughly 500,000 blocks (~29 days) above
  its fetch — the manifest and the Index tab say which block. After that the
  data set must be re-fetched and the app rebuilt; the shelf-life rule from the
  seed section applies unchanged. The Gnosis trust anchor embedded in the
  build ages out faster (~34 h), so the first start of a build older than that
  opens on the stale-anchor consent dialog — expected, press accept.

Packaging note that this build surfaced (and that applies to the regular
dmg): a jpackage'd app is ad-hoc signed with library validation, so macOS
refuses the unsigned `libjnidispatch` JNA extracts to `~/Library/Caches/JNA`
at runtime — the Rust engine then silently never loads and the app runs on
the Java engine, which has no log index. `prepareJnaBootLib` stages the stub
inside the bundle under a `.dylib` name (jpackage's signing pass signs
`*.dylib` files, not a `.jnilib`; JNA's boot-path lookup accepts either) and
the launcher passes `-Djna.boot.library.path=$APPDIR/resources`; the dmg
workflow fails unless the stub is present, of the dmg's architecture, and
validly signed.

A second packaging note that this build surfaced, and that applies to the
regular dmg just the same: the app is a GUI app that serves *other* processes
over localhost, and macOS **App Nap** throttles a GUI app whose window is
hidden or fully covered down to the background scheduling band — `ps -M -p
<pid>` shows every thread at kernel priority `4`, back to `31` the moment the
window is frontmost. On an otherwise busy Mac (load average ~120) that turned
into multi-second gaps before the RPC server even accepted a connection (Bee's
requests sat unread in the kernel's accept backlog, `CLOSE_WAIT` with the whole
POST in `Recv-Q`), safepoint syncs of seconds, one 92 s Full GC, a head bridge
that took seven minutes instead of thirty seconds, and Bee's 10-minute postage
stall. Measured 2026-09-16, same host, same minute: napped, 25 of 40
`eth_blockNumber` probes took over a second (up to 18 s); un-napped, 0 of 30
(16–144 ms). The app therefore holds an `NSProcessInfo` activity
(`NSActivityUserInitiatedAllowingIdleSystemSleep`) for its whole lifetime
(`AppNap.kt`, through JNA's Objective-C runtime calls) and logs the outcome as
the first line of every start; being in-process this covers `:app-desktop:run`
dev runs too. Measured the same way: with the activity held, two minutes
hidden left every thread at `28`–`31`, never `4`. Two things it deliberately does not do: keep the Mac awake (a
closed lid or the idle-sleep timer still stops everything — `caffeinate` or the
*Prevent automatic sleeping* energy setting is that layer), and rely on the
`NSAppSleepDisabled` Info.plist key, which current macOS ignores — measured on
15.7 with the same hide-the-window procedure, a bundle carrying the key napped
exactly like one without (every thread `4T` within 30 s). The key's
user-defaults form does work and remains the in-place fix for a build from
before this change: `defaults write io.myotis.desktop.beepoc NSAppSleepDisabled
-bool YES` (`io.myotis.desktop` for the regular app) and a relaunch.

Everything the *Demo only* section says about trust applies: this is an
RPC-sourced, unverified seed served indistinguishably from walked coverage,
for demonstrating the Bee-on-Myotis path — not for production. The PoC dmg
rides along with releases only as the best-effort, separately named demo asset
described above, never as the wallet.

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
