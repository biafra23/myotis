# Running Myotis as Bee's RPC node — what is extra, and how to build it from source

For the Swarm team. Myotis is a verified Ethereum light client (beacon sync
committee → execution header chain → every read checked against it) that
exposes a JSON-RPC endpoint on localhost. A Swarm Bee **full node** can use that
endpoint as its `blockchain-rpc-endpoint` on Gnosis Chain instead of a hosted
RPC. This document says what Bee needs beyond what a stock Myotis does, how to
build a node that has it from source, and what the "backfill" you will see in
the logs is doing and why.

The long-form reference — every checked RPC method, the run reports, the trust
analysis — is `docs/bee-rpc-service.md`. This is the short path.

## 1. What Bee asks of an RPC node

Bee 2.8.2 (`full-node: true`, `swap-enable: true`) talks plain HTTP JSON-RPC
and uses exactly twelve methods: `web3_clientVersion` (its first call, fatal if
it fails), `eth_chainId` (must be 100), `eth_getBlockByNumber` (`"latest"`, with
`baseFeePerGas` and `logsBloom`), `eth_getBalance`, `eth_call`,
`eth_estimateGas`, `eth_maxPriorityFeePerGas`, `eth_getTransactionCount`
(including `"pending"`), `eth_sendRawTransaction`, `eth_getTransactionReceipt`,
`eth_getTransactionByHash` and `eth_getLogs`. No WebSocket, no filters, no
batches. All twelve are served verified by Myotis.

Three of Bee's rules shape everything below:

- **Postage sync gates startup.** Before it serves anything, Bee replays the
  PostageStamp contract's events (`0x45a1502382541Cd610CC9068e88727426b696293`,
  deployed at block 31,305,656) with `eth_getLogs` in 5,000-block pages. Its
  binary embeds a snapshot of those events up to block **47,061,407**, so it
  asks only from **47,061,408** to the head — but it asks for all of that, and
  it will not start in full mode until it has it.
- **A page that fails for 10 minutes shuts Bee down** (exit code 0, "postage
  syncing stalled"). Bee retries a failed page every 5 s and its stall clock
  counts *successful* pages, so for Bee a slow success is always better than a
  fast refusal. Start Myotis first, and only start Bee once the index covers
  the head (below).
- **The latest header must be under 60 s old** when Bee starts, and after the
  chequebook deploy Bee waits up to ~200 s for the wallet to hold xDAI.

## 2. What a stock Myotis already does — and what is extra for Bee

Stock Myotis, any build, on Gnosis:

- verified head (beacon light client, sync-committee signatures — the only
  trust anchor, plus the embedded checkpoint the build ships);
- verified reads against that head from SNAP peers over devp2p: `eth_call`,
  `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
  `eth_getStorageAt`, blocks and receipts by number/hash, transaction
  broadcast to the peers and receipt lookup;
- a **log index** for `eth_getLogs`: logs are extracted from *verified*
  receipts (checked against each header's receipts root) for a configurable
  watch-list of contract addresses, stored locally, and served only for the
  block range the index actually covers. A query outside coverage is
  **refused** with a retryable error (`-32000`, "requested range is not indexed
  yet (covered: A–B)") — never answered with a misleading `[]`.

That last point is the whole difference. Bee's `eth_getLogs` needs coverage of
the PostageStamp address from 47,061,408 to the live head **before `bee
start`**. Building that coverage the verified way — walking the chain and
fetching every block's receipts from peers — takes days on a fresh install,
and Bee gives you ten minutes. So a Bee-ready Myotis needs three extra things:

1. **The watch-list entry**: the PostageStamp address at its real deployment
   block, `0x45a1502382541Cd610CC9068e88727426b696293:31305656`. The index
   refuses queries below an entry's deployment block, so the block matters.
2. **Coverage from before Bee's first page to the head, on day one.** This is
   what the *seed* provides: the contract's logs from block 47,000,000
   onward, fetched once from a full node with `eth_getLogs`, framed into the
   index's portable snapshot format by `scripts/synth_logindex.py`, and either
   imported into a running node or bundled into the app so it is in place at
   the first start. The seed is **unverified** when it lands (it is whatever
   the full node said); the walker re-fetches and verifies the same span in
   the background afterwards (section 5). The committed data set is
   `data/bee/gnosis/postagestamp-logs-47000000-48262804.jsonl.gz` (+ its
   `.meta.json`): ~39k logs, blocks 47,000,000–48,262,804, fetched
   2026-09-15 from a geth full node.
3. **Warm peer caches**, because a cold peer pool on Gnosis can starve the
   head-following machinery for long enough to trip Bee's 10-minute rule
   (`data/bee/gnosis/peers-gnosis.cache`, `cl-peers-gnosis.cache`: public
   peers only, re-verified on every dial).

Two things that are *not* Bee-specific but were found while doing this and
are now in every desktop build: the packaged macOS app opts out of App Nap
(a hidden window used to throttle the process to the background scheduling
band, which stalled the RPC for seconds at a time), and the JNA stub is
bundled so the Rust engine actually loads in an ad-hoc-signed app.

Nothing in Bee's path is answered from an unverified source except the seed
itself, and the seed is the reason this is called a PoC, not a release:
someone who controls the full node the logs came from could feed Bee wrong
postage events until the walker has re-fetched that span.

## 3. Build it from source

### Prerequisites

- **JDK 21**, of the same CPU architecture as the machine (Compose Desktop
  picks its natives by the Gradle JVM's arch while jpackage follows the
  toolchain JDK's; a mixed pair produces an app that dies at launch). On a
  Mac with several JDKs, pin it explicitly as shown below.
- **Rust** (rustup, stable — `rust/rust-toolchain.toml` selects the version).
  The Gradle build compiles the engine (`cargoBuildHost`) on its own.
- **Python 3.9+** for `scripts/synth_logindex.py` (standard library only).
- macOS + Xcode command-line tools for the dmg; the dev run works on Linux
  too.

```bash
git clone https://github.com/biafra23/myotis.git && cd myotis
```

### Route A — the Bee PoC desktop app (`-PbeePoc`)

A separate flavour of the desktop app: its own name ("Myotis Bee PoC"), bundle
id and data dir (`~/.myotis-bee-poc`), so it coexists with a regular Myotis.
The build synthesizes the seed from the committed data set, bundles it with a
manifest (coverage, usable-until block, sha256) and the peer caches; the first
start installs them into the data dir, enables Gnosis with the log index on
and the PostageStamp watch entry, and the engine activates the seed.

```bash
# dev run (any OS)
./gradlew :app-desktop:run -PbeePoc

# macOS .app and .dmg — Gradle must run under the target-arch JDK 21
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home   # your aarch64 (or x86_64) JDK 21
./gradlew :app-desktop:packageDmg -PbeePoc -Porg.gradle.java.installations.paths=$JAVA_HOME
# → app-desktop/build/compose/binaries/main/dmg/Myotis Bee PoC-<version>.dmg
#   (createDistributable instead of packageDmg gives just the .app under …/main/app/)
```

What `-PbeePoc` changes, so you can audit it: `app-desktop/build.gradle.kts`
(`prepareBeePocSeed` runs the script and stages seed + manifest + caches into
the bundle; the app name/bundle id; `-Dmyotis.beePoc=true` in the launcher) and
`app-desktop/src/main/kotlin/io/myotis/desktop/BeePoc.kt` (the first-start
install and settings). A build without the flag carries none of it.

You do not have to build it: CI produces the same artifact on every PR and
push (`Desktop DMG (macOS)` workflow → artifact `myotis-bee-poc-dmg-arm64-<sha>`)
and attaches `Myotis-bee-poc-arm64.dmg` to each release (best-effort; v0.1.10
has it).

### Route B — the daemon plus an imported seed

The headless daemon serves the same RPC. Useful on a server, or to use your
own full node as the seed source.

```bash
# 1. synthesize a seed from the committed data set (or your own, see below)
scripts/synth_logindex.py \
  --meta data/bee/gnosis/postagestamp-logs-47000000-48262804.meta.json \
  --logs data/bee/gnosis/postagestamp-logs-47000000-48262804.jsonl.gz \
  --watch 0x45a1502382541Cd610CC9068e88727426b696293:31305656 \
  --out /tmp/bee-logindex-gnosis-seed.db

# 2. run the Gnosis daemon (RPC on http://127.0.0.1:8546), wait for SYNCED
./gradlew :app:run -Pnetwork=gnosis
./gradlew :app:run -Pnetwork=gnosis -Pargs=beacon-status      # "state":"SYNCED"

# 3. import the seed; the head bridge then closes the gap from the seed's top
#    to the live head (seconds to minutes), after which head-follow takes over
./gradlew :app:run -Pnetwork=gnosis -Pargs="import-logindex /tmp/bee-logindex-gnosis-seed.db"
```

The same seed file also works as a drop-in for the **regular desktop app**:
enable the Gnosis log index in Settings with the watch entry above, stop the
network, copy the file to `~/.myotis/logindex-gnosis.db`, start it — the engine
activates a snapshot it finds there.

### Making your own data set (recommended for a real test)

The committed set is a snapshot in time. From any Gnosis full node you trust
(geth, nethermind, erigon — `eth_getLogs` over its HTTP RPC):

1. Fetch all logs for `address = 0x45a15023…6293` from block 47,000,000 (a
   round number safely below Bee's first page) to the node's head, in ≤5,000-
   block pages, and write them as JSON Lines — one log object per line, exactly
   as the node returned it — gzipped.
2. Write the `.meta.json` next to it with the same fields as the committed one
   (chain id, genesis hash, the filter address and block range, the sha256 of
   the uncompressed JSONL, and where it came from). The script cross-checks
   every one of them and refuses a set that does not match.
3. Run `scripts/synth_logindex.py` as above with your files (`--check` verifies
   an existing seed; `--manifest` writes the properties file the PoC app
   reads).

The walker later re-fetches the seeded span from peers and verifies it; the
seed only has to be *complete*, because a log missing from it would be
invisible to Bee until the walker reaches that block.

### Point Bee at it

`~/.bee/bee.yaml` (flat keys — Bee's config parser rejects unknown or nested
ones):

```yaml
full-node: true
swap-enable: true
chequebook-enable: true          # the wallet needs xDAI for the chequebook deploy
mainnet: true
network-id: 1
blockchain-rpc-endpoint: http://127.0.0.1:8546
storage-incentives-enable: false # true only once you stake; the agent runs at zero stake but IsPlaying reverts
resolver-options: []
cors-allowed-origins:            # only if you run Bee Dashboard (npx @ethersphere/bee-dashboard) against it
  - http://localhost:8080
```

Order of operations: start Myotis, wait for `SYNCED`, wait for the index to
cover the head (the Index tab shows the covered range; from the daemon,
`-Pargs=status`), then `bee start --config ~/.bee/bee.yaml`. Bee's log then
shows `connected to blockchain backend version="Myotis/verified-light-client"`
and, a few seconds later, `starting in full mode`.

## 4. What a working node looks like

From the 2026-09-15/16 runs against the PoC app: Bee synced postage events
from 47,061,408 to the head in 2–5 s from a seeded index, deployed its
chequebook through `eth_sendRawTransaction`, ran the zero-stake redistribution
agent through commit → reveal → claim → sample (where `IsPlaying` reverts for
an unstaked overlay, as designed), and every one of its calls came back
`VERIFIED`. Typical latencies are tens of milliseconds; `eth_call`s that need
fresh state proofs and `eth_getLogs` pages at the head edge occasionally take
1–20 s when a peer is slow (a hedged multi-peer fetch is the tracked
follow-up). Myotis's own log (`Logs` tab, filter `access`) shows every request
with its outcome and latency.

## 5. The backfill: what it does and why

The log index is honest about what it holds: **coverage** is one contiguous
block range whose logs, for the watch-list, have been extracted from verified
receipts (or, for a seeded span, imported and marked as such). A query
touching a block outside coverage is refused. Coverage grows on three paths,
all in a background task that shares the peer pool with your RPC traffic:

- **The backfill walker** — the one you see as "backfill progress cursor=…
  target=31305656" in the log. It descends from the low edge of coverage
  toward each watch entry's deployment block, fetching receipts for candidate
  blocks (bloom-filtered, in chunks), verifying them against the header chain,
  and inserting the logs. It is **insert-only**: it never evicts what is
  there, and it re-descends through a seeded span too — that is how the
  unverified seed becomes verified over time.
- **The per-block appender / head bridge** at finality: new finalized blocks
  are appended one by one (up to 16 per 6-s tick); a gap wider than 128 blocks
  (downtime, a laptop lid, a seed whose top is behind the head) is closed by
  the bridge in bulk, up to 500,000 blocks at a time.
- **The optimistic tail** above finality, which is where `"latest"` points and
  what Bee's page at the head needs. It is the only path that can reorg, and
  it carries the rewind for that.

Why the walker keeps going below Bee's range: the watch entry says the
contract has existed since 31,305,656, and the index promises verified
coverage for its watch-list — so it walks the ~16 million blocks between the
seed's low (47,000,000) and the deployment block. Bee never asks for any of
that (its embedded snapshot ends at 47,061,407), so this part is completeness
and verification, not a prerequisite: it runs at a bounded pace, it does not
block serving, and Bee is served from the first minute regardless. A knob to
stop the walk at a chosen block ("nothing below X is ever asked for") is an
open follow-up.

Two limits to know:

- **Shelf life.** The bridge closes gaps up to 500,000 blocks (~29 days of
  Gnosis blocks). An app whose seed is older than that never catches up to the
  head — the manifest and the Index tab show the block a bundled seed is
  usable until; past it, refresh the data set and rebuild (or import a fresh
  seed into the daemon).
- **Flaky peers can starve the appender.** The per-block appender gives up a
  tick on its first failed receipts read; with a bad peer set that can leave
  coverage drifting behind the head for longer than Bee's 10 minutes (seen
  once on 2026-09-16 after a canonicality drop at the tail). Restarting the
  node re-bridges in seconds; making the appender hedge across peers and the
  bridge trigger on stalled progress rather than on a fixed gap is the
  planned fix.

## 6. Trust, in one paragraph

Everything Bee receives is verified against sync-committee-signed headers —
except the seed, which is a full node's word until the walker has re-fetched
that span, and which is served indistinguishably from walked coverage while
that is the case. That is fine for a demo and for testing the integration; for
production the seed would have to come from a verifiable source (a signed
snapshot the walker can check, or simply a node that has walked the range
itself). Nothing here uses a hosted RPC at runtime: peers are devp2p and
libp2p only.
