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
batches. All twelve are served by Myotis, verified — with one carve-out this
document exists to explain: seeded `eth_getLogs` coverage is a full node's
word until the walker re-verifies it, and not all of it can be (sections 2, 5
and 6).

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
- **The latest header must be under 60 s old** when Bee starts, and before
  deploying its chequebook Bee waits up to ~200 s (10 × 20 s) for the wallet
  to hold xDAI.

## 2. What a stock Myotis already does — and what is extra for Bee

Stock Myotis, any build, on Gnosis:

- verified head (beacon light client, sync-committee signatures — the only
  trust anchor, plus the embedded checkpoint the build ships);
- verified reads against that head from SNAP peers over devp2p: `eth_call`,
  `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
  `eth_getStorageAt`, blocks and receipts by number/hash, transaction
  broadcast to the peers and receipt lookup;
- a **log index** for `eth_getLogs` (Rust engine only — the default, and the
  one every build in section 3 ships; a `-PskipRustEngine` build has no log
  index at all): logs are extracted from *verified* receipts (checked against
  each header's receipts root) for a configurable
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
   block, `0x45a1502382541Cd610CC9068e88727426b696293:31305656`. Below an
   entry's deployment block the index answers `[]` by definition (the contract
   did not exist) without consulting coverage — so the block must be the real
   one: with the seed's low edge (47,000,000) there instead, the whole
   unwalked band below the seed would be served as a silent empty answer
   instead of being refused.
2. **Coverage from before Bee's first page to the head, on day one.** This is
   what the *seed* provides: the contract's logs from block 47,000,000
   onward, fetched once from a full node with `eth_getLogs`, framed into the
   index's portable snapshot format by `scripts/synth_logindex.py`, and either
   imported into a running node or bundled into the app so it is in place at
   the first start. The seed is **unverified** when it lands (it is whatever
   the full node said); the walker later re-fetches the same span from peers
   in the background (section 5) — which fills holes and overwrites what it
   finds, but cannot remove a log the seed invented. The committed data set is
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
postage events, and an invented event survives the walker's re-fetch (below).

## 3. Build it from source

### Prerequisites

- **JDK 21**, of the same CPU architecture as the machine (Compose Desktop
  picks its natives by the Gradle JVM's arch while jpackage follows the
  toolchain JDK's; a mixed pair produces an app that dies at launch). On a
  Mac with several JDKs, pin it explicitly as shown below.
- **Rust** (rustup; `rust/rust-toolchain.toml` selects the stable channel and
  the Gradle build enforces the minimum version). The Gradle build compiles
  the engine (`cargoBuildHost`) on its own.
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
start installs them into the data dir, enables Gnosis (only — mainnet is
switched off) with the log index on and the PostageStamp watch entry, and
the engine activates the seed.

```bash
# dev run (any OS)
./gradlew :app-desktop:run -PbeePoc

# macOS .app and .dmg — Gradle must run under the target-arch JDK 21, and the
# toolchain must be pinned to that same JDK (the CI workflow does exactly this)
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home   # your aarch64 (or x86_64) JDK 21
./gradlew :app-desktop:packageDmg -PbeePoc \
  -Porg.gradle.java.installations.auto-detect=false \
  -Porg.gradle.java.installations.auto-download=false \
  -Porg.gradle.java.installations.paths=$JAVA_HOME
# → app-desktop/build/compose/binaries/main/dmg/Myotis Bee PoC-1.1.10.dmg
#   (jpackage rejects a 0 major, so the macOS package version is the project
#   version with the major raised by one: 0.1.10 → 1.1.10; createDistributable
#   instead of packageDmg gives just the .app under …/main/app/)
```

What `-PbeePoc` changes, so you can audit it: `app-desktop/build.gradle.kts`
(`prepareBeePocSeed` runs the script and stages seed + manifest + caches into
the bundle; the app name/bundle id; `-Dmyotis.beePoc=true` in the launcher) and
`app-desktop/src/main/kotlin/io/myotis/desktop/BeePoc.kt` (the first-start
install and settings). A build without the flag carries none of it.

You do not have to build it: CI produces the same artifact on every PR and
every push to `main` (`Desktop DMG (macOS)` workflow → artifact
`myotis-bee-poc-dmg-arm64-<sha>`)
and attaches `Myotis-bee-poc-arm64.dmg` to each release (best-effort; v0.1.10
has it).

### Route B — the daemon plus an imported seed

The headless daemon serves the same RPC. Useful on a server, or to use your
own full node as the seed source.

```bash
# 1. synthesize a seed from the committed data set (or your own, see below)
python3 scripts/synth_logindex.py \
  --meta data/bee/gnosis/postagestamp-logs-47000000-48262804.meta.json \
  --logs data/bee/gnosis/postagestamp-logs-47000000-48262804.jsonl.gz \
  --watch 0x45a1502382541Cd610CC9068e88727426b696293:31305656 \
  --out /tmp/bee-logindex-gnosis-seed.db

# 2. run the Gnosis daemon (RPC on http://127.0.0.1:8546) — it blocks until
#    stopped, so keep it running and do the rest from a second terminal
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
   round number safely below Bee's first page) to the node's head, in pages
   your node accepts (the committed set used 50,000-block pages), and write
   them as JSON Lines — one log object per line, exactly as the node returned
   it — gzipped. The script drops the top 128 blocks of the fetch by default
   (`--finality-margin`), so fetching to the head is safe; fetch to
   `finalized` and pass `--finality-margin 0` if you want every block kept.
2. Write the `.meta.json` next to it, shaped like the committed one. The
   script requires and cross-checks `chainId`, `genesisHash`, `fromBlock`,
   `toBlock`, `sha256Jsonl` (of the uncompressed JSONL) and
   `filter{address, fromBlock, toBlock}`, and refuses a set that does not
   match; the provenance fields (`rpcClientVersion`, `fetchedAtUtc`, `note`)
   are for humans.
3. Run `python3 scripts/synth_logindex.py` as above with your files
   (`--check` verifies an existing seed; `--manifest` writes the properties
   file the PoC app reads).

The walker later re-fetches the seeded span from peers; the seed has to be
*complete and honest*: a log missing from it is invisible to Bee until the
walker reaches that block, and a log invented in it is never removed.

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
`-Pargs=logindex-status` — read `coveredHigh` and `headGap`), then
`bee start --config ~/.bee/bee.yaml`. Bee's log then
shows `connected to blockchain backend version="Myotis/verified-light-client"`
and, a few seconds later, `starting in full mode`.

## 4. What a working node looks like

From the 2026-09-15/16 runs: against the PoC app on 2026-09-16 Bee synced
postage events from 47,061,408 to the head in 2–5 s from the seeded index
(the first run on 2026-09-15, against the daemon, took about four minutes
end to end); it deployed its
chequebook through `eth_sendRawTransaction`, ran the zero-stake redistribution
agent through commit → reveal → claim → sample (where `IsPlaying` reverts for
an unstaked overlay, as designed), and every one of its calls came back
`VERIFIED`. Typical latencies are tens of milliseconds; `eth_call`s that need
fresh state proofs and `eth_getLogs` pages at the head edge occasionally take
1–20 s when a peer is slow. Reads now ask a second peer after 3 s without an
answer (6 s for a block or receipt read far behind the head), which trims
most of that tail; the optimistic tail's own head-edge fetch is not hedged
yet. Myotis's own log (`Logs` tab, filter `access`) shows every request with
its outcome and latency.

## 5. The backfill: what it does and why

The log index is honest about what it holds: **coverage** is one contiguous
block range whose logs, for the watch-list, have been extracted from verified
receipts (or, for a seeded span, imported — the index itself does not
distinguish the two; only the PoC's manifest sidecar tells the Index tab). A
query touching a block outside coverage is refused with
`-32000 requested range is not indexed yet (covered: A-B); retry as the index
catches up`. Coverage grows on three paths,
all in a background task that shares the peer pool with your RPC traffic:

- **The backfill walker** — the one you see as "backfill progress cursor=…
  target=31305656" in the log. It descends from its trust cursor — the head
  block where the appender first anchored the index, which for a seeded
  index lies above the seed — toward each watch entry's deployment block,
  fetching receipts for candidate blocks (bloom-filtered, in chunks),
  verifying them against the header chain, and inserting the logs. It is
  **insert-only**: on its way down through a seeded span it fills holes and
  overwrites a seeded log that has a verified twin at the same (block, log
  index) key, but it never deletes anything — a seeded log with no verified
  counterpart stays. A wrong seed is fixed by deleting the index file and
  re-seeding, not by waiting.
- **The per-block appender / head bridge** at finality: new finalized blocks
  are appended one by one (up to 16 per 6-s tick); a gap wider than 128 blocks
  (downtime, a laptop lid, a seed whose top is behind the head) is closed by
  the bridge in bulk — but only up to 500,000 blocks; a wider gap is never
  closed (see *Shelf life*).
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
stop the walk at a chosen block ("nothing below X is ever asked for") is a
follow-up we intend to do; it is not tracked yet.

Two limits to know:

- **Shelf life.** The bridge closes gaps up to 500,000 blocks (~29 days of
  Gnosis blocks). An app whose seed is older than that never catches up to the
  head — the manifest and the Index tab show the block a bundled seed is
  usable until; past it, refresh the data set and rebuild (or import a fresh
  seed into the daemon).
- **Flaky peers can starve the appender.** The per-block appender gives up a
  tick on its first failed receipts read; with a bad peer set that can leave
  coverage drifting behind the head for longer than Bee's 10 minutes (seen
  once on 2026-09-16 after the optimistic tail detected a reorg and rewound).
  Both halves of the fix have landed: a stalled appender now hands its gap
  to the bridge after about 18 s, and the receipts read it depends on is
  hedged across peers. Restarting the node still re-bridges in seconds if
  you would rather not wait.

## 6. Trust, in one paragraph

Everything Bee receives is verified against sync-committee-signed headers —
except the seed, which is a full node's word, is served indistinguishably from
walked coverage, and is only partly repaired by the walker's re-fetch (holes
filled, same-key logs overwritten, invented logs kept). That is fine for a
demo and for testing the integration; for
production the seed would have to come from a verifiable source (a signed
snapshot the walker can check, or simply a node that has walked the range
itself). Nothing here uses a hosted RPC at runtime: peers are devp2p and
libp2p only.
