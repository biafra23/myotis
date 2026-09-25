# RAILGUN PoC desktop build

A flavour of the desktop app that the [RAILGUN Terminal Wallet
CLI](https://github.com/Terminal-Wallet/terminal-wallet-cli) can be pointed at
instead of a public RPC provider, from the first minute. It is the mainnet
sibling of the Bee PoC build (docs/bee-rpc-service.md) and shares all of its
machinery — see `PocFlavour.kt`, with `BeePoc.kt` and `RailgunPoc.kt` as the two
configurations of it.

```bash
./gradlew :app-desktop:packageDmg -PrailgunPoc -PrailgunSeedDir="$HOME/myotis-node/railgun"
```

**DEBUG / DEMO artefact, not a production path.** The bundled index is a full
node's `eth_getLogs` output framed by `scripts/synth_logindex.py`. It carries no
receipt-root proof and the engine serves it indistinguishably from logs the
walker verified itself. The repo rule stands: a local client over http "may only
be used for debugging purposes, it is not an option for production" (CLAUDE.md,
*Data sources*).

## Why a seed at all

The wallet rebuilds its private balances by scanning one contract's entire
history. Over devp2p that is a multi-day downward walk before the wallet can show
a balance, which is not a demo. The seed makes the same history available at
first start; the verified walk is the product, this is the thing you can show
today.

## What is in it

| | |
|---|---|
| contract | RailgunSmartWallet proxy, `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9` |
| deployment block | 14,737,691 |
| coverage | 14,737,691 → the fetch's `finalized` block |
| logs | ~426,000 over ~11.3M blocks |
| index size | ~243 MB |

The Terminal Wallet hardcodes no addresses. It depends on
`@railgun-community/wallet`, which reads them from
`@railgun-community/shared-models`; for chain id 1 that config names this proxy.
The relay-adapt contract it also names is used to build transactions rather than
scanned for history, and the V3 contracts are not deployed on mainnet, so one
watch entry covers what the wallet reads.

### The deployment block is load-bearing

`from_block` is the engine's assertion that the contract has **no logs below
it**: below that height `LogIndex::query` answers `[]` without consulting
coverage at all. So the number must be the contract's real deployment block, not
the low edge of whatever range was fetched.

**14,693,013 circulates as "the RAILGUN deployment block" and is wrong for this
purpose.** Both the SDK config and the chain say 14,737,691: the proxy's first
log falls on exactly that block, and a sweep from genesis to it found no logs at
all (zbox, 2026-09-22). Using the lower number would turn 44,678 blocks of real
history into plausible empty answers — the silent-corruption case the coverage
rules exist to prevent.

Because coverage starts *at* the deployment block, this seed's coverage is
complete downward. Nothing is left for the walker to fill, and every query is
either served or refused as above the covered head. That is the one way this
flavour is simpler than the Bee one, whose seed starts well above its contract's
deployment.

## Building the seed

The data is **not committed**. The Bee flavour's set is a 58 MB gzip of ~39k
logs; this one is 426k logs and 549 MB raw, which does not belong in a clone.
Fetch it once, onto a host with a synced mainnet node, and point the build at it.

```bash
SEED=$HOME/myotis-node/railgun && mkdir -p "$SEED"

# 1. fetch the logs, one JSON object per line exactly as returned.
#    ~36 min against a local geth; resumable if it is interrupted.
./scripts/fetch_contract_logs.py \
    --rpc http://127.0.0.1:8545 \
    --address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 \
    --from-block 14737691 --to-block finalized \
    --out "$SEED/railgun-logs.jsonl"

# 2. write the sidecar the framing script checks the JSONL against.
#    The command printed by step 1 has the resolved block filled in.
./scripts/write_logs_meta.py \
    --rpc http://127.0.0.1:8545 \
    --address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 \
    --from-block 14737691 --to-block <resolved> --to-block-tag finalized \
    --logs "$SEED/railgun-logs.jsonl"

# 3. the build frames it into build/railgunPocAppResources/common/
./gradlew :app-desktop:prepareRailgunPocSeed -PrailgunPoc -PrailgunSeedDir="$SEED"

# ...or frame it by hand first, to inspect what it claims before packaging
./scripts/synth_logindex.py \
    --meta "$SEED"/railgun-logs-14737691-<resolved>.meta.json \
    --logs "$SEED/railgun-logs.jsonl" \
    --watch 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9:14737691 \
    --finality-margin 0 \
    --out /tmp/railgun-seed.db
./scripts/synth_logindex.py --check /tmp/railgun-seed.db
```

Step 1 is resumable: rerun it after an interruption and it continues from the
last completed page. Pass the **resolved** high block rather than `finalized`
when you do, since that tag has moved on in the meantime — the script refuses a
range that does not match the partial fetch rather than silently restarting it,
and names the arguments that resume it.

**Fetch to `finalized`.** A finalized range cannot reorg, so the seed needs no
margin trimmed off its top, and `write_logs_meta.py` records that as
`toBlockTag`. The build reads that field and passes `--finality-margin 0` only
when it says `finalized`; any other fetch keeps the default 128-block margin.
This is deliberately not a convention the developer has to remember: a fetch to
`latest` framed with no margin would freeze a since-orphaned block into the seed,
and the engine would then serve it as fully covered — a silent wrong answer.

The claim is checked, not taken on trust: `write_logs_meta.py` compares the
fetch's high block against the node's current `finalized` height and refuses to
record the tag when the range can still reorg. That is stronger than believing
the tag, since a fetch that ran to `latest` yesterday is final today and
legitimately qualifies.

`prepareRailgunPocSeed` expects exactly one `*.meta.json` in the seed directory
and refuses to guess when it finds several, since the range is part of the name
and a re-fetch leaves the old one behind.

## Shelf life

**500,000 mainnet blocks, about 69 days.** The head bridge maps at most that much
above a file's top (`MAX_GAP`, `el/reader.rs`), so a seed older than that imports
fine and then never catches up to the head. The manifest records the block it is
usable until; rebuild the app with a fresh fetch after that.

## What the flavour does at runtime

- Lives in `~/.myotis-railgun-poc`, never touching a regular install's
  `~/.myotis` or the Bee flavour's dir. Bundle id
  `io.myotis.desktop.railgunpoc`, app name *Myotis RAILGUN PoC*.
- Installs the bundled seed into that dir before the engine starts, checking it
  against the manifest's sha256 first, and never over an index it did not install
  itself. A newer bundled seed re-seeds; an equal or older one is left alone —
  see *Re-seeding* below for a caveat.
- First start only: enables mainnet, disables gnosis, switches the log index on,
  stores the seed's watch entry, and **pins the RPC port to 8555**. Point the
  wallet at `http://127.0.0.1:8555`; it serves as soon as the beacon sync reaches
  `SYNCED`. Later starts never touch settings.
- The Index tab states what the seed covers and that it is unverified.

### Why 8555 and not 8545

A regular Myotis install serves mainnet on 8545. Two installed apps would compete
for it, only one would bind, and a wallet aimed at 8545 could silently reach the
regular install — which has no seeded index and answers this demo's own queries
with `-32000`, looking exactly like a broken configuration. The Bee flavour never
had this problem because no regular install serves gnosis on 8546 by default.

### Re-seeding, and a caveat worth knowing

A rebuilt app whose seed reaches further than the installed manifest records
replaces the index in the data dir. That is what makes an expired seed
recoverable: install the newer build and the demo works again.

**It can also move the index backwards.** The engine rewrites the same file as
its own checkpoint, so after a long run head-follow has taken the live index past
the manifest written at install time — possibly past the new seed too. Re-seeding
then swaps a further-along index for a shorter frame, and queries in the
difference turn from served into `-32000` until the bridge re-walks them. With a
69-day shelf life on mainnet that window is wide.

Deciding this correctly needs the live index's own coverage, which only the engine
can read; a file-timestamp proxy was tried and rejected as platform-dependent. The
shipped Bee flavour re-seeds unconditionally and its tests pin that, so changing
it is a decision for the owner rather than something this flavour does differently
on its own. Until then, the safe move before installing a rebuilt app on a machine
that has been running for weeks is to keep a copy of `~/.myotis-railgun-poc`.

Unlike the Bee flavour it ships **no warm peer caches** — none have been captured
for mainnet — so discovery seeds from the embedded bootnodes. That costs a slower
first minute, not correctness.

## CI

`.github/workflows/railgun-dmg.yml` builds the arm64 installer on every push to
`main`, on `v*` tags, and on manual dispatch. It is separate from
`desktop-dmg.yml` because this flavour's seed is not in the tree: gzipped it is
117 MB, over GitHub's 100 MB per-file limit, and nothing that size belongs in a
clone anyway.

**The seed lives on the `railgun-seed` release** as two assets, and the build
fetches them from there. Nothing needs configuring.

| asset | |
|---|---|
| `railgun-seed.tar.gz` | the fetch: `railgun-logs.jsonl` and its `*.meta.json` |
| `railgun-seed.tar.gz.sha256` | its checksum, which the build requires and checks before framing |

It is a release for data, deliberately separate from the app releases: an app
release cannot be built until the seed exists. Its tag triggers no workflow
(they all key on `v*`).

The workflow **bundles** the framed index into the dmg. The installed app never
touches the network for its index and works offline from the first start; the
dmg is roughly 100 MB larger than the standard one for it.

### Refreshing the seed

The seed's shelf life is ~69 mainnet days (500,000 blocks, `MAX_GAP`). To
refresh it, run the fetch again (*Building the seed* above), then replace both
assets and rebuild:

```bash
cd "$HOME/myotis-node/railgun" && tar -czf railgun-seed.tar.gz railgun-logs.jsonl railgun-logs-*.meta.json
sha256sum railgun-seed.tar.gz > railgun-seed.tar.gz.sha256
gh release upload railgun-seed railgun-seed.tar.gz railgun-seed.tar.gz.sha256 --clobber
gh workflow run railgun-dmg.yml
```

The archive may hold the files flat or under a directory; the build locates the
`*.meta.json` inside it either way, and refuses an archive holding more than one.

### Overrides

Two repository variables redirect a build at a different seed, for a refresh
under test or a fork's own asset. Both are optional.

| variable | |
|---|---|
| `RAILGUN_SEED_URL` | another `.tar.gz` of a fetch directory |
| `RAILGUN_SEED_SHA256` | its sha256, in place of the `.sha256` sidecar the build otherwise fetches from beside the archive |

### What the checksums establish

The sidecar travels from the same place as the archive, so in CI it proves the
download arrived intact — a truncated archive would otherwise frame
"successfully" with fewer logs than it should have, which no later step can tell
from a genuinely short range. It does not prove who published it; that rests on
GitHub's TLS and on release assets being writable only with write access to the
repository. The stronger check is the manifest inside the dmg: written at build
time with the framed index's own hash and sealed into the bundle, it is what the
app verifies before installing the index.

### Artifact names

| build | name |
|---|---|
| `main`, dispatch on a branch or a non-`v` tag | `Myotis-railgun-poc-arm64.dmg` |
| `v*` tag | `Myotis-v<version>-railgun-poc-arm64.dmg` |

The tag build carries the version so a downloaded file identifies itself; the
`main` build stays unversioned so "the latest build" is a stable name. On a tag
the dmg is also attached to the GitHub release, alongside the standard dmgs, the
Bee PoC dmg and the Android APK, and named the way they are: the whole tag right
after `Myotis-` (`Myotis-v<version>-arm64.dmg`,
`Myotis-v<version>-bee-poc-arm64.dmg`), so a release's macOS assets read as one
set. v0.1.12, the first release with this flavour, carries it under this name
too: its tag build failed before #479 fixed the seed check, and the dmg was
uploaded by hand.

### What CI asserts about the dmg

Beyond the architecture and engine checks the standard legs make, this one opens
the built image and requires that it carries `logindex.db` (mainnet's name, with
no network suffix — a suffixed one would install fine and never be opened), its
manifest, a manifest pinning `deploymentBlock=14737691`, coverage starting at
that block, and none of the Bee flavour's files. A dmg that installs cleanly with
no index inside is exactly the failure this artifact exists to prevent, and
nothing at runtime would report it except a wallet getting `-32000` forever.
