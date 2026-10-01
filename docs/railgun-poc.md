# RAILGUN PoC desktop build

A flavour of the desktop app that the [RAILGUN Terminal Wallet
CLI](https://github.com/Terminal-Wallet/terminal-wallet-cli) can be pointed at
instead of a public RPC provider, from the first minute, on mainnet and on
Sepolia. It is the sibling of the Bee PoC build (docs/bee-rpc-service.md) and
shares all of its machinery — see `PocFlavour.kt`, with `BeePoc.kt` and
`RailgunPoc.kt` as the two configurations of it, and a `PocSeed` per network.

```bash
./gradlew :app-desktop:packageDmg -PrailgunPoc \
    -PrailgunSeedDir="$HOME/myotis-node/railgun" \
    -PrailgunSepoliaSeedDir="$HOME/myotis-node/railgun-sepolia"
```

**DEBUG / DEMO artefact, not a production path.** Each bundled index is a full
node's `eth_getLogs` output framed by `scripts/synth_logindex.py`. It carries no
receipt-root proof and the engine serves it indistinguishably from logs the
walker verified itself. The repo rule stands: a local client over http "may only
be used for debugging purposes, it is not an option for production" (CLAUDE.md,
*Data sources*).

The seeded-history carve-out (CLAUDE.md, owner's decision 2026-09-25;
docs/seeded-log-histories.md) does not cover this build, so the label stands.
It accepts a seed on its protocol maintainers' word — the RAILGUN engine's
`rootHistory` check keeps forged commitments out of its tree but does not
surface a withheld or altered one — and these seeds are the repo's own fetches
from a node over JSON-RPC, served without the provenance marker the carve-out
makes a precondition.

## Why a seed at all

The wallet rebuilds its private balances by scanning one contract's entire
history. Over devp2p that is a multi-day downward walk before the wallet can show
a balance, which is not a demo. The seed makes the same history available at
first start; the verified walk is the product, this is the thing you can show
today.

## What is in it

| | mainnet | Sepolia |
|---|---|---|
| contract | RailgunSmartWallet proxy, `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9` | RailgunSmartWallet proxy, `0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea` |
| deployment block | 14,737,691 | 5,784,774 |
| coverage | 14,737,691 → the fetch's `finalized` block | 5,784,774 → the fetch's `finalized` block |
| logs | ~438,000 over ~11.4M blocks | ~14,800 over ~6M blocks |
| index size | ~261 MB | ~9 MB |
| served on | `http://127.0.0.1:8555` | `http://127.0.0.1:8557` |

The Terminal Wallet hardcodes no addresses. It depends on
`@railgun-community/wallet`, which reads them from
`@railgun-community/shared-models`; for chain ids 1 and 11155111 that config
names these proxies. The wallet hands its engine the proxy, the relay-adapt
contract and the V3 contracts (`loadNetwork`, in the wallet's
`load-provider.ts`). The relay adapt is used to build transactions rather than
scanned for history, and the V3 contracts are deployed on neither network (empty
in that config, with `supportsV3: false`), so one watch entry per network covers
what the wallet reads. Sepolia's config also names a registry and an EIP-7702
relay adapt; the wallet hands neither to its engine.

The Terminal Wallet CLI has its own Sepolia network entry
(`src/config/config-defaults.ts`, public providers by default), so it is pointed at
`http://127.0.0.1:8557` the same way it is pointed at 8555 for mainnet.

### The deployment block is load-bearing

`from_block` is the engine's assertion that the contract has **no logs below
it**: below that height `LogIndex::query` answers `[]` without consulting
coverage at all. So the number must be the contract's real deployment block, not
the low edge of whatever range was fetched.

**14,693,013 circulates as "the RAILGUN deployment block" and is wrong for this
purpose.** Both the SDK config and the chain say 14,737,691: the proxy's first
log falls on exactly that block, and a sweep from genesis to it found no logs at
all (zbox, 2026-09-22).

Had the watch entry used the lower number, the seed would still hold every
RAILGUN log — there are none in between — but the index would stop treating it
as complete: `from_block` would claim a history starting 44,678 blocks before
the seed's coverage does, so a query reaching into that span would be refused as
out of coverage, and under this flavour's paused backfill
(`pauseBackfillByDefault = true`, `RailgunPoc.kt`) it would stay refused. Safe,
but not free. The direction that corrupts is the other one: a `from_block`
*above* the real deployment turns the history below it into plausible empty
answers (`LogIndex::query` clamps its coverage check to `from_block`,
`el/logindex.rs:563`), which is why `synth_logindex.py` refuses a deployment
block above the fetch's low edge.

**On Sepolia the SDK and the chain disagree, and the chain decides.** The proxy
was created in block 5,784,774 by a top-level transaction whose receipt names it
as the created contract, its first log is at 5,784,776, and a sweep from genesis
found no logs below that (zbox, 2026-10-01). shared-models gives 5,784,866
instead: that is where the wallet *starts scanning*, after the 62 logs of the
deployment's own setup (verifying keys, ownership, initialisation). As a watch
floor it would assert that those 62 logs do not exist — the corrupting direction
just described — so the seed uses the creation block. The retired Kohaku preset
(`LogIndexWatch.legacyKohakuWatchJson`) has 5,784,774 for Sepolia, which is
right; its mainnet number is the one that is not.

Because coverage starts *at* the deployment block, each seed's coverage is
complete downward. Nothing is left for the walker to fill, and every query is
either served or refused as above the covered head. That is the one way this
flavour is simpler than the Bee one, whose seed starts well above its contract's
deployment.

## Building the seed

The data is **not committed**. The Bee flavour's set is a 58 MB gzip of ~39k
logs; the mainnet one here is ~438k logs and 589 MB raw, which does not belong in
a clone. Fetch each once, onto a host with synced nodes, and point the build at
them. Mainnet's range starts before the Merge (block 15,537,394), so its node must
still hold pre-Merge receipts.

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

# Sepolia: the same two steps against a synced Sepolia node (~4 min), with
#   --address 0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea --from-block 5784774
# into a directory of its own, e.g. $HOME/myotis-node/railgun-sepolia.
SEPOLIA_SEED=$HOME/myotis-node/railgun-sepolia

# 3. the build frames both into build/railgunPocAppResources/common/
./gradlew :app-desktop:prepareRailgunPocSeed -PrailgunPoc \
    -PrailgunSeedDir="$SEED" -PrailgunSepoliaSeedDir="$SEPOLIA_SEED"

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

`prepareRailgunPocSeed` needs both directories. It expects exactly one
`*.meta.json` in each and refuses to guess when it finds several, since the range
is part of the name and a re-fetch leaves the old one behind. It also requires
each meta's chain id to match the network its property names, before framing
anything: a swapped pair would otherwise frame fine, install fine, and be ignored
by the engine, which checks each index file's chain tag — a silently seedless
network.

## Shelf life

**500,000 blocks, about 69 days on either network** (both have 12-second
slots). The head bridge maps at most that much above a file's top (`MAX_GAP`,
`el/reader.rs`), so a seed older than that imports fine and then never catches
up to the head. The manifest records the block it is
usable until; rebuild the app with a fresh fetch after that.

## What the flavour does at runtime

- Lives in `~/.myotis-railgun-poc`, never touching a regular install's
  `~/.myotis` or the Bee flavour's dir. Bundle id
  `io.myotis.desktop.railgunpoc`, app name *Myotis RAILGUN PoC*.
- Installs each bundled seed into that dir before the engine starts, checking it
  against its manifest's sha256 first, and never over an index it did not install
  itself. A newer bundled seed re-seeds; an equal or older one is left alone —
  see *Re-seeding* below for a caveat.
- First start: enables mainnet and Sepolia, disables gnosis, switches each log
  index on, stores each seed's watch entry, and **pins the RPC ports: 8555 for
  mainnet, 8557 for Sepolia**. Point the wallet at `http://127.0.0.1:8555` or
  `http://127.0.0.1:8557`; each serves as soon as its beacon sync reaches `SYNCED`.
- Each network is configured exactly once. An install whose first start predates
  the Sepolia seed gets Sepolia configured the same way by its first start of a
  build that bundles it; the settings file records which networks are done
  (`poc.configuredNetworks`). Nothing else on a later start touches settings, and
  a network the user turned off stays off.
- The Index tab states what each seed covers and that it is unverified.

### Why 8555 and 8557, not 8545 and 8547

A regular Myotis install serves mainnet on 8545, and Sepolia on 8547 once it is
switched on. Two installed apps would compete for the port, only one would bind,
and a wallet aimed at it could silently reach the regular install — which has no
seeded index and answers this demo's own queries with `-32000`, looking exactly
like a broken configuration. So each is the regular port plus ten. The Bee
flavour never had this problem because no regular install serves gnosis on 8546
by default.

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
for mainnet or Sepolia — so discovery seeds from the embedded bootnodes. That costs a slower
first minute, not correctness.

## CI

`.github/workflows/railgun-dmg.yml` builds the arm64 installer on every push to
`main`, on `v*` tags, and on manual dispatch. It is separate from
`desktop-dmg.yml` because this flavour's seeds are not in the tree: mainnet's,
gzipped, is ~120 MB, over GitHub's 100 MB per-file limit, and nothing that size
belongs in a clone anyway.

**The seeds live on the `railgun-seed` release** as four assets, and the build
fetches them from there. Nothing needs configuring.

| asset | |
|---|---|
| `railgun-seed.tar.gz` | the mainnet fetch: `railgun-logs.jsonl` and its `*.meta.json` |
| `railgun-seed.tar.gz.sha256` | its checksum, which the build requires and checks before framing |
| `railgun-seed-sepolia.tar.gz` | the Sepolia fetch, in the same shape |
| `railgun-seed-sepolia.tar.gz.sha256` | its checksum |

It is a release for data, deliberately separate from the app releases: an app
release cannot be built until the seeds exist. Its tag triggers no workflow
(they all key on `v*`).

The workflow **bundles** the framed indexes into the dmg. The installed app never
touches the network for its indexes and works offline from the first start; the
dmg is roughly 110 MB larger than the standard one for them.

### Refreshing the seed

Each seed's shelf life is ~69 days (500,000 blocks, `MAX_GAP`). To refresh one,
run its fetch again (*Building the seed* above), then replace both of its assets
and rebuild. Fetch into a **fresh directory** rather than over the previous one:
the old meta would otherwise sit beside the new one, which the build refuses, and
the old fetch is what you roll back to.

```bash
# mainnet
cd "$SEED" && tar -czf railgun-seed.tar.gz railgun-logs.jsonl railgun-logs-*.meta.json
sha256sum railgun-seed.tar.gz > railgun-seed.tar.gz.sha256
gh release upload railgun-seed railgun-seed.tar.gz railgun-seed.tar.gz.sha256 --clobber
# Sepolia: the same, as railgun-seed-sepolia.tar.gz and its .sha256
gh workflow run railgun-dmg.yml
```

`--clobber` deletes each old asset before its replacement finishes uploading, so a
build that fetches in between fails. Over a slow link, upload under a temporary
name, then delete the old asset and rename the new one
(`gh api -X PATCH repos/<owner>/<repo>/releases/assets/<id> -f name=…`).

The archive may hold the files flat or under a directory; the build locates the
`*.meta.json` inside it either way, and refuses an archive holding more than one.

### Overrides

Repository variables redirect a build at a different seed, for a refresh under
test or a fork's own asset. All are optional.

| variable | |
|---|---|
| `RAILGUN_SEED_URL` | another `.tar.gz` of a mainnet fetch directory |
| `RAILGUN_SEED_SHA256` | its sha256, in place of the `.sha256` sidecar the build otherwise fetches from beside the archive |
| `RAILGUN_SEPOLIA_SEED_URL` | the same for the Sepolia fetch |
| `RAILGUN_SEPOLIA_SEED_SHA256` | the same for its checksum |

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
no network suffix — a suffixed one would install fine and never be opened) and
`logindex-sepolia.db`, each with its manifest; manifests naming the right
network and pinning `deploymentBlock=14737691` and `deploymentBlock=5784774`;
coverage starting at those blocks; and none of the Bee flavour's files. A dmg that installs cleanly with
no index inside is exactly the failure this artifact exists to prevent, and
nothing at runtime would report it except a wallet getting `-32000` forever.
