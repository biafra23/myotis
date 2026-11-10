# Log-index presets: predefined contracts to download and verify

Status: shipped in the Index tab on every host (desktop, Android, iOS) and in
the engine library (`Myotis.LogIndex`, and the catalog in
`io.myotis.logindex`). The live download has not yet been run end to end
against these presets — see *Testing* below.

The log index (`eth_getLogs`, [eth-getlogs-design.md](../design-history/eth-getlogs-design.md))
serves the logs of contracts it was told to watch, each verified against its
block's `receiptsRoot`. Watching a contract means walking from the head down to
its creation block over devp2p. The presets save a user from finding the right
contracts and the right blocks, and tell them first what the walk costs.

## What is offered

| Protocol | Network | Contracts | What a client reads them for |
|---|---|---|---|
| RAILGUN | mainnet, Sepolia | the RailgunSmartWallet proxy | private balances (docs/guides/railgun-poc.md) |
| Swarm | Gnosis | PostageStamp, PriceOracle, Staking, Redistribution | a Bee node's postage batches (docs/guides/bee-rpc-service.md) |
| Privacy Pools | mainnet, Sepolia | the 0xbow entrypoint and its ETH, USDT, USDC pools | deposits, withdrawals, the commitment tree |
| Tornado Cash | mainnet, Sepolia | the instance and relayer registries and every pool of kohaku's catalog | deposits, withdrawals, the trees |

Every preset is the plain verified walk. Nothing here is a seed, so the seeded
log histories carve-out ([seeded-log-histories.md](seeded-log-histories.md)) is
not involved: every log a preset brings in, myotis verified itself.

### The from-blocks

A watch entry's `fromBlock` is a trust assertion: below it the index answers
`[]` without consulting coverage. A value above the real deployment would hide
history silently; a value below it only walks further. Every preset contract
therefore starts at its **creation block** — the first block at which
`eth_getCode` returns code, found by bisection with
`scripts/logindex_preset_census.py` (2026-11-10) — never at a client's
"start scanning" block. The one deliberate exception is RAILGUN mainnet, whose
entry is its first log (14,737,691, not the 14,693,013 creation block) because
the seeds and the RAILGUN PoC already use that value and a different
`fromBlock` for the same address is a different index; nothing exists between
the two (railgun-poc.md, *The deployment block is load-bearing*).

The census reproduced every from-block the repository already pinned (the four
Swarm contracts, RAILGUN Sepolia, the Privacy Pools entrypoints, the Tornado
mainnet registries). It found one disagreement upstream: kohaku's Sepolia
Tornado config has the two registries' deployment blocks swapped (the instance
registry `0x4e69…` was created at 5,594,660, the relayer registry `0xD666…` at
5,594,611), which makes kohaku start the relayer registry 49 blocks late. The
preset uses the chain's values.

Nothing downstream re-checks a from-block — the walk only descends to it — so
each one was also re-bisected against a second, independent endpoint
(2026-11-10). 44 of the 51 contracts were, and all 44 agree (RAILGUN mainnet
returns its 14,693,013 creation block there, as expected). Seven Tornado Cash Sepolia
pools — 10 ETH, 100 DAI, and the 0.01/0.03/0.3/3/30 ETH pools — rest on one
endpoint so far, because the second one rate-limited before reaching them. They
sit in the same two deployment batches as their confirmed siblings (blocks
5,594,400–406 and 11,949,077–082). Confirming them is part of #752.

A pool registered after the catalog was written is not in it. A client reading
one gets the index's ordinary refusal for an unwatched address (`-32000`),
never an empty answer.

## What it costs

The walk downloads every header between the head and the lowest `fromBlock`
(~0.6 KB each), the receipts of every block whose header bloom matches a
watched contract, and the bodies of the blocks that really hold one of its
logs. What it keeps is only the logs. On mainnet the blooms are close to full,
so a large share of all blocks are candidates and their receipts dominate.

The estimates (`LogIndexDownloads.estimate`) are computed from a census of
public chain data taken once, per preset: its log count, the share of blocks
whose bloom matches it (300 sampled blocks), and the size of a matching block's
receipts in eth/69 form (sampled over the preset's own range — 2019's blocks
are several times smaller than today's). Stored bytes per log come from
indexes that were actually built (RAILGUN ~600 B, Swarm ~200 B) or are
estimates for the others. Headers ~0.6 KB and bodies ~100 KB on mainnet are the
figures of [disk-and-network-usage.md](disk-and-network-usage.md). The Swarm
figure is the one cross-check against a real walk: ~33 KB per walked block,
what the measured zbox rebuild implies too
([bee-rpc-service.md](../guides/bee-rpc-service.md), *Timings*).

At the census heads (mainnet 26.38 M, Sepolia 12.10 M, Gnosis 49.20 M):

<!-- @preset-table:begin -->
| Preset | Contracts | From block | Blocks walked | Logs | Download | Stored |
|---|---|---|---|---|---|---|
| RAILGUN, mainnet | 1 | 14,737,691 | 11.6 M | 486,880 | ~476 GB | ~292 MB |
| Privacy Pools, mainnet | 4 | 22,153,713 | 4.2 M | 60,591 | ~384 GB | ~15 MB |
| Tornado Cash, mainnet | 26 | 9,116,966 | 17.3 M | 791,516 | ~1.1 TB | ~174 MB |
| **all three, mainnet, together** | 31 | 9,116,966 | 17.3 M | 1.34 M | **~1.5 TB** (one at a time: ~2.0 TB) | ~481 MB |
| RAILGUN, Sepolia | 1 | 5,784,774 | 6.3 M | 17,393 | ~16 GB | ~10 MB |
| Privacy Pools, Sepolia | 4 | 8,461,453 | 3.6 M | 6,547 | ~114 GB | ~2 MB |
| Tornado Cash, Sepolia | 11 | 5,594,400 | 6.5 M | 6,881 | ~244 GB | ~2 MB |
| **all three, Sepolia, together** | 16 | 5,594,400 | 6.5 M | 30,821 | **~333 GB** (one at a time: ~374 GB) | ~14 MB |
| Swarm, Gnosis | 4 | 31,305,656 | 17.9 M | 1.32 M | ~640 GB | ~263 MB |
<!-- @preset-table:end -->

These are estimates; the UI shows them with "~", and recomputes them for the
current head. The sizes say why the mainnet histories have seeds at all
([seeded-log-histories.md](seeded-log-histories.md), *Why not the walk*): what
is kept is megabytes, what proves it complete is the chain's receipts. The index file is saved by
writing a new copy and renaming it over the old one, so the disk needs about
twice the stored size free at the peak.

### Adding presets together is cheaper

The walk descends once and serves every contract it watches: each header is
fetched once for all of them, and a block that is a candidate for two
contracts has its receipts fetched once. A contract added to an index that has
already walked joins through a re-walk — the engine merges it in, drops the
walk cursor and descends from the head again — so every header is fetched a
second time and the new contract's candidates are fetched on their own. The
Index tab therefore says, for a selection of several presets, how much adding
them together saves over adding them one at a time, and, when a user picks
fewer than all, what all of them together would cost against adding the rest
later. It counts a saving as worth saying from 10 % of the combined cost.

The model treats the presets' bloom matches as independent, which understates
the sharing on mainnet: there a full block matches nearly everything, so the
real combined walk saves more than the figure shown, not less.

## Unmetered only, by default

The walk is the one bulk download the index makes, so by default it waits for
an unmetered network. The engine enforces this, not the UI: while the host
reports a metered network (`MyotisEngine.setNetworkMetering(METERED)`,
docs/how-it-works/data-usage.md) and the index's config does not say
`"allowMetered":true`, the backfill walk is held — cursor and coverage
untouched, exactly like the pause switch — and the status JSON carries
`"meteredHold":true` (engine ABI 56). Head-follow keeps running: it costs a few
blocks a tick and is what keeps head-reaching queries answerable. Downloads
resume on their own when the device is back on Wi-Fi. Not held: the head
bridge that closes a gap after downtime or above an imported seed (at most
500,000 blocks, `BRIDGE_MAX_GAP`) — it is what makes head queries answerable
again, so it runs on any network. It is not small: the bridge fetches the
receipts of every bloom candidate in the gap, so by this page's figures a day
offline is ~7,200 mainnet blocks, ~440 MB with the Tornado Cash preset (71 % ×
~86 KB), and a gap near the bound is tens of GB. The metered copy says so.
Holding the bridge too past some gap size is an open design question, not done
here: it trades data on mobile networks against head queries staying refused
until the device is back on Wi-Fi. An engine before ABI 56 ignores
`allowMetered` and holds nothing; an embedding app must not promise
"unmetered only" on one.

| Host | Reports metering | What the switch does |
|---|---|---|
| Android | yes (`NET_CAPABILITY_NOT_METERED`) | off: the walk waits on mobile data |
| iOS | yes (`NWPath.isExpensive` / `isConstrained`) | off: the walk waits on cellular, a hotspot or Low Data Mode |
| desktop, daemon | no (`UNKNOWN` is not metered) | nothing is ever held; the choice is kept |

The switch is per network ("Download on metered connections on <network>",
`Settings.logIndexAllowMetered`, persisted as `logIndex.allowMetered.<network>`)
and is pushed with every config, so a resume after an idle pause re-applies it
like the other runtime bits.

## For an embedding app

The catalog, the estimates and the trigger are part of the engine library
(docs/guides/android-library.md, *Log history for a protocol*):
`Myotis.LogIndex.presets(handle)`, `estimate(handle, ids)` and
`download(handle, ids, allowMetered = false)`; on iOS
`handle.setLogIndexConfig(LogIndexDownloads.configJson(presets))`. The push is
additive, like every log-index config push: it adds the presets' contracts to
whatever the index already watches.

## Testing

The catalog, the estimate model, the config push, the status keys and the
engine's hold rule are unit-tested (`:myotis-logindex-presets:jvmTest`,
`:ui:desktopTest`, `cargo test -p myotis-engine -p myotis-net`). A download
itself needs devp2p and libp2p peers, which a cloud session's network does not
reach; the end-to-end plan — a measured walk per network against the estimates,
the metered hold on a real phone, an embedding app through the AAR — is tracked
in [#752](https://github.com/biafra23/myotis/issues/752).
