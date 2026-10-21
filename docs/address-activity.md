# Address activity (#691)

A host gives the engine a list of addresses to watch, and the engine reports, for
each verified block, which of them that block touched. The host then proves an
address's state again only when a block touched it, or when a block could not be
checked, instead of at every new head. A wallet's account list is the case it
was made for: almost every proof it makes at a new head re-proves a value that
has not changed.

Rust engine only. The Java engine keeps the contract's defaults (`false` and
`null`).

## The calls

On `ChainHandle` (`io.myotis.api`), in the style of the log index config:

- `setActivityWatch(json)`, with `{"watch":["0x…"]?,"unwatch":["0x…"]?}`. It drops
  `unwatch`, then adds `watch`. It is additive: an address left out of `watch`
  stays watched. `false` means refused, nothing changed: malformed JSON, an entry
  that is not a 20-byte hex address, an address under both keys, more than 256
  addresses, or a chain that is not running (a paused one included; the host
  pushes again).
- `addressActivityJson(afterBlock)` covers the blocks `(afterBlock, head]`. It is
  answered from memory, with no I/O, so a host can poll it as often as it polls
  `status()`.

```json
{
  "from": 11959150,
  "to": 11959171,
  "base": {"block": 11959149, "hash": "0x0173…"},
  "gaps": {"account": [[11959150, 11959171]], "log": []},
  "touched": [
    {"address": "0x1c7d…", "block": 11959151, "blockHash": "0x…", "via": ["log"]}
  ],
  "watching": ["0x1c7d…", "0x7b79…"]
}
```

C: `myotis_set_activity_watch` and `myotis_address_activity_json`. iOS:
`io.myotis.engine.ios.ChainHandle`, with the same names. ABI 51.

## What a report promises

**Every block of `[from, to]` is either covered or in a gap, per kind.** A
block the engine did not check is a gap, never a silence: before the follower
started, below its window, paused, or not fetched yet. So is a kept block that
nothing proves leads to the current head. Between a reorg and the follower's
next tick, the kept run may be on the fork the head left. A kept block counts
as covered only when it is the head, or the anchor's ring of recent beacon
heads links it to the head.

- **`log`** is the header's `logsBloom`. Each address is probed twice: as a log's
  emitter, and as an indexed topic, i.e. the address left-padded to 32 bytes, as
  a `Transfer` carries its `from` and `to`. A miss is definitive for exactly
  that: no log of the block names the address as emitter or indexed topic. It
  says nothing of a change no such log names: a rebasing token (stETH) moves
  balances with no log naming the holder, and some contracts put an address
  only in a log's data. A hit means the block *may* have such a log: a bloom
  gives false positives, and a hit costs the host one extra proof.
- **`account`** is the account itself: a balance, nonce or code change, or a
  storage write. It comes from the block access list (EIP-7928), fetched over
  eth/71 (EIP-8159) or snap/2 (EIP-8189), both `GetBlockAccessLists`, and
  verified against the header's `blockAccessListHash`: a peer can withhold one, not forge one. Where covered
  it is definitive, and it sees what no log shows: plain ETH transfers, ETH a
  contract sends, withdrawals, fees. An account the block only accessed (a
  read, a call, a zero-value transfer) is not a touch. A block whose BAL no
  peer served yet, or a block before Amsterdam (no commitment to check one
  against: mainnet and Gnosis today), is an account gap.
- A touch lists what saw it: `"via":["account"]`, `["log"]` or both.

`to` is the anchored (optimistic) head. `base` is the block `afterBlock` itself,
with its hash when the follower holds it, so a host whose proof anchors there
can check that block is still canonical. Above finality a block can come back
with a new `blockHash` after a reorg. The report always reflects the chain as
it is now.

## How the engine follows

`myotis-net/src/el/activity.rs` holds the state and the report. The follower is
`ElReader::ensure_activity_follower`, a task that runs only while the watch list
is non-empty:

- It keeps the last **256** verified headers (about 51 min at 12 s blocks, about
  21 min on Gnosis) as one contiguous run, each header parent-linked to the next,
  that ends at the anchored head.
- Every 2 s it compares the anchored head with the kept top. Usually it fetches
  only `[top ..= head]` through the shared window gate
  (`head_anchored_header_window`: the window's top is the beacon-attested hash and
  every header links to the next). The window's lowest header must be the kept
  top, by hash. The parent links then vouch for every kept block below it.
- If the kept top is no longer canonical (a reorg reached it), if nothing is
  kept, or if the head jumped past the window, it fetches one full window and
  installs it. A run that links to a kept block replaces only what is above that
  block. One that links to nothing kept starts over.
- A failed fetch keeps what is kept. The blocks above it are a gap until a later
  tick fills them.
- It keeps the blooms themselves, not per-address results. So an address added
  later is covered over every block already kept, from the first report after
  the push.
- On a tick with a new head, it asks for the BALs of the kept blocks that commit
  to one and have none verified yet: newest first, 16 at most, from up to 3
  peers that speak eth/71 or snap/2. On an eth/71 session the request goes over
  `eth`; otherwise over snap/2. Only blocks from the head where the run last started over
  count: a start, a resume after a pause, a head jump past the window. A
  host's proofs from then on anchor at that head or later, and an older proof
  meets a gap anyway. So a wake costs one BAL per new block, never a backfill of
  the 256 kept blocks, which would be about 14 MB on Sepolia that no proof can
  use. It keeps each BAL as the set of accounts the BAL changed, so
  BAL coverage is retroactive for a newly added address too. A block no peer
  served stays an account gap and is asked for again at the next head. Peers
  are not struck for serving no BAL, because serving them is optional, and
  such a peer is no worse at state reads.
- A block reinstalled under the same hash (the kept top, at every shallow
  window) keeps its verified BAL. A block replaced in a reorg loses it with the
  block.
- When the light client skipped a head, the ring cannot link the kept run to
  the new head. Until the follower's next tick fetches the window (2 s at most),
  the whole range reports as a gap: the host re-proves once, never trusts a
  stale fork. Measured on Sepolia: 1 poll in about 50.
- Once a minute it logs at INFO what its BAL passes found: passes, BALs wanted
  and verified, the most snap/2 peers in the pool, and the clients that served.

The list lives in the reader. A pause drops the reader; the host layer stashes
the list per handle and re-applies it on resume. The paused blocks then show as
a gap. A restart forgets it, as the log index's runtime settings are forgotten,
and the host pushes again: `watching` tells a host whether the engine still
holds its addresses.

## What it costs

A tick with no new head reads a lock. A new head usually costs one header-window
request of two headers. Answering a poll costs no I/O. It does cost two bloom
probes per watched address and kept block, each probe with its bits computed
once, at the push. The answer lists every bloom hit. On mainnet, whose blooms run
full, that is a fair share of all pairs, which is why the list is capped at 256
addresses and why a host should ask from the oldest block it needs, not further
back.

Measured on Sepolia on 2026-10-21, watching WETH, USDC, `0x…dEaD` and
`0x1111…1111` (`myotis-engine` built in release, 6 minutes):

- The engine was synced in 12 s. The first window covered exactly 256 blocks.
- Over about 27 heads the log coverage had no gaps.
- USDC was touched in 24 of 27 blocks and WETH in 20.

## Who serves block access lists

Measured on Sepolia on 2026-10-21, release build:

- **Over snap/2** (12 minutes, before eth/71): only Nethermind (v2.1.0 and
  v2.2.0) served BALs. The pool held no snap/2 peer for the first 6 minutes,
  and coverage came and went with the pool's churn. A pool that keeps and hunts
  for a BAL server (part 3) found Nethermind twice in 10 minutes, but the peers
  closed their sessions within a minute or two.
- **Over eth/71** (10 minutes, part 4): every peer the pool admitted negotiated
  eth/71 — 9 geth, 4 Nethermind and 2 enrscout sessions. geth (v1.17.7 and
  v1.17.8) serves BALs over `eth` by default, and every BAL wanted was verified
  in each of the 7 minute summaries, from up to 6 BAL-capable peers at once.
  Account coverage was complete except, at times, the newest block for one
  pass. eth/70 receipts read verified throughout.

geth also implements snap/2, but behind `--snap.v2`, off by default and
labelled "not safe on public networks". So on Sepolia today eth/71 is the
source.

## Next

- **Done in part 3:** while BALs are wanted, the pool keeps its one recent BAL
  server (benched, never evicted, for 5 minutes after its last verified BAL). If
  no pooled peer served one lately, it dials for a peer speaking eth/71 or snap/2,
  one slot past the target at most. Since eth/71, the pool rarely needs the hunt.
- **Mainnet and Gnosis** have no Amsterdam yet: their blocks commit to no BAL,
  and their account side stays a gap until the fork.
- **Shared with #685:** the fetch-and-verify step is
  `ManagedPeer::snap_get_block_access_lists`.
- The Node addon and the JVM daemon do not expose the calls yet.
