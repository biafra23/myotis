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
  that is not a 20-byte hex address, an address under both keys, more than 1024
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
watched address that is not in `touched` for a covered block was not touched
there. A block the engine did not check is a gap, never a silence: before the
follower started, below its window, paused, or not fetched yet.

- **`log`** is the header's `logsBloom`. Each address is probed twice: as a log's
  emitter, and as an indexed topic, i.e. the address left-padded to 32 bytes, as
  a `Transfer` carries its `from` and `to`. A miss is definitive. A hit means the
  block *may* have touched the address: a bloom gives false positives, and a hit
  costs the host one extra proof.
- **`account`** is the account itself: its balance, nonce and code. Seeing that
  needs the block access list (EIP-7928), which this part does not fetch, so every
  block is an account gap for now. That includes plain ETH transfers and ETH a
  contract sends, which no log shows.

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

The list lives in the reader. A pause drops the reader; the host layer stashes
the list per handle and re-applies it on resume. The paused blocks then show as
a gap. A restart forgets it, as the log index's runtime settings are forgotten,
and the host pushes again: `watching` tells a host whether the engine still
holds its addresses.

## What it costs

A tick with no new head reads a lock. A new head usually costs one header-window
request of two headers, plus two bloom probes per watched address. Answering a
poll costs no I/O.

Measured on Sepolia on 2026-10-21, watching WETH, USDC, `0x…dEaD` and
`0x1111…1111` (`myotis-engine` built in release, 6 minutes):

- The engine was synced in 12 s. The first window covered exactly 256 blocks.
- Over about 27 heads the log coverage had no gaps.
- USDC was touched in 24 of 27 blocks and WETH in 20.

## Next

- **Part 2: block access lists.** Fetch them over snap/2 (EIP-8189
  `GetBlockAccessLists`), verify each against the header's `blockAccessListHash`,
  and test membership. That turns the `account` gaps into coverage on Amsterdam
  networks (Sepolia since 2026-10-06; not mainnet or Gnosis yet). It shares this
  step with #685.
- The Node addon and the JVM daemon do not expose the calls yet.
