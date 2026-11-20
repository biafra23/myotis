# Verifying any historical block: a checkpoint table and a header walk

Status: **analysis and measurements — nothing here is built.** The measurements
were taken on 2026-11-16 against mainnet with `myotis-rpcd`; the deep-block
probe behind §[Are deep blocks available?](#are-deep-blocks-available) was a
local, unverified throwaway build that was never committed. Whether a bundled
checkpoint table becomes a trust anchor was the owner's decision
([§Open decisions](#open-decisions)): decided on 2026-11-20, bundled.

## TL;DR

- **Today a block read reaches 512 blocks below the finalized block** (about
  600 below the head), because verifying a block means fetching every header
  from it up to a beacon-attested block, in one request. Deeper reads are
  refused. That is a cost limit, not a protocol one.
- **Availability is not the obstacle.** Every one of 40 random heights — 20
  pre-Merge, 20 post-Merge — was served by a peer within 0.2–2.8 s once
  verification was switched off. Headers were served at every height even by
  a peer that prunes old bodies; bodies come from the archive peers eth/69's
  `earliestBlock` points at — 7 of 18 surveyed peers hold the full history
  ([§Survey](#survey-what-peers-announce)).
- **Verification is the obstacle**, and the cheapest fix is a **bundled table
  of every 1024th block hash**: 0.83 MB for all of mainnet's history, after
  which ANY block verifies with one `GetBlockHeaders` request of at most 1024
  headers (about 0.66 MB at most, 0.33 MB on average) plus its body. No proof format, no
  total difficulty, nothing devp2p does not already serve.
- **The table is a new trust anchor.** It must be derived by a verified walk
  from a beacon-attested block down to the genesis hash, committed as a pinned
  asset, and re-derivable in CI. Adding it changes the trust model, which is
  the owner's call.

## Today

`eth_getBlockByNumber` (and every read built on the block serve) verifies a
block by fetching the header window `[N ..= top]` from one peer, where `top`
is the beacon-attested finalized block (or the optimistic head for a block
above finality), and checking that every header's `parentHash` is the hash of
the one below it and that the top header hashes to the attested block hash.
The window is one request, so its length is capped:
`BLOCK_LOOKBACK_MAX = 512` in `rust/myotis-net/src/el/reader.rs` (about 300 KB,
inside the eth response soft limit). The Java engine's `get-block` walks up to
`MAX_HEADER_CHAIN_GAP = 8192` (`VerifiedAccountQuery`), and the spec lists the
historical accumulators as designed but unbuilt
([spec §10](../spec/README.md#10-implementation-status--recommended-build-order)).

Measured on mainnet (one request at a time, a block chosen at random within
the window, `myotis-rpcd` release build):

| Read | Served | min | median | mean | p90 | max |
|---|---|---|---|---|---|---|
| tx hashes (7–38 KB answer) | 30/30 | 148 ms | 287 ms | 338 ms | 622 ms | 764 ms |
| full transactions (up to 470 KB) | 20/20 | 233 ms | 373 ms | 401 ms | 651 ms | 694 ms |
| anywhere in the chain | 0/15 | refused in < 1 ms | | | | |

A deeper block is refused with
`block N is D behind the finalized block — beyond the 512-block verify window`.
The engine hands that refusal to its hosts as the plain `{"error"}` envelope
(`get_block_by_number_json`, `rust/myotis-engine/src/host.rs`), which every
host answers with the retryable `-32000` — `myotis-rpcd` and the Kotlin
`RpcRouter` alike; the receipts read has the same refusal
and the same envelope, and the Java engine answers the case with `null` →
`-32000` (`VerifiedRpcBackend`). A block below the window never comes back into
it, so by the rule in `CLAUDE.md` it should be the permanent `-32602`. The fix
belongs in the engines, not in a host: the reader returns `Result<_, String>`,
so it first needs a way to tell this refusal from a transient failure, and the
tri-state block and receipt reads need a permanent envelope their hosts unwrap.
That is a separate fix, whatever this document leads to.

## The problem is verification, not availability

A peer can hand over a header that claims any number. The only blocks Myotis
knows are canonical are the ones the sync committee signs, through the
execution payload of the beacon header: the head and the finalized block.
Anything older is canonical only if it hash-links to one of them, and the
linking costs one header per block of distance:

| Target | Headers | Download (~560 B each) | Requests (≤ 1024 headers each) |
|---|---|---|---|
| 512 back (today) | 512 | 0.3 MB | 1 |
| 1 day back | ~7,200 | ~4 MB | ~7 |
| 1 year back | ~2.6 M | ~1.5 GB | ~2,600 |
| the Merge (15,537,394) | ~10.9 M | ~6.4 GB | ~10,600 |
| genesis | ~26.4 M | ~14.8 GB | ~25,800 |

## Options considered

1. **Walk from the head every time.** Free of new trust, linear in distance:
   fine to a day back, impossible to genesis per request.
2. **`historical_summaries` (Capella on) and `historical_roots` (to Capella).**
   Constant-size per lookup, but no libp2p request serves a proof of
   `historical_summaries` against a verified beacon state, beacon nodes keep
   blocks only for `MIN_EPOCHS_FOR_BLOCK_REQUESTS` (about five months), and
   recomputing a period's summary root takes its 8192 beacon blocks.
3. **The pre-Merge epoch accumulator** (61 KB, 1897 epoch roots over
   `(block_hash, total_difficulty)` records). **No devp2p message carries its
   proofs** — the eth protocol (eth/66–71) has none, and clients never compute
   the accumulator; Portal served them and is effectively dead. A node can
   rebuild a proof from the epoch's 8192 headers, but each record also needs
   the total difficulty, which eth/69 no longer carries: the epochs' starting
   difficulties would have to be bundled too (another ~61 KB).
4. **Proofs or epoch files in Swarm.** Swarm would only be an availability
   layer — everything is checked against embedded roots — but it is a new data
   source (`CLAUDE.md` allows devp2p and libp2p only). Sizes: Portal-style
   proofs 480 B per pre-Merge block = 7.5 GB (15.5 GB with headers); one SSZ
   file of `(hash, total difficulty)` per pre-Merge epoch = 0.99 GB in 1897
   files of 512 KB; one file of hashes per 8192 blocks = 0.85 GB in ~3,230
   files of 256 KB. Bodies would not be in it unless they were added (pre-Merge
   bodies and receipts run to hundreds of GB).
5. **Bundle every block hash.** 846 MB for mainnet (497 MB pre-Merge, 349 MB
   post-Merge); hashes do not compress. Verification is the header itself.
6. **Bundle every k-th block hash and walk to it** — the proposal below.

## Proposal: a checkpoint table and a short header walk

### What is bundled

The hash of every k-th block from genesis up to a finalized block at release
time, per network, 32 bytes each. The size is `blocks × 32 B / k`:

| One hash every k blocks | Bundle (mainnet, 26.43 M blocks) | Download per lookup: worst / mean | Requests |
|---|---|---|---|
| 1 | 846 MB | header only | 1 |
| 64 | 13.2 MB | ~41 KB / ~20 KB | 1 |
| 256 | 3.3 MB | ~164 KB / ~82 KB | 1 |
| **1024** | **0.83 MB** | **~0.66 MB / ~0.33 MB** | **1** |
| 8192 | 0.10 MB | ~5.2 MB / ~2.6 MB | 8 / 4 |

The download is counted at a current header (~640 B since Prague); older
headers are smaller, so a pre-Merge walk costs less.

**k = 1024** is the recommended point: it is geth's `GetBlockHeaders`
response limit, so every lookup stays one request. Per network at k = 1024:

| Network | Blocks (census head) | Table | Growth |
|---|---|---|---|
| mainnet (12 s) | 26.43 M | 0.83 MB | ~82 KB a year |
| Gnosis (5 s) | 49.20 M | 1.54 MB | ~197 KB a year |
| Sepolia (12 s) | 12.10 M | 0.38 MB | ~82 KB a year |

The heads are the census heads of
[log-index-presets.md](../how-it-works/log-index-presets.md) (mainnet: this
document's own); Chiado is not counted. The apps offer every network, so their
bundle is about 2.7 MB before Chiado.

### What a running node adds

Each time the finalized block passes a multiple of k, the node appends that
block's hash to a local table: about seven entries a day on mainnet. The entry
is not free. Finality advances an epoch at a time, and the light client holds
one finalized execution block (`ExecAnchor::finalized_execution`), which lands
exactly on a multiple of 1024 about once in 32 updates. Otherwise the entry's
hash is known only after the window from it up to the new finalized block —
about 32 headers, ~20 KB, more after a stretch without finality — has been
fetched and hash-linked, as `fetch_anchored_window` does today. A hash seen
while the block was only the optimistic head must not be recorded: that block
can still be reorganized.

Two gaps are closed with the same walk: from the first finalized block after
start back to the last bundled entry (the time since the release), and over any
downtime. Each costs about seven requests (~4–5 MB) per day of gap: about
0.4 GB for an install started 90 days after its release, 1.5–1.7 GB after a
year, per network, and 2.4× that on Gnosis. On a phone that is the larger cost,
larger than the bundled table, so the walk should be:

- **lazy**: run only when a read lands in the gap, and close only the part of
  the gap between that read and the next entry above it (a single walk of at
  most k headers); and
- **held on a metered network**, as the log-index backfill is (`meteredHold`).

### Serving block N

1. Pick the first table entry at or above N, at block `c` (parent links point
   down, so the walk always runs from N up to an entry).
2. `GetBlockHeaders(origin = N, amount = c − N + 1)` from any peer: at most k
   headers, one request for k ≤ 1024. History expiry drops bodies and
   receipts, not headers: the pruned peer probed below served every height's
   header, so most peers qualify (the 512-block peers of the survey are
   untested).
3. Check every `parentHash` link and that the top header hashes to the entry.
4. Fetch the body from a peer whose eth/69 `earliestBlock` is at or below N and
   check it against the header: `transactionsRoot`, plus `withdrawalsRoot` from
   Shanghai on and `ommersHash` before the Merge (the block serve checks only
   `transactionsRoot` today). Receipts against `receiptsRoot`.
5. Optionally keep the walk's hashes, so later lookups near N skip it.

Expected latency, from the measurements above: the unverified probe served a
deep header and body at a median of 413 ms post-Merge and 712 ms pre-Merge,
and the 300 KB window behind today's reads costs a median of 287 ms. A walk
of about 0.66 MB at most on top should land at roughly 0.5–1.5 s per deep block — an
estimate, not a measurement.

### Building the table

- **The first build** walks every header from a beacon-attested finalized
  block down to genesis (~14.8 GB for mainnet, once). The walk must end exactly
  at the network's genesis hash, an end-to-end check of the whole chain.
- **Each release** only extends it over the blocks since the previous release
  (~4 MB of headers a day).
- **Cross-check:** the pre-Merge part can be checked against the pre-Merge
  epoch accumulator, the anchor `CLAUDE.md` already names (it needs the epochs'
  total difficulties, which the one-time build can compute while walking).
- **Reproducibility:** the table is committed as a pinned asset, not produced
  during the build, so release outputs stay byte-identical; a CI job can
  re-derive it and compare.

### What it does not solve

- **Body availability.** The table proves which header is canonical; the body
  still has to come from a peer that kept it (next section).
- **A deep block by hash.** `eth_getBlockByHash` for an unknown deep hash needs
  the header first (any peer: its number is inside it), then the walk.
- **State at a deep block.** Execution clients keep about 128 recent states;
  historical state is out of reach whatever the header verification.

## Are deep blocks available?

### The unverified probe

A local build (never committed) answered a block beyond the window by asking
EVERY pooled peer for the header by number and the body by hash, checking only
the body against the header's own `transactionsRoot` — no link to the beacon
anchor. 20 random post-Merge and 20 random pre-Merge heights:

| Range | Served | min | median | mean | p90 | max |
|---|---|---|---|---|---|---|
| post-Merge (15,537,394 – 26,429,000) | 20/20 | 226 ms | 413 ms | 583 ms | 1016 ms | 1822 ms |
| pre-Merge (1 – 15,537,393) | 20/20 | 365 ms | 712 ms | 876 ms | 1650 ms | 2771 ms |

The pool held only two peers, both Nethermind: one announcing
`earliestBlock = 1` served every block; one announcing
`earliestBlock = 25,380,563` served the **header** of every height but a
**body** only from its announced earliest block up — exactly what it announced.

### Survey: what peers announce

A second local build logged the eth/69 Status of every peer that completed a
handshake — not only the few the snap pool keeps — over 15 minutes of
discovery: 84 handshakes from 21 distinct addresses (most peers reconnect),
one of them a crawler (`enrscout`), left out. What the other 20 announce as
`earliestBlock`:

| Announced range | Peers | Clients |
|---|---|---|
| full history (`earliestBlock` 0 or 1) | 7 | Geth 6, Nethermind 1 |
| from the Merge | 4 | Nethermind 2, Geth 1, reth 1 |
| pruned to a later block (24.6 M – 25.4 M) | 4 | Nethermind 2, reth 2 |
| the last ~512 blocks only | 3 | Geth v1.17.10 (all three) |
| no range (eth/68) | 2 | Geth 1, Nethermind 1 |

Read as availability:

- **A pre-Merge body**: 7 of the 18 peers that announce a range (39 %) — every
  one of them also speaks snap, so they are the peers the pool dials anyway.
- **A post-Merge body**: 11 of 18 (61 %) for any height, more for the last
  year (the pruned peers start between 24.6 M and 25.4 M).
- **Headers**: the one pruned peer probed served the header of every height,
  pre-Merge included, so the walk does not depend on archive peers. Whether
  the three 512-block Geth peers serve old headers was not tested.

With several archive peers among a couple of dozen, a deep body is a matter of
asking the right peer, which `earliestBlock` names before the request. The
sample is small — one host, one evening, 21 peers — and a census over days
would firm it up before a decision. (A first survey keyed peers by client and
announced range instead of address and overcounted the 512-block peers, which
re-announce a new range on every reconnect; it is superseded by this one.)

## Open decisions

For the owner:

1. **The checkpoint table as a trust anchor.** It adds a third embedded anchor
   next to the sync-committee checkpoint and the historical accumulators, and
   it is only as good as the walk that produced it. **Decided (owner,
   2026-11-20): bundled, k = 1024; the rule is in `.claude/agent/data-sources.md`
   (Trust).**
2. **k**, and whether the table ships in the mobile apps (about 2.7 MB for
   mainnet, Gnosis and Sepolia at k = 1024, plus the gap walks above) or only
   in the daemon, the desktop app and `myotis-rpcd`.
3. **Pre-Merge bodies.** Served by archive peers only; whether that is enough
   to offer pre-Merge reads at all, or whether they stay refused.
4. **The `-32000` → `-32602` fix** for block and receipt reads below the
   window, in the engines' error envelope (both engines), independent of
   the rest.
