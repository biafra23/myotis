# Log-index bundles: downloadable block data the walker verifies (design)

Status: proposed 2026-09-21, not implemented. Tracking issue: #472.
Companion to [eth-getlogs-design.md](eth-getlogs-design.md) (the index this
feeds) and [bee-rpc-service.md](bee-rpc-service.md) (the first consumer).

## Why

Wallet protocols on top of myotis need a contract's complete log history from
its deployment block: Swarm's Bee needs every PostageStamp event on Gnosis,
kohaku's privacy protocols need every commitment their pools ever emitted on
mainnet. Building that coverage the verified way is the backfill walk — a
descending, parent-hash-chained header walk with receipt-root verification of
every bloom-positive block — and it is slow by construction: measured
30–83 blk/s on Gnosis (≈41 avg, [bee-rpc-service.md §Timings](bee-rpc-service.md#timings-measured-on-zbox-an-x86-64-linux-workstation)),
which puts the PostageStamp history (~16.5 M blocks at measurement, ~17 M
today) at 4–5 days of continuous running and any mainnet history at weeks.
Users will not wait that long, and there will be many such histories
("DLCs": one per protocol a wallet adds).

What exists today is the unverified shortcut: the portable MLIX snapshot
(PR #369 — `export-logindex` / `import-logindex` / the `dataDir` drop-in) and
`scripts/synth_logindex.py` (PR #443), which frames a full node's raw
`eth_getLogs` output into that format. Both are imported as **data claimed
verified by whoever generated it**. The wallet cannot tell a seeded log from
a walked one, the seed's publisher can omit a log and nothing detects it, and
the docs accordingly call that path debug/demo only. This design is the
production replacement: a downloadable format the client **verifies while
importing**, with no new trust and no provenance marker to explain away.

## What a file can prove, and what it cannot

The index makes two claims, and they need different witnesses:

- **Presence** — a served log was really emitted. Provable compactly per
  block: the header, the receipt under the header's `receiptsRoot`, the
  transaction under `transactionsRoot` (the log's `txHash`). The verifiers
  exist: `verify_block_receipts` and `verify_body_transactions`
  (`rust/myotis-net/src/el/reader.rs`).
- **Absence** — no watched log was omitted from a covered range. This is the
  load-bearing one (`eth-getlogs-design.md` §Trust model, *coverage
  honesty*): a wallet reads `[]` as "no events exist", so an omission
  silently corrupts its commitment tree. Before EIP-7745 the chain commits to
  exactly one absence witness: the header's `logsBloom`, which has no false
  negatives. A bloom miss proves absence; a bloom hit can only be settled by
  the block's **complete** receipt list under `receiptsRoot`. There is no
  proof that "no receipt in this trie carries a log for A" short of all of
  them.

So a verifiable bundle for a watch set W over blocks [a, b] is, necessarily:

1. **every header in [a, b]** (the bloom is in the header; the header is
   needed in full to hash it and chain it), and
2. **the complete receipts of every block whose bloom matches W** (receipts
   settle the hit), and
3. **the transaction list of every block that actually holds a watched log**
   (the log's `txHash` is the keccak of the raw transaction at the receipt's
   index — `StoredLog::tx_hash`, `logindex.rs`; the walker fetches bodies
   for that reason). A bloom false positive needs receipts but no
   transactions: the receipts show no watched log, so there is no hash to
   fill in. The body is a presence witness, never an absence one.

That is byte-for-byte what the walker fetches from peers today (minus the
bodies of false-positive blocks). The bundle changes the **transport**, not
the data or the verification, which `architecture-doc.md` (§"Block data via
IPFS or other storage") already sanctions: block data may come from IPFS, a
CDN, a centralized API, or a USB stick, because it is verified against
trusted headers regardless of source. The *client* never talks RPC; whether
the *generator* may is the owner's call (see Open questions).

The roots involved are therefore `receiptsRoot` and `transactionsRoot`, and
the header chain's `parentHash` links up to a header the client already
trusts. State roots play no part.

### Alternatives considered and why they do not replace the blooms

- **Receipt proofs only** (logs + Merkle proofs, no headers for silent
  blocks). Proves presence, cannot prove absence — exactly the property the
  index must not lose. Useful only as a hardening of a *trusted* seed (a
  publisher could then withhold but not forge; see mainnet below).
- **Historical accumulators** (`historical_summaries`; README roadmap, not
  implemented — `implementation-status.md` §2). They would let each chunk's
  top header be trusted on its own, without the walk from the head down to
  it — which removes the "top-up" cost below and lets chunks verify in
  parallel and in any order. They do not remove the need for every header's
  bloom. Worth doing; a follow-up, not a prerequisite.
- **EIP-7745** (log index committed in the header). Gives compact absence
  proofs, for blocks after activation only. Tracked as a separate follow-up
  in `eth-getlogs-design.md`; it does nothing for existing history.
- **A ZK proof of the whole `eth_getLogs` computation.** The principled
  answer; proving keccak over terabytes of receipts is not practical today.
- **A signed seed** (the tracked "signed snapshot" follow-up). Compact, but
  it is publisher trust, which CLAUDE.md's trust rule excludes for the wallet
  unless the owner decides otherwise — as the owner has, for root-committing
  protocols (2026-09-25, docs/seeded-log-histories.md). Not this design; see
  below.

## Where this pays: Gnosis yes, mainnet no

The bundle's size is the header stream plus the receipts of the
bloom-positive fraction, and that fraction is the whole story. Estimates,
**not measured** — the generator's census mode (below) replaces them before
any format is frozen:

| | Gnosis | Mainnet |
|---|---|---|
| Blocks bloom-positive for one address + topic0 | a few percent (sparse blooms) | ~85–95 % (2,048-bit bloom, 3 bits per element, ~2,000+ elements/block: nearly every bit set) |
| Header, raw | ~0.5–0.6 KB (256 B bloom; empty blooms compress to nothing) | ~0.6 KB |
| Bee range, 47.0 M–48.26 M (1.26 M blocks) | ~600 MB headers + ~1 GB receipts/bodies, raw | — |
| Full PostageStamp history, 31.3 M–head (~17 M blocks) | ~9 GB headers + receipts of ~3 % of blocks, raw | — |
| Tornado/privacy-pool history, 14.17 M–head (~9 M blocks) | — | receipts of ~90 % of blocks at 100–200 KB each: ~1 TB |

For Gnosis a fully verifiable bundle fits GitHub release assets (2 GiB per
asset, chunked) and imports at disk speed. For mainnet the verifiable form is
as large as the chain's receipts and saves nothing but peer round-trips; the
only compact mainnet options are the trusted ones — a signed seed, or the
withhold-but-not-forge hybrid (signed coverage plus receipt proofs for every
served log). That is a trust decision for the owner, deliberately outside this
document — made on 2026-09-25 for protocols whose client checks its rebuilt
tree against an on-chain root, which keeps forged leaves out of the client's
tree but does not prove completeness (docs/seeded-log-histories.md); for
everything else the walk stands. Note that even a trusted mainnet seed can
stand on this format's generator and verifier for its presence half.

## Design

### The bundle is a block source for the walker, not an import into the index

The one decision everything else follows from: a bundle is **never merged
into the index**. It is a local cache of block data that the backfill walker
reads **instead of asking a peer** for a batch. The walker's cursor, its
descending parent-hash chaining, the bloom skip, the receipt and body root
checks, the log extraction, the coverage rules and the checkpoints all stay
exactly as they are (`log_index_backfill_batch`, `reader.rs`). What changes
is where the bytes of a batch come from, and — because those two mechanisms
exist only to protect the shared peer pool — the pacing of a file-served
batch (below).

What this buys:

- **No new trust, no provenance.** Coverage built from a bundle is walked
  coverage. Nothing in the file is believed: a header must hash to the
  trusted cursor, every next header must be the previous one's parent, every
  receipt list must hash to its header's `receiptsRoot`, every transaction
  list to its `transactionsRoot`. A bundle has the standing of a peer — one
  that cannot be demoted, so a bad record is skipped instead (below).
- **No bridge cap.** The MLIX import needs the head bridge to close the gap
  above the snapshot's top, and the bridge spans at most 500,000 blocks
  (`BRIDGE_MAX_GAP`, ~29 days of Gnosis). A bundle has no top to bridge to:
  the walker descends from the head as always, takes the blocks above the
  bundle from peers, and switches to the file when its cursor enters the
  bundle's range. A stale bundle still imports; it just costs the walk above
  it (the "top-up" note below).
- **Fetching it adds no trust.** The snapshot import is a deliberate user
  act "never something fetched" because its content is trusted. A bundle is
  untrusted input by construction. Whether hosts download one is still an
  owner's ruling — against the data-source rule's transport clause, not its
  trust clause (open question below).
- **Failure is cheap, per record.** A missing block, a truncated chunk or a
  forged receipt costs that block a peer fetch. The user sees a log line and
  a status field, never an error.

### Batch source selection and per-block mixing

At each backfill tick the walker wants the batch below its cursor:
`(cur_n, cur_hash)` and up to `BATCH = 1023` blocks. Before choosing a peer
it asks the bundle store whether a **header chunk** holds the header at
`cur_n`. If one does, the batch is **file-served**:

1. `count` is clipped so the batch never leaves the header chunk (a batch
   never straddles two chunks; the walker re-slices by number and a chunk
   is one contiguous range).
2. The record at `cur_n` must hash to `cur_hash` — the trusted cursor.
3. Descending `parentHash` chain, each `number` one below the previous, the
   same loop as the peer path; the verified prefix is the batch.
4. Bloom prefilter against the **client's own config**
   (`LogIndex::bloom_may_match`); a miss is a definitive skip.
5. For each candidate: receipts from any registered **candidate chunk**
   that holds the block, `verify_block_receipts`, log extraction; then, for
   a block with a watched log, the transaction list from that chunk if
   present, `verify_body_transactions`, tx hashes. **A candidate no chunk
   can serve — no receipts, or no transactions for a block that turned out
   to hold a log — is fetched from a peer by its (now trusted) block hash**,
   the same way the head bridge fills logs for headers it already trusts
   (`fetch_logs_for_known_headers`), sized by the walker's own chunk sizer.
   With no peer available such candidates wait; the verified headers above
   them still apply, so the cursor stops at the first unserved candidate and
   resumes there.
6. Coverage extends over the verified, fully-served prefix; the cursor moves.

Per-block mixing is v1, not a follow-up, because the all-or-nothing form is
useless in practice: a client whose config adds one address that is
bloom-positive in even 0.5 % of blocks would see (1 − 0.005)^1023 ≈ 0.6 % of
batches file-served. Mixing also settles the generator/client config
mismatch: the file was filtered against the generator's W; a client watching
a subset of W (addresses and topics) is served entirely from the file; a
client watching more falls back to peers only for the blocks its extra
watches light up.

**Chunk boundaries.** The cursor is `(number, hash)`, so the cursor block's
header must be in the header chunk that serves the batch below it. Header
chunks therefore **overlap by one block**: a chunk covering [from, to] also
carries the header of `to + 1` (its upper neighbour's `from`), so descending
from one chunk into the next never needs a peer. The manifest's per-chunk
"top hash" is the hash of that `to + 1` record.

**Pacing.** Two mechanisms throttle the backfill to protect the shared snap
pool: one batch per 6 s tick in nice mode (`max_speed`), and the yield rule
that skips up to 10 of 11 ticks while the head-follow is trailing
(`backfill_should_yield`). Both exist for peer traffic, and a file-served
batch may still issue some (step 5), so the exemption is **retrospective**
— the walker cannot know at the tick boundary whether a batch will need a
peer (an extra-watch bloom hit or a "holds a log, needs its transactions"
record only emerges while processing), but it knows afterwards:

- a batch that touched **no peer** and **moved the cursor** is followed by
  the next batch immediately, under the tick's wall-clock budget;
- a batch that issued **one or more peer fetches** counts as a peer batch:
  the next batch waits for the normal tick and the yield rule applies to it
  exactly as today, so mixing never pushes unpaced traffic onto the snap
  pool while head-follow is trailing;
- a batch that **did not move the cursor** (an unserved candidate waiting
  for a peer) falls back to the 6 s tick — otherwise the walker would
  re-read and re-verify the same prefix in a busy loop at file speed, on
  the phones this flow is for.

Without the exemption the file path is capped at 1023 blocks per 6 s
(≈170 blk/s, ~28 h for the full PostageStamp history) and drops to ≈15 blk/s
while trailing. This is part of slice 2, not a follow-up. The remaining
ceiling is the index's own checkpoint rewrite (rate-bounded, PR #380), which
slice 3 measures.

**Memory.** The peer path bounds transient memory by the peer's response
budget and the adaptive chunk width. The file path must not lose that: a
file-served batch reads, verifies and drops one candidate at a time (never
the batch's receipts up front — 1,023 candidates × ~50 KB is 50 MB on a
dense range, on a platform where the bridge plan was capped at 24 MB), does
its file I/O off the async executor's threads, and never holds the index
lock across a read.

**Bad records.** A verification failure at step 2, 3 or 5 marks **that
record** bad for the process lifetime (status JSON: chunk, block, reason);
the block goes to a peer and the chunk stays eligible above and below it. A
single bit-rot or a non-canonical block at a bundle's top must not cost a
100,000-block chunk — the walk would silently drop to peer speed for that
range. But a chunk whose *content* is wholly wrong (a broken recompression,
or a file built to pass registration with garbage records) must not cost a
file read and a keccak per block on top of that silent drop either, so bad
records **escalate**: the 16th bad record in a chunk, or bad records
exceeding 1 % of the records read from it, fails the chunk for the run
(unregistered, reason and the first 16 bad blocks in the status JSON) and
the range goes to peers without further file I/O. The recorded list is
capped at those 16 per chunk. Structural damage (no valid footer, an offset
outside the file) fails a chunk at registration.

### Chunk file formats: `MLXH` header chunks and `MLXC` candidate chunks

A bundle is two kinds of file, because its two halves have different
owners: the **header stream** is the bulk (every block, ~0.5 KB each) and is
the same for every watch set on the chain, while the **candidates** (receipts
of bloom-positive blocks, transactions of blocks with a hit) are small on
Gnosis and specific to one watch set. Splitting them means a wallet that
adds a second protocol downloads only that protocol's candidate chunks and
reuses the header chunks it already has — which matters because of how the
index takes a new watch (see *Consumed chunks* below).

**Header chunk** (`*.mlxh`): one contiguous, ascending block range plus the
one overlap header above it. Random access by block number is the design
goal (the walker descends and re-slices by number), so the layout is a fixed
header, a record table, and a trailing offset index:

```
magic         "MLXH"
version       u32 = 1
chain tag     network id u64 + EL genesis hash [32]   (same tag MLIX v2 carries)
from, to      u64, u64 (inclusive, ascending); the table also holds to + 1
record table  for each block from..=to+1, ascending:
                header_len u32, header RLP (raw consensus bytes)
offset index  (to - from + 2) × u64 file offsets, one per record
footer        offset of the index u64, sha256 of everything before it [32]
```

**Candidate chunk** (`*.mlxc`): the candidates of one watch set W over one
block range, sparse (only bloom-positive blocks have a record), so the index
maps block number → offset:

```
magic         "MLXC"
version       u32 = 1
chain tag     as above
from, to      u64, u64 — the range the generator evaluated W over
watch set     count u32, then per entry: address [20], from_block u64,
              topic0 count u32, topic0s [32]…
              — the filter the generator's bloom decision used; informational
              (the client re-evaluates blooms against its OWN config)
record table  for each bloom-positive block, ascending:
                block u64
                receipts_count u32; per receipt: len u32, raw consensus bytes
                txs_count u32; per transaction: len u32, raw tx bytes
                  (present iff the block holds a watched log for W)
block index   count u32, then (block u64, offset u64) pairs, ascending
footer        offset of the index u64, sha256 of everything before it [32]
```

A candidate record is trusted only through the header the walker has
already verified for that block; a candidate chunk on its own proves
nothing and serves nothing. Several candidate chunks may hold the same
block (two watch sets both light it up); any one of them serves it.

Receipts are stored in their **consensus encoding with the bloom** (the
eth/68 wire form): `triehash::verify` hashes the raw bytes, so the bytes must
be exactly what `receiptsRoot` commits to (an eth/69 peer strips the bloom on
the wire and the decoder recomputes it — the file is not a wire format and
never strips). Pre-Byzantium receipts (intermediate state root instead of a
status) decode through the same `receipt::decode`. Only the transaction list
is stored, because `verify_body_transactions` checks only
`transactionsRoot`; ommers and withdrawals would be unverified filler. The
reader rebuilds the `BlockBody` the walker's code expects from it.

The generator's bloom decision is `myotis_core::bloom::may_contain` for
every address and topic0 in W, for **every** block of the range — not
`bloom_may_match`, whose per-entry `from_block` would leave blocks below a
watch's deployment without a record although they are not bloom misses,
and the client would then send them to peers. The decision deliberately
ignores `from_block`; it is recorded in the watch set as provenance (which
subscription the operator generated for), and nothing more.

**Reading is bounds-checked and lazy.** Every length and count is validated
against the file size before any allocation (a hostile `0xFFFFFFFF` must not
allocate), every offset against the index. Registration parses the footer
and the fixed header only; a file with no valid footer (a truncated
download — the index sits at the end) is not registered and is reported in
the status JSON. The sha256 is a download-integrity check the hosts run
once after fetching, not something the engine recomputes at every start
(that would hash gigabytes on each Android launch); corruption inside a
registered chunk is caught by the walker's own verification, per record.

Chunk size is a generator parameter set from the census; the guideline is
"well under 2 GiB raw" (GitHub's per-asset ceiling) — 100,000 Gnosis blocks
is ~55 MB of headers at ~0.55 KB each. Header and candidate chunks need not share ranges: a
watch set's candidates for a whole history may be one file. Transport
compression is gzip or zstd of the whole file; the store keeps chunks
decompressed so `seek` works.

A **manifest** (`bundle.json`) accompanies a set of chunks: chain, watch set,
generator and source-client versions, the source's finalized block at
generation, and per chunk: kind, file name, range, byte size, sha256, and
for header chunks the top hash (of the `to + 1` record) and bottom
`parentHash`. A manifest may list chunks published at different times (see
top-up), and a candidate manifest may point at a header stream published
separately (one header stream per chain, many candidate sets). The client
uses it only to locate chunks and to check downloads; nothing in it is
believed.

### Top-up cadence

Everything above the bundle's top is walked from peers at ≈41 blk/s. Gnosis
adds ~17,280 blocks a day, so a bundle N days old costs about N × 7 minutes
of peer walking before the file is touched — 3 months ≈ 10 h, a year ≈ 40 h
— and during that walk queries below the cursor are refused (coverage
honesty). History is immutable, so nothing in an old bundle goes stale; but
the publisher must keep adding **top-up chunks** (a small chunk from the
previous top to a recent finalized block) on a cadence, and the manifest
lists them alongside the old ones. The accumulator follow-up above is what
would remove this cost entirely.

### Generator

A Rust example binary, `rust/myotis-net/examples/logindex_bundle.rs`
(tooling, like `period_census.rs`; the engine crates gain no HTTP dependency —
`reqwest` as roost already uses it, as a dev/example dependency). Inputs: an
EL JSON-RPC URL, a block range, the watch set (addresses, optional topic0s),
an output directory, a chunk size.

- **Raw RLP from the source, never re-encoded from JSON fields.**
  `debug_getRawHeader`, `debug_getRawReceipts`, `debug_getRawBlock`
  (go-ethereum since v1.10.18; the Bee data set's source runs
  Geth/v1.17.5 per its `meta.json`, so the methods are there — they have
  not been exercised against it yet; Nethermind, Erigon and Reth advertise
  the same methods — confirm before relying on one). `debug_getRawBlock`
  returns the full block `rlp([header, txs, ommers, withdrawals])`; the
  generator takes the raw transaction items out of that list — a list
  re-framing, no field re-encoding. Re-encoding headers or receipts from
  JSON across forks would surface as a root mismatch at every client, which
  is why the raw methods are a requirement, not a preference.
- **Stops at the source's finalized block.** A chunk's top must be
  canonical for good; a bundle cut at `latest` can carry a reorged tail
  (Gnosis finality lags minutes) that every importer would have to skip.
- **The bloom decision is myotis's own predicate** (`may_contain`, above),
  so the generator's candidate set is the client's for the same W.
- **Self-verifying at generation.** The generator runs the client's checks
  on every block before writing it (hash chain, receipts root, tx root). A
  misbehaving or pruned source fails loudly at the operator's desk, not at
  every importer's.
- **Census mode** (`--census`): counts and byte sizes only, no writes —
  headers, candidates per address, receipt bytes, transaction bytes split
  by "holds a watched log" vs "bloom false positive". This is the first
  deliverable, because it turns the estimates above into numbers for the
  two ranges that matter (Bee's 47.0 M–head, and the full PostageStamp
  history) and settles the chunk sizes. It writes header chunks and
  candidate chunks in one pass (`--headers`, `--candidates`, or both).

The operator runs it against their own node (zbox's Gnosis geth for the Bee
bundle). Whether that is compatible with CLAUDE.md's data-source rule is the
owner's call, recorded under Open questions; the doc does not assume it.

### Installation and status

- **The bundle directory** `dataDir/logindex-bundles/` is owned by the
  engine. Every `*.mlxh` / `*.mlxc` in it is registered at start (footer +
  fixed header parse only). The daemon's `import-logindex-bundle <path…>` copies files
  in; the passive start-up scan skips a foreign-chain chunk with one log
  line, but the **explicit command refuses one with an error** — a chunk
  for another chain is a parameter that changes the answer, and CLAUDE.md's
  rule is applied or refused, never accepted and ignored (the MLIX import
  refuses a wrong chain the same way, `MergeError::ChainMismatch`).
- **Hosts** reuse the snapshot-import picker (desktop AWT / Android SAF /
  iOS document picker). SAF and the iOS picker hand over content URIs, not
  seekable files, so on phones "import" means copying the chunk into the
  bundle directory in app storage — the hosts must check free space first
  and say what a chunk costs. In-app download from a manifest URL is the
  open question below.
- **Consumed chunks: candidates go, headers stay where they can.** A chunk
  is *consumed* once the cursor has passed below its `from` and a
  checkpoint has recorded that coverage. What deletion costs depends on the
  kind, because of how the index takes a **new watch set** — the "many
  DLCs" case this design exists for. A config push with a new address does
  not invalidate the index (pushes union and merge; the old entries' coverage
  survives — `eth-getlogs-design.md` §Additive config), but the new entry
  has no coverage, so the cursor is dropped and the walker **re-descends
  from the head** through the kept spans down to the new entry's
  `from_block`, reading **every header again** for the bloom check
  (`bloom_may_match` is not coverage-aware) and fetching the new entry's
  candidates. Two consequences:
  - **Header chunks serve every future watch set**, so they are kept by
    default on desktop, and deleted-when-consumed by default on phones with
    the cost stated in the UI: adding a protocol later re-downloads the
    header stream for that protocol's range (or re-walks it at peer speed).
    Per-entry frontiers (the tracked lossless-merge follow-up) would not
    change this — a new entry needs its range's blooms regardless — so they
    are not a prerequisite; the header stream is simply what a new watch
    costs, and a chain has exactly one.
  - **Candidate chunks are per watch set**, so they are deleted when
    consumed everywhere by default. For the re-descent not to re-fetch
    receipts the old entries already stored, slice 2 makes the walker's
    bloom check skip entries whose coverage already contains the block —
    a new DLC then costs headers plus its own candidates only, which is
    exactly what its own candidate chunks hold.
  A setting keeps everything for operators who re-import. Files the engine
  did not copy in itself are never touched.
- **Status JSON** (`logindex-status`) gains: registered chunks with ranges,
  blocks served from bundles vs peers this run, bad records with reason,
  unregistered files with reason, and per chunk whether it is consumed.

### Trust statement

Nothing in a bundle is trusted: not the manifest, not the watch set, not a
single byte of block data. A record is used only after it hashes to the
trusted cursor or chains to a record that did, and its receipts and
transactions only after they hash to that header's roots. The bundle's
failure modes map onto a peer's: **withholding** (a missing chunk or record)
costs a peer fallback, **forging** (any altered byte) costs a root or hash
mismatch and a bad-record mark, a **wrong chain** costs a tag or hash
mismatch. Coverage the bundle helped build is indistinguishable from
peer-walked coverage because it *is* peer-walked coverage with a different
byte source. What a bundle can do is hide a dead peer pool for as long as it
serves — the status JSON's served-from-bundle vs served-from-peers counters
are there so that is visible.

### Out of scope

- Mainnet histories (the bloat argument above). A signed seed or the
  withhold-not-forge hybrid is a separate trust decision — made on
  2026-09-25 for protocols whose client checks its rebuilt tree against an
  on-chain root (docs/seeded-log-histories.md).
- Replacing the MLIX snapshot path. It stays for its documented debug/demo
  use and for operators who trust their own source; the bee docs keep
  pointing at it until a bundle exists.
- The head bridge and the appender: they keep fetching from peers; a bundle
  covers history, not the tail.

## Slices

1. **Census + format vectors.** The generator's `--census` against zbox's
   Gnosis geth for both ranges; the `MLXH`/`MLXC` readers and writers in
   `myotis-net` with round-trip tests, a bounds-check fuzz over lengths and
   offsets, and a corrupted-file test (every mutation must be a bad record,
   an escalated chunk or an unregistered file, never a served log).
2. **Walker block source.** Abstract the batch's byte source in
   `log_index_backfill_batch` (peer or chunks); clipping at header-chunk
   edges; per-block mixing via the known-header fetch; the retrospective
   pacing and yield exemption with the forward-progress rule; per-candidate
   streaming; bad-record marking, escalation and peer fallback; the
   coverage-aware bloom check for re-descents; status fields; daemon
   command, bundle directory, consumed-chunk deletion per kind.
3. **Generator against a live node**, the Bee bundle (47.0 M → finalized) as
   the first artifact: publish as release assets per
   [bee-rpc-service.md §Distributing](bee-rpc-service.md#distributing-the-prebuilt-snapshot),
   measure import time and checkpoint cost on a laptop and a phone; then the
   full PostageStamp history and the first top-up chunk.
4. **Hosts.** Pickers on desktop/Android/iOS with the copy-in and free-space
   check; the Index tab shows bundle coverage and consumed chunks.
5. **Follow-ups**, each its own issue when reached: wider file-served
   batches than `BATCH`; in-app download from a manifest URL (if ruled in);
   the `historical_summaries` accumulator so chunks anchor without the walk
   from the head; a bundle-backed head bridge for gaps beyond
   `BRIDGE_MAX_GAP`.

## Open questions for the owner

- **The generator and the data-source rule.** CLAUDE.md allows HTTP to a
  local client for debugging only, with one recorded carve-out (roost,
  2026-08-08) for self-verifying consensus objects. A bundle is
  self-verifying in a stronger sense — every byte is root-verified by the
  wallet against a header chain it walked itself — and the architecture
  doc lists "a centralized API" among acceptable block-data transports. But
  it is production tooling reading an operator's node over JSON-RPC, and it
  concentrates a liveness dependency the way roost does (no fresh bundle,
  back to a 4-day walk). Deferred: extending the carve-out to bundle
  generation is the owner's ruling to record here, not this doc's to
  assume.
- **In-app download.** Trust permits it, but CLAUDE.md's data-source rule
  is transport-scoped ("the only sources for data are devp2p and libp2p"),
  and a wallet fetching release assets over HTTPS is the wallet sourcing
  data over HTTP in production — the same posture as the generator bullet
  above: an owner's ruling to record, not a product choice. If it is
  granted, the questions are which networks (Wi-Fi only on phones) and the
  size the user consents to; on the JVM hosts the client is Ktor, per
  CLAUDE.md.
- **Chunk size** — to be set from the census, not guessed.
- **Retire the MLIX seed?** Once a Gnosis bundle exists the Bee docs can
  stop recommending the unverified path; the format itself can stay.
