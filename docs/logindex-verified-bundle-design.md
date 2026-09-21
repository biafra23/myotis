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
which puts the 16.5 M-block PostageStamp history at 4–5 days of continuous
running and any mainnet history at weeks. Users will not wait that long, and
there will be many such histories ("DLCs": one per protocol a wallet adds).

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
2. **the complete receipts and the body of every block whose bloom matches
   W** (receipts settle the hit; the body supplies the tx hashes — the same
   reason the walker fetches bodies, `logindex.rs` `StoredLog::tx_hash`).

That is byte-for-byte what the walker fetches from peers today. The bundle
changes the **transport**, not the data or the verification, which
`architecture-doc.md` (§"Block data via IPFS or other storage") already
sanctions: block data may come from IPFS, a CDN, a centralized API, or a USB
stick, because it is verified against trusted headers regardless of source.
An EL node reached over JSON-RPC by the *generator* is such a source; the
*client* never talks RPC.

The roots involved are therefore `receiptsRoot` and `transactionsRoot`, and
the header chain's `parentHash` links up to a header the client already
trusts. State roots play no part.

### Alternatives considered and why they do not replace the blooms

- **Receipt proofs only** (logs + Merkle proofs, no headers for silent
  blocks). Proves presence, cannot prove absence — exactly the property the
  index must not lose. Useful only as a hardening of a *trusted* seed (a
  publisher could then withhold but not forge; see mainnet below).
- **Historical accumulators** (`historical_summaries`; README roadmap, not
  implemented — `implementation-status.md` §2). They would replace the
  parent-hash chain as the way to trust a scattered old header, which is
  worth having for other reasons, but they do not remove the need for every
  header's bloom.
- **EIP-7745** (log index committed in the header). Gives compact absence
  proofs, for blocks after activation only. Tracked as a separate follow-up
  in `eth-getlogs-design.md`; it does nothing for existing history.
- **A ZK proof of the whole `eth_getLogs` computation.** The principled
  answer; proving keccak over terabytes of receipts is not practical today.
- **A signed seed** (the tracked "signed snapshot" follow-up). Compact, but
  it is publisher trust, which CLAUDE.md's trust rule excludes for the wallet
  unless the owner decides otherwise. Not this design; see below.

## Where this pays: Gnosis yes, mainnet no

The bundle's size is the header stream plus the receipts of the
bloom-positive fraction, and that fraction is the whole story. Estimates,
**not measured** — the generator's census mode (below) replaces them before
any format is frozen:

| | Gnosis | Mainnet |
|---|---|---|
| Blocks bloom-positive for one address + topic0 | a few percent (sparse blooms) | ~60–80 % (blooms saturated at ~1,500+ elements/block) |
| Header, raw | ~0.5–0.6 KB (256 B bloom; empty blooms compress to nothing) | ~0.6 KB |
| Bee range, 47.0 M–48.26 M (1.26 M blocks) | ~600 MB headers + ~1 GB receipts/bodies, raw | — |
| Full PostageStamp history, 31.3 M–head (~17 M blocks) | ~9 GB headers + receipts of ~3 % of blocks, raw | — |
| Tornado/privacy-pool history, 14.17 M–head (~9 M blocks) | — | receipts of most of the chain: hundreds of GB |

For Gnosis a fully verifiable bundle fits GitHub release assets (2 GiB per
asset, chunked) and imports at disk speed. For mainnet the verifiable form is
as large as the chain's receipts and saves nothing but peer round-trips; the
only compact mainnet options are the trusted ones — a signed seed, or the
withhold-but-not-forge hybrid (signed coverage plus receipt proofs for every
served log). That is a trust decision for the owner, deliberately outside
this document. Note that even a trusted mainnet seed can stand on this
format's generator and verifier for its presence half.

## Design

### The bundle is a block source for the walker, not an import into the index

The one decision everything else follows from: a bundle is **never merged
into the index**. It is a local cache of block data that the backfill walker
reads **instead of asking a peer** for a batch. The walker's cursor, its
descending parent-hash chaining, the bloom skip, the receipt and body root
checks, the log extraction, the coverage rules and the checkpoints all stay
exactly as they are (`log_index_backfill_batch`, `reader.rs`). The only
change is where the bytes of a batch come from.

What this buys:

- **No new trust, no provenance.** Coverage built from a bundle is walked
  coverage. Nothing in the file is believed: a header must hash to the
  trusted cursor, every next header must be the previous one's parent, every
  receipt list must hash to its header's `receiptsRoot`, every body to its
  `transactionsRoot`. A bundle has the standing of a peer — one that cannot
  be demoted, so it gets quarantined instead (below).
- **No bridge cap, no shelf life.** The MLIX import needs the head bridge to
  close the gap above the snapshot's top, and the bridge spans at most
  500,000 blocks (`BRIDGE_MAX_GAP`, ~29 days of Gnosis). A bundle has no top
  to bridge to: the walker descends from the head as always, takes the blocks
  above the bundle from peers, and switches to the file when its cursor
  enters the bundle's range. History is immutable, so a bundle built today
  is as good in a year; only the walk above it grows, at the normal rate.
- **Hosts may fetch it.** The snapshot import is a deliberate user act
  "never something fetched" because its content is trusted. A bundle is
  untrusted input by construction, so downloading one in-app from a release
  URL is safe in principle. Whether hosts do so is a product decision, not a
  trust one (open question below).
- **Failure is cheap.** A missing block, a truncated chunk or a forged
  receipt makes that batch fall back to a peer. The user sees a log line and
  a status field, never an error.

### Batch source selection

At each backfill tick the walker wants the batch below its cursor:
`(cur_n, cur_hash)` and `count` (`BATCH = 1023`). Before choosing a peer it
asks the bundle store:

> Serve `[cur_n - count, cur_n]` from a bundle iff one chunk holds **every
> header** of the range, and holds **receipts and body for every block whose
> bloom matches the client's own config** (`LogIndex::bloom_may_match`).

The second clause is what makes the generator's watch set irrelevant to
trust: a bundle was filtered against the generator's W, the client's config
may be a subset (fine — extra receipts are ignored) or may add an address (a
bloom-positive block for it has no receipts in the file, so that batch goes
to a peer). A batch is never mixed between file and peer in v1; a per-block
mix is a follow-up if census numbers say it matters.

The file-served batch then runs the identical verification the peer path
runs, on the same types (`VerifiedHeader`, raw receipt bytes, `BlockBody`):

1. the record at `cur_n` must hash to `cur_hash` — the trusted cursor;
2. descending `parentHash` chain, each `number` one below the previous;
3. bloom prefilter against the client config; a miss is a definitive skip;
4. for each candidate: `verify_block_receipts`, `verify_body_transactions`,
   log extraction, exactly as today;
5. coverage extends over the verified prefix; the cursor moves.

A verification failure at any step **quarantines the chunk** for the process
lifetime (it is recorded in the status JSON with the failing block and
reason) and the batch is retried from a peer on the next tick. The walker's
peer-blame machinery is not involved: a file is not a peer, and its failure
must not distort peer ranking.

Expected rate: keccak of 1,023 headers plus a few receipt tries per batch is
milliseconds; the walk becomes disk- and checkpoint-bound, thousands of
blocks per second against 40–60 from peers. The tick structure is unchanged
in v1; letting file-served batches be wider than `BATCH` (which only exists
because geth caps header responses at 1,024) is a follow-up.

### Chunk file format: `MLXB` v1

One chunk = one file = one contiguous, ascending block range. Random access
by block number is the design goal (the walker descends and re-slices by
number), so the layout is a fixed header, a block table, and a trailing
offset index:

```
magic         "MLXB"
version       u32 = 1
chain tag     network id u64 + EL genesis hash [32]   (same tag MLIX v2 carries)
from, to      u64, u64 (inclusive, ascending)
watch set     count u32, then per entry: address [20], topic0 count u32, topic0s [32]…
              — the filter the generator's bloom decision used; informational
              (the client re-evaluates blooms against its OWN config)
block table   for each block from..=to, ascending:
                header_len u32, header RLP (raw consensus bytes)
                receipts_count u32; per receipt: len u32, raw consensus bytes
                body_len u32, body RLP (0 = absent)
              receipts and body are present iff the generator's bloom
              decision was positive; a header-only record is a claim of
              "bloom miss for W", which the client checks itself
offset index  (to - from + 1) × u64 file offsets, one per block
footer        offset of the index u64, sha256 of everything before it [32]
```

Receipts are stored in their **consensus encoding with the bloom** (the
eth/68 wire form): `triehash::verify` hashes the raw bytes, so the bytes must
be exactly what `receiptsRoot` commits to (an eth/69 peer strips the bloom on
the wire and the decoder recomputes it — the file is not a wire format and
never strips). Bodies are the block body RLP as `GetBlockBodies` serves it
(transactions, ommers, withdrawals), so `verify_body_transactions` runs
unchanged.

The sha256 is integrity, not trust — it catches a truncated download, nothing
more. Chunk size is a generator parameter; the guideline is "well under
2 GiB raw" (GitHub's per-asset ceiling) — 100,000 Gnosis blocks is ~50 MB of
headers plus receipts. Transport compression is gzip or zstd of the whole
file; the store keeps chunks decompressed so `seek` works. A phone installs
only the chunks it needs; that is why chunks, not one file.

A **manifest** (`bundle.json`) accompanies a set of chunks: chain, watch set,
generator and source-client versions, fetch time, and per chunk: file name,
range, byte size, sha256, top block hash, bottom `parentHash`. The client uses
it only to locate chunks and to check downloads; nothing in it is believed.

### Generator

A Rust example binary, `rust/myotis-net/examples/logindex_bundle.rs`
(tooling, like `period_census.rs`; the engine crates gain no HTTP dependency —
`reqwest` as roost already uses it, as a dev/example dependency). Inputs: an
EL JSON-RPC URL, a block range, the watch set (addresses, optional topic0s),
an output directory, a chunk size.

- **Raw RLP from the source, never re-encoded from JSON.** `debug_getRawHeader`,
  `debug_getRawReceipts`, `debug_getRawBlock` (geth ≥ 1.11 — verified on the
  Bee data set's source, Geth/v1.17.5; Nethermind, Erigon and Reth advertise
  the same methods — confirm before relying on one). JSON → RLP re-encoding
  across forks is precisely the drift `synth_logindex.py` had to defend
  against, and here it would surface as a root mismatch at every client.
- **The bloom decision is myotis's own predicate**, `myotis_core::bloom` via
  the same `bloom_may_match` rule the walker applies, so the generator's
  candidate set is the client's for the same W — no second implementation
  of the bloom to drift.
- **Self-verifying at generation.** The generator runs the client's checks
  on every block before writing it (hash chain, receipts root, tx root). A
  misbehaving or pruned source fails loudly at the operator's desk, not at
  every importer's.
- **Census mode** (`--census`): counts and byte sizes only, no writes —
  headers, candidates per address, receipt and body bytes. This is the first
  deliverable, because it turns the estimates above into numbers for the two
  ranges that matter (Bee's 47.0 M–head, and the full PostageStamp history)
  and settles the chunk size.

The operator runs it against their own node (zbox's Gnosis geth for the Bee
bundle). CLAUDE.md's data-source rule is untouched: JSON-RPC is used by
tooling to *package* data that the wallet then verifies from the file; the
wallet itself never queries an RPC node.

### Installation and status

- **Drop-in directory**, `dataDir/logindex-bundles/`: every `*.mlxb` in it is
  registered at start and on the daemon's `import-logindex-bundle <path…>`
  (which copies or links files into the directory). Chunks for another chain
  are ignored with one log line (the chain tag decides; the network suffix
  rule of `host::create` does not apply since the file names its chain).
- **Hosts** reuse the snapshot-import picker (desktop AWT / Android SAF / iOS
  document picker) for local files. In-app download from a manifest URL is
  the open question below.
- **Status JSON** (`logindex-status`) gains: registered chunks with ranges,
  blocks served from bundles vs peers this run, quarantined chunks with
  reason, and per chunk whether the walk has passed below it ("consumed" —
  safe to delete; the store never deletes a user's file).

### Trust statement

Nothing in a bundle is trusted: not the manifest, not the watch set, not a
single byte of block data. A record is used only after it hashes to the
trusted cursor or chains to a record that did, and its receipts and body
only after they hash to that header's roots. The bundle's failure modes map
onto a peer's: **withholding** (a missing chunk or record) costs a peer
fallback, **forging** (any altered byte) costs a root or hash mismatch and a
quarantine, a **wrong chain** costs a tag or hash mismatch. Coverage the
bundle helped build is indistinguishable from peer-walked coverage because
it *is* peer-walked coverage with a different byte source.

### Out of scope

- Mainnet histories (the bloat argument above). A signed seed or the
  withhold-not-forge hybrid is a separate trust decision.
- Replacing the MLIX snapshot path. It stays for its documented debug/demo
  use and for operators who trust their own source; the bee docs keep
  pointing at it until a bundle exists.
- The head bridge and the appender: they keep fetching from peers; a bundle
  covers history, not the tail.

## Slices

1. **Census + format vectors.** The generator's `--census` against zbox's
   Gnosis geth for both ranges; the `MLXB` reader/writer in `myotis-net`
   with round-trip tests and a corrupted-file test (every mutation must be a
   quarantine, never a served log).
2. **Walker block source.** Abstract the batch's byte source in
   `log_index_backfill_batch` (peer or chunk); source selection rule;
   verification on the file path via the existing functions; quarantine and
   peer fallback; status fields; daemon command and drop-in directory.
3. **Generator against a live node**, the Bee bundle (47.0 M → head) as the
   first artifact: publish as release assets per
   [bee-rpc-service.md §Distributing](bee-rpc-service.md#distributing-the-prebuilt-snapshot),
   measure import time on a laptop and a phone; then the full PostageStamp
   history.
4. **Hosts.** Pickers on desktop/Android/iOS; the Index tab shows bundle
   coverage and consumed chunks.
5. **Follow-ups**, each its own issue when reached: wider file-served
   batches; per-block file/peer mixing within a batch; in-app download from
   a manifest URL; a bundle-backed head bridge for gaps beyond
   `BRIDGE_MAX_GAP`.

## Open questions for the owner

- **In-app download.** Trust permits it; does the product want the wallet
  fetching multi-hundred-MB assets from GitHub, and on which networks
  (Wi-Fi only on phones)?
- **Chunk size** — to be set from the census, not guessed.
- **Retire the MLIX seed?** Once a Gnosis bundle exists the Bee docs can
  stop recommending the unverified path; the format itself can stay.
