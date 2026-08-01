# eth_getLogs: scoped, verified log index (design)

Status: accepted design, implementation in progress on `feat/eth-getlogs`.
Scope decision (2026-08-01): **iteration 1 sources everything from EL/CL peers**;
shipping pre-built index seeds with an app is a later optimization layered on the
same store. The feature is **opt-in** per network and scoped to a configured
**watch-list** of contracts (kohaku's privacy contracts are the motivating set).

## Why

Wallet libraries that consume myotis as their data layer (the kohaku monorepo)
need `eth_getLogs` over historical ranges: their privacy protocols
(tornado-cash, privacy-pools, railgun) rebuild note-commitment trees from every
event a contract has emitted since deployment. Myotis today serves only a
near-head window and has no log index — `eth_getLogs` is the single missing
method of the eleven kohaku requires (the receipt and fullTransactions gaps
closed with the verified receipt/body paths).

Generic archive `getLogs` (any address, any range) is explicitly a non-goal:
that is an archive-node feature. This is a **watch-list index**: a small set of
(address, from-block) subscriptions per network, indexed once, then followed at
head.

## Trust model

Nothing new is trusted. Every log served passes the existing gates:

- Headers become trusted only via the beacon anchor + parent-hash chaining
  (same rule as `fetch_anchored_window`, `el/reader.rs:2350`, generalized to a
  descending walk of unbounded depth).
- Receipts are fetched by (trusted) block hash and verified against the
  trusted header's `receiptsRoot` (`verify_block_receipts`, `el/reader.rs:2430`)
  before any log is extracted.
- The header's `logsBloom` is used only as a *skip* heuristic: a non-match is a
  definitive "no watched logs here" (bloom has no false negatives); a match
  still requires receipt verification. Bloom checking reuses
  `myotis_core::bloom::accrue` (`myotis-core/src/bloom.rs:18`).
- **Coverage honesty (the load-bearing correctness rule):** `eth_getLogs`
  answers only when the requested range × addresses lies inside indexed
  coverage; anything else is a hard error (strict `-32000` retryable while
  indexing, never an empty array). Wallets interpret `[]` as "no events exist";
  serving it for an unindexed range would silently corrupt commitment trees.

## Architecture

All I/O-bearing code lives in `myotis-net` (the tokio/fs shell); `myotis-core`
stays sans-I/O; `myotis-engine` adds only JSON + thin FFI delegation — per
`docs/myotis-rust-engine-guidelines.md` (§1 wasm canary, §9 no globals).

New module: `rust/myotis-net/src/el/logindex/`.

### 1. Store (`logindex/store.rs`)

Per-network file under `dataDir`, following the suffix rule of
`host::create` (`myotis-engine/src/host.rs:149`): `logindex.db` /
`logindex-sepolia.db`. In-memory authoritative state + atomic persistence
(temp-file + rename, the `persist_snapshot` pattern, `sync.rs:1114`),
checkpointed after each backfill batch and periodically at head. Contents:

- config echo: watch-list (address, from_block) entries + config hash — a
  changed watch-list invalidates affected coverage, not the whole store;
- coverage: per watch entry, the contiguous indexed span `[low, high]` plus
  the backfill cursor (lowest verified header hash + number of the walk);
- logs: matching logs as stored tuples
  (block_number, block_hash, tx_hash, tx_index, log_index, address, topics,
  data) — the fields `eljson.rs:317` already emits per log;
- format: versioned framed blob; unknown version ⇒ discard and re-index
  (an index is derived data, never correctness-critical state).

Size expectation (kohaku set): tens–hundreds of MB on Sepolia; single-digit GB
on mainnet (railgun ciphertexts dominate) — acceptable for an opt-in feature.

**Recorded constraint (slice-1 memory model):** the initial store is fully
resident with whole-buffer snapshots — fine for the dormant slice and for
Sepolia-scale, but mainnet/railgun scale needs a paged/segmented store (or
streaming serialization + delta checkpoints) before slice 4 backfills
mainnet on mobile hosts. Full-rewrite checkpoints across a long backfill are
also O(n²) write amplification; the segmented store fixes both.

### 2. Head-follow appender (forward, cheap, always-on while enabled)

A tokio task owned by `ElReader` (so `ElReader::stop`/pause aborts it —
lifecycle rule from `SyncHandle::stop`, `sync.rs:461`). It polls
`anchor.optimistic_block_number()` (`el/anchor.rs:154`; no head-advance
callback exists today — polling at block cadence is fine, a `watch` channel is
a later nicety). For each newly anchored block: bloom-check the header; on
match run the existing whole-block verified path (`block_receipts_from`,
`el/reader.rs:1940`), extract watched logs, append, advance coverage `high`.

Reorg rule mirrors the tx-scan cursor (`el/reader.rs:2017`): below
`finalized_block_number()` (`el/reader.rs:649`) entries are immutable; above
it, on hash mismatch rewind coverage to the fork point and drop the orphaned
logs (iteration 1 drops rather than emits `removed:true`, since only
finalized-or-reconfirmed data is served — see Serving).

### 3. Backfill walker (backward, the expensive one-time job)

From the first anchored block downward to `min(watch.from_block)`:

1. Fetch headers descending in batches (`get_block_headers_by_number` with
   `reverse`, up to 1024/req — `el/peer.rs:240`); verify each batch by
   parent-hash chaining into the already-trusted lower edge (the
   `fetch_anchored_window` invariant generalized: the walk's trust root is the
   anchored head, extended downward hash-by-hash).
2. Per verified header: bloom-check against the watch-list (addresses +
   optional topic0s). Non-match ⇒ record coverage and discard the header.
3. Match ⇒ `get_receipts([hash])` (`el/peer.rs:325`) + `verify_block_receipts`;
   extract matching logs; store.
4. Checkpoint cursor + coverage after each batch; restart is idempotent from
   the checkpoint (any await may be the last).

Peers that cannot serve deep history (EIP-4444 rollout) make this **stall, not
fail**: track per-peer "history depth" refusals the same way snap-capability is
tracked, rotate peers, back off, surface progress via status. If the network
genuinely cannot serve a range, coverage simply never reaches it and getLogs
for that range keeps erroring — honest by construction. (This is exactly the
case where a bundled seed becomes the necessary optimization.)

**Tracked follow-up (upward bridging):** after node downtime longer than the
appender's window guard (~128 blocks), the coverage gap sits ABOVE the walk
cursor and neither component closes it — the appender waits, the walker only
descends. Bridge design: anchor a fresh chained window at the new finalized
head, walk down to the old high edge, then resume appending — absorbable by
the single-span coverage model without a second cursor as long as the bridge
completes before the high edge advances. Until it lands, the append-side warn
says plainly that coverage above the edge stays frozen.

### 4. Serving (`getLogs`)

Filter support: `fromBlock`/`toBlock` (hex or `latest`/`finalized`),
`address` (single or array), `topics` (positional, null wildcards, OR-arrays) —
the shapes kohaku's sync actually sends (batched consecutive ranges plus wide
historical ranges). Answer from the store when the full requested range is
inside coverage for every requested address **and** at-or-below the last
reconfirmed head; else `{"error": …}` → strict `-32000`. Output reuses the
per-log JSON of `receipt_json` (`eljson.rs:313-341`, factored into a shared
`log_json`), wrapped in an array; golden tests pin the shape on both sides.

### 5. Config & opt-in plumbing

There is no existing config channel into the Rust engine beyond
(network, dataDir) (`RustMyotisEngine.java:121` → `ffi.rs:61`), and
`servedBlockWindow` never crosses the FFI — so the watch-list gets a dedicated
post-create call rather than a `create_handle` signature break:

- FFI: `set_log_index_config(handle, config_json) -> bool`,
  `log_index_status_json(handle) -> String`,
  `get_logs_json(handle, filter_json) -> String` — UniFFI (`ffi.rs`) + C ABI
  (`capi.rs` + `rust/include/myotis_engine.h`), `ABI_VERSION` bump with a
  changelog line (`lib.rs:34`).
- Config JSON: `{ "enabled": bool, "watch": [{"address": "0x…",
  "fromBlock": n, "topic0s": ["0x…", …]? }, …] }`. Presets (the kohaku
  contract set per network) live host-side as data, not in the engine.
- Hosts: `NodeController` gains logIndex getters/setters next to
  `servedBlockWindow` (`ui/.../NodeController.kt:158`); persisted by each
  host's `Settings` actual; applied on (re)start via `RustChainHandle` right
  after create. UI: an opt-in toggle + progress row (coverage low edge vs
  target, blocks/sec) on the network card.
- Router: `eth_getLogs` added to `VERIFIED_METHODS` (`RpcRouter.kt:43`) and
  `tryVerified`, backed by a new `RpcBackend.getLogs(filterJson)`; tri-state
  string convention like `getBlockReceipts` (`VerifiedReads.java:76`).

### Kohaku preset (per network, from kohaku's configs)

| Contract | Mainnet from | Sepolia from |
|---|---|---|
| tornado-cash (registry + relayer registry) | 14,173,129 / 14,173,395 | 5,594,611 / 5,594,660 |
| railgun proxy | 14,693,013 | 5,784,774 |
| privacy-pools entrypoint | 22,153,713 | 8,461,453 |

### Engine-twin note

The Java engine does not get this in iteration 1: the embedding target for
wallet hosts is the Rust engine (iOS/Android/RN can only bundle Rust), so the
indexer lives in the Rust core. The `VerifiedReads.getLogs` default for the
Java engine returns null → strict "cannot serve" — same graceful path as any
unavailable verified method. A JVM twin (or a shared JVM-side indexer over
`VerifiedHistoryAccess`-style hooks) is tracked as follow-up work; the shared
router/API changes in this design already accommodate it.

### Slices

1. `logindex` module: types, filter matching, store + coverage + persistence,
   serve path with coverage honesty — pure logic + fs, unit-tested.
2. FFI + router + `VerifiedReads` + golden tests (shape pinned both sides).
3. Head-follow appender (reorg rule, status reporting).
4. Backfill walker (batch header walk, bloom skip, peer rotation/backoff,
   checkpointing) + Sepolia end-to-end run against the kohaku preset.
5. Hosts: settings plumbing + opt-in UI + kohaku preset data.
6. Follow-ups (separate): index-seed import/export (the bundling
   optimization), Unchained-Index-assisted discovery, JVM twin, `watch`-channel
   head notifications, EIP-7745 alignment.
