# eth_getLogs: scoped, verified log index (design)

Status: accepted design, implemented (iteration 1 on `feat/eth-getlogs`;
generic build/import/export on `feat/logindex-import` — see §Import below).
Scope decision (2026-08-01): **iteration 1 sources everything from EL/CL peers**;
scope extension (2026-08-14): the index is **generic** — any address set can be
indexed (`build-logindex`), exported as a portable snapshot, and imported on
any host of the same chain. The feature is **opt-in** per network; the shipped
**watch-list** preset (kohaku's privacy contracts) is one config among many.

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

**Checkpoint cadence (size-aware).** Until the segmented store lands, every
checkpoint rewrites the whole file, so a fixed interval makes the write RATE
grow with the index. Measured on the Gnosis Bee backfill: with a flat 10 s
cadence and an index that reached 238 MB, the daemon wrote **366 GB over a
6 h 22 m walk** (~15 MiB/s averaged; ~17.8 MiB/s sustained over the sampled
window). At that size the 10 s interval is not even the binding constraint —
one 238 MB write takes longer than 10 s, so the next checkpoint was due the
moment the previous finished and the process wrote essentially continuously,
at whatever the disk would take. On a phone that is flash wear, not just
noise.

What is bounded is therefore the sustained write rate, not the interval:
`persist_interval(last_snapshot_bytes) = ceil(bytes / 1 MiB/s)` clamped to
`[10 s, 600 s]` (rounded *up* — rounding down puts every non-multiple size
over budget). The lower clamp keeps a small or freshly-started index
checkpointing briskly, since when the file is small lost progress is the only
cost that matters; the upper clamp bounds how much of a walk a crash re-does
once the budget is unachievable anyway. The same index (238 MB = 227 MiB):
~227 s between checkpoints, ~22 GiB per walk instead of 366 GB.

Every *periodic* checkpoint path shares this throttle — walker, head bridge,
tail, and the appender's 64-block checkpoint. The appender's block counter is
not on its own a bound on the write rate: catching up after a gap applies 16
blocks per 6 s tick, so 64 blocks arrive every ~24 s whatever the index
weighs. The counter says *there is work to record*; the throttle says *when*,
and is not cleared when it defers (that would drop the checkpoint rather than
delay it). Two once-per-event writes are deliberately exempt: `ElReader::stop`
(the last write before the index goes away) and a head bridge's FINAL slice.

The clock those intervals are measured from (`PersistClock`) obeys one rule:
**only a write ends an interval, and the decision to write is taken where the
write happens.** `PersistClock::is_due` is a pure read — asking never consumes
anything — and `persist_log_index` consults it *under the checkpoint lock*,
not the caller before calling. Both halves are load-bearing. A predicate that
stamped would charge a full interval (up to 600 s of re-walked work on a crash)
to a checkpoint that may never be written, since a writer skips when another
holds the lock; and a decision taken outside the lock is not a claim — two
writers genuinely race here (the backfill step runs outside `log_index_drive`,
and a host thread can drive the tail on the `getLogs` path), so a "yes" read
before the other's write would be honoured after it, rewriting the whole file
back to back.

Everything that makes the file current starts an interval, so an off-budget
write can never be followed seconds later by a throttled one measuring from a
stale stamp — a phone waking repeatedly from sleep completing a bridge, or an
import that just wrote a multi-GB merge and would otherwise see the very next
appender tick rewrite it. That covers the throttled checkpoints, the two
exempt ones, the wholesale replacements (config push, import merge — which
stamp only if the write actually landed), and, distinctly, *adoption*: loading
a snapshot writes nothing but the file already describes the index installed
from it. Adoption credits all but the 10 s floor of the interval, so a launch
does not rewrite hundreds of MB byte-identical but for the header, while a
session shorter than the interval — routine on Android, where the platform
restarts the process — still banks its progress once.

A failed checkpoint is logged, not swallowed. It stays best-effort — the
previous snapshot is what a crash finds, which is safe — but a *permanently*
failing one (`ENOSPC` being the realistic cause) now costs up to 600 s of walk
per crash rather than 10 s, so it must not be invisible.

This bounds the constant — the O(n²) asymptotics still need the segmented
store above.

**Serialize under the lock, fsync outside it.** A checkpoint reads the whole
store, so serialization has to hold the index mutex; the write and the `fsync`
must not. On a multi-hundred-MB index the fsync dominates the checkpoint by
orders of magnitude, and holding the mutex across it stalls the appender, the
backfill walker and every `getLogs` query for the whole duration. This applies
to the PERIODIC checkpoint; the config push, the export and the import merge
still serialize and fsync under the index lock, which is fine because they run
once per user action, not on a clock.

Dropping the index lock before the write means it can no longer be what keeps
two checkpoints apart, and it was: every writer used to hold it across the
whole create→write→fsync→rename. Two mechanisms replace it.

- `write_atomic` (`logindex.rs`) names its temp file with a per-**call**
  counter, not just the pid (`next_tmp_path`). Two writers aiming at one path
  would otherwise share a temp file: the loser's `File::create` truncates the
  winner's mid-write, or the winner renames the shared temp out from under the
  loser, whose still-open fd then writes into the LIVE `.db` that readers are
  reading. It removes the temp on failure of either the write or the rename —
  the likely trigger is `ENOSPC`, and after a successful write the leftover is
  a *full-size* snapshot, which is exactly what keeps a disk full — and fsyncs
  the parent directory so the rename itself is durable. This is the log
  index's primitive, not a repo-wide one — `sync.rs` and roost keep their own.
- `ElReader::log_index_write` is a dedicated mutex held across
  serialize→rename by every site that writes an index `.db` (the periodic
  checkpoint, the config-push checkpoint, the export and the import merge).
  Without it the rename order need not match the serialize order, and an older
  snapshot can silently land on top of a newer one — or an export, which
  strips display names, can land on the canonical file. **Lock order: acquired
  before `log_index`, never after.** The periodic checkpoint takes it with
  `try_lock` and skips on contention: an import merges GBs under it, the
  checkpoint is best-effort, and whoever holds it is writing a newer snapshot
  anyway. A skip un-stamps the clock so the next tick retries rather than
  waiting out a whole interval.

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

**Request sizing (adaptive).** Candidate blocks are fetched in chunks, and a
peer answers `get_block_bodies`/`get_receipts` up to a soft BYTE budget — a
chunk that exceeds it comes back short. A truncated chunk ends the whole batch
(everything above the cut is still applied; coverage never claims more than was
verified), so the batch advances the cursor only as far as the first truncated
chunk, having already paid for a full ~1023-header window. On a candidate-dense
range where peers cut at ~15 blocks, a fixed 64-block chunk truncates *every*
time — measured on Gnosis, that walk spent ~a quarter of its bandwidth
re-downloading the same header window to advance ~15 blocks (1023 × ~600 B of
headers per batch against ~1.3 MiB/s total, at ~0.55 batches/s).

So the chunk width tracks what peers in the current range actually serve:

- **Down** toward the observed serve width on truncation, but floored at a
  quarter of the current width. `served` describes the blocks in *that* chunk,
  not the range — one fat block, or one degenerate peer, can report 1 where the
  range serves 40, and the width is shared across peers. Unfloored, a single
  such observation costs ~70 batches of probing to climb back from.
- **Up** only as a periodic probe, on the Nth consecutive untruncated batch that
  actually exercised the full width (a bloom-sparse window that asked for 5
  blocks and got 5 says nothing about 64). Never as a reflex after each clean
  batch: growth overshoots by construction, so growing on every clean batch
  settles into a stable truncate-every-*other*-batch limit cycle — the same
  pathology, re-entered through the back door.

A truncation counts as evidence about the width when the chunk was **the widest
one that batch could have asked for** — `min(width, candidates)`, not `width`.
A bloom-sparse window with 30 candidates at width 64 yields a single 30-block
chunk, and a peer cutting it at 15 is the only budget measurement such a batch
can produce; ignoring it left every window with `budget < candidates < width`
permanently stuck (the width never moved, and the truncation ended the batch
before the clean path could run). What is excluded is a batch's short *tail*
chunk, which exists only when `candidates > width` and therefore always follows
a full-width chunk that already succeeded.

Chunks that come back full also leave the request pipeline at full depth. A
truncation the probe itself provoked is excluded from that signal, so a probe
costs one short batch rather than one short batch plus a full window run at
depth 1. Only an observation that is evidence about the width may spend a
pending probe — otherwise the probe survives untested and the next truncation,
quite plausibly that same probe hitting its ceiling, is misattributed to the
range.

The width is shared across peers on purpose (the byte budget is a property of
the range as much as of the peer), which makes it a throughput/latency griefing
vector but not a correctness one — every block is verified on arrival however
many were requested. The latency side is the sharper one: chunks per batch is
`ceil(candidates / width)` at pipeline depth 4, so a floored width turns a full
window from ~4 requests into ~1023, overrunning the walker's tick budget (only
checked between rounds) and delaying the head-follow appender that shares the
task. Self-heals over the probe ladder; a hard chunks-per-batch bound is the
natural pairing for the width floor if it ever shows up in practice.

Policy is pure (`next_chunk_len` / `fold_chunk_observation`, `el/reader.rs`);
the limit-cycle bound and the floor are pinned by test. The width is *not*
persisted — the walk resumes at a checkpointed cursor that may be in a
different density regime, and re-learning costs one truncated batch per step
down the ladder (at most three, since the floor bounds each step to a quarter).

Peers that cannot serve deep history (EIP-4444 rollout) make this **stall, not
fail**: track per-peer "history depth" refusals the same way snap-capability is
tracked, rotate peers, back off, surface progress via status. If the network
genuinely cannot serve a range, coverage simply never reaches it and getLogs
for that range keeps erroring — honest by construction. (This is exactly the
case where a bundled seed becomes the necessary optimization.)

**Peer choice is a throughput decision, not just an availability one.** A
byte-budget-truncated batch is deliberately a success (it applies above the cut
and the next round resumes at it), so "served 62 blocks" and "served 1023
blocks" are both `Ok`. The round therefore cannot pick a peer by success alone:
taking the first success pins the walk to whatever the pool happens to list
first. Observed on gnosis (2026-08-15): one peer held the backfill at ~62
blocks/batch (~50 blk/s) for hours while eleven other live peers were never
tried — a ~15x throughput loss with no error anywhere and no dishonest
coverage, which is why nothing else surfaced it. The round now ranks peers by
the THROUGHPUT of their last batch — blocks the cursor actually advanced,
divided by how long the batch took (`rank_backfill_peers` — pure and
unit-tested). The rate, not the block count, is the metric that matters: a peer
serving 1023 blocks slowly is worse than one serving 300 quickly, and a peer
that fully serves the inherently short final batch near the walk's target must
not read as having truncated.

Around that metric:

- **Unmeasured peers are sampled first**, so a better server can be discovered
  at all. "No score" means "not measured" — never sampled, or pruned when the
  peer left the pool (the score map is bounded by the live pool, so a score
  never outlives the connection it describes).
- **A peer-attributable failure scores zero** rather than staying unscored, so a
  peer that cannot serve the range stops costing a round-trip ahead of every
  good one. A failure of *ours* — a config swapped mid-batch, our own gap reset
  — does not score the peer at all; charging it would let our own bookkeeping
  demote a good server, and the ranking is sticky between exploration rounds.
- **Every `RESAMPLE_EVERY`-th round is an exploration round**: the peer whose
  measurement is *stalest* is promoted over its score. Truncation depends on the
  RANGE as much as the peer, so a peer demoted on a candidate-dense stretch must
  be able to climb back. Exploration is load-bearing — the round stops at the
  first peer that serves, so leaving the ranking alone would only ever
  re-measure the current best, and a demoted peer could never recover. Promotion
  is keyed on the peer's ADDRESS, not on a pool position: `snap_peers()` lists
  newest-dialed first, so every dial or drop shifts the peers below it and a
  position-based rotation would silently walk toward a different peer than the
  one it started on — the guarantee has to be per-peer to mean anything. The
  clock is a dedicated round counter, not the success counter, which freezes
  during precisely the stall that exploration exists to escape. It is advanced
  on every attempt that reaches a verdict about a peer, *including* one that
  failed for reasons of ours: that failure must not change the peer's rate, but
  its turn still has to count, or the peer stays permanently "stalest", captures
  every exploration round, and starves the rest — the same guarantee failing in
  the opposite direction.
- **Ranking never *excludes* a peer** — the round still tries the whole pool,
  because the peer that fails one range may be the only one holding the next.
- **The peer does not choose the batch size.** `max_headers` is a request field
  an honest peer honours, not something the wire format enforces (the header
  decoder caps only at the 10 MiB frame ceiling), so the response is clamped to
  what was asked for. Unclamped, an over-serving peer would decide how much
  candidate work one batch does, and would push the applied count past the
  requested one — which voids the measurement, leaving that peer permanently
  "unmeasured", the rank that sorts *first*. It would monopolize the walk by
  exactly the route this ranking closes.
- **An unmeasurable success drops the peer's score rather than keeping it.** If
  the cursor moves under a batch (a reorg rewind, a config swap, a snapshot
  import), the delta is not that peer's throughput. Keeping the old value would
  be wrong in one specific and costly way: a retained zero from an earlier
  failure would demote a peer that just demonstrated it can serve the range.
  "Absent" already means "not measured", which is the honest state.

Known limitation, accepted: the scores are not strictly commensurable. A
batch's elapsed time also covers our own root recomputation, contention on the
index lock, the candidate density of that particular range, and the global
pipeline depth — so a peer measured on a dense range at depth 1 can rate below
one measured on a sparse range at depth 4. Only the round's winner is
re-measured each ordinary round, so the losers' scores go stale. The
exploration round is what bounds the damage — promoting the stalest measurement
means the losers are re-measured in a bounded number of rounds, oldest first —
and a decaying score would be the further fix if this proves to matter. It would
be measurable as a walk that stays slow while a faster peer sits idle in the
pool.

Known property, accepted: a request timeout on the batch's opening header fetch
blames the peer unconditionally, where the chunk fetch withholds blame at
pipeline depth > 1. The asymmetry is deliberate. A timeout here can occasionally
be our own cancelled prefetches from a previous truncated batch still occupying
the peer's serving queue — but withholding blame would leave a peer that
*always* times out permanently unscored, and unscored sorts first, so it would
cost a full 15s round-trip ahead of every good peer on every round. That is the
pathology the zero-on-failure rule exists to prevent, reintroduced through its
most expensive door. A peer wrongly blamed is not stranded: it becomes the
stalest measurement and the next exploration rounds re-measure it.

Known property, accepted: this makes the walk's concentration on a single peer
deterministic where it was previously incidental, and a peer can deliberately
win the rank by serving well. That is bounded by the trust model rather than by
the ranking — everything served is verified against the parent-hash chain and
the receipts root before it is applied, so a peer that wins the rank still
cannot forge a log or hide one. It can only withhold, which is the liveness
attack CLAUDE.md already treats as detected-not-silent: coverage stops
advancing, and getLogs keeps erroring honestly for the range it never reached.

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
  "fromBlock": n, "topic0s": ["0x…", …]? }, …] }`. Watch lists live host-side
  as data, not in the engine — originally a built-in preset (the kohaku
  contract set per network), since 2026-08-20 the user's own entries
  (`LogIndexWatch`, entered on the Index tab and persisted per network).
- Hosts: `NodeController` gains logIndex getters/setters next to
  `servedBlockWindow` (`ui/.../NodeController.kt:158`); persisted by each
  host's `Settings` actual; applied on (re)start via `RustChainHandle` right
  after create. UI: an opt-in toggle + progress row (coverage low edge vs
  target, blocks/sec) on the network card.
- Router: `eth_getLogs` added to `VERIFIED_METHODS` (`RpcRouter.kt:43`) and
  `tryVerified`, backed by a new `RpcBackend.getLogs(filterJson)`; tri-state
  string convention like `getBlockReceipts` (`VerifiedReads.java:76`).

### Kohaku preset (RETIRED 2026-08-20 — now migration seed data)

The original built-in preset (tornado-cash registries, railgun proxy,
privacy-pools + its sepolia pools, per network from kohaku's configs) was
replaced by user-entered watch lists. The data survives ONLY as
`LogIndexWatch.legacyKohakuWatchJson`: a user who had the preset toggle on has
the enabled flag persisted but no watch entries (the preset lived in code), so
each host seeds its watch store from the legacy table on first read — without
that, the first post-upgrade config push would silently drop the user's
subscriptions.

| Contract | Mainnet from | Sepolia from |
|---|---|---|
| tornado-cash (instance registry / relayer registry) | 14,173,395 / 14,173,129 | 5,594,611 / 5,594,660 |
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
6. Generic build / import / export — DONE (2026-08-14), see §Import below.
7. Follow-ups (separate): Unchained-Index-assisted discovery, JVM twin,
   `watch`-channel head notifications, EIP-7745 alignment, per-entry
   frontiers (see §Import, canonical-shape note), snapshot provenance
   (imported-coverage marker / signed snapshots) and an explicit
   unsubscribe surface (see §Import, trust notes).
8. Follow-up (observability, found 2026-08-15 while building the Bee/Swarm
   index): the daemon's `peers` IPC command reads the engine-routed
   `ChainHandle`, and `RustChainHandle` stubs both `discoveredPeers()` and
   `connectedPeers()` to an empty list — so on a `-Pengine=rust` daemon it
   always answers `{"count":0,"peers":[]}` while the Rust pool is in fact
   serving a dozen peers. That is the shape
   this document warns about everywhere else — an empty result that reads as
   "none exist" when it means "not measured here" — and it cost real time
   during the backfill investigation by making peer scarcity look like the
   bottleneck. It should report the Rust pool, or say the table is
   unavailable for this engine; it must not answer a confident zero.

## Import: generic build, portable snapshots, merge (v2 format)

The snapshot format is **self-describing** (`MLIX` v2): the frame carries a
**chain tag** (network id + EL genesis hash, checked on every load — logs are
keyed by block-global `(block, log_index)`, so a foreign chain's file would
silently collide keys and fabricate coverage) and the full **watch-table**
(address, from_block, topic0s, display name), so a file can be imported on a
host that has never seen its config. v1 files (fingerprint-keyed) still load
for upgrade — the next checkpoint rewrites them as v2 — but are refused on the
portable path: they name no subscription set.

**Generator (daemon, Rust engine):**

    ./gradlew :app:run -Pengine=rust                    # generator daemon
    :app:run -Pargs="build-logindex 0xAAA… 0xBBB… --from 14173129"
    :app:run -Pargs=logindex-status                     # poll to complete
    :app:run -Pargs="export-logindex /tmp/mainnet-privacy.db"

`build-logindex` takes plain addresses (no preset) and subscribes them at max
download speed. Entries are written UNNAMED by design — display names are
cosmetic, exist purely so the Index tab shows which contracts' logs are
available, and are filled in by the importing wallet itself (see §Naming
below); the generator has no naming duties. `--from` is a trust assertion:
`LogIndex::query` clamps its coverage requirement to it, so overshooting the
real deployment silently hides events; undershooting (the default 0) only
walks further.

**Import** (`import_log_index_files`, ABI v24): hosts pick snapshot files
(desktop AWT dialog / Android SAF / iOS document picker; the daemon has
`import-logindex <file>…` plus the zero-effort drop-in — a portable file at
`dataDir/logindex[-net].db` activates itself at start). The engine merges
all-or-nothing with its current index and starts catch-up immediately for
every imported address via the existing walker/bridge/appender. Trust: an
imported file is data CLAIMED VERIFIED by whoever generated it — the same
standing as the node's own snapshot — so import is a deliberate user act on
the hosts, never something fetched. Two properties to state plainly
(review, 2026-08-14): served logs do not distinguish locally-verified from
imported coverage (a provenance marker in the status JSON, or a signed
snapshot format, is tracked follow-up hardening); and subscriptions are
currently ADD-ONLY — config pushes union and imports merge, so an address
can only leave the index via a topic-conflict replace or a cache wipe. An
explicit unsubscribe/replace surface is follow-up work; until then, note
that an imported subscription is sticky.

**Merge rules** (`LogIndex::merge`): watch union (same address requires equal
topic0 sets — a span's meaning includes the restriction it was indexed under;
`from_block` = min; name = first non-empty), coverage clamped to the MINIMUM
of the sources' own highs and unioned per address, logs kept only inside the
merged span, cursor = the deepest source trust edge the walk can RESUME from
(`walk_resumable`: every incomplete span must sit at or below the cursor —
the walker only descends, so a hole above it is unreachable forever; when no
source cursor qualifies, the cursor is dropped and the appender re-seeds it
at the top, making the walker re-descend through the kept spans — headers-only
where the bloom misses — until every hole closes). The output is **canonical**
— every present span shares one global high — because that is the only shape
the appender/walker pair can resume (`append_block` demands each new block
adjoin EVERY live entry's span; per-entry frontiers would wedge the appender).
A residual gap at apply time self-heals the same way: the walker drops its
cursor and re-descends rather than re-fetching the same batch forever. The
min-high clamp is also what resolves same-address disjoint spans: the lower,
deployment-anchored history survives and the band above re-indexes —
re-fetched, never trusted from the staler file. Redundant sources (subset
coverage, nothing new) are pruned first so a stale re-import cannot drag the
merged high back in time. Lifting the canonical-shape constraint (true
per-entry frontiers) is the tracked follow-up that would make merges lossless;
it needs append/bridge machinery per entry.

**Additive config (behavior change in v23):** `set_log_index_config` unions
the pushed config with the already-subscribed set (live index, or on boot the
portable snapshot's own watch-table). Without this, every host restart's
preset push would fingerprint-mismatch an imported index into a full
re-index. Coverage survives bit flips, renames, LOWERED from_blocks (the
cursor drops when the new hole sits above it — the walk re-descends), and
even genuinely NEW addresses (the push merges with the existing index as a
config-only source, so a preset that grew — or a preset pushed on top of a
dropped-in snapshot — keeps the accumulated coverage and re-descends for the
new entries). Only a changed topic set replaces outright: a span's meaning
includes its restriction, nothing is mergeable.

**Naming:** display names are cosmetic — they exist so the Index tab shows
which contracts' logs are available — and they are resolved IN THE IMPORTING
WALLET, not at generation (owner's call, 2026-08-14: the generator writes
unnamed entries). A naming pass inside the appender task resolves one
unnamed address per tick (forward-verified `EnsQuery::Reverse` against the
Auto root ladder, 30s-bounded, ≤3 attempts each) and fills ONLY empty
names — a host-pushed preset label outranks a late lookup, and a name that
cannot resolve just stays an address. Names are excluded from the config
fingerprint: renaming never costs a re-index.
