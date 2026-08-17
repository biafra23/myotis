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
