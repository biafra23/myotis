# myotis-net, part 6: the verified reader

*Stop 14 · crate `myotis-net`, `src/el/reader.rs`* · 1 file · 18,846 lines · about 185 minutes

`ElReader` is where the execution layer comes together. It combines discv4, the peer pool and the beacon-fed `ExecAnchor` into verified wallet reads (accounts, storage, proofs, code, `eth_call` and friends, ENS, blocks, receipts, fees, transactions), the transaction send path, and the engine behind the `eth_getLogs` index. Since September the file has more than doubled, to 18,846 lines. Most of the growth is new subsystems: a per-head fee memo with a background follower, an address-activity follower that reads block access lists, a judged and Tor-capable send path, finalized-state reads, and a log index that survives restarts with a finality claim. Read it with the section map. This stop is about how it is *built*: which lock guards what, which tasks own what, and how work is cancelled.

## Rust you will practise

- **One struct, many locks** — a `&self`-only API behind `Arc`: `std` vs tokio mutexes, data-less `Mutex<()>` tokens, owned guards, semaphores, `Notify`, a documented lock order.
- **Racing and detaching** — `FuturesUnordered` + `select!`; a dropped future is cancelled, a dropped `JoinHandle` is not.
- **Background tasks without leaks** — `self: &Arc<Self>`, a `Weak` in each follower, `'static` spawns that own their data, drop guards, paused-clock tests.

## What changed since September

The old tour read this file at 8,914 lines. The structure it described is still there (configuration, result types, hedging, the struct, construction, state reads, EVM reads, blocks, writes, receipts, the log index, tests), but each part grew and several new parts arrived:

- **Finalized reads.** Most reads take a `ReadAnchor` (`Head` or `Finalized`). A finalized read is proven against the beacon-finalized state root with no fallback to any other root. `eth_getProof` (`get_proof`) is new.
- **More EVM entry points.** `eth_call` for a full transaction object, `eth_createAccessList`, `trace_call` and `simulate`, all on the same setup.
- **The send path judges and detaches.** `send_raw_transaction` refuses non-transactions and other chains' transactions, refuses a transaction the sender provably cannot pay for (a pre-broadcast check on fresh, verified state), answers at the first peer write that lands (`first_accepted`), and in Tor mode sends only over Tor.
- **The fee memo.** Fee reads are answered from a per-head memo, kept fresh by a fee follower task, with single-flight computes and bounded waits.
- **The address-activity follower** (#691) keeps verified headers for watched addresses and answers some account reads from block access lists (BALs) with no peer request at all.
- **Peer bookkeeping in races.** A hedged race now also reports peers the winner *outpaced*, and block/receipt reads defer strikes during tip lag.
- **Log index.** Receipts-first candidate fetches, a separate chunk sizer for the head side, unwatch, a restart finality claim, and many more pure policy functions with their own test modules.
- **Pause and resume.** `ElCarry` carries the node key and pool memory from a paused reader to the one that resumes it.

<a id="f-myotis-net-src-el-reader-rs"></a>

### myotis-net/src/el/reader.rs

*library · 18,846 lines · Java twin · VerifiedAccountQuery / VerifiedRpcBackend*

One `ElReader` per hosted chain. It owns a discv4 service and a snap/eth `PeerPool`, and shares the light client's `ExecAnchor`, the only trust bridge from consensus to execution. **State reads** check Merkle-Patricia proofs against a state root, then tie that root to the beacon chain (`stateRootMatch` or `headerChain`). An unverifiable state read still returns `Ok`, with the reason in `fail_reason`. **Block, receipt, fee and transaction reads** check that a header window hash-links to a beacon-anchored block (the optimistic head, or the finalized block), then check the trie roots. For those reads, returning a result at all *is* the verification. The file also holds the send path and the whole log-index engine.

`rust/myotis-net/src/el/reader.rs` · lines 1–20

```rust
//! The EL verified-read reader (EL-A7b): composes discv4 discovery + the peer
//! pool + the CL-fed [`ExecAnchor`] into verified account/storage queries — the
//! Rust twin of the Java `VerifiedAccountQuery` / `VerifiedStorageQuery` ladders.
//!
//! One [`ElReader`] per hosted chain owns its own discv4 UDP service and
//! [`PeerPool`], and borrows the beacon sync loop's [`ExecAnchor`] (the CL→EL
//! trust bridge). A query:
//!
//! 1. picks a live snap peer from the pool,
//! 2. picks the state root: the beacon anchor's optimistic root (a head read),
//!    or the finalized root (a `finalized` read, ABI ≥ 32 — servable while
//!    the peer's state window, ~128 blocks on geth, still holds it: finality
//!    trails the head by two epochs, 64–96 blocks, so a finality delay puts
//!    it out of reach), with the peer's own head as the head read's fallback,
//! 3. snap-fetches the account/slot and MPT-verifies it against that state root
//!    (the proof is the trust anchor, never the peer's slim body),
//! 4. anchors the state root to the beacon chain via the verified ladder
//!    (`stateRootMatch` fast path, else the `headerChain` walk),
//! 5. returns the data + the verdict tokens; verification failures are recorded
//!    in `fail_reason`, never raised.
```

*[Protocol & domain](01-primer.md#primer-domain)* The module doc still describes the five-step state-read ladder. Step 2 is new since September: a read picks either the optimistic root (head read) or the finalized root (`finalized` tag). The doc explains why a finalized read can fail: geth keeps about 128 recent states, and finality trails the head by 64–96 blocks, so a finality delay pushes the finalized state out of what peers still hold.

#### Section map

| Lines | What happens |
|---|---|
| 1–51 | Module doc (the read ladder), imports. |
| 53–192 | `ElConfig`; the dedicated Sepolia enode; `parse_enode` (strict, for host-pushed pins) and `parse_boot_enodes` (lenient, for shipped pins); `fork_filter_for` (the discv4 fork-id filter on the chain's epoch grid). |
| 194–388 | `impl ElConfig`: `mainnet()` (bootnodes re-synced from geth 2026-10-04, EIP-1459 DNS tree), `sepolia()`, `gnosis()`, and the new `chiado()`. |
| 390–470 | `SendError` (Refused / Rejected / Unavailable), `judge_read` and `PreBroadcast`: the pre-broadcast verdict on the sender's account. |
| 472–640 | Result types: `VerifiedAccount`, `VerifiedStorage`, `VerifiedCode`, `VerifiedBlock`; `account_fact`, `StorageSnapCost` (shadow-cache inputs), `BlockDepth`. |
| 641–700 | Block lookback (512), hash-scan depth (64), the tip-lag retry policy, `all_tip_lag`, `PoolReadError` (Fatal vs TipLag with deferred strikes). |
| 702–810 | Receipt-scan constants (lookback, per-poll cap, TTL, deadline, bodies in flight), `VerifiedReceipt`, `VerifiedTransaction`, LRU caps, the 20 s rebroadcast interval. |
| 811–950 | Log-index head-follow constants (`APPEND_WINDOW`, stall ticks, bridge and tail limits, backfill yield), `backfill_should_yield`, `AppendStall`. |
| 951–1022 | `SentTxState`, `SentTx`, `RebroadcastRoute` and `rebroadcast_route`, `tor_routing_on`, with a test. |
| 1023–1152 | `UnwatchError`, `BridgePlan` (descend, then ascend), `TxLookup`, `Found`, `raw_at` (+ test), `TxLocation`, `TxScanState`, the tip sample size. |
| 1153–1298 | Hedging constants: `HEDGE_DELAY` (3 s), `BULK_HEDGE_DELAY` (6 s) and `block_hedge_delay`, the 5 s on-demand fill deadline with compile-time `const _: () = assert!(…)` checks, `MAX_HEDGED_ATTEMPTS` (3), `RaceOutcome`. |
| 1299–1589 | Broadcast helpers: `first_accepted`, `rotated_take`, `tor_candidates`, `TorBroadcast`, `tor_broadcast`, `broadcast_pushes` (+ paused-clock tests), `TorRebroadcastGuard`. |
| 1590–1787 | **`hedged_race`**; `BlockAttempt`; `PoolRaceVerdict` and `pool_race_verdict` (who gets struck, excused or credited); `race_served_by_winner`. |
| 1788–2045 | Tor bounds; fee and activity constants; `ActivityBalStats`; `FeeHistoryError`, `BlockFromError`, `FeeBuildError` (no `From<String>`, on purpose); `summarize_peer_failures`; `FeeHistory`, `FeeEstimate::raised_for`. |
| 2046–2275 | The **`ElReader` struct** (47 fields), `TxScanMap`, the EVM proof-cache size, the ENS attempt deadline. |
| 2276–2521 | Request budgets (`request`, `request_with_budget`, `cancel_requests`); construction (`start_mainnet`, `start_for`, `start_carried`, `start`, `start_inner`). |
| 2522–3300 | Log-index configuration: `set_log_index_config` (additive union, refused push is a no-op), `unwatch_log_index`, activation from disk, `export_log_index`, `import_log_index`. |
| 3301–3458 | `stop_log_index_appender`, **`ensure_log_index_appender`** (the 6 s background task), `log_index_name_tick` (ENS reverse names for unnamed entries). |
| 3459–3678 | The finalized per-block append tick; `advance_log_index_tail_now` (the on-demand fill, 5 s deadline). |
| 3679–4059 | The optimistic tail: `log_index_tail_tick` (reorg detection against its own record, rewind), `log_index_rewind_to`. |
| 4060–4436 | Checkpoints: `persist_log_index`, clamp, restart-claim bookkeeping (`write_own_checkpoint`, `publish_finality_claim`, `settle_restart_claim`), chain tag, bridge and tail-record clearing. |
| 4437–4866 | The head-gap bridge: `log_index_bridge_step`, `bridge_fetch_logs`, `fetch_logs_for_known_headers`. |
| 4867–5597 | The descending backfill: step, peer ranking, round, and `log_index_backfill_batch` with its pipelined chunk fetches. |
| 5598–5748 | Status accessors: backfill rate, `with_log_index`, runtime bits, pool counts, anchor numbers and slots. |
| 5750–6358 | Account reads: `get_account` / `_pinned` / `_following`, answers from the activity follower (`followed_account`, `seed_followed`), `get_account_proven`, **`hedged_read`**, `settle_pool_race`, the per-peer fetch, finalized anchor selection, root choice, verdict, result building. |
| 6359–6554 | The Tor account read (`get_account_over_tor`), feature-gated, fail-closed. |
| 6555–6936 | Storage reads; `get_proof` (`eth_getProof`, new), `confirm_recent_head`, `proof_from`. |
| 6937–7012 | Code reads: `get_code`, `get_code_pinned`, `fetch_bytecode`. |
| 7013–7335 | EVM calls, each a public wrapper over an `_inner`: create, overridden, transaction object, `estimate_gas_tx`, `create_access_list`, `trace_call`, `simulate`. |
| 7336–7525 | ENS: forward resolution, the `Auto`/`Finalized`/`Optimistic` root ladder, the CCIP-Read callback, `call_answer`. |
| 7526–7701 | EVM setup: head or finalized header, `evm_executor_for`, `snap_oracle`, the fixture-recorder seam. |
| 7702–8062 | Blocks: by number, verified headers, `resolve_block_hash`, `head_anchored_header_window`, the hedged block read and the per-peer serve. |
| 8063–8456 | The fee memo: `fee_estimate`, `bounded_fee_compute`, `wait_for_fee`, single-flight refresh, the peer ladder, the fee follower task. |
| 8457–8805 | Address activity (#691): `set_activity_watch`, `activity_report`, the follower task, the BAL pass, teardown. |
| 8806–9097 | `fee_history`: plan, refresh, build, per-peer build. |
| 9098–9470 | Writes: `send_raw_transaction`, `send_judged`, `record_sent`, `pre_broadcast_check`, the pending-nonce overlay, clearnet and Tor rebroadcast. |
| 9471–9893 | Transaction and receipt reads, raw transactions, block receipts, the block-hash LRU, strike banking, the anchored head. |
| 9894–10196 | The receipt scan: `locate_mined_tx`, `scan_window`, `tx_scan_state`, canonicality re-checks, per-peer scan. |
| 10197–10224 | **`stop`**; the end of `impl ElReader`. |
| 10226–10600 | Free functions: receipt builders, `WindowTop`, `choose_window_top`, **`fetch_anchored_window`** (the header trust gate), bounded body streams, root checks, the watched-log test. |
| 10601–10943 | Receipts-first candidate chunks: `CandidateScan`, `CandidateChunk`, the `CandidateSource` trait, `fetch_candidate_logs`, `BodyPolicy`. |
| 10944–11342 | `log_call_cost`, `await_bounded`, `FeeFailOnDrop`, fee math (tips, reward inputs, gas-weighted percentiles). |
| 11343–11690 | `fresh_head`, verdict helpers, `storage_key`, `ElCarry`, `generate_node_key`, base-fee math, ENS and CCIP helpers. |
| 11691–13868 | `mod tests`: 95 tests, with nested modules for failure summaries, finalized anchors, tip lag, hedged reads (paused clock), bounded fee waits, reward inputs, receipt-scan bodies. |
| 13869–15156 | Log-index pure policy: stored-log conversion, tail rules, the restart claim, bridge chunks, `BackfillBatchError`, peer ranking, `ChunkSizer`, persist cadence, `checkpoint_bytes`. |
| 15157–18846 | Fourteen more test modules for that policy, then `first_accepted_tests` and `pre_broadcast_tests`. |

*[Tests](01-primer.md#primer-testing) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* About 13,000 lines are production code and 5,900 are tests: 185 `#[test]` and 80 `#[tokio::test]` functions in 20 `#[cfg(test)]` modules, 31 of them on tokio's paused clock. Many test modules sit right after the pure function they test, so the file alternates between code and tests in its second half.

#### The struct: a map of the memory model

Hosts hold the reader as `Arc<ElReader>` (`host.rs` keeps an `Option<Arc<ElReader>>` per running chain). `ElReader` is not `Clone`, and almost every method takes `&self`. So every field that changes after construction is behind something that allows mutation through a shared reference: a mutex, an atomic, a semaphore. In Java terms, every field is `final`, and the mutable ones are `final` references to synchronized objects. Sorted by the kind of guard:

| Guard | Fields | Why that guard |
|---|---|---|
| none (set once) | `discovery`, `pool`, `min_suggested_tip_wei`, `block_time`, `chain_id`, `log_index_path` | Owned values. `discovery` and `pool` lock internally. |
| `Arc<…>` | `anchor`, `eth_cfg`, `evm_proof_cache`, `evm_bytecode_cache`, `read_stats`, `sent_tx_watch` | Shared with other owners: the beacon loop, every `eth_call` executor, every peer read loop. |
| `std::sync::Mutex`, brief holds | `requests`, `tx_scans`, `block_hash_numbers`, `unplaced_hashes`, `sent_txs`, `log_index`, `log_index_peer_serve`, `log_index_rate`, `log_index_bridge`, `log_index_tail`, `log_index_claim`, `fee_cache`, `activity`, `activity_bal_liars`, `activity_bal_stats`, and the four task slots | In-memory work only, never held across an `.await`. |
| `std::sync::Mutex<()>` | `log_index_write` | Guards no data: a token that serialises checkpoint writes. |
| `tokio::sync::Mutex<()>` | `log_index_drive`, `fee_fill`, `fee_estimate_compute` (in an `Arc`) | Held across network awaits on purpose: they serialise slow work. |
| atomics | `log_index_unwatch_owed`, `log_index_pipeline_full`, `log_index_backfill_rounds` | Single flags and counters. |
| locks inside the type | `log_index_persist` (`PersistClock`), the two `ChunkSizer`s (atomics), `log_index_body_policy` | Small helper types that are themselves `&self`-mutable. |
| `Arc<Semaphore>`, `Notify`, `watch::Sender` | `fee_compute_permits`, `send_check_permits`, `fee_stored`, `request_shutdown` | Bounding detached work, waking waiters, broadcasting shutdown. |

`rust/myotis-net/src/el/reader.rs` · lines 2046–2107

```rust
/// A running EL reader: owns discv4 + the peer pool, borrows the beacon anchor.
pub struct ElReader {
    request_shutdown: tokio::sync::watch::Sender<bool>,
    requests: std::sync::Mutex<Vec<std::sync::Weak<super::request::Operation>>>,
    discovery: Discv4Service,
    pool: PeerPool,
    anchor: Arc<ExecAnchor>,
    /// Our eth handshake parameters — reused by the Tor read path
    /// (`docs/privacy-and-tor.md`) to dial a per-address isolated circuit with a
    /// fresh ephemeral identity, independent of the pool's clearnet connections.
    /// Only read on the `tor` feature; kept unconditionally so the struct shape
    /// doesn't depend on the feature.
    #[cfg_attr(not(feature = "tor"), allow(dead_code))]
    eth_cfg: Arc<EthConfig>,
    /// Network floor for the suggested tip (from `ElConfig::min_suggested_tip_wei`).
    min_suggested_tip_wei: u128,
    /// From `ElConfig::block_time`.
    block_time: Duration,
    /// The chain's id: `ElConfig::network_id`, which equals it on every
    /// network served. A send signed for another chain is refused (#665).
    chain_id: u64,
    /// Cross-call EVM caches, shared across every `eth_call` on this reader. Both
    /// hold `stateRoot`-keyed / content-addressed cryptographic facts, so reuse is
    /// sound. Because a call pins to the CURRENT head (whose root advances ~every
    /// 12 s), the win is on a burst of identical calls that land on the same head,
    /// plus bytecode (content-addressed → never re-fetched once seen) — NOT across
    /// a head advance. Freezing a per-block-number context so a slow retry reuses
    /// the cache is a later dispatch-fairness refinement (EL-C-3).
    evm_proof_cache: Arc<InMemoryStateProofCache>,
    evm_bytecode_cache: Arc<InMemoryBytecodeCache>,
    /// The read-fetch shadow cache (`el::readstats`): every verified account /
    /// storage / bytecode fetch on this reader — the direct reads below and the
    /// EVM oracle's — reports here so `read_stats_json` can say how much of
    /// the traffic a cache (and which keying) would have served. Counts only;
    /// it never serves a value.
    read_stats: Arc<ReadStats>,
    /// Per-tx receipt scan cursors (`eth_getTransactionReceipt` /
    /// `locateMinedTx`). Outer std Mutex guards only the map (held briefly);
    /// each entry's tokio Mutex serializes the (network-slow) scan per tx hash,
    /// so concurrent polls for the SAME tx don't duplicate fetches while
    /// different txs proceed in parallel.
    tx_scans: std::sync::Mutex<TxScanMap>,
    /// Recently-VERIFIED block hash → number, so `eth_getBlockByHash` (which
    /// wallets call right after a receipt to finalize a tx) resolves to the
    /// verified by-number path (the Java `blockHashToNumber` twin). Populated
    /// ONLY by blocks this reader itself verified (the receipt/tx scan and the
    /// by-number serve); the shared LRU is the myotis-evm cache one.
    block_hash_numbers: std::sync::Mutex<myotis_evm::Lru<[u8; 32], u64>>,
    /// Block hashes a [`Self::resolve_block_hash`] window did not hold, each
    /// with the HASH of the optimistic head that window was anchored at — the
    /// head itself, not its number, which a head replaced at the same height
    /// keeps: the same head gives the same answer, so a retry is not another
    /// fetch.
    unplaced_hashes: std::sync::Mutex<myotis_evm::Lru<[u8; 32], [u8; 32]>>,
    /// The sent-tx watch + pending-nonce overlay + raw-bytes cache (the Java
    /// `sentTxWatch`/`pendingNonces`/`sentTxCache` trio). One brief-hold lock:
    /// every access is a map poke; the rebroadcast collects its work under the
    /// lock and BROADCASTS outside it.
    sent_txs: std::sync::Mutex<SentTxState>,
    /// The sent-tx WATCH, shared with every peer's read loop (which marks
    /// gossip sightings) — the Java TxGossipObserver seam's equivalent.
    sent_tx_watch: crate::el::sent_tx::SharedSentTxWatch,
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **The cancellation pair.** `request_shutdown` is a tokio `watch::Sender<bool>`: every registered operation subscribes to it. `requests` holds `Weak<Operation>`s, so the registry never keeps a finished request alive. Only `stop()` upgrades them, to wait for the live ones.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `tx_scans: std::sync::Mutex<TxScanMap>` **nests the two mutex kinds**. The outer `std` lock guards only the map and is held for a few statements. Each entry is an `Arc<tokio::sync::Mutex<TxScanState>>` that serialises the slow network scan for *one* transaction hash, so different transactions proceed in parallel.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `#[cfg_attr(not(feature = "tor"), allow(dead_code))]` applies an attribute only when a condition holds, here to silence a warning in non-Tor builds. Its comment is still stale: `eth_cfg` is read outside Tor code too (the restart-claim chain tag, ENS naming, a log line).

`rust/myotis-net/src/el/reader.rs` · lines 2123–2132

```rust
/// Serializes CHECKPOINT WRITES to `log_index_path` against each other,
/// spanning serialize→rename. `log_index` used to do this by accident:
/// every writer held it across the whole write. Now that the fsync happens
/// outside it, something has to keep two checkpoints from interleaving —
/// otherwise the bytes that land last are not necessarily the newest, and
/// an older snapshot silently renames over a newer one.
///
/// LOCK ORDER: acquired BEFORE `log_index`, never after. Every site that
/// writes the canonical `.db` takes it at the top of the function.
log_index_write: std::sync::Mutex<()>,
```

*[Interior mutability](01-primer.md#primer-interior-mutability)* `log_index_write: std::sync::Mutex<()>` guards *no data*. Its guard means “a checkpoint write is in progress”. The documented lock order (before `log_index`, never after) prevents deadlocks: two threads that take the same two locks in the same order can never each hold the one the other waits for. Java has no direct equivalent of a mutex that protects nothing; the nearest is a dedicated `Object` used only for `synchronized` blocks.

`rust/myotis-net/src/el/reader.rs` · lines 2205–2228

```rust
/// The head-follow appender task (spawned on enable, aborted on stop).
log_index_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
/// Serializes coverage-advancing ticks. The background appender and an
/// on-demand fill ([`Self::advance_log_index_tail_now`]) both mutate
/// coverage and the tail's `(number, hash)` reorg record; running them
/// concurrently would race that bookkeeping. Async mutex: held across the
/// tick's network awaits.
log_index_drive: tokio::sync::Mutex<()>,
/// The per-head fee memo (`el::feecache`, #510): the last verified fee
/// estimate and feeHistory results plus the rolling per-block tips window.
/// Brief-hold lock; never held across an await.
fee_cache: std::sync::Mutex<crate::el::feecache::FeeCache>,
/// Single-flight for the fee estimate compute: concurrent misses (and the
/// follower) run ONE peer ladder per head. Held across the network build;
/// in an `Arc` so a read can hand its compute an owned guard.
fee_estimate_compute: Arc<tokio::sync::Mutex<()>>,
/// Serializes the per-block fills (bodies, receipts) of all fee computes,
/// each re-reading the memo under it: concurrent computes — the follower
/// and a read's, or two `eth_feeHistory` shapes — never fetch the same
/// block twice (PR #535 review).
fee_fill: tokio::sync::Mutex<()>,
/// The fee follower (see [`Self::ensure_fee_follower`]): refreshes the fee
/// reads a wallet is polling on every new head, off the request path.
fee_follow_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
```

- *[async/await & tokio](01-primer.md#primer-async) · [Interior mutability](01-primer.md#primer-interior-mutability)* `log_index_drive` is an *async* mutex held across network awaits, so two coverage-advancing ticks (the background appender and an on-demand fill from a host thread) never interleave. A `std` guard held across an `.await` would block a runtime worker thread, and tokio would not be able to run other tasks on it meanwhile.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [async/await & tokio](01-primer.md#primer-async)* `fee_estimate_compute` is an `Arc<tokio::sync::Mutex<()>>` because a read hands its *owned* guard (`OwnedMutexGuard`) to a spawned compute. An owned guard keeps its own `Arc` to the mutex, so it has no lifetime tied to `&self` and can move into a `'static` task.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* Each background task sits in a `std::sync::Mutex<Option<JoinHandle<()>>>` slot: `Some` while it may run, `take()`n by the stop path to abort it.

#### Construction

`rust/myotis-net/src/el/reader.rs` · lines 2316–2325

```rust
pub async fn start_carried(
    anchor: Arc<ExecAnchor>,
    cache_path: Option<std::path::PathBuf>,
    base: ElConfig,
    read_stats: Arc<ReadStats>,
    carry: ElCarry,
) -> Result<ElReader, String> {
    let cfg = ElConfig { cache_path, ..base };
    ElReader::start_inner(carry.key, anchor, cfg, read_stats, carry.pool).await
}
```

*[Ownership & moves](01-primer.md#primer-ownership)* `ElConfig { cache_path, ..base }` is struct-update syntax: take `cache_path` from the local, and every other field from `base`. It *moves* those fields out of `base`, so `base` cannot be used afterwards (Kotlin's `copy(cacheField = …)` copies instead). `carry.key` and `carry.pool` are moved out of `carry` the same way. `ElCarry` (line 11451) is what a pause leaves for the resume: the clearnet node key and the pool's dial verdicts, so neighbours do not have to bond with a new node id after every wake.

`rust/myotis-net/src/el/reader.rs` · lines 2391–2431

```rust
let local_pubkey = key.public_key_bytes();
let sent_tx_watch: crate::el::sent_tx::SharedSentTxWatch = Arc::new(
    std::sync::Mutex::new(crate::el::sent_tx::SentTxTracker::new()),
);
let pool = PeerPool::start(
    key,
    local_pubkey,
    Arc::clone(&eth_cfg),
    cfg.pool_config,
    cache,
    cfg.boot_enodes.clone(),
    rx,
    Some(Arc::clone(&sent_tx_watch)),
    Some(discovery.probe_sender()),
    // Header-backfill head source: the beacon-anchored optimistic head —
    // number AND hash, because every backfill batch must hash-chain to it.
    Some(Box::new({
        let anchor = Arc::clone(&anchor);
        // One lock: a number from one update paired with the hash of
        // the next would fail a peer's correct header (and the head
        // probe would count that against the peer).
        move || anchor.optimistic_head()
    })),
    Arc::clone(&cfg.traffic),
    pool_memory,
);
// Gloas: the light client proves only execution block hashes; the pool
// fetches their headers for the anchor to verify and adopt.
pool.start_anchor_resolver(Arc::clone(&anchor));
// #539: while below target the pool re-offers discovery's whole table.
pool.attach_discovery(discovery.table_handle(), below_target);
// #539, part 3: the network's EIP-1459 DNS trees, a dial source and a
// DHT seed independent of the bootnodes — on hosts that allow DNS
// (`dnsdisco::set_enabled`) and never under Tor; the walk's leaves go
// through the same fork-id filter as discovery's candidates.
if let Some(seeder) = crate::el::dnsdisco::DnsSeeder::new(&cfg.enr_tree_urls, fork_filter_for(&cfg)) {
    pool.attach_dns_seeder(Arc::new(seeder));
}
Ok(ElReader {
    request_shutdown: tokio::sync::watch::channel(false).0,
    requests: std::sync::Mutex::new(Vec::new()),
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* Earlier in `start_inner`, `mpsc::channel(256)` is created: discv4 gets the sender, and the pool gets the receiver (`rx` here), a stream of candidates to dial.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `Some(Box::new({ let anchor = Arc::clone(&anchor); move || anchor.optimistic_head() }))`: a block expression clones the `Arc` *first*, and the `move` closure then owns that clone. The original `anchor` is still available below (`start_anchor_resolver`, the struct literal). The boxed closure becomes the pool's head source.
- *[async/await & tokio](01-primer.md#primer-async)* `request_shutdown: tokio::sync::watch::channel(false).0` keeps the sender and drops the first receiver at once. That is fine: receivers are created later with `subscribe()`, and `cancel_requests` uses `send_replace`, which stores the value even when no receiver exists (plain `send` would return an error then).

#### Request budgets and stop

`rust/myotis-net/src/el/reader.rs` · lines 2276–2288

```rust
impl ElReader {
    /// Budget a host operation, including its network and blocking EVM work.
    pub async fn request<T>(&self, future: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
        self.request_with_budget(super::request::REQUEST_BUDGET, future).await
    }

    async fn request_with_budget<T>(&self, budget: std::time::Duration,
        future: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
        super::request::run_registered(&self.requests, self.request_shutdown.subscribe(), budget, future).await
    }

    /// Signal active readers before waiting for any other shutdown work.
    pub fn cancel_requests(&self) { self.request_shutdown.send_replace(true); }
```

*[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* Every host-facing read runs inside `request()`: a 90 s `Operation` (`request::REQUEST_BUDGET`) registered weakly in `requests` (see [request.rs](12-el-pool.md#f-myotis-net-src-el-request-rs)). The future is passed *by value* as `impl Future`: the operation owns it, and dropping it at the deadline cancels it. `request_with_budget` is the same with another budget; the fee follower, the detached pre-broadcast read and ENS use it.

`rust/myotis-net/src/el/reader.rs` · lines 10197–10223

```rust

/// Stop discovery + the pool.
pub async fn stop(&self) {
    self.cancel_requests();
    // Stop producers before collecting/draining registered work.
    self.stop_log_index_appender().await;
    self.stop_fee_follower().await;
    self.stop_activity_follower().await;
    // Log the window so far: a pause or stop would otherwise lose it
    // (#532 review). A read the stop cancelled is not in it.
    log_fee_summary(self.with_fee_cache(|c| c.stats.flush(Instant::now())).ok().flatten());
    let requests: Vec<_> = self.requests.lock().map(|requests| requests.iter().filter_map(std::sync::Weak::upgrade).collect()).unwrap_or_default();
    for request in requests { request.settled().await; }
    if let Ok(mut t) = self.log_index_task.lock() {
        if let Some(h) = t.take() {
            h.abort();
        }
    }
    // Best-effort index checkpoint before teardown: a failed write only
    // costs a re-index of the uncheckpointed tail, never correctness.
    // OFF-BUDGET (`respect_throttle = false`) — it is the last write
    // before the index goes away, and on Android a graceful teardown is
    // what banks a session whose interval had not elapsed.
    self.persist_log_index(self.finalized_block_number(), false);
    self.pool.stop().await;
    self.discovery.stop().await;
}
```

- *[async/await & tokio](01-primer.md#primer-async)* **The order matters.** First the shutdown flag, so every registered operation and every follower sees it. Then the three producers are aborted *and awaited*, so none of them starts new work while the requests drain. Then each live request is upgraded from its `Weak` (`filter_map(std::sync::Weak::upgrade)`) and awaited to `settled()`. Then the appender slot is aborted once more, without awaiting, in case something started it again during the drain. Then the final, unthrottled checkpoint, and only then the pool and discovery.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `self.requests.lock().map(…).unwrap_or_default()` treats a poisoned lock as an empty list instead of panicking. The workspace builds with `panic = "abort"`, so a panic would kill the host app.

#### Background tasks: the appender and the followers

`rust/myotis-net/src/el/reader.rs` · lines 3322–3380

```rust
/// Spawn (or keep) the head-follow appender for this reader. Idempotent:
/// a live task is left alone. `rt` makes the runtime-context invariant
/// unforgeable (a bare tokio::spawn outside a runtime would abort the
/// whole host process under panic="abort").
pub fn ensure_log_index_appender(self: &Arc<Self>, rt: &tokio::runtime::Handle) {
    let Ok(mut slot) = self.log_index_task.lock() else {
        return;
    };
    if slot.as_ref().is_some_and(|h| !h.is_finished()) {
        return;
    }
    // The task holds only a WEAK reference: a strong Arc here would keep
    // the reader's strong count above 1 forever, making the host's
    // Arc::try_unwrap → ElReader::stop teardown unreachable (leaked
    // networking on stop/pause). Each tick upgrades for its duration and
    // the task exits on its own once the reader is gone; the abort in
    // stop() is the fast path.
    let weak = Arc::downgrade(self);
    *slot = Some(rt.spawn(async move {
        // Coverage grows on three paths, in this order of preference:
        // the per-block appender (finalized, contiguous, cheap), the head
        // BRIDGE when a gap outgrows the appender's window, and the
        // optimistic TAIL above finality — which is where `latest` points
        // and so what head-reaching queries actually need. Only the tail
        // can reorg, and it carries the rewind machinery for that.
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(6));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut since_persist = 0u32;
        let mut append_stall = AppendStall::default();
        let mut ticks = 0u64;
        let mut backfill_ok = 0u64;
        let mut backfill_yielded = 0u32;
        let mut name_attempts: std::collections::HashMap<[u8; 20], (u8, u64)> =
            std::collections::HashMap::new();
        loop {
            tick.tick().await;
            let Some(reader) = weak.upgrade() else {
                return; // reader torn down; the appender dies with it
            };
            {
                // Serialize only the coverage-advancing tick against
                // on-demand fills (advance_log_index_tail_now): both mutate
                // coverage + the tail reorg record. The backfill step works
                // the low-side cursor only (never the tail record), so it
                // runs OUTSIDE the lock — holding it there would make an
                // on-demand caller (a synchronous FFI thread) wait behind the
                // backfill budget for nothing.
                let _drive = reader.log_index_drive.lock().await;
                reader
                    .log_index_append_tick(&mut since_persist, Some(&mut append_stall), ticks)
                    .await;
            }
            reader
                .log_index_backfill_step(ticks, &mut backfill_ok, &mut backfill_yielded)
                .await;
            reader.log_index_name_tick(&mut name_attempts, ticks).await;
            ticks = ticks.wrapping_add(1);
        }
    }));
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership)* **`self: &Arc<Self>`** is an explicit receiver type. The method needs the `Arc` itself to call `Arc::downgrade(self)`; a plain `&self` is a reference to the `ElReader` inside the allocation and cannot produce a `Weak`. Callers must hold an `Arc<ElReader>` to call it.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [async/await & tokio](01-primer.md#primer-async)* **A `Weak` in a spawned task.** A strong `Arc` captured by the task would keep the reader, and all its networking, alive for as long as the loop runs. `weak.upgrade()` yields a strong `Arc` for one tick, or `None` once every strong reference is gone, which ends the loop. The comment still justifies this with an `Arc::try_unwrap` teardown that no host uses any more (`host.rs` calls `reader.stop().await`). The `Weak` is still right: it means a host that drops the reader without calling `stop()` does not leak a running appender.
- *[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* `rt.spawn` on an explicit runtime `Handle`, because this synchronous method may be called from an FFI thread, where a bare `tokio::spawn` would panic (no runtime), and a panic means an abort.
- *[async/await & tokio](01-primer.md#primer-async) · [Interior mutability](01-primer.md#primer-interior-mutability)* `let _drive = reader.log_index_drive.lock().await;` inside a block: the async guard is held across the append tick's awaits and released at the block's `}`, so the backfill step and the naming pass run *outside* it. `_drive` is a real binding; the pattern `_` alone would drop the guard at once.

`rust/myotis-net/src/el/reader.rs` · lines 3662–3677

```rust
pub async fn advance_log_index_tail_now(&self, target: u64) {
    let fill = async {
        let _drive = self.log_index_drive.lock().await;
        // Re-check under the lock: the background tick — or another caller's
        // fill that just finished — may already cover the target. Skipping
        // saves a full header-window fetch per queued caller.
        if self.log_index_covered_high().is_some_and(|top| top >= target) {
            return;
        }
        let mut since_persist = 0u32;
        self.log_index_append_tick(&mut since_persist, None, 0).await;
    };
    // Cancellation at an await point is safe: coverage and the tail record
    // mutate only synchronously under the index lock (append_block).
    let _ = tokio::time::timeout(LOG_INDEX_FILL_DEADLINE, fill).await;
}
```

*[async/await & tokio](01-primer.md#primer-async)* The on-demand fill takes the same `log_index_drive` lock, re-checks coverage under it (another caller may just have filled it), and runs one append tick. `tokio::time::timeout(…, fill)` drops `fill` after 5 s. Dropping a future at an `.await` is safe here because, as the comment says, coverage only changes synchronously under the index lock, never half-way through an await.

The fee follower (`ensure_fee_follower`, line 8340) and the activity follower (`ensure_activity_follower`, line 8513) use the same shape: a task slot, an idempotence check with `is_finished()`, a `Weak` that is upgraded per tick, and a `tokio::time::interval` with `MissedTickBehavior::Delay`. Two differences: they use `Handle::try_current()` and quietly do nothing outside a runtime, and they check `request_shutdown` first, so a read racing `stop()` cannot restart them. Both end themselves when their demand goes away (no fee reads being polled, an empty watch list), and the next read or push respawns them.

`rust/myotis-net/src/el/reader.rs` · lines 8555–8578

```rust
async fn activity_follow_tick(self: &Arc<Self>) -> bool {
    use crate::el::activity::{BlockRecord, WINDOW};
    let Ok(top) = self.activity.lock().map(|s| {
        if !s.is_active() {
            // Following ends: the pool stops keeping and hunting for a BAL
            // server — under the lock, so a push refilling the list wins.
            self.pool.set_bal_demand(false);
        }
        s.is_active().then(|| s.top())
    }) else {
        return false;
    };
    let Some(top) = top else {
        return false;
    };
    if *self.request_shutdown.borrow() {
        return false;
    }
    let Ok(head) = self.anchored_head() else {
        return true;
    };
    if top == Some(head) {
        return true;
    }
```

`rust/myotis-net/src/el/reader.rs` · lines 8778–8790

```rust
/// Abort and await the activity follower (teardown; see [`Self::stop`]).
async fn stop_activity_follower(&self) {
    for slot in [&self.activity_task, &self.activity_bal_task] {
        let handle = match slot.lock() {
            Ok(mut t) => t.take(),
            Err(_) => None,
        };
        if let Some(h) = handle {
            h.abort();
            let _ = h.await;
        }
    }
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `self.activity.lock().map(|s| { … })`: `lock()` returns `Result<MutexGuard, PoisonError>`, and `map` moves the guard `s` into the closure. The guard is dropped when the closure returns, so the lock is held only for that expression, and `set_bal_demand(false)` runs under it on purpose (a push refilling the list must win).
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `s.is_active().then(|| s.top())` turns a `bool` into an `Option`; together with `let Ok(top) = … else` and `let Some(top) = top else` the tick separates “lock poisoned”, “list empty” and “nothing kept yet” (`top` is itself an `Option`).
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* `for slot in [&self.activity_task, &self.activity_bal_task]` iterates an array of two references. The follower is stopped first, so it cannot spawn a new BAL pass after the BAL slot is emptied.

#### Hedged reads

![Hedged read timeline over seconds. Peer A starts at 0 seconds and is slow. At 3 seconds, the hedge delay, peer B is started alongside A. B fails at 3.5 seconds, which immediately starts peer C. A answers with a verdict at 4 seconds and is accepted; C, still in flight, is dropped and cancelled without being counted as good, bad or outpaced. B gets a strike, A is recorded as served.](img/14-el-reader-1.svg)

*At most 3 attempts are in flight at once, both to limit load and because every attempt discloses `keccak(address)` to one more peer. A slow peer is never abandoned: hedging starts another *alongside* it, so a slow but working answer still wins. This is an illustrative run, traced through the loop below. C is not reported as *outpaced*: its request went out after A's, so its slowness proves nothing. A loser counts as outpaced only if its request went out no later than the winner's and has been with its peer for at least the hedge delay.*

`rust/myotis-net/src/el/reader.rs` · lines 1615–1658

```rust
pub(crate) async fn hedged_race<T, P: Clone, Fut>(
    peers: &[P],
    delay: std::time::Duration,
    mut make: impl FnMut(P) -> Fut,
    accept: impl Fn(&T) -> bool,
) -> RaceOutcome<T>
where
    Fut: std::future::Future<Output = Result<T, String>>,
{
    use futures::stream::{FuturesUnordered, StreamExt};

    let total = peers.len();
    let mut in_flight = FuturesUnordered::new();
    let mut next = 0usize;
    // When each attempt started, when its request actually went out, and
    // whether it has finished — what decides which in-flight losers the winner
    // OUTPACED.
    let mut started: Vec<Option<tokio::time::Instant>> = vec![None; total];
    let mut sent: Vec<Option<std::sync::Arc<std::sync::OnceLock<tokio::time::Instant>>>> = vec![None; total];
    let mut done = vec![false; total];
    let mut out = RaceOutcome {
        accepted: None,
        fallback: None,
        missed: Vec::new(),
        outpaced: Vec::new(),
        errors: Vec::new(),
    };
    // ONE push site: two `async move` blocks are distinct anonymous types and
    // could not share a FuturesUnordered without boxing every attempt. Pushed
    // whenever there is capacity: every select arm below that continues the
    // loop — failed attempt, non-verdict answer, hedge timer — is a
    // "start another" trigger, so no flag needs to gate this.
    loop {
        if next < total && in_flight.len() < MAX_HEDGED_ATTEMPTS {
            let idx = next;
            let (marker, fut) = crate::el::peer::scope_send_marker(make(peers[idx].clone()));
            started[idx] = Some(tokio::time::Instant::now());
            sent[idx] = Some(marker);
            in_flight.push(async move { (idx, fut.await) });
            next += 1;
        }
        if in_flight.is_empty() {
            break;
        }
```

`rust/myotis-net/src/el/reader.rs` · lines 1659–1703

```rust
        let hedge = tokio::time::sleep(delay);
        tokio::select! {
            Some((idx, res)) = in_flight.next() => { done[idx] = true; match res {
                Ok(value) => {
                    if accept(&value) {
                        // OUTPACED = the loser's request went out no later than
                        // the winner's AND has been with its peer for at least
                        // the delay. Timed from the actual send: a request still
                        // queued for its connection's writer never reached the
                        // peer, so it proves nothing. A request sent after the
                        // winner's had less time than the winner needed, which
                        // on a uniformly slow link proves nothing either, and
                        // one sent just before it has not had the delay yet.
                        let now = tokio::time::Instant::now();
                        let sent_at = |i: usize| sent[i].as_ref().and_then(|m| m.get().copied());
                        // The winner's own send, or its start if it recorded
                        // none (an answer that needed no request).
                        let winner_ref = sent_at(idx).or(started[idx]).unwrap_or(now);
                        out.outpaced = (0..next)
                            .filter(|&i| i != idx && !done[i])
                            .filter(|&i| {
                                sent_at(i).is_some_and(|s| s <= winner_ref && now.duration_since(s) >= delay)
                            })
                            .collect();
                        out.accepted = Some((idx, value));
                        return out;
                    }
                    // Answered, but without a verdict (stale head / bad proof):
                    // a different peer can still verify.
                    out.missed.push(idx);
                    out.fallback.get_or_insert(value);
                }
                Err(e) => {
                    out.missed.push(idx);
                    out.errors.push((idx, e));
                }
            }},
            // Nobody answered in time and a candidate remains: wake the loop,
            // which starts it ALONGSIDE the ones running, never instead of them.
            _ = hedge, if next < total && in_flight.len() < MAX_HEDGED_ATTEMPTS => {}
            else => break,
        }
    }
    out
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [async/await & tokio](01-primer.md#primer-async)* A generic async higher-order function: `make: impl FnMut(P) -> Fut` with `where Fut: Future<Output = Result<T, String>>`. Every `async move` block has its own anonymous type, so there is exactly *one* push site into the `FuturesUnordered`. Two different blocks could not share the collection without boxing.
- *[async/await & tokio](01-primer.md#primer-async)* `make(…)` only *creates* a future; nothing runs until it is polled. `scope_send_marker` wraps it in a tokio task-local scope that records when the request frame actually left (a `OnceLock<Instant>` shared through an `Arc`); that timestamp decides who was outpaced. The wrapper `async move { (idx, fut.await) }` owns the future and tags the result with the peer index.
- *[async/await & tokio](01-primer.md#primer-async)* `select!` races the next completed attempt against a fresh `sleep(delay)`, created anew on every loop pass, so the hedge timer restarts whenever an attempt finishes. The `if` guard disables the timer arm when no more peers may be started, and `else => break` handles “all branches disabled”.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* **Cancellation by drop.** `return out;` drops `in_flight`, and with it every attempt still running. There are no `cancel()` calls; in Java you would call `future.cancel(true)` on each. The doc comment above warns that a dropped attempt can leave that peer's writer torn (it condemns the connection), a price paid only once the answer is in hand. For the same reason the losers are not polled again after the winner arrives.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `out.fallback.get_or_insert(value)` keeps the *first* non-accepted answer as a fallback.

`rust/myotis-net/src/el/reader.rs` · lines 5901–5956

```rust
async fn get_account_proven(
    &self,
    anchor: ReadAnchor,
    address: [u8; 20],
) -> Result<VerifiedAccount, String> {
    // Tor mode (docs/privacy-and-tor.md): route this read — the §1 "core
    // leak" flow — over a per-address isolated Tor circuit instead of the
    // pool's clearnet connections. Fail-closed if no aged peer is available.
    #[cfg(feature = "tor")]
    if crate::el::tor::is_enabled() {
        if anchor == ReadAnchor::Finalized {
            tracing::info!("tor: account read refused — finalized reads are not routed over Tor");
            return Err("finalized state reads are not routed over Tor (head only)".to_string());
        }
        return self.get_account_over_tor(address).await;
    }
    let fin = self.finalized_anchor_for(anchor, "a finalized account read")?;
    let peers = self.pool.snap_peers().await;
    if peers.is_empty() {
        return Err("no snap peer available".to_string());
    }
    // Hedged across peers: a silent peer no longer blocks the read for the
    // full request timeout, and a slow-but-working one still wins if it
    // answers before its hedge does. Accepted = a verdict, or a GLOBAL
    // failure (beacon not ready — identical for every peer); a per-peer
    // verdict failure (stale head / bad proof) becomes the fallback. Only
    // a verdict is a SERVE — the winner's credit and the misses' witness.
    let (result, snap_elapsed) = self
        .hedged_read(
            &peers,
            HEDGE_DELAY,
            |peer| async move { self.get_account_from(&peer, address, fin).await },
            |(r, _): &(VerifiedAccount, Duration)| {
                r.verify_method.is_some() || is_global_fail(r.fail_reason)
            },
            |(r, _): &(VerifiedAccount, Duration)| r.verify_method.is_some(),
            |e: &str| fin.is_some() && crate::el::snap::fetch::is_unknown_root_error(e),
            "a verifiable account",
        )
        .await?;
    // Shadow-cache bookkeeping for the VERIFIED answer only (an unverified
    // fallback is not a fact a cache could ever have served), costed at the
    // winning peer's snap round-trip — not the anchoring ladder after it.
    // Head reads only: the cache measures the head-state traffic, and a
    // finalized root interleaved with head roots would read as churn.
    if result.verify_method.is_some() && fin.is_none() {
        self.read_stats.observe_account(
            address,
            result.peer_state_root,
            account_fact(&result),
            snap_elapsed,
        );
    }
    Ok(result)
}

```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `#[cfg(feature = "tor")]` on an `if` statement: in Tor builds with Tor switched on, the read goes over an isolated Tor circuit instead (`get_account_over_tor`, line 6366), with no hedging. It fails closed: no ready Tor peer means an error, never a clearnet fallback. Finalized reads are refused under Tor.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [async/await & tokio](01-primer.md#primer-async)* `|peer| async move { self.get_account_from(&peer, address, fin).await }`: the future *borrows* `self`. That is fine because the race is awaited inside this method and never spawned, so no `'static` bound applies. `address` (`[u8; 20]`) and `fin` (`Option<FinalizedExecution>`, which derives `Copy`) are copied into each future. That is also why the closure can be `FnMut`: it gives nothing away when it is called.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* Four closures, four roles: `accept` ends the race (a verdict, or a *global* failure such as “beacon not synced” that no other peer could fix); `served` says whether that answer earns credit; `excused` forgives a finalized read's empty proof (the peer is not obliged to keep an old root); the last is the label for error messages.
- *[Protocol & domain](01-primer.md#primer-domain)* Only a verified head read feeds the shadow cache (`read_stats.observe_account`). `get_account_following`, which calls this, first tries the activity follower and, after a verified head proof, seeds it (`seed_followed`): a watched account can then be answered from verified block access lists with `verifyMethod` `blockAccessList` and no peer request.

*[Protocol & domain](01-primer.md#primer-domain)* `hedged_read` (line 5988) applies the outcome to the pool: misses that were not excused are banked as failures (witnessed only if another peer served), outpaced peers are reported with `record_snap_outpaced`, and the winner gets `record_snap_served` only if its answer was a serve. Block and receipt reads use `settle_pool_race` instead, whose tip-lag arm hands strikes back to the caller unbanked, so a retry that succeeds strikes nobody.

#### EVM reads

`rust/myotis-net/src/el/reader.rs` · lines 7083–7107

```rust
async fn eth_call_overridden_inner(
    &self,
    anchor: ReadAnchor,
    from: Option<[u8; 20]>,
    to: [u8; 20],
    data: Vec<u8>,
    value: U256,
    chain_id: u64,
    overrides: myotis_evm::overrides::StateOverrides,
) -> Result<CallAnswer, String> {
    let (ctx, executor) = self.evm_setup_at(anchor, chain_id, "eth_call").await?;
    let block_number = ctx.block_number;
    let state_root = ctx.state_root;
    // Run the SYNCHRONOUS executor off the runtime worker so the oracle's
    // per-fetch `block_on` is a fresh (non-nested) runtime entry.
    let joined = super::request::blocking(move || {
        // A from-less call still honours `value` — the default sender is the zero
        // ADDRESS, not zero value — so always thread `value` through
        // call_view_from (call_view would force value = 0 and drop it).
        let sender = from.unwrap_or([0u8; 20]);
        executor.call_view_overridden(sender, to, &data, value, &ctx, overrides)
    })
    .await?;
    Ok(self.call_answer(anchor, block_number, &state_root, joined))
}
```

`rust/myotis-net/src/el/reader.rs` · lines 7635–7649

```rust
async fn evm_executor_for(
    &self,
    ctx: myotis_evm::BlockContext,
    what: &str,
    finalized: bool,
) -> Result<(myotis_evm::BlockContext, EvmExecutor), String> {
    let oracle = self.snap_oracle(what, finalized).await?;
    // Bind the concrete Arc types first, then let the unsizing coercion to the
    // trait objects happen at the constructor call (a coercion directly on
    // `Arc::clone` would instead infer `Arc<dyn Trait>` and fail to type-check).
    let proof_cache = Arc::clone(&self.evm_proof_cache);
    let bytecode_cache = Arc::clone(&self.evm_bytecode_cache);
    let executor = EvmExecutor::new(oracle, proof_cache, bytecode_cache);
    Ok((ctx, executor))
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* The sync-to-async bridge from the reader's side. `snap_oracle` runs in async code, so `Handle::current()` works, and it stores the handle in the oracle. Then `request::blocking(move || …)` moves the executor, calldata, context and overrides onto a blocking thread, where the oracle's `block_on` is legal. `blocking` limits native work to 8 slots with a bounded FIFO wait, and the closure must be `Send + 'static`, which the `move` provides.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* The `?` after `.await` covers only `blocking`'s own failures: no free slot, a cancelled or expired request, a join error. `joined` is the EVM's `Result`, which `call_answer` maps into a `CallOutcome` and labels with the block hash only if the call actually ran.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Unsizing coercion.** `Arc<InMemoryStateProofCache>` becomes `Arc<dyn StateProofCache>` at the constructor call. Binding the concrete clones to variables first matters: `Arc::clone(&x)` written directly in a `dyn`-typed position would be inferred as `Arc::<dyn …>::clone` and fail to type-check.
- *[Protocol & domain](01-primer.md#primer-domain)* `evm_setup_at` picks the head or the finalized header. The finalized header comes over a window anchored at the finalized block itself and is then cross-checked against the anchor's own hash and state root (`finalized_header`, line 7581).

#### The header trust gate

`rust/myotis-net/src/el/reader.rs` · lines 10353–10365

```rust
fn choose_window_top(
    target: u64,
    head: (u64, [u8; 32]),
    fin: Option<(u64, [u8; 32])>,
) -> Option<WindowTop> {
    match fin {
        Some((number, hash)) if target <= number && target != head.0 => {
            Some(WindowTop::Finalized { number, hash })
        }
        _ if target > head.0 => None,
        _ => Some(WindowTop::Head { number: head.0, hash: head.1 }),
    }
}
```

`rust/myotis-net/src/el/reader.rs` · lines 10375–10419

```rust
async fn fetch_anchored_window(
    peer: &ManagedPeer,
    from: u64,
    top: WindowTop,
) -> Result<Vec<crate::el::eth::messages::VerifiedHeader>, String> {
    let Some(count) = top.number().checked_sub(from).map(|span| span + 1) else {
        return Err(format!("window start {from} is above its anchor {}", top.number()));
    };
    let window = peer.get_block_headers_by_number(from, count, 0, false).await?;
    // Distinct messages on purpose: a SHORT window is tip-lag-shaped (the peer
    // may simply not have imported up to our anchor yet — all_tip_lag matches
    // "headers, expected"), while returning MORE than asked is a protocol
    // violation that must never read as retryable.
    if (window.len() as u64) < count {
        return Err(format!("peer returned {} headers, expected {count}", window.len()));
    }
    if window.len() as u64 != count {
        return Err(format!(
            "peer over-served the header request: {} returned for {count} asked",
            window.len()
        ));
    }
    if window[0].header.number != from {
        return Err("peer returned the wrong starting block number".to_string());
    }
    // The window's top must BE the beacon-anchored block, and each header must
    // hash-link to the next — proving every header in it chains to the verified
    // anchor (the trust gate: the hash is light-client-attested).
    if &window[window.len() - 1].hash != top.hash() {
        return Err("window head does not match the beacon-anchored head hash".to_string());
    }
    for i in 0..window.len() - 1 {
        if window[i + 1].header.parent_hash != window[i].hash {
            return Err("header window is not hash-linked".to_string());
        }
    }
    // Proof of the peer's head, only when the window reached the tip: it
    // served a verified window up to our optimistic head (peer::KnownHead),
    // what the read ladder ranks it by from here on. A finalized-anchored
    // window proves it holds an older block, which says nothing about the tip.
    if top.is_head() {
        peer.note_head_served(top.number());
    }
    Ok(window)
}
```

- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* “The sole gate that turns peer-supplied headers into trusted ones”, with seven callers. The window must have the exact length, start at the requested number, end at the anchored hash, and be parent-linked throughout. New since September: the anchor is a `WindowTop`, either the optimistic head or the *finalized* block. A read at or below finality anchors at the finalized block, which every roughly synced peer holds, so it no longer depends on the head.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The error messages differ on purpose. A *short* window looks like tip lag (the peer has not imported that far yet, so a retry is reasonable), while an over-served window is a protocol violation. `all_tip_lag` (line 676) string-matches these messages, and the comment there names the coupling.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `top.number().checked_sub(from).map(|span| span + 1)` with `let Some(count) = … else`: subtraction that would underflow becomes `None` instead of wrapping (in release builds) or panicking (in debug builds).
- *[Protocol & domain](01-primer.md#primer-domain)* Only a head-anchored window counts as proof of the peer's head (`note_head_served`), which the read ladder then ranks peers by.

#### Writes: judged, detached, and Tor-only in Tor mode

`rust/myotis-net/src/el/reader.rs` · lines 9098–9113

```rust
pub async fn send_raw_transaction(self: &Arc<Self>, raw_tx: &[u8]) -> Result<[u8; 32], SendError> {
    let summary = match tx::decode_sendable(raw_tx) {
        Ok(summary) => summary,
        Err(reason) => {
            tracing::info!(%reason, "transaction refused: not a transaction this node relays");
            return Err(SendError::Refused(reason));
        }
    };
    if let Err(reason) = tx::check_chain(&summary, self.chain_id) {
        let tx_hash = crate::el::sent_tx::raw_hash_hex(raw_tx);
        tracing::info!(tx = %tx_hash, %reason, "transaction refused: signed for another chain");
        return Err(SendError::Refused(reason));
    }
    let verdict = self.pre_broadcast_check(&summary).await;
    self.send_judged(raw_tx, summary, verdict).await
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* Three refusals before anything goes out. Bytes that are not a sendable transaction, and a transaction signed for another chain, are `SendError::Refused` (hosts answer the permanent `-32602`). A transaction the sender provably cannot pay for, or whose nonce is used, is `Rejected` in geth's own words, so wallets classify it as they would geth's. The method takes `self: &Arc<Self>` because the pre-broadcast check spawns a task that needs its own `Arc`.

`rust/myotis-net/src/el/reader.rs` · lines 9265–9306

```rust
async fn pre_broadcast_check(self: &Arc<Self>, tx: &TxSummary) -> PreBroadcast {
    let Ok(since_epoch) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return PreBroadcast::Unchecked("wall clock unreadable");
    };
    let (tx, from, head) = match self.ready_to_judge(tx, since_epoch.as_secs()) {
        Ok(ready) => ready,
        Err(why) => return PreBroadcast::Unchecked(why),
    };
    // A Tor-routed read answers at a fresh session's own head, never at the
    // anchored root, so it could never judge: spare the send its wait and
    // the circuit (docs/privacy-and-tor.md).
    #[cfg(feature = "tor")]
    if crate::el::tor::is_enabled() {
        return PreBroadcast::Unchecked("Tor reads are not at the anchored root");
    }
    let Ok(permit) = Arc::clone(&self.send_check_permits).try_acquire_owned() else {
        return PreBroadcast::Unchecked("account reads busy");
    };
    let reader = Arc::clone(self);
    let read = tokio::spawn(async move {
        let _permit = permit;
        reader
            // At the head itself (no lag): the verdict needs the head's
            // own state root.
            .request_with_budget(
                send_check::DETACHED_READ_BUDGET,
                reader.get_account_following(ReadAnchor::Head, from, 0, None),
            )
            .await
    });
    let read = match tokio::time::timeout(send_check::ACCOUNT_READ_BUDGET, read).await {
        Err(_) => None, // still running: detached, not cut
        Ok(joined) => Some(joined.unwrap_or_else(|e| Err(format!("account read task failed: {e}")))),
    };
    // The bound must hold at the verdict, not only before the read: a
    // head just inside it when the read began may have crossed it since
    // (PR #537 review).
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return PreBroadcast::Unchecked("wall clock unreadable");
    };
    judge_read(tx, &head, read, now.as_secs(), self.block_time)
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **Detached, not cut.** The account read is `tokio::spawn`ed, so it must be `'static`: it gets its own `Arc` (`let reader = Arc::clone(self)`) and an owned semaphore permit (`try_acquire_owned` on an `Arc<Semaphore>`). `timeout(ACCOUNT_READ_BUDGET, read)` wraps the `JoinHandle`. When it expires, the handle is dropped, and **dropping a `JoinHandle` does not cancel the task**; it only detaches it. Contrast `hedged_race`, where dropping the *futures* cancels them. The comment says why it matters: a read dropped mid-request can tear the connection the broadcast is about to use.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* `let _permit = permit;` moves the permit into the task, so it is released when the task ends, whenever that is. At most `send_check::DETACHED_READS_MAX` such reads run; past that, the send goes out unchecked. The detached read is still registered via `request_with_budget`, so `stop()` cancels and drains it.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `joined.unwrap_or_else(|e| Err(…))` flattens the `JoinError` (the task was aborted) into the read's own `Result`. Every reason not to judge becomes `PreBroadcast::Unchecked`, and the send goes out as before: the check only ever adds refusals on proven state.

`rust/myotis-net/src/el/reader.rs` · lines 1314–1351

```rust
pub(crate) async fn first_accepted<Fut>(
    attempts: impl IntoIterator<Item = Fut>,
    grace: std::time::Duration,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> bool
where
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let landed = std::sync::Arc::new(tokio::sync::watch::channel(false).0);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for attempt in attempts {
        let tx = tx.clone();
        let landed = std::sync::Arc::clone(&landed);
        let mut others = landed.subscribe();
        let mut shutdown = shutdown.clone();
        tokio::spawn(async move {
            let ok = tokio::select! {
                result = attempt => result.is_ok(),
                _ = async {
                    let _ = others.wait_for(|landed| *landed).await;
                    tokio::time::sleep(grace).await;
                } => false,
                _ = shutdown.wait_for(|stop| *stop) => false,
            };
            if ok {
                landed.send_replace(true);
            }
            let _ = tx.send(ok);
        });
    }
    drop(tx); // the channel closes once every attempt has reported
    while let Some(ok) = rx.recv().await {
        if ok {
            return true;
        }
    }
    false
}
```

`rust/myotis-net/src/el/reader.rs` · lines 9184–9221

```rust
    let sent_via_tor =
        matches!(self.sent_txs.lock().unwrap().bytes.get(&hash), Some(SentTx { via_tor: true, .. }));
    if sent_via_tor {
        tracing::info!(tx = %tx_hash, "tor: transaction already sent over Tor; not pushed from the real IP");
        return Ok(hash);
    }
    let peers = self.pool.snap_peers().await;
    if peers.is_empty() {
        return Err(not_broadcast("no peer available to broadcast the transaction"));
    }
    // Broadcast to every peer, but answer the wallet at the FIRST write that
    // lands (#320): the success criterion is "≥1 peer received it", and
    // waiting for all of them let one wedged connection's writer hold the
    // send step for its whole frame-write timeout. The other writes run on
    // detached, for [`BROADCAST_WRITE_DEADLINE`] more at most, and a pause
    // or stop cuts them (`first_accepted`).
    let raw = std::sync::Arc::<[u8]>::from(raw_tx);
    let accepted = first_accepted(
        peers.iter().cloned().map(|peer| {
            let raw = std::sync::Arc::clone(&raw);
            async move { peer.send_transaction(&raw).await }
        }),
        BROADCAST_WRITE_DEADLINE,
        self.request_shutdown.subscribe(),
    )
    .await;
    if !accepted {
        // A pause or stop cut the writes (`first_accepted`'s shutdown):
        // say so, rather than blame the peers for a send we cut ourselves.
        if *self.request_shutdown.borrow() {
            return Err(not_broadcast("transaction broadcast cut: the node is pausing or stopping"));
        }
        return Err(not_broadcast("no peer accepted the transaction broadcast"));
    }
    tracing::info!(tx = %tx_hash, peers = peers.len(), "transaction broadcast");
    self.record_sent(hash, raw_tx, &summary, false);
    Ok(hash)
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* `first_accepted` spawns every write as its own task (hence `Fut: Send + 'static`) and returns at the first success. The raw transaction is shared as `Arc<[u8]>`, one allocation for all peers, each task holding a clone. Each task's `select!` has three arms: the write, “another write landed, then `grace` elapsed”, and shutdown. So writes are never cut before one has landed, and are cut `grace` after.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* `drop(tx)` after the loop is load-bearing. `rx.recv()` returns `None` only once *every* sender is gone; the tasks hold clones, and this local original would otherwise keep the channel open forever. A `watch` channel (`landed`) broadcasts “one landed” to all tasks; `subscribe()` gives each its own receiver.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Borrowing & slices](01-primer.md#primer-borrowing)* `matches!(self.sent_txs.lock().unwrap().bytes.get(&hash), …)`: the `MutexGuard` is a temporary, dropped at the end of the `let` statement, before the `.await` on the next lines. That matters: a `std` guard alive across an `.await` would make the future non-`Send`.

`rust/myotis-net/src/el/reader.rs` · lines 9357–9422

```rust
async fn maybe_rebroadcast_sent_txs(&self) {
    let now = std::time::Instant::now();
    let (unseen, dropped) = {
        let mut watch = self.sent_tx_watch.lock().unwrap();
        if !watch.watching_any() {
            return;
        }
        let dropped = watch.evict_expired(now);
        (watch.unseen(), dropped)
    };
    crate::el::sent_tx::log_unseen_expiries(&dropped);
    let work: Vec<SentTx> = {
        let mut st = self.sent_txs.lock().unwrap();
        if now.saturating_duration_since(st.last_rebroadcast) < TX_REBROADCAST_INTERVAL {
            return;
        }
        st.last_rebroadcast = now;
        unseen
            .iter()
            // Bytes aged out of the LRU → nothing to push (Java parity).
            .filter_map(|h| st.bytes.get(h).cloned())
            .collect()
    };
    // Each send's route: over Tor while Tor mode is on, in the clear only
    // what first went in the clear (rebroadcast_route).
    let tor_on = tor_routing_on();
    let (mut clear, mut over_tor) = (Vec::new(), Vec::new());
    for sent in work {
        match rebroadcast_route(tor_on, sent.via_tor) {
            RebroadcastRoute::Clearnet => clear.push(sent.raw),
            RebroadcastRoute::Tor => over_tor.push(sent.raw),
            RebroadcastRoute::Skip => {}
        }
    }
    if !clear.is_empty() {
        self.rebroadcast_in_the_clear(clear).await;
    }
    #[cfg(feature = "tor")]
    if !over_tor.is_empty() {
        self.rebroadcast_over_tor(over_tor).await;
    }
    #[cfg(not(feature = "tor"))]
    drop(over_tor);
}

/// The clearnet half of [`Self::maybe_rebroadcast_sent_txs`]: every pool
/// peer, every send. DETACHED, like the Java warmer thread: the wallet's
/// receipt poll carries the trigger but must never wait on the pushes — a
/// wedged peer (writer lock held, full send buffer) would otherwise freeze
/// the confirm loop. Bounded per write; peers are owned Arcs.
async fn rebroadcast_in_the_clear(&self, work: Vec<Vec<u8>>) {
    let peers = self.pool.snap_peers().await;
    if peers.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let count = work.len();
        for raw in work {
            let sends = peers.iter().map(|peer| {
                tokio::time::timeout(BROADCAST_WRITE_DEADLINE, peer.send_transaction(&raw))
            });
            futures::future::join_all(sends).await;
        }
        tracing::debug!("rebroadcast {} sent tx(s) to {} peer(s)", count, peers.len());
    });
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Collect under the lock, act outside it.** Each `let x = { let mut g = m.lock().unwrap(); …; value };` block drops its guard at the `}`. The network sends happen with no lock held.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `#[cfg(not(feature = "tor"))] drop(over_tor);`: without the Tor feature the Tor branch is compiled out, so this explicit `drop` is the only use of `over_tor` and keeps the build free of an unused-variable warning.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* The clearnet rebroadcast is a detached `tokio::spawn` that must be `'static`, so it owns everything: `work: Vec<Vec<u8>>` and `peers: Vec<Arc<ManagedPeer>>` are moved in. The wallet's receipt poll triggers the rebroadcast but never waits for it. Each send is bounded by a 5 s `timeout`.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `.lock().unwrap()` here vs `if let Ok` / `map_err` elsewhere: two lock-poison styles in one file. A lock is poisoned only when a thread panics while holding it *and the program keeps running*. Under `panic = "abort"` that cannot happen, so these `unwrap()`s cannot fire in production.

`rust/myotis-net/src/el/reader.rs` · lines 1555–1573

```rust
#[cfg(feature = "tor")]
struct TorRebroadcastGuard(Arc<std::sync::atomic::AtomicBool>);

#[cfg(feature = "tor")]
impl TorRebroadcastGuard {
    fn claim(busy: &Arc<std::sync::atomic::AtomicBool>) -> Option<TorRebroadcastGuard> {
        use std::sync::atomic::Ordering;
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| TorRebroadcastGuard(Arc::clone(busy)))
    }
}

#[cfg(feature = "tor")]
impl Drop for TorRebroadcastGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}
```

`rust/myotis-net/src/el/reader.rs` · lines 9428–9469

```rust
#[cfg(feature = "tor")]
async fn rebroadcast_over_tor(&self, work: Vec<Vec<u8>>) {
    let (guard, round) = {
        let mut st = self.sent_txs.lock().unwrap();
        let Some(guard) = TorRebroadcastGuard::claim(&st.tor_rebroadcast_busy) else {
            return; // a round is still running; the next sweep retries
        };
        st.tor_rounds = st.tor_rounds.wrapping_add(1);
        (guard, st.tor_rounds)
    };
    // Only the targets go into the task, not the pool's peer handles.
    let eligible = self.pool.tor_candidates(false).await;
    let targets = self
        .pool
        .claim_for_tor(
            tor_candidates(&eligible, round.wrapping_mul(TOR_MAX_CANDIDATES)),
            tokio::time::Instant::now() + TOR_PUSH_DEADLINE + TOR_BROADCAST_GRACE,
        )
        .await;
    if targets.is_empty() {
        return;
    }
    let (eth_cfg, shutdown) = (Arc::clone(&self.eth_cfg), self.request_shutdown.subscribe());
    let outcomes = self.pool.tor_reserve_handle();
    tokio::spawn(async move {
        let _guard = guard;
        for raw in work {
            // Each push can outlast the claim: the round pushes one pending
            // send after another, so keep the targets quarantined to past
            // this one's end.
            crate::el::pool::note_tor_contact_until(
                targets.iter().map(|(_, node)| *node),
                tokio::time::Instant::now() + TOR_PUSH_DEADLINE + TOR_BROADCAST_GRACE,
            );
            let raw = std::sync::Arc::<[u8]>::from(raw);
            match tor_broadcast(targets.clone(), &eth_cfg, &raw, shutdown.clone(), outcomes.clone()).await {
                Ok(sent) => tracing::debug!(confirmed = sent.confirmed, "rebroadcast a sent tx over Tor"),
                Err(e) => tracing::debug!(error = %e, "Tor rebroadcast of a sent tx failed"),
            }
        }
    });
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **A drop guard for a flag.** `TorRebroadcastGuard::claim` uses `compare_exchange(false, true, …)`: it succeeds for exactly one caller while the flag is clear, and returns a guard whose `Drop` clears it. The guard is moved into the spawned task (`let _guard = guard;`), so the flag stays set until that task ends, or is dropped, however it ends. Java would need a `try/finally` around the whole round.
- *[Protocol & domain](01-primer.md#primer-domain)* A Tor rebroadcast round walks on through the pool: `round.wrapping_mul(TOR_MAX_CANDIDATES)` is the offset into the eligible peers, so each round reaches peers the earlier ones did not. Only target *identities* go into the task, not the pool's peer handles; each push is a fresh Tor stream with an ephemeral key. A send that first went over Tor is never pushed from the real IP (`rebroadcast_route`).

`rust/myotis-net/src/el/reader.rs` · lines 10024–10050

```rust
fn tx_scan_state(
    &self,
    tx_hash: [u8; 32],
) -> Result<Arc<tokio::sync::Mutex<TxScanState>>, String> {
    let mut scans = self.tx_scans.lock().map_err(|_| "engine lock poisoned".to_string())?;
    let now = std::time::Instant::now();
    if now.duration_since(scans.last_sweep) >= RECEIPT_SCAN_SWEEP_INTERVAL {
        scans.last_sweep = now;
        // An entry whose tokio lock is HELD is in use — keep it regardless.
        // saturating: a concurrent poll can stamp last_touched AFTER `now`
        // was captured; that reads as zero idle (kept), never a panic. (On
        // Rust >= 1.60 plain duration_since saturates too — this just says
        // so explicitly, matching the workspace's panic-free-by-construction
        // policy under panic="abort".)
        scans.map.retain(|_, st| match st.try_lock() {
            Ok(guard) => now.saturating_duration_since(guard.last_touched) < RECEIPT_SCAN_TTL,
            Err(_) => true,
        });
    }
    Ok(Arc::clone(scans.map.entry(tx_hash).or_insert_with(|| {
        Arc::new(tokio::sync::Mutex::new(TxScanState {
            high_scanned: None,
            found: None,
            last_touched: now,
        }))
    })))
}
```

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* The receipt scan's per-transaction cursor. `st.try_lock()` inside `retain`: an entry whose tokio lock is currently held is in use, so it is kept regardless of age. `Arc::clone(scans.map.entry(tx_hash).or_insert_with(…))` returns a handle to the per-transaction mutex, and the caller (`locate_mined_tx`) locks it *after* this function has returned and the map guard is gone. `map_err(|_| "engine lock poisoned")?` turns poison into an error rather than a panic.

#### The fee memo: single flight, bounded waits

Fee reads (`eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`) used to compute on every call, up to the 90 s budget, while wallets give up after about 10 s. Now `fee_estimate` looks in a per-head memo (`el::feecache`). A fresh hit is returned. A stale hit (a previous head's value) is returned raised by the most the base fee can have grown since (12.5% per block). Only a miss starts a compute.

`rust/myotis-net/src/el/reader.rs` · lines 8086–8105

```rust
        Lookup::Miss => {
            // A compute already in flight (the follower's, or another
            // read's) is waited on, not queued behind (#532 review). The
            // read that takes the single-flight lock hands it, owned, to
            // its compute: no other read can take a permit and park it
            // behind that lock in between (PR #535 review).
            let result = match Arc::clone(&self.fee_estimate_compute).try_lock_owned() {
                Ok(flight) => {
                    self.bounded_fee_compute(FEE_READ_WAIT, move |r| async move {
                        r.fee_estimate_refresh_locked(head, flight).await
                    })
                    .await
                }
                Err(_) => self.wait_for_fee(FEE_READ_WAIT, || self.estimate_settled()).await,
            };
            let _ = self.with_fee_cache(|c| c.stats.missed(false, result.is_ok(), Instant::now()));
            result
        }
    }
}
```

`rust/myotis-net/src/el/reader.rs` · lines 8122–8157

```rust
async fn bounded_fee_compute<T, F, Fut>(self: &Arc<Self>, wait: Duration, compute: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>> + Send,
{
    let Ok(permit) = Arc::clone(&self.fee_compute_permits).try_acquire_owned() else {
        return Err("fee data is being computed; retry shortly".to_string());
    };
    let reader = Arc::clone(self);
    let task = tokio::spawn(async move {
        let _permit = permit;
        let compute = compute(Arc::clone(&reader));
        reader.request_with_budget(FEE_REFRESH_BUDGET, compute).await
    });
    await_bounded(task, wait).await
}

/// Wait at most `wait` for a fee compute already in flight — the
/// follower's or another read's — to settle what `settled` looks for,
/// woken by every store ([`Self::fee_stored`]) instead of queueing another
/// compute behind it (#532 review).
async fn wait_for_fee<T>(&self, wait: Duration, settled: impl Fn() -> Option<Result<T, String>>) -> Result<T, String> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let stored = self.fee_stored.notified();
        tokio::pin!(stored);
        stored.as_mut().enable();
        if let Some(answer) = settled() {
            return answer;
        }
        if tokio::time::timeout_at(deadline, stored).await.is_err() {
            return Err(still_computing(wait));
        }
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `Arc::clone(&self.fee_estimate_compute).try_lock_owned()` either takes the single-flight lock now, as an `OwnedMutexGuard`, or fails at once. The winner moves the guard into its compute (`move |r| async move { … flight … }`); everyone else waits for the result instead of queueing behind the lock.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [async/await & tokio](01-primer.md#primer-async)* `bounded_fee_compute` takes `F: FnOnce(Arc<Self>) -> Fut + Send + 'static`. The closure is `'static` because it is moved into `tokio::spawn`; its future `Fut` need only be `Send`, because it is created and awaited inside the task. The compute receives its own `Arc<ElReader>` (`r`) instead of borrowing `&self`, which a `'static` task could not hold. `await_bounded` then waits at most 5 s; giving up drops only the `JoinHandle`, and the compute runs on to fill the memo for the next poll.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [async/await & tokio](01-primer.md#primer-async)* **No lost wake-ups.** `wait_for_fee` creates the `notified()` future, pins it (`tokio::pin!`, because `Notified` must not move once registered) and enables it *before* it checks `settled()`. `notify_waiters` stores no permit, so a store that landed between the check and the await would otherwise be missed, and the read would sleep until its deadline. Java's `Condition.await` has the same trap, solved by checking under the lock.

`rust/myotis-net/src/el/reader.rs` · lines 8199–8233

```rust
async fn fee_estimate_refresh_locked(
    &self,
    requested: Head,
    _flight: tokio::sync::OwnedMutexGuard<()>,
) -> Result<FeeEstimate, String> {
    // The head may have moved on while this waited: compute for the one
    // current now, not an outdated one whose result `store` would discard
    // (#532 review).
    let head = self.anchored_head().unwrap_or(requested);
    // Another caller (or the follower) may have finished it while we waited,
    // or failed it a moment ago: that ladder is not rerun for every caller
    // that queued behind it (#532 review).
    let (hit, failed) = self.with_fee_cache(|c| {
        let now = Instant::now();
        (c.estimate.lookup(head, now, false), c.estimate.failed_recently(head, now))
    })?;
    if let Lookup::Fresh(est) = hit {
        return Ok(est);
    }
    if failed {
        return Err(ESTIMATE_JUST_FAILED.to_string());
    }
    // A local, so dropped before the `_flight` parameter: a ladder cut
    // mid-way records its failure before the lock is released.
    let mut on_drop = FeeFailOnDrop::new(self, move |c: &mut FeeCache| c.estimate.record_failure(head, Instant::now()));
    let result = self.fee_estimate_at(head).await;
    on_drop.disarm();
    let current = self.anchored_head().ok();
    self.with_fee_cache(|c| match &result {
        Ok(est) => c.estimate.store(head, *est, Instant::now(), current),
        Err(_) => c.estimate.record_failure(head, Instant::now()),
    })?;
    self.fee_stored.notify_waiters();
    result
}
```

`rust/myotis-net/src/el/reader.rs` · lines 11006–11030

```rust
struct FeeFailOnDrop<'a, F: Fn(&mut FeeCache)> {
    reader: &'a ElReader,
    record: F,
    armed: bool,
}

impl<'a, F: Fn(&mut FeeCache)> FeeFailOnDrop<'a, F> {
    fn new(reader: &'a ElReader, record: F) -> Self {
        FeeFailOnDrop { reader, record, armed: true }
    }

    /// The compute ran to its end: it records its own outcome.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<F: Fn(&mut FeeCache)> Drop for FeeFailOnDrop<'_, F> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.reader.with_fee_cache(|c| (self.record)(c));
            self.reader.fee_stored.notify_waiters();
        }
    }
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [async/await & tokio](01-primer.md#primer-async)* **Drop order as a design tool.** Locals are dropped in reverse order of declaration, and an `async fn`'s parameters are bound before its body, so they are dropped after its locals. `on_drop` is a local and `_flight` a parameter: if this future is dropped mid-ladder (a budget cut, a stop), `on_drop` records the failure and wakes the waiters *before* the single-flight lock is released. A caller queued on that lock then sees “just failed” and does not rerun the ladder.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `FeeFailOnDrop<'a, F: Fn(&mut FeeCache)>` borrows the reader for `'a` and stores the recording closure by value; it is a stack guard, never stored or spawned. `disarm()` on the success path turns the `Drop` into a no-op, like a Java `finally` with a “completed normally” flag.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* `_flight` is named, so the guard lives until the function returns. A parameter written as `_: OwnedMutexGuard<()>` would drop it at once.

#### The log-index engine

*[Protocol & domain](01-primer.md#primer-domain)* A 6 s appender task keeps the index current along four paths. (1) A finalized per-block appender. (2) A head-gap bridge that takes over when the gap exceeds `APPEND_WINDOW` (128 blocks) or the edge has not moved for three ticks; it first walks down from the finalized anchor, then back up, and its `BridgePlan` is `take()`n out of a `std` mutex before the network I/O and put back afterwards. (3) An optimistic tail above finality, the only part that can reorg; it keeps its own `(number, hash)` record and rewinds on a mismatch. (4) A descending backfill, with peers ranked by measured throughput and chunk requests pipelined through `futures::StreamExt::buffered`. New since September: candidates fetch receipts first and bodies only for blocks that hold a watched log; the head side has its own chunk sizer; entries can be unwatched; and a checkpoint records a finality claim, so a restart keeps coverage it proved final instead of re-walking it.

`rust/myotis-net/src/el/reader.rs` · lines 4095–4123

```rust
fn persist_log_index(&self, finalized: u64, respect_throttle: bool) -> bool {
    let Some(path) = self.log_index_path.as_deref() else {
        return false;
    };
    // Held across serialize→rename so checkpoints are totally ordered:
    // the bytes that land last are the newest. Taken BEFORE the index
    // lock — see `log_index_write`.
    //
    // TRY-lock, because the other holders are slow and this one is
    // best-effort: an import merges GBs under it, and blocking here would
    // stall the appender tick and every getLogs that needs a head advance
    // for the whole merge — the exact stall this change exists to remove,
    // moved rather than fixed. Skipping instead costs nothing: the writer
    // holding the lock is writing a NEWER snapshot than this one would.
    let Ok(_writing) = self.log_index_write.try_lock() else {
        // Clock deliberately UNTOUCHED: nothing was written, so no interval
        // started, so the next tick is due again immediately. Writing to it
        // here — in either direction — is the bug: stamping would charge a
        // full interval for a checkpoint that never happened, and clearing
        // would race the holder that is stamping it as we look (it may be
        // finishing its write right now), discarding a fresh interval and
        // forcing the duplicate full rewrite this whole change removes.
        return false;
    };
    // The throttle, consulted under the lock — see this function's doc.
    // Before any serialize: a deferred checkpoint must cost nothing.
    if respect_throttle && !self.log_index_persist.is_due() {
        return false;
    }
```

`rust/myotis-net/src/el/reader.rs` · lines 4124–4138

```rust
// Serialize under the index lock — it reads the whole store — but do
// the write and the FSYNC outside it. On a multi-hundred-MB index the
// fsync dominates the checkpoint by orders of magnitude, and holding
// the index mutex across it stalls the appender, the backfill walker
// and every getLogs query for the whole duration.
let (bytes, clamp) = {
    let Ok(slot) = self.log_index.lock() else {
        return false;
    };
    let Some(ix) = slot.as_ref() else {
        return false;
    };
    let clamp = self.checkpoint_clamp_for(finalized);
    (checkpoint_bytes(ix, &self.chain_tag(), clamp), clamp)
};
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `let Ok(_writing) = self.log_index_write.try_lock() else { return false; };` skips instead of waiting: whoever holds the lock is writing a *newer* snapshot anyway. `try_lock` returns `Err` both for “held” and for “poisoned”, and both mean skip here.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* The `(bytes, clamp)` block serialises under the index lock and releases it at the `}`, before the slow write and fsync, so the appender, the walker and every `eth_getLogs` are not blocked by the disk. Lock order inside: checkpoint lock, then index lock, then (in `checkpoint_clamp_for`) the tail and claim locks.

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Result, ? and panics](01-primer.md#primer-error-handling)* `unwatch_log_index` (line 2902) shows the same order with a twist. It first answers the common “nothing to drop” case under the index lock *alone*, so a repeated unwatch does not queue behind a multi-gigabyte import holding the checkpoint lock. Only then does it take the checkpoint lock and the index lock again, in the documented order, and re-read the state under both. The “unwatch owed” atomic is set *before* the write attempt, so no outcome can leave it unset; the write that lands clears it.

`rust/myotis-net/src/el/reader.rs` · lines 10773–10800

```rust
trait CandidateSource: Sync {
    fn receipts(
        &self,
        hashes: &[[u8; 32]],
    ) -> impl std::future::Future<Output = Result<Vec<crate::el::eth::messages::BlockReceipts>, String>>
           + Send;
    fn bodies(
        &self,
        hashes: &[[u8; 32]],
    ) -> impl std::future::Future<Output = Result<Vec<crate::el::eth::messages::BlockBody>, String>>
           + Send;
}

impl CandidateSource for ManagedPeer {
    async fn receipts(
        &self,
        hashes: &[[u8; 32]],
    ) -> Result<Vec<crate::el::eth::messages::BlockReceipts>, String> {
        self.get_receipts(hashes).await
    }

    async fn bodies(
        &self,
        hashes: &[[u8; 32]],
    ) -> Result<Vec<crate::el::eth::messages::BlockBody>, String> {
        self.get_block_bodies(hashes).await
    }
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [async/await & tokio](01-primer.md#primer-async)* **Async methods in a trait.** The trait declares `fn receipts(&self, …) -> impl Future<Output = …> + Send` (return-position `impl Trait` in a trait), and the impl writes plain `async fn`. The explicit form is what lets the trait promise `+ Send`, which the spawned appender task needs; a bare `async fn` in the trait could not say that. The trait exists only so `fetch_candidate_logs` can be tested against a scripted peer.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `trait CandidateSource: Sync` is a supertrait bound: every implementor must be `Sync`, so a `&P` may be held across awaits in a `Send` future.

`rust/myotis-net/src/el/reader.rs` · lines 5352–5375

```rust
// Receipts first, bodies only where a block holds a watched log — or
// both together while candidates mostly are hits (#544; the choice is
// read once so every chunk of the batch is fetched the same way).
// Each chunk is fetched AND verified inside its own future
// ([`fetch_candidate_logs`]): the body request depends on what the
// receipts turned out to hold.
let eager_bodies = self.log_index_body_policy.eager();
// Built with a plain loop into boxed futures, not `chunks().map(|..|
// async move {..})`: a closure returning a future that borrows the
// header slices is not general enough over their lifetime for the
// spawned appender task's `Send` bound. Nothing runs until `buffered`
// polls it, so building them all up front costs a box per chunk.
let mut chunk_fetches: Vec<ChunkFetch<'_>> = Vec::new();
for (i, chunk) in candidates.chunks(chunk_len).enumerate() {
    chunk_fetches.push(Box::pin(async move {
        // Timed from its first poll, i.e. from when `buffered` let it
        // start — not from when the batch queued it.
        let started = Instant::now();
        let fetched = fetch_candidate_logs(peer, chunk, config, eager_bodies).await;
        (i, fetched, started.elapsed())
    }));
}
let mut fetches =
    futures::StreamExt::buffered(futures::stream::iter(chunk_fetches), depth);
```

*[Lifetimes](01-primer.md#primer-lifetimes) · [async/await & tokio](01-primer.md#primer-async)* `ChunkFetch<'a>` (line 10804) is a `BoxFuture<'a, …>`: a heap-allocated, type-erased, `Send` future that may borrow for `'a`. The comment explains why the loop boxes instead of writing `chunks().map(|c| async move { … })`: a closure returning a future that borrows the header slices is “not general enough” over their lifetime for the spawned task's `Send` bound, a known limitation of how the compiler checks such closures. `buffered(depth)` then polls up to `depth` fetches at once and yields results *in order*, which the truncation logic depends on. Dropping the stream on a failure cancels the fetches still in flight.

`rust/myotis-net/src/el/reader.rs` · lines 14189–14207

```rust
impl std::fmt::Display for BackfillBatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

// Bare `?`/`ok_or` sites in the batch are peer-response failures; the handful
// that are ours are constructed explicitly with `BackfillBatchError::ours`.
impl From<String> for BackfillBatchError {
    fn from(message: String) -> Self {
        Self::peer(message)
    }
}

impl From<&str> for BackfillBatchError {
    fn from(message: &str) -> Self {
        Self::peer(message)
    }
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `From` impls decide what a bare `?` means. In the backfill batch every `String` error becomes a *peer*-blamed failure, so the few failures that are the engine's own fault are built explicitly with `BackfillBatchError::ours`. Compare `FeeBuildError` (line 1944), which deliberately has *no* `From<String>`: there, a `?` on a plain `String` error fails to compile, so every site must state whose fault it is. A wrongly blamed check once struck every snap peer on every fee-history build.

`rust/myotis-net/src/el/reader.rs` · lines 13979–13987

```rust
fn restart_claim_fate(finalized: u64, vouched: u64, first: u64, finality_current: bool) -> RestartClaim {
    if finalized >= vouched {
        RestartClaim::Subsumed
    } else if finality_current && finalized > first && vouched - finalized > RESTART_CLAIM_MAX_LEAD {
        RestartClaim::Contradicted
    } else {
        RestartClaim::Hold
    }
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Tests](01-primer.md#primer-testing)* The restart claim, as one pure function. After a restart the beacon store resumes from a snapshot written once per sync-committee period, so its finality can sit hours below a checkpoint this node already proved final. The claim (`RestartClaimState`, under `log_index_claim`) lets the tail hold that coverage instead of rewinding it. It ends when the anchor catches up (`Subsumed`), or when a current finality verified *after* the claim was first weighed sits more than 512 blocks below it (`Contradicted`). Decisions like this one are free functions marked “Pure — unit-tested”, so the tests need no peers; `restart_claim_reader_tests` goes one step further and starts an offline `ElReader` with no bootnodes.

#### Testing on a virtual clock

`rust/myotis-net/src/el/reader.rs` · lines 11998–12012

```rust
#[tokio::test(start_paused = true)]
async fn a_slow_peer_still_wins_when_the_others_are_broken() {
    // THE regression a fixed per-attempt deadline introduces: peer 0
    // answers at 4 s (past HEDGE_DELAY) while peers 1-2 fail instantly.
    // Abandoning peer 0 would turn a working read into "all failed".
    let started = tokio::time::Instant::now();
    let out = race(vec![
        Peer::Answers(Duration::from_secs(4), 7),
        Peer::FailsNow,
        Peer::FailsNow,
    ])
    .await;
    assert_eq!(out, Ok(7), "a working peer must not be abandoned");
    assert_eq!(started.elapsed(), Duration::from_secs(4));
}
```

`rust/myotis-net/src/el/reader.rs` · lines 18265–18292

```rust
#[tokio::test(start_paused = true)]
async fn answers_at_the_first_accepted_write_then_gives_the_rest_a_grace() {
    // #320: a wedged writer held the send step for its whole frame-write
    // timeout. It must not hold the answer; the writes still in flight are
    // not cut with the answer (that tears a connection that may be fine)
    // but get GRACE more — measured from the first acceptance at 20 ms.
    let [quick, inside, outside, wedged] = flags();
    let (_stop, shutdown) = watch::channel(false);
    let started = tokio::time::Instant::now();
    let ok = first_accepted(
        vec![
            write(Duration::from_millis(20), true, Arc::clone(&quick)),
            write(Duration::from_millis(5_010), true, Arc::clone(&inside)),
            write(Duration::from_millis(5_030), true, Arc::clone(&outside)),
            write(Duration::from_secs(30), true, Arc::clone(&wedged)),
        ],
        GRACE,
        shutdown,
    )
    .await;
    assert!(ok);
    assert_eq!(started.elapsed(), Duration::from_millis(20));
    assert!(quick.load(Ordering::SeqCst));
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert!(inside.load(Ordering::SeqCst), "a write landing inside the grace runs on");
    assert!(!outside.load(Ordering::SeqCst), "the grace ends 5 s after the first acceptance");
    assert!(!wedged.load(Ordering::SeqCst), "a wedged write is cut, not left holding its writer");
}
```

- *[Tests](01-primer.md#primer-testing) · [async/await & tokio](01-primer.md#primer-async)* `#[tokio::test(start_paused = true)]` runs the test on tokio's paused clock: when every task is waiting on a timer, time jumps forward instantly. `started.elapsed()` can then be asserted *exactly* (4 s, 20 ms) in a test that takes milliseconds. This needs tokio's `test-util` feature, which `myotis-net` enables only for dev builds ([Stop 2](02-workspace.md)).
- *[Tests](01-primer.md#primer-testing)* `let (_stop, shutdown) = watch::channel(false);` keeps the sender alive in `_stop`. Writing `let (_, shutdown)` would drop the sender at once, and `first_accepted` treats a dropped sender as a shutdown, so every write would be cut. The `broadcast_pushes` tests solve the same problem with `std::mem::forget(tx)`.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Tests](01-primer.md#primer-testing)* `fn flags<const N: usize>() -> [Arc<AtomicBool>; N]` is a const generic: the array length is a type parameter, inferred from the destructuring pattern `let [quick, inside, outside, wedged] = flags();`. `std::array::from_fn` builds each element.

> [!WARNING]
> **Stale or inaccurate comments**
>
> The old tour listed five. All five are still there:
>
> - The `eth_cfg` field doc (line 2056) says it is “only read on the `tor` feature”, but lines 3050, 3434 and 4371 read it outside Tor code.
> - Comments name functions that do not exist: `log_index_note_chunk_served` (line 14639; the sizer's entry points are now `ChunkSizer::note_*`) and `note_checkpoint_on_disk` (a test comment at line 17266; the methods are `note_checkpoint_written` and `note_checkpoint_adopted`).
> - The `Arc::try_unwrap` teardown is mentioned at lines 3310, 3335 and 3386. No code in the workspace calls `try_unwrap`; hosts call `reader.stop().await`.
> - Two “future work” notes describe implemented features: the receipt doc (lines 9486–9492) says the own-transaction reachback “lands with the sent-tx slice”, but `locate_mined_tx` does it at line 9931; the transaction-by-hash doc (lines 9543–9545) says the same of the pending answer, which `TxLookup::Pending` provides.
> - The peer-ranking doc (lines 4979–4993) sits on `log_index_note_peer_tried` and merges with that function's own doc; it belongs to `log_index_backfill_peer_order` (line 5019), which has none.
>
> New ones:
>
> - `all_tip_lag`'s doc (line 671) says `fetch_anchored_window` has six callers; it has seven, as that function's own doc says.
> - `log_index_backfill_batch` has two stacked doc paragraphs (lines 5200–5214). The first says the headers are fetched “ascending”, the second, correctly, that the request is `reverse=true` from the cursor (line 5245).
> - On `account_from_tor_session` the `#[cfg(feature = "tor")]` attribute sits in the middle of the doc comment (line 6486). It still compiles into one doc, but it reads as if the last paragraph were separate.

## Checkpoint

14 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-reader-q1"></a>

**Q1** · Multiple choice

The log-index appender, the fee follower and the activity follower each hold a `Weak<ElReader>` and call `upgrade()` once per tick. Hosts now call `reader.stop().await`, which aborts these tasks. What does the `Weak` still buy?

- **A.** Nothing; it is left over from the `Arc::try_unwrap` design
- **B.** A `Weak` is cheaper to clone than an `Arc`
- **C.** If a host drops its last `Arc` without calling `stop()`, the task's next `upgrade()` returns `None` and the loop ends; a strong `Arc` in the task would keep the reader and its networking alive for as long as the loop runs
- **D.** It lets the task mutate the reader without a lock

[Answer →](answers.md#a-reader-q1)

<a id="q-reader-q2"></a>

**Q2** · Multiple choice

`send_raw_transaction` and `pre_broadcast_check` take `self: &Arc<Self>`. Why?

- **A.** The pre-broadcast check spawns a `'static` task that needs its own owned reference to the reader, and only an `&Arc<Self>` receiver lets the method call `Arc::clone(self)`
- **B.** Async methods must take `Arc<Self>`
- **C.** It makes the method thread-safe
- **D.** It lets the method replace the reader

[Answer →](answers.md#a-reader-q2)

<a id="q-reader-q3"></a>

**Q3** · Written answer

In `hedged_race`, how are the losing attempts cancelled once a winner is found, and what does the doc comment warn this can cost?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-reader-q3)

<a id="q-reader-q4"></a>

**Q4** · Multiple choice

In `get_account_proven`, the closure `|peer| async move { self.get_account_from(&peer, address, fin).await }` produces futures that borrow `self`. Why does this compile without a `'static` bound?

- **A.** `self` is always `'static`
- **B.** `async move` makes everything inside it `'static`
- **C.** The compiler clones the reader into each future
- **D.** The futures are never spawned: `hedged_read` drives them to completion inside this method, so they only need to live as long as the borrowed locals, and `address` and `fin` are `Copy` and copied in

[Answer →](answers.md#a-reader-q4)

<a id="q-reader-q5"></a>

**Q5** · Multiple choice

`pre_broadcast_check` spawns the account read and then does `tokio::time::timeout(ACCOUNT_READ_BUDGET, read)` on its `JoinHandle`. What happens to the read when the timeout fires?

- **A.** It is cancelled, because the timeout drops what it wraps
- **B.** It keeps running: dropping a `JoinHandle` detaches the task rather than cancelling it, and the read is still bounded by its own registered budget and by `stop()`
- **C.** It panics, because a `JoinHandle` must be awaited
- **D.** It is aborted and its peer connection is torn

[Answer →](answers.md#a-reader-q5)

<a id="q-reader-q6"></a>

**Q6** · Written answer

In `fee_estimate_refresh_locked`, the single-flight guard arrives as the parameter `_flight`, and the body declares `let mut on_drop = FeeFailOnDrop::new(…)`. Explain why the comment says the local is “dropped before the `_flight` parameter”, and what would go wrong in the other order.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-reader-q6)

<a id="q-reader-q7"></a>

**Q7** · Multiple choice

`wait_for_fee` creates `self.fee_stored.notified()`, pins and enables it, and only then calls `settled()`. Why this order?

- **A.** So that a store that lands between the check and the await is not missed: `notify_waiters` stores no permit and only wakes futures already registered
- **B.** Because `Notify` must be pinned before any method call on the reader
- **C.** To make the wait FIFO
- **D.** Because `settled()` holds the fee-cache lock and must run after the wait

[Answer →](answers.md#a-reader-q7)

<a id="q-reader-q8"></a>

**Q8** · Multiple choice

`tx_scans` is a `std::sync::Mutex` holding a map of `Arc<tokio::sync::Mutex<TxScanState>>`. Why two kinds of mutex?

- **A.** An accident of history
- **B.** tokio mutexes cannot be stored in maps
- **C.** The std lock guards only the map and is held briefly, never across `.await`; each per-transaction tokio lock is held across the slow network scan, so concurrent polls for the same transaction do not duplicate work while different transactions proceed in parallel
- **D.** std mutexes are async-aware

[Answer →](answers.md#a-reader-q8)

<a id="q-reader-q9"></a>

**Q9** · Multiple choice

What must `fetch_anchored_window` establish before any header in the window is trusted?

- **A.** That at least two peers returned the same headers
- **B.** Exact length and start number, that the last header's hash equals the anchored hash (optimistic head or finalized block), and that every header is parent-linked to the next
- **C.** That the headers are recent
- **D.** That the peer is pinned

[Answer →](answers.md#a-reader-q9)

<a id="q-reader-q10"></a>

**Q10** · Written answer

`persist_log_index` starts with `self.log_index_write.try_lock()` on a `Mutex<()>`, then serialises the index inside a block that holds `self.log_index`, then writes the bytes. Explain the lock, the `try_lock`, and the block.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-reader-q10)

<a id="q-reader-q11"></a>

**Q11** · Multiple choice

The backfill batch builds its chunk fetches in a plain loop as `Box::pin(async move { … })` into a `Vec<ChunkFetch<'_>>`, instead of `candidates.chunks(n).map(|c| async move { … })`. According to the comment, why?

- **A.** Boxed futures run faster
- **B.** `buffered` only accepts boxed futures
- **C.** A closure returning a future that borrows the header slices is not general enough over their lifetime for the spawned appender task's `Send` bound; boxing each future into a named `BoxFuture` type avoids that
- **D.** So the fetches start immediately, before `buffered` polls them

[Answer →](answers.md#a-reader-q11)

<a id="q-reader-q12"></a>

**Q12** · Multiple choice

A `first_accepted` test writes `let (_stop, shutdown) = watch::channel(false);`. What would change with `let (_, shutdown) = …`?

- **A.** Nothing; both ignore the sender
- **B.** The sender would be dropped at once, and `first_accepted` treats a dropped sender as a shutdown, so every write would be cut and the call would return `false`
- **C.** The test would not compile
- **D.** The paused clock would stop advancing

[Answer →](answers.md#a-reader-q12)

<a id="q-reader-q13"></a>

**Q13** · Written answer

`BackfillBatchError` implements `From<String>` and `From<&str>`, while `FeeBuildError` deliberately implements neither. What does each choice mean for a bare `?` on a `Result<_, String>`, and why does the difference matter?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-reader-q13)

<a id="q-reader-q14"></a>

**Q14** · Written answer

Describe the order of `ElReader::stop()` and why each step comes where it does.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-reader-q14)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
