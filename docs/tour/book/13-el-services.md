# myotis-net, part 5: EVM bridge, log index and transactions

*Stop 13 · crate `myotis-net`, `src/el/`* · 7 files · 9,551 lines · about 155 minutes

The execution-layer services that sit just below the reader facade. The EVM's network bridge turns revm's synchronous state lookups into hedged, proof-checked snap requests. The `eth_getLogs` index, the new address-activity follower and the new fee memo are pure state machines that the reader feeds with verified data. The transaction modules decode, gate and track what the wallet sends. Almost every file here is pure and clock-injected; the one that is not, `evm.rs`, is where synchronous and asynchronous Rust meet.

## Rust you will practise

- **Sync code that waits on async code** `Handle::block_on` on a blocking-pool thread, borrowed futures driven by `join_all`, and `tokio::pin!` + `select!` around a request.
- **Moving big state instead of copying it** `mem::take`, `BTreeMap::split_off`, partial moves and the `..ix` struct update.
- **Borrowing one field while mutating another** — disjoint field borrows inside `retain` closures, and cloning a key so a shared borrow ends before a `remove`.

Seven files, three themes. Read them in this order:

| File | Lines | What it is |
|---|---|---|
| [`evm.rs`](#f-myotis-net-src-el-evm-rs) | 2,117 | The EVM's I/O half: `PoolOracle`, the outcome types, the prefetch wave. |
| [`logindex.rs`](#f-myotis-net-src-el-logindex-rs) | 3,718 | The scoped `eth_getLogs` index: watch list, coverage, store, snapshot file, merge. |
| [`activity.rs`](#f-myotis-net-src-el-activity-rs) | 1,213 | New. Which watched addresses each verified block touched (#691), and accounts carried forward without a new proof. |
| [`feecache.rs`](#f-myotis-net-src-el-feecache-rs) | 786 | New. A per-head memo for `eth_gasPrice` and `eth_feeHistory`. |
| [`tx.rs`](#f-myotis-net-src-el-tx-rs) | 1,131 | Transaction decoders and the `eth_sendRawTransaction` gate. |
| [`send_check.rs`](#f-myotis-net-src-el-send-check-rs) | 197 | New. geth's two txpool verdicts and the head-freshness rule for the pre-broadcast check. |
| [`sent_tx.rs`](#f-myotis-net-src-el-sent-tx-rs) | 389 | The sent-transaction watch and the pending-nonce overlay. |

The request lifetimes (`request.rs`), the trust decision (`verify.rs`), the anchor, the peer pool and the serving window were in this stop in the first edition; they are now in [Stop 12](12-el-pool.md). The reader that owns the locks, tasks and I/O around everything here is [Stop 14](14-el-reader.md).

![The sync to async bridge of eth_call. Top lane: tokio worker threads, where the async ElReader method builds a PoolOracle and the hedged snap requests run. Bottom lane: a blocking-pool thread, where request::blocking runs the revm executor. revm calls PoolOracle fetch methods synchronously; each one calls wait, which uses Handle::block_on to drive a hedged race over the call's peers. The verified value comes back down to revm. When revm finishes, the async reader receives the result by awaiting the blocking task's JoinHandle.](img/13-el-services-1.svg)

*The one rule behind the bridge: `Handle::block_on` runs only on a blocking-pool thread, never on a runtime worker. The future it drives is polled on that blocking thread; the timers and sockets it waits on are driven by the runtime. Every value is verified before it reaches revm: an account or storage proof against the call's state root, or `keccak(code) == code_hash`.*

<a id="f-myotis-net-src-el-evm-rs"></a>

### myotis-net/src/el/evm.rs

*library · 2,117 lines · Java twin · SnapBackedStateOracle*

The I/O half of `eth_call`, `eth_estimateGas`, `eth_createAccessList`, `debug_traceCall`, `eth_simulateV1` and ENS. `myotis-evm` ([Stop 7](07-evm.md)) is sans-I/O, and its `SnapStateOracle` trait is synchronous. `PoolOracle` implements that trait over a fixed snapshot of snap peers, one oracle per call. It verifies on fetch: account and storage proofs against the call's state root, `keccak(code)` against the code hash, and a `BLOCKHASH` answer by walking headers down from the call's verified parent. If no peer can prove a value, the fetch fails closed with an `OracleError`. The file also defines the outcome and answer types the reader returns for every EVM-backed read, the ENS query types, and `block_context`, which turns a verified header into revm's `BlockContext`.

| Lines | What happens |
|---|---|
| 1–48 | Module doc (verify on fetch, hedging, the `panic = "abort"` caveat); imports; `WalkKey`. |
| 50–131 | `CallOutcome` (five variants) and `from_executor`; `ReadAnchor` (head or finalized); `CallAnswer`. |
| 133–288 | `GasOutcome`, `AccessListOutcome`, `TraceOutcome`, `SimulateOutcome` (#716) and their answer structs, all mapped from `EvmError` the same way. |
| 290–399 | ENS: `EnsOutcome`, `EnsRootMode`, `EnsQuery` (ten query kinds), `EnsRecordValue`, `EnsQueryOutcome` (its `Offchain` variant carries a boxed CCIP-Read lookup). |
| 401–461 | `block_context`, `leaf_account`, saturating scalar conversions. |
| 463–669 | The prefetch wave's machinery: the silence deadline (#320), `DISCOVERY_TIME_BUDGET`, `WaveFailure`, **`wave_request`**, `AttemptTally`, `ChunkLedger`, the chunk rotation `wave_peer`. |
| 671–826 | `PoolOracle`'s fields; `WireCounters` and the `WireTimer` guard (#532); the pure ask-order helpers `next_order`, `note_losers`, `demoted`, `wave_positions`. |
| 828–1055 | `impl PoolOracle`: `new`, shadow-cache notes, **`wait` (the bridge)**, `record_race`, the per-call ladder, the memoized account `leaf`. |
| 1057–1553 | `impl SnapStateOracle`: `fetch_account`, `prefetch_batch` (1112–1412), `fetch_storage`, `fetch_block_hash` (#664), `fetch_bytecode`. |
| 1555–2117 | Tests: scalar guards, the outcome mapping, the wave's silence and ledger rules, the rotation, the wire counters, the discovery budget. |

`rust/myotis-net/src/el/evm.rs` · lines 76–89

```rust
impl CallOutcome {
    /// The executor's verdict: a revert keeps its payload (a verified answer),
    /// a refusal stays permanent, and anything else is the retryable
    /// `Unavailable`. One mapping for every call shape.
    pub fn from_executor(joined: Result<Vec<u8>, EvmError>) -> CallOutcome {
        match joined {
            Ok(bytes) => CallOutcome::Success(bytes),
            Err(EvmError::Reverted { data }) => CallOutcome::Revert(data),
            Err(e) if e.is_refusal() => CallOutcome::Refused(e.to_string()),
            Err(e) if e.is_infeasible() => CallOutcome::Infeasible(e.to_string()),
            Err(e) => CallOutcome::Unavailable(e.to_string()),
        }
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Match guards, in order.** `joined` is owned, so `Err(EvmError::Reverted { data })` moves the revert payload out of the error into the new variant: no copy. The next three arms bind the whole error as `e` and test it with `if` guards; arms are tried top to bottom, so the order is the policy. A refusal (a call this build can never answer) becomes `Refused`, which the host serves as the permanent `-32602`; an infeasible call (out of gas, fee cap, funds, #509) is an answer served as geth serves it; everything else is the retryable `Unavailable`. This is the CLAUDE.md rule “applied or refused, never silently ignored” in type form. The four sibling types repeat the same match.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The doc on `CallOutcome` itself (lines 50–53) still says the Java contract treats “every other outcome (revert, halt, unavailable)” as no answer. It predates the `Refused` and `Infeasible` variants, whose own docs (and `myotis-engine`'s `call_json`) give them a permanent `-32602` and a geth-style `-32000`. Trust the variant docs. The first edition's note about this module doc listing reputation and batching as “deferred” no longer applies: the doc now describes both.

#### The bridge

> [!TIP]
> **The sync→async bridge, step by step**<br>
>
> - The async reader builds the oracle in `snap_oracle` (reader.rs): a snapshot of `pool.snap_peers()`, `Handle::current()` (a cloneable handle to the engine's runtime), the quality sink and the read stats. `PoolOracle::new` also calls `Operation::current()`. That task-local is visible only while the request's future is being polled, and task-locals do not reach `spawn_blocking` threads, so it is captured here, eagerly.
> - The reader runs revm through `request::blocking(move || …)` ([Stop 12](12-el-pool.md)), on a thread from tokio's blocking pool.
> - revm calls `fetch_account`, `fetch_storage` and the rest synchronously. Each one ends in `wait`.
> - `wait` calls `self.handle.block_on(…)`. The blocking thread polls that future itself and parks between polls; the sockets and timers it waits on are driven by the runtime's drivers and the peer connection tasks on the worker threads.
> - **Why not on a runtime worker?** `Handle::block_on` panics when it is called from inside an async execution context. Even if it did not, a worker parked in it would stall every task queued on that worker.

`rust/myotis-net/src/el/evm.rs` · lines 900–907

```rust
fn wait<T>(&self, future: impl std::future::Future<Output = T>) -> Result<T, OracleError> {
    self.handle.block_on(async {
        match &self.operation {
            Some(op) => op.wait(future).await.map_err(|reason| OracleError::Cancelled { reason }),
            None => Ok(future.await),
        }
    })
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `future: impl std::future::Future<Output = T>` is argument-position `impl Trait`: an anonymous generic parameter, so each call site gets its own monomorphized `wait`. The async block captures `future` and `self` by reference or move as needed.
- *[async/await & tokio](01-primer.md#primer-async) · [Lifetimes](01-primer.md#primer-lifetimes)* **`block_on` needs neither `Send` nor `'static`.** Its signature is just `fn block_on<F: Future>(&self, future: F) -> F::Output`, and it returns only when the future is done. So the futures handed to `wait` may borrow `self` and locals of the calling function. `tokio::spawn` would demand `'static`, because a spawned task may outlive its spawner.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `op.wait(future)` (request.rs) re-checks the request's deadline and cancel flags every 10 ms while it polls `future`, and returns `Err(String)` when they fire. `map_err(|reason| OracleError::Cancelled { reason })` turns that into the oracle's error type, which revm propagates like any other state error.

`rust/myotis-net/src/el/evm.rs` · lines 1005–1054

```rust
fn leaf(
    &self,
    state_root: &[u8; 32],
    address: [u8; 20],
) -> Result<Option<AccountLeaf>, OracleError> {
    self.check_request()?;
    if let Some(cached) = self.leaf_memo.lock().unwrap().get(&address) {
        return Ok(cached.clone());
    }
    // No lock held across the network fetch.
    let quality = self.quality.clone();
    let started = std::time::Instant::now();
    let (asked, peers) = self.ladder();
    let peers = &peers;
    let fetched = self.wait(async {
        // Hedged across the call's peers (reader::hedged_race). An eth_call
        // makes several state reads, and a silent first peer used to hold
        // EACH of them for a full request timeout — the main source of
        // multi-second eth_call latency on a flaky pool. Any proof-verified
        // answer ends the race; a bad proof or transport error is a miss.
        // The call's ask order learns from each race (see `order`).
        let out = hedged_race(
            peers,
            HEDGE_DELAY,
            |peer: Arc<ManagedPeer>| async move {
                peer.snap_get_account(state_root, &address).await
            },
            |_: &AccountOutcome| true,
        )
        .await;
        Self::record_race(&quality, peers, &out, self.finalized).await;
        self.learn_order(&asked, &out);
        out.accepted.map(|(_, outcome)| match outcome {
            AccountOutcome::Present(leaf) => Some(leaf),
            AccountOutcome::Absent => None,
        })
    })?;
    match fetched {
        Some(leaf) => {
            self.note_account(address, state_root, leaf.as_ref(), started);
            self.leaf_memo.lock().unwrap().insert(address, leaf.clone());
            Ok(leaf)
        }
        None => Err(OracleError::StateUnavailable {
            state_root: *state_root,
            address,
            slot: None,
        }),
    }
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Memo first, no lock across I/O.** In `if let Some(cached) = self.leaf_memo.lock().unwrap().get(&address)`, the temporary `MutexGuard` lives until the end of the `if let`, and `cached` borrows through it. `cached.clone()` copies the value out before the guard drops. The network fetch below runs with no lock held; a second fetch of the same address in the same call is possible, and harmless.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [async/await & tokio](01-primer.md#primer-async)* `let peers = &peers;` shadows the owned `Vec` with a reference. The async block given to `wait` is not `move`, so it borrows `peers`, `asked`, `quality`, `state_root` and `self`. That is legal because of the `block_on` property above.
- *[Ownership & moves](01-primer.md#primer-ownership) · [async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* The closure `|peer: Arc<ManagedPeer>| async move { … }` is the race's per-attempt factory. `hedged_race` (reader.rs, [Stop 14](14-el-reader.md)) starts the first peer and adds another every `HEDGE_DELAY` (3 s) without an answer, up to three in flight; the first answer the `accept` closure approves wins. Each attempt gets its own `Arc` clone, and `async move` moves it, the `&[u8; 32]` reference and a copy of `address` into the future.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `out.accepted.map(|(_, outcome)| match outcome { … })` yields an `Option<Option<AccountLeaf>>`: the outer `None` means no peer proved anything (`StateUnavailable`), `Some(None)` means the account is proven absent. The memo stores the inner `Option`, so a proven absence is cached too.
- *[Methods & self](01-primer.md#primer-methods)* `Self::record_race(&quality, peers, &out, self.finalized)` is an associated function with no `self` parameter. It takes exactly the parts it needs, so it can be called while other parts of `self` are borrowed. It feeds the pool's reputation sink: the winner served, each miss failed (witnessed when someone else served), each loser the winner outpaced. On a finalized-root call, a miss caused by the peer not holding that old root is excused.

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Protocol & domain](01-primer.md#primer-domain)* **A per-call ask order.** `order`, `lost` and `silence_reported` are `Mutex<Vec<…>>` fields indexed by peer id. After each race, `learn_order` moves the winner to the front and the losers to the back (`next_order`), so a dead first peer costs one hedge delay per call instead of one per state read. The helpers are pure functions over slices, which is why they can be unit-tested without peers. Two small idioms: `first_time` uses `!std::mem::replace(flag, true)`, a non-atomic “get and set”, and `demoted` uses `Iterator::partition` to split `&usize` items into two `Vec<usize>`s (a `Vec<T>` of a `Copy` type can be extended from `&T` items).

#### Timing the waits

`rust/myotis-net/src/el/evm.rs` · lines 764–776

```rust
/// Adds the time since it was made to its counter when dropped — however the
/// read it times ends.
struct WireTimer<'a> {
    nanos: &'a std::sync::atomic::AtomicU64,
    started: std::time::Instant,
}

impl Drop for WireTimer<'_> {
    fn drop(&mut self) {
        let nanos = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, std::sync::atomic::Ordering::Relaxed);
    }
}
```

*[Lifetimes](01-primer.md#primer-lifetimes) · [Ownership & moves](01-primer.md#primer-ownership)* **An RAII guard that borrows.** `WireTimer<'a>` holds `&'a AtomicU64`, a reference into the oracle's `WireCounters`, so the compiler guarantees the timer cannot outlive the counter it adds to. `impl Drop for WireTimer<'_>` uses the anonymous lifetime because the impl does not need to name it. Each fetch starts with `let _timer = self.wire.serial();`: the name `_timer` keeps the guard alive to the end of the function, and its `drop` adds the elapsed time however the function leaves, including an early `?` return. `Relaxed` ordering is enough for counters that nothing else synchronizes on. `u64::try_from(…).unwrap_or(u64::MAX)` saturates a `u128` nanosecond count instead of panicking.

#### The prefetch wave

*[Protocol & domain](01-primer.md#primer-domain)* The executor's convergence loop runs discovery passes: an EVM run that collects the accounts, slots and code it reached, then one prefetch wave that fetches them all at once (`prefetch_batch`), so the real runs mostly hit the caches. The account items are cut into chunks of 64; each chunk is pinned to one peer per attempt, with up to three attempts across peers; every wire request needs one of 48 semaphore permits; and the whole wave is bounded at 30 s. Failures are silent per item, because the serial per-item path re-fetches whatever is missing. A chunk's first ask goes to a peer that has not lost a race or gone silent in this call (`wave_ladder`, `wave_peer`). `keep_discovering` bounds how long the loop may keep starting such passes (15 s, `DISCOVERY_TIME_BUDGET`).

`rust/myotis-net/src/el/evm.rs` · lines 527–554

```rust
async fn wave_request<T>(
    last_response: impl Fn() -> Option<tokio::time::Instant>,
    link_heard_after: impl Fn(tokio::time::Instant) -> bool,
    request: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, WaveFailure> {
    let (sent, request) = crate::el::peer::scope_send_marker(request);
    tokio::pin!(request);
    loop {
        let quiet_since = sent.get().copied().map(|at| match last_response() {
            Some(heard) if heard > at => heard,
            _ => at,
        });
        let wait = match quiet_since {
            Some(since) => {
                let quiet = since.elapsed();
                if quiet >= WAVE_SILENCE_DEADLINE {
                    return Err(WaveFailure::Silent { link_proven: link_heard_after(since) });
                }
                WAVE_SILENCE_DEADLINE - quiet
            }
            None => WAVE_SILENCE_RECHECK,
        };
        tokio::select! {
            out = &mut request => return out.map_err(WaveFailure::Failed),
            _ = tokio::time::sleep(wait) => {}
        }
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async)* **Polling one future across loop iterations.** `tokio::pin!(request)` pins the request future on the stack. A future that has been polled may hold pointers into itself and must not move again; pinning makes `&mut request` pollable, repeatedly, without moving it. Each `select!` races the request against a sleep. When the sleep wins, the request is *not* dropped (it lives outside the loop); the loop just re-evaluates the silence.
- *[Protocol & domain](01-primer.md#primer-domain) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Silence, not age.** `sent` is an `Arc<OnceLock<Instant>>` that the peer code fills when the request frame is actually written (`scope_send_marker`, a task-local scope in peer.rs). The clock starts at the later of that send and the peer's last delivered response. Only after `WAVE_SILENCE_DEADLINE` (6 s) of complete silence does the function return `Err(Silent { … })`, dropping the request. A request that has not gone out yet is never cut, because dropping it inside the shared writer would tear the connection for every request on it.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Iterators & closures](01-primer.md#primer-iterators-closures)* The two `impl Fn` parameters are callbacks that the wave fills with `|| peer.last_response()` and `|since| self.link_heard_after(&peer, since)`. `link_proven` records whether some *other* peer of the call delivered during this silence, which is the evidence that the silence was the peer's and not our own link.

`rust/myotis-net/src/el/evm.rs` · lines 1224–1250

```rust
let values = futures::future::join_all(missing.iter().map(|slot| {
    let position = slot.to_be_bytes::<32>();
    let peer = Arc::clone(&peer);
    let leaf = leaf.clone();
    let sem = Arc::clone(&sem);
    async move {
        let Ok(_permit) = sem.acquire().await else {
            // closed semaphore = local failure
            return Err(WaveFailure::Failed("semaphore closed".to_string()));
        };
        let started = std::time::Instant::now();
        let value = wave_request(
            || peer.last_response(),
            |since| self.link_heard_after(&peer, since),
            peer.snap_get_storage(state_root, &addr, &leaf, &position),
        )
        .await
        .and_then(|bytes| {
            u256_be(&bytes).ok_or_else(|| WaveFailure::Failed("storage scalar too long".to_string()))
        });
        if let Ok(v) = value {
            self.note_storage(addr, position, state_root, leaf.storage_root, v, started);
        }
        value
    }
}))
.await;
```

- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* The per-future clone pattern: each `async move` future gets its own `Arc` clones (`peer`, `sem`), its own clone of `leaf` and its own `position` array. `join_all` polls them all on the one blocking thread that called `block_on`, like `CompletableFuture.allOf` without a thread pool.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [async/await & tokio](01-primer.md#primer-async)* These futures still *borrow* `state_root`, `self` and the cache sinks from the enclosing frame (the `move` copies the references in). That is fine because they are never spawned, only driven to completion before `prefetch_batch` returns.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `let Ok(_permit) = sem.acquire().await else { … };` keeps the permit until the end of the block, after the request. Binding it to `_` instead would drop it at once, and the 48-request limit would do nothing. A closed semaphore fails the item; it never bypasses the bound.

`rust/myotis-net/src/el/evm.rs` · lines 1406–1412

```rust
    // The whole wave is bounded (Java PREFETCH_WAVE_TIMEOUT_SEC): on timeout
    // whatever landed is kept and the loop's next iteration proceeds — an
    // eth_call must never hang on a slow warm-up.
    let _ = self.wait(async {
        let _ = tokio::time::timeout(WAVE_TIMEOUT, wave).await;
    });
}
```

*[async/await & tokio](01-primer.md#primer-async)* Two nested cancellation layers: a 30 s `timeout` on the warm-up wave, inside `wait`'s request-level deadline. Both results are ignored on purpose (`let _ =`), because warm-up is best-effort and whatever landed in the caches stays there. When the timeout fires, the `wave` future is dropped, and with it every chunk future and every in-flight request; the peer's pending-request guard discards late answers.

<a id="f-myotis-net-src-el-logindex-rs"></a>

### myotis-net/src/el/logindex.rs

*library · 3,718 lines*

The pure state behind the opt-in, scoped `eth_getLogs`. It holds a host-supplied watch list, per-entry **contiguous coverage**, a `BTreeMap` log store keyed by `(block, log_index)`, and the backfill walk's trust cursor. Since September a watch entry can be an **address** (every log the contract emits) or a **topic value** (#673: every log, from any emitter, that carries the value at one of the entry's topic positions, 1 to 3; that is how a token transfer names a wallet). The file also provides filter matching, an explicit unwatch, an atomically written, versioned binary snapshot (`MLIX` v2, or v3 when a topic entry exists) with portable import, export and merge, and a finality-claim sidecar. It does no networking and no verification: callers feed only logs that passed the header and `receiptsRoot` checks. The appender, the walker and the checkpoints live in reader.rs.

`rust/myotis-net/src/el/logindex.rs` · lines 1–14

```rust
//! Scoped, verified log index behind `eth_getLogs` (docs/eth-getlogs-design.md).
//!
//! This module is the pure state half of the feature: watch-list config,
//! the in-memory index, coverage bookkeeping, filter matching, and the
//! atomic on-disk snapshot. It does no networking and no verification —
//! callers (the head-follow appender and the backfill walker) only feed it
//! logs that already passed the anchored-header + receiptsRoot gates, the
//! same contract as `receipt::DecodedReceipt` ("callers must have already
//! verified").
//!
//! The one load-bearing rule lives in [`LogIndex::query`]: a request outside
//! indexed coverage is an error, never an empty answer. Wallets read `[]` as
//! "no events exist"; serving it for an unindexed range would corrupt
//! event-sourced state (commitment trees) silently and permanently.
```

| Lines | What happens |
|---|---|
| 20–177 | `WatchKey` (address or topic), `TOPIC_POSITIONS`, `WatchEntry` with `selects` (the one indexing rule), `same_restriction`, `answers`. |
| 179–348 | `ChainTag`; `LogIndexConfig`: `watches`, `union_with` (a re-pushed preset extends, never replaces), `invalid`, the FNV-1a `fingerprint` (names, pacing and the pause switch excluded). |
| 350–522 | `StoredLog`, `Coverage` (contiguous extends only), `InvalidWatchList`, `CoverageGap`, `LogFilter` (`matches`, `pins`), `QueryError`. |
| 524–985 | `LogIndex`: `new`, `adopt_config`, **`unwatch`**, the runtime setters, **`append_block`**, `backfill_block`, `rewind_above` (reorgs), **`query`**, the bloom prefilter, `walk_target` / `backfill_complete`. |
| 987–1131 | Durability: `next_tmp_path`, `write_atomic`; the frame constants (v1 legacy, v2, v3); `fnv64`; the `Cursor<'a>` reader. |
| 1133–1424 | `serialize_impl` (clamped at finality, optional name stripping); `deserialize` (v1, v2, v3; coverage re-paired by key); portable import; load and persist. |
| 1426–1552 | The finality claim: `SnapshotId`, an 80-byte `MLXF` sidecar that counts only beside the exact file it was written for. |
| 1554–1766 | `MergeError`; canonical `merge` of imported snapshots. |
| 1768–1919 | `walk_resumable`, the hardened `parse_v2` and `parse_body`. |
| 1921–3718 | Three test modules, 67 tests: a Python-generated frame pin, coverage honesty, corruption and bit flips, concurrent writers, merge, unwatch, topic entries, the bloom prefilter, finality claims. |

`rust/myotis-net/src/el/logindex.rs` · lines 119–131

```rust
/// Would this entry store a log at `block_number` emitted by `address`
/// with `topics`? The one rule behind indexing, the receipts-only scan
/// and merge, so none of them can disagree with another.
pub fn selects(&self, block_number: u64, address: &[u8; 20], topics: &[[u8; 32]]) -> bool {
    block_number >= self.from_block
        && match self.key {
            WatchKey::Address(a) => a == *address,
            WatchKey::Topic(v) => {
                self.positions.iter().any(|&p| topics.get(p as usize) == Some(&v))
            }
        }
        && (self.topic0s.is_empty() || topics.first().is_some_and(|t| self.topic0s.contains(t)))
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* **One rule for indexing, scanning and merging.** `match self.key` reads a field through `&self`, and the arms bind `a` and `v` *by value*. Moving out of a borrowed place is normally forbidden, but `WatchKey`'s arrays are `Copy`, so the bytes are simply copied. `topics.get(p as usize) == Some(&v)` compares two `Option<&[u8; 32]>`s without indexing (no panic past the log's last topic). An empty `topic0s` means “any event”.

`rust/myotis-net/src/el/logindex.rs` · lines 710–748

```rust
pub fn append_block(
    &mut self,
    block_number: u64,
    block_hash: [u8; 32],
    logs: Vec<StoredLog>,
) -> Result<(), CoverageGap> {
    for (w, c) in self.config.watch.iter().zip(self.coverage.iter()) {
        if block_number >= w.from_block {
            if let Some((low, high)) = c.span {
                if block_number > high.saturating_add(1) || block_number < low {
                    return Err(CoverageGap { edge: high, block: block_number });
                }
            }
        }
    }
    for log in logs {
        // Unconditional (not debug_assert): a mislabeled log would be
        // keyed by its own number, possibly inside covered range it was
        // never verified for. Drop it instead.
        if log.block_number != block_number {
            continue;
        }
        if self.watched(&log) {
            self.logs.insert((log.block_number, log.log_index), log);
        }
    }
    for (w, c) in self.config.watch.iter().zip(self.coverage.iter_mut()) {
        if block_number >= w.from_block {
            // Pre-checked above; a gap here is unreachable.
            let _ = c.extend_up(block_number);
        }
    }
    // Seed the backfill trust edge at the first-ever appended block: the
    // walker chains DOWNWARD from here (backfill_block then advances it).
    if self.cursor.is_none() {
        self.cursor = Some((block_number, block_hash));
    }
    Ok(())
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **All-or-nothing.** The first loop only checks: a gap against *any* affected entry returns `Err` before anything changed. Only then are logs stored and spans extended. That is why the second `extend_up` can ignore its result with `let _ =`. An empty `logs` vector still advances coverage, which is what makes an empty answer honest.
- *[Ownership & moves](01-primer.md#primer-ownership)* `for log in logs` consumes the `Vec` by value, so each `StoredLog` (with its topics and data) is *moved* into the map, never copied. A mislabeled log is dropped, not stored under its own number.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Disjoint field borrows**: line 736 zips `self.config.watch.iter()` (shared) with `self.coverage.iter_mut()` (mutable) at the same time. The borrow checker allows it because they are different fields of `self`.

`rust/myotis-net/src/el/logindex.rs` · lines 818–870

```rust
pub fn query(&self, filter: &LogFilter) -> Result<Vec<StoredLog>, QueryError> {
    if !self.config.enabled {
        return Err(QueryError::Disabled);
    }
    if filter.from_block > filter.to_block {
        return Err(QueryError::Unanswerable);
    }
    // The topic entries first. A refusal from one is kept to explain
    // the answer if nothing else serves — a covered-but-not-yet span is
    // the most useful (the caller can wait it out), so it wins.
    let mut topic_refusal: Option<QueryError> = None;
    for (w, cov) in self.config.watch.iter().zip(self.coverage.iter()) {
        let WatchKey::Topic(v) = w.key else {
            continue;
        };
        if !w.answers(filter) {
            // Pinned, but where this entry does not look, or outside its
            // topic0 restriction: the entry exists for the value and
            // cannot serve this shape of question.
            if (1..filter.topics.len()).any(|p| filter.pins(p, &v)) && topic_refusal.is_none() {
                topic_refusal = Some(QueryError::UnindexedTopic(w.key));
            }
            continue;
        }
        match Self::check_coverage(w, cov, filter) {
            Ok(()) => return Ok(self.scan(filter)),
            Err(e) => topic_refusal = Some(e),
        }
    }
    if filter.addresses.is_empty() {
        return Err(topic_refusal.unwrap_or(QueryError::UnwatchedTopic));
    }
    let address_refusal = |e: QueryError| match topic_refusal.clone() {
        Some(t @ QueryError::OutOfCoverage { .. }) => t,
        _ => e,
    };
    for addr in &filter.addresses {
        let Some((w, cov)) = self
            .config
            .watch
            .iter()
            .zip(self.coverage.iter())
            .find(|(w, _)| w.key == WatchKey::Address(*addr))
        else {
            return Err(address_refusal(QueryError::UnwatchedAddress(*addr)));
        };
        if !w.answers(filter) {
            return Err(address_refusal(QueryError::UnindexedTopic(w.key)));
        }
        Self::check_coverage(w, cov, filter).map_err(address_refusal)?;
    }
    Ok(self.scan(filter))
}
```

- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Coverage honesty in code.** A range that is not fully indexed is `Err(OutOfCoverage { key, covered })`, never `[]`. A wallet would read `[]` as “no events” and silently corrupt event-sourced state such as a commitment tree. It is the same principle as the #314 state-override fix: a parameter is applied or refused.
- *[Protocol & domain](01-primer.md#primer-domain)* Two ways to answer: a topic entry whose value the filter pins at one of its positions answers the whole filter, whatever addresses the filter lists; otherwise every address the filter names must be an address entry that covers the range. Either way `scan` returns every stored log the filter matches, whichever entry stored it.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let WatchKey::Topic(v) = w.key else { continue; };` is let-else with an enum pattern: skip address entries in this loop. `Some(t @ QueryError::OutOfCoverage { .. }) => t` binds the whole matched value to `t` while testing its shape.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* `address_refusal` is a closure that borrows `topic_refusal` and clones it when called. `.map_err(address_refusal)?` passes the closure itself where a function is expected. The rule it encodes: a topic entry's “not covered yet” beats an address refusal, because the caller can wait it out.

`rust/myotis-net/src/el/logindex.rs` · lines 872–890

```rust
/// Only the part of the range at/after the entry's from_block must
/// be covered — below it the entry selects no log by config, which the
/// config itself asserts (deployment block, wallet creation).
fn check_coverage(w: &WatchEntry, cov: &Coverage, filter: &LogFilter) -> Result<(), QueryError> {
    let need_from = filter.from_block.max(w.from_block);
    if need_from <= filter.to_block && !cov.contains(need_from, filter.to_block) {
        return Err(QueryError::OutOfCoverage { key: w.key, covered: *cov });
    }
    Ok(())
}

fn scan(&self, filter: &LogFilter) -> Vec<StoredLog> {
    self.logs
        .range((filter.from_block, 0)..=(filter.to_block, u32::MAX))
        .map(|(_, l)| l)
        .filter(|l| filter.matches(l))
        .cloned()
        .collect()
}
```

*[Iterators & closures](01-primer.md#primer-iterators-closures) · [Ownership & moves](01-primer.md#primer-ownership)* Only the part of the range at or after the entry's `from_block` must be covered; below it the config itself asserts there are no logs (a deployment block, a wallet's creation block). `self.logs.range((from, 0)..=(to, u32::MAX))`: tuple keys compare lexicographically, so this is a `TreeMap.subMap` scan with an inclusive per-block upper bound. `.cloned()` returns owned logs. A `Vec<&StoredLog>` would keep the index borrowed, and in the reader locked, for as long as the caller holds the answer.

#### Unwatch

`rust/myotis-net/src/el/logindex.rs` · lines 615–640

```rust
pub fn unwatch(&mut self, keys: &[WatchKey]) -> usize {
    let watch = std::mem::take(&mut self.config.watch);
    let coverage = std::mem::take(&mut self.coverage);
    let mut dropped = Vec::new();
    for (w, c) in watch.into_iter().zip(coverage) {
        if keys.contains(&w.key) {
            dropped.push(w);
        } else {
            self.config.watch.push(w);
            self.coverage.push(c);
        }
    }
    if dropped.is_empty() {
        return 0;
    }
    let (watch, coverage) = (&self.config.watch, &self.coverage);
    self.logs.retain(|_, l| {
        let (b, a, t) = (l.block_number, &l.address, &l.topics[..]);
        !dropped.iter().any(|d| d.selects(b, a, t))
            || watch.iter().zip(coverage).any(|(w, c)| w.selects(b, a, t) && c.contains(b, b))
    });
    if !walk_resumable(&self.config.watch, &self.coverage, self.cursor) {
        self.cursor = None;
    }
    dropped.len()
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* **Rebuilding two parallel vectors in place.** You cannot move a `Vec` out of a field you only reach through `&mut self`. `std::mem::take` swaps an empty `Vec` in and hands back the full one. The loop then moves each `WatchEntry` either into `dropped` or back into `self.config.watch`, keeping `coverage` parallel. Nothing is cloned.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `let (watch, coverage) = (&self.config.watch, &self.coverage);` takes shared borrows of two fields, and `self.logs.retain(…)` then borrows a third field mutably. Disjoint fields, so this compiles. (In edition 2021 a closure that wrote `self.config.watch` would also capture just that field; the local names make the split visible.)
- *[Protocol & domain](01-primer.md#primer-domain)* A log stays when no dropped entry selected it, or when a surviving entry both selects it and covers its block. A transfer from a watched wallet on a watched token belongs to both entries and outlives either one's unwatch. The fingerprint changes with the entries, which makes any backfill batch computed against the old list discard itself.

#### The snapshot file

`rust/myotis-net/src/el/logindex.rs` · lines 1020–1049

```rust
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = next_tmp_path(path);
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    };
    if let Err(e) = write() {
        // A partial temp is dead weight at full snapshot size, and the likely
        // trigger is ENOSPC — leaving it behind is what keeps the disk full.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Same reasoning, and here the temp is FULL size: a failed rename
        // (EACCES, EROFS, a dataDir symlinked across filesystems) would
        // otherwise leave a whole snapshot behind on every attempt.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Best-effort: a rename is not durable until the directory entry is. If
    // this fails the old checkpoint is still what a crash would find, which is
    // the same safe degradation as no checkpoint at all.
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `let write = || -> std::io::Result<()> { … };` is a closure with its own return type, so `?` works inside it, and one cleanup path covers all three failure points. The temp file is removed on any failure: the likely trigger is a full disk, and a leftover temp at snapshot size keeps it full. The temp name comes from `next_tmp_path`, which appends the pid and a `static SEQ: AtomicU64` counter. A `static` inside a function is still one process-wide value. Per-call names became necessary once the fsync moved out from under the index lock: two writers in one process would otherwise share a temp file, and one could truncate the other's or write into the renamed live file.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The `write_atomic` doc (lines 1015–1016) says it “is not a repo-wide primitive”. Its own module does use it alone for index files, but `myotis-engine/src/host.rs` (line 624) also calls it for a JSON file. The `SnapshotId` doc (line 1442) speaks of “one v2 snapshot file”; `of_frame` accepts v3 frames as well.

`rust/myotis-net/src/el/logindex.rs` · lines 1102–1131

```rust
struct Cursor<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.d.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).and_then(|b| b.try_into().ok())
    }
}
```

*[Lifetimes](01-primer.md#primer-lifetimes) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* Another `Cursor<'a>`, like the consensus snapshot's `Reader<'a>` in [Stop 6](06-consensus.md). The explicit `'a` ties every returned slice to the *input bytes*, not to `&mut self`, so the parser can keep slices while it keeps advancing the cursor. `fn arr<const N: usize>(&mut self) -> Option<[u8; N]>` uses **const generics**: `c.arr::<32>()` returns a `[u8; 32]`, through the standard `TryFrom<&[u8]> for [u8; N]`. Every read is checked (`checked_add`, `get`), so a truncated file yields `None`, never a panic. `parse_v2` also caps its pre-allocations (`n_watch.min(1024)`), so a hostile count cannot make it allocate gigabytes.

#### Merge

`rust/myotis-net/src/el/logindex.rs` · lines 1747–1764

```rust
// Logs: only what the merged coverage can actually serve.
let mut logs = BTreeMap::new();
for s in &mut sources {
    let taken = std::mem::take(&mut s.logs);
    for (key, log) in taken {
        let served = watch.iter().zip(coverage.iter()).any(|(w, c)| {
            w.selects(log.block_number, &log.address, &log.topics)
                && c.contains(log.block_number, log.block_number)
        });
        if served {
            logs.insert(key, log);
        }
    }
}
let config = LogIndexConfig { enabled: false, max_speed: false, backfill_paused: false, watch };
// Duplicates are impossible post-union; new() also re-validates.
let ix = Self::new(config).expect("union has unique keys");
Ok((expected, Self { coverage, logs, cursor, ..ix }))
```

*[Ownership & moves](01-primer.md#primer-ownership)* `for s in &mut sources` holds each source by `&mut`, and `std::mem::take(&mut s.logs)` moves its whole map out, leaving an empty one. Iterating `taken` by value then *moves* each log into the output, so a store that may be gigabytes is never cloned. `Self { coverage, logs, cursor, ..ix }` is struct-update syntax: it moves the remaining field, `config`, out of `ix`, which is allowed because `LogIndex` has no `Drop` impl. The merged index is canonical (every span ends at one global high, the cursor at the deepest resumable edge), because that is the only shape the appender and walker can resume from.

<details>
<summary>Deeper: finality claims and resumable walks</summary>

A checkpoint is clamped at finality: coverage above it is only verifiable against an in-memory tail record that does not survive a restart, so `serialize_clamped` leaves it out of the file. But a restart restores the beacon store from a snapshot that may be hours old, so the first finality after a start can trail the checkpoint, and the file alone cannot say its top was final. The sidecar `<index>.final` records, for one exact file (`SnapshotId`: chain tag, fingerprint, payload checksum), the finality its writer clamped it at. It never travels with an exported file.

`walk_resumable` states when the single descending walk can still finish every entry from a cursor: each present span is complete or has its low at or below the cursor, and each absent span belongs to an entry starting above the global high. When that fails, `adopt_config`, `unwatch` and `merge` drop the cursor and the appender re-seeds it at the top. The doc records that getting this backwards once wedged the walker.

</details>

<a id="f-myotis-net-src-el-activity-rs"></a>

### myotis-net/src/el/activity.rs

*library · 1,213 lines*

New since September (#691). A host watches up to 256 addresses; the follower in reader.rs (`ensure_activity_follower`) keeps the last 256 verified headers as one contiguous, parent-linked run ending at the anchored head. This module is that state and the report built from it, with no I/O. It reports two kinds of coverage. **Log**: each header's `logsBloom` is probed for the address as a log's emitter and as an indexed topic; a miss is definitive, a hit means “maybe”. **Account**: the block's access list (BAL, EIP-7928), fetched over eth/71 or snap/2 and verified against the header's `blockAccessListHash`, lists every account the block changed with its post-block values. A host then re-proves an address's state only when a block touched it. On top of that, an account proven once at block N is *followed*: each verified BAL carries its values forward, so a read near the head can be answered without a new proof.

| Lines | What happens |
|---|---|
| 1–31 | Module doc: the two kinds of coverage, and coverage honesty (every block is covered or listed as a gap, per kind). |
| 33–63 | `WINDOW` (256), `FOLLOW_MARGIN` (8), `FOLLOW_MAX_LAG` (2), `MAX_WATCHED` (256). |
| 65–165 | `BlockRecord`, `AccountValues`, `Followed`, `FollowedAnswer`, the `Carry` error and **`carry`**. |
| 167–234 | `Touch`, `Via`, `ActivityReport`; `ActivityState`'s four fields. |
| 236–330 | `apply` (additive, bounded), accessors, **`install`** (link, replace, trim). |
| 332–504 | `bals_wanted`, `set_account`, `seed`, **`advance_followed`**, `followed_answer`, small setters. |
| 506–605 | **`report`**, `gaps_of`, the bloom `probes`. |
| 607–1213 | Tests: gaps, reorgs, trimming, BAL coverage, following through BALs, ancestry. |

`rust/myotis-net/src/el/activity.rs` · lines 136–165

```rust
/// Carry `values` through block `r`, by its verified BAL.
fn carry(values: &mut AccountValues, address: &[u8; 20], r: &BlockRecord) -> Result<(), Carry> {
    let Some(changed) = &r.account else {
        return Err(if r.bal_undecodable || r.bal_hash.is_none() { Carry::Never } else { Carry::NotYet });
    };
    if changed.binary_search(address).is_err() {
        return Ok(());
    }
    let i = r.watched_changes.binary_search_by(|c| c.address.cmp(address)).map_err(|_| Carry::Never)?;
    let change = &r.watched_changes[i];
    if change.storage_written {
        return Err(Carry::Never);
    }
    if let Some(balance) = &change.balance {
        values.balance = balance.clone();
    }
    if let Some(nonce) = change.nonce {
        values.nonce = nonce;
    }
    if let Some(code_hash) = change.code_hash {
        values.code_hash = code_hash;
    }
    // EIP-161: an account left empty is not in the state, and a proof says
    // it does not exist. A credit to one that did not makes it exist.
    values.exists = !(values.nonce == 0
        && values.balance.is_empty()
        && values.code_hash == EMPTY_CODE_HASH
        && values.storage_root == EMPTY_TRIE_ROOT);
    Ok(())
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* `let Some(changed) = &r.account else { … };` matches a pattern against a *reference*. Rust's default binding modes then bind `changed` as `&Box<[[u8; 20]]>`, a borrow, so nothing moves out of the record. `binary_search` works through the box because the list is kept sorted.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `Result<(), Carry>` with a two-variant error: `NotYet` (the BAL may still arrive; stop here for now) and `Never` (this account cannot be carried through this block; go back to a proof). `.map_err(|_| Carry::Never)?` converts the `binary_search` miss into it.
- *[Protocol & domain](01-primer.md#primer-domain)* A block that wrote the account's storage is `Never`: the account's storage root changed to a value the BAL does not carry, so a carried state would be wrong. The last statement recomputes `exists` by EIP-161: an account with zero nonce, zero balance, no code and an empty storage trie is not in the state.
- *[Ownership & moves](01-primer.md#primer-ownership)* `values: &mut AccountValues` is an out-parameter. The callers clone first (`let mut next = f.values.clone();`) and keep the clone only on `Ok`, so a failed carry leaves the original untouched.

`rust/myotis-net/src/el/activity.rs` · lines 296–330

```rust
pub fn install(&mut self, segment: Vec<BlockRecord>, head: u64) {
    let Some(first) = segment.first() else { return };
    let linked_run = segment
        .windows(2)
        .all(|w| w[1].number == w[0].number.wrapping_add(1) && w[1].parent_hash == w[0].hash);
    if !linked_run || segment.last().map(|r| r.number) != Some(head) {
        return;
    }
    let links_below = first
        .number
        .checked_sub(1)
        .and_then(|below| self.records.get(&below))
        .is_some_and(|r| r.hash == first.parent_hash);
    // Replaced records hand a verified BAL on to the same block re-fetched
    // (the shallow window always repeats the kept top).
    let mut replaced = if links_below {
        self.records.split_off(&first.number)
    } else {
        self.bal_floor = head;
        std::mem::take(&mut self.records)
    };
    for mut r in segment {
        if let Some(old) = replaced.remove(&r.number).filter(|old| old.hash == r.hash) {
            if r.account.is_none() && old.account.is_some() {
                r.account = old.account;
                r.watched_changes = old.watched_changes;
            }
            r.bal_undecodable |= old.bal_undecodable;
        }
        self.records.insert(r.number, r);
    }
    let floor = head.saturating_sub(WINDOW - 1);
    self.records = self.records.split_off(&floor);
    self.advance_followed();
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* `segment: Vec<BlockRecord>` is taken by value: the reader hands the records over. `for mut r in segment` moves each one out, and `mut` on the binding lets the loop edit it before it is inserted.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **`BTreeMap::split_off(&k)`** moves every entry with key ≥ `k` into a new map and returns it, like Java's `tailMap` but transferring ownership. Here it pulls out the records the new segment replaces. When nothing links, `std::mem::take` takes them all. The last line, `self.records = self.records.split_off(&floor)`, keeps the upper part and drops the old map (the lower part) on assignment.
- *[Ownership & moves](01-primer.md#primer-ownership)* **A partial move.** `old` is an owned `BlockRecord`. `r.account = old.account;` and `r.watched_changes = old.watched_changes;` move two fields out of it, and `old.bal_undecodable` is still readable afterwards because `bool` is `Copy`. Rust tracks moves per field; the rest of `old` is dropped at the end of the `if let`. This keeps an already verified BAL when the same block (same hash) is fetched again.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `segment.windows(2).all(…)` checks the parent links pair by pair; a broken segment is dropped whole. `wrapping_add` avoids a debug-build overflow panic on a `u64::MAX` block number.

`rust/myotis-net/src/el/activity.rs` · lines 399–430

```rust
fn advance_followed(&mut self) {
    // Nothing kept yet (the follower's first window is still on its way):
    // a proof made meanwhile waits for it.
    let Some((&lowest, _)) = self.records.first_key_value() else {
        return;
    };
    let top = self.records.last_key_value().map_or(0, |(n, _)| *n);
    let target = top.saturating_sub(FOLLOW_MARGIN);
    let records = &self.records;
    self.followed.retain(|address, f| {
        match records.get(&f.number) {
            Some(r) if r.hash == f.hash => {}
            // Proven above the kept top: the follower has not fetched that
            // block yet.
            None if f.number > top => return true,
            _ => return false,
        }
        debug_assert!(f.number >= lowest);
        while f.number < target {
            let Some(r) = records.get(&(f.number + 1)) else { break };
            let mut next = f.values.clone();
            match carry(&mut next, address, r) {
                Ok(()) => {
                    *f = Followed { number: r.number, hash: r.hash, values: next };
                }
                Err(Carry::NotYet) => break,
                Err(Carry::Never) => return false,
            }
        }
        true
    });
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* `let records = &self.records;` then `self.followed.retain(|address, f| …)`: a shared borrow of one field inside a closure while `retain` holds the other field mutably. `retain` hands each entry as `&mut Followed`, and `*f = Followed { … }` overwrites it in place.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* The `return true` and `return false` statements return from the *closure* (keep or drop this entry), not from `advance_followed`. A followed account stops `FOLLOW_MARGIN` blocks below the top; the blocks above are applied per answer in `followed_answer`, so a shallow reorg replaces them without losing the account.
- *[Protocol & domain](01-primer.md#primer-domain)* The soundness argument, from `followed_answer`'s doc: the account was proven at a block the run holds under the proof's hash, the run is parent-linked to a block the beacon anchor vouches for, and every block in between has a BAL that hashes to its header's commitment. A BAL lists every account a block touched, so an account it does not list is unchanged.

`rust/myotis-net/src/el/activity.rs` · lines 514–541

```rust
pub fn report(&self, after: u64, head: u64, is_ancestor: impl Fn(u64, &[u8; 32]) -> bool) -> ActivityReport {
    let from = after.saturating_add(1);
    let to = head;
    let vouched_top = self
        .records
        .range(..=head)
        .rev()
        .find(|(_, r)| is_ancestor(r.number, &r.hash))
        .map(|(n, _)| *n);
    let base = (after, self.records.get(&after).filter(|_| vouched_top.is_some_and(|t| after <= t)).map(|r| r.hash));
    let watching = self.watching();
    if from > to {
        return ActivityReport {
            from,
            to,
            base,
            account_gaps: Vec::new(),
            log_gaps: Vec::new(),
            touched: Vec::new(),
            watching,
        };
    }
    // Kept blocks above the head (it moved back), or above the highest one
    // known to lead to it, are not covered.
    let kept: Vec<&BlockRecord> = match vouched_top {
        Some(top) if top >= from => self.records.range(from..=top).map(|(_, r)| r).collect(),
        _ => Vec::new(),
    };
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Borrowing & slices](01-primer.md#primer-borrowing) · [Protocol & domain](01-primer.md#primer-domain)* `is_ancestor: impl Fn(u64, &[u8; 32]) -> bool` lets the reader say which blocks it knows lead to the current head, without this module knowing about the anchor. Kept blocks above the highest vouched one may be on a fork the head has left, so they count as a gap until the follower re-links the run. `kept: Vec<&BlockRecord>` borrows into `self.records` for the rest of the function; the report it builds copies out what it needs (numbers, hashes, addresses), so the returned `ActivityReport` owns its data. `Box<LogsBloom>` in each record keeps the 256-byte bloom on the heap, so moving a record moves a pointer, and `Box<[[u8; 20]]>` (from `into_boxed_slice`) is a fixed-size heap array with no spare capacity.

<a id="f-myotis-net-src-el-feecache-rs"></a>

### myotis-net/src/el/feecache.rs

*library · 786 lines*

New since September (#510, #532). A per-head memo for the verified fee reads, `eth_gasPrice` / `eth_maxPriorityFeePerGas` (`FeeEstimate`) and `eth_feeHistory` (`FeeHistory`), so a wallet's fee poll is answered from memory instead of re-downloading and re-verifying blocks on the request path. The soundness argument is short: every cached value is a pure function of the anchored window top `(number, hash)` it was computed against, plus the request shape. While that top is unchanged the value is `Fresh`. After the head moves it is `Stale` for at most 5 blocks and 75 s while the reader's follower task refreshes it; the base fee moves at most 12.5% per block, so a few-blocks-old fee is a better answer than a timeout. A reorg (same number, other hash) or a head that moved backwards is a `Miss`, never stale. The module is pure state; the reader holds it in a `std::sync::Mutex<FeeCache>` and owns the computes and the follower.

`rust/myotis-net/src/el/feecache.rs` · lines 101–137

```rust
pub(crate) fn lookup(&self, head: Head, now: Instant, allow_stale: bool) -> Lookup<T> {
    let Some((at_head, value, at)) = &self.cached else {
        return Lookup::Miss;
    };
    if *at_head == head {
        return Lookup::Fresh(value.clone());
    }
    // Strictly older, and within both bounds. Same number with another
    // hash is a reorg; a HIGHER cached number means the head went
    // backwards — both are misses, never stale.
    let behind = head.0.checked_sub(at_head.0).filter(|&b| b > 0);
    let age = now.saturating_duration_since(*at);
    if let Some(behind) = behind.filter(|&b| allow_stale && b <= STALE_MAX_BLOCKS && age <= STALE_MAX_AGE) {
        return Lookup::Stale(value.clone(), Staleness { behind, age });
    }
    Lookup::Miss
}

/// Store a value computed against `head` — unless a value for a NEWER top
/// is already there and `head` is no longer the `current` one (a slow
/// compute finishing late must not regress it). A head that really moved
/// backwards (re-anchor, reorg to a shorter chain) IS current and replaces
/// it; refusing it would leave the follower recomputing it every tick. Nor
/// may a late compute for a reorged-away sibling displace the value for the
/// top that IS current.
pub(crate) fn store(&mut self, head: Head, value: T, now: Instant, current: Option<Head>) {
    if current != Some(head)
        && self
            .cached
            .as_ref()
            .is_some_and(|(h, _, _)| h.0 > head.0 || Some(*h) == current)
    {
        return;
    }
    self.cached = Some((head, value, now));
    self.failed = None;
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `Slot<T>` is generic over the cached value. Its `Default` is written by hand (lines 94–98) instead of derived, because `#[derive(Default)]` on a generic struct adds a `T: Default` bound that `FeeEstimate` need not meet. The lookup methods sit in `impl<T: Clone> Slot<T>`: the bound applies only where a value is cloned out.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* `let Some((at_head, value, at)) = &self.cached else` destructures a tuple behind a reference, so all three names are borrows; `*at_head == head` dereferences to compare. `Lookup<T>` is the generic result: `Fresh(T)`, `Stale(T, Staleness)` or `Miss`.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `head.0.checked_sub(at_head.0).filter(|&b| b > 0)` is “strictly older” as an `Option` chain: `None` when the head went backwards (underflow) or did not move. `|&b|` destructures the `&u64` that `filter` passes.
- *[Protocol & domain](01-primer.md#primer-domain)* `store` drops a late compute for a top that is no longer current when the cached value is for a higher block or for the current top. A head that really moved backwards (a re-anchor, a reorg to a shorter chain) is current, so its value is stored.

`rust/myotis-net/src/el/feecache.rs` · lines 296–325

```rust
/// Look up a history for `shape` at `top`, noting the demand and handing
/// back the shape's single-flight lock for a miss.
pub(crate) fn history_lookup(
    &mut self,
    shape: &HistoryShape,
    top: Head,
    now: Instant,
) -> (Lookup<FeeHistory>, Arc<tokio::sync::Mutex<()>>) {
    if !self.histories.contains_key(shape) && self.histories.len() >= HISTORY_SHAPES_MAX {
        // Victim preference: a shape with no build in flight (evicting one
        // drops its result and splits its single-flight), then a pinned
        // shape over a followed `latest` one (whose demand only moves on
        // wallet polls), then the least recently requested.
        if let Some(victim) = self
            .histories
            .iter()
            .min_by_key(|(s, e)| (e.lock.try_lock().is_err(), s.follows_head(), e.last_demand))
            .map(|(k, _)| k.clone())
        {
            self.histories.remove(&victim);
        }
    }
    let entry = self.histories.entry(shape.clone()).or_insert_with(|| HistoryEntry {
        slot: Slot::default(),
        lock: Arc::new(tokio::sync::Mutex::new(())),
        last_demand: now,
    });
    entry.last_demand = now;
    (entry.slot.lookup(top, now, shape.follows_head()), Arc::clone(&entry.lock))
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Clone the key so the borrow ends.** `self.histories.iter().min_by_key(…)` yields references into the map. `.map(|(k, _)| k.clone())` turns the victim's key into an owned value, which ends the shared borrow, so `self.histories.remove(&victim)` can borrow the map mutably on the next line.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* The eviction key is a tuple `(bool, bool, Instant)`; tuples order lexicographically and `false < true`. So the victim is a shape with no build in flight, then a pinned shape before a head-following one, then the least recently requested. `e.lock.try_lock().is_err()` probes whether the tokio mutex is held; the guard it would return is dropped at once.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **Two kinds of lock.** The whole `FeeCache` sits under one brief-hold `std` mutex that is never held across an `.await`. Each history shape also has an `Arc<tokio::sync::Mutex<()>>`: a lock that protects no data, used as a single-flight gate for that shape's network compute. The function returns a clone of the `Arc`, so the caller can await the gate after the `std` guard is gone.

*[Macros & attributes](01-primer.md#primer-macros) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* Two more details. `HistoryShape` derives `Eq` and `Hash` to be a map key, which `f64` cannot be (NaN is not equal to itself), so the percentiles are stored as their bit patterns via `f64::to_bits`. And line 60, `const _: () = assert!(BLOCKS_KEEP as u64 > crate::el::reader::FEE_HISTORY_MAX_BLOCKS + STALE_MAX_BLOCKS);`, is a compile-time assertion across modules (16 > 10 + 5): raising the `eth_feeHistory` clamp without growing the memo fails the build.

<a id="f-myotis-net-src-el-tx-rs"></a>

### myotis-net/src/el/tx.rs

*library · 1,131 lines · Java twin · EthTxDecoder / VerifiedRpcBackend*

Pure decoders over raw, consensus-encoded transactions. `effective_tip` reads just the fee fields, for gas-price suggestions. `decode_summary` returns every transaction field a receipt or `eth_getTransactionByHash` needs, including **sender recovery**: it rebuilds the signing preimage from the raw item bytes, for typed transactions and for legacy and EIP-155. New since September is the `eth_sendRawTransaction` gate (#360): `decode_sendable` accepts only bytes that are one strictly encoded transaction of a type this node relays, with signature values a geth peer accepts, and `check_chain` (#665) refuses a transaction signed for another chain. `effective_gas_price` and `contract_address` follow the receipt conventions.

| Lines | What happens |
|---|---|
| 1–70 | `effective_tip` (saturating `u128` math) and `scalar_u128` (a `fold` over big-endian bytes). |
| 72–188 | `TxSummary`; `decode_summary` for typed transactions 0x01–0x04; `typed_layout`, the one table of field counts (11/12/14/13) and indexes. |
| 190–243 | `decode_summary_legacy` (v = 27/28, or EIP-155 with chainId = (v − 35) / 2). |
| 245–364 | The send gate: `BLOB_SEND_REFUSAL`, the secp256k1 constants, `decode_sendable`, `check_chain`. |
| 366–399 | Access list and EIP-7702 authorization list shapes, as geth decodes them. |
| 401–488 | Helpers: `to_field`, `recover_sender`, padding; `effective_gas_price`, `contract_address`. |
| 490–1131 | Tests: the EIP-155 spec vector, signed round trips, every refusal of the send gate in its exact words. |

`rust/myotis-net/src/el/tx.rs` · lines 118–156

```rust
pub fn decode_summary(raw: &[u8]) -> Option<TxSummary> {
    let first = *raw.first()?;
    if first >= 0xc0 {
        return decode_summary_legacy(raw);
    }
    let (expected, gas_price_idx, to_idx) = typed_layout(first)?; // unknown / reserved → None
    let payload = &raw[1..];
    let items = rlp::decode(payload).ok()?;
    let list = items.as_list().ok()?;
    let raws = rlp::raw_list_items(payload).ok()?;
    if list.len() != expected {
        return None;
    }
    let chain_id = list.first()?.as_u64().ok()?;
    let nonce = list.get(1)?.as_u64().ok()?;
    let to = to_field(list.get(to_idx)?)?;
    let (gas_price, max_priority, max_fee) = match gas_price_idx {
        Some(i) => (Some(scalar_u128(list.get(i)?)?), None, None),
        None => (None, Some(scalar_u128(list.get(2)?)?), Some(scalar_u128(list.get(3)?)?)),
    };
    // gas sits just before `to`; value and data just after (every typed layout).
    let gas = list.get(to_idx - 1)?.as_u64().ok()?;
    let value = scalar_bytes(list.get(to_idx + 1)?)?;
    let input = list.get(to_idx + 2)?.as_bytes().ok()?.to_vec();
    // Signing preimage: type ‖ rlp([all fields except yParity, r, s]). The raw
    // item slices are canonical wire bytes, so re-wrapping them is byte-exact.
    let mut unsigned = Vec::new();
    for item in raws.get(..expected - 3)? {
        unsigned.extend_from_slice(item);
    }
    let mut preimage = vec![first];
    preimage.extend_from_slice(&rlp::encode_list_payload(&unsigned));
    // The typed v IS the recovery id (yParity); consensus requires 0/1, so a
    // wider value fails the whole decode (Java would emit it but its recovery
    // throws the same way — no real tx reaches here with yParity > 1).
    let v = list.get(expected - 3)?.as_u64().ok()?;
    let r_item = list.get(expected - 2)?;
    let s_item = list.get(expected - 1)?;
    let from = recover_sender(&keccak256(&preimage), r_item, s_item, Some(v));
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `let payload = &raw[1..];` borrows the bytes after the type byte; nothing is copied. `rlp::raw_list_items(payload)` returns the raw encoded bytes of each list item, and the signing preimage is `type ‖ rlp(all fields except the last three)`, rebuilt by concatenating those raw slices. Because the slices are the canonical wire bytes, re-wrapping them is byte-exact.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* Every step uses `?` on an `Option`: `raws.get(..expected - 3)?` slices without the panic that `&raws[..n]` could raise, and `.as_u64().ok()?` turns a `Result` into an `Option` first. Any malformed layout returns `None`, the Java decoder's `null`.
- *[Ownership & moves](01-primer.md#primer-ownership)* `.as_bytes().ok()?.to_vec()` copies the calldata out of the borrowed buffer. `TxSummary` therefore owns its data and needs no lifetime parameter, at the cost of one copy.

`rust/myotis-net/src/el/tx.rs` · lines 293–345

```rust
pub fn decode_sendable(raw: &[u8]) -> Result<TxSummary, String> {
    let Some(&first) = raw.first() else {
        return Err("invalid raw transaction: empty".into());
    };
    // The payload, and the index of `to` (value and data follow it).
    let (payload, to_idx) = match first {
        0xc0..=0xff => (raw, 3), // legacy: [nonce, gasPrice, gas, to, value, data, v, r, s]
        0x03 => return Err(BLOB_SEND_REFUSAL.into()),
        _ => match typed_layout(first) {
            Some((_, _, to_idx)) => (&raw[1..], to_idx),
            // geth's words (ErrTxTypeNotSupported), then which type.
            None if first <= 0x7f => {
                return Err(format!("invalid raw transaction: transaction type not supported ({first:#x})"))
            }
            None => {
                return Err("invalid raw transaction: neither an RLP list nor an EIP-2718 typed transaction".into())
            }
        },
    };
    // The lists: a typed transaction's access list after its data, and a
    // set-code transaction's authorization list after that.
    let is_list = |i: usize| first < 0xc0 && (i == to_idx + 3 || (first == 0x04 && i == to_idx + 4));
    let kind = if first >= 0xc0 { "legacy".to_string() } else { format!("type {first:#x}") };
    let malformed = || format!("invalid raw transaction: malformed {kind} transaction");
    let item = rlp::decode(payload).map_err(|_| malformed())?;
    let fields = item.as_list().map_err(|_| malformed())?;
    let canonical = fields.iter().enumerate().all(|(i, field)| match field.as_bytes() {
        Err(_) => is_list(i),
        Ok(_) if is_list(i) => false,
        // `to` and `data` are free-form bytes; every other field is an integer.
        Ok(bytes) => i == to_idx || i == to_idx + 2 || bytes.first() != Some(&0),
    });
    let lists_well_formed = first >= 0xc0
        || (fields.get(to_idx + 3).is_some_and(access_list_well_formed)
            && (first != 0x04 || fields.get(to_idx + 4).is_some_and(authorization_list_well_formed)));
    if !(canonical && lists_well_formed) {
        return Err(malformed());
    }
    let tx = decode_summary(raw).ok_or_else(malformed)?;
    if first == 0x04 && tx.to.is_none() {
        return Err("invalid raw transaction: a type 0x4 transaction cannot create a contract".into());
    }
    let v_valid = if tx.ty == 0 { matches!(tx.v, 27 | 28) || tx.v >= 35 } else { tx.v <= 1 };
    let r_valid = tx.r != [0; 32] && tx.r < SECP256K1_N;
    let s_valid = tx.s != [0; 32] && tx.s <= SECP256K1_HALF_N;
    if !(v_valid && r_valid && s_valid) {
        return Err("invalid transaction v, r, s values".into());
    }
    if tx.from.is_none() {
        return Err("invalid sender: the signature recovers no address".into());
    }
    Ok(tx)
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match first` with a range arm (`0xc0..=0xff`), a literal arm, and a nested `match` whose arms use a guard (`None if first <= 0x7f`). The refusals are geth's own words, served under the permanent `-32602`, because no retry changes the bytes.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* `is_list` and `malformed` are small local closures; `malformed` borrows `kind` and is passed by name to `map_err` and `ok_or_else`. The canonical check is one `all` over `enumerate()`, with a `match` on each field's `as_bytes()` result: lists only where lists belong, and no integer with a leading zero byte.
- *[Protocol & domain](01-primer.md#primer-domain)* **Why strict.** Only a canonical encoding makes `keccak256(raw)` the hash peers compute for the transaction, so the hash the node answers is the transaction's own. A malformed access list would also make geth drop the peer that relayed it.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `tx.r < SECP256K1_N` compares two `[u8; 32]` arrays. Arrays implement `Ord` lexicographically, which for equal-length big-endian numbers is numeric order. That gives 0 &amp;lt; r &amp;lt; n and, with `SECP256K1_HALF_N`, the EIP-2 bound s ≤ n/2, without a big-integer type.

`rust/myotis-net/src/el/tx.rs` · lines 401–432

```rust
/// A tx `to` field: 20 bytes → the target, empty → contract creation (`None`);
/// any other length is consensus-invalid → the outer `None` (bad tx).
#[allow(clippy::option_option)]
fn to_field(item: &Item) -> Option<Option<[u8; 20]>> {
    let bytes = item.as_bytes().ok()?;
    match bytes.len() {
        0 => Some(None),
        20 => {
            let mut out = [0u8; 20];
            out.copy_from_slice(bytes);
            Some(Some(out))
        }
        _ => None,
    }
}

/// Recover the 20-byte sender from the signing hash + minimal-BE `r`/`s` items
/// and the recovery id. `None` on any malformed input — never an error.
fn recover_sender(hash: &[u8; 32], r: &Item, s: &Item, recid: Option<u64>) -> Option<[u8; 20]> {
    let recid = match recid {
        Some(v @ 0..=1) => v as u8,
        _ => return None,
    };
    let mut sig = [0u8; 65];
    pad32_into(r, &mut sig[..32])?;
    pad32_into(s, &mut sig[32..64])?;
    sig[64] = recid;
    let pubkey = recover_public_key(hash, &sig).ok()?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&keccak256(&pubkey)[12..32]);
    Some(out)
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **`Option<Option<[u8; 20]>>`** keeps the two “absent” meanings apart: the outer `None` means malformed (reject the transaction), and `Some(None)` means contract creation. A caller writes `let to = to_field(…)?;`, which bails on the first and keeps the second. Java would need a sentinel or an exception. Clippy's `option_option` lint warns about this shape, so the `#[allow]` marks it as deliberate.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* The 65-byte signature is a *stack* array. `&mut sig[..32]` lends one window to `pad32_into`, which writes through it. That mutable borrow ends when the call returns, so the next line can lend a different window.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `Some(v @ 0..=1) => v as u8` matches a range and binds the value. A bad signature yields `from = None` rather than an error, as in Java.

<a id="f-myotis-net-src-el-send-check-rs"></a>

### myotis-net/src/el/send\_check.rs

*library · 197 lines*

New since September (#531). The pure half of the pre-broadcast check of `eth_sendRawTransaction`. A transaction its sender cannot pay for, or whose nonce is already used, is never mined, and the eth protocol sends no word back when a peer drops it. geth, Nethermind, Besu and Reth refuse such a transaction before answering, and wallets classify errors by geth's message text, so this module reproduces geth's two txpool verdicts in geth's order and words. The reader (`judge_read`, [Stop 14](14-el-reader.md)) supplies the sender's verified account, and judges only when the account was proven against the head's own state root. The check **fails open**: anything that stops it from judging (an undecodable or blob transaction, a stale head, a slow read, Tor-routed reads, too many reads in flight) broadcasts the transaction as before, because a node that lags the chain must never block a send.

`rust/myotis-net/src/el/send_check.rs` · lines 50–96

```rust
/// Whether a head is fresh enough to judge a send by ([`fresh_bound`]): by
/// its proven timestamp (unix seconds) against the wall clock `now_unix` — a
/// head in the future, clock skew, counts as fresh — AND by how long ago this
/// node learned it advancing, on its own monotonic clock, which a wall clock
/// set wrong cannot fake: a stalled light client's head ages there whatever
/// the wall clock says. A head never seen to advance (`adopted_ago` `None`:
/// the first after a start, a restored snapshot's) is not fresh.
pub fn head_is_fresh(now_unix: u64, head_timestamp: u64, adopted_ago: Option<Duration>, block_time: Duration) -> bool {
    let bound = fresh_bound(block_time);
    now_unix <= head_timestamp.saturating_add(bound.as_secs()) && adopted_ago.is_some_and(|ago| ago <= bound)
}

/// What the transaction may cost its sender at most: `value + gas × fee`, the
/// fee being the gas price (types 0 and 1) or the max fee per gas (types 2 and
/// 4), as geth's `tx.Cost()` reckons it. `None` for a blob transaction (type 3
/// also pays the blob fee, which the summary does not carry) and for fields
/// the summary lacks; the check then does not judge.
pub fn max_cost(tx: &TxSummary) -> Option<U256> {
    let fee = match tx.ty {
        0 | 1 => tx.gas_price?,
        2 | 4 => tx.max_fee_per_gas?,
        _ => return None,
    };
    let value = U256::try_from_be_slice(&tx.value)?;
    Some((U256::from(tx.gas) * U256::from(fee)).saturating_add(value))
}

/// geth's txpool verdict for `tx` against its sender's account, in geth's
/// order and words: `Some(message)` when the transaction can never be mined as
/// sent, `None` when it may be. A nonce above the account's is a gap a later
/// transaction fills (geth queues it). Each transaction is judged alone
/// against the balance: geth's pool also counts the sender's transactions it
/// already queued, which this node does not see, and a replacement at the
/// same nonce must still pass. A transaction whose cost is unknown (a decoded
/// blob transaction) is judged by its nonce only.
pub fn verdict(tx: &TxSummary, balance: U256, account_nonce: u64) -> Option<String> {
    if tx.nonce < account_nonce {
        return Some(format!("nonce too low: next nonce {account_nonce}, tx nonce {}", tx.nonce));
    }
    let cost = max_cost(tx)?;
    (balance < cost).then(|| {
        format!(
            "insufficient funds for gas * price + value: balance {balance}, tx cost {cost}, overshot {}",
            cost - balance
        )
    })
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Two clocks.** A head is fresh only if its proven timestamp is within two block times plus 6 s of the wall clock *and* this node saw it advance within that bound on its own monotonic clock (`adopted_ago`). A wall clock set wrong cannot fake the second test: a stalled light client's head ages there whatever the wall clock says. A head never seen to advance (`None`, such as one restored from a snapshot) is not fresh.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* In `max_cost`, `tx.gas_price?` inside a `match` arm returns `None` from the whole function when the field is missing; `_ => return None` does the same for a blob transaction, whose blob fee the summary does not carry. In `verdict`, `max_cost(tx)?` then means “cost unknown: judge the nonce only”.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `(balance < cost).then(|| format!(…))` turns a `bool` into an `Option`, building the message only when it is needed. `cost - balance` cannot underflow inside that closure, since it runs only when `balance < cost`.
- *[Protocol & domain](01-primer.md#primer-domain)* A nonce above the account's is not an error: geth queues it, and wallets send several transactions in a row. Each transaction is judged alone against the balance, because this node does not see what geth's pool already holds for the sender.

<a id="f-myotis-net-src-el-sent-tx-rs"></a>

### myotis-net/src/el/sent\_tx.rs

*library · 389 lines · Java twin · SentTxTracker / PendingNonceTracker*

Two small, pure, clock-injected state machines for the wallet's own broadcasts. `SentTxTracker` watches each broadcast (180 s TTL) until it is seen in gossip, confirmed mined, or expired; the reader uses it for rebroadcasts and to bound receipt scans, and since #531 logs a watch that expires unseen as “likely dropped”. A re-send of a transaction the network already echoed stays seen. `PendingNonceTracker` makes `eth_getTransactionCount("pending")` return `max(verified mined count, own highest nonce + 1)` for up to 90 s. Neither is proof-backed, and neither needs to be: one only gates a rebroadcast of self-signed bytes, and the other only raises a pending answer above the verified floor. Neither is ever consulted for settled tags. The file also has the `0x…` hash formatting for the send log lines.

`rust/myotis-net/src/el/sent_tx.rs` · lines 20–32

```rust
/// The watch as shared between the reader (broadcast/rebroadcast/confirm) and
/// every peer's read loop (gossip sightings). A std Mutex — every access is a
/// brief map poke, never held across I/O.
pub type SharedSentTxWatch = std::sync::Arc<std::sync::Mutex<SentTxTracker>>;

/// How long a broadcast tx stays watched (rebroadcast candidates + the
/// broadcast-head reachback) before the watch gives up. Java
/// `SENT_TX_WATCH_TTL_MS = 180_000`.
pub const SENT_TX_WATCH_TTL: Duration = Duration::from_secs(180);

/// How long a recorded pending nonce may raise `getTransactionCount("pending")`
/// before it expires unmined. Java `PENDING_NONCE_TTL_MS = 90_000`.
pub const PENDING_NONCE_TTL: Duration = Duration::from_secs(90);
```

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Ownership & moves](01-primer.md#primer-ownership)* The trackers contain no locks; their mutating methods take `&mut self`, and the *caller* decides how to share them. The watch is `SharedSentTxWatch`, an `Arc<std::sync::Mutex<SentTxTracker>>` held by the reader and by every peer's read loop (gossip sightings); the guard provides `&mut` through `DerefMut`. The nonce tracker lives inside the reader's `SentTxState`, behind `sent_txs: std::sync::Mutex<SentTxState>`. A `std` mutex fits because every access is “a brief map poke, never held across I/O”.

`rust/myotis-net/src/el/sent_tx.rs` · lines 100–115

```rust
/// Drop watches older than [`SENT_TX_WATCH_TTL`] (strictly older — at
/// exactly the boundary a watch is still live, the Java `>` mirrored).
/// Returns the evicted ones the network never echoed back: likely dropped
/// (#531), for the caller to log. Weak evidence, as a peer does not
/// announce a transaction back to the connection it came from.
pub fn evict_expired(&mut self, now: Instant) -> Vec<[u8; 32]> {
    let mut unseen = Vec::new();
    self.watched.retain(|hash, w| {
        let live = now.saturating_duration_since(w.broadcast_at) <= SENT_TX_WATCH_TTL;
        if !live && w.seen_at.is_none() {
            unseen.push(*hash);
        }
        live
    });
    unseen
}
```

*[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* `retain` takes an `FnMut` closure. This one mutably borrows the local `unseen` vector while `retain` mutably borrows `self.watched`; they are different objects, so both borrows can coexist. `*hash` copies the 32-byte key out of the map entry. The boundary is inclusive (`<=`), mirroring the Java `>` test for expiry.

`rust/myotis-net/src/el/sent_tx.rs` · lines 174–209

```rust
/// Record a broadcast tx's sender nonce. Keeps the HIGHEST nonce per
/// sender — an out-of-order lower record never lowers it; an EQUAL nonce
/// refreshes the timestamp (the Java `merge` with `>=`, mirrored).
pub fn record(&mut self, sender: [u8; 20], nonce: u64, now: Instant) {
    match self.by_sender.get_mut(&sender) {
        Some(e) if nonce >= e.nonce => {
            e.nonce = nonce;
            e.at = now;
        }
        Some(_) => {}
        None => {
            self.by_sender.insert(sender, PendingEntry { nonce, at: now });
        }
    }
}

/// The pending-tag answer: `mined_count` untouched when there's no live
/// entry; `max(mined_count, nonce + 1)` while our broadcast is unmined and
/// unexpired. An entry the chain has caught up with (`mined_count >
/// nonce`) or one older than [`PENDING_NONCE_TTL`] (strictly — the exact
/// boundary still holds, the Java `>` mirrored) is dropped. Never returns
/// below the verified mined floor.
pub fn overlay(&mut self, sender: &[u8; 20], mined_count: u64, now: Instant) -> u64 {
    let Some(e) = self.by_sender.get(sender) else {
        return mined_count;
    };
    let mined = mined_count > e.nonce;
    let expired = now.saturating_duration_since(e.at) > PENDING_NONCE_TTL;
    if mined || expired {
        self.by_sender.remove(sender);
        return mined_count;
    }
    // saturating: a u64::MAX nonce in a (self-signed) recorded tx must not
    // wrap the +1 (panic-free workspace; the value is absurd, not unsafe).
    mined_count.max(e.nonce.saturating_add(1))
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Non-lexical lifetimes across `match` arms.** In `record`, the `get_mut` borrow is live only in the arms that bind `e`. In the `None` arm nothing borrowed survives, so `insert` on the same map is allowed. In `overlay`, `e` is a shared borrow, yet `remove` compiles: on the path through the `if`, `e` is never used again. On the other path `e` is used at the last line, and no `remove` happens there. The borrow checker reasons per control-flow path.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `Some(e) if nonce >= e.nonce` followed by `Some(_) => {}`: a guarded arm and its fallback, the Java `merge` with `>=`.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `saturating_add(1)`: a nonce of `u64::MAX` must not wrap (release) or panic (debug).

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> `PendingNonceTracker::has` (line 211) says “Whether a live entry exists”. It only checks the key, so it also returns `true` for an entry past its TTL that no `overlay` call has evicted yet. It is a logging helper, so the effect is cosmetic.

## Checkpoint

14 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-els-q1"></a>

**Q1** · Multiple choice

`PoolOracle::wait` calls `self.handle.block_on(…)`. Why does the reader run revm through `request::blocking` instead of calling the executor directly inside its async method?

- **A.** `block_on` is faster on a blocking thread
- **B.** `Handle::block_on` panics when called from inside an async execution context, and a runtime worker parked in it would stall every task queued on that worker; a blocking-pool thread may block
- **C.** revm requires a `'static` closure, which only `spawn_blocking` provides
- **D.** Task-locals such as `Operation::current()` are only visible on blocking threads

[Answer →](answers.md#a-els-q1)

<a id="q-els-q2"></a>

**Q2** · Written answer

In `PoolOracle::leaf`, the async block passed to `wait` borrows `self`, `peers`, `asked` and `state_root`. `tokio::spawn` would reject such a future. Explain why it is accepted here.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-els-q2)

<a id="q-els-q3"></a>

**Q3** · Multiple choice

In the prefetch wave, each slot request starts with `let Ok(_permit) = sem.acquire().await else { … };`. What would change if it were written `let Ok(_) = sem.acquire().await else { … };`?

- **A.** Nothing; both keep the permit until the end of the block
- **B.** It would not compile, because `_` cannot appear inside `Ok(…)`
- **C.** `_` does not bind, so the permit is dropped at the end of that statement, before the request is sent, and the 48-request limit no longer limits anything
- **D.** The semaphore would be closed after the first request

[Answer →](answers.md#a-els-q3)

<a id="q-els-q4"></a>

**Q4** · Multiple choice

An address entry has `from_block` 100 and coverage \[200, 201\]. A wallet asks `eth_getLogs` for that address over \[150, 201\]. What does `LogIndex::query` return?

- **A.** `Err(OutOfCoverage { … })`, because blocks 150–199 were never processed and `[]` would falsely claim there were no events
- **B.** `Ok([])`, because no logs are stored for 150–199
- **C.** Only the logs for 200–201
- **D.** `Err(UnwatchedAddress(…))`

[Answer →](answers.md#a-els-q4)

<a id="q-els-q5"></a>

**Q5** · Multiple choice

`LogIndex::merge` iterates `for s in &mut sources` and calls `std::mem::take(&mut s.logs)`. What does that achieve?

- **A.** It clears the source map and copies its contents into the output
- **B.** It locks each source while its logs are read
- **C.** It sorts each source's logs by block number
- **D.** It moves the whole, possibly huge, map out through the `&mut` reference without cloning, leaving an empty map behind; iterating it by value then moves each log into the output

[Answer →](answers.md#a-els-q5)

<a id="q-els-q6"></a>

**Q6** · Written answer

Explain how `LogIndex::unwatch` rebuilds `config.watch` and `coverage` without cloning, and why the later `self.logs.retain(…)` may read `watch` and `coverage` while it mutates `self.logs`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-els-q6)

<a id="q-els-q7"></a>

**Q7** · Multiple choice

In `PendingNonceTracker::record`, the `None` arm of `match self.by_sender.get_mut(&sender)` calls `self.by_sender.insert(…)`. Why is that allowed while the map is borrowed by the `match`?

- **A.** It is not; the code uses `unsafe`
- **B.** Non-lexical lifetimes: the `get_mut` borrow is live only in the arms that bind `e`, and in the `None` arm no reference survives, so a new mutable borrow is fine
- **C.** `insert` takes `&self`
- **D.** The map is cloned before the `match`

[Answer →](answers.md#a-els-q7)

<a id="q-els-q8"></a>

**Q8** · Multiple choice

`tx::to_field` returns `Option<Option<[u8; 20]>>`. What does `Some(None)` mean?

- **A.** The field is malformed and the transaction must be rejected
- **B.** The recipient is the zero address
- **C.** An empty `to` field: the transaction creates a contract
- **D.** The field was not decoded yet

[Answer →](answers.md#a-els-q8)

<a id="q-els-q9"></a>

**Q9** · Written answer

The pre-broadcast check in `send_check.rs` fails open. What does that mean, why was it chosen, and how does `head_is_fresh` stop a wrong wall clock from making a stalled head look fresh?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-els-q9)

<a id="q-els-q10"></a>

**Q10** · Multiple choice

A `Slot<FeeEstimate>` holds a value computed for top `(100, hash A)` two seconds ago. The current top is `(100, hash B)`, and the caller allows stale values. What does `lookup` return?

- **A.** `Fresh`, because the block number is the same
- **B.** `Stale` with `behind` = 0
- **C.** `Stale` with `behind` = 1
- **D.** `Miss`, because the same number with another hash is a reorg, and a reorg is never served stale

[Answer →](answers.md#a-els-q10)

<a id="q-els-q11"></a>

**Q11** · Written answer

In `activity.rs`, explain what `carry` does with a block whose verified BAL lists the followed account with `storage_written` set, and why the callers clone `values` before they call `carry`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-els-q11)

<a id="q-els-q12"></a>

**Q12** · Written answer

`WireTimer<'a>` holds `&'a AtomicU64` and adds elapsed time in its `Drop`. What does the lifetime guarantee, and why do the fetch methods write `let _timer = self.wire.serial();` rather than `let _ = self.wire.serial();`?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-els-q12)

<a id="q-els-q13"></a>

**Q13** · Multiple choice

`decode_sendable` checks `tx.r < SECP256K1_N`, where both sides are `[u8; 32]`. What does that comparison do?

- **A.** It compares the arrays element by element from the first byte (lexicographic order), which for equal-length big-endian numbers is numeric order
- **B.** It compares the arrays' memory addresses
- **C.** It compares only the lengths, which are always equal
- **D.** It does not compile; arrays need a big-integer type for `<`

[Answer →](answers.md#a-els-q13)

<a id="q-els-q14"></a>

**Q14** · Multiple choice

`FeeCache::history_lookup` picks an eviction victim with `self.histories.iter().min_by_key(…).map(|(k, _)| k.clone())` and then calls `self.histories.remove(&victim)`. Why the `clone`?

- **A.** Because `HashMap::remove` takes ownership of the key
- **B.** Because `HistoryShape` is not `Copy` and keys cannot be compared by reference
- **C.** Without it, the victim would be a reference into the map, keeping the shared borrow from `iter()` alive, and the mutable borrow for `remove` would be rejected
- **D.** To keep a copy of the evicted shape for logging

[Answer →](answers.md#a-els-q14)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
