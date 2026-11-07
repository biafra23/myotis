# myotis-net, part 4: the peer pool and the trust chain

*Stop 12 · crate `myotis-net`, `src/el/`* · 9 files · 9,786 lines · about 200 minutes

How a state root a stranger handed you becomes one you may answer a wallet with, and how the engine keeps a small set of strangers worth asking. The anchor the light client fills, the verification ladder that ties a peer's root to it, the request lifetime that every read and EVM job runs inside, the peer pool that dials, ranks, benches and evicts, and four smaller files around them: the served-header window, receipts, `eth_getProof`'s pin rules, the fork watch and a cache that caches nothing. The EVM bridge, the log index and the transaction decoders moved to [Stop 13](13-el-services.md).

## Rust you will practise

- **RAII as control flow** — permits and worker counts moved into `spawn_blocking`, a `Drop` that cancels, a `Drop` that breaks an `Arc` cycle, a `Drop` that stamps a timestamp.
- **Two kinds of semaphore permit** `SemaphorePermit<'static>` from a `static` semaphore versus `OwnedSemaphorePermit` from an `Arc<Semaphore>`, and why both can travel into another task.
- **Borrowing through a guard** — deref coercion of a `MutexGuard`, copying a field out before you mutate, and `&mut *guard` to split field borrows.

## The trust chain, top to bottom

A verified state read asks a snap peer for an account or a storage slot *at some state root*, together with a Merkle-Patricia (MPT) proof. The proof only shows that the value belongs to that root. The question this stop answers is why you may believe the root. The only things the engine trusts are the light client's sync-committee signatures ([Stop 10](10-net-sync.md)) and two embedded accumulators. Everything else must be linked to them by hashes.

The link has three forms. The **fast path**: the peer's root is one the light client already recorded, so `stateRootMatch`. The **header chain**: fetch the headers from the peer's block up to the newest attested block; the newest one must hash to the attested block hash, each header must hash to its child's `parentHash`, and the oldest must carry the peer's root, so `headerChain`. And, for a read pinned to `finalized`, the proof is checked against the finalized root itself.

![Trust chain for a state read. A sync-committee BLS signature feeds the ExecAnchor, which holds the optimistic head (number, block hash, slot), the finalized block, a window of up to 8192 attested state roots and the last 128 heads. Under Gloas the light client proves only a block hash; the pool fetches the header and the anchor adopts it only if keccak of its RLP equals the hash. The header chain runs from the peer's block up to the anchor block: the anchor header's keccak must equal the attested block hash, each header's hash must equal its child's parentHash, and the peer block's stateRoot must equal the root the proof was checked against. A dashed fast path goes straight from the known-roots window to the MPT proof.](img/12-el-pool-1.svg)

*Trust flows *down* the header chain, from the attested block to the peer's block, because a `parentHash` commits a header to its parent and never to its children. The anchor is therefore the *newest* header (the optimistic head at or above the peer's block). And it is the block *hash*, not the state root, because a state root is public: a peer could copy it into a fabricated header, but cannot make another header hash to the same value. `verify.rs` holds the decision, `anchor.rs` the anchor, [`peer.rs`](11-el-transport.md#f-myotis-net-src-el-peer-rs) fetches the headers, and [the reader](14-el-reader.md) drives it.*

> [!WARNING]
> **What changed since September**<br>
>
> The header walk used to start at the *finalized* block and climb to the peer's block. That direction was unsound: a peer could name the real finalized block as the parent of a header it made up, with any state root, and the chain verified. The walk now ends at the optimistic head and checks the newest hash, and `verify.rs` carries a test for exactly that attack. Also new: the Gloas pending-hash path in the anchor, a ring of 128 recent heads, a five-second FIFO wait in front of the EVM slots, three new files (`fork_watch.rs`, `readstats.rs`, `getproof.rs`), and a pool that has nearly tripled in size (head-aware ranking, head probes, lagging eviction, scarcity backoff, DNS seeding, a BAL hunt and a Tor reserve).

<a id="f-myotis-net-src-el-request-rs"></a>

### myotis-net/src/el/request.rs

*library · 656 lines*

Gives every host-level execution-layer operation a managed lifetime: a deadline (90 s by default, never later than a parent's or a native caller's), a cancellation flag, a parent link, and a count of the blocking jobs it started. `run` and `run_registered` execute a future in that scope. When the future ends, or its deadline or a cancel fires, they cancel the scope and then **wait until every blocking job has actually returned**, because a started `spawn_blocking` closure cannot be killed. `blocking` is the single door into tokio's blocking pool for EVM work: 8 jobs run at once, up to 32 more wait in a FIFO line for at most 5 s, and anything past that is refused. The module doc says: “Permits belong to jobs, never to the caller's patience.”

`rust/myotis-net/src/el/request.rs` · lines 16–31

```rust
pub const REQUEST_BUDGET: Duration = Duration::from_secs(90);

/// Native executions running at once, each on its own Tokio blocking thread.
pub const BLOCKING_SLOTS_MAX: usize = 8;
/// How long a call waits for a free slot before it is refused. Well under
/// what a wallet gives a call (Terminal Wallet gives up at 10 s, #532) and
/// far beyond a token-balance `eth_call`, so a polling burst drains instead
/// of failing, while a cap held by long runs still refuses within seconds.
pub const BLOCKING_WAIT: Duration = Duration::from_secs(5);
/// Calls that may wait at once; past that the refusal is immediate, so a
/// flood never stacks up waiters (and the closures they carry) for the whole
/// wait before failing anyway.
pub const BLOCKING_WAITERS_MAX: usize = 32;

static BLOCKING_SLOTS: Semaphore = Semaphore::const_new(BLOCKING_SLOTS_MAX);
static BLOCKING_WAITERS: Semaphore = Semaphore::const_new(BLOCKING_WAITERS_MAX);
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `Semaphore::const_new` is a `const fn`, so a process-wide semaphore can be a plain `static` with no lazy initialization. Two of them: `BLOCKING_SLOTS` counts running jobs and `BLOCKING_WAITERS` counts tickets for the waiting line. In Java you would write `static final Semaphore`; Rust needs no class to hang it on.
- *[Protocol & domain](01-primer.md#primer-domain)* The comments carry the reason for each number: the 5 s wait sits under the 10 s a wallet (Terminal Wallet, #532) gives a call, and the 32-waiter cap stops a flood from stacking closures that would fail anyway.

`rust/myotis-net/src/el/request.rs` · lines 33–52

```rust
/// Submission metadata supplied by the native scheduler before entering the C ABI.
#[derive(Clone)]
pub struct Submission {
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}
thread_local! { static SUBMISSION: std::cell::RefCell<Option<Submission>> = const { std::cell::RefCell::new(None) }; }

pub fn submitted<T>(submission: Submission, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Submission>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SUBMISSION.with(|s| {
                s.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(SUBMISSION.with(|s| s.replace(Some(submission))));
    f()
}
```

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **`thread_local!` + `RefCell` + an RAII restore.** The Node addon's scheduler ([Stop 18](18-node.md)) calls `submitted` before it enters a request, so the request picks up the JavaScript caller's deadline and cancel flag. `SUBMISSION` is a `ThreadLocal<Optional<Submission>>`; `s.replace(Some(submission))` installs the new value and returns the old one, which the function-local `Restore` guard owns. Its `Drop` puts the old value back, even if `f` panics. That is a `try/finally` without the keyword. `self.0.take()` moves the value out of the guard's `Option`, leaving `None`, because a `&mut self` in `drop` does not let you move a field out directly.

`rust/myotis-net/src/el/request.rs` · lines 54–91

```rust
tokio::task_local! { static CURRENT: Arc<Operation>; }

pub struct Operation {
    deadline: Instant,
    submission: Option<Submission>,
    cancelled: watch::Sender<bool>,
    shutdown: watch::Receiver<bool>,
    parent: Option<Arc<Operation>>,
    active: AtomicBool,
    workers: AtomicUsize,
    drained: Notify,
}

impl Operation {
    fn new(shutdown: watch::Receiver<bool>, budget: Duration) -> Arc<Self> {
        let parent = CURRENT.try_with(Arc::clone).ok();
        let submission = SUBMISSION.with(|s| s.borrow().clone());
        let deadline = Instant::now() + budget;
        let deadline = submission
            .as_ref()
            .map_or(deadline, |s| deadline.min(s.deadline));
        Arc::new(Self {
            deadline: parent
                .as_ref()
                .map_or(deadline, |p| deadline.min(p.deadline)),
            submission,
            cancelled: watch::channel(false).0,
            shutdown,
            parent,
            active: AtomicBool::new(true),
            workers: AtomicUsize::new(0),
            drained: Notify::new(),
        })
    }

    pub fn current() -> Option<Arc<Self>> {
        CURRENT.try_with(Arc::clone).ok()
    }
```

- *[async/await & tokio](01-primer.md#primer-async)* **A task-local.** `tokio::task_local! { static CURRENT: Arc<Operation>; }` binds a value only while a particular future is polled, like a JDK 21 `ScopedValue` or a Kotlin coroutine-context element. `CURRENT.try_with(Arc::clone).ok()` passes a function path where a closure is expected and yields `None` outside any scope. Task-locals do *not* reach `spawn_blocking` threads, which is why the EVM bridge captures `Operation::current()` eagerly ([Stop 13](13-el-services.md)).
- *[Ownership & moves](01-primer.md#primer-ownership)* Three deadlines fold into one with `min`: the budget, the native submission's and the parent's. `Option::map_or(default, f)` is Kotlin's `?.let(f) ?: default`. The `Arc` clone of the parent is what keeps the parent alive while a child exists.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* `watch::channel(false).0` keeps only the sender, which then works as a `volatile boolean`: `send_replace` sets it and `borrow()` reads it. The `shutdown` field is the receiving half of the reader's own shutdown channel.

`rust/myotis-net/src/el/request.rs` · lines 93–130

```rust
pub fn check(&self) -> Result<(), String> {
    if self
        .submission
        .as_ref()
        .is_some_and(|s| s.cancelled.load(Ordering::Acquire))
    {
        return Err("request cancelled".into());
    }
    if *self.shutdown.borrow() || *self.cancelled.borrow() {
        return Err("request cancelled".into());
    }
    if Instant::now() >= self.deadline {
        return Err("request deadline exceeded".into());
    }
    if let Some(parent) = &self.parent {
        parent.check()?;
    }
    Ok(())
}

fn cancel(&self) {
    self.cancelled.send_replace(true);
}

/// Also wraps writer-lock/send waits, not just peer response timeouts.
pub async fn wait<T>(&self, future: impl Future<Output = T>) -> Result<T, String> {
    self.check()?;
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep(Duration::from_millis(10)) => self.check()?,
            // Ready is a committed result, including side effects. A late
            // cancellation must not replace it with a false failure.
            value = &mut future => return Ok(value),
        }
    }
}
```

*[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* `check` walks the parent chain recursively with `parent.check()?`, so cancelling a parent stops every child, while a child's own cancel leaves the parent alone (a test pins “an ENS attempt does not cancel AUTO”). `wait` races the future against a 10 ms timer: every tick re-runs `check`, so cancellation and deadlines take effect within about 10 ms even when the inner future never wakes. `tokio::pin!` pins the future on the stack so `&mut future` can be polled repeatedly by `select!`; dropping `wait` drops the future and abandons whatever it was doing. `biased;` polls the branches in written order instead of randomly.

`rust/myotis-net/src/el/request.rs` · lines 132–142

```rust
pub async fn settled(&self) {
    loop {
        let notified = self.drained.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.active.load(Ordering::Acquire) && self.workers.load(Ordering::Acquire) == 0 {
            return;
        }
        notified.await;
    }
}
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [async/await & tokio](01-primer.md#primer-async)* **No lost wake-ups.** The `Notified` future is created, pinned and `enable()`d *before* the atomics are checked, so a `notify_waiters()` that fires between the check and the `.await` still wakes this task. `notify_waiters` stores no permit. In Java terms: register as a waiter before testing the condition, as with `Condition.await` inside the lock. `drain`, just below it, is the same loop without the `active` test. Compare [`ExecAnchor`](#f-myotis-net-src-el-anchor-rs), which uses `notify_one` because that one *does* store a permit.

`rust/myotis-net/src/el/request.rs` · lines 157–187

```rust
struct CancelOnDrop(Arc<Operation>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
        self.0.active.store(false, Ordering::Release);
        self.0.drained.notify_waiters();
    }
}

struct Worker(Arc<Operation>);
impl Worker {
    fn new(op: Arc<Operation>) -> Self {
        let mut current = Some(&op);
        while let Some(o) = current {
            o.workers.fetch_add(1, Ordering::AcqRel);
            current = o.parent.as_ref();
        }
        Self(op)
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let mut current = Some(&self.0);
        while let Some(o) = current {
            if o.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
                o.drained.notify_waiters();
            }
            current = o.parent.as_ref();
        }
    }
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `CancelOnDrop` and `Worker` are RAII guards around an `Arc<Operation>`. `Worker::new` increments the worker count on the op and on every ancestor: the loop walks the parent chain through `Option<&Arc<Operation>>`, borrowing each link without touching reference counts. `Drop` decrements, and `fetch_sub(1, …) == 1` detects the step to zero (the method returns the value *before* the subtraction) to wake waiters.

`rust/myotis-net/src/el/request.rs` · lines 189–227

```rust
pub async fn run<T>(
    shutdown: watch::Receiver<bool>,
    budget: Duration,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    run_operation(Operation::new(shutdown, budget), future).await
}

pub async fn run_registered<T>(
    registry: &Mutex<Vec<Weak<Operation>>>,
    shutdown: watch::Receiver<bool>,
    budget: Duration,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let op = Operation::new(shutdown, budget);
    {
        let mut registry = registry
            .lock()
            .map_err(|_| "request registry unavailable".to_string())?;
        op.check()?;
        registry.retain(|o| o.strong_count() > 0);
        registry.push(Arc::downgrade(&op));
    }
    run_operation(op, future).await
}

async fn run_operation<T>(
    op: Arc<Operation>,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let guard = CancelOnDrop(Arc::clone(&op));
    let result = CURRENT
        .scope(Arc::clone(&op), op.wait(future))
        .await
        .and_then(|r| r);
    drop(guard);
    op.drain().await;
    result
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **A weak registry.** `registry: &Mutex<Vec<Weak<Operation>>>` works like a list of `WeakReference`s, so it never keeps a finished op alive. `retain(|o| o.strong_count() > 0)` prunes dead entries and `Arc::downgrade` makes a weak pointer. `op.check()?` runs *while holding the registry lock*, which closes the race with the reader's stop: a stop either sees this op in the list or this op sees the stop.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [async/await & tokio](01-primer.md#primer-async)* `CURRENT.scope(Arc::clone(&op), op.wait(future)).await.and_then(|r| r)` flattens a `Result<Result<T, String>, String>`: the outer one is “cancelled or timed out”, the inner one is the future's own answer. The explicit `drop(guard)` cancels the op *before* `drain()` waits for blocking jobs, so they see the cancel at their next check. If this whole future is dropped mid-await, the guard's `Drop` still runs.

`rust/myotis-net/src/el/request.rs` · lines 229–253

```rust
/// No unbounded Tokio blocking queue: a job reaches `spawn_blocking` only
/// with one of the [`BLOCKING_SLOTS_MAX`] slots in hand, so the pool's own
/// queue never grows. A call that finds every slot taken waits its turn —
/// FIFO, at most [`BLOCKING_WAIT`], and only while its operation is live —
/// and is refused (`native execution busy`) when the wait runs out, or at
/// once when [`BLOCKING_WAITERS_MAX`] calls are already waiting: a wallet's
/// polling burst drains, a genuine overload still fails fast. Before, a
/// burst of 8–15 `eth_call`s in one second (MetaMask polling token balances
/// for several accounts) had every call past the eighth refused and retried.
/// A started job owns both its permit and its accounting guard until the
/// closure returns, even if its future is dropped.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let op = Operation::current();
    let permit = acquire_slot(op.as_deref(), BLOCKING_WAIT).await?;
    let worker = op.map(Worker::new);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _worker = worker;
        f()
    })
    .await
    .map_err(|e| format!("native task join error: {e}"))
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency) · [async/await & tokio](01-primer.md#primer-async)* The primer's key example, now with a queue in front. `permit` and `worker` are moved into the closure, so the slot and the counts are released when the *native job* ends, not when the caller gives up. `let _permit = permit;` is a use of `permit`, so the `move` closure captures it by value, and the binding keeps it alive until the closure body returns. A bare `let _ = permit;` would not do: with edition 2021's precise closure captures, `let _ = x;` does not count as a use, so the closure would not capture the permit at all and it would stay with the caller. `T: Send + 'static` and the closure's `Send + 'static` are required because both cross to another thread and may outlive the caller. `op.as_deref()` turns `Option<Arc<Operation>>` into `Option<&Operation>` for the wait, and `op.map(Worker::new)` then moves the `Arc` into the guard.

`rust/myotis-net/src/el/request.rs` · lines 264–316

```rust
async fn acquire_slot(
    op: Option<&Operation>,
    wait: Duration,
) -> Result<SemaphorePermit<'static>, String> {
    let check = || op.map_or(Ok(()), Operation::check);
    check()?;
    if let Ok(permit) = BLOCKING_SLOTS.try_acquire() {
        return Ok(permit);
    }
    // Calls in the line besides this one (while this one holds a ticket).
    let others = |ticketed: bool| {
        let in_line = BLOCKING_WAITERS_MAX - BLOCKING_WAITERS.available_permits();
        in_line.saturating_sub(usize::from(ticketed))
    };
    let Ok(_ticket) = BLOCKING_WAITERS.try_acquire() else {
        tracing::debug!(waiting = others(false), "evm slot: line full, refused at once");
        return Err(format!(
            "native execution busy: {BLOCKING_SLOTS_MAX} running, {BLOCKING_WAITERS_MAX} waiting"
        ));
    };
    let queued = Instant::now();
    let acquire = tokio::time::timeout(wait, BLOCKING_SLOTS.acquire());
    let acquired = match op {
        Some(o) => o.wait(acquire).await?,
        None => acquire.await,
    };
    let waited_ms = u64::try_from(queued.elapsed().as_millis()).unwrap_or(u64::MAX);
    let permit = match acquired {
        Ok(Ok(permit)) => permit,
        // The static semaphore is never closed; refuse rather than panic.
        Ok(Err(_)) => return Err("native execution busy: slots closed".to_string()),
        Err(_) => {
            tracing::debug!(
                waited_ms,
                waiting = others(true),
                "evm slot: no slot freed within the wait, refused"
            );
            return Err(format!(
                "native execution busy: no slot freed within {}s",
                wait.as_secs()
            ))
        }
    };
    tracing::debug!(
        waited_ms,
        waiting = others(true),
        "evm slot: waited for a free execution slot"
    );
    // The wait checks every 10 ms; a cancellation inside the last tick, before
    // the slot landed, must not start a job.
    check()?;
    Ok(permit)
}
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **`SemaphorePermit<'static>`.** A permit borrows its semaphore. Here the semaphore is a `static`, so the borrow lasts for `'static` and the permit may move into a `spawn_blocking` closure. The pool's dial semaphore lives in an `Arc` instead, and needs `acquire_owned` for the same effect (see [`try_dial_with`](#f-myotis-net-src-el-pool-rs)).
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* A ticket from `BLOCKING_WAITERS` admits a call to the line; `let Ok(_ticket) = … else` keeps it until the function returns, so a refused or cancelled caller leaves the line automatically. Tokio's semaphore is fair: a released slot goes to the oldest `acquire()` waiter, never to a newcomer's `try_acquire`.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* Three nested results: `o.wait(…)` gives `Result<_, String>` (cancelled), `timeout` gives `Result<_, Elapsed>`, and `acquire` gives `Result<Permit, AcquireError>`. The first `?` peels the outer one; the `match` on `Ok(Ok(permit))`, `Ok(Err(_))`, `Err(_)` names the other three cases. The final `check()?` covers a cancel that landed inside the last 10 ms tick: dropping the permit on that path returns the slot.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `let check = || op.map_or(Ok(()), Operation::check);` is a closure that captures `op` (a `Copy` `Option<&Operation>`) and is called twice; `Operation::check` is passed as a function path.

*[Tests](01-primer.md#primer-testing) · [async/await & tokio](01-primer.md#primer-async)* The tests share the process-wide semaphores, so they serialise through a `static SLOT_TESTS: tokio::sync::Mutex<()>`. Two of them use `#[tokio::test(start_paused = true)]`: tokio's clock jumps from timer to timer, so the 5 s wait runs in no real time. The request deadline uses `std::time::Instant`, which the paused clock does not move, and the test comment relies on exactly that.

<a id="f-myotis-net-src-el-verify-rs"></a>

### myotis-net/src/el/verify.rs

*library · 550 lines · Java twin · VerifiedAccountQuery / VerifiedStorageQuery*

The pure decision that ties a peer-served state root to the beacon chain. It emits the exact `verifyMethod` / `failReason` tokens the Java engine, operator tooling and integration tests look for (`"verifyMethod":"headerChain"` is the success string the project's integration test expects). The fast path is `stateRootMatch`. Otherwise it returns either an early failure token, in the Java order, or a request to fetch headers from the peer's block up to the optimistic head, which `header_chain_verdict` then checks. It does no I/O. `walked_block_hashes` reuses the same downward walk for the EVM's `BLOCKHASH` opcode (#664).

`rust/myotis-net/src/el/verify.rs` · lines 71–90

```rust
/// The next step after the pre-check: either a final verdict, or the
/// caller must fetch `[peer_block ..= anchor_block]` and call
/// [`header_chain_verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderStep {
    /// A final verdict (stateRootMatch success, or an early failReason).
    Done(Verdict),
    /// Fetch the header range, then call [`header_chain_verdict`].
    NeedHeaderChain {
        /// The block the peer's state root belongs to: the FIRST header.
        peer_block: u64,
        /// The beacon-attested optimistic head at or above it: the LAST header.
        anchor_block: u64,
        /// `anchor_block`'s BLS-attested BLOCK HASH — the trust anchor the
        /// last fetched header must hash to.
        anchor_hash: [u8; 32],
        /// The beacon slot that attested `anchor_block`.
        anchor_slot: i64,
    },
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `LadderStep` is a sealed-class-style result: either a final `Verdict`, or “fetch these headers and come back”. A struct-like variant (`NeedHeaderChain { … }`) carries named fields, like a Kotlin data class nested in a sealed interface. The I/O stays with the caller, so the whole ladder is unit-testable.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `Verdict` (lines 22–40) holds `Option<&'static str>` for its tokens. They are string literals that live forever, so the struct needs no lifetime parameter, like `static final String` constants. `..Verdict::default()` in `failed` fills every field it doesn't set.

`rust/myotis-net/src/el/verify.rs` · lines 92–120

```rust
/// Run the verification ladder up to (but not including) the header fetch.
/// Mirrors `VerifiedAccountQuery.verify`'s decision tree exactly, token for
/// token. `peer_proof_valid` = "the MPT account/storage proof verified against
/// `peer_state_root`" (the caller runs the EL-A2 verifier first).
pub fn ladder_precheck(
    peer_state_root: Option<&[u8; 32]>,
    peer_proof_valid: bool,
    peer_block_number: i64,
    anchor: &ExecAnchor,
) -> LadderStep {
    // Fast path: the BLC has already attested the peer's exact state root —
    // taken only when the proof verified against it. An attested root vouches
    // for what a proof proves under it, never for a value no proof proved, so a
    // matching root with a bad proof falls through to `peerProofInvalid`.
    // Today's Rust callers verify before anchoring and always pass `true`; the
    // gate keeps this tree identical to `VerifiedAccountQuery.verify` (the same
    // gate now applies there; a failed proof used to reach its fast path) and
    // holds for any future caller.
    if peer_proof_valid {
        if let Some(root) = peer_state_root {
            if let Some(m) = anchor.find_state_root(root) {
                return LadderStep::Done(Verdict::verified(
                    "stateRootMatch",
                    m.slot as i64,
                    m.bls_verified,
                ));
            }
        }
    }
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Protocol & domain](01-primer.md#primer-domain)* `peer_state_root: Option<&[u8; 32]>` borrows the root instead of copying 32 bytes, and `anchor: &ExecAnchor` is a shared borrow, which is all `find_state_root` needs because the anchor mutates through its own mutex. The comment explains a change: the fast path is now taken only when the proof verified. An attested root vouches for what a proof proves under it, never for a value no proof proved.

`rust/myotis-net/src/el/verify.rs` · lines 122–170

```rust
    // headerChain failure ladder — token order matches VerifiedAccountQuery.verify
    // EXACTLY (a reordering would change which failReason a caller/grep sees).
    if peer_state_root.is_none() {
        return LadderStep::Done(Verdict::failed("noPeerStateRoot"));
    }
    if !peer_proof_valid {
        return LadderStep::Done(Verdict::failed("peerProofInvalid"));
    }
    // is_synced() is derived from "have a finalized exec root", so past this
    // point finalized_execution() is Some (updates only add, never remove it).
    if !anchor.is_synced() {
        return LadderStep::Done(Verdict::failed("beaconNotSynced"));
    }
    if peer_block_number <= 0 {
        return LadderStep::Done(Verdict::failed("noPeerBlockNumber"));
    }
    let peer_block = peer_block_number as u64;
    let Some(fin) = anchor.finalized_execution() else {
        return LadderStep::Done(Verdict::failed("beaconBlockUnavailable"));
    };
    if fin.block_number == 0 {
        return LadderStep::Done(Verdict::failed("beaconBlockUnavailable"));
    }
    // The freshness floor: state at or below finality is too old to answer
    // with (and its root, were it current, would have matched above).
    if peer_block <= fin.block_number {
        return LadderStep::Done(Verdict::failed("peerBlockBehindFinalized"));
    }
    // The walk ends at an attested block AT OR ABOVE the peer's, never below
    // it: a header's parent hash pins its parent, so an attested block pins
    // every header beneath it, while nothing pins a child — a walk upward
    // from an attested block accepts any header that names it as parent. So
    // the anchor is the optimistic head, and a peer block past it has nothing
    // attested above it yet.
    let Some((anchor_block, anchor_hash, anchor_slot)) =
        anchor.optimistic_anchor().filter(|&(number, _, _)| peer_block <= number)
    else {
        return LadderStep::Done(Verdict::failed("peerBlockAheadOfAnchor"));
    };
    if anchor_block - peer_block >= MAX_HEADER_CHAIN_GAP {
        return LadderStep::Done(Verdict::failed("headerChainGapTooLarge"));
    }
    LadderStep::NeedHeaderChain {
        peer_block,
        anchor_block,
        anchor_hash,
        anchor_slot: anchor_slot as i64,
    }
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **The failure ladder.** The order is load-bearing, because a caller greps for the first token. Two tokens are new: `peerBlockBehindFinalized` (state at or below finality is too old, and its root would have matched the fast path if it were current) and `peerBlockAheadOfAnchor` (nothing attested sits above the peer's block yet). The bound is inclusive of both ends: `anchor_block - peer_block >= 8192` refuses, so at most 8192 headers are ever walked.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `let Some((a, b, c)) = anchor.optimistic_anchor().filter(|&(number, _, _)| …) else { … };` combines let-else with `Option::filter`. The closure pattern `|&(number, _, _)|` destructures through the reference `filter` passes, copying out the `u64`.
- *[Ownership & moves](01-primer.md#primer-ownership)* `finalized_execution()` returns a `FinalizedExecution` by value. It is `Copy`, so the ladder holds a snapshot and no lock.

`rust/myotis-net/src/el/verify.rs` · lines 202–238

```rust
/// Pure verification of a contiguous header range (twin of
/// `VerifiedAccountQuery.verifyHeaderChain`):
/// 1. the LAST header's HASH == the attested anchor block hash — THE trust
///    anchor. It must be the block HASH, not just the state root: the hash is
///    `keccak256` of the whole header, so it pins that header completely,
///    whereas a state-root-only check lets a peer copy a PUBLIC attested
///    state root into a fabricated header.
/// 2. the FIRST header's state root == the peer-reported root (the query target);
/// 3. every consecutive pair links: `header[i].hash == header[i+1].parentHash`.
///
/// The anchor must be the NEWEST header. A parent hash commits a header to its
/// parent, never to its children, so trust flows only DOWN from the anchor:
/// the anchor pins its parent, which pins its own, and so on to the first
/// header. Anchored at the OLDEST header instead (as this walk once was),
/// nothing pins the headers above it — a peer could name the anchor as the
/// parent of a header it made up, with any state root, and pass.
pub fn verify_header_chain(
    headers: &[ChainHeader],
    expected_last_block_hash: &[u8; 32],
    expected_first_state_root: &[u8; 32],
) -> bool {
    if headers.is_empty() {
        return false;
    }
    if &headers[headers.len() - 1].hash != expected_last_block_hash {
        return false;
    }
    if &headers[0].header.state_root != expected_first_state_root {
        return false;
    }
    for pair in headers.windows(2) {
        if pair[0].hash != pair[1].header.parent_hash {
            return false;
        }
    }
    true
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Protocol & domain](01-primer.md#primer-domain)* The whole trust argument in a dozen lines, and its doc records why the direction flipped. `&headers[headers.len() - 1].hash != expected_last_block_hash` compares arrays *by value*, unlike Java's `==` on arrays; both sides are `&[u8; 32]`, and `PartialEq` on references compares what they point to. `windows(2)` yields overlapping two-element slices with no allocation. Indexing would panic on an empty slice, which is why `is_empty` comes first. The tests include `a_made_up_child_of_the_attested_block_is_rejected`, the attack the old upward walk let through.

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `walked_block_hashes` (lines 249–267) is the same check with stricter numbering, written as a chain of `?` on `Option`: `checked_sub(number)?`, `checked_add(1)?`, `usize::try_from(…).ok()?`, `headers.get(..wanted)?`. Each step returns `None` instead of panicking or wrapping, so a peer-supplied range can never overflow anything.

<a id="f-myotis-net-src-el-anchor-rs"></a>

### myotis-net/src/el/anchor.rs

*library · 1,130 lines · Java twin · BeaconSyncState*

The light client's only hand-off to the execution layer, which its doc calls “the only thing the EL trusts”. It holds the finalized execution block (slot, number, state root, hash, timestamp), the optimistic head with its parent hash, a window of up to 8192 BLS-attested `(slot, state_root)` pairs for the fast path, and a ring of the last 128 optimistic heads for `eth_getProof` and EIP-1898 block-hash pins. Since Gloas (EIP-7732) a light-client header proves only an execution *block hash*; the anchor then records it as pending, and adopts a header only when the keccak of its RLP is that hash. `sync.rs` ([Stop 10](10-net-sync.md)) writes it, and every verified read consults it.

| Lines | What happens |
|---|---|
| 1–26 | Module doc, including the Gloas chain of custody: signature → beacon header → body root → block hash → keccak → header fields. |
| 28–116 | Constants (`MAX_KNOWN_ROOTS` 8192, `RECENT_HEADS` 128) and the public value types: `RecentHeadAt`, `SlottedStateRoot`, `FinalizedExecution`, `HeadState`. |
| 118–177 | `Inner` (every field behind one lock) and `ExecAnchor` with its `Notify`. |
| 179–231 | `update_finalized` / `update_optimistic`, the pre-Gloas writers. |
| 233–342 | Gloas: `note_finalized_hash`, `note_optimistic_hash`, `pending_hashes`, `pending_changed`, `resolve_header`. |
| 344–556 | Readers, each under one lock: `is_synced` (derived), finality and its currency, the optimistic head and anchor, `optimistic_root_at`, `recent_head_at`, `attested_block_of`, `optimistic_head_state` (#531), `find_state_root`. |
| 558–683 | Free helpers over `&mut Inner`: `set_finalized`, `set_optimistic`, the ring walk, `remember_head`, `push_root`. |
| 685–1130 | Tests: the ring under reorgs and gaps, placement by hash, adoption time, the Gloas pending and resolve rules, the `Notify` permit. |

`rust/myotis-net/src/el/anchor.rs` · lines 161–177

```rust
/// Shared, mutable execution anchor. Cloneable handle over one `Mutex` — the
/// CL loop writes, the EL query path reads (both off their own threads).
pub struct ExecAnchor {
    inner: Mutex<Inner>,
    /// Wakes the pool's resolver when a hash becomes pending (`notify_one`
    /// stores a permit, so a hash noted between two waits is not missed).
    pending_changed: tokio::sync::Notify,
}

impl Default for ExecAnchor {
    fn default() -> Self {
        ExecAnchor {
            inner: Mutex::new(Inner::default()),
            pending_changed: tokio::sync::Notify::new(),
        }
    }
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* Every method takes `&self` and mutates through `Mutex<Inner>`, so one `Arc<ExecAnchor>` is shared by the consensus task, the pool's resolver and every reader: an object whose methods are all `synchronized`. The doc still says “Cloneable handle”, but the type does not derive `Clone`; it is shared through `Arc`.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **An atomic multi-field snapshot.** One lock guards the whole struct, so a number, its root and its hash always come from the same update. Several readers exist only to read two things under one lock (`finalized_execution_with_currency`, `optimistic_anchor`): two separate calls could pair a number from one update with the hash of the next, and a correct header would then fail.
- *[async/await & tokio](01-primer.md#primer-async)* The lock is a `std::sync::Mutex`, never held across `.await`. The `Notify` beside it is tokio's, and the comment notes that `notify_one` stores a permit, so a hash noted while the resolver was busy still wakes its next wait.

`rust/myotis-net/src/el/anchor.rs` · lines 233–260

```rust
/// Gloas: the light client proved `block_hash` as the finalized execution
/// block at beacon slot `slot`. Nothing about that block but its hash is
/// known yet, so it waits for [`Self::resolve_header`]. The same hash as the
/// resolved finality (payloads empty or withheld since) only moves its slot
/// forward; a finality older than the one resolved or pending is ignored.
pub fn note_finalized_hash(&self, slot: u64, block_hash: [u8; 32]) {
    let mut inner = self.inner.lock().expect("anchor mutex");
    if inner.execution_block_hash == Some(block_hash) {
        if slot > inner.finalized_slot {
            inner.finalized_slot = slot;
            if let Some(root) = inner.execution_state_root {
                push_root(&mut inner.known_roots, slot, root, true);
            }
        }
        // This IS the newest finality — unless a newer one is already pending.
        if inner.pending_finalized.is_some_and(|(s, _)| s <= slot) {
            inner.pending_finalized = None;
        }
        return;
    }
    if slot < inner.finalized_slot || inner.pending_finalized.is_some_and(|(s, _)| s > slot) {
        return;
    }
    if inner.pending_finalized.map(|(_, h)| h) != Some(block_hash) {
        self.pending_changed.notify_one();
    }
    inner.pending_finalized = Some((slot, block_hash));
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `inner` is a `MutexGuard<Inner>`. `inner.execution_block_hash` reads through `Deref`, and `push_root(&mut inner.known_roots, …)` lends one field mutably through `DerefMut`. `inner.pending_finalized.is_some_and(|(s, _)| s <= slot)` calls a by-value method on a field: that works because `Option<(u64, [u8; 32])>` is `Copy`, so the method gets a copy and the field stays. The rules: the same hash under a newer slot only moves the slot, an older finality is ignored, and a different one becomes pending and wakes the resolver.

`rust/myotis-net/src/el/anchor.rs` · lines 308–342

```rust
/// Offer an execution header fetched by one of the pending hashes. Adopted
/// only if the keccak of ITS RAW RLP is a pending hash — recomputed here,
/// not taken from the decoder's `hash` field alone — and then for every
/// pending slot that hash names (the finalized and optimistic heads can be
/// the same block). Its number and state root become the anchor's, and the
/// root joins the `stateRootMatch` window as verified: the hash was proven
/// under a sync-committee signature, and only one header hashes to it.
/// Returns whether anything was adopted; a header nobody asked for, or for a
/// head since superseded, changes nothing.
pub fn resolve_header(&self, header: &VerifiedHeader) -> bool {
    let hash = myotis_core::keccak::keccak256(&header.raw_rlp);
    if hash != header.hash {
        return false;
    }
    let (number, root, timestamp) = (header.header.number, header.header.state_root, header.header.timestamp);
    let parent = header.header.parent_hash;
    let mut inner = self.inner.lock().expect("anchor mutex");
    let mut adopted = false;
    if let Some((slot, pending)) = inner.pending_finalized {
        if pending == hash {
            set_finalized(&mut inner, slot, root, number, hash, timestamp);
            inner.pending_finalized = None;
            adopted = true;
        }
    }
    if let Some((slot, pending)) = inner.pending_optimistic {
        if pending == hash {
            let learned = inner.pending_optimistic_noted;
            set_optimistic(&mut inner, slot, number, hash, parent, root, timestamp, learned);
            inner.pending_optimistic = None;
            adopted = true;
        }
    }
    adopted
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Recompute, don't trust.** `VerifiedHeader` already carries a `hash` field set by the decoder, but `resolve_header` recomputes `keccak256(&header.raw_rlp)` and refuses a mismatch first. The fields it adopts (`number`, `state_root`, `timestamp`) come from the decoded header, so the test `a_header_is_adopted_only_under_its_own_hash` forges exactly that case: the pending hash claimed over another header's bytes.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `if let Some((slot, pending)) = inner.pending_finalized` copies the tuple out of the guard, so the block may then call `set_finalized(&mut inner, …)`. If the pattern had borrowed the field, that mutable borrow would conflict. `&mut inner` is a `&mut MutexGuard<Inner>`; **deref coercion** turns it into the `&mut Inner` the helper asks for.
- *[Protocol & domain](01-primer.md#primer-domain)* One header can resolve both pending heads, because the finalized and optimistic blocks may be the same. The optimistic one keeps the time its hash was *noted*, so a head counts as old as its proof, not as its fetch (PR #537 review).

`rust/myotis-net/src/el/anchor.rs` · lines 540–551

```rust
/// The `stateRootMatch` fast-path lookup: is `state_root` a root the beacon
/// client already recorded? Searches NEWEST-first (twin of
/// `findStateRoot`'s `descendingIterator`) so the freshest/best match wins.
pub fn find_state_root(&self, state_root: &[u8; 32]) -> Option<SlottedStateRoot> {
    let inner = self.inner.lock().expect("anchor mutex");
    inner
        .known_roots
        .iter()
        .rev()
        .find(|r| &r.state_root == state_root)
        .cloned()
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Interior mutability](01-primer.md#primer-interior-mutability)* `find` yields a reference *into* the guarded deque. Returning it would let it outlive the `MutexGuard` dropped at the closing brace, which the borrow checker rejects. `.cloned()` copies the entry out. `.rev()` searches newest-first, like Java's `descendingIterator`.

`rust/myotis-net/src/el/anchor.rs` · lines 609–644

```rust
/// [`ExecAnchor::recent_head_at`]'s walk: from the newest head in `heads` (the
/// current one) down to `number`, noting whether every step is a proven parent
/// link. The ring's numbers strictly ascend ([`remember_head`] drops every
/// head at or above a new one), so each step is the next head down; one that
/// is not the parent of the head above it — a sibling, or a gap — unlinks it
/// and everything below it.
fn recent_head_at(heads: &VecDeque<RecentHead>, number: u64) -> Option<RecentHeadAt> {
    let mut walk = heads.iter().rev();
    let mut child = walk.next()?;
    let mut linked = true;
    loop {
        if child.number == number {
            return Some(RecentHeadAt { hash: child.hash, state_root: child.state_root, linked });
        }
        let head = walk.next().filter(|h| h.number >= number)?;
        linked &= head.number + 1 == child.number && head.hash == child.parent_hash;
        child = head;
    }
}

/// Append a head to [`Inner::recent_heads`] (a re-offered head is no new
/// entry), first dropping every remembered head at or above its number: a
/// head that does not advance replaces what was remembered there, so a
/// reorged-out block is never served by number. Then cap to [`RECENT_HEADS`].
fn remember_head(heads: &mut VecDeque<RecentHead>, head: RecentHead) {
    if heads.back() == Some(&head) {
        return;
    }
    while heads.back().is_some_and(|h| h.number >= head.number) {
        heads.pop_back();
    }
    heads.push_back(head);
    while heads.len() > RECENT_HEADS {
        heads.pop_front();
    }
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Canonical is checked, not assumed.** The ring keeps heads with strictly ascending numbers: `remember_head` drops every head at or above a new one, so a reorg that steps back forgets the replaced blocks. But a sibling can replace a head *without* a step back (11A, then 12B built on an 11B the light client never reported). `recent_head_at` therefore walks down from the current head and marks a head `linked` only if every step is a proven parent link with consecutive numbers. `optimistic_root_at` serves only linked heads; [`getproof.rs`](#f-myotis-net-src-el-getproof-rs) can confirm an unlinked one against a header window.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Result, ? and panics](01-primer.md#primer-error-handling)* `let mut walk = heads.iter().rev();` is an iterator held in a variable and advanced by hand with `next()`. `walk.next().filter(|h| h.number >= number)?` stops the function with `None` once the walk passes below the wanted number. `linked &= …` keeps the flag false after the first break.
- *[Ownership & moves](01-primer.md#primer-ownership)* `remember_head` takes `head: RecentHead` by value; it is `Copy`, so `heads.back() == Some(&head)` compares a borrowed entry with a borrow of the local copy before it is pushed.

*[Protocol & domain](01-primer.md#primer-domain)* `push_root` (lines 660–683) deduplicates on `(slot, state_root)` and only ever upgrades `bls_verified`, as the Java twin does. `set_optimistic` stamps `optimistic_adopted` only when the head moves to a new, higher block, because the first head after a start comes from a restored snapshot and is no proof of freshness (#531).

<a id="f-myotis-net-src-el-pool-rs"></a>

### myotis-net/src/el/pool.rs

*library · 4,745 lines · Java twin · ChainStack dial bookkeeping / trySnapPeer*

The execution-layer peer pool keeps a live set (target 8) of snap-capable `ManagedPeer`s for verified reads. It dials candidates from four sources (pinned enodes, the persisted peer cache, discv4 and, since #539, EIP-1459 DNS trees) through the RLPx and eth handshake with at most 16 dials in flight, and records each outcome in an address backoff, a node-id blacklist or the peer cache. It **ranks** peers for each read, **benches** a peer that fails one, **strikes** and **evicts** one that keeps failing or lags behind the anchored head, and hunts harder when nobody can serve. Up to four background loops run: the dialer, a 10 s maintainer, a 1 s start-up prober that gives up after its first minute with a head, and (Gloas) the anchor resolver. Around them sit newer duties: block access list (BAL) servers for address activity (#691), the eth/69 served-header backfill, and a Tor reserve of peers it never dials directly.

| Lines | What happens |
|---|---|
| 1–146 | Module doc (dial outcome → bookkeeping), backoff constants, `is_busy_disconnect`, scarcity and hunt constants, `Enode`. `Mutex` is **tokio's**; `Instant` is `tokio::time::Instant`, so paused-clock tests work. |
| 148–313 | Pure dial policy: `pins_to_dial`, `union_pins`, `BackoffKind` / `Backoff`, scarcity scaling, `el_hunt_due`. |
| 315–636 | Pure read-side policy: bench, strike and outpace constants with a compile-time assert, `PooledPeer`, `LadderKey` / `ladder_order`, BAL predicates, `read_failure_verdict`, `persist_verdict`, `log_client_id`, `is_serving`, `QualityOutcome`. |
| 638–758 | `PoolInner`, the shared state. |
| 760–1284 | `impl PoolInner`: Tor-reserve bookkeeping (760–943), `record_outpaced` / `record_quality` / `persist_quality` (945–1086), the online signal and `prune_closed`, counts, `evict_lagging`, backoff writers. |
| 1286–1513 | `dial_one`: dial → handshake → fork-watch feed → classify (pool it, refuse as lagging, cool it off, blacklist it). |
| 1515–2048 | `PeerPool`: `PoolMemory`, `start`, `snap_peers`, the BAL API, Tor candidates and claims, counters, `set_boot_enodes`, quality sinks, `attach_*`, `stop`, `Drop`. |
| 2050–2099 | `anchor_resolver_loop` (Gloas). |
| 2101–2414 | Tor separation: the process-wide contact logs, a salted fill order, reserve load and flush, `tor_eligible`, and its tests. |
| 2416–2572 | `dialer_loop`, `dial_pins`, `try_dial` / `DialVerdict` / `try_dial_with`. |
| 2574–2738 | Served-header backfill: `BatchAnchor`, `backfill_plan`, `batch_anchored`, the spawned fetch. |
| 2740–2973 | `evict_lagging_peers`, head probes, the start-up prober, the `BlockRangeUpdate` broadcast. |
| 2975–3391 | `maintainer_loop`, the DNS walk, `bal_hunt_tick`, `dns_seed_tick`, `scarcity_redial`, address helpers, `SnapQualitySink`. |
| 3393–4745 | Tests: scarcity windows, the Tor reserve, table walks, the ladder order, eviction and persistence rules, client-id sanitising, backfill anchoring, warm start over real sockets, the hunt trigger. |

#### Picking: the read ladder

`rust/myotis-net/src/el/pool.rs` · lines 439–479

```rust
/// One peer's read-ladder sort key. FIELD ORDER IS THE POLICY — the derived
/// `Ord` sorts lexicographically:
///  1. `behind`: a peer whose fresh word says it lacks the anchored head goes
///     last, whatever else is true of it — its "0 headers" is the answer it
///     predicted (#465), and asking it first is what made a cold pool fail
///     every read;
///  2. `benched`: a peer that just failed a read trails those that did not —
///     a preference, never a veto, so the sole server stays reachable;
///  3. `coverage`: its own word or a served proof put it at our anchor
///     (Covers), near it (Near), or said nothing usable (Unknown) —
///     `peer::Coverage`'s variant order;
///  4. `unproven`: a peer that has neither served this session nor was
///     cache-Confirmed when dialed trails one that has — the persisted cache
///     now pays off on the READ path, not just the dial path (before #465 a
///     warm start dialed its proven servers first, which made them the OLDEST
///     connections and put them at the bottom of a newest-first ladder).
///
/// Ties keep the pool's newest-connection-first order — the pre-#465 ladder —
/// because `ladder_order` sorts stably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LadderKey {
    behind: bool,
    benched: bool,
    coverage: Coverage,
    unproven: bool,
}

impl LadderKey {
    fn new(benched: bool, coverage: Coverage, unproven: bool) -> LadderKey {
        LadderKey { behind: coverage == Coverage::Behind, benched, coverage, unproven }
    }
}

/// Read-ladder order over the pool's per-peer keys (newest connection first):
/// the positions STABLY sorted by [`LadderKey`]. Pure — the ordering IS the
/// rotation, so it is pinned by tests.
fn ladder_order(keys: &[LadderKey]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|&i| keys[i]);
    order
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **A derived `Ord` as policy.** `#[derive(PartialOrd, Ord)]` on a struct compares fields lexicographically in declaration order, and `false < true`. So the field order *is* the ranking: a peer that says it is behind goes last, then benched peers, then by `Coverage` (whose own derived `Ord` is `Covers < Near < Unknown < Behind`, declared in [`peer.rs`](11-el-transport.md#f-myotis-net-src-el-peer-rs)), then unproven peers. In Java you would write a `Comparator.comparing(…).thenComparing(…)` chain.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `ladder_order` sorts *indices*, not peers: `order.sort_by_key(|&i| keys[i])`. The closure copies each `LadderKey` (it is `Copy`). `sort_by_key` is stable, so ties keep the newest-connection-first order the caller passed in.

`rust/myotis-net/src/el/pool.rs` · lines 1702–1715

```rust
pub async fn snap_peers(&self) -> Vec<Arc<ManagedPeer>> {
    self.inner.prune_closed().await;
    let now = Instant::now();
    let peers = self.inner.peers.lock().await;
    let newest_first: Vec<&PooledPeer> = peers.iter().rev().collect();
    let keys: Vec<LadderKey> = newest_first
        .iter()
        .map(|p| LadderKey::new(p.is_benched(now), p.peer.coverage(), p.unproven()))
        .collect();
    ladder_order(&keys)
        .into_iter()
        .map(|i| Arc::clone(&newest_first[i].peer))
        .collect()
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [async/await & tokio](01-primer.md#primer-async)* `newest_first: Vec<&PooledPeer>` borrows *through the tokio guard* `peers`. The function returns owned `Arc::clone`s, so the guard is released when the function returns, before any caller does network I/O. Every peer stays in the list: a benched or lagging peer moves to the back, never out, so the sole server remains reachable.

#### Scoring: bench, strike, evict

`rust/myotis-net/src/el/pool.rs` · lines 509–525

```rust
/// Live verdict after a verified-read failure — pure. Returns
/// `(new_fail_count, evict)`: evict once the count reaches
/// [`READ_FAILS_EVICT`], except for the sole remaining peer.
///
/// A sole peer's failures are NOT banked (`read_fails` stays 0): a failure
/// against the only server is ambiguous — likely our own stale ask, the same
/// reason the persisted-verdict guard shields it — so banking strikes there
/// would evict it on its very next failure the instant the pool grows, before
/// it has actually failed as a NON-sole peer. It is still benched by the
/// caller (30 s) so a second peer, once found, leads the ladder.
fn read_failure_verdict(fails_before: u32, pool_len: usize) -> (u32, bool) {
    if pool_len <= 1 {
        return (0, false);
    }
    let fails = fails_before.saturating_add(1);
    (fails, fails >= READ_FAILS_EVICT)
}
```

*[Protocol & domain](01-primer.md#primer-domain)* A read failure benches the peer for 30 s (`READ_FAIL_BENCH`) and banks a strike; three in a row evict it (`READ_FAILS_EVICT`). The sole remaining peer gets no strike at all, not even a banked one, because a failure against the only server is probably our own stale request, and a banked strike would evict it the moment a second peer arrived. Being pure, the rule is tested without a network. A related rule: an *outpaced* peer (silent while a hedged read was answered by another) is benched, and from its second outpace in a row each outpace also counts as a failure, so a dead but open connection is eventually evicted (lines 380–396).

`rust/myotis-net/src/el/pool.rs` · lines 373–378

```rust
const READ_FAILS_EVICT: u32 = 3;

/// Enforce the equality the doc above calls load-bearing at COMPILE time, not
/// just in prose: tuning peercache's threshold without moving this one now
/// fails the build instead of silently reopening the re-admit churn.
const _: () = assert!(READ_FAILS_EVICT == crate::el::peercache::FAILURE_THRESHOLD);
```

*[Macros & attributes](01-primer.md#primer-macros) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* `const _: () = assert!(…);` is a **build-time** assertion: the expression is evaluated by the compiler, and tuning the peer cache's threshold without this one fails compilation. The comment above it explains why they must be equal: the live strike and the persisted cache strike then move in lockstep, so an evicted laggard is marked `Denied` in the same beat.

`rust/myotis-net/src/el/pool.rs` · lines 612–636

```rust
/// A verified-read outcome against one peer, as the pool's quality accounting
/// records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QualityOutcome {
    /// Usable, verified data came back.
    Served,
    /// The read failed and another peer served the same read: WITNESSED —
    /// evidence about this peer, banked live and persisted (under the
    /// sole-peer shield).
    Failed,
    /// The read failed and no peer served it: benched and counted toward
    /// eviction, so the live pool still rotates, but persisted NOWHERE (see
    /// `persist_verdict`).
    FailedUnwitnessed,
}

impl QualityOutcome {
    fn failed(witnessed: bool) -> QualityOutcome {
        if witnessed {
            QualityOutcome::Failed
        } else {
            QualityOutcome::FailedUnwitnessed
        }
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* **Witnessed or not (#465).** A failure is `Failed` when another peer served the same read, and `FailedUnwitnessed` when nobody did. Both bench and strike in the live pool, so it still rotates. Only a witnessed one may reach the persisted cache, and then only while another peer is live (`persist_verdict`). A cold pool once turned 14 of 27 cache entries into `snapbad` verdicts with failures that were really about our own request. `QualityOutcome::failed(witnessed)` is an associated function used as a small constructor.

`rust/myotis-net/src/el/pool.rs` · lines 1002–1048

```rust
    self.prune_closed().await;
    {
        let mut peers = self.peers.lock().await;
        let len = peers.len();
        let shielded = self.shields_bal_server(&peers, addr, Instant::now());
        if let Some(p) = peers.iter_mut().find(|p| p.addr == addr) {
            if served {
                p.benched_until = None;
                p.read_fails = 0;
                p.outpaced = 0;
                p.probe_misses = 0;
                p.served = p.served.saturating_add(1);
            } else {
                let (fails, evict) = read_failure_verdict(p.read_fails, len);
                // The pool's one recent BAL server is benched, not evicted,
                // while BALs are wanted: state reads go elsewhere first.
                if evict && !shielded {
                    tracing::info!(%addr, fails,
                        client = ?log_client_id(&p.peer.peer_hello.client_id),
                        "evicting snap peer after repeated verified-read failures — \
                         freeing the slot for a fresh candidate");
                    if let Some(evicted) = peers.iter().find(|p| p.addr == addr) {
                        self.note_evicted(&evicted.peer);
                    }
                    peers.retain(|p| p.addr != addr);
                    // NOTE the order across the next awaits: the address stays
                    // claimed in `attempted` until AFTER its backoff is
                    // recorded, so a concurrent try_dial (which checks backoff
                    // first, then the attempted claim) can never see this
                    // laggard as both un-backed-off AND un-claimed and re-dial
                    // it in the gap.
                    drop(peers);
                    self.record_backoff(addr, BackoffKind::Transient, Instant::now()).await;
                    self.attempted.lock().await.remove(&addr);
                    // fall through to the persisted verdict below
                    return self.persist_quality(addr, outcome).await;
                }
                // Not evicting: bank the strike and bench the peer so the
                // read ladder tries others first. (On the evict branch the
                // entry is retained away, so writing these would be dead.)
                p.read_fails = fails;
                p.benched_until = Some(Instant::now() + READ_FAIL_BENCH);
            }
        }
    }
    self.persist_quality(addr, outcome).await;
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Locks taken one at a time.** `prune_closed` locks `peers` itself, so it runs *before* this function takes the lock: tokio's `Mutex` is not reentrant, and locking it twice in one task deadlocks. On the evict path the guard is dropped explicitly with `drop(peers)` before the next `.await` locks `backoff` and then `attempted`.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **Ordering as a correctness argument.** The evicted address stays in `attempted` until its backoff is recorded. A concurrent `try_dial` checks the backoff first and the claim second, so it can never see the address as neither backed off nor claimed and re-dial it in the gap.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `if let Some(p) = peers.iter_mut().find(…)` holds a mutable borrow of one element. Inside the evict branch, `peers.iter().find(…)` and `peers.retain(…)` use the vector again; that compiles because `p` is not used after the borrow checker's last use of it on that path (non-lexical lifetimes). `return self.persist_quality(…).await;` returns the unit value of the awaited call.
- *[Protocol & domain](01-primer.md#primer-domain)* `shields_bal_server`: while a host follows address activity, the pool's one recent BAL server is benched rather than evicted. Its BALs are checked against header commitments, so the worst it can do is withhold, which ends the shield after 5 minutes.

#### Dialing and admission

`rust/myotis-net/src/el/pool.rs` · lines 2514–2572

```rust
async fn try_dial_with(
    inner: &Arc<PoolInner>,
    addr: SocketAddr,
    pubkey: [u8; 64],
    bal_only: bool,
) -> DialVerdict {
    if inner.blacklist.lock().await.contains(&pubkey) {
        return DialVerdict::Skipped;
    }
    // Backoff: skip while cooling off — for a window the pool's shortfall may
    // have shortened (`Backoff::blocks`, #539) — and drop the entry once it no
    // longer blocks so the map doesn't grow unbounded. The live count is read
    // before the backoff lock, never under it.
    let live = inner.peers.lock().await.len();
    {
        let mut backoff = inner.backoff.lock().await;
        if let Some(b) = backoff.get(&addr) {
            if b.blocks(live, inner.pool_cfg.target_snap_peers, Instant::now()) {
                return DialVerdict::Skipped;
            }
            backoff.remove(&addr);
        }
    }
    // Claim the address (bounded), or skip if in-flight/connected already —
    // or if the node is in the Tor reserve (never dialed directly, Tor mode on
    // or off; docs/privacy-and-tor.md §5), or was reached over Tor lately: a
    // direct dial now could pair the two by timing. The checks and the
    // direct-contact stamp happen under the claim lock, the one
    // `PeerPool::claim_for_tor` and the reserve's fill take, so a Tor claim, a
    // move into the reserve and a direct dial of one node never overlap.
    {
        let mut attempted = inner.attempted.lock().await;
        if inner.tor_reserved(&pubkey)
            || tor_quarantined(pubkey, Instant::now())
            || attempted.len() >= inner.pool_cfg.max_attempted
            || !attempted.insert(addr)
        {
            return DialVerdict::Skipped;
        }
        note_direct_contact(pubkey, Instant::now());
    }
    // Bound concurrency: acquire a dial permit (waits when saturated), then dial
    // in a task that releases it when done.
    let Ok(permit) = Arc::clone(&inner.dial_slots).acquire_owned().await else {
        inner.attempted.lock().await.remove(&addr);
        return DialVerdict::Shutdown;
    };
    let inner2 = Arc::clone(inner);
    inner.tasks.spawn(async move {
        // When the dial ends — returned, or aborted by a pool stop — the peer
        // saw us until then: a dial that did not end in the pool (refused,
        // wrong chain, lagging) is stamped here; a pooled one is live and
        // stamped again when its session ends.
        let _stamp = DirectContactOnDrop(pubkey);
        inner2.dial_one(addr, pubkey, bal_only).await;
        drop(permit);
    });
    DialVerdict::Dialed
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Lifetimes](01-primer.md#primer-lifetimes) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Owned permits.** `tokio::spawn` (here via `inner.tasks.spawn`) needs a `'static` future, which may not borrow the semaphore. `acquire_owned()` on an `Arc<Semaphore>` returns a permit that holds its own `Arc`, so it can move into the task. `drop(permit)` after the dial is `semaphore.release()` in a `finally`; it is also released if the task is aborted. Contrast `request.rs`, whose `static` semaphore gives a `'static` borrow for free.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [async/await & tokio](01-primer.md#primer-async)* `if let Some(b) = backoff.get(&addr)` borrows an entry; after the `if b.blocks(…)` test, `b` is dead, so `backoff.remove(&addr)` on the same map compiles. The `{ … }` blocks release each tokio guard before the next lock. The live count is read before the backoff lock, never under it.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `let _stamp = DirectContactOnDrop(pubkey);` is a guard whose only job is its `Drop`: when the dial task ends, returned or aborted, it stamps a direct contact with that node. The Tor path waits ten minutes after such a contact before reaching the same node, so a peer cannot pair our IP with a Tor read by timing (docs/privacy-and-tor.md).
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `DialVerdict` separates `Skipped`, `Dialed` and `Shutdown`; `try_dial` folds it to the old `bool` with `!= DialVerdict::Shutdown`, and the scarcity re-dial counts only real dials.

`rust/myotis-net/src/el/pool.rs` · lines 1482–1511

```rust
    Err(e) => {
        // Only the network-id/genesis mismatch and Status-decode errors
        // start with these prefixes (see EthSession::handshake). An
        // undecodable Status is a foreign-chain client with a divergent
        // Status shape (e.g. Polygon's bor keeps the TD field eth/69
        // removed) — treat it as incompatible so it gets the long
        // backoff + blacklist instead of a re-dial every transient
        // window. Match the PREFIX, not a substring: a peer's client id
        // is echoed into other error strings, so `contains` could be
        // steered by a hostile peer.
        let incompatible =
            e.starts_with("incompatible peer") || e.starts_with("peer Status decode");
        let busy = is_busy_disconnect(&e);
        tracing::debug!(%addr, incompatible, busy, error = %e, "el dial: failed");
        if incompatible {
            self.blacklist.lock().await.insert(pubkey);
        }
        let kind = if incompatible {
            BackoffKind::Incompatible
        } else if busy {
            // Busy retries on the transient cadence while the hunt is
            // engaged — see `backoff_window`.
            BackoffKind::Busy
        } else {
            BackoffKind::Transient
        };
        self.record_backoff(addr, kind, now).await;
        self.attempted.lock().await.remove(&addr);
    }
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Protocol & domain](01-primer.md#primer-domain)* **Classifying by prefix, not substring.** A peer's client id is echoed into some error strings, so `contains` could be steered by a hostile peer; `starts_with` on a producer-written prefix cannot. A wrong chain gets the node id blacklisted and a 10-minute backoff; `TooManyPeers` (Disconnect reason 4) gets 60 s, or 30 s while the hunt is engaged; anything else 30 s. Earlier arms of the same `match` refuse a snap peer whose announced head trails the anchored one by more than 32 blocks (`refusing_lag`, a 10-minute lagging backoff, no cache strike), and pool the rest with a fresh `ManagedPeer::spawn_serving`.

#### Backoff that shrinks with the shortfall

`rust/myotis-net/src/el/pool.rs` · lines 258–290

```rust
/// Pure: how far scarcity may shorten a window of this kind — the inbound
/// throttle for transient and busy, a longer floor for a laggard, and `None`
/// for a wrong-chain peer, whose window never shrinks.
fn scarcity_floor(kind: BackoffKind) -> Option<Duration> {
    match kind {
        BackoffKind::Transient | BackoffKind::Busy => Some(PEER_INBOUND_THROTTLE),
        BackoffKind::Lagging => Some(LAGGING_RECHECK_FLOOR),
        BackoffKind::Incompatible => None,
    }
}

/// Pure: `window` shortened by the pool's shortfall — `window × live / target`,
/// clamped to `[floor, window]`. At or above target, or with no target, the
/// window is whole; a window already under the floor is never lengthened.
fn scaled_backoff(window: Duration, live: usize, target: usize, floor: Duration) -> Duration {
    if target == 0 || live >= target {
        return window;
    }
    window
        .mul_f64(live as f64 / target as f64)
        .max(floor)
        .min(window)
}

/// Pure: how many discovery-known peers the maintainer may re-dial this tick —
/// [`SCARCITY_REDIALS_PER_TICK`] scaled by the shortfall, rounded up, so one
/// peer short costs one dial a tick and an empty pool the whole budget.
fn scarcity_budget(live: usize, target: usize) -> usize {
    if target == 0 || live >= target {
        return 0;
    }
    (SCARCITY_REDIALS_PER_TICK * (target - live)).div_ceil(target)
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* Since #539, a backoff window is not fixed. Below target it shrinks to `window × live / target`, clamped between a floor and the full window: a pool holding 2 of 8 re-dials a 10-minute laggard after 2.5 minutes. The floors come from geth: it closes a second inbound connection from the same IP within 30 s (`PEER_INBOUND_THROTTLE`), so nothing is re-dialed sooner. A wrong-chain window returns `None` from `scarcity_floor` and never shrinks. `div_ceil` rounds the per-tick dial budget up, so one peer short still costs one dial a tick. `Duration::mul_f64` scales a duration by a float.

#### Shared state and the loops

`rust/myotis-net/src/el/pool.rs` · lines 638–667

```rust
struct PoolInner {
    tasks: super::tasks::Tasks,
    key: Arc<NodeKey>,
    /// Every RLPx session this pool dials counts its bytes here (EL layer).
    traffic: Arc<crate::traffic::TrafficMeter>,
    local_pubkey: [u8; 64],
    cfg: Arc<EthConfig>,
    pool_cfg: PoolConfig,
    peers: Mutex<Vec<PooledPeer>>,
    /// Addresses dialed and not yet failed — in-flight OR connected. Prevents
    /// re-dialing a live peer or racing two dials to the same address.
    attempted: Mutex<HashSet<SocketAddr>>,
    /// Address → its cooling-off record; the pool's shortfall may shorten
    /// the window it blocks for ([`Backoff::blocks`]). Shared through
    /// [`PoolMemory`], so it outlives an idle pause.
    backoff: Arc<Mutex<HashMap<SocketAddr, Backoff>>>,
    /// Node ids of wrong-chain peers, never dialed again this run. Shared
    /// through [`PoolMemory`], so it outlives an idle pause.
    blacklist: Arc<Mutex<HashSet<[u8; 64]>>>,
    /// Peers evicted from `peers` whose sessions may still be open — a read or
    /// a detached clearnet push can hold the `Arc` for a while. Counted as
    /// live for Tor until closed, then stamped as a direct contact
    /// ([`PoolInner::sweep_lingering`]).
    lingering: std::sync::Mutex<Vec<([u8; 64], std::sync::Weak<ManagedPeer>)>>,
    /// Proven snap-capable peers, persisted for warm-start on the next run.
    cache: Mutex<ElPeerCache>,
    /// The Tor reserve (`el::torreserve`): verified peers the pool never dials
    /// directly, persisted beside the cache. Locked after `attempted` and
    /// `cache` when held with them, never across an await.
    tor_reserve: std::sync::Mutex<TorReserve>,
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [async/await & tokio](01-primer.md#primer-async)* Two mutex types side by side. `Mutex` (imported from tokio) guards state the pool locks around awaits; `std::sync::Mutex` guards state that is only touched in synchronous code, like `lingering` and `tor_reserve`, and the comment on `tor_reserve` fixes its lock order. Flags are atomics, and immutable configuration is plain data.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `backoff` and `blacklist` are `Arc<Mutex<…>>` because they are shared with `PoolMemory`, which survives an idle pause. On resume, `start` keeps only wrong-chain windows: the others are measured on a monotonic clock that stands still while a phone sleeps, so an overnight pause would hand back windows that never ran down.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `lingering: Vec<([u8; 64], std::sync::Weak<ManagedPeer>)>` tracks evicted peers whose sessions may still be open (a read may still hold the `Arc`). A `Weak` observes without keeping the peer alive; `weak.upgrade()` in `sweep_lingering` answers whether it still exists.

`rust/myotis-net/src/el/pool.rs` · lines 1582–1592

```rust
// Both the discv4 dialer and the maintainer dial through one shared
// concurrency budget — and so does a host's seed-pin push.
let dial_slots = Arc::new(Semaphore::new(pool_cfg.max_concurrent_dials));
// A memory handed over by a paused pool keeps its wrong-chain verdicts
// only (see `PoolMemory`). Uncontended: the previous pool is stopped,
// and nothing else holds the map; a first pool's memory is empty.
if let Ok(mut backoff) = memory.backoff.try_lock() {
    backoff.retain(|_, b| retain_across_pause(b.kind));
}
let mut cache = cache;
let tor_reserve = load_tor_reserve(&mut cache, &boot_enodes);
```

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* One `Arc<Semaphore>` is the dial budget for the dialer, the maintainer and a host's seed-pin push alike. `let mut cache = cache;` moves the by-value parameter into a mutable binding, because a parameter is immutable unless declared `mut`. `try_lock()` on the shared backoff map never waits; the comment explains why it cannot be contended here. A few lines further, `head_source.map(|f| -> AnchorSource { Arc::from(f) })` converts the caller's `Box<dyn Fn() -> Option<(u64, [u8; 32])> + Send + Sync>` into an `Arc<dyn Fn …>`, so every pooled peer's read loop can share the same closure: a `Supplier` that keeps the pool independent of the anchor type. Then three loops are spawned, each with its own `Arc::clone(&inner)`.

`rust/myotis-net/src/el/pool.rs` · lines 3040–3063

```rust
let serving = inner.count_where(counts_for_hunt).await;
// target == 0 = maintainer deliberately idle: an empty pool is the
// EXPECTED state — never engage the hunt (Java maintainSnapPeers twin).
if inner.pool_cfg.target_snap_peers == 0 {
    zero_since = None;
    inner.hunting.store(false, Ordering::Relaxed);
    continue;
}
if serving > 0 {
    zero_since = None;
    if inner.hunting.swap(false, Ordering::Relaxed) {
        tracing::info!(serving, live, "EL hunt disengaged — snap peer serving again");
    }
} else {
    zero_since.get_or_insert_with(Instant::now);
}
let hunting = el_hunt_due(serving, zero_since, Instant::now());
if hunting && !inner.hunting.swap(true, Ordering::Relaxed) {
    tracing::info!(stall_secs = EL_HUNT_STALL.as_secs(),
        "EL hunt engaged — serving pool empty past the stall window \
         (busy peers retry on the transient cadence; below target, backoff \
         windows shrink with the shortfall — floors: 30 s transient/busy, \
         60 s lagging)");
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **The EL hunt.** The maintainer keys its emergency mode on peers that *could* serve (`counts_for_hunt`: not benched and not known to be behind), not on the live count, because eight lagging peers once held every slot “through days of failing reads” while “live” looked healthy. `zero_since` is a local of the loop: `get_or_insert_with` starts the stall clock once, and the hunt engages after 60 s. `inner.hunting.swap(true, …)` returns the old value, so the INFO line is logged only on the transition. The rest of the tick (lines 2986–3133): backfill served headers, evict lagging peers, probe unknown heads, broadcast the eth/69 range, prune, balance the Tor reserve, feed the fork watch, re-dial pins, run the BAL hunt, refill from the cache, then the scarcity re-dial and the DNS batch.

`rust/myotis-net/src/el/pool.rs` · lines 2064–2099

```rust
async fn anchor_resolver_loop(inner: Arc<PoolInner>, anchor: Arc<ExecAnchor>) {
    let mut rotation = 0usize;
    loop {
        let pending = anchor.pending_hashes();
        if pending.is_empty() {
            anchor.pending_changed().await;
            continue;
        }
        inner.prune_closed().await;
        let peers: Vec<Arc<ManagedPeer>> =
            inner.peers.lock().await.iter().map(|p| Arc::clone(&p.peer)).collect();
        for hash in &pending {
            for i in 0..peers.len().min(RESOLVE_PEERS_PER_ROUND) {
                let peer = &peers[rotation.wrapping_add(i) % peers.len()];
                let served =
                    tokio::time::timeout(RESOLVE_TIMEOUT, peer.get_block_headers_by_hash(hash, 1)).await;
                if let Ok(Ok(headers)) = served {
                    if headers.iter().any(|vh| vh.hash == *hash && anchor.resolve_header(vh)) {
                        tracing::debug!(hash = ?&hash[..8], peer = %peer.addr(),
                            "execution anchor: header resolved by hash");
                        break;
                    }
                }
            }
            rotation = rotation.wrapping_add(1);
        }
        if anchor.pending_hashes().is_empty() {
            continue;
        }
        tracing::debug!(peers = peers.len(), "execution anchor: hash still unresolved — retrying");
        tokio::select! {
            _ = anchor.pending_changed() => {}
            _ = tokio::time::sleep(RESOLVE_RETRY) => {}
        }
    }
}
```

*[async/await & tokio](01-primer.md#primer-async) · [Protocol & domain](01-primer.md#primer-domain)* The Gloas resolver needs no trust in the peer: it asks up to four peers for the header by hash, with a 5 s timeout each, and hands every answer to `anchor.resolve_header`, which recomputes the keccak. The peers are snapshotted as `Vec<Arc<ManagedPeer>>` so no lock is held across the requests. `tokio::select!` between `pending_changed()` and a 2 s sleep retries an unserved hash, unless a newer one arrives first. `headers.iter().any(|vh| … && anchor.resolve_header(vh))` relies on `&&` short-circuiting, so only a header with the right hash is offered.

`rust/myotis-net/src/el/pool.rs` · lines 2643–2664

```rust
/// Validate an ascending backfill batch before admission: exact numbering
/// `[from..from+len)`, internal parent-hash chain, and the top anchored per
/// [`BatchAnchor`]. Any failure rejects the WHOLE batch.
fn batch_anchored(
    headers: &[crate::el::eth::messages::VerifiedHeader],
    from: u64,
    anchor: &BatchAnchor,
) -> bool {
    let Some(top) = headers.last() else { return false };
    for (i, h) in headers.iter().enumerate() {
        if h.header.number != from + i as u64 {
            return false;
        }
        if i > 0 && h.header.parent_hash != headers[i - 1].hash {
            return false;
        }
    }
    match anchor {
        BatchAnchor::Head(h) => top.hash == *h,
        BatchAnchor::ChildParent(p) => top.hash == *p,
    }
}
```

*[Protocol & domain](01-primer.md#primer-domain)* The served-header backfill uses the same trust rule as the read ladder. A batch enters the eth/69 window only if its numbers are exact, its parent hashes chain, and its *top* hash equals either the beacon-anchored head hash or the parent hash of the held header just above it. The head probe reuses this gate with a batch of one: a peer that returns the anchored header proves it holds the head, even on eth/68, which announces no number.

#### Shutdown

`rust/myotis-net/src/el/pool.rs` · lines 2009–2048

```rust
    /// Stop the pool: flush the peer cache, abort the background tasks, and drop
    /// all held peers (closing them).
    pub async fn stop(&self) {
        // Close admission and join parent loops AND their dial/backfill/send
        // jobs before flushing caches or clearing peers. No late dial can
        // publish a fresh peer after stop has cleared the set.
        self.inner.tasks.stop().await;
        self.inner.cache.lock().await.flush();
        let mut peers = self.inner.peers.lock().await;
        for peer in peers.iter() { peer.peer.close().await; }
        // Their direct sessions end here: stamp them, and every evicted one
        // still tracked, so a resumed pool's Tor path keeps clear of them for
        // the full window (the records outlive this pool; its lists do not).
        let now = Instant::now();
        for peer in peers.iter() {
            note_direct_contact(peer.peer.peer_pubkey(), now);
        }
        peers.clear();
        drop(peers);
        self.inner.stamp_lingering(now);
        self.inner.close_tor_reserve();
    }
}

impl Drop for PeerPool {
    fn drop(&mut self) {
        self.inner.tasks.abort();
        // A pool dropped without `stop`: its sessions close as their `Arc`s
        // drop, so stamp them now, as `stop` does (best effort: a locked set
        // is skipped rather than awaited in a destructor).
        let now = Instant::now();
        if let Ok(peers) = self.inner.peers.try_lock() {
            for peer in peers.iter() {
                note_direct_contact(peer.peer.peer_pubkey(), now);
            }
        }
        self.inner.stamp_lingering(now);
        self.inner.close_tor_reserve();
    }
}
```

> [!WARNING]
> **An `Arc` cycle, and how it is broken**<br>
>
> The loops each own an `Arc<PoolInner>`, and `PoolInner` owns the `Tasks` that own those loops' handles ([`tasks.rs`](11-el-transport.md#f-myotis-net-src-el-tasks-rs)). While the loops run, the reference count can never reach zero, so `Tasks`' own `Drop` would never fire. `Drop for PeerPool`, the outer handle, breaks the cycle by aborting the tasks. Without it, dropping the pool would leave its loops running forever. `stop()` holds the tokio `peers` guard across `peer.close().await`, which is legal for an async mutex and would not be for a `std` one. `Drop` cannot `.await`, so it uses `try_lock()` and skips a locked set rather than block in a destructor.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The doc on `all_pins` (line 800) says “the network's, then the host's that add an address”, but `union_pins` puts the host's pins first and lets them win on a shared address, as its own doc says. The doc on `PeerPool` (lines 1515–1516) mentions only “the dialer task”; `start` spawns three loops.

*[Protocol & domain](01-primer.md#primer-domain)* Design choices recorded in the file: pins are dialed directly rather than seeded into the cache, so a disabled cache cannot swallow them and an earned snap flag is never downgraded; a pin is re-dialed when the pool is below target, when the anchor has a head and nobody serves at it, or, above target, only if it once served (`pins_to_dial`); the BAL hunt may take exactly one slot past the target, and only for a peer speaking eth/71 or snap/2, checked under the same lock that inserts it; client ids in logs are stripped of control characters and cut to 64 characters (`log_client_id`), because a `\n` in a peer-controlled string would forge a log line.

<a id="f-myotis-net-src-el-served-rs"></a>

### myotis-net/src/el/served.rs

*library · 456 lines · Java twin · ServedHeaderWindow / ServeStats*

A bounded, shared, per-network store of recent block headers that the node can **serve** to other peers. It backs the eth/69 advertised block range and counts inbound demand. `advertise()` names only blocks actually held, because a peer that asks inside the advertised range and gets nothing scores us down. A self-verified mainnet genesis header is held outside the window, so genesis fork probes get a real answer. The pool fills the window with the anchored backfill you just saw.

`rust/myotis-net/src/el/served.rs` · lines 101–122

```rust
#[derive(Default)]
struct Inner {
    /// number → (hash, parentHash, raw header RLP), bounded to the newest window.
    /// The parent hash lets the backfill anchor a downward batch to the held run
    /// without re-decoding the stored RLP.
    by_number: BTreeMap<u64, ([u8; 32], [u8; 32], Vec<u8>)>,
    /// hash → number, kept in lockstep with `by_number` (fork probes ask by hash).
    by_hash: BTreeMap<[u8; 32], u64>,
}

/// Bounded shared store of recent servable headers.
pub struct ServedHeaders {
    inner: Mutex<Inner>,
    /// Live-settable window size (the Settings knob adjusts it, mirroring the
    /// Java `ServedHeaderWindow.setMaxWindow`). Read on every put.
    window: AtomicU64,
    /// Genesis header (hash, raw RLP) — always servable for fork probes, held
    /// OUTSIDE the sliding window and never part of the advertised range
    /// (mirrors the Java window's genesis seeding). None where we embed no
    /// genesis bytes (non-mainnet, tests).
    genesis: Option<([u8; 32], Vec<u8>)>,
}
```

`rust/myotis-net/src/el/served.rs` · lines 180–198

```rust
/// Record a header we hold (raw wire RLP, hash recomputed at decode).
/// Genesis (number 0) is not tracked — the range never claims it and the
/// Rust EL has no embedded genesis header to serve.
pub fn put(&self, number: u64, hash: [u8; 32], parent_hash: [u8; 32], raw_rlp: Vec<u8>) {
    if number == 0 || raw_rlp.len() > MAX_SERVED_HEADER_BYTES {
        return;
    }
    let mut g = match self.inner.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some((old_hash, _, _)) = g.by_number.insert(number, (hash, parent_hash, raw_rlp)) {
        if old_hash != hash {
            g.by_hash.remove(&old_hash); // reorg: drop the stale hash key
        }
    }
    g.by_hash.insert(hash, number);
    Self::evict_locked(&mut g, self.window.load(Ordering::Relaxed));
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Poison recovery.** If a thread panicked while holding a `std` lock, `lock()` returns `Err(poisoned)`, and `poisoned.into_inner()` takes the guard anyway. Java has no counterpart. `fork_watch.rs` chooses the other policy: a poisoned lock there means “no answer”.
- *[Ownership & moves](01-primer.md#primer-ownership)* `raw_rlp: Vec<u8>` was taken by value and is *moved* into the map without a copy. `insert` returns the previous tuple, which reveals a reorg (a different hash at the same number). Both indexes change under one lock, so they stay in step.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* `window: AtomicU64` is a lock-free configuration knob, read on every `put`. `evict_locked(g: &mut Inner, …)` encodes “caller holds the lock” in its signature: it can only be called with data taken out of a guard.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `#[derive(Clone)] ServeContext` holds two `Arc`s, so cloning copies two pointers, not the window.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The module doc (lines 11–13) still says that “unlike Java no genesis header RLP is embedded to serve”, and the doc on `put` (lines 181–182) says “the Rust EL has no embedded genesis header to serve”. Both are out of date: `MAINNET_GENESIS_HEADER_RLP_HEX` is embedded, self-checked by `mainnet_genesis`, and served by `run_from(0, …)` and `by_hash`.

<a id="f-myotis-net-src-el-receipt-rs"></a>

### myotis-net/src/el/receipt.rs

*library · 169 lines · Java twin · eth.messages.Receipt*

Decodes one consensus-encoded receipt (a legacy RLP list or an EIP-2718 typed envelope) into status, cumulative gas, bloom and logs. It is pure and lenient, because the caller must already have verified the bytes against a trusted `receiptsRoot`. Since September it reads the receipt in place through an RLP view and copies out only what it returns (#454).

`rust/myotis-net/src/el/receipt.rs` · lines 45–78

```rust
pub fn decode(raw: &[u8]) -> Result<DecodedReceipt, String> {
    let Some(&first) = raw.first() else {
        return Err("receipt bytes are empty".to_string());
    };
    // RLP list → legacy receipt; else EIP-2718 envelope: type byte + payload.
    let (ty, payload) = if first >= 0xc0 { (0, raw) } else { (first, &raw[1..]) };
    let top = rlp::View::new(payload).map_err(|e| format!("receipt RLP: {}", e.0))?;
    let mut fields = top.as_list().map_err(|e| format!("receipt RLP: {}", e.0))?;
    let (Some(status_or_root), Some(cumulative_gas_used), Some(logs_bloom), Some(log_items)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        let count = top.as_list().map_or(0, Iterator::count);
        return Err(format!("receipt: expected 4 fields, got {count}"));
    };
    let status_or_root = status_or_root.as_bytes().map_err(|e| format!("receipt status: {}", e.0))?;
    // A <= 1-byte first field is the status; a longer one (32 bytes) is the
    // pre-Byzantium intermediate stateRoot — no status bit.
    let (has_status, success) = if status_or_root.len() <= 1 {
        (true, status_or_root.last().is_some_and(|&b| b != 0))
    } else {
        (false, false)
    };
    let cumulative_gas_used = cumulative_gas_used
        .as_u64()
        .map_err(|e| format!("receipt cumulativeGasUsed: {}", e.0))?;
    let logs_bloom =
        logs_bloom.as_bytes().map_err(|e| format!("receipt logsBloom: {}", e.0))?.to_vec();
    let log_items = log_items.as_list().map_err(|e| format!("receipt logs: {}", e.0))?;
    let mut logs = Vec::new();
    for item in log_items {
        logs.push(decode_log(item)?);
    }
    Ok(DecodedReceipt { ty, has_status, success, cumulative_gas_used, logs_bloom, logs })
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* `let Some(&first) = raw.first() else { … };` destructures through a reference and copies the byte. The `if` expression returns a tuple holding a *borrowed* slice (`&raw[1..]`), so no bytes are copied.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `rlp::View` ([Stop 4](04-core.md)) is a borrowed view over `payload`, and `as_list()` returns an iterator of child views rather than a `Vec`. Four `fields.next()` calls are matched as one tuple pattern with let-else. On failure the list is walked again just to count it for the message: `map_or(0, Iterator::count)`.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Ownership & moves](01-primer.md#primer-ownership)* `.map_err(|e| format!(…, e.0))?` converts the RLP error tuple struct into a `String`. `.to_vec()` is where bytes are finally copied, so the returned `DecodedReceipt` owns its data and does not borrow the input buffer. A first field of at most one byte is a status; a 32-byte one is a pre-Byzantium state root.

<a id="f-myotis-net-src-el-getproof-rs"></a>

### myotis-net/src/el/getproof.rs

*library · 411 lines*

The pure half of `eth_getProof` (EIP-1186): which state root a request may be proven at, and the answer types. An `eth_getProof` answer carries no root, so a client checks it against the `stateRoot` of the block it named. Other reads may answer a near-head number from head state; a proof at the wrong root would be a well-formed answer that fails the client's check, which is indistinguishable from a forgery. So a proof is served only at a root the node holds *attested for exactly that block*: the optimistic head, one of the last 128 heads that the current head builds on, the finalized block, or a block hash the anchor places. Anything else is refused, permanently below the head and retryably above it. The I/O is in the reader ([Stop 14](14-el-reader.md)).

`rust/myotis-net/src/el/getproof.rs` · lines 106–123

```rust
/// Resolve the block a request names to the root it is proven at, by the pin
/// rules above. `head` is the optimistic head's `(number, state_root)`, read
/// together; `finalized` the beacon-finalized block; `recent` the root of a
/// number among the recent heads (`ExecAnchor::optimistic_root_at`); `by_hash`
/// the `(number, state_root)` of a hash among the attested blocks
/// (`ExecAnchor::attested_block_of`) — all as the anchor holds them now.
pub fn resolve_target(
    block: ProofBlock,
    head: Option<(u64, [u8; 32])>,
    finalized: Option<FinalizedExecution>,
    recent: impl Fn(u64) -> Option<[u8; 32]>,
    by_hash: impl Fn(&[u8; 32]) -> Option<(u64, [u8; 32])>,
) -> Result<ProofTarget, ProofError> {
    let at_head = |(block_number, state_root): (u64, [u8; 32])| ProofTarget { block_number, state_root };
    let at_finalized = |fin: FinalizedExecution| ProofTarget {
        block_number: fin.block_number,
        state_root: fin.state_root,
    };
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `recent: impl Fn(u64) -> Option<[u8; 32]>` and `by_hash: impl Fn(&[u8; 32]) -> …` are closures passed as arguments. `impl Trait` in argument position is a generic parameter in disguise: each call site gets its own monomorphised copy, with no boxing. The production caller passes closures over `ExecAnchor`; the tests pass plain functions like `fn none(_: u64) -> Option<[u8; 32]>`, which also implement `Fn`. Inside, `at_head` and `at_finalized` are local closures used as `map` arguments.

`rust/myotis-net/src/el/getproof.rs` · lines 143–174

```rust
        ProofBlock::Number(n) => {
            if let Some(h) = head.filter(|&(number, _)| number == n) {
                return Ok(at_head(h));
            }
            if let Some(fin) = finalized.filter(|fin| fin.block_number == n) {
                return Ok(at_finalized(fin));
            }
            if let Some(root) = recent(n) {
                return Ok(at_head((n, root)));
            }
            let Some((head_number, _)) = head else {
                return Err(ProofError::Unavailable(format!(
                    "beacon not synced: no verified head to check block {n:#x} against"
                )));
            };
            if n > head_number {
                return Err(ProofError::Unavailable(format!(
                    "block {n:#x} ({n}) is ahead of the verified head ({head_number})"
                )));
            }
            let fin = finalized
                .map(|f| format!(", or the finalized block ({})", f.block_number))
                .unwrap_or_default();
            Err(ProofError::Refused(format!(
                "eth_getProof at block {n:#x} ({n}) is not served: a proof is pinned to a state \
                 root this node holds attested for exactly that block — the last {RECENT_HEADS} \
                 heads it held that the verified head ({head_number}) builds on{fin} — and a \
                 proof at another root would not verify against block {n}'s stateRoot"
            )))
        }
    }
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **Refused or Unavailable.** `ProofError::Refused` becomes the permanent JSON-RPC `-32602`, `Unavailable` the retryable `-32000`. A number below the head will never become servable, so retrying it would spin; a number above the head may be reached. This applies the project's rule that a parameter that can change the answer must be applied or refused, never silently ignored (#314).
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `head.filter(|&(number, _)| number == n)` filters an `Option` of a `Copy` tuple; `let Some((head_number, _)) = head else { … }` then reuses the same `head`, which still exists because filtering copied it.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `{n:#x}` in `format!` prints `0x`-prefixed hex; `{RECENT_HEADS}` is an inline captured identifier, here a constant.

*[Protocol & domain](01-primer.md#primer-domain)* `confirmable` and `confirmed_root` (lines 198–216) handle a recent head the anchor's ring could not link: the reader fetches one header window anchored at the current head, and the head is served only if that window's block at its number has the same hash. `proof_hedge_delay` scales the hedge delay with the number of storage keys, capped at a third of the budget, so a large proof is not duplicated on a second peer while it is still arriving.

<a id="f-myotis-net-src-el-fork-watch-rs"></a>

### myotis-net/src/el/fork\_watch.rs

*library · 884 lines · Java twin · networking.eth.ForkWatch*

EIP-2124 stale-software detection. A build pins its fork id. From the fork ids that peers on our chain present in their eth Status, the watch notices that the network has scheduled, or already activated, an execution-layer fork this build does not implement, so hosts can say “update required” instead of the wallet going mute at the fork. Evidence is either **announced** (our hash with an unknown `forkNext`) or **placed** (the hash that follows ours after a fork at time T, recovered by `forkid::activation_of`). Peers can lie, so votes count per source network (IPv4 /24, IPv6 /48), need at least 3 sources, and must outnumber the dissent. It is advisory only: nothing in verification reads it. It runs on Sepolia for now. The pool feeds it from every compatible handshake and touches the sources it still holds on every maintainer tick.

`rust/myotis-net/src/el/fork_watch.rs` · lines 87–105

```rust
/// The vote key for a peer at `ip`: its IPv4 /24 or IPv6 /48 (an IPv4-mapped
/// IPv6 address counts as IPv4). Same strings as Java `ForkWatch.sourceOf`.
pub fn source_of(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4_source(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4_source(v4),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        },
    }
}

fn v4_source(v4: Ipv4Addr) -> String {
    let [a, b, c, _] = v4.octets();
    format!("{a}.{b}.{c}.0/24")
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* A nested `match` over `IpAddr`, with `to_ipv4_mapped()` folding `::ffff:a.b.c.d` back into IPv4. `let [a, b, c, _] = v4.octets();` destructures a `[u8; 4]` array by position, and `format!("{a}.{b}.{c}.0/24")` captures the bindings by name. The strings match the Java twin's, so both engines vote on the same keys. Node ids are free to mint; networks are not.

`rust/myotis-net/src/el/fork_watch.rs` · lines 304–335

```rust
/// Apply `mutate` at `now`, then log if the advisory changed.
fn update(&self, now: u64, mutate: impl FnOnce(&mut Inner)) {
    let current = {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        mutate(&mut inner);
        let current = self.evaluate_locked(&mut inner, now);
        if Advisory::same_fork(inner.last_logged.as_ref(), current.as_ref()) {
            return;
        }
        inner.last_logged = current;
        current
    };
    match current {
        None => tracing::info!(network = %self.label, "fork-watch: upgrade advisory cleared"),
        Some(a) if a.phase == Phase::Scheduled => tracing::warn!(
            network = %self.label,
            sources = a.peers,
            activation = a.activation_time,
            fork_id = %a.fork_hash_hex(),
            "fork-watch: peers announce a network upgrade this build does not support — update before then"
        ),
        Some(a) => tracing::warn!(
            network = %self.label,
            sources = a.peers,
            activation = a.activation_time,
            fork_id = %a.fork_hash_hex(),
            "fork-watch: peers report the network upgraded — this build cannot follow it; update required"
        ),
    }
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Interior mutability](01-primer.md#primer-interior-mutability)* `mutate: impl FnOnce(&mut Inner)` lets `observe_at` and `touch_at` pass their change as a closure that receives a mutable borrow of the locked state. The caller never sees the lock; this is the “execute around” pattern, like passing a lambda to a `synchronized` helper.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Ownership & moves](01-primer.md#primer-ownership)* The guard lives only inside the block `let current = { … };`. The block returns an `Option<Advisory>` (a `Copy` value), the guard drops at its closing brace, and logging happens after the lock is released. The early `return` inside the block drops the guard too. `let Ok(mut inner) = self.inner.lock() else { return; };` treats a poisoned lock as “do nothing”.

`rust/myotis-net/src/el/fork_watch.rs` · lines 389–414

```rust
    // Most-backed fork; ties → more placed, then earliest, then the current
    // baseline's. It must clear both the absolute floor and the dissent: a
    // minority can't outvote the peers it contradicts. The same date from
    // two baselines is two forks: never pooled.
    let ((base, t), best) = support
        .into_iter()
        .filter(|(_, s)| s.total() >= MIN_PEERS && s.total() > dissent)
        .max_by(|((ba, ta), a), ((bb, tb), b)| {
            a.total()
                .cmp(&b.total())
                .then(a.placed.cmp(&b.placed))
                .then(tb.cmp(ta))
                .then((*ba == local_hash).cmp(&(*bb == local_hash)))
        })?;
    let phase = if t <= now || best.placed >= MIN_PEERS {
        Phase::Active
    } else {
        Phase::Scheduled
    };
    Some(Advisory {
        phase,
        activation_time: t,
        fork_hash: forkid::successor(base, t),
        peers: best.total(),
    })
}
```

*[Iterators & closures](01-primer.md#primer-iterators-closures) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `support.into_iter()` consumes the `HashMap`, yielding owned `((u32, u64), Support)` pairs. `max_by` takes a comparator built from `Ordering::then`: more total votes, then more placed votes, then the *earlier* time (note `tb.cmp(ta)`, reversed), then the current baseline. The trailing `?` returns `None` when no fork clears both bars. The destructuring `let ((base, t), best) = …` takes the winner apart in one pattern.

<a id="f-myotis-net-src-el-readstats-rs"></a>

### myotis-net/src/el/readstats.rs

*library · 785 lines · Java twin · ReadStats*

A **shadow cache** that caches nothing. After every verified account, storage or bytecode fetch that crossed the network, the reader and the EVM oracle report it here, and the observer counts how many repeats a cache could have served, and under which keying: the same world state root (same block), the same contract storage root (the sound cross-block scheme, since the account proof is the freshness check), or merely the same value (a ceiling no sound cache can reach without a proof). It also buckets repeats by age. Costs accumulate in nanoseconds and are converted once at report time. It never returns a value to anyone; the counters come out as JSON whose shape the Java twin pins, and as a log line every 5 minutes.

`rust/myotis-net/src/el/readstats.rs` · lines 117–170

```rust
struct RecentMap<K, V> {
    cap: usize,
    seq: u64,
    map: HashMap<K, (V, u64)>,
    order: VecDeque<(K, u64)>,
}

impl<K: Hash + Eq + Clone, V> RecentMap<K, V> {
    fn new(cap: usize) -> RecentMap<K, V> {
        RecentMap {
            cap,
            seq: 0,
            map: HashMap::with_capacity(cap.min(1024)),
            order: VecDeque::with_capacity(cap.min(1024)),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(v, _)| v)
    }

    fn put(&mut self, key: K, value: V) {
        if self.cap == 0 {
            return;
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let fresh = self.map.insert(key.clone(), (value, seq)).is_none();
        self.order.push_back((key, seq));
        if fresh {
            while self.map.len() > self.cap {
                match self.order.pop_front() {
                    Some((k, s)) => {
                        // Only the queue entry that matches the key's CURRENT
                        // sequence evicts it; older entries are stale re-puts.
                        if self.map.get(&k).is_some_and(|(_, cur)| *cur == s) {
                            self.map.remove(&k);
                        }
                    }
                    None => break,
                }
            }
        }
        if self.order.len() > self.cap.saturating_mul(2).max(16) {
            let map = &self.map;
            self.order
                .retain(|(k, s)| map.get(k).is_some_and(|(_, cur)| cur == s));
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `impl<K: Hash + Eq + Clone, V> RecentMap<K, V>` puts the bounds on the `impl`, not on the struct, the usual Rust style: the type can be named for any `K`, but its methods need a hashable, clonable key. `key.clone()` is needed because the key is stored twice, in the map and in the queue.
- *[Protocol & domain](01-primer.md#primer-domain) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **An O(1) LRU without a linked list.** Every observation re-puts its key, so evicting the oldest put evicts the least recently observed key. Re-puts leave stale queue entries, tagged with an old sequence number and skipped at eviction; the queue is compacted once it exceeds twice the capacity.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* In the compaction, `let map = &self.map;` takes a shared borrow of one field before `self.order.retain(…)` borrows another field mutably. The closure then captures `map`, not `self`. With edition 2021 the closure would capture the field precisely on its own, but the local makes the disjoint borrow explicit.

`rust/myotis-net/src/el/readstats.rs` · lines 341–373

```rust
fn observe_account_at(
    &self,
    address: [u8; 20],
    state_root: [u8; 32],
    fact: AccountFact,
    elapsed: Duration,
    now: Instant,
) {
    let ns = elapsed.as_nanos() as u64;
    let summary = {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let inner = &mut *g;
        let c = &mut inner.counters.account;
        c.fetches += 1;
        c.fetch_ns += ns;
        if let Some(prev) = inner.accounts.get(&address) {
            c.repeats += 1;
            let unchanged = prev.fact == fact;
            if prev.state_root == state_root {
                c.same_state_root += 1;
                c.same_state_root_ns += ns;
            } else if unchanged {
                c.unchanged += 1;
            }
            c.by_age.record(now.saturating_duration_since(prev.at), unchanged);
        }
        inner.accounts.put(address, AccountSeen { state_root, fact, at: now });
        inner.summary_due(now).then(|| inner.snapshot())
    };
    if let Some(s) = summary {
        log_summary(&s);
    }
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Interior mutability](01-primer.md#primer-interior-mutability)* **`let inner = &mut *g;`** Every field access through a `MutexGuard` goes through `DerefMut::deref_mut(&mut g)`, which borrows the *whole* guard. Two field borrows through the guard at once would conflict. Reborrowing the guard into a plain `&mut Inner` first lets the compiler see fields: `c` borrows `inner.counters.account` mutably while `inner.accounts.get(…)` borrows another field. The summary is computed under the lock as a `Copy` snapshot (`then(|| inner.snapshot())`), and logged after the block, outside the lock.

## Checkpoint

12 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-pool-q1"></a>

**Q1** · Multiple choice

`verify_header_chain` requires the *last* (newest) header to hash to the attested block hash. Why not anchor the walk at the oldest header, the finalized block, as the code once did?

- **A.** The newest header is cheaper to fetch
- **B.** A `parentHash` commits a header to its parent only. Anchored at the oldest header, nothing pins the headers above it, so a peer could name the attested block as the parent of a made-up header with any state root
- **C.** The finalized block hash is not BLS-verified
- **D.** Java anchors at the newest header, and the tokens must match

[Answer →](answers.md#a-pool-q1)

<a id="q-pool-q2"></a>

**Q2** · Written answer

In `request::blocking`, the semaphore permit and the `Worker` guard are moved into the `spawn_blocking` closure. Explain why they must live there rather than in the async caller.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-pool-q2)

<a id="q-pool-q3"></a>

**Q3** · Multiple choice

`request.rs` moves a plain `SemaphorePermit` into a `spawn_blocking` closure, while `try_dial_with` in the pool needs `Arc::clone(&inner.dial_slots).acquire_owned()`. Why the difference?

- **A.** `spawn_blocking` does not require `'static`
- **B.** `BLOCKING_SLOTS` is a `static`, so its permit is `SemaphorePermit<'static>`; the dial semaphore lives in an `Arc`, so a borrowed permit would not be `'static` and the owned permit carries its own `Arc` instead
- **C.** Owned permits are faster
- **D.** The dial semaphore allows more than 16 permits

[Answer →](answers.md#a-pool-q3)

<a id="q-pool-q4"></a>

**Q4** · Multiple choice

`Operation::settled()` creates the `Notified` future and calls `enable()` *before* checking the atomics, while `ExecAnchor::pending_changed()` just awaits `notified()`. Why is the anchor's simpler form safe?

- **A.** The anchor uses a `std` mutex
- **B.** The anchor wakes with `notify_one`, which stores a permit when nobody waits, so a notification between two waits is not lost; `request.rs` uses `notify_waiters`, which stores none
- **C.** The anchor is never accessed concurrently
- **D.** `enable()` is called implicitly by `await`

[Answer →](answers.md#a-pool-q4)

<a id="q-pool-q5"></a>

**Q5** · Multiple choice

`Tasks` already aborts its tasks in `Drop`. Why does `PeerPool` need its own `Drop` that calls `abort()`?

- **A.** It does not; it is redundant
- **B.** The loops hold `Arc<PoolInner>` and `PoolInner` owns `Tasks`, so the count never reaches zero while the loops run and `Tasks::drop` never fires; the outer handle must break the cycle
- **C.** To flush the peer cache
- **D.** Because tokio requires every spawned task to be aborted

[Answer →](answers.md#a-pool-q5)

<a id="q-pool-q6"></a>

**Q6** · Written answer

The pool holds three peers, newest first: A (benched, `Covers`, proven), B (not benched, `Behind`, proven), C (not benched, `Unknown`, unproven). In what order does `snap_peers` return them, and which Rust feature produces that order?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-pool-q6)

<a id="q-pool-q7"></a>

**Q7** · Multiple choice

`read_failure_verdict(fails_before, pool_len)` returns `(0, false)` when `pool_len <= 1`. What does that rule protect against?

- **A.** Integer overflow of the strike counter
- **B.** A failure against the only server is likely our own stale request; banking a strike would evict that peer the moment a second peer arrived, before it ever failed as a non-sole peer
- **C.** The sole peer being benched
- **D.** A deadlock on the peers mutex

[Answer →](answers.md#a-pool-q7)

<a id="q-pool-q8"></a>

**Q8** · Written answer

Explain the difference between `QualityOutcome::Failed` and `QualityOutcome::FailedUnwitnessed`: what each does to the live pool and to the persisted peer cache, and why the distinction was introduced.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-pool-q8)

<a id="q-pool-q9"></a>

**Q9** · Multiple choice

`ExecAnchor::resolve_header` recomputes `keccak256(&header.raw_rlp)` although `VerifiedHeader` already has a `hash` field. Why?

- **A.** The `hash` field is a different hash function
- **B.** The adopted number, root and timestamp come from the decoded header; a value whose `hash` field claims the pending hash over another header's bytes must be refused, so the anchor checks the bytes itself
- **C.** To make the function slower to call
- **D.** Because `raw_rlp` is borrowed and the field is owned

[Answer →](answers.md#a-pool-q9)

<a id="q-pool-q10"></a>

**Q10** · Multiple choice

Why does `ReadStats::observe_account_at` write `let inner = &mut *g;` before borrowing `inner.counters.account` and `inner.accounts`?

- **A.** To copy the state out of the mutex
- **B.** Field access through a `MutexGuard` goes through `deref_mut`, which borrows the whole guard; reborrowing to a plain `&mut Inner` lets the compiler see two disjoint field borrows
- **C.** To release the lock early
- **D.** Because `Inner` is not `Copy`

[Answer →](answers.md#a-pool-q10)

<a id="q-pool-q11"></a>

**Q11** · Multiple choice

The verified head is block 1,000 and the finalized block is 936. A client calls `eth_getProof` at block 999, which is not among the linked recent heads. What does `resolve_target` return, and why?

- **A.** The proof at the head's root, since 999 is near the head
- **B.** `Unavailable` (retryable), since the head may reach it
- **C.** `Refused` (permanent `-32602`): a proof at another root would not verify against block 999's stateRoot, and a block below the head never becomes servable later
- **D.** The proof at the finalized root

[Answer →](answers.md#a-pool-q11)

<a id="q-pool-q12"></a>

**Q12** · Written answer

`fork_watch.rs` counts one vote per `source_of(ip)` and is "advisory only". Explain both choices and what an attacker who controls many node ids on one /24 can achieve.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-pool-q12)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
