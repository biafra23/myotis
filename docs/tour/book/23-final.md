# Final checkpoint: one request, end to end

*Stop 23 · final checkpoint* · no new files · about 30 minutes

A wallet on Android asks for an account balance. This stop follows that one call through every layer you've read, from Java to Rust, across threads, over the network and back, and names the memory-model decision made at each step. Then comes a final set of questions that deliberately mix topics. Your results feed the progress page, which suggests book chapters for whatever is still shaky.

![The path of one verified account read. 1: Java RustChainHandle.requestAccount calls the generated Kotlin. 2: ffi.rs calls host.rs, which clones the Arc of the reader under the handle-map lock and releases it. 3: the caller's thread blocks in rt.block_on on reader.request; a followed account is answered from block access lists, otherwise a hedged read races snap peers. 4: ManagedPeer registers a oneshot sender under the request id and sends the frame under the writer lock. The snap peer replies; 5: the peer's read task on a runtime thread decodes the frame and completes the oneshot, waking the blocked future. 6: the account proof is verified against the state root and the root is tied to the beacon chain through the ExecAnchor, which the consensus sync task keeps updated. 7: eljson serializes the result. 8: the JSON string returns to Kotlin and is parsed into AccountProofResult.](img/23-final-1.svg)

*Only the reader's read task and the consensus sync task live on runtime threads. The request itself, including hedging and proof checks, is a future that `block_on` polls on the caller's own thread, and serialisation happens on that same thread once it returns. The `oneshot` channel is the hand-off between the two worlds.*

### The steps, with the decision each one makes

| Step | Where | What happens | Memory-model moment |
|---|---|---|---|
| ① | Java, generated Kotlin | `RustChainHandle` calls `RustEngineNative.nativeRequestAccountJson(handle, address, block)`, which calls the generated `requestAccountJson`; that copies each string into a Rust-allocated `RustBuffer` ([Stop 17](17-uniffi.md) shows exactly how). | Data crosses the boundary *by copy*; no Java object is ever borrowed by Rust. |
| ② | [ffi.rs](16-engine.md#f-myotis-engine-src-ffi-rs) → [host.rs](16-engine.md#f-myotis-engine-src-host-rs) | UniFFI's wrapper turns the buffers into owned `String`s. `request_account_json(handle, &address, &block)` parses the address and the block selector without panicking (an unknown selector is refused, never ignored); `snapshot_reader` locks the handle map, clones `Arc<ElReader>`, and unlocks. | Owned in, borrowed onward. The lock covers only a reference-count increment, never I/O. |
| ③ | host.rs, [request.rs](12-el-pool.md#f-myotis-net-src-el-request-rs), [reader.rs](14-el-reader.md#f-myotis-net-src-el-reader-rs) | `engine.rt.block_on(reader.request(async { reader.get_account_pinned(anchor, address, pin).await }))`: an `Operation` with a 90 s budget, registered through a `Weak`. A head read of an address the reader *follows* is answered from block access lists ([activity.rs](13-el-services.md#f-myotis-net-src-el-activity-rs)); anything else goes to `get_account_proven`, a `hedged_read` over the snap peers (or one isolated Tor circuit when Tor is on). | A *borrowing* async block, fine because `block_on` waits for it (no `'static`). Losing attempts are cancelled by being dropped. |
| ④ | [peer.rs](11-el-transport.md#f-myotis-net-src-el-peer-rs) | `snap_get_account` → `request`: allocate an id from an atomic, insert `(id, oneshot::Sender)` into the pending map, write the frame under the writer lock, then await the `Receiver` with a timeout. | `&self` everywhere, with interior mutability (a tokio mutex and atomics). A `PendingGuard` removes the entry if this future is dropped. |
| ⑤ | peer.rs (read task) | The task spawned in `ManagedPeer::spawn` decodes the response frame, removes the pending entry by id, and sends the payload through the `oneshot`. | This task *owns* the reader half of the connection. Ownership was split at spawn time, so there's no shared socket. |
| ⑥ | [myotis-wire snap/fetch.rs](05-wire.md#f-myotis-wire-src-snap-fetch-rs), [myotis-core trie](04-core.md#f-myotis-core-src-trie-rs), [verify.rs](12-el-pool.md#f-myotis-net-src-el-verify-rs), [anchor.rs](12-el-pool.md#f-myotis-net-src-el-anchor-rs) | `verify_account` (now in `myotis-wire`) checks the Merkle-Patricia proof for `keccak(address)` against the state root. `verified_state_root` ties that root to the beacon chain: `stateRootMatch` against the `ExecAnchor`, or a `headerChain` walk that must end at the attested head and link down by `parentHash` ([Stop 12](12-el-pool.md)). | Pure functions over borrowed slices (`&[u8; 32]`, `&[Vec<u8>]`). The anchor is shared through `Arc`, written by the [sync task](10-net-sync.md#f-myotis-net-src-sync-rs), and read here. |
| ⑦ | [eljson.rs](16-engine.md#f-myotis-engine-src-eljson-rs) | `account_json(&address, &account, …)` builds the exact JSON Java expects; a failed verification is still a full result with `failReason`. | Borrowed input, owned output: a new `String` that moves to the caller. |
| ⑧ | UniFFI, Java | The `String` is lowered into a `RustBuffer`, and Kotlin copies it and frees the buffer through Rust. Java parses it into `AccountProofResult`. | Whoever allocates, frees: the buffer goes back to Rust's allocator (compare `myotis_string_free` on the C route). |

### The same request, one level down

`rust/myotis-net/src/el/peer.rs` · lines 520–597

```rust
async fn request(
    &self,
    send_code: u64,
    want_code: u64,
    encode: impl FnOnce(u64) -> Vec<u8>,
) -> Result<Vec<u8>, String> {
    let id = self.next_id.fetch_add(1, Ordering::Relaxed);
    let body = encode(id);
    let (tx, rx) = oneshot::channel();

    // Insert while holding the pending lock, checking `closed` inside it.
    // `fail_all` sets `closed` under the SAME lock, so we can't lose the
    // race where the read loop drains the map (on disconnect) between an
    // unlocked check and our insert — either we insert before the drain (and
    // it delivers our Err) or we observe `closed` and bail here.
    {
        let mut map = self.pending.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err("peer connection closed".to_string());
        }
        map.insert(id, Pending { want_code, tx });
    }
    let mut guard =
        PendingGuard { pending: Arc::clone(&self.pending), id, armed: true };

    // Send under the writer lock; a write failure leaves the egress frame
    // stream in an indeterminate state (a partial frame may be on the wire),
    // so fail EVERY in-flight request — not just this one, which would leave
    // the others hanging until their own timeouts on a dead connection.
    // (If THIS future is cancelled inside the send, the torn marker in
    // `send_frame` makes the next writer fail here instead; the pending
    // entry inserted above is then drained by that `fail_all`, or by the
    // discarded late response — either way it stays bounded.)
    if let Err(e) = send_frame(&self.writer, send_code, &body).await {
        fail_all(&self.pending, &self.closed, &self.close_reason, format!("peer write failure: {e}")).await;
        guard.armed = false; // fail_all drained the map
        return Err(e);
    }
    mark_request_sent();

    let out = match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
        Ok(Ok(result)) => {
            self.timeout_streak.store(0, Ordering::Relaxed);
            result
        }
        // The read loop dropped the sender (disconnect drained the map).
        Ok(Err(_)) => Err("peer connection closed".to_string()),
        Err(_) => {
            self.pending.lock().await.remove(&id);
            // Name the silent peer at WARN — once per silent streak (#465):
            // the pool-level whole-pool WARNs list the peers that failed,
            // but a single peer going silent under a prefetch or a probe
            // left no trace at info+, the level the hosts' log rings keep.
            // (A hedged loser never reaches this arm — the race drops it
            // when a winner answers; that event logs in the pool's
            // `record_outpaced`.)
            let streak = self.timeout_streak.fetch_add(1, Ordering::Relaxed) + 1;
            if streak == 1 {
                tracing::warn!(
                    addr = %self.addr,
                    code = %format_args!("0x{want_code:02x}"),
                    timeout_s = REQUEST_TIMEOUT.as_secs(),
                    "peer request timed out"
                );
            } else {
                tracing::debug!(
                    addr = %self.addr,
                    code = %format_args!("0x{want_code:02x}"),
                    streak,
                    "peer request timed out (silent streak continues)"
                );
            }
            Err(format!("timed out awaiting code 0x{want_code:02x}"))
        }
    };
    guard.armed = false;
    out
}
```

*[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* Read this excerpt as a recap of the whole tour. `fetch_add` on an atomic, a `oneshot` channel as a single-use future, a block scoping a tokio mutex guard, a “check `closed` under the same lock” race fix, an RAII `PendingGuard` that cleans up when the future is dropped mid-flight, `timeout` producing a nested `Result`, and a `match` that turns every outcome into a `Result<Vec<u8>, String>`.

> [!TIP]
> **The memory model in five sentences**
>
> - Every value has **one owner**; assignment and passing by value *move* it, unless the type is `Copy`.
> - You can lend a value as **many `&T` or one `&mut T`**, and lifetimes are how the compiler proves no loan outlives its owner.
> - **Sharing** needs a smart pointer (`Arc`), and **shared mutation** needs interior mutability (`Mutex`, `RwLock`, atomics). The lock *contains* the data.
> - **Values are freed when their owner goes out of scope** (`Drop`). That's how guards unlock, tasks abort, files close and futures cancel.
> - Work handed to another thread or task must **own its data** (`Send + 'static`); work awaited in place may borrow.

Next, open [your progress](reading-list.md#progress). It lists the concepts you answered weakly and the matching chapters from your EPUBs and from the Rust docs installed with rustup, all of which open offline. Before you close the browser, download your progress file there. Back on the ground, paste the summary (“Copy a summary for Claude”) into a Claude session, and we can go through your weak spots together.

## Checkpoint

10 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-s17-q1"></a>

**Q1** · Multiple choice

During a verified account read from Android, which thread polls the `hedged_race` future?

- **A.** A tokio worker thread, via `tokio::spawn`
- **B.** The JVM caller's own thread, inside `engine.rt.block_on(…)`. Only long-lived tasks such as the peer read loop and the sync loop run on runtime threads
- **C.** The Android main thread
- **D.** A new OS thread per request

[Answer →](answers.md#a-s17-q1)

<a id="q-s17-q2"></a>

**Q2** · Multiple choice

How does the response bytes' journey from the peer's read task to the waiting request work?

- **A.** Through a shared global buffer
- **B.** The request inserted a `oneshot::Sender` into the peer's pending map under its request id. The read task removes that entry and calls `send`, which completes the `Receiver` the request is awaiting and wakes it
- **C.** The read task calls the request function directly
- **D.** Via a `Condvar`

[Answer →](answers.md#a-s17-q2)

<a id="q-s17-q3"></a>

**Q3** · Multiple choice

Which of these is a *move*, not a borrow or a copy?

- **A.** `snap_get_account(&root, &address)`
- **B.** `ManagedPeer::spawn(session, addr)`: the `EthSession` is handed over, and the old name can't be used afterwards
- **C.** `let n = header.number;` for a `u64`
- **D.** `Arc::clone(&reader)`

[Answer →](answers.md#a-s17-q3)

<a id="q-s17-q4"></a>

**Q4** · Multiple choice

`block_on(reader.request(async { reader.get_account(address).await }))` borrows `reader`, but `tokio::spawn(async { reader.get_account(address).await })` would not compile. Why?

- **A.** `spawn` needs `async move` only as a matter of style
- **B.** `spawn` requires a `'static` future, because the task may outlive the current stack frame. `block_on` doesn't return until the future finishes, so borrowing locals is safe
- **C.** `block_on` copies `reader`
- **D.** `get_account` isn't `Send`

[Answer →](answers.md#a-s17-q4)

<a id="q-s17-q5"></a>

**Q5** · Multiple choice

Which lock would you choose for a map that is updated in microseconds and read from both async and synchronous code, and never held across `.await`?

- **A.** `tokio::sync::Mutex`
- **B.** `std::sync::Mutex` (or `RwLock`): cheap, usable from synchronous code, and safe in async code as long as the guard is dropped before any `.await`
- **C.** No lock; Rust prevents data races automatically
- **D.** A `RefCell`

[Answer →](answers.md#a-s17-q5)

<a id="q-s17-q6"></a>

**Q6** · Multiple choice

Why does so much of this codebase avoid `unwrap()`, indexing and unchecked arithmetic on runtime data?

- **A.** Performance
- **B.** The engine is built with `panic = "abort"` and runs inside JVM, iOS and Node hosts. Any panic would kill the host app, so failures must become `Option`/`Result` values, sentinels, or `{"error"}` JSON
- **C.** Those features are deprecated
- **D.** Clippy forbids them

[Answer →](answers.md#a-s17-q6)

<a id="q-s17-q7"></a>

**Q7** · Multiple choice

What cancels the losing attempts of a hedged read, and what cancels an in-flight request when a host calls `stop`?

- **A.** Explicit `cancel()` calls in both cases
- **B.** Losing attempts are cancelled by being *dropped* when `hedged_race` returns. On `stop`, the shutdown watch flips, and each registered `Operation`, reached by upgrading its `Weak`, is signalled and awaited until it settles
- **C.** Thread interrupts
- **D.** Garbage collection

[Answer →](answers.md#a-s17-q7)

<a id="q-s17-q8"></a>

**Q8** · Written answer

In your own words, compare how Java and Rust would each make the handle registry in `host.rs` (a map from id to chain state, used from many host threads) safe. Name the Rust types involved and what the compiler enforces that Java doesn't.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-s17-q8)

<a id="q-s17-q9"></a>

**Q9** · Multiple choice

`Arc<LcStore>` is passed where `Arc<dyn LcResponder>` is expected, and `RlpxConnection<S>` is instantiated with `S = DataStream`. Which statement is right?

- **A.** Both use dynamic dispatch
- **B.** The first is a trait object (a pointer plus a vtable, resolved at run time). The second is a generic, monomorphised at compile time into specialised code with static calls
- **C.** Both are resolved at compile time
- **D.** Both require `unsafe`

[Answer →](answers.md#a-s17-q9)

<a id="q-s17-q10"></a>

**Q10** · Multiple choice

Which statement matches the trust model you've seen across the tour?

- **A.** Peers are trusted once they complete the RLPx handshake
- **B.** Nothing a peer says is trusted until it's checked: account and storage data by Merkle-Patricia proofs, state roots and headers by tying them to a beacon block the light client verified with sync-committee BLS signatures, starting from a pinned checkpoint. roost only relays objects that wallets verify themselves
- **C.** roost is trusted because the project runs it
- **D.** Local HTTP RPC is used in production for convenience

[Answer →](answers.md#a-s17-q10)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
