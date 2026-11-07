# Rust's memory model for JVM developers

*Stop 1 · Orientation* · about 60 minutes · the most important stop

Each idea in this stop is shown with a short excerpt from the Myotis code, not a toy example. When a later stop says “see the primer”, it means one of the sections below. If a section doesn't stick, the checkpoint at the end will say so, and the reading list will point to the right chapter.

## By the end of this stop you can

- **Predict moves and copies** — and say when a value is freed, without a garbage collector.
- **Read borrows and lifetimes** — such as `&'a [u8]`, `&mut self` and `+ 'static`.
- **Pick the right sharing tool:** `Arc`, `Mutex`, atomics, channels, and know why async needs `Send + 'static`.

## The one-paragraph difference

In Java, every object lives on the heap, variables hold references, any number of references may point at the same object, and the garbage collector frees it once nothing points at it anymore. Thread safety is your responsibility. In Rust, a value lives where you put it: in the stack frame by default, on the heap only through a type such as `Box`, `Vec`, `String` or `Arc`. Each value has **exactly one owner**, and it is freed the moment that owner goes away. The compiler tracks every reference (a *borrow*) and refuses to compile code that could read freed memory, or write while someone else is reading. That single rule is where the rest of this stop comes from.

![Java versus Rust memory. In Java two stack variables a and b both reference one heap byte array, which the garbage collector frees later. In Rust, variable a has been moved into b; b is a pointer, length and capacity on the stack that owns a heap buffer of capacity 8 holding 5 bytes; s is a slice, a pointer plus length 3, that borrows bytes 1 to 3 of the same buffer. The buffer is freed when b goes out of scope.](img/01-primer-1.svg)

*The Java reference and the Rust owner both point at heap bytes. The differences are how many names may use them, and who decides when they are freed. A Rust `Vec` is three machine words on the stack (pointer, length, capacity). A slice `&[u8]` is two words (pointer, length) that *borrow* part of a buffer somebody else owns.*

<a id="primer-ownership"></a>

## Ownership and moves

**Rule:** every value has one owner, a variable or a field. Assigning it, passing it to a function *by value*, or returning it **moves** it. The old name becomes unusable, and the compiler rejects any later use with “use of moved value”. When the owner goes out of scope, the value is dropped: its memory is freed and its `Drop` code runs.

**Copy types are the exception.** Integers, `bool`, fixed arrays of them such as `[u8; 32]`, and shared references `&T` implement `Copy`. Assigning one duplicates the bits, and the original stays usable. That's why this codebase passes 32-byte roots and 20-byte addresses around by value so freely: they are small arrays on the stack, not heap objects.

**Deep copies are explicit.** Only `.clone()` duplicates a `Vec`, `String` or struct. When a function signature takes `T` (not `&T`), it wants ownership. If you still need the value afterwards, you clone it first. Look for the phrase “the one deep clone” in `host.rs`:

`rust/myotis-engine/src/host.rs` · lines 730–739

```rust
// SyncHandle::start must run inside the tokio runtime (it spawns tasks).
// The one deep ChainConfig clone: SyncHandle::start takes it by value.
let sync = match engine.rt.block_on(async {
    let mut cfg = (*config).clone();
    cfg.cl_fork_watch = cl_watch;
    SyncHandle::start(cfg)
}) {
    Ok(s) => s,
    Err(_) => return false,
};
```

`SyncHandle::start` takes a `ChainConfig` by value because the sync loop will own it for its whole life. The engine keeps its own copy behind an `Arc` (more on that below), so it clones once: `(*config)` dereferences the `Arc` to reach the `ChainConfig`, and `.clone()` makes an owned copy. Because `cfg` is now *owned* by this block, it may be changed (`let mut`, then `cfg.cl_fork_watch = cl_watch;`) without touching the shared original, and is then moved into `start`. After that line `cfg` is gone: the sync loop owns it.

> [!NOTE]
> **JVM lens**
>
> Think of a move as *handing over the only key*. In Java, `b = a` gives you two keys to one object. In Rust, `let b = a;` gives the key to `b` and melts `a`'s. There is no aliasing, so there is nothing for a garbage collector to track: the compiler knows exactly where each value dies. Kotlin's `val` and `var` map to `let` and `let mut`, with one twist: in Rust, a non-`mut` binding also forbids mutating the value's *contents*, not just reassigning the variable.

Sometimes you need to move a value out of a place that you only borrow mutably, such as a field behind `&mut`. Rust won't let you leave a hole, so `std::mem::take` swaps in an empty default and hands you the old value. You will see it in the smallest complete example of ownership in the codebase, the peer pool's task set:

`rust/myotis-net/src/el/tasks.rs` · lines 1–40

```rust
//! Ownership for the peer pool's parent loops and their spawned network jobs.
use std::future::Future;
use std::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Default)]
pub(super) struct Tasks(Mutex<(bool, Vec<JoinHandle<()>>)>);
impl Tasks {
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if tasks.0 {
            return;
        }
        tasks.1.retain(|task| !task.is_finished());
        tasks.1.push(tokio::spawn(future));
    }

    fn take(&self) -> Vec<JoinHandle<()>> {
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        tasks.0 = true;
        for task in &tasks.1 {
            task.abort();
        }
        std::mem::take(&mut tasks.1)
    }

    pub async fn stop(&self) {
        for task in self.take() {
            let _ = task.await;
        }
    }
    pub fn abort(&self) {
        drop(self.take());
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.abort();
    }
}
```

> [!TIP]
> **Read it line by line**
>
> - **L7**: `Tasks` is a tuple struct wrapping `Mutex<(bool, Vec<JoinHandle<()>>)>`: a “stopped” flag plus the handles of spawned tasks. The data lives *inside* the mutex.
> - **L9**: `spawn` takes the future *by value* (`impl Future…`), because the runtime will own it. It needs `Send + 'static`; see [async](#primer-async).
> - **L10**: `lock()` returns a guard. `unwrap_or_else(|e| e.into_inner())` says “if a previous holder panicked (the lock is *poisoned*), take the data anyway”.
> - **L24**: `std::mem::take(&mut tasks.1)` moves the whole `Vec` out and leaves an empty one behind. The caller now owns the handles.
> - **L33**: `drop(self.take())` ends the taken `Vec`'s life immediately.
> - **L36–40**: `impl Drop` is a destructor. When a `Tasks` value dies, for example when the pool that owns it is dropped, it aborts every task. There's no `close()` to forget.

<a id="primer-borrowing"></a>

## Borrowing: `&T`, `&mut T` and slices

Most functions don't want ownership. They want to *look at* or *modify* a value for a while. That's a borrow:

- `&T` is a **shared** borrow. It is read-only, and any number may exist at once.
- `&mut T` is an **exclusive** borrow. It may modify the value, and while it exists no other borrow of that value may exist.

This “many readers *or* one writer” rule is checked at compile time. It is what makes data races impossible in safe Rust, and it is also why a method signature tells you so much. `fn fixed(&mut self, …)` changes the reader's position. `fn check_request(&self)` promises not to change anything visible (unless the type uses [interior mutability](#primer-interior-mutability)).

A **slice** is a borrowed view into a contiguous sequence: `&[u8]` for bytes, `&str` for UTF-8 text. It is a pointer plus a length. Taking `&data[a..b]` copies nothing; it just narrows the view. Protocol decoders in this codebase are built from exactly that move. Here is the snapshot decoder's cursor:

`rust/myotis-consensus/src/snapshot.rs` · lines 315–342

```rust
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn fixed(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.fixed(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.fixed(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.fixed(8)?.try_into().ok()?))
    }
    fn root(&mut self) -> Option<[u8; 32]> {
        self.fixed(32)?.try_into().ok()
    }
}
```

`fixed(len)` checks bounds with `checked_add` (no overflow panic), then returns `&self.data[self.pos..end]`, a view into the caller's buffer, and advances `pos`. `u32()` turns four borrowed bytes into a number. Nothing is allocated until a caller explicitly asks for an owned copy with `.to_vec()` (see line 237 just above the struct).

> [!NOTE]
> **JVM lens**
>
> A slice is like `ByteBuffer.slice()` or `ByteBuf.slice()` in Netty, with two guarantees Java cannot give you. The backing buffer cannot be freed or reallocated while the slice exists, and nobody can write to it while you read. In Netty you manage that by hand with `retain()`/`release()`; here the compiler does it.

<a id="primer-lifetimes"></a>

## Lifetimes: naming how long a borrow lives

A lifetime is the compiler's name for “the span of code during which this reference is valid”. Usually it is inferred. You write one when a struct *stores* a reference, or when a function returns a reference and the compiler must know which input it borrows from.

In `Reader<'a>` above, `'a` is a **parameter**: “a `Reader` borrows some byte buffer for a span called `'a`, and may not outlive it”. The return type of `fixed`, `Option<&'a [u8]>`, says the returned slice borrows from *that buffer*, not from the `Reader` itself. That distinction matters: the caller can keep several returned slices alive while calling `fixed` again, because the slices don't borrow the reader. If the signature had said `-> Option<&[u8]>`, elision would tie the result to `&mut self`, and a second call would be rejected.

Three spellings you will meet everywhere:

- `'_` means “some lifetime, infer it”, as in `Reader<'_>` or `Formatter<'_>`.
- `&'static T` is a reference valid for the whole program: string literals, `static` items. `myotis-consensus` returns its BLS domain-separation tag as `&'static [u8]`.
- `T: 'static` as a **bound** means “`T` contains no borrowed references (it owns all its data)”. It does *not* mean the value lives forever. `tokio::spawn` demands it, because a task may outlive the function that spawned it.

`rust/myotis-consensus/src/lib.rs` · lines 27–30

```rust
/// The production BLS DST (re-exported for callers that log/compare it).
pub fn bls_dst() -> &'static [u8] {
    myotis_bls::DST
}
```

> [!WARNING]
> **Common confusion**
>
> Lifetime annotations never change what a program does. They are claims the compiler checks. If you can't satisfy the checker, the usual fixes are to return an owned value (`Vec`/`String`), clone, or restructure so the borrow ends sooner. Adding more `'a`s rarely helps.

<a id="primer-bytes-strings"></a>

## Bytes and strings

| Type | Owned? | Where | Java/Kotlin analogue |
|---|---|---|---|
| \[u8; 32\] | yes (Copy) | inline (stack / inside struct) | a value type; `byte[]` without the heap |
| Vec&amp;lt;u8> | yes | heap buffer | `byte[]` / `ByteArrayOutputStream` |
| &\[u8\] | no (borrow) | points into someone's buffer | `ByteBuffer.slice()` |
| String | yes | heap, always valid UTF-8 | `StringBuilder`-ish |
| &str | no (borrow) | points into a `String` or a literal | `String` (read-only) |
| b"…" | no (`&'static [u8; N]`) | in the binary | a byte literal |

Converting a slice into a fixed array is fallible, because the length might be wrong. So `slice.try_into()` returns a `Result`, and you'll constantly see `.try_into().ok()?`, as in `Reader::root` above. `format!("{b:02x}")` and `write!(s, …)` are the formatting macros, the `String.format` of Rust. [Rust by Example's “Formatted print”](https://doc.rust-lang.org/rust-by-example/hello/print.html) covers them.

<a id="primer-error-handling"></a>

## Errors are values: `Option`, `Result` and `?`

Rust has no `null` and no exceptions. A value that may be missing is `Option<T>` (`Some(v)` or `None`). An operation that may fail returns `Result<T, E>` (`Ok(v)` or `Err(e)`). The `?` operator is the workhorse. On `None` or `Err` it *returns early* from the current function, and for `Result` it first converts the error with `From::from`. Reread `Reader::u32`:

`rust/myotis-consensus/src/snapshot.rs` · lines 333–335

```rust
fn u32(&mut self) -> Option<u32> {
    Some(u32::from_be_bytes(self.fixed(4)?.try_into().ok()?))
}
```

From inside out: `self.fixed(4)?` returns `None` from `u32` if fewer than 4 bytes remain. `.try_into()` converts the slice to `[u8; 4]` and yields a `Result`. `.ok()` turns that into an `Option` so it fits this function's return type, and the second `?` returns `None` if the conversion failed. No panic is possible anywhere in the line. That's rule 3 from Stop 0 in action.

Error types are usually enums, and a `From` impl lets `?` convert between layers. In `myotis-evm`, any state-fetch error can bubble out of an EVM call unchanged in meaning:

`rust/myotis-evm/src/error.rs` · lines 11–39

```rust
/// Everything a view call can return other than the success bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmError {
    /// State could not be fetched or verified (from the oracle / revm `Database`)
    /// — includes `BlockHashUnsupported`. See [`OracleError`].
    Oracle(OracleError),
    /// The contract reverted. `data` is the raw revert payload (a Solidity
    /// `Error(string)` is ABI-encoded behind the `0x08c379a0` selector).
    Reverted { data: Vec<u8> },
    /// The call ran out of gas within the 30 M ceiling.
    OutOfGas,
    /// The EVM halted for another reason (invalid opcode, stack error, …). The
    /// string is revm's `HaltReason` debug form — diagnostic, not a stable token.
    Halted { reason: String },
    /// The target block predates London; the engine does not execute pre-London
    /// state (no local archive, and the fork rules below London aren't modelled).
    ForkTooOld { block_number: u64, timestamp: u64 },
    /// The block context is for a chain this executor has no fork table for (the
    /// table covers mainnet, Sepolia, Gnosis and Chiado), so any other chain id would
    /// otherwise run under another chain's forks — fail closed instead of returning
    /// a silently-wrong result.
    UnsupportedChain { chain_id: u64 },
    /// revm rejected the transaction envelope itself (should not happen for a
    /// well-formed view call — surfaced rather than swallowed).
    Transaction { detail: String },
    /// The speculative prefetch convergence loop didn't settle within its
    /// iteration cap (Java `IterationLimitExceeded` twin) — fail closed rather
    /// than answer from a run that was still discovering state.
    IterationLimitExceeded { cap: usize },
```

The enum has grown well beyond these first variants (refusals, gas answers, ENS outcomes). Further down the same file sits the one-line bridge that makes `?` work across the crate boundary:

`rust/myotis-evm/src/error.rs` · lines 170–174

```rust
impl From<OracleError> for EvmError {
    fn from(e: OracleError) -> EvmError {
        EvmError::Oracle(e)
    }
}
```

When the executor's code does `let acct = oracle.fetch_account(…)?;` inside a function returning `Result<_, EvmError>`, the compiler inserts `EvmError::from(oracle_error)`. The `match` in `Display` must handle every variant. Add a variant and every non-exhaustive `match` elsewhere stops compiling, which is the point.

One more pattern you'll see in the engine: `let … else`. It destructures or bails out, and the `else` block must leave the function:

`rust/myotis-engine/src/host.rs` · lines 703–706

```rust
fn spin_up(handle: i64, from: SpinUpFrom) -> bool {
    let Some(engine) = engine() else {
        return false;
    };
```

> [!NOTE]
> **JVM lens**
>
> `Result` is a checked exception that is part of the return type, and `?` is a one-character “rethrow”. `Option` is Kotlin's `T?`, where `?` plays the role of `?: return null`. `unwrap()` is `!!`: it panics on `None`. With `panic = "abort"`, that means “crash the host app”, so the engine code avoids it on runtime data.

<a id="primer-enums-patterns"></a>

## Enums and pattern matching

A Rust `enum` is a *tagged union*: each variant can carry its own data, just like Kotlin's sealed classes. `match` must cover every variant; `_` is the wildcard. The engine's per-handle state machine is one enum:

`rust/myotis-engine/src/host.rs` · lines 64–87

```rust
/// One hosted chain: created-but-not-started, or running. Running keeps the
/// config so status reads can derive wall-clock values (targetPeriod) fresh.
/// `Arc` because the config is cloned out of the map on every such read (and
/// in `start`) — the deep `ChainConfig` clone happens only once, into
/// `SyncHandle::start`.
enum ChainEntry {
    Created(Arc<ChainConfig>),
    /// A running chain: the CL sync loop plus (optionally) the EL verified-read
    /// reader. The reader is `None` if its discovery/pool failed to start — the
    /// CL still runs, but EL queries report the reader unavailable. `Arc` so a
    /// query can clone it out and run OUTSIDE the handle-map lock (a verified
    /// read can take up to ~60 s for a header-chain walk).
    Running(Arc<ChainConfig>, SyncHandle, Option<Arc<ElReader>>),
    /// An idle-slept chain (the ChainHandle contract's PAUSED): networking is
    /// fully torn down (zero sockets, zero timers — the radio can sleep) but the
    /// handle stays valid and `resume` re-runs the start path, which warm-starts
    /// from the persisted snapshot / peer caches under the host's dataDir (no
    /// checkpoint re-bootstrap). Carries the last `SyncStatus` observed at pause
    /// time so status reads keep reporting the warm beacon fields while asleep,
    /// and the read-fetch shadow cache so its counters outlive the torn-down
    /// reader (they are per handle, like the Java stack's — resume hands them
    /// to the new reader).
    Paused(Arc<ChainConfig>, SyncStatus, Arc<ReadStats>),
}
```

A chain is `Created`, `Running` or `Paused`, and each state carries exactly the data that state needs, so a paused chain cannot have a live `SyncHandle`. The start path matches on a *tuple* of (requested transition, current state) and binds the config with a pattern:

`rust/myotis-engine/src/host.rs` · lines 711–726

```rust
let (config, read_stats) = {
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    match (from, map.get(&handle)) {
        (SpinUpFrom::Created, Some(ChainEntry::Created(c))) => {
            (Arc::clone(c), Arc::new(ReadStats::new()))
        }
        // Resume keeps the shadow cache the paused reader accumulated.
        (SpinUpFrom::Paused, Some(ChainEntry::Paused(c, _, stats))) => {
            (Arc::clone(c), Arc::clone(stats))
        }
        _ => return false, // unknown id, or not in the expected state
    }
};
```

Three things at once here. The inner block `{ … }` is an expression whose value, here a tuple, becomes `(config, read_stats)`: the pattern on the left destructures it. The `map` guard dies at the closing brace, which *releases the lock* before the slow `block_on`. And `_ => return false` covers “unknown id or wrong state” without a single `null` check.

<a id="primer-methods"></a>

## Methods and `self`

Rust has no classes. Data lives in a `struct` (or an `enum`), and behaviour lives in separate `impl` blocks. A function in an `impl` block whose first parameter is some form of `self` is a **method**, and `self` is Java's `this`. The difference is that Rust writes it in the signature, because a method has to say *how* it receives the object. This small type from roost has three kinds of function in one `impl`:

`rust/roost/src/enr.rs` · lines 23–65

```rust
/// A persisted, monotonically increasing ENR sequence number.
#[derive(Debug)]
pub struct EnrSeq {
    path: PathBuf,
    current: u64,
}

impl EnrSeq {
    /// Load the sequence number, starting at 1 if there is none.
    ///
    /// A corrupt or unreadable file is a hard error rather than a reset to 1:
    /// silently restarting the sequence is exactly the failure this exists to
    /// prevent, and it would be invisible until an update failed to take.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let current = match std::fs::read_to_string(&path) {
            Ok(raw) => raw
                .trim()
                .parse::<u64>()
                .with_context(|| format!("parsing the ENR sequence number in {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 1,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path, current })
    }

    /// The last issued number. Callers publishing a record want [`Self::bump`]
    /// instead — see its note on ordering. `serve` reads this only for the
    /// initial, endpoint-less (unpublished) record.
    pub fn current(&self) -> u64 {
        self.current
    }

    /// Advance and persist, returning the new value.
    ///
    /// Written before it is used, not after: a crash between publishing and
    /// persisting would otherwise re-issue a number the network has already
    /// seen, and the DHT would ignore the re-issued record.
    pub fn bump(&mut self) -> Result<u64> {
        let next = self
            .current
            .checked_add(1)
            .context("ENR sequence number overflowed u64")?;
```

- `load(path: …) -> Result<Self>` has no `self`, so it's an **associated function**: Java's `static` method, or a factory in a Kotlin `companion object`. You call it on the type, `EnrSeq::load(path)`. `Self` with a capital S is shorthand for the type being implemented, here `EnrSeq`. Rust has no constructors and no `new` keyword; `new`, `load` and `start` are ordinary associated functions that return `Self`.
- `current(&self)` is a method with a **shared-borrow receiver**. `&self` is shorthand for `self: &Self`, here `self: &EnrSeq`. It may read fields (`self.current`: a field and a method may share a name), and any number of callers may use the value at the same time.
- `bump(&mut self)` ends with `self.current = next;` (line 107), so it needs an **exclusive-borrow receiver**. The caller must have mutable access, which is why `serve.rs` keeps the counter in a `let mut` binding.

### What the dot does

`seq.bump()` is sugar for `EnrSeq::bump(&mut seq)`. In the trait below, `oracle.fetch_account(&root, addr)` is sugar for `SnapStateOracle::fetch_account(&oracle, &root, addr)`. The value left of the dot becomes the first argument, so `fetch_account` really has three parameters even though a call shows two. Both spellings compile and mean the same thing. roost even passes a method where a plain function is expected:

`rust/roost/src/serve.rs` · lines 511–526

```rust
let mut enr_seq = match EnrSeq::load(archive_path.with_extension("enrseq")) {
    Ok(seq) => Some(seq),
    Err(e) => {
        tracing::error!(error = %e,
            "ENR sequence file unusable — the record will NOT be published this run; \
             repair the file (a bare decimal number) and restart");
        None
    }
};
let discovery = start_discovery(
    &client,
    &gvr,
    &keypair,
    port,
    enr_seq.as_ref().map(EnrSeq::current).unwrap_or(1),
)
```

`enr_seq` is an `Option<EnrSeq>`, `None` when the file is unusable. `.as_ref()` turns it into an `Option<&EnrSeq>`, and `.map(EnrSeq::current)` calls `EnrSeq::current(&seq)` on the value inside, if there is one. That only works because a method is an ordinary function whose first parameter is the receiver.

The compiler also adjusts the receiver for you. It inserts the `&` or `&mut` the method asks for (*auto-ref*), and it follows references, `Box`, `Arc` and lock guards to find the method (*auto-deref*). That's why `reader.get_account(address)` works when `reader` is an `Arc<ElReader>`. The long form shows up only where the short one would be ambiguous or unavailable. Stop 12 writes `futures::StreamExt::next(&mut fetches)` instead of importing the trait, and Stop 15 uses `LcStore::bootstrap(self, …)` to pick the type's own method over a trait method with the same name.

| Receiver | What it means | Java/Kotlin | In Myotis |
|---|---|---|---|
| (none) | An associated function, called as `Type::name(…)`. | `static` method, companion-object factory | `EnrSeq::load`, `ElReader::start`, `Arc::clone(&x)` |
| &self | Shared borrow: read-only, and many callers may use the value at once. | an ordinary instance method | `EnrSeq::current`, `SnapStateOracle::fetch_account` |
| &mut self | Exclusive borrow: may change fields, and nobody else can use the value meanwhile. | a method that modifies `this`, with a guarantee Java can't give | `EnrSeq::bump`, `Reader::fixed` (above) |
| self | By value: the method takes ownership, and the caller can't use the value afterwards. | no equivalent; like “don't touch it after `close()`”, but enforced | `SyncHandle::stop(self)`, `Cancellation::finish(self, …)` (Stop 14) |
| mut self | By value, and the method may change its own copy, typically to return it. | a builder method | `ForkSchedule::with_blob_schedule(mut self, …) -> Self` (Stop 15) |
| self: Arc&amp;lt;Self> | The method needs the `Arc` itself, for example to hand a clone or a `Weak` to a task. `self: &Arc<Self>` borrows it instead. | none | the Node scheduler's `worker` (Stop 14), `ElReader::ensure_log_index_appender` (Stop 11) |

### Methods from traits, and `self.inner`

There are two kinds of `impl` block. `impl EnrSeq { … }` is an *inherent* impl: the type's own methods. `impl SnapStateOracle for Counting { … }` implements a trait's methods for a type. It's like `class Counting implements SnapStateOracle`, except that it's written separately from the struct, and a type can have any number of these blocks. A trait's methods can only be called where the trait is in scope, which is why `eljson.rs` writes `use std::fmt::Write;` before it calls `write!` on a `String`. Here is a test helper from `executor.rs` that wraps another oracle:

`rust/myotis-evm/src/executor.rs` · lines 2124–2146

```rust
#[derive(Default)]
struct Counting {
    inner: FixtureSnapStateOracle,
    fetches: std::sync::atomic::AtomicUsize,
}
impl crate::oracle::SnapStateOracle for Counting {
    fn fetch_account(
        &self, r: &[u8; 32], a: [u8; 20],
    ) -> Result<Option<OracleAccount>, crate::oracle::OracleError> {
        self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.fetch_account(r, a)
    }
    fn fetch_storage(
        &self, r: &[u8; 32], a: [u8; 20], s: U256,
    ) -> Result<U256, crate::oracle::OracleError> {
        self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.fetch_storage(r, a, s)
    }
    fn fetch_bytecode(&self, h: &[u8; 32]) -> Result<Vec<u8>, crate::oracle::OracleError> {
        self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.fetch_bytecode(h)
    }
}
```

- `inner` is only a field name, a common convention for “the thing this struct wraps”. `self.inner` means “my field `inner`”, Java's `this.inner`. `Counting` is a decorator: it implements the same trait, counts every call, and forwards it to the fixture oracle it wraps.
- Inside `fetch_account`, `self` is a `&Counting`. `self.inner` is the field reached through that reference, and calling a `&self` method on it borrows it again. Nothing is copied or moved; moving a field out of something you only borrow wouldn't compile anyway.
- The counter changes even though `self` is a shared reference, because it's an `AtomicUsize`. That's [interior mutability](#primer-interior-mutability), which has its own section below.
- `Counting` is declared inside a test function. Rust allows items (structs, impls, functions) inside any block, visible only there. `#[derive(Default)]` gives it a `Counting::default()` with a default fixture and a zero counter.

You'll see `inner` in other places with other types, for example `LcStore { inner: RwLock<Inner> }` in roost and the Node scheduler's `State { inner: Mutex<Inner>, … }`. The name only says “wrapped”; the type says what it is.

> [!NOTE]
> **JVM lens**
>
> Java hides `this`, but it's there: the JVM passes it as argument 0 of every instance method (that's what `aload_0` loads). Kotlin extension functions make the same idea visible: `fun EnrSeq.bump()` compiles to a static method whose first parameter is the receiver. Rust simply writes that parameter down, and in doing so states the access mode Java can't express: shared and read-only (`&self`), exclusive (`&mut self`), or consumed (`self`).

<a id="primer-traits-generics"></a>

## Traits, generics and `dyn`

A `trait` is an interface. It can have default methods and *supertraits* (requirements on implementors). Here is the contract `myotis-evm` uses to read verified state without knowing about networks:

`rust/myotis-evm/src/oracle.rs` · lines 184–230

```rust
/// The verified world-state source the EVM reads through. See the module docs
/// for the verification and threading contract.
pub trait SnapStateOracle: Send + Sync {
    /// Cooperative execution check, including cache-only EVM instruction runs.
    /// Fixtures and sans-I/O consumers may leave this unlimited.
    fn check_request(&self) -> Result<(), OracleError> { Ok(()) }

    /// What this oracle's reads have cost on the wire so far — for the
    /// per-call breakdown a host logs (#532). Default: nothing measured.
    fn wire_cost(&self) -> WireCost {
        WireCost::default()
    }

    /// Whether a convergence loop may start discovery pass `pass`: the loop
    /// asks before each one, and pass 0 starts a loop. A pass is an EVM run
    /// plus a prefetch wave, and its yield does not predict the next one's,
    /// so discovery is bounded in time (#532 review). The bound is the
    /// oracle's to keep, as it owns a clock and this crate holds none. It
    /// decides when passes may start, and a pass under way finishes its wave,
    /// which fetches the state the pass found. Past
    /// it the loop makes its real runs, which fetch what is left one read at
    /// a time; the answer never depends on it. Default: always, so only the
    /// iteration cap bounds discovery.
    fn keep_discovering(&self, _pass: usize) -> bool {
        true
    }

    /// The proof-verified account at `address`, or `Ok(None)` when an exclusion
    /// proof shows it absent. `Err` only when it cannot be verified.
    fn fetch_account(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
    ) -> Result<Option<OracleAccount>, OracleError>;

    /// The proof-verified value at `slot` (a raw 32-byte storage position, as the
    /// `U256` index `revm` passes). `Ok(U256::ZERO)` for an absent/zero slot.
    fn fetch_storage(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
        slot: U256,
    ) -> Result<U256, OracleError>;

    /// Bytecode whose `keccak256` equals `code_hash` (content-addressed, so not
    /// tied to a state root). Empty for the empty-code hash.
    fn fetch_bytecode(&self, code_hash: &[u8; 32]) -> Result<Vec<u8>, OracleError>;
```

- **Default methods.** `check_request`, `wire_cost` and `keep_discovering` have bodies, so an implementor may skip them, exactly like Java 8 `default` interface methods. The three `fetch_*` methods end in `;`: every implementor must write them.
- `SnapStateOracle: Send + Sync` means every implementor must be safe to move between threads and to share between threads. That lets callers hold it in an `Arc<dyn SnapStateOracle>` used by several threads.
- `&self` everywhere: every method borrows the oracle it's called on (see [Methods and `self`](#primer-methods) above). The oracle is shared, so any caching inside it must use [interior mutability](#primer-interior-mutability).
- **Two ways to use a trait.** A generic `fn run<O: SnapStateOracle>(o: &O)` (or `impl SnapStateOracle` in argument position) is compiled once per concrete type. This is *static dispatch*, with no type erasure. `&dyn SnapStateOracle`, `Box<dyn …>` and `Arc<dyn …>` are *trait objects*: a data pointer plus a vtable pointer, dispatched at run time exactly like a Java interface call.
- `#[derive(Clone, Debug, PartialEq, Eq)]`, as on `EvmError` above, asks the compiler to generate those trait impls, much like a Kotlin `data class` generates `equals`/`toString`.

<a id="primer-smart-pointers"></a>

## Box, Arc and Drop: owning things on the heap

- `Box<T>` is **one** owner of a heap value. It's used for large values, recursive types, and `Box<dyn Trait>`.
- `Rc<T>` and `Arc<T>` provide **shared** ownership. The heap block carries a reference count. `Arc::clone(&x)` only increments the count: it is cheap and copies nothing else. Each drop decrements it, and at zero the value is freed. `Arc` uses an atomic counter, so it can cross threads; this codebase uses `Arc` throughout, because nearly everything runs on a multi-threaded runtime.
- `Weak<T>` is a non-owning pointer into an `Arc`. `upgrade()` gives `Some(Arc)` only while the value still exists. `ElReader` keeps its in-flight operations as `Weak`, so the registry never keeps a finished request alive.
- `Drop` is the destructor trait. It runs deterministically when the last owner goes away, which makes *guards* possible: values whose whole job is to clean up when they die.

Why `ChainEntry::Running` keeps its reader as `Option<Arc<ElReader>>` is explained right in the source (line 68–70, above): a verified read can take a minute, so a query clones the `Arc` out of the locked map and runs *outside* the lock. If `stop` removes the entry meanwhile, the reader stays alive until that query's clone is dropped.

`rust/myotis-net/src/el/peer.rs` · lines 153–172

```rust
struct PendingGuard {
    pending: PendingMap,
    id: u64,
    armed: bool,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pending = Arc::clone(&self.pending);
            let id = self.id;
            handle.spawn(async move {
                pending.lock().await.remove(&id);
            });
        }
    }
}
```

`PendingGuard` is a guard. When a request future is dropped (cancelled) before its answer arrives, the guard's `drop` removes the request's entry from the pending map. `drop` can't `.await`, so it clones the `Arc` and *moves* the clone into a small spawned task (`async move`) that takes the async lock. The task owns its own reference, so it doesn't matter that the guard is gone by then.

> [!NOTE]
> **JVM lens**
>
> `Drop` is `try-with-resources` / `AutoCloseable` without the `try`. It runs on every exit path, including early `return`, `?` and cancellation. `Arc` behaves like a Java reference whose GC is a counter you can reason about: you know exactly which line frees the object.

<a id="primer-interior-mutability"></a>

## Interior mutability: changing things through `&self`

Shared ownership (`Arc<T>`) only hands out `&T`, and `&T` forbids mutation. To change shared state, the *type itself* must coordinate access:

- `Mutex<T>`: the data lives *inside* the mutex. `lock()` returns a `MutexGuard` that dereferences to `&mut T` and unlocks when dropped. You physically cannot touch the data without the lock. `RwLock<T>` is the many-readers variant.
- Atomics (`AtomicU64`, `AtomicBool`, …) handle single numbers or flags with `load`/`store`/`fetch_add` and an `Ordering` argument, which here means CPU memory ordering, not sorting.
- `OnceLock<T>`: initialise once, read forever. It's how the engine singleton is built.
- `Cell`/`RefCell` are the single-threaded versions, rare here (`myotis-node` uses a `RefCell` in a thread-local).

`rust/myotis-engine/src/host.rs` · lines 181–215

```rust
static ENGINE: OnceLock<Option<EngineState>> = OnceLock::new();

/// Lazily build (or return) the engine. `None` means the tokio runtime could not
/// be created — the whole hosting surface is then unavailable, but no panic.
fn engine() -> Option<&'static EngineState> {
    ENGINE
        .get_or_init(|| {
            match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("myotis-engine")
                .build()
            {
                Ok(rt) => Some(EngineState {
                    rt,
                    handles: Mutex::new(HashMap::new()),
                    // Start at 1 so a valid id is never confused with the -1 sentinel.
                    next_id: AtomicI64::new(1),
                    pending_served_window: Mutex::new(HashMap::new()),
                    pending_boot_enodes: Mutex::new(HashMap::new()),
                    boot_enodes_apply: Mutex::new(()),
                    log_index_runtime_bits: Mutex::new(HashMap::new()),
                    activity_watch: Mutex::new(HashMap::new()),
                    fee_history_cache: Mutex::new(HashMap::new()),
                    fork_watches: Mutex::new(HashMap::new()),
                    cl_fork_watches: Mutex::new(HashMap::new()),
                    el_carries: Mutex::new(HashMap::new()),
            create_lock: Mutex::new(()),
            tearing_down: Mutex::new(std::collections::HashSet::new()),
                    usage: Mutex::new(HashMap::new()),
                }),
                Err(_) => None,
            }
        })
        .as_ref()
}
```

`static ENGINE` is a process-global. `get_or_init` runs the closure at most once, even if several JVM threads call in at the same time; the others wait. The result is `Option<EngineState>` (`None` if the tokio runtime could not start), and `engine()` returns `Option<&'static EngineState>`: a borrow valid for the rest of the program. Inside `EngineState`, every mutable part is wrapped: `handles: Mutex<HashMap<…>>`, `next_id: AtomicI64`.

![Two tasks each own an Arc pointing to the same heap allocation, which holds a strong count of 2 and a Mutex wrapping a HashMap of pending requests. The read-loop task currently holds the MutexGuard and has mutable access to the map; the request caller waits for the lock. Cloning an Arc increments the count; dropping one decrements it and the allocation is freed at zero.](img/01-primer-2.svg)

*`Arc<Mutex<T>>` is the Rust spelling of “a shared object guarded by a lock”. The `Arc` answers *who keeps it alive*; the `Mutex` answers *who may touch it right now*. The example is the pending-request map in `el/peer.rs`.*

<a id="primer-concurrency"></a>

## Threads, `Send` and `Sync`

Two marker traits carry thread safety in the type system. `Send` means a value may be *moved* to another thread. `Sync` means a `&T` may be *shared* between threads. The compiler derives them automatically from a type's fields: `Arc<Mutex<T>>` is both when `T: Send`, while `Rc` and `RefCell` are neither. So “forgot to synchronise” is a compile error, not a heisenbug.

Channels are the other half: `mpsc` (many producers, one consumer), `oneshot` (exactly one value), and `watch` (the latest value, observed by many). Here is how one managed peer correlates responses with requests:

`rust/myotis-net/src/el/peer.rs` · lines 52–58

```rust
/// One in-flight request: the response code it expects and the delivery channel.
struct Pending {
    want_code: u64,
    tx: oneshot::Sender<Result<Vec<u8>, String>>,
}

type PendingMap = Arc<Mutex<HashMap<u64, Pending>>>;
```

Every outstanding request inserts a `Pending` keyed by its request id. The `tx` half of a `oneshot` channel sits in the map, and the requester awaits the `rx` half. When the read loop decodes a response, it removes the entry and sends the bytes through `tx`. The struct that owns all this shows the whole concurrency toolbox in its first fields:

`rust/myotis-net/src/el/peer.rs` · lines 299–321

```rust
/// A negotiated eth/snap peer, driven by a background read loop.
pub struct ManagedPeer {
    writer: SharedWriter,
    pending: PendingMap,
    next_id: AtomicU64,
    /// Set once the read loop terminates (disconnect / read error); requests
    /// short-circuit instead of hanging until timeout.
    closed: Arc<AtomicBool>,
    /// Why (see [`SharedCloseReason`]); `None` while open.
    close_reason: SharedCloseReason,
    /// Consecutive request timeouts with no answer in between — the log
    /// throttle: the first of a silent streak is a WARN naming the peer, the
    /// rest are DEBUG (an EVM prefetch has dozens of requests in flight
    /// against one peer; one line says which peer went silent, the next 47
    /// would only repeat it). Reset by any delivered response.
    timeout_streak: AtomicU64,
    /// When the read loop last delivered a response to one of our requests
    /// (any request: a snap proof, a header window, a body). A peer whose
    /// responses keep arriving — however slowly, on a slow link — is not
    /// SILENT, whatever one request's age; the prefetch wave judges silence by
    /// this, not by request age (#320).
    last_response: SharedLastResponse,
    reader_task: std::sync::Mutex<Option<JoinHandle<()>>>,
```

> [!NOTE]
> **JVM lens**
>
> `PendingMap` is the Rust version of `ConcurrentHashMap<Long, CompletableFuture<byte[]>>`: `oneshot::Sender` ≈ `complete()`, `oneshot::Receiver` ≈ `get()`. `next_id: AtomicU64` is `AtomicLong.incrementAndGet()`. `closed: Arc<AtomicBool>` is a shared `volatile boolean` that the read-loop task also holds.

<a id="primer-async"></a>

## async/await and tokio

An `async fn` returns a `Future`: a state machine that does **nothing** until something polls it. `.await` polls it and, if it isn't ready, suspends the current task so the thread can run other tasks. tokio's multi-threaded runtime is the thing that polls: a few worker threads, thousands of tasks, and an I/O reactor (Netty's event loop, essentially).

- **`tokio::spawn(fut)`** hands a future to the runtime as an independent task and returns a `JoinHandle`. The task may run on any worker thread and may outlive its creator, hence `Send + 'static`. Data it needs is *moved* in, usually through `async move { … }` and cloned `Arc`s.
- **Cancellation is dropping.** A future that is dropped is simply never polled again. It stops at its last `.await`, and its locals' destructors run. There is no exception, which is why guards such as `PendingGuard` exist, and why `peer.rs` marks a frame write as `torn` before it starts (lines 56–62): a write cancelled halfway must not be followed by another.
- **`tokio::select!`** waits on several futures and runs the branch of whichever finishes first, dropping the others.
- **Two kinds of mutex.** `std::sync::Mutex` is fine for short critical sections that never `.await` while locked. `tokio::sync::Mutex` (`lock().await`) is for locks held *across* an `.await`, such as the peer's frame writer, which sends over the network while locked.

`rust/myotis-net/src/el/request.rs` · lines 117–130

```rust
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

`Operation::wait` wraps any future with a cooperative budget. `tokio::pin!` fixes the future in place so it can be polled *by reference* (`&mut future`) on every loop iteration without being restarted. Each 10 ms the `sleep` branch wins, `self.check()?` returns `Err` if the operation was cancelled or ran out of time, and dropping out of the function drops the wrapped future. `biased;` makes `select!` poll the branches in order instead of randomly.

### Crossing between blocking and async code

FFI callers (JVM threads, iOS threads) are ordinary blocking threads, and so is revm, the EVM library. Two bridges connect them to the async world:

- `runtime.block_on(fut)` / `Handle::block_on(fut)`: a *blocking* thread runs a future to completion. The engine uses it for every FFI call (`host.rs` line 614). It must never be called on a runtime worker thread, where it panics.
- `tokio::task::spawn_blocking(closure)`: async code hands blocking work to a separate thread pool and awaits the result.

The EVM path uses both in sequence: the async reader `spawn_blocking`s the revm execution, and inside it, each state read `block_on`s an async network fetch.

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

Note the RAII in the closure. `let _permit = permit;` moves the semaphore permit into the blocking thread. The permit is released when the closure returns and `_permit` is dropped, which caps concurrent EVM executions at `BLOCKING_SLOTS_MAX` (8) process-wide. A ninth call waits its turn in a FIFO queue for up to `BLOCKING_WAIT` (5 s) before it is refused. The `_worker` guard does the same RAII trick for the operation's bookkeeping.

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

> [!NOTE]
> **Kotlin lens**
>
> Kotlin coroutines are the closest match. `async fn` ≈ `suspend fun`, `tokio::spawn` ≈ `scope.launch`, `block_on` ≈ `runBlocking`, `spawn_blocking` ≈ `withContext(Dispatchers.IO)`, `select!` ≈ `select { }`, and a `oneshot` ≈ `CompletableDeferred`. The big difference is cancellation: Kotlin throws `CancellationException` at the next suspension point, while Rust just stops polling and runs destructors.

<a id="primer-iterators-closures"></a>

## Closures and iterators

A closure `|x| …` captures variables from its surroundings, by reference by default and by value with `move`. Closures that must outlive the current function (spawned tasks, `spawn_blocking`) are almost always `move`. Iterator chains are lazy like Kotlin sequences: `(0..len).map(|i| …).collect()` builds a `Vec` in one pass, and `tasks.1.retain(|task| !task.is_finished())` (in `tasks.rs` above) filters in place. The closure traits `Fn`, `FnMut` and `FnOnce` say whether a closure can be called repeatedly and whether it mutates or consumes its captures. `blocking(f: impl FnOnce() -> T …)` accepts a closure that runs exactly once, so it may move captured values out.

<a id="primer-macros"></a>

## Macros and attributes

Anything with a `!` is a macro call that expands at compile time: `format!`, `write!`, `vec!`, `tokio::select!`, `tokio::pin!`. Attributes in `#[…]` either configure the compiler or run a procedural macro:

- `#[derive(Debug, Clone)]` generates trait impls.
- `#[cfg(test)]` and `#[cfg(feature = "tor")]` include code only in test builds or when a Cargo feature is on. `host.rs` has two bodies for `set_tor_enabled`, and exactly one is compiled.
- `#[tokio::test]`, `#[tokio::main]`, `#[uniffi::export]` and `#[napi]` rewrite the item they sit on: they start a runtime, or generate FFI glue.

`rust/myotis-engine/src/host.rs` · lines 233–244

```rust
pub fn set_tor_enabled(on: bool) -> bool {
    #[cfg(feature = "tor")]
    {
        myotis_net::el::tor::set_enabled(on);
        true
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = on;
        false
    }
}
```

<a id="primer-modules-cargo"></a>

## Crates, modules and features (short)

A *crate* is a compilation unit, either a library or a binary. A *workspace* builds several crates together. Inside a crate, `mod x;` declares a module, which lives in `x.rs` or `x/mod.rs`. Items are private by default. `pub` exports an item, `pub(crate)` exposes it to the whole crate only, and `pub(super)` to the parent module. Cargo *features* are compile-time switches, such as `tor` or `jni`. Full treatment in [Stop 2](02-workspace.md).

<a id="primer-unsafe-ffi"></a>

## `unsafe` and FFI (short)

`unsafe { … }` lets you do five extra things, the main one being dereferencing a raw pointer. You then promise the compiler the invariants it can't check. At a foreign-function boundary (`extern "C"`), ownership stops being visible to the compiler, so the API must document who allocates and who frees. The C header says it bluntly: every returned string must be released with `myotis_string_free`. Full treatment in [Stop 13](13-el-services.md).

<a id="primer-testing"></a>

## Tests (short)

Unit tests live next to the code in a `#[cfg(test)] mod tests { … }` block and may test private items. Integration tests live in a crate's `tests/` directory and see only the public API. `#[ignore]` keeps a test out of the default run (`cargo test -- --ignored` runs it). Myotis uses that for every test that needs the live network. Full treatment in [Stop 12](12-el-pool.md).

<a id="primer-cli"></a>

## Binaries and CLIs (short)

A binary crate has `fn main()`. An async one uses `#[tokio::main]` to start the runtime. Applications often use `anyhow::Result`, a catch-all error type with context messages, where libraries define precise error enums. `roost` is the example; see [Stop 15](15-net-tests.md).

<a id="primer-domain"></a>

## Protocol knowledge (short)

You know the protocols from the Java engine. The Rust code uses the same vocabulary: slots (12 s), sync-committee periods (8,192 slots), SSZ and `hash_tree_root` on the consensus side, RLP and keccak-256 on the execution side, and never the two hashes mixed. When a term is unclear, the design docs under `docs/reimplementation/` are the reference. [Stop 0](00-map.md) lists the trust chain.

## Cheat sheet: Java/Kotlin → Rust

| You would write | Rust spelling | Notes |
|---|---|---|
| null / T? | `Option<T>` | `?` ≈ `?: return null`; `unwrap()` ≈ `!!` (panics) |
| throws / try-catch | `Result<T, E>` + `?` | `impl From<A> for B` makes `?` convert errors |
| interface | `trait` | generic = static dispatch; `dyn Trait` = virtual call |
| this / instance method | `fn m(&self, …)` in an `impl` | `x.m(a)` is `Type::m(&x, a)`; the receiver says read, modify or consume |
| static method / companion | associated function `Type::f(…)` | no `self`; `new` is a naming convention, not a keyword |
| sealed class + when | `enum` + `match` | exhaustive; variants carry data |
| data class | `#[derive(Clone, Debug, PartialEq)] struct` | `Clone` is always explicit |
| synchronized / ReentrantLock | `Mutex<T>` | data inside the lock; unlock = guard dropped |
| AtomicLong / volatile | `AtomicU64` / `AtomicBool` | explicit `Ordering` per operation |
| shared reference + GC | `Arc<T>` | freed when the last clone drops |
| try-with-resources | `impl Drop` | runs on every exit path, including cancellation |
| static lazy singleton | `static X: OnceLock<T>` | initialised once, thread-safe |
| CompletableFuture | `Future` / `oneshot` | futures are lazy until polled |
| ExecutorService / Netty loop | tokio `Runtime` | `spawn`, `block_on`, `spawn_blocking` |
| byte\[\] / ByteBuffer.slice() | `Vec<u8>` / `&[u8]` | fixed sizes: `[u8; 32]` (Copy) |
| val / var | `let` / `let mut` | immutability is deep for owned data |
| generics (erased) | generics (monomorphised) | a specialised copy per type; bounds like `T: Send` |

## Checkpoint

18 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-s01-q1"></a>

**Q1** · Multiple choice

`SyncHandle::start` takes `config: ChainConfig` by value. What happens here?

```text
let cfg = ChainConfig::mainnet();
let h = SyncHandle::start(cfg);
println!("{}", cfg.name);
```

- **A.** It prints `mainnet`
- **B.** It fails to compile: `cfg` was moved into `start`
- **C.** It compiles but panics at run time because `cfg` is null
- **D.** It prints a copy that `start` made

[Answer →](answers.md#a-s01-q1)

<a id="q-s01-q2"></a>

**Q2** · Multiple choice

Which of these types is `Copy`, so assigning it leaves the original usable?

- **A.** `Vec<u8>`
- **B.** `String`
- **C.** `[u8; 32]`
- **D.** `Arc<ElReader>`

[Answer →](answers.md#a-s01-q2)

<a id="q-s01-q3"></a>

**Q3** · Multiple choice

`Reader::fixed(&mut self, len)` returns `Option<&'a [u8]>`. Why `'a` rather than the lifetime of `&mut self`?

- **A.** So the returned slice borrows the original buffer, and the caller can keep it while calling `fixed` again
- **B.** Because `'a` means the slice is copied to the heap
- **C.** Because lifetimes must always be named in structs
- **D.** So that the slice lives for the whole program

[Answer →](answers.md#a-s01-q3)

<a id="q-s01-q4"></a>

**Q4** · Written answer

Explain in your own words what `struct Reader<'a> { data: &'a [u8], pos: usize }` promises, and what bug this rules out that a C program could have.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-s01-q4)

<a id="q-s01-q5"></a>

**Q5** · Multiple choice

In `Some(u32::from_be_bytes(self.fixed(4)?.try_into().ok()?))`, what does the *second* `?` do?

- **A.** Panics if the slice has the wrong length
- **B.** Returns `None` from the enclosing function if the slice could not be converted to `[u8; 4]`
- **C.** Converts the error into a `String`
- **D.** Retries the read

[Answer →](answers.md#a-s01-q5)

<a id="q-s01-q6"></a>

**Q6** · Multiple choice

What does `impl From<OracleError> for EvmError` enable?

- **A.** Catching `OracleError` exceptions
- **B.** Using `?` on a `Result<_, OracleError>` inside a function that returns `Result<_, EvmError>`; the error is converted automatically
- **C.** Converting an `EvmError` back into an `OracleError`
- **D.** Printing an `OracleError`

[Answer →](answers.md#a-s01-q6)

<a id="q-s01-q7"></a>

**Q7** · Multiple choice

In `spin_up`, the code does `Arc::clone(c)` inside a block that holds `engine.handles.lock()`, then calls `block_on` after the block. Why?

- **A.** `Arc::clone` deep-copies the config so it can be mutated
- **B.** It takes a cheap extra reference so the lock can be released *before* the slow start, and other FFI calls aren't blocked
- **C.** It is required because `block_on` only accepts clones
- **D.** It leaks the config on purpose

[Answer →](answers.md#a-s01-q7)

<a id="q-s01-q8"></a>

**Q8** · Written answer

`Tasks::spawn(&self, …)` only has a shared reference, yet it pushes into a `Vec`. Explain how that is allowed, and what releases the lock.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-s01-q8)

<a id="q-s01-q9"></a>

**Q9** · Multiple choice

Why does `Tasks::spawn` require `impl Future<Output = ()> + Send + 'static`?

- **A.** Because futures must return `()` to compile
- **B.** tokio may run the task on any worker thread (`Send`), and the task may outlive the caller, so it may not hold borrowed references (`'static`)
- **C.** Because `'static` futures are cached forever
- **D.** It is only a style convention

[Answer →](answers.md#a-s01-q9)

<a id="q-s01-q10"></a>

**Q10** · Multiple choice

How is an in-flight async request cancelled in Rust?

- **A.** By throwing `CancellationException` into it
- **B.** By calling `future.cancel()`, which interrupts the thread
- **C.** By dropping its future: it is never polled again, stops at its last `.await`, and its destructors run
- **D.** It cannot be cancelled

[Answer →](answers.md#a-s01-q10)

<a id="q-s01-q11"></a>

**Q11** · Multiple choice

The peer's frame writer uses `tokio::sync::Mutex` rather than `std::sync::Mutex`. What is the reason?

- **A.** tokio's mutex is faster in every case
- **B.** The lock is held across `writer.send(…).await`. An async mutex yields instead of blocking a worker thread, and its guard can be held across `.await` in a `Send` task
- **C.** std's mutex cannot hold a `Vec`
- **D.** tokio's mutex cannot be poisoned, which is required by `panic = "abort"`

[Answer →](answers.md#a-s01-q11)

<a id="q-s01-q12"></a>

**Q12** · Written answer

The EVM (revm) is synchronous, but state has to be fetched from peers over the async network. Describe how `myotis-net` connects the two, and why the EVM must not run directly on a tokio worker thread.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-s01-q12)

<a id="q-s01-q13"></a>

**Q13** · Multiple choice

When does `PendingGuard::drop` run, and why does it spawn a task instead of removing the map entry directly?

- **A.** Only when the program exits; spawning makes it faster
- **B.** When the guard goes out of scope, including when the request future is dropped. `drop` cannot `.await` the async mutex, so it moves an `Arc` clone into a spawned task that can
- **C.** Whenever the garbage collector runs; spawning avoids pauses
- **D.** Never, because guards are `'static`

[Answer →](answers.md#a-s01-q13)

<a id="q-s01-q14"></a>

**Q14** · Multiple choice

`match (from, map.get(&handle)) { (Created, Some(ChainEntry::Created(c))) => …, (Paused, Some(ChainEntry::Paused(c, _, stats))) => …, _ => return false }`. What is the final arm for?

- **A.** It is optional decoration
- **B.** `match` must be exhaustive. `_` covers an unknown handle id (`None`) and every state/transition mismatch in one arm
- **C.** It matches only `None`
- **D.** It re-throws the error

[Answer →](answers.md#a-s01-q14)

<a id="q-s01-q15"></a>

**Q15** · Multiple choice

`fn fetch_account(&self, state_root: &[u8; 32], address: [u8; 20])` is called as `oracle.fetch_account(&root, addr)`. Which statement is right?

- **A.** `self` isn't a real parameter; a method only receives what's in the parentheses
- **B.** It has three parameters. The value left of the dot is passed as `self` (borrowed as `&oracle`), so the call is the same as `SnapStateOracle::fetch_account(&oracle, &root, addr)`
- **C.** `self` refers to a global oracle object
- **D.** `&self` means the method works on a copy of the oracle

[Answer →](answers.md#a-s01-q15)

<a id="q-s01-q16"></a>

**Q16** · Multiple choice

`EnrSeq::bump` ends with `self.current = next;`. Which receiver does it need, and what does that require from the caller?

- **A.** `&self`, and any reference to the `EnrSeq` will do
- **B.** `&mut self`: the caller needs mutable access, for example a `let mut` binding, and no other borrow of the value may be alive during the call
- **C.** `self`, so the caller loses the value
- **D.** No receiver: it's an associated function

[Answer →](answers.md#a-s01-q16)

<a id="q-s01-q17"></a>

**Q17** · Multiple choice

`SyncHandle` has `pub async fn stop(self)`. What happens if code calls `handle.status()` after `handle.stop().await`?

- **A.** It returns the last status before the stop
- **B.** It fails to compile: `stop` takes `self` by value, so `handle` was moved into it
- **C.** It panics at run time
- **D.** It restarts the sync loop

[Answer →](answers.md#a-s01-q17)

<a id="q-s01-q18"></a>

**Q18** · Written answer

The test helper `struct Counting { inner: FixtureSnapStateOracle, fetches: AtomicUsize }` implements `SnapStateOracle`. Explain what `self.inner.fetch_account(r, a)` does inside its `fetch_account`: what are `self` and `inner`, is anything copied, and how can `fetches` be incremented through `&self`?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-s01-q18)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
