# Checkpoint answers

*Appendix*

One section per stop. For multiple choice, the correct option and why. For written answers, a model answer and the points a good answer covers: count how many of yours hit. Four of five is solid; two or fewer means the concept deserves a second pass with the reading list.

## Stop 0 · Start here: the map

<a id="a-s00-q1"></a>

**Q1** · Which crate is allowed to open sockets and read the wall clock?

**Answer: C.** `myotis-net`

`myotis-net` owns all I/O. Core, wire, consensus and EVM are sans-I/O: they receive bytes and plain numbers (such as the current slot) and return values. Core, wire and consensus are additionally compiled for wasm32 as a canary, which fails as soon as tokio or sockets sneak in.

[← Back to the question](00-map.md#q-s00-q1)

<a id="a-s00-q2"></a>

**Q2** · How does a call from the Android app reach the Rust engine, compared with a call from the iOS app?

**Answer: B.** Android: UniFFI-generated Kotlin bindings over JNA into `ffi.rs`. iOS: Kotlin/Native cinterop against the plain C ABI in `capi.rs`

JVM hosts use UniFFI (the old hand-JNI shims are gone, see `lib.rs`). The iOS host has no JVM, so it links the static library and calls the `extern "C"` functions declared in `rust/include/myotis_engine.h`. `myotis-node` reuses those same C-ABI functions by Rust path.

[← Back to the question](00-map.md#q-s00-q2)

<a id="a-s00-q3"></a>

**Q3** · Why are `roost` and `tor-poc` excluded from the workspace instead of being members?

**Answer: B.** They pull large dependency trees (an HTTP stack, Arti) that no engine target should compile. `roost` also needs `panic = "unwind"`, which a member cannot set

Both depend on `myotis-net` by path, but as members they would make every `cargo build --workspace` compile their heavy dependencies. Profiles are workspace-wide, so only a separate workspace root lets `roost` unwind on panic. That turns a panic into a logged, supervised restart instead of an instant abort. Stop 15 shows why it still doesn't isolate a single connection.

[← Back to the question](00-map.md#q-s00-q3)

<a id="a-s00-q4"></a>

**Q4** · The release profile sets `panic = "abort"`. Explain what that means for a Rust panic inside the Android app, and how it changes the way the code handles untrusted bytes.

**Model answer.** With `panic = "abort"`, a panic does not unwind the stack. It terminates the process immediately. The Rust engine runs inside the app's process (loaded through JNA or cinterop), so a panic kills the whole Android or iOS app, and `catch_unwind` cannot help because nothing unwinds. The code therefore treats every decode of peer-supplied bytes as fallible: it returns `Option`/`Result`, uses checked arithmetic and `.get()` instead of indexing, and avoids `unwrap()`/`expect()` on runtime data. The FFI layer turns errors into sentinels or `{"error": …}` JSON.

A good answer covers:

- abort = no unwinding; the process ends immediately
- the engine lives in the host's process, so the host app dies
- catch\_unwind cannot recover it
- hence no unwrap/indexing on untrusted data; errors are values (Option/Result) mapped to sentinels/JSON

[← Back to the question](00-map.md#q-s00-q4)

<a id="a-s00-q5"></a>

**Q5** · In the trust chain, what anchors an account balance that the reader returns?

**Answer: B.** A Merkle-Patricia proof against a state root, whose header is linked by hash to a block that the beacon light client verified through sync-committee BLS signatures

Rule 5: signatures anchor the beacon chain, which anchors an execution block hash, which anchors headers and their state roots, which anchor MPT proofs. HTTP calls to a local client are allowed only for debugging, never in production.

[← Back to the question](00-map.md#q-s00-q5)

## Stop 1 · Rust's memory model for JVM developers

<a id="a-s01-q1"></a>

**Q1** ·

`SyncHandle::start` takes `config: ChainConfig` by value. What happens here?

```text
let cfg = ChainConfig::mainnet();
let h = SyncHandle::start(cfg);
println!("{}", cfg.name);
```

**Answer: B.** It fails to compile: `cfg` was moved into `start`

Passing by value moves ownership into `start`. Any later use of `cfg` is a compile-time error, “borrow of moved value”. To keep using it you would pass `cfg.clone()`, which is exactly what `host.rs` does with `(*config).clone()`.

[← Back to the question](01-primer.md#q-s01-q1)

<a id="a-s01-q2"></a>

**Q2** · Which of these types is `Copy`, so assigning it leaves the original usable?

**Answer: C.** `[u8; 32]`

A fixed-size array of `Copy` elements is itself `Copy`: the 32 bytes are duplicated bit for bit. `Vec` and `String` own heap memory, so they move. `Arc` is not `Copy` either; you duplicate it with `Arc::clone`, which bumps the reference count.

[← Back to the question](01-primer.md#q-s01-q2)

<a id="a-s01-q3"></a>

**Q3** · `Reader::fixed(&mut self, len)` returns `Option<&'a [u8]>`. Why `'a` rather than the lifetime of `&mut self`?

**Answer: A.** So the returned slice borrows the original buffer, and the caller can keep it while calling `fixed` again

`'a` is the lifetime of the *data* the reader borrows. Tying the result to `'a` means “this slice points into that data”, not into the reader. With the elided form, the slice would keep the `&mut` borrow of the reader alive, and a second `fixed` call would not compile.

[← Back to the question](01-primer.md#q-s01-q3)

<a id="a-s01-q4"></a>

**Q4** · Explain in your own words what `struct Reader<'a> { data: &'a [u8], pos: usize }` promises, and what bug this rules out that a C program could have.

**Model answer.** The struct doesn't own its bytes; it borrows a byte slice owned by someone else, for some span `'a`. The compiler then guarantees that no `Reader` outlives the buffer it reads, and that nobody mutates or frees the buffer while the reader (or any slice it returned) exists. In C, a reader struct holding a raw pointer could outlive the buffer (use-after-free), or the buffer could be reallocated underneath it. In Rust, that is a compile error. Java avoids the problem with GC instead: the array stays alive as long as any reference exists.

A good answer covers:

- Reader borrows (does not own) the bytes
- 'a ties the reader's validity to the buffer's lifetime
- compiler rejects outliving the buffer / mutating it meanwhile
- prevents use-after-free / dangling pointer (C); Java avoids it via GC

[← Back to the question](01-primer.md#q-s01-q4)

<a id="a-s01-q5"></a>

**Q5** · In `Some(u32::from_be_bytes(self.fixed(4)?.try_into().ok()?))`, what does the *second* `?` do?

**Answer: B.** Returns `None` from the enclosing function if the slice could not be converted to `[u8; 4]`

`try_into()` yields `Result<[u8; 4], _>`. `.ok()` turns it into `Option`, and `?` on an `Option` returns `None` early. The first `?` handles “not enough bytes left”.

[← Back to the question](01-primer.md#q-s01-q5)

<a id="a-s01-q6"></a>

**Q6** · What does `impl From<OracleError> for EvmError` enable?

**Answer: B.** Using `?` on a `Result<_, OracleError>` inside a function that returns `Result<_, EvmError>`; the error is converted automatically

`?` calls `From::from` on the error before returning it, so a state-fetch failure becomes `EvmError::Oracle(e)` without any explicit mapping. `Display` is what printing needs.

[← Back to the question](01-primer.md#q-s01-q6)

<a id="a-s01-q7"></a>

**Q7** · In `spin_up`, the code does `Arc::clone(c)` inside a block that holds `engine.handles.lock()`, then calls `block_on` after the block. Why?

**Answer: B.** It takes a cheap extra reference so the lock can be released *before* the slow start, and other FFI calls aren't blocked

`Arc::clone` only increments a counter. With its own reference, the code can let the `MutexGuard` drop at the end of the block, which unlocks the map, and then do slow work without serialising every other native call behind it.

[← Back to the question](01-primer.md#q-s01-q7)

<a id="a-s01-q8"></a>

**Q8** · `Tasks::spawn(&self, …)` only has a shared reference, yet it pushes into a `Vec`. Explain how that is allowed, and what releases the lock.

**Model answer.** The `Vec` lives inside a `Mutex` (interior mutability). `&self` gives shared access to the mutex, and `lock()` returns a `MutexGuard` that dereferences to `&mut` of the inner tuple, so the push is legal while the guard exists. The lock is released automatically when the guard (`tasks`) goes out of scope at the end of the method, including on the early `return`, because the guard's `Drop` unlocks. `unwrap_or_else(|e| e.into_inner())` recovers the guard even if the mutex was poisoned.

A good answer covers:

- the Vec is inside a Mutex (interior mutability)
- lock() yields a guard that gives &mut access
- unlock happens when the guard is dropped (end of scope, any exit path)
- poison recovery via into\_inner (optional detail)

[← Back to the question](01-primer.md#q-s01-q8)

<a id="a-s01-q9"></a>

**Q9** · Why does `Tasks::spawn` require `impl Future<Output = ()> + Send + 'static`?

**Answer: B.** tokio may run the task on any worker thread (`Send`), and the task may outlive the caller, so it may not hold borrowed references (`'static`)

`tokio::spawn` itself has these bounds. `Send` lets the scheduler move the task between threads. `'static` means the future owns everything it touches, so no dangling borrow can appear when the spawning function returns. That's why tasks are written as `async move { … }` with cloned `Arc`s.

[← Back to the question](01-primer.md#q-s01-q9)

<a id="a-s01-q10"></a>

**Q10** · How is an in-flight async request cancelled in Rust?

**Answer: C.** By dropping its future: it is never polled again, stops at its last `.await`, and its destructors run

Dropping is cancellation. Code has to be *cancel-safe*: it must not leave half-finished state at an `.await`. That's why `PendingGuard` cleans up in `Drop`, and why `GuardedWriter` sets `torn` before a frame write.

[← Back to the question](01-primer.md#q-s01-q10)

<a id="a-s01-q11"></a>

**Q11** · The peer's frame writer uses `tokio::sync::Mutex` rather than `std::sync::Mutex`. What is the reason?

**Answer: B.** The lock is held across `writer.send(…).await`. An async mutex yields instead of blocking a worker thread, and its guard can be held across `.await` in a `Send` task

Holding a std guard across an `.await` would block the thread and makes the future non-`Send`. The rule of thumb: a std mutex for short, non-awaiting critical sections; a tokio mutex when the critical section awaits.

[← Back to the question](01-primer.md#q-s01-q11)

<a id="a-s01-q12"></a>

**Q12** · The EVM (revm) is synchronous, but state has to be fetched from peers over the async network. Describe how `myotis-net` connects the two, and why the EVM must not run directly on a tokio worker thread.

**Model answer.** The async reader first moves the EVM run onto a blocking thread with `spawn_blocking` (via `request::blocking`). While executing, revm calls the synchronous `SnapStateOracle` methods. The implementation (`PoolOracle`) bridges each call back into async code with `Handle::block_on`, which drives the network fetch and verification to completion and blocks only that blocking thread. If revm ran on a worker thread, `block_on` would panic (it may not be called from an async execution context), and the blocking EVM loop would starve other tasks on that worker.

A good answer covers:

- spawn\_blocking moves revm off the async workers
- the sync oracle trait is implemented with Handle::block\_on around async fetches
- block\_on on a runtime worker panics / blocking starves the worker
- result flows back through the awaited JoinHandle

[← Back to the question](01-primer.md#q-s01-q12)

<a id="a-s01-q13"></a>

**Q13** · When does `PendingGuard::drop` run, and why does it spawn a task instead of removing the map entry directly?

**Answer: B.** When the guard goes out of scope, including when the request future is dropped. `drop` cannot `.await` the async mutex, so it moves an `Arc` clone into a spawned task that can

`Drop::drop` is a synchronous function. The pending map sits behind `tokio::sync::Mutex`, whose `lock()` must be awaited, so the guard spawns a tiny `async move` task that owns its own `Arc` and does the removal.

[← Back to the question](01-primer.md#q-s01-q13)

<a id="a-s01-q14"></a>

**Q14** · `match (from, map.get(&handle)) { (Created, Some(ChainEntry::Created(c))) => …, (Paused, Some(ChainEntry::Paused(c, _, stats))) => …, _ => return false }`. What is the final arm for?

**Answer: B.** `match` must be exhaustive. `_` covers an unknown handle id (`None`) and every state/transition mismatch in one arm

The compiler insists that every possible value is handled. The wildcard makes “anything else → refuse” explicit, which in Java would be a pile of null checks and `instanceof` tests.

[← Back to the question](01-primer.md#q-s01-q14)

<a id="a-s01-q15"></a>

**Q15** · `fn fetch_account(&self, state_root: &[u8; 32], address: [u8; 20])` is called as `oracle.fetch_account(&root, addr)`. Which statement is right?

**Answer: B.** It has three parameters. The value left of the dot is passed as `self` (borrowed as `&oracle`), so the call is the same as `SnapStateOracle::fetch_account(&oracle, &root, addr)`

Method-call syntax is sugar: the receiver becomes the first argument, and the compiler inserts the `&` the signature asks for. That's why roost can pass `EnrSeq::current` to `Option::map` as a plain function.

[← Back to the question](01-primer.md#q-s01-q15)

<a id="a-s01-q16"></a>

**Q16** · `EnrSeq::bump` ends with `self.current = next;`. Which receiver does it need, and what does that require from the caller?

**Answer: B.** `&mut self`: the caller needs mutable access, for example a `let mut` binding, and no other borrow of the value may be alive during the call

Assigning to a field needs exclusive access. With `&self` that's only possible for fields with interior mutability (atomics, `Mutex`). `self` would consume the counter, which the daemon needs for its whole run.

[← Back to the question](01-primer.md#q-s01-q16)

<a id="a-s01-q17"></a>

**Q17** · `SyncHandle` has `pub async fn stop(self)`. What happens if code calls `handle.status()` after `handle.stop().await`?

**Answer: B.** It fails to compile: `stop` takes `self` by value, so `handle` was moved into it

A by-value receiver consumes the object, exactly like passing it by value to any function. The compiler rejects every later use, so a stopped handle can't be used by accident. Java can only document that rule; Rust enforces it.

[← Back to the question](01-primer.md#q-s01-q17)

<a id="a-s01-q18"></a>

**Q18** · The test helper `struct Counting { inner: FixtureSnapStateOracle, fetches: AtomicUsize }` implements `SnapStateOracle`. Explain what `self.inner.fetch_account(r, a)` does inside its `fetch_account`: what are `self` and `inner`, is anything copied, and how can `fetches` be incremented through `&self`?

**Model answer.** `self` is the method's receiver, here `&Counting`: a shared borrow of the `Counting` value the method was called on. `inner` is an ordinary field of `Counting` that holds the wrapped fixture oracle, so `self.inner` is that field, reached through the reference. Calling `fetch_account` on it borrows the field again (`&self.inner`) and forwards the arguments. That's the decorator pattern, Java's `this.inner.fetchAccount(r, a)`. Nothing is copied or moved, and moving a field out of a borrowed struct wouldn't compile anyway. `fetches` is an `AtomicUsize`, whose `fetch_add` takes `&self`, so it can change through a shared reference: interior mutability.

A good answer covers:

- self is the receiver, a shared borrow &Counting
- inner is an ordinary field holding the wrapped oracle; the call forwards to it (decorator)
- nothing is copied or moved; the field is borrowed again
- fetches is atomic, so it can change through &self (interior mutability)

[← Back to the question](01-primer.md#q-s01-q18)

## Stop 2 · The workspace: crates, features and profiles

<a id="a-ws-q1"></a>

**Q1** · `crate-type = ["cdylib", "rlib"]` in `myotis-bls` produces…

**Answer: B.** a C-compatible shared library the JVM can load, and a Rust library other workspace crates link against

`cdylib` is for foreign loaders such as JNI, JNA or `process.dlopen`. `rlib` is Rust-to-Rust linking, which is how `myotis-consensus` calls the verify core directly. The iOS `staticlib` of the engine is produced separately with `cargo rustc --crate-type staticlib`.

[← Back to the question](02-workspace.md#q-ws-q1)

<a id="a-ws-q2"></a>

**Q2** · `myotis-bls` has `default = ["jni", "std"]`. `myotis-consensus` depends on it with `default-features = false` and has `std = ["sha2/std", "tracing/std", "myotis-bls/std"]` as a default feature. What does a default build of consensus get from `myotis-bls`?

**Answer: B.** The BLS verify core with `std`, but without the JNI shim and without the `jni` crate

Turning the defaults off removes `jni` and `std`. Consensus's own default `std` feature then turns `myotis-bls/std` back on. `jni` stays off, so the optional `jni` crate and every `#[cfg(feature = "jni")]` item disappear from the build.

[← Back to the question](02-workspace.md#q-ws-q2)

<a id="a-ws-q3"></a>

**Q3** · Why can't `roost` simply be a workspace member with its own `panic = "unwind"`?

**Answer: B.** Cargo ignores `[profile.*]` in member crates; only the workspace root's profile applies, and that one says `abort`

Profiles are workspace-wide. The only way to get a different panic strategy is a separate workspace root, which an empty `[workspace]` table in `roost/Cargo.toml` creates.

[← Back to the question](02-workspace.md#q-ws-q3)

<a id="a-ws-q4"></a>

**Q4** · `myotis-net` lists itself under `[dev-dependencies]` as `myotis-net = { path = ".", features = ["fixture-recorder"] }`. What is the effect?

**Answer: B.** The feature is on for the crate's tests and examples, and off in the library that the engine links

Dev-dependencies apply only to tests, examples and benches, and under resolver 2 their features do not leak into the normal build. So the fixture recorder example compiles in every `cargo test`, while the shipped library never carries the seam.

[← Back to the question](02-workspace.md#q-ws-q4)

<a id="a-ws-q5"></a>

**Q5** · Trace what happens, from the Gradle flag to the source code, when the desktop host library is built with Tor support.

**Model answer.** `-PtorEngine` makes `cargoBuildHost` run `cargo build --release --workspace --features myotis-engine/tor`. The package/feature form is used because a bare `--features tor` with `--workspace` would apply to every member. `myotis-engine`'s `tor = ["myotis-net/tor"]` turns on the `tor` feature of `myotis-net`, which enables the optional dependencies `arti-client`, `tor-rtcompat` and `rustls` (`dep:` syntax); on a desktop target, the non-Android table's native-tls variants are the ones that exist. With the feature on, items guarded by `#[cfg(feature = "tor")]` are compiled: the `el::tor` module and the first block of `host::set_tor_enabled`. Without it, those items do not exist, and the `#[cfg(not(feature = "tor"))]` block that returns `false` is compiled instead.

A good answer covers:

- Gradle passes --features myotis-engine/tor to cargo (package/feature form because of --workspace)
- the engine feature forwards to myotis-net/tor
- the net feature enables the optional Arti dependencies through dep: entries, from the target table that matches the build
- \#\[cfg(feature = "tor")\] items (el::tor, the real set\_tor\_enabled block) are compiled; otherwise the fallback block that returns false

[← Back to the question](02-workspace.md#q-ws-q5)

<a id="a-ws-q6"></a>

**Q6** · What does `.cargo/config.toml` change, and for whom?

**Answer: B.** It adds a 16 KB page-alignment linker flag for the Android targets and an `aes_force_soft` cfg for the bare-metal targets, and nothing for host builds

The `[target.<triple>]` tables apply only to those targets. Host builds and tests are untouched. The compiler comes from `rust-toolchain.toml` (stable), and the minimum version from `rust-version` in the workspace manifest.

[← Back to the question](02-workspace.md#q-ws-q6)

<a id="a-ws-q7"></a>

**Q7** · `myotis-wire` has `std = ["myotis-core/std", "myotis-consensus?/std", ...]`. What does the `?` do?

**Answer: B.** It enables `std` on `myotis-consensus` only if that optional dependency is already enabled by something else, such as the `eth2` feature

This is a weak dependency feature. Without the `?`, enabling `std` would also enable the optional `myotis-consensus` dependency, so an execution-layer-only host with `std` but without `eth2` could not leave consensus and blst out.

[← Back to the question](02-workspace.md#q-ws-q7)

<a id="a-ws-q8"></a>

**Q8** · `myotis-core` promises to build without the standard library. Name the manifest techniques that keep the promise, and explain how the project tests it.

**Model answer.** The crate has a `std` feature (on by default) that forwards to its dependencies' `std` features (`std = ["sha3/std"]`), and each dependency is declared with `default-features = false` so none of them turns its own `std` on behind the crate's back. k256 is used without its `std` feature at all. For bare-metal targets, a `[target.'cfg(...)'.dependencies]` table adds sha2's `force-soft` feature, which resolver 2 keeps on those targets only. The no\_std canary (`cargoBuildNoStd`, part of `check`, and a CI workflow) runs `cargo build --no-default-features` for `x86_64-unknown-none`, a target that ships no std, so any leak fails to build there.

A good answer covers:

- a std feature that forwards to the dependencies' std features
- default-features = false on dependencies so none of them pulls std on its own
- a target-specific dependency table for the bare-metal sha2 backend
- the canary builds with --no-default-features for x86\_64-unknown-none, which has no std at all

[← Back to the question](02-workspace.md#q-ws-q8)

<a id="a-ws-q9"></a>

**Q9** · Why does `myotis-rpcd` not depend on tokio, even though it serves HTTP?

**Answer: B.** The engine owns its own tokio runtime and every read it offers blocks, so the daemon uses a blocking HTTP server with a fixed worker pool

The manifest comments say so directly: the engine owns its runtime and log ring, and the daemon only calls blocking functions. A synchronous server (`tiny_http`) with worker threads is the whole design.

[← Back to the question](02-workspace.md#q-ws-q9)

<a id="a-ws-q10"></a>

**Q10** · The root manifest sets `panic = "abort"`. Explain why that is the right rule for the engine and for `myotis-rpcd`, and what `roost`'s `panic = "unwind"` does and does not buy it.

**Model answer.** The engine is called across FFI from the JVM, Node and Swift. A Rust panic must not unwind out through a foreign frame (depending on the ABI that is undefined behaviour or an abort anyway), so ending the process at once is the predictable rule. `myotis-rpcd` links the engine in-process and already lives under that contract, so it gains nothing from a separate profile and stays a member. `roost` is a server daemon. With `unwind`, a panic ends only the tokio task it happens in, and the task's `JoinHandle` reports it as an error. But requests are handled inline on the single swarm task, so such a panic still ends every connection. `serve` notices, logs and exits non-zero, and systemd restarts it: a controlled, observable restart, not per-connection isolation.

A good answer covers:

- abort avoids a panic unwinding out through FFI frames, which is not allowed
- rpcd links the engine in-process, so the abort contract already applies to it
- unwind lets a panic end only its tokio task, reported through JoinHandle/JoinError::is\_panic
- in roost the swarm task handles requests, so a panic there still drops every connection; the gain is a logged non-zero exit that systemd restarts

[← Back to the question](02-workspace.md#q-ws-q10)

## Stop 3 · myotis-bls: BLS through blst

<a id="a-bls-q1"></a>

**Q1** · `let pk_refs: Vec<&PublicKey> = pks.iter().collect();`. What does `pk_refs` contain, and what does the compiler enforce?

**Answer: B.** References to the keys stored in `pks`; `pks` must stay alive and unmodified while `pk_refs` is used

`iter()` yields `&PublicKey` borrowed from `pks`. The borrow checker will not let `pks` be dropped, moved or pushed to while those references are in use. Pushing could reallocate the buffer and leave the references dangling.

[← Back to the question](03-bls.md#q-bls-q1)

<a id="a-bls-q2"></a>

**Q2** · How does `myotis-consensus` use this crate without compiling any JNI code?

**Answer: B.** It depends on `myotis-bls` with `default-features = false`, so `#[cfg(feature = "jni")] mod jni_shim` and the `jni` dependency are compiled out

Features are compile-time switches. With the default `jni` feature off, the module does not exist in that build, and the rlib exposes only the pure functions. Consensus turns `std` back on through its own `std` feature.

[← Back to the question](03-bls.md#q-bls-q2)

<a id="a-bls-q3"></a>

**Q3** · What does the `'local` lifetime on `JByteArray<'local>` prevent?

**Answer: B.** Keeping a JNI local reference after the native call has returned, for example by storing it in a global

JNI local references are only valid inside the native call's frame. Encoding that in a lifetime turns "used a stale local ref", a classic JNI crash, into a compile error.

[← Back to the question](03-bls.md#q-bls-q3)

<a id="a-bls-q4"></a>

**Q4** · Why does `fast_aggregate_verify_with_dst` check `n > MAX_PUBKEYS` before computing `n * PK_LEN`, and why does it matter more in this project than in a typical Java library?

**Model answer.** On 32-bit targets (older Android ABIs) `usize` is 32 bits, so a huge caller-supplied `n` could overflow `n * 48`. The length comparison could then pass incorrectly, and `Vec::with_capacity(n)` could try an enormous allocation. In release builds the overflow wraps silently, and an allocation failure or panic aborts the process because of `panic = "abort"`. Capping first keeps all later arithmetic in range, so bad input just yields `false`. In Java, int overflow also wraps, but a failed allocation is an `OutOfMemoryError` the app may survive; here the host app dies.

A good answer covers:

- usize can be 32-bit (Android), so n\*48 can overflow
- the overflow could defeat the length check or cause a huge allocation
- abort semantics: a crash ends the host app
- capping first means malformed input simply returns false

[← Back to the question](03-bls.md#q-bls-q4)

<a id="a-bls-q5"></a>

**Q5** · Why can `parse_kv(text: &str)` return `HashMap<&str, &str>` instead of `HashMap<String, String>`?

**Answer: B.** The keys and values are sub-slices of `text`; the map borrows from it and may not outlive it, and nothing needs copying

`trim` and `split_once` return views into the input, and lifetime elision ties the map to `text`. Since the input is an `include_str!` constant (`'static`), the map can live as long as needed.

[← Back to the question](03-bls.md#q-bls-q5)

<a id="a-bls-q6"></a>

**Q6** · `#![cfg_attr(not(feature = "std"), no_std)]` sits at the top of `lib.rs`. When is the crate `no_std`?

**Answer: B.** Only when the `std` feature is off, which needs a dependent to disable the defaults and not request `std` (directly or through `jni`)

`cfg_attr(cond, attr)` adds `attr` only when `cond` holds. The defaults are `["jni", "std"]` and `jni` implies `std`, so the crate drops `std` only for a dependent that turns both off, such as `myotis-consensus` built with `--no-default-features`.

[← Back to the question](03-bls.md#q-bls-q6)

<a id="a-bls-q7"></a>

**Q7** · The verify core uses `Vec` in both the `std` and the `no_std` build, with the same code. Explain what `extern crate alloc;` and `use alloc::vec::Vec;` do, and why the function bodies did not need to change.

**Model answer.** `alloc` is the layer of the standard library that provides heap types (`Vec`, `Box`, `String`) on top of an allocator, without any OS services. A `no_std` crate does not see it automatically, so `extern crate alloc;` brings it into scope by name. `std::vec::Vec` is just a re-export of `alloc::vec::Vec`, so importing from `alloc` names the very same type in both builds. The bodies call `Vec::with_capacity`, `push`, `iter().collect()`, all of which are defined in `alloc`, so nothing else changes.

A good answer covers:

- alloc provides heap types without OS services
- extern crate alloc makes the crate available by name, which no\_std code needs
- std's Vec is a re-export of alloc's Vec, so it is the same type
- the methods used (with\_capacity, push, collect) all live in alloc

[← Back to the question](03-bls.md#q-bls-q7)

<a id="a-bls-q8"></a>

**Q8** · The public keys are decompressed with `PublicKey::uncompress` and no subgroup check, but the signature is subgroup-checked. Why the difference?

**Answer: B.** The keys arrive Merkle-proven against a trusted header, while the signature comes from a peer and is attacker-controlled

The crate docs say so: the pubkeys arrive Merkle-proven, so the per-key subgroup check is skipped (the same trade-off the Java path makes), and the attacker-controlled signature is checked through `sig_groupcheck = true`.

[← Back to the question](03-bls.md#q-bls-q8)

<a id="a-bls-q9"></a>

**Q9** · The aggregate-vector test checks each vector twice: once with `fast_aggregate_verify_with_dst(..., NUL_DST)`, expecting `true`, and once with `fast_aggregate_verify(...)`, expecting `false`. What bug does the second assertion catch, and why is it needed?

**Model answer.** The fixtures were generated under the NUL ciphersuite, so the first assertion proves the plumbing (flattening, caps, decompression, subgroup policy) reproduces the recorded verdict. If `fast_aggregate_verify_with_dst` silently ignored its `dst` argument and always used one tag, the first assertion alone could not tell. Running the same vector through the production POP path and expecting a rejection proves that the DST really changes the result, so the parameter is applied, not dropped.

A good answer covers:

- the fixtures are NUL-ciphersuite vectors
- the first assertion checks the plumbing reproduces the recorded verdict
- the second catches a dst parameter that is silently ignored
- a different DST must change the verdict, so POP must reject the NUL vector

[← Back to the question](03-bls.md#q-bls-q9)

## Stop 4 · myotis-core: bytes, hashes and tries

<a id="a-core-q1"></a>

**Q1** · `rlp::decode` returns an `Item` (no lifetime); `rlp::raw_list_items` returns `Vec<&[u8]>`. What does each mean for the caller's input buffer?

**Answer: C.** `Item` owns copies, so the buffer may be dropped immediately; the slices borrow the buffer, so it must stay alive and unmodified while they are used

`decode_item` calls `payload.to_vec()`, so the tree is self-contained. `raw_list_prefix` pushes `&data[pos..next]`, windows into the input, and the elided lifetime ties them to it.

[← Back to the question](04-core.md#q-core-q1)

<a id="a-core-q2"></a>

**Q2** · `View::as_bytes(&self)` returns `Result<&'a [u8], CoreError>`, where `'a` is the struct's lifetime parameter. What does writing `'a` (instead of letting the lifetime be elided) allow?

**Answer: A.** The returned slice may outlive the `View` value itself, as long as the underlying buffer is still alive

With elision the result would borrow from `&self`, the small View value. Naming `'a` ties it to the buffer the View points into. `Item::as_bytes` cannot do this, because its bytes live inside the tree.

[← Back to the question](04-core.md#q-core-q2)

<a id="a-core-q3"></a>

**Q3** · `BlockHeader::decode_view` reads every field through a `View` that borrows the caller's bytes, yet it copies each field (`copy_from_slice`, `to_vec`). Explain why, and name the alternative and its cost.

**Model answer.** `BlockHeader` has no lifetime parameter, so it can only hold owned data. The slices a `View` hands out are `&'a [u8]` borrows of the caller's buffer; storing them would require the struct to be `BlockHeader<'a>`. So the helpers (`fixed32`, `any_bytes`, …) copy each field into an array or `Vec` the header owns. The alternative, a `BlockHeader<'a>` holding slices, would avoid the copies, but the borrow checker would then forbid it from outliving the frame it was decoded from, so it could not be cached or sent elsewhere after the frame is dropped. Java would keep references and let the GC keep the buffer alive.

A good answer covers:

- BlockHeader has no lifetime parameter, so it can hold only owned data
- View's accessors return slices that borrow the caller's buffer
- therefore fields are copied into \[u8;32\] / Vec owned by the header
- a BlockHeader&amp;lt;'a> holding slices would avoid copies but could not outlive the input buffer

[← Back to the question](04-core.md#q-core-q3)

<a id="a-core-q4"></a>

**Q4** · In the trie walk, why does `Step::Embedded` carry a *cloned* `Item` rather than `&Item`?

**Answer: D.** The loop does `current = child;`. A child borrowed from `current` would make that reassignment a borrow error, so the child must be owned

You cannot overwrite a value while something borrowed from it is still in use. Owning the child breaks that link, and the reassignment drops the parent subtree.

[← Back to the question](04-core.md#q-core-q4)

<a id="a-core-q5"></a>

**Q5** · The trie walk's node index changed from `HashMap` to `BTreeMap<[u8; 32], &[u8]>`. What is the reason in this crate?

**Answer: B.** `HashMap` lives in `std` (its default hasher is seeded from OS randomness), and the crate must build as `no_std` + `alloc`, where only `BTreeMap` is available

`alloc::collections` has `BTreeMap` but no `HashMap`. The no\_std canary (`cargoBuildNoStd`) names a HashMap as one of the leaks it catches. Both maps compare array keys by content.

[← Back to the question](04-core.md#q-core-q5)

<a id="a-core-q6"></a>

**Q6** · In `bloom.rs`'s test, `let snapshot = bloom; accrue(&mut bloom, …); assert_eq!(bloom, snapshot);`. Why is `snapshot` unaffected by the second `accrue`?

**Answer: C.** `[u8; 256]` is `Copy`: the assignment copied all 256 bytes

Fixed arrays are values. In Java, `byte[] snapshot = bloom;` would alias the array, and the assertion would be meaningless.

[← Back to the question](04-core.md#q-core-q6)

<a id="a-core-q7"></a>

**Q7** · Explain what `#![cfg_attr(not(feature = "std"), no_std)]` and `extern crate alloc;` in `lib.rs` do, and why nearly every module starts with imports such as `use alloc::vec::Vec;`.

**Model answer.** `cfg_attr` applies `#![no_std]` to the crate only when the `std` feature is off. The crate then links only `core`, plus `alloc` because `extern crate alloc;` brings it into scope; `alloc` is not nameable by default even in a std build. A no\_std crate's prelude does not contain `Vec`, `String`, `format!` or `vec!`, so each module imports them from `alloc`. In the default std build those imports name the same types std re-exports, so they are harmless. The compiler then rejects any `std::` use in the no\_std build, which the `cargoBuildNoStd` canary exercises on `x86_64-unknown-none`.

A good answer covers:

- cfg\_attr applies no\_std only when the std feature is off
- extern crate alloc makes the alloc crate nameable (it is not in scope by default)
- the no\_std prelude lacks Vec/String/format!/vec!, hence the explicit alloc imports
- in a std build the imports are the same types, so they are harmless
- the no\_std build makes any std use a compile error (checked by the canary build)

[← Back to the question](04-core.md#q-core-q7)

<a id="a-core-q8"></a>

**Q8** · `myotis-wire` depends on myotis-core with `default-features = false`; `myotis-net` depends on it with defaults. When you build `myotis-net` (which also pulls in myotis-wire), how is myotis-core compiled?

**Answer: B.** With `std` on: Cargo compiles it once with the union of all requested features

Features are additive and unified per build. `default-features = false` only means “I do not ask for the defaults”, not “forbid them”. That is why the canary builds just myotis-core and myotis-wire.

[← Back to the question](04-core.md#q-core-q8)

<a id="a-core-q9"></a>

**Q9** · Why does `trie.rs` walk proofs iteratively with a lookup counter, and why does `rlp.rs` have `MAX_DEPTH`? What would happen without these guards?

**Model answer.** Both handle attacker-controlled structure. A recursive walk or decoder descends once per nesting level, and a hostile proof or a deeply nested RLP packet could exhaust the native stack. In Rust a stack overflow is not a catchable exception: the process aborts, taking the host app with it. Making the trie walk iterative (with a lookup counter bounded by the node count) and capping RLP depth at 32 keeps memory use bounded and guarantees termination, so bad input ends as `Invalid` or `Err` instead of a crash.

A good answer covers:

- input structure is attacker-controlled
- recursion depth grows with nesting, so the stack can be exhausted
- a stack overflow aborts the process (there is no StackOverflowError to catch)
- the iterative walk with a counter and the depth cap bound the work and return Invalid/Err

[← Back to the question](04-core.md#q-core-q9)

<a id="a-core-q10"></a>

**Q10** · `forkid.rs` builds `CRC32_TABLE` in a `const` initialiser using `while` loops with hand-counted indices. Why not `for n in 0..256`?

**Answer: A.** A `for` loop calls `Iterator::next`, a trait method that cannot run during compile-time evaluation

Const evaluation supports `while`, `if` and arithmetic, but a `for` loop desugars to iterator trait calls, which are not allowed in const contexts.

[← Back to the question](04-core.md#q-core-q10)

<a id="a-core-q11"></a>

**Q11** · In `verify_proof_path`, `walk(root, key, proof_nodes, |node| path.push(node.to_vec()))` is followed by `path.clear()`. Why is that second use of `path` allowed?

**Answer: C.** The closure was a temporary argument; it was dropped when `walk` returned, which ended its mutable borrow of `path`

The closure borrows `path` mutably for as long as it exists. It exists only for the duration of the call, so afterwards `path` is free to be used again.

[← Back to the question](04-core.md#q-core-q11)

<a id="a-core-q12"></a>

**Q12** · `skip_item` repeats every check of `decode_item` without building anything. What risk does that duplication create, how do the tests in `rlp.rs` control it, and why does `validate_agrees_with_decode` also count accepted and rejected inputs?

**Model answer.** Two copies of the same validation can drift: a check added to one and not the other would make `validate` (and every `View`) accept or reject different inputs from `decode`. The differential tests feed about 100,000 inputs (all strings up to two bytes, depth bounds, the shared corpus, seeded random trees with truncations and header mutations) through both and `assert_eq!` the full `Result`s, including error messages and end offsets. Counting both verdicts (more than 5,000 each) keeps the test from passing vacuously, for example if the generator only produced inputs that both reject.

A good answer covers:

- duplicated checks can drift apart, changing what validate/View accept versus decode
- the tests run the same large generated + corpus input set through both
- they compare whole Results, so end offsets and error messages must match
- the accepted/rejected counts guard against a vacuous pass

[← Back to the question](04-core.md#q-core-q12)

<a id="a-core-q13"></a>

**Q13** · `tests/rlp_alloc_bound.rs` counts allocations. Explain why it is a separate test file, why the counters are thread-local `Cell`s, why the `impl` is `unsafe`, and what the test `the_counter_sees_a_per_element_decode` is for.

**Model answer.** `#[global_allocator]` replaces the allocator for the whole binary, and each file under `tests/` compiles to its own binary, so the counting allocator affects only these tests. Tests run in parallel threads, so per-thread counters keep their numbers apart; a `Cell` can be updated through a shared reference without a lock because a thread-local is never shared, and the const initialiser avoids allocating inside the allocator. `GlobalAlloc` is an unsafe trait because the compiler must trust the returned memory; the impl forwards every call to `System` and documents that in a SAFETY comment. The control test checks that an owned decode of 4,096 elements registers at least 4,096 allocations, proving the counter works, so the zero-allocation assertions are not vacuous.

A good answer covers:

- global\_allocator applies to a whole binary; each tests/ file is its own binary
- thread-local counters keep parallel tests from mixing counts
- Cell allows mutation through a shared reference without a lock (never shared across threads)
- GlobalAlloc is unsafe to implement; the impl forwards to System
- the control test proves the counter sees allocations, so the zero checks are meaningful

[← Back to the question](04-core.md#q-core-q13)

## Stop 5 · myotis-wire: the protocols as pure functions

<a id="a-wire-q1"></a>

**Q1** · Every source file in `myotis-wire` starts with `#[allow(unused_imports)] use alloc::{borrow::ToOwned, format, string::{String, ToString}, vec, vec::Vec};`. Why is this import there, and why the `allow`?

**Answer: A.** In a `no_std` build the prelude is `core`'s and has no heap types, so they must be imported from `alloc`; every file copies the same list and not every file uses every name, so unused ones would warn

`std` re-exports the same `alloc` types. Without `std` they are not in scope unless imported, and the shared header names more than each file needs.

[← Back to the question](05-wire.md#q-wire-q1)

<a id="a-wire-q2"></a>

**Q2** · What does an execution-layer-only host avoid by building `myotis-wire` without the `eth2` feature?

**Answer: C.** `myotis-consensus` and, through it, `myotis-bls` and the blst C library, which would otherwise have to be cross-compiled for its target

`eth2` is the only part that needs `myotis-consensus` (for three SSZ helpers in `status.rs`). Without it, the crate's dependency tree is pure Rust.

[← Back to the question](05-wire.md#q-wire-q2)

<a id="a-wire-q3"></a>

**Q3** · In the built-in Snappy decoder, a copy element repeats `l` bytes from `off` bytes back. Why does it push one byte at a time instead of `out.extend_from_slice(&out[start..start + l])`?

**Answer: C.** That line borrows `out` immutably and mutably at once, which does not compile, and a copy may overlap its own output (`l > off`), so the source bytes do not all exist yet when the copy starts

`let b = out[start + i];` copies a `u8`, ending the immutable borrow before `out.push(b)`. Each pushed byte can then be read by a later round, which is exactly what an overlapping copy needs.

[← Back to the question](05-wire.md#q-wire-q3)

<a id="a-wire-q4"></a>

**Q4** · Explain `FrameCodec::split(self) -> (FrameEncoder, FrameDecoder)`: what happens to ownership, why the compiler allows it, and why the encoder's and decoder's methods take `&mut self`.

**Model answer.** `split` takes the codec by value, so the caller gives it up, and moves its two fields out into a tuple. After the call the `FrameCodec` no longer exists; the encoder and decoder are independent owned values that can be moved into different tasks, the reader and the writer, with no shared state and no lock. Moving fields out of a value is only allowed because `FrameCodec` has no `Drop` impl (otherwise error E0509). The methods take `&mut self` because each call advances an AES-CTR keystream and a keccak MAC chain; exclusive access is checked at compile time, so two users of one half cannot exist.

A good answer covers:

- split takes self by value and moves both fields out; the codec is gone afterwards
- the halves are independent owned values that can live in different tasks without a lock
- moving fields out is allowed because FrameCodec has no Drop impl
- &mut self because every call advances the keystream and the MAC chain, so access must be exclusive

[← Back to the question](05-wire.md#q-wire-q4)

<a id="a-wire-q5"></a>

**Q5** · In `SlimFields::read(body: rlp::View<'a>)`, the line `let body = if body.is_list() { body } else { rlp::View::new(body.as_bytes()?)? };` builds a view of the inner bytes, and the result is stored in a `SlimFields<'a>`. Why does this compile?

**Answer: D.** Because `View::as_bytes` returns `&'a [u8]`, tied to the original input rather than to the view value, so the new view also borrows the caller's buffer for `'a`

If `as_bytes` returned a slice tied to `&self`, the inner view would borrow the old local `body`, which is shadowed and could not be returned. Tying it to `'a` makes both forms views of the same input.

[← Back to the question](05-wire.md#q-wire-q5)

<a id="a-wire-q6"></a>

**Q6** · `BlockReceipts::canonical` returns `Cow<'_, RawList>`. What does a caller get for an eth/68 response?

**Answer: A.** `Cow::Borrowed` pointing at the stored list, with nothing copied, because eth/66-68 receipts are already receipts-trie values

Only the eth/69 shape must be rebuilt (with a recomputed bloom), which gives `Cow::Owned`. The caller uses both through `&RawList`.

[← Back to the question](05-wire.md#q-wire-q6)

<a id="a-wire-q7"></a>

**Q7** · Why does `encode_frame` write the header data as `0xc2 0x80 0x80` instead of an empty RLP list `0xc0`?

**Answer: C.** Nethermind's frame-header reader decodes an integer from the first list item and throws on `0xc0`, disconnecting on the first frame, which is fatal on gnosis, where most nodes run Nethermind

`0xc2 0x80 0x80` is `rlp([0, 0])`, geth's zeroHeader. Our own decoder ignores those bytes, as the bomb test with a bare `0xc0` shows.

[← Back to the question](05-wire.md#q-wire-q7)

<a id="a-wire-q8"></a>

**Q8** · In `discv4::decode_neighbors`, what happens to an entry whose fields are well-formed RLP but whose IP is 5 bytes long?

**Answer: C.** That entry is skipped with `continue` and the walk goes on, matching where Java's `InetAddress` construction throws

Structural errors (the `let … else` or a short field list) `break`; a bad IP length or a UDP port over 65535 only skips the entry.

[← Back to the question](05-wire.md#q-wire-q8)

<a id="a-wire-q9"></a>

**Q9** · In `bal_account_changes`, `let mut field = |name: &str| fields.next()…` captures `fields`. Why may line 493 call `fields.next()` directly?

**Answer: A.** The closure's mutable borrow of `fields` ends after its last use on line 492, so `fields` is free again

The closure is an `FnMut` holding `&mut fields`. Non-lexical lifetimes end that borrow at the closure's last use, not at the end of the block.

[← Back to the question](05-wire.md#q-wire-q9)

<a id="a-wire-q10"></a>

**Q10** · `parse_request_ssz_expecting` compares `uncompressed_len != expected as u64` before it ever writes `uncompressed_len as usize`. What would go wrong if it cast first?

**Answer: D.** On a 32-bit target such as armv7 Android, `as usize` truncates silently, so a declared 2^32 + 32 would pass as 32

Comparing in the wide type first makes the later narrowing provably lossless.

[← Back to the question](05-wire.md#q-wire-q10)

<a id="a-wire-q11"></a>

**Q11** · `myotis-net/src/codec.rs` is now `pub use myotis_wire::eth2::codec::*;`. What does this line do to types and visibility, and why was it worth keeping nine such files?

**Model answer.** It re-exports every `pub` item of the wire module under the old path, without copying anything: `myotis_net::codec::CodecError` is the same type as `myotis_wire::eth2::codec::CodecError`, so values pass freely between code using either path. `pub(crate)` items such as `eth::kept` and `#[cfg(test)]` items are not carried. The shims were kept because many users still name the old paths: `roost` and `tor-poc` (separate Cargo workspaces), `myotis-net`'s examples and conformance tests, and modules inside `myotis-net` such as `reqresp.rs` and `sync.rs`. The move therefore needed no change in any of them.

A good answer covers:

- a glob re-export of the pub items under the old path; nothing is copied
- the re-exported items are the same types, so values mix freely
- pub(crate) and test-only items are not re-exported
- names at least one real user of an old path: roost, tor-poc, myotis-net tests/examples, or reqresp/sync

[← Back to the question](05-wire.md#q-wire-q11)

<a id="a-wire-q12"></a>

**Q12** · Both the RLPx frame decoder and the eth2 codec defend against Snappy “bombs”. Describe how each one does it and why their strategies differ.

**Model answer.** RLPx raw Snappy declares the decoded length in a leading varint. `FrameDecoder::decode_body` reads that declaration with `snappy::decompress_len` and only decompresses when it is at most `MAX_FRAME_BODY_SIZE` (10 MiB); otherwise, or when decompression fails, it passes the raw bytes up, where the RLP decoder rejects them. eth2 req/resp carries its own declared length in the request or response header, and the spec requires it to be exact. `snappy_decompress` refuses a declared length of 0 or above 10 MiB, decompresses the framed stream with a reader capped at declared + 1 bytes, and rejects any output whose length differs. RLPx falls back to raw because some peers send control messages uncompressed; eth2 fails hard because a mismatch is a protocol violation.

A good answer covers:

- RLPx checks the declared decoded length (decompress\_len) against 10 MiB before decompressing
- RLPx falls back to the raw bytes, which the layer above rejects, because some peers send uncompressed control messages
- eth2 rejects a declared length of 0 or over 10 MiB before decompressing
- eth2 caps the reader at declared + 1 and requires the output length to equal the declaration

[← Back to the question](05-wire.md#q-wire-q12)

<a id="a-wire-q13"></a>

**Q13** · `Initiator<'a>` holds `local_key: &'a NodeKey`, `build_auth` takes `&mut self`, and `process_ack` takes `&self`. What does each of these choices express, and what copies does `process_ack` make to build its result?

**Model answer.** The lifetime parameter says the initiator borrows the node key instead of owning it; the compiler guarantees the key outlives every `Initiator`, so no `Arc` or clone of the key is needed for a single handshake. `build_auth(&mut self)` changes state: it stores the auth wire bytes in `auth_wire: Option<Vec<u8>>`. `process_ack(&self)` only reads; it checks the precondition with `self.auth_wire.as_ref()` (borrowing, not moving) and returns an error if `build_auth` has not run. Because it only borrows `self`, it cannot move the stored auth bytes into `SessionSecrets`, so it clones them (`auth_wire.clone()`), and it copies the caller's ack slice with `ack_wire.to_vec()`.

A good answer covers:

- 'a means the key is borrowed and must outlive the Initiator; no Arc needed
- &mut self on build\_auth because it records auth\_wire; &self on process\_ack because it only reads
- as\_ref() borrows the Option's content; calling process\_ack first is an Err, not a panic
- process\_ack clones the stored auth bytes and copies the ack slice into the owned SessionSecrets

[← Back to the question](05-wire.md#q-wire-q13)

## Stop 6 · myotis-consensus: the light client as a state machine

<a id="a-cons-q1"></a>

**Q1** · During rotation, the store does `self.current_sync_committee = self.next_sync_committee.take();`. Why `take()` rather than `clone()`?

**Answer: D.** `take()` moves the committee out and leaves `None`, exactly the desired new state, without copying 24 KB

`Option::take` is `mem::replace(&mut self, None)`: the `Vec` handle moves, the 24,576 bytes of keys stay where they are. Cloning would duplicate them and leave `next` still set, which is the wrong state.

[← Back to the question](06-consensus.md#q-cons-q1)

<a id="a-cons-q2"></a>

**Q2** · In `process_update`, `committee` is a reference obtained through `&self`, yet later the method calls `self.store.update_next_sync_committee(…)`, which needs `&mut`. Why does this compile, and what change would break it?

**Model answer.** Rust uses non-lexical lifetimes: a borrow lasts until its *last use*, not until the end of the scope. `committee` is last used in the `verify_sync_aggregate` call (line 383), so the shared borrow of `self` has ended by the time the `&mut` call runs (line 445). The calls in between, `verify_finality_branch` and `verify_header`, only take `&self`, and shared borrows may overlap. Using `committee` again after the mutation, for example logging its root afterwards, would extend the shared borrow past the mutable one, and the compiler would reject it (cannot borrow as mutable because it is also borrowed as immutable).

A good answer covers:

- a borrow ends at its last use (non-lexical lifetimes)
- committee's last use is the BLS call, before the &mut call
- the &self calls in between are shared borrows and may overlap
- using committee after the mutation would be a compile error

[← Back to the question](06-consensus.md#q-cons-q2)

<a id="a-cons-q3"></a>

**Q3** · `read_roots` is `(0..n).map(|i| ssz::read_root(data, offset + i * 32)).collect()` with return type `Option<Vec<Root>>`. What does it produce when the buffer is two nodes short?

**Answer: A.** `None`, because collecting into `Option` stops at the first `None`

`Option` implements `FromIterator` so that collecting an iterator of `Option<T>` yields `Some(collection)` only if every item is `Some`, and short-circuits to `None` otherwise. `Result` works the same way.

[← Back to the question](06-consensus.md#q-cons-q3)

<a id="a-cons-q4"></a>

**Q4** · Why do the Gloas decoders take an `LcFork` from the caller instead of sniffing the layout from offsets, as the pre-Gloas decoders do?

**Answer: C.** Every Gloas container is fixed-size with no offsets left to sniff, so the only honest source of the format is the fork of the object's slot, which the req/resp context bytes give

The Gloas header has no variable payload header any more, so no container has an offset field. The module doc of `types.rs` says the only honest way to tell the format is the fork of the object's slot. The `const` size asserts are a second line of defense, not the rule.

[← Back to the question](06-consensus.md#q-cons-q4)

<a id="a-cons-q5"></a>

**Q5** · Why are the Gloas gindices (735, 2945, 2946) constants in `spec.rs`, while the pre-Gloas ones are computed from the branch length?

**Answer: A.** The Gloas `BeaconState` is a progressive container, so a field's gindex is no longer `(1 << depth) + field_index`; the formula gives 553, 2070 and 2071 instead

The comment in `spec.rs` says the field indices did not move but the tree shape did. A unit test asserts both the constants and that the depth-derived formulas miss them, and `gloas_spec_vectors.rs` checks the same against the official vectors.

[← Back to the question](06-consensus.md#q-cons-q5)

<a id="a-cons-q6"></a>

**Q6** · `HeaderExecution` is `Payload(Box<ExecutionPayloadHeader>)` or `BlockHash(Root)`. What does the `Box` buy?

**Answer: B.** An enum is as large as its largest variant; boxing puts the ~470-byte payload on the heap and leaves an 8-byte pointer, so a Gloas header doesn't carry unused space

Enums can hold structs inline; the doc comment says the box is there because the payload is about 20 times the other variant. A `Box` is still a unique owner: cloning the header deep-copies the payload, and dropping it frees it. Sharing would need `Rc` or `Arc`.

[← Back to the question](06-consensus.md#q-cons-q6)

<a id="a-cons-q7"></a>

**Q7** · A Gloas finality update arrives in the first epochs after the fork. Its attested header is at a Gloas slot, its finalized header is a Fulu block. Describe how the processor checks the finalized header's execution data, and which rules each header must satisfy.

**Model answer.** The shape gate first requires both headers to be in the shape of the attested slot's fork, so the Fulu finalized header must arrive in the Gloas shape (a block hash plus 11 branch nodes). If it arrived payload-shaped, the update is refused before BLS. `verify_header` then picks the proof by each header's *own* slot: the attested header (Gloas slot) proves its block hash at gindex 2856, while the finalized header (pre-Gloas slot) proves its block hash at the Deneb-era gindex 812, which is only 9 levels deep. Its 11-node vector therefore starts with two padding nodes, and `verify_normalized_merkle_branch` accepts the padding only if every extra leading node is zero. The finality branch itself is checked at 735, chosen by the attested slot's fork.

A good answer covers:

- the shape gate requires the Gloas shape for both headers, because the attested slot is Gloas
- each header's execution proof is chosen by its own slot's fork (verify\_header)
- the Fulu header proves its block hash at 812 (depth 9) inside the 11-node vector
- the two extra leading nodes must be zero (normalized branch), otherwise rejected
- the finality branch uses 735, picked by the attested slot

[← Back to the question](06-consensus.md#q-cons-q7)

<a id="a-cons-q8"></a>

**Q8** · Gloas activates at epoch 20 on a 32-slot chain, so slot 640 is its first slot. An update has attested slot 640 and signature slot 640. Which format and which signing version apply?

**Answer: D.** Gloas format, but the signature verifies under the version before Gloas

The format follows the slot's own epoch (640 / 32 = 20, Gloas). The domain follows the epoch of `max(signature_slot, 1) − 1` = slot 639, epoch 19, the old fork. `the_lc_format_switches_at_the_gloas_epoch` in `fork.rs` pins exactly this.

[← Back to the question](06-consensus.md#q-cons-q8)

<a id="a-cons-q9"></a>

**Q9** · `next_committee_adoption.rs` builds an update whose signature and next-committee branch both genuinely verify, and expects the processor to reject it. What is the update, why is adopting its committee harmful, and which check refuses it?

**Model answer.** It is the last block of period P−1 (attested in P−1), signed at the first slot of P. Its signature period is P, so the committee gate admits it and it verifies against the store's current committee. An update carries the next committee of its attested state, which here is committee(P), the store's own current committee. If a store at P without a next committee adopted it, the next rotation would install committee(P) as the keys for P+1, and every genuine P+1 update would fail BLS: the walk would stall. `process_update` refuses it with the adoption gate: when no next committee is held, the attested period must equal the store's period. Honest servers leave the committee empty in such an update, but it is public data, so any server can fill it in.

A good answer covers:

- attested in P−1, signed in P, so it passes the committee gate and BLS
- its next committee is committee(P), the store's own current committee
- adopting it would install the wrong keys for P+1 and stall all later updates
- refused because, with no next held, period(attested) must equal the store's period

[← Back to the question](06-consensus.md#q-cons-q9)

<a id="a-cons-q10"></a>

**Q10** · `shape(&self)` writes `match self.execution { HeaderExecution::Payload(_) => …, HeaderExecution::BlockHash(_) => … }` with no `&`. Why does that compile even though `self` is only borrowed?

**Answer: B.** The `_` patterns bind nothing, so nothing is moved out of the borrowed value

Matching a place expression does not move it by itself; only a binding pattern does. `_` never binds. Writing `Payload(p)` there would try to move the `Box` out of borrowed data and fail. `HeaderExecution` is not `Copy` (it holds a `Box`).

[← Back to the question](06-consensus.md#q-cons-q10)

<a id="a-cons-q11"></a>

**Q11** · `types.rs` contains `const _: () = assert!(LightClientHeader::GLOAS_SIZE < MIN_PRE_GLOAS_HEADER_SIZE);`. What happens if someone changes a size so the condition becomes false?

**Answer: A.** The build fails, because the assert is evaluated at compile time

A `const` item is evaluated by the compiler, and a failing `assert!` during const evaluation is a compile error. It is Rust's form of a static assert. The `_` name means the constant itself is never used.

[← Back to the question](06-consensus.md#q-cons-q11)

<a id="a-cons-q12"></a>

**Q12** · `the_shape_gate_runs_before_the_bls_verify` cannot read a BLS call counter. How does it prove the order of the checks, and how does `logged_during` share its log with the subscriber?

**Model answer.** Every misrouted update is given a genuine aggregate signature over a different header, so it would fail BLS if it reached that step. The test captures the processor's debug log while it runs: a refusal by the shape gate logs a message containing “wire shape” and none containing “BLS”. A control case, a well-shaped update with the same foreign signature, shows that a BLS failure does log “BLS”. `logged_during` creates an `Arc<Mutex<Vec<String>>>`, clones the `Arc` (a reference-count increment) into the `Capture` subscriber, installs it with `tracing::subscriber::with_default` for the closure's run, and the subscriber pushes each event's message through `lock()`. Afterwards the test locks the mutex and clones the `Vec` out.

A good answer covers:

- misrouted updates carry a signature that would fail BLS
- the log must show the shape-gate message and no BLS message
- a control case proves a BLS failure would be logged
- Arc clone shares one Vec; Mutex allows pushing through &self
- with\_default installs the subscriber only while the closure runs

[← Back to the question](06-consensus.md#q-cons-q12)

<a id="a-cons-q13"></a>

**Q13** · Why does `apply_finality_update` return `FinalityOutcome` rather than the `bool` from `process_finality_update`?

**Answer: C.** A re-served update verifies but moves nothing; the sync loop must not count that as the poll's win, or a stalled server keeps outrunning a current one

`Stale` means verified but not advanced: finalized and optimistic slots are unchanged. The doc cites Sepolia's Gloas fork, where stalled Lighthouse servers answered first every round and hid roost's current update.

[← Back to the question](06-consensus.md#q-cons-q13)

<a id="a-cons-q14"></a>

**Q14** · When does `snapshot::serialize` write format version 2 instead of 1, and why is that choice made per file rather than always writing v2?

**Model answer.** It writes v1 when both the finalized and the optimistic header are payload-shaped (`execution_payload().is_some()`), and v2 as soon as either is block-hash-shaped. In v2 every header gets a one-byte shape tag (0 = payload framing, 1 = block hash plus 11 nodes). Writing v1 whenever possible keeps the file byte-identical to what older builds and the Java v1 codec produce, so an older build can still resume a pre-Gloas store. A v2 file only appears when the store already holds Gloas state, which an older build could not follow anyway. The reader accepts both versions and refuses an unknown shape tag.

A good answer covers:

- v1 when both headers are payload-shaped, v2 when either is block-hash-shaped
- v2 adds one shape tag byte per header
- v1 stays byte-identical so older builds can still resume
- an older build couldn't follow Gloas state anyway
- the reader rejects unknown versions and unknown shape tags

[← Back to the question](06-consensus.md#q-cons-q14)

## Stop 7 · myotis-evm: an EVM over verified state

<a id="a-evm-q1"></a>

**Q1** · What would break if `SnapStateOracle` were declared without `: Send + Sync`?

**Answer: C.** `Arc<dyn SnapStateOracle>` would not be `Send`, so an executor holding it could not be moved to a blocking thread or shared across threads

`Arc<T>` is `Send` only if `T: Send + Sync`. With a bare `dyn SnapStateOracle` the compiler cannot know that, so every cross-thread use would be rejected.

[← Back to the question](07-evm.md#q-evm-q1)

<a id="a-evm-q2"></a>

**Q2** · `InMemoryStateProofCache::get_account` returns `…get(&key).cloned()` rather than a reference into the map. Why?

**Answer: A.** The map is only reachable through a `MutexGuard` that dies at the end of the statement; a reference into the map cannot outlive that guard

A reference derived from the guard borrows the guard. Returning it would let the caller read the map after the lock is released, which is exactly the data race the compiler forbids. Copying the value out is the sound option.

[← Back to the question](07-evm.md#q-evm-q2)

<a id="a-evm-q3"></a>

**Q3** · In `OracleDatabase::account`, the sentinel check sits in its own `{ … }` block before the network fetch. What does the block do, and what could go wrong without it?

**Model answer.** The block limits the lifetime of the `MutexGuard` (`let mut track = self.track.lock().unwrap();`). At the closing brace the guard is dropped and the lock released, so it is not held during `self.oracle.fetch_account(…)`, which may block on the network for a long time. Without the block the guard would live to the end of the function, so the lock would be held across the slow fetch. Anything else that needs `track` during that time would wait, and any nested lock of it on the same thread (for example from code added later in the function) would deadlock, because Rust mutexes are not reentrant.

A good answer covers:

- the block scopes the MutexGuard; the lock is released at the closing brace
- the lock is not held across the potentially blocking oracle fetch
- without the block the guard lives until the end of the function
- risk: other users of track wait for the whole fetch, and a nested lock on the same thread deadlocks because Mutex is not reentrant

[← Back to the question](07-evm.md#q-evm-q3)

<a id="a-evm-q4"></a>

**Q4** · Why does `OracleDatabase` implement revm's `DatabaseRef` (`&self`) rather than `Database` (`&mut self`)?

**Answer: D.** So the executor can keep ownership of one database and lend it to every loop iteration and every gas-search probe; the price is interior mutability inside

revm implements `DatabaseRef` for `&T`, so `execute_recording` passes `with_ref_db(db)` each time, and everything learned in one run stays in the view cache for the next.

[← Back to the question](07-evm.md#q-evm-q4)

<a id="a-evm-q5"></a>

**Q5** · In `converge_runs`, `self.prefetch_wave(ctx, &fresh, …);` is followed by `seen.merge(fresh);`. What happens if you swap the two lines?

**Answer: B.** Compile error: `merge` takes `fresh` by value (moves it), so the later `&fresh` uses a moved value

Borrow first, then move. Once a value has been moved into `merge`, the name `fresh` is dead.

[← Back to the question](07-evm.md#q-evm-q5)

<a id="a-evm-q6"></a>

**Q6** · Explain how the prefetch convergence loop decides when to stop, and why an answer can never come from a placeholder.

**Model answer.** Each iteration runs the EVM. While still discovering, the run is a sentinel pass: a read that would need the network gets an uncached zero placeholder and bumps a miss counter, and the database records every account, slot and code hash touched. After each run the loop diffs the touched set against what it has seen. A sentinel run that handed out no placeholder and did not fail read only verified state, so it is returned at once. A sentinel run with an empty diff ends discovery. Otherwise the fresh accesses (plus the code of contracts the pass called or inspected) are fetched in one parallel verified wave into the shared caches. Discovery also ends when the oracle's `keep_discovering` time bound says no, or when only two iterations of the cap (12) are left. A real run's error propagates; a real run with an empty diff is the answer; a real run that still touched something new triggers another wave. Hitting the cap is `IterationLimitExceeded`. Placeholders only appear in sentinel runs, and a sentinel run is returned only when its miss counter did not move.

A good answer covers:

- sentinel passes hand out counted, uncached zero placeholders and record accesses
- fresh = touched minus seen; non-empty fresh is fetched in one parallel verified wave
- a sentinel run is returned only if it handed out no placeholder and did not fail
- discovery ends at an empty diff, at the oracle's keep\_discovering bound, or two iterations before the cap; real runs then answer
- cap reached gives IterationLimitExceeded (fail closed)

[← Back to the question](07-evm.md#q-evm-q6)

<a id="a-evm-q7"></a>

**Q7** · `RequestInspector` records needed code into a `&RefCell<HashSet<…>>`, while `OracleDatabase` keeps its access set in a `Mutex`. Why the difference?

**Answer: B.** The database's type must be `Sync` (it is reached through a shared reference that the type system lets cross threads), and a `RefCell` is never `Sync`; the inspector's set is a local of one run on one thread, where a run-time borrow check is enough

Both give mutation behind a shared reference. `RefCell` checks borrows at run time on one thread; `Mutex` also makes the type safe to share between threads. Use the cheaper one only when the compiler lets you.

[← Back to the question](07-evm.md#q-evm-q7)

<a id="a-evm-q8"></a>

**Q8** · During a discovery pass, `block_hash_ref` reads the EIP-2935 history slot for block k and gets zero, and the miss counter has moved. What does it do?

**Answer: C.** Returns zero as a placeholder: the slot is in the access set, the next wave fetches it, and the real run reads the true value

Lines 437–449: a moved counter means the zero was a sentinel placeholder, not a proven value. Only a proven zero (counter unchanged) means the ring never wrote the slot, and then the header walk runs.

[← Back to the question](07-evm.md#q-evm-q8)

<a id="a-evm-q9"></a>

**Q9** · `read_index` checks `v <= MAX_INDEX as u64` *before* `v as usize`. Why does the order matter?

**Answer: A.** On 32-bit targets `as usize` truncates silently (232 → 0), which would bypass the guard

`as` casts never fail; they wrap or truncate. Checking in the wider type first keeps the guard meaningful on armeabi-v7a devices.

[← Back to the question](07-evm.md#q-evm-q9)

<a id="a-evm-q10"></a>

**Q10** · Why is an ERC-3668 `OffchainLookup` revert reported as `Err(EnsError::OffchainLookup{…})` instead of `Ok(None)`?

**Answer: D.** The record exists, just offchain. “No record” would be a well-formed but wrong answer, so the host must be told to perform the gateway round

The same principle behind #314 and the log index: never return a plausible answer computed from something other than what was asked. A plain revert means “no record”; `OffchainLookup` means “ask the gateway”.

[← Back to the question](07-evm.md#q-evm-q10)

<a id="a-evm-q11"></a>

**Q11** · `EvmError::FailedWithGas` holds `error: Box<EvmError>`. What would happen with `error: EvmError` instead?

**Answer: B.** Compile error: a recursive type has infinite size, because an enum is as large as its largest variant and this variant would contain the whole enum

The `Box` stores the inner error on the heap and leaves a pointer-sized field in the variant, which breaks the size recursion. Java never meets this because every object field is already a reference.

[← Back to the question](07-evm.md#q-evm-q11)

<a id="a-evm-q12"></a>

**Q12** · `with_sender_nonce(mut overrides: StateOverrides, tx: &TxRequest) -> Result<StateOverrides, EvmError>` starts its edit with `let mut entry = overrides.get(&tx.from).cloned().unwrap_or_default();`. Explain the ownership of `overrides` through this function, and why the `.cloned()` is needed.

**Model answer.** The caller moves its `StateOverrides` into the function; `mut` on the parameter lets the function change the value it now owns, and it moves the edited value back in `Ok(overrides)`, so the caller cannot keep using a stale copy. `overrides.get(…)` returns a reference into the map. `.cloned()` turns it into an owned `AccountOverride`, so `entry` does not borrow `overrides`. That matters because the function later calls `overrides.insert(tx.from, entry)`, which needs a mutable borrow of the map; with an active shared borrow from `entry` it would not compile. A nonce in the override that differs from the request's is refused as `InvalidRequest`.

A good answer covers:

- the overrides are moved in by value and moved back out in the Ok result
- mut on a by-value parameter only allows the function to change its own value
- get returns a reference into the map; cloned makes an owned copy
- without the clone, the later insert (mutable borrow) would conflict with entry's shared borrow
- a contradictory override nonce is refused, not overwritten

[← Back to the question](07-evm.md#q-evm-q12)

<a id="a-evm-q13"></a>

**Q13** · `v1_decides` decides whether ENS v1 still speaks for a name. Why does `resolve_ownership` refuse instead of answering from v1 when it is unsure, and why is the v1 mirror pinned by address rather than recognised by its `REGISTRY_V1()` getter?

**Model answer.** For a name that ENSv2 decides, the v1 registry and registrar may hold no owner or a stale one, so a v1 answer would show an ENSv2 name as unowned or name a previous holder: a well-formed wrong answer the caller cannot detect. So any doubt leads to `Unsupported(ENSV2_OWNERSHIP)`: no pinned mirror where ENSv2 is live, a Universal Resolver that cannot walk the name, or a resolver other than the mirror. A name's ENSv2 owner can set its own resolver and make it answer `REGISTRY_V1()` with the v1 registry; trusting the getter would let anyone make their ENSv2 name read as v1-owned. Pinning the mirror's address, and also requiring its getter to name this registry, closes that. Only a revert is read as "no"; a halt or unavailable state propagates as `EnsError::Call`.

A good answer covers:

- answering from v1 for an ENSv2 name gives a well-formed wrong owner (unowned or stale)
- any doubt (no pinned mirror, unwalkable name, other resolver) is a refusal, not v1's answer
- a name owner controls its resolver and could fake REGISTRY\_V1(), so the getter alone proves nothing
- the mirror must be the pinned address AND name this registry
- only reverts read as none; other call failures propagate as errors

[← Back to the question](07-evm.md#q-evm-q13)

<a id="a-evm-q14"></a>

**Q14** · `MockCaller` stores handlers as `Vec<Box<dyn Fn([u8; 20], &[u8]) -> Option<Result<Vec<u8>, EvmError>>>>`, added with `on(mut self, f: impl Fn(…) + 'static) -> Self`. A test handler that returns a captured byte vector is written `move |t, cd| (…).then(|| Ok(claimed.clone()))`. Explain the `Box<dyn …>`, the `'static`, and the `.clone()`.

**Model answer.** Each closure has its own unnamed type, so a vector holding several different closures must store them behind a pointer to a trait object: `Box<dyn Fn …>`. The handler is stored in the mock and called later, so it must not borrow locals that die before it; `'static` forbids such borrows, and `move` makes the closure own `claimed`. Because the bound is `Fn`, the handler can be called many times through a shared reference and may not give away what it owns. Returning `claimed` itself would move it out on the first call. The inner closure borrows `claimed` and returns a fresh clone each time.

A good answer covers:

- closures have unique anonymous types, so a Vec of them needs Box&amp;lt;dyn Fn>
- 'static means the stored closure contains no short-lived borrows
- move transfers ownership of the captured vector into the closure
- Fn closures may be called repeatedly and cannot move captured values out
- clone returns a new copy per call while the closure keeps the original

[← Back to the question](07-evm.md#q-evm-q14)

## Stop 8 · myotis-evm, part 2: simulation, tracing and fixtures

<a id="a-sim-q1"></a>

**Q1** · `TraceRecorder` keeps its state in a `RefCell`, while `RecordingOracle` uses a `Mutex`. Why the difference?

**Answer: B.** `RecordingOracle` implements `SnapStateOracle`, which requires `Send + Sync`; a `RefCell` field would make it non-`Sync`. A recorder is only lent to one run on one thread.

The oracle trait is `Send + Sync` because oracles are shared behind `Arc` across threads, and `RefCell` is not `Sync`. The inspector's recorders are borrowed for a run that executes on a single blocking thread, so the cheaper single-thread `RefCell` suffices.

[← Back to the question](08-evm-sim.md#q-sim-q1)

<a id="a-sim-q2"></a>

**Q2** · In `Run::call`, the EVM is built with `.with_db(&mut *cache)` inside a block `let outcome = { … };`, and later `credit(cache, …)` uses the cache again. Explain what `&mut *cache` does, why plain `cache` would be a problem, and why the inner block matters.

**Model answer.** `cache` is a `&mut SimCache`. `&mut *cache` reborrows it: a new, shorter mutable borrow of the same cache. `with_db` is generic, so passing `cache` would move the mutable reference into the builder (mutable references are not `Copy`) and `cache` could not be used afterwards. The EVM, which holds the reborrow, is created inside the inner block and dropped at its closing brace, so the reborrow ends there and `credit(cache, …)` may borrow the cache mutably again.

A good answer covers:

- `&mut *cache` creates a fresh, shorter mutable borrow (a reborrow) of the same cache
- passing `cache` to a generic parameter would move the `&mut` itself, since `&mut T` is not Copy
- the EVM value is dropped at the end of the inner block, ending the reborrow
- only after that may the cache be borrowed mutably again for `credit`

[← Back to the question](08-evm-sim.md#q-sim-q2)

<a id="a-sim-q3"></a>

**Q3** · During `eth_simulateV1`, a call writes a storage slot. Where does that write go?

**Answer: C.** Into the pass's `CacheDB<SimDb>`, which layers writes over the read-only verified database and is dropped at the end of the pass

`SimCache` is revm's `CacheDB` over `SimDb`, a `DatabaseRef`. Writes stay in the `CacheDB`, carry to the next call and block, and are never written to a cache another request reads. Each pass of the prefetch loop builds a fresh one.

[← Back to the question](08-evm-sim.md#q-sim-q3)

<a id="a-sim-q4"></a>

**Q4** · Name three things `eth_simulateV1` refuses to serve, and explain the common reason behind the `BLOCKHASH` and EIP-2935 refusals in particular.

**Model answer.** It refuses: `BLOCKHASH` of a simulated block (and the EIP-2935 history slot holding one), `BLOBBASEFEE` unless the `blobBaseFee` override sets it, Amsterdam blocks, withdrawals on Gnosis, and state overrides of precompile addresses. A simulated block's hash depends on its post-state root, which needs trie nodes no proof carries. So the hash is unknown, and a call that reads it is refused rather than run against a made-up value. The refusal is raised during the run (by `SimDb::block_hash_ref` or by the recorder's `step`) and reported as `SimulationNotServed`.

A good answer covers:

- names at least three refusals from the module doc (simulated BLOCKHASH or history slot, BLOBBASEFEE without override, Amsterdam, Gnosis withdrawals, precompile override)
- the simulated block's hash needs its post-state root, which this node cannot compute from proofs
- the node refuses instead of inventing a value (applied or refused, never silently wrong)
- the refusal surfaces as SimulationNotServed, not as a normal call result

[← Back to the question](08-evm-sim.md#q-sim-q4)

<a id="a-sim-q5"></a>

**Q5** · `ShieldRequests::around` builds `ShieldRequests { retry_from_delegated: retry_from_delegated(&shield), without_authorization, require_success_false, shield }`. What happens if you move `shield` to be the first field in the literal?

**Answer: B.** A compile error: fields are evaluated in the order written, so `shield` would be moved before `&shield` is taken (borrow of moved value)

Expressions in a struct literal are evaluated in source order. Borrowing `shield` after it was moved into the struct is rejected at compile time. The declared field order of the struct is irrelevant.

[← Back to the question](08-evm-sim.md#q-sim-q5)

<a id="a-sim-q6"></a>

**Q6** · The `fixture` module must be usable by `myotis-net`'s example but must never ship in the engine library. Explain the three Cargo mechanisms that achieve this.

**Model answer.** In `myotis-evm/src/lib.rs`, `pub mod fixture` is behind `#[cfg(any(test, feature = "fixture"))]`: `cfg(test)` covers this crate's own tests, but it is not set when another crate compiles against `myotis-evm`, so a feature is needed too. The `fixture` feature enables the optional `serde_json` dependency (`dep:serde_json`). `myotis-net` has a `fixture-recorder` feature that turns on `myotis-evm/fixture` and the gated `head_evm_oracle`, and lists itself as a dev-dependency with that feature, so only tests and examples build with it; the library the engine links does not.

A good answer covers:

- cfg(test) applies only to the crate's own test build, so a feature is also needed
- the fixture feature gates the module and enables the optional serde\_json dependency
- myotis-net's fixture-recorder feature forwards to myotis-evm/fixture
- myotis-net depends on itself as a dev-dependency with that feature, so only tests/examples get it

[← Back to the question](08-evm-sim.md#q-sim-q6)

<a id="a-sim-q7"></a>

**Q7** · In `runs_at`, what does the pattern `Ok(result @ ExecutionResult::Success { .. })` bind?

**Answer: C.** `result` is bound to the whole `ExecutionResult` value, after checking that it is the `Success` variant

`name @ pattern` tests the value against the pattern and, if it matches, binds the entire value to `name`. Here it keeps the full `ExecutionResult::Success` to return it in `Some(result)`.

[← Back to the question](08-evm-sim.md#q-sim-q7)

<a id="a-sim-q8"></a>

**Q8** · Look at `RecordingOracle::fetch_account`. When is the mutex locked and unlocked, and why is the inner fetch done before taking the lock?

**Model answer.** The inner oracle's `fetch_account` runs first, without the lock. Then `self.lock().bind(…)?.accounts.insert(…)` is one statement: `lock()` returns a `MutexGuard` temporary that lives until the end of the statement, so the lock is held only for `bind` and the insert and released at the semicolon (or when `?` returns early, the guard is dropped then). Doing the fetch first means a slow network read never holds the lock, so other threads can record their reads meanwhile.

A good answer covers:

- the inner fetch happens before the lock is taken
- the MutexGuard is a temporary that lives until the end of the statement (the semicolon)
- on an early return via ?, the guard is dropped and the lock released
- holding the lock across a slow fetch would block other threads' reads

[← Back to the question](08-evm-sim.md#q-sim-q8)

<a id="a-sim-q9"></a>

**Q9** · The `ReplayOracle` gets a read for an account that the recording never read. What does it return?

**Answer: C.** `Err(OracleError::StateUnavailable { … })`, so the run fails rather than running against state nobody recorded

Absence must be recorded (a `null` entry) to be served. Treating a missing entry as absent would describe a world no block had; the error tells you to re-record the fixture.

[← Back to the question](08-evm-sim.md#q-sim-q9)

<a id="a-sim-q10"></a>

**Q10** · `TraceRecorder` builds a tree of `CallFrame`s without parent pointers or `Rc`. How does it do it, and who owns a frame while it is open and after it ends?

**Model answer.** Open frames live on `State::stack`, a `Vec<CallFrame>`; the stack owns them. When revm reports the end of a frame, `end` pops it off the stack (moving it out by value), fills in gas used, output and errors, and then moves it into the `calls` vector of the frame now on top of the stack, or into `root` if the stack is empty. Every frame has exactly one owner at a time, so plain ownership is enough; a Java version would typically keep a parent reference in each node.

A good answer covers:

- open frames are owned by a Vec used as a stack
- when a frame ends it is popped, i.e. moved out of the stack by value
- the finished frame is moved into its parent's calls vector, or becomes the root
- one owner at a time, so no Rc or parent pointer is needed

[← Back to the question](08-evm-sim.md#q-sim-q10)

<a id="a-sim-q11"></a>

**Q11** · Why do the shield replay tests share their result through `static REPLAY: OnceLock<Replay>`?

**Answer: B.** Because the replay takes seconds, tests run on several threads, and `OnceLock` runs the initializer once and hands every caller a `&'static Replay`

`get_or_init` runs the closure on first use; other threads wait for it and then get the same `&'static` reference. It is the Rust equivalent of a thread-safe `by lazy`.

[← Back to the question](08-evm-sim.md#q-sim-q11)

<a id="a-sim-q12"></a>

**Q12** · How does `record_shield` make sure that a fixture it produces will actually replay, and why does it build the executor over empty caches?

**Model answer.** It runs `measure` through a `RecordingOracle` over fresh, empty in-memory caches, so every read goes through the recorder at least once (a value already cached would never be re-read and would be missing from the world). Prefetch waves are not forwarded for the same reason. After building the `EvmFixture`, it creates a new executor whose only oracle is `fixture.oracle()` and runs `measure` again; if the replayed `ShieldMeasurements` differ from the live ones, or the replay errors on an unrecorded read, the recording fails and nothing is written.

A good answer covers:

- empty caches ensure every read passes through the RecordingOracle
- a value served from a pre-filled cache would be missing from the recorded world
- after recording, measure runs again against the recorded world alone
- any difference (or an unrecorded read error) fails the recording instead of writing the file

[← Back to the question](08-evm-sim.md#q-sim-q12)

<a id="a-sim-q13"></a>

**Q13** · The recorder example calls `tokio::task::spawn_blocking(move || railgun::record_shield(oracle, …, &ephemeral_key, &params, …))`. What does `move` do here?

**Answer: B.** It transfers ownership of the captured values (oracle, block, key, params, meta) into the closure, which must be `'static` because the blocking thread may outlive the current stack frame

`spawn_blocking` requires a `'static + Send` closure. Without `move` the closure would borrow locals of `record`. The `&ephemeral_key` inside borrows the closure's own moved copy.

[← Back to the question](08-evm-sim.md#q-sim-q13)

## Stop 9 · myotis-net, part 1: libp2p, req/resp and discovery

<a id="a-netcl-q1"></a>

**Q1** · Describe how a response gets from the network back to the code that called `ReqRespClient::request_raw_at`. Which task owns what at each step?

**Model answer.** `request_raw_at` walks the addresses in order (`request_in_order`). For each attempt, `request_raw_once` resolves DNS, creates a `oneshot` channel and moves its sender into a `Command::Request`, which it sends over the bounded `mpsc` inbox to the swarm task, then awaits the receiver. The swarm task owns the `Swarm` and `SwarmCtx`. If the peer hasn't finished its Status exchange, the request (with its sender) is parked in `ctx.queued` and the peer is dialled. Otherwise `send_tracked` sends the bytes on the protocol's behaviour and stores the sender in `ctx.pending[(protocol, id)]`. When the response or failure event arrives, `complete` removes the sender from the map and calls `send(result)`, which wakes the caller's `rx.await`. If the task dies, its stored senders are dropped and the caller gets `RequestError::Shutdown`.

A good answer covers:

- the oneshot sender is moved into a Command sent over the mpsc channel
- the swarm task owns Swarm and SwarmCtx and parks the request if Status is not done
- the sender is stored in pending keyed by (protocol, request id)
- complete() removes it and sends; a dropped sender becomes RequestError::Shutdown

[← Back to the question](09-net-cl.md#q-netcl-q1)

<a id="a-netcl-q2"></a>

**Q2** · Why does `SwarmCtx` hold plain `HashMap`s, while `LocalStatus`, `AgentMap` and `TcpFirst` wrap their data in a lock?

**Answer: C.** `SwarmCtx` is moved into the one swarm task and only used there through `&mut`; the other three are shared with the client or the sync loop through an `Arc`, which only gives out `&T`, so mutation needs interior mutability

Exclusive ownership needs no lock, and the compiler enforces it. Shared ownership (`Arc`) only hands out shared references, so changing the data needs a `Mutex`, an `RwLock` or an atomic.

[← Back to the question](09-net-cl.md#q-netcl-q2)

<a id="a-netcl-q3"></a>

**Q3** · What went wrong when `pending` was keyed by `OutboundRequestId` alone?

**Answer: A.** Each request/response behaviour numbers its requests from 1, so ids from different protocols collided; a second insert evicted the first entry and a reply could reach the wrong caller

Keying by `(protocol, id)`, with `send_tracked` as the single insertion point, makes the key always name the behaviour that issued the id (commit `aa123758`).

[← Back to the question](09-net-cl.md#q-netcl-q3)

<a id="a-netcl-q4"></a>

**Q4** · In `resolve_dial_addrs`, the DNS memo (a `std::sync::Mutex`) is locked only after `lookup_host(…).await` has returned. What would go wrong if the guard were held across that `.await`?

**Answer: C.** A `std` `MutexGuard` is not `Send`, so the future would not be `Send` and could not run inside `tokio::spawn`; it would also block other users for the whole lookup

The compiler rejects non-`Send` futures in `tokio::spawn`. The general rule: never hold a `std` lock across an `.await`; use a tokio mutex if you must.

[← Back to the question](09-net-cl.md#q-netcl-q4)

<a id="a-netcl-q5"></a>

**Q5** · What does dropping the `JoinHandle` returned by `tokio::spawn` do to the task?

**Answer: D.** It detaches the task, which keeps running; stopping it needs `abort()`, which is why `ServerDiscovery` and `DiscoveryGuard` abort in `Drop`

Unlike a dropped future, a spawned task belongs to the runtime. `JoinHandle::abort` cancels it at its next `.await`, dropping everything it owns (here the last `Arc<Discv5>`).

[← Back to the question](09-net-cl.md#q-netcl-q5)

<a id="a-netcl-q6"></a>

**Q6** · The host runs a gossipsub behaviour but never subscribes to a topic. Why is it there?

**Answer: B.** So that the `/meshsub/` protocol negotiates: Lighthouse treats a failed gossipsub upgrade as fatal and bans the peer id for 12 h, and the whole IP after more than five banned ids

The doc on `Behaviour::gossipsub` and the test `meshsub_negotiates_without_any_subscription` pin this. Negotiating the protocol is all Lighthouse checks; the mesh is never joined.

[← Back to the question](09-net-cl.md#q-netcl-q6)

<a id="a-netcl-q7"></a>

**Q7** · `ClPeerCache` has no lock inside. What prevents two writers from corrupting it?

**Answer: A.** Its mutators take `&mut self`, and the sync loop owns it as a local variable, so the compiler guarantees one writer; sharing it would require something like `Arc<Mutex<_>>`

`&mut` is exclusive by construction. Across processes, only the atomic temp-file plus rename protects the file, and the last writer wins.

[← Back to the question](09-net-cl.md#q-netcl-q7)

<a id="a-netcl-q8"></a>

**Q8** · In `consume_discovered`, a `std::sync::Mutex` guard is held while calling `tx.try_send(peer)`. Explain why that is acceptable, and why `tx.send(peer).await` would not be.

**Model answer.** `try_send` is synchronous and never blocks: it either enqueues immediately or fails with `Full`/`Closed`. The critical section (check `seen` via `classify_heard`, send, insert into `seen`) therefore stays short and contains no `.await`, so holding a `std` mutex there is safe and keeps check and insert atomic with respect to the lookup task. `send(peer).await` could suspend while the channel is full. Holding a `std` guard across that `.await` would block the lookup task, which needs the same lock, and would make the future non-`Send`, which `tokio::spawn` rejects. On `Full` the code deliberately does not mark the peer as seen, so it is emitted again when it is next heard.

A good answer covers:

- try\_send never blocks, so there is no await inside the critical section
- a std guard held across an await would block the other task that needs the lock
- a std guard is not Send, so the future would not be Send and tokio::spawn rejects it
- check, send and insert stay atomic; on Full the node is not marked seen

[← Back to the question](09-net-cl.md#q-netcl-q8)

<a id="a-netcl-q9"></a>

**Q9** · `dial_order` runs `addrs.sort_by_key(is_quic)` for a peer on `TcpFirst`. What is the result?

**Answer: B.** TCP addresses first, because `false < true`; the sort is stable, so the order within each transport is kept

A function item can be passed wherever a closure with a matching signature is expected. `bool` implements `Ord` with `false < true`, and `sort_by_key` is stable (use `sort_unstable_by_key` for the faster unstable variant).

[← Back to the question](09-net-cl.md#q-netcl-q9)

<a id="a-netcl-q10"></a>

**Q10** · `Discv5Ledger::live` stores `Weak<TrafficMeter>`, not `Arc<TrafficMeter>`, and `Discv5Share` implements `Drop`. Explain what each choice buys, and what happens to discv5 bytes when a meter's network stops.

**Model answer.** A `Weak` does not count as an owner, so registering a meter in the global ledger does not keep it alive: when the network's last `Arc<TrafficMeter>` goes away, the meter is freed even if it is still listed. `share_growth` prunes such entries with `strong_count() > 0` and uses `Weak::upgrade` to get a temporary `Arc` for each live one. With `Arc` entries the static would keep every meter alive forever. `Discv5Share` is a token held by the discovery lookup task: its `Drop` runs when the task ends or is aborted, flushes the pending growth to the meters live until then, and removes its own entry (found with `ptr_eq`). From then on that meter receives no discv5 bytes; growth with no live meter is dropped.

A good answer covers:

- Weak does not keep the meter alive, unlike Arc in a static
- upgrade() gives a temporary Arc for live meters; dead entries are pruned via strong\_count
- Drop on the share token unregisters automatically when the owning task ends or is aborted
- Drop flushes first, so earlier bytes go to the meters live at that time

[← Back to the question](09-net-cl.md#q-netcl-q10)

<a id="a-netcl-q11"></a>

**Q11** · Why are the `LcResponder` methods plain `fn` returning `Option<Vec<u8>>`, not `async fn`?

**Answer: B.** They are called from `respond_inbound`, which runs inline on the swarm task; an implementation that did I/O there would stall every connection, so it must be a cache read, and a miss is answered with `ResourceUnavailable`

The event loop handlers never `.await`. The trait's doc spells out the contract: a pure cache read, `None` on a miss.

[← Back to the question](09-net-cl.md#q-netcl-q11)

<a id="a-netcl-q12"></a>

**Q12** · Before mplex was added, the Rust host could not reach Nimbus nodes. Why does the test helper `dial_outcome` wait for an Identify answer instead of `ConnectionEstablished`?

**Answer: C.** The dialer negotiates the muxer optimistically and reports the connection established even with no muxer in common; only a completed stream (the Identify exchange) proves a muxer was agreed

The live Nimbus log showed exactly that shape: connection established, then closed with a decode error. The control test `a_yamux_only_host_cannot_connect_to_an_mplex_only_peer` keeps the helper honest.

[← Back to the question](09-net-cl.md#q-netcl-q12)

<a id="a-netcl-q13"></a>

**Q13** · `request_raw_at` calls `self.request_in_order(peer, addrs.clone(), protocol, wire.clone())` and may call it a second time. Why the clones, and exactly when does the retry happen?

**Model answer.** `request_in_order` takes `addrs` and `wire` by value and consumes them. To be able to call it again, the first call must get copies, and the retry then moves the originals in. The retry happens only on `Err(Timeout)` or `Err(ConnectionClosed)`, and only if the peer was not on `TcpFirst` before the request, this walk did not put it there itself, and it is on `TcpFirst` now. That combination means the swarm task demoted the peer while the request was out (a QUIC timeout it closed with `demote_stalled_quic`, or a Nimbus agent), so the request was lost to a close made by this node. It is retried once, TCP first; any other outcome is returned unchanged.

A good answer covers:

- request\_in\_order takes Vec arguments by value, so a retry needs copies made before the first call
- the retry moves the original addrs and wire, so they are not cloned twice
- retry only on Timeout or ConnectionClosed
- only when the peer became TcpFirst during this request, by the swarm, not before and not by this walk; at most once

[← Back to the question](09-net-cl.md#q-netcl-q13)

<a id="a-netcl-q14"></a>

**Q14** · Several locks in this stop are taken with `.lock().unwrap_or_else(|e| e.into_inner())` or `.read().unwrap_or_else(|e| e.into_inner())`. What does that do?

**Answer: D.** If another thread panicked while holding the lock, the lock is poisoned and returns `Err(PoisonError)`; `into_inner()` takes the guard anyway, accepting data that a panic may have left half-updated

`std` locks record a panic in a critical section. For log labels, dial-order hints and byte counters a possibly inconsistent value is harmless, so the code proceeds instead of propagating the panic with `unwrap()`.

[← Back to the question](09-net-cl.md#q-netcl-q14)

## Stop 10 · myotis-net, part 2: the light-client sync loop

<a id="a-sync-q1"></a>

**Q1** · The host calls “accept stale anchor” *after* `run_sync` received its own clone of `ChainConfig`. How does the parked loop notice?

**Answer: C.** `ws_policy` is an `Arc<WsPolicy>`; cloning the config only copied the pointer, so both copies share the same `AtomicBool`, which the loop re-reads every second

A `Clone` struct can contain shared parts. The atomics give lock-free, cross-thread visibility, like a Java `volatile` field. The test `ws_gate_staleness_and_bound_precedence` checks exactly this through a clone.

[← Back to the question](10-net-sync.md#q-sync-q1)

<a id="a-sync-q2"></a>

**Q2** · Bootstrap, catch-up and finality polling all fire many network requests concurrently, yet `PeerPool` and `LightClientProcessor` are plain structs without any `Mutex`. Explain why this is safe.

**Model answer.** Only the `run_sync` task owns them, and it lends them to helpers as `&mut`. The concurrent requests are *futures* that the same task polls (`join_all`, `FuturesUnordered`, `select!`). Each future owns only a cloned `ReqRespClient`, the peer and the wire bytes, never a reference to the pool or the processor (the `'static` bound on `BoxFuture` enforces this in `catch_up`). Responses are handled one at a time in the task's loop, with exclusive `&mut` access. The borrow checker guarantees there is never a second mutable accessor, so no lock is needed. Concurrency comes from interleaved futures on one task, not from threads sharing memory.

A good answer covers:

- single owner: the run\_sync task, which lends the state as &mut
- request futures capture only clones (client, peer, bytes), not the pool or processor
- responses are processed sequentially by the owner as futures complete
- compiler-enforced exclusivity replaces locks; the concurrency is interleaved futures, not threads sharing memory

[← Back to the question](10-net-sync.md#q-sync-q2)

<a id="a-sync-q3"></a>

**Q3** · `catch_up` declares `in_flight: FuturesUnordered<BoxFuture<'static, Answer>>` and pushes `Box::pin(async move { … })` blocks that each own a `client.clone()`, the peer and the wire bytes. What does the `'static` bound force, and why?

**Answer: B.** Each future may not borrow anything from `catch_up`'s stack (such as `pool`); it must own what it uses, because the set outlives any single top-up and the pool is mutated while the requests are in flight

`'static` on a type means it contains no non-`'static` borrows, not that the value lives forever. The `move` makes each block own its clones. If a request future borrowed `pool`, the loop could not take `&mut pool` to process answers while the request was still in the set.

[← Back to the question](10-net-sync.md#q-sync-q3)

<a id="a-sync-q4"></a>

**Q4** · `pub async fn stop(self)` runs `for task in &self.tasks { task.abort(); }` and then `for task in self.tasks { let _ = task.await; }`. Why two different loops?

**Answer: C.** The first only needs to borrow the handles to signal abort; `.await` consumes a `JoinHandle`, so the second must move each handle out of `self`

Borrow for what does not consume, move for what does. Moving a field out of `self` is allowed because `SyncHandle` implements no `Drop`.

[← Back to the question](10-net-sync.md#q-sync-q4)

<a id="a-sync-q5"></a>

**Q5** · What does `DiscoveryGuard` achieve that simply storing the discovery `JoinHandle` in a local would not?

**Answer: D.** When `run_sync` is aborted, its locals are dropped and the guard's `Drop` aborts the discovery task immediately, freeing its UDP port. A dropped `JoinHandle` would only detach the task

RAII turns “the sync task was cancelled” into “discovery stops now”. The comment explains why it matters: a fast stop→start on a fixed port would otherwise fail.

[← Back to the question](10-net-sync.md#q-sync-q5)

<a id="a-sync-q6"></a>

**Q6** · What must hold before `try_bootstrap` calls `store.initialize(…)` with a peer's bootstrap?

**Answer: B.** The header's `hash_tree_root` must equal the embedded checkpoint root, and `processor.verify_bootstrap` must accept it: shape matching the header's fork, the sync-committee branch, and the execution branch

“The peer chose the payload, WE chose the root.” The checkpoint is a trust anchor, so the peer earns credit (`mark_proven`) only after these checks. A slot mismatch is only logged, because the root, not the slot, is what is verified.

[← Back to the question](10-net-sync.md#q-sync-q6)

<a id="a-sync-q7"></a>

**Q7** · `let fail = |pool: &mut PeerPool, buf: &mut Vec<String>, id: PeerId| { … }`. Why is the pool a parameter instead of being captured by the closure?

**Answer: A.** A captured `&mut pool` would stay borrowed for the closure's whole lifetime, blocking later uses like `pool.mark_proven(peer)`; passing it per call keeps each borrow short

A common Rust idiom: pass the mutable state into the closure at each call rather than capturing it, so other code can use it between calls. `PeerPool::candidates` uses the same trick with its `ok` closure.

[← Back to the question](10-net-sync.md#q-sync-q7)

<a id="a-sync-q8"></a>

**Q8** · Explain the weak-subjectivity (STALE\_ANCHOR) gate: what attack does it prevent, where in `run_sync` does it run, and how is it released?

**Model answer.** A light client trusts sync-committee signatures. Once an anchor (checkpoint, snapshot or the committee held in memory) is older than the weak-subjectivity bound, enough validators of that old committee may have exited to sign a forged continuation that still BLS-verifies. So if the anchor's period is more than the effective bound behind the wall-clock period (`ws_anchor_stale`, 13 periods on mainnet, 3 on Gnosis, a host override if set), the loop refuses to sync and publishes `StaleAnchor` (fail closed). It runs at entry on the newer of checkpoint and snapshot (re-checking every second), before a re-bootstrap from the checkpoint after a poisoned resume, and in the main loop on the held committee (both re-checking every 5 s). It is released when the host raises the bound or gives per-run consent through the shared `WsPolicy` atomics (never persisted), or when the task is aborted.

A good answer covers:

- exited validators of an old committee can sign a forged chain that still verifies
- fires when wall period minus anchor period exceeds the effective bound (13 mainnet, 3 gnosis, or the host override)
- parks fail-closed in StaleAnchor and publishes that status (entry: every 1 s; pre-bootstrap and in-run: every 5 s)
- runs at entry (best of checkpoint and snapshot), before a re-bootstrap, and in-run on the held committee
- released by a raised bound or per-run consent through the WsPolicy atomics, or by aborting the task

[← Back to the question](10-net-sync.md#q-sync-q8)

<a id="a-sync-q9"></a>

**Q9** · In `run_sync`, the entry gate reads the snapshot with `persisted_snap.as_ref().map(|s| s.current_sync_committee_period)`, and a few lines later the code says `if let Some(snap) = persisted_snap { … processor.store.restore(snap); }`. Explain what each form does with ownership, and why the gate must use the first.

**Model answer.** `as_ref()` turns `&Option<Snapshot>` into `Option<&Snapshot>`, so the closure sees a reference and copies out one `u64`; `persisted_snap` still owns the snapshot afterwards. `if let Some(snap) = persisted_snap` matches the `Option` by value and moves the snapshot into `snap`; `restore(snap)` then moves it into the store. After that, `persisted_snap` can no longer be used. If the gate had used `persisted_snap.map(…)` without `as_ref()`, it would have consumed the snapshot, and the later resume would not compile (use of a moved value).

A good answer covers:

- as\_ref() borrows: Option&amp;lt;&Snapshot>, only a u64 is copied out
- persisted\_snap still owns the snapshot after the gate
- if let Some(snap) = persisted\_snap moves the snapshot out, restore(snap) moves it into the store
- without as\_ref() the gate would consume the Option and the later resume would be a use of a moved value

[← Back to the question](10-net-sync.md#q-sync-q9)

<a id="a-sync-q10"></a>

**Q10** · In `ClForkWatch::update`, the lock is taken inside an inner block `let current = { let Ok(mut inner) = self.inner.lock() else { return; }; … current };` and the `tracing::warn!` calls come after that block. What does that structure achieve?

**Answer: B.** The `MutexGuard` is dropped at the block's closing brace, so logging happens after the lock is released and other observers do not wait on the log sink

A guard unlocks when it goes out of scope. Ending the scope early is the idiomatic way to keep a critical section short. `current` can leave the block because `Option<Advisory>` is `Copy`; it is not a reference into the locked data.

[← Back to the question](10-net-sync.md#q-sync-q10)

<a id="a-sync-q11"></a>

**Q11** · Describe what `cl_fork_watch.rs` does and how it connects to `sync.rs`: who creates and owns the watch, who feeds it with what, who reads it, and what it can and cannot affect.

**Model answer.** It detects that consensus peers have scheduled or activated a fork this build's `ForkSchedule` does not know, and produces an `Advisory` (Scheduled or Active). The engine host creates one `Arc<ClForkWatch>` per handle on first spin-up and keeps it across pause/resume; it puts a clone into `ChainConfig::cl_fork_watch`. `SyncHandle::start` hands clones to the swarm task (via `HostConfig`: every peer Status `fork_digest`, through `observe_status`) and to the discovery task (via `DiscoveryConfig`: every routing-table ENR's `eth2` field, through `observe_enr`). `run_sync` itself never calls it. Votes are one per source network (/24 or /48) and need at least three sources and more than the dissent. The host reads `advisory()` at status time and merges it with the EL watch's. It is advisory only: verification never reads it, so it can show a banner but cannot change any answer.

A good answer covers:

- detects an unknown scheduled or active fork from peer advertisements and yields an Advisory
- engine host creates one Arc per handle, reused across pause/resume, passed in via ChainConfig.cl\_fork\_watch
- fed by the swarm task (Status fork\_digest, observe\_status) and the discovery task (routing-table ENR eth2 field, observe\_enr); run\_sync only threads it
- votes keyed by source network, needs 3 sources and more than the dissent
- read by the host at status time and merged with the EL advisory; never used by verification

[← Back to the question](10-net-sync.md#q-sync-q11)

<a id="a-sync-q12"></a>

**Q12** · In `poll_finality`, a response comes back `FinalityOutcome::Stale`: it verified against the held committee but did not advance the store. What does the round do with it?

**Answer: C.** Sets `verified = true` and keeps reading: it is not a win (so `advanced` stays false and a hunt may still run) and not a strike, and it spares the round's losers from cache strikes

Only `Advanced` breaks the loop and earns `mark_proven`. `verified` also confirms a resumed snapshot in `run_sync` (`resume.confirm()`), since a stale update proves the committee just as well.

[← Back to the question](10-net-sync.md#q-sync-q12)

<a id="a-sync-q13"></a>

**Q13** · `lc_crawl` writes `let _permit = sem.acquire_owned().await…;` while `period_census` writes `let permit = …;` and later `drop(permit);`. Explain what each does, why `let _ = sem.acquire_owned().await…` would be a bug, and why `acquire_owned` rather than `acquire`.

**Model answer.** A semaphore permit returns its slot when it is dropped. `let _permit` binds the permit to a named (if unused) variable, so it lives until the end of the task's block: the whole probe holds a slot. `let _ =` does not bind at all, so the permit is dropped immediately and the semaphore limits nothing. `period_census` drops the permit explicitly after the probe, because the following Identify poll does not need a probe slot; `drop` takes ownership and ends the value's life early. `acquire_owned` works on an `Arc<Semaphore>` and returns an `OwnedSemaphorePermit` that borrows nothing, so it can live inside a `'static` spawned task; `acquire` returns a permit that borrows the semaphore.

A good answer covers:

- a permit releases its slot when dropped
- let \_permit keeps it to the end of the task; let \_ = drops it at once, so nothing is limited
- drop(permit) releases it early, after the probe, before the Identify poll
- acquire\_owned on Arc&amp;lt;Semaphore> yields a permit with no borrow, usable in a 'static spawned task

[← Back to the question](10-net-sync.md#q-sync-q13)

<a id="a-sync-q14"></a>

**Q14** · In `catch_up`'s quota wait, the code runs `tokio::join!(tokio::time::sleep(wait), tokio::time::timeout(probe_budget, hunt_round(config, client, pool, processor, clcache, …)))`. Explain how the two futures run, why the borrow checker accepts `hunt_round` borrowing `pool` mutably here, and what happens to the hunt when the budget runs out.

**Model answer.** `join!` polls both futures concurrently on the current task (no new task, no thread) and completes when both are done, so the wait is at least `wait` long. Only `hunt_round` holds borrows of `pool`, `processor` and `clcache` (all `&mut`, reborrowed from `catch_up`'s parameters); `sleep` borrows nothing, so there is no second mutable borrow and the code compiles. Two futures in one `join!` that both needed `&mut pool` would be rejected. When `probe_budget` elapses, `timeout` drops the `hunt_round` future; its in-flight probes are abandoned, but whatever it already recorded in the pool, the cache and `hunt.probed`/`hunt.confirmed` stays. The borrows end when `join!` returns, and the result tuple is discarded with `let (_, _)`.

A good answer covers:

- join! polls both futures on the same task and finishes when both finish
- only hunt\_round borrows pool/processor/clcache mutably; sleep borrows nothing, so no conflict
- two futures both needing &mut pool in one join! would not compile
- timeout drops the hunt future at the budget; results already recorded remain

[← Back to the question](10-net-sync.md#q-sync-q14)

## Stop 11 · myotis-net, part 3: execution-layer peers

<a id="a-elt-q1"></a>

**Q1** · Why can a `ManagedPeer` serve many requests concurrently, when an `EthSession` can only handle one at a time?

**Model answer.** An `EthSession` owns the whole connection and uses a single `&mut self` for both sending and receiving (`recv_answering_ping` takes `&mut RlpxConnection`), so every request has to wait for its response before the next can start. A `ManagedPeer` first `split`s the connection. The reader is moved into a background task that reads all frames, and the writer sits behind an `Arc<tokio::Mutex>` that callers take only for the duration of one frame write. Each request gets a unique id from an `AtomicU64` and registers a `oneshot` sender in a shared pending map. The read loop matches each response by id and code and completes the right oneshot. Because the methods take `&self` and the shared state is behind locks and atomics, many callers holding an `Arc<ManagedPeer>` can await different responses at once.

A good answer covers:

- EthSession: one &mut borrow for send and recv, so strictly sequential
- split: the reader is owned by the read-loop task, the writer is behind Arc&amp;lt;tokio::Mutex>
- request ids from an AtomicU64 plus a pending map of oneshot senders
- the read loop routes responses by (id, code); request methods take &self

[← Back to the question](11-el-transport.md#q-elt-q1)

<a id="a-elt-q2"></a>

**Q2** · `pub struct RlpxConnection<S = TcpStream>`, with `split` in `impl RlpxConnection<TcpStream>` and the handshake in `impl<S: AsyncReadExt + AsyncWriteExt + Unpin> RlpxConnection<S>`. What does this arrangement buy?

**Answer: C.** Callers can keep writing `RlpxConnection` for TCP, the handshake and framing run unchanged over any async stream (Arti's `DataStream`, an in-memory `DuplexStream`), and `split` exists only where `into_split` does

A default type parameter plus a trait-bounded impl, compiled per concrete type (static dispatch). An impl block for one concrete instantiation adds methods only to that type, which erased Java generics can't express.

[← Back to the question](11-el-transport.md#q-elt-q2)

<a id="a-elt-q3"></a>

**Q3** · `send_frame` sets `w.torn = true` before `writer.send(…).await` and afterwards sets `w.torn = result.is_err()`. What does this protect against?

**Answer: B.** A frame write that was cancelled or failed may have left a partial frame on the wire with the egress MAC already advanced; the marker makes every later writer refuse the stream instead of appending MAC-garbage

Cancellation in Rust is dropping the future: no exception, no cleanup callback, nothing after the `.await` runs. So the code records “a write is in progress” before the await and clears it only on a completed, successful write.

[← Back to the question](11-el-transport.md#q-elt-q3)

<a id="a-elt-q4"></a>

**Q4** · In discv4's `emit`, why is the discovered entry offered with `try_send` instead of `send().await`?

**Answer: C.** The whole service is one `select!` loop in one task; waiting on a full channel would stall receiving, the refresh, the ENR sweep and even stop. The event is advisory because the table already holds the entry

In a single-task actor, any await inside a handler pauses every branch. Non-essential messages are offered, not forced.

[← Back to the question](11-el-transport.md#q-elt-q4)

<a id="a-elt-q5"></a>

**Q5** · `DnsSeeder::walk_once` starts with `let _claim = WalkClaim(self);`. What does the guard do, in which situations does it do it, and what would change if the line were `let _ = WalkClaim(self);`?

**Model answer.** `begin_walk_if_due` sets `walking = true` so no two walks run at once. `WalkClaim`'s `Drop` sets `walking = false` and stamps `last_walk`. Because the guard is bound to a named variable, it lives until `walk_once`'s scope ends, so the claim is released when the walk returns normally, when its future is dropped (for example the pool stopping and cancelling the task), or when it unwinds. With `let _ =` the value is dropped immediately at the end of the statement, so the claim would be released before the walk even started and a second walk could begin concurrently.

A good answer covers:

- Drop clears the walking flag and records last\_walk
- runs on normal return, on cancellation (future dropped) and on unwind
- let \_claim keeps the guard alive to the end of the scope
- let \_ drops it at once, releasing the claim before the walk runs

[← Back to the question](11-el-transport.md#q-elt-q5)

<a id="a-elt-q6"></a>

**Q6** · In `walk_all`, `let system;` is declared before the `match` and assigned inside the `ResolverSource::System` arm, whose value is `&system`. Why not write `let system = r;` inside the arm?

**Answer: C.** Declared inside the arm, `system` would be dropped at the arm's end while `resolver` still borrowed it, which is a compile error; declaring it outside makes it live until the function returns

This is how to borrow from one of two owners without `Box` or `Cow`: give the possibly-needed owner a longer-lived binding. Rust allows a `let` without an initializer as long as every use comes after an assignment.

[← Back to the question](11-el-transport.md#q-elt-q6)

<a id="a-elt-q7"></a>

**Q7** · In discv4's `consider`, `enr` is `self.enr.as_mut()`, a mutable borrow of part of `self`. Yet the function later calls `self.forget(…)` and `self.emit(…).await`, which need all of `self`. Why does this compile, and what role does the `Seen` enum play?

**Model answer.** A borrow lasts until its last use, not until the end of its lexical scope (non-lexical lifetimes). In each match arm, `enr` is used for the last time (for example `enr.skip_foreign()`) before `self.forget` or `self.emit` is called, so the mutable borrow has ended by then. In the `let … else` at the top, the `else` branch has no `enr` at all. `Seen` converts the borrowed lookup `enr.verdicts.get(&entry.node_id)` into an owned summary: it holds no references, only a copied `Option<u32>`. So the shared borrow of the verdicts map ends when `seen` is computed, and the second match can call `get_mut` or `remove` on the same map.

A good answer covers:

- non-lexical lifetimes: a borrow ends at its last use
- enr is last used before self.forget/self.emit in each arm
- the else branch of let-else has no borrow of self.enr
- Seen holds no references (copied Option&amp;lt;u32>), ending the map borrow before the mutating match

[← Back to the question](11-el-transport.md#q-elt-q7)

<a id="a-elt-q8"></a>

**Q8** · `TxtLookup::txt` returns `Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>` instead of being an `async fn`. Why?

**Answer: B.** An `async fn` in a trait makes the trait unusable as `dyn TxtLookup`, because each implementation's future is a different unnamed type; one boxed future type lets `walk` take `&dyn TxtLookup` and the seeder hold `Arc<dyn TxtLookup>`

Returning a boxed trait-object future gives every implementation the same return type. `'a` lets the future keep borrowing `self` and `name` until it completes; `Send` lets it run on a multi-threaded runtime.

[← Back to the question](11-el-transport.md#q-elt-q8)

<a id="a-elt-q9"></a>

**Q9** · In `tor.rs`, `client()` runs the Arti bootstrap inside `tokio::spawn` and hands callers a `Shared` future over the task's `JoinHandle`. What does this achieve?

**Answer: B.** A caller whose deadline expires drops only its clone of the shared future; the task keeps running (dropping a `JoinHandle` detaches it), so a bootstrap is never cancelled halfway, and all waiting callers see the same result

`Shared` requires a `Clone` output, here `Result<(), String>`; the client itself lives in the `static OnceCell`. The generation counter makes sure a caller clears only the failed bootstrap it waited on.

[← Back to the question](11-el-transport.md#q-elt-q9)

<a id="a-elt-q10"></a>

**Q10** · `ManagedPeer::request` inserts its pending entry while holding the pending lock and checks `closed` inside that lock, then arms a `PendingGuard`. Which two failure cases do these choices prevent?

**Model answer.** First, a lost wake-up on disconnect: `fail_all` sets `closed` and drains the map while holding the same pending lock. A request that checked `closed` without the lock could insert just after the drain and then wait 15 s on a dead connection. Under the lock, it either inserts before the drain (and receives the drain's `Err`) or sees `closed` and returns at once. Second, a leaked entry on cancellation: if the request future is dropped at a later `.await` (send or response wait), the guard's `Drop` spawns a task that removes the entry. There is no `.await` between the insert and arming the guard, so there is no window in which a cancellation could leak the entry. On normal completion the guard is disarmed because the entry is already gone.

A good answer covers:

- fail\_all sets closed and drains under the same pending lock
- a request either inserts before the drain (gets Err) or sees closed and bails
- PendingGuard::drop removes the entry if the future is dropped mid-flight
- no .await between insert and arming the guard; disarmed on completed paths

[← Back to the question](11-el-transport.md#q-elt-q10)

<a id="a-elt-q11"></a>

**Q11** · `TorReserve::ready` sorts with `sort_by_cached_key(|(node, e)| (e.quality.dial_rank(), e.tor_fails, draw(node)))`, where `draw` returns a random number. Why `sort_by_cached_key` and not `sort_by_key`?

**Answer: C.** `sort_by_cached_key` computes each key once, so each node gets one random draw; `sort_by_key` recomputes keys during comparisons, which with a random key gives an inconsistent order (and recent Rust sorts may panic on that)

A key function must be consistent for the sort to be well defined. Caching makes a random key a fixed property of each element for the duration of one sort.

[← Back to the question](11-el-transport.md#q-elt-q11)

<a id="a-elt-q12"></a>

**Q12** · Why does discv4 answer an ENRRequest only from a node whose pong it verified, checked against the signing key, and within the Ping rate limit?

**Answer: C.** Without a bond, a spoofed source address could make us send signed records to a victim (amplification); the key check stops a spoofer from borrowing a bootnode's bond, and the rate limit stops a bonded node from asking at line rate

This is geth's `checkBond` rule. The bond is keyed by address and checked against the signer (`EnrExchange::is_bonded`), and expired requests are ignored so a captured one can't be replayed.

[← Back to the question](11-el-transport.md#q-elt-q12)

<a id="a-elt-q13"></a>

**Q13** · What does `scope_send_marker` record, how does a call deep inside `ManagedPeer::request` reach it without a parameter, and why is a `OnceLock` used?

**Model answer.** It records when the first request frame of one hedged-read attempt was actually written to the peer's socket, as opposed to when the attempt was created; the two can differ by up to the 30 s frame-write timeout because every request first waits for the shared writer. `scope_send_marker` creates an `Arc<OnceLock<Instant>>`, keeps one clone for the caller, and wraps the attempt's future with `REQUEST_SENT.scope(sent, fut)`, a tokio task-local: any code polled inside that future can reach the value. `mark_request_sent` calls `REQUEST_SENT.try_with`, which fails (ignored) outside a scope. `OnceLock::set` succeeds only the first time, so later requests of the same attempt don't move the mark.

A good answer covers:

- records when the attempt's first request frame was written, not when the attempt started
- task\_local scope: visible to code polled inside the wrapped future, no parameter passing
- the Arc is shared between the caller and the scoped future
- OnceLock keeps only the first set; try\_with makes it a no-op outside a hedged read

[← Back to the question](11-el-transport.md#q-elt-q13)

## Stop 12 · myotis-net, part 4: the peer pool and the trust chain

<a id="a-pool-q1"></a>

**Q1** · `verify_header_chain` requires the *last* (newest) header to hash to the attested block hash. Why not anchor the walk at the oldest header, the finalized block, as the code once did?

**Answer: B.** A `parentHash` commits a header to its parent only. Anchored at the oldest header, nothing pins the headers above it, so a peer could name the attested block as the parent of a made-up header with any state root

Trust flows down a hash chain, from child to parent. The test `a_made_up_child_of_the_attested_block_is_rejected` pins the attack the old upward walk let through.

[← Back to the question](12-el-pool.md#q-pool-q1)

<a id="a-pool-q2"></a>

**Q2** · In `request::blocking`, the semaphore permit and the `Worker` guard are moved into the `spawn_blocking` closure. Explain why they must live there rather than in the async caller.

**Model answer.** A `spawn_blocking` job cannot be aborted: once started it runs to the end, even if the async caller that awaited it is dropped (for example on a deadline). If the permit and the worker count lived in the caller, they would be released when the caller gave up, while the native EVM job was still running. The engine would then admit more than 8 concurrent jobs, and `drain()` or `settled()` would think nothing was running. Moved into the closure, their `Drop` runs exactly when the job ends, so the slot limit and the worker accounting track real work. “Permits belong to jobs, never to the caller's patience.”

A good answer covers:

- spawn\_blocking jobs cannot be aborted, and the caller may be dropped first
- guards held by the caller would be released too early: over-admission past 8 and a false 'drained'
- moved into the closure, their Drop runs when the job actually finishes
- the closure binds them (let \_permit = permit), so the move closure captures and owns them

[← Back to the question](12-el-pool.md#q-pool-q2)

<a id="a-pool-q3"></a>

**Q3** · `request.rs` moves a plain `SemaphorePermit` into a `spawn_blocking` closure, while `try_dial_with` in the pool needs `Arc::clone(&inner.dial_slots).acquire_owned()`. Why the difference?

**Answer: B.** `BLOCKING_SLOTS` is a `static`, so its permit is `SemaphorePermit<'static>`; the dial semaphore lives in an `Arc`, so a borrowed permit would not be `'static` and the owned permit carries its own `Arc` instead

A permit borrows its semaphore. A borrow of a static lasts forever; a borrow of an `Arc`'s contents does not, so it cannot move into a spawned task.

[← Back to the question](12-el-pool.md#q-pool-q3)

<a id="a-pool-q4"></a>

**Q4** · `Operation::settled()` creates the `Notified` future and calls `enable()` *before* checking the atomics, while `ExecAnchor::pending_changed()` just awaits `notified()`. Why is the anchor's simpler form safe?

**Answer: B.** The anchor wakes with `notify_one`, which stores a permit when nobody waits, so a notification between two waits is not lost; `request.rs` uses `notify_waiters`, which stores none

`notify_waiters` wakes only futures already registered, so `settled` must register before testing. `notify_one` leaves a permit behind; the test `a_new_pending_hash_wakes_the_resolver` checks it.

[← Back to the question](12-el-pool.md#q-pool-q4)

<a id="a-pool-q5"></a>

**Q5** · `Tasks` already aborts its tasks in `Drop`. Why does `PeerPool` need its own `Drop` that calls `abort()`?

**Answer: B.** The loops hold `Arc<PoolInner>` and `PoolInner` owns `Tasks`, so the count never reaches zero while the loops run and `Tasks::drop` never fires; the outer handle must break the cycle

Reference counting cannot collect cycles. Either break them explicitly, as `PeerPool` does, or avoid them with `Weak`.

[← Back to the question](12-el-pool.md#q-pool-q5)

<a id="a-pool-q6"></a>

**Q6** · The pool holds three peers, newest first: A (benched, `Covers`, proven), B (not benched, `Behind`, proven), C (not benched, `Unknown`, unproven). In what order does `snap_peers` return them, and which Rust feature produces that order?

**Model answer.** C, A, B. `LadderKey` derives `Ord`, which compares fields lexicographically in declaration order (`behind`, `benched`, `coverage`, `unproven`), with `false < true`. B has `behind = true`, so it is last whatever else is true. Between A and C, the next field is `benched`: C is not benched, A is, so C comes first. `ladder_order` sorts indices with the stable `sort_by_key`, so ties would keep the newest-first input order. No peer is removed; benched and behind peers only move back.

A good answer covers:

- the order is C, A, B
- derived Ord compares fields in declaration order, false before true
- behind is the first field, so B is last regardless of the rest
- benched is compared before coverage, so unbenched C leads benched A
- sort\_by\_key is stable; ties keep newest-first order

[← Back to the question](12-el-pool.md#q-pool-q6)

<a id="a-pool-q7"></a>

**Q7** · `read_failure_verdict(fails_before, pool_len)` returns `(0, false)` when `pool_len <= 1`. What does that rule protect against?

**Answer: B.** A failure against the only server is likely our own stale request; banking a strike would evict that peer the moment a second peer arrived, before it ever failed as a non-sole peer

The sole peer is still benched for 30 s by the caller, so a second peer, once found, leads the ladder. It just never accumulates strikes while alone.

[← Back to the question](12-el-pool.md#q-pool-q7)

<a id="a-pool-q8"></a>

**Q8** · Explain the difference between `QualityOutcome::Failed` and `QualityOutcome::FailedUnwitnessed`: what each does to the live pool and to the persisted peer cache, and why the distinction was introduced.

**Model answer.** Both bench the peer and count a strike toward eviction, so the live pool keeps rotating either way. `Failed` means another peer served the same read, so the failure is evidence about this peer; it may be persisted to the cache (toward `Denied`), but only if another peer is live (`persist_verdict(true, other_live)`, the older sole-peer shield). `FailedUnwitnessed` means nobody served the read, so the failure is more likely about our own request (a head nobody has yet, a pruned root); `persist_quality` returns early and nothing is written. It was introduced in #465 after a cold pool's tip-lag failures flipped 14 of 27 cache entries to snapbad, so the next cold start dialed its proven servers last.

A good answer covers:

- both bench and strike in the live pool
- Failed = another peer served the same read; FailedUnwitnessed = no peer did
- only Failed can be persisted, and only while another peer is live
- unwitnessed failures say more about our request than about the peer
- motivated by #465: cold-start failures poisoned the cache

[← Back to the question](12-el-pool.md#q-pool-q8)

<a id="a-pool-q9"></a>

**Q9** · `ExecAnchor::resolve_header` recomputes `keccak256(&header.raw_rlp)` although `VerifiedHeader` already has a `hash` field. Why?

**Answer: B.** The adopted number, root and timestamp come from the decoded header; a value whose `hash` field claims the pending hash over another header's bytes must be refused, so the anchor checks the bytes itself

The anchor is the verifier, not the resolver loop or the decoder. The test `a_header_is_adopted_only_under_its_own_hash` forges exactly that case.

[← Back to the question](12-el-pool.md#q-pool-q9)

<a id="a-pool-q10"></a>

**Q10** · Why does `ReadStats::observe_account_at` write `let inner = &mut *g;` before borrowing `inner.counters.account` and `inner.accounts`?

**Answer: B.** Field access through a `MutexGuard` goes through `deref_mut`, which borrows the whole guard; reborrowing to a plain `&mut Inner` lets the compiler see two disjoint field borrows

Disjoint field borrows work on a plain `&mut` struct, not through a smart pointer's `DerefMut`. The lock is still held until `g` drops.

[← Back to the question](12-el-pool.md#q-pool-q10)

<a id="a-pool-q11"></a>

**Q11** · The verified head is block 1,000 and the finalized block is 936. A client calls `eth_getProof` at block 999, which is not among the linked recent heads. What does `resolve_target` return, and why?

**Answer: C.** `Refused` (permanent `-32602`): a proof at another root would not verify against block 999's stateRoot, and a block below the head never becomes servable later

A refusal below the head is permanent, so a client does not spin on a retryable code. Above the head (1,001) the answer would be `Unavailable`.

[← Back to the question](12-el-pool.md#q-pool-q11)

<a id="a-pool-q12"></a>

**Q12** · `fork_watch.rs` counts one vote per `source_of(ip)` and is "advisory only". Explain both choices and what an attacker who controls many node ids on one /24 can achieve.

**Model answer.** Node ids are free to generate, so counting by node id would let one operator cast any number of votes. `source_of` maps a peer to its IPv4 /24 or IPv6 /48 (IPv4-mapped addresses count as IPv4), and `by_source` holds one observation per source, so many ids behind one /24 are one vote (the test `one_network_is_one_vote`). An advisory also needs at least `MIN_PEERS` (3) sources and more than the dissenting sources on our own hash. Advisory only means nothing in verification reads it: a false advisory is a wrong banner, never a wrong answer. So the attacker on one /24 gets one vote and cannot raise an advisory alone; even with enough networks, the worst outcome is a misleading update banner.

A good answer covers:

- node ids are free, so votes are counted per source network
- source\_of maps IPv4 to /24 and IPv6 to /48, and by\_source keeps one entry per source
- an advisory needs at least 3 sources and more than the dissent
- nothing in verification reads the advisory, so a false one cannot change an answer
- one /24 is one vote

[← Back to the question](12-el-pool.md#q-pool-q12)

## Stop 13 · myotis-net, part 5: EVM bridge, log index and transactions

<a id="a-els-q1"></a>

**Q1** · `PoolOracle::wait` calls `self.handle.block_on(…)`. Why does the reader run revm through `request::blocking` instead of calling the executor directly inside its async method?

**Answer: B.** `Handle::block_on` panics when called from inside an async execution context, and a runtime worker parked in it would stall every task queued on that worker; a blocking-pool thread may block

The bridge parks a thread until the network answers. Only a thread that runs no async tasks may do that, and tokio enforces it with a panic. Task-locals are the opposite: they do not reach blocking threads, which is why `PoolOracle::new` captures the operation eagerly.

[← Back to the question](13-el-services.md#q-els-q1)

<a id="a-els-q2"></a>

**Q2** · In `PoolOracle::leaf`, the async block passed to `wait` borrows `self`, `peers`, `asked` and `state_root`. `tokio::spawn` would reject such a future. Explain why it is accepted here.

**Model answer.** `Handle::block_on` has the signature `fn block_on<F: Future>(&self, future: F) -> F::Output`: no `Send` and no `'static` bound. It drives the future to completion on the calling thread and only then returns, so every borrow inside the future ends before `wait` returns, while `peers`, `asked` and `state_root` are still alive in `leaf`'s frame. `tokio::spawn` needs `'static` (and `Send`) because a spawned task may outlive the function that spawned it and run on another thread, so it may not hold borrows of that function's locals.

A good answer covers:

- block\_on has no Send or 'static bound on its future
- block\_on returns only after the future has completed
- the borrowed locals live in leaf's frame for the whole time the future runs
- tokio::spawn needs 'static because a spawned task can outlive its spawner

[← Back to the question](13-el-services.md#q-els-q2)

<a id="a-els-q3"></a>

**Q3** · In the prefetch wave, each slot request starts with `let Ok(_permit) = sem.acquire().await else { … };`. What would change if it were written `let Ok(_) = sem.acquire().await else { … };`?

**Answer: C.** `_` does not bind, so the permit is dropped at the end of that statement, before the request is sent, and the 48-request limit no longer limits anything

`_permit` is a real binding that lives to the end of the scope; `_` is a pattern that binds nothing, so the value is dropped immediately. The same distinction makes `let _timer = self.wire.serial();` time the whole fetch.

[← Back to the question](13-el-services.md#q-els-q3)

<a id="a-els-q4"></a>

**Q4** · An address entry has `from_block` 100 and coverage \[200, 201\]. A wallet asks `eth_getLogs` for that address over \[150, 201\]. What does `LogIndex::query` return?

**Answer: A.** `Err(OutOfCoverage { … })`, because blocks 150–199 were never processed and `[]` would falsely claim there were no events

`check_coverage` requires \[max(150, 100), 201\] = \[150, 201\] to be covered. With `from_block` 180 it would still be \[180, 201\], not covered either; with `from_block` 200 the range \[200, 201\] is covered and the stored logs are returned.

[← Back to the question](13-el-services.md#q-els-q4)

<a id="a-els-q5"></a>

**Q5** · `LogIndex::merge` iterates `for s in &mut sources` and calls `std::mem::take(&mut s.logs)`. What does that achieve?

**Answer: D.** It moves the whole, possibly huge, map out through the `&mut` reference without cloning, leaving an empty map behind; iterating it by value then moves each log into the output

You cannot move out of a place you only hold by `&mut`. `mem::take` swaps in `Default::default()` and hands you the original. `unwatch` uses the same trick on two fields at once.

[← Back to the question](13-el-services.md#q-els-q5)

<a id="a-els-q6"></a>

**Q6** · Explain how `LogIndex::unwatch` rebuilds `config.watch` and `coverage` without cloning, and why the later `self.logs.retain(…)` may read `watch` and `coverage` while it mutates `self.logs`.

**Model answer.** It calls `std::mem::take` on both vectors, which moves the full vectors out of the fields (through `&mut self`) and leaves empty ones behind. Iterating `watch.into_iter().zip(coverage)` by value then moves each entry and its coverage either into `dropped` or back into the (now empty) fields, so they stay parallel and nothing is copied. Afterwards `let (watch, coverage) = (&self.config.watch, &self.coverage);` takes shared borrows of two fields, and `self.logs.retain` takes a mutable borrow of a different field, `logs`. The borrow checker tracks borrows per field, so shared borrows of `config.watch` and `coverage` can coexist with a mutable borrow of `logs`. The closure captures those references and `dropped`.

A good answer covers:

- mem::take moves each Vec out of its field and leaves an empty Vec
- into\_iter().zip moves each entry into dropped or back into the field, keeping coverage parallel, with no clone
- shared borrows of config.watch and coverage and a mutable borrow of logs are borrows of different fields
- the borrow checker allows disjoint field borrows at the same time

[← Back to the question](13-el-services.md#q-els-q6)

<a id="a-els-q7"></a>

**Q7** · In `PendingNonceTracker::record`, the `None` arm of `match self.by_sender.get_mut(&sender)` calls `self.by_sender.insert(…)`. Why is that allowed while the map is borrowed by the `match`?

**Answer: B.** Non-lexical lifetimes: the `get_mut` borrow is live only in the arms that bind `e`, and in the `None` arm no reference survives, so a new mutable borrow is fine

The borrow checker reasons per control-flow path: a borrow that is not used on a path does not block that path. `overlay` relies on the same rule when it calls `remove` after reading `e`.

[← Back to the question](13-el-services.md#q-els-q7)

<a id="a-els-q8"></a>

**Q8** · `tx::to_field` returns `Option<Option<[u8; 20]>>`. What does `Some(None)` mean?

**Answer: C.** An empty `to` field: the transaction creates a contract

The outer `None` is "malformed" and short-circuits through `?`; the inner `None` is a legitimate value, contract creation. `decode_sendable` later refuses `Some(None)` only for a type 0x4 transaction.

[← Back to the question](13-el-services.md#q-els-q8)

<a id="a-els-q9"></a>

**Q9** · The pre-broadcast check in `send_check.rs` fails open. What does that mean, why was it chosen, and how does `head_is_fresh` stop a wrong wall clock from making a stalled head look fresh?

**Model answer.** Failing open means that whenever the check cannot judge (undecodable or blob transaction, stale head, slow or unproven account read, Tor-routed reads, too many reads in flight) the transaction is broadcast as before; only a positive verdict (nonce too low, insufficient funds) refuses it. It was chosen because a light client that lags the chain must never block a send; the check only exists to report sends that can never be mined, which peers would drop silently. `head_is_fresh` needs two tests: the head's proven timestamp must be within two block times plus 6 s of the wall clock, and the node must have seen the head advance within the same bound on its own monotonic clock (`adopted_ago`). A stalled client's head ages on the monotonic clock whatever the wall clock says, and a head never seen to advance (`None`) is never fresh.

A good answer covers:

- fail open: when the check cannot judge, the transaction is broadcast unchanged
- only a definite verdict (nonce too low / insufficient funds) refuses the send
- reason: a lagging node must never block a send
- freshness also requires the head to have advanced recently on the node's own monotonic clock, which a wrong wall clock cannot fake
- a head never seen to advance (adopted\_ago None) is not fresh

[← Back to the question](13-el-services.md#q-els-q9)

<a id="a-els-q10"></a>

**Q10** · A `Slot<FeeEstimate>` holds a value computed for top `(100, hash A)` two seconds ago. The current top is `(100, hash B)`, and the caller allows stale values. What does `lookup` return?

**Answer: D.** `Miss`, because the same number with another hash is a reorg, and a reorg is never served stale

`head.0.checked_sub(at_head.0).filter(|&b| b > 0)` is `None` when the number did not grow, so only a strictly older top can be stale. A fee computed on the losing fork is not a pure function of the current top.

[← Back to the question](13-el-services.md#q-els-q10)

<a id="a-els-q11"></a>

**Q11** · In `activity.rs`, explain what `carry` does with a block whose verified BAL lists the followed account with `storage_written` set, and why the callers clone `values` before they call `carry`.

**Model answer.** `carry` returns `Err(Carry::Never)`: the block wrote at least one of the account's storage slots, so its storage root changed to a value the BAL does not carry. The carried `AccountValues` (which include `storage_root`) would be wrong, so the account cannot be followed through that block; `advance_followed` drops it and `followed_answer` returns `None`, which sends the read to a fresh proof. The callers clone first (`let mut next = f.values.clone();`) because `carry` writes through a `&mut AccountValues` and may update balance, nonce or code hash before it finds a reason to fail. Working on a clone and keeping it only on `Ok` makes the carry all-or-nothing.

A good answer covers:

- storage\_written makes carry return Err(Carry::Never)
- the BAL does not carry the new storage root, so the carried values would be wrong
- Never drops the followed account and sends the next read to a proof
- carry mutates through &mut, so callers work on a clone and keep it only on Ok

[← Back to the question](13-el-services.md#q-els-q11)

<a id="a-els-q12"></a>

**Q12** · `WireTimer<'a>` holds `&'a AtomicU64` and adds elapsed time in its `Drop`. What does the lifetime guarantee, and why do the fetch methods write `let _timer = self.wire.serial();` rather than `let _ = self.wire.serial();`?

**Model answer.** The lifetime ties the timer to the `WireCounters` it borrows from: the compiler rejects any code in which a timer could outlive its counter, so `drop` can never write through a dangling reference. `let _timer = …` binds the guard to a named variable that lives until the end of the function, so `drop` runs when the fetch ends, on every path, including early returns through `?`, and adds the fetch's whole duration. `let _ = …` binds nothing, so the guard would be dropped at once and record about zero time.

A good answer covers:

- 'a means the timer cannot outlive the AtomicU64 (the WireCounters) it points into
- Drop runs on every exit path, including early ? returns
- a named \_timer lives to the end of the function and so times the whole fetch
- let \_ = drops the guard immediately, recording almost no time

[← Back to the question](13-el-services.md#q-els-q12)

<a id="a-els-q13"></a>

**Q13** · `decode_sendable` checks `tx.r < SECP256K1_N`, where both sides are `[u8; 32]`. What does that comparison do?

**Answer: A.** It compares the arrays element by element from the first byte (lexicographic order), which for equal-length big-endian numbers is numeric order

Arrays of an `Ord` type implement `Ord` lexicographically. Big-endian puts the most significant byte first, so the first differing byte decides, exactly as in a numeric comparison.

[← Back to the question](13-el-services.md#q-els-q13)

<a id="a-els-q14"></a>

**Q14** · `FeeCache::history_lookup` picks an eviction victim with `self.histories.iter().min_by_key(…).map(|(k, _)| k.clone())` and then calls `self.histories.remove(&victim)`. Why the `clone`?

**Answer: C.** Without it, the victim would be a reference into the map, keeping the shared borrow from `iter()` alive, and the mutable borrow for `remove` would be rejected

An owned key ends the iterator's borrow of the map. `remove` only needs `&victim`; it is the earlier borrow that must end first.

[← Back to the question](13-el-services.md#q-els-q14)

## Stop 14 · myotis-net, part 6: the verified reader

<a id="a-reader-q1"></a>

**Q1** · The log-index appender, the fee follower and the activity follower each hold a `Weak<ElReader>` and call `upgrade()` once per tick. Hosts now call `reader.stop().await`, which aborts these tasks. What does the `Weak` still buy?

**Answer: C.** If a host drops its last `Arc` without calling `stop()`, the task's next `upgrade()` returns `None` and the loop ends; a strong `Arc` in the task would keep the reader and its networking alive for as long as the loop runs

A task that owns a strong reference to its owner keeps it alive. The `Weak` makes the task's lifetime follow the host's references; `stop()` is the fast, deterministic path.

[← Back to the question](14-el-reader.md#q-reader-q1)

<a id="a-reader-q2"></a>

**Q2** · `send_raw_transaction` and `pre_broadcast_check` take `self: &Arc<Self>`. Why?

**Answer: A.** The pre-broadcast check spawns a `'static` task that needs its own owned reference to the reader, and only an `&Arc<Self>` receiver lets the method call `Arc::clone(self)`

`tokio::spawn` requires `'static`, so the task cannot borrow `&self`. With a plain `&self` receiver there is no `Arc` to clone.

[← Back to the question](14-el-reader.md#q-reader-q2)

<a id="a-reader-q3"></a>

**Q3** · In `hedged_race`, how are the losing attempts cancelled once a winner is found, and what does the doc comment warn this can cost?

**Model answer.** All attempts live in a local `FuturesUnordered` (`in_flight`). When an accepted answer arrives, the function `return`s, which drops `in_flight` and every future inside it. Dropping a future is cancellation in Rust: it is never polled again, and the destructors of what it holds run. No explicit cancel calls are needed. The cost: an attempt dropped in the middle of a frame write leaves that peer's writer marked torn, which condemns the connection (`fail_all`). The code accepts that trade only once it has the answer, and does not poll the losers again after the winner arrives, so no loser starts a new request that would then be cut.

A good answer covers:

- attempts are owned by a local FuturesUnordered
- returning drops it, and every in-flight future is dropped, which cancels it
- no explicit cancel call; destructors run
- a mid-write cancellation can tear that peer's connection (torn writer, fail\_all)

[← Back to the question](14-el-reader.md#q-reader-q3)

<a id="a-reader-q4"></a>

**Q4** · In `get_account_proven`, the closure `|peer| async move { self.get_account_from(&peer, address, fin).await }` produces futures that borrow `self`. Why does this compile without a `'static` bound?

**Answer: D.** The futures are never spawned: `hedged_read` drives them to completion inside this method, so they only need to live as long as the borrowed locals, and `address` and `fin` are `Copy` and copied in

`'static` is required by `tokio::spawn` because a spawned task may outlive its creator. Futures awaited in place may borrow freely.

[← Back to the question](14-el-reader.md#q-reader-q4)

<a id="a-reader-q5"></a>

**Q5** · `pre_broadcast_check` spawns the account read and then does `tokio::time::timeout(ACCOUNT_READ_BUDGET, read)` on its `JoinHandle`. What happens to the read when the timeout fires?

**Answer: B.** It keeps running: dropping a `JoinHandle` detaches the task rather than cancelling it, and the read is still bounded by its own registered budget and by `stop()`

The timeout drops the handle, not the task. That is the point here: a read cut mid-request could tear the connection the broadcast is about to use. Contrast dropping a future, which does cancel it.

[← Back to the question](14-el-reader.md#q-reader-q5)

<a id="a-reader-q6"></a>

**Q6** · In `fee_estimate_refresh_locked`, the single-flight guard arrives as the parameter `_flight`, and the body declares `let mut on_drop = FeeFailOnDrop::new(…)`. Explain why the comment says the local is “dropped before the `_flight` parameter”, and what would go wrong in the other order.

**Model answer.** Locals are dropped in reverse declaration order, and an async fn binds its parameters before the body's locals, so parameters are dropped last. If the future is dropped mid-ladder (a budget cut or a stop), `on_drop` is still armed: its `Drop` records the failure in the fee memo and calls `notify_waiters`. Only after that is `_flight` dropped, releasing the single-flight lock. A caller queued on that lock therefore finds “just failed” and returns the retryable error instead of rerunning the peer ladder. In the other order, the lock would be released first, the queued caller could see no failure recorded, and it would start a duplicate ladder. On success `disarm()` makes the guard a no-op, and the result is stored normally.

A good answer covers:

- locals drop in reverse declaration order; async fn parameters are dropped after the body's locals
- the armed guard records the failure and wakes waiters when the future is dropped mid-ladder
- only then is the single-flight lock released
- a queued caller then sees the recorded failure and does not rerun the ladder
- disarm() on the success path turns the Drop into a no-op

[← Back to the question](14-el-reader.md#q-reader-q6)

<a id="a-reader-q7"></a>

**Q7** · `wait_for_fee` creates `self.fee_stored.notified()`, pins and enables it, and only then calls `settled()`. Why this order?

**Answer: A.** So that a store that lands between the check and the await is not missed: `notify_waiters` stores no permit and only wakes futures already registered

Check-then-wait without prior registration is the classic lost wake-up. Registering first means any notification after the check wakes this waiter.

[← Back to the question](14-el-reader.md#q-reader-q7)

<a id="a-reader-q8"></a>

**Q8** · `tx_scans` is a `std::sync::Mutex` holding a map of `Arc<tokio::sync::Mutex<TxScanState>>`. Why two kinds of mutex?

**Answer: C.** The std lock guards only the map and is held briefly, never across `.await`; each per-transaction tokio lock is held across the slow network scan, so concurrent polls for the same transaction do not duplicate work while different transactions proceed in parallel

Choose the lock by how long it is held: a std mutex for quick in-memory work, a tokio mutex for critical sections that `.await`.

[← Back to the question](14-el-reader.md#q-reader-q8)

<a id="a-reader-q9"></a>

**Q9** · What must `fetch_anchored_window` establish before any header in the window is trusted?

**Answer: B.** Exact length and start number, that the last header's hash equals the anchored hash (optimistic head or finalized block), and that every header is parent-linked to the next

This is the single gate for block, receipt, fee, transaction and block-hash reads. The anchored hash is attested by the light client, and the parent links extend that trust backwards.

[← Back to the question](14-el-reader.md#q-reader-q9)

<a id="a-reader-q10"></a>

**Q10** · `persist_log_index` starts with `self.log_index_write.try_lock()` on a `Mutex<()>`, then serialises the index inside a block that holds `self.log_index`, then writes the bytes. Explain the lock, the `try_lock`, and the block.

**Model answer.** `log_index_write` guards no data: holding it means “a checkpoint write is in progress”, so checkpoints are totally ordered and the newest bytes land last. The documented order is checkpoint lock before index lock, which prevents deadlock. `try_lock` skips instead of waiting, because the other holders are slow (an import merging gigabytes) and whoever holds it is writing a newer snapshot anyway; the clock is left untouched so the next tick tries again. The block takes the index lock only to serialise, and the guard drops at its closing brace, so the slow write and fsync happen without the index lock, and the appender, the walker and getLogs queries are not stalled. `_writing` is a named binding, so it stays held until the function returns.

A good answer covers:

- Mutex&amp;lt;()> is a token that serialises checkpoint writes; it protects no data
- lock order: checkpoint lock before the index lock
- try\_lock skips because the holder writes a newer snapshot and waiting would stall the appender
- the index guard is dropped at the end of the block, before the write and fsync
- \_writing (not \_) keeps the token held to the end of the function

[← Back to the question](14-el-reader.md#q-reader-q10)

<a id="a-reader-q11"></a>

**Q11** · The backfill batch builds its chunk fetches in a plain loop as `Box::pin(async move { … })` into a `Vec<ChunkFetch<'_>>`, instead of `candidates.chunks(n).map(|c| async move { … })`. According to the comment, why?

**Answer: C.** A closure returning a future that borrows the header slices is not general enough over their lifetime for the spawned appender task's `Send` bound; boxing each future into a named `BoxFuture` type avoids that

It is a compiler limitation around closures that return borrowing futures. The boxes cost one allocation per chunk, and nothing runs until `buffered` polls them.

[← Back to the question](14-el-reader.md#q-reader-q11)

<a id="a-reader-q12"></a>

**Q12** · A `first_accepted` test writes `let (_stop, shutdown) = watch::channel(false);`. What would change with `let (_, shutdown) = …`?

**Answer: B.** The sender would be dropped at once, and `first_accepted` treats a dropped sender as a shutdown, so every write would be cut and the call would return `false`

`_` is not a binding, so the value is dropped immediately. `_stop` is a binding that lives to the end of the scope. `wait_for` on a closed channel returns an error, and that `select!` arm then cuts the write.

[← Back to the question](14-el-reader.md#q-reader-q12)

<a id="a-reader-q13"></a>

**Q13** · `BackfillBatchError` implements `From<String>` and `From<&str>`, while `FeeBuildError` deliberately implements neither. What does each choice mean for a bare `?` on a `Result<_, String>`, and why does the difference matter?

**Model answer.** The `?` operator converts the error with `From::from` into the function's error type. In the backfill batch, that conversion builds `BackfillBatchError::peer`, so every bare `?` blames the peer, and the few failures that are the engine's own fault must be built explicitly with `BackfillBatchError::ours`. `FeeBuildError` has no such conversion, so a `?` on a `String` error does not compile: every site must state whether it is the peer's fault (`Peer`) or ours (`Ours`). The difference matters because blame drives peer strikes and eviction: a check that was wrong on our side once struck every snap peer on every fee-history build, and the missing `From` makes that mistake a compile error.

A good answer covers:

- ? converts the error with From::from into the function's error type
- in the backfill, a bare ? therefore blames the peer; our own faults use BackfillBatchError::ours
- FeeBuildError has no From&amp;lt;String>, so a bare ? on a String error fails to compile
- every fee-build site must state Peer or Ours, because blame drives strikes and eviction

[← Back to the question](14-el-reader.md#q-reader-q13)

<a id="a-reader-q14"></a>

**Q14** · Describe the order of `ElReader::stop()` and why each step comes where it does.

**Model answer.** First `cancel_requests()` flips the shutdown watch, so every registered operation and every follower sees the stop. Then the log-index appender, the fee follower and the activity follower are aborted and awaited, so their per-tick strong `Arc`s are gone and none of them starts new work during the drain; the followers also refuse to respawn once the flag is set. Then the fee stats are flushed to the log. Then each live request is upgraded from its `Weak` in the registry and awaited until it has settled. Then the appender slot is aborted once more, without awaiting, in case it was started again meanwhile. Then a final checkpoint is written off the throttle (`respect_throttle = false`), and only after that are the pool and discovery stopped, since the requests and the checkpoint may still need them.

A good answer covers:

- the shutdown flag is set first so operations and followers see it
- producers (appender, fee and activity followers) are aborted and awaited before the drain
- live requests are found by upgrading Weak&amp;lt;Operation> and awaited to settled()
- a final unthrottled checkpoint is written
- the pool and discovery are stopped last

[← Back to the question](14-el-reader.md#q-reader-q14)

## Stop 15 · myotis-net, part 7: integration tests and probes

<a id="a-ntests-q1"></a>

**Q1** · In `live_eth.rs`, `assert!(ok, …)` runs inside a `tokio::spawn`ed task, and the test later does `if let Ok(outcome) = h.await`. A peer serves a broken chain. What happens?

**Answer: C.** The task panics, `h.await` returns `Err(JoinError)`, the `if let` skips it, and the test still passes

Only a panic on the test's own thread fails a test. Tokio catches a task's panic and reports it through the `JoinHandle`. Test targets always unwind, whatever the profile's `panic` setting. `live_discv4`'s census does it right with `probe.await.expect(…)`.

[← Back to the question](15-net-tests.md#q-ntests-q1)

<a id="a-ntests-q2"></a>

**Q2** · Why does `live_eth.rs` write `let key = Arc::clone(&key);` before each `tokio::spawn(async move { … })`, while the census in `live_discv4.rs` spawns `census_one(i, *addr)` with no clone at all?

**Answer: B.** A spawned future must own its data (`'static`). `live_eth`'s tasks share one key, so each gets its own `Arc` handle; `census_one` receives only `Copy` values and creates its key inside

`Arc::clone` copies a pointer and increments a counter; the `async move` block then owns that handle. When all inputs are `Copy` or created inside, the future owns them anyway.

[← Back to the question](15-net-tests.md#q-ntests-q2)

<a id="a-ntests-q3"></a>

**Q3** · `live_dedicated_node.rs` runs `futures::future::join(peer.get_block_bodies(&chunk), peer.get_receipts(&chunk))` with no `Arc` clones. Why is that allowed?

**Answer: A.** Nothing is spawned: `join` polls both futures inside the current task, so they can borrow. `ManagedPeer` methods take `&self`, and shared borrows may overlap

Borrowing is fine when the futures cannot outlive the borrowed data. With an `EthSession` (`&mut self` methods) the two calls could not overlap.

[← Back to the question](15-net-tests.md#q-ntests-q3)

<a id="a-ntests-q4"></a>

**Q4** · What makes the five `el_*_conformance.rs` files a *contract* between the Java and Rust engines, and what happens when a corpus directory is missing?

**Model answer.** A Java test run with `-Dmyotis.el.writeExpected=true` generates the vector files and an `expected.txt` answer sheet into `rust/testdata/el/<layer>/`. The Java test then replays them, and the Rust test replays the same bytes through its own implementation and must reproduce every key and value in `expected.txt`, with no missing and no extra keys (the final `assert_eq!(expected, actual)`). For discv4 this even includes byte-identical signed packets, thanks to deterministic RFC 6979 signatures. If the directory is missing, the Rust test prints a note and returns early, which counts as a pass (Rust has no skipped status), mirroring Java's `assumeTrue`. A present corpus with an empty `expected.txt` fails loudly.

A good answer covers:

- Java generates the vectors and expected.txt (writeExpected flag)
- both engines replay the same bytes
- Rust must reproduce every key and value, and no extra keys (assert\_eq of the two maps)
- a missing corpus returns early, which is a pass (mirrors assumeTrue; there is no skipped status)

[← Back to the question](15-net-tests.md#q-ntests-q4)

<a id="a-ntests-q5"></a>

**Q5** · Why is `el_hostile_frames.rs` a test file of its own, and why are its counters `thread_local!`?

**Answer: B.** A `#[global_allocator]` replaces the allocator for the whole binary, so it needs its own binary; the harness runs tests in parallel threads, and per-thread counters keep their allocations apart

Every integration-test file is its own binary, so the counting allocator affects only these tests. `const`-initialised `Cell` thread-locals cannot allocate or re-enter the allocator when touched.

[← Back to the question](15-net-tests.md#q-ntests-q5)

<a id="a-ntests-q6"></a>

**Q6** · In `snap_probe.rs`, each task starts with `let _permit = sem.acquire_owned().await.unwrap();`. What would change if the line were `let _ = sem.acquire_owned().await.unwrap();`?

**Answer: C.** The permit would be dropped at once, releasing the slot, so the 96-probe cap would no longer limit anything

`_` is not a binding: the value is dropped at the end of the statement. `_permit` is a real binding (the underscore only silences the unused warning), so it lives to the end of the block.

[← Back to the question](15-net-tests.md#q-ntests-q6)

<a id="a-ntests-q7"></a>

**Q7** · In `live_cold_start.rs`, `ColdStart::stop(self)` calls `self.el.stop().await` and then `self.sync.stop().await`, and `ColdStart::start` calls `sync.stop().await` before `panic!` when the EL reader fails. Explain the ownership in both.

**Model answer.** `stop(self)` takes the whole `ColdStart` by value. `ElReader::stop` takes `&self`, so `self.el.stop()` only borrows that field. `SyncHandle::stop` takes `self`, so `self.sync.stop()` moves the `sync` field out of the struct, a partial move, which is allowed because `ColdStart` has no `Drop` impl. The remaining fields are dropped when the method ends. In `start`, the sync handle has already been started; if the reader fails, `sync.stop().await` consumes it and shuts the sync loop down before the panic, so no background sync is left running. Earlier, `cl.clone()` keeps a copy of the config because `SyncHandle::start(cl)` takes the original.

A good answer covers:

- stop(self) owns the struct
- el.stop borrows (&self) while sync.stop consumes the field (self): a partial move
- partial moves out of self are allowed because ColdStart has no Drop impl
- start stops the already-running sync before panicking, so nothing keeps running

[← Back to the question](15-net-tests.md#q-ntests-q7)

<a id="a-ntests-q8"></a>

**Q8** · `config.ws_policy.accept_stale_anchor.store(true, Ordering::Relaxed)` modifies state reached through an `Arc`, which only hands out shared references. How?

**Answer: D.** `AtomicBool::store` takes `&self`: the atomic provides interior mutability, and every clone of the config shares the same flag, so a parked sync loop sees it

This is the same idea as Java's `AtomicBoolean.set` on a shared object. Sharing plus mutation needs an atomic, a mutex or another interior-mutability type.

[← Back to the question](15-net-tests.md#q-ntests-q8)

<a id="a-ntests-q9"></a>

**Q9** · Why does the dead-pins cold-start test point every pin at a `203.0.113.x` address instead of clearing `static_peers`?

**Answer: A.** Pinned peers are exempt from eviction, so dead pins keep pool slots, catch-up fan-out slots and targeted discovery lookups. That was the real #422 situation, and it is harder than having no pins

The test reproduces the harder situation that actually shipped. TEST-NET-3 addresses are never routed, so a dial fails like one to a decommissioned server.

[← Back to the question](15-net-tests.md#q-ntests-q9)

<a id="a-ntests-q10"></a>

**Q10** · In `live_pins_alive.rs`, `outcome` has the type `Option<Result<Result<Vec<u8>, RequestError>, Elapsed>>`. Explain the inner shapes, and why the retry loop uses `match &outcome` while the code after the loop uses `outcome.expect(…)`.

**Model answer.** The outer `Result` comes from `tokio::time::timeout`: `Err(Elapsed)` means no answer within `PIN_TIMEOUT`. The inner `Result` is the request itself: `Ok(Ok(raw))` means the server answered, possibly with an error result code in byte 0, and `Ok(Err(e))` means the dial or stream failed. The `Option` is `None` only before the first attempt. Inside the loop the code only needs to *look* at the value (is byte 0 ResourceUnavailable? then retry), and the value must survive for the next iteration and after the loop, so it borrows with `&outcome`. After the loop, `outcome.expect(…)` takes ownership of the `Option` and moves the inner `Result` into the final `match`, which can then bind `raw` by value.

A good answer covers:

- outer Result = timeout (Err means no answer in time)
- inner Result = the request (Ok = answered, possibly with an error code; Err = dial or stream failure)
- the loop borrows because the value must survive iterations and the loop
- after the loop expect consumes the Option so the final match owns the bytes

[← Back to the question](15-net-tests.md#q-ntests-q10)

<a id="a-ntests-q11"></a>

**Q11** · `live_pins_alive` runs the anchor period's update through the full production processor, BLS aggregate included, but checks the *current* period's update only for its period, wire shape and 2/3 participation. Why not verify the current update's BLS aggregate too?

**Answer: C.** Verifying it needs that period's sync committee, which means walking every period between the anchor and now; the anchor-period ask has already verified the server's data in full

The processor starts from the bootstrap's committee, which signs only the anchor's period (and hands over to the next). The current-period ask exists to show the server still produces the head's updates in the head's format.

[← Back to the question](15-net-tests.md#q-ntests-q11)

<a id="a-ntests-q12"></a>

**Q12** · The old-anchor test checks `wall_period > anchor_period && wall_period - anchor_period > bound`. The release gate runs it with `cargo test --release`. What could happen without the first comparison if the anchor were newer than the wall clock?

**Answer: B.** In release builds overflow checks are off, so the `u64` subtraction would wrap to a huge number and the bound check would pass for an anchor that proves nothing

Debug builds panic on integer overflow; release builds wrap. `&&` short-circuits, so the subtraction only runs when it is safe. The message uses `saturating_sub` for the same reason.

[← Back to the question](15-net-tests.md#q-ntests-q12)

<a id="a-ntests-q13"></a>

**Q13** · In `snap_probe.rs`, `probe_peer` passes `&mut r` to `probe_inner` inside `tokio::time::timeout(…)`, and after a timeout it still reads and returns `r`. Why is that allowed, and what does it buy the census?

**Model answer.** `r` is a local owned by `probe_peer`. The future returned by `probe_inner` holds a mutable borrow of it. When the 45 s timeout fires, `timeout` drops that future, which cancels the probe at its current `.await` and ends the borrow. After the `.await` on the timeout, no borrow is alive, so `probe_peer` may set `r.verdict = "timeout"` (if empty) and return `r` by value. Everything `probe_inner` wrote before the cancellation, such as `stage`, `client` and `network_id`, is still in `r`, so the summary can show how far each timed-out peer got.

A good answer covers:

- r is owned by probe\_peer; probe\_inner only borrows it mutably
- on timeout the inner future is dropped, which ends the borrow
- after the timeout r can be read and returned by value
- partial progress (stage, client, network id) survives into the report

[← Back to the question](15-net-tests.md#q-ntests-q13)

## Stop 16 · myotis-engine: the boundary

<a id="a-engine-q1"></a>

**Q1** · In `spin_up`, the config is copied out with `Arc::clone(c)` inside `let (config, read_stats) = { … };` before `block_on`. What is the block for?

**Answer: C.** The mutex guard lives only inside the block and is dropped at its `}`, so the lock is released before the slow start. Holding it across `block_on` would stall every other FFI call and risk deadlock

A guard unlocks when it is dropped, and a block is the tool for choosing when that happens. Only reference-count increments leave the locked region.

[← Back to the question](16-engine.md#q-engine-q1)

<a id="a-engine-q2"></a>

**Q2** · Why does `pause` use `map.remove(&handle)` and then re-insert, instead of `map.get(&handle)`?

**Answer: A.** `SyncHandle::stop(self)` consumes the handle, so `pause` must *own* it. `get` only lends a reference. Entries that aren't `Running` are put back unchanged

Moving a value out of a collection is how Rust expresses taking it over. `remove` returns the owned value.

[← Back to the question](16-engine.md#q-engine-q2)

<a id="a-engine-q3"></a>

**Q3** · `start_usage_ticker(engine: &'static EngineState)` calls `engine.rt.spawn(async move { … tick_all_ledgers(engine) … })`. What would happen if the parameter were a plain `&EngineState`?

**Answer: B.** It would not compile: `spawn` requires a `'static` future, because the task may outlive the caller, and a future holding a non-`'static` reference is not `'static`

`async move` moves the reference, not the struct. The reference is allowed into the task only because it is `'static`, which it is since it points into `static ENGINE`. `Runtime::spawn` works from any thread.

[← Back to the question](16-engine.md#q-engine-q3)

<a id="a-engine-q4"></a>

**Q4** · Walk through `host::request_account_json(handle, address_hex, block)` from the incoming strings to the returned JSON. Mention where the lock is held, what is cloned, how the block selector is handled, how the async code runs, and why the `async` block may borrow local variables.

**Model answer.** First the address and the block selector are parsed without panicking; a bad address returns `{"error"}`, a selector no retry can serve (such as `safe` or `earliest`) returns the permanent `-32602` envelope, both before the handle is looked up. Then `engine()` fetches the singleton. `snapshot_reader` takes the handles mutex, checks the entry is `Running` with a reader, clones the `Arc<ElReader>` (a reference-count increment) plus two period numbers, and the guard is dropped when it returns. `read_anchor` checks a numbered block against the current head window and maps the selector to `Head` or `Finalized`, or returns refusal JSON. The foreign calling thread then blocks in `engine.rt.block_on(reader.request(async { reader.get_account_pinned(anchor, address, pin).await }))`; `request` adds the 90 s budget and cancellation. The async block can borrow `reader` and `address` because `block_on` does not return until the future completes, so there is no `'static` requirement, unlike `spawn`. Finally `Ok` becomes `eljson::account_json` (a failed verification is still an `Ok` with `failReason`) and `Err` becomes `error_json`.

A good answer covers:

- address and block selector parsed first; bad input answered before the handle lookup, unservable selector as -32602
- lock held only inside snapshot\_reader; Arc&amp;lt;ElReader> cloned out, guard dropped on return
- read\_anchor applies or refuses the selector against the current head
- caller's thread blocks in rt.block\_on, wrapped in reader.request's budget; borrowing is fine because block\_on waits (no 'static)
- Result becomes account\_json or error\_json; a verification failure is inside the result

[← Back to the question](16-engine.md#q-engine-q4)

<a id="a-engine-q5"></a>

**Q5** · An iOS caller receives a `char*` from `myotis_status_json`. Who frees it, and how?

**Answer: D.** The caller, by passing it to `myotis_string_free`, which rebuilds the `CString` with `from_raw` and drops it. It came from Rust's allocator via `into_raw`, so `free(3)` would be undefined behavior

`into_raw` and `from_raw` are a matched pair: ownership goes out to C and comes back only through the engine's own free function. `RustEngine.kt` does this in a `finally` right after copying the string.

[← Back to the question](16-engine.md#q-engine-q5)

<a id="a-engine-q6"></a>

**Q6** · `myotis-rpcd` calls `myotis_engine::ffi::create_handle("gnosis".into(), dir)`, while `myotis-node` calls `myotis_engine::capi::myotis_create(ptr, ptr)` inside `unsafe`. Explain why both work, why neither can call `myotis_engine::host::create`, and what each route costs.

**Model answer.** Both crates link `myotis-engine` as an rlib. `#[uniffi::export]` leaves `create_handle` as an ordinary `pub fn` taking owned `String`s and only adds a C-callable twin, so rpcd calls it like any Rust function with no FFI and no `unsafe`. `capi::myotis_create` is a `pub unsafe extern "C" fn`; calling it from Rust is allowed but needs `unsafe` and C strings (`CString`), and each returned `*mut c_char` must go back through `myotis_string_free`. Neither can reach `host` because `lib.rs` declares `mod host;` without `pub`, so it is private to the crate. The ffi route costs a `String` allocation per argument (the export takes ownership); the capi route costs a C-string conversion on the way in and a copy plus explicit free on the way out.

A good answer covers:

- \#\[uniffi::export\] keeps a normal pub fn, so it is callable by Rust path
- capi functions are unsafe extern "C" and need unsafe, C strings and myotis\_string\_free
- host is private (mod host without pub) so other crates cannot call it
- ffi takes owned Strings; capi borrows C strings and returns caller-owned pointers

[← Back to the question](16-engine.md#q-engine-q6)

<a id="a-engine-q7"></a>

**Q7** · `parse_state_overrides` returns `Result<StateOverrides, String>`, yet contains `val.as_str().ok_or("override 'code' must be a hex string")?`, whose error is a `&str`. Why does this compile?

**Answer: A.** `?` calls `From::from` on the error before returning it, and `String` implements `From<&str>`, so the literal is copied into a `String` on that path

The conversion in `?` is what lets one function mix error sources, like a checked exception being wrapped automatically. It happens only when the error actually occurs.

[← Back to the question](16-engine.md#q-engine-q7)

<a id="a-engine-q8"></a>

**Q8** · In `create`, what would change if `let Ok(_serial) = engine.create_lock.lock() else { … };` were written as `let Ok(_) = engine.create_lock.lock() else { … };`?

**Answer: C.** With `_` nothing is bound, so the guard is dropped at the end of the statement and the lock is released immediately. The rest of `create` would run unserialized

`_name` binds (and silences the unused warning); `_` does not bind at all. For RAII guards the difference is the whole point. The same applies to `let _guard = engine.rt.enter();`.

[← Back to the question](16-engine.md#q-engine-q8)

<a id="a-engine-q9"></a>

**Q9** · `set_activity_watch_json` calls `let _guard = engine.rt.enter();` before `reader.set_activity_watch(…)`, while `spin_up` uses `engine.rt.block_on(async { SyncHandle::start(cfg) })`. What does each do, and why is `enter` enough in the first case?

**Model answer.** Both exist because the called code may use `tokio::spawn`, which needs a current runtime on the calling thread, and host threads (JVM, iOS, Node) have none. `block_on` runs a future to completion on the calling thread inside the runtime's context, blocking until it finishes. `rt.enter()` only sets the runtime as this thread's current one and returns a guard; while the guard lives, `tokio::spawn` and similar calls find the runtime. `set_activity_watch` is a plain (non-async) function that may spawn the follower task and has nothing to await, so entering the context is enough and cheaper. The guard must be named (`_guard`), because `_` would drop it at once and leave the context before the call.

A good answer covers:

- tokio::spawn needs a current runtime; foreign host threads have none
- block\_on drives a future to completion and blocks the thread
- enter() only installs the runtime context for the guard's lifetime
- set\_activity\_watch is not async and has nothing to await, so enter suffices
- the guard must be bound to a name, not \_, or the context ends immediately

[← Back to the question](16-engine.md#q-engine-q9)

<a id="a-engine-q10"></a>

**Q10** · A wallet calls `eth_call` with block `0x10` while the verified head is 20,000,000. What does `check_call_block` make of it, and why that code?

**Answer: D.** `Behind`: the permanent `{"error","code":-32602}`, because the number is more than 64 blocks below the head, head state would answer a different question, and the head never moves back that far

Only numbers in \[head − 64, head + 16\] run, and they run against head state. Behind is permanent; Ahead and NoHead are retryable, so a merely lagging node is never told to stop being asked.

[← Back to the question](16-engine.md#q-engine-q10)

<a id="a-engine-q11"></a>

**Q11** · In `UsageLedger::tick_on`, the comment insists that `self.meter.snapshot()` is taken *after* `self.state.lock()`. Describe the bug that would appear if the snapshot were taken before the lock, with two threads (the minute ticker and a status read).

**Model answer.** Each tick computes the growth as `now - seen` and then stores `seen = now`. Suppose thread A reads the meter (value 100), then thread B reads it (value 120), B takes the lock first, adds 120 − seen and sets `seen = 120`; then A takes the lock and sets `seen` back to 100 (its own `now`), after adding `100 - 120`, which `saturating_sub` turns into 0. The next tick then measures from 100 again, so the 20 bytes between 100 and 120 are counted twice. Reading the meter inside the critical section means the snapshots are applied in the order they were taken, so `seen` never steps back.

A good answer covers:

- growth is now - seen, then seen = now
- two snapshots taken outside the lock can be applied in the opposite order
- the older snapshot overwrites seen, so seen steps back
- bytes between the two snapshots are then counted twice
- taking the snapshot under the lock orders the ticks

[← Back to the question](16-engine.md#q-engine-q11)

<a id="a-engine-q12"></a>

**Q12** · How does `header_pins_the_current_abi_version` in `capi.rs` notice that someone bumped `ABI_VERSION` but forgot the C header?

**Answer: B.** `include_str!` embeds `rust/include/myotis_engine.h` at compile time; the test extracts the single column-0 `#define MYOTIS_ABI_VERSION` and asserts it equals `crate::ABI_VERSION`. Because the header is a compile input, an edit to it alone also reruns the test

The header is hand-maintained, and iOS reads its expected ABI from it, so a mismatch would make iOS refuse a good engine or accept a stale one. `RustEngineNative.EXPECTED_ABI_VERSION` on the JVM is still a hand-kept mirror.

[← Back to the question](16-engine.md#q-engine-q12)

<a id="a-engine-q13"></a>

**Q13** · The `eth_getLogs` debounce declares `static RECENT_REFUSALS: Mutex<Option<HashMap<u64, Instant>>> = Mutex::new(None);`. Why the `Option`?

**Answer: A.** A `static` initializer must be a constant expression; `Mutex::new` is `const` but `HashMap::new` is not, so the map starts as `None` and is created on first use under the lock

`get_or_insert_with(HashMap::new)` builds it lazily. `OnceLock` would also work; this form keeps creation and updates under one lock.

[← Back to the question](16-engine.md#q-engine-q13)

## Stop 17 · Deep dive: how UniFFI connects Kotlin to Rust

<a id="a-uniffi-q1"></a>

**Q1** · Kotlin receives the `RustBuffer` holding the JSON result of `requestAccountJson`. Who frees that memory, and how?

**Answer: B.** `FfiConverterString.lift` copies the bytes into a `ByteArray` and, in `finally`, calls `ffi_myotis_engine_rustbuffer_free`; Rust rebuilds the `Vec` with `from_raw_parts` and drops it

The buffer came from Rust's allocator (the `String`'s own `Vec`), so only Rust may free it. Kotlin decides when, by calling back into Rust. The GC frees only the small JVM object, not the native bytes.

[← Back to the question](17-uniffi.md#q-uniffi-q1)

<a id="a-uniffi-q2"></a>

**Q2** · Which of these edits to `ffi.rs` does NOT require running `./gradlew uniffiGenerateKotlin`?

**Answer: C.** Changing the `match` inside the body of `get_raw_transaction_by_block_json`

The checksum covers the metadata: module path, name, parameter names and types, return type and doc comment. A function's body is not part of it.

[← Back to the question](17-uniffi.md#q-uniffi-q2)

<a id="a-uniffi-q3"></a>

**Q3** · A bug makes `host::request_account_json` panic in the shipped Android app. What happens?

**Answer: A.** The process aborts. The release profile sets `panic = "abort"`, so no unwinding happens and `catch_unwind` never gets control

The `catch_unwind` answer is what UniFFI does in an unwinding build, such as the dev profile. Myotis ships release builds with `panic = "abort"`, which is why the engine is written to be panic-free and reports failures in its JSON.

[← Back to the question](17-uniffi.md#q-uniffi-q3)

<a id="a-uniffi-q4"></a>

**Q4** · Why are UniFFI's conversion traits generic over a tag type (`FfiConverter<UT>`), with `UniFfiTag` defined in each crate by `setup_scaffolding!`?

**Answer: D.** Because of the orphan rule: a crate may implement a foreign trait for a foreign type only if a local type appears in the impl. `FfiConverter<crate::UniFfiTag>` contains a local type, so each consumer crate can write impls for types it does not own

Built-in types are covered by blanket impls in `uniffi_core` (`impl<UT> FfiConverter<UT> for String`), and the generated code always asks for `<T as Lift<crate::UniFfiTag>>`.

[← Back to the question](17-uniffi.md#q-uniffi-q4)

<a id="a-uniffi-q5"></a>

**Q5** · A JSON-RPC worker thread calls `RustChainHandle.accountVerified`. On which thread does the Rust code of `request_account_json` run?

**Answer: C.** On the calling JVM thread itself. JNA calls the C function directly, and `host.rs` blocks that thread in `rt.block_on` while tokio's worker threads drive the spawned network tasks

There is no thread switch at the boundary. This is why the header and the docs say verified reads block for up to about 90 seconds and must be called off the UI thread.

[← Back to the question](17-uniffi.md#q-uniffi-q5)

<a id="a-uniffi-q6"></a>

**Q6** · The committed Kotlin compares checksums as `(lib.uniffi_myotis_engine_checksum_func_…() and 0xFFFF) != N`. Why the mask?

**Answer: A.** The Rust function returns a `u16`, but the bindings read it as a 32-bit `Int`. The x86-64 calling conventions do not promise that the upper 16 bits of the return register are zero, so an unmasked compare can fail on a correct library. The root Gradle task adds the mask after generation

UniFFI 0.32's template compares unmasked. A Linux debug build returned `0x5DB5166E` for checksum `0x166E`, and the Windows build fell back to the Java engine. The Gradle task also fails if the number of rewritten comparisons does not match the declared functions.

[← Back to the question](17-uniffi.md#q-uniffi-q6)

<a id="a-uniffi-q7"></a>

**Q7** · Trace the memory of the `address` argument from the Kotlin `String` in `requestAccountJson` to the moment it is freed. Name who allocates, who writes, how ownership moves, and where the bytes are dropped.

**Model answer.** `FfiConverterString.lower` encodes the UTF-16 string to UTF-8 (throwing on malformed input), then calls `RustBuffer.alloc`, a native call to `ffi_myotis_engine_rustbuffer_alloc`. Rust allocates `vec![0u8; n]` and turns it into a `RustBuffer` with `RustBuffer::from_vec`, which wraps the `Vec` in `ManuallyDrop` so it is not freed. Kotlin copies the bytes into that native memory. The buffer is then passed by value to `uniffi_myotis_engine_fn_func_request_account_json`, and from that point it belongs to Rust; Kotlin never frees it. The scaffolding's lift closure calls `String::try_lift`: `destroy_into_vec` rebuilds the `Vec` with `Vec::from_raw_parts`, and `from_utf8_unchecked` relabels it as a `String`, with no copy. The `String` is moved into `ffi::request_account_json`, which lends `&address` to `host`. When the ffi function returns, the `String` goes out of scope and its buffer is freed by Rust's allocator.

A good answer covers:

- Rust allocates the buffer (rustbuffer\_alloc), Kotlin only fills it with UTF-8 bytes
- from\_vec uses ManuallyDrop so Rust stops tracking the Vec while Kotlin holds it
- passing the RustBuffer by value transfers ownership to Rust; Kotlin never frees argument buffers
- try\_lift rebuilds the Vec with from\_raw\_parts and makes a String without copying
- the String is dropped, and the memory freed, when ffi::request\_account\_json returns

[← Back to the question](17-uniffi.md#q-uniffi-q7)

<a id="a-uniffi-q8"></a>

**Q8** · Describe everything `#[uniffi::export]` adds to the crate for one function such as `request_account_json`, and what each item is for.

**Model answer.** It keeps the function and adds three items. First, a `#[no_mangle] pub extern "C" fn uniffi_myotis_engine_fn_func_request_account_json` whose parameters are the FFI types of the Rust parameters (`i64`, `RustBuffer`, `RustBuffer`) plus `&mut RustCallStatus`. Its body builds a `move` closure that lifts each argument with `Lift::try_lift` and reports which argument failed, then runs `uniffi::rust_call`, which wraps the call in `catch_unwind`, calls the real function, and lowers the result with `LowerReturn::lower_return`; failures are written into the status. Second, a metadata constant built with `const fn` calls (module path, name, async flag, arguments with names and types, return type, doc comment) and a `#[no_mangle]` static `UNIFFI_META_MYOTIS_ENGINE_FUNC_REQUEST_ACCOUNT_JSON` holding those bytes, which `uniffi-bindgen` reads from the compiled library. Third, `uniffi_myotis_engine_checksum_func_request_account_json() -> u16`, returning a checksum of the metadata computed at compile time, which the Kotlin bindings compare at load.

A good answer covers:

- an extern "C" #\[no\_mangle\] scaffolding function with FFI-typed parameters plus &mut RustCallStatus
- a lift closure that converts each argument and names the one that failed
- rust\_call with catch\_unwind around the call, and lower\_return for the result
- a metadata const plus a no\_mangle UNIFFI\_META\_ static that the bindgen reads out of the library
- a checksum function returning a compile-time u16 over the metadata bytes

[← Back to the question](17-uniffi.md#q-uniffi-q8)

<a id="a-uniffi-q9"></a>

**Q9** · You add a parameter to an exported function in `ffi.rs`, update `RustEngineNative`'s call, and forget `uniffiGenerateKotlin`. What happens in a desktop build and in an Android build, and which mechanisms notice?

**Model answer.** In the desktop build the committed Kotlin is not regenerated, so its wrapper still has the old parameter list, and the updated Java call does not compile against it. If you had not updated the Java call, everything would compile, the fresh library would load, and at `uniffiEnsureInitialized()` the checksum for that one function would differ, so `uniffiCheckApiChecksums` throws inside `IntegrityCheckingUniffiLib`'s initializer; `RustEngineNative.load()` catches the `ExceptionInInitializerError`, logs "failed UniFFI validation" and reports unavailable, and the selector serves the Java engine. In an Android build, `:myotis-engine`'s `preBuild` runs `uniffiGenerateKotlin` automatically, so the bindings are regenerated; the build then works with the updated Java call, but leaves a modified `myotis_engine.kt` in the working tree. CI's regenerate-and-diff step in the APK workflow fails if the committed file is stale.

A good answer covers:

- desktop/JVM builds never regenerate the committed bindings automatically
- a stale wrapper either fails Java compilation (signature mismatch) or fails the load-time checksum check
- the checksum failure surfaces as ExceptionInInitializerError, caught in RustEngineNative.load, and isAvailable() becomes false (Java engine fallback)
- Android builds regenerate in preBuild, so the bindings match the library there
- CI's regenerate-and-diff catches a stale committed file

[← Back to the question](17-uniffi.md#q-uniffi-q9)

<a id="a-uniffi-q10"></a>

**Q10** · UniFFI could pass typed records. Why does the Myotis engine pass compound values as JSON strings instead, and what does that cost?

**Model answer.** The switch from hand-JNI to UniFFI was a transport swap only: the functions mirror the old natives one to one, and the JSON shapes were already defined, parsed by Java and pinned by golden tests on both sides. The same JSON is what the iOS C ABI and the Node addon return as `char*`, so `eljson.rs` serializes once for all hosts and one set of golden files covers them. With only integers and strings crossing, the UniFFI signatures and checksums rarely change; new result fields are payload extensions with no signature change and no regeneration. The costs: results are serialized to text and parsed again; field names and types are no longer checked by a compiler across the boundary, only by golden tests and defensive parsing in `RustChainHandle`; and payload changes must be tracked by bumping `ABI_VERSION` by hand. The typed-record mapping in docs 05 remains the documented alternative.

A good answer covers:

- a transport swap from hand-JNI: shapes already existed and were pinned by golden tests on both sides
- the same JSON serves the C ABI (iOS, Node), which can only carry char\*
- the UniFFI surface stays primitives and strings, so checksums and bindings rarely change; fields can be added without a signature change
- cost: double serialization and parsing
- cost: no compile-time type checking across the boundary; golden tests, defensive parsing and manual ABI\_VERSION bumps replace it

[← Back to the question](17-uniffi.md#q-uniffi-q10)

<a id="a-uniffi-q11"></a>

**Q11** · `<String as FfiConverter>::try_lift` uses `String::from_utf8_unchecked`. What makes that sound?

**Answer: D.** The generated Kotlin encodes every string with a UTF-8 encoder set to `CodingErrorAction.REPORT`, so it throws before sending malformed data. The traits are `unsafe trait` precisely because their soundness depends on the foreign code matching them

Rust's safe `str` methods assume valid UTF-8, so an invalid `String` is undefined behavior. The guarantee comes from the other side, which is why `RustEngineNative`'s `nz()` must sanitize malformed UTF-16 instead of letting the encoder throw.

[← Back to the question](17-uniffi.md#q-uniffi-q11)

<a id="a-uniffi-q12"></a>

**Q12** · How does the `holder: Option<String>` argument of `get_storage_proof_json` cross the boundary?

**Answer: C.** Serialized into one `RustBuffer`: a tag byte (0 for `None`, 1 for `Some`), then a big-endian `i32` byte length and the UTF-8 bytes. Rust reads it with `try_read`, which validates the UTF-8 and copies

Only a bare `String` gets the zero-copy treatment where the buffer's `len` is the string length. Anything compound is written with `write` and read with `try_read`, and leftover bytes are rejected.

[← Back to the question](17-uniffi.md#q-uniffi-q12)

<a id="a-uniffi-q13"></a>

**Q13** · `RustEngineNative.load()` calls `Myotis_engineKt.uniffiEnsureInitialized()` before `engineInit()`. What would change if that line were removed?

**Answer: B.** The checksums and the contract version would never be checked. A wrapper call touches only the `UniffiLib` object, whose `init` registers the functions without checks; the checks live in the `init` of `IntegrityCheckingUniffiLib`, which runs only when that object is referenced

A Kotlin `object` is initialized on first use. `uniffiEnsureInitialized()` exists to force the integrity object's initialization; without it, a reshaped symbol would be called with the wrong arguments instead of failing loudly at load.

[← Back to the question](17-uniffi.md#q-uniffi-q13)

<a id="a-uniffi-q14"></a>

**Q14** · List what an Android build of `:myotis-engine` does, before compiling anything, so that the AAR can run the Rust engine through UniFFI, and say what would break on a device if each step were missing.

**Model answer.** `preBuild` depends on: `extractJnaAndroidNatives`, which copies `libjnidispatch.so` for each shipped ABI out of `jna-<v>.aar` into the jniLibs (without it JNA cannot dispatch any native call, so the Rust engine cannot load); `requireAndroidRustEngine`, which fails fast if the Android Rust toolchain is missing unless `-PskipRustEngine` is set; `uniffiGenerateKotlin`, which rebuilds the host library and regenerates the committed bindings from it (stale bindings would fail the checksum check and fall back to the Java engine, or now fail Java compilation); `cargoNdkAndroid`, which cross-compiles `libmyotis_engine.so` for arm64-v8a and x86\_64 into `src/androidMain/jniLibs` (without it there is no library to load); and `verifyAndroidJniLibs`, which checks that each `.so` is an ELF file containing every `uniffi_myotis_engine_*`/`ffi_myotis_engine_*` symbol the bindings declare (a missing symbol would make `Native.register` throw on the device). The JNA jar version is pinned with `strictly` because JNA refuses a jar and dispatcher of different versions.

A good answer covers:

- extracts libjnidispatch.so from the JNA aar into jniLibs; without it JNA cannot call anything
- regenerates the bindings with uniffiGenerateKotlin, from the host library
- cross-compiles libmyotis\_engine.so per ABI with cargoNdkAndroid
- verifyAndroidJniLibs checks the .so files contain every symbol the bindings declare (otherwise Native.register fails on device)
- a failure on device means isAvailable() is false and a fallback to the Java engine (or no engine below API 33)

[← Back to the question](17-uniffi.md#q-uniffi-q14)

## Stop 18 · myotis-node: the Node.js addon

<a id="a-node-q1"></a>

**Q1** · `request_account_json` returns a Promise and passes `move || …` to `scheduler::submit`. Why must that closure be `move`, `Send` and `'static`?

**Answer: C.** It runs later on one of the addon's worker threads, after the JS call has returned, so it must own everything it uses and be allowed to cross threads

The same rule applies to `std::thread::spawn` and `tokio::spawn`: work that may outlive the caller and change threads must own its data.

[← Back to the question](18-node.md#q-node-q1)

<a id="a-node-q2"></a>

**Q2** · Why does `create` bind `let (Ok(n), Ok(d)) = (c_arg(&network), c_arg(&data_dir))` before calling `myotis_create(n.as_ptr(), d.as_ptr())`?

**Answer: A.** `as_ptr()` only borrows the `CString`'s buffer, and the compiler doesn't tie the raw pointer to it. A pointer taken from a temporary `CString` in one statement dangles in the next, because the temporary is freed at the end of its statement

Raw pointers escape the borrow checker, so keeping the owner alive is on you.

[← Back to the question](18-node.md#q-node-q2)

<a id="a-node-q3"></a>

**Q3** · The admission queue holds jobs for handles `[1, 1, 2]` (in that order) and handle 1 already has a running job. What does `take_ready()` return, and why does its body compile even though it reads `self.queued` and `self.active` and then mutates `self.queued`?

**Model answer.** It returns the job for handle 2: `position` skips every queued job whose handle is in `active`, so both jobs for handle 1 are passed over; handle 2 is then inserted into `active` and stays there until `finish(2)`. It compiles because the shared borrows taken by `iter().position(…)` (of `queued` and, inside the closure, of `active`) end when `position` returns a plain `usize`; nothing borrowed survives into the next statement, so `self.queued.remove(index)` may borrow mutably. The `?` operators return `None` when no job is ready or the index is gone.

A good answer covers:

- returns handle 2's job; handle 1's jobs are overtaken while it is busy
- handle 2 is marked active until finish(2)
- the shared borrows end when position returns a usize
- so the mutable remove on the next line is allowed
- ? returns None instead of panicking

[← Back to the question](18-node.md#q-node-q3)

<a id="a-node-q4"></a>

**Q4** · Why does `Job` store the Promise handle as `deferred: usize` instead of a raw pointer?

**Answer: D.** A `Job` moves to a worker thread, so all its fields must be `Send`. Raw pointers aren't `Send`, integers are; the value is cast back to a pointer where Node-API is called

It's a deliberate escape hatch: the compiler can no longer help, so the invariant (only the JS thread ever uses it as a pointer) is enforced by design.

[← Back to the question](18-node.md#q-node-q4)

<a id="a-node-q5"></a>

**Q5** · In the worker loop, what does `inner = self.changed.wait(inner)` do?

**Answer: A.** Takes the mutex guard, releases the lock while the thread sleeps, and returns a guard with the lock re-acquired when notified. It's Java's `wait()`, but the guard hand-off makes it impossible to touch `inner` without the lock

Rust encodes "you hold the lock" as owning the guard value.

[← Back to the question](18-node.md#q-node-q5)

<a id="a-node-q6"></a>

**Q6** · Why does the worker call `std::mem::replace(&mut job.run, Box::new(String::new))` instead of simply calling `(job.run)()`?

**Model answer.** `job.run` is a `Box<dyn FnOnce() -> String + Send>`. An `FnOnce` is called by value: calling it moves the closure out of `job`. Rust does not let you move a field out of a struct you still need afterwards (a struct with a hole), and `job` is still needed, because `self.finish(job, value)` takes it to find its id, handle and deferred. `mem::replace` moves the closure out and leaves a valid placeholder in the field; `Box::new(String::new)` type-checks because `String::new` is itself an `FnOnce() -> String`. The placeholder is never called and is dropped with the job.

A good answer covers:

- FnOnce is called by value, which moves the closure
- job is still needed afterwards for finish
- a field can't be moved out of a struct that is used later
- mem::replace swaps in a valid placeholder (String::new is an FnOnce() -> String)

[← Back to the question](18-node.md#q-node-q6)

<a id="a-node-q7"></a>

**Q7** · Explain how a request's 90-second deadline and cancellation flag, created in `scheduler::submit` on the JS thread, reach the engine's network code in `myotis-net`.

**Model answer.** `submit` creates a `Submission { deadline, cancelled: Arc<AtomicBool> }`, stores a clone of the same `Arc` in the environment's request table (so `cancel_handle` can set it), and puts the submission into the `Job`. A worker thread takes the job and calls `submitted(submission, run)`, which stores the submission in a `myotis-net` thread-local (restored afterwards by a drop guard) and runs the closure. The closure checks its arguments, then calls the C ABI and `host.rs`, which calls `rt.block_on(…)`. `block_on` polls the request future on that same worker thread, so `Operation::new` can read the thread-local, take the earlier of its own budget and Node's deadline, and `Operation::check` observes the shared cancellation flag. A job that was already cancelled or expired while queued never calls the engine at all.

A good answer covers:

- Submission holds the deadline and a shared Arc&amp;lt;AtomicBool>, also kept in the request table
- the worker calls submitted(), which sets a thread-local and restores it with a drop guard
- capi → host → rt.block\_on runs the future on the same thread, so the thread-local is visible
- Operation::new takes the earlier deadline; Operation::check reads the cancellation flag
- cancelled or expired queued jobs never reach the engine

[← Back to the question](18-node.md#q-node-q7)

<a id="a-node-q8"></a>

**Q8** · How does a worker's result string get to the JS thread?

**Answer: C.** `finish` boxes a `Completion`, turns it into a raw pointer with `Box::into_raw`, and queues it with `napi_call_threadsafe_function` (non-blocking). On the JS thread, `complete` takes ownership back with `Box::from_raw` and resolves the Promise

Ownership leaves Rust through `into_raw` and comes back through `from_raw`, exactly once.

[← Back to the question](18-node.md#q-node-q8)

<a id="a-node-q9"></a>

**Q9** · A JS caller passes the address `"0x1234"` to `requestAccountJson` on a handle it owns. What happens?

**Answer: D.** The Promise resolves to `{"error":"invalid address (expected 20-byte hex)","code":-32602}`, produced on a worker before the engine is called

Since #503 the binding makes the router's check itself, inside the submitted closure, and refuses with the permanent -32602 instead of the engine's retryable-looking shape.

[← Back to the question](18-node.md#q-node-q9)

<a id="a-node-q10"></a>

**Q10** · In `fee_history_json`, explain the type of `reward_percentiles(&percentiles).map(|p| c_arg(&p))` and what each of the three match arms means.

**Model answer.** `reward_percentiles` returns `Result<String, String>`: `Ok` is the re-serialised list to hand the engine, `Err` a finished -32602 refusal. `.map` applies `c_arg` only to the `Ok` value, giving `Result<Result<CString, String>, String>`. `Ok(Ok(p))` binds the C string that is passed to the engine (it lives until the closure ends). `Ok(Err(_))` means the list contained a NUL byte and returns `NUL_INVALID_PARAMS`. `Err(refusal)` returns the validator's refusal unchanged.

A good answer covers:

- outer Result is the validator's: Ok = list for the engine, Err = refusal JSON
- map applies c\_arg only to Ok, nesting a second Result
- Ok(Ok(p)) binds the CString, which stays alive for the engine call
- Ok(Err(\_)) is the NUL-byte case → NUL\_INVALID\_PARAMS
- Err(refusal) returns the refusal as the Promise's value

[← Back to the question](18-node.md#q-node-q10)

<a id="a-node-q11"></a>

**Q11** · Why does `getBlockByNumberJson` refuse the selector `"23500000"` instead of passing it on?

**Answer: A.** The engine reads a bare-digit selector as hex, so a JS caller who meant decimal would get a block far past the head, or silently the wrong block

Applied or refused, never silently misread: the routers on the other hosts refuse bare digits for the same reason.

[← Back to the question](18-node.md#q-node-q11)

<a id="a-node-q12"></a>

**Q12** · `pause` calls `scheduler::cancel_handle(env, handle, false)?` before `myotis_pause`. What does `cancel_handle` do, and why does it block the JS thread?

**Model answer.** It locks the environment state, returns `owned: false` at once if the handle isn't this environment's, and otherwise sets the cancellation flag of every request of that handle, removes the handle's queued jobs (their Promises resolve with "request cancelled" through the TSFN), notifies the workers, and then waits on the `Condvar` until `queue.is_active(handle)` is false, i.e. until the running job has returned. It blocks because pause/stop are synchronous: the engine must not tear the reader down while a worker is inside it. Uninterruptible native work can make that wait long.

A good answer covers:

- unknown handle → owned: false, no engine call
- sets the AtomicBool of the handle's requests
- removes queued jobs, whose Promises resolve with "request cancelled"
- waits on the Condvar until the handle's active job finishes
- synchronous on the JS thread, so it can block the event loop

[← Back to the question](18-node.md#q-node-q12)

## Stop 19 · myotis-rpcd: a JSON-RPC daemon in Rust

<a id="a-rpcd-q1"></a>

**Q1** · Why does myotis-rpcd answer `GET /` and `eth_chainId` on separate intake threads instead of sending every request to the read workers?

**Answer: B.** A read may be held for up to `--ready-wait` waiting for a verified head; if every worker is held, a health check queued behind them would time out. Non-blocking methods need no engine readiness, so intake answers them at once

`Body::blocking` classifies the body; only bodies naming a gated method go to the read pool.

[← Back to the question](19-rpcd.md#q-rpcd-q1)

<a id="a-rpcd-q2"></a>

**Q2** · In `answer`, `shared.reads.try_send((req, body))` fails with `TrySendError::Full((req, body))`. Why can the code still respond to `req`?

**Answer: C.** A failed `try_send` returns ownership of the value inside the error, so the pattern binds `req` and `body` again

Sending moves the value. On failure it comes back in the error, so nothing is lost and every request is answered (here with 503).

[← Back to the question](19-rpcd.md#q-rpcd-q2)

<a id="a-rpcd-q3"></a>

**Q3** · Why do the read workers share the channel's receiver as `Arc<Mutex<Receiver>>`?

**Answer: A.** A `Receiver` can't be cloned and is not `Sync`, so several threads can only share it behind a lock; one worker at a time waits in `recv()` while holding it

std's `mpsc` is multi-producer, single-consumer. The lock turns it into a work queue; the guard is dropped once a request arrives.

[← Back to the question](19-rpcd.md#q-rpcd-q3)

<a id="a-rpcd-q4"></a>

**Q4** · Explain `Budget` and `Gate<'b>`: what each represents, why they use `Cell` rather than `Mutex`, and what the lifetime `'b` guarantees.

**Model answer.** A `Budget` is the readiness hold one HTTP body may spend: a deadline `now + ready_wait` and a `spent` flag, created once in `handle_parsed`. A `Gate` is one request's pass through the hold, created in `handle_one` and holding `&'b Budget`; its `passed` flag makes the request wait at most once however many engine reads it makes. Handlers only get `&Gate`, so the flags need interior mutability; `Cell` gives it without a lock because both live on the stack of the one thread serving the body and are never shared (`Cell` is not `Sync`, so the compiler would refuse sharing). The lifetime `'b` ensures a gate can't outlive the budget it borrows.

A good answer covers:

- Budget: one per HTTP body, deadline + spent flag; a batch shares it
- Gate: one per request, passed flag, waits at most once
- Cell because handlers hold &Gate and the values never leave one thread
- Cell is not Sync, so sharing across threads would not compile
- 'b: the Gate cannot outlive the Budget it borrows

[← Back to the question](19-rpcd.md#q-rpcd-q4)

<a id="a-rpcd-q5"></a>

**Q5** · The verified head is block 1000. Which answer does `eth_getBalance` give for the pin `"0x100"` (block 256), if this node never reported a head at or below 256?

**Answer: C.** `-32602`: more than 64 blocks behind the head, and this node holds no historical state, so no retry can help

`pin_servable` refuses for good. A pin up to 16 ahead would be served; further ahead is retryable `-32000`.

[← Back to the question](19-rpcd.md#q-rpcd-q5)

<a id="a-rpcd-q6"></a>

**Q6** · The project rule says a parameter must be applied or refused, never silently ignored. Name three places in rpc.rs where that rule decides the code, and explain why the refusal uses -32602 rather than -32000.

**Model answer.** Examples: `arity` plus `dispatch` refuse too many positional arguments and a non-array `params`; `block_override_present` refuses any `blockOverrides` because they are never applied (`OVERRIDE_UNSUPPORTED`: rejected, not ignored); `state_override_param` returns `Malformed` for an unknown override field instead of treating it as absent; `parse_selector` refuses `safe`, `earliest`, bare digits and genesis instead of reading them as the head; `parse_tx` refuses differing `data`/`input`, blob fields and conflicting fee fields, and routes gas/fee/type fields to the transaction-object call so they are applied; `check_chain_id` refuses another chain's id. A result computed without the parameter would look correct, so the client could not detect it. -32602 is permanent; -32000 is documented as retryable, so a client would retry forever.

A good answer covers:

- names at least three concrete refusals (arity, blockOverrides, malformed state override, safe/earliest/bare digits, data≠input, chainId)
- mentions that gas/fee/type fields are routed to the transaction-object call (extended) so they are applied
- explains that a silently ignored parameter gives a plausible but wrong answer the client cannot detect
- -32602 is permanent; -32000 is retryable and would make a client spin

[← Back to the question](19-rpcd.md#q-rpcd-q6)

<a id="a-rpcd-q7"></a>

**Q7** · Why is the `Engine` trait declared as `pub trait Engine: Send + Sync`?

**Answer: B.** The router is shared by many threads through an `Arc`; it can only be `Send + Sync` if its engine is, and the supertraits make every implementation, including the test `Fake`, guarantee that

That is also why `Fake` records calls in a `Mutex` and an `AtomicUsize` instead of a `RefCell`.

[← Back to the question](19-rpcd.md#q-rpcd-q7)

<a id="a-rpcd-q8"></a>

**Q8** · In `run`, what does `let guard = StopOnDrop(handle);` guarantee, and why would it be defeated if `run` itself called `std::process::exit(1)` on an error?

**Model answer.** `StopOnDrop` implements `Drop` by calling `ffi::stop_handle`. Once the guard exists, every way out of `run` drops it: a `return Err(…)`, a `?` that propagates an error, or the graceful path's explicit `drop(guard)`. So the engine handle is always stopped and persists its sync state, like a `finally` block. `std::process::exit` ends the process without unwinding the stack, so destructors of values still alive do not run; if `run` called it, the guard would never drop. That is why `run` returns `Result` and `main` calls `exit(1)` only after `run` has returned.

A good answer covers:

- Drop for StopOnDrop calls ffi::stop\_handle
- every exit path (return Err, ?, explicit drop) runs it
- stopping lets the engine persist its sync state
- process::exit skips destructors of live values
- main exits only after run has returned and dropped the guard

[← Back to the question](19-rpcd.md#q-rpcd-q8)

<a id="a-rpcd-q9"></a>

**Q9** · `decode_revert_reason` reads offsets and lengths from a revert payload. Why does it use `d.get(range)?` and `checked_add` instead of `&d[a..b]` and `+`, and what would go wrong otherwise?

**Model answer.** The payload comes from a contract, so its offset and length words are attacker-controlled. Indexing with `&d[a..b]` panics when the range is out of bounds, and `+` on a huge offset overflows, which panics in debug builds. The workspace builds with `panic = "abort"`, so a panic would kill the whole daemon. `get` returns `None` for an out-of-range slice and `checked_add` returns `None` on overflow, and `?` turns either into "no decoded reason" while the raw payload is still returned as `data`. The test `revert_reason_decoding_is_bounded` pins an offset of `u64::MAX`.

A good answer covers:

- offsets/lengths in the payload are attacker-controlled
- slice indexing panics out of bounds; + can overflow
- panic = abort would end the whole daemon
- get/checked\_add return None, and ? maps it to no reason (raw data still returned)

[← Back to the question](19-rpcd.md#q-rpcd-q9)

<a id="a-rpcd-q10"></a>

**Q10** · An `eth_call` request carries `{"to": …, "gas": "0x5208"}`. Which engine function answers it, and why?

**Answer: A.** `eth_call_tx`: `gas` makes the transaction `extended`, and the plain call has no gas parameter, so it would silently drop it

The `extended` flag routes any field the plain call would drop to the transaction-object call, which applies it or refuses it.

[← Back to the question](19-rpcd.md#q-rpcd-q10)

<a id="a-rpcd-q11"></a>

**Q11** · A test writes `let r2 = Router { engine: moved, ..r };`. What happens to `r`?

**Answer: B.** Its remaining fields are moved into `r2` (they are not `Copy`), so `r` can no longer be used as a whole

Struct update syntax moves (or copies, for `Copy` fields) the rest. The test uses it to keep the recorded `ReportedHeads` while swapping the engine.

[← Back to the question](19-rpcd.md#q-rpcd-q11)

<a id="a-rpcd-q12"></a>

**Q12** · A client sends a 4 KiB JSON body very slowly. Follow it through http.rs: which thread reads it, what bounds that, and what happens if it doesn't arrive within `--http-body-timeout`?

**Model answer.** tiny\_http buffers only small bodies (at most 1 KiB with a Content-Length and no Expect), so `body_in_memory` is false and `intake` does not read it: it spawns a body-reader thread and returns at once, keeping the intake thread free. That thread increments `body_reads`; if 32 bodies are already being received it answers 503 without reading. Otherwise `answer` runs with a deadline; `read_body` wraps the reader in `Deadline` (and `take(MAX+1)` for the 5 MiB limit). Each `read` first checks the deadline and fails with `TimedOut` once it has passed, which becomes HTTP 408. A client that stops sending entirely blocks that body thread in a read until it closes or sends again, but never an intake thread.

A good answer covers:

- body over 1 KiB is not in memory, so intake hands it to a body-reader thread
- at most 32 bodies are received at once; past that 503
- Deadline&amp;lt;R> checks the time before every read; TimedOut → 408
- take(MAX\_BODY\_BYTES + 1) detects a body over 5 MiB (413)
- a fully stalled client holds a body thread, never an intake thread

[← Back to the question](19-rpcd.md#q-rpcd-q12)

<a id="a-rpcd-q13"></a>

**Q13** · What does `args.import_log_index.iter().map(|p| std::fs::canonicalize(p).map_err(…)).collect::<Result<Vec<_>, _>>()?` do when the second of three paths does not exist?

**Answer: D.** Stops at the second path and returns its error from `run` through `?`; the third path is never canonicalised

Collecting into `Result<Vec<_>, E>` short-circuits on the first `Err`.

[← Back to the question](19-rpcd.md#q-rpcd-q13)

## Stop 20 · roost: the light-client server

<a id="a-roost-q1"></a>

**Q1** · roost builds with `panic = "unwind"`. If `LcStore::updates_range` panicked while answering one wallet, what would happen?

**Answer: B.** The swarm task, which answers all requests inline, would end. `serve` sees `JoinError::is_panic()`, logs it, and exits non-zero, and systemd restarts roost. Every connection drops

Unwinding turns the panic into a value that the daemon can handle, a supervised restart. It doesn't isolate connections, because requests are handled on one task.

[← Back to the question](20-roost.md#q-roost-q1)

<a id="a-roost-q2"></a>

**Q2** · Why is `LcStore` guarded by `std::sync::RwLock` rather than `tokio::sync::RwLock`?

**Answer: B.** Its reader, `respond_inbound`, is synchronous code on the swarm task. It can't `.await` an async lock, and `block_on` inside a runtime worker would panic. The std lock is held briefly, and never across an await

Pick the lock that fits the calling code: synchronous callers and short critical sections mean `std`.

[← Back to the question](20-roost.md#q-roost-q2)

<a id="a-roost-q3"></a>

**Q3** · `record_bootstrap_miss` checks under a read lock inside `{ }`, then takes the write lock and checks again. Why both?

**Answer: B.** The common “nothing to do” case needs only a shared lock. The block drops the read guard first, because `std`'s `RwLock` can't upgrade, and the state may change between the two locks, so it must be re-checked

Double-checked locking with RAII: the closing `}` is what releases the read lock.

[← Back to the question](20-roost.md#q-roost-q3)

<a id="a-roost-q4"></a>

**Q4** · How can `Archive::append(&mut self, …)` be safe in a concurrent daemon without a `Mutex`?

**Answer: B.** Only the main task owns the `Archive`, and `&mut` is an exclusive borrow checked at compile time. The swarm task never has a reference to it, so a second in-process writer can't exist

Ownership can replace locking when data isn't shared. (Another *process* could still write the file; there's no OS lock.)

[← Back to the question](20-roost.md#q-roost-q4)

<a id="a-roost-q5"></a>

**Q5** · Why does `get_ssz_classified` treat HTTP 429 as `FetchError::Transient` even though it's a 4xx?

**Answer: B.** A bootstrap root is marked as attempted before the fetch, and only `Transient` failures are requeued. A 429 classified as “unavailable” would leave a wallet's pinned checkpoint permanently unserved after one rate-limit answer

The typed enum exists because the caller branches on it, so the classification is a policy decision.

[← Back to the question](20-roost.md#q-roost-q5)

<a id="a-roost-q6"></a>

**Q6** · `ChainParams`'s fields are private and `from_spec` is the only constructor. What does that buy?

**Answer: B.** A value that refuses zero, missing or overflowing geometry is the only kind that can exist, so `slot / slots_per_period` can't divide by zero and archive keys can't be silently wrong. With `pub` fields a zero compiled

Invariants enforced by visibility are guarantees; invariants in comments are hopes.

[← Back to the question](20-roost.md#q-roost-q6)

<a id="a-roost-q7"></a>

**Q7** · In `serve`'s loop, why is the swarm task's handle written as `joined = &mut swarm_task` inside `select!`?

**Answer: B.** Passing it by value would move it into the first `select!`, and the next loop iteration wouldn't compile (use of moved value). Polling `&mut` keeps the same handle across iterations

A future polled by `&mut` must be `Unpin`, which `JoinHandle` is. The `ctrl_c()` future, by contrast, is recreated each time, which is why a Ctrl-C during a tick can be missed.

[← Back to the question](20-roost.md#q-roost-q7)

<a id="a-roost-q8"></a>

**Q8** · A fresh wallet asks roost for a `light_client_bootstrap` at its pinned checkpoint root, which roost has never seen. Describe what happens on the swarm task and on the main task until the wallet is served, including what happens if Nimbus times out, and if Nimbus answers 404.

**Model answer.** On the swarm task, the `LcResponder::bootstrap` implementation finds nothing in the store. It calls `record_bootstrap_miss` (read-lock check, then write lock plus re-check) to queue the root, unless it was already attempted or queued, or the queue is full at 32. It answers `None`, so the wallet gets `ResourceUnavailable`, with no I/O and no await on that task. On a later 12 s tick, the main task's `fill_bootstrap_misses` takes up to 4 roots (marking them attempted) and fetches each from Nimbus over REST. On success it computes the digest and `insert_bootstrap`s the pre-encoded response, so the wallet's retry hits. On `FetchError::Transient` (a timeout, a 5xx, 408/429), the root is requeued at the front and its attempted marker cleared, so a hiccup doesn't block it for good. On `Unavailable` (404: Nimbus doesn't have it), the root stays marked as attempted and isn't fetched again, which prevents refetch storms from repeated wallet retries.

A good answer covers:

- swarm task: store miss → queue root (bounded, deduped) → ResourceUnavailable, no I/O
- main task drains ≤4 per tick, marks attempted, fetches over REST
- success → insert pre-encoded bootstrap; wallet retry hits
- Transient → requeue at front (not poisoned)
- Unavailable → stays attempted, never refetched

[← Back to the question](20-roost.md#q-roost-q8)

<a id="a-roost-q9"></a>

**Q9** · Why does `EnrSeq::bump` persist the new number (fsync file, rename, fsync directory) *before* returning it?

**Answer: B.** If roost crashed after publishing a record but before persisting, a restart would reuse a sequence number the network already saw, and the DHT ignores records that don't out-rank the one it has

Persist before use. Durability of the *name* change needs the directory fsync too.

[← Back to the question](20-roost.md#q-roost-q9)

<a id="a-roost-q10"></a>

**Q10** · Why does `UpdateChunk` own `ssz: Vec<u8>` instead of borrowing a `&[u8]` from the REST body?

**Answer: B.** The chunks outlive the HTTP response buffer on their way to the archive and the store. A borrowing struct would need a lifetime parameter tied to `body`, and couldn't outlive it

Owning data frees a type from lifetime parameters, at the cost of one copy.

[← Back to the question](20-roost.md#q-roost-q10)

<a id="a-roost-q11"></a>

**Q11** · In `clear_bootstraps`, why iterate over `inner.bootstrap_order.clone()`?

**Answer: B.** Both field accesses go through the same write guard (`DerefMut`), so iterating one field while mutating another looks like a shared and a mutable borrow of `inner` at once. Cloning (at most 64 roots) sidesteps that; `let i = &mut *inner;` would allow disjoint field borrows

Through a guard, the compiler sees one borrow of the whole guard, not separate fields.

[← Back to the question](20-roost.md#q-roost-q11)

<a id="a-roost-q12"></a>

**Q12** · `serve` builds its `HostConfig` by naming all seven fields, including `listen_quic: None`, instead of writing `..HostConfig::default()` for the ones it does not care about. What does that buy?

**Answer: B.** When `myotis-net` adds a field, this literal stops compiling until roost decides the value. With `..HostConfig::default()` roost would silently inherit the wallet's defaults, such as an ephemeral QUIC listener a server must not open

A struct literal without `..base` must list every field, so a new field is a compile error at each construction site. `HostConfig::default()` is the wallet's shape: `listen_quic` is `Some(/ip4/0.0.0.0/udp/0/quic-v1)` there, while roost's relay forwards no UDP port and its ENR advertises no QUIC.

[← Back to the question](20-roost.md#q-roost-q12)

<a id="a-roost-q13"></a>

**Q13** · `participation_of` now chooses between `LcFork::Gloas` and `LcFork::PreGloas` by the length of the SSZ bytes. Explain why roost may decide this way when a wallet does not, what `.ok().map(…)` does with the result, and what went wrong for Gloas periods before the change.

**Model answer.** A Gloas `LightClientUpdate` has a fixed size (`GLOAS_SIZE`), and according to the doc comment no pre-Gloas update has that length, so the length alone identifies the shape. A wallet decodes by the chunk's context bytes because it must verify the update in the right fork's layout. roost only needs the sync-aggregate participant count to judge whether a stored update is provisional. `decode_for` returns a `Result`; `.ok()` turns it into an `Option` and drops the error, and `.map(|u| u.sync_aggregate.count_participants())` reads the count only when decoding succeeded, so an undecodable record gives `None`. Before the change the pre-Gloas decoder rejected every Gloas update, so it read as `None`. `should_replace` never lets an undecodable fresh chunk replace anything, so a Gloas period was stored once and never replaced by a better copy.

A good answer covers:

- the Gloas update is fixed-size and no pre-Gloas update has that length
- roost only needs the participant count, not a verified decode by context bytes
- decode\_for gives a Result; .ok() makes it an Option and .map reads the count only on success
- before, Gloas updates read as None, and should\_replace never replaces with an undecodable chunk, so the first copy stayed forever

[← Back to the question](20-roost.md#q-roost-q13)

## Stop 21 · tor-poc: the same stack over Tor

<a id="a-tor-q1"></a>

**Q1** · What change let the existing RLPx and eth code run over a Tor stream?

**Answer: B.** `RlpxConnection` and `EthSession` became generic over the stream type `S` (default `TcpStream`, bounded by tokio's async read/write traits plus `Unpin`), and `handshake_over` accepts an already-connected stream. Arti's `DataStream` meets those bounds

The default type parameter kept every clearnet caller unchanged; the compiler emits a separate copy of the handshake for `DataStream`.

[← Back to the question](21-torpoc.md#q-tor-q1)

<a id="a-tor-q2"></a>

**Q2** · How does Rust compile `RlpxConnection::handshake_over` for both `TcpStream` and `DataStream`, compared with Java generics?

**Answer: B.** Monomorphisation: the compiler generates a specialised copy per concrete `S`, with static calls and no boxing. Java erases generics to a single implementation that dispatches at run time

`dyn Trait` is the opt-in for Java-like dynamic dispatch.

[← Back to the question](21-torpoc.md#q-tor-q2)

<a id="a-tor-q3"></a>

**Q3** · Why does `pick_working_peer` need the explicit lifetime `'a`?

**Answer: B.** It returns a reference but has several reference parameters, so elision cannot tell which input the result borrows from. `'a` ties the returned `&Peer` to `peers`

With exactly one reference input (or `&self`), elision picks it automatically.

[← Back to the question](21-torpoc.md#q-tor-q3)

<a id="a-tor-q4"></a>

**Q4** · `RlpxConnection::handshake_over(stream, Arc::clone(&key), peer.pubkey)`: what happens to each argument?

**Answer: B.** `stream` is moved into the connection. The `Arc` handle is cloned (a reference-count bump), so `key` stays usable afterwards. `peer.pubkey`, a `[u8; 64]`, is copied

Move, share, copy: the three ways values cross a function boundary.

[← Back to the question](21-torpoc.md#q-tor-q4)

<a id="a-tor-q5"></a>

**Q5** · In September, tor-poc failed to compile because `EthConfig` had gained a field that `mainnet_eth_config()` did not set. Why did CI not catch it?

**Answer: B.** `tor-poc` is its own workspace root, excluded from the main workspace, so `cargo build/test --workspace` (and the Gradle tasks built on it) never compile it

Excluded crates buy build speed and independence at the price of silent drift. A struct literal must list every field (or use `..base`). The fix is in now, and `EthConfig`'s doc comment tells the next author to run `cargo check --manifest-path tor-poc/Cargo.toml`.

[← Back to the question](21-torpoc.md#q-tor-q5)

<a id="a-tor-q6"></a>

**Q6** · The handshake works over `TcpStream` without the `flush()` after writing the auth message, but over Arti's `DataStream` it failed with "early eof" until the flush was added. Explain why, and what this says about writing code generic over a stream type.

**Model answer.** A `TcpStream` hands each write to the kernel at once, so the auth bytes go out immediately. Arti's `DataStream` keeps written bytes in its own buffer until it is flushed. Without the flush, the handshake waits for the peer's ack while the auth is still sitting in the buffer; the peer sees nothing, gives up and closes the connection, and the read of the ack ends with an early EOF. The trait bound `AsyncWriteExt` only promises the operations, not when bytes leave: generic code has to follow the trait's contract (flush when the other side must see the data), not the behaviour of the one implementation it was first written against. On TCP the flush is a harmless no-op.

A good answer covers:

- TcpStream sends writes immediately; DataStream buffers until flush
- without flush the peer never receives the auth and closes, so reading the ack hits EOF
- the flush comes before blocking on the ack
- generic code must rely on the trait contract, not on one implementation's behaviour; the flush is a no-op on TCP

[← Back to the question](21-torpoc.md#q-tor-q6)

<a id="a-tor-q7"></a>

**Q7** · `let mut since = || { let d = mark.elapsed().as_millis(); mark = Instant::now(); d };` Why must `since` be declared `mut`?

**Answer: B.** The closure assigns to its captured `mark`, so it is `FnMut`; calling an `FnMut` needs a mutable borrow of the closure itself

A closure that mutates captured state borrows that state mutably, and each call mutates the closure's own captured reference, so the binding must be `mut`. While the closure is still in use, `mark` cannot be touched directly.

[← Back to the question](21-torpoc.md#q-tor-q7)

<a id="a-tor-q8"></a>

**Q8** · In `pick_working_peer`, a peer that completes the handshake is matched as `Ok(Ok(mut session))`. Follow the `session` value: who owns it, what happens to the Tor circuit when the arm ends, and what the function returns instead. Why can `best` be read with `map_or` and still be used afterwards?

**Model answer.** `eth_handshake_over_tor` returns an owned `EthSession<DataStream>`, which owns the RLPx connection, which owns the Tor `DataStream`. The pattern moves it into the arm's binding `session` (made mutable so `head_number(&mut session)` can send a request). When the arm ends, `session` goes out of scope and is dropped, closing the connection and the stream. The function returns only `Some(peer)`, a `&'a Peer` borrowed from the input slice; the caller opens a fresh circuit later. `best` is an `Option<(&Peer, u64)>`; shared references and `u64` are `Copy`, so the tuple and the option are `Copy`, and `map_or` consumes a copy.

A good answer covers:

- the session owns the RLPx connection, which owns the Tor stream
- the match arm binds it mutably so head\_number can borrow it with &mut
- at the end of the arm the session is dropped, closing the circuit
- the function returns a &'a Peer from the input slice, not the session
- Option&amp;lt;(&Peer, u64)> is Copy, so map\_or uses a copy

[← Back to the question](21-torpoc.md#q-tor-q8)

<a id="a-tor-q9"></a>

**Q9** · `main` builds `ordered_owned: Vec<Peer>` from `ordered: Vec<&Peer>` before calling `pick_working_peer`. Why?

**Answer: B.** `pick_working_peer` takes `&[Peer]`, and a `Vec<&Peer>` derefs to `&[&Peer]`, a different type. `Peer` is not `Clone`, so the code rebuilds each one field by field

A slice of references and a slice of values are different types. The returned `&Peer` then borrows from `ordered_owned`, which lives until the end of `main`.

[← Back to the question](21-torpoc.md#q-tor-q9)

<a id="a-tor-q10"></a>

**Q10** · Which trust shortcut makes tor-poc a networking proof rather than a production read path?

**Answer: B.** It verifies the snap proof against the state root of the peer's own claimed head header, not against a beacon-verified anchor

The proof is checked (the account is MPT-verified), but the root it is checked against comes from the same peer. The crate docs say so: production anchors to the beacon chain, which is the wallet's real trust root.

[← Back to the question](21-torpoc.md#q-tor-q10)

## Stop 22 · Workbook: ten exercises you can run offline

<a id="a-wb-q1"></a>

**Q1** · Exercise 1: explain why `fixed(&mut self, len) -> Option<&'a [u8]>` lets the caller keep two returned slices at once, and what goes wrong with `-> Option<&[u8]>`.

**Model answer.** `'a` is the lifetime of the borrowed buffer the reader was created over. A result typed `&'a [u8]` points into that buffer and is unrelated to the temporary `&mut self` borrow of the reader, so the mutable borrow ends when `fixed` returns, and the next call can borrow the reader mutably again. With `-> Option<&[u8]>`, lifetime elision ties the result to `&mut self`: as long as the first slice is alive, the reader stays mutably borrowed, so a second `fixed` call is rejected (cannot borrow as mutable more than once).

A good answer covers:

- 'a names the buffer's lifetime, not the reader's
- the returned slice points into the buffer
- with 'a the &mut self borrow ends when fixed returns
- with elision the result keeps the reader mutably borrowed, so a second call fails to compile

[← Back to the question](22-workbook.md#q-wb-q1)

<a id="a-wb-q2"></a>

**Q2** · Exercise 5: why must `start` release the map lock before calling `slow_start`, and why does it re-check the entry afterwards?

**Model answer.** Holding the lock during a slow start would block every other caller (create, stop, status) for the whole duration, and code inside `slow_start` that touches the registry on the same thread would deadlock, because `std::sync::Mutex` is not reentrant. So the code copies an `Arc<Config>` out (a cheap reference-count increment), drops the guard at the block's end, and does the slow work unlocked. While unlocked, another thread may have stopped or started the entry, so the code re-locks and publishes `Running` only if the entry is still `Created`; otherwise it returns false rather than bringing a stopped entry back.

A good answer covers:

- a held lock blocks all other registry calls during the slow work
- std Mutex is not reentrant: re-locking on the same thread deadlocks
- Arc::clone copies the config out cheaply so the guard can drop
- state may change while unlocked, so publish only if still Created

[← Back to the question](22-workbook.md#q-wb-q2)

<a id="a-wb-q3"></a>

**Q3** · Exercise 7: the worker thread moves a `Weak<Service>` into its closure. What happens if you move an `Arc<Service>` clone instead?

**Answer: B.** The thread becomes an owner: dropping the test's Arc no longer frees the service, upgrade never fails, the loop never ends and join() hangs

A strong reference from a background task keeps its target alive forever. `Weak` observes without owning, and `upgrade()` returns `None` once the last owner is gone.

[← Back to the question](22-workbook.md#q-wb-q3)

<a id="a-wb-q4"></a>

**Q4** · Exercise 9: how are the losing attempts cancelled when `hedged` returns the first `Ok`, and why don't the futures need to be `'static`?

**Model answer.** All attempts are owned by the local `FuturesUnordered`. `return Some(..)` drops it, and with it every future still inside. A dropped future is never polled again, and its destructors run: that is cancellation in Rust, so no explicit cancel call is needed. The futures don't need `'static` because they are never spawned onto the runtime: `hedged` polls them in place while it is itself being awaited, so they can't outlive the data they borrow. `tokio::spawn` is what demands `'static`.

A good answer covers:

- attempts are owned by the local FuturesUnordered
- returning drops it and every in-flight future (= cancellation)
- no explicit cancel call; destructors run
- no 'static needed: the futures are polled in place, not spawned

[← Back to the question](22-workbook.md#q-wb-q4)

<a id="a-wb-q5"></a>

**Q5** · Exercise 10: `total<S: StateSource + ?Sized>(src: &S, …)` is called with a `Counting<Fixture>` and with a `&dyn StateSource`. How many copies of `total` does the compiler produce, and how is `balance` called in each?

**Answer: B.** Two copies (monomorphisation): for Counting&amp;lt;Fixture> the call to balance is static and can be inlined; for dyn StateSource it goes through the trait object's vtable

Each concrete `S` gets its own compiled copy. With `S = dyn StateSource` (allowed by `?Sized`), the copy calls through the vtable, like a Java interface call.

[← Back to the question](22-workbook.md#q-wb-q5)

## Stop 23 · Final checkpoint: one request, end to end

<a id="a-s17-q1"></a>

**Q1** · During a verified account read from Android, which thread polls the `hedged_race` future?

**Answer: B.** The JVM caller's own thread, inside `engine.rt.block_on(…)`. Only long-lived tasks such as the peer read loop and the sync loop run on runtime threads

`block_on` drives the future on the calling thread, and the runtime's workers deliver I/O events and wake it.

[← Back to the question](23-final.md#q-s17-q1)

<a id="a-s17-q2"></a>

**Q2** · How does the response bytes' journey from the peer's read task to the waiting request work?

**Answer: B.** The request inserted a `oneshot::Sender` into the peer's pending map under its request id. The read task removes that entry and calls `send`, which completes the `Receiver` the request is awaiting and wakes it

A `oneshot` is a single-use, thread-safe hand-off: an ownership transfer of the payload between tasks.

[← Back to the question](23-final.md#q-s17-q2)

<a id="a-s17-q3"></a>

**Q3** · Which of these is a *move*, not a borrow or a copy?

**Answer: B.** `ManagedPeer::spawn(session, addr)`: the `EthSession` is handed over, and the old name can't be used afterwards

`u64` is `Copy`, `Arc::clone` creates a new handle (the original stays), and `&` borrows.

[← Back to the question](23-final.md#q-s17-q3)

<a id="a-s17-q4"></a>

**Q4** · `block_on(reader.request(async { reader.get_account(address).await }))` borrows `reader`, but `tokio::spawn(async { reader.get_account(address).await })` would not compile. Why?

**Answer: B.** `spawn` requires a `'static` future, because the task may outlive the current stack frame. `block_on` doesn't return until the future finishes, so borrowing locals is safe

The fix for `spawn` is to move an `Arc` clone into an `async move` block.

[← Back to the question](23-final.md#q-s17-q4)

<a id="a-s17-q5"></a>

**Q5** · Which lock would you choose for a map that is updated in microseconds and read from both async and synchronous code, and never held across `.await`?

**Answer: B.** `std::sync::Mutex` (or `RwLock`): cheap, usable from synchronous code, and safe in async code as long as the guard is dropped before any `.await`

Use a tokio mutex only when the critical section itself must `.await`. A `RefCell` isn't `Sync` and can't be shared between threads.

[← Back to the question](23-final.md#q-s17-q5)

<a id="a-s17-q6"></a>

**Q6** · Why does so much of this codebase avoid `unwrap()`, indexing and unchecked arithmetic on runtime data?

**Answer: B.** The engine is built with `panic = "abort"` and runs inside JVM, iOS and Node hosts. Any panic would kill the host app, so failures must become `Option`/`Result` values, sentinels, or `{"error"}` JSON

roost is the one exception: it unwinds, and turns a panic into a supervised restart.

[← Back to the question](23-final.md#q-s17-q6)

<a id="a-s17-q7"></a>

**Q7** · What cancels the losing attempts of a hedged read, and what cancels an in-flight request when a host calls `stop`?

**Answer: B.** Losing attempts are cancelled by being *dropped* when `hedged_race` returns. On `stop`, the shutdown watch flips, and each registered `Operation`, reached by upgrading its `Weak`, is signalled and awaited until it settles

In Rust, dropping a future is cancellation. `Weak` lets the reader track requests without keeping them alive.

[← Back to the question](23-final.md#q-s17-q7)

<a id="a-s17-q8"></a>

**Q8** · In your own words, compare how Java and Rust would each make the handle registry in `host.rs` (a map from id to chain state, used from many host threads) safe. Name the Rust types involved and what the compiler enforces that Java doesn't.

**Model answer.** In Java you'd use a `ConcurrentHashMap`, or a `HashMap` guarded by `synchronized`. Nothing stops code from touching the map without the lock, and entries are freely aliased references collected by the GC. In Rust the registry is `Mutex<HashMap<i64, ChainEntry>>` inside a `static OnceLock`. The data lives *inside* the mutex, so it can only be reached through the guard, and the guard unlocks when it's dropped (often at the end of a `{ }` block chosen to keep the critical section tiny). The map entry uniquely owns the `SyncHandle`. Things that must be used outside the lock (the config, the reader) are `Arc`s that callers clone out and use after unlocking. Consuming operations such as `stop(self)` force the code to `remove` the entry to gain ownership. The compiler enforces that the map is `Sync` only because of the mutex, that no reference to an entry outlives the guard, and that the moved-out `SyncHandle` can't be used again.

A good answer covers:

- Java: ConcurrentHashMap/synchronized, lock discipline by convention, GC-managed aliasing
- Rust: static OnceLock + Mutex&amp;lt;HashMap&amp;lt;..>>; data only reachable through the guard
- guard drop = unlock; block scopes keep critical sections short
- Arc clones carried out of the lock; unique ownership of SyncHandle; remove to consume
- compiler enforces Sync, no borrow outliving the guard, no use after move

[← Back to the question](23-final.md#q-s17-q8)

<a id="a-s17-q9"></a>

**Q9** · `Arc<LcStore>` is passed where `Arc<dyn LcResponder>` is expected, and `RlpxConnection<S>` is instantiated with `S = DataStream`. Which statement is right?

**Answer: B.** The first is a trait object (a pointer plus a vtable, resolved at run time). The second is a generic, monomorphised at compile time into specialised code with static calls

`dyn Trait` is Rust's equivalent of calling through a Java interface; generics are closer to C++ templates.

[← Back to the question](23-final.md#q-s17-q9)

<a id="a-s17-q10"></a>

**Q10** · Which statement matches the trust model you've seen across the tour?

**Answer: B.** Nothing a peer says is trusted until it's checked: account and storage data by Merkle-Patricia proofs, state roots and headers by tying them to a beacon block the light client verified with sync-committee BLS signatures, starting from a pinned checkpoint. roost only relays objects that wallets verify themselves

The only trust anchors are the embedded checkpoint (plus historical accumulators) and sync-committee signatures.

[← Back to the question](23-final.md#q-s17-q10)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
