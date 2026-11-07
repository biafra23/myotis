# myotis-node: the Node.js addon

*Stop 18 · crate `myotis-node`* · 4 files · 1,922 lines · about 110 minutes

A `napi-rs` addon for Electron and Node hosts, built as `myotis-node.node`. It calls the engine's C functions ([Stop 16](16-engine.md)) by Rust path. Lifecycle and status calls are synchronous; verified reads return Promises that the addon's *own* worker threads settle, never libuv's. Since September the addon has grown from 20 to 42 JavaScript functions: it now exports every read a dApp provider needs (#503), and because no JSON-RPC router stands in front of it, it makes the routers' argument checks itself. The heart of the crate is still `scheduler.rs`, a small hand-written thread pool: Java's `synchronized`/`wait`/`notifyAll`, rewritten with Rust's guarantees, plus raw pointers handed back and forth with Node.

## Rust you will practise

- **Threads without async** — `Mutex` + `Condvar`, `std::thread`, atomics with compare-and-swap, `thread_local!` + `RefCell`.
- **Closures that travel** — `Box<dyn FnOnce() -> String + Send>`, `move` closures, `mem::replace`, and validation that runs inside the closure.
- **Ownership through C** — `CString` lifetimes, `Box::into_raw` → Node → `Box::from_raw`, drop guards, pointers stored as `usize`, and nested `Result`/`Option` patterns in `let … else`.

![A verified read in myotis-node. On the JS thread, submit creates a Promise, pushes a Job and notifies the workers, then returns the Promise at once so the event loop keeps running. On a Myotis worker thread, take_ready waits on the Condvar until a job whose handle is free is available, then submitted runs the closure, which checks the arguments, calls the C ABI and the engine's block_on. finish posts the result through a thread-safe function without blocking, and on the JS thread complete takes the boxed result back and resolves the Promise.](img/18-node-1.svg)

*The worker, not the JS thread, waits for the network. Admission allows at most 32 requests in flight per environment (including results not yet delivered), at most 4 queued or running per handle, and at most one *running* per handle, so a slow chain can't hold up another. Every request has a 90-second deadline and a cancellation flag.*

> [!TIP]
> **What changed since September**
>
> `scheduler.rs` and `admission.rs` are byte-for-byte unchanged. `lib.rs` grew from 340 to 1,078 lines: 22 new exports (blocks, receipts, transactions, fee history, code, storage, `eth_getProof`, logs, the log index, the transaction-object calls, block-hash resolution, network metering, the pending-nonce overlay) and a block of small pure validators with nine unit tests. `Cargo.toml` gained one dependency, `serde_json`, used only by those validators.

<a id="f-myotis-node-build-rs"></a>

### myotis-node/build.rs

*build script · 3 lines*

A Cargo build script: Cargo compiles and runs `build.rs` before building the crate, and the `cargo:` lines it prints configure the build, much like a small Gradle task. `napi_build::setup()` adds the platform linker flags a Node addon needs. On macOS, for example, it lets the library find Node-API symbols in the host process at load time.

`rust/myotis-node/build.rs` · lines 1–3

```rust
fn main() {
    napi_build::setup();
}
```

**myotis-node/Cargo.toml** · `rust/myotis-node/Cargo.toml` · lines 9–23

```toml
[lib]
# myotis-node.node — loaded by Node's process.dlopen via a thin JS loader.
crate-type = ["cdylib"]

[dependencies]
# Linked for its exported C-ABI symbols (capi.rs) — the same seam the iOS
# cinterop consumes, JSON shapes pinned by the cross-engine golden tests.
myotis-engine = { path = "../myotis-engine" }
napi = { version = "3", default-features = false, features = ["napi8"] }
napi-derive = "3"
# Checks the JSON arguments the engine leaves to its caller (#503).
serde_json = "1"

[build-dependencies]
napi-build = "2"
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* `crate-type = ["cdylib"]` produces a C-compatible shared library, which you rename to `.node` (the README's build steps do exactly that). `[build-dependencies]` are available only to `build.rs`. `default-features = false, features = ["napi8"]` picks exactly the Node-API level the addon uses. `serde_json` is new: the addon now parses two JSON arguments itself (reward percentiles and import paths) before it hands them to the engine.

<a id="f-myotis-node-src-lib-rs"></a>

### myotis-node/src/lib.rs

*Node addon · 1,078 lines*

Forty-two JavaScript functions: catalog, lifecycle, weak-subjectivity and EL-seed controls, 25 calls that return Promises (the verified reads and the log-index administration), and one synchronous nonce lookup. Engine failures stay *in-band* (`{"error"}`, negative handles, `false`), exactly as on the JVM and iOS routes; only Node-API and scheduler failures throw. Each handle belongs to the Node environment that created it. New since September: the binding refuses malformed arguments itself, as permanent `{"error", "code": -32602}` objects, because on the other hosts a JSON-RPC router makes those checks before the engine is called, and here nothing does.

| Lines | What happens |
|---|---|
| 1–53 | Crate docs (the design rules), `#![allow(unused_unsafe)]`, the `mod` declarations, and the `use` of 44 C-ABI functions from `myotis_engine::capi`. |
| 55–78 | `take` (engine string → Rust `String`), `NUL_INVALID_PARAMS`, `c_arg` (JS string → `CString`). |
| 80–120 | Catalog, no handle: `init`, `drainLogs`, `availableNetworksJson`, `canonicalNetworkName`. |
| 122–242 | Lifecycle: `create`, `createWithCheckpoint`, `start`, network metering, `statusJson`, `pause`, `resume`, `stop`. |
| 244–293 | Host policy: `setWsBoundPeriods`, `setBootEnodes`, `acceptStaleAnchor`. |
| 295–540 | The original verified reads: account, `eth_call` (plain, transaction object, with overrides), gas estimates, access lists, ENS, fees, send-raw. |
| 542–671 | The #503 comment block and the pure validators: `invalid_params`, `safe_integer`, `bare_digits`, `hex_of_len`, `hex_bytes`, `decimal_u256`, `storage_word`, `reward_percentiles`, `import_paths_ok`, `nonce_arg`. |
| 673–889 | The provider reads: blocks by number and hash, `resolveBlockHashJson`, fee history, receipts, transactions, code, storage, `getProofJson`, `getLogsJson`. |
| 891–948 | The log index: `setLogIndexConfig`, `logIndexStatusJson`, `importLogIndexFiles` (all on the workers). |
| 950–971 | `pendingNonceOverlay`, synchronous. |
| 973–1078 | Nine unit tests of the validators. |

`rust/myotis-node/src/lib.rs` · lines 55–78

```rust
/// Take ownership of an engine-allocated C string: copy to a Rust `String`,
/// release via `myotis_string_free` (never `free(3)` — the header's contract).
/// Null (the engine's OOM/interior-NUL sentinel) becomes an in-band error
/// object so JS never has to branch on empty strings.
fn take(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return r#"{"error":"engine returned null"}"#.to_string();
    }
    let s = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    unsafe { myotis_string_free(ptr) };
    s
}

/// A JS string crossing into C. Interior NULs can't appear in addresses/names/
/// JSON, but a hostile caller must get an in-band error, not a panic (the
/// workspace builds with `panic = "abort"`).
/// The in-band refusal of an argument with a NUL byte on the calls whose own
/// refusals are permanent (`eth_call`, the state reads): the same -32602 the
/// engine gives a malformed selector.
const NUL_INVALID_PARAMS: &str = r#"{"error":"argument contains NUL","code":-32602}"#;

fn c_arg(s: &str) -> std::result::Result<CString, String> {
    CString::new(s).map_err(|_| r#"{"error":"argument contains NUL"}"#.to_string())
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* **`take` owns the engine's buffer.** It copies the C string into a Rust `String`, then hands the memory back to the engine's allocator with `myotis_string_free`. The copy *must* come first: the borrow checker doesn't track raw pointers, so the order is the programmer's responsibility. `r#"…"#` is a raw string literal, so the quotes need no escaping.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `c_arg` turns a JS string into a `CString`. An interior NUL byte (a hostile caller) becomes an in-band error string rather than a panic. Note the two different strings: `c_arg`'s own error has no `code` (retryable in the README's terms), while `NUL_INVALID_PARAMS`, used by most reads, carries `-32602`. A few older calls (`resolveEnsJson`, `ensRecordJson`) still pass `c_arg`'s code-less string through.
- *[Macros & attributes](01-primer.md#primer-macros) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `#![allow(unused_unsafe)]` (line 22) is a crate-level attribute (note the `!`). Some of the C functions are safe to call, but every call is wrapped in `unsafe` the same way.

> [!WARNING]
> **Stale or inaccurate comments**
>
> Lines 68–70 are `c_arg`'s doc comment ("A JS string crossing into C…"), but the constant `NUL_INVALID_PARAMS` was later inserted between that comment and the function. A `///` comment documents the *next item*, so rustdoc now shows both paragraphs on the constant, and `c_arg` has no documentation at all.

`rust/myotis-node/src/lib.rs` · lines 131–140

```rust
#[napi]
pub fn create(env: &Env, network: String, data_dir: String) -> Result<i64> {
    scheduler::prepare(env)?;
    let (Ok(n), Ok(d)) = (c_arg(&network), c_arg(&data_dir)) else {
        return Ok(-1);
    };
    let handle = unsafe { myotis_create(n.as_ptr(), d.as_ptr()) };
    if handle > 0 { scheduler::created(env, handle)?; }
    Ok(handle)
}
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **Keep the `CString` alive.** `n.as_ptr()` only *borrows* the buffer, and the compiler doesn't connect that raw pointer to `n`'s lifetime. Binding the `CString`s to `n` and `d` keeps them alive past the C call. By contrast, `let p = CString::new(s).unwrap().as_ptr();` frees the temporary at the end of that statement, so `p` dangles by the next line (rustc even has a lint for this).
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **Two ways to fail.** A scheduler (infrastructure) failure propagates with `?` and becomes a JS exception; an engine refusal is an ordinary value such as `Ok(-1)`. The environment is set up *before* the handle exists, so a failed setup never leaves an orphaned handle.
- *[Macros & attributes](01-primer.md#primer-macros)* `#[napi]` generates the JS binding and a TypeScript declaration under a camelCase name (`statusJson`, `createWithCheckpoint`). napi-rs supplies the `env: &Env` argument, and returning `Err` throws.

`rust/myotis-node/src/lib.rs` · lines 161–188

```rust
#[napi]
pub fn create_with_checkpoint(
    env: &Env,
    network: String,
    data_dir: String,
    checkpoint_root: String,
    checkpoint_slot: f64,
) -> Result<i64> {
    // The documented JS representation is a safe integer; anything else is a
    // permanently malformed request, answered in-band like every other engine
    // refusal (never a JS exception).
    if !checkpoint_slot.is_finite()
        || checkpoint_slot.fract() != 0.0
        || checkpoint_slot < 1.0
        || checkpoint_slot > 9_007_199_254_740_991.0
    {
        return Ok(-1);
    }
    scheduler::prepare(env)?;
    let (Ok(n), Ok(d), Ok(r)) = (c_arg(&network), c_arg(&data_dir), c_arg(&checkpoint_root)) else {
        return Ok(-1);
    };
    let handle = unsafe {
        myotis_create_with_checkpoint(n.as_ptr(), d.as_ptr(), r.as_ptr(), checkpoint_slot as u64)
    };
    if handle > 0 { scheduler::created(env, handle)?; }
    Ok(handle)
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* A JS number is an `f64`. Before `as u64`, the code checks that it is finite, a whole number, and between 1 and 2⁵³−1 (`Number.MAX_SAFE_INTEGER`), because `as` casts from float saturate silently. `let (Ok(n), Ok(d), Ok(r)) = (…) else` uses a tuple pattern: all three conversions must succeed, or the `else` block (which must leave the function) runs.

`rust/myotis-node/src/lib.rs` · lines 218–242

```rust
/// Idle-sleep: Running→Paused (tear down networking, keep warm state).
#[napi]
pub fn pause(env: &Env, handle: i64) -> Result<bool> {
    let cancellation = scheduler::cancel_handle(env, handle, false)?;
    let result = cancellation.owned && unsafe { myotis_pause(handle) };
    cancellation.finish(env);
    Ok(result)
}

/// Paused→Running warm restart. False = rebuild failed (still PAUSED, retry).
#[napi]
pub fn resume(env: &Env, handle: i64) -> bool {
    if !scheduler::owns(env, handle) { return false; }
    unsafe { myotis_resume(handle) }
}

/// Cancel queued/active native work, drain it, then remove and shut down.
/// Promise callbacks deliver once JS regains control. Unknown id is a no-op.
#[napi]
pub fn stop(env: &Env, handle: i64) -> Result<()> {
    let cancellation = scheduler::cancel_handle(env, handle, true)?;
    if cancellation.owned { unsafe { myotis_stop(handle) }; }
    cancellation.finish(env);
    Ok(())
}
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Ownership & moves](01-primer.md#primer-ownership)* `pause` and `stop` first cancel the handle's requests and *wait* for its running job (`cancel_handle`), then call the engine, then call `cancellation.finish(env)`. Cancelled jobs normally settle their Promises through the thread-safe function like any other result. `finish` handles the rare case where that hand-off failed: it poisons the scheduler and settles those Promises directly. `Cancellation` is marked `#[must_use]`, so the compiler warns if a caller ignores it, and `finish(self, …)` takes it *by value*, so it can be finished only once. `cancellation.owned && unsafe { … }` short-circuits, so the engine is never called for a handle this environment doesn't own. `resume` cancels nothing; it only asks the engine for a warm restart. Lifecycle calls are otherwise serialised simply by being made on the environment's single JS thread.

#### A read, and where its arguments are checked

`rust/myotis-node/src/lib.rs` · lines 306–323

```rust
#[napi(ts_return_type = "Promise<string>")]
pub fn request_account_json<'env>(
    env: &'env Env,
    handle: i64,
    address: String,
    block: Option<String>,
) -> Result<Object<'env>> {
    let block = block.unwrap_or_default();
    scheduler::submit(env, handle, move || {
        let (Ok(a), Ok(b)) = (c_arg(&address), c_arg(&block)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        if !hex_of_len(&address, 20) {
            return invalid_params("invalid address (expected 20-byte hex)");
        }
        take(unsafe { myotis_request_account_json(handle, a.as_ptr(), b.as_ptr()) })
    })
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **A closure that travels.** Nothing here blocks: the function packages the work and returns a Promise immediately. The `move` closure takes ownership of `address` and `block` (and copies `handle`, an `i64`, which is `Copy`), because `submit` requires `FnOnce() -> String + Send + 'static`: it will run later, on another thread. `block.unwrap_or_default()` runs first, on the JS thread, turning `Option<String>` (an optional JS argument) into a plain `String` (empty when omitted).
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **The checks run inside the closure**, on a worker. So an unknown handle is answered first (`submit` refuses it with "handle does not belong to this environment"), and a malformed address still takes an admission slot and waits behind a running job on the same handle before it is refused. The refusal is the project's permanent `-32602`: the address is applied or refused, never read loosely.
- *[Lifetimes](01-primer.md#primer-lifetimes)* `Object<'env>`: the returned JS handle can't outlive the `&'env Env` borrow, a lifetime that mirrors Node's own handle-scope rules. `ts_return_type` sets the TypeScript type by hand, because the Rust type is an untyped object.

#### The validators

The comment at lines 554–567 states the rule: each check is "the engine's own parse or a router's rule, so what this binding refuses, the other hosts refuse too". The helpers are small pure functions, which is why they could be unit-tested without Node.

`rust/myotis-node/src/lib.rs` · lines 569–602

```rust
/// A permanent refusal of the request: `{"error": why, "code": -32602}`.
fn invalid_params(why: &str) -> String {
    format!(r#"{{"error":{},"code":-32602}}"#, serde_json::Value::from(why))
}

/// Whether a JS number is an integer this binding can pass on exactly.
fn safe_integer(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0
}

/// A block number in bare digits, which the block and fee-history selectors
/// would take as HEX — `"23500000"` a block far past the head, or a smaller
/// number silently the wrong block — while a JS caller means decimal. The
/// JSON-RPC routers refuse it, and so do those reads; the receipts selector
/// is refused up front too, which the engine refuses only once the handle
/// runs.
fn bare_digits(selector: &str) -> bool {
    let s = selector.trim();
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Hex of exactly `len` bytes, `0x` optional: the engine's own address and
/// 32-byte-word parsers, mirrored, so only what it would refuse is refused.
fn hex_of_len(s: &str, len: usize) -> bool {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    h.len() == 2 * len && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Hex bytes of any length up to 1 MiB, `0x` optional: the engine's parser
/// for call data and raw transactions, mirrored.
fn hex_bytes(s: &str) -> bool {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    h.len() <= 2 * 1024 * 1024 && h.len().is_multiple_of(2) && h.bytes().all(|b| b.is_ascii_hexdigit())
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* **`invalid_params` escapes its message** by building a `serde_json::Value` from the `&str` and formatting it, so a quote in the reason can't break the JSON. In `format!`, `{{` and `}}` are literal braces.
- *[Protocol & domain](01-primer.md#primer-domain)* **Why bare digits are refused.** The engine reads a block-number selector as hex, so `"23500000"` from a JS caller who meant decimal would name a block far past the head, or a smaller number would silently name the wrong block. A refusal is the only safe answer.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)` borrows: every step returns a `&str` slice of the caller's string, and nothing is copied. `.bytes().all(|b| b.is_ascii_hexdigit())` checks bytes, not `char`s, which is enough for ASCII hex and avoids UTF-8 decoding. `hex_bytes` also caps the input at 1 MiB, as the engine's parser does.

`rust/myotis-node/src/lib.rs` · lines 624–660

```rust
/// eth_feeHistory's reward percentiles, checked as the routers check them (the
/// engine leaves range and order to its caller): `''`, `null` or `[]` ask for
/// no reward column — geth answers none for an empty list — and anything else
/// must be JSON numbers in [0, 100], non-decreasing, at most 100. What to hand
/// the engine — the numbers re-serialised, as the routers hand them over, so
/// long numerals cannot overrun its 4 KiB bound — or the refusal.
fn reward_percentiles(json: &str) -> std::result::Result<String, String> {
    let json = json.trim();
    if json.is_empty() || json == "null" {
        return Ok(String::new());
    }
    // A numeral past f64's range fails the parse itself, so the message names
    // the numbers too.
    let not_an_array = || invalid_params("reward percentiles must be a JSON array of numbers");
    let parsed: serde_json::Value = serde_json::from_str(json).map_err(|_| not_an_array())?;
    let list = parsed.as_array().ok_or_else(not_an_array)?;
    if list.is_empty() {
        return Ok(String::new());
    }
    if list.len() > 100 {
        return Err(invalid_params(&format!("at most 100 reward percentiles, got {}", list.len())));
    }
    let mut last = 0.0;
    for p in list {
        let Some(d) = p.as_f64() else {
            return Err(invalid_params("reward percentiles must be JSON numbers"));
        };
        if !(0.0..=100.0).contains(&d) {
            return Err(invalid_params(&format!("reward percentile {d} is outside [0, 100]")));
        }
        if d < last {
            return Err(invalid_params("reward percentiles must be non-decreasing"));
        }
        last = d;
    }
    Ok(parsed.to_string())
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **`Result<String, String>`**: `Ok` is what to hand the engine, `Err` is the finished refusal JSON. `not_an_array` is a closure stored in a variable, so it can be reused: `map_err(|_| not_an_array())` calls it, and `ok_or_else(not_an_array)` passes the closure itself, which is called only on `None`.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Re-serialised on purpose.** `parsed.to_string()` hands the engine the numbers as serde writes them, so a list of very long numerals can't exceed the engine's 4 KiB bound (the test at lines 1029–1032 pins exactly that). `(0.0..=100.0).contains(&d)` is an inclusive range used as a predicate.

#### Nested patterns

`rust/myotis-node/src/lib.rs` · lines 734–760

```rust
#[napi(ts_return_type = "Promise<string>")]
pub fn fee_history_json<'env>(
    env: &'env Env,
    handle: i64,
    block_count: f64,
    newest_block: String,
    percentiles_json: Option<String>,
) -> Result<Object<'env>> {
    let percentiles = percentiles_json.unwrap_or_default();
    scheduler::submit(env, handle, move || {
        let (Ok(n), Ok(_)) = (c_arg(&newest_block), c_arg(&percentiles)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        if !safe_integer(block_count) {
            return invalid_params("blockCount must be an integer");
        }
        if bare_digits(&newest_block) {
            return invalid_params("a block number must be 0x-hex");
        }
        let p = match reward_percentiles(&percentiles).map(|p| c_arg(&p)) {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return NUL_INVALID_PARAMS.to_string(),
            Err(refusal) => return refusal,
        };
        take(unsafe { myotis_fee_history_json(handle, block_count as i64, n.as_ptr(), p.as_ptr()) })
    })
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* `reward_percentiles(…).map(|p| c_arg(&p))` has the type `Result<Result<CString, String>, String>`: the outer error is a refusal, the inner one a NUL byte. One `match` takes it apart: `Ok(Ok(p))` binds the `CString`, `Ok(Err(_))` is the NUL case, and `Err(refusal) => return refusal` returns the finished JSON. The `CString` `p` lives until the closure ends, so the pointer passed to the engine stays valid. `block_count as i64` is safe only because `safe_integer` ran first.

`rust/myotis-node/src/lib.rs` · lines 828–849

```rust
#[napi(ts_return_type = "Promise<string>")]
pub fn get_storage_at_json<'env>(
    env: &'env Env,
    handle: i64,
    address: String,
    position: String,
    block: Option<String>,
) -> Result<Object<'env>> {
    let block = block.unwrap_or_default();
    scheduler::submit(env, handle, move || {
        let (Ok(a), Ok(_), Ok(b)) = (c_arg(&address), c_arg(&position), c_arg(&block)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        if !hex_of_len(&address, 20) {
            return invalid_params("invalid address (expected 20-byte hex)");
        }
        let Some(Ok(p)) = storage_word(&position).map(|w| c_arg(&w)) else {
            return invalid_params("invalid storage position (expected hex of at most 32 bytes)");
        };
        take(unsafe { myotis_get_storage_at_json(handle, a.as_ptr(), p.as_ptr(), b.as_ptr()) })
    })
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* `let Some(Ok(p)) = storage_word(&position).map(|w| c_arg(&w)) else { … }`: an `Option<Result<CString, String>>` must be `Some` *and* `Ok`. The padded word `w` is a temporary `String` that lives only inside the closure; `c_arg` copies it into the `CString`, which is what survives. In the first tuple, `Ok(_)` checks the raw position for a NUL byte without binding it, so that `CString` is dropped at the end of the statement.

`rust/myotis-node/src/lib.rs` · lines 1022–1039

```rust
#[test]
fn reward_percentiles_are_checked_as_the_routers_check_them() {
    assert_eq!(reward_percentiles("").as_deref(), Ok(""));
    assert_eq!(reward_percentiles("null").as_deref(), Ok(""));
    // geth answers no reward column for an empty list.
    assert_eq!(reward_percentiles(" [] ").as_deref(), Ok(""));
    assert_eq!(reward_percentiles("[25, 50, 50, 75]").as_deref(), Ok("[25,50,50,75]"));
    // Re-serialised, a list of long numerals fits the engine's 4 KiB bound.
    let long = format!("[{}]", vec!["50.000000000000000000000000000000000000001"; 100].join(","));
    assert!(long.len() > 4096);
    assert_eq!(reward_percentiles(&long).map(|p| p.len() <= 4096), Ok(true));
    for bad in ["[75, 25]", "[101]", "[-1]", "[\"50\"]", "{\"p\":1}", "not json", "[1e400]"] {
        let refusal = reward_percentiles(bad).expect_err(bad);
        assert!(refusal.contains("\"code\":-32602"), "{bad}: {refusal}");
    }
    let many = format!("[{}]", vec!["50"; 101].join(","));
    assert!(reward_percentiles(&many).is_err());
}
```

*[Tests](01-primer.md#primer-testing)* `#[cfg(test)] mod tests` is compiled only by `cargo test`, and `use super::*` brings the parent module's *private* functions into scope: privacy in Rust is per module, and a child module may see its parent's items. `expect_err(bad)` panics with `bad` as the message if the result is `Ok`, so a failing case names itself. `.as_deref()` turns `Result<String, String>` into `Result<&str, &String>`, which can be compared with `Ok("")`.

The log-index functions (lines 891–948) also run on the workers, because installing a config or importing a snapshot takes the index's write lock, which can be held for a while. The comment at lines 897–901 is candid about the cost: an import is neither bounded by the 90 s budget nor cancellable, so it occupies its handle's one execution slot, that handle's reads queue behind it, and `stop`/`pause` wait for it.

<a id="f-myotis-node-src-admission-rs"></a>

### myotis-node/src/admission.rs

*Node addon · 95 lines*

A generic job queue with one rule: at most one running job per handle. A queued job may overtake an older one whose handle is busy, so a slow chain doesn't block the others. The queue has no lock of its own; the scheduler's `Mutex` protects it. Cancelling queued jobs never frees the slot of a job that is already running.

`rust/myotis-node/src/admission.rs` · lines 1–52

```rust
//! Pure queue ownership. Cancelling queued work never releases an active slot.
use std::collections::{HashSet, VecDeque};

pub(crate) trait HasHandle {
    fn handle(&self) -> i64;
}

pub(crate) struct Admission<T> {
    queued: VecDeque<T>,
    active: HashSet<i64>,
}

impl<T: HasHandle> Admission<T> {
    pub fn new() -> Self {
        Self {
            queued: VecDeque::new(),
            active: HashSet::new(),
        }
    }
    pub fn push(&mut self, job: T) {
        self.queued.push_back(job);
    }
    pub fn take_ready(&mut self) -> Option<T> {
        let index = self
            .queued
            .iter()
            .position(|job| !self.active.contains(&job.handle()))?;
        let job = self.queued.remove(index)?;
        self.active.insert(job.handle());
        Some(job)
    }
    pub fn finish(&mut self, handle: i64) {
        self.active.remove(&handle);
    }
    pub fn is_active(&self, handle: i64) -> bool {
        self.active.contains(&handle)
    }
    pub fn cancel_queued(&mut self, handle: Option<i64>) -> Vec<T> {
        let mut cancelled = Vec::new();
        let mut index = 0;
        while index < self.queued.len() {
            if handle.is_none_or(|h| self.queued[index].handle() == h) {
                if let Some(job) = self.queued.remove(index) {
                    cancelled.push(job);
                }
            } else {
                index += 1;
            }
        }
        cancelled
    }
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `impl<T: HasHandle> Admission<T>` is roughly `class Admission<T extends HasHandle>`. Unlike Java, the compiler generates separate code for each concrete `T` (monomorphisation), so there is no boxing or casting. `pub(crate)` means visible inside this crate only.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Borrows end early.** In `take_ready`, the read-only borrows of `queued` and `active` end as soon as `position` returns an index, so the mutable `remove` on the next line is allowed. The two `?` operators return `None` instead of panicking.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `cancel_queued` walks by *index*, because a deque can't be changed while an iterator borrows it. `handle.is_none_or(|h| …)` treats `None` as "cancel everything".
- *[Tests](01-primer.md#primer-testing)* The two tests (lines 54–95) pin the rule that matters: cancelling a queued sibling must not release the handle that is *actually running*.

<a id="f-myotis-node-src-scheduler-rs"></a>

### myotis-node/src/scheduler.rs

*Node addon · 746 lines*

A worker pool per Node environment: two OS threads (capped at eight across the process), an `Admission` queue behind a `Mutex` + `Condvar`, per-request deadlines and cancellation flags, and a Node-API *thread-safe function* (TSFN) that carries results back to the JS thread. It also handles pause/stop draining, environment shutdown, and a fail-safe "poisoned" state. Unchanged since September.

| Lines | What happens |
|---|---|
| 1–67 | Limits, the thread-locals, `Job`, `Completion`, `Inner` (everything behind the mutex), `State`. |
| 69–178 | `check`; `complete` (the TSFN callback) and `deliver_completion`, which settles one Promise on the JS thread and poisons the scheduler if Node-API fails. |
| 180–288 | `cancel_queued`, `poison`, `decrement_pending`, `delivered` (unrefs the TSFN when idle), `finalize`, `post_completion`. |
| 290–381 | `State::finish`, the worker loop, and `cleanup` for environment shutdown. |
| 383–569 | The cleanup hook, and `state(env)`: lazy per-environment setup (worker reservation, fallback error, TSFN, threads, hook). |
| 571–746 | `created`, `prepare`, `Cancellation`, `cancel_handle`, `submit`, `owns`, `fatal_completion`. |

`rust/myotis-node/src/scheduler.rs` · lines 21–67

```rust
const WORKERS: usize = 2;
const MAX_WORKERS: usize = 8;
const CAPACITY: usize = 32;
const PER_HANDLE: usize = 4;
const BUDGET: Duration = Duration::from_secs(90);
static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static ENVS: RefCell<HashMap<usize, Arc<State>>> = RefCell::new(HashMap::new());
    static INITIALIZING: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
}

type Work = Box<dyn FnOnce() -> String + Send>;
struct Job {
    id: u64,
    handle: i64,
    deferred: usize,
    submission: Submission,
    run: Work,
}
impl HasHandle for Job {
    fn handle(&self) -> i64 {
        self.handle
    }
}

struct Completion {
    deferred: usize,
    value: String,
}
struct Inner {
    // Used only under this mutex; cleared BEFORE cleanup cancels/joins workers.
    tsfn: Option<usize>,
    closing: bool,
    cleanup_started: bool,
    poisoned: bool,
    fallback_error: Option<usize>,
    queue: Admission<Job>,
    requests: HashMap<u64, (i64, Arc<AtomicBool>)>,
    handles: HashSet<i64>,
    pending: usize,
    next_id: u64,
}
struct State {
    inner: Mutex<Inner>,
    changed: Condvar,
    workers: Mutex<Vec<JoinHandle<()>>>,
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **`Box<dyn FnOnce() -> String + Send>`** is a heap-allocated closure of unknown type that can move to another thread and be called exactly once. `Box<dyn …>` gives closures of different sizes one field type.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Pointers stored as `usize`.** A `Job` moves to a worker thread, so every field must be `Send`. Raw pointers aren't `Send`, but integers are, so the Promise handle (`deferred`) and the TSFN are stored as numbers and cast back where Node-API is called. It works, but it tells the compiler nothing, so correctness rests on the surrounding invariants.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `thread_local!` + `RefCell`: each thread has its own map from environment to state, so no lock is needed. `RefCell` checks the borrowing rules at *run time* and panics on a violation. `static LIVE_WORKERS: AtomicUsize` is a process-wide counter.

#### The worker loop

`rust/myotis-node/src/scheduler.rs` · lines 290–333

```rust
impl State {
    fn finish(&self, job: Job, value: String) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.requests.remove(&job.id);
        inner.queue.finish(job.handle);
        if post_completion(&mut inner, job, value).is_some() {
            // A worker has no alternate JS-thread delivery path.
            fatal_completion();
        }
        self.changed.notify_all();
    }

    fn worker(self: Arc<Self>) {
        struct Slot;
        impl Drop for Slot {
            fn drop(&mut self) {
                LIVE_WORKERS.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _slot = Slot;
        loop {
            let mut job = {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if inner.closing {
                        return;
                    }
                    if let Some(job) = inner.queue.take_ready() {
                        break job;
                    }
                    inner = self.changed.wait(inner).unwrap_or_else(|e| e.into_inner());
                }
            };
            let value = if job.submission.cancelled.load(Ordering::Acquire) {
                r#"{"error":"request cancelled"}"#.to_string()
            } else if Instant::now() >= job.submission.deadline {
                r#"{"error":"request deadline exceeded in queue"}"#.to_string()
            } else {
                let run = std::mem::replace(&mut job.run, Box::new(String::new));
                submitted(job.submission.clone(), run)
            };
            self.finish(job, value);
        }
    }
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Java's monitor pattern, made safe.** This is `while (!ready) cond.wait();`. `self.changed.wait(inner)` takes the guard, releases the lock while sleeping, and returns the guard with the lock held again. Because the guard is *moved* into `wait` and handed back, `inner` can never be used without the lock. `unwrap_or_else(|e| e.into_inner())` keeps using the data even if the lock is poisoned (a thread panicked while holding it); the engine's `host.rs` takes the opposite approach and fails.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `loop` is an expression, and `break job` supplies its value. The guard is dropped at `};`, so the lock is released *before* the job runs.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **`mem::replace`.** A boxed `FnOnce` must be called by value, but `job` is still needed afterwards for `finish`. So the closure is swapped out and a harmless placeholder left in its place; `Box::new(String::new)` works because `String::new` is itself an `FnOnce() -> String`.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **A drop guard.** `struct Slot`, whose `Drop` decrements `LIVE_WORKERS`, runs however the loop exits: by `return`, by falling off the end, or, in builds that unwind, by a panic. It's `try/finally` without the `finally` block. `self: Arc<Self>` means each worker thread owns its own `Arc` handle to the shared state.
- *[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* A cancelled or expired job never reaches the engine. Otherwise `submitted(job.submission.clone(), run)` sets a *thread-local* in `myotis-net` for the duration of the call (below).

**myotis-net/src/el/request.rs: the bridge the worker calls** · `rust/myotis-net/src/el/request.rs` · lines 33–52

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

*[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **How the deadline and cancellation flag reach the network code.** `submitted` stores the `Submission` in a thread-local and restores the previous value through a drop guard (`Restore`), even on an early exit. The closure then checks its arguments and calls the C ABI → `host.rs` → `rt.block_on(…)`. `block_on` runs the request future *on this same thread*, so when `Operation::new` (request.rs lines 68–87) reads `SUBMISSION`, it sees Node's values, takes the earlier of the two deadlines, and `Operation::check` watches the cancellation flag. The engine re-exports both names as `myotis_engine::capi::{submitted, Submission}`, which is how scheduler.rs imports them.

#### Results back to JavaScript

`rust/myotis-node/src/scheduler.rs` · lines 245–288

```rust
/// Enqueue under the producer/cleanup mutex. Unexpected failure returns the
/// still-owned completion for a JS-thread caller; workers must fail the invariant.
fn post_completion(inner: &mut Inner, job: Job, value: String) -> Option<Completion> {
    if let Some(tsfn) = inner.tsfn {
        let completion = Box::into_raw(Box::new(Completion {
            deferred: job.deferred,
            value,
        }));
        // Nonblocking: a worker NEVER needs the JS thread to make progress.
        // Admission bounds this otherwise-unbounded TSFN queue to CAPACITY.
        let status = unsafe {
            sys::napi_call_threadsafe_function(
                tsfn as sys::napi_threadsafe_function,
                completion.cast(),
                sys::ThreadsafeFunctionCallMode::nonblocking,
            )
        };
        if status != sys::Status::napi_ok {
            let failed = unsafe { *Box::from_raw(completion) };
            if status == sys::Status::napi_closing {
                // No more Node-API operations on a closing TSFN. The env
                // cleanup hook owns worker joins and remaining bookkeeping.
                inner.tsfn = None;
                inner.closing = true;
                decrement_pending(inner);
                for (_, token) in inner.requests.values() {
                    token.store(true, Ordering::Release);
                }
            } else {
                // Queue-full is impossible (max_queue_size=0); invalid-arg
                // indicates a broken lifetime invariant. There is no safe
                // JS-thread delivery path through an invalid TSFN.
                inner.poisoned = true;
                for (_, token) in inner.requests.values() {
                    token.store(true, Ordering::Release);
                }
                return Some(failed);
            }
        }
    } else {
        decrement_pending(inner);
    }
    None
}
```

`rust/myotis-node/src/scheduler.rs` · lines 79–91

```rust
unsafe extern "C" fn complete(
    env: sys::napi_env,
    _callback: sys::napi_value,
    context: *mut c_void,
    data: *mut c_void,
) {
    if data.is_null() {
        return;
    }
    let completion = unsafe { Box::from_raw(data.cast::<Completion>()) };
    let state = unsafe { &*context.cast::<Arc<State>>() };
    deliver_completion(env, state, *completion);
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* **Handing a `Box` to C and back.** `Box::into_raw` gives up ownership and produces a raw pointer that Node queues. On the JS thread, `complete` takes ownership back with `Box::from_raw`, and `*completion` moves the value out of the box. If the hand-off fails, the box is reclaimed immediately (`*Box::from_raw(completion)`), so nothing leaks and nothing is freed twice.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **Non-blocking on purpose.** A worker never waits for the JS thread. The TSFN queue itself is unbounded, and admission's limit of 32 is what bounds it.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* If a Node-API call fails, the scheduler is marked `poisoned` and refuses new requests. A broken invariant on a worker thread ends in `fatal_completion() -> !` (lines 735–746), which calls `napi_fatal_error` and then `abort`. The `!` ("never") return type tells the compiler the function doesn't come back.

#### Submitting and cancelling

`rust/myotis-node/src/scheduler.rs` · lines 639–669

```rust
pub fn submit<'env>(
    env: &'env Env,
    handle: i64,
    run: impl FnOnce() -> String + Send + 'static,
) -> Result<Object<'env>> {
    let deadline = Instant::now() + BUDGET;
    let state = state(env)?;
    let mut deferred = std::ptr::null_mut();
    let mut promise = std::ptr::null_mut();
    // Promise hooks may synchronously reenter the addon. Never hold our lock
    // while creating or settling a Promise.
    check(unsafe { sys::napi_create_promise(env.raw(), &mut deferred, &mut promise) })?;
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    let error = if !inner.handles.contains(&handle) {
        Some("handle does not belong to this environment")
    } else if inner.closing {
        Some("environment closing")
    } else if inner.poisoned {
        Some("native scheduler poisoned")
    } else if inner.pending >= CAPACITY
        || inner
            .requests
            .values()
            .filter(|(h, _)| *h == handle)
            .count()
            >= PER_HANDLE
    {
        Some("native scheduler busy")
    } else {
        None
    };
```

`rust/myotis-node/src/scheduler.rs` · lines 670–716

```rust
    if let Some(error) = error {
        drop(inner);
        let json = format!(r#"{{"error":"{error}"}}"#);
        let mut value = std::ptr::null_mut();
        check(unsafe {
            sys::napi_create_string_utf8(
                env.raw(),
                json.as_ptr().cast(),
                json.len() as isize,
                &mut value,
            )
        })?;
        check(unsafe { sys::napi_resolve_deferred(env.raw(), deferred, value) })?;
    } else {
        let next_id = inner
            .next_id
            .checked_add(1)
            .ok_or_else(|| Error::from_reason("request id exhausted"))?;
        if inner.pending == 0 {
            if let Some(tsfn) = inner.tsfn {
                check(unsafe {
                    sys::napi_ref_threadsafe_function(
                        env.raw(),
                        tsfn as sys::napi_threadsafe_function,
                    )
                })?;
            }
        }
        let id = inner.next_id;
        inner.next_id = next_id;
        let cancelled = Arc::new(AtomicBool::new(false));
        inner.pending += 1;
        inner.requests.insert(id, (handle, Arc::clone(&cancelled)));
        inner.queue.push(Job {
            id,
            handle,
            deferred: deferred as usize,
            submission: Submission {
                deadline,
                cancelled,
            },
            run: Box::new(run),
        });
        state.changed.notify_all();
    }
    unsafe { Object::from_napi_value(env.raw(), promise) }
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* The Promise is created *before* taking the lock, because Promise hooks may call back into the addon. A refused request still gets a Promise, resolved at once with `{"error"}`; `drop(inner)` releases the lock before that. The first pending request "refs" the TSFN, which keeps Node's process alive until the work is delivered.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Interior mutability](01-primer.md#primer-interior-mutability)* `Arc::new(AtomicBool::new(false))` is shared between the request table (so `cancel_handle` can set it) and the job's `Submission` (so the engine can check it). `checked_add` turns id overflow into an error instead of wrapping.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* Raw Node-API calls (`sys::napi_create_promise`, `napi_resolve_deferred`) are each wrapped in `check(…)?`, which maps a status code to a `Result`. `run: impl FnOnce() -> String + Send + 'static` in argument position is a generic parameter written briefly; `Box::new(run)` then erases the concrete type into a `Work`.

`rust/myotis-node/src/scheduler.rs` · lines 607–637

```rust
pub fn cancel_handle(env: &Env, handle: i64, remove: bool) -> Result<Cancellation> {
    let state = state(env)?;
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    if !inner.handles.contains(&handle) {
        drop(inner);
        return Ok(Cancellation {
            state,
            owned: false,
            failed: Vec::new(),
        });
    }
    for (h, token) in inner.requests.values() {
        if *h == handle {
            token.store(true, Ordering::Release);
        }
    }
    let failed = cancel_queued(&mut inner, Some(handle));
    state.changed.notify_all();
    while inner.queue.is_active(handle) {
        inner = state.changed.wait(inner).unwrap_or_else(|e| e.into_inner());
    }
    if remove {
        inner.handles.remove(&handle);
    }
    drop(inner);
    Ok(Cancellation {
        state,
        owned: true,
        failed,
    })
}
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency)* `cancel_handle` sets the flags of that handle's running requests, removes its queued jobs (their Promises resolve with "request cancelled"), and then waits on the `Condvar` until the handle's running job returns. That wait blocks the JS event loop. Native work that can't be interrupted may take longer than 90 s, a trade-off the README states plainly: cleanup "cannot preempt indivisible work", and a host that needs a hard shutdown deadline needs a separate process. `drop(inner)` releases the lock explicitly before the struct is built.

`rust/myotis-node/src/scheduler.rs` · lines 394–421

```rust
fn state(env: &Env) -> Result<Arc<State>> {
    let key = env.raw() as usize;
    if let Some(state) = ENVS.with(|envs| envs.borrow().get(&key).cloned()) {
        return Ok(state);
    }
    // TSFN creation may invoke async_hooks synchronously before ENVS can
    // publish a fully initialized state. Refuse recursive initialization rather
    // than create a second owner whose handles the outer insertion would lose.
    // Calling initialization/read APIs from that hook is unsupported. The error
    // thrown here is process-fatal if an async_hooks init hook doesn't catch it;
    // owns()-gated lifecycle/status calls return false/{} during this window.
    if !INITIALIZING.with(|initializing| initializing.borrow_mut().insert(key)) {
        return Err(Error::from_reason("Myotis scheduler initializing"));
    }
    struct Initializing(usize);
    impl Drop for Initializing {
        fn drop(&mut self) {
            INITIALIZING.with(|initializing| {
                initializing.borrow_mut().remove(&self.0);
            });
        }
    }
    let _initializing = Initializing(key);
    LIVE_WORKERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n + WORKERS <= MAX_WORKERS).then_some(n + WORKERS)
        })
        .map_err(|_| Error::from_reason("Myotis environment worker limit reached"))?;
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **A lock-free reservation.** `fetch_update` is a compare-and-swap loop: the closure proposes `n + 2` and returns `None` (via `bool::then_some`) when the process-wide cap of 8 would be exceeded, so at most four environments can have workers. `Initializing` is another drop guard, which clears its flag even when a `?` returns early. An environment is identified by the numeric value of its `napi_env` pointer. The rest of `state` (lines 422–569) creates a preallocated fallback error, the TSFN (its context is a `Box<Arc<State>>` handed to Node and freed in `finalize`), the two threads, and finally the environment cleanup hook; every failure path undoes what was already done.

## Checkpoint

12 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-node-q1"></a>

**Q1** · Multiple choice

`request_account_json` returns a Promise and passes `move || …` to `scheduler::submit`. Why must that closure be `move`, `Send` and `'static`?

- **A.** napi-rs requires every closure to be `move`
- **B.** `'static` makes the closure faster to call
- **C.** It runs later on one of the addon's worker threads, after the JS call has returned, so it must own everything it uses and be allowed to cross threads
- **D.** So that it can be called several times

[Answer →](answers.md#a-node-q1)

<a id="q-node-q2"></a>

**Q2** · Multiple choice

Why does `create` bind `let (Ok(n), Ok(d)) = (c_arg(&network), c_arg(&data_dir))` before calling `myotis_create(n.as_ptr(), d.as_ptr())`?

- **A.** `as_ptr()` only borrows the `CString`'s buffer, and the compiler doesn't tie the raw pointer to it. A pointer taken from a temporary `CString` in one statement dangles in the next, because the temporary is freed at the end of its statement
- **B.** It's only style
- **C.** `as_ptr()` copies the string
- **D.** Because `c_arg` is async

[Answer →](answers.md#a-node-q2)

<a id="q-node-q3"></a>

**Q3** · Written answer

The admission queue holds jobs for handles `[1, 1, 2]` (in that order) and handle 1 already has a running job. What does `take_ready()` return, and why does its body compile even though it reads `self.queued` and `self.active` and then mutates `self.queued`?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-node-q3)

<a id="q-node-q4"></a>

**Q4** · Multiple choice

Why does `Job` store the Promise handle as `deferred: usize` instead of a raw pointer?

- **A.** `usize` is smaller
- **B.** Node-API returns integers
- **C.** To enable arithmetic on it
- **D.** A `Job` moves to a worker thread, so all its fields must be `Send`. Raw pointers aren't `Send`, integers are; the value is cast back to a pointer where Node-API is called

[Answer →](answers.md#a-node-q4)

<a id="q-node-q5"></a>

**Q5** · Multiple choice

In the worker loop, what does `inner = self.changed.wait(inner)` do?

- **A.** Takes the mutex guard, releases the lock while the thread sleeps, and returns a guard with the lock re-acquired when notified. It's Java's `wait()`, but the guard hand-off makes it impossible to touch `inner` without the lock
- **B.** Busy-waits while holding the lock
- **C.** Creates a new mutex
- **D.** Spawns another worker

[Answer →](answers.md#a-node-q5)

<a id="q-node-q6"></a>

**Q6** · Written answer

Why does the worker call `std::mem::replace(&mut job.run, Box::new(String::new))` instead of simply calling `(job.run)()`?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-node-q6)

<a id="q-node-q7"></a>

**Q7** · Written answer

Explain how a request's 90-second deadline and cancellation flag, created in `scheduler::submit` on the JS thread, reach the engine's network code in `myotis-net`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-node-q7)

<a id="q-node-q8"></a>

**Q8** · Multiple choice

How does a worker's result string get to the JS thread?

- **A.** The worker calls the JS callback directly
- **B.** Through a tokio channel
- **C.** `finish` boxes a `Completion`, turns it into a raw pointer with `Box::into_raw`, and queues it with `napi_call_threadsafe_function` (non-blocking). On the JS thread, `complete` takes ownership back with `Box::from_raw` and resolves the Promise
- **D.** Through a shared global string

[Answer →](answers.md#a-node-q8)

<a id="q-node-q9"></a>

**Q9** · Multiple choice

A JS caller passes the address `"0x1234"` to `requestAccountJson` on a handle it owns. What happens?

- **A.** A JS exception is thrown at once
- **B.** The engine is called and decides
- **C.** The Promise resolves to a code-less `{"error"}` object, which a host should retry
- **D.** The Promise resolves to `{"error":"invalid address (expected 20-byte hex)","code":-32602}`, produced on a worker before the engine is called

[Answer →](answers.md#a-node-q9)

<a id="q-node-q10"></a>

**Q10** · Written answer

In `fee_history_json`, explain the type of `reward_percentiles(&percentiles).map(|p| c_arg(&p))` and what each of the three match arms means.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-node-q10)

<a id="q-node-q11"></a>

**Q11** · Multiple choice

Why does `getBlockByNumberJson` refuse the selector `"23500000"` instead of passing it on?

- **A.** The engine reads a bare-digit selector as hex, so a JS caller who meant decimal would get a block far past the head, or silently the wrong block
- **B.** Block numbers above 2³² are unsupported
- **C.** Only tags are accepted
- **D.** Strings longer than 6 characters are refused

[Answer →](answers.md#a-node-q11)

<a id="q-node-q12"></a>

**Q12** · Written answer

`pause` calls `scheduler::cancel_handle(env, handle, false)?` before `myotis_pause`. What does `cancel_handle` do, and why does it block the JS thread?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-node-q12)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
