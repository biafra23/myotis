# myotis-engine: the boundary

*Stop 16 · crate `myotis-engine`* · 9 files · 12,941 lines · about 190 minutes

This is where Kotlin, Swift, JavaScript and other Rust binaries meet the engine. Four host routes lead through two thin export files into one big file, `host.rs`. It owns the process's only engine tokio runtime and a registry of chain handles, and exposes every contract operation as a plain blocking function: strings and integers in, a JSON string, a `bool` or a negative sentinel out. Exceptions and panics never cross the boundary. The C half of the boundary is the one place in the codebase where raw pointers are handed to foreign code.

## Rust you will practise

- **Blocking meets async** `rt.block_on` on a foreign thread, `rt.enter()` and `rt.spawn` from outside the runtime, and why a lock must never be held across `block_on`.
- **Ownership across a C boundary** `CString::into_raw` / `from_raw`, `CStr`, `unsafe extern "C"` and its `# Safety` contract, and one `unsafe` call into libc.
- **Global state** `static OnceLock<…>`, `static AtomicU8`, `std::sync::Once`, an enum state machine inside a `Mutex<HashMap>`, and moving values out of a map.

### Four routes, two doors

Every host ends up in `host.rs`, but there are two doors into it. `ffi.rs` is the UniFFI surface: ordinary Rust functions marked `#[uniffi::export]`. `capi.rs` is a hand-written C ABI. Which door a host takes depends on what it can link against.

- **JVM** (the Android app, the desktop app, the daemon, and the engine library `eth.myotis:myotis-engine` that a separate wallet consumes): `RustEngineNative` in `:myotis-engine-rust` calls the UniFFI-generated Kotlin in `myotis_engine.kt`, which calls `libmyotis_engine` through JNA. That reaches `ffi.rs`. Stop 17 ([UniFFI end to end](17-uniffi.md)) takes this route apart; here it is a black box.
- **iOS**: `:myotis-engine-ios` runs Kotlin/Native cinterop over the hand-kept header `rust/include/myotis_engine.h`. Its `RustEngine.kt` calls the `myotis_*` functions in `capi.rs`, statically linked from `libmyotis_engine.a`.
- **Node and Electron**: `myotis-node` (napi-rs, [Stop 18](18-node.md)) links this crate as an `rlib` and calls the `capi` functions by Rust path.
- **The standalone daemon** `myotis-rpcd` ([Stop 19](19-rpcd.md)) is new since September. It also links the `rlib`, but calls the `ffi` functions by Rust path, as plain Rust functions. It uses `capi` only for the two functions UniFFI does not export: `myotis_set_boot_enodes` and `myotis_create_with_checkpoint`.

A `#[uniffi::export]` function stays an ordinary `pub fn`; the macro only adds a C-callable twin beside it. That is why `myotis-rpcd` and the example binary at the end of this stop can call `ffi::create_handle(String, String)` directly, with no FFI in between.

![Four host routes into the engine. The JVM calls ffi.rs through UniFFI-generated Kotlin over JNA. myotis-rpcd calls ffi.rs by Rust path. iOS calls capi.rs through a C header and cinterop. Node and Electron call capi.rs by Rust path from myotis-node. ffi.rs and capi.rs both call host.rs with strings and integers. host.rs blocks the calling thread in rt.block_on while the tokio runtime's own threads run the sync loop, EL reader and appender tasks; results are serialized by eljson.rs, data usage is kept by usage.rs, and the answer returns as a JSON string, bool or negative sentinel.](img/16-engine-1.svg)

*Every route ends in the same `host.rs` functions. The caller's thread (a JVM, iOS, Node or rpcd thread) blocks in `rt.block_on`, while long-lived work runs on the runtime's own threads. Only strings, integers and booleans cross the boundary; compound values are JSON whose shape is pinned by golden tests on both sides.*

> [!TIP]
> **No HTTP server in this crate**<br>
>
> The engine answers function calls, not HTTP. The JVM apps' loopback JSON-RPC listener is a port, `LoopbackRpc`, in `:myotis-engine-rust`; the `:myotis-engines` selector fills it with `KtorLoopbackRpc`. An in-process consumer of the engine library (`Myotis.newEngine()`) gets no listener at all and calls `reads()` directly. `myotis-rpcd` brings its own JSON-RPC server, in Rust. All three end in the functions on this page.

> [!NOTE]
> **What changed since September**<br>
>
> `ABI_VERSION` went from 26 to 55. The UniFFI surface grew from 38 to 55 exports and the C ABI from 40 to 58 functions: `eth_getProof`, block-hash resolution, raw transactions, the full transaction object for `eth_call` / `eth_estimateGas` / `eth_createAccessList`, `debug_traceCall`, `eth_simulateV1`, a send gate, DNS discovery, data usage, address activity and Tor storage directories. The catalog gained Chiado (four networks, all hosted), and Gnosis now has names (`.gno`). `host.rs` doubled to 7,199 lines; `EngineState` went from 7 fields to 15. `usage.rs` is new. The NULL-`to` inconsistency in `myotis_eth_call_json` that the old tour flagged was fixed in ABI 29.

<a id="f-myotis-engine-src-lib-rs"></a>

### myotis-engine/src/lib.rs

*crate root · 406 lines · Java twin · RustEngineNative.EXPECTED\_ABI\_VERSION*

Declares the modules, expands UniFFI's crate-level scaffolding, and defines `ABI_VERSION` (now 55), the number every host checks at startup. Most of the file's 406 lines are that constant's doc comment: one entry per version since v2, a changelog of every surface change. The crate is built as a `cdylib` (loaded by JNA), as an `rlib` (linked by `myotis-node` and `myotis-rpcd`), and, via Gradle, as an iOS `staticlib`. It is the library crate that *builds and owns* a tokio runtime for its hosts.

`rust/myotis-engine/src/lib.rs` · lines 16–29

```rust
// Public: the plain C ABI doubles as the in-process seam for Rust hosts (the
// napi-rs Node binding in `myotis-node` calls these by Rust path — linking the
// rlib does not reliably resolve `extern "C"` imports of no_mangle symbols).
pub mod capi;
pub mod catalog;
mod eljson;
pub mod ffi;
mod host;
mod usage;
pub mod ringlog;

// UniFFI scaffolding (checksums, FFI glue) for the `ffi` exports; must be invoked
// at the crate root — `#[uniffi::export]` resolves its `UniFfiTag` here.
uniffi::setup_scaffolding!();
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Visibility at the module line.** Each `mod x;` pulls `x.rs` into the module tree, and that line decides its visibility. `pub mod capi` and `pub mod ffi` are reachable from other crates; `mod host`, `mod eljson` and `mod usage` are visible only inside this one, like a package whose classes are all package-private. So `myotis-rpcd` can call `myotis_engine::ffi::status_json` but not `myotis_engine::host::status_json`.
- *[Macros & attributes](01-primer.md#primer-macros) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `uniffi::setup_scaffolding!()` expands into whole items at the crate root: a tag type, checksum functions and `#[no_mangle]` glue that the generated Kotlin calls. `#[uniffi::export]` in `ffi.rs` refers back to that tag. The details are in [Stop 17](17-uniffi.md).

`rust/myotis-engine/src/lib.rs` · lines 384–406

```rust
/// v54: `debug_traceCall` (#716). `debug_trace_call_json` (UniFFI and the C
///      ABI: `myotis_debug_trace_call_json`): the run `eth_call_tx_json` makes
///      for a transaction object, seen through geth's `callTracer` or
///      `prestateTracer`, as `{"status":"ok","trace":…}`. An additive function
///      — bumped so a host that serves `debug_traceCall` is never paired with
///      an engine that lacks it.
/// v55: `eth_simulateV1` (#716). `simulate_v1_json` (UniFFI and the C ABI:
///      `myotis_simulate_v1_json`): blocks of calls simulated on top of a
///      verified block, as geth simulates them, as
///      `{"status":"ok","result":[…]}` with geth's `result`, or geth's own
///      simulation error as `{"status":"failed","code","message"}`. An
///      additive function — bumped so a host that serves `eth_simulateV1` is
///      never paired with an engine that lacks it.
pub const ABI_VERSION: i32 = 55;

// Keep the workspace edge alive so `cargo build -p myotis-engine` type-checks the
// consensus crate too.
pub use myotis_consensus::bls_dst;

/// The most storage keys one `eth_getProof` serves — for hosts that check a
/// request before handing it on (myotis-rpcd), so they refuse what the engine
/// would.
pub use myotis_net::el::getproof::MAX_PROOF_STORAGE_KEYS;
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Bump on every shape change.** The last two entries show the house rule: an *additive* function still bumps the version, "so a host that serves `eth_simulateV1` is never paired with an engine that lacks it". On the JVM the number is a backup check, because UniFFI's per-function checksums fail first when a stale library is loaded. For the iOS C ABI it is the main check: `RustEngine.EXPECTED_ABI_VERSION` is read from the header's `MYOTIS_ABI_VERSION`, and a test in `capi.rs` pins the header to this constant.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `pub use` re-exports an item from a dependency under this crate's name. `MAX_PROOF_STORAGE_KEYS` is re-exported so `myotis-rpcd` can refuse an oversized `eth_getProof` before it reaches the engine, without depending on `myotis-net` itself. `bls_dst` is re-exported only to keep the consensus crate in the build graph.

<a id="f-myotis-engine-src-catalog-rs"></a>

### myotis-engine/src/catalog.rs

*engine · 136 lines · Java twin · NetworkConfig.allNetworks() / NetworkInfo*

The built-in network list: a `const` array of four records (mainnet, gnosis, sepolia, chiado), serialized to the same camelCase JSON as `io.myotis.api.NetworkInfo`, plus alias resolution (`xdai` and `gbc` → `gnosis`). The golden file `rust/testdata/networks_catalog.json` is compared byte for byte here and parsed by the Java side's `NetworksJsonGoldenTest`. A new test pins `has_ens` to the EVM crate's name-tree table, so a network cannot offer names its engine refuses. Gnosis now has names (Genome's `.gno`); Chiado has none.

`rust/myotis-engine/src/catalog.rs` · lines 10–23

```rust
/// Mirrors `io.myotis.api.NetworkInfo` (see its javadoc for field semantics).
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    pub name: &'static str,
    pub display_name: &'static str,
    pub chain_id: u64,
    pub has_ens: bool,
    pub default_el_port: u16,
    pub default_discv5_port: u16,
    pub default_rpc_port: u16,
    pub cl_genesis_time: u64,
    pub seconds_per_slot: u32,
}
```

`rust/myotis-engine/src/catalog.rs` · lines 83–97

```rust
/// Resolve a name or alias (case-insensitive; `xdai`/`gbc` → `gnosis`) to the
/// canonical name, mirroring the Java engine's `canonicalNetworkName`. `None` for
/// unknown networks (the Java wrapper turns that into an `EngineException`).
/// Deliberately NO trim(): the Java reference (`NetworkConfig.byName`) doesn't trim,
/// and the two engines must reject exactly the same inputs.
pub fn canonical_network_name(name_or_alias: &str) -> Option<&'static str> {
    match name_or_alias.to_ascii_lowercase().as_str() {
        "mainnet" => Some("mainnet"),
        "gnosis" | "gbc" | "xdai" => Some("gnosis"),
        "sepolia" => Some("sepolia"),
        "chiado" => Some("chiado"),
        // holesky retired: the EF shut it down in Oct 2025.
        _ => None,
    }
}
```

- *[Macros & attributes](01-primer.md#primer-macros) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `#[derive(Serialize)]` generates the JSON writer at compile time: Jackson without reflection. `rename_all = "camelCase"` maps `display_name` to `displayName`.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [Ownership & moves](01-primer.md#primer-ownership)* Every field is `Copy`. A `&'static str` is a pointer and a length into the binary's read-only data. So the whole struct is `Copy` and can live in a `const` with no heap allocation. A `String` field would own heap memory and make both impossible.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* In `canonical_network_name`, the lowercase `String` is a temporary, borrowed only while the `match` runs. Every arm returns a *literal*, so the result can be `'static` and never points into the temporary. `|` separates alternative patterns. Input is deliberately not trimmed, so both engines reject exactly the same inputs.

<a id="f-myotis-engine-src-ringlog-rs"></a>

### myotis-engine/src/ringlog.rs

*engine · 175 lines*

A process-wide ring of the last 4,096 `tracing` lines, which hosts drain on a timer into their own logs (Android's Logs tab and logcat, slf4j on desktop). Before it existed, Rust logs were invisible on Android. Pulling instead of pushing means no callbacks into the host, no Android dependencies, bounded memory, and no panics. The file is unchanged since September.

`rust/myotis-engine/src/ringlog.rs` · lines 23–27

```rust
static RING: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn ring() -> &'static Mutex<VecDeque<String>> {
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(256)))
}
```

`rust/myotis-engine/src/ringlog.rs` · lines 51–95

```rust
/// Drain up to `max` buffered lines, oldest first, newline-joined. Empty string
/// when nothing is buffered. Cheap to call on a poll loop.
pub fn drain(max: usize) -> String {
    let Ok(mut ring) = ring().lock() else {
        return String::new();
    };
    let n = ring.len().min(max);
    if n == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(n * 96);
    for _ in 0..n {
        // n <= len is checked above; pop_front can't fail here.
        if let Some(line) = ring.pop_front() {
            out.push_str(&line);
            out.push('\n');
        }
    }
    // Drop the trailing newline so the Java side can split('\n') cleanly.
    out.pop();
    out
}

/// `tracing_subscriber::fmt` writer: one `write` call per formatted event.
struct RingWriter;

impl Write for RingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf);
        let trimmed = line.trim_end();
        if !trimmed.is_empty() {
            if let Ok(mut ring) = ring().lock() {
                if ring.len() >= CAPACITY {
                    ring.pop_front(); // oldest-out — bounded memory beats history
                }
                ring.push_back(trimmed.to_string());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **A lazy, mutable global.** Every `static` must be safe to share between threads. `OnceLock` creates the value exactly once (its `new()` is a `const fn`, so no startup code runs), and the `Mutex` allows changes through the shared `&'static` reference. In Java terms, it's a `static final` holder whose contents can only be touched under `synchronized`, and the compiler enforces that.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `let Ok(mut ring) = ring().lock() else { return String::new(); };` means a poisoned lock degrades to "no lines" instead of an `unwrap()` panic, which in this workspace (`panic = "abort"`) would kill the host app.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `impl Write for RingWriter` is how `tracing` writes into the ring. `RingWriter` has no fields, so it takes no memory. `String::from_utf8_lossy` returns a `Cow`: borrowed when the bytes are valid UTF-8, allocated only when something has to be replaced. `trimmed.to_string()` then makes the owned copy the ring keeps.
- *[Protocol & domain](01-primer.md#primer-domain)* `write` reports success even when it drops a line, and anything logged before `init()` is lost.

<a id="f-myotis-engine-src-usage-rs"></a>

### myotis-engine/src/usage.rs

*engine · 394 lines · Java twin · DataUsageLedger (Java engine)*

New since September: data usage per handle (ABI 50, docs/data-usage.md). Each handle's `ChainConfig` carries a `TrafficMeter` from `myotis_net::traffic`, a set of byte counters that only grow. A `UsageLedger` turns those totals into per-day figures: every `tick` adds the growth since the previous tick to the current *local* day, and to the day's metered figures too when the host last said the network is metered. Today's figures are kept in `data-usage[-net].json` beside the sync snapshot, in a format the Java engine's ledger writes byte for byte, so the figures survive both a restart and an engine switch.

`rust/myotis-engine/src/usage.rs` · lines 56–68

```rust
static METERING: AtomicU8 = AtomicU8::new(Metering::Unknown as u8);

/// The metering the host reported last (engine-wide: it is the device's
/// network, not a chain's).
pub fn metering() -> Metering {
    Metering::from_code(METERING.load(Ordering::Relaxed) as i32).unwrap_or(Metering::Unknown)
}

/// Record the host's report. The caller ticks every ledger FIRST, so bytes
/// moved before the change are labelled by the old state.
pub fn set_metering(m: Metering) {
    METERING.store(m as u8, Ordering::Relaxed);
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* **An atomic global with no lock.** The metering is one byte for the whole process (it describes the device's network, not a chain), so a `static AtomicU8` holds it. Atomics are `Sync`, so a plain `static` works with no `OnceLock` or `Mutex`, and `AtomicU8::new` is a `const fn`. `Ordering::Relaxed` is enough because the value guards no other memory; Java's `getOpaque`/`setOpaque` on an `AtomicInteger` is the nearest analogue.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `Metering::Unknown as u8` works because the enum has explicit discriminants (`= 0`, `= 1`, `= 2`) and no data. The way back, `from_code`, is a `match` returning `Option`, because an integer can hold values no variant has. `#[default]` on a variant tells `#[derive(Default)]` which one to use.

`rust/myotis-engine/src/usage.rs` · lines 146–185

```rust
fn tick_on(&self, day: &str, metering: Metering, force: bool) -> UsageSnapshot {
    // The snapshot is taken under the lock: two ticks racing (the minute
    // ticker and a status read) must apply theirs in order, or `seen` could
    // step back and the bytes in between be counted twice.
    let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
    let now = self.meter.snapshot();
    let rx = now.rx().saturating_sub(st.seen.rx());
    let tx = now.tx().saturating_sub(st.seen.tx());
    st.seen = now;
    let new_day = st.day != day;
    if new_day {
        // The growth since the last tick lands on the new day: ticks are a
        // minute apart, so at most a minute's bytes cross midnight.
        st.day = day.to_string();
        st.today = DayTotals::default();
        st.dirty = true;
    }
    if rx > 0 || tx > 0 {
        st.today.rx = st.today.rx.saturating_add(rx);
        st.today.tx = st.today.tx.saturating_add(tx);
        if metering == Metering::Metered {
            st.today.metered_rx = st.today.metered_rx.saturating_add(rx);
            st.today.metered_tx = st.today.metered_tx.saturating_add(tx);
        }
        st.dirty = true;
    }
    let due = st.last_write.is_none_or(|t| t.elapsed() >= WRITE_EVERY);
    if st.dirty && (force || new_day || due) {
        if let Some(path) = &self.path {
            match write_file(path, &st.day, st.today) {
                Ok(()) => {
                    st.dirty = false;
                    st.last_write = Some(Instant::now());
                }
                Err(e) => tracing::debug!(path = %path.display(), error = %e, "data-usage write failed"),
            }
        }
    }
    UsageSnapshot { session: now, day: st.day.clone(), today: st.today }
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **Read the counter under the lock.** The comment explains a race Java code would have too: the minute ticker and a status read may tick at the same moment. If each read `meter.snapshot()` before taking the lock, the later one could store an older `seen` and count bytes twice. Taking the snapshot inside the critical section orders them.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Interior mutability](01-primer.md#primer-interior-mutability)* `lock().unwrap_or_else(|e| e.into_inner())` is the other way to treat a poisoned mutex: take the guard anyway. `PoisonError::into_inner` returns it. That is safe here because the state is a few counters that cannot be left half-updated in a way that matters; `ringlog` chooses to give up instead.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* `st` is a `MutexGuard<LedgerState>`; through it, `st.today.rx = …` writes into the locked state. `DayTotals` is `Copy`, so `today: st.today` in the returned snapshot copies four integers, while `st.day.clone()` must copy the `String` explicitly. The guard is dropped at the closing brace, after the return value is built.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `st.last_write.is_none_or(|t| t.elapsed() >= WRITE_EVERY)`: true for "never written" or "written long enough ago". `saturating_sub` / `saturating_add` stop at 0 and `u64::MAX` instead of wrapping; a counter that moved backwards would otherwise wrap to a huge number.

`rust/myotis-engine/src/usage.rs` · lines 238–253

```rust
/// `epoch_secs` as a local date (`localtime_r`, so the C library's notion of
/// the zone: `TZ`, `/etc/localtime`, Android's `persist.sys.timezone`, the iOS
/// system zone). UTC where that fails or there is no C library to ask.
fn local_day(epoch_secs: i64) -> String {
    #[cfg(unix)]
    {
        let t = epoch_secs as libc::time_t;
        // SAFETY: `tm` is plain old data, fully written by a successful
        // localtime_r, which reads only `t` and is thread-safe.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            return format!("{:04}-{:02}-{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
        }
    }
    utc_day(epoch_secs)
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **One call into libc.** Rust's standard library has no time zones, so `local_day` asks the C library with `localtime_r`. `std::mem::zeroed()` is `unsafe` because an all-zero bit pattern is not a valid value for every type (a reference or a `NonZeroU32` would be undefined behavior); for the plain C struct `libc::tm` it is fine, which is what the `SAFETY:` comment states. `localtime_r` itself is `unsafe` because it is a foreign function taking raw pointers; `&t` and `&mut tm` coerce to them. `#[cfg(unix)]` removes the block entirely on other targets, where the UTC fallback below (Howard Hinnant's date algorithm) is the only path.

*[Ownership & moves](01-primer.md#primer-ownership)* In `open_on` (lines 119–138), the struct literal names `state` first and `meter` last. Fields are evaluated in the order written, so `meter.snapshot()` borrows `meter` before the next field moves it into the struct. Swapping the two lines would not compile: "borrow of moved value".

<a id="f-myotis-engine-src-host-rs"></a>

### myotis-engine/src/host.rs

*engine core · 7,199 lines · Java twin · ChainStack lifecycle (+ RustChainHandle caller)*

Behind every FFI entry point sits one engine for the whole process. It owns a multi-threaded tokio runtime and a registry of chain handles, and each contract operation (lifecycle, status, settings, verified reads, the EVM calls, ENS, transactions, the `eth_getLogs` index, address activity) is a blocking function. The file enforces the trust-anchor rules for data directories used by `create_with_checkpoint` (#441), applies or refuses every block selector, and parses all untrusted input without panicking. 87 of its tests sit in eight test modules; none starts networking.

#### Section map

| Lines | What happens |
|---|---|
| 1–62 | Module doc (lifecycle, panic policy), imports, the sentinels −1 `CREATE_FAILED`, −2 `UNSUPPORTED_NETWORK`, −3 `ANCHOR_MISMATCH`. |
| 64–215 | `enum ChainEntry`, `struct EngineState` (15 fields), `static ENGINE` and `engine()`. |
| 217–291 | `config_for` (four networks); process-wide switches: Tor (`cfg(feature = "tor")`), Tor storage directories, DNS discovery. |
| 293–672 | `create`, `create_with_checkpoint`, data-directory guards, anchor markers, `register` (which also opens the usage ledger). |
| 674–993 | `spin_up` (shared by `start` and `resume`), replay of stashed host settings, `pause`, `shutdown`. |
| 995–1215 | `status_json`, `ElCounts`, the per-handle EL and CL fork watches and the EL carry. |
| 1217–1339 | `stop`; the data-usage glue (ledger lookup, minute ticker, network metering). |
| 1341–1511 | Live settings: served block window, host seed pins (`set_boot_enodes_json`), weak-subjectivity bound, stale-anchor consent. |
| 1513–1800 | State reads with a block selector: account, storage, code, storage-at, `eth_getProof`. |
| 1802–2161 | The `eth_call` family; `call_target`; `BlockSelector`, `parse_call_block`, `CallBlockRefusal`, `check_call_block`; state overrides. |
| 2163–2321 | ENS forward resolution and the generic record dispatch, including the CCIP-Read callback. |
| 2323–2975 | Gas estimates and the transaction-object calls (`eth_call_tx`, `eth_createAccessList`, `debug_traceCall`, `eth_simulateV1`) with their parsers. |
| 2977–3238 | Blocks, receipts, transactions, the pending-nonce overlay, block-hash resolution, raw transactions. |
| 3240–3541 | Send and check raw transactions, fee estimate, block receipts, fee history with a stale cache, block-target parsing. |
| 3543–3804 | The `snapshot_reader*` helpers, ENS query parsing, hex parsers, `beacon_state`. |
| 3806–3958 | `Lifecycle`, `status_object`, `NOT_STARTED_FALLBACK`. |
| 3960–5282 | `mod tests`. |
| 5284–6212 | The `eth_getLogs` index (config, unwatch, import/export, status, query), the address-activity watch, read stats. |
| 6214–7199 | Seven more test modules: log-index JSON, send gate, call target, call block, `getLogs` filter, tracer config, the `eth_simulateV1` golden. |

#### The singleton and the state machine

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

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `ChainEntry` is a sealed class with data: `Created(config)`, `Running(config, sync, reader?)`, `Paused(config, frozen status, read stats)`. The map entry is the *only* owner of the `SyncHandle`. The config, the reader and the read stats are behind `Arc`, so a caller can copy a pointer out and work without holding the lock.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `Paused` gained an `Arc<ReadStats>` since September: the reader is dropped on pause, but its read counters must outlive it. Holding a second `Arc` to the same counters is all it takes; whoever drops the last `Arc` frees them.

`rust/myotis-engine/src/host.rs` · lines 154–175

```rust
    /// Serializes `create` / `create_with_checkpoint` end to end (in-use guard,
    /// anchor-marker read/write, registration). Every guard in those paths is
    /// check-then-act against the filesystem and the handle map; without one
    /// lock across all of it, two racing creates on the same dataDir could both
    /// pass and persist different generations into one snapshot. Creates are
    /// cold, so a coarse lock costs nothing (the JVM's `RustMyotisEngine.create`
    /// is `synchronized` for the same reason). Never held while `handles` is
    /// taken by anything that could wait on a create.
    create_lock: Mutex<()>,
    /// Snapshot paths whose handle has been removed from `handles` but whose
    /// sync loop is still being awaited by `stop` (teardown runs OUTSIDE the
    /// map lock). A loop in that window can still persist a snapshot, so the
    /// directory stays "in use" for the create guards until the await returns
    /// — otherwise a `createWithCheckpoint` slipping in between would label a
    /// late embedded-anchor snapshot as the caller's generation.
    tearing_down: Mutex<std::collections::HashSet<std::path::PathBuf>>,
    /// Per-handle data-usage ledger (`crate::usage`) over the handle's
    /// `ChainConfig::traffic`: created with the handle, ticked by every status
    /// read and by the minute ticker, written at pause and stop. Dies with the
    /// handle.
    usage: Mutex<HashMap<i64, Arc<UsageLedger>>>,
}
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Protocol & domain](01-primer.md#primer-domain)* **One lock per concern.** `EngineState` now has nine per-handle side maps beside `handles` (served window, seed pins, log-index runtime bits, activity watch, fee-history cache, the two fork watches, the EL carry, the usage ledger). Each is its own `Mutex<HashMap<i64, …>>`, so a status read touching the ledger never waits on a seed-pin push. The cost is discipline: every map must be cleared in `stop`, and the comments repeat "Dies with the handle" for that reason. Besides the `usage` map, the excerpt shows the two coarse locks: `create_lock` serializes every create, and `tearing_down` keeps a stopping handle's directory "in use" until its loop has finished writing.

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

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `static ENGINE: OnceLock<Option<EngineState>>`: `get_or_init` runs its closure once, even when several threads race. `None` means the runtime couldn't be built, so every entry point returns its failure value rather than panicking. Statics are never dropped, so the runtime lives until the process exits. `.as_ref()` turns `&Option<T>` into `Option<&T>`, and because the `Option` lives in a static, that reference is `&'static`.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* Handle ids come from an `AtomicI64` starting at 1, so a valid id can't be confused with −1, and ids are never reused. Locks are taken in the order `create_lock` → `handles` → `tearing_down`.

#### Create: a named guard

`rust/myotis-engine/src/host.rs` · lines 300–331

```rust
pub fn create(network_name: &str, data_dir: &str) -> i64 {
    let Some(engine) = engine() else {
        return CREATE_FAILED;
    };
    let mut config = match resolve_config(network_name) {
        Ok(c) => c,
        Err(sentinel) => return sentinel,
    };
    // Guard + register under one lock (see `EngineState::create_lock`).
    let Ok(_serial) = engine.create_lock.lock() else {
        return CREATE_FAILED;
    };
    if !data_dir.is_empty() {
        let dir = match bind_persistence(&mut config, data_dir) {
            Ok(d) => d,
            Err(sentinel) => return sentinel,
        };
        // A directory carrying a caller-supplied anchor belongs to that
        // generation: the embedded checkpoint is a different trust anchor, and
        // the snapshot-resume rule would happily continue from the caller's
        // verified state as if it descended from ours. Fail closed: only a
        // marker entry that is DEFINITELY absent lets the embedded anchor in —
        // a file, a dangling symlink, an unreadable entry, or one that cannot
        // even be stat'ed all refuse (same rule as create_with_checkpoint).
        if !marker_entry_absent(&anchor_marker_path(&dir, &config)) {
            tracing::warn!(data_dir, "dataDir was bootstrapped from a caller-supplied \
                checkpoint — refusing to create it from the embedded anchor");
            return ANCHOR_MISMATCH;
        }
    }
    register(engine, config)
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Ownership & moves](01-primer.md#primer-ownership)* **A named guard.** `let Ok(_serial) = engine.create_lock.lock() else { … };` binds the guard, so the lock is held until the function returns, which serializes every create end to end. The pattern `_` would bind nothing, and the guard would be dropped, releasing the lock, at the end of the statement. (`_serial` only suppresses the unused-variable warning.) `Mutex<()>` guards no data; it is purely a critical section.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `resolve_config` and `bind_persistence` return `Result<_, i64>` whose error *is* the sentinel to hand back, so `Err(sentinel) => return sentinel` passes it straight through. `&mut config` lends the config so `bind_persistence` can set its snapshot and peer-cache paths.
- *[Protocol & domain](01-primer.md#primer-domain)* **Fail closed.** A directory that carries a caller-supplied anchor marker belongs to that anchor. A plain `create` on it returns −3, because resuming it from the embedded checkpoint would silently swap trust anchors.

`rust/myotis-engine/src/host.rs` · lines 576–584

```rust
/// Whether the marker ENTRY is definitely absent. Judged on the directory entry
/// itself (`symlink_metadata`, never following links): a dangling symlink at
/// the marker path is an entry, not absence — following it would read ENOENT
/// and let a caller rebind the directory and overwrite the link
/// (freedom-browser#353). Any error other than NotFound also counts as
/// present (fail closed).
fn marker_entry_absent(path: &std::path::Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* `matches!(expr, pattern if guard)` is a `match` that yields `true` or `false`. Here only a definite `NotFound` counts as absent. `symlink_metadata` looks at the directory entry itself, so a dangling symlink is "present" (an issue reported from freedom-browser#353). Any other error, such as a permission problem, also counts as present. Uncertainty refuses.

#### Start and resume: the lock scope

`rust/myotis-engine/src/host.rs` · lines 703–739

```rust
fn spin_up(handle: i64, from: SpinUpFrom) -> bool {
    let Some(engine) = engine() else {
        return false;
    };
    // Take the config under the lock, then RELEASE it before entering the runtime.
    // Holding the map lock across block_on would serialize every other native
    // (status/stop/create) behind a potentially-slow start and invites deadlock on
    // future changes — even though SyncHandle::start is fast today (spawn + return).
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
    // The handle's CL fork watch rides into the loop on its config: created on
    // the first spin-up, reused (evidence intact) on every resume.
    let cl_watch = cl_fork_watch_for(engine, handle, &config);
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

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **A block as a lock scope.** The guard `map` lives only inside `let (config, read_stats) = { … };`. It is dropped at the `}`, so only two cheap `Arc` copies leave the locked region, and the slow start runs without the lock. Holding the map lock across `block_on` would stall every other FFI call and risk deadlock.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership)* **Two kinds of clone.** `Arc::clone(c)` increments a reference count. `(*config).clone()` dereferences the `Arc` and deep-copies the whole `ChainConfig`, because `SyncHandle::start` takes it by value. The copy still shares its inner `Arc`s (the `WsPolicy`, the traffic meter), which is how a settings call later reaches the running loop.
- *[async/await & tokio](01-primer.md#primer-async)* `SyncHandle::start` is not async, but it calls `tokio::spawn`, which only works inside a runtime. `block_on(async { … })` is there purely to be *inside* the runtime while it runs. It is not an `async move` block, so it captures by reference where it can: `config` is only borrowed. `cl_watch` is still taken by value, because the block assigns it into `cfg`.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match (from, map.get(&handle))` matches a tuple, so one match covers "the expected variant for this transition". `_ => return false` covers an unknown id or the wrong state.

*[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* The EL reader starts in a second `block_on` (lines 776–797). Its `async` block ends in `?` and `.await`: an `async` block has its own return type, here a `Result`, so `?` inside it returns from the block, not from `spin_up`. A reader that fails to start is not fatal: the chain runs on the consensus layer alone, and status reports `elReaderAvailable: false`.

`rust/myotis-engine/src/host.rs` · lines 843–893

```rust
    // Re-lock and publish ONLY if the entry is still the same Created/Paused one
    // we spun up from: a concurrent stop() may have removed it, or a racing
    // start()/resume() may have already published a Running one, while we were
    // starting. Either way, shut the handle we just started down rather than
    // orphan its tokio/libp2p host.
    let pins_reader = reader.clone();
    let mut map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => {
            shutdown(engine, sync, reader);
            return false;
        }
    };
    match (from, map.get(&handle)) {
        (SpinUpFrom::Created, Some(ChainEntry::Created(_)))
        | (SpinUpFrom::Paused, Some(ChainEntry::Paused(..))) => {
            map.insert(handle, ChainEntry::Running(config, sync, reader));
            drop(map);
            // The host's seed pins, applied AFTER the entry is Running (#465):
            // the pool was rebuilt from scratch, and the pins are the host's
            // answer to a starving pool. After, not before, the publish: a
            // push that lands while the reader is being built sees a
            // Created/Paused entry and only stashes, so reading the stash
            // here catches it, and a push from now on applies itself live.
            // Applying twice is idle (set semantics; `try_dial` dedups).
            apply_pending_boot_enodes(engine, handle, pins_reader.as_ref());
            true
        }
        _ => {
            // A concurrent stop() removed the handle while we were starting, so
            // the watch fork_watch_for() may have just re-inserted for it has no
            // owner left: drop it (ids are never reused). A racing start/resume
            // that already published keeps it — its reader holds the same Arc.
            let gone = map.get(&handle).is_none();
            drop(map);
            if gone {
                if let Ok(mut watches) = engine.fork_watches.lock() {
                    watches.remove(&handle);
                }
                if let Ok(mut watches) = engine.cl_fork_watches.lock() {
                    watches.remove(&handle);
                }
                if let Ok(mut carries) = engine.el_carries.lock() {
                    carries.remove(&handle);
                }
            }
            shutdown(engine, sync, reader);
            false
        }
    }
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Protocol & domain](01-primer.md#primer-domain)* **Publish only if nothing changed.** After the lock-free start, the entry is re-checked. If a concurrent `stop` removed it, or a racing start already published `Running`, the freshly built stack is shut down rather than orphaned. `(… Created(_)) | (… Paused(..))` is a single arm with two alternative patterns; `..` ignores the remaining fields.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `map.insert(handle, ChainEntry::Running(config, sync, reader))` *moves* `sync` and `reader` into the map. That is why `pins_reader = reader.clone()` is taken first: one more `Arc` (inside the `Option`) for the seed-pin replay after the publish. `drop(map)` releases the lock explicitly before that slow call.
- *[Protocol & domain](01-primer.md#primer-domain)* Lines 798–841, above this excerpt, replay what the host set while the handle was not running: the served-block window, the log-index runtime bits and the activity watch list. A pause drops the reader that held them, and no host re-pushes on resume, so the engine stashes each push per handle and re-applies it on every spin-up.

#### Pause: moving a value out of a map

`rust/myotis-engine/src/host.rs` · lines 929–981

```rust
pub fn pause(handle: i64) -> bool {
    let Some(engine) = engine() else {
        return false;
    };
    let (sync, reader) = {
        let mut map = match engine.handles.lock() {
            Ok(m) => m,
            Err(_) => return false,
        };
        // remove-then-reinsert (not get) because the teardown needs OWNERSHIP of
        // the SyncHandle; a non-Running entry is put back untouched.
        match map.remove(&handle) {
            Some(ChainEntry::Running(config, sync, reader)) => {
                let mut frozen = sync.status();
                // The frozen status keeps the warm STORE facts (state, slots,
                // periods) but must not keep live-CONNECTION facts: the libp2p
                // host and discovery are about to go down, and a paused status
                // reporting pause-time peer counts would read as live ones.
                frozen.peer_count = 0;
                frozen.served_peers_last_min = 0;
                frozen.discv5_table_size = 0;
                // The shadow cache outlives the reader; a CL-only chain
                // (no reader) parks an empty one so resume has something to
                // hand the reader it may then manage to start.
                let stats = reader
                    .as_ref()
                    .map(|r| r.read_stats())
                    .unwrap_or_else(|| Arc::new(ReadStats::new()));
                map.insert(handle, ChainEntry::Paused(config, frozen, stats));
                (sync, reader)
            }
            Some(other) => {
                map.insert(handle, other);
                return false; // created-but-not-started, or already paused
            }
            None => return false, // unknown id
        }
    };
    // Await the async teardown outside the map lock, like stop().
    engine.rt.block_on(async move {
        if let Some(reader) = &reader { reader.cancel_requests(); }
        sync.stop().await;
        if let Some(reader) = reader {
            reader.stop().await;
        }
    });
    // Today's figures go to disk with the rest of the warm state.
    if let Some(ledger) = usage_ledger(engine, handle) {
        ledger.tick(true);
    }
    tracing::info!(handle, "paused (networking torn down; warm state persisted)");
    true
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `SyncHandle::stop(self)` *consumes* the handle, so `pause` must own it. `map.get` would only lend it, so the code `remove`s the entry, which moves the value out, and puts back anything that isn't `Running`. The tuple `(sync, reader)` is the block's value, carried out past the lock.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* `block_on(async move { … })`: the teardown block *owns* `sync` and `reader`, because it consumes them. Inside it, `if let Some(reader) = &reader` only borrows (to cancel requests), and the later `if let Some(reader) = reader` moves the `Arc` out to call `stop`. Compare the borrowing `async { … }` blocks in the read path below.
- *[Protocol & domain](01-primer.md#primer-domain)* The frozen status keeps the warm store facts but zeroes the live-connection counts. `Paused` is published *before* the teardown finishes, which is why the doc forbids concurrent lifecycle calls on one handle; the Java `RustChainHandle` serializes them with `synchronized`. The ledger tick with `true` forces today's figures to disk with the rest of the warm state.

#### A background task started from a foreign thread

`rust/myotis-engine/src/host.rs` · lines 1291–1318

```rust
/// Start the minute ticker once per process: it keeps every ledger's day
/// current (bytes moved before midnight land on the old day give or take a
/// minute) and its file within `usage::WRITE_EVERY` of the truth, with no host
/// polling status at all.
fn start_usage_ticker(engine: &'static EngineState) {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        engine.rt.spawn(async move {
            let mut every = tokio::time::interval(std::time::Duration::from_secs(60));
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                tick_all_ledgers(engine);
            }
        });
    });
}

/// Tick every handle's ledger (not forced: each writes when it is due).
fn tick_all_ledgers(engine: &EngineState) {
    let ledgers: Vec<Arc<UsageLedger>> = match engine.usage.lock() {
        Ok(m) => m.values().cloned().collect(),
        Err(_) => return,
    };
    for ledger in ledgers {
        ledger.tick(false);
    }
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **`Once` inside a function.** A `static` declared inside a function body is still one global; only its name is local. `std::sync::Once::call_once` runs the closure the first time and never again, which is how `register` can call `start_usage_ticker` on every create and get exactly one ticker.
- *[async/await & tokio](01-primer.md#primer-async) · [Lifetimes](01-primer.md#primer-lifetimes)* **Why `&'static EngineState`.** `rt.spawn` needs a future that is `'static`: it may run after the caller's stack frame is gone. The `async move` block captures `engine`, a reference. That is allowed only because the reference itself is `'static` (it points into `static ENGINE`). With an ordinary `&EngineState` parameter this would not compile. `Runtime::spawn` can be called from any thread; unlike `tokio::spawn`, it does not need to be inside the runtime.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `tick_all_ledgers` clones the `Arc`s out under the lock and ticks them after the guard is gone. The temporary guard in `match engine.usage.lock() { … }` lives until the end of the `match`, so by the `for` loop it is already dropped.

#### A verified read, start to finish

`rust/myotis-engine/src/host.rs` · lines 1540–1570

```rust
pub fn request_account_json(handle: i64, address_hex: &str, block: &str) -> String {
    let Some(address) = parse_address(address_hex) else {
        return eljson::error_json("invalid address (expected 20-byte hex)");
    };
    let selector = match parse_read_block(block) {
        Ok(selector) => selector,
        Err(json) => return json,
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    // Snapshot the reader + the CL status/config under the lock, then release it
    // before the (potentially slow) query — never hold the map lock across a
    // verified read.
    let (reader, finalized_period, wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    let anchor = match read_anchor(selector, &reader) {
        Ok(anchor) => anchor,
        Err(json) => return json,
    };
    let pin = match selector {
        BlockSelector::Number(n) => Some(n),
        _ => None,
    };
    match engine.rt.block_on(reader.request(async { reader.get_account_pinned(anchor, address, pin).await })) {
        Ok(account) => eljson::account_json(address_hex, &account, finalized_period, wall_period),
        Err(e) => eljson::error_json(&e),
    }
}
```

`rust/myotis-engine/src/host.rs` · lines 3562–3580

```rust
/// Snapshot `(reader, finalizedPeriod, wallClockPeriod)` for a running handle,
/// or an error message. Holds the map lock only for the clone.
fn snapshot_reader(
    engine: &EngineState,
    handle: i64,
) -> Result<(Arc<ElReader>, u64, u64), &'static str> {
    let map = engine.handles.lock().map_err(|_| "engine lock poisoned")?;
    match map.get(&handle) {
        Some(ChainEntry::Running(config, sync, Some(reader))) => Ok((
            Arc::clone(reader),
            sync.status().finalized_slot / SLOTS_PER_PERIOD,
            config.wall_clock_period(),
        )),
        Some(ChainEntry::Running(_, _, None)) => Err("EL reader unavailable on this handle"),
        Some(ChainEntry::Paused(..)) => Err("handle is paused"),
        Some(ChainEntry::Created(_)) => Err("handle not started"),
        None => Err("unknown handle"),
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Borrowing & slices](01-primer.md#primer-borrowing)* **The standard bridge.** (1) Parse the input, with no panics, including the block selector. (2) `snapshot_reader` clones the `Arc<ElReader>` under the lock and releases it. (3) `read_anchor` applies or refuses the selector against the current head. (4) `engine.rt.block_on(reader.request(async { … }))` blocks *this* thread until the future finishes; `request` wraps it in the 90-second request budget with cancellation. (5) Turn the `Result` into JSON. The `async` block may borrow `reader` and `address`, because `block_on` doesn't return before the future completes. Unlike `spawn`, it needs no `'static`.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `engine.handles.lock().map_err(|_| "engine lock poisoned")?`: poison becomes an error value, and `?` returns it. The helper's error type is `&'static str`, so each state has a precise message ("handle is paused", "handle not started").
- *[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Never on a runtime thread.** Calling `block_on` from one of the runtime's own worker threads makes tokio panic, which aborts the host. Every caller of this file runs on a foreign thread: a JVM, iOS, Node or rpcd thread.
- *[Protocol & domain](01-primer.md#primer-domain)* Three kinds of answer: the result JSON (a failed verification is reported *inside* it, as `failReason`), `{"error": …}` (bad input, a stopped chain, or no peers), and the literal `"null"` for an item verified not to exist. A fourth arrived with ABI 27: `{"error": …, "code": -32602}`, a *permanent* refusal of the request itself.

#### Block selectors: apply or refuse

`rust/myotis-engine/src/host.rs` · lines 2058–2080

```rust
/// Whether a call for `block` may run against the verified head `head` (0 =
/// none yet). A number must lie in `[head - 64, head + 16]`, the hosts'
/// window: wallets pin reads to the number `eth_blockNumber` just returned,
/// which is at or near the head. Inside the window the call still runs against
/// HEAD state, the documented near-head trade-off (exact-block execution is
/// #382). A tag needs no check here: `Head` runs at the head, `Finalized` at
/// the beacon-finalized block, whose own not-synced refusal comes from the
/// reader.
fn check_call_block(block: BlockSelector, head: u64) -> Result<(), CallBlockRefusal> {
    let BlockSelector::Number(block) = block else {
        return Ok(());
    };
    if head == 0 {
        return Err(CallBlockRefusal::NoHead { block });
    }
    if block < head.saturating_sub(CALL_BLOCK_LAG_TOLERANCE) {
        return Err(CallBlockRefusal::Behind { block, head });
    }
    if block > head.saturating_add(CALL_BLOCK_AHEAD_TOLERANCE) {
        return Err(CallBlockRefusal::Ahead { block, head });
    }
    Ok(())
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let BlockSelector::Number(block) = block else { return Ok(()); };` is `let-else` on an enum: if the value is a `Number`, bind its payload and continue; otherwise run the `else` block, which must leave the function. It reads like Kotlin's `val n = (x as? Number)?.n ?: return`. The new `block` shadows the old one, a common Rust idiom.
- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Three refusals, two codes.** `CallBlockRefusal::to_json` (just above) turns `Behind` into the permanent −32602, because the head never moves back that far, and `Ahead` and `NoHead` into the retryable `{"error"}`, because they clear as the node syncs. Calling a lagging node's answer "permanent" would tell a client to stop asking. A number inside the window still runs against *head* state; that is the documented near-head trade-off.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `saturating_sub` and `saturating_add` keep `head - 64` from wrapping below zero near genesis and `head + 16` from wrapping at the top.

`rust/myotis-engine/src/host.rs` · lines 2091–2149

```rust
fn parse_state_overrides(json: &str) -> Result<myotis_evm::overrides::StateOverrides, String> {
    use myotis_evm::overrides::{AccountOverride, StateOverrides};
    let mut out = StateOverrides::new();
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(out);
    }
    let v: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|_| "malformed state override object".to_string())?;
    let Some(map) = v.as_object() else {
        return Err("state overrides must be an object keyed by address".to_string());
    };
    for (addr_str, entry) in map {
        let address =
            parse_address(addr_str).ok_or_else(|| format!("invalid override address {addr_str}"))?;
        let obj = entry
            .as_object()
            .ok_or_else(|| format!("override for {addr_str} must be an object"))?;
        let mut over = AccountOverride::default();
        for (k, val) in obj {
            match k.as_str() {
                "code" => {
                    let hex = val.as_str().ok_or("override 'code' must be a hex string")?;
                    over.code =
                        Some(parse_hex_bytes(hex).ok_or("override 'code' is not valid hex")?);
                }
                "balance" => {
                    over.balance = Some(parse_u256_hex_or_dec(val)?);
                }
                "nonce" => {
                    let n = parse_u256_hex_or_dec(val)?;
                    over.nonce = Some(u64::try_from(n).map_err(|_| "override 'nonce' too large")?);
                }
                "state" | "stateDiff" => {
                    let slots = val
                        .as_object()
                        .ok_or_else(|| format!("override '{k}' must be an object"))?;
                    let mut parsed = std::collections::HashMap::new();
                    for (slot, sv) in slots {
                        let key = parse_word32(slot).ok_or("override slot is not a 32-byte hex")?;
                        let sval = parse_word32(
                            sv.as_str().ok_or("override slot value must be a hex string")?,
                        )
                        .ok_or("override slot value is not a 32-byte hex")?;
                        parsed.insert(U256::from_be_bytes(key), U256::from_be_bytes(sval));
                    }
                    if k == "state" {
                        over.state = Some(parsed);
                    } else {
                        over.state_diff = parsed;
                    }
                }
                other => return Err(format!("unsupported state override field '{other}'")),
            }
        }
        out.insert(address, over);
    }
    Ok(out)
}
```

- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Apply or refuse.** The `eth_call` state-override parser treats an unknown key as an *error*, not a skip, because a silently ignored override answers a different question (#314, the rule in your CLAUDE.md). `call_target` above it applies the same rule to `to`: empty means contract creation, and anything malformed is refused rather than turned into a creation.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **`?` converts the error.** The function returns `Result<_, String>`, but `val.as_str().ok_or("override 'code' must be a hex string")?` produces an error of type `&str`. `?` calls `From::from` on the error before returning, and `String` implements `From<&str>`, so the literal is copied into an owned `String` only on that failure path. `ok_or_else(|| format!(…))` is used where the message needs formatting, so the work happens only when needed.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `for (addr_str, entry) in map` iterates a *borrowed* `serde_json::Map`, so both are references into the parsed JSON; nothing is copied until `parsed.insert` builds `U256` values.

`rust/myotis-engine/src/host.rs` · lines 1472–1489

```rust
pub fn set_ws_bound_periods(handle: i64, periods: i64) -> bool {
    let Some(engine) = engine() else { return false };
    let sane = periods.max(0) as u64;
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    match map.get(&handle) {
        Some(ChainEntry::Created(c)) | Some(ChainEntry::Running(c, _, _))
        | Some(ChainEntry::Paused(c, ..)) => {
            c.ws_policy
                .bound_override_periods
                .store(sane, std::sync::atomic::Ordering::Relaxed);
            true
        }
        None => false,
    }
}
```

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* A live setting reaches a *running* loop through `c.ws_policy.bound_override_periods.store(…)`, an atomic behind the shared `Arc<WsPolicy>`. It works in all three states, and one arm lists them with `|`. In `Some(ChainEntry::Created(c)) | Some(ChainEntry::Running(c, _, _)) | …`, every alternative must bind the same names with the same types, here `c: &Arc<ChainConfig>`. It's the same mechanism as the consent flag in `live_cold_start` ([Stop 15](15-net-tests.md)).

#### A write: judged before it is sent

`rust/myotis-engine/src/host.rs` · lines 3252–3289

```rust
pub fn send_raw_transaction_json(handle: i64, raw_hex: &str) -> String {
    let Some(raw) = parse_hex_bytes(raw_hex) else {
        return eljson::error_json("invalid raw transaction hex");
    };
    // Judged on the bytes alone (#360), BEFORE the engine is asked whether it
    // is up: a paused or starting node must not turn the permanent refusal of
    // bytes that are no transaction into a retryable "unavailable". The reader
    // checks again (its own callers need the gate too); the decode is cheap.
    let summary = match myotis_net::el::tx::decode_sendable(&raw) {
        Ok(summary) => summary,
        Err(reason) => return eljson::invalid_params_json(&reason),
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    // Another chain's transaction (#665), likewise before the handle is asked
    // whether it is up: its chain is in its config in every state, so a
    // paused, not-yet-started or reader-less handle refuses it permanently
    // too. The reader checks again (its own callers need the check).
    if let Some(chain_id) = handle_chain_id(engine, handle) {
        if let Err(reason) = myotis_net::el::tx::check_chain(&summary, chain_id) {
            let tx_hash = myotis_net::el::sent_tx::raw_hash_hex(&raw);
            tracing::info!(tx = %tx_hash, %reason, "transaction refused: signed for another chain");
            return eljson::invalid_params_json(&reason);
        }
    }
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    use myotis_net::el::reader::SendError;
    match engine.rt.block_on(reader.request(async { Ok(reader.send_raw_transaction(&raw).await) })) {
        Ok(Ok(hash)) => eljson::tx_hash_json(&hash),
        Ok(Err(SendError::Refused(reason))) => eljson::invalid_params_json(&reason),
        Ok(Err(SendError::Rejected(reason))) => eljson::send_rejected_json(&reason),
        Ok(Err(SendError::Unavailable(e))) | Err(e) => eljson::error_json(&e),
    }
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **The order of the checks is the point.** Bytes that are no transaction (#360) are refused before the engine is even asked whether it is up, so a paused node gives the same permanent −32602 as a running one. A transaction signed for another chain (#665) is refused next, from the handle's config, which exists in every state. Only then does the code need a running reader. `check_raw_transaction_json` below runs the first gate alone, with no handle, so hosts can call it before their readiness wait.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Nested results.** `reader.request` expects a future returning `Result<T, String>`, and `send_raw_transaction` returns `Result<hash, SendError>`. Wrapping it in `Ok(…)` makes `T` that whole inner result, so the match sees `Result<Result<…, SendError>, String>`. One `match` then separates all five cases, and `Ok(Err(SendError::Unavailable(e))) | Err(e)` joins the two retryable ones, since both bind `e: String`.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `use myotis_net::el::reader::SendError;` in the middle of a function body is legal; the import is scoped to that block.

#### Hex parsing without panics

`rust/myotis-engine/src/host.rs` · lines 3722–3734

```rust
/// Parse a `0x`-prefixed-or-bare hex string into exactly `N` bytes. Panic-free:
/// `None` for any malformed input (JNI callers pass untrusted strings).
fn parse_hex_fixed<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    if hex.len() != 2 * N || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Const generics.** `parse_hex_fixed::<32>` returns a stack array `[u8; 32]`; `N` is a compile-time number, something Java generics can't express. The length check and `all(is_ascii_hexdigit)` run first, so every later slice is two ASCII bytes. `hex.get(a..b)?` still returns `None` where `&hex[a..b]` could panic (on a range that is out of bounds or splits a multi-byte character), and `.ok()?` turns a parse error into `None`. Elsewhere, `slot as u64` in `get_storage_proof_json` deliberately keeps the bit pattern of a negative Java `long` (a slot index ≥ 2⁶³).

#### Entering the runtime without blocking

`rust/myotis-engine/src/host.rs` · lines 5605–5646

```rust
pub fn set_activity_watch_json(handle: i64, config_json: &str) -> bool {
    let Some((watch, unwatch)) = parse_activity_watch(config_json) else {
        tracing::warn!(
            "activity watch refused: not a JSON object whose `watch` and `unwatch` are arrays \
             of 20-byte hex addresses, one address is under both, or `watch` names more \
             addresses than the engine follows; ignoring the push"
        );
        return false;
    };
    let Some(engine) = engine() else {
        return false;
    };
    // Held from the reader lookup to the stash write, so pushes are applied
    // and stashed in one order, and a resume — whose re-apply takes this lock
    // too — sees either none of a push or all of it: a push that reached a
    // reader a pause then dropped is still in the stash its resume re-applies.
    let Ok(mut stash) = engine.activity_watch.lock() else {
        return false;
    };
    let Ok((reader, _, _)) = snapshot_reader(engine, handle) else {
        return false;
    };
    // The follower is spawned on the engine runtime, from a host thread.
    let _guard = engine.rt.enter();
    if let Err(e) = reader.set_activity_watch(&watch, &unwatch) {
        tracing::warn!(error = %e, "activity watch refused");
        return false;
    }
    // The reader's resulting list, not this push's delta: the two cannot drift.
    // Kept while the handle exists, paused included; a stopped one is gone,
    // and `stop` dropped its entry already.
    let still_there = engine.handles.lock().is_ok_and(|map| map.contains_key(&handle));
    if still_there {
        let list = reader.activity_watching();
        if list.is_empty() {
            stash.remove(&handle);
        } else {
            stash.insert(handle, list.into_iter().collect());
        }
    }
    true
}
```

- *[async/await & tokio](01-primer.md#primer-async)* **`rt.enter()`.** `reader.set_activity_watch` is a plain function, but it may `tokio::spawn` the follower task, and that needs a "current runtime". `let _guard = engine.rt.enter();` sets this thread's current runtime until the guard is dropped at the end of the function. It is cheaper than `block_on(async { … })` when there is nothing to await. Note the name: `_guard`, not `_`, for the same reason as `_serial` above.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **A lock held on purpose.** The `activity_watch` stash lock is taken first and held across the reader call, so pushes are applied and stashed in one order, and a resume (which takes the same lock to re-apply the list) sees all of a push or none. `snapshot_reader` takes the `handles` lock briefly inside it; `spin_up` and `stop` never hold both, so the nesting cannot deadlock.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `engine.handles.lock().is_ok_and(|map| map.contains_key(&handle))`: `is_ok_and` consumes the `Result`, so the closure receives the guard itself by value, and the guard is dropped when the closure returns.

`rust/myotis-engine/src/host.rs` · lines 6017–6041

```rust
// Per-key debounce map, NOT a single slot: wallets poll several
// distinct filters (one per watched contract), and alternating
// refusals would evict a single slot every call — logging everything
// during exactly the catch-up window the debounce targets. Bounded:
// swept of expired entries whenever it grows past a handful.
static RECENT_REFUSALS: std::sync::Mutex<
    Option<std::collections::HashMap<u64, std::time::Instant>>,
> = std::sync::Mutex::new(None);
const DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(60);
let log_it = match RECENT_REFUSALS.lock() {
    Ok(mut slot) => {
        let map = slot.get_or_insert_with(std::collections::HashMap::new);
        if map.len() > 64 {
            map.retain(|_, at| at.elapsed() < DEBOUNCE);
        }
        match map.get(&key) {
            Some(at) if at.elapsed() < DEBOUNCE => false,
            _ => {
                map.insert(key, std::time::Instant::now());
                true
            }
        }
    }
    Err(_) => true,
};
```

*[Interior mutability](01-primer.md#primer-interior-mutability)* **Why `Option<HashMap>`.** A `static` initializer must be a constant expression. `Mutex::new` is a `const fn`, but `HashMap::new` is not (it seeds a random hasher), so the map starts as `None` and `get_or_insert_with` creates it on first use, under the lock. `OnceLock` would work too; this form keeps one lock for both the creation and every later update. This debounce keeps a polling wallet's repeated refused `eth_getLogs` filter to one log line per minute.

> [!WARNING]
> **Stale or inaccurate comments in host.rs**<br>
>
> - The module doc (lines 2–5, 25–26) still calls the callers "the JNI natives (lib.rs)" and "the JNI shim". The JNI layer is gone: the callers are `ffi.rs` (UniFFI) and `capi.rs`. Many function docs still begin with the deleted `nativeXxx` names; `lib.rs` explains that history, this file does not.
> - `status_object` (lines 3819–3820) says its key *ordering* is part of the golden contract, but it builds a `serde_json::Map`, and this build compiles `serde_json` without `preserve_order` (checked with `cargo tree -e features` on the snapshot). Keys come out in alphabetical order. The tests compare parsed values, and Java reads keys by name, so nothing breaks; only the comment is wrong. `eljson::invalid_params_json` gets this right and says so.
> - The doc for `get_transaction_receipt_json` (lines 3011–3016) sits directly above `pending_nonce_overlay`'s doc, so rustdoc attaches both to `pending_nonce_overlay`, and the receipt function has none.
> - `parse_block_target`'s doc (lines 3496–3499) says its `Err` becomes −32000. Every caller now wraps it in `invalid_params_json`, which is −32602.
> - Two doc links name `Engine::pending_served_window` (line 120) and `Engine::log_index_runtime_bits` (line 5357); the struct is `EngineState`.

<a id="f-myotis-engine-src-ffi-rs"></a>

### myotis-engine/src/ffi.rs

*FFI · JVM · 515 lines · Java twin · (deleted) nativeXxx JNI functions*

The UniFFI entry points used by the JVM: 55 `#[uniffi::export]` functions, nearly all a one-line call into `host`, `catalog` or `ringlog` (the exception is shown below). The file has no state, no `unsafe` and no `async`. Only the transport is UniFFI; compound values still travel as JSON. `create_with_checkpoint` and `set_boot_enodes_json` are deliberately not exported (ABI 26 and 31): the JVM hosts have no surface for them. Because the exports remain plain Rust functions, `myotis-rpcd` uses this file as its Rust API too.

`rust/myotis-engine/src/ffi.rs` · lines 23–67

```rust
/// ABI handshake: installs the ring-buffer tracing subscriber (idempotent) and
/// returns the compiled-in [`crate::ABI_VERSION`]. UniFFI's checksum validation
/// already guarantees signature compatibility; this coarse version remains for
/// the wrapper's log line and as a shared constant with the iOS C ABI.
#[uniffi::export]
pub fn engine_init() -> i32 {
    crate::ringlog::init();
    crate::ABI_VERSION
}

/// Up to `max` buffered engine tracing lines (oldest first, newline-joined;
/// empty when idle) — the drainable-ring end of the observability seam.
#[uniffi::export]
pub fn drain_logs(max: i32) -> String {
    crate::ringlog::drain(max.max(0) as usize)
}

/// The embedded network catalog as a JSON array of NetworkInfo objects
/// (camelCase keys, display order).
#[uniffi::export]
pub fn available_networks_json() -> String {
    crate::catalog::networks_json()
}

/// Canonical name for a name/alias, or None when unknown (the Java wrapper
/// raises `EngineException`).
#[uniffi::export]
pub fn canonical_network_name(name_or_alias: String) -> Option<String> {
    crate::catalog::canonical_network_name(&name_or_alias).map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Hosting surface. create returns the handle id (>= 1), -1 for
// unknown-name/runtime-init failure, -2 for canonical-but-unsupported, and (v26)
// -3 for a dataDir bound to a caller-supplied checkpoint via the plain-C/Node
// `myotis_create_with_checkpoint` — the JVM has no wrapper for that path and
// must not resume such a directory from the embedded anchor.
// ---------------------------------------------------------------------------

/// Allocate a not-yet-started handle for `network` (`mainnet`, `sepolia` or `gnosis`
/// — the catalog's canonical names; an alias is canonicalised first).
#[uniffi::export]
pub fn create_handle(network: String, data_dir: String) -> i64 {
    crate::host::create(&network, &data_dir)
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Macros & attributes](01-primer.md#primer-macros)* **How a Kotlin call arrives, in one paragraph.** `RustEngineNative` calls the generated `createHandle` in `myotis_engine.kt`, which encodes each string into a buffer and calls a JNA native. The wrapper that `#[uniffi::export]` generated turns the buffers back into owned `String`s and calls `create_handle`. On load, the generated Kotlin compares a checksum per function (today 44197 for `create_handle`; it was 39066 in September), so a stale `.so` fails loudly instead of crashing on a changed signature. [Stop 17](17-uniffi.md) follows every step.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Owned in, borrowed onward.** UniFFI hands over owned `String`s (copied out of Kotlin memory), and `&network` lends them to `host`, whose functions take `&str`. The `String`s are dropped when the export returns. `.map(str::to_owned)` copies the `'static` literal into a `String` for Kotlin, and `None` becomes `null`. Further down, `holder.as_deref()` turns `Option<String>` into `Option<&str>` without allocating.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `max.max(0) as usize` clamps before casting, because a negative `i32` cast straight to `usize` would wrap around to a huge number.
- *[Protocol & domain](01-primer.md#primer-domain)* **Project rule:** *any* edit to this file, even to a doc comment, changes the UniFFI checksums, so run `./gradlew uniffiGenerateKotlin` afterwards. The `create_handle` doc now lists "`mainnet`, `sepolia` or `gnosis`"; Chiado is hosted too, and the doc has been copied into the generated Kotlin.

`rust/myotis-engine/src/ffi.rs` · lines 409–422

```rust
/// Verified `eth_getRawTransactionByBlock{Number,Hash}AndIndex` (ABI ≥ 53,
/// #715): the raw bytes of the transaction at `index` of the block `selector`
/// names (a tag, a 0x number or a 0x block hash) as `"0x…"`, the literal
/// `"null"`, `{"error"}`, or the permanent `{"error","code":-32602}`; see
/// `crate::host::get_raw_transaction_by_block_json`. `index` is signed as every
/// UniFFI integer here is (a JVM `long`, no `ULong`); a negative one is refused
/// for good.
#[uniffi::export]
pub fn get_raw_transaction_by_block_json(handle: i64, selector: String, index: i64) -> String {
    match u64::try_from(index) {
        Ok(index) => crate::host::get_raw_transaction_by_block_json(handle, &selector, index),
        Err(_) => crate::eljson::invalid_params_json("negative transaction index"),
    }
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* **No unsigned integers on the JVM.** Kotlin has `ULong`, but these bindings keep to Java-friendly signed types, so the transaction index arrives as `i64`. `u64::try_from(index)` refuses a negative one instead of reinterpreting it, and the refusal is permanent (−32602). The C twin in `capi.rs` takes `u64` directly. Compare `slot as u64` in the storage read, where reinterpreting the bits *is* the intent.

<a id="f-myotis-engine-src-capi-rs"></a>

### myotis-engine/src/capi.rs

*FFI · C ABI · 1,190 lines · Java twin · RustEngine.kt (iOS) mirrors RustEngineNative*

The plain C interface: 58 `#[no_mangle] extern "C"` functions declared by hand in `rust/include/myotis_engine.h`. iOS uses it through cinterop, `myotis-node` calls it by Rust path, and `myotis-rpcd` uses two of its functions. The JSON shapes and sentinels are the same as in `ffi.rs`, plus three functions UniFFI does not have: `myotis_create_with_checkpoint`, `myotis_set_boot_enodes` and `myotis_string_free`. The last line re-exports `submitted` and `Submission` from `myotis-net`: the Node scheduler uses them to carry a deadline and a cancel flag (in a thread-local) into a blocking C call.

#### Section map

| Lines | What happens |
|---|---|
| 1–42 | Module doc (memory contract, panic policy), `read_string`, `into_c`. |
| 44–132 | Handshake, log drain, catalog, `myotis_create`, `myotis_create_with_checkpoint`. |
| 134–252 | Lifecycle and switches: start, Tor, DNS discovery, metering, status, stop, pause, served window, resume, weak-subjectivity bound, stale anchor. |
| 254–795 | Verified reads, the `eth_call` family, gas, ENS, blocks, transactions, fees, send and check. |
| 797–810 | `myotis_string_free`. |
| 812–1082 | Tests (9), including the header pin. |
| 1084–1190 | Log index, seed pins, activity, read stats, import/export; the scheduler re-export. |

`rust/myotis-engine/src/capi.rs` · lines 19–52

```rust
use std::ffi::{c_char, CStr, CString};

/// Read a C string into an owned Rust `String`. Null → `None`; invalid UTF-8 is
/// replaced lossily (panic-free) rather than rejected — same spirit as the JNI
/// shim's `read_string`, which tolerates whatever the JVM hands it.
///
/// # Safety
/// `p` must be null or a valid null-terminated C string.
unsafe fn read_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    Some(CStr::from_ptr(p).to_string_lossy().into_owned())
}

/// Hand a Rust `String` to the caller as a `CString`. Interior NUL bytes cannot
/// occur in the engine's JSON/log output, but if one ever did, return null
/// instead of panicking (the caller already treats null as unavailable).
fn into_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The availability + ABI handshake (`nativeInit` twin). Installs the tracing
/// subscriber feeding the drainable ring (idempotent) and returns `ABI_VERSION`;
/// hosts must refuse to call anything else if the value doesn't match the header
/// they compiled against.
#[no_mangle]
pub extern "C" fn myotis_init() -> i32 {
    crate::ringlog::init();
    crate::ABI_VERSION
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **Raw pointers.** `*const c_char` carries no ownership and no lifetime, and may be null, so every use is guarded by `is_null()`. `CStr::from_ptr` scans for the terminating NUL and *borrows* the caller's memory. `.into_owned()` copies it, so the result no longer depends on how long the C side keeps its buffer. `CStr` / `CString` relate like `&str` / `String`.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* **Handing ownership to C.** `CString::new(s)` takes the `String`'s buffer by move, so the text is not copied (the buffer may grow by one byte for the NUL). It fails on an interior NUL byte, which `into_c` turns into a null pointer instead of a panic. `into_raw()` gives up Rust's ownership: no Rust code will free it unless it comes back.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `#[no_mangle] extern "C"` keeps the symbol name exactly `myotis_init` and uses the C calling convention. Functions that take only integers are plain `extern "C"`; functions that dereference caller pointers are `unsafe extern "C"` with a `# Safety` section, because the compiler can't check the caller's promise.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **No panics.** There's no `catch_unwind`. The workspace builds with `panic = "abort"`, and since Rust 1.81 a panic unwinding out of an `extern "C"` function aborts anyway. So every failure path returns null, `false` or −1.

`rust/myotis-engine/src/capi.rs` · lines 117–132

```rust
#[no_mangle]
pub unsafe extern "C" fn myotis_create_with_checkpoint(
    network: *const c_char,
    data_dir: *const c_char,
    checkpoint_root: *const c_char,
    checkpoint_slot: u64,
) -> i64 {
    let (Some(network), Some(data_dir), Some(root)) = (
        read_string(network),
        read_string(data_dir),
        read_string(checkpoint_root),
    ) else {
        return -1;
    };
    crate::host::create_with_checkpoint(&network, &data_dir, &root, checkpoint_slot)
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let (Some(network), Some(data_dir), Some(root)) = (…) else { return -1; };` uses a tuple pattern: all three strings must be present. By contrast, most functions treat a null string as `""` via `unwrap_or_default()`.

`rust/myotis-engine/src/capi.rs` · lines 364–392

```rust
pub unsafe extern "C" fn myotis_eth_call_json(
    handle: i64,
    from: *const c_char,
    to: *const c_char,
    data: *const c_char,
    value: *const c_char,
    block: *const c_char,
) -> *mut c_char {
    let from = read_string(from).unwrap_or_default();
    // NOT `unwrap_or_default()`, for the reason its overrides twin spells out:
    // an EMPTY `to` means CONTRACT CREATION, so a NULL one collapsed onto the
    // same value would run the caller's calldata as init code — a different
    // question than the one asked, which CLAUDE.md's apply-or-refuse rule
    // exists to prevent. `read_string` yields None for a NULL pointer only;
    // bad UTF-8 decodes lossily and is refused by the address parser instead,
    // which is why the message names the pointer. Both wrappers word it
    // identically: one condition, one wording.
    let Some(to) = read_string(to) else {
        return into_c(crate::eljson::invalid_params_json(
            "invalid 'to' (null pointer; pass an empty string for contract creation)",
        ));
    };
    let data = read_string(data).unwrap_or_default();
    let value = read_string(value).unwrap_or_default();
    let block = read_string(block).unwrap_or_default();
    into_c(crate::host::eth_call_json(
        handle, &from, &to, &data, &value, &block,
    ))
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Absent is not empty.** An empty `to` means contract creation, so a NULL `to` cannot fall back to `""`: that would run the caller's calldata as init code. The old tour flagged that this function still did so; ABI 29 fixed it, and both `eth_call` wrappers now refuse NULL with the same message. The comment is also more careful than before: `read_string` replaces bad UTF-8 rather than rejecting it, and the address parser then refuses the result.

`rust/myotis-engine/src/capi.rs` · lines 797–810

```rust
/// Release a string previously returned by any `myotis_*` function. Null is a
/// no-op.
///
/// # Safety
/// `s` must be null or a pointer previously returned by this module and not yet
/// freed. Passing anything else (including a pointer freed twice) is undefined
/// behavior.
#[no_mangle]
pub unsafe extern "C" fn myotis_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* **Taking ownership back.** `from_raw` rebuilds the owning `CString`, and `drop` frees it right away, where Java would wait for the garbage collector. This is sound only for a pointer that came from `into_raw` and hasn't been freed yet, which is exactly the promise the `# Safety` section asks for. Calling `free(3)` on it instead would be undefined behavior. On iOS, `RustEngine.kt`'s `take` copies the string with `toKString()` and calls `myotis_string_free` in a `finally`.

`rust/myotis-engine/src/capi.rs` · lines 841–879

```rust
#[test]
fn header_pins_the_current_abi_version() {
    const HEADER: &str = include_str!("../../include/myotis_engine.h");
    // Collect every definition rather than taking the first: being defined
    // exactly once is itself part of the contract, so a leftover copy in a
    // dead `#if 0` branch (or a per-platform variant) fails loudly instead
    // of shadowing the live one and passing against a stale value.
    // Column 0 only (no `trim()`): the live definition starts its line, while a
    // `#define` quoted inside a comment sits behind the block's ` * ` or is
    // indented — so prose ABOUT a bump can't read as a stray second definition
    // and turn the duplicate rule into a false positive.
    let defined: Vec<&str> = HEADER
        .lines()
        .filter_map(|l| l.strip_prefix("#define MYOTIS_ABI_VERSION"))
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .filter_map(|rest| rest.split_whitespace().next())
        .collect();
    assert_eq!(
        defined.len(),
        1,
        "rust/include/myotis_engine.h must #define MYOTIS_ABI_VERSION exactly once, \
         found {defined:?}"
    );
    // First token only, so the house style of annotating a bump inline
    // (`#define MYOTIS_ABI_VERSION 23 /* + setFoo */`, the C twin of
    // RustEngineNative.EXPECTED_ABI_VERSION's trailing comment) still parses.
    let declared: i32 = defined[0]
        .parse()
        .expect("MYOTIS_ABI_VERSION must be an integer literal");
    assert_eq!(
        declared,
        crate::ABI_VERSION,
        "rust/include/myotis_engine.h declares MYOTIS_ABI_VERSION {declared} but \
         crate::ABI_VERSION is {}. Update the header; :app-ios picks the new value \
         up automatically, but RustEngineNative.EXPECTED_ABI_VERSION (myotis-engine-rust) \
         is still a hand-kept mirror.",
        crate::ABI_VERSION
    );
}
```

- *[Tests](01-primer.md#primer-testing) · [Macros & attributes](01-primer.md#primer-macros)* **A test that reads a C header.** `include_str!` embeds the header's text at compile time, so the header becomes an input of the test binary: editing only the header still reruns the test. The test requires exactly one column-0 `#define MYOTIS_ABI_VERSION` and that it equals `crate::ABI_VERSION`. Bumping one without the other fails `cargo test`.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* The chain `lines → filter_map(strip_prefix) → filter → filter_map(split_whitespace().next()) → collect` borrows slices of `HEADER`, a `&'static str`; nothing is allocated until `collect` builds the `Vec<&str>`.

> [!WARNING]
> **Stale or inaccurate comments in capi.rs**<br>
>
> The module doc (lines 1, 15) and `read_string`'s doc (line 22) still compare this file with "the JNI shim", which no longer exists. The functions after the test module (from line 1084) mostly lack `# Safety` sections, and `myotis_log_index_status_json`, `myotis_address_activity_json` and `myotis_read_stats_json` are declared `unsafe` although they take no pointer. That is harmless for C callers, but a Rust caller must wrap them in `unsafe { }` for nothing.

<a id="f-myotis-engine-src-eljson-rs"></a>

### myotis-engine/src/eljson.rs

*engine · 2,805 lines · Java twin · VerifiedRpcBackend.buildBlockJson / buildReceiptJson / buildTxJson*

Pure functions that turn verified-read results into exactly the JSON the Java, iOS and Node sides parse: account, storage, code and proof results, JSON-RPC blocks, transactions, receipts and logs, result wrappers for `eth_call`, gas, access lists, traces, simulations and ENS, fees, address activity, and the two error envelopes. About 1,300 of its 2,805 lines are tests, the Rust half of the golden contract.

#### Section map

| Lines | What happens |
|---|---|
| 1–57 | Imports, `error_json`, `INVALID_PARAMS`, `invalid_params_json`. |
| 59–203 | Account, storage and code results. |
| 205–537 | Blocks, receipts, transactions (mined and pending), raw transactions, block receipts. |
| 539–660 | Fee history, fee estimate, the `eth_call` result. |
| 661–815 | ENS forward and record shapes. |
| 816–1235 | Access list, trace (`callTracer` frames), `eth_simulateV1` blocks, gas estimate. |
| 1236–1305 | Resolved block hash, tx hash, send rejected, `eth_getProof`. |
| 1306–1443 | Encoding helpers (quantities, hex, `be_to_decimal`) and `activity_json`. |
| 1445–2631 | `mod tests`. |
| 2633–2805 | `get_logs_json` (placed after the tests), then two more test modules. |

`rust/myotis-engine/src/eljson.rs` · lines 26–57

```rust
/// `{"error": "..."}` — a transport / not-running / bad-input failure the Java
/// side turns into an `EngineException` (distinct from a verification failure,
/// which is a full result with `failReason` set).
pub fn error_json(message: &str) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("error".into(), message.into());
    serde_json::Value::Object(obj).to_string()
}

/// JSON-RPC's "invalid params" code, carried by [`invalid_params_json`].
pub const INVALID_PARAMS: i32 = -32602;

/// `{"error": "...", "code": -32602}` — a PERMANENT refusal of the request's
/// parameters: no retry can make this request succeed on this node, so a host
/// that speaks JSON-RPC answers it with exactly this code. Emitted by eth_call
/// today, and by eth_call / eth_estimateGas for an executor refusal
/// ([`CallOutcome::Refused`], [`GasOutcome::Refused`]). A plain [`error_json`]
/// (no `code`) makes no such promise, and hosts answer it with the retryable
/// -32000. Old hosts see an ordinary `{"error"}` and lose nothing but the
/// classification.
///
/// `error` is always the FIRST key, whatever serde_json's key-order feature is,
/// so a prefix check for `{"error"` still recognises it. NOT for the JSON-string
/// tri-state reads (blocks, receipts, txs, feeHistory, logs): the JVM router and
/// the iOS backend unwrap only a SINGLE-key envelope there, and would pass this
/// one through as if it were a result.
pub fn invalid_params_json(message: &str) -> String {
    format!(
        "{{\"error\":{},\"code\":{INVALID_PARAMS}}}",
        serde_json::Value::from(message)
    )
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **Two kinds of failure, and now two envelopes.** `{"error": …}` means transport trouble, a stopped chain or bad input, and the hosts answer it as retryable (−32000). `{"error": …, "code": -32602}` means no retry can help. A *verification* failure is neither: it is a complete result with `failReason` set and `verifyMethod: null`.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Key order by construction.** `error_json` uses a `serde_json::Map`, whose key order depends on a feature flag. `invalid_params_json` uses `format!` so that `error` is always the first key and a host's prefix check for `{"error"` still works. `serde_json::Value::from(message)` produces a JSON string literal with correct escaping, which `{}` then prints. `{{` and `}}` are literal braces in a format string, and `{INVALID_PARAMS}` captures the constant by name (inline format arguments, Rust 1.58 and later).
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `"error".into()` and `message.into()` use `From` impls to build the owned key and the JSON value. `mut obj` is needed because `insert` changes the map, and Rust variables are immutable by default.

`rust/myotis-engine/src/eljson.rs` · lines 205–247

```rust
pub fn block_json(b: &VerifiedBlock) -> String {
    let h = &b.header;
    let mut s = String::with_capacity(1024);
    s.push_str("{\"number\":\"");
    s.push_str(&hex_quantity(h.number));
    s.push_str("\",\"hash\":\"");
    s.push_str(&hex0x(&b.hash));
    s.push_str("\",\"parentHash\":\"");
    s.push_str(&hex0x(&h.parent_hash));
    s.push_str("\",\"nonce\":\"");
    s.push_str(&hex0x_var(&h.nonce));
    s.push_str("\",\"sha3Uncles\":\"");
    s.push_str(&hex0x(&h.ommers_hash));
    s.push_str("\",\"logsBloom\":\"");
    s.push_str(&hex0x_var(&h.logs_bloom));
    s.push_str("\",\"transactionsRoot\":\"");
    s.push_str(&hex0x(&h.transactions_root));
    s.push_str("\",\"stateRoot\":\"");
    s.push_str(&hex0x(&h.state_root));
    s.push_str("\",\"receiptsRoot\":\"");
    s.push_str(&hex0x(&h.receipts_root));
    s.push_str("\",\"miner\":\"");
    s.push_str(&hex0x_var(&h.beneficiary));
    s.push_str("\",\"difficulty\":\"");
    s.push_str(&hex_quantity_scalar(&h.difficulty));
    s.push_str("\",\"extraData\":\"");
    s.push_str(&hex0x_var(&h.extra_data));
    s.push_str("\",\"gasLimit\":\"");
    s.push_str(&hex_quantity(h.gas_limit));
    s.push_str("\",\"gasUsed\":\"");
    s.push_str(&hex_quantity(h.gas_used));
    s.push_str("\",\"timestamp\":\"");
    s.push_str(&hex_quantity(h.timestamp));
    s.push_str("\",\"mixHash\":\"");
    s.push_str(&hex0x(&h.mix_hash_or_prev_randao));
    s.push('"');
    // Optional post-fork fields — emitted only when present (fork-gated), exactly
    // like the Java serializer.
    if let Some(bf) = &h.base_fee_per_gas {
        s.push_str(",\"baseFeePerGas\":\"");
        s.push_str(&hex_quantity_scalar(bf));
        s.push('"');
    }
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Hand-built JSON** for blocks, receipts, transactions, fee history and logs: a fixed field order, fields from inactive forks left out (`if let Some(bf) = &h.base_fee_per_gas`), and nothing that needs escaping, because only hex, numbers and fixed text are inserted. `let h = &b.header;` is a local borrow, and `&h.parent_hash` passes a `&[u8; 32]`. `String::with_capacity(1024)` reserves the buffer once, like `new StringBuilder(1024)`.

`rust/myotis-engine/src/eljson.rs` · lines 613–648

```rust
pub fn call_json(answer: &CallAnswer) -> String {
    let mut obj = serde_json::Map::new();
    match &answer.outcome {
        CallOutcome::Refused(reason) => return invalid_params_json(reason),
        CallOutcome::Success(data) => {
            obj.insert("status".into(), "ok".into());
            obj.insert("resultHex".into(), hex0x_var(data).into());
        }
        CallOutcome::Revert(data) => {
            obj.insert("status".into(), "revert".into());
            obj.insert("dataHex".into(), hex0x_var(data).into());
        }
        CallOutcome::Unavailable(reason) => {
            obj.insert("status".into(), "unavailable".into());
            obj.insert("reason".into(), reason.as_str().into());
        }
        // ABI ≥ 35: the transaction-object call, and a plain call whose
        // calldata alone costs more than the budget.
        CallOutcome::Infeasible(reason) => {
            obj.insert("status".into(), "infeasible".into());
            obj.insert("reason".into(), reason.as_str().into());
        }
    }
    obj.insert("blockNumber".into(), json_u64(answer.block_number));
    // ABI ≥ 52: that block's hash when proven (the anchor vouches for a block
    // of that number with the state root the call ran against), else null.
    obj.insert(
        "blockHash".into(),
        answer.block_hash.map(|h| serde_json::Value::from(hex0x(&h))).unwrap_or(serde_json::Value::Null),
    );
    // "Ran against the finalized block": an `unavailable` call ran nowhere, so
    // it is never `verified`, whatever anchor it asked for.
    let ran = !matches!(answer.outcome, CallOutcome::Unavailable(_));
    obj.insert("verified".into(), (answer.finalized && ran).into());
    serde_json::Value::Object(obj).to_string()
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match &answer.outcome` matches a *reference*, so each arm binds its payload by reference (`data: &Vec<u8>`, `reason: &String`) and nothing is moved out of `answer`. A refusal leaves early with `return invalid_params_json(reason)`: it ran nowhere, so it names no block.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `!matches!(answer.outcome, CallOutcome::Unavailable(_))` asks a yes-or-no question about a variant without binding anything. `verified` is true only for a call that ran, against the finalized block.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `answer.block_hash.map(|h| …).unwrap_or(serde_json::Value::Null)`: an `Option<[u8; 32]>` becomes a JSON string or JSON null. The array is `Copy`, so `map` takes it by value without disturbing `answer`.

`rust/myotis-engine/src/eljson.rs` · lines 1347–1386

```rust
/// A 32-byte hash as `0x`-prefixed lowercase hex.
fn hex0x(bytes: &[u8; 32]) -> String {
    hex0x_var(bytes)
}

/// Variable-length bytes as `0x`-prefixed lowercase hex.
fn hex0x_var(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        // Append directly into the buffer — no per-byte String allocation.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Big-endian bytes → base-10 decimal string (schoolbook division by 10; no
/// bignum dep). Empty / all-zero → "0".
fn be_to_decimal(bytes: &[u8]) -> String {
    // Strip leading zero bytes.
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let digits = &bytes[start..];
    if digits.is_empty() {
        return "0".to_string();
    }
    let mut value = digits.to_vec();
    let mut out = Vec::new();
    while value.iter().any(|&b| b != 0) {
        let mut remainder = 0u16;
        for byte in value.iter_mut() {
            let acc = (remainder << 8) | u16::from(*byte);
            *byte = (acc / 10) as u8;
            remainder = acc % 10;
        }
        out.push(b'0' + remainder as u8);
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `hex0x(&[u8; 32])` passes its argument straight to `hex0x_var(&[u8])`: an array reference coerces to a slice (a pointer plus a length) with nothing copied.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `use std::fmt::Write;` inside the function lets `write!` append to a `String` in place, like `StringBuilder.append`. `let _ =` discards a `Result` that can't be an error here. The final `s` has no semicolon, so it is the return value.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* In `be_to_decimal`, `|&b|` destructures the `&u8`, and `iter_mut()` hands out `&mut u8` so that `*byte = …` divides the big number by 10 in place: schoolbook long division, with no bignum library. `digits.to_vec()` makes the private copy that the division destroys. `u16::from` widens without loss; `as u8` narrows explicitly.

> [!WARNING]
> **Stale or inaccurate comments in eljson.rs**<br>
>
> The doc "Serialize a broadcast transaction hash" (line 595) is still attached to `call_json`; `tx_hash_json` (line 1243) has no doc. In the same block, "a JSON-RPC null for the other two" (line 609) dates from when the call had three statuses; it has five. `invalid_params_json`'s doc (lines 40–42) lists only `eth_call` and `eth_estimateGas` as emitters; most entry points in `host.rs` now use it.

<a id="f-myotis-engine-examples-bal-follow-check-rs"></a>

### myotis-engine/examples/bal\_follow\_check.rs

*example binary · 121 lines*

A live cross-check, run by hand with `cargo run --release -p myotis-engine --example bal_follow_check -- sepolia 10`. It starts the engine on a network whose blocks commit to a block access list (BAL; Sepolia since Amsterdam), watches the senders of a recent block, and reads their accounts at `latest` again and again. Each answer the engine took from its BALs (`verifyMethod: "blockAccessList"`) is compared field by field with an `eth_getProof` at the same block, which always fetches a fresh snap proof. It fails on any mismatch, and also when no BAL answer carried a change, since that run compared nothing a BAL applied. The binary is also the shortest example of a Rust host: it calls the `ffi` functions as plain Rust functions.

`rust/myotis-engine/examples/bal_follow_check.rs` · lines 27–59

```rust
fn main() {
    let mut args = std::env::args().skip(1);
    let network = args.next().unwrap_or_else(|| "sepolia".to_string());
    let minutes: u64 = args.next().and_then(|m| m.parse().ok()).unwrap_or(10);
    let dir = std::env::temp_dir().join(format!("myotis-bal-follow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("data dir");
    let handle = ffi::create_handle(network.clone(), dir.to_string_lossy().into_owned());
    assert!(handle > 0, "create failed: {handle}");
    assert!(ffi::start_handle(handle), "start failed");
    println!("started {network} in {}", dir.display());

    // Synced once a head block reads verified, with its transactions.
    let started = Instant::now();
    let senders = loop {
        assert!(started.elapsed() < Duration::from_secs(900), "not synced within 15 minutes");
        std::thread::sleep(Duration::from_secs(5));
        let block: Value = serde_json::from_str(&ffi::get_block_by_number_json(handle, "latest".into(), true))
            .unwrap_or(Value::Null);
        let Some(txs) = block.get("transactions").and_then(Value::as_array) else { continue };
        let mut senders: Vec<String> = txs
            .iter()
            .filter_map(|tx| tx.get("from").and_then(Value::as_str).map(str::to_lowercase))
            .collect();
        senders.sort();
        senders.dedup();
        if senders.len() >= 3 {
            senders.truncate(16);
            break senders;
        }
    };
    println!("synced after {:?}; watching {} senders", started.elapsed(), senders.len());
    let push = serde_json::json!({ "watch": senders }).to_string();
    assert!(ffi::set_activity_watch(handle, push), "watch push refused");
```

- *[Binaries, CLIs & signals](01-primer.md#primer-cli) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* An example under `examples/` is a separate binary that links the crate like an outside user would, so it sees only `pub` items: `myotis_engine::ffi`, not `host`. `std::env::args().skip(1)` drops the program name; `args.next()` then yields owned `String`s one at a time.
- *[Ownership & moves](01-primer.md#primer-ownership)* `ffi::create_handle(network.clone(), …)` must clone: the export takes its `String` by value (that is the UniFFI shape) and the code still prints `network` afterwards. `"latest".into()` builds the owned `String` the same signature needs.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `let senders = loop { … break senders; };`: a `loop` is an expression, and `break value` is its result. `let Some(txs) = … else { continue };` skips a poll whose block had no transactions yet. `sort` then `dedup` removes duplicate senders, since `dedup` drops only adjacent repeats.

`rust/myotis-engine/examples/bal_follow_check.rs` · lines 66–112

```rust
while Instant::now() < deadline {
    for address in &senders {
        let account: Value = serde_json::from_str(&ffi::request_account_json(handle, address.clone(), "latest".into()))
            .unwrap_or(Value::Null);
        let Some(method) = account.get("verifyMethod").and_then(Value::as_str) else { continue };
        let nonce = account["nonce"].as_i64().unwrap_or(-1).max(0);
        let balance = account["balanceWei"].as_str().unwrap_or("0").to_string();
        let previous = last.insert(address.clone(), (nonce.to_string(), balance.clone()));
        if method != "blockAccessList" {
            proven += 1;
            continue;
        }
        bal_answers += 1;
        let block = account["blockNumber"].as_u64().expect("blockNumber");
        let proof: Value = serde_json::from_str(&ffi::get_proof_json(
            handle,
            address.clone(),
            "[]".into(),
            format!("0x{block:x}"),
        ))
        .unwrap_or(Value::Null);
        if proof.get("accountProof").is_none() {
            no_proof += 1;
            println!("{address} @{block}: no proof to compare ({})", proof);
            continue;
        }
        let quantity = |v: &Value| u128::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).ok();
        let want_balance = quantity(&proof["balance"]).map(|b| b.to_string());
        let want_nonce = quantity(&proof["nonce"]).map(|n| n as i64);
        let same = want_balance.as_deref() == Some(balance.as_str())
            && want_nonce == Some(nonce)
            && proof["codeHash"].as_str() == account["codeHashHex"].as_str()
            && proof["storageHash"].as_str() == account["storageRootHex"].as_str();
        compared += 1;
        let changed = previous.is_some_and(|p| p != (nonce.to_string(), balance.clone()));
        if changed {
            carried += 1;
        }
        if same {
            println!("{address} @{block}: match (nonce {nonce}, balance {balance}{})", if changed { ", CARRIED A CHANGE" } else { "" });
        } else {
            mismatches += 1;
            println!("{address} @{block}: MISMATCH\n  bal:   {account}\n  proof: {proof}");
        }
    }
    std::thread::sleep(Duration::from_secs(6));
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `last.insert(address.clone(), (…))` returns the *previous* value as an `Option`, which is how the loop learns what the last read said without a separate lookup. `previous.is_some_and(|p| p != …)` consumes that `Option`.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `account["nonce"]` indexes a `serde_json::Value`; a missing key yields `Value::Null` instead of panicking, and `as_i64()` then gives `None`. The proof's QUANTITYs are hex strings, parsed with `u128::from_str_radix` after `trim_start_matches("0x")`.
- *[Tests](01-primer.md#primer-testing) · [Protocol & domain](01-primer.md#primer-domain)* The example uses `assert!` and `expect` freely. It is a test tool, not engine code, so a panic simply ends the run with a message; the panic-free rule applies to the library.

> [!WARNING]
> **Other stale docs in this crate**<br>
>
> - `lib.rs`'s module doc (line 9) lists "mainnet, Sepolia and Gnosis"; Chiado is hosted too. The old "mainnet only" wording is gone.
> - `ringlog.rs` (line 5) says hosts poll `drain` "over JNI (`nativeDrainLogs`)". Today it is UniFFI's `drain_logs` or the C `myotis_drain_logs`.
> - The manifest's comment on `myotis-net` says this is "the only crate that pulls in tokio/libp2p", but `myotis-net` itself depends on both (tokio pinned to the same `=1.52.3`). Its `description` still says "(JNI cdylib)".
> - The `ABI_VERSION` history entry v30 says `safe` "still resolves to the head". The code now refuses `safe` everywhere (`SAFE_TAG_REFUSAL`), and no later entry records the change.

## Checkpoint

13 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-engine-q1"></a>

**Q1** · Multiple choice

In `spin_up`, the config is copied out with `Arc::clone(c)` inside `let (config, read_stats) = { … };` before `block_on`. What is the block for?

- **A.** It makes the clone cheaper, because a block can borrow without counting
- **B.** Blocks are required around a `match` on a tuple
- **C.** The mutex guard lives only inside the block and is dropped at its `}`, so the lock is released before the slow start. Holding it across `block_on` would stall every other FFI call and risk deadlock
- **D.** It turns the `Arc` into a deep copy of the config

[Answer →](answers.md#a-engine-q1)

<a id="q-engine-q2"></a>

**Q2** · Multiple choice

Why does `pause` use `map.remove(&handle)` and then re-insert, instead of `map.get(&handle)`?

- **A.** `SyncHandle::stop(self)` consumes the handle, so `pause` must *own* it. `get` only lends a reference. Entries that aren't `Running` are put back unchanged
- **B.** `get` would take the lock a second time
- **C.** To give the paused handle a new id
- **D.** Because a `HashMap` cannot hold an enum with an `Arc` inside

[Answer →](answers.md#a-engine-q2)

<a id="q-engine-q3"></a>

**Q3** · Multiple choice

`start_usage_ticker(engine: &'static EngineState)` calls `engine.rt.spawn(async move { … tick_all_ledgers(engine) … })`. What would happen if the parameter were a plain `&EngineState`?

- **A.** Nothing; `async move` copies the whole `EngineState` into the task
- **B.** It would not compile: `spawn` requires a `'static` future, because the task may outlive the caller, and a future holding a non-`'static` reference is not `'static`
- **C.** It would compile, but the ticker would stop when `register` returns
- **D.** It would panic at runtime, because `spawn` must be called inside the runtime

[Answer →](answers.md#a-engine-q3)

<a id="q-engine-q4"></a>

**Q4** · Written answer

Walk through `host::request_account_json(handle, address_hex, block)` from the incoming strings to the returned JSON. Mention where the lock is held, what is cloned, how the block selector is handled, how the async code runs, and why the `async` block may borrow local variables.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-engine-q4)

<a id="q-engine-q5"></a>

**Q5** · Multiple choice

An iOS caller receives a `char*` from `myotis_status_json`. Who frees it, and how?

- **A.** The caller, with `free(3)`
- **B.** Nobody; Rust frees it when the next call comes in
- **C.** Rust frees it automatically when the function returns
- **D.** The caller, by passing it to `myotis_string_free`, which rebuilds the `CString` with `from_raw` and drops it. It came from Rust's allocator via `into_raw`, so `free(3)` would be undefined behavior

[Answer →](answers.md#a-engine-q5)

<a id="q-engine-q6"></a>

**Q6** · Written answer

`myotis-rpcd` calls `myotis_engine::ffi::create_handle("gnosis".into(), dir)`, while `myotis-node` calls `myotis_engine::capi::myotis_create(ptr, ptr)` inside `unsafe`. Explain why both work, why neither can call `myotis_engine::host::create`, and what each route costs.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-engine-q6)

<a id="q-engine-q7"></a>

**Q7** · Multiple choice

`parse_state_overrides` returns `Result<StateOverrides, String>`, yet contains `val.as_str().ok_or("override 'code' must be a hex string")?`, whose error is a `&str`. Why does this compile?

- **A.** `?` calls `From::from` on the error before returning it, and `String` implements `From<&str>`, so the literal is copied into a `String` on that path
- **B.** `&'static str` and `String` are the same type in Rust 2021
- **C.** `ok_or` always returns a `String` error
- **D.** The compiler inserts `.unwrap()` when the types differ

[Answer →](answers.md#a-engine-q7)

<a id="q-engine-q8"></a>

**Q8** · Multiple choice

In `create`, what would change if `let Ok(_serial) = engine.create_lock.lock() else { … };` were written as `let Ok(_) = engine.create_lock.lock() else { … };`?

- **A.** Nothing; both hold the lock until the function returns
- **B.** It would not compile, because `_` is not allowed in `let-else`
- **C.** With `_` nothing is bound, so the guard is dropped at the end of the statement and the lock is released immediately. The rest of `create` would run unserialized
- **D.** The lock would be held forever

[Answer →](answers.md#a-engine-q8)

<a id="q-engine-q9"></a>

**Q9** · Written answer

`set_activity_watch_json` calls `let _guard = engine.rt.enter();` before `reader.set_activity_watch(…)`, while `spin_up` uses `engine.rt.block_on(async { SyncHandle::start(cfg) })`. What does each do, and why is `enter` enough in the first case?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-engine-q9)

<a id="q-engine-q10"></a>

**Q10** · Multiple choice

A wallet calls `eth_call` with block `0x10` while the verified head is 20,000,000. What does `check_call_block` make of it, and why that code?

- **A.** It runs the call against head state, since any number is accepted
- **B.** `Ahead`: a retryable `{"error"}`, because the head will catch up
- **C.** It runs the call against block 16's state, which the engine fetches
- **D.** `Behind`: the permanent `{"error","code":-32602}`, because the number is more than 64 blocks below the head, head state would answer a different question, and the head never moves back that far

[Answer →](answers.md#a-engine-q10)

<a id="q-engine-q11"></a>

**Q11** · Written answer

In `UsageLedger::tick_on`, the comment insists that `self.meter.snapshot()` is taken *after* `self.state.lock()`. Describe the bug that would appear if the snapshot were taken before the lock, with two threads (the minute ticker and a status read).

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-engine-q11)

<a id="q-engine-q12"></a>

**Q12** · Multiple choice

How does `header_pins_the_current_abi_version` in `capi.rs` notice that someone bumped `ABI_VERSION` but forgot the C header?

- **A.** It runs the C compiler on the header at test time
- **B.** `include_str!` embeds `rust/include/myotis_engine.h` at compile time; the test extracts the single column-0 `#define MYOTIS_ABI_VERSION` and asserts it equals `crate::ABI_VERSION`. Because the header is a compile input, an edit to it alone also reruns the test
- **C.** It loads the iOS framework and calls `myotis_init`
- **D.** UniFFI's checksums cover the C header too

[Answer →](answers.md#a-engine-q12)

<a id="q-engine-q13"></a>

**Q13** · Multiple choice

The `eth_getLogs` debounce declares `static RECENT_REFUSALS: Mutex<Option<HashMap<u64, Instant>>> = Mutex::new(None);`. Why the `Option`?

- **A.** A `static` initializer must be a constant expression; `Mutex::new` is `const` but `HashMap::new` is not, so the map starts as `None` and is created on first use under the lock
- **B.** So the map can be dropped when the engine stops
- **C.** Because a `HashMap` inside a `Mutex` must always be optional
- **D.** To make the static `Copy`

[Answer →](answers.md#a-engine-q13)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
